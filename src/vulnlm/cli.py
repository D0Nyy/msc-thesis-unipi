"""Typer entrypoint. One command per stage, mirroring the brief.

    build --> re --> analysis --> report
                         |
                       eval

Stages are separate processes writing to disk, so any stage can be re-run
without repeating the expensive one (`analyze`).
"""

from pathlib import Path
from typing import Annotated

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from vulnlm.build.sample import DEFAULT_SEED

load_dotenv()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Vulnerability analysis of binary/executable files with LLMs.",
)

# stdout carries data, stderr carries everything a human reads. Keeps
# `vulnlm eval > metrics.json` clean and pipeable.
console = Console()
err = Console(stderr=True)

# Paths are Path, never str — this project is authored on Windows and runs on
# rented Linux GPUs. Anything persisted to JSONL gets converted to a relative
# POSIX string first, or run directories stop being portable between the two.
DataDir = Annotated[
    Path, typer.Option("--data-dir", envvar="VULNLM_DATA_DIR", help="Dataset root.")
]
ResultsDir = Annotated[
    Path,
    typer.Option("--results-dir", envvar="VULNLM_RESULTS_DIR", help="Run output root."),
]
RunId = Annotated[
    str | None, typer.Option("--run-id", help="Target run directory. Defaults to latest.")
]


def _todo(stage: str) -> None:
    err.print(f"[yellow]{stage}[/yellow] is not implemented yet.")
    raise typer.Exit(1)


@app.command()
def build(
    data_dir: DataDir = Path("data"),
    survey: Annotated[
        bool,
        typer.Option("--survey", help="Report what is in the archives; build nothing."),
    ] = False,
    json_out: Annotated[
        Path,
        typer.Option("--json", help="Where to write the survey JSON."),
    ] = Path("results/survey.json"),
    sample_only: Annotated[
        bool,
        typer.Option("--sample", help="Draw the sample and stop; compile nothing."),
    ] = False,
    compile_: Annotated[
        bool,
        typer.Option("--compile", help="Compile the existing manifest; do not redraw."),
    ] = False,
    java: Annotated[
        bool, typer.Option("--java/--no-java", help="Include the Java arm. Needs a JDK.")
    ] = True,
    jobs: Annotated[
        int | None, typer.Option("--jobs", "-j", help="Parallel compiles. Default: CPU count.")
    ] = None,
    # Default keeps everything under data/, which .gitignore already excludes.
    # Override it when the repo lives on a Windows drive: building 344 ELFs
    # across /mnt/c is slow, and DrvFs will not let the tree be cleared.
    build_dir: Annotated[
        Path | None,
        typer.Option(
            "--build-dir",
            envvar="VULNLM_BUILD_DIR",
            help="Where to extract and compile. Default: <data-dir>/processed.",
        ),
    ] = None,
    per_stratum: Annotated[
        int,
        typer.Option("--per-stratum", "-n", help="Cases to draw per CWE/lang/flow cell."),
    ] = 2,
    seed: Annotated[
        int, typer.Option("--seed", help="RNG seed. Changing it changes the sample.")
    ] = DEFAULT_SEED,
) -> None:
    """Prepare the dataset: draw the sample and build the corpus.

    With no flags this runs the whole stage — draw the stratified sample, then
    compile it: C/C++ to ELF at two optimisation levels with the flaw-survival
    gate, Java to bytecode. Each flag runs one step on its own instead:

      --survey    read-only precondition. Reports what the archives contain and
                  reconciles the filename parse against SARD's own manifest,
                  exiting non-zero if either invariant fails. Builds nothing.
      --sample    draw the sample and commit data/manifest.json, then stop
      --compile   build from the existing manifest without redrawing it

    Redrawing is safe to repeat: the sample is a pure function of the seed and
    the archives, so the default path regenerates a byte-identical manifest
    unless one of those actually changed. `--compile` exists for the reverse
    case — iterating on the toolchain without touching the sample at all.
    """
    if survey:
        _run_survey(data_dir / "raw", json_out)
        return
    if sample_only and compile_:
        err.print("[red]--sample and --compile are mutually exclusive.[/red]")
        raise typer.Exit(2)

    if not compile_:
        _draw_sample(data_dir, per_stratum, seed)
    if not sample_only:
        _compile_corpus(data_dir, build_dir or data_dir / "processed", jobs, java)


def _compile_corpus(
    data_dir: Path, build_dir: Path, jobs: int | None, java: bool = True
) -> None:
    """Build the sampled cases and report the survival gate (§7.1)."""
    from vulnlm.schema import BuildStatus

    report = _run_build(data_dir, build_dir, jobs, java)

    console.print(f"[dim]{report.compiler_version}[/dim]")
    console.print(
        f"[dim]{' '.join(report.common_flags)}  {' '.join(report.optimisations)}[/dim]"
    )
    if report.java_version:
        console.print(f"[dim]{report.java_version}[/dim]")
    console.print()

    console.print(_survival_table(report))
    _print_exclusions(report)
    _print_medians(report)

    out = data_dir / "build-report.json"
    out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    _print_totals(report, java)
    err.print(f"wrote {out}")

    # Non-zero when anything left the corpus, so this can gate a pipeline the
    # same way --survey does. ERASED is deliberately not counted: it is a §7.1
    # measurement, not a failure.
    if any(
        c.status in (BuildStatus.COMPILE_FAILED, BuildStatus.NO_FLAW_SYMBOLS)
        for c in report.cases
    ):
        raise typer.Exit(1)


def _run_build(data_dir: Path, build_dir: Path, jobs: int | None, java: bool):
    """Load the manifest and build it, turning setup failures into exit codes."""
    from vulnlm.build.compile import ToolchainError, build_corpus
    from vulnlm.build.suites import ArchiveNotFound
    from vulnlm.schema import Manifest

    manifest_path = data_dir / "manifest.json"
    if not manifest_path.exists():
        err.print(f"[red]{manifest_path} not found. Run `vulnlm build` first.[/red]")
        raise typer.Exit(2)

    manifest = Manifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    try:
        return build_corpus(
            manifest,
            manifest_path,
            data_dir / "raw",
            build_dir,
            jobs=jobs,
            warn=lambda msg: err.print(f"[yellow]{msg}[/yellow]"),
            java=java,
        )
    except (ArchiveNotFound, ToolchainError) as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc


def _native(report) -> list:
    """C/C++ cases. Only these have a survival column.

    Java is reported as a count instead: javac has no optimisation levels, so
    there is nothing for the gate to measure, and an empty row would imply a
    missing measurement rather than an inapplicable one.
    """
    return [c for c in report.cases if c.language != "java"]


def _survival_table(report) -> Table:
    """One row per C/C++ case: bad-path bytes at each level, and the ratio."""
    from vulnlm.schema import BuildStatus

    table = Table(box=None, pad_edge=False)
    table.add_column("case", style="dim")
    table.add_column("bad -O0", justify="right")
    table.add_column("-O2", justify="right")
    table.add_column("kept", justify="right")
    table.add_column("good kept", justify="right")

    def pct(value: float | None) -> str:
        return "—" if value is None else f"{value:.0%}"

    for case in _native(report):
        s = case.survival
        if s is None:
            table.add_row(case.case_id[:58], "—", "—", "—", "—", style="red")
            continue
        style = "" if case.status == BuildStatus.OK else "yellow"
        if s.bad_retained is not None and s.bad_retained > 1.0:
            style = "cyan"  # grew: the compiler inlined the sink into the source
        table.add_row(
            case.case_id[:58],
            f"{s.bad_o0:,}",
            f"{s.bad_o2:,}",
            pct(s.bad_retained),
            pct(s.good_retained),
            style=style,
        )
    return table


def _print_exclusions(report) -> None:
    """The three ways a case leaves the corpus, each reported as its own rate.

    Never a silent drop: an excluded case nobody counted is indistinguishable
    from a case the model failed on.
    """
    from vulnlm.schema import BuildStatus

    def of(status: BuildStatus) -> list:
        return [c for c in report.cases if c.status == status]

    if failed := of(BuildStatus.COMPILE_FAILED):
        err.print(f"\n[red]{len(failed)} case(s) did not compile:[/red]")
        for case in failed:
            lines = (case.error or "").splitlines()
            first = next(
                (ln for ln in lines if "error:" in ln), lines[0] if lines else ""
            )
            err.print(f"  {case.case_id}\n    [dim]{first.strip()[:150]}[/dim]")

    if no_syms := of(BuildStatus.NO_FLAW_SYMBOLS):
        err.print(
            f"\n[red]{len(no_syms)} case(s) built but exposed no bad-path symbol — "
            f"the oracle cannot label them at F2:[/red]"
        )
        for case in no_syms:
            err.print(f"  {case.case_id}")

    if erased := of(BuildStatus.ERASED):
        err.print(
            f"\n[yellow]{len(erased)} case(s) below the "
            f"{report.survival_threshold:.0%} survival threshold — excluded from "
            f"the F2 arm:[/yellow]"
        )
        for case in erased:
            assert case.survival is not None
            err.print(
                f"  {case.case_id}: {case.survival.bad_retained:.0%} retained "
                f"({case.survival.bad_o0} → {case.survival.bad_o2} bytes)"
            )


def _print_medians(report) -> None:
    """The §7.1 headline: median bad- and good-path retention at -O2."""
    import statistics

    measured = [c.survival for c in report.cases if c.survival is not None]
    if not measured:
        return
    bad = [s.bad_retained for s in measured if s.bad_retained is not None]
    good = [s.good_retained for s in measured if s.good_retained is not None]
    if not bad:
        return
    console.print(
        f"\nmedian retained at -O2: [bold]bad {statistics.median(bad):.0%}[/bold]"
        + (f", good {statistics.median(good):.0%}" if good else "")
    )


def _print_totals(report, java: bool) -> None:
    """Corpus size per language."""
    from vulnlm.schema import BuildStatus

    native = _native(report)
    jvm_cases = [c for c in report.cases if c.language == "java"]

    native_ok = sum(1 for c in native if c.status == BuildStatus.OK)
    console.print(
        f"[bold]C/C++[/bold] {native_ok} of {len(native)} cases in the F2 corpus, "
        f"{sum(len(c.binaries) for c in native):,} binaries"
    )
    if jvm_cases:
        jvm_ok = sum(1 for c in jvm_cases if c.status == BuildStatus.OK)
        classes = sum(len(c.binaries) for c in jvm_cases)
        scrubbed = sum(1 for c in jvm_cases for b in c.binaries if b.scrubbed)
        console.print(
            f"[bold]Java[/bold]  {jvm_ok} of {len(jvm_cases)} cases compiled, "
            f"{classes:,} class files ({scrubbed:,} scrubbed, "
            f"{classes - scrubbed:,} unscrubbed) "
            f"[dim](no gate — javac has no optimiser)[/dim]"
        )
    elif not java:
        err.print("[dim]Java arm skipped (--no-java).[/dim]")


def _draw_sample(data_dir: Path, per_stratum: int, seed: int) -> None:
    """Draw the stratified sample and commit data/manifest.json."""
    from vulnlm.build.sample import build_manifest
    from vulnlm.build.suites import ArchiveNotFound

    try:
        manifest = build_manifest(data_dir / "raw", per_stratum=per_stratum, seed=seed)
    except ArchiveNotFound as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    table = Table(box=None, pad_edge=False)
    table.add_column("stratum", style="dim")
    table.add_column("CWE")
    table.add_column("suite")
    table.add_column("flow")
    table.add_column("got", justify="right")
    table.add_column("avail", justify="right")
    short = {
        "cross_language": "cross-lang",
        "memory_safety": "mem-safety",
        "web_injection": "web-inject",
    }
    for s in manifest.strata:
        style = "red" if s.available == 0 else ("yellow" if s.selected < s.requested else "")
        table.add_row(
            short[s.kind],
            s.cwe_id,
            s.suite,
            s.flow_group,
            f"{s.selected}/{s.requested}",
            f"{s.available:,}",
            style=style,
        )
    console.print(table)

    # An empty cell is a design hole: the dataset cannot supply something the
    # sample assumes exists. A short cell is merely small. Both must be visible,
    # because either one silently unbalances the strata.
    empty = [s for s in manifest.strata if s.available == 0]
    short_cells = [s for s in manifest.strata if 0 < s.available < s.requested]
    if empty:
        err.print(f"\n[red]{len(empty)} EMPTY cell(s) — no cases exist:[/red]")
        for s in empty:
            err.print(f"  {s.cwe_id} {s.suite} {s.flow_group}")
    if short_cells:
        err.print(f"\n[yellow]{len(short_cells)} cell(s) came up short:[/yellow]")
        for s in short_cells:
            err.print(
                f"  {s.cwe_id} {s.suite} {s.flow_group}: "
                f"{s.selected} of {s.requested} (only {s.available} available)"
            )

    out = data_dir / "manifest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    by_kind: dict[str, int] = {}
    for c in manifest.cases:
        by_kind[c.stratum] = by_kind.get(c.stratum, 0) + 1
    console.print(
        f"\n[bold]{len(manifest.cases)} cases[/bold] in {len(manifest.strata)} strata "
        f"({', '.join(f'{k}={v}' for k, v in sorted(by_kind.items()))}), seed {manifest.seed}"
    )
    err.print(f"wrote {out}")


def _run_survey(raw_dir: Path, json_out: Path | None) -> None:
    """Render a dataset survey and exit non-zero if it is not clean."""
    from vulnlm.build.suites import ArchiveNotFound
    from vulnlm.build.survey import survey_dataset

    try:
        result = survey_dataset(raw_dir)
    except ArchiveNotFound as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    for s in result.suites:
        console.print(f"\n[bold]{s.key}[/bold]  {s.archive}")
        console.print(f"  sha256 {s.archive_sha256[:16]}…")

        table = Table(box=None, pad_edge=False, show_header=False)
        table.add_column(style="dim")
        table.add_column(justify="right")
        table.add_row("source files", f"{s.source_files:,}")
        table.add_row("  support", f"{s.support_files:,}")
        table.add_row("  parsed", f"{s.parsed_files:,}")
        table.add_row("cases", f"{s.cases:,}")
        table.add_row("  cross-file", f"{s.cross_file_cases:,}")
        table.add_row("distinct CWEs", f"{s.cwes:,}")
        table.add_row("headers", f"{s.header_files:,}")
        table.add_row("windows-only", f"{s.windows_only_files:,}")
        table.add_row("variant-declaring (§4.1)", f"{s.variant_declaring_files:,}")
        for name, count in s.flow_types.items():
            table.add_row(f"flow: {name}", f"{count:,}")
        if s.manifest_present:
            table.add_row("manifest overlap", f"{s.manifest_overlap:,}")
            table.add_row("  agreements", f"{s.manifest_agreements:,}")
            table.add_row("  flaw lines", f"{s.flaw_lines:,}")
        console.print(table)

        if s.manifest_repaired_lines:
            console.print(
                f"  [yellow]manifest repaired: dropped unmatched tags at lines "
                f"{s.manifest_repaired_lines}[/yellow]"
            )

        # The two invariants. Loud, and last, so they are what you read.
        if s.unexplained_rejects:
            console.print(
                f"  [red]FAIL {s.unexplained_rejects:,} unexplained rejects[/red]"
            )
            for name in s.reject_examples:
                console.print(f"    {name}")
        if s.manifest_disagreements:
            console.print(
                f"  [red]FAIL {s.manifest_disagreements:,} CWE disagreements "
                f"with manifest.xml[/red]"
            )
            for line in s.disagreement_examples:
                console.print(f"    {line}")
        if s.orphan_flaw_entries:
            console.print(
                f"  [red]FAIL {s.orphan_flaw_entries:,} flaw entries with no "
                f"parsed source file[/red]"
            )
        if s.ok:
            console.print("  [green]OK[/green] parse accounts for every source file")

    # Both sampling arms are visible here: shared feeds the cross-language
    # stratum, c-cpp-exclusive feeds the memory-safety one.
    console.print(
        f"\n[bold]shared[/bold] (in all {len(result.suites)} suites): "
        f"{len(result.shared_cwes)} CWEs"
    )
    console.print(f"  {', '.join(result.shared_cwes)}")
    # The number that actually constrains CWE selection. Much smaller than
    # `shared`, because Win32-only and single-flow-group CWEs drop out.
    console.print(
        f"\n[bold]sampleable[/bold] (shared, and every cell survives exclusions): "
        f"[green]{len(result.sampleable_cwes)}[/green] CWEs"
    )
    console.print(f"  {', '.join(result.sampleable_cwes)}")
    for key, ids in sorted(result.exclusive_cwes.items()):
        console.print(f"\n[bold]{key} only:[/bold] {len(ids)} CWEs")
        console.print(f"  {', '.join(ids)}")

    # Always written. A survey is cheap and the JSON is the diffable record of
    # what the dataset looked like on a given day — useful precisely when a
    # later run disagrees with an earlier one.
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    err.print(f"\nwrote {json_out}")

    if not result.ok:
        raise typer.Exit(1)


@app.command()
def recover(
    data_dir: DataDir = Path("data"),
    binary: Annotated[
        Path | None,
        typer.Option("--binary", help="Analyse one executable (F2, or F1 for bytecode)."),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option("--source", help="Analyse source directly (F0). No decompiler."),
    ] = None,
    tier: Annotated[
        str | None, typer.Option("--tier", help="Restrict to one of F0, F1, F2.")
    ] = None,
) -> None:
    """Stage 1 — recover code and chunk it. Emits Chunk records.

    Scrubbing is NOT here. §4.1 puts every caller at build time — Java before
    javac, C/C++ source for the F0 condition — so `build` emits the scrubbed
    tree and `recover` reads whichever tree the run calls for. That leaves this
    pipeline with no dataset-specific behaviour at all, which is what makes it
    usable on an arbitrary binary.

    (Currently emitted for Java only; the C/C++ F0 tree is still pending. See
    `docs/todo.md`.)

    Three entry points, one pipeline (protocol §4.0):

      (no flag)   work through the committed sample manifest — benchmark mode
      --binary    an arbitrary executable: decompile, then chunk
      --source    source as written: skip the decompiler, chunk directly

    `--source` is the same F0 path the experiment uses as its control
    condition, so it costs nothing to expose. Note it makes vulnlm a source
    scanner, a crowded space where dedicated tools are stronger — the value
    here is having ONE pipeline that treats source and decompiled output
    identically, which is what makes the fidelity comparison valid.
    """
    if binary and source:
        err.print("[red]--binary and --source are mutually exclusive.[/red]")
        raise typer.Exit(2)
    _todo("recover")


@app.command()
def analyze(
    data_dir: DataDir = Path("data"),
    results_dir: ResultsDir = Path("results"),
    model: Annotated[
        str | None, typer.Option("--model", help="Model key: S, M, L or A.")
    ] = None,
    resume: Annotated[
        bool, typer.Option("--resume", help="Skip chunks already present in the run.")
    ] = False,
) -> None:
    """Stage 2 — run the model tiers over chunks, append to results/raw/."""
    _todo("analyze")


@app.command()
def report(
    results_dir: ResultsDir = Path("results"), run_id: RunId = None
) -> None:
    """Stage 3 — deterministic JSON -> SARIF 2.1.0 export."""
    _todo("report")


@app.command("eval")
def eval_(
    data_dir: DataDir = Path("data"),
    results_dir: ResultsDir = Path("results"),
    run_id: RunId = None,
) -> None:
    """Score results against ground truth. Emits results/metrics/."""
    _todo("eval")


if __name__ == "__main__":
    app()
