"""Compile the sampled C/C++ cases and gate on flaw survival (protocol §7.1).

Stage 0.5, between `sample` and `recover`. For each case in the manifest this
produces four ELF binaries per variant --- {-O0, -O2} x {symbols, stripped} ---
measures how much of the flaw survives optimisation, and excludes the cases
where it does not.

The gate is the point of the module. In 7% of cases `-O2` proves the result a
constant and deletes the vulnerability outright; Ghidra then decompiles a
function with no flaw in it and the model is scored against a bug that is not
there. Those are guaranteed false negatives, and without this stage they would
be silently attributed to the model rather than to the compiler.

Java is handled by `jvm`, which this module calls: its F0->F1 walk is javac
plus Vineflower, and with no optimiser there is nothing for a survival gate to
catch.

Layout under the build directory (`--build-dir`, default `data/processed`).
Sources keep their archive layout; binaries are split by suite. A Juliet C/C++
case can be either `.c` or `.cpp` and the two share one include tree, so the
compiler is chosen per case rather than per directory:

    src/C/             sources from the C/C++ archive
    src/Java/          sources from the Java archive, plus the jars it ships
    src-scrubbed/      the §4.1 F0 tree, one directory per case
    bin/c-cpp/         one directory per case: {bad,good}-O{0,2}.{sym,stripped}
    bin/java/          one directory per case: .class files, scrubbed/ and not

`src-scrubbed/` is what the F0 condition reads, and the two arms need it for
different reasons. For C/C++ the binaries are built from `src/` unmodified —
`objcopy --strip-all` already anonymises them — so this tree exists purely to
be read as text. For Java there is no `strip`, so the scrubbed tree is also
what javac compiles.

`src/` keeps each archive's own top-level directory rather than adding a suite
layer of its own — `C/` and `Java/` already distinguish them, and preserving
the archive-relative path means a path in `manifest.json` is literally the path
on disk. It is also what makes the 5x family's sibling `#include`s resolve.
`bin/` does need the suite split, because there the two arms produce different
kinds of artifact into flat per-case directories.

Everything here is regenerable and gitignored; `data/build-report.json` is the
committed record of what was produced, with paths relative to the build root.
"""

import posixpath
import re
import shutil
import subprocess
import zipfile
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from vulnlm.build.juliet import parse_name
from vulnlm.build.scrub import CaseScrub, scrub_tree
from vulnlm.build.suites import SUITES, Suite, find_archive, sha256_file
from vulnlm.schema import (
    BinaryArtifact,
    BuildReport,
    BuildStatus,
    BuildVariant,
    Case,
    CaseBuild,
    FlawSurvival,
    FlawSymbol,
    Language,
    Manifest,
    ScrubbedSymbol,
    ScrubRecord,
)

# --------------------------------------------------------------------------- #
# Build settings — protocol §7.1
# --------------------------------------------------------------------------- #
#
# Everything in this block is a decision, not a default. Each one changes what
# the model sees at F2, and each is copied into the BuildReport so a corpus can
# be traced back to the flags that produced it.

# Pinned explicitly rather than inherited from the compiler. gcc's default
# standard has moved (gnu17 in gcc 11, gnu23 in gcc 15) and the newer defaults
# turn implicit declarations and incompatible pointer assignments — both of
# which Juliet 1.3 contains — from warnings into hard errors. Without a pin,
# the set of buildable cases becomes a function of which Ubuntu the build ran
# on, which would silently reshape the sample.
C_STANDARD = "gnu11"
CXX_STANDARD = "gnu++14"

# Juliet is deliberately warning-dense — the warnings ARE the test material —
# so warnings are silenced rather than read. Errors are still fatal.
_QUIET = "-w"

# `_FORTIFY_SOURCE` is enabled by Ubuntu's gcc at -O1 and above but not at -O0,
# which would make the -O0/-O2 pair differ in the libc API surface as well as
# in optimisation: `printf` becomes `__printf_chk`, `memcpy` becomes
# `__memcpy_chk`. Since §4.1 treats imported API names as signal, and §7.1's
# -O0 subset exists to isolate optimisation specifically, that confound is
# removed rather than tolerated. Set to 2 here if the intent changes to
# "whatever a distro release build would produce".
_FORTIFY = "-U_FORTIFY_SOURCE"

# Dynamic linking is required, not incidental (§7.1): imported libc names
# survive stripping through the PLT, and static linking would turn `strcpy`
# into an unnamed blob and destroy the API-call signal.
_LINKAGE = "-no-pie"  # fixed load address; keeps Ghidra addresses comparable

# Juliet ships each case with its own `main()` behind this guard. The
# alternative build mode — the 350 shared `main.cpp` files that call dozens of
# cases into one application — is for testing source analysers over a tree, and
# is not ours.
_ENTRY = "-DINCLUDEMAIN"

COMMON_FLAGS: tuple[str, ...] = (_QUIET, _FORTIFY, _LINKAGE, _ENTRY, "-g")

OPTIMISATIONS: tuple[str, ...] = ("-O0", "-O2")

# Under this share of bad-path code retained at -O2, the flaw is treated as
# erased and the case leaves the F2 arm. 15% is low enough that ordinary
# tightening does not trip it and high enough to catch the cases that reduce to
# a constant — one of them compiles down to `xor %edi,%edi; jmp printIntLine`.
SURVIVAL_THRESHOLD = 0.15

# Every case calls printLine/printIntLine, which live here. `std_testcase.h`
# carries an `extern "C"` guard, so one C build of io.c links into C++ cases
# too — but it is compiled with the case's own compiler anyway, to keep a
# single translation-unit language per binary.
SUPPORT_DIR = "C/testcasesupport"
SUPPORT_SOURCES: tuple[str, ...] = (f"{SUPPORT_DIR}/io.c",)
SUPPORT_MEMBERS: tuple[str, ...] = (
    *SUPPORT_SOURCES,
    f"{SUPPORT_DIR}/std_testcase.h",
    f"{SUPPORT_DIR}/std_testcase_io.h",
    f"{SUPPORT_DIR}/std_thread.h",
    f"{SUPPORT_DIR}/testcases.h",
)

_CCPP_SUITE: Suite = next(s for s in SUITES if s.key == "c-cpp")


# --------------------------------------------------------------------------- #
# Source selection
# --------------------------------------------------------------------------- #
#
# Which of a case's files go into which binary. This is NOT the same question
# as -DOMITGOOD/-DOMITBAD, and getting it wrong is not a subtle failure.

def select_sources(files: list[str], *, bad: bool) -> list[str]:
    """The compilable files for one variant of a case.

    Juliet states the variant in the filename for 4,323 cases (`..._81_bad.cpp`
    next to `..._81_goodG2B.cpp`). For the 81-84 family the preprocessor alone
    is enough, because those files are wholly inside `#ifndef OMITBAD`. For the
    23 flow-01 `good1` cases it is NOT: each variant file carries its own
    `main()` OUTSIDE the guard, so compiling the pair yields two `main`s and
    the link fails. Selecting by filename variant is correct for both, so it is
    done unconditionally rather than special-cased by flow.
    """
    out: list[str] = []
    for path in sorted(files):
        if posixpath.splitext(path)[1].lower() not in (".c", ".cpp"):
            continue  # headers are #included, never compiled
        parsed = parse_name(path)
        variant = parsed.variant if parsed is not None else None
        if variant is None or variant == "base":
            out.append(path)  # shared between both binaries
        elif (variant == "bad") == bad:
            out.append(path)
    return out


def compiler_for(sources: list[str]) -> str:
    """g++ when any translation unit is C++, gcc otherwise.

    Decided per case rather than per language field: a case's `Language` comes
    from one representative file, and a C++ case can carry `.c` parts.
    """
    return "g++" if any(s.endswith(".cpp") for s in sources) else "gcc"


def standard_flag(compiler: str) -> str:
    return f"-std={CXX_STANDARD if compiler == 'g++' else C_STANDARD}"


# --------------------------------------------------------------------------- #
# The symbol oracle
# --------------------------------------------------------------------------- #
#
# At F2 there is no other way to know which recovered function holds the flaw.
# Derived from the symbol-bearing build and never shown to the model.

# Juliet's two spellings. A C case emits `<case_id>_bad`; a C++ case wraps the
# same function in a namespace named for the case, so it demangles to
# `<case_id>::bad()`. Both reduce to the same tail.
BAD_TAILS: frozenset[str] = frozenset({"bad", "badSink", "badSource"})
GOOD_TAILS: frozenset[str] = frozenset(
    {
        "good", "good1", "good2", "goodG2B", "goodB2G",
        "goodG2BSink", "goodB2GSink", "goodG2BSource", "goodB2GSource",
    }
)

# `nm -S` output: address, size, type, name. Size is absent for symbols the
# linker could not size, so the size group is optional and those are skipped.
_NM_LINE = re.compile(r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S)\s+(.+)$")


class ToolchainError(RuntimeError):
    """A required binutils/gcc program is missing or failed."""


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    kind: str


def _text_symbols(binary: Path) -> Iterator[Symbol]:
    """Defined, demangled function symbols.

    Weak symbols are dropped: at -O2 a C++ case pulls in hundreds of `W` STL
    template instantiations (`std::_Rb_tree<...>::_M_insert_node`), and letting
    them into the size sum would swamp the few hundred bytes of Juliet code the
    measurement is about.
    """
    proc = subprocess.run(
        ["nm", "--print-size", "--defined-only", "--demangle", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolchainError(f"nm failed on {binary.name}: {proc.stderr.strip()[:200]}")
    for line in proc.stdout.splitlines():
        m = _NM_LINE.match(line.strip())
        if m is None:
            continue
        kind = m.group(3)
        if kind not in ("t", "T"):
            continue
        yield Symbol(
            name=m.group(4),
            address=int(m.group(1), 16),
            size=int(m.group(2), 16),
            kind=kind,
        )


def symbol_tail(name: str, case_id: str) -> str | None:
    """Reduce a symbol to the Juliet function name, or None if it is not one.

    Both spellings collapse here:

        CWE121_..._01_bad                       -> "bad"
        CWE121_..._74::badSink(std::map<...>)   -> "badSink"

    The C++ argument list is dropped first, so overloads do not fragment.
    """
    base = name.split("(", 1)[0].strip()
    if "::" in base:
        return base.rsplit("::", 1)[1] or None
    prefix = f"{case_id}_"
    return base[len(prefix):] if base.startswith(prefix) else None


def path_sizes(
    binary: Path, case_id: str
) -> tuple[int, int, list[FlawSymbol], list[FlawSymbol]]:
    """(bad bytes, good bytes, bad symbols, good symbols) for one binary.

    Addresses are kept, not just names. `nm` reports all three fields and the
    address is the one that survives into the stripped twin — it is what joins
    Ghidra's `FUN_00401316` back to `badSink`. Sorted by address so the list
    reads in load order.
    """
    bad_bytes = good_bytes = 0
    bad: list[FlawSymbol] = []
    good: list[FlawSymbol] = []
    for sym in _text_symbols(binary):
        tail = symbol_tail(sym.name, case_id)
        if tail is None:
            continue
        found = FlawSymbol(
            name=sym.name, tail=tail, address=sym.address, size=sym.size
        )
        if tail in BAD_TAILS:
            bad_bytes += sym.size
            bad.append(found)
        elif tail in GOOD_TAILS:
            good_bytes += sym.size
            good.append(found)
    return (
        bad_bytes,
        good_bytes,
        sorted(bad, key=lambda s: s.address),
        sorted(good, key=lambda s: s.address),
    )


# --------------------------------------------------------------------------- #
# The scrub oracle
# --------------------------------------------------------------------------- #
#
# The F0 counterpart of the symbol oracle above, and shared with the Java arm.
# Same job — say which function holds the flaw — but the join is by name rather
# than by address, because F0 text has names and a stripped binary does not.

# Shared support scrubbed alongside each case. `testcases.h` is excluded: it is
# a generated index declaring all 77,567 case functions, so scrubbing it 44
# times would dominate the runtime and put every case name in every mapping.
# Nothing here includes it — it belongs to the shared-main build mode, which
# §7.1 does not use.
SCRUB_SUPPORT_MEMBERS: tuple[str, ...] = tuple(
    m for m in SUPPORT_MEMBERS if not m.endswith("testcases.h")
)


def variant_tail(name: str, case_id: str) -> str | None:
    """The Juliet variant a declared name represents, or None.

    Three spellings reach this, and only the first is what `symbol_tail` was
    written for:

        CWE121_..._01_bad      C, qualified by the case id   -> "bad"
        CWE369_...::bad()      C++, qualified by namespace   -> "bad"
        bad                    Java, and C's inner statics   -> "bad"

    The bare form has to be accepted because a Java case declares `void bad()`
    outright and a C case declares `static void goodG2B()` beside its qualified
    `..._01_good`.
    """
    if name in BAD_TAILS | GOOD_TAILS:
        return name
    return symbol_tail(name, case_id)


def scrub_symbols(
    result: CaseScrub, sources: list[str], case_id: str
) -> list[ScrubbedSymbol]:
    """The flaw-carrying entries of a scrub mapping.

    **Filtered on what the case's own sources DECLARE**, not on what the
    mapping contains and not on the whole scrub unit. Two distinct ways the
    looser readings go wrong, both found by running this over the sample:

    * Every C case's mapping holds a bare `bad`, minted from the status string
      `printLine("Calling bad()...")`. A legitimate rename, but not a function —
      filtering on the mapping yields a second `bad` pointing at nothing, and
      scoring cannot tell which of the two was the flaw.
    * `io.c` defines empty stubs `good1()`..`good9()`, and `good1`/`good2` are
      *also* real Juliet variant names for the flow-01 family. Only the
      declaring file separates them, which is why `CaseScrub.declared` is per
      file rather than a flat set.
    """
    found: list[ScrubbedSymbol] = []
    for name in sorted(result.declared_in(sources)):
        if name not in result.mapping:
            continue  # declared but preserved — `main` and the RUNTIME_CONTRACT
        tail = variant_tail(name, case_id)
        if tail in BAD_TAILS | GOOD_TAILS:
            found.append(ScrubbedSymbol(name=result.mapping[name], tail=tail))
    return found


def scrub_record(result: CaseScrub, sources: list[str], case_id: str) -> ScrubRecord:
    """The F0 oracle for one case, narrowed to the case's own sources.

    `paths` covers only the case's files. The scrubbed support tree is a build
    input, not something `recover` or `eval` has to locate, and carrying ten
    extra rows per case would bury the three that matter.
    """
    return ScrubRecord(
        mapping=dict(result.mapping),
        paths={s: result.paths[s] for s in sources if s in result.paths},
        symbols=scrub_symbols(result, sources, case_id),
    )


def scrub_corpus(
    cases: list[Case], work: Path, scrub_root: Path
) -> dict[str, ScrubRecord]:
    """Scrub every C/C++ case into `scrub_root`, keyed by case id.

    Run over ALL cases, independently of whether they compile. §7.1's
    exclusions — unbuildable, and erased by `-O2` — are exclusions from the
    **F2** arm; the source is still perfectly good F0 material, and a case gcc
    refuses is still a case a model can be asked to read. Gating this on the
    compiler would silently shrink the control condition to match the treatment.
    """
    records: dict[str, ScrubRecord] = {}
    for case in cases:
        sources = sorted(case.files)
        members = sources + [
            m for m in SCRUB_SUPPORT_MEMBERS if m not in sources
        ]
        result = scrub_tree(members, work, scrub_root / case.case_id)
        records[case.case_id] = scrub_record(result, sources, case.case_id)
    return records


def retained(o0: int, o2: int) -> float | None:
    """Share of bad-path code left at -O2. None when there was none at -O0.

    Values above 1.0 are real and expected: -O2 inlines the sink into the
    source, so one function absorbs another and grows. That is the compiler
    doing part of §4.2's chunk assembly, and it is a result rather than an
    artefact.
    """
    return None if o0 == 0 else o2 / o0


# --------------------------------------------------------------------------- #
# Compiling
# --------------------------------------------------------------------------- #


def compiler_version(compiler: str = "gcc") -> str:
    try:
        proc = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ToolchainError(
            f"{compiler} is not usable: {exc}. This stage needs a C/C++ "
            f"toolchain and binutils (nm, objcopy) on PATH."
        ) from exc
    return proc.stdout.splitlines()[0].strip()


def extract_sources(archive: Path, cases: list[Case], dest: Path) -> None:
    """Unpack the sampled cases and the shared support files.

    Archive-relative paths are preserved: a case's `#include "std_testcase.h"`
    resolves through -I, but the 5x family also includes sibling parts by
    relative path.
    """
    dest.mkdir(parents=True, exist_ok=True)
    wanted = {member for case in cases for member in case.files}
    wanted.update(SUPPORT_MEMBERS)
    with zipfile.ZipFile(archive) as zf:
        present = set(zf.namelist())
        missing = sorted(wanted - present)
        if missing:
            raise ToolchainError(
                f"{len(missing)} manifest file(s) absent from {archive.name}, "
                f"first: {missing[0]}. The manifest was drawn from a different "
                f"archive — regenerate it or restore the original."
            )
        for member in sorted(wanted):
            zf.extract(member, dest)


def _compile(
    compiler: str, sources: list[str], opt: str, variant: BuildVariant,
    work: Path, out: Path,
) -> subprocess.CompletedProcess[str]:
    omit = "-DOMITGOOD" if variant is BuildVariant.BAD else "-DOMITBAD"
    cmd = [
        compiler,
        standard_flag(compiler),
        *COMMON_FLAGS,
        omit,
        opt,
        f"-I{SUPPORT_DIR}",
        *sources,
        *SUPPORT_SOURCES,
        "-o",
        str(out),
    ]
    return subprocess.run(cmd, cwd=work, capture_output=True, text=True, check=False)


def strip_copy(symbolled: Path, stripped: Path) -> None:
    """Produce the model's binary from the oracle's, via objcopy.

    Copy-and-strip rather than a second `-s` link: this way the two builds are
    the same machine code by construction, so a difference between the F2 chunk
    and the ground-truth mapping cannot be a build artefact.
    """
    proc = subprocess.run(
        ["objcopy", "--strip-all", str(symbolled), str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolchainError(f"objcopy failed: {proc.stderr.strip()[:200]}")


def _text_bytes(binary: Path) -> int:
    proc = subprocess.run(
        ["size", "--format=sysv", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == ".text":
            return int(parts[1])
    return 0


def clear_dir(path: Path) -> str | None:
    """Empty a build directory, or explain why it could not be emptied.

    Not fatal when it fails. Windows-backed mounts — `/mnt/c` under WSL, and
    the 9p mounts some sandboxes use — permit creating files but refuse to
    unlink them, and a rebuild that overwrites in place is still correct for
    every case the manifest names. What it cannot do is remove artifacts left
    by a PREVIOUS manifest, so the caller warns rather than continuing quietly.
    """
    if not path.exists():
        return None
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return (
            f"could not clear {path}: {exc.strerror or exc}. Rebuilding in "
            f"place — binaries from an earlier manifest may survive. Point "
            f"--build-dir at a native Linux filesystem to avoid this."
        )
    return None


def relative_path(path: Path, root: Path) -> str:
    """An artifact path relative to the build root.

    Never absolute. A build directory is a local choice — ext4 scratch on one
    machine, `data/processed` on another — and `build-report.json` is
    committed, so an absolute path here would make the record machine-specific
    and defeat the point of committing it. `BuildReport.build_dir` carries the
    root; consumers join the two.
    """
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:  # pragma: no cover - defensive
        return path.name


def build_case(case: Case, work: Path, bin_root: Path, root: Path) -> CaseBuild:
    """Compile, measure and gate one case. Never raises on a compiler error.

    `bin_root` must be absolute: the compiler runs with its working directory
    set to the extracted source tree so that the 5x family's relative includes
    resolve, which makes any relative output path resolve against the wrong
    directory.
    """
    sources = {
        variant: select_sources(case.files, bad=variant is BuildVariant.BAD)
        for variant in BuildVariant
    }
    compiler = compiler_for(sources[BuildVariant.BAD])
    out_dir = bin_root.resolve() / case.case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[BinaryArtifact] = []
    sizes: dict[tuple[BuildVariant, str], tuple[int, int]] = {}

    for variant in BuildVariant:
        for opt in OPTIMISATIONS:
            sym_path = out_dir / f"{variant.value}{opt}.sym"
            proc = _compile(compiler, sources[variant], opt, variant, work, sym_path)
            if proc.returncode != 0:
                return CaseBuild(
                    case_id=case.case_id,
                    language=case.language,
                    status=BuildStatus.COMPILE_FAILED,
                    compiler=compiler,
                    sources=sources[BuildVariant.BAD],
                    error=proc.stderr.strip()[:2000],
                )

            bad_bytes, good_bytes, bad_syms, good_syms = path_sizes(
                sym_path, case.case_id
            )
            sizes[(variant, opt)] = (bad_bytes, good_bytes)
            oracle = bad_syms if variant is BuildVariant.BAD else good_syms

            stripped_path = out_dir / f"{variant.value}{opt}.stripped"
            strip_copy(sym_path, stripped_path)
            for path, is_stripped in ((sym_path, False), (stripped_path, True)):
                artifacts.append(
                    BinaryArtifact(
                        path=relative_path(path, root),
                        variant=variant,
                        optimisation=opt,
                        stripped=is_stripped,
                        sha256=sha256_file(path),
                        text_bytes=_text_bytes(path),
                        # Only the symbol-bearing build carries the mapping.
                        # The stripped twin shares its addresses, so recording
                        # them twice would invite the two copies to disagree.
                        symbols=[] if is_stripped else oracle,
                    )
                )

    bad_o0, _ = sizes[(BuildVariant.BAD, "-O0")]
    bad_o2, _ = sizes[(BuildVariant.BAD, "-O2")]
    _, good_o0 = sizes[(BuildVariant.GOOD, "-O0")]
    _, good_o2 = sizes[(BuildVariant.GOOD, "-O2")]

    if bad_o0 == 0:
        # The case built but the oracle recognised nothing. Either Juliet used a
        # naming convention this module does not know, or the flaw is not in a
        # function at all. Loud, because every downstream F2 label depends on it.
        return CaseBuild(
            case_id=case.case_id,
            language=case.language,
            status=BuildStatus.NO_FLAW_SYMBOLS,
            compiler=compiler,
            sources=sources[BuildVariant.BAD],
            binaries=artifacts,
            error="no bad/badSink/badSource symbol found in the -O0 build",
        )

    bad_retained = retained(bad_o0, bad_o2)
    survived = bad_retained is not None and bad_retained >= SURVIVAL_THRESHOLD
    survival = FlawSurvival(
        bad_o0=bad_o0,
        bad_o2=bad_o2,
        good_o0=good_o0,
        good_o2=good_o2,
        bad_retained=bad_retained,
        good_retained=retained(good_o0, good_o2),
        threshold=SURVIVAL_THRESHOLD,
        survived=survived,
    )
    return CaseBuild(
        case_id=case.case_id,
        language=case.language,
        status=BuildStatus.OK if survived else BuildStatus.ERASED,
        compiler=compiler,
        sources=sources[BuildVariant.BAD],
        binaries=artifacts,
        survival=survival,
    )


def build_corpus(
    manifest: Manifest,
    manifest_path: Path,
    raw_dir: Path,
    out_dir: Path,
    jobs: int | None = None,
    warn: Callable[[str], None] | None = None,
    java: bool = True,
) -> BuildReport:
    """Build every case in the manifest, C/C++ here and Java via `jvm`.

    One report covers both languages. They share almost no build machinery —
    see `jvm` for why — but they are one sample, and splitting the record would
    make it possible to have a corpus where half the strata are stale.
    """
    cases = [c for c in manifest.cases if c.language in (Language.C, Language.CPP)]
    java_cases = [c for c in manifest.cases if c.language is Language.JAVA]
    archive = find_archive(_CCPP_SUITE, raw_dir)

    # Both toolchains are checked before either is used. The Java arm runs
    # last, so without this a missing JDK would be reported only after several
    # minutes of C/C++ compiling had already been done and thrown away.
    compiler_version()
    if java and java_cases:
        from vulnlm.build import jvm

        jvm.javac_version()

    work = (out_dir / "src").resolve()
    bin_root = (out_dir / "bin" / _CCPP_SUITE.key).resolve()
    scrub_root = (out_dir / "src-scrubbed" / _CCPP_SUITE.key).resolve()
    for directory in (work, bin_root, scrub_root):
        if (problem := clear_dir(directory)) is not None and warn is not None:
            warn(problem)

    extract_sources(archive, cases, work)
    bin_root.mkdir(parents=True, exist_ok=True)
    scrub_root.mkdir(parents=True, exist_ok=True)

    # Scrubbing first, and separately. It is not a step of compiling — §4.1
    # builds the C/C++ binaries from UNMODIFIED source, because stripping
    # already anonymises them, so the scrubbed tree exists only to be read at
    # F0. Keeping it out of `build_case` is what lets it cover the cases that
    # fail to compile, which are still valid F0 material.
    records = scrub_corpus(cases, work, scrub_root)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        builds = list(pool.map(lambda c: build_case(c, work, bin_root, out_dir), cases))
    builds = [b.model_copy(update={"scrub": records.get(b.case_id)}) for b in builds]

    java_version: str | None = None
    classpath: list[str] = []
    if java and java_cases:
        # Imported here rather than at module scope: `jvm` imports from this
        # module, and --no-java must not require a JDK to be discoverable.
        from vulnlm.build import jvm

        # `clear_src=False`: both arms extract into one `src/` tree, and the
        # C/C++ half is already there. Clearing again would delete it.
        java_builds, java_version, classpath = jvm.build_java(
            java_cases, raw_dir, out_dir, warn=warn, clear_src=False
        )
        builds.extend(java_builds)

    return BuildReport(
        manifest_sha256=sha256_file(manifest_path),
        build_dir=out_dir.as_posix(),
        compiler_version=compiler_version(),
        java_version=java_version,
        classpath=classpath,
        common_flags=[
            f"-std={C_STANDARD}|{CXX_STANDARD}",
            *COMMON_FLAGS,
            f"-I{SUPPORT_DIR}",
        ],
        optimisations=list(OPTIMISATIONS),
        survival_threshold=SURVIVAL_THRESHOLD,
        cases=sorted(builds, key=lambda b: b.case_id),
    )
