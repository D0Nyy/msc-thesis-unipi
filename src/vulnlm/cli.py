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
def build(data_dir: DataDir = Path("data")) -> None:
    """Prepare the dataset: compile Juliet, write the sample manifest."""
    _todo("build")


@app.command()
def recover(
    data_dir: DataDir = Path("data"),
    tier: Annotated[
        str | None, typer.Option("--tier", help="Restrict to one of F0, F1, F2.")
    ] = None,
) -> None:
    """Stage 1 — decompile, scrub identifiers, chunk. Emits Chunk records."""
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
