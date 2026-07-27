# Vulnerability Analysis of Binary/Executable Files with LLMs

**MSc Thesis — University of Piraeus, Department of Digital Systems**
Cybersecurity & AI Technologies · Antonios Kallias (mte25013)

A pipeline that reverse-engineers compiled binaries, analyses the recovered code
with LLMs across capability tiers, and emits structured, machine-readable
vulnerability findings — measuring how much code fidelity lost to compilation and
decompilation degrades detection.

> **The methodology, experimental design and open questions live in [`docs/protocol.md`](docs/protocol.md).** Read that first. This file
> only covers installation and usage.

## Install

Requires Python 3.13 and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env    # then fill in API keys / hosts
```

External tools (not installed by `uv`): Ghidra (headless), `ilspycmd`,
Vineflower, `pycdc`, Ollama. See §7 (Toolchain) and §10 (Environment) of the protocol.

## Usage

```bash
uv run vulnlm --help
```

| Command | Module | Does |
|---|---|---|
| `vulnlm build` | `build/` | compile Juliet, write the sample manifest |
| `vulnlm recover` | `re/` | decompile, scrub, chunk → `chunks.jsonl` |
| `vulnlm analyze` | `analysis/` | run the model tiers → `results/raw/` |
| `vulnlm report` | `report/` | records → SARIF 2.1.0 + Markdown |
| `vulnlm eval` | `eval/` | score against ground truth → `results/metrics/` |

The middle three are the brief's three mandated stages (protocol §2).

## Layout

```
docs/         protocol, thesis document, exported figures
prompts/      versioned prompt templates (hash recorded in every run)
src/vulnlm/   build/ · re/ · analysis/ · report/ · eval/ · schema.py
data/         raw/ untouched datasets · processed/ derived artifacts (gitignored)
results/      raw/ model output JSONL · metrics/ computed scores (gitignored)
```

`data/manifest.json` is committed even though the rest of `data/` is ignored —
it is what makes the sample reproducible.

## Scope

Defensive security research on labeled academic datasets (NIST Juliet/SARD) and
self-authored artifacts. Proof-of-concept work is scoped to protocol §9 Phase 5
and runs only in an isolated VM. See §11.
