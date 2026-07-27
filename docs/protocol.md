# Protocol — Vulnerability Analysis of Binary/Executable Files with LLMs

**MSc Thesis — Cybersecurity & AI Technologies**
University of Piraeus, Department of Digital Systems

| | |
|---|---|
| **Student** | Antonios Kallias |
| **Student ID (AM)** | mte25013 |
| **Supervisor** | Γιαπαντζής Κωνσταντίνος |

---

## 1. Thesis title & one-line summary

**Title:** Vulnerability analysis of binary/executable files with LLMs

A pipeline that reverse-engineers compiled binaries, analyses the recovered
code with LLMs across capability tiers, and emits structured, machine-readable
vulnerability findings — measuring how much **code fidelity lost to
compilation and decompilation** degrades detection.

---

## 2. The assigned brief (verbatim)

> **Θεματική Περιοχή:** Vulnerability assessment, LLM-security, Reverse engineering
>
> **Μεθοδολογία:** Στόχος της εργασίας είναι η ανάλυση ευπαθειών σε εκτελέσιμα
> αρχεία με τη χρήση LLM. Η εργασία επικεντρώνεται στην χρήση αντίστροφης
> μηχανικής με σκοπό την εξαγωγή του πηγαίου κώδικα/ψευδοκώδικα, στην ανάλυσή
> του από LLM και τέλος στην δημιουργία αναφοράς που συνδέεται με τα ευρήματα.
> Επομένως, ο διαχωρισμός γίνεται σε τρία διακριτά στάδια:
>
> - Reverse engineering εκτελέσιμων αρχείων με σκοπό την εξαγωγή του πηγαίου κώδικα.
> - Ανάλυση του παραγόμενου κώδικα με LLM για τον εντοπισμό πιθανών ευπαθειών
>   και αδυναμιών ασφαλείας.
> - Δημιουργία αναφοράς ευρημάτων σε προκαθορισμένο format που συνδέει τα
>   αποτελέσματα της ανάλυσης με τις εντοπισμένες ευπάθειες.
>
> **Αναμενόμενο αποτέλεσμα:** Ανάπτυξη μιας πλήρως λειτουργικής μεθοδολογίας για
> την ανάλυση ευπαθειών σε εκτελέσιμα αρχεία με τη χρήση LLM: εξαγωγή κώδικα
> μέσω reverse engineering, αξιολόγηση του κώδικα από το LLM, και δημιουργία
> δομημένης αναφοράς ευρημάτων σε προκαθορισμένο format. Η αναφορά θα
> παρουσιάζει τις εντοπισμένες ευπάθειες, τη σοβαρότητά τους και τη σύνδεσή τους
> με τα αντίστοιχα τμήματα του κώδικα. Επίσης, τα ευρήματα θα πρέπει να
> περιλαμβάνουν λειτουργικό proof-of-concept κώδικα ώστε να διαπιστωθεί το
> exploitability της ευπάθειας, καθώς και το αντίστοιχο mitigation.

**Supervisor additions:** explore binaries built from **C++, C#, Java, Python**;
compare a small local ~7B model, a medium model, and a flagship API (Claude);
optionally a larger self-hosted model on rented cloud GPU; each model emits
findings in a fixed structured format; **Ollama** recommended for local serving.

---

## 3. Research framing

### 3.1 The analytical lens: code fidelity

The brief mandates *what* to build. The research contribution is *what the build
reveals*: *how much of the original program survives compilation and
decompilation, and how much that loss costs an LLM.*

Fidelity is treated as a first-class independent variable, not noise.

| Tier | Languages | Recovered by | What survives |
|---|---|---|---|
| **F0 — Original source** | C, C++, C#, Java, Python | nothing — source as written | Everything. The **fidelity ceiling / control condition** |
| **F1 — Bytecode-decompiled** | C#, Java, Python | ILSpy, Vineflower, pycdc | Names, types, structure, near-original logic |
| **F2 — Native-decompiled** | C, C++ | Ghidra | Control flow only. No names, no types, no comments |

Every language has an F0. Python has no F2 — there is no native compilation
step to lose anything in — and its F1 sits at the *top* of that band: `.pyc`
decompilation is close to lossless, which is precisely why §5 treats Python as
the trivial case and keeps it qualitative.

> **Design note.** F0 is available for *every* dataset sample in *every*
> language. This is what makes the design work: the fidelity axis can be walked
> **within a single language**, holding the vulnerability, the CWE, and the
> program constant, with only fidelity varying. This is the primary defence
> against the language↔fidelity confound.

Fidelity is also measured **continuously per sample** — identifier recovery
rate, type fidelity, compilability, token count — so results can be reported
against continuous measures, not only a bucket. Combining these into a single
scalar is deferred; the components are recorded individually and any
weighting can be applied later.

### 3.2 Research questions

- **RQ1 (primary).** To what extent does the fidelity of reverse-engineered code
  affect an LLM's ability to detect known vulnerabilities in compiled binaries?
- **RQ2.** Does increasing model capability compensate for reduced fidelity, or
  do all models degrade proportionally? *(interaction effect)*
- **RQ3.** How do detection characteristics differ across the fidelity boundary —
  missed vulnerabilities (recall), false alarms (precision), or wrong-CWE
  misclassification?
- **RQ4.** How closely can self-hosted open-weight models approach flagship API
  performance, and where does the gap widen or narrow? *(privacy / practicality)*

### 3.3 Hypotheses

| # | Hypothesis | Tested by |
|---|---|---|
| **H1** | Detection F1 correlates positively with fidelity across all models | Main effect of fidelity |
| **H2** | The small-vs-flagship gap **widens** as fidelity drops | Fidelity × model interaction |
| **H3** | Low fidelity degrades **precision** more than recall (over-reporting on decompiled native code) | Precision vs recall deltas across tiers |
| **H4** | CWE-classification accuracy degrades **faster** than binary detect/don't | Two nested metrics, same samples |
| **H5** | **Confidence calibration** degrades with fidelity — models become less accurate *and* less aware of it | ECE / reliability diagrams per tier |

---

## 4. Pipeline architecture

```
                  ┌── F0: source as written ───────────┐
                  │   control — never compiled         │
source ─▶ [build] ┤                                    ├─▶ [re] ──▶ chunks.jsonl
                  └── binary ─▶ ghidra · ilspy ────────┘   scrub          │
                                vineflower · pycdc         + chunk        │
                                → F2, F1                                  ▼
                                                                     [analysis]
                                                              constrained JSON,
                                                              schema-enforced
                                                                          │
                                                                          ▼
                                                                   records.jsonl
                                             ┌────────────────────────────┤
                                             ▼                            ▼
                                          [eval]                      [report]
                                   P / R / F1 · CWE acc          SARIF · Markdown
```

`records.jsonl` holds `AnalysisRecord` rows, not findings — a row may carry
`outcome: context_overflow` and no findings at all. `eval` and `report` are
siblings reading the same file; neither feeds the other.

**Stage 2 (normalisation) is not in the brief but is mandatory.** It scrubs
ground-truth-leaking identifiers and assembles chunks, uniformly across all
three tiers. It is presented in the thesis as part of Stage 1 (code recovery),
not as a fourth stage.

### 4.1 Identifier scrubbing

Juliet encodes the answer in its identifiers:

```c
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01_bad()
{
    char * data;
    char dataBadBuffer[10];
```

A model can emit `CWE-121` from the function name alone, without reading any
logic. Crucially this **leaks unevenly across tiers**: Ghidra destroys all names
at F2, while F1 and F0 preserve them intact. Unscrubbed, the headline result
would largely measure removal of the answer key rather than loss of fidelity,
and RQ1 would be invalid.

**Rule — applied uniformly to every tier, F0 included:**

- Functions → `func_<n>`, classes → `Class_<n>`, locals and parameters → `v_<n>`
- Filenames → opaque IDs; comments stripped
- **Standard library and API calls preserved** (`strcpy`, `Runtime.exec`) — a
  human analyst sees these too, so they are signal, not leakage
- Renaming is deterministic; the mapping table is retained out-of-band for
  scoring and never enters a prompt

Scrubbed is the **primary condition**. Re-running a subset unscrubbed gives a
*leakage sensitivity* measurement — how far these models rely on identifier
names versus code semantics — which is reported as a secondary result.

### 4.2 Chunking

A whole program does not fit in a 7B model's context on 8 GB of VRAM, so the
text that goes in each prompt has to be selected. That selection *is* chunking.

One function per prompt fails on Juliet specifically: the suite deliberately
separates where tainted data enters from where it is used, often across files.
Per-function chunks would leave the model looking at a sink with no evidence its
input is attacker-controlled, making those cases undetectable **by
construction** — measuring the chunking policy rather than the model.

**Chunk = target function + transitive intra-sample callees, depth-limited**,
assembled into a single context. The call graph comes from Ghidra at F2 and from
the AST at F0/F1. The policy is identical across tiers, or it becomes a
confound. When an assembled chunk exceeds the model's window, the result is
recorded as `context_overflow` (§8.2) — a real constraint of the 8 GB tier and a
reportable finding, not an error.


## 5. Datasets

- **Primary — NIST Juliet Test Suite (SARD).** Labeled CWE cases in C/C++, C#,
  Java. `good`/`bad` variants give a naturally balanced design: `bad` = positive
  class, `good` = negative class for FPR.
- **Sampling.** Juliet is far too large to run exhaustively across 4 models × 3
  fidelity tiers × repetitions (§6.2). Use a **stratified sample**: N CWE classes
  chosen for cross-language coverage, M cases per class per language, fixed
  random seed, sample manifest committed to the repo.
- **Secondary (optional).** Known-CVE real binaries to test rediscovery on
  non-synthetic code; a small hand-authored set for controlled edge cases.
- **Python.** Juliet has no Python. Python is therefore **out of the
  quantitative comparison** and covered qualitatively — a demonstration that the
  pipeline handles `.pyc` → source, with a discussion of why near-lossless
  recovery makes it the trivial case. This is honest and defensible; forcing
  Python into the statistics with a different dataset would break comparability.

---

## 6. Model tiers

Naming reflects what actually varies: **parameter count** and **open-weight vs
proprietary API**. ("Local" is misleading when the medium and large models run
on rented cloud GPUs.)

### 6.1 The same-family rule

The open-weight ladder uses **one model family, dense variants only, identical
quantization**. This is not a convenience choice — it is what makes RQ4
answerable. If tier S were Qwen, tier M Mistral and tier L Llama, the results
would measure *training recipe*, not *scale*, and no claim about size
compensating for lost fidelity would survive review.

**Mixture-of-Experts models are excluded from the ladder.** An MoE that
activates ~3B parameters per token is not comparable to a dense 32B on a
"parameter count" axis. MoE may appear only as the optional currency check
below, reported separately.

| Tier | Model | Q4_K_M VRAM | Serving |
|---|---|---|---|
| **S — Constrained edge** | Qwen3-Coder-7B-Instruct | ~5 GB | **Local**, RX 6650 XT 8 GB |
| **M — Mid open-weight** | Qwen3-Coder-14B-Instruct | ~9 GB | Rented 24 GB GPU |
| **L — Large open-weight** | Qwen3-Coder-32B-Instruct | ~20 GB | Rented 24 GB GPU |
| **A — Flagship API** | Claude Sonnet 5 (main run) · Claude Opus 5 (subset) | — | Anthropic API |

> **Tag verification required before Phase 2.** Confirm the exact Ollama tags
> for all three dense variants exist and pull cleanly. If any rung is missing,
> the fallback ladder is **Qwen2.5-Coder 7B / 14B / 32B** — older, but a
> complete and fully dense family, which matters more here than raw capability.
> A missing rung breaks the ladder; a slightly dated family does not.

**Rules:**
- Exact model version strings and quantization are **pinned and recorded** in
  every result row. "Qwen3-Coder-7B" is not sufficient provenance.
- **Q4_K_M for every open-weight tier.** Quantization must not co-vary with
  size, or it becomes an uncontrolled confound.
- All models served through an **OpenAI-compatible interface** (Ollama locally
  and in cloud; thin adapter for the Anthropic API) so one code path drives
  every model.
- **Identical prompt, chunking, scrubbing, temperature, and schema across all
  models — no exceptions.** Any per-model prompt tuning invalidates RQ4.
- Temperature `0.0`, `top_p` 1.0, fixed seed where supported.

### 6.2 Repetitions and determinism

**Temperature 0.0 is not a determinism guarantee.** Greedy decoding fixes the
selection rule, not the logits it selects from. Floating-point reduction on GPU
is not associative, so batch composition and kernel scheduling can change the
last bits of a logit and flip a near-tie token; hosted APIs additionally change
underneath you between runs. Repetition establishes empirically whether this
matters here, rather than assuming it either way.

**Policy — measure first, then decide.**

1. **Pilot.** Run `k = 3` on a stratified ~20% subset covering every
   (fidelity tier × model tier) cell.
2. **Decision rule, fixed in advance.** If ≥99% of subset chunks yield an
   identical *detection outcome* across all three runs, treat the configuration
   as deterministic and run `k = 1` for the remainder, reporting the measured
   agreement rate as justification. Otherwise keep `k = 3` throughout.
3. **Report either way.** Run-to-run disagreement rate is a reported metric per
   (model × tier), not a diagnostic that gets discarded. Non-determinism at
   temperature 0 is a finding, not a nuisance.

This is stronger than blanket triplication: it *demonstrates* stability instead
of guarding against instability that may not exist, and it costs roughly a third
of the GPU budget that `k = 3` everywhere would.

**Aggregation — never collapse at write time.** Every run is persisted as its
own `AnalysisRecord` with its own `run_index`. Whether repeated runs are later
majority-voted or treated as separate observations is a question for the
statistical plan, and majority voting in particular changes what is being
measured — an ensemble of three is not the system under test. Collapsing in the
harness would make that choice irreversible; collapsing in `eval` leaves it open.

---

## 7. Toolchain

| Stage | Target | Tool |
|---|---|---|
| RE | C / C++ | Ghidra (headless, scripted) |
| RE | C# | ILSpy (`ilspycmd`) |
| RE | Java | Vineflower |
| RE | Python | `pycdc` for `.pyc` → F1; source as-is → F0 |
| Analysis | all | Ollama (local + cloud) + Anthropic API |
| Reporting | all | Constrained JSON → SARIF 2.1.0 + Markdown |

### 7.1 Build settings

Fixed for the duration of the experiment and recorded in `Provenance` on every
chunk. These are not incidental details — each one silently changes F2 fidelity
if left to drift.

- **Optimisation pinned at `-O2`.** Optimisation is a second fidelity axis
  running alongside the intended one: `-O0` keeps a near one-to-one mapping to
  source, while `-O2` inlines calls, holds variables in registers, unrolls loops
  and deletes dead code. `-O2` is what release binaries actually use, so it
  keeps F2 representative. A small `-O0` subset is run as a sensitivity check —
  it separates how much of "F2 is hard" is decompilation versus optimisation.
  *Note:* inlining at `-O2` can merge callee into caller, partly performing the
  §4.2 chunk assembly in the compiler. Expect it in the results.
- **Dynamic linking required.** Imported libc names survive stripping through
  the PLT; static linking turns `strcpy` into an unnamed blob and destroys the
  API-call signal §4.1 deliberately preserves.
- **`-DOMITGOOD` / `-DOMITBAD`.** Juliet places the flawed and fixed variants in
  one translation unit. Built naively, a single binary contains both and the
  `good`-chunk-as-negative-class accounting collapses. One variant per binary.
- **Build every C/C++ case twice** — once with symbols to derive the
  ground-truth function mapping out-of-band, once stripped for the model. At F2
  there is otherwise no way to know which recovered function holds the flaw.
  `Chunk.stripped` records which build a chunk came from.

---

## 8. Output schema

The LLM emits **constrained JSON only**. SARIF is generated downstream by a
deterministic exporter.

> **Why not have the model emit SARIF directly?** SARIF is verbose and deeply
> nested; a Q4 7B model will fail to produce valid SARIF at an acceptable rate,
> and the token overhead distorts the latency and cost comparison. Emitting
> minimal JSON and converting downstream keeps the model's burden identical
> across tiers — which is what RQ4 requires.

### 8.1 Model output (the thing that gets scored)

The model emits **findings and nothing else**. `chunk_id` is already known to
the harness, and `outcome` is *determined* by the harness — a run that
overflowed its context window cannot report that it overflowed. Both are
attached to the result row afterwards. Keeping them out of the model's schema
removes two fields the 7B tier could get wrong, and schema-compliance rate is
itself a reported metric.

```jsonc
{
  "findings": [
    {
      "cwe_id": "CWE-121",
      "title": "Stack-based buffer overflow in fixed-size copy",
      "severity": "HIGH",   // CRITICAL|HIGH|MEDIUM|LOW|INFO — ordinal, no CVSS
      "confidence": 0.86,   // float 0.0–1.0, self-reported
      "symbol": "func_7",   // primary localisation anchor — tier-neutral
      "evidence": "copy into 64-byte stack buffer with unbounded length",
      "reasoning": "…",
      "mitigation": "…"     // optional; Phase 5
    }
  ]
}
```

- Enforced with `pydantic` + constrained decoding / JSON mode where the backend
  supports it. **2 retries** on invalid output, then `outcome: schema_failure`.

### 8.2 The `outcome` field is mandatory and must not be collapsed

`outcome` is recorded by the harness on every result row (never by the model,
see §8.1). `findings: []` is ambiguous on its own — four distinct situations
produce an empty result set and they **must not share a bucket**:

| `outcome` | Meaning | Effect on metrics |
|---|---|---|
| `analysed` + empty findings | Model read the chunk and reported nothing | TN (on `good`) or FN (on `bad`) |
| `context_overflow` | Chunk exceeded the model's window | Excluded from P/R/F1; **reported as its own rate** |
| `schema_failure` | Unparseable after 2 retries | Excluded from P/R/F1; **reported as its own rate** |
| `api_error` | Transport/quota failure | Excluded entirely; retried later |

Collapsing these inflates the recall denominator and silently converts the small
model's hardware limits into apparent detection failures — which would
misattribute a *context* result to *capability*, breaking RQ4. Context-overflow
rate is expected to be non-trivial at tier S and is a finding in its own right.


### 8.3 SARIF export rules

The exporter is deterministic and adds no information the model did not supply.

- **`logicalLocations` is primary.** `fullyQualifiedName` + `kind: "function"`
  is the only anchor that survives all three fidelity tiers. `physicalLocation`
  / `region` is optional and, at F2, refers to lines of the *recovered artifact*
  — never the original source. Never emit an F2 snippet containing original
  identifiers or original source text; if that happens, the scrubbing pass
  has failed and the run is invalid.
- **`rank` ← `confidence × 100`, and not duplicated** into `properties`.
- **`ruleId` = CWE ID** (e.g. `CWE-121`) with `helpUri` to MITRE. This is a
  deliberate simplification: SARIF models CWE via `taxonomies`/`taxa` with
  `rules` reserved for tool-specific detection rules. The shortcut is common in
  real tools; note the deviation in one sentence in the thesis.
- **`level`** (note/warning/error/none) is display-only. All scoring uses the
  5-point ordinal `severity` in `properties`.
- **`automationDetails.id`** required, formatted
  `<case_id>/<fidelity_tier>/<model>/run-<k>`, so individual runs are addressable.
- **`invocations[]`** with `startTimeUtc` / `endTimeUtc` — captures latency in-band.
- **Model provenance in `tool.driver.properties`** must be complete:
  `qwen3-coder:7b-instruct-q4_K_M` plus the Ollama digest. Not `qwen3-coder:7b`.
- **Tier labels use the F0/F1/F2 glossary** (§3.1). Not `T1`/`T2`/`T3`.

### 8.4 Scoring rules

Fixed **before any run**, because the matching rule determines the headline
numbers and must not be chosen after seeing them. Line numbers do not survive
decompilation, so matching has to be tier-neutral.

**Primary — detection.** Binary, per chunk:

| Chunk | Model reported ≥1 finding | Model reported nothing |
|---|---|---|
| `bad` (contains the flaw) | TP | FN |
| `good` (fixed variant) | FP | TN |

Not line-level, not per-finding. A model that reports three spurious CWEs in a
`bad` chunk still scores one TP; precision is protected by the `good` chunks.

**Secondary — CWE classification.** Of the TPs only, scored at three levels:
exact ID match, same CWE parent or pillar (via the MITRE hierarchy), unrelated.
Requires a MITRE hierarchy export in `data/`; the CWE list is never
hand-maintained.

**Tertiary — localisation.** Does the reported `symbol` fall inside the mapped
sink region? Reported for F0/F1 only; **not defined at F2**, where recovered
function boundaries need not correspond to source ones.

**Evidence groundedness.** `evidence` must be a verbatim quote from the chunk;
`eval` checks it is a literal substring. The failure rate is reported per tier —
a cheap, objective hallucination measure, expected to worsen at F2.

**Exclusions.** `context_overflow` and `schema_failure` are excluded from
P/R/F1 and reported as their own rates. `api_error` is excluded entirely and
retried. None of these is ever scored as "found nothing" (§8.2).

---

## 9. Roadmap

| Phase | Milestone | Est. |
|---|---|---|
| **0** | Scoping & setup — lock RQs, environment, build Juliet, commit sample manifest | 2–3 wks |
| **1** | RE / recovery pipeline (all targets → normalised, scrubbed, chunked) | 3–4 wks |
| **2** | LLM analysis engine (model abstraction, schema enforcement, `--resume`) | 3 wks |
| **3** | Scoring harness (P/R/F1 per model × tier, baselines). Statistical plan TBD | 3 wks |
| **4** | **Base tool complete → README → supervisor checkpoint** | — |
| **5** | PoC + mitigation module (supervisor-guided, isolated VM, optional/pluggable) | 3 wks |
| **6** | Writing (continuous from Phase 0) | — |

**Phase 5 scope note.** Automatically generating working exploits for the full
sample is neither feasible nor informative — Juliet sinks are synthetic. Scope
Phase 5 to a **small hand-picked subset (~5–10 cases)** demonstrating that the
pipeline *can* produce a verified PoC and a mitigation, evaluated against a
rubric rather than automatically at scale. This satisfies the brief's PoC
requirement without inflating the experiment.

---

## 10. Environment

**Hardware:** Ryzen 5 5600X · 16 GB RAM · Radeon RX 6650 XT (8 GB, gfx1032).

## 11. Scope & ethics

- Fully aligned with the assigned brief: RE extraction → LLM analysis →
  structured reporting. Fidelity is the analytical lens, not added scope.
- All quantitative experiments use **labeled academic research datasets**
  (NIST Juliet/SARD, published for exactly this purpose) or self-authored
  samples.
- Proof-of-concept generation is a **later, supervisor-guided, optional module**,
  executed only in a network-isolated VM, and only to verify exploitability of
  vulnerabilities in the researcher's own test artifacts.
- No third-party production systems are tested. If secondary CVE work involves
  real-world software, only **already-public, already-patched** CVEs are used,
  and no new vulnerability disclosures arise from this work. Should an unknown
  issue surface incidentally, it is handled through coordinated disclosure with
  the supervisor.
- No personal data is processed. Dataset artifacts and derived results are
  redistributable under their original licences.
- The deliverable is a **defensive analysis tool**: it identifies weaknesses and
  proposes mitigations.
