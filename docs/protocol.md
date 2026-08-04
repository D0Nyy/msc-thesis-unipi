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

### 4.0 Two modes: the tool, and the experiment that validates it

The brief asks for a **working methodology** — RE extraction, LLM analysis,
structured report with PoC and mitigation — not merely a benchmark number. The
pipeline is therefore built to run on any binary, and the Juliet machinery is
scaffolding whose job is to prove that it works.

| Stage | Analysis mode (any binary) | Benchmark mode (Juliet) |
|---|---|---|
| `build` | not used | compiles the suite, writes the sample manifest |
| `re` | ✔ | ✔ |
| `analysis` | ✔ | ✔ |
| `report` | ✔ | ✔ |
| `eval` | not possible — no labels | ✔ |

**`re → analysis → report` is the deliverable.** `build` and `eval` exist to
measure it. This is why `analysis` must never import `GroundTruth` (§8) — that
rule is not only about leakage, it is what keeps the analysis path runnable
when no label exists at all.

Three things differ in analysis mode, and each is a *narrowing* rather than a
new code path:

- **No F0.** Without source there is no control condition, so fidelity is
  whatever the binary gives: F2 for native, F1 for bytecode. The fidelity tier
  is recorded exactly as in benchmark mode; only the comparison is unavailable.
- **No ground truth.** `Chunk.ground_truth` is `None`. It is optional rather
  than default-constructed on purpose: `vulnerable=False` on an unlabelled
  chunk is indistinguishable from a true negative and would silently enter
  `eval`'s recall denominator. `eval` skips unlabelled chunks.
- **Scrubbing is a no-op, not a bug.** §4.1 exists to destroy Juliet's
  answer-key identifiers. A stripped real binary has no such names — Ghidra
  already emits `FUN_00401000` — so the pass runs and finds nothing to rename.
  On an *unstripped* real binary it still applies, and there it is a genuine
  question whether to scrub: real symbol names are legitimate evidence a human
  analyst would also see. Default is not to scrub in analysis mode.

Everything downstream — chunking, the constrained-JSON schema, SARIF export,
PoC and mitigation — is identical in both modes.

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

**Rule — one transform, applied wherever names exist:**

- Functions → `func_<n>`, classes → `Class_<n>`, locals and parameters → `v_<n>`
- Filenames and packages → opaque IDs; comments stripped
- **Standard library and API calls preserved** (`strcpy`, `Runtime.exec`) — a
  human analyst sees these too, so they are signal, not leakage
- **Juliet's own support surface is NOT preserved.** `printLine`,
  `globalReturnsTrue`, `ALLOCA`, `AbstractTestCase` are not stdlib; they are
  this benchmark's furniture, and leaving them in keeps the corpus
  recognisable, which defeats §11.1. Enumerated in `build/scaffolding.py`,
  derived from the archives and re-derived by a test so it cannot drift.
- Renaming is deterministic; the mapping table is retained out-of-band for
  scoring and never enters a prompt

**Where it is applied differs by language, because what leaks differs.** The
earlier "uniformly to every tier" phrasing was wrong in a way worth stating: it
implied scrubbing Ghidra's output, which is both unnecessary and risky.

| Artifact | Scrubbed | Why |
|---|---|---|
| C/C++ source → F0 | yes, at build time | `..._bad()`, `namespace CWE121_...`, `dataBadBuffer` are the answer key |
| C/C++ stripped binary → F2 | **no** | `objcopy --strip-all` already removed every name. Scrubbing would be a no-op on input that is often not valid C |
| Java source → F0, and via javac → F1 | yes, **before compiling** | names are structural in the class file and survive javac and Vineflower. There is no `strip` for bytecode, so pre-compilation is the only point at which the leak can be closed |

The scrubbing *procedure* is one function; only its point of application moves.
At F2 there is nothing left to scrub, which is a stronger guarantee than
scrubbing would be — it is checkable with `nm`, and a scrubber that changes
anything at F2 indicates the binary was not stripped properly.

**All scrubbing happens in `build`; `recover` never scrubs.** Both callers are
build-time — Java before javac, C/C++ source for the F0 condition — so `build`
emits two source trees, scrubbed and original, and `recover` simply reads
whichever the run calls for. That leaves the recovery pipeline with no
dataset-specific behaviour at all.

Two consequences worth recording. The C/C++ *binaries* are built from
unmodified source, since F2 gets its anonymity from stripping; that keeps the
§7.1 symbol oracle matching on Juliet's own names rather than through a scrub
mapping, and halves the artifact count. And the unscrubbed sensitivity
condition for C/C++ is free — it is the original tree, already on disk.

**Scrubbing is an experimental control, not a pipeline stage.** In analysis
mode (§4.0) — an arbitrary binary handed to the tool — there is no answer key
to hide, and scrubbing would destroy the meaningful identifiers a real analyst
depends on. Analysis mode never invokes it. Both the mechanism
(`build/scrub.py`) and the Juliet denylist (`build/scaffolding.py`) therefore
sit with the dataset code, not in the pipeline the tool shares with real
targets.

Scrubbed is the **primary condition**. Re-running a subset unscrubbed gives a
*leakage sensitivity* measurement — how far these models rely on identifier
names versus code semantics — which is reported as a secondary result. For
C/C++ that subset is free (scrub the F0 text or don't); for Java it requires a
second build, since the condition is baked in at compile time.

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

### 5.1 Language scope: C/C++ and Java

**C# is deferred, not dropped.** The quantitative comparison runs on C/C++ and
Java only.

The deciding argument is that this is the *minimum set that spans the entire
fidelity axis*. C/C++ is the only source of F2 — native decompilation is the
whole reason the research question exists. Java supplies F1. Both supply F0.
Adding C# supplies a second F1 and **no new tier**, so it buys breadth on the
axis that is not under study while costing a third decompiler, a third build
toolchain, a third tree-sitter grammar and a third validation pass. Every
language multiplies work across `build`, `re`, scrubbing and `eval`
simultaneously; at Phase 1 that multiplier is the difference between reaching
the Phase 4 checkpoint and not.

Secondary reasons: Ghidra and Vineflower are the two most mature and most
studied recovery paths, so tooling failures are likelier to be *our* bugs than
theirs; and the comparable literature is overwhelmingly C/C++ (VulBinLLM,
BinMetric, REBench) with Java second (Vul4J), while C# has almost no prior work
to situate a result against.

**The cost, stated plainly.** With one F1 language and one F2 language, the
F1-versus-F2 contrast is perfectly confounded with language. This does not
damage RQ1 — §3.1's defence was always the *within-language* walk (F0→F1 for
Java, F0→F2 for C/C++), which is untouched. What is lost is a robustness check:
with two F1 languages we could ask whether F1 behaviour is a property of the
fidelity tier or of the language, and with one we cannot. Any cross-tier claim
must therefore be phrased as within-language degradation, never as a bare
"F1 beats F2".

**Re-adding C# is cheap by construction.** The suite uses the same generator
and the same naming convention, `build/juliet.py` already parses it,
`ilspycmd` is a single command, and the manifest is regenerated rather than
edited. If Phase 3 finishes ahead of schedule, C# is the first extension —
precisely because it restores the robustness check above.
- **Sampling.** Juliet is far too large to run exhaustively across 4 models × 3
  fidelity tiers × repetitions (§6.2). Use a **stratified sample** with a fixed
  random seed and the manifest committed to the repo. Structure in §5.2.

### 5.2 Sample structure

A stratum is **CWE × language × flow group**. Two things forced the shape.

**Memory-safety CWEs do not exist outside C/C++.** Of the 59 CWEs present in
both suites, *zero* are buffer overflows, use-after-free, double-free or memory
leaks — Java and C# are memory-safe by construction, so those flaw classes have
no counterpart there. That is inconvenient, because memory safety is what
binary vulnerability analysis is principally about and where Ghidra's loss of
types and bounds information should hurt most. The flaws most relevant to RQ1
are therefore exactly the ones with no cross-language comparison available.

The same is true in reverse. Juliet's C/C++ suite models systems programming —
libc, sockets, filesystem — so **SQL injection, XSS, XPath injection and unsafe
reflection have no C/C++ cases at all** (CWE-89: 0 in C/C++, 2,220 in Java).
Evaluating Java only on CWEs that happen to also exist in C would be a strange
sample of "Java vulnerabilities", containing no injection classes a Java
developer would recognise.

The sample is consequently **three strata, each answering the question it can**:

| Stratum | Languages | CWEs | Answers |
|---|---|---|---|
| **A — cross-language** | C/C++, Java | shared and sampleable | the language comparison |
| **B — memory safety** | C/C++ only | buffer overflow, UAF, double free, leak | the F0→F2 fidelity walk, on the flaws that matter most for binaries |
| **C — web injection** | Java only | SQLi, XSS, XPath, HTTP splitting, reflection | model capability on realistic Java flaws (RQ4, external validity) |

Results are reported per stratum and **never pooled**: pooling would let a
single-language arm masquerade as a cross-language finding.

**Stratum C does not inform RQ1.** Java's walk is F0→F1, which is near-lossless,
so varying fidelity there measures little. It exists for external validity and
RQ4, and is excluded from the fidelity analysis by construction.

> **Deserialization is not available.** CWE-502, and generic XSS (CWE-79), are
> absent from *both* suites — Juliet 1.3 does not model them. If they are wanted
> later the source is Vul4J (79 reproducible Java CVEs with proof-of-vulnerability
> tests), not Juliet.

**Flow groups are `baseline` and `cross_file`.** Rather than sampling the flow
variants proportionally, take the two ends of the complexity axis:

- **`baseline`** — flow variant `01`, the flaw in its simplest form.
- **`cross_file`** — variants `22`, `51`–`54`, `61`–`68`, `71`–`75`, `81`–`84`,
  where source and sink live in different files.

The second group is not decoration. It is the only part of the suite that tests
whether §4.2's chunk assembly works: a chunk holding only the sink has no
evidence its input is attacker-controlled, so those cases are undetectable by
construction if callees are not pulled in. Sampling only `01` would leave the
central design decision of Stage 1 unexercised. Two discrete groups also report
more cleanly than a 47-value continuum.

**Exclusions, applied before drawing:**

- **CWE-506 and CWE-510** — Appendix D of the User Guide lists them as having no
  `good` variant. With no negative class they cannot contribute to precision or
  FPR (§8.4), and including them silently biases precision upward.
- **Win32-only functional variants** — 9,395 C/C++ files use the Win32 API and
  will not build with gcc. Admitting them would mean two compilers in one
  sample, making the compiler a confound on top of the fidelity axis.

**Strata are keyed on suite, not language.** Juliet writes a functional variant
in either `.c` or `.cpp` depending on whether it needs C++ features, so
stratifying on `Language` fragments cells that are one arm for the fidelity
question — CWE-23 has only `.cpp` cases, CWE-78 has no `.cpp` baseline. Each
`Case` still records its own precise language for provenance.

Every stratum records `requested`, `selected` and `available`, and **is emitted
even when empty**. A cell the design assumes exists but the dataset cannot fill
is the single most important line on the report; skipping it would make the
hole invisible.

### 5.3 CWE selection

Chosen from data, not intuition. Of the 59 shared CWEs, only **14 are
sampleable** — every (suite × flow group) cell non-empty after the exclusions.
Most plausible-sounding picks are unbalanced by construction, and the failure is
usually Win32: CWE-15, CWE-90 (LDAP injection) and CWE-327 all *look* shared but
have zero eligible C/C++ cases because 100% of theirs use Windows APIs.
`build --survey` reports `sampleable_cwes` alongside `shared_cwes` for exactly
this reason.

| Stratum A — cross-language | Class | Smallest cell |
|---|---|---|
| CWE-78 | OS command injection — taint to external process | 12 |
| CWE-23 | Relative path traversal — taint to filesystem | 12 |
| CWE-134 | Uncontrolled format string — taint to formatter | 18 |
| CWE-190 | Integer overflow — numeric | 90 |
| CWE-369 | Divide by zero — numeric, different failure mode | 18 |
| CWE-789 | Uncontrolled memory allocation — resource exhaustion | 20 |

| Stratum B — memory safety (C/C++) | Smallest cell |
|---|---|
| CWE-121 Stack-based buffer overflow | 118 |
| CWE-122 Heap-based buffer overflow | 126 |
| CWE-401 Memory leak | 42 |
| CWE-415 Double free | 22 |
| CWE-416 Use after free | 22 |

| Stratum C — web injection (Java) | Smallest cell |
|---|---|
| CWE-89 SQL injection | 60 |
| CWE-80 Cross-site scripting | 18 |
| CWE-113 HTTP response splitting | 36 |
| CWE-643 XPath injection | 12 |
| CWE-470 Unsafe reflection | 12 |

The smallest cell caps how far `--per-stratum` can usefully be raised: at
`n = 12` every cell is still full, beyond that CWE-78 and CWE-23 start to
short.

> **Crypto and hardcoded credentials had to be dropped.** CWE-327 (broken
> crypto) and CWE-259 (hardcoded password) were the obvious picks for a
> security thesis. **100% of their C/C++ cases are Win32-only** — all 54 and
> all 96 respectively use `CryptGenRandom`, `LogonUser` and similar. Excluding
> Win32 to keep a single compiler therefore leaves them with no C/C++ arm at
> all, and they would have appeared as Java-only strata masquerading as
> cross-language ones. Worth stating in the thesis: the Win32 exclusion is not
> cost-free, and it removes two entire weakness classes from the C/C++ side.
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
| **S — Constrained edge** | Qwen2.5-Coder-7B-Instruct | 4.7 GB | **Local**, RX 6650 XT 8 GB |
| **M — Mid open-weight** | Qwen2.5-Coder-14B-Instruct | 9.0 GB | Rented 24 GB GPU |
| **L — Large open-weight** | Qwen2.5-Coder-32B-Instruct | 20 GB | Rented 24 GB GPU |
| **A — Flagship API** | Claude Sonnet 5 (main run) · Claude Opus 5 (subset) | — | Anthropic API |

> **Why Qwen2.5-Coder and not Qwen3-Coder** (verified against the Ollama
> registry, 2026-07-27). Qwen3-Coder publishes only `30b-a3b` and `480b-a35b` —
> both Mixture-of-Experts, and therefore both excluded by the no-MoE rule above.
> There is no dense Qwen3-Coder rung at *any* size, so this is not a case of one
> missing rung: the family cannot furnish a dense ladder at all. Qwen2.5-Coder
> is complete and fully dense at 7B / 14B / 32B under a single quantization,
> which is what RQ4 requires. A generation-older family is the cheaper price;
> the alternative would be either an MoE-vs-dense comparison or a mixed-family
> one, and both measure something other than scale.
>
> Two consequences worth recording. First, the **context window is 32K on every
> rung** — Qwen3-Coder's 256K does not apply, so `context_overflow` (§8.2) is a
> live constraint at tier S rather than a theoretical one. Second, Ollama
> publishes **no `32b-instruct-q4_K_M` tag**: the bare `qwen2.5-coder:32b` is
> the instruct build at Q4_K_M size, distinguishable from `32b-base` only by
> digest. The L rung is therefore pinned by digest, not by tag string.

**Rules:**
- Exact model version strings, quantization **and Ollama digest** are **pinned
  and recorded** in every result row. "Qwen2.5-Coder-7B" is not sufficient
  provenance, and at the L rung the tag string alone is actively misleading.
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

  **Measured, gcc 15.2.0 (Ubuntu 26.04), all 41 buildable C/C++ cases in the
  sample:**

  | | |
  |---|---|
  | Flaw body **erased** by `-O2` | **4 / 41 (10%)** |
  | Median bad-path code retained at `-O2` | 74% |
  | Median good-path code retained at `-O2` | 72% |
  | *Grew* at `-O2` (inlining) | 5 / 41, up to 315% |

  The inlining prediction above is confirmed rather than anticipated: five
  cases grow, one to more than three times its `-O0` size, because `-O2` pulls
  the sink into the source and one function absorbs another.

  > **These numbers move with the compiler, and that is itself a result.** The
  > same measurement on gcc 11.4 gives 3 / 43 erased, median bad 69% and median
  > good 84%. The erasure rate is therefore a property of the *toolchain*, not
  > of Juliet, and any comparison against published F2 results that used a
  > different compiler inherits that variance. gcc 15.2 is the version of
  > record here because it is what Ubuntu 26.04 ships;
  > `BuildReport.compiler_version` pins every corpus to the compiler that built
  > it, so a future disagreement is traceable rather than mysterious.
  >
  > One figure from the 11.4 run is *not* carried over: "lost all dangerous API
  > imports, 2 / 43". `build` does not measure import survival, so that number
  > has not been reproduced and should not be cited until it is.

- **Gate on flaw survival.** In the erased 7%, the compiler proved the result a
  constant and deleted the vulnerability outright — one case reduced to
  `xor %edi,%edi; jmp printIntLine`. Ghidra then decompiles a function with no
  flaw in it, and the model is scored against a bug that is not there. These are
  guaranteed false negatives that would depress F2 recall and be misattributed
  to the model.

  So `build` compiles each case at both `-O0` and `-O2`, sums the sizes of the
  bad-path functions (`bad`, `badSink`, `badSource`, demangled — C++ cases
  namespace them as `CWE415_...::bad()` rather than suffixing `_bad`), and
  **flags any case retaining under 15%**. Flagged cases are excluded from the
  F2 arm and reported as their own rate, never silently dropped.

  **Size is a proxy, and its error rate is measured rather than assumed.**
  Disassembling the `-O2` bad path of all 43 buildable cases (gcc 11.4) finds
  four with the flaw genuinely deleted; the gate catches three. Precision is
  perfect — every excluded case is confirmed erased at the instruction level —
  but recall is 3/4: a leaked `new[]` in CWE-401 retains 22% of its bytes while
  containing no allocation, because C++14 permits eliding unused allocations.
  The reported erasure rate is therefore a **lower bound**, and a per-CWE
  semantic check is needed alongside the ratio before it can be quoted as
  exact. Threshold and method are recorded per case so the number can be
  recomputed rather than re-measured.

  Implemented in `build/compile.py`; `vulnlm build --compile` writes
  `data/build-report.json`, which carries the per-case sizes, the gate outcome,
  the oracle's symbol names and the exact compiler and flags used. That file is
  deliberately separate from `manifest.json`: a manifest is a sample and must
  stay reproducible from a seed alone, whereas a build is a sample *plus* a
  toolchain, and the toolchain changes far more often. Folding them would make
  every compiler upgrade look like a resampling.

  **The good side is measured too, and the asymmetry is small and unstable.**
  The concern was that `goodG2B` — which replaces the tainted source with a
  constant — would be markedly more foldable than `bad`, collapsing the
  negative class and flattering the F2 false-positive rate. On gcc 15.2 the two
  sides are close to level: median 74% bad against 72% good, with the good side
  marginally the more optimised. On gcc 11.4 the gap ran the other way and was
  wider (69% against 84%).

  The honest reading is that neither direction is a stable property of the
  corpus, so no exclusion rule is justified on this evidence and none is
  applied. What the measurement does establish is the weaker, useful claim: the
  negative class does not systematically collapse, so `good` chunks are not
  trivially separable from `bad` ones by size alone. `FlawSurvival` records
  both sides on every case so the question can be revisited against whatever
  compiler the final run uses.
- **Dynamic linking required.** Imported libc names survive stripping through
  the PLT; static linking turns `strcpy` into an unnamed blob and destroys the
  API-call signal §4.1 deliberately preserves.
- **`-DOMITGOOD` / `-DOMITBAD`, and select files by variant as well.** Juliet
  places the flawed and fixed variants in one translation unit. Built naively, a
  single binary contains both and the `good`-chunk-as-negative-class accounting
  collapses. One variant per binary.

  The preprocessor is not sufficient on its own. 4,323 cases state the variant
  in the *filename* instead (`..._81_bad.cpp` beside `..._81_goodG2B.cpp`). For
  the 81–84 family those files sit wholly inside `#ifndef OMITBAD`, so the flag
  empties them and the flag alone would do. For the 23 flow-01 `good1` cases it
  does not: each variant file carries its own `main()` *outside* the guard, so
  compiling the pair yields two `main` symbols and the link fails. `build`
  therefore partitions a case's files by `ParsedName.variant` — bad-side gets
  `bad` plus the unmarked shared parts, good-side gets `good*` plus the same
  shared parts — and applies the `-D` flag on top. Correct for both families,
  so it is unconditional rather than special-cased by flow.

- **Language standard pinned: `-std=gnu11` for C, `-std=gnu++14` for C++.** Not
  a detail. gcc's default has moved from `gnu17` (gcc 11) to `gnu23` (gcc 15),
  and the newer default rejects implicit declarations that Juliet 1.3 relies
  on. Left unpinned, the set of buildable cases — and therefore the realised
  sample — becomes a function of which Ubuntu the build happened to run on.

  The pin does not absorb everything. gcc 14 promoted
  `-Wincompatible-pointer-types` to an error *independently of `-std`*, and
  three cases fail on gcc 15 that compiled on gcc 11: two CWE-78
  (`popen(wchar_t *)`, `execl(wchar_t *)`) and one CWE-23
  (`getenv` into a `wchar_t *`). These are not toolchain pedantry — Juliet's
  `#else` branch for POSIX is simply wrong, and the binary gcc 11 produced
  would have passed a wide pointer to a narrow-char API rather than exercising
  the intended flaw. They are left failing and reported as unbuildable, not
  forced through with `-fpermissive`: a case that does not exercise its own
  flaw is worse than a missing case, because it would be scored as one the
  model failed to find.

- **`-U_FORTIFY_SOURCE`.** Ubuntu's gcc enables `_FORTIFY_SOURCE=2` at `-O1` and
  above but not at `-O0`. Left alone, the `-O0`/`-O2` pair would therefore
  differ in *libc API surface* as well as optimisation: `printf` becomes
  `__printf_chk`, `memcpy` becomes `__memcpy_chk`. Since §4.1 treats imported
  API names as signal and the `-O0` subset exists precisely to isolate
  optimisation, the fortification is disabled so the contrast stays clean. This
  trades a little distro realism for interpretability, and is the one build
  setting where the choice runs against "`-O2` is what release binaries use".

- **Not position-independent (`-no-pie`).** A fixed load address keeps Ghidra's
  addresses stable across cases and comparable in write-ups. Real binaries are
  PIE; the same trade as above, at lower stakes.
- **`-DINCLUDEMAIN`, and ignore the shared `main.cpp`.** Juliet supports two
  build modes. The 350 `main.cpp` / `main_linux.cpp` files call dozens of cases
  into one application — that is the mode for testing *source* analysers over a
  whole tree, and it is not ours. Each case instead carries its own `main()`
  behind `#ifdef INCLUDEMAIN`, which the suite documents as the mode "for
  building a binary to use in testing binary analysis tools". Compile a case's
  files together with `-DINCLUDEMAIN`; without it the case has no entry point
  and will not link. Verified: 64,122 case files carry one, always on the
  single-file part or the `a` part of a multi-file case — exactly one entry
  point per case.
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
  `qwen2.5-coder:7b-instruct-q4_K_M` plus the Ollama digest. Not
  `qwen2.5-coder:7b`.
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

**Local GPU serving caveat.** gfx1032 is not on ROCm's officially supported
target list, so Ollama requires `HSA_OVERRIDE_GFX_VERSION=10.3.0` to map the
card onto gfx1030 (RDNA 2, binary-compatible for this purpose). A SIGSEGV
regression affecting gfx1031/gfx1032 is reported on ROCm 6.4.3 and later, with
6.4.1 as the working version. The ROCm version in use is recorded alongside the
build settings, because it determines whether tier S ran on GPU at all — a
silent CPU fallback would make tier-S latency incomparable to M and L.

## 11. Threats to validity

Each threat below is paired with either a mitigation already in the design or a
measurement that converts it from a caveat into a number. Threats with neither
are stated plainly as limits on what the results can claim.

### 11.1 Training-data contamination (the most serious)

Juliet has been public since 2010, v1.3 since 2017, mirrored widely on GitHub
and used in hundreds of papers. **It is almost certainly in the training data of
every model on the ladder, including the flagship.** Three mechanisms, in
increasing difficulty of exclusion:

| Mechanism | Status |
|---|---|
| **Filename recall** — `CWE121_..._bad.c` states the answer | Eliminated by §4.1 scrubbing |
| **Scaffolding fingerprints** — `printLine()`, `globalReturnsTrue()`, `CHAR_ARRAY_SIZE`, the `do {...} while(0)` idiom identify the corpus without the filename | Must be scrubbed. These are Juliet support symbols, **not** standard library, so §4.1's "preserve stdlib and API calls" rule must not admit them. Verify the allowlist. |
| **Body memorisation** — the model has seen the file | Not eliminable. Measured by §11.2. |

**The asymmetry is what threatens RQ1.** Contamination inflates F0 far more than
F2: the original source is in the training data, Ghidra's decompilation of it
almost certainly is not. Memorisation would therefore make F0 look artificially
strong and **exaggerate the F0→F2 drop, which is the headline result**.

**It also threatens H2.** Larger models memorise more. If the flagship's F0
advantage is partly recall, the "capability gap widens as fidelity falls"
interaction is partly an artefact of the flagship having more to lose.

**What the design already mitigates, and it is more than it first appears.**
Juliet's `good` and `bad` variants are near-identical code sharing a filename
stem. Recalling "this case is CWE-121" does not reveal *which variant* is in
front of you. Since the primary metric is per-chunk detection scored against
both variants (§8.4), filename-level memorisation earns nothing — the model
would have to have memorised the variant, a far stronger claim.

### 11.2 Perturbation probe — measuring contamination

Take a stratified subset and apply **semantics-preserving rewrites**: change
buffer sizes, swap `char` for `wchar_t`, reorder independent statements, rename
the Juliet support functions, alter literal values. Re-run and compare.

- Detection holds → the result reflects analysis.
- Detection drops sharply → memorisation was carrying part of it, and the drop
  size is the estimate of how much.

Cheap, runs on the pilot, and turns the largest threat into a reported
quantity rather than a paragraph of hedging. Hand-authored cases (§5) serve the
same purpose from the other direction: they are guaranteed uncontaminated.

### 11.3 Synthetic data

Juliet cases are generated, small, single-purpose, and contain exactly one
seeded flaw in a program that does nothing else. Real code is large, has many
interacting concerns, and its bugs are not templated. **Results transfer to
real binaries only as an upper bound.** The secondary ARVO/Vul4J track (§5)
exists to probe this; it is not a substitute for it.

### 11.4 Base-rate shift at deployment

Juliet is roughly balanced — about half of all chunks contain a flaw. A real
binary may hold one vulnerability per several hundred functions. Precision
collapses under that shift by arithmetic alone, with no change in the model: a
detector at 80% precision on balanced data can fall below 10% at a 1:100 base
rate. **Reported precision is not a deployment estimate**, and the thesis must
say so wherever a precision figure appears.

### 11.5 Toolchain monoculture

One compiler, one optimisation level (`-O2`, with an `-O0` subset), one
decompiler per language, one architecture. Every result is conditional on that
stack. The `-O0` sensitivity check (§7.1) partially separates decompilation
loss from optimisation loss, but architecture and decompiler remain fixed.
REBench (x86/x64/ARM/MIPS, O0–O3) is the natural extension if scope allows.

### 11.6 Model drift

Open-weight rungs are pinned by digest and are stable. **The flagship API is
not** — the model behind `claude-sonnet-5` can change without notice, so
tier A results are reproducible only in the weaker sense of "same tag, later
date". Record run dates; treat a re-run months later as a new observation, not
a replication. This is a further argument against putting Ollama cloud models
in the ladder (§6.1), where retirement makes it worse still.

### 11.7 Chunking as a confound

The chunk assembly policy (§4.2) determines what the model can possibly see,
so every result is a joint measurement of the model and the policy. The policy
is held identical across all tiers and models, which makes *comparisons* valid,
but absolute detection rates would move under a different policy. Reported
`context_overflow` rates (§8.2) are the visible edge of this.

## 12. Scope & ethics

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
