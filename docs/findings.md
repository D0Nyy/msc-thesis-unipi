# Findings

Observations worth reporting, kept apart from the two files either side of it:
`protocol.md` records decisions that are settled, `todo.md` records questions
that are open. This file records things that turned out to be *true* and that
the write-up should say.

Each entry states what was measured, on what, and what it does and does not
license as a claim. Anything not yet measured is marked as such — an entry here
is meant to be citable.

---

## F1. The compiler is a semantic actor in the pipeline

**Measured.** gcc 11.4 and 15.2, `-O2`, all 43/41 buildable C/C++ cases in the
committed sample. Verified at the instruction level by disassembly, not
inferred from code size.

Four cases have their vulnerability **removed outright** by optimisation:

| CWE | flaw at `-O0` | what `-O2` leaves |
|---|---|---|
| CWE-121 | stack overflow via `memmove` | `xor %edi,%edi ; jmp printIntLine` |
| CWE-369 | divide by zero | a bare `ud2` |
| CWE-415 | double free | an empty `ret` |
| CWE-401 | leaked `new[]` | `mov $0x5 ; jmp printLongLongLine` |

This matters to the thesis in three separate ways, and they should not be
collapsed into one sentence.

### F1.1 Most of it is dead-code elimination, which is a fact about *benchmarks*

In three of the four, the compiler proved the flawed computation had no
observable effect and deleted it. That is ordinary dead-code elimination, and
it fires here because Juliet's cases are synthetic: the input is a literal, the
result is unused, nothing escapes the translation unit. Real vulnerable code
almost always has the tainted value flow somewhere the compiler cannot see —
across a library boundary, into a syscall, out of the process.

So the honest reading is **not** "compilers fix bugs." It is that a synthetic
benchmark can present a flaw the optimiser is allowed to notice is pointless,
and a benchmark result at `-O2` therefore measures something slightly different
from what the same tool would find on production code. This belongs in §11 as a
limitation on external validity, and it applies to any binary-analysis
evaluation built on Juliet — not just to this one.

### F1.2 One of them is standard-sanctioned, and does happen in real code

The CWE-401 case is different in kind. C++14 (N3664) explicitly permits an
implementation to elide an allocation whose result is unused, so gcc deleting a
leaked `new[]` is not the optimiser exploiting synthetic-ness — it is the
language standard saying the leak need not exist. Unused-allocation leaks
really can vanish between a debug and a release build.

Consequence: **CWE-401 and CWE-789 are structurally the most exposed classes**
in this corpus, and a low F2 recall on them should not be read as a model
failure without checking the binary first. This is exactly what the §7.1 gate
exists to prevent, and exactly the case the current size-based gate misses.

### F1.3 The CWE-369 case is not removal at all — it is substitution

`ud2` is not "the division was deleted." It is gcc recognising that the divisor
is provably zero, concluding the program has undefined behaviour, and emitting
an instruction guaranteed to fault. The vulnerability has been *transformed*:
a divide-by-zero became an unconditional illegal-instruction trap.

Whether that counts as removing a vulnerability is a genuinely interesting
question for the write-up. A defender might call it a mitigation — the fault is
now deterministic and immediate rather than dependent on input. An analyst
would call it a different bug. For scoring purposes it is neither: the CWE-369
signature the model was asked to find is not present in the binary, so the case
has to leave the F2 arm regardless of how one labels the result.

### F1.4 The inverse problem exists and Juliet cannot show it

The well-known form of this effect runs the other way: the compiler removing a
security *mitigation* rather than a flaw. The canonical case is a `memset` that
scrubs a key or password being deleted as a dead store, since the buffer is
never read afterwards — CWE-14, *Compiler Removal of Code to Clear Buffers*.

**Checked: CWE-14 and CWE-733 have zero cases in Juliet 1.3's C/C++ suite.**
The nearest neighbours are CWE-226 (*Sensitive Information Uncleared Before
Release*, 72 files) and CWE-244 (*Heap Inspection*, 72 files), which model the
programmer failing to clear a buffer — not the compiler removing the clear that
was written. So this corpus cannot exhibit the inverse effect at all.

That is a coverage gap, not a flaw in the work, and it is a natural candidate
for the hand-authored cases already planned in `todo.md`: a CWE-14 case is
about five lines, its whole point is that it only manifests after optimisation,
and it demonstrates something the F2 pipeline is uniquely positioned to catch —
a vulnerability that *does not exist in the source at all* and appears only in
the binary. That is a strong argument for binary-level analysis over source
analysis, made with evidence rather than assertion.

### What this licenses as a claim

Supported: *optimisation materially changes which vulnerabilities are present
in a binary, in both directions, and a fidelity study that compares source
against decompiled output must control for it or it will attribute compiler
behaviour to the model.*

Not yet supported: any rate. The gate's measured recall is 3/4 (see `todo.md`),
so the 10% erasure figure in §7.1 is a lower bound until the semantic check
lands.

---

## F2. The optimiser sometimes does the chunker's job

**Measured**, same runs. Five of 41 cases *grow* at `-O2`, one to 315% of its
`-O0` size. The cause is inlining across the source/sink split: in a 5x-family
case, `badSource` and `badSink` live in different files, and `-O2` pulls the
callee into the caller so one function ends up containing the whole data flow.

§4.2 exists because per-function chunking would make cross-file cases
undetectable by construction — the chunk holding the sink has no evidence its
input is attacker-controlled. The measurement above says the compiler
*sometimes performs that assembly itself*, which means the cross-file penalty
at F2 is smaller than at F0 for reasons that have nothing to do with the model.

Worth reporting because it cuts against the intuitive expectation. Optimisation
is usually framed as pure loss of information; here it partially reconstructs a
data flow that the source deliberately split apart.

---

## F3. Juliet 1.3 does not build cleanly on a modern toolchain

**Measured**, gcc 15.2 / Ubuntu 26.04 against the committed sample.

Three failure families, all of them Juliet's, not the toolchain's:

1. **Win32-only functional variants** (3,372 files in the eligible population).
   Marked `w32` in the filename, but as a *prefix* on the API name
   (`w32CreateFile`, `w32spawnl`), which a token-boundary rule misses.
2. **A broken POSIX `#else` branch** — `getenv` returning `char *` into a
   `wchar_t *`, `popen`/`execl`/`fopen` receiving `wchar_t *`. Compiled with a
   warning on gcc 11; a hard error from gcc 14 onward, which promoted
   `-Wincompatible-pointer-types` to an error independently of `-std`.
   Confirmed to span at least CWE-23 and CWE-78.
3. **Duplicate `main`** in the 23 flow-01 cases that state the variant in the
   filename, where `-DOMITGOOD` empties the body but leaves the entry point.

Relevant to anyone reproducing this work, and a small contribution in its own
right: the suite is fourteen years old and the standard build instructions
assume a compiler generation that no longer exists on current distributions.

---

## F4. Label leakage in Juliet is not confined to identifiers, and reading the
## code does not find it

**Measured.** The scrubber run over all 88 sampled cases, with an assertion
that no `CWE\d+` and no `bad`/`good` token survives. 223 surviving tokens
before, 0 after.

§4.1 was written against the obvious leak: Juliet names its functions
`CWE121_..._bad()`. A scrubber that renames declared identifiers closes it, and
that scrubber passed every unit test written for it. The corpus-wide assertion
then found **five further leak classes**, none of which anyone had thought to
write a test for:

| Leak | Where | Occurrences |
|---|---|---|
| Java `package testcases.CWE89_SQL_Injection.s04;` | every Java case | 44 |
| String literals — `printLine("Calling bad()...")`, `IO.writeLine("bad: 100/")` | both suites | ~200 |
| `#ifndef OMITBAD` / `#ifdef INCLUDEMAIN` | every C/C++ case | 283 |
| Local `#include "CWE369_..._81.h"` | C/C++ multi-file cases | 12 |
| `#define` names | C/C++ | 174 |

Plus one that is not leakage but would have broken the Java arm outright:
scrubbing per *file* gave 43 of the 44 multi-file cases divergent mappings, so
`badSink` was `func_3` in `52a` and `func_2` in `52b`.

Two things worth saying in the write-up.

**The string-literal class is the interesting one.** `printLine("Calling
bad()...")` is not an identifier, survives every AST-based renaming rule, and
sits in the same basic block as the call to the flaw. It is also invisible to
the intuition that drives scrubber design — one reasons about *names*, and a
status message is not a name. Any binary-analysis evaluation built on Juliet
that scrubs identifiers and stops has this leak, and it is not detectable by
inspecting the scrubber.

**The method generalises past this project.** The check is three lines — run
the transform over the whole corpus, regex for the answer key — and it is the
only thing here that found a leak nobody had hypothesised. That is worth
stating as a recommendation rather than an implementation note: a
contamination control should be asserted over the corpus, not argued for in
prose, because the failure mode is silent. A leaked label does not crash. It
produces a corpus that builds, scores, and quietly measures the model's ability
to read a function name.

One residual, recorded so it is not mistaken for an oversight: the build
report's own artifact paths are rooted at `bin/java/<case_id>/`, and the case
ID names the CWE. That is the report's index into the manifest, never prompt
text, and renaming it would cost the traceability it exists for.

### F4.1 A scrubbing rule has a blast radius, and the default is silence

The same structural rule that removes `bad()` also removed `main`, `doGet` and
`doPost` — in all 44 Java cases — because all three are *declared by the file*
and that is the only question the rule asks. Nobody decided to rename `main`.
Nobody decided not to. §4.1 sorted names into "declared here" and "stdlib or
API", and these belong to a third category the split does not name: **names
fixed by a runtime contract rather than chosen by an author.**

The two failures are different in kind, and the second is the instructive one.

Renaming `main` is *loud*: no entry point, nothing runs, and you find out the
first time you try. Renaming `doGet` is *silent*. The class still compiles,
because Java does not require `@Override` — it simply stops overriding
`HttpServlet.doGet`, so a container calls the inherited handler, returns 405,
and the case's code never executes. Every test still passes. The corpus still
builds. Eighteen servlet cases are dead.

Worth reporting for two reasons beyond this project. First, it is a concrete
cost of scrubbing that the contamination literature does not discuss: the
control introduced to protect validity can quietly destroy the artifact's
semantics, and "it compiled" does not detect it. Second, it bears directly on
the thesis's own requirement for working proof-of-concept code — a PoC has to
run against the artifact the model analysed, not a differently-compiled twin,
so scrubbed artifacts being executable is a precondition of the exploitability
work rather than a convenience.

Also worth checking, and not yet checked: Ghidra generally recovers `main` in a
stripped binary, because `__libc_start_main` receives it as an argument and the
ELF analyser knows the pattern. If that holds here, then renaming `main` at F0
created an asymmetry running the *opposite* direction to the one §4.1 exists to
prevent — the decompiled tier keeping a name the source tier had removed.
