# Open questions & pending decisions

The live agenda. Everything here is undecided or unverified — decisions that get
settled move into `protocol.md` and out of this file.

## Blocking Phase 2

- [ ] **Prompt design: single-shot vs chain-of-thought.** Must be fixed before
      the main run and identical across all models, or RQ4 is invalid. Decide
      from the pilot.
- [ ] **Contamination perturbation probe (§11.2).** Semantics-preserving
      rewrites on a stratified subset — buffer sizes, `char`→`wchar_t`,
      statement reordering, renaming Juliet's support functions. Run alongside
      the pilot. This is the largest threat to RQ1 and the probe is what turns
      it from a hedging paragraph into a reported number.
- [x] ~~**Check whether `-O2` erases the flaw at F2.**~~ **Measured** (gcc 11.4,
      43 cases, §7.1): 7% erased, median 69% retained, 2 lose all API imports,
      6 grow through inlining. `-O2` stays as primary; the erased cases need a
      build-time gate.
- [x] ~~**Implement the flaw-survival gate in `build`.**~~ **Done** —
      `build/compile.py`, `vulnlm build --compile`. Compiles both variants at
      both levels, sums demangled bad-path symbol sizes, gates at 15%, strips a
      copy for the model and keeps the symbol-bearing original as the oracle.
      On the committed sample: 40 of 44 cases enter the F2 corpus, 3 erased,
      1 unbuildable, 344 binaries. Reproduces the §7.1 table exactly.
- [x] ~~**Also check the `good` side for the same effect.**~~ **Measured, and
      the worry was backwards.** The good side retains *more* than the bad
      side, not less: median 84% against 69%, and 1 of 43 collapses against 3.
      So the negative class does not become trivially separable, and no
      exclusion rule is needed. The asymmetry does run the other way, though —
      bad binaries are systematically the more heavily optimised of the pair,
      which is a size-based shortcut a model could in principle exploit. Worth
      a line in §11 and worth checking against the F2 false-positive rate once
      the pilot exists. `FlawSurvival` records both sides on every case.
- [ ] **Audit the scrubber allowlist for Juliet scaffolding.** §4.1 preserves
      "standard library and API calls", but `printLine`, `globalReturnsTrue`,
      `CHAR_ARRAY_SIZE` and `std_testcase.h` are Juliet support, not stdlib. If
      the allowlist admits them the corpus stays identifiable even after
      scrubbing, which defeats §11.1.
- [ ] **Get Ollama serving on the local card.** gfx1032 needs
      `HSA_OVERRIDE_GFX_VERSION=10.3.0`, and ROCm ≥6.4.3 has a reported SIGSEGV
      regression on gfx1031/1032 (6.4.1 works). Budget a day, not an hour.
      Confirm tier S is actually on GPU and has not silently fallen back to CPU,
      which would make its latency incomparable to M and L. Then pull all three
      rungs and check the digests against `analysis/models.py`.
- [ ] **Re-check the 32K context window against the chunking policy.** §4.2
      assembles callees into one context; at 32K on tier S the overflow rate may
      be high enough to force a depth limit decision. Measure in the pilot
      before changing anything — a high overflow rate is a §8.2 result, not
      automatically a bug.

## Blocking the build — new, from implementing `--compile`

- [ ] **Which gcc?** §7.1 records the `-O2` measurements as gcc 11.4, and the
      numbers in it were reproduced exactly on gcc 11.4. The WSL2 box now has
      **gcc 15.2.0**. These are not interchangeable: gcc 14 turned implicit
      declarations and incompatible pointer assignments — both of which Juliet
      1.3 contains — from warnings into errors, so the *set of buildable cases*
      is compiler-dependent. `compile.py` pins `-std=gnu11` / `-std=gnu++14`
      to hold the language fixed. **Partially measured:** on gcc 11.4, building
      the sample under C23 semantics (`-std=c2x` plus the four `-Werror`s gcc
      15 turns on by default) costs one further case — 42 of 44 against the
      pin's 43 — so the pin absorbs most but not all of the difference. That is
      a simulation of gcc 15 on gcc 11, not gcc 15 itself. The real check is one
      command on the WSL box: `vulnlm build --compile` and compare
      `data/build-report.json` against the committed one. Either install gcc-11
      alongside and pin the compiler too, or adopt 15.2 and reconcile §7.1
      against what it reports. Whichever is chosen has to be recorded, because
      `BuildReport.compiler_version` will make a mismatch obvious later.
- [ ] **Unbuildable cases are in the population, not just the sample.** The
      `w32` filename rule was wrong — it required a token boundary, but Juliet
      writes the API name straight onto the marker (`w32CreateFile`,
      `w32spawnl`), so **3,372 Win32 files** were counted as buildable,
      including 820 each in CWE-78 and CWE-23. Fixed and regression-tested; the
      manifest was regenerated and 7 cases changed. But a second family has no
      filename marker at all: 12 CWE-23 `wchar_t` cases fail because Juliet's
      own `#else` branch is broken on POSIX (`getenv` returns `char *` into a
      `wchar_t *`; `fopen`/`open` take `char *`). One is in the committed
      sample. Decide: probe the eligible population once and commit the
      failures as data that `is_eligible` reads, or accept that a stratum can
      come up short after the draw and report the rate. The first is ~25
      minutes of compiling for the 10,885 eligible C/C++ cases in the 11
      sampled CWEs, and is toolchain-specific — so it depends on the question
      above.
- [ ] **Confirm `-U_FORTIFY_SOURCE`.** Ubuntu's gcc enables `_FORTIFY_SOURCE=2`
      at `-O1` and above but *not* at `-O0`, so the `-O0`/`-O2` pair would
      otherwise differ in libc API surface as well as optimisation: `printf`
      becomes `__printf_chk`, `memcpy` becomes `__memcpy_chk`. Since §4.1
      treats imported API names as signal and the `-O0` subset exists to
      isolate optimisation specifically, `compile.py` disables it. The counter
      argument is §7.1's own "`-O2` is what release binaries actually use" —
      real Ubuntu release builds *are* fortified. Pick one and say why; the
      current choice favours a clean contrast over distro realism.
- [ ] **Confirm `-no-pie`.** Chosen so Ghidra addresses are stable across
      cases and comparable in write-ups. Real binaries are PIE. Same trade as
      above, lower stakes.

## Blocking the main run

- [ ] **Final CWE set** for cross-language comparison. Coverage is no longer
      the constraint: `build --survey` reports **59 CWEs present in both C/C++
      and Java**, including all four original candidates (CWE-78/90 injection,
      CWE-23/36 path traversal, CWE-256/259/321 credentials, CWE-327/328
      crypto). Pick on scientific grounds — spread across CWE pillars, a mix
      of memory-safety and logic flaws, and enough cases per stratum — not on
      availability.
- [ ] **Exclude the bad-only CWEs from the balanced design.** Appendix D of the
      C/C++ User Guide lists **CWE-506 and CWE-510** as having no `good`
      variant. Both appear in the 59 shared CWEs above. With no negative class
      they cannot contribute to precision or FPR, so either drop them or score
      them separately — silently including them biases precision upward.
- [ ] **Sample size per stratum.** Run a pilot (~50 cases) to estimate effect
      size, then size the full run.
- [ ] **`k` (repetitions).** Fixed by the §6.2 pilot decision rule: k=3 on a
      ~20% subset, then k=1 if ≥99% agreement. Record the measured rate.
- [ ] **Juliet flow variants — the range is wider than `01`–`22`.** Juliet 1.3
      also uses the 3x (intra-function data flow), 4x (inter-function), 5x
      (**inter-file**, split across `a`–`e` files), 6x and 8x bands. The 5x band
      is the one §4.2 was written for — source and sink in different files — so
      excluding it would remove exactly the cases that justify the chunking
      policy. Decide: stratify across bands, or hold at `01`? Confirm the real
      distribution with `vulnlm build --survey` before choosing; the band
      boundaries in `build/juliet.py` are inferred from the numbering scheme and
      not yet validated against the dataset.
- [ ] **Cloud GPU provider and budget ceiling** for tiers M and L. One 24 GB
      card covers both; estimate GPU-hours from the pilot before committing.

## Smaller, decide when convenient

- [ ] **Drop `cwe_name` from `Finding`?** Redundant with `cwe_id`, costs tokens,
      and a model-supplied name disagreeing with the ID is unscoreable noise.
      Derive it from the MITRE export instead. (Keep it on `GroundTruth`.)
- [ ] **MITRE CWE hierarchy export** into `data/` — needed for parent/pillar
      scoring (§8.4) and `helpUri` generation. Never hand-maintained.
- [ ] **Statistical analysis plan** (§5.6 in an earlier draft, now deferred).
      Must be written down before the full run, not chosen after seeing results.
- [ ] **Tests for `eval/`** at Phase 3. A bug there does not crash — it produces
      plausible wrong numbers that reach the thesis. The one module worth
      testing.
- [ ] **Hand-authored cases for the classes Juliet does not model.** CWE-502
      (unsafe deserialization) and CWE-79 (generic XSS) are absent from *both*
      suites. Analysis mode (`recover --source` / `--binary`, §4.0) already runs
      arbitrary code, so the work is authoring the cases and attaching a
      `GroundTruth` to each — probably a small separate manifest rather than the
      Juliet one. Keep them out of the P/R/F1 numbers: N is ~5-10, so they are a
      demonstration that the pipeline handles the class, not a measurement.
      Deserialization is the best candidate — a gadget chain is genuinely hard to
      see in decompiled bytecode, so it serves the fidelity story rather than
      just filling a coverage gap. Natural home is Phase 5, alongside the PoC work.
- [ ] **Second flagship API?** Would strengthen RQ4 if affordable.
- [ ] **Optional MoE currency-check tier X**, reported separately from the
      dense ladder.


maybe add chain for all stages