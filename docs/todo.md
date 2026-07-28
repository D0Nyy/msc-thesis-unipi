# Open questions & pending decisions

The live agenda. Everything here is undecided or unverified — decisions that get
settled move into `protocol.md` and out of this file.

## Blocking Phase 2

- [ ] **Prompt design: single-shot vs chain-of-thought.** Must be fixed before
      the main run and identical across all models, or RQ4 is invalid. Decide
      from the pilot.
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