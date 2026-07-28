# Juliet dataset notes

Everything the code in `src/vulnlm/build/` knows about the dataset, in one
place. Written against the three v1.3 archives and verified against all
197,672 source filenames in them, not against a sample.

The modules stay short by pointing here. This document is also the raw material
for the dataset section of the methodology chapter.

---

## 1. Where the data comes from

**SARD** — NIST's *Software Assurance Reference Dataset* — is the repository
that publishes Juliet. Three archives are relevant:

| Suite | SARD id | Archive |
|---|---|---|
| C/C++ 1.3 | [112](https://samate.nist.gov/SARD/test-suites/112) | `2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip` |
| Java 1.3 | [111](https://samate.nist.gov/SARD/test-suites/111) | `2017-10-01-juliet-test-suite-for-java-v1-3.zip` |
| C# 1.3 | [110](https://samate.nist.gov/SARD/test-suites/110) | `2020-08-01-juliet-test-suite-for-csharp-v1-3.zip` |

Only C/C++ and Java are in scope — see protocol §5.1. The C# archive stays in
`data/raw/` and its entry in `suites.py` is disabled rather than deleted.

Each archive ships its own documentation in `doc/`. The *Juliet Test Suite v1.2
for C/C++ User Guide* is the authority for everything in §2 and §3 below;
where this document states a rule, it comes from there and not from inference.

---

## 2. Filename grammar

Test-case filenames are structured, and the structure carries the ground truth
(User Guide §3.4.1):

```
CWE<id>_<shortened name>__<functional variant>_<flow variant><sub-file?>.<ext>

CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_54a.c
└─┬──┘ └────────────┬────────────┘  └─┬──┘ └──────┬──────┘ └┤└┤
  │                 │                 │           │         │ └ sub-file id
  │                 │                 │           │         └── flow variant
  │                 │                 │           └──────────── functional variant
  │                 │                 └──────────────────────── secondary CWE (optional)
  │                 └────────────────────────────────────────── CWE name
  └──────────────────────────────────────────────────────────── CWE id  ← THE LABEL
```

Parsed by `build/juliet.py`.

---

## 3. Four traps

Each of these was an incorrect assumption at some point during development.
None of them raises an error when you get it wrong; each one silently produces
a smaller or mislabelled sample. That is why `build --survey` exists.

### 3.1 The secondary CWE is not the label

`CWE121_..._CWE193_char_alloca_cpy_01.c` is a **CWE-121** stack-based buffer
overflow. The embedded CWE-193 (off-by-one) describes *how* the overflow is
reached, not what the flaw is.

Both are real CWE IDs and both look plausible in a results table, so scoring
the wrong one corrupts the §8.4 classification metric without any visible
symptom. Only the leading ID is ground truth.

### 3.2 The sub-file identifier has two disjoint forms

Either a **letter** (`a`–`e`), splitting one case across source files:

```
CWE476_NULL_Pointer_Dereference__char_54a.c   … through …_54e.c
```

or a **variant word**, splitting the flawed and fixed constructs into separate
files — used where the flaw is inherent in a class and cannot be two functions
in one file (User Guide §3.4.2):

```
CWE563_Unused_Variable__unused_class_member_01_bad.cpp
CWE563_Unused_Variable__unused_class_member_01_good1.cpp
```

The variant words are `bad`, `base`, `good1`, `good2`, `goodG2B`, `goodB2G`.

**This matters for §4.1.** Where the second form is used, the *filename states
the answer*. 12,984 files across the two active suites do this. The scrubber
must destroy it — a chunk derived from `..._81_bad.cpp` must not carry that
name into a prompt.

### 3.3 `.h` files can be test-case files

4,300 headers in the C/C++ suite are case files, not support code. They hold
the class declaration for cases whose implementation is in `_81a.cpp`.
Filtering on `.c`/`.cpp` alone drops part of every case in the 81–84 band.

### 3.4 Flow variants are not `01`–`22`

The documented taxonomy (User Guide §3.3, Appendix C):

| Range | Flow type |
|---|---|
| `01` | Baseline — simplest form of the flaw |
| `02`–`22` | Control flow |
| `31`+ | Data flow |

`23`–`30` is a reserved gap and is currently empty. The suites use 01–22,
31–34, 41–45, 51–54, 61–68, 72–74 and 81–84.

**Cross-file cases matter more than the rest.** Where the taint source and the
sink live in different files, a chunk containing only the sink has no evidence
its input is attacker-controlled — those cases are undetectable by
construction unless §4.2 assembles callees into the chunk. The cross-file set:

```
22, 51–54, 61–68, 71–75, 81–84
```

**`22` is the one a range-based rule gets wrong.** The guide describes it as
"flow controlled by the value of a global variable; sink functions are in a
separate file from sources" — a cross-file case sitting inside the control-flow
band. 34,371 cases across the two suites are cross-file, over a third of the
total.

### 3.5 Bad-only CWEs

Appendix D lists **CWE-506** (Embedded Malicious Code) and **CWE-510**
(Trapdoor) as having no `good` variant. Both appear in the cross-language
shared set. With no negative class they cannot contribute to precision or FPR
and must be excluded or scored separately.

---

## 4. The SARD manifest

Each archive ships a `manifest.xml` written by NIST, listing every case, its
files, and for each flawed file the CWE **and the line number of the flaw**:

```xml
<file path="CWE114_Process_Control__w32_char_connect_socket_01.c">
  <flaw line="121" name="CWE-114: Process Control"/>
</file>
```

Read by `build/sard.py`. Two uses:

**As a check on the filename parser.** The two are independent derivations of
the same fact, so agreement is evidence and disagreement is a defect in one of
them. Current state: 89,555 files overlap, **zero disagreements**, zero flaw
entries without a matching source file.

**As localisation ground truth.** 102,540 flaw line numbers across the two
suites. Map a line to its enclosing function and you have the sink symbol that
a model's `symbol` field should point at — the §8.4 tertiary metric, without
hand-labelling.

### 4.1 Two defects in the shipped files

**Zero padding is inconsistent between the two sources.** The manifest writes
`CWE-036` where the filename writes `CWE36`. Comparing raw strings reports
~10,000 spurious disagreements in C/C++ alone. Both sides are normalised
before comparison.

**The Java manifest is not well-formed XML.** It contains two unmatched
`</testcase>` tags, at lines 50084 and 66737. A standard parser aborts at the
first one, losing roughly two thirds of the Java ground truth — silently, if
the exception is caught. `repair_manifest` removes exactly those tags and
reports which lines it dropped; anything else still raises.

The C/C++ manifest is clean. The C# suite ships no manifest at all, which is a
further small argument for §5.1: it is the one language with no independent
label to check the filename parse against.

---

## 5. Survey invariants

`vulnlm build --survey` reads the archives and exits non-zero if either
invariant fails.

**`unexplained_rejects` must be zero.** A source file that is neither
recognised as scaffolding nor parsed as a case has been silently dropped.

**`manifest_disagreements` must be zero.** If the filename and the manifest
disagree on a CWE, the label reaching `eval` is a coin flip.

Current state, both suites clean:

| | C/C++ | Java |
|---|---|---|
| Source files | 105,735 | 46,811 |
| Support (excluded) | 552 | 635 |
| Parsed | 105,183 | 46,176 |
| Cases | 64,099 | 28,881 |
| — cross-file | 23,459 | 10,912 |
| Distinct CWEs | 118 | 112 |
| Variant-declaring files (§4.1 leakage) | 10,214 | 2,770 |
| Manifest agreements | 64,125 | 25,430 |
| Flaw lines | 65,263 | 37,277 |

**59 CWEs are present in both suites** — the population §5's cross-language
design draws from.

---

## 6. Scaffolding that is not a test case

Excluded by `is_support_file`. Directories: `testcasesupport`, `support`,
`lib`, `WebContent`, and the JNI project directories. Filenames: `main`,
`main_linux`, `io`, `std_testcase`, `AbstractTestCase`, `Program`,
`AssemblyInfo`, `stdafx`, and any `*_Helper`.

The JNI entries are narrower than they look: Java's CWE-111 (Unsafe JNI) ships
a small C++ project so the case has a native library to call into. Those
sources are infrastructure for a Java test case, not C++ cases, and admitting
them would put three unlabelled C++ files into the Java stratum.
