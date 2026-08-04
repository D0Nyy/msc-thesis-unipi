"""Juliet's own support surface — the identifiers that are NOT stdlib.

This lives in `build/` with the rest of the dataset knowledge, not in `re/`
with the pipeline, and the distinction is load-bearing rather than tidiness.

**Scrubbing is an experimental control, not a pipeline stage.** In the analysis
mode of §4.0 — an arbitrary binary someone hands the tool — there is no answer
key to hide, and scrubbing would actively destroy meaningful names a real
analyst would rely on. Scrubbing exists solely to neutralise an artifact of
*this benchmark*: Juliet encodes its own answer in its identifiers. So the
scrubbing *mechanism* in `build/scrub.py` is dataset-agnostic; the *list of
names to treat as scaffolding* is Juliet knowledge and belongs here, beside
`juliet.py` and `suites.py`. `scrub()` takes a denylist as an argument and
defaults to none, which is what keeps the tool usable on real binaries.

Why a denylist is needed at all: §4.1 preserves "standard library and API
calls" because a human analyst sees those too. Read naively that means "keep
anything the file does not itself declare" — and Juliet's support library sails
straight through. `printLine`, `globalReturnsTrue` and `ALLOCA` are not libc;
they are this benchmark's furniture, and leaving them in keeps the corpus
recognisable to a model that has seen Juliet before, which defeats §11.1.

So scrubbing needs both halves:

  * a STRUCTURAL rule — anything declared inside the sample gets renamed,
    which tree-sitter determines from the parse tree; and
  * this DENYLIST — identifiers declared in Juliet's support files, which a
    chunk references but never declares, so the structural rule cannot see
    them.

Everything below was derived by parsing the archives rather than typed by hand,
and `tests/test_scaffolding.py` re-derives it and fails if the two disagree.
A hand-maintained list would rot silently, and silently is the worst way for
this particular thing to fail.
"""

from typing import Final

# --------------------------------------------------------------------------- #
# C/C++ — from testcasesupport/{io.c,std_testcase.h,std_testcase_io.h,std_thread.h}
# --------------------------------------------------------------------------- #
#
# `testcases.h` is deliberately excluded from the derivation: it is a generated
# index declaring all 77,567 test-case functions, so folding it in would put
# every case name in the denylist and tell us nothing.

# The output helpers every case calls to make its flaw observable. Present in
# literally every binary, and the single most recognisable Juliet fingerprint.
C_IO_FUNCTIONS: Final[frozenset[str]] = frozenset({
    "printLine", "printWLine", "printIntLine", "printShortLine",
    "printFloatLine", "printLongLine", "printLongLongLine", "printSizeTLine",
    "printHexCharLine", "printHexUnsignedCharLine", "printWcharLine",
    "printUnsignedLine", "printDoubleLine", "printStructLine",
    "printBytesLine", "decodeHexChars", "decodeHexWChars",
})

# Opaque always-true / always-false values. Juliet uses these to build control
# flow an optimiser cannot fold, so they appear in every 02-22 flow variant.
C_GLOBALS: Final[frozenset[str]] = frozenset({
    "globalTrue", "globalFalse", "globalFive", "globalArgc", "globalArgv",
    "globalReturnsTrue", "globalReturnsFalse", "globalReturnsTrueOrFalse",
})

# Empty stubs defined in io.c. They matter twice: they are scaffolding, and
# their names collide with the oracle's vocabulary — a substring rule looking
# for "bad" would count `bad1`..`bad9` as flaw code in every single binary.
C_STUBS: Final[frozenset[str]] = frozenset(
    {f"bad{i}" for i in range(1, 10)} | {f"good{i}" for i in range(1, 10)}
)

C_MACROS: Final[frozenset[str]] = frozenset({
    "ALLOCA", "RAND32", "RAND64", "URAND31", "URAND63",
})

# `stdThreadRoutine` and `stdThreadLock` are typedefs rather than functions,
# which is why a function-shaped regex missed them on the first pass and the
# archive-derivation test caught it.
C_THREAD_HELPERS: Final[frozenset[str]] = frozenset({
    "stdThreadCreate", "stdThreadDestroy", "stdThreadJoin", "stdThreadRoutine",
    "stdThreadLock", "stdThreadLockAcquire", "stdThreadLockCreate",
    "stdThreadLockDestroy", "stdThreadLockRelease",
})

C_TYPES: Final[frozenset[str]] = frozenset({"twoIntsStruct"})

# Juliet's build switches. These are not merely recognisable — `OMITBAD` and
# `OMITGOOD` spell the ground-truth label in capitals, and `#ifndef OMITBAD`
# brackets the flaw in every single C/C++ case. They are referenced but never
# defined in a case (the build system passes `-D`), so the structural rule
# cannot see them.
#
# Renaming them does not break the build: §4.1 compiles the C/C++ *binaries*
# from unmodified source and scrubs only the F0 text, so the scrubbed tree is
# never handed to gcc. `_WIN32` is deliberately absent — a platform guard is
# not leakage, and a human analyst sees it too.
C_BUILD_MACROS: Final[frozenset[str]] = frozenset({
    "OMITBAD", "OMITGOOD", "INCLUDEMAIN",
})

# Stems of the shared support headers, for `#include "std_testcase.h"`. Held as
# stems rather than filenames because the scrubber maps a filename by its stem,
# so a sibling header whose stem is also a namespace name reuses that entry.
C_SUPPORT_HEADERS: Final[frozenset[str]] = frozenset({
    "std_testcase", "std_testcase_io", "std_thread", "testcases",
})

C_SCAFFOLDING: Final[frozenset[str]] = (
    C_IO_FUNCTIONS | C_GLOBALS | C_STUBS | C_MACROS | C_THREAD_HELPERS | C_TYPES
    | C_BUILD_MACROS | C_SUPPORT_HEADERS
)

# --------------------------------------------------------------------------- #
# Java — from Java/src/testcasesupport/
# --------------------------------------------------------------------------- #

# Every case extends one of these, so the `extends` clause alone announces the
# file is a benchmark specimen.
JAVA_BASE_CLASSES: Final[frozenset[str]] = frozenset({
    "AbstractTestCase", "AbstractTestCaseBase", "AbstractTestCaseBadOnly",
    "AbstractTestCaseClassIssue", "AbstractTestCaseClassIssueBad",
    "AbstractTestCaseClassIssueGood", "AbstractTestCaseServlet",
    "AbstractTestCaseServletBase", "AbstractTestCaseServletBadOnly",
})

JAVA_SUPPORT_CLASSES: Final[frozenset[str]] = JAVA_BASE_CLASSES | {"IO"}

JAVA_SUPPORT_METHODS: Final[frozenset[str]] = frozenset({
    "writeLine", "writeString", "toHex", "getDBConnection",
    "staticReturnsTrue", "staticReturnsFalse", "staticReturnsTrueOrFalse",
    "runTest", "runTestSolo", "mainFromParent",
})

JAVA_SUPPORT_PACKAGE: Final[str] = "testcasesupport"

JAVA_SCAFFOLDING: Final[frozenset[str]] = (
    JAVA_SUPPORT_CLASSES | JAVA_SUPPORT_METHODS | {JAVA_SUPPORT_PACKAGE}
)

# --------------------------------------------------------------------------- #
# The answer key
# --------------------------------------------------------------------------- #

# These are not merely recognisable — they ARE the ground-truth label, and in
# Java they survive into bytecode and back out of the decompiler as method
# names. A model that reads `void bad()` needs no analysis at all. Scrubbing
# these is not a refinement of the experiment; it is the precondition for the
# experiment meaning anything.
VARIANT_NAMES: Final[frozenset[str]] = frozenset({
    "bad", "good", "good1", "good2", "goodG2B", "goodB2G",
    "badSink", "badSource", "goodG2BSink", "goodB2GSink",
    "goodG2BSource", "goodB2GSource",
})

ALL_SCAFFOLDING: Final[frozenset[str]] = (
    C_SCAFFOLDING | JAVA_SCAFFOLDING | VARIANT_NAMES
)
