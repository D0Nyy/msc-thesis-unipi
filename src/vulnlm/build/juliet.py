"""Parse Juliet filenames into their parts. Pure functions, no I/O.

A filename carries the ground truth:

    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_54a.c
    └ cwe_id └ cwe_name                 └ 2nd  └ functional     └ flow + sub-file

The grammar, and the four ways it is easy to misread, are documented in
`docs/dataset-notes.md` §2-3. Read that before changing anything here.
"""

import re
from pathlib import PurePosixPath
from typing import Final, NamedTuple

from vulnlm.schema import Language

_EXTENSIONS: Final[dict[str, Language]] = {
    ".c": Language.C,
    ".cpp": Language.CPP,
    ".cs": Language.CSHARP,
    ".java": Language.JAVA,
}

# Headers are test-case files too (notes §3.3), not support code.
_HEADER_EXTENSIONS: Final[set[str]] = {".h", ".hpp"}

_SUPPORT_DIRS: Final[set[str]] = {
    "testcasesupport", "juliet_support", "support", "lib", "webcontent",
    # CWE-111 ships a C++ JNI shim; it is infrastructure for a Java case, not
    # a C++ case (notes §6).
    "jnitest", "linux.jni.files", "visual.studio.jni.dll.project",
}

_SUPPORT_STEMS: Final[set[str]] = {
    "main", "main_linux", "io", "std_testcase", "std_testcase_io",
    "abstracttestcase", "abstracttestcaseclass", "servletmain", "testcases",
    "program", "assemblyinfo", "stdafx", "jnitest", "targetver", "dllmain",
    "libjnitest",
}

_SUPPORT_SUFFIXES: Final[tuple[str, ...]] = ("_helper",)

# Sub-file identifier, variant-word form. Lowercase key -> canonical spelling.
_VARIANTS: Final[dict[str, str]] = {
    "bad": "bad", "base": "base", "good1": "good1", "good2": "good2",
    "goodg2b": "goodG2B", "goodb2g": "goodB2G",
}

# `name` is non-greedy so the FIRST `__` ends it; `tail` is greedy so the LAST
# `_<2 digits>` is the flow variant. Both are needed: some CWE names contain a
# double underscore, and functional variants contain digits (`int64_t_fscanf`).
_CASE_RE: Final[re.Pattern[str]] = re.compile(
    r"^CWE(?P<cwe>\d+)_(?P<name>.+?)__(?P<tail>.+)_(?P<flow>\d{2})"
    r"(?:(?P<letter>[a-z])|_(?P<variant>[A-Za-z0-9]+))?$"
)
_SECONDARY_RE: Final[re.Pattern[str]] = re.compile(r"^CWE(?P<cwe>\d+)_(?P<rest>.+)$")
_WINDOWS_RE: Final[re.Pattern[str]] = re.compile(r"(?:^|_)(?:w32|windows)(?:_|$)")

# Cross-file flow variants (notes §3.4). Confirmed by counting sub-file
# identifiers across the archives. 22 is the one a range rule misses.
_CROSS_FILE: Final[set[int]] = {
    22, *range(51, 55), *range(61, 69), *range(71, 76), *range(81, 85)
}


class ParsedName(NamedTuple):
    """One decomposed filename.

    `case_id` excludes the sub-file identifier in both its forms, so `_54a.c`,
    `_81.h`, `_81a.cpp` and `_81_bad.cpp` all collapse onto their case.
    """

    case_id: str
    language: Language
    cwe_id: str  # the label
    cwe_name: str
    secondary_cwe_id: str | None  # NOT the label — notes §3.1
    functional_variant: str
    flow_variant: str
    letter: str | None  # "a".."e", or
    # "bad" | "good1" | ... — at most one of the two. When set, the FILENAME
    # states bad-vs-good outright, which is a §4.1 leakage surface.
    variant: str | None
    is_header: bool
    windows_only: bool  # Win32 API; will not build with gcc


def _is_support(p: PurePosixPath) -> bool:
    if any(part.lower() in _SUPPORT_DIRS for part in p.parts):
        return True
    stem = p.stem.lower()
    return stem in _SUPPORT_STEMS or stem.endswith(_SUPPORT_SUFFIXES)


def is_support_file(path: str) -> bool:
    """True for suite scaffolding that is not part of any test case."""
    return _is_support(PurePosixPath(path))


def parse_name(path: str) -> ParsedName | None:
    """Decompose a Juliet source path, or None if it is not a test-case file.

    None is the normal outcome for build scripts, docs and support code, so it
    is returned rather than raised. Callers that need to distinguish
    "correctly ignored" from "silently lost" filter with `is_support_file`
    first and treat any remaining None as a defect — that is what `survey`
    reports on.
    """
    # PurePosixPath, not Path: zip members always use forward slashes whatever
    # the host OS, and on Windows a Path would also treat a backslash as a
    # separator — misparsing any filename that legitimately contains one.
    p = PurePosixPath(path)
    suffix = p.suffix.lower()
    is_header = suffix in _HEADER_EXTENSIONS
    language = _EXTENSIONS.get(suffix)

    if (language is None and not is_header) or _is_support(p):
        return None

    m = _CASE_RE.match(p.stem)
    if m is None:
        return None

    variant = m.group("variant")
    if variant is not None:
        # A trailing `_<word>` that is not a known variant means the grammar
        # has drifted. Refuse rather than invent a case.
        if variant.lower() not in _VARIANTS:
            return None
        variant = _VARIANTS[variant.lower()]

    # Strip the optional secondary CWE off the front of the functional variant.
    tail = m.group("tail")
    secondary_cwe_id = None
    if (sec := _SECONDARY_RE.match(tail)) is not None:
        secondary_cwe_id = f"CWE-{int(sec.group('cwe'))}"
        tail = sec.group("rest")

    return ParsedName(
        # Rebuilt from parts, not sliced off the stem: the two sub-file forms
        # have different lengths and slicing gets one of them wrong.
        case_id=f"CWE{m.group('cwe')}_{m.group('name')}__{m.group('tail')}_{m.group('flow')}",
        # Headers have no language of their own; they belong to a C++ case.
        language=language if language is not None else Language.CPP,
        # int() normalises padding: CWE015_ and CWE15_ are the same weakness
        # and must not become two strata.
        cwe_id=f"CWE-{int(m.group('cwe'))}",
        cwe_name=m.group("name"),
        secondary_cwe_id=secondary_cwe_id,
        functional_variant=tail,
        flow_variant=m.group("flow"),
        letter=m.group("letter"),
        variant=variant,
        is_header=is_header,
        windows_only=bool(_WINDOWS_RE.search(tail)),
    )


def flow_type(flow_variant: str) -> str:
    """`baseline` | `control` | `data` | `unknown` (notes §3.4).

    `unknown` is returned rather than raised so an unexpected code lands in a
    survey histogram instead of aborting the run that would have revealed it.
    """
    try:
        n = int(flow_variant)
    except ValueError:
        return "unknown"
    if n == 1:
        return "baseline"
    if 2 <= n <= 22:
        return "control"
    return "data" if n >= 31 else "unknown"


def is_cross_file(flow_variant: str) -> bool:
    """True when the case spans several source files.

    These are the cases where per-function chunking fails by construction:
    source and sink are in different files, so a chunk holding only the sink
    has no evidence its input is attacker-controlled.
    """
    try:
        return int(flow_variant) in _CROSS_FILE
    except ValueError:
        return False
