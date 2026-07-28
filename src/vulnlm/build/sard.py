"""Read NIST's `manifest.xml` — the suite's own statement of ground truth.

Each archive ships one, listing every flawed file with its CWE and the line
number of the flaw. It is an independent derivation of the same label the
filename carries, so it is used both to check `juliet.py` and to supply
localisation ground truth for §8.4.

Two defects in the shipped files are handled here (padding, malformed Java
XML). See `docs/dataset-notes.md` §4.
"""

import re
import xml.etree.ElementTree as ET
from typing import Final, NamedTuple

_CWE_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^\s*CWE-(\d+)\s*:\s*(.*?)\s*$")
_OPEN: Final[str] = "<testcase>"
_CLOSE: Final[str] = "</testcase>"


class Flaw(NamedTuple):
    """One flaw the suite declares, in one file."""

    cwe_id: str  # normalised: "CWE-36", never "CWE-036"
    cwe_name: str
    line: int  # 1-based, in the ORIGINAL source (F0 coordinates)


def normalise_cwe_id(raw: str | int) -> str:
    """`36`, `"CWE-036"`, `"CWE36"` -> `"CWE-36"`.

    Applied to BOTH sources before comparison. The manifest zero-pads and the
    filename does not; without this they disagree on every padded ID, which
    looks like a parser bug and is not one.
    """
    m = re.search(r"(\d+)", str(raw))
    if m is None:
        raise ValueError(f"no CWE number in {raw!r}")
    return f"CWE-{int(m.group(1))}"


def repair_manifest(text: str) -> tuple[str, list[int]]:
    """Drop unmatched `</testcase>` tags. Returns (repaired, dropped lines).

    Deliberately narrow: it removes closing tags that would take nesting depth
    negative, and nothing else. Any other malformation still raises from the
    XML parser. This repairs one known defect in one shipped file; it is not a
    general-purpose fallback, and a manifest needing a different repair should
    fail loudly because it means the dataset changed.
    """
    out: list[str] = []
    dropped: list[int] = []
    depth = 0

    for lineno, line in enumerate(text.splitlines(keepends=True), start=1):
        delta = line.count(_OPEN) - line.count(_CLOSE)
        if depth + delta < 0 and line.strip() == _CLOSE:
            dropped.append(lineno)
            continue
        depth = max(depth + delta, 0)
        out.append(line)

    return "".join(out), dropped


def parse_manifest(text: str) -> tuple[dict[str, list[Flaw]], list[int]]:
    """`manifest.xml` -> ({source basename: [Flaw, ...]}, repaired line numbers).

    Keyed on basename because manifest paths are relative to the suite's
    `testcases/` root while archive members carry a full path. Basenames are
    unique across Juliet.

    Files with no `<flaw>` child are omitted rather than mapped to `[]`.
    Absence is ambiguous — it covers good-only files, the non-sink halves of
    multi-file cases, and non-source members like `JNITest.dll` — so callers
    must decide what it means rather than receive an empty list that reads as
    "checked, none found".
    """
    repaired, dropped = repair_manifest(text)
    root = ET.fromstring(repaired)

    flaws: dict[str, list[Flaw]] = {}
    for file_el in root.iter("file"):
        basename = (file_el.get("path") or "").rsplit("/", 1)[-1]
        for flaw_el in file_el.findall("flaw"):
            m = _CWE_NAME_RE.match(flaw_el.get("name") or "")
            if m is None:
                continue
            try:
                line = int(flaw_el.get("line") or 0)
            except ValueError:
                continue
            flaws.setdefault(basename, []).append(
                Flaw(normalise_cwe_id(m.group(1)), m.group(2), line)
            )

    return flaws, dropped
