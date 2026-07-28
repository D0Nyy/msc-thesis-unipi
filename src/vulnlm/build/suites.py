"""Which archives make up the dataset, and where to find them.

Kept separate from the parsing modules so that "what are we studying" is one
short, auditable file rather than a constant scattered through the pipeline.

Scope is C/C++ and Java (protocol §5.1). C# is deferred, not deleted: its entry
is present but disabled, because the reason it is off is a schedule decision
that could reverse, and a commented-out block loses that information.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from vulnlm.schema import Language


@dataclass(frozen=True)
class Suite:
    """One Juliet archive."""

    key: str
    languages: tuple[Language, ...]
    version: str
    # Substring matched against filenames in data/raw. The archives carry a
    # release date in their name, so an exact filename would break the moment
    # NIST reposts one; a substring keeps discovery stable without matching
    # something unrelated.
    archive_marker: str
    # Path of manifest.xml INSIDE the archive. None where the suite ships
    # none — the C# suite does not, which is a further small argument for
    # §5.1: it is the one language with no independent ground truth to check
    # the filename parse against.
    manifest_member: str | None
    enabled: bool = True


SUITES: Final[tuple[Suite, ...]] = (
    Suite(
        key="c-cpp",
        languages=(Language.C, Language.CPP),
        version="1.3",
        archive_marker="juliet-test-suite-for-c-cplusplus",
        manifest_member="C/manifest.xml",
    ),
    Suite(
        key="java",
        languages=(Language.JAVA,),
        version="1.3",
        archive_marker="juliet-test-suite-for-java",
        manifest_member="Java/manifest.xml",
    ),
    Suite(
        key="csharp",
        languages=(Language.CSHARP,),
        version="1.3",
        archive_marker="juliet-test-suite-for-csharp",
        manifest_member=None,  # ships no manifest.xml
        enabled=False,  # §5.1 — deferred, re-enable to extend
    ),
)

ACTIVE_SUITES: Final[tuple[Suite, ...]] = tuple(s for s in SUITES if s.enabled)

# Extensions that can be test-case files. `.h` is here because 4,300 C/C++
# headers are case files, not support — see build/juliet.py.
SOURCE_EXTENSIONS: Final[set[str]] = {".c", ".cpp", ".cs", ".java", ".h", ".hpp"}


class ArchiveNotFound(FileNotFoundError):
    """Raised with the marker that failed, so the message is actionable."""


def find_archive(suite: Suite, raw_dir: Path) -> Path:
    """Locate a suite's zip in `raw_dir`. Raises if absent or ambiguous."""
    matches = sorted(
        p for p in raw_dir.glob("*.zip") if suite.archive_marker in p.name
    )
    if not matches:
        raise ArchiveNotFound(
            f"no archive matching {suite.archive_marker!r} in {raw_dir}. "
            f"Download the Juliet {suite.key} suite from https://samate.nist.gov/SARD/test-suites"
        )
    if len(matches) > 1:
        raise ArchiveNotFound(
            f"{len(matches)} archives match {suite.archive_marker!r} in {raw_dir}: "
            f"{[p.name for p in matches]}. Keep exactly one — the sample must "
            f"be traceable to a single archive."
        )
    return matches[0]


def sha256_file(path: Path, *, chunk_size: int = 1 << 20) -> str:
    """Archive hash, recorded in the manifest so a run is tied to its input."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
