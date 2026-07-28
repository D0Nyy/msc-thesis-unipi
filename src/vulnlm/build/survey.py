"""Count what is actually in the archives and check the two label sources agree.

`build --survey` exists because several assumptions about this dataset turned
out to be wrong, and none of them raised an error — each would have produced a
quietly biased sample. Two invariants must hold, both explained in
`docs/dataset-notes.md` §5:

    unexplained_rejects   == 0    nothing silently dropped
    manifest_disagreements == 0   filename and NIST agree on every label

Reads straight from the zips; extracting 200,000 files to answer counting
questions is slow and creates a second copy that can drift from the first.
"""

import posixpath
import zipfile
from collections import Counter
from pathlib import Path

from pydantic import BaseModel, Field

from vulnlm.build.juliet import (
    ParsedName,
    flow_type,
    is_cross_file,
    is_support_file,
    parse_name,
)
from vulnlm.build.sard import parse_manifest
from vulnlm.build.suites import (
    ACTIVE_SUITES,
    SOURCE_EXTENSIONS,
    Suite,
    find_archive,
    sha256_file,
)

# How many offending names to keep. Enough to diagnose without turning the
# report into a file listing; the assertion is on the count, not the sample.
_MAX_EXAMPLES = 10


class SuiteSurvey(BaseModel):
    """Everything counted for one archive."""

    key: str
    version: str
    archive: str
    archive_sha256: str

    source_files: int = 0
    support_files: int = 0
    parsed_files: int = 0

    # MUST be zero. Files that are neither scaffolding nor a parseable case.
    unexplained_rejects: int = 0
    reject_examples: list[str] = Field(default_factory=list)

    cases: int = 0
    cwe_ids: list[str] = Field(default_factory=list)
    cross_file_cases: int = 0

    @property
    def cwes(self) -> int:
        return len(self.cwe_ids)

    flow_types: dict[str, int] = Field(default_factory=dict)
    header_files: int = 0
    windows_only_files: int = 0
    # Filenames that state bad/good outright — a §4.1 leakage surface.
    variant_declaring_files: int = 0

    # Reconciliation against the suite's own manifest.xml.
    manifest_present: bool = False
    manifest_repaired_lines: list[int] = Field(default_factory=list)
    manifest_overlap: int = 0
    manifest_agreements: int = 0
    manifest_disagreements: int = 0
    disagreement_examples: list[str] = Field(default_factory=list)
    orphan_flaw_entries: int = 0
    flaw_lines: int = 0

    @property
    def ok(self) -> bool:
        return self.unexplained_rejects == 0 and self.manifest_disagreements == 0


class Survey(BaseModel):
    """The whole dataset, and how its CWEs divide between the suites.

    Both sampling strata are visible here. `shared_cwes` is the population
    stratum A draws from; `exclusive_cwes["c-cpp"]` is where stratum B's
    memory-safety CWEs come from. Reporting only the intersection would hide
    half the design — and, as it happens, all of the memory-safety CWEs, since
    none of them exist outside C/C++.
    """

    suites: list[SuiteSurvey] = Field(default_factory=list)

    # Present in EVERY active suite. Moves whenever the scope in suites.py
    # changes, so it is computed rather than written down.
    shared_cwes: list[str] = Field(default_factory=list)
    # Present in exactly one suite: {suite key -> CWE ids}.
    exclusive_cwes: dict[str, list[str]] = Field(default_factory=dict)

    # Shared AND actually drawable: every (suite x flow group) cell non-empty
    # after the §5.2 exclusions.
    #
    # This is the number that matters, and it is far smaller than
    # `shared_cwes`. CWE-15 is "shared" but all 48 of its C/C++ cases are
    # Win32-only, so after exclusion it is Java-only in practice; CWE-90 and
    # CWE-327 fail the same way. Reporting only the raw intersection
    # advertises CWEs that cannot be sampled.
    sampleable_cwes: list[str] = Field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.suites)


def _iter_case_files(zf: zipfile.ZipFile) -> tuple[list[str], list[str], list[str]]:
    """Split archive members into (support, parsed-ok, unexplained)."""
    support: list[str] = []
    parsed: list[str] = []
    rejected: list[str] = []

    for name in zf.namelist():
        if name.endswith("/"):
            continue
        if posixpath.splitext(name)[1].lower() not in SOURCE_EXTENSIONS:
            continue
        if is_support_file(name):
            support.append(name)
        elif parse_name(name) is not None:
            parsed.append(name)
        else:
            rejected.append(name)

    return support, parsed, rejected


def survey_suite(suite: Suite, raw_dir: Path) -> SuiteSurvey:
    """Count one archive and reconcile it against its manifest."""
    archive = find_archive(suite, raw_dir)
    result = SuiteSurvey(
        key=suite.key,
        version=suite.version,
        archive=archive.name,
        archive_sha256=sha256_file(archive),
    )

    with zipfile.ZipFile(archive) as zf:
        support, parsed_names, rejected = _iter_case_files(zf)

        result.source_files = len(support) + len(parsed_names) + len(rejected)
        result.support_files = len(support)
        result.parsed_files = len(parsed_names)
        result.unexplained_rejects = len(rejected)
        result.reject_examples = rejected[:_MAX_EXAMPLES]

        parsed: dict[str, ParsedName] = {}
        cases: dict[str, ParsedName] = {}
        for name in parsed_names:
            p = parse_name(name)
            assert p is not None  # filtered above
            parsed[posixpath.basename(name)] = p
            cases.setdefault(p.case_id, p)

        result.cases = len(cases)
        result.cwe_ids = sorted(
            {p.cwe_id for p in parsed.values()}, key=lambda c: int(c.split("-")[1])
        )
        result.cross_file_cases = sum(
            1 for p in cases.values() if is_cross_file(p.flow_variant)
        )
        result.flow_types = dict(
            Counter(flow_type(p.flow_variant) for p in parsed.values()).most_common()
        )
        result.header_files = sum(1 for p in parsed.values() if p.is_header)
        result.windows_only_files = sum(1 for p in parsed.values() if p.windows_only)
        # Filenames that state bad-vs-good outright — a §4.1 leakage surface.
        result.variant_declaring_files = sum(
            1 for p in parsed.values() if p.variant is not None
        )

        if suite.manifest_member:
            result.manifest_present = True
            flaws, repaired_lines = parse_manifest(
                zf.read(suite.manifest_member).decode("utf-8")
            )
            result.manifest_repaired_lines = repaired_lines
            result.flaw_lines = sum(len(v) for v in flaws.values())

            # A file can declare several flaws, usually the same CWE on several
            # lines. So this is a membership test, not an equality test.
            declared = {b: {f.cwe_id for f in v} for b, v in flaws.items()}
            overlap = set(parsed) & set(flaws)
            disagreements = [
                b for b in sorted(overlap) if parsed[b].cwe_id not in declared[b]
            ]
            result.manifest_overlap = len(overlap)
            result.manifest_disagreements = len(disagreements)
            result.manifest_agreements = len(overlap) - len(disagreements)
            result.disagreement_examples = [
                f"{b}: filename={parsed[b].cwe_id} manifest={sorted(declared[b])}"
                for b in disagreements[:_MAX_EXAMPLES]
            ]
            # A flaw entry with no matching source file means the parser lost
            # a file the suite says exists — the same defect as a reject, seen
            # from the other side.
            result.orphan_flaw_entries = len(set(flaws) - set(parsed))

    return result


def _by_cwe_number(cwe_id: str) -> int:
    return int(cwe_id.split("-")[1])


def _sampleable(raw_dir: Path, suites: tuple[Suite, ...], shared: set[str]) -> list[str]:
    """Shared CWEs whose every (suite x flow group) cell survives the §5.2
    exclusions. Imported here rather than at module scope to keep `survey`'s
    dependency on sampling policy explicit and local."""
    from vulnlm.build.sample import flow_group_of, is_eligible

    cells: dict[str, set[tuple[str, str]]] = {c: set() for c in shared}
    for suite in suites:
        with zipfile.ZipFile(find_archive(suite, raw_dir)) as zf:
            _, parsed_names, _ = _iter_case_files(zf)
            for name in parsed_names:
                p = parse_name(name)
                if p is None or p.cwe_id not in cells or not is_eligible(p):
                    continue
                group = flow_group_of(p)
                assert group is not None
                cells[p.cwe_id].add((suite.key, group.value))

    expected = len(suites) * 2  # baseline and cross_file, per suite
    return sorted(
        (c for c, seen in cells.items() if len(seen) == expected), key=_by_cwe_number
    )


def survey_dataset(raw_dir: Path, suites: tuple[Suite, ...] = ACTIVE_SUITES) -> Survey:
    """Survey every active suite and work out how their CWEs divide."""
    per_suite = [survey_suite(s, raw_dir) for s in suites]

    # Derived from the per-suite results rather than by re-walking the
    # archives: a second pass would double the runtime and could disagree with
    # the first if the two ever drifted apart.
    sets = {s.key: set(s.cwe_ids) for s in per_suite}
    shared = set.intersection(*sets.values()) if sets else set()
    exclusive = {
        key: sorted(
            ids - set.union(*(v for k, v in sets.items() if k != key), set()),
            key=_by_cwe_number,
        )
        for key, ids in sets.items()
    }

    return Survey(
        suites=per_suite,
        shared_cwes=sorted(shared, key=_by_cwe_number),
        exclusive_cwes=exclusive,
        sampleable_cwes=_sampleable(raw_dir, suites, shared),
    )
