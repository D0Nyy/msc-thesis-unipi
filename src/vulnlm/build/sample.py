"""Draw the stratified sample and emit the committed manifest (protocol §5.2).

A stratum is CWE x language x flow group, split across two arms that are never
pooled: a cross-language arm, and a C/C++-only memory-safety arm that exists
because no memory-safety CWE has a counterpart in Java.

Reproducibility is the whole point of this module. The same seed against the
same archives must produce a byte-identical manifest, which is why the sample
is drawn from a sorted population with a per-stratum seeded RNG rather than
from dict or zip iteration order.
"""

import hashlib
import posixpath
import zipfile
from collections import defaultdict
from pathlib import Path
from random import Random

from vulnlm.build.juliet import ParsedName, is_cross_file, is_support_file, parse_name
from vulnlm.build.suites import (
    ACTIVE_SUITES,
    SOURCE_EXTENSIONS,
    Suite,
    find_archive,
    sha256_file,
)
from vulnlm.schema import (
    Case,
    FlowGroup,
    GroundTruth,
    Manifest,
    Stratum,
    StratumKind,
)

DEFAULT_SEED = 20260728

# --------------------------------------------------------------------------- #
# CWE selection
# --------------------------------------------------------------------------- #
#
# Chosen, not sampled. Coverage is not the constraint -- 59 CWEs are available
# in both suites -- so the selection is made on scientific grounds: spread
# across weakness classes, and each one recognisable to a reviewer.

# Only 14 of the 57 eligible shared CWEs have all four cells (suite x flow
# group) populated. These six are chosen from those 14 for spread across
# weakness classes; the number in each comment is the smallest cell, which
# caps how large --per-stratum can usefully go.
#
# Crypto (CWE-327) and hardcoded credentials (CWE-259) were the obvious picks
# and had to be dropped: 100% of their C/C++ cases use Win32 APIs
# (CryptGenRandom, LogonUser), so excluding Win32 to keep one compiler leaves
# them with no C/C++ arm at all.
CROSS_LANGUAGE_CWES: dict[str, str] = {
    "CWE-78": "OS command injection - taint to external process (min cell 12)",
    "CWE-23": "Relative path traversal - taint to filesystem (min cell 12)",
    "CWE-134": "Uncontrolled format string - taint to formatter (min cell 18)",
    "CWE-190": "Integer overflow - numeric, no external sink (min cell 90)",
    "CWE-369": "Divide by zero - numeric, different failure mode (min cell 18)",
    "CWE-789": "Uncontrolled memory allocation - resource exhaustion (min cell 20)",
}

# C/C++ only. These are the flaw classes binary analysis is principally about
# and where F2's loss of types and bounds should hurt most.
MEMORY_SAFETY_CWES: dict[str, str] = {
    "CWE-121": "Stack-based buffer overflow",
    "CWE-122": "Heap-based buffer overflow",
    "CWE-415": "Double free",
    "CWE-416": "Use after free",
    "CWE-401": "Memory leak",
}

# Java only. Juliet's C/C++ suite models systems programming -- libc, sockets,
# filesystem -- so SQL and web injection have no C/C++ counterpart at all
# (CWE-89: 0 cases in C/C++, 2,220 in Java). That is NIST's scope decision, not
# a property of the language.
#
# This arm serves RQ4 and external validity, NOT RQ1. Java's walk is F0->F1,
# which is near-lossless, so it says little about fidelity. It exists because
# evaluating Java only on CWEs that happen to also exist in C is a strange
# sample of "Java vulnerabilities" -- no SQL injection, no XSS. Reported
# separately and never pooled with the fidelity analysis.
#
# Deserialization (CWE-502) is absent from BOTH suites, as is generic XSS
# (CWE-79). Juliet 1.3 does not model them; Vul4J would be the source if they
# are wanted later.
WEB_INJECTION_CWES: dict[str, str] = {
    "CWE-89": "SQL injection (min cell 60)",
    "CWE-80": "Cross-site scripting, basic (min cell 18)",
    "CWE-113": "HTTP response splitting (min cell 36)",
    "CWE-643": "XPath injection (min cell 12)",
    "CWE-470": "Unsafe reflection - class name from untrusted input (min cell 12)",
}

# No `good` variant exists for these (User Guide Appendix D), so they have no
# negative class and cannot contribute to precision or FPR.
BAD_ONLY_CWES: set[str] = {"CWE-506", "CWE-510"}


# --------------------------------------------------------------------------- #
# Collecting the population
# --------------------------------------------------------------------------- #


class CaseFiles:
    """The files belonging to one case, and the parse of one of them.

    All files in a case share CWE, flow variant and functional variant, so any
    one of them describes the case; only the sub-file identifier differs.
    """

    __slots__ = ("head", "paths")

    def __init__(self, head: ParsedName, paths: list[str]) -> None:
        self.head = head
        self.paths = paths


def collect_cases(zf: zipfile.ZipFile) -> dict[str, CaseFiles]:
    """Group an archive's test-case files by case_id."""
    grouped: dict[str, list[tuple[str, ParsedName]]] = defaultdict(list)

    for name in zf.namelist():
        if name.endswith("/"):
            continue
        if posixpath.splitext(name)[1].lower() not in SOURCE_EXTENSIONS:
            continue
        if is_support_file(name):
            continue
        if (p := parse_name(name)) is not None:
            grouped[p.case_id].append((name, p))

    cases: dict[str, CaseFiles] = {}
    for case_id, entries in grouped.items():
        entries.sort(key=lambda e: e[0])
        # Prefer a non-header file as the descriptor: headers carry no language
        # of their own and are typed C++ by fallback.
        head = next((p for _, p in entries if not p.is_header), entries[0][1])
        cases[case_id] = CaseFiles(head, [name for name, _ in entries])
    return cases


def flow_group_of(p: ParsedName) -> FlowGroup | None:
    """Which sampling group a case belongs to, or None if neither."""
    if p.flow_variant == "01":
        return FlowGroup.BASELINE
    return FlowGroup.CROSS_FILE if is_cross_file(p.flow_variant) else None


def is_eligible(p: ParsedName) -> bool:
    """Exclusions from protocol §5.2, applied before any draw."""
    if p.cwe_id in BAD_ONLY_CWES:
        return False
    # Win32 variants need MSVC; mixing compilers would confound the fidelity
    # axis with the toolchain.
    if p.windows_only:
        return False
    return flow_group_of(p) is not None


# --------------------------------------------------------------------------- #
# Drawing
# --------------------------------------------------------------------------- #


def _case_sha256(zf: zipfile.ZipFile, paths: list[str]) -> str:
    """Hash of a case's concatenated sources, in sorted path order.

    Ties the manifest to exact file contents, so a re-released archive with the
    same name is detected rather than silently substituted.
    """
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(zf.read(path))
    return digest.hexdigest()


def _to_case(
    zf: zipfile.ZipFile, cf: CaseFiles, kind: StratumKind, group: FlowGroup
) -> Case:
    p = cf.head
    return Case(
        case_id=p.case_id,
        language=p.language,
        cwe_id=p.cwe_id,
        cwe_name=p.cwe_name,
        secondary_cwe_id=p.secondary_cwe_id,
        functional_variant=p.functional_variant,
        flow_variant=p.flow_variant,
        flow_group=group,
        stratum=kind,
        files=sorted(cf.paths),
        source_sha256=_case_sha256(zf, cf.paths),
        windows_only=p.windows_only,
    )


# Which suites each arm draws from. The cross-language arm takes every active
# suite; the other two are single-language by definition, because the flaw
# classes they cover do not exist in the other suite.
_ARM_SUITES: dict[StratumKind, set[str] | None] = {
    StratumKind.CROSS_LANGUAGE: None,  # all active suites
    StratumKind.MEMORY_SAFETY: {"c-cpp"},
    StratumKind.WEB_INJECTION: {"java"},
}


def _applies(suite: Suite, kind: StratumKind) -> bool:
    allowed = _ARM_SUITES[kind]
    return allowed is None or suite.key in allowed


def build_manifest(
    raw_dir: Path,
    per_stratum: int,
    seed: int = DEFAULT_SEED,
    suites: tuple[Suite, ...] = ACTIVE_SUITES,
) -> Manifest:
    """Draw `per_stratum` cases from every CWE x language x flow-group cell.

    Everything is accumulated locally and the Manifest is constructed once at
    the end: Strict models are frozen, so a manifest cannot be assembled by
    mutation. That is deliberate — a manifest is evidence, and evidence built
    in place can be half-built.
    """
    selected: list[Case] = []
    strata: list[Stratum] = []
    suite_versions: dict[str, str] = {}
    suite_sha256: dict[str, str] = {}

    arms: list[tuple[StratumKind, dict[str, str]]] = [
        (StratumKind.CROSS_LANGUAGE, CROSS_LANGUAGE_CWES),
        (StratumKind.MEMORY_SAFETY, MEMORY_SAFETY_CWES),
        (StratumKind.WEB_INJECTION, WEB_INJECTION_CWES),
    ]

    for suite in suites:
        archive = find_archive(suite, raw_dir)
        suite_versions[suite.key] = suite.version
        suite_sha256[suite.key] = sha256_file(archive)

        with zipfile.ZipFile(archive) as zf:
            cases = collect_cases(zf)

            # Bucket the eligible population once: cell -> sorted case ids.
            # Sorted because dict order reflects zip layout, and a sample that
            # depends on archive ordering is not reproducible in any useful
            # sense.
            buckets: dict[tuple[str, FlowGroup], list[str]] = defaultdict(list)
            for case_id, cf in cases.items():
                if not is_eligible(cf.head):
                    continue
                group = flow_group_of(cf.head)
                assert group is not None  # is_eligible guarantees it
                buckets[(cf.head.cwe_id, group)].append(case_id)
            for ids in buckets.values():
                ids.sort()

            for kind, cwes in arms:
                if not _applies(suite, kind):
                    continue
                for cwe_id in sorted(cwes):
                    for group in FlowGroup:
                        pool = buckets.get((cwe_id, group), [])
                        # Emitted even when empty. A cell the design expects but
                        # the dataset cannot fill is the most important thing on
                        # this report, and skipping it makes the hole invisible.
                        take = min(per_stratum, len(pool))
                        strata.append(
                            Stratum(
                                kind=kind,
                                cwe_id=cwe_id,
                                suite=suite.key,
                                flow_group=group,
                                requested=per_stratum,
                                selected=take,
                                available=len(pool),
                            )
                        )
                        if not pool:
                            continue
                        # Seed per cell, so adding a CWE or changing one cell's
                        # size does not reshuffle cells already drawn.
                        rng = Random(f"{seed}:{cwe_id}:{suite.key}:{group}")
                        chosen = rng.sample(pool, take)
                        selected.extend(
                            _to_case(zf, cases[cid], kind, group)
                            for cid in sorted(chosen)
                        )

    return Manifest(
        seed=seed,
        suite_versions=suite_versions,
        suite_sha256=suite_sha256,
        strata=sorted(strata, key=lambda s: (s.kind, s.cwe_id, s.suite, s.flow_group)),
        cases=sorted(selected, key=lambda c: c.case_id),
    )


def ground_truth_for(case: Case, *, vulnerable: bool) -> GroundTruth:
    """Label for one built variant of a case.

    A case yields two binaries — `-DOMITGOOD` and `-DOMITBAD` (§7.1) — so
    `vulnerable` is a property of the build, not of the case, and is supplied
    by the caller rather than derived here.
    """
    return GroundTruth(
        vulnerable=vulnerable,
        cwe_id=case.cwe_id if vulnerable else None,
        cwe_name=case.cwe_name if vulnerable else None,
        variant="bad" if vulnerable else "good",
        flow_variant=case.flow_variant,
    )
