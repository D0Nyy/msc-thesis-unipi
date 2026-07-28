"""Tests for the stratified sampler.

Split in two. The pure-function tests always run. The tests that need the
actual 285 MB of archives are marked `integration` and skip when `data/raw` is
empty, so a fresh clone can still run the suite.

The property that matters most here is reproducibility: the committed manifest
is the thing that makes the experiment repeatable, and a sampler that quietly
depends on dict or archive ordering would produce a different sample on a
different machine while looking perfectly deterministic on this one.
"""

from pathlib import Path

import pytest

from vulnlm.build.juliet import parse_name
from vulnlm.build.sample import (
    BAD_ONLY_CWES,
    CROSS_LANGUAGE_CWES,
    DEFAULT_SEED,
    MEMORY_SAFETY_CWES,
    WEB_INJECTION_CWES,
    build_manifest,
    flow_group_of,
    is_eligible,
)
from vulnlm.build.suites import ACTIVE_SUITES
from vulnlm.schema import FlowGroup, StratumKind

RAW = Path("data/raw")
HAS_ARCHIVES = RAW.is_dir() and any(RAW.glob("*.zip"))
integration = pytest.mark.skipif(
    not HAS_ARCHIVES, reason="Juliet archives not present in data/raw"
)


def _p(name: str):
    parsed = parse_name(name)
    assert parsed is not None, name
    return parsed


# Building a manifest costs ~5s: it hashes 285 MB of archives and walks 150,000
# members. Module-scoped so the integration tests share one build each rather
# than paying for eleven.


@pytest.fixture(scope="module")
def manifest_n1():
    return build_manifest(RAW, per_stratum=1)


@pytest.fixture(scope="module")
def manifest_n2():
    return build_manifest(RAW, per_stratum=2, seed=DEFAULT_SEED)


@pytest.fixture(scope="module")
def manifest_n4():
    return build_manifest(RAW, per_stratum=4, seed=DEFAULT_SEED)


class TestFlowGroup:
    def test_baseline_is_01(self) -> None:
        assert flow_group_of(_p("CWE476_NULL_Pointer_Dereference__char_01.c")) is FlowGroup.BASELINE

    def test_cross_file_variants(self) -> None:
        assert flow_group_of(_p("CWE476_NULL_Pointer_Dereference__char_54a.c")) is FlowGroup.CROSS_FILE

    def test_22_counts_as_cross_file(self) -> None:
        """Control-flow band, but sinks live in a separate file."""
        assert flow_group_of(_p("CWE78_OS_Command_Injection__char_console_execl_22a.c")) is FlowGroup.CROSS_FILE

    def test_middle_variants_excluded(self) -> None:
        """Single-file control and data flow are in neither sampling group."""
        assert flow_group_of(_p("CWE190_Integer_Overflow__int_fscanf_add_17.c")) is None
        assert flow_group_of(_p("CWE190_Integer_Overflow__int_fscanf_add_45.c")) is None


class TestEligibility:
    def test_bad_only_cwes_excluded(self) -> None:
        """CWE-506/510 have no `good` variant, so no negative class (§8.4)."""
        p = _p("CWE506_Embedded_Malicious_Code__basic_01.java")
        assert p.cwe_id in BAD_ONLY_CWES
        assert not is_eligible(p)

    def test_win32_excluded(self) -> None:
        """Win32 cases need MSVC; two compilers would confound the fidelity axis."""
        p = _p("CWE114_Process_Control__w32_char_connect_socket_01.c")
        assert p.windows_only
        assert not is_eligible(p)

    def test_middle_flow_variant_excluded(self) -> None:
        assert not is_eligible(_p("CWE190_Integer_Overflow__int_fscanf_add_17.c"))

    def test_ordinary_case_eligible(self) -> None:
        assert is_eligible(_p("CWE190_Integer_Overflow__int_fscanf_add_01.c"))


ALL_ARMS = (CROSS_LANGUAGE_CWES, MEMORY_SAFETY_CWES, WEB_INJECTION_CWES)


class TestCweSelection:
    def test_arms_are_disjoint(self) -> None:
        """A CWE in two arms would be drawn twice and pooled by accident."""
        for i, a in enumerate(ALL_ARMS):
            for b in ALL_ARMS[i + 1 :]:
                assert not (set(a) & set(b))

    def test_no_bad_only_cwes_selected(self) -> None:
        selected = set().union(*(set(a) for a in ALL_ARMS))
        assert not (selected & BAD_ONLY_CWES)


@integration
class TestManifest:
    def test_every_expected_cell_is_reported(self, manifest_n1) -> None:
        """Strata are emitted even when empty — a hole must not be invisible."""
        expected = len(FlowGroup) * (
            len(CROSS_LANGUAGE_CWES) * len(ACTIVE_SUITES)
            + len(MEMORY_SAFETY_CWES)  # c-cpp only
            + len(WEB_INJECTION_CWES)  # java only
        )
        assert len(manifest_n1.strata) == expected

    def test_web_injection_arm_is_java_only(self, manifest_n1) -> None:
        suites = {
            s.suite for s in manifest_n1.strata if s.kind is StratumKind.WEB_INJECTION
        }
        assert suites == {"java"}

    def test_no_empty_cells_with_current_selection(self, manifest_n1) -> None:
        """The CWEs were chosen so every cell is populated. If this fails, the
        dataset or the selection changed and the design is unbalanced."""
        assert [s for s in manifest_n1.strata if s.available == 0] == []

    def test_memory_safety_arm_is_c_cpp_only(self, manifest_n1) -> None:
        suites = {
            s.suite for s in manifest_n1.strata if s.kind is StratumKind.MEMORY_SAFETY
        }
        assert suites == {"c-cpp"}

    def test_selected_cases_match_strata_counts(self, manifest_n2) -> None:
        assert len(manifest_n2.cases) == sum(s.selected for s in manifest_n2.strata)

    def test_exclusions_hold_in_the_drawn_sample(self, manifest_n2) -> None:
        assert all(not c.windows_only for c in manifest_n2.cases)
        assert all(c.cwe_id not in BAD_ONLY_CWES for c in manifest_n2.cases)
        assert all(c.flow_group in set(FlowGroup) for c in manifest_n2.cases)

    def test_multi_file_cases_carry_all_their_files(self, manifest_n4) -> None:
        cross = [c for c in manifest_n4.cases if c.flow_group is FlowGroup.CROSS_FILE]
        assert cross, "expected some cross-file cases"
        # A cross-file case is split across at least two source files; if only
        # one is carried, §4.2 cannot assemble the source with the sink.
        assert all(len(c.files) >= 2 for c in cross)

    def test_cases_are_sorted(self, manifest_n2) -> None:
        """Stable order, so a committed manifest diffs cleanly."""
        ids = [c.case_id for c in manifest_n2.cases]
        assert ids == sorted(ids)


@integration
class TestReproducibility:
    def test_same_seed_gives_identical_manifest(self, manifest_n2) -> None:
        again = build_manifest(RAW, per_stratum=2, seed=DEFAULT_SEED)
        assert [c.case_id for c in again.cases] == [
            c.case_id for c in manifest_n2.cases
        ]
        assert again.suite_sha256 == manifest_n2.suite_sha256
        assert [c.source_sha256 for c in again.cases] == [
            c.source_sha256 for c in manifest_n2.cases
        ]

    def test_different_seed_gives_a_different_sample(self, manifest_n2) -> None:
        other = build_manifest(RAW, per_stratum=2, seed=DEFAULT_SEED + 1)
        assert [c.case_id for c in other.cases] != [
            c.case_id for c in manifest_n2.cases
        ]

    def test_growing_a_cell_extends_rather_than_reshuffles(
        self, manifest_n2, manifest_n4
    ) -> None:
        """Per-cell seeding means enlarging the sample keeps the smaller one's
        cells intact — so a pilot's strata stay comparable to the full run."""
        assert len(manifest_n4.cases) > len(manifest_n2.cases)
        by_cell_small = {(s.cwe_id, s.suite, s.flow_group) for s in manifest_n2.strata}
        by_cell_large = {(s.cwe_id, s.suite, s.flow_group) for s in manifest_n4.strata}
        assert by_cell_small == by_cell_large
