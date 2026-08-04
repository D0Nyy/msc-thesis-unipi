"""Tests for the build stage (protocol §7.1).

Two halves. The pure functions — source selection, the symbol oracle, the
retention arithmetic — are tested directly, because a mistake in any of them
produces a plausible wrong number rather than a crash: a case silently built
with both variants in it, or a flaw scored against the wrong function.

The compiler-dependent half is behind `needs_toolchain`. It is not the same
test twice: it checks that gcc and nm actually agree with what the pure
functions assume, which is the assumption most likely to rot when the
toolchain moves.
"""

import shutil
import subprocess
import textwrap
from pathlib import Path
from typing import ClassVar

import pytest

from vulnlm.build.compile import (
    BAD_TAILS,
    COMMON_FLAGS,
    GOOD_TAILS,
    SURVIVAL_THRESHOLD,
    compiler_for,
    path_sizes,
    retained,
    select_sources,
    standard_flag,
    strip_copy,
    symbol_tail,
)

needs_toolchain = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("gcc", "g++", "nm", "objcopy")),
    reason="needs gcc, g++, nm and objcopy on PATH",
)


class TestSelectSources:
    """Which files go into which binary.

    This is the check that matters most in the module. Getting it wrong in one
    direction fails loudly at link time; getting it wrong in the other puts
    good and bad code in one binary, which builds fine and quietly destroys the
    negative class.
    """

    SIMPLE: ClassVar[list[str]] = ["C/testcases/x/CWE121_Stack_Based_Buffer_Overflow__char_alloca_cpy_01.c"]

    def test_plain_case_goes_in_both(self) -> None:
        assert select_sources(self.SIMPLE, bad=True) == self.SIMPLE
        assert select_sources(self.SIMPLE, bad=False) == self.SIMPLE

    # The 23 flow-01 cases that state the variant in the filename. Each file
    # carries its own main() outside the OMIT guards, so compiling the pair
    # gives two mains and the link fails.
    GOOD1: ClassVar[list[str]] = [
        "C/testcases/x/CWE401_Memory_Leak__destructor_01_bad.cpp",
        "C/testcases/x/CWE401_Memory_Leak__destructor_01_good1.cpp",
    ]

    def test_variant_files_are_split(self) -> None:
        assert select_sources(self.GOOD1, bad=True) == [self.GOOD1[0]]
        assert select_sources(self.GOOD1, bad=False) == [self.GOOD1[1]]

    # The 81-84 family: a shared `a` part with main(), a header, and one file
    # per variant. The good files are wholly inside `#ifndef OMITGOOD`, so the
    # preprocessor would also handle them — but selecting by variant is correct
    # here too, which is why it is applied unconditionally.
    FAMILY_81: ClassVar[list[str]] = [
        "C/testcases/x/CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81.h",
        "C/testcases/x/CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81_bad.cpp",
        "C/testcases/x/CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81_goodB2G.cpp",
        "C/testcases/x/CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81_goodG2B.cpp",
        "C/testcases/x/CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81a.cpp",
    ]

    def test_81_family_bad_side(self) -> None:
        got = select_sources(self.FAMILY_81, bad=True)
        assert [Path(p).name for p in got] == [
            "CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81_bad.cpp",
            "CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_connect_socket_81a.cpp",
        ]

    def test_81_family_good_side_keeps_both_good_files(self) -> None:
        # goodG2B and goodB2G are different functions in one namespace and the
        # `a` part calls both, so the good binary needs them together.
        got = [Path(p).name for p in select_sources(self.FAMILY_81, bad=False)]
        assert sum("_goodG2B.cpp" in n for n in got) == 1
        assert sum("_goodB2G.cpp" in n for n in got) == 1
        assert sum(n.endswith("81a.cpp") for n in got) == 1

    def test_no_variant_file_reaches_the_wrong_binary(self) -> None:
        for bad in (True, False):
            names = [Path(p).name for p in select_sources(self.FAMILY_81, bad=bad)]
            forbidden = "_good" if bad else "_bad."
            assert not any(forbidden in n for n in names)

    def test_headers_are_never_compiled(self) -> None:
        for bad in (True, False):
            assert not any(
                p.endswith(".h") for p in select_sources(self.FAMILY_81, bad=bad)
            )

    def test_output_is_sorted(self) -> None:
        shuffled = list(reversed(self.FAMILY_81))
        assert select_sources(shuffled, bad=True) == select_sources(
            self.FAMILY_81, bad=True
        )


class TestCompilerChoice:
    def test_cpp_anywhere_selects_gxx(self) -> None:
        assert compiler_for(["a.c", "b.cpp"]) == "g++"

    def test_pure_c_selects_gcc(self) -> None:
        assert compiler_for(["a.c", "b.c"]) == "gcc"

    def test_standard_is_pinned_not_inherited(self) -> None:
        # gcc's default moved from gnu17 to gnu23 between 11 and 15, and the
        # newer default rejects code Juliet 1.3 contains. An unpinned build
        # would make the buildable set depend on the host distribution.
        assert standard_flag("gcc").startswith("-std=gnu")
        assert standard_flag("g++").startswith("-std=gnu++")


class TestSymbolTail:
    """Juliet writes the same function two ways; the oracle must see one."""

    CASE = "CWE121_Stack_Based_Buffer_Overflow__CWE805_int_declare_memmove_01"
    CPP_CASE = "CWE121_Stack_Based_Buffer_Overflow__CWE805_wchar_t_alloca_snprintf_74"

    def test_c_flat_symbol(self) -> None:
        assert symbol_tail(f"{self.CASE}_bad", self.CASE) == "bad"

    def test_cpp_namespaced_symbol(self) -> None:
        assert symbol_tail(f"{self.CPP_CASE}::bad()", self.CPP_CASE) == "bad"

    def test_cpp_argument_list_is_dropped(self) -> None:
        name = f"{self.CPP_CASE}::badSink(std::map<int, wchar_t*, std::less<int> >)"
        assert symbol_tail(name, self.CPP_CASE) == "badSink"

    def test_unrelated_symbol_is_rejected(self) -> None:
        assert symbol_tail("printLine", self.CASE) is None
        assert symbol_tail("main", self.CASE) is None

    def test_other_case_prefix_is_rejected(self) -> None:
        # Two cases are linked into different binaries, but a stale artifact or
        # a mis-globbed source would put both in one. The oracle must not
        # attribute another case's flaw to this one.
        assert symbol_tail("CWE416_Use_After_Free__malloc_free_int_01_bad", self.CASE) is None

    def test_tails_cover_juliets_vocabulary(self) -> None:
        assert {"bad", "badSink", "badSource"} == set(BAD_TAILS)
        assert {"goodG2B", "goodB2G", "good1"} <= GOOD_TAILS
        assert not (BAD_TAILS & GOOD_TAILS)


class TestRetained:
    def test_none_when_nothing_to_retain(self) -> None:
        # Guards the division, but also the meaning: 0/0 is "the oracle found
        # no flaw", which is a different finding from "the flaw was erased".
        assert retained(0, 0) is None
        assert retained(0, 40) is None

    def test_erasure(self) -> None:
        r = retained(136, 11)
        assert r is not None and r < SURVIVAL_THRESHOLD

    def test_growth_is_representable(self) -> None:
        # -O2 inlines the sink into the source, so one function absorbs another.
        # Measured up to 250% on the committed sample; clamping this at 1.0
        # would hide the effect §7.1 predicts.
        assert retained(100, 250) == pytest.approx(2.5)

    def test_threshold_is_a_floor_not_a_window(self) -> None:
        assert retained(100, 15) == pytest.approx(SURVIVAL_THRESHOLD)


class TestBuildFlags:
    def test_fortify_is_disabled(self) -> None:
        # Ubuntu's gcc enables _FORTIFY_SOURCE at -O1 and above but not at -O0,
        # which would make the two arms differ in libc API surface as well as
        # optimisation — printf becomes __printf_chk. §4.1 treats API names as
        # signal, so that confound is removed deliberately.
        assert "-U_FORTIFY_SOURCE" in COMMON_FLAGS

    def test_entry_point_is_requested(self) -> None:
        # Without it a case has no main() and will not link.
        assert "-DINCLUDEMAIN" in COMMON_FLAGS

    def test_not_statically_linked(self) -> None:
        # Static linking turns strcpy into an unnamed blob and destroys the
        # PLT-visible API names §7.1 deliberately preserves.
        assert "-static" not in COMMON_FLAGS


# --------------------------------------------------------------------------- #
# Toolchain agreement
# --------------------------------------------------------------------------- #

_C_CASE = "CWE000_Synthetic__probe_01"
_C_SOURCE = textwrap.dedent(
    f"""
    #include <string.h>
    #include <stdio.h>
    void {_C_CASE}_badSource(char *d) {{ strcpy(d, "0123456789"); }}
    void {_C_CASE}_bad(void) {{ char b[4]; {_C_CASE}_badSource(b); puts(b); }}
    void {_C_CASE}_goodG2B(void) {{ char b[32]; strcpy(b, "ok"); puts(b); }}
    int main(void) {{ {_C_CASE}_bad(); {_C_CASE}_goodG2B(); return 0; }}
    """
)


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A synthetic case in Juliet's C naming convention, built for real."""
    d = tmp_path_factory.mktemp("probe")
    src = d / "probe.c"
    src.write_text(_C_SOURCE, encoding="utf-8")
    out = d / "probe.sym"
    subprocess.run(
        ["gcc", standard_flag("gcc"), *COMMON_FLAGS, "-O0", str(src), "-o", str(out)],
        check=True,
        capture_output=True,
    )
    return out


@needs_toolchain
class TestToolchainAgreement:
    """Does the real toolchain behave the way the pure functions assume?"""

    def test_oracle_finds_both_paths(self, built: Path) -> None:
        bad, good, bad_syms, good_syms = path_sizes(built, _C_CASE)
        assert bad > 0 and good > 0
        assert {s.tail for s in bad_syms} == {"bad", "badSource"}
        assert {s.tail for s in good_syms} == {"goodG2B"}

    def test_oracle_records_addresses(self, built: Path) -> None:
        # The address is the whole point: it is the only field that survives
        # into the stripped twin, so it is what joins Ghidra's FUN_<addr> back
        # to `badSink`. A name-only oracle cannot label an F2 chunk at all.
        _, _, bad_syms, _ = path_sizes(built, _C_CASE)
        assert all(s.address > 0 for s in bad_syms)
        assert all(s.size > 0 for s in bad_syms)
        # Sorted by address, and distinct — two functions cannot share a start.
        addrs = [s.address for s in bad_syms]
        assert addrs == sorted(addrs)
        assert len(set(addrs)) == len(addrs)

    def test_oracle_ignores_libc_and_main(self, built: Path) -> None:
        _, _, bad_syms, good_syms = path_sizes(built, _C_CASE)
        names = [s.name for s in bad_syms + good_syms]
        assert not any(n in ("main", "puts", "strcpy") for n in names)

    def test_strip_preserves_machine_code(self, built: Path, tmp_path: Path) -> None:
        # The whole reason for copy-and-strip rather than a second `-s` link:
        # the model's binary and the oracle's must be the same code, so a
        # mismatch later cannot be blamed on the build.
        stripped = tmp_path / "probe.stripped"
        strip_copy(built, stripped)


        def text_of(binary: Path) -> bytes:
            return subprocess.run(
                ["objcopy", "-O", "binary", "--only-section=.text",
                 str(binary), "/dev/stdout"],
                capture_output=True,
                check=False,
            ).stdout

        assert text_of(built) == text_of(stripped)

    def test_stripped_binary_has_no_oracle_symbols(
        self, built: Path, tmp_path: Path
    ) -> None:
        stripped = tmp_path / "probe2.stripped"
        strip_copy(built, stripped)
        bad, good, _, _ = path_sizes(stripped, _C_CASE)
        assert (bad, good) == (0, 0)

    def test_dynamic_api_names_survive_stripping(
        self, built: Path, tmp_path: Path
    ) -> None:
        # §4.1's "API calls are signal" rests on this: the dynamic symbol table
        # is not what --strip-all removes.
        stripped = tmp_path / "probe3.stripped"
        strip_copy(built, stripped)
        out = subprocess.run(
            ["nm", "-D", "--undefined-only", str(stripped)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        assert "puts" in out
