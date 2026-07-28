"""Tests for the Juliet naming convention parser.

These run without the dataset, which is the point — the parser decides what
the ground-truth label IS, and a mistake here does not crash, it produces a
manifest that is confidently wrong. Same failure mode as `eval/` (see
`docs/todo.md`), so it gets the same treatment.

Every filename below is a real Juliet 1.3 name taken from the archives. The
conventions they encode are documented in `build/juliet.py` and sourced from
the User Guide shipped in `doc/`.
"""

import pytest

from vulnlm.build.juliet import (
    flow_type,
    is_cross_file,
    is_support_file,
    parse_name,
)
from vulnlm.schema import Language


class TestPrimaryLabel:
    """The leading CWE is the ground truth. Nothing else is."""

    def test_simple_case(self) -> None:
        p = parse_name("CWE476_NULL_Pointer_Dereference__char_01.c")
        assert p is not None
        assert p.cwe_id == "CWE-476"
        assert p.cwe_name == "NULL_Pointer_Dereference"
        assert p.functional_variant == "char"
        assert p.flow_variant == "01"
        assert p.secondary_cwe_id is None
        assert p.letter is None
        assert p.variant is None

    def test_secondary_cwe_is_not_the_label(self) -> None:
        """The trap. CWE-193 describes the route; CWE-121 is the flaw."""
        p = parse_name(
            "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_01.c"
        )
        assert p is not None
        assert p.cwe_id == "CWE-121"
        assert p.secondary_cwe_id == "CWE-193"
        # Also stripped from the functional variant, or stratifying on that
        # field silently splits the population in two.
        assert p.functional_variant == "char_alloca_cpy"

    def test_zero_padding_normalised(self) -> None:
        a = parse_name("CWE015_External_Control_of_System_Setting__basic_01.c")
        b = parse_name("CWE15_External_Control_of_System_Setting__basic_01.c")
        assert a is not None and b is not None
        assert a.cwe_id == b.cwe_id == "CWE-15"


class TestLanguages:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("CWE476_NULL_Pointer_Dereference__char_01.c", Language.C),
            ("CWE563_Unused_Variable__unused_class_member_01_bad.cpp", Language.CPP),
            ("CWE129_Improper_Validation_of_Array_Index__connect_tcp_01.cs", Language.CSHARP),
            ("CWE129_Improper_Validation_of_Array_Index__connect_tcp_01.java", Language.JAVA),
        ],
    )
    def test_extension_maps_to_language(self, filename: str, expected: Language) -> None:
        p = parse_name(filename)
        assert p is not None
        assert p.language is expected

    def test_unknown_extension_rejected(self) -> None:
        assert parse_name("README.txt") is None
        assert parse_name("Makefile") is None


class TestHeaderFiles:
    """4,300 .h files in the C/C++ suite are test-case files, not support.
    Filtering on .c/.cpp alone drops part of every 81-84 case."""

    def test_header_is_a_case_file(self) -> None:
        p = parse_name("CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_84.h")
        assert p is not None
        assert p.is_header is True
        assert p.cwe_id == "CWE-789"
        assert p.flow_variant == "84"

    def test_header_groups_with_its_sources(self) -> None:
        base = "CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_81"
        ids = {
            parse_name(f"{base}{sfx}").case_id  # type: ignore[union-attr]
            for sfx in (".h", "a.cpp", "_bad.cpp", "_goodG2B.cpp")
        }
        assert len(ids) == 1

    def test_source_is_not_marked_header(self) -> None:
        p = parse_name("CWE476_NULL_Pointer_Dereference__char_01.c")
        assert p is not None
        assert p.is_header is False


class TestSubFileIdentifiers:
    """Two disjoint forms: a letter, or a variant word. Never both."""

    def test_letter_form(self) -> None:
        p = parse_name("CWE476_NULL_Pointer_Dereference__char_54c.c")
        assert p is not None
        assert p.letter == "c"
        assert p.variant is None

    def test_variant_word_form(self) -> None:
        p = parse_name("CWE563_Unused_Variable__unused_class_member_01_bad.cpp")
        assert p is not None
        assert p.variant == "bad"
        assert p.letter is None

    @pytest.mark.parametrize(
        ("suffix", "expected"),
        [
            ("_bad", "bad"),
            ("_good1", "good1"),
            ("_goodG2B", "goodG2B"),
            ("_goodB2G", "goodB2G"),
            ("_base", "base"),
        ],
    )
    def test_all_variant_words(self, suffix: str, expected: str) -> None:
        p = parse_name(f"CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_81{suffix}.cpp")
        assert p is not None
        assert p.variant == expected

    def test_unknown_trailing_word_is_refused(self) -> None:
        """Grammar drift must not be invented into a case."""
        assert parse_name("CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_81_wat.cpp") is None

    def test_parts_collapse_to_one_case_id(self) -> None:
        names = [
            "CWE476_NULL_Pointer_Dereference__char_54a.c",
            "CWE476_NULL_Pointer_Dereference__char_54b.c",
            "CWE476_NULL_Pointer_Dereference__char_54e.c",
        ]
        parsed = [parse_name(n) for n in names]
        assert all(p is not None for p in parsed)
        assert len({p.case_id for p in parsed}) == 1  # type: ignore[union-attr]
        assert [p.letter for p in parsed] == ["a", "b", "e"]  # type: ignore[union-attr]
        assert all(p.case_id.endswith("_54") for p in parsed)  # type: ignore[union-attr]


class TestTrickyFunctionalVariants:
    """Digits inside the functional variant must not be read as the flow
    variant. These break a naive parser."""

    @pytest.mark.parametrize(
        ("filename", "functional", "flow"),
        [
            ("CWE190_Integer_Overflow__int64_t_fscanf_add_01.c", "int64_t_fscanf_add", "01"),
            ("CWE191_Integer_Underflow__int_fscanf_sub_17.c", "int_fscanf_sub", "17"),
            ("CWE590_Free_Memory_Not_on_Heap__free_char_static_34.c", "free_char_static", "34"),
        ],
    )
    def test_digits_in_variant(self, filename: str, functional: str, flow: str) -> None:
        p = parse_name(filename)
        assert p is not None
        assert p.functional_variant == functional
        assert p.flow_variant == flow


class TestSupportFiles:
    @pytest.mark.parametrize(
        "path",
        [
            "C/testcasesupport/io.c",
            "C/testcasesupport/std_testcase.h",
            "src/testcasesupport/AbstractTestCase.java",
            "C/testcases/CWE121_x/main_linux.cpp",
            "src/testcases/CWE113_x/Program.cs",
            "src/testcases/CWE113_x/AssemblyInfo.cs",
            "Java/lib/whatever.java",
            "Java/src/testcases/CWE111_Unsafe_JNI/linux.jni.files/libJNITest.cpp",
            "Java/src/testcases/CWE111_Unsafe_JNI/visual.studio.jni.dll.project/JNITest/dllmain.cpp",
            "src/testcases/CWE586_x/CWE586_Explicit_Call_to_Finalize__basic_Helper.java",
            "TestCaseSupport/IO.cs",  # case-insensitive
        ],
    )
    def test_support_files_rejected(self, path: str) -> None:
        assert is_support_file(path)
        assert parse_name(path) is None

    def test_real_case_not_flagged_as_support(self) -> None:
        path = "C/testcases/CWE476_x/CWE476_NULL_Pointer_Dereference__char_01.c"
        assert not is_support_file(path)
        assert parse_name(path) is not None


class TestWindowsOnly:
    def test_w32_flagged(self) -> None:
        p = parse_name("CWE114_Process_Control__w32_char_connect_socket_01.c")
        assert p is not None
        assert p.windows_only is True

    def test_portable_not_flagged(self) -> None:
        p = parse_name("CWE476_NULL_Pointer_Dereference__char_01.c")
        assert p is not None
        assert p.windows_only is False


class TestFlowType:
    """The suite's own three-way split: 01 baseline, 02-22 control, 31+ data."""

    @pytest.mark.parametrize(
        ("flow", "expected"),
        [
            ("01", "baseline"),
            ("02", "control"),
            ("18", "control"),
            ("22", "control"),
            ("31", "data"),
            ("45", "data"),
            ("54", "data"),
            ("74", "data"),
            ("84", "data"),
        ],
    )
    def test_types(self, flow: str, expected: str) -> None:
        assert flow_type(flow) == expected

    def test_reserved_gap_is_unknown(self) -> None:
        """23-30 is reserved for expansion and currently empty."""
        assert flow_type("25") == "unknown"

    def test_garbage_reported_not_raised(self) -> None:
        assert flow_type("zz") == "unknown"


class TestCrossFile:
    def test_22_is_cross_file_despite_being_control_flow(self) -> None:
        """The one a range-based rule gets wrong: sinks live in a separate
        file from sources, inside the control-flow band."""
        assert flow_type("22") == "control"
        assert is_cross_file("22")

    @pytest.mark.parametrize("flow", ["51", "54", "61", "68", "72", "74", "81", "84"])
    def test_cross_file_bands(self, flow: str) -> None:
        assert is_cross_file(flow)

    @pytest.mark.parametrize("flow", ["01", "02", "18", "31", "34", "41", "45"])
    def test_single_file_bands(self, flow: str) -> None:
        assert not is_cross_file(flow)

    def test_garbage_is_not_cross_file(self) -> None:
        assert not is_cross_file("zz")
