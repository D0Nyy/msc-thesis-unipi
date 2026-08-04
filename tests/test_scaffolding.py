"""The scaffolding denylist must match the archives, not the author's memory.

Every constant in `build/scaffolding.py` was derived by parsing Juliet's support
files. These tests re-derive them and fail on disagreement, so the list cannot
drift away from the suite it describes.

That matters more here than for most constants. A missing entry does not crash
anything — it leaves a Juliet fingerprint in a prompt, the model recognises the
corpus, and the contamination threat in §11.1 quietly comes true while every
test still passes.
"""

import re
import zipfile
from pathlib import Path

import pytest

from vulnlm.build.scaffolding import (
    C_GLOBALS,
    C_IO_FUNCTIONS,
    C_SCAFFOLDING,
    C_STUBS,
    C_THREAD_HELPERS,
    JAVA_BASE_CLASSES,
    JAVA_SUPPORT_METHODS,
    VARIANT_NAMES,
)

C_ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip")
J_ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-java-v1-3.zip")

needs_c = pytest.mark.skipif(not C_ARCHIVE.exists(), reason="C/C++ archive absent")
needs_java = pytest.mark.skipif(not J_ARCHIVE.exists(), reason="Java archive absent")


def _support_text(archive: Path, marker: str, exclude: str | None = None) -> str:
    with zipfile.ZipFile(archive) as zf:
        return "\n".join(
            zf.read(n).decode("utf-8", "replace")
            for n in zf.namelist()
            if marker in n
            and n.endswith((".h", ".c", ".java"))
            and (exclude is None or exclude not in n)
        )


@pytest.fixture(scope="module")
def c_support() -> str:
    # `testcases.h` is excluded: it is a generated index declaring all 77,567
    # case functions, so including it would put every case name in the denylist.
    return _support_text(C_ARCHIVE, "testcasesupport/", exclude="testcases.h")


@needs_c
class TestCSurface:
    def test_io_helpers_all_present(self, c_support: str) -> None:
        found = {
            m for m in re.findall(r"\b(print\w*Line|printLine|decodeHex\w+)\b", c_support)
        }
        assert found <= C_IO_FUNCTIONS, f"undeclared scaffolding: {found - C_IO_FUNCTIONS}"
        assert C_IO_FUNCTIONS <= found, f"stale entries: {C_IO_FUNCTIONS - found}"

    def test_globals_all_present(self, c_support: str) -> None:
        found = set(re.findall(r"\b(global\w+)\b", c_support))
        assert found == C_GLOBALS

    def test_thread_helpers_all_present(self, c_support: str) -> None:
        found = set(re.findall(r"\b(stdThread\w+)\b", c_support))
        assert found == C_THREAD_HELPERS

    def test_stubs_exist_and_collide_with_the_oracle(self, c_support: str) -> None:
        # io.c defines empty `bad1()`..`bad9()`. They land in every binary, so
        # any substring-based oracle would score them as flaw code.
        assert re.search(r"void\s+bad1\s*\(", c_support) is not None
        assert {"bad1", "good1"} <= C_STUBS

    def test_libc_is_not_in_the_denylist(self) -> None:
        # §4.1 keeps real library calls: a human analyst sees them, so they are
        # signal. Scrubbing them would destroy the API-call evidence the whole
        # F2 argument rests on.
        for name in ("printf", "puts", "free", "malloc", "strcpy", "memmove"):
            assert name not in C_SCAFFOLDING


@pytest.fixture(scope="module")
def java_support() -> str:
    return _support_text(J_ARCHIVE, "Java/src/testcasesupport/")


@needs_java
class TestJavaSurface:
    def test_base_classes_all_present(self, java_support: str) -> None:
        declared = set(re.findall(r"(?:class|interface)\s+(AbstractTestCase\w*)", java_support))
        assert declared == JAVA_BASE_CLASSES

    def test_io_methods_present(self, java_support: str) -> None:
        for method in ("writeLine", "staticReturnsTrue", "getDBConnection"):
            assert method in JAVA_SUPPORT_METHODS
            assert re.search(rf"\b{method}\s*\(", java_support)


class TestVariantNames:
    def test_covers_the_oracle_vocabulary(self) -> None:
        # The scrubber and the build-stage oracle must agree on what a variant
        # is called, or one will rename something the other still expects.
        from vulnlm.build.compile import BAD_TAILS, GOOD_TAILS

        assert BAD_TAILS <= VARIANT_NAMES
        assert GOOD_TAILS <= VARIANT_NAMES

    def test_bad_and_good_are_the_label_itself(self) -> None:
        # Stated as a test because it is the reason this set exists at all.
        assert {"bad", "good", "goodG2B", "goodB2G"} <= VARIANT_NAMES
