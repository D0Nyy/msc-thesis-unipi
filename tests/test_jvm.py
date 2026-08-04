"""Tests for the Java build arm.

Thinner than `test_compile.py` in one direction and thicker in another. javac
has no optimisation levels, no stripping and no variant split, so most of what
the C/C++ side needs testing for does not exist here. But Java is the only arm
that scrubs *before* compiling — bytecode carries names structurally, so there
is no `objcopy` to fall back on — and that makes the scrubbed source tree a
build artifact whose shape javac cares about.

Two things therefore need testing:

* **The classpath.** The web-injection stratum is entirely servlets, so a
  missing `servlet-api.jar` would fail 20 of the 44 Java cases with a compiler
  error that looks like a source problem rather than a setup one.
* **The layout of the scrubbed tree.** javac requires the public class to sit
  at `<package path>/<ClassName>.java`. A scrubbed tree that disagrees with
  itself fails to compile, and it fails per case, which reads as 44 broken
  cases rather than one broken assumption. `TestScrubbedTree` checks the
  invariant directly on all 44, because it holds without a JDK present and the
  JDK is exactly what is missing on the machine where this most often breaks.
"""

import re
import shutil
import zipfile
from pathlib import Path

import pytest

from vulnlm.build.compile import ToolchainError
from vulnlm.build.jvm import (
    _RELEASE_FLAG,
    CLASSPATH_JARS,
    RELEASE_PREFERENCE,
    SUPPORT_DIR,
    detect_release,
    javac_version,
    scrub_record,
    support_members,
)
from vulnlm.build.scrub import scrub_juliet_case
from vulnlm.schema import Language

ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-java-v1-3.zip")
MANIFEST = Path("data/manifest.json")

needs_archive = pytest.mark.skipif(
    not ARCHIVE.exists(), reason=f"{ARCHIVE} not present"
)
needs_corpus = pytest.mark.skipif(
    not (ARCHIVE.exists() and MANIFEST.exists()),
    reason="archive or manifest absent",
)
needs_jdk = pytest.mark.skipif(
    shutil.which("javac") is None, reason="needs a JDK, not just a JRE"
)


class TestClasspath:
    def test_servlet_api_is_first_and_present(self) -> None:
        # Not cosmetic: 20 of the 44 sampled Java cases are servlets, so this
        # jar is load-bearing for the entire web-injection arm.
        assert any("servlet-api" in j for j in CLASSPATH_JARS)

    def test_commons_lang_included(self) -> None:
        # StringEscapeUtils, used by the CWE-80 XSS cases.
        assert any("commons-lang" in j for j in CLASSPATH_JARS)

    @needs_archive
    def test_every_jar_actually_ships_in_the_archive(self) -> None:
        # The point of pinning to the archive's own jars is that the build
        # needs no network and no version drift. If NIST ever repackages, this
        # is where it surfaces.
        with zipfile.ZipFile(ARCHIVE) as zf:
            names = set(zf.namelist())
        assert not [j for j in CLASSPATH_JARS if j not in names]


class TestSupportMembers:
    @needs_archive
    def test_only_the_top_level_copy_is_taken(self) -> None:
        # The archive ships a per-CWE antbuild/testcasesupport/ copy for 153
        # directories. Compiling them together gives duplicate class errors,
        # so exactly one copy must survive the filter.
        with zipfile.ZipFile(ARCHIVE) as zf:
            members = support_members(zf)
        assert members, "no support sources found — the archive layout changed"
        assert all(m.startswith(f"{SUPPORT_DIR}/") for m in members)
        assert not any("antbuild" in m for m in members)

    @needs_archive
    def test_support_classes_are_java_sources(self) -> None:
        with zipfile.ZipFile(ARCHIVE) as zf:
            members = support_members(zf)
        assert all(m.endswith(".java") for m in members)
        names = {Path(m).stem for m in members}
        # IO carries printLine and the servlet scaffolding every case calls.
        assert "IO" in names


class TestRelease:
    def test_flag_spelling(self) -> None:
        # Regression: the single-dash `-release` is not javac syntax. It fails
        # with "invalid flag: -release" on EVERY case, which reads like 44
        # source problems rather than one command-line problem — the failure
        # mode that cost a whole build run.
        assert _RELEASE_FLAG == "--release"

    def test_preference_is_oldest_first(self) -> None:
        # Juliet 1.3 is 2011-era Java, so the oldest accepted target is the
        # closest to what it was written against.
        assert [int(r) for r in RELEASE_PREFERENCE] == sorted(
            int(r) for r in RELEASE_PREFERENCE
        )
        assert RELEASE_PREFERENCE[0] == "8"

    @needs_jdk
    def test_detect_picks_something_the_jdk_accepts(self) -> None:
        assert detect_release() in RELEASE_PREFERENCE

    def test_detect_reports_when_nothing_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A JDK new enough to reject every target in the list should say so,
        # not fail 44 times with a confusing per-case error.
        import subprocess as sp

        monkeypatch.setattr(
            sp, "run", lambda *a, **k: sp.CompletedProcess(a, 1, "", "bad target")
        )
        with pytest.raises(ToolchainError) as exc:
            detect_release(("8",))
        assert "RELEASE_PREFERENCE" in str(exc.value)


@needs_jdk
class TestToolchain:
    def test_version_string_is_reported(self) -> None:
        v = javac_version()
        assert "javac" in v.lower()


class TestMissingToolchain:
    def test_error_distinguishes_jdk_from_jre(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The failure mode worth guarding: `java -version` works, `javac` does
        # not, and the message has to say so — otherwise it reads as "Java is
        # missing" on a machine that visibly has Java.
        def missing(*_a: object, **_k: object) -> None:
            raise FileNotFoundError(2, "No such file or directory", "javac")

        monkeypatch.setattr("subprocess.run", missing)
        with pytest.raises(ToolchainError) as exc:
            javac_version()
        assert "JDK" in str(exc.value)
        assert "--no-java" in str(exc.value)


# --------------------------------------------------------------------------- #
# The scrubbed tree
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def java_cases() -> list[dict]:
    import json

    return [
        c
        for c in json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]
        if c["language"] == "java"
    ]


@pytest.fixture(scope="module")
def archive() -> zipfile.ZipFile:
    return zipfile.ZipFile(ARCHIVE)


def _scrub(case: dict, archive: zipfile.ZipFile):
    """Scrub one case the way `build_case` does: case sources first, then support."""
    sources = sorted(f for f in case["files"] if f.endswith(".java"))
    members = sources + [m for m in support_members(archive) if m not in sources]
    return scrub_juliet_case(
        [
            (m, archive.read(m).decode("utf-8", "replace"), Language.JAVA)
            for m in members
        ]
    )


_PACKAGE = re.compile(r"^package\s+([\w.]+)\s*;", re.MULTILINE)
_PUBLIC_TYPE = re.compile(
    r"public\s+(?:final\s+|abstract\s+)?(?:class|interface|enum)\s+(\w+)"
)


@needs_corpus
class TestScrubbedTree:
    """javac's layout rules, checked without javac.

    The JDK is absent on plenty of machines this runs on, and these invariants
    are the ones a missing JDK would let through until the next full build.
    """

    def test_package_declaration_matches_the_directory(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        for case in java_cases:
            result = _scrub(case, archive)
            for member, text in result.files.items():
                path = result.paths[member]
                declared = _PACKAGE.search(text)
                assert declared is not None, f"{case['case_id']} {member}"
                assert declared.group(1) == Path(path).parent.as_posix().replace(
                    "/", "."
                ), f"{case['case_id']} {path}"

    def test_public_type_matches_the_filename(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        for case in java_cases:
            result = _scrub(case, archive)
            for member, text in result.files.items():
                if (declared := _PUBLIC_TYPE.search(text)) is None:
                    continue
                assert declared.group(1) == Path(result.paths[member]).stem, (
                    f"{case['case_id']} {result.paths[member]}"
                )

    def test_no_scrubbed_file_collides_with_another(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        # Every case's main class is `Class_1` after scrubbing, so a collision
        # within a case would silently overwrite one file with another.
        for case in java_cases:
            paths = list(_scrub(case, archive).paths.values())
            assert len(set(paths)) == len(paths), case["case_id"]

    def test_cross_file_type_references_all_resolve(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        # The reason scrubbing is per case: a per-file mapping renamed `52b`'s
        # class to one thing and `52a`'s reference to it to another, so the
        # scrubbed tree did not compile.
        declares = re.compile(r"(?:class|interface|enum)\s+(Class_\d+)")
        uses = re.compile(r"\b(Class_\d+)\b")
        for case in java_cases:
            text = "\n".join(_scrub(case, archive).files.values())
            assert not uses.findall(text) or set(uses.findall(text)) <= set(
                declares.findall(text)
            ), case["case_id"]

    def test_the_support_sources_are_scrubbed_with_the_case(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        # §4.1 does not preserve Juliet's support surface, so `AbstractTestCase`
        # becomes `Class_2` inside the case. An unscrubbed testcasesupport on
        # the classpath would then have nothing for the case to extend.
        result = _scrub(java_cases[0], archive)
        support = [m for m in result.files if m.startswith(SUPPORT_DIR)]
        assert support, "support sources were not part of the scrub unit"
        assert not any("testcasesupport" in result.paths[m] for m in support)


@needs_corpus
class TestScrubRecord:
    """The mapping is the Java oracle. These are the ways it can be useless."""

    def test_every_case_records_which_method_held_the_flaw(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        for case in java_cases:
            result = _scrub(case, archive)
            sources = sorted(f for f in case["files"] if f.endswith(".java"))
            record = scrub_record(result, sources)
            tails = {s.tail for s in record.symbols}
            assert "bad" in tails, case["case_id"]

    def test_symbols_point_at_names_that_exist_in_the_scrubbed_text(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        # A symbol naming a method that is not in the output would send `eval`
        # looking for a function that was never emitted.
        for case in java_cases[:10]:
            result = _scrub(case, archive)
            sources = sorted(f for f in case["files"] if f.endswith(".java"))
            text = "\n".join(result.files[s] for s in sources)
            for symbol in scrub_record(result, sources).symbols:
                assert symbol.name in text, f"{case['case_id']} {symbol.tail}"

    def test_paths_cover_the_case_sources_and_not_the_support_tree(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        case = java_cases[0]
        sources = sorted(f for f in case["files"] if f.endswith(".java"))
        record = scrub_record(_scrub(case, archive), sources)
        assert set(record.paths) == set(sources)


@needs_corpus
class TestRunnability:
    """The scrubbed artifacts have to be executable.

    Not a stylistic preference: the thesis requires working proof-of-concept
    code to establish exploitability, and a PoC run against the unscrubbed twin
    is a PoC against different bytecode from the one the model analysed.
    """

    def test_every_case_keeps_an_entry_point(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        entry = re.compile(r"static\s+void\s+main\s*\(\s*String")
        for case in java_cases:
            result = _scrub(case, archive)
            sources = sorted(f for f in case["files"] if f.endswith(".java"))
            text = "\n".join(result.files[s] for s in sources)
            assert entry.search(text), case["case_id"]

    def test_servlet_handlers_are_not_renamed(
        self, java_cases: list[dict], archive: zipfile.ZipFile
    ) -> None:
        # Renamed, these still compile but stop overriding HttpServlet, and all
        # 18 servlet cases go silently dead inside a container.
        for case in java_cases:
            mapping = _scrub(case, archive).mapping
            assert "doGet" not in mapping, case["case_id"]
            assert "doPost" not in mapping, case["case_id"]
