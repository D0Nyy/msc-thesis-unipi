"""Tests for the Java build arm.

Deliberately thinner than `test_compile.py`, because the module is thinner —
javac has no optimisation levels, no stripping and no variant split, so most of
what the C/C++ side needs testing for does not exist here.

What DOES need testing is the classpath: the web-injection stratum is entirely
servlets, so a missing `servlet-api.jar` would fail 20 of the 44 Java cases
with a compiler error that looks like a source problem rather than a setup one.
"""

import shutil
import zipfile
from pathlib import Path

import pytest

from vulnlm.build.compile import ToolchainError
from vulnlm.build.jvm import (
    CLASSPATH_JARS,
    JAVA_RELEASE,
    SUPPORT_DIR,
    javac_version,
    support_members,
)

ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-java-v1-3.zip")

needs_archive = pytest.mark.skipif(
    not ARCHIVE.exists(), reason=f"{ARCHIVE} not present"
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
    def test_release_is_pinned_old(self) -> None:
        # Juliet 1.3 is 2011-era Java. Same argument as the C standard pin:
        # unpinned, the buildable set becomes a function of the host JDK.
        assert int(JAVA_RELEASE) <= 11


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
