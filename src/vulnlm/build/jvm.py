"""Compile the sampled Java cases to bytecode (protocol §5.1, §7).

The Java half of stage 0.5. Much smaller than the C/C++ half, and deliberately
so — almost everything `compile.py` does has no Java counterpart:

* **No optimisation levels.** javac does essentially no optimisation; the JIT
  does it at runtime, where it cannot affect a `.class` file. So there is no
  `-O0`/`-O2` pair and no flaw-survival gate. The 7% erasure that motivates the
  gate for C/C++ simply cannot happen here.
* **No stripping.** Bytecode carries method names as a structural requirement
  of the class-file format, not as an optional symbol table. This is exactly
  why Java's walk is F0->F1 and lossless-ish, while C/C++ goes to F2.
* **No variant split.** Juliet's Java cases put `bad()`, `good()`, `goodG2B()`
  and `goodB2G()` in ONE class with no preprocessor guards. There is no
  `-DOMITGOOD` equivalent: a single `.class` holds both. The good/bad
  separation therefore happens at CHUNK time, per method, in `recover` — not
  here. Anything that assumes one variant per artifact is a C/C++ assumption
  and does not transfer.

What is left is: put the right jars on the classpath and run javac.
"""

import posixpath
import subprocess
import zipfile
from collections.abc import Callable
from pathlib import Path

from vulnlm.build.compile import ToolchainError, clear_dir, relative_path
from vulnlm.build.suites import SUITES, Suite, find_archive, sha256_file
from vulnlm.schema import (
    BinaryArtifact,
    BuildStatus,
    Case,
    CaseBuild,
    Language,
)

# The suite ships its own dependencies, so the classpath is self-contained and
# no network fetch is needed. Pinned by the archive, which is the point: a
# newer servlet-api would change what the web-injection arm compiles against.
LIB_DIR = "Java/lib"
CLASSPATH_JARS: tuple[str, ...] = (
    f"{LIB_DIR}/servlet-api.jar",  # the whole web-injection arm is servlets
    f"{LIB_DIR}/commons-lang-2.5.jar",  # StringEscapeUtils, used by the XSS cases
    f"{LIB_DIR}/commons-codec-1.5.jar",
    f"{LIB_DIR}/javamail-1.4.4.jar",
)

SUPPORT_DIR = "Java/src/testcasesupport"

# Juliet 1.3 is 2011-era Java. Pinned for the same reason the C standard is:
# left to the default, the buildable set becomes a function of which JDK the
# build happened to run on. 8 is the oldest target modern javac still accepts
# without warnings escalating to errors.
JAVA_RELEASE = "8"

_JAVA_SUITE: Suite = next(s for s in SUITES if s.key == "java")


def javac_version() -> str:
    """First line of `javac -version`, recorded in the report."""
    try:
        proc = subprocess.run(
            ["javac", "-version"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ToolchainError(
            f"javac is not usable: {exc}. The Java arm needs a JDK, not just a "
            f"JRE — `java -version` working is not sufficient. "
            f"Install default-jdk (Debian/Ubuntu) or pass --no-java to skip."
        ) from exc
    # Older JDKs print the version to stderr, newer ones to stdout.
    return (proc.stdout or proc.stderr).strip().splitlines()[0]


def support_members(archive: zipfile.ZipFile) -> list[str]:
    """The shared `testcasesupport` sources every case compiles against.

    Taken from the top-level copy only. The archive also ships a per-CWE
    `antbuild/testcasesupport/` copy for each of 153 directories; compiling all
    of them together would give duplicate class definitions.
    """
    return sorted(
        n
        for n in archive.namelist()
        if n.startswith(f"{SUPPORT_DIR}/")
        and n.endswith(".java")
        and "antbuild" not in n
    )


def extract_sources(archive: Path, cases: list[Case], dest: Path) -> list[str]:
    """Unpack the sampled cases, the shared support sources and the jars.

    Returns the classpath entries, work-directory-relative.
    """
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        present = set(zf.namelist())
        wanted = {member for case in cases for member in case.files}
        wanted.update(support_members(zf))

        missing = sorted(wanted - present)
        if missing:
            raise ToolchainError(
                f"{len(missing)} manifest file(s) absent from {archive.name}, "
                f"first: {missing[0]}. The manifest was drawn from a different "
                f"archive — regenerate it or restore the original."
            )

        jars = [j for j in CLASSPATH_JARS if j in present]
        if missing_jars := [j for j in CLASSPATH_JARS if j not in present]:
            raise ToolchainError(
                f"the Java archive is missing {missing_jars}. The web-injection "
                f"arm compiles against servlet-api; without it those cases "
                f"cannot build."
            )
        for member in sorted(wanted) + jars:
            zf.extract(member, dest)
    return list(jars)


def build_case(
    case: Case, work: Path, out_root: Path, classpath: list[str], root: Path
) -> CaseBuild:
    """Compile one Java case. Never raises on a compiler error.

    Every case is compiled into its own output directory. Juliet reuses class
    names across flow variants, so a shared directory would let one case's
    `.class` files satisfy another's references and silently mask a failure.
    """
    sources = sorted(f for f in case.files if f.endswith(".java"))
    out_dir = (out_root / case.case_id).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # The support sources are compiled alongside rather than pre-built into a
    # jar: they are small, and it keeps every case's build independent.
    cp = ":".join([*classpath, SUPPORT_DIR, str(out_dir)])
    cmd = [
        "javac",
        "-nowarn",
        "-encoding", "UTF-8",
        "-release", JAVA_RELEASE,
        "-cp", cp,
        "-d", str(out_dir),
        *sources,
        *support_members_on_disk(work),
    ]
    proc = subprocess.run(
        cmd, cwd=work, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return CaseBuild(
            case_id=case.case_id,
            language=Language.JAVA,
            status=BuildStatus.COMPILE_FAILED,
            compiler="javac",
            sources=sources,
            error=proc.stderr.strip()[:2000],
        )

    artifacts = [
        BinaryArtifact(
            path=relative_path(cls, root),
            sha256=sha256_file(cls),
            text_bytes=cls.stat().st_size,
        )
        for cls in sorted(out_dir.rglob("*.class"))
    ]
    if not artifacts:
        return CaseBuild(
            case_id=case.case_id,
            language=Language.JAVA,
            status=BuildStatus.NO_FLAW_SYMBOLS,
            compiler="javac",
            sources=sources,
            error="javac reported success but produced no .class files",
        )

    # No survival gate: see the module docstring. `survival` stays None, which
    # is how the report distinguishes a Java case from a C/C++ one that failed
    # before it could be measured.
    return CaseBuild(
        case_id=case.case_id,
        language=Language.JAVA,
        status=BuildStatus.OK,
        compiler="javac",
        sources=sources,
        binaries=artifacts,
    )


def support_members_on_disk(work: Path) -> list[str]:
    """The extracted support sources, work-relative, for the javac command."""
    root = work / SUPPORT_DIR
    if not root.is_dir():
        return []
    return sorted(
        posixpath.join(SUPPORT_DIR, p.name)
        for p in root.glob("*.java")
    )


def build_java(
    cases: list[Case],
    raw_dir: Path,
    out_dir: Path,
    warn: Callable[[str], None] | None = None,
) -> tuple[list[CaseBuild], str, list[str]]:
    """Compile every Java case. Returns (builds, javac version, classpath)."""
    if not cases:
        return [], "", []

    version = javac_version()
    archive = find_archive(_JAVA_SUITE, raw_dir)

    work = (out_dir / "java-src").resolve()
    class_root = (out_dir / "classes").resolve()
    for directory in (work, class_root):
        if (problem := clear_dir(directory)) is not None and warn is not None:
            warn(problem)

    classpath = extract_sources(archive, cases, work)
    class_root.mkdir(parents=True, exist_ok=True)

    # Sequential rather than pooled: javac spends most of its time in JVM
    # startup, and 44 concurrent JVMs on a laptop is worse than 44 sequential
    # ones. Revisit if the sample grows by an order of magnitude.
    builds = [build_case(c, work, class_root, classpath, out_dir) for c in cases]
    return sorted(builds, key=lambda b: b.case_id), version, classpath
