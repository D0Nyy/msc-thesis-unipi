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

What Java has instead, and C/C++ does not, is **scrubbing before compilation**.
`objcopy --strip-all` gives the C/C++ binaries their anonymity for free, so
§4.1 compiles those from unmodified source. Bytecode has no equivalent: the
class-file format carries package, class and method names as structure rather
than as an optional symbol table, so they survive javac and come straight back
out of Vineflower. Pre-compilation is the only point at which `void bad()` can
be removed, which makes the scrubber part of this module's job rather than a
step someone runs afterwards.

So every case is compiled **twice**:

* **scrubbed** — the primary condition. `package pkg_1.pkg_2.pkg_3;`,
  `class Class_1`, `public void func_3()`.
* **unscrubbed** — §4.1's leakage-sensitivity arm, which measures how far a
  model leans on identifier names rather than code semantics. For C/C++ that
  condition is free (scrub the F0 text or don't); here it costs a second
  compile, because the condition is baked in at compile time.

The scrub mapping is recorded on `CaseBuild.scrub` and **is the Java arm's
ground truth**, exactly as `BinaryArtifact.symbols` is for C/C++. After
scrubbing, nothing else records that `func_3` was `bad`.

The shared `testcasesupport` sources are scrubbed *with* each case and against
that case's mapping. They have to be: §4.1 does not preserve Juliet's support
surface, so `AbstractTestCase` becomes `Class_2` in the case, and a case
importing `pkg_4.*` will not link against an unscrubbed `testcasesupport`.
"""

import posixpath
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path

from vulnlm.build.compile import ToolchainError, clear_dir, relative_path
from vulnlm.build.scaffolding import VARIANT_NAMES
from vulnlm.build.scrub import CaseScrub, language_of, scrub_juliet_case
from vulnlm.build.suites import SUITES, Suite, find_archive, sha256_file
from vulnlm.schema import (
    BinaryArtifact,
    BuildStatus,
    Case,
    CaseBuild,
    Language,
    ScrubbedSymbol,
    ScrubRecord,
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
# build happened to run on.
#
# Which values are ACCEPTED is itself JDK-dependent, and the floor rises with
# every few releases — JDK 20 dropped 7, and 8 is deprecated and on its way
# out. So the preference list is probed against the actual compiler rather
# than hard-coded, lowest first: the oldest release the JDK still accepts is
# the one closest to what Juliet was written against.
RELEASE_PREFERENCE: tuple[str, ...] = ("8", "11", "17", "21")

# `--release`, two dashes. The single-dash spelling is not valid javac syntax
# and fails with "invalid flag: -release" on every case, which reads like a
# source problem rather than a command-line one.
_RELEASE_FLAG = "--release"

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


def detect_release(preference: tuple[str, ...] = RELEASE_PREFERENCE) -> str:
    """The oldest release target this JDK still accepts.

    Probed with a throwaway compile rather than derived from the JDK version,
    because the mapping from JDK version to supported release floor is a table
    that changes and would have to be maintained here. One `javac` invocation
    answers it directly.
    """
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "Probe.java"
        probe.write_text("class Probe {}\n", encoding="utf-8")
        for release in preference:
            proc = subprocess.run(
                ["javac", _RELEASE_FLAG, release, "-d", tmp, str(probe)],
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode == 0:
                return release
    raise ToolchainError(
        f"this JDK accepts none of {preference} as a --release target. "
        f"Juliet 1.3 is 2011-era Java; a JDK this new may no longer be able to "
        f"target it. Add a higher value to RELEASE_PREFERENCE in build/jvm.py."
    )


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


def scrub_case_tree(case: Case, work: Path, dest: Path) -> CaseScrub:
    """Scrub one case plus the support sources, and write the result to `dest`.

    The case's own files come first in the list because encounter order fixes
    the numbering, and a mapping dominated by `testcasesupport` would be harder
    to read in the report for no gain.

    Scrubbing is per CASE, not per file: Juliet's 5x-8x flow variants split
    source from sink across `a`/`b`/`c` files, and a per-file mapping gives
    `badSink` two different replacements. That does not merely look untidy —
    the scrubbed Java does not compile, because `52a` calls a method `52b` no
    longer has.
    """
    sources = sorted(f for f in case.files if f.endswith(".java"))
    members = sources + [
        m for m in support_members_on_disk(work) if m not in sources
    ]
    files = [
        (m, (work / m).read_text(encoding="utf-8", errors="replace"), language_of(m))
        for m in members
    ]
    result = scrub_juliet_case(files)

    for member, text in result.files.items():
        target = dest / result.paths[member]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return result


def scrub_record(result: CaseScrub, sources: list[str]) -> ScrubRecord:
    """The oracle, pulled out of a `CaseScrub` and narrowed to the case.

    `paths` covers only the case's own sources. The scrubbed support tree is a
    build input, not something `recover` or `eval` ever has to locate, and
    carrying ten extra rows per case would bury the three that matter.
    """
    return ScrubRecord(
        mapping=dict(result.mapping),
        paths={s: result.paths[s] for s in sources if s in result.paths},
        symbols=[
            ScrubbedSymbol(name=result.mapping[tail], tail=tail)
            for tail in sorted(VARIANT_NAMES)
            if tail in result.mapping
        ],
    )


def _javac(
    sources: list[str], cwd: Path, out_dir: Path, classpath: list[str], release: str
) -> subprocess.CompletedProcess[str]:
    """Run javac with `sources` relative to `cwd`.

    `classpath` must be absolute. The scrubbed and unscrubbed builds run from
    different working directories, so the suite-relative jar paths that used to
    work here silently resolve to nothing in one of them.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "javac",
        "-nowarn",
        "-encoding", "UTF-8",
        _RELEASE_FLAG, release,
        "-cp", ":".join([*classpath, str(out_dir)]),
        "-d", str(out_dir),
        *sources,
    ]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)


def _artifacts(out_dir: Path, root: Path, *, scrubbed: bool) -> list[BinaryArtifact]:
    return [
        BinaryArtifact(
            path=relative_path(cls, root),
            scrubbed=scrubbed,
            sha256=sha256_file(cls),
            text_bytes=cls.stat().st_size,
        )
        for cls in sorted(out_dir.rglob("*.class"))
    ]


def build_case(
    case: Case,
    work: Path,
    out_root: Path,
    classpath: list[str],
    root: Path,
    release: str,
    scrub_root: Path,
) -> CaseBuild:
    """Compile one Java case twice — scrubbed and unscrubbed. Never raises.

    Every case gets its own output directory, and each condition its own
    subdirectory beneath it. Juliet reuses class names across flow variants, so
    a shared directory would let one case's `.class` files satisfy another's
    references and silently mask a failure; and after scrubbing, every case's
    classes are called `Class_1`, which turns that from a risk into a
    certainty.
    """
    sources = sorted(f for f in case.files if f.endswith(".java"))
    support = support_members_on_disk(work)
    out_dir = (out_root / case.case_id).resolve()

    def failed(status: BuildStatus, error: str) -> CaseBuild:
        return CaseBuild(
            case_id=case.case_id,
            language=Language.JAVA,
            status=status,
            compiler="javac",
            sources=sources,
            error=error[:2000],
        )

    # Unscrubbed first: it is the condition that has been known to work, so a
    # failure here is a Juliet-or-toolchain problem, while a failure only in
    # the scrubbed build is the scrubber's.
    plain = _javac(sources + support, work, out_dir / "unscrubbed", classpath, release)
    if plain.returncode != 0:
        return failed(BuildStatus.COMPILE_FAILED, plain.stderr.strip())

    case_scrub = scrub_case_tree(case, work, scrub_root / case.case_id)
    scrubbed_sources = sorted(case_scrub.paths[m] for m in case_scrub.files)
    clean = _javac(
        scrubbed_sources,
        scrub_root / case.case_id,
        out_dir / "scrubbed",
        classpath,
        release,
    )
    if clean.returncode != 0:
        # Distinguished in the message rather than the status, because to the
        # corpus this is still a case that did not build. Worth reading as a
        # scrubber bug report: the unscrubbed twin compiled fine.
        return failed(
            BuildStatus.COMPILE_FAILED,
            f"scrubbed source failed to compile (the unscrubbed source did "
            f"not): {clean.stderr.strip()}",
        )

    artifacts = _artifacts(out_dir / "scrubbed", root, scrubbed=True) + _artifacts(
        out_dir / "unscrubbed", root, scrubbed=False
    )
    if not artifacts:
        return failed(
            BuildStatus.NO_FLAW_SYMBOLS,
            "javac reported success but produced no .class files",
        )

    record = scrub_record(case_scrub, sources)
    if not record.symbols:
        # `bad` absent from the mapping means nothing records which method
        # held the flaw. The case built, but it cannot be scored.
        return failed(
            BuildStatus.NO_FLAW_SYMBOLS,
            "the scrub mapping contains no variant name, so the case has no "
            "ground truth. Check build/scaffolding.py VARIANT_NAMES against "
            "this case's method names.",
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
        scrub=record,
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
    clear_src: bool = True,
) -> tuple[list[CaseBuild], str, list[str]]:
    """Compile every Java case. Returns (builds, javac version, classpath)."""
    if not cases:
        return [], "", []

    version = javac_version()
    release = detect_release()
    archive = find_archive(_JAVA_SUITE, raw_dir)

    work = (out_dir / "src").resolve()
    class_root = (out_dir / "bin" / _JAVA_SUITE.key).resolve()
    # The scrubbed tree is a separate root rather than a sibling inside `src/`,
    # so that "the sources as Juliet ships them" and "the sources the model
    # sees" cannot be confused for one another by anything downstream.
    scrub_root = (out_dir / "src-scrubbed" / _JAVA_SUITE.key).resolve()
    # `src/` is shared with the C/C++ arm and cleared by whoever runs first.
    to_clear = (work, class_root, scrub_root) if clear_src else (class_root, scrub_root)
    for directory in to_clear:
        if (problem := clear_dir(directory)) is not None and warn is not None:
            warn(problem)

    classpath = extract_sources(archive, cases, work)
    class_root.mkdir(parents=True, exist_ok=True)
    scrub_root.mkdir(parents=True, exist_ok=True)
    # Absolute, because the two builds run from different working directories.
    # The suite-relative form is what goes in the report.
    classpath_abs = [str((work / j).resolve()) for j in classpath]

    # Sequential rather than pooled: javac spends most of its time in JVM
    # startup, and 44 concurrent JVMs on a laptop is worse than 44 sequential
    # ones — now 88, which is the same argument twice over rather than a new
    # reason to parallelise. Revisit if the sample grows by an order of
    # magnitude.
    builds = [
        build_case(c, work, class_root, classpath_abs, out_dir, release, scrub_root)
        for c in cases
    ]
    return sorted(builds, key=lambda b: b.case_id), f"{version} --release {release}", classpath
