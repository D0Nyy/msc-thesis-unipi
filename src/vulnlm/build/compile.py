"""Compile the sampled C/C++ cases and gate on flaw survival (protocol §7.1).

Stage 0.5, between `sample` and `recover`. For each case in the manifest this
produces four ELF binaries per variant --- {-O0, -O2} x {symbols, stripped} ---
measures how much of the flaw survives optimisation, and excludes the cases
where it does not.

The gate is the point of the module. In 7% of cases `-O2` proves the result a
constant and deletes the vulnerability outright; Ghidra then decompiles a
function with no flaw in it and the model is scored against a bug that is not
there. Those are guaranteed false negatives, and without this stage they would
be silently attributed to the model rather than to the compiler.

Java is out of scope here (protocol §5.1): its F0->F1 walk is javac plus
Vineflower, and with no optimiser there is nothing for a survival gate to
catch.
"""

import posixpath
import re
import shutil
import subprocess
import zipfile
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from vulnlm.build.juliet import parse_name
from vulnlm.build.suites import SUITES, Suite, find_archive, sha256_file
from vulnlm.schema import (
    BinaryArtifact,
    BuildReport,
    BuildStatus,
    BuildVariant,
    Case,
    CaseBuild,
    FlawSurvival,
    Language,
    Manifest,
)

# --------------------------------------------------------------------------- #
# Build settings — protocol §7.1
# --------------------------------------------------------------------------- #
#
# Everything in this block is a decision, not a default. Each one changes what
# the model sees at F2, and each is copied into the BuildReport so a corpus can
# be traced back to the flags that produced it.

# Pinned explicitly rather than inherited from the compiler. gcc's default
# standard has moved (gnu17 in gcc 11, gnu23 in gcc 15) and the newer defaults
# turn implicit declarations and incompatible pointer assignments — both of
# which Juliet 1.3 contains — from warnings into hard errors. Without a pin,
# the set of buildable cases becomes a function of which Ubuntu the build ran
# on, which would silently reshape the sample.
C_STANDARD = "gnu11"
CXX_STANDARD = "gnu++14"

# Juliet is deliberately warning-dense — the warnings ARE the test material —
# so warnings are silenced rather than read. Errors are still fatal.
_QUIET = "-w"

# `_FORTIFY_SOURCE` is enabled by Ubuntu's gcc at -O1 and above but not at -O0,
# which would make the -O0/-O2 pair differ in the libc API surface as well as
# in optimisation: `printf` becomes `__printf_chk`, `memcpy` becomes
# `__memcpy_chk`. Since §4.1 treats imported API names as signal, and §7.1's
# -O0 subset exists to isolate optimisation specifically, that confound is
# removed rather than tolerated. Set to 2 here if the intent changes to
# "whatever a distro release build would produce".
_FORTIFY = "-U_FORTIFY_SOURCE"

# Dynamic linking is required, not incidental (§7.1): imported libc names
# survive stripping through the PLT, and static linking would turn `strcpy`
# into an unnamed blob and destroy the API-call signal.
_LINKAGE = "-no-pie"  # fixed load address; keeps Ghidra addresses comparable

# Juliet ships each case with its own `main()` behind this guard. The
# alternative build mode — the 350 shared `main.cpp` files that call dozens of
# cases into one application — is for testing source analysers over a tree, and
# is not ours.
_ENTRY = "-DINCLUDEMAIN"

COMMON_FLAGS: tuple[str, ...] = (_QUIET, _FORTIFY, _LINKAGE, _ENTRY, "-g")

OPTIMISATIONS: tuple[str, ...] = ("-O0", "-O2")

# Under this share of bad-path code retained at -O2, the flaw is treated as
# erased and the case leaves the F2 arm. 15% is low enough that ordinary
# tightening does not trip it and high enough to catch the cases that reduce to
# a constant — one of them compiles down to `xor %edi,%edi; jmp printIntLine`.
SURVIVAL_THRESHOLD = 0.15

# Every case calls printLine/printIntLine, which live here. `std_testcase.h`
# carries an `extern "C"` guard, so one C build of io.c links into C++ cases
# too — but it is compiled with the case's own compiler anyway, to keep a
# single translation-unit language per binary.
SUPPORT_DIR = "C/testcasesupport"
SUPPORT_SOURCES: tuple[str, ...] = (f"{SUPPORT_DIR}/io.c",)
SUPPORT_MEMBERS: tuple[str, ...] = (
    *SUPPORT_SOURCES,
    f"{SUPPORT_DIR}/std_testcase.h",
    f"{SUPPORT_DIR}/std_testcase_io.h",
    f"{SUPPORT_DIR}/std_thread.h",
    f"{SUPPORT_DIR}/testcases.h",
)

_CCPP_SUITE: Suite = next(s for s in SUITES if s.key == "c-cpp")


# --------------------------------------------------------------------------- #
# Source selection
# --------------------------------------------------------------------------- #
#
# Which of a case's files go into which binary. This is NOT the same question
# as -DOMITGOOD/-DOMITBAD, and getting it wrong is not a subtle failure.

def select_sources(files: list[str], *, bad: bool) -> list[str]:
    """The compilable files for one variant of a case.

    Juliet states the variant in the filename for 4,323 cases (`..._81_bad.cpp`
    next to `..._81_goodG2B.cpp`). For the 81-84 family the preprocessor alone
    is enough, because those files are wholly inside `#ifndef OMITBAD`. For the
    23 flow-01 `good1` cases it is NOT: each variant file carries its own
    `main()` OUTSIDE the guard, so compiling the pair yields two `main`s and
    the link fails. Selecting by filename variant is correct for both, so it is
    done unconditionally rather than special-cased by flow.
    """
    out: list[str] = []
    for path in sorted(files):
        if posixpath.splitext(path)[1].lower() not in (".c", ".cpp"):
            continue  # headers are #included, never compiled
        parsed = parse_name(path)
        variant = parsed.variant if parsed is not None else None
        if variant is None or variant == "base":
            out.append(path)  # shared between both binaries
        elif (variant == "bad") == bad:
            out.append(path)
    return out


def compiler_for(sources: list[str]) -> str:
    """g++ when any translation unit is C++, gcc otherwise.

    Decided per case rather than per language field: a case's `Language` comes
    from one representative file, and a C++ case can carry `.c` parts.
    """
    return "g++" if any(s.endswith(".cpp") for s in sources) else "gcc"


def standard_flag(compiler: str) -> str:
    return f"-std={CXX_STANDARD if compiler == 'g++' else C_STANDARD}"


# --------------------------------------------------------------------------- #
# The symbol oracle
# --------------------------------------------------------------------------- #
#
# At F2 there is no other way to know which recovered function holds the flaw.
# Derived from the symbol-bearing build and never shown to the model.

# Juliet's two spellings. A C case emits `<case_id>_bad`; a C++ case wraps the
# same function in a namespace named for the case, so it demangles to
# `<case_id>::bad()`. Both reduce to the same tail.
BAD_TAILS: frozenset[str] = frozenset({"bad", "badSink", "badSource"})
GOOD_TAILS: frozenset[str] = frozenset(
    {
        "good", "good1", "good2", "goodG2B", "goodB2G",
        "goodG2BSink", "goodB2GSink", "goodG2BSource", "goodB2GSource",
    }
)

# `nm -S` output: address, size, type, name. Size is absent for symbols the
# linker could not size, so the size group is optional and those are skipped.
_NM_LINE = re.compile(r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S)\s+(.+)$")


class ToolchainError(RuntimeError):
    """A required binutils/gcc program is missing or failed."""


@dataclass(frozen=True)
class Symbol:
    name: str
    size: int
    kind: str


def _text_symbols(binary: Path) -> Iterator[Symbol]:
    """Defined, demangled function symbols.

    Weak symbols are dropped: at -O2 a C++ case pulls in hundreds of `W` STL
    template instantiations (`std::_Rb_tree<...>::_M_insert_node`), and letting
    them into the size sum would swamp the few hundred bytes of Juliet code the
    measurement is about.
    """
    proc = subprocess.run(
        ["nm", "--print-size", "--defined-only", "--demangle", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolchainError(f"nm failed on {binary.name}: {proc.stderr.strip()[:200]}")
    for line in proc.stdout.splitlines():
        m = _NM_LINE.match(line.strip())
        if m is None:
            continue
        kind = m.group(3)
        if kind not in ("t", "T"):
            continue
        yield Symbol(name=m.group(4), size=int(m.group(2), 16), kind=kind)


def symbol_tail(name: str, case_id: str) -> str | None:
    """Reduce a symbol to the Juliet function name, or None if it is not one.

    Both spellings collapse here:

        CWE121_..._01_bad                       -> "bad"
        CWE121_..._74::badSink(std::map<...>)   -> "badSink"

    The C++ argument list is dropped first, so overloads do not fragment.
    """
    base = name.split("(", 1)[0].strip()
    if "::" in base:
        return base.rsplit("::", 1)[1] or None
    prefix = f"{case_id}_"
    return base[len(prefix):] if base.startswith(prefix) else None


def path_sizes(binary: Path, case_id: str) -> tuple[int, int, list[str], list[str]]:
    """(bad bytes, good bytes, bad symbols, good symbols) for one binary."""
    bad_bytes = good_bytes = 0
    bad_names: list[str] = []
    good_names: list[str] = []
    for sym in _text_symbols(binary):
        tail = symbol_tail(sym.name, case_id)
        if tail in BAD_TAILS:
            bad_bytes += sym.size
            bad_names.append(sym.name)
        elif tail in GOOD_TAILS:
            good_bytes += sym.size
            good_names.append(sym.name)
    return bad_bytes, good_bytes, sorted(bad_names), sorted(good_names)


def retained(o0: int, o2: int) -> float | None:
    """Share of bad-path code left at -O2. None when there was none at -O0.

    Values above 1.0 are real and expected: -O2 inlines the sink into the
    source, so one function absorbs another and grows. That is the compiler
    doing part of §4.2's chunk assembly, and it is a result rather than an
    artefact.
    """
    return None if o0 == 0 else o2 / o0


# --------------------------------------------------------------------------- #
# Compiling
# --------------------------------------------------------------------------- #


def compiler_version(compiler: str = "gcc") -> str:
    try:
        proc = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ToolchainError(
            f"{compiler} is not usable: {exc}. This stage needs a C/C++ "
            f"toolchain and binutils (nm, objcopy) on PATH."
        ) from exc
    return proc.stdout.splitlines()[0].strip()


def extract_sources(archive: Path, cases: list[Case], dest: Path) -> None:
    """Unpack the sampled cases and the shared support files.

    Archive-relative paths are preserved: a case's `#include "std_testcase.h"`
    resolves through -I, but the 5x family also includes sibling parts by
    relative path.
    """
    dest.mkdir(parents=True, exist_ok=True)
    wanted = {member for case in cases for member in case.files}
    wanted.update(SUPPORT_MEMBERS)
    with zipfile.ZipFile(archive) as zf:
        present = set(zf.namelist())
        missing = sorted(wanted - present)
        if missing:
            raise ToolchainError(
                f"{len(missing)} manifest file(s) absent from {archive.name}, "
                f"first: {missing[0]}. The manifest was drawn from a different "
                f"archive — regenerate it or restore the original."
            )
        for member in sorted(wanted):
            zf.extract(member, dest)


def _compile(
    compiler: str, sources: list[str], opt: str, variant: BuildVariant,
    work: Path, out: Path,
) -> subprocess.CompletedProcess[str]:
    omit = "-DOMITGOOD" if variant is BuildVariant.BAD else "-DOMITBAD"
    cmd = [
        compiler,
        standard_flag(compiler),
        *COMMON_FLAGS,
        omit,
        opt,
        f"-I{SUPPORT_DIR}",
        *sources,
        *SUPPORT_SOURCES,
        "-o",
        str(out),
    ]
    return subprocess.run(cmd, cwd=work, capture_output=True, text=True, check=False)


def strip_copy(symbolled: Path, stripped: Path) -> None:
    """Produce the model's binary from the oracle's, via objcopy.

    Copy-and-strip rather than a second `-s` link: this way the two builds are
    the same machine code by construction, so a difference between the F2 chunk
    and the ground-truth mapping cannot be a build artefact.
    """
    proc = subprocess.run(
        ["objcopy", "--strip-all", str(symbolled), str(stripped)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ToolchainError(f"objcopy failed: {proc.stderr.strip()[:200]}")


def _text_bytes(binary: Path) -> int:
    proc = subprocess.run(
        ["size", "--format=sysv", str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == ".text":
            return int(parts[1])
    return 0


def clear_dir(path: Path) -> str | None:
    """Empty a build directory, or explain why it could not be emptied.

    Not fatal when it fails. Windows-backed mounts — `/mnt/c` under WSL, and
    the 9p mounts some sandboxes use — permit creating files but refuse to
    unlink them, and a rebuild that overwrites in place is still correct for
    every case the manifest names. What it cannot do is remove artifacts left
    by a PREVIOUS manifest, so the caller warns rather than continuing quietly.
    """
    if not path.exists():
        return None
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return (
            f"could not clear {path}: {exc.strerror or exc}. Rebuilding in "
            f"place — binaries from an earlier manifest may survive. Point "
            f"--build-dir at a native Linux filesystem to avoid this."
        )
    return None


def relative_path(path: Path) -> str:
    """Repo-relative where possible, absolute otherwise.

    Run directories have to stay portable between the Windows checkout and the
    rented Linux GPU, so an absolute path in a persisted record is a defect.
    """
    try:
        return path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.as_posix()


def build_case(case: Case, work: Path, bin_root: Path) -> CaseBuild:
    """Compile, measure and gate one case. Never raises on a compiler error.

    `bin_root` must be absolute: the compiler runs with its working directory
    set to the extracted source tree so that the 5x family's relative includes
    resolve, which makes any relative output path resolve against the wrong
    directory.
    """
    sources = {
        variant: select_sources(case.files, bad=variant is BuildVariant.BAD)
        for variant in BuildVariant
    }
    compiler = compiler_for(sources[BuildVariant.BAD])
    out_dir = bin_root.resolve() / case.case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[BinaryArtifact] = []
    sizes: dict[tuple[BuildVariant, str], tuple[int, int]] = {}
    bad_symbols: list[str] = []
    good_symbols: list[str] = []

    for variant in BuildVariant:
        for opt in OPTIMISATIONS:
            sym_path = out_dir / f"{variant.value}{opt}.sym"
            proc = _compile(compiler, sources[variant], opt, variant, work, sym_path)
            if proc.returncode != 0:
                return CaseBuild(
                    case_id=case.case_id,
                    language=case.language,
                    status=BuildStatus.COMPILE_FAILED,
                    compiler=compiler,
                    sources=sources[BuildVariant.BAD],
                    error=proc.stderr.strip()[:2000],
                )

            bad_bytes, good_bytes, bad_names, good_names = path_sizes(
                sym_path, case.case_id
            )
            sizes[(variant, opt)] = (bad_bytes, good_bytes)
            if variant is BuildVariant.BAD and opt == "-O0":
                bad_symbols = bad_names
            if variant is BuildVariant.GOOD and opt == "-O0":
                good_symbols = good_names

            stripped_path = out_dir / f"{variant.value}{opt}.stripped"
            strip_copy(sym_path, stripped_path)
            for path, is_stripped in ((sym_path, False), (stripped_path, True)):
                artifacts.append(
                    BinaryArtifact(
                        path=relative_path(path),
                        variant=variant,
                        optimisation=opt,
                        stripped=is_stripped,
                        sha256=sha256_file(path),
                        text_bytes=_text_bytes(path),
                    )
                )

    bad_o0, _ = sizes[(BuildVariant.BAD, "-O0")]
    bad_o2, _ = sizes[(BuildVariant.BAD, "-O2")]
    _, good_o0 = sizes[(BuildVariant.GOOD, "-O0")]
    _, good_o2 = sizes[(BuildVariant.GOOD, "-O2")]

    if bad_o0 == 0:
        # The case built but the oracle recognised nothing. Either Juliet used a
        # naming convention this module does not know, or the flaw is not in a
        # function at all. Loud, because every downstream F2 label depends on it.
        return CaseBuild(
            case_id=case.case_id,
            language=case.language,
            status=BuildStatus.NO_FLAW_SYMBOLS,
            compiler=compiler,
            sources=sources[BuildVariant.BAD],
            binaries=artifacts,
            error="no bad/badSink/badSource symbol found in the -O0 build",
        )

    bad_retained = retained(bad_o0, bad_o2)
    survived = bad_retained is not None and bad_retained >= SURVIVAL_THRESHOLD
    survival = FlawSurvival(
        bad_o0=bad_o0,
        bad_o2=bad_o2,
        good_o0=good_o0,
        good_o2=good_o2,
        bad_retained=bad_retained,
        good_retained=retained(good_o0, good_o2),
        threshold=SURVIVAL_THRESHOLD,
        survived=survived,
    )
    return CaseBuild(
        case_id=case.case_id,
        language=case.language,
        status=BuildStatus.OK if survived else BuildStatus.ERASED,
        compiler=compiler,
        sources=sources[BuildVariant.BAD],
        binaries=artifacts,
        survival=survival,
        bad_symbols=bad_symbols,
        good_symbols=good_symbols,
    )


def build_corpus(
    manifest: Manifest,
    manifest_path: Path,
    raw_dir: Path,
    out_dir: Path,
    jobs: int | None = None,
    warn: Callable[[str], None] | None = None,
    java: bool = True,
) -> BuildReport:
    """Build every case in the manifest, C/C++ here and Java via `jvm`.

    One report covers both languages. They share almost no build machinery —
    see `jvm` for why — but they are one sample, and splitting the record would
    make it possible to have a corpus where half the strata are stale.
    """
    cases = [c for c in manifest.cases if c.language in (Language.C, Language.CPP)]
    java_cases = [c for c in manifest.cases if c.language is Language.JAVA]
    archive = find_archive(_CCPP_SUITE, raw_dir)

    # Both toolchains are checked before either is used. The Java arm runs
    # last, so without this a missing JDK would be reported only after several
    # minutes of C/C++ compiling had already been done and thrown away.
    compiler_version()
    if java and java_cases:
        from vulnlm.build import jvm

        jvm.javac_version()

    work = (out_dir / "src").resolve()
    bin_root = (out_dir / "bin").resolve()
    for directory in (work, bin_root):
        if (problem := clear_dir(directory)) is not None and warn is not None:
            warn(problem)

    extract_sources(archive, cases, work)
    bin_root.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        builds = list(pool.map(lambda c: build_case(c, work, bin_root), cases))

    java_version: str | None = None
    classpath: list[str] = []
    if java and java_cases:
        # Imported here rather than at module scope: `jvm` imports from this
        # module, and --no-java must not require a JDK to be discoverable.
        from vulnlm.build import jvm

        java_builds, java_version, classpath = jvm.build_java(
            java_cases, raw_dir, out_dir, warn=warn
        )
        builds.extend(java_builds)

    return BuildReport(
        manifest_sha256=sha256_file(manifest_path),
        compiler_version=compiler_version(),
        java_version=java_version,
        classpath=classpath,
        common_flags=[
            f"-std={C_STANDARD}|{CXX_STANDARD}",
            *COMMON_FLAGS,
            f"-I{SUPPORT_DIR}",
        ],
        optimisations=list(OPTIMISATIONS),
        survival_threshold=SURVIVAL_THRESHOLD,
        cases=sorted(builds, key=lambda b: b.case_id),
    )
