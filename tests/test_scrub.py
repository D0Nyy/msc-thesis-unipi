"""The scrubber must remove the answer key, and nothing else.

Two kinds of test here, and the second is the one that earns its keep.

The unit tests pin individual behaviours on small hand-written inputs, which is
where a regression is easiest to read.

`TestCorpus` is different: it runs the real scrubber over every file of all 88
sampled cases and asserts that no `CWE\\d+` and no `bad`/`good` token survives.
That is a weaker statement than "the scrubber is correct" but a much harder one
to satisfy by accident, and it is the only check that can catch a leak nobody
thought to write a unit test for. Every leak class handled in `scrub.py` beyond
bare identifiers — package paths, string literals, `#define`, `#ifndef OMITBAD`,
local `#include` — was found by this test and not by reading the code.

A leak does not crash anything. It produces a corpus that still builds, still
scores, and quietly measures the model's ability to read a function name.
"""

import json
import zipfile
from pathlib import Path

import pytest

from vulnlm.build.scrub import (
    CLASS_PREFIX,
    FUNCTION_PREFIX,
    MACRO_PREFIX,
    PACKAGE_PREFIX,
    VARIABLE_PREFIX,
    language_of,
    mapping_is_reversible,
    scrub,
    scrub_juliet,
    scrub_juliet_case,
    unresolved_leaks,
)
from vulnlm.schema import Language

C_ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip")
J_ARCHIVE = Path("data/raw/2017-10-01-juliet-test-suite-for-java-v1-3.zip")
MANIFEST = Path("data/manifest.json")

needs_corpus = pytest.mark.skipif(
    not (C_ARCHIVE.exists() and J_ARCHIVE.exists() and MANIFEST.exists()),
    reason="archives or manifest absent",
)


# --------------------------------------------------------------------------- #
# Unit
# --------------------------------------------------------------------------- #


class TestDeclaredNames:
    def test_functions_classes_and_locals_get_their_own_prefixes(self) -> None:
        result = scrub_juliet(
            "namespace Outer { void bad(int count) { int total = count; } }",
            Language.CPP,
        )
        assert result.mapping["Outer"].startswith(CLASS_PREFIX)
        assert result.mapping["bad"].startswith(FUNCTION_PREFIX)
        assert result.mapping["count"].startswith(VARIABLE_PREFIX)
        assert result.mapping["total"].startswith(VARIABLE_PREFIX)

    def test_library_calls_survive(self) -> None:
        # §4.1: a human analyst reads these too, so they are signal. Scrubbing
        # them would destroy the API evidence the whole F2 argument rests on.
        text = "void bad() { char *p = malloc(10); strcpy(p, src); free(p); }"
        out = scrub_juliet(text, Language.C).text
        for name in ("malloc", "strcpy", "free"):
            assert name in out

    def test_a_name_maps_to_one_replacement_everywhere(self) -> None:
        result = scrub_juliet(
            "void bad() { helper(); } void helper() { } void other() { helper(); }",
            Language.C,
        )
        assert result.text.count(result.mapping["helper"]) == 3

    def test_mapping_is_reversible(self) -> None:
        result = scrub_juliet("void bad() { int good = 1; }", Language.C)
        assert mapping_is_reversible(result.mapping)
        assert result.inverse[result.mapping["bad"]] == "bad"

    def test_comments_are_stripped(self) -> None:
        # Juliet annotates the flaw: `/* POTENTIAL FLAW: ... */`.
        text = "void bad() { /* POTENTIAL FLAW: buffer overflow */ int x; }"
        assert "POTENTIAL FLAW" not in scrub_juliet(text, Language.C).text


class TestPreprocessor:
    def test_define_names_are_renamed(self) -> None:
        # A `#define` name IS an identifier node, but under `preproc_def`, so
        # nothing marked it declared and it came through untouched.
        result = scrub_juliet("#define SNPRINTF _snprintf\n", Language.C)
        assert result.mapping["SNPRINTF"].startswith(MACRO_PREFIX)
        assert "SNPRINTF" not in result.text
        # The body names a real API and must survive.
        assert "_snprintf" in result.text

    def test_juliet_build_guards_are_renamed(self) -> None:
        text = "#ifndef OMITBAD\nvoid bad() {}\n#endif\n"
        out = scrub_juliet(text, Language.C).text
        assert "OMITBAD" not in out

    def test_platform_guards_are_not_renamed(self) -> None:
        # `_WIN32` is a platform fact, not leakage, and an analyst sees it.
        out = scrub_juliet("#ifdef _WIN32\n#include <winsock2.h>\n#endif\n", Language.C).text
        assert "_WIN32" in out
        assert "<winsock2.h>" in out

    def test_local_includes_are_renamed_and_system_includes_are_not(self) -> None:
        text = (
            '#include <stdio.h>\n'
            '#include "std_testcase.h"\n'
            '#include "CWE369_Divide_by_Zero__int_rand_divide_81.h"\n'
        )
        out = scrub_juliet(text, Language.C).text
        assert "<stdio.h>" in out
        assert "std_testcase.h" not in out
        assert "CWE369" not in out

    def test_a_sibling_header_shares_its_namespace_replacement(self) -> None:
        # Juliet names the header after the namespace it declares. If the two
        # got different replacements the include would stop resolving.
        name = "CWE369_Divide_by_Zero__int_rand_divide_81"
        result = scrub_juliet(f'#include "{name}.h"\nnamespace {name} {{ }}\n', Language.CPP)
        assert f"{result.mapping[name]}.h" in result.text


class TestJavaPackages:
    SOURCE = (
        "package testcases.CWE89_SQL_Injection.s04;\n"
        "import testcasesupport.*;\n"
        "import java.io.IOException;\n"
        "import javax.servlet.http.HttpServletRequest;\n"
        "public class CWE89_SQL_Injection__connect_01 extends AbstractTestCase {\n"
        "  public void bad() throws IOException { }\n"
        "}\n"
    )

    def test_every_package_segment_is_renamed(self) -> None:
        result = scrub_juliet(self.SOURCE, Language.JAVA)
        for segment in ("testcases", "CWE89_SQL_Injection", "s04"):
            assert result.mapping[segment].startswith(PACKAGE_PREFIX)
        assert "CWE89" not in result.text

    def test_the_support_package_is_renamed_as_a_package(self) -> None:
        result = scrub_juliet(self.SOURCE, Language.JAVA)
        assert result.mapping["testcasesupport"].startswith(PACKAGE_PREFIX)

    def test_stdlib_and_api_imports_survive(self) -> None:
        out = scrub_juliet(self.SOURCE, Language.JAVA).text
        assert "java.io.IOException" in out
        assert "javax.servlet.http.HttpServletRequest" in out


class TestStringLiterals:
    def test_status_strings_follow_the_mapping(self) -> None:
        # `printLine("Calling bad()...")` sits directly beside the call site.
        result = scrub_juliet(
            'void bad() { printLine("Calling bad()..."); }', Language.C
        )
        assert "bad" not in result.text
        assert f'"Calling {result.mapping["bad"]}()..."' in result.text

    def test_the_bare_word_is_caught_when_no_identifier_spells_it(self) -> None:
        # In C the functions are called `CWE121_..._bad`, so the word `bad`
        # appears ONLY inside the status string and is minted from there.
        text = 'void CWE121_x_bad() { } int main() { printLine("Calling bad()..."); }'
        assert not unresolved_leaks(scrub_juliet(text, Language.C).text)

    def test_evidence_bearing_literals_are_left_alone(self) -> None:
        # CWE-89, CWE-134 and CWE-23 are carried by their literals. A scrubber
        # that rewrites these destroys the thing the model is meant to find.
        text = (
            'void bad(char *data) {\n'
            '  char *query = "select * from users where name=\'";\n'
            '  char *base = "/tmp/";\n'
            '  printf("%s %d\\n", data, 1);\n'
            '}\n'
        )
        out = scrub_juliet(text, Language.C).text
        assert "select * from users where name='" in out
        assert '"/tmp/"' in out
        assert '"%s %d\\n"' in out

    def test_locals_are_never_substituted_into_literals(self) -> None:
        # `data` maps to `v_1`; a SQL column of the same name must survive.
        text = 'void bad() { char *data = "update t set data = 1"; }'
        out = scrub_juliet(text, Language.C).text
        assert "update t set data = 1" in out


class TestCaseIsTheUnit:
    A = (
        "package testcases.CWE89_SQL_Injection.s04;\n"
        "public class Case_52a { public void bad() { new Case_52b().badSink(); } }\n"
    )
    B = (
        "package testcases.CWE89_SQL_Injection.s04;\n"
        "public class Case_52b { public void badSink() { } }\n"
    )

    def test_one_mapping_spans_every_file(self) -> None:
        # Per-file scrubbing gave `badSink` -> func_3 in 52a and func_2 in 52b,
        # in 43 of the 44 multi-file cases in the sample. The scrubbed Java did
        # not compile and the oracle could not say which method held the flaw.
        result = scrub_juliet_case(
            [("a.java", self.A, Language.JAVA), ("b.java", self.B, Language.JAVA)]
        )
        assert result.files["a.java"].count(result.mapping["badSink"]) == 1
        assert result.files["b.java"].count(result.mapping["badSink"]) == 1
        assert result.mapping["Case_52b"] in result.files["a.java"]

    def test_scrubbed_path_carries_the_scrubbed_package(self) -> None:
        # javac requires `<package path>/<ClassName>.java`, so this is not
        # cosmetic — an unrenamed path both leaks and fails to compile.
        result = scrub_juliet_case([("x/y/Case_52a.java", self.A, Language.JAVA)])
        path = result.paths["x/y/Case_52a.java"]
        assert path.endswith(f"{result.mapping['Case_52a']}.java")
        assert path.startswith(result.mapping["testcases"] + "/")

    def test_c_paths_lose_their_directory(self) -> None:
        # `C/testcases/CWE121_Stack_Based_Buffer_Overflow/s04/` names the CWE
        # just as loudly as the file does.
        result = scrub_juliet_case(
            [("C/testcases/CWE121_x/s04/CWE121_x_01.c", "void bad() {}", Language.C)]
        )
        assert "/" not in result.paths["C/testcases/CWE121_x/s04/CWE121_x_01.c"]


class TestAnalysisMode:
    def test_no_denylist_leaves_scaffolding_alone(self) -> None:
        # §4.0 analysis mode: an arbitrary binary has no answer key to hide,
        # and renaming its symbols destroys what a real analyst relies on.
        text = "void handler() { printLine(x); }"
        result = scrub(text, Language.C)
        assert "printLine" in result.text
        # The file's own declarations are still renamed — that is rule 1, and
        # it is what `scrub` is for. Only the denylist half is switched off.
        assert "handler" not in result.text


# --------------------------------------------------------------------------- #
# Corpus
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def sampled_cases() -> list[dict]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]


@pytest.fixture(scope="module")
def archives() -> dict[str, zipfile.ZipFile]:
    c = zipfile.ZipFile(C_ARCHIVE)
    return {"c": c, "cpp": c, "java": zipfile.ZipFile(J_ARCHIVE)}


def _scrub_sampled(case: dict, archives: dict[str, zipfile.ZipFile]):
    archive = archives[case["language"]]
    files = sorted(
        (name, archive.read(name).decode("utf-8", "replace"), language_of(name))
        for name in case["files"]
    )
    return scrub_juliet_case(files)


@needs_corpus
class TestCorpus:
    """Run the real scrubber over the whole sample and look for the answer key."""

    def test_no_answer_key_survives_in_any_scrubbed_file(
        self, sampled_cases: list[dict], archives: dict[str, zipfile.ZipFile]
    ) -> None:
        leaks: dict[str, list[str]] = {}
        for case in sampled_cases:
            result = _scrub_sampled(case, archives)
            for name, text in result.files.items():
                if found := unresolved_leaks(text):
                    leaks[name] = found
        assert not leaks, f"answer key survives in {len(leaks)} file(s): {leaks}"

    def test_no_answer_key_survives_in_any_scrubbed_path(
        self, sampled_cases: list[dict], archives: dict[str, zipfile.ZipFile]
    ) -> None:
        # The path reaches the prompt too, via the chunk header and the report.
        leaks = {
            path: found
            for case in sampled_cases
            for path in _scrub_sampled(case, archives).paths.values()
            if (found := unresolved_leaks(path))
        }
        assert not leaks, f"answer key survives in {len(leaks)} path(s): {leaks}"

    def test_every_mapping_is_reversible(
        self, sampled_cases: list[dict], archives: dict[str, zipfile.ZipFile]
    ) -> None:
        # Two originals sharing one replacement would make `inverse` lose one,
        # and the Java oracle would point at the wrong method.
        for case in sampled_cases:
            mapping = _scrub_sampled(case, archives).mapping
            assert mapping_is_reversible(mapping), case["case_id"]

    def test_the_flaw_carrying_names_are_all_mapped(
        self, sampled_cases: list[dict], archives: dict[str, zipfile.ZipFile]
    ) -> None:
        # The mapping is the Java oracle. If `bad` is absent from it, nothing
        # records which method held the flaw.
        for case in sampled_cases:
            mapping = _scrub_sampled(case, archives).mapping
            assert "bad" in mapping, case["case_id"]

    def test_api_evidence_survives(
        self, sampled_cases: list[dict], archives: dict[str, zipfile.ZipFile]
    ) -> None:
        # A scrubber that removed the answer key by removing everything would
        # pass every test above. This is the counterweight.
        witnesses = {
            "c": ("printf", "strlen"),
            "cpp": ("printf", "strlen"),
            "java": ("String", "Throwable"),
        }
        seen = {lang: False for lang in witnesses}
        for case in sampled_cases:
            texts = "\n".join(_scrub_sampled(case, archives).files.values())
            if any(w in texts for w in witnesses[case["language"]]):
                seen[case["language"]] = True
        assert all(seen.values()), seen
