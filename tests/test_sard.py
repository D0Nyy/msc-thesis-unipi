"""Tests for the SARD manifest.xml reader.

The manifest is one of the two independent statements of ground truth (the
other is the filename). Both feed the label that everything downstream is
scored against, so a silent misparse here has the same consequence as a bug in
`eval/`: numbers that look plausible and are wrong.

The XML fragments below reproduce the real structures, including the two
defects found in the shipped archives — inconsistent zero padding, and the
unmatched closing tags in Juliet Java 1.3.
"""

import pytest

from vulnlm.build.sard import Flaw, normalise_cwe_id, parse_manifest, repair_manifest

CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<container>
  <testcase>
    <file path="CWE114_Process_Control__w32_char_connect_socket_01.c">
      <flaw line="121" name="CWE-114: Process Control"/>
    </file>
  </testcase>
  <testcase>
    <file path="CWE113_HTTP_Response_Splitting__Environment_addCookie_01.java">
      <flaw line="33" name="CWE-113: Improper Neutralization of CRLF Sequences"/>
      <flaw line="39" name="CWE-113: Improper Neutralization of CRLF Sequences"/>
    </file>
    <file path="JNITest.dll"/>
  </testcase>
</container>
"""

# The Juliet Java 1.3 defect: a duplicated </testcase>.
MALFORMED = """<?xml version="1.0" encoding="utf-8"?>
<container>
  <testcase>
    <file path="CWE190_Integer_Overflow__short_rand_postinc_81a.java"/>
  </testcase>
  </testcase>
  <testcase>
    <file path="CWE190_Integer_Overflow__byte_console_readLine_preinc_01.java">
      <flaw line="42" name="CWE-190: Integer Overflow or Wraparound"/>
    </file>
  </testcase>
</container>
"""


class TestNormaliseCweId:
    """The manifest writes CWE-036, the filename writes CWE36. Same weakness.
    Comparing raw strings reports ~10,000 false disagreements in C/C++ alone."""

    @pytest.mark.parametrize(
        "raw", ["CWE-036", "CWE-36", "CWE36", "036", "36", 36, " CWE-036 "]
    )
    def test_all_forms_normalise(self, raw: str | int) -> None:
        assert normalise_cwe_id(raw) == "CWE-36"

    def test_no_number_raises(self) -> None:
        with pytest.raises(ValueError):
            normalise_cwe_id("not a cwe")


class TestRepairManifest:
    def test_clean_document_untouched(self) -> None:
        repaired, dropped = repair_manifest(CLEAN)
        assert dropped == []
        assert repaired == CLEAN

    def test_unmatched_close_dropped_and_reported(self) -> None:
        repaired, dropped = repair_manifest(MALFORMED)
        assert dropped == [6]
        assert repaired.count("</testcase>") == repaired.count("<testcase>")

    def test_repair_preserves_content(self) -> None:
        """Only the stray tag goes. Every file entry must survive."""
        repaired, _ = repair_manifest(MALFORMED)
        assert "CWE190_Integer_Overflow__short_rand_postinc_81a.java" in repaired
        assert "CWE190_Integer_Overflow__byte_console_readLine_preinc_01.java" in repaired


class TestParseManifest:
    def test_single_flaw(self) -> None:
        flaws, dropped = parse_manifest(CLEAN)
        assert dropped == []
        key = "CWE114_Process_Control__w32_char_connect_socket_01.c"
        assert flaws[key] == [
            Flaw(cwe_id="CWE-114", cwe_name="Process Control", line=121)
        ]

    def test_multiple_flaw_lines_same_file(self) -> None:
        flaws, _ = parse_manifest(CLEAN)
        key = "CWE113_HTTP_Response_Splitting__Environment_addCookie_01.java"
        assert [f.line for f in flaws[key]] == [33, 39]
        assert {f.cwe_id for f in flaws[key]} == {"CWE-113"}

    def test_files_without_flaws_are_omitted(self) -> None:
        """Absence is ambiguous — good-only files, non-sink halves and .dll
        members all lack flaws. Callers must decide, so they must not receive
        an empty list that reads as 'checked, none found'."""
        flaws, _ = parse_manifest(CLEAN)
        assert "JNITest.dll" not in flaws

    def test_parses_through_the_java_defect(self) -> None:
        """Content after the stray tag must still be reachable — a parser that
        aborts here loses two thirds of the Java ground truth."""
        flaws, dropped = parse_manifest(MALFORMED)
        assert dropped == [6]
        key = "CWE190_Integer_Overflow__byte_console_readLine_preinc_01.java"
        assert flaws[key][0].cwe_id == "CWE-190"
        assert flaws[key][0].line == 42

    def test_padded_ids_normalised_on_read(self) -> None:
        doc = CLEAN.replace('name="CWE-114:', 'name="CWE-0114:')
        flaws, _ = parse_manifest(doc)
        key = "CWE114_Process_Control__w32_char_connect_socket_01.c"
        assert flaws[key][0].cwe_id == "CWE-114"

    def test_basename_keying(self) -> None:
        doc = CLEAN.replace('path="CWE114', 'path="testcases/CWE114_x/CWE114')
        flaws, _ = parse_manifest(doc)
        assert "CWE114_Process_Control__w32_char_connect_socket_01.c" in flaws
