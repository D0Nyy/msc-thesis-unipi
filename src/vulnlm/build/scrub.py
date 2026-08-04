"""Rename Juliet's identifiers so the model has to read the code (§4.1).

Juliet writes the answer into its names — `CWE121_..._bad()`, `dataBadBuffer`,
`class CWE89_SQL_Injection__...`. A model can emit the right CWE from the
function name alone, and because Ghidra destroys names at F2 while F0 and F1
keep them, that leakage is *uneven across tiers*. Left alone, the headline
F0→F2 drop would largely measure removal of the answer key rather than loss of
fidelity, and RQ1 would be invalid.

Two rules decide whether a name is renamed:

1. **Declared here** — anything the case declares (function, class, namespace,
   parameter, local, typedef, macro, package) is the author's own vocabulary
   and is renamed.
2. **On the denylist** — Juliet's support surface (`printLine`,
   `globalReturnsTrue`, `AbstractTestCase`, `OMITBAD`, `std_testcase`) is
   referenced but never declared by a case, so rule 1 cannot see it.
   `build/scaffolding.py` enumerates it.

Everything else is left alone, which is the point: `strcpy`, `malloc`,
`Runtime.exec` and `Statement.execute` are what a human reverse engineer reads
too. They are signal, not leakage, and scrubbing them would destroy the
API-call evidence the F2 argument rests on. `_WIN32`, `java.io` and
`javax.servlet` are left alone for the same reason.

Renaming is by NAME, not by scope. A given name maps to one replacement
throughout the case, so every reference follows its declaration automatically
and the result still compiles. Juliet does not shadow in ways that make this
wrong, and a scope-aware renamer would be more machinery for no gain here.

The mapping is returned, never embedded. It is the Java arm's ground-truth
oracle — after scrubbing, `bad()` is `func_3`, and nothing else records which
method held the flaw.

**The unit of scrubbing is the CASE, not the file.** Juliet's 5x/6x/7x/8x flow
variants split source from sink across `a`/`b`/`c` files, and 43 of the 44
multi-file cases in the committed sample declare at least one name in more than
one file. Scrubbing each file with its own counter gives `badSink` → `func_3`
in `52a` and `func_2` in `52b`: the scrubbed Java would not compile, and the
mapping recorded as the oracle would be ambiguous about which method held the
flaw. `scrub_case` therefore collects declarations across every file of a case
before minting a single replacement, and `scrub` — the single-file entry point
— is the degenerate one-file case of it.

Five leak classes beyond bare identifiers, all found by the corpus-wide
assertion in `tests/test_scrub.py` rather than by reading the code:

* **Java package and import paths.** `package testcases.CWE89_SQL_Injection.s04;`
  names the CWE, survives javac as a structural part of the class file, and is
  not an identifier declaration any grammar rule would catch. Each segment
  becomes `pkg_<n>`. `import java.io.IOException` is untouched, because those
  segments are neither declared nor denylisted.
* **String literals.** `printLine("Calling bad()...")` and
  `IO.writeLine("bad: 100/" + data)` sit directly beside the flaw. Only tokens
  already in the mapping are rewritten, at word boundaries, and only those that
  name a function, class, package, macro or file — never a local. SQL queries,
  format strings and `BASEPATH "/tmp/"` are the CWE-89/134/23 evidence and must
  survive intact.
* **`#define` names.** An `identifier` node, but under `preproc_def`, which no
  declaration rule recognised.
* **`#ifndef OMITBAD` / `#ifdef INCLUDEMAIN`.** Denylisted rather than declared,
  since the `-D` comes from the build system. See `scaffolding.py` for why
  renaming them is safe.
* **Local `#include` paths.** `#include "CWE369_..._81.h"` carries the whole
  answer. Mapped by stem, so a sibling header whose stem is also the case's
  namespace reuses that replacement and the include still resolves.
  `#include <stdio.h>` is untouched.
"""

import posixpath
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from tree_sitter import Language as TSLanguage
from tree_sitter import Node, Parser, Tree

from vulnlm.build.scaffolding import (
    ALL_SCAFFOLDING,
    C_BUILD_MACROS,
    C_MACROS,
    C_SUPPORT_HEADERS,
    C_TYPES,
    JAVA_SUPPORT_CLASSES,
    JAVA_SUPPORT_PACKAGE,
)
from vulnlm.schema import Language

# --------------------------------------------------------------------------- #
# Naming
# --------------------------------------------------------------------------- #

FUNCTION_PREFIX: Final[str] = "func"
CLASS_PREFIX: Final[str] = "Class"
VARIABLE_PREFIX: Final[str] = "v"
PACKAGE_PREFIX: Final[str] = "pkg"
MACRO_PREFIX: Final[str] = "MACRO"
FILE_PREFIX: Final[str] = "file"

ALL_PREFIXES: Final[tuple[str, ...]] = (
    FUNCTION_PREFIX, CLASS_PREFIX, VARIABLE_PREFIX,
    PACKAGE_PREFIX, MACRO_PREFIX, FILE_PREFIX,
)

# Kinds whose names are Juliet vocabulary rather than ordinary English, and so
# are safe to rewrite inside string literals. Locals are excluded on purpose:
# `data`, `source` and `count` plausibly occur in a SQL query or a format
# string, and corrupting those would destroy the evidence §4.1 exists to keep.
LITERAL_SAFE_PREFIXES: Final[frozenset[str]] = frozenset({
    FUNCTION_PREFIX, CLASS_PREFIX, PACKAGE_PREFIX, MACRO_PREFIX, FILE_PREFIX,
})

# Which tree-sitter node types declare which kind of name. The `name`/
# `declarator` field is followed down to the identifier leaf.
_FUNCTION_NODES: Final[frozenset[str]] = frozenset({
    "function_definition", "function_declarator", "method_declaration",
    "constructor_declaration",
})
_CLASS_NODES: Final[frozenset[str]] = frozenset({
    "class_specifier", "struct_specifier", "namespace_definition",
    "class_declaration", "interface_declaration", "enum_specifier",
    "type_definition", "enum_declaration",
})
_VARIABLE_NODES: Final[frozenset[str]] = frozenset({
    "parameter_declaration", "init_declarator", "declaration",
    "formal_parameter", "local_variable_declaration", "variable_declarator",
    "field_declaration", "array_declarator", "pointer_declarator",
    "catch_formal_parameter",
})
# `#define FOO` and `#define FOO(x)`. The name is a plain `identifier`, so the
# walk already visits it; what was missing is that nothing marked it declared.
_MACRO_NODES: Final[frozenset[str]] = frozenset({
    "preproc_def", "preproc_function_def",
})
# Every identifier under a package declaration is a path segment, including the
# nested `scoped_identifier` spine.
_PACKAGE_NODES: Final[frozenset[str]] = frozenset({"package_declaration"})

_IDENTIFIER_LEAVES: Final[frozenset[str]] = frozenset({
    "identifier", "type_identifier", "field_identifier", "namespace_identifier",
    "statement_identifier", "scoped_identifier",
})

_COMMENT_NODES: Final[frozenset[str]] = frozenset({"comment", "line_comment", "block_comment"})

# The text inside a quoted string, without the quotes. C and Java spell it
# differently; `system_lib_string` (`<stdio.h>`) is absent on purpose.
_STRING_BODY_NODES: Final[frozenset[str]] = frozenset({
    "string_content", "string_fragment",
})

# Denylisted names carry no kind of their own, so it is supplied here. Doing it
# by table rather than by "capitalised means class" keeps `testcasesupport` a
# package and `OMITBAD` a macro, which is what the replacement has to look like
# for the scrubbed text to still read as the language it is written in.
_DENY_KINDS: Final[dict[str, str]] = {
    **{n: PACKAGE_PREFIX for n in (JAVA_SUPPORT_PACKAGE,)},
    **{n: CLASS_PREFIX for n in JAVA_SUPPORT_CLASSES | C_TYPES},
    **{n: MACRO_PREFIX for n in C_MACROS | C_BUILD_MACROS},
    **{n: FILE_PREFIX for n in C_SUPPORT_HEADERS},
}


@dataclass
class ScrubResult:
    """Scrubbed text plus the mapping needed to score against it."""

    text: str
    # original -> replacement. The Java oracle: `bad` -> `func_3`.
    mapping: dict[str, str] = field(default_factory=dict)

    @property
    def inverse(self) -> dict[str, str]:
        """replacement -> original. What `eval` needs to localise a finding."""
        return {v: k for k, v in self.mapping.items()}


@dataclass
class CaseScrub:
    """One case's files scrubbed against a single shared mapping.

    `files` is keyed by the input path and holds the scrubbed text. `paths`
    maps input path to the path the scrubbed file should be written at, which
    for Java is load-bearing: javac requires `pkg_1/pkg_2/Class_1.java`.
    """

    files: dict[str, str] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)
    mapping: dict[str, str] = field(default_factory=dict)

    @property
    def inverse(self) -> dict[str, str]:
        return {v: k for k, v in self.mapping.items()}


def _parser_for(language: Language) -> Parser:
    if language is Language.JAVA:
        import tree_sitter_java as ts

        return Parser(TSLanguage(ts.language()))
    if language is Language.CPP:
        import tree_sitter_cpp as ts

        return Parser(TSLanguage(ts.language()))
    import tree_sitter_c as ts

    return Parser(TSLanguage(ts.language()))


def _leaf_name(node: Node) -> Node | None:
    """The identifier a declarator ultimately names.

    Declarators nest — `char **argv[]` is pointer inside array inside
    identifier — so the name is found by descending rather than by indexing a
    fixed field.
    """
    if node.type in _IDENTIFIER_LEAVES:
        return node
    for child in node.children:
        if child.type in _IDENTIFIER_LEAVES:
            return child
    for child in node.children:
        if (found := _leaf_name(child)) is not None:
            return found
    return None


def _text_of(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _classify_declarations(root: Node, source: bytes, kinds: dict[str, str]) -> None:
    """Record name -> kind for everything this file declares.

    Accumulates into `kinds` rather than returning, so a case's files can be
    classified together before any replacement is minted.
    """

    def visit(node: Node) -> None:
        if node.type in _PACKAGE_NODES:
            # Every segment of the path, not just the last: `testcases`,
            # `CWE89_SQL_Injection` and `s04` are three separate names and only
            # the middle one carries the CWE.
            for name in _identifiers_under(node, source):
                kinds.setdefault(name, PACKAGE_PREFIX)
            return

        prefix: str | None = None
        if node.type in _MACRO_NODES:
            prefix = MACRO_PREFIX
        elif node.type in _FUNCTION_NODES:
            prefix = FUNCTION_PREFIX
        elif node.type in _CLASS_NODES:
            prefix = CLASS_PREFIX
        elif node.type in _VARIABLE_NODES:
            prefix = VARIABLE_PREFIX

        if prefix is not None:
            target = node.child_by_field_name("name") or node.child_by_field_name(
                "declarator"
            )
            leaf = _leaf_name(target if target is not None else node)
            if leaf is not None:
                name = _text_of(leaf, source)
                # A function declarator inside a declaration wins: the outer
                # node would otherwise label `void f(void)` as a variable.
                if name and (prefix != VARIABLE_PREFIX or name not in kinds):
                    kinds[name] = prefix
        for child in node.children:
            visit(child)

    visit(root)


def _identifiers_under(node: Node, source: bytes) -> list[str]:
    """Every identifier leaf beneath `node`, in source order."""
    found: list[str] = []

    def walk(n: Node) -> None:
        if n.type in _IDENTIFIER_LEAVES and not n.children:
            found.append(_text_of(n, source))
        for child in n.children:
            walk(child)

    walk(node)
    return found


class _Renamer:
    """The shared mapping and counters for one scrub unit."""

    def __init__(self, deny: frozenset[str]) -> None:
        self.deny = deny
        self.kinds: dict[str, str] = {}
        self.counters: dict[str, int] = dict.fromkeys(ALL_PREFIXES, 0)
        self.mapping: dict[str, str] = {}

    def kind_of(self, name: str) -> str | None:
        if (prefix := self.kinds.get(name)) is not None:
            return prefix
        if name in self.deny:
            # Scaffolding referenced but not declared here. Kind comes from the
            # table above where known, and falls back to the capitalisation
            # convention for a caller-supplied denylist we know nothing about.
            return _DENY_KINDS.get(
                name, CLASS_PREFIX if name[:1].isupper() else FUNCTION_PREFIX
            )
        return None

    def replacement_for(self, name: str) -> str | None:
        """Mint or recall the replacement for `name`, or None to leave it."""
        if name in self.mapping:
            return self.mapping[name]
        prefix = self.kind_of(name)
        if prefix is None:
            return None
        self.counters[prefix] += 1
        self.mapping[name] = f"{prefix}_{self.counters[prefix]}"
        return self.mapping[name]

    def replacement_for_file(self, stem: str) -> str | None:
        """A filename stem. Reuses the identifier entry when there is one.

        Juliet names a sibling header after the namespace it declares, so
        `CWE369_..._81.h` and `namespace CWE369_..._81` are the same string and
        must land on the same replacement or the include stops resolving.
        """
        if (existing := self.replacement_for(stem)) is not None:
            return existing
        self.counters[FILE_PREFIX] += 1
        self.mapping[stem] = f"{FILE_PREFIX}_{self.counters[FILE_PREFIX]}"
        return self.mapping[stem]

    def literal_token(self, token: str) -> str | None:
        """Mint the replacement a token inside a string literal should get.

        Two ways a token qualifies, and the second is why this is not just a
        lookup in `mapping`:

        1. It names something renamed elsewhere, and the kind is literal-safe.
           In C this is the only path that catches `"Calling bad()..."` — the
           functions are called `CWE121_..._bad`, so the bare word `bad` never
           appears as an identifier and is minted here for the first time.
        2. It is answer-key shaped and nothing else claims it —
           `CWE643_Xpath_Injection__Helper` in a resource path. Mapped whole, as
           a filename, so the `.xml` extension survives and the string still
           reads as a path.
        """
        if (prefix := self.kind_of(token)) is not None:
            if prefix not in LITERAL_SAFE_PREFIXES:
                return None
            return self.replacement_for(token)
        if any(p.search(token) for p in LEAK_PATTERNS):
            return self.replacement_for_file(token)
        return None


def _include_path_node(node: Node) -> Node | None:
    """The `string_content` of a local `#include "..."`, if this is one.

    Returns None for `#include <stdio.h>`: a system header is API surface, and
    §4.1 keeps API surface.
    """
    if node.type != "preproc_include":
        return None
    path = node.child_by_field_name("path")
    if path is None or path.type != "string_literal":
        return None
    for child in path.children:
        if child.type in _STRING_BODY_NODES:
            return child
    return None


# A maximal identifier-shaped run. String literals are rewritten token by token
# rather than by alternation over the mapping, so the longest match wins for
# free: `goodG2BSink` is one token, never `good` followed by a tail.
_LITERAL_TOKEN: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9_]+")


def _mint(tree: Tree, source: bytes, renamer: _Renamer, literals: bool) -> None:
    """Pass 1 — walk the file and create every replacement it needs.

    Separate from emitting edits so that a string literal seen early can still
    be rewritten with a name first declared later in the case. Encounter order
    fixes the numbering, so this pass must visit in exactly the order pass 2
    does. Run twice per case: once for identifiers over every file, then once
    for string literals, so a literal never mints ahead of a real declaration.
    """

    def walk(node: Node) -> None:
        if node.type in _COMMENT_NODES:
            return
        if (path := _include_path_node(node)) is not None:
            if not literals:
                stem, _ = posixpath.splitext(_text_of(path, source))
                renamer.replacement_for_file(stem)
            return
        if node.type in _STRING_BODY_NODES:
            if literals:
                for match in _LITERAL_TOKEN.finditer(_text_of(node, source)):
                    renamer.literal_token(match.group(0))
            return
        if not literals and node.type in _IDENTIFIER_LEAVES and not node.children:
            renamer.replacement_for(_text_of(node, source))
        for child in node.children:
            walk(child)

    walk(tree.root_node)


def _rewrite_literal(body: str, renamer: _Renamer) -> str:
    """Substitute the literal-safe half of the mapping into one string body.

    Locals are skipped by construction: `data` maps to `v_2`, and `v` is not a
    literal-safe prefix, so a SQL query mentioning a column called `data` comes
    through untouched.
    """

    def swap(match: re.Match[str]) -> str:
        new = renamer.mapping.get(match.group(0))
        if new is None or new.rsplit("_", 1)[0] not in LITERAL_SAFE_PREFIXES:
            return match.group(0)
        return new

    return _LITERAL_TOKEN.sub(swap, body)


def _edits(tree: Tree, source: bytes, renamer: _Renamer) -> list[tuple[int, int, str]]:
    """Pass 2 — (start, end, replacement) for everything this file changes."""
    out: list[tuple[int, int, str]] = []

    def walk(node: Node) -> None:
        if node.type in _COMMENT_NODES:
            out.append((node.start_byte, node.end_byte, ""))
            return
        if (path := _include_path_node(node)) is not None:
            stem, ext = posixpath.splitext(_text_of(path, source))
            if (new := renamer.mapping.get(stem)) is not None:
                out.append((path.start_byte, path.end_byte, f"{new}{ext}"))
            return
        if node.type in _STRING_BODY_NODES:
            body = _text_of(node, source)
            if (rewritten := _rewrite_literal(body, renamer)) != body:
                out.append((node.start_byte, node.end_byte, rewritten))
            return
        if (
            node.type in _IDENTIFIER_LEAVES
            and not node.children
            and (new := renamer.mapping.get(_text_of(node, source))) is not None
        ):
            out.append((node.start_byte, node.end_byte, new))
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return out


def _apply(source: bytes, edits: list[tuple[int, int, str]]) -> str:
    out = bytearray(source)
    # Back to front, so earlier offsets stay valid as later ones are replaced.
    for start, end, new in sorted(edits, key=lambda e: e[0], reverse=True):
        out[start:end] = new.encode("utf-8")
    text = out.decode("utf-8", "replace")
    # Comment removal leaves ragged whitespace; collapse it so the prompt is
    # not padded with blank lines that cost tokens and tell the model nothing.
    text = re.sub(r"[ \t]+\n", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text)


def _scrubbed_path(path: str, source: bytes, tree: Tree, renamer: _Renamer) -> str:
    """Where the scrubbed file should be written.

    §4.1 sends filenames to opaque IDs, and for Java that is not cosmetic:
    javac requires the public class to sit at `<package path>/<ClassName>.java`,
    so an unrenamed path would leak the CWE *and* fail to compile.

    The result is always relative and never keeps the input directory —
    `C/testcases/CWE121_Stack_Based_Buffer_Overflow/s04/` names the CWE just as
    loudly as the file does. Java gets the scrubbed package path because javac
    demands it; everything else gets a bare basename and the caller chooses
    where to root it.
    """
    stem, ext = posixpath.splitext(posixpath.basename(path))
    new_stem = renamer.mapping.get(stem) or renamer.replacement_for_file(stem)

    package = _package_of(tree.root_node, source)
    if package is None:
        return f"{new_stem}{ext}"
    segments = [renamer.mapping.get(s, s) for s in package]
    return posixpath.join(*segments, f"{new_stem}{ext}")


def _package_of(root: Node, source: bytes) -> list[str] | None:
    for child in root.children:
        if child.type in _PACKAGE_NODES:
            return _identifiers_under(child, source)
    return None


def scrub_case(
    files: Sequence[tuple[str, str, Language]],
    *,
    denylist: frozenset[str] | None = None,
) -> CaseScrub:
    """Scrub every file of one case against a single shared mapping.

    `files` is (path, text, language) in a stable order — sort it before
    calling, because encounter order determines the numbering and an unstable
    order would make the mapping non-reproducible.

    Declarations are collected from *all* files before any replacement is
    minted, so a name defined in `52b` and referenced in `52a` still gets the
    right kind. See the module docstring for why the case, not the file, is the
    unit.
    """
    renamer = _Renamer(denylist if denylist is not None else frozenset())

    parsed: list[tuple[str, bytes, Tree]] = []
    for path, text, language in files:
        source = text.encode("utf-8")
        parsed.append((path, source, _parser_for(language).parse(source)))

    for _, source, tree in parsed:
        _classify_declarations(tree.root_node, source, renamer.kinds)
    for _, source, tree in parsed:
        _mint(tree, source, renamer, literals=False)
    # The case's own filenames, before literals, so a stem that also appears in
    # a resource path gets one replacement rather than two.
    for path, _, _ in parsed:
        renamer.replacement_for_file(posixpath.splitext(posixpath.basename(path))[0])
    for _, source, tree in parsed:
        _mint(tree, source, renamer, literals=True)

    result = CaseScrub(mapping=renamer.mapping)
    for path, source, tree in parsed:
        result.files[path] = _apply(source, _edits(tree, source, renamer))
        result.paths[path] = _scrubbed_path(path, source, tree, renamer)
    return result


def scrub(
    text: str, language: Language, *, denylist: frozenset[str] | None = None
) -> ScrubResult:
    """Rename declared and scaffolding identifiers in one file; strip comments.

    The single-file case of `scrub_case`. `denylist` defaults to none, which
    makes this a safe no-op transform for the analysis mode of §4.0 — an
    arbitrary target has no answer key to hide, and renaming its symbols would
    destroy what a real analyst relies on. Benchmark mode passes
    `ALL_SCAFFOLDING`.
    """
    case = scrub_case([("<text>", text, language)], denylist=denylist)
    return ScrubResult(text=case.files["<text>"], mapping=case.mapping)


def scrub_juliet(text: str, language: Language) -> ScrubResult:
    """Benchmark-mode scrub of one file: declared names plus Juliet's surface."""
    return scrub(text, language, denylist=ALL_SCAFFOLDING)


def scrub_juliet_case(files: Sequence[tuple[str, str, Language]]) -> CaseScrub:
    """Benchmark-mode scrub of a whole case. The form `build` calls."""
    return scrub_case(files, denylist=ALL_SCAFFOLDING)


def language_of(path: str) -> Language:
    """The language a Juliet source file is written in, from its extension.

    `.h` is treated as C++ because Juliet's headers are shared between `.c` and
    `.cpp` cases and the C++ grammar parses the C subset, while the reverse is
    not true — a header declaring a namespace would fail to parse as C and the
    namespace name, which is the leak, would survive.
    """
    if path.endswith(".java"):
        return Language.JAVA
    if path.endswith((".cpp", ".hpp", ".cc", ".h")):
        return Language.CPP
    return Language.C


def unresolved_leaks(
    text: str, patterns: Iterable[re.Pattern[str]] | None = None
) -> list[str]:
    """Every answer-key token still present in `text`.

    Kept beside the scrubber rather than in the tests because `build` asserts
    on it too: a leak that only the test suite checks is a leak that reaches a
    prompt the first time someone runs the corpus with the tests skipped.
    """
    checks = list(patterns) if patterns is not None else list(LEAK_PATTERNS)
    return sorted({m.group(0) for p in checks for m in p.finditer(text)})


# `CWE\d+` in any casing, and any identifier-shaped token starting `bad`/`good`.
# The second is deliberately broad: it fires on `badSink`, `goodG2B`, `bad1`
# and the bare words in `"Calling bad()..."`.
LEAK_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"CWE[-_]?\d+", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])(?:bad|good)[A-Za-z0-9_]*", re.IGNORECASE),
)


def mapping_is_reversible(mapping: Mapping[str, str]) -> bool:
    """No two originals share a replacement.

    If they did, `inverse` would silently lose one and the Java oracle would
    point at the wrong method.
    """
    return len(set(mapping.values())) == len(mapping)
