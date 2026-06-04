"""
refactor/parser.py
──────────────────
tree-sitter wrapper. The only module in the project that imports tree-sitter directly.
Everything else interacts with C source through the types and functions defined here.

Dependency note: requires tree-sitter==0.21.3 and tree-sitter-c==0.21.4
The API changed significantly in 0.21 — if you see Language.build_library() anywhere
in documentation or tutorials, that is the OLD API. Ignore it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

import tree_sitter_c
from tree_sitter import Language, Node, Parser


# ─────────────────────────────────────────────
# MODULE-LEVEL SINGLETONS
# Building Language and Parser objects is non-trivial work.
# Do it once at import time, reuse everywhere.
# ─────────────────────────────────────────────

C_LANGUAGE = Language(tree_sitter_c.language(), "c")
_PARSER = Parser()
_PARSER.set_language(C_LANGUAGE)


# ─────────────────────────────────────────────
# RESULT TYPE
# ─────────────────────────────────────────────

@dataclass
class ParsedFile:
    """
    The result of parsing a single C source file.
    Everything downstream (CFG builder, detectors) receives one of these.

    source_bytes: the raw file content as bytes.
                  tree-sitter works in bytes internally — always pass source_bytes
                  when calling node.text or any byte-offset operation, never
                  re-read the file. This is the single source of truth for content.

    has_errors:   True if tree-sitter embedded any ERROR nodes in the tree.
                  We still return the partial tree — tree-sitter's error recovery
                  means the rest of the file is often still usable.

    error_nodes:  the ERROR nodes themselves, for reporting to the user.

    file_path:    None when parsed from a raw string (e.g. in tests or for
                  verifier re-parsing of LLM output).
    """
    tree:           object          # tree_sitter.Tree — opaque outside this module
    source_bytes:   bytes
    has_errors:     bool
    error_nodes:    list[Node]      = field(default_factory=list)
    file_path:      Optional[Path]  = None

    @property
    def root(self) -> Node:
        """The root node of the syntax tree (always a translation_unit in C)."""
        return self.tree.root_node


# ─────────────────────────────────────────────
# PARSE ENTRYPOINTS
# ─────────────────────────────────────────────

def parse_file(path: str | Path) -> ParsedFile:
    """
    Parse a C source file from disk.
    Raises FileNotFoundError if the path doesn't exist.
    Never raises on parse errors — check result.has_errors instead.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {path}")

    source_bytes = path.read_bytes()
    return _parse_bytes(source_bytes, file_path=path)


def parse_string(source: str, file_path: Optional[Path] = None) -> ParsedFile:
    """
    Parse C source from a string.
    Used by:
      - tests (no temp files needed)
      - verifier.py (re-parsing LLM suggestions before accepting them)
      - the tree-sitter playground equivalent in your own debugging

    file_path is optional metadata — pass it if you know the origin.
    """
    return _parse_bytes(source.encode("utf-8"), file_path=file_path)


def _parse_bytes(source_bytes: bytes, file_path: Optional[Path]) -> ParsedFile:
    """
    Internal implementation — both public entrypoints delegate here.
    Keeping the byte-handling in one place means we never accidentally
    mix encodings between the two entrypoints.
    """
    tree = _PARSER.parse(source_bytes)
    error_nodes = list(_collect_error_nodes(tree.root_node))
    return ParsedFile(
        tree=tree,
        source_bytes=source_bytes,
        has_errors=len(error_nodes) > 0,
        error_nodes=error_nodes,
        file_path=file_path,
    )


# ─────────────────────────────────────────────
# NODE TEXT EXTRACTION
# ─────────────────────────────────────────────

def node_text(node: Node, source_bytes: bytes) -> str:
    """
    Extract the source text for a node.

    Why not node.text?
    tree-sitter's Node.text property only works when the tree was parsed
    with source bytes attached directly to the parser — which is not
    guaranteed in all versions of the Python bindings. Going through
    byte offsets is always safe and explicit.

    This is the function you will call hundreds of times. Know it well.
    """
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8")


def node_lines(node: Node, source_bytes: bytes) -> list[str]:
    """
    Return the source lines covered by this node, as a list.
    Useful for the context extractor when building the LLM prompt —
    you often want a few lines of surrounding context, not just the node itself.
    """
    text = node_text(node, source_bytes)
    return text.splitlines()


# ─────────────────────────────────────────────
# TREE TRAVERSAL
# ─────────────────────────────────────────────

def iter_functions(parsed: ParsedFile) -> Iterator[Node]:
    """
    Yield every function_definition node in the file.
    This is the primary entry point for detectors and the CFG builder —
    both operate function by function.

    tree-sitter node type for a C function definition:
        function_definition
            type:         (primitive_type) | (type_specifier) | ...
            declarator:   (function_declarator
                              declarator: (identifier)       ← function name
                              parameters: (parameter_list))
            body:         (compound_statement)               ← the { ... } block
    """
    yield from _iter_nodes_of_type(parsed.root, "function_definition")


def iter_nodes_of_type(root: Node, node_type: str) -> Iterator[Node]:
    """
    Public wrapper for recursive node-type search.
    Used by detectors that need to find all nodes of a given type
    within a subtree (e.g. all call_expression nodes inside a function body).
    """
    yield from _iter_nodes_of_type(root, node_type)


def _iter_nodes_of_type(node: Node, node_type: str) -> Iterator[Node]:
    """
    Depth-first recursive traversal yielding all nodes of the given type.
    Visits the entire subtree rooted at 'node'.

    Note: tree-sitter also provides cursor-based traversal (node.walk())
    which is faster for very large files. For files under ~5000 lines,
    this recursive version is fine and easier to reason about.
    We'll note this as an optimisation opportunity if profiling ever shows it matters.
    """
    if node.type == node_type:
        yield node
    for child in node.children:
        yield from _iter_nodes_of_type(child, node_type)


def get_function_name(func_node: Node, source_bytes: bytes) -> Optional[str]:
    """
    Extract the name of a function from its function_definition node.

    The structure is always:
        function_definition
            declarator: function_declarator
                declarator: identifier    ← this is the name

    We navigate this path explicitly rather than searching the whole subtree
    to avoid accidentally picking up a nested function pointer's name.
    """
    declarator = func_node.child_by_field_name("declarator")
    if declarator is None:
        return None

    # Handle pointer-returning functions: int *foo() {...}
    # The declarator is a pointer_declarator wrapping the function_declarator
    if declarator.type == "pointer_declarator":
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None:
        return None

    if declarator.type == "function_declarator":
        name_node = declarator.child_by_field_name("declarator")
        if name_node is not None:
            return node_text(name_node, source_bytes)

    return None


def get_function_body(func_node: Node) -> Optional[Node]:
    """
    Return the compound_statement node (the { } block) of a function.
    Returns None for function declarations (no body — just a prototype).
    """
    return func_node.child_by_field_name("body")


def get_function_signature(func_node: Node, source_bytes: bytes) -> str:
    """
    Return the function signature (everything before the opening brace).
    Used by the context extractor when building LLM prompts —
    the LLM needs to know the parameter types to write a correct fix.

    e.g. "int *make_buffer(int n)"
    """
    body = get_function_body(func_node)
    if body is None:
        return node_text(func_node, source_bytes)
    # Everything from function start up to (not including) the body
    sig_bytes = source_bytes[func_node.start_byte:body.start_byte]
    return sig_bytes.decode("utf-8").strip()


# ─────────────────────────────────────────────
# SCOPE UTILITIES
# ─────────────────────────────────────────────

def get_enclosing_function(node: Node) -> Optional[Node]:
    """
    Walk up the tree from a node to find its enclosing function_definition.
    Returns None if the node is at file scope (global variable, etc.)

    Used by detectors when they have a flagged node and need the
    full function context to hand to the CFG builder.
    """
    current = node.parent
    while current is not None:
        if current.type == "function_definition":
            return current
        current = current.parent
    return None


def get_enclosing_block(node: Node) -> Optional[Node]:
    """
    Walk up the tree to find the nearest enclosing compound_statement ({ }).
    This is the syntactic scope boundary in C.

    Note: C has block scope, not function scope, for local variables.
    A variable declared inside an if-body is not visible after the closing brace.
    This matters for the pointer state tracker.
    """
    current = node.parent
    while current is not None:
        if current.type == "compound_statement":
            return current
        current = current.parent
    return None


def iter_variable_declarations(scope_node: Node) -> Iterator[Node]:
    """
    Yield all declaration nodes that are direct children of a scope node.
    Only yields declarations at this scope level — not nested scopes.

    Used by the context extractor to build the ScopeVariable list
    that gets sent to the LLM.
    """
    for child in scope_node.children:
        if child.type == "declaration":
            yield child


# ─────────────────────────────────────────────
# PATTERN QUERIES
# ─────────────────────────────────────────────

def run_query(pattern: str, node: Node, source_bytes: bytes) -> list[dict[str, Node]]:
    """
    Run a tree-sitter S-expression query against a subtree.
    Returns a list of match dicts, each mapping capture name → Node.

    S-expression query syntax (tree-sitter specific):
        (call_expression
            function: (identifier) @fn_name
            (#eq? @fn_name "malloc"))

    This captures the identifier node of any call to malloc().
    The capture name is "fn_name" — it appears in the result dict.

    For a full query language reference:
    https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries

    Example usage in a detector:
        matches = run_query(MALLOC_QUERY, func_node, source_bytes)
        for match in matches:
            malloc_node = match["fn_name"].parent  # the call_expression
    """
    query = C_LANGUAGE.query(pattern)
    # query.matches() returns list of (pattern_index, capture_dict)
    # We discard the pattern index and return just the capture dicts
    return [captures for _, captures in query.matches(node)]


# ─────────────────────────────────────────────
# ERROR HANDLING
# ─────────────────────────────────────────────

def _collect_error_nodes(node: Node) -> Iterator[Node]:
    """
    Recursively find all ERROR and MISSING nodes in the tree.

    tree-sitter never raises on malformed input — it embeds ERROR nodes
    instead and continues parsing. This is what makes it suitable for
    analysing real-world code that may not be perfectly formatted.

    MISSING nodes appear when tree-sitter inserted a token to recover
    from an error — e.g. a missing semicolon. Both types are worth surfacing.
    """
    if node.type in ("ERROR", "MISSING") or node.is_error:
        yield node
    for child in node.children:
        yield from _collect_error_nodes(child)


def has_parse_errors(parsed: ParsedFile) -> bool:
    """Convenience predicate. Use this rather than checking has_errors directly."""
    return parsed.has_errors


# ─────────────────────────────────────────────
# MULTI-FILE INGESTION
# ─────────────────────────────────────────────

def parse_directory(
    directory: str | Path,
    recursive: bool = True,
    extensions: tuple[str, ...] = (".c", ".h"),
) -> dict[Path, ParsedFile]:
    """
    Parse all C source files in a directory.
    Returns a dict mapping file path → ParsedFile.

    Files that fail to read (permissions, encoding) are skipped with a warning.
    Files with parse errors are included — the caller decides what to do with them.

    This is the entry point for multi-file analysis and the call graph builder.
    """
    directory = Path(directory)
    results: dict[Path, ParsedFile] = {}

    pattern = "**/*" if recursive else "*"
    for path in directory.glob(pattern):
        if path.suffix not in extensions:
            continue
        if not path.is_file():
            continue
        try:
            results[path] = parse_file(path)
        except (OSError, UnicodeDecodeError) as exc:
            # Don't crash on unreadable files — warn and continue
            import warnings
            warnings.warn(f"Skipping {path}: {exc}", stacklevel=2)

    return results