"""
refactor/verifier.py
─────────────────────
Re-parses LLM suggestions and verifies them before showing to the user.

Consumes: Finding + LLMResponse (from llm_client.py)
Produces: VerifiedSuggestion (defined in models.py)

This is the final deterministic gate in the pipeline. The LLM's output
is probabilistic — it can hallucinate syntax, change function signatures,
or produce code that doesn't compile. The verifier catches these cases
before they reach the user.

THREE-STAGE VERIFICATION
─────────────────────────
Stage 1 — Parse check:
  Re-parse the corrected_code through tree-sitter.
  If it produces ERROR nodes: reject with REJECTED_PARSE_ERR.
  This catches: syntax errors, unmatched braces, malformed expressions.

Stage 2 — Structural integrity check:
  Verify the corrected function still has the same name and signature
  as the original. The LLM must not change what the function is called
  or how it is called by existing code.
  If name or parameter count changed: reject with REJECTED_BAD_DIFF.

Stage 3 — Diff generation:
  Generate a unified diff between original and corrected code.
  The diff is stored on the VerifiedSuggestion for the formatter to display.
  At this stage we also do a basic sanity check: if the diff is empty,
  the LLM made no changes — reject as unhelpful.

WHY NOT AST DIFF?
──────────────────
A full AST-level diff (comparing tree nodes) would be the ideal verification:
we could check that exactly the expected transformation was applied.
In practice, this is hard to get right — the LLM may reformulate the fix
in ways that are semantically equivalent but structurally different
(e.g. adding free() before vs after an existing statement).

The three-stage approach above is more robust: it catches the failure
modes that actually matter (unparseable output, signature changes, no-ops)
without over-constraining the fix to a specific AST shape.
Full AST diffing is left as a future improvement for high-confidence
fix_kind values like ADD_FREE where the expected diff is well-defined.
"""

from __future__ import annotations

import difflib
from typing import Optional

from refactor.models import (
    Finding, FixKind, LLMResponse,
    VerificationStatus, VerifiedSuggestion,
)
from refactor.parser import (
    ParsedFile, get_function_name, iter_functions,
    node_text, parse_string,
)


# ─────────────────────────────────────────────
# PUBLIC ENTRYPOINT
# ─────────────────────────────────────────────

def verify(
    finding:      Finding,
    llm_response: LLMResponse,
    original_parsed: ParsedFile,
    attempt:      int = 1,
) -> VerifiedSuggestion:
    """
    Verify an LLM suggestion against the original source.

    finding:          the Finding the LLM was asked to fix
    llm_response:     the parsed LLM output from llm_client.py
    original_parsed:  the ParsedFile of the original source
                      (used for signature comparison and diff generation)
    attempt:          which retry attempt this is (1 = first try)

    Returns a VerifiedSuggestion with the appropriate status.
    Never raises — all failures are encoded as rejection statuses.
    """
    corrected_code = llm_response.corrected_code

    # ── Stage 1: parse check ──────────────────────────────────────────
    try:
        corrected_parsed = parse_string(corrected_code)
    except Exception as exc:
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.REJECTED_PARSE_ERR,
            llm_response=llm_response,
            attempts=attempt,
            parse_error=f"parse_string raised unexpectedly: {exc}",
        )

    if corrected_parsed.has_errors:
        error_texts = [
            node_text(n, corrected_parsed.source_bytes)
            for n in corrected_parsed.error_nodes[:3]   # first 3 errors
        ]
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.REJECTED_PARSE_ERR,
            llm_response=llm_response,
            attempts=attempt,
            parse_error=(
                f"Corrected code has {len(corrected_parsed.error_nodes)} parse "
                f"error(s). First errors near: {error_texts}"
            ),
        )

    # ── Stage 2: structural integrity check ──────────────────────────
    integrity_error = _check_structural_integrity(
        finding, corrected_parsed, original_parsed
    )
    if integrity_error is not None:
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.REJECTED_BAD_DIFF,
            llm_response=llm_response,
            attempts=attempt,
            parse_error=integrity_error,
        )

    # ── Stage 3: diff generation and no-op check ─────────────────────
    original_func_text  = _extract_function_text(finding, original_parsed)
    corrected_func_text = _extract_first_function_text(corrected_parsed)

    diff = _generate_diff(
        original  = original_func_text  or "",
        corrected = corrected_func_text or corrected_code,
        file_path = str(finding.location.file) if finding.location.file else "<source>",
    )

    if not diff.strip():
        # LLM returned identical code — no fix was applied
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.REJECTED_BAD_DIFF,
            llm_response=llm_response,
            attempts=attempt,
            parse_error="LLM suggestion is identical to the original — no fix applied.",
        )

    return VerifiedSuggestion(
        finding=finding,
        status=VerificationStatus.ACCEPTED,
        llm_response=llm_response,
        diff=diff,
        attempts=attempt,
    )


# ─────────────────────────────────────────────
# STRUCTURAL INTEGRITY CHECK
# ─────────────────────────────────────────────

def _check_structural_integrity(
    finding:          Finding,
    corrected_parsed: ParsedFile,
    original_parsed:  ParsedFile,
) -> Optional[str]:
    """
    Verify the corrected code preserves the original function's structure.

    Checks:
    1. A function definition is present in the corrected code.
    2. The function name is unchanged.
    3. The parameter count is unchanged.

    Returns an error string if integrity fails, None if it passes.

    Why parameter count not parameter types?
    Checking types requires full type resolution which tree-sitter
    doesn't provide without a compiler. Parameter count is a good
    proxy — if the LLM added or removed parameters, the fix is
    certainly wrong. Type changes within the same parameter count
    are unusual and handled by the user reviewing the diff.
    """
    corrected_functions = list(iter_functions(corrected_parsed))
    if not corrected_functions:
        return (
            "Corrected code contains no function definition. "
            "corrected_code must be a complete function, not a snippet."
        )

    # Get the original function name from the finding location
    original_name = _get_function_name_at_finding(finding, original_parsed)

    corrected_func = corrected_functions[0]
    corrected_name = get_function_name(corrected_func, corrected_parsed.source_bytes)

    if original_name and corrected_name and original_name != corrected_name:
        return (
            f"Function name changed from '{original_name}' to '{corrected_name}'. "
            f"The fix must not rename the function."
        )

    # Check parameter count
    original_param_count  = _get_param_count(finding, original_parsed)
    corrected_param_count = _get_param_count_from_node(
        corrected_func, corrected_parsed.source_bytes
    )

    if (original_param_count is not None
            and corrected_param_count is not None
            and original_param_count != corrected_param_count):
        return (
            f"Parameter count changed from {original_param_count} to "
            f"{corrected_param_count}. The fix must not change the function signature."
        )

    return None


# ─────────────────────────────────────────────
# DIFF GENERATION
# ─────────────────────────────────────────────

def _generate_diff(original: str, corrected: str, file_path: str) -> str:
    """
    Generate a unified diff between original and corrected function text.
    Uses Python's difflib — no external tools required.

    The diff is what the formatter displays to the user and what gets
    stored in the VerifiedSuggestion for review.
    """
    original_lines  = original.splitlines(keepends=True)
    corrected_lines = corrected.splitlines(keepends=True)

    diff_lines = list(difflib.unified_diff(
        original_lines,
        corrected_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    ))

    return "\n".join(diff_lines)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _get_function_name_at_finding(
    finding: Finding,
    parsed:  ParsedFile,
) -> Optional[str]:
    """
    Find the name of the function containing the finding's location.
    Searches by line number overlap.
    """
    for func in iter_functions(parsed):
        if (func.start_point[0] <= finding.location.line
                <= func.end_point[0]):
            return get_function_name(func, parsed.source_bytes)
    return None


def _get_param_count(finding: Finding, parsed: ParsedFile) -> Optional[int]:
    """Parameter count of the function containing the finding."""
    for func in iter_functions(parsed):
        if (func.start_point[0] <= finding.location.line
                <= func.end_point[0]):
            return _get_param_count_from_node(func, parsed.source_bytes)
    return None


def _get_param_count_from_node(func_node, source_bytes: bytes) -> Optional[int]:
    """
    Count parameters in a function_definition node.
    Navigates: function_definition → declarator → function_declarator → parameter_list
    Counts parameter_declaration children, excluding void-only parameter lists.
    """
    declarator = func_node.child_by_field_name("declarator")
    if declarator is None:
        return None

    # Handle pointer-returning functions: int *foo(...)
    if declarator.type == "pointer_declarator":
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None or declarator.type != "function_declarator":
        return None

    params = declarator.child_by_field_name("parameters")
    if params is None:
        return 0

    # Count parameter_declaration nodes — excludes punctuation and void keyword
    param_nodes = [
        c for c in params.children
        if c.type == "parameter_declaration"
    ]

    # void parameter list (f(void)) has one parameter_declaration
    # containing just "void" — treat as zero parameters
    if len(param_nodes) == 1:
        param_text = node_text(param_nodes[0], source_bytes).strip()
        if param_text == "void":
            return 0

    return len(param_nodes)


def _extract_function_text(finding: Finding, parsed: ParsedFile) -> Optional[str]:
    """
    Extract the source text of the function containing the finding.
    Used as the 'before' side of the diff.
    """
    for func in iter_functions(parsed):
        if (func.start_point[0] <= finding.location.line
                <= func.end_point[0]):
            return node_text(func, parsed.source_bytes)
    return None


def _extract_first_function_text(parsed: ParsedFile) -> Optional[str]:
    """
    Extract the source text of the first function in a ParsedFile.
    Used as the 'after' side of the diff — the LLM's corrected_code
    should contain exactly one function.
    """
    for func in iter_functions(parsed):
        return node_text(func, parsed.source_bytes)
    return None