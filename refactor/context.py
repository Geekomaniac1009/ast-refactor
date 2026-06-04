"""
refactor/context.py
────────────────────
Transforms a Finding into a ContextPackage ready for the LLM.

Consumes: Finding + ParsedFile + CFG + DataflowResult
Produces: ContextPackage (defined in models.py)

This module is the boundary between deterministic analysis and LLM inference.
Everything upstream (parser, cfg, pointer_state, detectors) is deterministic.
Everything downstream (llm_client, verifier) is probabilistic.
The quality of the ContextPackage determines the quality of the LLM's output.

DESIGN PRINCIPLES
──────────────────
1. Minimum viable context.
   The LLM receives the flagged function's source text, not the whole file.
   It receives only the scope variables relevant to the finding.
   Less context = fewer hallucinations = more precise fixes.

2. Structured over freeform.
   The prompt is generated programmatically from typed Finding fields,
   not assembled by hand. This means every finding of the same kind
   gets a consistently structured prompt — the LLM learns a predictable
   input format across retries and across findings.

3. Output schema enforced in the prompt.
   The LLM is told exactly what JSON to return, with field names,
   types, and constraints. The verifier expects this schema.
   If the prompt changes the schema, the verifier must be updated too.

4. State trace as narrative.
   For memory-safety findings, we include a human-readable trace of
   the pointer's lifecycle: "allocated at line 5, freed at line 12,
   dereferenced again at line 15." This gives the LLM the causal chain
   it needs to suggest a minimal fix, not a wholesale rewrite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from tree_sitter import Node

from refactor.models import (
    CFG, ContextPackage, Finding, FindingKind,
    PointerStatus, ScopeVariable, SourceLocation
)
from refactor.parser import (
    ParsedFile, get_enclosing_function, get_function_signature,
    iter_variable_declarations, node_text, run_query
)
from refactor.pointer_state import DataflowResult


# ─────────────────────────────────────────────
# PUBLIC ENTRYPOINT
# ─────────────────────────────────────────────

def build_context(
    finding:  Finding,
    parsed:   ParsedFile,
    cfg:      CFG,
    result:   DataflowResult,
) -> ContextPackage:
    """
    Build a ContextPackage from a Finding.
    This is the only public function in this module.
    Everything else is implementation detail.

    Steps:
    1. Find the enclosing function of the flagged node.
    2. Extract the function's full source text as the subtree.
    3. Collect scope variables visible at the finding location.
    4. Build the pointer state trace narrative.
    5. Render the prompt string from all of the above.
    """
    src       = parsed.source_bytes
    file_path = parsed.file_path

    # Step 1: get the enclosing function node
    # raw_node is the tree-sitter Node stored on the Finding by the detector
    raw_node = finding.raw_node
    func_node: Optional[Node] = None

    if raw_node is not None:
        func_node = get_enclosing_function(raw_node)

    # Fallback: if raw_node wasn't set or enclosing function not found,
    # search all functions for the one containing the finding's line
    if func_node is None:
        from refactor.parser import iter_functions
        for fn in iter_functions(parsed):
            if (fn.start_point[0] <= finding.location.line
                    <= fn.end_point[0]):
                func_node = fn
                break

    # Step 2: extract subtree text
    if func_node is not None:
        subtree_text     = node_text(func_node, src)
        func_signature   = get_function_signature(func_node, src)
    else:
        # Last resort: extract lines around the finding from source
        subtree_text   = _extract_lines_around(finding.location, src, context_lines=10)
        func_signature = "<unknown function>"

    # Step 3: collect scope variables
    scope_variables = _collect_scope_variables(
        finding, func_node, parsed, cfg, result
    )

    # Step 4: build state trace narrative
    state_trace = _build_state_trace(finding, parsed, cfg, result)

    # Step 5: render prompt
    prompt = _render_prompt(
        finding       = finding,
        subtree_text  = subtree_text,
        func_signature= func_signature,
        scope_variables = scope_variables,
        state_trace   = state_trace,
    )

    return ContextPackage(
        finding          = finding,
        subtree_text     = subtree_text,
        function_signature = func_signature,
        scope_variables  = scope_variables,
        state_trace      = state_trace,
        prompt           = prompt,
    )


# ─────────────────────────────────────────────
# SCOPE VARIABLE COLLECTION
# ─────────────────────────────────────────────

# Query: extract variable name and type from a declaration
_VAR_DECL_QUERY = """
(declaration
  type: (_) @var_type
  declarator: [
    (identifier)                              @var_name
    (pointer_declarator declarator: (identifier) @var_name)
    (array_declarator   declarator: (identifier) @var_name)
    (init_declarator    declarator: (identifier) @var_name)
    (init_declarator
      declarator: (pointer_declarator
        declarator: (identifier) @var_name))
  ])
"""

# Query: extract function parameter names and types
_PARAM_QUERY = """
(parameter_declaration
  type: (_) @param_type
  declarator: [
    (identifier)                               @param_name
    (pointer_declarator declarator: (identifier) @param_name)
    (array_declarator   declarator: (identifier) @param_name)
  ])
"""


def _collect_scope_variables(
    finding:  Finding,
    func_node: Optional[Node],
    parsed:   ParsedFile,
    cfg:      CFG,
    result:   DataflowResult,
) -> list[ScopeVariable]:
    """
    Collect all variables visible in the function containing the finding.
    Includes: local declarations + function parameters.
    Annotates each with its PointerStatus from the dataflow result if known.

    We intentionally collect ALL variables in the function, not just those
    at the exact finding line. The LLM needs to know about variables that
    are declared earlier but used in the fix — e.g. a buffer size variable
    declared at the top of the function that should be passed to snprintf.
    """
    src         = parsed.source_bytes
    scope_vars: dict[str, ScopeVariable] = {}

    if func_node is None:
        return []

    # Collect local variable declarations
    for match in run_query(_VAR_DECL_QUERY, func_node, src):
        name_node = match.get("var_name")
        type_node = match.get("var_type")
        if name_node is None or type_node is None:
            continue
        name_node = name_node if isinstance(name_node, Node) else name_node[0]
        type_node = type_node if isinstance(type_node, Node) else type_node[0]

        var_name = node_text(name_node, src)
        var_type = node_text(type_node, src).strip()

        # Look up pointer status from the dataflow result
        ptr_status = _get_pointer_status_at_finding(
            var_name, finding, cfg
        )

        scope_vars[var_name] = ScopeVariable(
            name=var_name,
            c_type=var_type,
            pointer_status=ptr_status,
            declared_at=SourceLocation(
                file=str(parsed.file_path) if parsed.file_path else "",
                line=name_node.start_point[0],
                col=name_node.start_point[1],
                end_line=name_node.end_point[0],
                end_col=name_node.end_point[1],
            ),
        )

    # Collect function parameters (may not appear as declarations)
    declarator = func_node.child_by_field_name("declarator")
    if declarator is not None:
        for match in run_query(_PARAM_QUERY, declarator, src):
            name_node = match.get("param_name")
            type_node = match.get("param_type")
            if name_node is None or type_node is None:
                continue
            name_node = name_node if isinstance(name_node, Node) else name_node[0]
            type_node = type_node if isinstance(type_node, Node) else type_node[0]

            param_name = node_text(name_node, src)
            param_type = node_text(type_node, src).strip()

            if param_name not in scope_vars:
                scope_vars[param_name] = ScopeVariable(
                    name=param_name,
                    c_type=param_type,
                    pointer_status=None,
                )

    return list(scope_vars.values())


def _get_pointer_status_at_finding(
    var_name: str,
    finding:  Finding,
    cfg:      CFG,
) -> Optional[PointerStatus]:
    """
    Find the pointer status of a variable at the block containing the finding.
    Searches CFG blocks by line number overlap with the finding location.
    Returns None if the variable is not tracked or block not found.
    """
    finding_line = finding.location.line
    for block in cfg.nodes.values():
        for stmt in block.statements:
            if stmt.start_point[0] <= finding_line <= stmt.end_point[0]:
                return block.pointer_states.get(var_name)
    return None


# ─────────────────────────────────────────────
# STATE TRACE NARRATIVE
# ─────────────────────────────────────────────

def _build_state_trace(
    finding:  Finding,
    parsed:   ParsedFile,
    cfg:      CFG,
    result:   DataflowResult,
) -> list[str]:
    """
    Build a human-readable narrative of the pointer's lifecycle.
    Used in the LLM prompt to explain the causal chain of the bug.

    For a use-after-free with trace [alloc_loc, uaf_loc]:
        ["'p' allocated at line 5",
         "'p' freed at line 12",
         "'p' dereferenced again at line 15 — use after free"]

    The trace entries come from Finding.trace (SourceLocations set by
    the detector). We annotate each with a narrative label based on
    the FindingKind.
    """
    if not finding.trace:
        return [f"Issue detected at line {finding.location.line + 1}."]

    # Extract the variable name from the finding message if possible
    # Messages are formatted as "...: 'varname' is ..."
    var_name = _extract_var_from_message(finding.message)
    prefix   = f"'{var_name}'" if var_name else "pointer"

    narrative: list[str] = []

    kind = finding.kind

    if kind == FindingKind.USE_AFTER_FREE:
        labels = _uaf_labels(prefix, finding.trace)
    elif kind == FindingKind.DOUBLE_FREE:
        labels = _double_free_labels(prefix, finding.trace)
    elif kind == FindingKind.MALLOC_WITHOUT_FREE:
        labels = _leak_labels(prefix, finding.trace)
    elif kind == FindingKind.NULL_DEREF:
        labels = _null_deref_labels(prefix, finding.trace)
    else:
        # Generic: just list the trace locations
        labels = [
            f"Relevant location at line {loc.line + 1}"
            for loc in finding.trace
        ]

    return labels


def _uaf_labels(prefix: str, trace: list[SourceLocation]) -> list[str]:
    labels = []
    if len(trace) >= 1:
        labels.append(f"{prefix} allocated at line {trace[0].line + 1}")
    if len(trace) >= 2:
        # Second-to-last is free site if trace has 3 entries
        if len(trace) == 3:
            labels.append(f"{prefix} freed at line {trace[1].line + 1}")
            labels.append(
                f"{prefix} dereferenced after free at line {trace[2].line + 1} "
                f"— undefined behaviour"
            )
        else:
            labels.append(
                f"{prefix} dereferenced after free at line {trace[1].line + 1} "
                f"— undefined behaviour"
            )
    return labels


def _double_free_labels(prefix: str, trace: list[SourceLocation]) -> list[str]:
    labels = []
    if len(trace) >= 1:
        labels.append(f"{prefix} allocated at line {trace[0].line + 1}")
    if len(trace) >= 2:
        labels.append(f"{prefix} freed a second time at line {trace[1].line + 1} "
                      f"— heap corruption")
    return labels


def _leak_labels(prefix: str, trace: list[SourceLocation]) -> list[str]:
    return [
        f"{prefix} allocated at line {trace[0].line + 1} "
        f"but not freed on all execution paths — memory leak"
    ]


def _null_deref_labels(prefix: str, trace: list[SourceLocation]) -> list[str]:
    labels = []
    if len(trace) >= 1:
        labels.append(
            f"{prefix} allocated at line {trace[0].line + 1} "
            f"(return value may be NULL)"
        )
    if len(trace) >= 2:
        labels.append(
            f"{prefix} dereferenced at line {trace[1].line + 1} "
            f"without a null check on all paths"
        )
    return labels


def _extract_var_from_message(message: str) -> Optional[str]:
    """
    Extract a quoted variable name from a finding message.
    Messages are formatted as "...: 'varname' is ..."
    Returns None if no quoted name found.
    """
    import re
    match = re.search(r"'([^']+)'", message)
    return match.group(1) if match else None


# ─────────────────────────────────────────────
# PROMPT RENDERER
# ─────────────────────────────────────────────

# Maps FindingKind to a one-line problem description for the prompt header
_KIND_DESCRIPTIONS: dict[FindingKind, str] = {
    FindingKind.USE_AFTER_FREE:      "use-after-free memory error",
    FindingKind.DOUBLE_FREE:         "double-free memory error",
    FindingKind.MALLOC_WITHOUT_FREE: "memory leak (malloc without free)",
    FindingKind.NULL_DEREF:          "potential null pointer dereference",
    FindingKind.BUFFER_OVERRUN:      "potential buffer overrun",
    FindingKind.INTEGER_OVERFLOW:    "integer overflow before type widening",
    FindingKind.API_MISUSE:          "unsafe C standard library API usage",
    FindingKind.TAINT_PROPAGATION:   "tainted data reaching a sensitive sink",
}

# Maps FindingKind to the fix_kind values the LLM should choose from
_KIND_FIX_OPTIONS: dict[FindingKind, list[str]] = {
    FindingKind.USE_AFTER_FREE:      ["nullify_after_free", "reorder_ops"],
    FindingKind.DOUBLE_FREE:         ["nullify_after_free", "reorder_ops"],
    FindingKind.MALLOC_WITHOUT_FREE: ["add_free", "reorder_ops"],
    FindingKind.NULL_DEREF:          ["add_null_check"],
    FindingKind.BUFFER_OVERRUN:      ["add_bounds_check", "reorder_ops"],
    FindingKind.INTEGER_OVERFLOW:    ["widen_type"],
    FindingKind.API_MISUSE:          ["replace_call", "add_bounds_check"],
    FindingKind.TAINT_PROPAGATION:   ["add_bounds_check", "replace_call"],
}


def _render_prompt(
    finding:         Finding,
    subtree_text:    str,
    func_signature:  str,
    scope_variables: list[ScopeVariable],
    state_trace:     list[str],
) -> str:
    """
    Render the final prompt string.

    Structure:
        [ROLE]          You are a C security expert.
        [PROBLEM]       One-line description of the bug type.
        [LOCATION]      File and line number.
        [TRACE]         The pointer lifecycle narrative.
        [CODE]          The full function source.
        [SCOPE]         Variables in scope with their types and states.
        [TASK]          Precise instruction: output JSON only.
        [SCHEMA]        The exact JSON schema expected.
        [CONSTRAINTS]   Hard rules the LLM must follow.

    The schema and constraints sections are what make the verifier's
    job tractable — they constrain the output space so re-parsing
    succeeds more often on the first attempt.
    """
    problem_desc = _KIND_DESCRIPTIONS.get(finding.kind, "code quality issue")
    fix_options  = _KIND_FIX_OPTIONS.get(finding.kind, ["other"])
    fix_options_str = ", ".join(f'"{f}"' for f in fix_options)

    # Scope summary: include type and pointer status for each variable
    scope_lines = []
    for sv in scope_variables:
        status_note = ""
        if sv.pointer_status is not None:
            status_note = f" [{sv.pointer_status.name}]"
        scope_lines.append(f"  {sv.c_type} {sv.name}{status_note}")
    scope_block = "\n".join(scope_lines) if scope_lines else "  (none)"

    trace_block = "\n".join(f"  - {t}" for t in state_trace)

    location_str = finding.location.display()

    prompt = f"""You are a C security expert performing a code review. \
A static analysis tool has detected a {problem_desc} in the following function.

LOCATION: {location_str}

BUG DESCRIPTION:
{finding.message}

EXECUTION TRACE:
{trace_block}

FUNCTION SOURCE:
```c
{subtree_text}
```

VARIABLES IN SCOPE:
{scope_block}

TASK:
Produce a minimal fix for the bug described above. Change only what is \
necessary to fix the specific issue — do not refactor, rename, or reformat \
unrelated code.

Respond with ONLY a valid JSON object. No explanation text before or after. \
No markdown code fences around the JSON itself. The JSON must conform exactly \
to this schema:

{{
  "fix_kind": <one of: {fix_options_str}, "other">,
  "corrected_code": <the complete corrected function as a string, preserving \
original indentation>,
  "explanation": <one paragraph explaining what was wrong and why the fix \
works, written for a developer who will review this change>,
  "confidence": <your confidence that this fix is correct and complete, \
as a float between 0.0 and 1.0>
}}

HARD CONSTRAINTS:
- corrected_code must be valid C that compiles without errors.
- corrected_code must contain the complete function, not just a snippet.
- Do not change the function signature.
- Do not add #include statements.
- Do not introduce new variables unless absolutely necessary for the fix.
- If you are not confident in the fix, set confidence below 0.5 and \
explain the uncertainty in the explanation field."""

    return prompt


# ─────────────────────────────────────────────
# UTILITY
# ─────────────────────────────────────────────

def _extract_lines_around(
    location:      SourceLocation,
    source_bytes:  bytes,
    context_lines: int = 10,
) -> str:
    """
    Fallback when no enclosing function can be found.
    Returns context_lines lines above and below the finding location.
    """
    all_lines = source_bytes.decode("utf-8", errors="replace").splitlines()
    start = max(0, location.line - context_lines)
    end   = min(len(all_lines), location.line + context_lines + 1)
    return "\n".join(all_lines[start:end])