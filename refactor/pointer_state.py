"""
refactor/pointer_state.py
─────────────────────────
Dataflow analysis over a CFG that tracks the lifecycle state of pointer variables.

Consumes: CFG (from cfg.py) + source_bytes (from parser.py)
Produces: the same CFG with CFGNode.pointer_states populated on every node,
          plus a list of StateViolation objects for bugs detected during analysis.

ALGORITHM: forward dataflow analysis with a worklist
─────────────────────────────────────────────────────
1. Start at the entry block. All pointers begin as UNKNOWN.
2. For each block, compute the OUT state by applying transfer functions
   to each statement in the block, starting from the IN state.
3. The IN state of a block is the JOIN of the OUT states of all its predecessors.
4. If a block's OUT state changes, add all its successors to the worklist.
5. Repeat until the worklist is empty (fixpoint reached).

This is textbook monotone dataflow analysis. The lattice is PointerStatus,
ordered by "severity of danger." JOIN takes the more dangerous state.
Fixpoint is guaranteed because the lattice has finite height and
transfer functions are monotone (state never moves to a less dangerous value).

WHY NOT JUST WALK THE AST LINEARLY?
─────────────────────────────────────
Linear AST walk assumes code executes top-to-bottom with no branching.
That means:

    int *p = malloc(8);
    if (flag) { free(p); }  // p might be freed here
    use(p);                 // is this safe?

A linear walk sees: malloc -> free -> use. It might flag or miss depending on order.
The dataflow approach sees: on the true branch p is FREED at use(p),
on the false branch p is still ALLOCATED. The JOIN at the merge point
is FREED (conservative). The use-after-free detector then correctly flags
this as a potential bug with a path trace.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Node

from refactor.models import (
    CFG, CFGNode, Finding, FindingKind, PointerStatus, Severity, SourceLocation
)
from refactor.parser import node_text, run_query


# ─────────────────────────────────────────────
# STATE TYPES
# ─────────────────────────────────────────────

# PointerMap: the state at a single program point.
# Maps variable name (str) → PointerStatus.
# Immutable dict — we never mutate in place, always create new dicts.
PointerMap = dict[str, PointerStatus]


@dataclass
class StateViolation:
    """
    A bug detected during dataflow analysis.
    These are NOT the same as Finding objects — they are intermediate
    signals that the detectors will convert into Findings with full context.

    Keeping this separate from Finding means pointer_state.py has no
    dependency on the detector layer — it stays a pure analysis module.

    kind:       what type of violation was detected
    variable:   the pointer variable involved
    location:   where the violation was detected
    path_trace: the sequence of states the variable passed through,
                as (location, state) pairs — used to build the trace
                in the resulting Finding
    """
    kind:           FindingKind
    variable:       str
    location:       SourceLocation
    path_trace:     list[tuple[SourceLocation, PointerStatus]] = field(default_factory=list)


@dataclass
class DataflowResult:
    """
    The result of running dataflow analysis over a CFG.

    The CFG is returned with pointer_states populated on every node.
    violations contains all StateViolations detected during analysis.
    tracked_variables is the set of all pointer variable names the analysis tracked —
    useful for the detector to know which variables were monitored.
    """
    cfg:                CFG
    violations:         list[StateViolation]
    tracked_variables:  set[str]


# ─────────────────────────────────────────────
# LATTICE OPERATIONS
# ─────────────────────────────────────────────

# The partial order on PointerStatus, from least to most dangerous.
# JOIN takes the higher (more dangerous) of two states.
# This ordering encodes: we never downgrade our assessment of danger.
_LATTICE_ORDER: dict[PointerStatus, int] = {
    PointerStatus.UNKNOWN:      0,
    PointerStatus.UNALLOCATED:  1,
    PointerStatus.ALLOCATED:    2,
    PointerStatus.ALIASED:      3,
    PointerStatus.FREED:        4,
    PointerStatus.INVALID:      5,  # terminal — stays INVALID forever
}


def _join_status(a: PointerStatus, b: PointerStatus) -> PointerStatus:
    """
    Lattice JOIN: return the more dangerous of two pointer states.
    Used at merge points (e.g. after an if/else) to conservatively
    represent uncertainty about which path was taken.

    Examples:
        join(ALLOCATED, FREED)      → FREED   (might be freed on some path)
        join(ALLOCATED, ALLOCATED)  → ALLOCATED (same on both paths, safe)
        join(FREED, INVALID)        → INVALID  (already broken)
        join(UNKNOWN, ALLOCATED)    → ALLOCATED (we learned something)
    """
    return a if _LATTICE_ORDER[a] >= _LATTICE_ORDER[b] else b


def _join_maps(a: PointerMap, b: PointerMap) -> PointerMap:
    """
    Join two PointerMaps at a merge point.
    For variables present in both: take the JOIN of their states.
    For variables present in only one: carry forward with UNKNOWN
    (the other path didn't initialise it — conservatively unsafe).
    """
    result: PointerMap = {}
    all_vars = set(a) | set(b)
    for var in all_vars:
        state_a = a.get(var, PointerStatus.UNKNOWN)
        state_b = b.get(var, PointerStatus.UNKNOWN)
        result[var] = _join_status(state_a, state_b)
    return result


# ─────────────────────────────────────────────
# TREE-SITTER QUERY PATTERNS
# These S-expression patterns match the specific AST shapes
# we care about for pointer tracking.
# ─────────────────────────────────────────────

# Matches: int *p = malloc(...) or int *p = calloc(...) or int *p = realloc(...)
# Captures: the variable name being assigned to
_ALLOC_QUERY = """
(declaration
  declarator: (init_declarator
    declarator: (pointer_declarator
      declarator: (identifier) @var_name)
    value: (call_expression
      function: (identifier) @fn_name
      (#match? @fn_name "^(malloc|calloc|realloc|strdup|fopen)$"))))
"""

# Matches: p = malloc(...) — assignment (not declaration)
# Captures: variable name on LHS
_ALLOC_ASSIGN_QUERY = """
(assignment_expression
  left: (identifier) @var_name
  right: (call_expression
    function: (identifier) @fn_name
    (#match? @fn_name "^(malloc|calloc|realloc|strdup|fopen)$")))
"""

# Matches: free(p) or fclose(p)
# Captures: the argument being freed
_FREE_QUERY = """
(call_expression
  function: (identifier) @fn_name
  (#match? @fn_name "^(free|fclose)$")
  arguments: (argument_list
    (identifier) @var_name))
"""

# Matches: *p, p->field, p[i] — dereference operations
# Captures: the pointer being dereferenced
_DEREF_QUERY = """
[
  (pointer_expression
    argument: (identifier) @var_name)
  (field_expression
    argument: (identifier) @var_name)
  (subscript_expression
    argument: (identifier) @var_name)
]
"""

# Matches: int *q = p — pointer alias declaration
_ALIAS_DECL_QUERY = """
(declaration
  declarator: (init_declarator
    declarator: (pointer_declarator
      declarator: (identifier) @alias_name)
    value: (identifier) @source_name))
"""

# Matches: q = p — pointer alias assignment
_ALIAS_ASSIGN_QUERY = """
(assignment_expression
  left: (identifier) @alias_name
  right: (identifier) @source_name)
"""


# ─────────────────────────────────────────────
# PUBLIC ENTRYPOINT
# ─────────────────────────────────────────────

def analyse(cfg: CFG, source_bytes: bytes) -> DataflowResult:
    """
    Run forward dataflow analysis over the CFG.
    Populates CFGNode.pointer_states on every node.
    Returns a DataflowResult with violations found during analysis.

    This is the function that detectors call — they don't implement
    their own traversal logic.
    """
    # in_states[block_id]  = PointerMap at the START of that block
    # out_states[block_id] = PointerMap at the END of that block
    in_states:  dict[int, PointerMap] = {bid: {} for bid in cfg.nodes}
    out_states: dict[int, PointerMap] = {bid: {} for bid in cfg.nodes}

    # Worklist: blocks that need (re-)processing
    # Initialise with the entry block
    worklist: deque[int] = deque([cfg.entry_id])
    processed: set[int] = set()

    violations: list[StateViolation] = []
    tracked_variables: set[str] = set()

    while worklist:
        block_id = worklist.popleft()
        block = cfg.nodes[block_id]

        # Compute IN state: join of all predecessors' OUT states
        predecessors = cfg.predecessors(block_id)
        if not predecessors:
            # Entry block: starts with empty map (all pointers UNKNOWN)
            in_state: PointerMap = {}
        else:
            in_state = out_states[predecessors[0].id]
            for pred in predecessors[1:]:
                in_state = _join_maps(in_state, out_states[pred.id])

        in_states[block_id] = in_state

        # Apply transfer function: process each statement in the block
        out_state, block_violations = _transfer(block, in_state, source_bytes)

        violations.extend(block_violations)
        for v in block_violations:
            tracked_variables.add(v.variable)

        # Collect all variables we've seen
        tracked_variables.update(out_state.keys())

        # Annotate the CFGNode with the pointer states at END of this block
        block.pointer_states = dict(out_state)

        # If out_state changed, successors need reprocessing
        if out_state != out_states[block_id] or block_id not in processed:
            out_states[block_id] = out_state
            processed.add(block_id)
            for successor in cfg.successors(block_id):
                if successor.id not in worklist:
                    worklist.append(successor.id)

    return DataflowResult(
        cfg=cfg,
        violations=violations,
        tracked_variables=tracked_variables,
    )


# ─────────────────────────────────────────────
# TRANSFER FUNCTION
# ─────────────────────────────────────────────

def _transfer(
    block: CFGNode,
    in_state: PointerMap,
    source_bytes: bytes,
) -> tuple[PointerMap, list[StateViolation]]:
    """
    Apply the transfer function for a basic block.
    Starting from in_state, process each statement and update the state.
    Returns (out_state, violations_found_in_this_block).

    The transfer function is the heart of the analysis.
    Each statement type has a specific effect on the pointer map:
      - malloc/calloc/realloc → ALLOCATED
      - free/fclose           → FREED (or INVALID if already FREED)
      - dereference           → check current state; flag if FREED or UNKNOWN
      - alias assignment      → ALIASED on both source and alias
    """
    # Work on a mutable copy — we never mutate in_state
    state: PointerMap = dict(in_state)
    violations: list[StateViolation] = []

    for stmt_node in block.statements:
        stmt_violations = _process_stmt(stmt_node, state, source_bytes)
        violations.extend(stmt_violations)

    return state, violations


def _process_stmt(
    node: Node,
    state: PointerMap,
    source_bytes: bytes,
) -> list[StateViolation]:
    """
    Process a single statement node, mutating state in place.
    Returns any violations detected while processing this statement.

    Order of checks matters:
    1. Allocation (creates new state entry)
    2. Free (transitions state, or flags double-free)
    3. Alias (links two variable names to the same conceptual allocation)
    4. Dereference (reads state to check safety)

    Dereference is checked last because a statement can both free and
    (incorrectly) dereference in the same expression. We want to catch that.
    """
    violations: list[StateViolation] = []

    violations.extend(_check_allocations(node, state, source_bytes))
    violations.extend(_check_frees(node, state, source_bytes))
    violations.extend(_check_aliases(node, state, source_bytes))
    violations.extend(_check_dereferences(node, state, source_bytes))

    return violations


# ─────────────────────────────────────────────
# TRANSFER FUNCTION — per-operation handlers
# ─────────────────────────────────────────────

def _check_allocations(
    node: Node, state: PointerMap, source_bytes: bytes
) -> list[StateViolation]:
    """
    Detect malloc/calloc/realloc/strdup/fopen calls and
    transition the assigned variable to ALLOCATED.

    Handles both declaration form (int *p = malloc(...))
    and assignment form (p = malloc(...)).
    """
    for pattern in (_ALLOC_QUERY, _ALLOC_ASSIGN_QUERY):
        for match in run_query(pattern, node, source_bytes):
            var_nodes = match.get("var_name")
            if var_nodes is None:
                continue
            # run_query may return a single Node or a list
            var_node = var_nodes if isinstance(var_nodes, Node) else var_nodes[0]
            var_name = node_text(var_node, source_bytes)
            state[var_name] = PointerStatus.ALLOCATED
    return []  # allocation itself never produces a violation


def _check_frees(
    node: Node, state: PointerMap, source_bytes: bytes
) -> list[StateViolation]:
    """
    Detect free()/fclose() calls.
    - If variable was ALLOCATED or ALIASED: transition to FREED.
    - If variable was already FREED: transition to INVALID, emit double-free violation.
    - If variable was UNKNOWN: transition to FREED (conservative — we assume
      it might have been allocated on a path we didn't see).
    """
    violations: list[StateViolation] = []

    for match in run_query(_FREE_QUERY, node, source_bytes):
        var_nodes = match.get("var_name")
        if var_nodes is None:
            continue
        var_node = var_nodes if isinstance(var_nodes, Node) else var_nodes[0]
        var_name = node_text(var_node, source_bytes)
        current = state.get(var_name, PointerStatus.UNKNOWN)

        if current == PointerStatus.FREED:
            # Already freed — this is a double-free
            state[var_name] = PointerStatus.INVALID
            violations.append(StateViolation(
                kind=FindingKind.DOUBLE_FREE,
                variable=var_name,
                location=_node_location(var_node, source_bytes),
                path_trace=[(_node_location(var_node, source_bytes), PointerStatus.INVALID)],
            ))
        elif current == PointerStatus.UNALLOCATED:
            # Freeing a NULL/unallocated pointer — technically undefined behaviour
            # depending on implementation, but free(NULL) is safe in C99+.
            # We flag this as a NOTE-level finding via the detector, not here.
            state[var_name] = PointerStatus.FREED
        else:
            state[var_name] = PointerStatus.FREED

        # When a pointer is freed, any known aliases become INVALID
        for alias, alias_state in list(state.items()):
            if alias != var_name and alias_state == PointerStatus.ALIASED:
                state[alias] = PointerStatus.FREED  # conservative

    return violations


def _check_aliases(
    node: Node, state: PointerMap, source_bytes: bytes
) -> list[StateViolation]:
    """
    Detect pointer alias operations: int *q = p or q = p.
    When we see this, both q and p become ALIASED (or remain ALLOCATED —
    we use ALIASED to signal "shares allocation with another variable").

    Alias tracking is necessarily approximate. We don't track aliasing
    through function parameters or struct fields — only direct local variable
    assignments. This is documented as a known limitation.
    """
    for pattern in (_ALIAS_DECL_QUERY, _ALIAS_ASSIGN_QUERY):
        for match in run_query(pattern, node, source_bytes):
            alias_nodes  = match.get("alias_name")
            source_nodes = match.get("source_name")
            if alias_nodes is None or source_nodes is None:
                continue

            alias_node  = alias_nodes  if isinstance(alias_nodes,  Node) else alias_nodes[0]
            source_node = source_nodes if isinstance(source_nodes, Node) else source_nodes[0]

            alias_name  = node_text(alias_node,  source_bytes)
            source_name = node_text(source_node, source_bytes)

            # Only track if the source is a known pointer in our state
            if source_name in state:
                source_status = state[source_name]
                # If source is ALLOCATED, both become ALIASED
                if source_status in (PointerStatus.ALLOCATED, PointerStatus.ALIASED):
                    state[alias_name]  = PointerStatus.ALIASED
                    state[source_name] = PointerStatus.ALIASED
                # If source is FREED, the alias immediately inherits that danger
                elif source_status == PointerStatus.FREED:
                    state[alias_name] = PointerStatus.FREED

    return []


def _check_dereferences(
    node: Node, state: PointerMap, source_bytes: bytes
) -> list[StateViolation]:
    """
    Detect pointer dereference operations: *p, p->field, p[i].
    Check the current state of the dereferenced variable.

    - FREED or INVALID: use-after-free violation
    - UNKNOWN: we don't know if it was allocated — emit with lower confidence
      (the detector will set confidence=0.6 on these)
    - ALLOCATED or ALIASED: safe, no violation

    We do NOT flag UNALLOCATED here — that's null dereference territory,
    handled by the null_deref detector which uses the CFG paths directly.
    """
    violations: list[StateViolation] = []

    for match in run_query(_DEREF_QUERY, node, source_bytes):
        var_nodes = match.get("var_name")
        if var_nodes is None:
            continue
        var_node = var_nodes if isinstance(var_nodes, Node) else var_nodes[0]
        var_name = node_text(var_node, source_bytes)
        current  = state.get(var_name, PointerStatus.UNKNOWN)

        if current in (PointerStatus.FREED, PointerStatus.INVALID):
            violations.append(StateViolation(
                kind=FindingKind.USE_AFTER_FREE,
                variable=var_name,
                location=_node_location(var_node, source_bytes),
                path_trace=[
                    (_node_location(var_node, source_bytes), current)
                ],
            ))

    return violations


# ─────────────────────────────────────────────
# QUERY UTILITIES
# (used by detectors after analysis is complete)
# ─────────────────────────────────────────────

def get_state_at_node(
    cfg: CFG,
    target_node: Node,
    variable: str,
    source_bytes: bytes,
) -> PointerStatus:
    """
    Query the pointer state of a variable at the point where a given
    AST node appears.

    Strategy: find which CFG block contains this node (by byte offset),
    then return the state of the variable at the END of that block.

    This is an approximation — ideally we'd track state at every statement,
    not just at block boundaries. For the detectors we're building,
    end-of-block state is sufficient. A finer-grained version would
    maintain per-statement state maps, at higher memory cost.
    """
    target_start = target_node.start_byte
    target_end   = target_node.end_byte

    for block in cfg.nodes.values():
        for stmt in block.statements:
            if stmt.start_byte <= target_start and stmt.end_byte >= target_end:
                return block.pointer_states.get(variable, PointerStatus.UNKNOWN)

    return PointerStatus.UNKNOWN


def get_allocation_location(
    cfg: CFG,
    variable: str,
    source_bytes: bytes,
) -> Optional[SourceLocation]:
    """
    Find where a variable transitioned to ALLOCATED in the CFG.
    Used by detectors to build the path_trace on a Finding —
    "allocated at line X, freed at line Y, used again at line Z."

    Searches all blocks for an allocation statement for this variable.
    Returns the first one found (DFS order from entry).
    """
    for block in _dfs_block_order(cfg):
        for stmt in block.statements:
            for pattern in (_ALLOC_QUERY, _ALLOC_ASSIGN_QUERY):
                for match in run_query(pattern, stmt, source_bytes):
                    var_nodes = match.get("var_name")
                    if var_nodes is None:
                        continue
                    var_node = var_nodes if isinstance(var_nodes, Node) else var_nodes[0]
                    if node_text(var_node, source_bytes) == variable:
                        return _node_location(var_node, source_bytes)
    return None


def _dfs_block_order(cfg: CFG) -> list[CFGNode]:
    """Return CFG nodes in DFS order from the entry block."""
    order: list[CFGNode] = []
    visited: set[int] = set()
    stack = [cfg.entry_id]
    while stack:
        bid = stack.pop()
        if bid in visited:
            continue
        visited.add(bid)
        order.append(cfg.nodes[bid])
        for succ in cfg.successors(bid):
            if succ.id not in visited:
                stack.append(succ.id)
    return order


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _node_location(node: Node, source_bytes: bytes) -> SourceLocation:
    """Build a SourceLocation from a tree-sitter Node."""
    # We don't have the file path here — detectors attach it when building Findings
    return SourceLocation(
        file="",
        line=node.start_point[0],
        col=node.start_point[1],
        end_line=node.end_point[0],
        end_col=node.end_point[1],
    )