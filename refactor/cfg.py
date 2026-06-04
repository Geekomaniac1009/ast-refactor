"""
refactor/cfg.py
───────────────
Control Flow Graph builder for C functions.

Consumes: a function_definition Node + source_bytes from parser.py
Produces: a CFG dataclass (defined in models.py)

SCOPE AND APPROXIMATIONS
─────────────────────────
This is an intraprocedural CFG — one graph per function, no cross-function edges.
The call graph (call_graph.py) handles interprocedural structure separately.

Handled fully:
  - Sequential statements
  - if / if-else
  - while loops
  - for loops  
  - do-while loops
  - return statements (edge to exit block)
  - Nested versions of all the above

Approximated conservatively (documented per case):
  - switch/case: each case arm becomes a branch from the switch node;
    fallthrough is NOT modelled — each case implicitly breaks.
    This is unsound but safe: we may miss some paths, never invent fake ones.
  - break/continue: wired to the nearest enclosing loop's exit/header.
    Labelled break (break label;) is treated as a regular break — imprecise
    for multi-level loop exits but not a common pattern in the code we target.
  - goto: emits a warning, the goto statement is treated as a no-op edge
    (sequential fall-through). This is unsound. goto in C is rare in modern code;
    if a file uses goto heavily (e.g. Linux kernel error-handling style),
    the detectors will emit a low-confidence flag on their findings for that file.

Not handled:
  - setjmp/longjmp: treated as regular function calls.
  - Function pointers: call sites through function pointers are not resolved.
  - __attribute__((noreturn)): functions like exit() are not treated as exits.

These limitations are documented in findings via FindingKind metadata and in the
README. They are known, intentional, and defensible.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Optional

from tree_sitter import Node

from refactor.models import CFG, CFGEdge, CFGNode
from refactor.parser import get_function_name, node_text


# ─────────────────────────────────────────────
# INTERNAL BUILDER STATE
# ─────────────────────────────────────────────

@dataclass
class _BuilderState:
    """
    Mutable state threaded through the recursive CFG construction.
    Using a state object avoids a wall of parameters on every recursive call.

    next_id:        monotonically increasing block ID counter
    nodes:          the blocks built so far
    edges:          the edges built so far
    loop_stack:     stack of (loop_header_id, loop_exit_id) tuples.
                    Pushed when entering a loop, popped on exit.
                    break → jump to loop_exit_id (top of stack)
                    continue → jump to loop_header_id (top of stack)
    source_bytes:   needed to read node text for warnings
    function_name:  for error messages
    """
    source_bytes:   bytes
    function_name:  str
    next_id:        int                             = 0
    nodes:          dict[int, CFGNode]              = field(default_factory=dict)
    edges:          list[CFGEdge]                   = field(default_factory=list)
    loop_stack:     list[tuple[int, int]]           = field(default_factory=list)

    def new_block(self, is_entry: bool = False, is_exit: bool = False) -> CFGNode:
        """Allocate a new basic block and register it."""
        block = CFGNode(id=self.next_id, statements=[], is_entry=is_entry, is_exit=is_exit)
        self.nodes[self.next_id] = block
        self.next_id += 1
        return block

    def add_edge(self, src: int, dst: int, condition: Optional[str] = None) -> None:
        """Add a directed edge between two blocks."""
        self.edges.append(CFGEdge(src=src, dst=dst, condition=condition))

    def add_stmt(self, block: CFGNode, node: Node) -> None:
        """Append a statement node to a block."""
        block.statements.append(node)

    @property
    def in_loop(self) -> bool:
        return len(self.loop_stack) > 0

    @property
    def current_loop_header(self) -> int:
        return self.loop_stack[-1][0]

    @property
    def current_loop_exit(self) -> int:
        return self.loop_stack[-1][1]


# ─────────────────────────────────────────────
# PUBLIC ENTRYPOINT
# ─────────────────────────────────────────────

def build_cfg(func_node: Node, source_bytes: bytes) -> CFG:
    """
    Build a CFG for a single C function.

    func_node must be a function_definition node (from iter_functions in parser.py).
    Returns a CFG with entry and exit blocks wired up.

    The caller should check cfg.nodes[cfg.entry_id] to begin traversal.
    """
    function_name = get_function_name(func_node, source_bytes) or "<anonymous>"

    state = _BuilderState(source_bytes=source_bytes, function_name=function_name)

    # Create the structural entry and exit blocks.
    # Entry: where execution begins (before the first statement).
    # Exit:  a synthetic block representing "function has returned".
    #        All return statements wire an edge here.
    entry_block = state.new_block(is_entry=True)
    exit_block  = state.new_block(is_exit=True)

    # Get the function body (compound_statement — the { } block)
    body = func_node.child_by_field_name("body")
    if body is None:
        # Function declaration without a body (prototype) — just entry → exit
        state.add_edge(entry_block.id, exit_block.id)
        return _make_cfg(state, function_name, entry_block.id, exit_block.id)

    # _process_block returns the id of the "continuation block" —
    # the block that will receive control after this block finishes
    # (if it doesn't end in a return/break/continue).
    # We start from the entry block and process the entire function body.
    continuation_id = _process_compound(
        body, state, current_block_id=entry_block.id, exit_block_id=exit_block.id
    )

    # If the function fell off the end without a return (valid in void functions,
    # or a code path that's missing a return — both are real), wire to exit.
    if continuation_id is not None:
        state.add_edge(continuation_id, exit_block.id)

    return _make_cfg(state, function_name, entry_block.id, exit_block.id)


def _make_cfg(state: _BuilderState, function_name: str, entry_id: int, exit_id: int) -> CFG:
    return CFG(
        function_name=function_name,
        nodes=state.nodes,
        edges=state.edges,
        entry_id=entry_id,
        exit_id=exit_id,
    )


# ─────────────────────────────────────────────
# COMPOUND STATEMENT PROCESSING
# ─────────────────────────────────────────────

def _process_compound(
    compound_node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    Process a compound_statement (a { } block).
    Iterates over the direct children, dispatching each to the appropriate handler.

    Returns the ID of the block that is "live" after processing all statements
    — i.e. the block that subsequent code should attach to.
    Returns None if control cannot fall through (e.g. last statement was a return).
    """
    current_id = current_block_id

    for child in compound_node.children:
        if child.type in ("{", "}"):
            # Structural tokens — not statements, skip
            continue

        if current_id is None:
            # Dead code after a return/break/continue — skip silently.
            # A real linter would warn here; for now we just don't model it.
            break

        current_id = _process_statement(child, state, current_id, exit_block_id)

    return current_id


def _process_statement(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    Dispatch a single statement node to its handler.
    Returns the continuation block ID, or None if control does not fall through.
    """
    t = node.type

    if t == "if_statement":
        return _process_if(node, state, current_block_id, exit_block_id)

    elif t == "while_statement":
        return _process_while(node, state, current_block_id, exit_block_id)

    elif t == "for_statement":
        return _process_for(node, state, current_block_id, exit_block_id)

    elif t == "do_statement":
        return _process_do_while(node, state, current_block_id, exit_block_id)

    elif t == "switch_statement":
        return _process_switch(node, state, current_block_id, exit_block_id)

    elif t == "return_statement":
        return _process_return(node, state, current_block_id, exit_block_id)

    elif t == "break_statement":
        return _process_break(node, state, current_block_id)

    elif t == "continue_statement":
        return _process_continue(node, state, current_block_id)

    elif t == "goto_statement":
        return _process_goto(node, state, current_block_id)

    elif t == "compound_statement":
        # Nested block e.g. bare { int x = 1; } without a control structure
        return _process_compound(node, state, current_block_id, exit_block_id)

    elif t == "comment":
        # Comments are in the CST but carry no semantics — skip
        return current_block_id

    else:
        # All other statement types: expression_statement, declaration,
        # labeled_statement, etc. — treat as sequential.
        state.add_stmt(state.nodes[current_block_id], node)
        return current_block_id


# ─────────────────────────────────────────────
# CONTROL FLOW STATEMENT HANDLERS
# ─────────────────────────────────────────────

def _process_if(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    if (cond) { then_body } else { else_body }

    Graph shape:

        [current_block] ──true──▶ [then_block] ──▶ [merge_block]
                        ──false─▶ [else_block] ──▶ [merge_block]

    If there is no else clause, the false edge goes directly to merge_block.
    merge_block is where execution continues after the if statement.
    merge_block may receive no edges if both branches always return —
    in that case we return None (no continuation).
    """
    # The condition is part of the current block — add it as a statement
    condition = node.child_by_field_name("condition")
    if condition:
        state.add_stmt(state.nodes[current_block_id], condition)

    # Then branch
    then_block = state.new_block()
    state.add_edge(current_block_id, then_block.id, condition="true")

    then_body = node.child_by_field_name("consequence")
    then_continuation = None
    if then_body is not None:
        then_continuation = _process_statement(
            then_body, state, then_block.id, exit_block_id
        )

    # Else branch (may not exist)
    else_body = node.child_by_field_name("alternative")
    merge_block = state.new_block()

    if else_body is not None:
        else_block = state.new_block()
        state.add_edge(current_block_id, else_block.id, condition="false")
        else_continuation = _process_statement(
            else_body, state, else_block.id, exit_block_id
        )
        if else_continuation is not None:
            state.add_edge(else_continuation, merge_block.id)
    else:
        # No else: false path goes directly to merge
        state.add_edge(current_block_id, merge_block.id, condition="false")

    # Wire then continuation to merge (if then didn't return)
    if then_continuation is not None:
        state.add_edge(then_continuation, merge_block.id)

    # If merge has no predecessors, it's unreachable (both branches returned)
    predecessors = [e for e in state.edges if e.dst == merge_block.id]
    if not predecessors:
        return None

    return merge_block.id


def _process_while(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    while (cond) { body }

    Graph shape:

        [current_block] ──▶ [header_block (cond)] ──true──▶ [body_block] ──▶ (back to header)
                                                   ──false─▶ [exit_block]

    The back-edge from body to header is what makes this a loop.
    break  → edge to loop_exit_block
    continue → edge to header_block
    """
    header_block = state.new_block()
    state.add_edge(current_block_id, header_block.id)

    condition = node.child_by_field_name("condition")
    if condition:
        state.add_stmt(header_block, condition)

    loop_exit_block = state.new_block()

    # Push loop context so break/continue know where to jump
    state.loop_stack.append((header_block.id, loop_exit_block.id))

    body_block = state.new_block()
    state.add_edge(header_block.id, body_block.id, condition="true")
    state.add_edge(header_block.id, loop_exit_block.id, condition="false")

    body = node.child_by_field_name("body")
    body_continuation = None
    if body is not None:
        body_continuation = _process_statement(body, state, body_block.id, exit_block_id)

    # Back-edge: body falls through back to header
    if body_continuation is not None:
        state.add_edge(body_continuation, header_block.id, condition="loop")

    state.loop_stack.pop()
    return loop_exit_block.id


def _process_for(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    for (init; cond; update) { body }

    Graph shape:

        [current_block] → [init_block] → [header_block (cond)]
                                           ──true──▶ [body_block] → [update_block] → (back to header)
                                           ──false─▶ [loop_exit_block]

    init and update are modelled as separate blocks for precision —
    the pointer state tracker needs to see the initialiser as happening
    before the condition is checked.
    """
    # Initialiser: executed once before the loop
    init = node.child_by_field_name("initializer")
    if init and init.type not in (";",):
        state.add_stmt(state.nodes[current_block_id], init)

    header_block = state.new_block()
    state.add_edge(current_block_id, header_block.id)

    condition = node.child_by_field_name("condition")
    if condition and condition.type not in (";",):
        state.add_stmt(header_block, condition)

    loop_exit_block = state.new_block()
    update_block = state.new_block()

    state.loop_stack.append((update_block.id, loop_exit_block.id))

    body_block = state.new_block()
    state.add_edge(header_block.id, body_block.id, condition="true")
    state.add_edge(header_block.id, loop_exit_block.id, condition="false")

    body = node.child_by_field_name("body")
    body_continuation = None
    if body is not None:
        body_continuation = _process_statement(body, state, body_block.id, exit_block_id)

    # Body falls through to update, update loops back to header
    if body_continuation is not None:
        state.add_edge(body_continuation, update_block.id)

    update = node.child_by_field_name("update")
    if update:
        state.add_stmt(update_block, update)
    state.add_edge(update_block.id, header_block.id, condition="loop")

    state.loop_stack.pop()
    return loop_exit_block.id


def _process_do_while(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    do { body } while (cond);

    Graph shape:

        [current_block] → [body_block] → [condition_block]
                                          ──true──▶ (back to body_block)
                                          ──false─▶ [loop_exit_block]

    Key difference from while: body executes at least once.
    The condition is checked *after* the body, not before.
    """
    body_block = state.new_block()
    state.add_edge(current_block_id, body_block.id)

    condition_block = state.new_block()
    loop_exit_block = state.new_block()

    state.loop_stack.append((condition_block.id, loop_exit_block.id))

    body = node.child_by_field_name("body")
    body_continuation = None
    if body is not None:
        body_continuation = _process_statement(body, state, body_block.id, exit_block_id)

    if body_continuation is not None:
        state.add_edge(body_continuation, condition_block.id)

    condition = node.child_by_field_name("condition")
    if condition:
        state.add_stmt(condition_block, condition)

    state.add_edge(condition_block.id, body_block.id, condition="true")
    state.add_edge(condition_block.id, loop_exit_block.id, condition="false")

    state.loop_stack.pop()
    return loop_exit_block.id


def _process_switch(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> Optional[int]:
    """
    switch (expr) { case A: ...; case B: ...; default: ...; }

    APPROXIMATION: fallthrough is NOT modelled.
    Each case is treated as an independent branch from the switch header.
    This is conservative — we may miss paths where fallthrough creates
    a longer execution sequence, but we never invent paths that don't exist.

    All case continuations (that don't return) wire to the merge block.
    """
    switch_expr = node.child_by_field_name("condition")
    if switch_expr:
        state.add_stmt(state.nodes[current_block_id], switch_expr)

    merge_block = state.new_block()
    state.loop_stack.append((current_block_id, merge_block.id))  # break → merge

    body = node.child_by_field_name("body")
    if body is not None:
        for child in body.children:
            if child.type in ("case_statement", "default_statement"):
                case_block = state.new_block()
                state.add_edge(current_block_id, case_block.id, condition="true")
                case_continuation = _process_statement(
                    child, state, case_block.id, exit_block_id
                )
                if case_continuation is not None:
                    state.add_edge(case_continuation, merge_block.id)

    state.loop_stack.pop()
    return merge_block.id


def _process_return(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
    exit_block_id: int,
) -> None:
    """
    return expr;
    Adds the return statement to the current block, then wires to the exit block.
    Returns None — control does not fall through after a return.
    """
    state.add_stmt(state.nodes[current_block_id], node)
    state.add_edge(current_block_id, exit_block_id)
    return None


def _process_break(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
) -> None:
    """
    break; — jump to the exit of the nearest enclosing loop or switch.
    Returns None — control does not fall through.
    """
    state.add_stmt(state.nodes[current_block_id], node)
    if state.in_loop:
        state.add_edge(current_block_id, state.current_loop_exit)
    # If not in a loop, break is a syntax error — tree-sitter will have flagged it
    return None


def _process_continue(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
) -> None:
    """
    continue; — jump to the header of the nearest enclosing loop.
    Returns None — control does not fall through.
    """
    state.add_stmt(state.nodes[current_block_id], node)
    if state.in_loop:
        state.add_edge(current_block_id, state.current_loop_header)
    return None


def _process_goto(
    node: Node,
    state: _BuilderState,
    current_block_id: int,
) -> int:
    """
    goto label; — APPROXIMATION: treated as sequential fall-through.

    We emit a warning and continue as if the goto wasn't there.
    This is unsound (we invent a fall-through path that may not exist)
    but goto is rare in modern C and handling it correctly requires
    a two-pass algorithm to resolve forward references to labels.

    A future improvement: first pass collects all label locations,
    second pass wires goto edges correctly.
    """
    target = node_text(node, state.source_bytes).strip()
    warnings.warn(
        f"[cfg] goto in '{state.function_name}': '{target}' — "
        f"approximated as fall-through. CFG may be imprecise for this function.",
        stacklevel=4,
    )
    state.add_stmt(state.nodes[current_block_id], node)
    return current_block_id


# ─────────────────────────────────────────────
# CFG INTROSPECTION UTILITIES
# (used by detectors and pointer_state.py)
# ─────────────────────────────────────────────

def all_paths(cfg: CFG) -> list[list[int]]:
    """
    Enumerate all paths from entry to exit as lists of block IDs.
    Used by path-sensitive detectors (null deref, use-after-free).

    IMPORTANT: this uses DFS with a visited set to break cycles (loop back-edges).
    For a loop, we traverse the loop body ONCE — we don't unroll iterations.
    This means we may miss bugs that only manifest after multiple iterations,
    but it keeps path enumeration tractable.

    For functions with very high cyclomatic complexity (many branches),
    the number of paths grows exponentially. We cap at MAX_PATHS and
    emit a low-confidence flag on any findings from capped functions.
    """
    MAX_PATHS = 512
    paths: list[list[int]] = []
    _dfs_paths(cfg, cfg.entry_id, cfg.exit_id, [], set(), paths, MAX_PATHS)
    return paths


def _dfs_paths(
    cfg: CFG,
    current: int,
    target: int,
    path: list[int],
    visited: set[int],
    results: list[list[int]],
    max_paths: int,
) -> None:
    if len(results) >= max_paths:
        return

    path = path + [current]

    if current == target:
        results.append(path)
        return

    if current in visited:
        return

    visited = visited | {current}

    for edge in cfg.edges:
        if edge.src != current:
            continue
        # Cut loop back-edges explicitly — following them would
        # recurse infinitely. The loop body has already been added
        # to the path by visiting the body block once.
        if edge.condition == "loop":
            continue
        _dfs_paths(cfg, edge.dst, target, path, visited, results, max_paths)

def get_block_statements(block: CFGNode, source_bytes: bytes) -> list[str]:
    """
    Return the source text of each statement in a block.
    Convenience function for detectors that need to inspect statement text.
    """
    from refactor.parser import node_text as _node_text
    return [_node_text(stmt, source_bytes) for stmt in block.statements]


def is_path_capped(cfg: CFG) -> bool:
    """
    Returns True if all_paths() would hit the MAX_PATHS cap for this function.
    Detectors should attach lower confidence to findings in capped functions.
    """
    paths = all_paths(cfg)
    return len(paths) >= 512