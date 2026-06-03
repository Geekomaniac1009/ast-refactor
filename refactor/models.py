"""
refactor/models.py
──────────────────
Central data contracts for the entire pipeline.
Every module imports from here. Nothing imports from other modules into here.

Rule: if you find yourself passing a raw dict between modules, 
that dict belongs here as a dataclass instead.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ─────────────────────────────────────────────
# ENUMS — typed vocabularies, no magic strings
# ─────────────────────────────────────────────

class Severity(Enum):
    """
    How bad is this finding?
    ERROR   -> likely causes a crash or security vulnerability at runtime
    WARNING -> dangerous under specific conditions (e.g. only on error paths)
    NOTE    -> code quality / maintainability issue, not immediately dangerous
    """
    ERROR   = "error"
    WARNING = "warning"
    NOTE    = "note"


class FindingKind(Enum):
    """
    What class of problem did a detector find?
    Each enum member maps 1:1 to a detector module.
    Adding a new detector = adding a member here first.
    """
    MALLOC_WITHOUT_FREE     = "malloc_without_free"
    USE_AFTER_FREE          = "use_after_free"
    DOUBLE_FREE             = "double_free"
    NULL_DEREF              = "null_deref"          # path-sensitive
    BUFFER_OVERRUN          = "buffer_overrun"
    INTEGER_OVERFLOW        = "integer_overflow"
    API_MISUSE              = "api_misuse"
    TAINT_PROPAGATION       = "taint_propagation"   # interprocedural (stretch)


class FixKind(Enum):
    """
    What type of transformation does the LLM suggest?
    The verifier uses this to know what AST diff to expect
    before re-parsing — different fixes have different expected diffs.
    """
    ADD_FREE                = "add_free"            # insert free() call
    ADD_NULL_CHECK          = "add_null_check"      # insert if (ptr == NULL)
    REORDER_OPS             = "reorder_ops"         # move statements
    ADD_BOUNDS_CHECK        = "add_bounds_check"    # insert bounds guard
    WIDEN_TYPE              = "widen_type"          # e.g. int to long before multiply
    NULLIFY_AFTER_FREE      = "nullify_after_free"  # ptr = NULL after free()
    REPLACE_CALL            = "replace_call"        # swap unsafe API for safe variant
    OTHER                   = "other"               # LLM suggested something structural


class PointerStatus(Enum):
    """
    State machine values for pointer lifetime tracking.
    Transitions are enforced in pointer_state.py.

    UNKNOWN       : we've seen the variable declared but don't know its value yet
    UNALLOCATED   : declared, explicitly not yet allocated (e.g. int *p = NULL)
    ALLOCATED     : malloc/calloc/realloc/fopen returned and assigned to this variable
    ALIASED       : another pointer variable points to the same allocation
    FREED         : free() or fclose() was called on this pointer
    INVALID       : used after free, or double-freed — a bug has been detected
    """
    UNKNOWN       = auto()
    UNALLOCATED   = auto()
    ALLOCATED     = auto()
    ALIASED       = auto()
    FREED         = auto()
    INVALID       = auto()


class VerificationStatus(Enum):
    """
    What happened when the verifier re-parsed the LLM's suggestion?
    """
    ACCEPTED            = "accepted"        # re-parsed clean, AST diff matches expected
    REJECTED_PARSE_ERR  = "rejected_parse"  # tree-sitter couldn't parse the output
    REJECTED_BAD_DIFF   = "rejected_diff"   # parsed but AST diff didn't match fix_kind
    REJECTED_MAX_RETRY  = "rejected_retry"  # still failing after 2 retries
    NO_SUGGESTION       = "no_suggestion"   # LLM returned nothing usable


# ─────────────────────────────────────────────
# LOCATION — where in the source file
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class SourceLocation:
    """
    A precise point in a source file.
    frozen=True means it's hashable — we can use it as a dict key or in sets.
    All line/col values are 0-indexed internally (matching tree-sitter).
    The formatter is responsible for displaying them as 1-indexed to the user.
    """
    file:       str     # absolute path to the source file
    line:       int     # 0-indexed start line of the flagged node
    col:        int     # 0-indexed start column
    end_line:   int     # 0-indexed end line
    end_col:    int     # 0-indexed end column

    def display(self) -> str:
        """Human-readable 1-indexed location string, like clang-tidy output."""
        return f"{self.file}:{self.line + 1}:{self.col + 1}"


# ─────────────────────────────────────────────
# CFG — control flow graph primitives
# ─────────────────────────────────────────────

@dataclass
class CFGNode:
    """
    A basic block in the control flow graph.
    A basic block is a maximal straight-line sequence of statements —
    no branches in, no branches out (except at the very end).

    'statements' holds the tree-sitter AST nodes in this block.
    We store them as opaque objects here — cfg.py owns the tree-sitter types.
    """
    id:             int
    statements:     list           # list of tree-sitter Node objects
    is_entry:       bool = False
    is_exit:        bool = False

    # Computed by pointer_state.py during analysis —
    # maps variable name to PointerStatus at the END of this block
    pointer_states: dict[str, PointerStatus] = field(default_factory=dict)


@dataclass
class CFGEdge:
    """
    A directed edge between two basic blocks.
    condition=None means unconditional (e.g. end of a block with no branch).
    condition="true" / "false" for the two arms of an if/else.
    condition="loop" for the back-edge of a while/for loop.
    """
    src:        int             # CFGNode.id of source block
    dst:        int             # CFGNode.id of destination block
    condition:  Optional[str]   # None | "true" | "false" | "loop"


@dataclass
class CFG:
    """
    The full control flow graph for a single function.
    nodes and edges are the graph structure.
    entry_id and exit_id are the IDs of the entry and exit blocks.
    function_name is stored for error messages and caching.
    """
    function_name:  str
    nodes:          dict[int, CFGNode]  # node_id → CFGNode
    edges:          list[CFGEdge]
    entry_id:       int
    exit_id:        int

    def successors(self, node_id: int) -> list[CFGNode]:
        """Return all blocks reachable in one step from node_id."""
        return [
            self.nodes[e.dst]
            for e in self.edges
            if e.src == node_id
        ]

    def predecessors(self, node_id: int) -> list[CFGNode]:
        """Return all blocks that can reach node_id in one step."""
        return [
            self.nodes[e.src]
            for e in self.edges
            if e.dst == node_id
        ]


# ─────────────────────────────────────────────
# FINDING — what a detector produces
# ─────────────────────────────────────────────

@dataclass
class Finding:
    """
    A single detected problem in the source code.
    This is the output contract of every detector — all detectors return list[Finding].

    trace: the sequence of SourceLocations relevant to understanding the bug.
    For a use-after-free, trace = [allocation site, free site, use-after-free site].
    For a simple null deref, trace = [allocation site, first use without null check].
    An empty trace means the finding is self-contained at 'location'.

    confidence: 0.0–1.0. Use 1.0 for certain (e.g. free() called twice on same pointer
    in straight-line code). Use lower values for path-sensitive findings where we're
    reporting a possible path, not a guaranteed execution.
    """
    kind:           FindingKind
    severity:       Severity
    location:       SourceLocation      # primary location to show the user
    message:        str                 # one-line human-readable description
    trace:          list[SourceLocation] = field(default_factory=list)
    confidence:     float = 1.0         # 0.0–1.0
    detector_id:    str = ""            # which detector produced this e.g. "malloc_free"
    raw_node:       object = None       # the tree-sitter node — not serialised, used internally

    def __post_init__(self):
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")


# ─────────────────────────────────────────────
# CONTEXT PACKAGE — what the LLM receives
# ─────────────────────────────────────────────

@dataclass
class ScopeVariable:
    """
    A variable visible in the scope of the flagged code.
    The context extractor populates these to give the LLM
    enough information to write a correct fix without seeing the whole file.
    """
    name:           str
    c_type:         str             # e.g. "int *", "char[]", "FILE *"
    pointer_status: Optional[PointerStatus] = None  # None if not a tracked pointer
    declared_at:    Optional[SourceLocation] = None


@dataclass
class ContextPackage:
    """
    The structured context handed to llm_client.py.
    Everything the LLM needs is in here — nothing else is passed.

    subtree_text:       the source text of the flagged function/block
    scope_variables:    variables visible at the point of the finding
    state_trace:        human-readable description of the pointer's lifecycle
                        e.g. ["allocated at line 12", "freed at line 18", 
                               "dereferenced again at line 22"]
    prompt:             the fully-rendered prompt string, built by context.py
    """
    finding:            Finding
    subtree_text:       str
    function_signature: str
    scope_variables:    list[ScopeVariable]
    state_trace:        list[str]
    prompt:             str             # rendered by context.py from all the above


# ─────────────────────────────────────────────
# LLM RESPONSE — raw output before verification
# ─────────────────────────────────────────────

@dataclass
class LLMResponse:
    """
    The parsed (but not yet verified) response from the LLM.
    We ask the LLM to return JSON matching this schema.
    llm_client.py is responsible for parsing the raw string into this.

    corrected_code:  the LLM's suggested rewrite of the flagged function/block.
                     This is what gets fed to the verifier.
    explanation:     one-paragraph explanation of what the bug is and why the fix works.
                     Shown to the user in 'explain' mode.
    confidence:      the LLM's self-reported confidence (0.0–1.0).
                     We track this but don't fully trust it.
    """
    fix_kind:           FixKind
    corrected_code:     str
    explanation:        str
    confidence:         float
    raw_response:       str     # the original JSON string from the API, for debugging


# ─────────────────────────────────────────────
# VERIFIED SUGGESTION — final output
# ─────────────────────────────────────────────

@dataclass
class VerifiedSuggestion:
    """
    The output of verifier.py — a suggestion that has been re-parsed
    and whose AST diff has been checked against the expected transformation.

    diff:           unified diff string (what the formatter will show the user)
    attempts:       how many LLM calls were needed (1 = first try, 2 = one retry)
    parse_error:    populated if status is REJECTED_PARSE_ERR
    """
    finding:        Finding
    status:         VerificationStatus
    llm_response:   Optional[LLMResponse]   = None
    diff:           Optional[str]           = None
    attempts:       int                     = 1
    parse_error:    Optional[str]           = None

    @property
    def accepted(self) -> bool:
        return self.status == VerificationStatus.ACCEPTED