"""
refactor/detectors/integer_overflow.py
────────────────────────────────────────
Detects integer overflow in arithmetic expressions before type widening.

The classic pattern:
    long size = n * sizeof(int);   // OVERFLOW: n * sizeof computed as int first

The multiplication of two int values produces an int result. If that result
overflows (> INT_MAX), the overflow happens BEFORE the assignment widens
to long. The C standard defines signed integer overflow as undefined behaviour
— compilers are free to assume it never happens, which enables optimisations
that silently produce wrong results.

This is LLM-GROUNDED: rule-based detection finds the syntactic pattern
(arithmetic on int types assigned to wider type). The LLM explains the
fix with the correct cast placement and why it prevents the overflow.
That explanation is what the 'explain' subcommand surfaces.

Detection heuristic:
1. Find assignment/declaration where LHS type is wider than RHS expression type.
2. RHS contains a binary arithmetic expression (* or +) on identifiers
   that are typed as int/unsigned in the current scope.
3. No explicit cast on the sub-expression before the widening assignment.

Limitation: we don't do full type inference. We use a conservative heuristic:
if the RHS of a widening assignment contains * or + and at least one operand
is not a sizeof() expression, we flag as potential. Sizeof expressions are
excluded because sizeof always returns size_t (already wide enough).
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text, run_query
from refactor.pointer_state import DataflowResult


# Widening assignment: long/size_t/int64_t = expr containing arithmetic
_WIDENING_ASSIGN_QUERY = """
(declaration
  type: (_) @lhs_type
  declarator: (init_declarator
    value: (binary_expression
      operator: ["*" "+"] @op) @rhs))
"""

_WIDENING_ASSIGN2_QUERY = """
(assignment_expression
  left: (identifier) @lhs
  right: (binary_expression
    operator: ["*" "+"] @op) @rhs)
"""

# Detect sizeof expressions — these are already safe (return size_t)
_SIZEOF_QUERY = """(sizeof_expression)"""

_WIDE_TYPES = {
    "long", "long long", "size_t", "ssize_t",
    "int64_t", "uint64_t", "ptrdiff_t", "intptr_t",
}

_NARROW_TYPES = {"int", "unsigned int", "unsigned", "short", "char"}


def _contains_sizeof(node, source_bytes: bytes) -> bool:
    """Check if a node's subtree contains any sizeof expression."""
    from refactor.parser import iter_nodes_of_type
    return any(True for _ in iter_nodes_of_type(node, "sizeof_expression"))


def _has_explicit_cast(node, source_bytes: bytes) -> bool:
    """Check if a node is wrapped in an explicit cast expression."""
    from refactor.parser import iter_nodes_of_type
    return any(True for _ in iter_nodes_of_type(node, "cast_expression"))


class IntegerOverflowDetector(Detector):

    detector_id  = "integer_overflow"
    finding_kind = FindingKind.INTEGER_OVERFLOW
    severity     = Severity.WARNING

    def detect(
        self,
        parsed:   ParsedFile,
        cfg:      CFG,
        result:   DataflowResult,
    ) -> list[Finding]:

        findings: list[Finding] = []
        file_path = parsed.file_path
        path_str  = str(file_path) if file_path else ""
        src       = parsed.source_bytes
        seen: set[int] = set()

        for block in cfg.nodes.values():
            for stmt in block.statements:

                for query in (_WIDENING_ASSIGN_QUERY, _WIDENING_ASSIGN2_QUERY):
                    for match in run_query(query, stmt, src):

                        rhs_node = match.get("rhs")
                        type_node = match.get("lhs_type")

                        if rhs_node is None:
                            continue
                        rhs_node = rhs_node if not isinstance(rhs_node, list) else rhs_node[0]

                        # Skip if RHS already has an explicit cast
                        if _has_explicit_cast(rhs_node, src):
                            continue

                        # Skip if both operands involve sizeof (safe pattern)
                        if _contains_sizeof(rhs_node, src):
                            # sizeof * n: the sizeof is size_t, n*sizeof is also size_t
                            # Only skip if the NON-sizeof operand is also safe
                            # Conservative: flag it anyway with lower confidence
                            confidence = 0.4
                        else:
                            confidence = 0.7

                        # Check LHS type is genuinely wide (if we can determine it)
                        if type_node is not None:
                            type_node = type_node if not isinstance(type_node, list) else type_node[0]
                            type_text = node_text(type_node, src).strip()
                            if not any(w in type_text for w in _WIDE_TYPES):
                                continue  # not a widening assignment

                        if rhs_node.start_byte in seen:
                            continue
                        seen.add(rhs_node.start_byte)

                        rhs_text = node_text(rhs_node, src)
                        loc = SourceLocation(
                            file=path_str,
                            line=rhs_node.start_point[0], col=rhs_node.start_point[1],
                            end_line=rhs_node.end_point[0], end_col=rhs_node.end_point[1],
                        )

                        findings.append(Finding(
                            kind=self.finding_kind,
                            severity=self.severity,
                            location=loc,
                            message=(
                                f"Potential integer overflow before widening: "
                                f"'{rhs_text}' is computed as a narrow integer type "
                                f"before being assigned to a wider type. "
                                f"Cast operands explicitly: (long)a * b."
                            ),
                            trace=[loc],
                            confidence=confidence,
                            detector_id=self.detector_id,
                        ))

        return findings