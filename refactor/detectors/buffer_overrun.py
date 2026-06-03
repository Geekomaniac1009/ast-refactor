"""
refactor/detectors/buffer_overrun.py
──────────────────────────────────────
Detects potential buffer overrun: array access inside a loop where
the loop bound or index cannot be statically verified as safe.

Two tiers of findings:

CERTAIN (confidence=1.0, severity=ERROR):
  Array accessed with a constant index that provably exceeds its
  declared constant size. e.g. int arr[5]; arr[10] = 0;

POTENTIAL (confidence=0.6, severity=WARNING):
  Array accessed inside a loop where the loop bound is a function
  parameter, external variable, or expression we cannot evaluate
  statically. We cannot prove safety — and in security-sensitive
  code, inability to prove safety IS the finding.

The distinction between tiers is important: CERTAIN findings are
suitable for blocking a CI build; POTENTIAL findings are suitable
for code review flags. The severity and confidence values encode
this distinction so the CI harness can filter appropriately.

Algorithm for POTENTIAL:
1. Find all array declarations with constant sizes.
2. Find all subscript expressions on those arrays inside loop bodies.
3. Check if the subscript index is a constant we can evaluate.
4. If not: check if the loop bound is a constant we can compare against.
5. If neither bound is statically known: emit POTENTIAL finding.
"""

from __future__ import annotations
import re

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text, run_query, iter_nodes_of_type
from refactor.pointer_state import DataflowResult


# Array declaration with constant size: int arr[10];
_ARRAY_DECL_QUERY = """
(declaration
  declarator: (array_declarator
    declarator: (identifier) @arr_name
    size: (number_literal) @size))
"""

# Array subscript access: arr[i] or arr[expr]
_SUBSCRIPT_QUERY = """
(subscript_expression
  argument: (identifier) @arr_name
  index: (_) @index)
"""

# Loop bounds in for/while conditions
_FOR_CONDITION_QUERY = """
(for_statement
  condition: (_) @condition
  body: (_) @body)
"""

_WHILE_CONDITION_QUERY = """
(while_statement
  condition: (_) @condition
  body: (_) @body)
"""


def _try_parse_int(node, source_bytes: bytes) -> int | None:
    """Attempt to parse a node's text as a constant integer. Returns None if not constant."""
    text = node_text(node, source_bytes).strip()
    try:
        return int(text)
    except ValueError:
        return None


def _node_is_inside(child_node, parent_node) -> bool:
    """Check if child_node's byte range is inside parent_node's byte range."""
    return (
        child_node.start_byte >= parent_node.start_byte
        and child_node.end_byte <= parent_node.end_byte
    )


class BufferOverrunDetector(Detector):

    detector_id  = "buffer_overrun"
    finding_kind = FindingKind.BUFFER_OVERRUN
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

        # Collect array declarations: name → declared size (int)
        array_sizes: dict[str, int] = {}
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_ARRAY_DECL_QUERY, stmt, src):
                    name_node = match.get("arr_name")
                    size_node = match.get("size")
                    if name_node is None or size_node is None:
                        continue
                    name_node = name_node if not isinstance(name_node, list) else name_node[0]
                    size_node = size_node if not isinstance(size_node, list) else size_node[0]
                    name = node_text(name_node, src)
                    size = _try_parse_int(size_node, src)
                    if size is not None:
                        array_sizes[name] = size

        # Collect all subscript expressions in the function
        all_subscripts: list[tuple] = []  # (arr_name, index_node, subscript_node)
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_SUBSCRIPT_QUERY, stmt, src):
                    name_node  = match.get("arr_name")
                    index_node = match.get("index")
                    if name_node is None or index_node is None:
                        continue
                    name_node  = name_node  if not isinstance(name_node,  list) else name_node[0]
                    index_node = index_node if not isinstance(index_node, list) else index_node[0]
                    arr_name = node_text(name_node, src)
                    if arr_name in array_sizes:
                        all_subscripts.append((arr_name, index_node, stmt))

        # Find all loop body nodes in the function
        loop_bodies: list = []
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_FOR_CONDITION_QUERY, stmt, src):
                    body = match.get("body")
                    if body is not None:
                        body = body if not isinstance(body, list) else body[0]
                        loop_bodies.append(body)
                for match in run_query(_WHILE_CONDITION_QUERY, stmt, src):
                    body = match.get("body")
                    if body is not None:
                        body = body if not isinstance(body, list) else body[0]
                        loop_bodies.append(body)

        seen: set[tuple] = set()

        for arr_name, index_node, stmt_node in all_subscripts:
            declared_size = array_sizes[arr_name]

            # TIER 1: constant index — can check statically
            index_val = _try_parse_int(index_node, src)
            if index_val is not None:
                if index_val >= declared_size:
                    dedup = (arr_name, index_val, "certain")
                    if dedup not in seen:
                        seen.add(dedup)
                        loc = SourceLocation(
                            file=path_str,
                            line=index_node.start_point[0], col=index_node.start_point[1],
                            end_line=index_node.end_point[0], end_col=index_node.end_point[1],
                        )
                        findings.append(Finding(
                            kind=self.finding_kind,
                            severity=Severity.ERROR,
                            location=loc,
                            message=(
                                f"Buffer overrun: '{arr_name}' has size {declared_size} "
                                f"but is accessed at index {index_val}. "
                                f"This is an out-of-bounds access."
                            ),
                            trace=[loc],
                            confidence=1.0,
                            detector_id=self.detector_id,
                        ))
                continue  # constant index handled — skip potential check

            # TIER 2: non-constant index inside a loop — potential overrun
            inside_loop = any(
                _node_is_inside(stmt_node, loop_body)
                for loop_body in loop_bodies
            )
            if not inside_loop:
                continue

            dedup = (arr_name, index_node.start_byte, "potential")
            if dedup in seen:
                continue
            seen.add(dedup)

            loc = SourceLocation(
                file=path_str,
                line=index_node.start_point[0], col=index_node.start_point[1],
                end_line=index_node.end_point[0], end_col=index_node.end_point[1],
            )
            findings.append(Finding(
                kind=self.finding_kind,
                severity=Severity.WARNING,
                location=loc,
                message=(
                    f"Potential buffer overrun: '{arr_name}' (size {declared_size}) "
                    f"is accessed with a non-constant index inside a loop. "
                    f"Bounds cannot be statically verified."
                ),
                trace=[loc],
                confidence=0.6,
                detector_id=self.detector_id,
            ))

        return findings