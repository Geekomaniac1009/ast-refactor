"""
refactor/detectors/null_deref.py
──────────────────────────────────
Path-sensitive null dereference detection.

Detects: a pointer returned from malloc/fopen/calloc is dereferenced
on at least one CFG path without a prior null check on that path.

"Path-sensitive" means we check EVERY path from allocation to dereference,
not just "is there a null check somewhere in the function."

The critical distinction:
    int *p = malloc(8);
    if (p == NULL) { return; }   // null check on true branch
    *p = 5;                       // safe — null check guards this

vs:
    int *p = malloc(8);
    if (flag) { if (p == NULL) { return; } }  // check only on one path
    *p = 5;                                    // unsafe on flag=false path

A linear scan sees a null check and reports clean in both cases.
Path-sensitive analysis correctly distinguishes them.

Algorithm:
1. Find all malloc/calloc/fopen call sites.
2. Find all dereferences of the allocated variable.
3. For each (alloc_site, deref_site) pair, enumerate CFG paths
   that pass through both, in that order.
4. For each such path, check whether a null check on the variable
   appears between the alloc and the deref.
5. If any path has no null check: emit WARNING.
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text, run_query
from refactor.pointer_state import DataflowResult
from refactor.cfg import all_paths, is_path_capped


_ALLOC_QUERY = """
[
  (declaration
    declarator: (init_declarator
      declarator: (pointer_declarator
        declarator: (identifier) @var_name)
      value: (call_expression
        function: (identifier) @fn
        (#match? @fn "^(malloc|calloc|realloc|fopen|strdup)$"))))
  (assignment_expression
    left: (identifier) @var_name
    right: (call_expression
      function: (identifier) @fn
      (#match? @fn "^(malloc|calloc|realloc|fopen|strdup)$")))
]
"""

_DEREF_QUERY = """
[
  (pointer_expression   argument: (identifier) @var_name)
  (field_expression     argument: (identifier) @var_name)
  (subscript_expression argument: (identifier) @var_name)
]
"""

# Null check patterns: if (p == NULL), if (!p), if (p != NULL) is a SAFE check
# We detect the guard form: condition that would cause early exit if null
_NULL_CHECK_QUERY = """
[
  (binary_expression
    left:  (identifier) @var_name
    right: (null) )
  (binary_expression
    left:  (null)
    right: (identifier) @var_name)
  (unary_expression
    operator: "!"
    argument: (identifier) @var_name)
]
"""


class NullDerefDetector(Detector):

    detector_id  = "null_deref"
    finding_kind = FindingKind.NULL_DEREF
    severity     = Severity.ERROR

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
        paths     = all_paths(cfg)
        capped    = is_path_capped(cfg)

        # Map: var_name → (alloc_node, alloc_block_id)
        alloc_sites: dict[str, tuple] = {}
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_ALLOC_QUERY, stmt, src):
                    vn = match.get("var_name")
                    if vn is None:
                        continue
                    vn = vn if not isinstance(vn, list) else vn[0]
                    name = node_text(vn, src)
                    alloc_sites[name] = (vn, block.id)

        # Map: var_name → list of (deref_node, deref_block_id)
        deref_sites: dict[str, list] = {}
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_DEREF_QUERY, stmt, src):
                    vn = match.get("var_name")
                    if vn is None:
                        continue
                    vn = vn if not isinstance(vn, list) else vn[0]
                    name = node_text(vn, src)
                    deref_sites.setdefault(name, []).append((vn, block.id))

        # Map: var_name → set of block_ids containing a null check
        null_check_blocks: dict[str, set[int]] = {}
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_NULL_CHECK_QUERY, stmt, src):
                    vn = match.get("var_name")
                    if vn is None:
                        continue
                    vn = vn if not isinstance(vn, list) else vn[0]
                    name = node_text(vn, src)
                    null_check_blocks.setdefault(name, set()).add(block.id)

        # For each (alloc, deref) pair, check all interposing paths
        seen: set[tuple] = set()   # deduplicate findings

        for var_name, (alloc_node, alloc_block_id) in alloc_sites.items():
            if var_name not in deref_sites:
                continue

            checked_blocks = null_check_blocks.get(var_name, set())

            for deref_node, deref_block_id in deref_sites[var_name]:

                # Find paths that pass through alloc then deref (in order)
                unsafe_paths = []
                for path in paths:
                    if alloc_block_id not in path:
                        continue
                    if deref_block_id not in path:
                        continue
                    alloc_idx = path.index(alloc_block_id)
                    deref_idx = path.index(deref_block_id)
                    if alloc_idx >= deref_idx:
                        continue  # deref before alloc on this path — skip

                    # Is there a null check between alloc and deref on this path?
                    path_segment = path[alloc_idx:deref_idx + 1]
                    has_check = any(bid in checked_blocks for bid in path_segment)
                    if not has_check:
                        unsafe_paths.append(path)

                if not unsafe_paths:
                    continue

                dedup_key = (var_name, alloc_block_id, deref_block_id)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                confidence = (0.75 if capped else 1.0) * (
                    len(unsafe_paths) / max(len(paths), 1)
                )

                alloc_loc = SourceLocation(
                    file=path_str,
                    line=alloc_node.start_point[0], col=alloc_node.start_point[1],
                    end_line=alloc_node.end_point[0], end_col=alloc_node.end_point[1],
                )
                deref_loc = SourceLocation(
                    file=path_str,
                    line=deref_node.start_point[0], col=deref_node.start_point[1],
                    end_line=deref_node.end_point[0], end_col=deref_node.end_point[1],
                )

                findings.append(Finding(
                    kind=self.finding_kind,
                    severity=self.severity,
                    location=deref_loc,
                    message=(
                        f"Potential null dereference: '{var_name}' may be NULL "
                        f"(return value of allocation function) and is dereferenced "
                        f"without a null check on {len(unsafe_paths)} execution path(s)."
                    ),
                    trace=[alloc_loc, deref_loc],
                    confidence=round(confidence, 2),
                    detector_id=self.detector_id,
                ))

        return findings