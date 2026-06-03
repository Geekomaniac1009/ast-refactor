"""
refactor/detectors/malloc_free.py
───────────────────────────────────
Detects malloc-without-free: memory allocated but never freed before
the function returns, on at least one execution path.

This is MORE than a simple "does free() appear in the function" check.
It uses the CFG to verify that on EVERY path from allocation to function
exit, a free() is called. A free inside only one branch of an if/else
is a leak on the other branch — this detector catches that.

This is the detector that most directly demonstrates why the CFG matters.
A linear AST scan would see malloc and free in the same function and
report "clean." The CFG-based analysis sees that free is inside an
if-branch and correctly reports a leak on the else path.

Algorithm:
1. Find all malloc call sites in the function (via query).
2. For each malloc, identify the variable receiving the allocation.
3. Enumerate all CFG paths from entry to exit (all_paths).
4. For each path, simulate pointer state: does this variable get freed
   on this path before exit?
5. If any path reaches exit without a free: emit a Finding with
   confidence proportional to how many paths are affected.
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, PointerStatus, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text, run_query
from refactor.pointer_state import DataflowResult
from refactor.cfg import all_paths, is_path_capped


# Query: find all malloc/calloc/realloc assignments in the function
_ALLOC_QUERY = """
[
  (declaration
    declarator: (init_declarator
      declarator: (pointer_declarator
        declarator: (identifier) @var_name)
      value: (call_expression
        function: (identifier) @fn
        (#match? @fn "^(malloc|calloc|realloc|strdup)$"))))
  (assignment_expression
    left: (identifier) @var_name
    right: (call_expression
      function: (identifier) @fn
      (#match? @fn "^(malloc|calloc|realloc|strdup)$")))
]
"""

# Query: find all free() calls, capture the argument variable name
_FREE_QUERY = """
(call_expression
  function: (identifier) @fn
  (#eq? @fn "free")
  arguments: (argument_list (identifier) @var_name))
"""


class MallocWithoutFreeDetector(Detector):

    detector_id  = "malloc_without_free"
    finding_kind = FindingKind.MALLOC_WITHOUT_FREE
    severity     = Severity.WARNING   # not always immediately exploitable

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

        # Collect all allocation sites: variable name → allocating node
        alloc_sites: dict[str, object] = {}   # var_name → tree-sitter Node
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_ALLOC_QUERY, stmt, src):
                    var_nodes = match.get("var_name")
                    if var_nodes is None:
                        continue
                    var_node = var_nodes if not isinstance(var_nodes, list) else var_nodes[0]
                    name = node_text(var_node, src)
                    alloc_sites[name] = var_node

        if not alloc_sites:
            return []

        # Collect all free sites: variable name → list of nodes where it's freed
        free_sites: dict[str, list] = {}
        for block in cfg.nodes.values():
            for stmt in block.statements:
                for match in run_query(_FREE_QUERY, stmt, src):
                    var_nodes = match.get("var_name")
                    if var_nodes is None:
                        continue
                    var_node = var_nodes if not isinstance(var_nodes, list) else var_nodes[0]
                    name = node_text(var_node, src)
                    free_sites.setdefault(name, []).append(var_node)

        # For each allocated variable, check all CFG paths for a free
        paths = all_paths(cfg)
        capped = is_path_capped(cfg)

        for var_name, alloc_node in alloc_sites.items():

            # Find which block contains the allocation
            alloc_block_id = self._find_block_for_node(cfg, alloc_node)
            if alloc_block_id is None:
                continue

            # Only consider paths that pass through the allocation block
            relevant_paths = [
                p for p in paths
                if alloc_block_id in p
            ]

            # For each relevant path, check if a free occurs after the alloc
            leaking_path_count = 0
            for path in relevant_paths:
                alloc_idx = path.index(alloc_block_id)
                path_after_alloc = path[alloc_idx:]

                # Does any block on the path after allocation contain a free
                # of this variable?
                freed_on_path = self._is_freed_on_path(
                    cfg, path_after_alloc, var_name, src
                )
                if not freed_on_path:
                    leaking_path_count += 1

            if leaking_path_count == 0:
                continue  # freed on all paths — clean

            # Confidence: proportion of paths that leak, adjusted for capping
            leak_ratio  = leaking_path_count / max(len(relevant_paths), 1)
            confidence  = leak_ratio * (0.75 if capped else 1.0)

            alloc_loc = SourceLocation(
                file=path_str,
                line=alloc_node.start_point[0],
                col=alloc_node.start_point[1],
                end_line=alloc_node.end_point[0],
                end_col=alloc_node.end_point[1],
            )

            path_note = (
                f"on {leaking_path_count} of {len(relevant_paths)} execution path(s)"
            )

            findings.append(Finding(
                kind=self.finding_kind,
                severity=self.severity,
                location=alloc_loc,
                message=(
                    f"Memory leak: '{var_name}' is allocated but not freed {path_note}. "
                    f"The pointer exits scope without a corresponding free()."
                ),
                trace=[alloc_loc],
                confidence=round(confidence, 2),
                detector_id=self.detector_id,
            ))

        return findings

    def _find_block_for_node(self, cfg: CFG, node) -> int | None:
        """Find the CFG block ID that contains the given AST node."""
        for block in cfg.nodes.values():
            for stmt in block.statements:
                if (stmt.start_byte <= node.start_byte
                        and stmt.end_byte >= node.end_byte):
                    return block.id
        return None

    def _is_freed_on_path(
        self,
        cfg: CFG,
        path_block_ids: list[int],
        var_name: str,
        source_bytes: bytes,
    ) -> bool:
        """
        Check whether var_name is freed in any block on the given path.
        Checks each block's pointer_states (populated by dataflow analysis)
        for a transition to FREED status.
        """
        for block_id in path_block_ids:
            block = cfg.nodes[block_id]
            status = block.pointer_states.get(var_name)
            if status in (PointerStatus.FREED, PointerStatus.INVALID):
                return True
        return False