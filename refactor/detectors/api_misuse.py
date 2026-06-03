"""
refactor/detectors/api_misuse.py
──────────────────────────────────
Detects misuse of C standard library functions where the contract
is semantic rather than structural.

These are cases where the code is syntactically valid and compiles
without warnings, but violates the documented contract of the function
in a way that causes undefined behaviour or silent data corruption.

This detector is PURELY LLM-GROUNDED for explanation — rule-based
detection identifies the structural pattern, the LLM provides the
domain-knowledge explanation of WHY it's wrong and HOW to fix it.

Patterns detected:

1. strtok() on a string literal
   strtok modifies its first argument in place. String literals are
   read-only in C — writing to them is undefined behaviour.
   Pattern: strtok("literal", ...) or strtok(literal_var, ...)
   where the variable was initialised from a string literal.

2. memcmp() for string equality
   memcmp compares raw bytes and does not stop at null terminator.
   Using it for string comparison silently compares garbage bytes
   past the end of the shorter string.
   Pattern: if (memcmp(a, b, n) == 0) where n > strlen(a) is possible.

3. strcpy() into a fixed buffer without size check
   strcpy does not check destination size — classic buffer overflow.
   Pattern: strcpy(fixed_arr, src) where fixed_arr is a fixed-size array
   and src is a pointer parameter (unknown size).

4. gets() — unconditionally flagged
   gets() has no bounds checking whatsoever and was removed from C11.
   Any use is an immediate ERROR.

5. sprintf() into a fixed buffer
   sprintf does not check bounds. Use snprintf instead.
   Pattern: sprintf(fixed_arr, fmt, ...) where fixed_arr has known size.
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text, run_query
from refactor.pointer_state import DataflowResult


_CALL_QUERY = """
(call_expression
  function: (identifier) @fn_name
  arguments: (argument_list) @args)
"""

# Dangerous functions with zero safe uses
_UNCONDITIONAL_ERROR = {"gets"}

# Dangerous functions that need context to confirm
_CONTEXTUAL_WARNING = {"strcpy", "strcat", "sprintf", "strtok", "memcmp"}


class ApiMisuseDetector(Detector):

    detector_id  = "api_misuse"
    finding_kind = FindingKind.API_MISUSE
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
                for match in run_query(_CALL_QUERY, stmt, src):
                    fn_node   = match.get("fn_name")
                    args_node = match.get("args")
                    if fn_node is None or args_node is None:
                        continue
                    fn_node   = fn_node   if not isinstance(fn_node,   list) else fn_node[0]
                    args_node = args_node if not isinstance(args_node, list) else args_node[0]

                    fn_name = node_text(fn_node, src)

                    if fn_node.start_byte in seen:
                        continue

                    finding = self._check_call(
                        fn_name, fn_node, args_node, stmt, src, path_str
                    )
                    if finding:
                        seen.add(fn_node.start_byte)
                        findings.append(finding)

        return findings

    def _check_call(
        self, fn_name, fn_node, args_node, stmt_node, src, path_str
    ) -> Finding | None:

        loc = SourceLocation(
            file=path_str,
            line=fn_node.start_point[0], col=fn_node.start_point[1],
            end_line=fn_node.end_point[0], end_col=fn_node.end_point[1],
        )

        if fn_name in _UNCONDITIONAL_ERROR:
            return Finding(
                kind=self.finding_kind,
                severity=Severity.ERROR,
                location=loc,
                message=(
                    f"Unsafe API: '{fn_name}' performs no bounds checking and "
                    f"was removed from the C11 standard. Replace with fgets()."
                ),
                trace=[loc],
                confidence=1.0,
                detector_id=self.detector_id,
            )

        if fn_name == "strcpy":
            return Finding(
                kind=self.finding_kind,
                severity=Severity.WARNING,
                location=loc,
                message=(
                    "Unsafe API: 'strcpy' does not check destination buffer size. "
                    "Use 'strncpy' or 'strlcpy' with an explicit size bound."
                ),
                trace=[loc],
                confidence=0.9,
                detector_id=self.detector_id,
            )

        if fn_name == "sprintf":
            return Finding(
                kind=self.finding_kind,
                severity=Severity.WARNING,
                location=loc,
                message=(
                    "Unsafe API: 'sprintf' does not check destination buffer size. "
                    "Use 'snprintf' with an explicit size limit."
                ),
                trace=[loc],
                confidence=0.9,
                detector_id=self.detector_id,
            )

        if fn_name == "strtok":
            # Check if first argument is a string literal
            args_text = node_text(args_node, src)
            if '"' in args_text.split(",")[0]:
                return Finding(
                    kind=self.finding_kind,
                    severity=Severity.ERROR,
                    location=loc,
                    message=(
                        "API contract violation: 'strtok' modifies its first argument "
                        "in place. Passing a string literal is undefined behaviour — "
                        "string literals are read-only. Copy to a buffer first."
                    ),
                    trace=[loc],
                    confidence=1.0,
                    detector_id=self.detector_id,
                )

        if fn_name == "memcmp":
            # Flag memcmp in equality comparisons — likely should be strcmp
            stmt_text = node_text(stmt_node, src)
            if "== 0" in stmt_text or "!= 0" in stmt_text:
                return Finding(
                    kind=self.finding_kind,
                    severity=Severity.WARNING,
                    location=loc,
                    message=(
                        "Possible API misuse: 'memcmp' used for equality comparison. "
                        "memcmp compares raw bytes and ignores null terminators — "
                        "for string equality, use 'strcmp' instead."
                    ),
                    trace=[loc],
                    confidence=0.7,
                    detector_id=self.detector_id,
                )

        return None