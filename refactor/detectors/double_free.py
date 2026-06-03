"""
refactor/detectors/double_free.py
───────────────────────────────────
Detects double-free: free() called twice on the same pointer.

Like UseAfterFreeDetector, this is a thin interpretation layer over
the dataflow violations produced by pointer_state.py.
Double-free is a critical memory safety vulnerability — it can corrupt
the heap allocator's internal state and is commonly exploited to
achieve arbitrary code execution (heap exploitation primitives).
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, Severity, SourceLocation
)
from refactor.parser import ParsedFile
from refactor.pointer_state import DataflowResult, get_allocation_location


class DoubleFreeDetector(Detector):

    detector_id  = "double_free"
    finding_kind = FindingKind.DOUBLE_FREE
    severity     = Severity.ERROR

    def detect(
        self,
        parsed:   ParsedFile,
        cfg:      CFG,
        result:   DataflowResult,
    ) -> list[Finding]:

        findings: list[Finding] = []
        file_path = parsed.file_path

        for violation in result.violations:
            if violation.kind != FindingKind.DOUBLE_FREE:
                continue

            alloc_loc = get_allocation_location(cfg, violation.variable, parsed.source_bytes)
            trace: list[SourceLocation] = []
            path_str = str(file_path) if file_path else ""

            if alloc_loc:
                trace.append(SourceLocation(
                    file=path_str,
                    line=alloc_loc.line, col=alloc_loc.col,
                    end_line=alloc_loc.end_line, end_col=alloc_loc.end_col,
                ))

            loc = violation.location
            findings.append(Finding(
                kind=self.finding_kind,
                severity=self.severity,
                location=SourceLocation(
                    file=path_str,
                    line=loc.line, col=loc.col,
                    end_line=loc.end_line, end_col=loc.end_col,
                ),
                message=(
                    f"Double-free: '{violation.variable}' is freed more than once. "
                    f"This corrupts heap allocator metadata and is exploitable "
                    f"for arbitrary code execution on most platforms."
                ),
                trace=trace,
                confidence=1.0,   # straight-line double-free is always certain
                detector_id=self.detector_id,
            ))

        return findings