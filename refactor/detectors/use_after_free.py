"""
refactor/detectors/use_after_free.py
─────────────────────────────────────
Detects use-after-free: a pointer is dereferenced after free() was called on it.

Relies entirely on pointer_state.py's dataflow violations — this detector
is deliberately thin. The dataflow analysis already did the hard work of
tracking pointer states across all CFG paths. This detector's job is to
convert StateViolations of the right kind into well-formed Finding objects
with proper traces, locations, and confidence values.

This separation is intentional: pointer_state.py is a reusable analysis
module; this detector is the domain-specific interpretation layer.
"""

from __future__ import annotations

from refactor.detectors.base import Detector
from refactor.models import (
    CFG, Finding, FindingKind, PointerStatus, Severity, SourceLocation
)
from refactor.parser import ParsedFile
from refactor.pointer_state import DataflowResult, get_allocation_location


class UseAfterFreeDetector(Detector):

    detector_id  = "use_after_free"
    finding_kind = FindingKind.USE_AFTER_FREE
    severity     = Severity.ERROR      # always ERROR — exploitable in production

    def detect(
        self,
        parsed:   ParsedFile,
        cfg:      CFG,
        result:   DataflowResult,
    ) -> list[Finding]:

        findings: list[Finding] = []
        file_path = parsed.file_path

        for violation in result.violations:
            if violation.kind != FindingKind.USE_AFTER_FREE:
                continue

            # Build the trace: allocation site → free site → use site
            # get_allocation_location finds where this variable was malloc'd
            alloc_loc = get_allocation_location(cfg, violation.variable, parsed.source_bytes)
            trace: list[SourceLocation] = []

            if alloc_loc:
                trace.append(SourceLocation(
                    file=str(file_path) if file_path else "",
                    line=alloc_loc.line,
                    col=alloc_loc.col,
                    end_line=alloc_loc.end_line,
                    end_col=alloc_loc.end_col,
                ))

            # Add the use-after-free site itself
            uaf_loc = violation.location
            trace.append(SourceLocation(
                file=str(file_path) if file_path else "",
                line=uaf_loc.line,
                col=uaf_loc.col,
                end_line=uaf_loc.end_line,
                end_col=uaf_loc.end_col,
            ))

            # Confidence: lower if the function's path space was capped
            # (we may have missed the free on an unchecked path)
            from refactor.cfg import is_path_capped
            confidence = 0.75 if is_path_capped(cfg) else 1.0

            findings.append(Finding(
                kind=self.finding_kind,
                severity=self.severity,
                location=SourceLocation(
                    file=str(file_path) if file_path else "",
                    line=uaf_loc.line,
                    col=uaf_loc.col,
                    end_line=uaf_loc.end_line,
                    end_col=uaf_loc.end_col,
                ),
                message=(
                    f"Use-after-free: '{violation.variable}' is dereferenced "
                    f"after being freed. This is undefined behaviour and a "
                    f"common source of memory corruption vulnerabilities."
                ),
                trace=trace,
                confidence=confidence,
                detector_id=self.detector_id,
            ))

        return findings