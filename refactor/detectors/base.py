"""
refactor/detectors/base.py
──────────────────────────
Abstract base class for all detectors.
Every detector in this package inherits from Detector and implements detect().

Design constraints enforced here:
  - detect() is a pure function: same inputs → same outputs, no side effects
  - detect() never calls the LLM — that is context.py and llm_client.py's job
  - detect() never reads from disk — it only operates on what's passed in
  - All detectors are stateless — instantiate once, call detect() many times
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from refactor.models import (
    CFG, Finding, FindingKind, PointerStatus, Severity, SourceLocation
)
from refactor.parser import ParsedFile, node_text
from refactor.pointer_state import DataflowResult

from tree_sitter import Node


# ─────────────────────────────────────────────
# ABSTRACT BASE
# ─────────────────────────────────────────────

class Detector(ABC):
    """
    Base class for all detectors.

    Subclasses must set:
        detector_id:  short snake_case string, unique across all detectors
                      e.g. "use_after_free", "null_deref"
        finding_kind: the FindingKind this detector produces
        severity:     default severity for findings from this detector
                      (individual findings may override if confidence warrants)

    Subclasses must implement:
        detect(): the analysis logic
    """

    detector_id:    str         = ""
    finding_kind:   FindingKind = None
    severity:       Severity    = Severity.WARNING

    @abstractmethod
    def detect(
        self,
        parsed:     ParsedFile,
        cfg:        CFG,
        result:     DataflowResult,
    ) -> list[Finding]:
        """
        Run detection on a single function's CFG.
        Returns a list of Findings (empty list if nothing detected).

        parsed:  the full ParsedFile — use for node_text(), source_bytes
        cfg:     the CFG with pointer_states populated on every node
        result:  the DataflowResult from pointer_state.analyse()
                 contains violations and tracked_variables
        """
        ...

    # ── Convenience helpers available to all subclasses ──────────────────

    def make_finding(
        self,
        node:           Node,
        source_bytes:   bytes,
        message:        str,
        file_path:      Optional[Path]  = None,
        severity:       Optional[Severity] = None,
        trace:          Optional[list[SourceLocation]] = None,
        confidence:     float           = 1.0,
    ) -> Finding:
        """
        Construct a Finding from a tree-sitter node.
        Handles the SourceLocation boilerplate so detector code stays clean.
        """
        path_str = str(file_path) if file_path else ""
        return Finding(
            kind=self.finding_kind,
            severity=severity or self.severity,
            location=SourceLocation(
                file=path_str,
                line=node.start_point[0],
                col=node.start_point[1],
                end_line=node.end_point[0],
                end_col=node.end_point[1],
            ),
            message=message,
            trace=trace or [],
            confidence=confidence,
            detector_id=self.detector_id,
            raw_node=node,
        )

    def make_location(self, node: Node, file_path: Optional[Path] = None) -> SourceLocation:
        """Build a SourceLocation from any node — useful for building trace lists."""
        path_str = str(file_path) if file_path else ""
        return SourceLocation(
            file=path_str,
            line=node.start_point[0],
            col=node.start_point[1],
            end_line=node.end_point[0],
            end_col=node.end_point[1],
        )


# ─────────────────────────────────────────────
# REGISTRY
# ─────────────────────────────────────────────

class DetectorRegistry:
    """
    Central registry of all active detectors.
    The CLI and eval harness use this to run all detectors without
    importing each one individually.

    Usage:
        registry = DetectorRegistry.default()
        for detector in registry:
            findings = detector.detect(parsed, cfg, result)

    Adding a new detector: import it and call registry.register(MyDetector()).
    The default() classmethod wires up all shipped detectors automatically.
    """

    def __init__(self) -> None:
        self._detectors: list[Detector] = []

    def register(self, detector: Detector) -> None:
        if not detector.detector_id:
            raise ValueError(f"{type(detector).__name__} must set detector_id")
        self._detectors.append(detector)

    def __iter__(self):
        return iter(self._detectors)

    def __len__(self):
        return len(self._detectors)

    def get(self, detector_id: str) -> Optional[Detector]:
        for d in self._detectors:
            if d.detector_id == detector_id:
                return d
        return None

    @classmethod
    def default(cls) -> DetectorRegistry:
        """
        Build the registry with all shipped detectors.
        Import here (not at module top) to avoid circular imports —
        detectors import from base, base should not import from detectors.
        """
        from refactor.detectors.use_after_free  import UseAfterFreeDetector
        from refactor.detectors.double_free     import DoubleFreeDetector
        from refactor.detectors.malloc_free     import MallocWithoutFreeDetector
        from refactor.detectors.null_deref      import NullDerefDetector
        from refactor.detectors.buffer_overrun  import BufferOverrunDetector
        from refactor.detectors.integer_overflow import IntegerOverflowDetector
        from refactor.detectors.api_misuse      import ApiMisuseDetector

        registry = cls()
        registry.register(UseAfterFreeDetector())
        registry.register(DoubleFreeDetector())
        registry.register(MallocWithoutFreeDetector())
        registry.register(NullDerefDetector())
        registry.register(BufferOverrunDetector())
        registry.register(IntegerOverflowDetector())
        registry.register(ApiMisuseDetector())
        return registry