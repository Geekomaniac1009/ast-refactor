"""
eval/fixture_schema.py
───────────────────────
Typed schema for benchmark fixture metadata.

Each fixture is a pair of files in benchmarks/fixtures/:
  - <name>.c        the C source containing exactly one buggy function
  - <name>.json     metadata conforming to this schema

Design decision: one bug per fixture.
Real CVE files contain thousands of lines and multiple functions.
We extract just the relevant function into a minimal .c file. This
makes ground truth unambiguous — exactly one expected finding, at a
known line, of a known kind. The tradeoff is manual extraction effort
upfront. That effort is worth it: ambiguous ground truth produces
ambiguous metrics, and ambiguous metrics prove nothing.

Design decision: correct_fix stored as complete function text, not a diff.
Diffs are fragile when line numbers shift between tool runs. The scorer
checks correctness functionally — re-run the detector on the corrected
function. If the finding disappears, the fix is correct. This is a
behavioural definition of correctness, not a textual one. It's also
stricter: a fix that removes the malloc call entirely would pass a diff
check but would fail our functional check because it changes semantics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class FixtureSource(str, Enum):
    CVE         = "cve"          # extracted from a real CVE
    HANDCRAFTED = "handcrafted"  # written specifically for the benchmark
    OSS         = "oss"          # from open-source project, not a CVE


@dataclass
class ExpectedFinding:
    """
    The one finding we expect on this fixture.
    One fixture = one expected finding. Hard constraint.
    """
    kind:     str   # FindingKind value e.g. "malloc_without_free"
    line:     int   # 1-indexed line number of primary location
    detector: str   # detector_id that should fire


@dataclass
class FixtureMetadata:
    """
    Complete metadata for one benchmark fixture.

    fixture_file:    filename of the .c file (basename only, no path)
    function_name:   the buggy function's name inside the .c file
    expected:        the one finding we expect
    correct_fix:     complete corrected function text (not a diff)
    source:          provenance of the fixture
    source_ref:      CVE ID, GitHub URL, or description
    notes:           human-readable explanation of the bug pattern
    copilot_output:  pre-collected Copilot raw response, or None
    tags:            optional tags for subsetting e.g. ["alias", "loop"]
    """
    fixture_file:   str
    function_name:  str
    expected:       ExpectedFinding
    correct_fix:    str
    source:         FixtureSource
    source_ref:     str
    notes:          str
    copilot_output: Optional[str]   = None
    tags:           list[str]       = field(default_factory=list)

    @property
    def name(self) -> str:
        return Path(self.fixture_file).stem

    @classmethod
    def from_json(cls, path: Path) -> FixtureMetadata:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            fixture_file   = data["fixture_file"],
            function_name  = data["function_name"],
            expected       = ExpectedFinding(**data["expected"]),
            correct_fix    = data["correct_fix"],
            source         = FixtureSource(data.get("source", "handcrafted")),
            source_ref     = data.get("source_ref", ""),
            notes          = data.get("notes", ""),
            copilot_output = data.get("copilot_output"),
            tags           = data.get("tags", []),
        )

    def to_json(self, path: Path) -> None:
        path.write_text(json.dumps({
            "fixture_file":   self.fixture_file,
            "function_name":  self.function_name,
            "expected": {
                "kind":     self.expected.kind,
                "line":     self.expected.line,
                "detector": self.expected.detector,
            },
            "correct_fix":    self.correct_fix,
            "source":         self.source.value,
            "source_ref":     self.source_ref,
            "notes":          self.notes,
            "copilot_output": self.copilot_output,
            "tags":           self.tags,
        }, indent=2), encoding="utf-8")