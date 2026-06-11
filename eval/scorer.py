"""
eval/scorer.py
───────────────
Computes precision, recall, fix validity rate, and fix correctness rate
from a list of RunResults.

Design decision: metrics are computed per-system, per-kind, and overall.
Per-kind breakdown is what makes the eval genuinely useful — if your
null_deref detector has 0.4 precision but your use_after_free detector
has 0.95, that's important information. An overall number hides it.

Design decision: Copilot metrics are computed on the collected subset only.
The subset size is always reported alongside the metrics so the reader
knows the denominator. A 0.7 correctness rate on n=8 is very different
from the same rate on n=60.

Design decision: line tolerance is ±3 lines, documented and justified.
Different tools report different AST nodes for the same semantic bug.
clang-tidy may report the malloc call site; our tool reports the return
statement where the leak occurs. Both are correct — the bug is real and
located in the same region. ±3 lines captures this without being so
loose that wrong findings count as matches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from eval.runner import RunResult


# ─────────────────────────────────────────────
# METRIC DATACLASSES
# ─────────────────────────────────────────────

@dataclass
class DetectionMetrics:
    """
    Precision and recall for finding detection.

    true_positives:   expected finding detected within line tolerance
    false_positives:  findings reported that were not the expected kind
    false_negatives:  fixtures where the expected finding was missed
    """
    true_positives:  int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> Optional[float]:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else None

    @property
    def recall(self) -> Optional[float]:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class FixMetrics:
    """
    Fix validity and correctness rates.

    attempted:     number of fix attempts made
    valid:         fixes that re-parsed and compiled cleanly
    correct:       valid fixes where re-detection showed no finding

    validity_rate = valid / attempted
    correctness_rate = correct / valid
    """
    attempted: int = 0
    valid:     int = 0
    correct:   int = 0

    @property
    def validity_rate(self) -> Optional[float]:
        return self.valid / self.attempted if self.attempted > 0 else None

    @property
    def correctness_rate(self) -> Optional[float]:
        return self.correct / self.valid if self.valid > 0 else None


@dataclass
class SystemMetrics:
    """All metrics for one system across all fixtures it was run on."""
    system:      str
    n_fixtures:  int
    detection:   DetectionMetrics   = field(default_factory=DetectionMetrics)
    fix:         FixMetrics         = field(default_factory=FixMetrics)
    # Per-kind breakdown: kind_str → DetectionMetrics
    by_kind:     dict[str, DetectionMetrics] = field(default_factory=dict)
    errors:      int                = 0
    skipped:     int                = 0  # not_collected etc.


@dataclass
class EvalSummary:
    """
    Full eval summary: metrics for all three systems side by side.
    Also stores the raw RunResults for the report generator.
    """
    ast_refactor: SystemMetrics
    clang_tidy:   SystemMetrics
    copilot:      SystemMetrics
    all_results:  list[RunResult]


# ─────────────────────────────────────────────
# SCORER
# ─────────────────────────────────────────────

def score(results: list[RunResult]) -> EvalSummary:
    """
    Compute all metrics from a flat list of RunResults.
    Results for all three systems are expected in the same list.
    """
    by_system: dict[str, list[RunResult]] = {
        "ast_refactor": [],
        "clang_tidy":   [],
        "copilot":      [],
    }
    for r in results:
        if r.system in by_system:
            by_system[r.system].append(r)

    return EvalSummary(
        ast_refactor = _score_system("ast_refactor", by_system["ast_refactor"]),
        clang_tidy   = _score_system("clang_tidy",   by_system["clang_tidy"]),
        copilot      = _score_system("copilot",      by_system["copilot"],
                                     skip_error="not_collected"),
        all_results  = results,
    )


def _score_system(
    system:     str,
    results:    list[RunResult],
    skip_error: Optional[str] = None,
) -> SystemMetrics:
    """
    Compute SystemMetrics from a list of results for one system.

    skip_error: if set, results with this error string are counted as
                skipped rather than errors. Used for Copilot's
                "not_collected" results.
    """
    n_total  = len(results)
    errors   = 0
    skipped  = 0
    detection = DetectionMetrics()
    fix       = FixMetrics()
    by_kind:  dict[str, DetectionMetrics] = {}

    for r in results:
        # Handle skipped and errored results
        if r.error:
            if skip_error and r.error == skip_error:
                skipped += 1
                continue
            errors += 1
            detection.false_negatives += 1
            continue

        # Detection metrics
        kind = r.detection.raw_output  # we'll extract kind from fixture below
        # Use fixture name to look up expected kind in the result
        # (the kind is embedded in the RunResult via detection.raw_output
        # for our tool; for clang-tidy and copilot we count at system level)

        if r.detection.found:
            detection.true_positives += 1
        else:
            detection.false_negatives += 1

        detection.false_positives += r.detection.false_positives

        # Fix metrics
        if r.fix.attempted:
            fix.attempted += 1
            if r.fix.valid:
                fix.valid += 1
            if r.fix.correct:
                fix.correct += 1

    return SystemMetrics(
        system     = system,
        n_fixtures = n_total,
        detection  = detection,
        fix        = fix,
        errors     = errors,
        skipped    = skipped,
    )


def score_with_metadata(
    results:  list[RunResult],
    metadata: dict[str, object],  # fixture_name → FixtureMetadata
) -> EvalSummary:
    """
    Enhanced scoring that uses fixture metadata to compute per-kind breakdowns.
    Pass the metadata dict from the harness for richer metrics.
    """
    summary = score(results)
    # Populate per-kind breakdown using metadata
    for system_metrics in [
        summary.ast_refactor,
        summary.clang_tidy,
        summary.copilot,
    ]:
        _populate_by_kind(system_metrics, results, metadata)
    return summary


def _populate_by_kind(
    system_metrics: SystemMetrics,
    results:        list[RunResult],
    metadata:       dict[str, object],
) -> None:
    """Populate the by_kind dict on a SystemMetrics using fixture metadata."""
    for r in results:
        if r.system != system_metrics.system:
            continue
        if r.error:
            continue
        meta = metadata.get(r.fixture)
        if meta is None:
            continue
        kind = meta.expected.kind
        if kind not in system_metrics.by_kind:
            system_metrics.by_kind[kind] = DetectionMetrics()
        dm = system_metrics.by_kind[kind]
        if r.detection.found:
            dm.true_positives += 1
        else:
            dm.false_negatives += 1
        dm.false_positives += r.detection.false_positives