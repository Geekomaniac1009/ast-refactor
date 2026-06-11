"""
eval/report.py
───────────────
Generates the human-readable markdown comparison table from EvalSummary.

Design decision: the report is generated as markdown, not printed directly.
This means it can be written to a file, included in the README, and
embedded in CI output. The harness prints it to stdout and writes it
to benchmarks/results/report_<timestamp>.md.

Design decision: every metric is shown alongside its denominator (n=X).
A 0.85 fix validity rate on n=6 looks different from n=60.
The reader should never have to guess the sample size.

Design decision: the report explicitly documents what each system
can and cannot measure. clang-tidy gets N/A for fix metrics because
it doesn't produce fixes for memory safety checks — not because it failed.
Copilot gets N/A for precision/recall because it has no structured finding
output. These are honest characterisations of the systems, not gaps.
"""

from __future__ import annotations

from eval.scorer import EvalSummary, SystemMetrics


def generate_report(summary: EvalSummary, elapsed_secs: float = 0.0) -> str:
    """Generate the full markdown comparison report."""
    sections = [
        _header(summary),
        _overview_table(summary),
        _fix_table(summary),
        _per_kind_table(summary),
        _methodology_note(summary),
        _footer(elapsed_secs),
    ]
    return "\n\n".join(s for s in sections if s)


# ─────────────────────────────────────────────
# SECTIONS
# ─────────────────────────────────────────────

def _header(summary: EvalSummary) -> str:
    ar = summary.ast_refactor
    ct = summary.clang_tidy
    cp = summary.copilot
    n_collected = cp.n_fixtures - cp.skipped
    return (
        "# ast-refactor eval report\n\n"
        f"Benchmark: **{ar.n_fixtures}** fixtures  "
        f"(ast-refactor: n={ar.n_fixtures - ar.errors}, "
        f"clang-tidy: n={ct.n_fixtures - ct.errors}, "
        f"Copilot: n={n_collected} collected subset)"
    )


def _overview_table(summary: EvalSummary) -> str:
    ar = summary.ast_refactor
    ct = summary.clang_tidy
    cp = summary.copilot
    n_cp = cp.n_fixtures - cp.skipped

    rows = [
        "## Detection metrics\n",
        "| Metric | ast-refactor | clang-tidy | Copilot (raw LLM) |",
        "|--------|-------------|------------|-------------------|",
        f"| **Fixtures run** | {ar.n_fixtures - ar.errors} | {ct.n_fixtures - ct.errors} | {n_cp} (subset) |",
        f"| **Precision** | {_fmt(ar.detection.precision)} | {_fmt(ct.detection.precision)} | N/A ² |",
        f"| **Recall** | {_fmt(ar.detection.recall)} | {_fmt(ct.detection.recall)} | N/A ² |",
        f"| **F1** | {_fmt(ar.detection.f1)} | {_fmt(ct.detection.f1)} | N/A ² |",
        f"| **True positives** | {ar.detection.true_positives} | {ct.detection.true_positives} | {cp.detection.true_positives} |",
        f"| **False positives** | {ar.detection.false_positives} | {ct.detection.false_positives} | N/A ² |",
        f"| **False negatives** | {ar.detection.false_negatives} | {ct.detection.false_negatives} | {cp.detection.false_negatives} |",
        f"| **Needs compile DB** | No | Yes ¹ | No |",
        f"| **Errors/crashes** | {ar.errors} | {ct.errors} | {cp.errors} |",
        "",
        "> ¹ clang-tidy run without a compile database — some type-dependent checks",
        "> are disabled. This matches the deployment model of ast-refactor (both",
        "> operate on raw source without a build system).",
        ">",
        "> ² Copilot has no structured finding output with line numbers.",
        "> Detection is proxied by whether Copilot produced a non-trivial response.",
        "> Precision/recall are not meaningful for this proxy.",
    ]
    return "\n".join(rows)


def _fix_table(summary: EvalSummary) -> str:
    ar = summary.ast_refactor
    cp = summary.copilot
    n_cp_fix = cp.fix.attempted

    rows = [
        "## Fix metrics\n",
        "| Metric | ast-refactor | clang-tidy | Copilot (raw LLM) |",
        "|--------|-------------|------------|-------------------|",
        f"| **Fix attempts** | {ar.fix.attempted} | N/A ³ | {n_cp_fix} |",
        f"| **Valid fixes** (re-parsed + compiled) | {ar.fix.valid} | N/A ³ | {cp.fix.valid} |",
        f"| **Fix validity rate** | {_fmt(ar.fix.validity_rate)} | N/A ³ | {_fmt(cp.fix.validity_rate)} |",
        f"| **Correct fixes** (detector no longer fires) | {ar.fix.correct} | N/A ³ | {cp.fix.correct} |",
        f"| **Fix correctness rate** | {_fmt(ar.fix.correctness_rate)} | N/A ³ | {_fmt(cp.fix.correctness_rate)} |",
        f"| **Verified before showing user** | Yes | N/A | No |",
        f"| **Runs in CI pipeline** | Yes | Yes | No |",
        "",
        "> ³ clang-tidy does not produce automated fixes for memory safety checks.",
        "> Its fix suggestions are limited to style and naming issues.",
        "> This is accurately represented as N/A, not a failure.",
    ]
    return "\n".join(rows)


def _per_kind_table(summary: EvalSummary) -> str:
    """Per-finding-kind precision and recall for ast-refactor and clang-tidy."""
    ar = summary.ast_refactor
    ct = summary.clang_tidy

    all_kinds = sorted(
        set(ar.by_kind.keys()) | set(ct.by_kind.keys())
    )
    if not all_kinds:
        return ""

    rows = [
        "## Per-detector breakdown (ast-refactor vs clang-tidy)\n",
        "| Detector | ast-refactor precision | ast-refactor recall | clang-tidy precision | clang-tidy recall |",
        "|----------|----------------------|--------------------|--------------------|------------------|",
    ]
    for kind in all_kinds:
        ar_dm = ar.by_kind.get(kind)
        ct_dm = ct.by_kind.get(kind)
        rows.append(
            f"| `{kind}` "
            f"| {_fmt(ar_dm.precision if ar_dm else None)} "
            f"| {_fmt(ar_dm.recall    if ar_dm else None)} "
            f"| {_fmt(ct_dm.precision if ct_dm else None)} "
            f"| {_fmt(ct_dm.recall    if ct_dm else None)} |"
        )
    return "\n".join(rows)


def _methodology_note(summary: EvalSummary) -> str:
    cp = summary.copilot
    n_collected = cp.n_fixtures - cp.skipped
    return (
        "## Methodology\n\n"
        "**Fixture dataset:** C functions extracted from real CVEs and hand-crafted "
        "test cases covering use-after-free, double-free, malloc-without-free, "
        "null dereference, buffer overrun, integer overflow, and API misuse. "
        "One bug per fixture. Ground truth is the fixture JSON metadata.\n\n"
        "**Line tolerance:** ±3 lines. Different tools report different AST nodes "
        "for the same semantic bug (e.g. the allocation site vs the leaking return). "
        "Both are correct characterisations of the same bug.\n\n"
        "**Fix correctness:** functional definition — re-run the detector on the "
        "corrected function. If no finding of the same kind is produced, the fix "
        f"is correct. This is stricter than textual diff comparison.\n\n"
        f"**Copilot baseline:** n={n_collected} fixtures, manually collected. "
        "Standard prompt: *'This C function has a memory safety bug. Fix it and "
        "return only the corrected function, no explanation.'* Outputs stored in "
        "fixture JSON. Model: GitHub Copilot Chat (GPT-4o backbone, as of collection date)."
    )


def _footer(elapsed_secs: float) -> str:
    from datetime import datetime
    return (
        f"---\n"
        f"*Generated by ast-refactor eval harness · "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M')} · "
        f"elapsed: {elapsed_secs:.1f}s*"
    )


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _fmt(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.0%}"