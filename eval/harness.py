"""
eval/harness.py
────────────────
Orchestrates the full benchmark run.

Loads all fixtures, runs all three systems, collects results,
scores them, and writes output files.

Usage:
    python -m eval.harness
    python -m eval.harness --fixtures benchmarks/fixtures --no-llm
    python -m eval.harness --system ast_refactor --tag cve
    python -m eval.harness --fixture malloc_early_return

Output files written to benchmarks/results/:
    results_<timestamp>.json     raw RunResult objects
    summary_<timestamp>.json     scored metrics
    report_<timestamp>.md        human-readable comparison table
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

from eval.fixture_schema import FixtureMetadata
from eval.runner import AstRefactorRunner, ClangTidyRunner, CopilotRunner, RunResult
from eval.scorer import EvalSummary, score_with_metadata
from eval.report import generate_report


FIXTURES_DIR = Path("benchmarks/fixtures")
RESULTS_DIR  = Path("benchmarks/results")


# ─────────────────────────────────────────────
# FIXTURE LOADING
# ─────────────────────────────────────────────

def load_fixtures(
    fixtures_dir: Path,
    tag:          str | None     = None,
    fixture_name: str | None     = None,
) -> list[tuple[FixtureMetadata, str]]:
    """
    Load all fixture (metadata, source) pairs from fixtures_dir.

    tag:          if set, only load fixtures with this tag
    fixture_name: if set, load only this one fixture by stem name
    """
    pairs: list[tuple[FixtureMetadata, str]] = []

    json_files = sorted(fixtures_dir.glob("*.json"))
    if not json_files:
        print(f"[harness] No fixture JSON files found in {fixtures_dir}", file=sys.stderr)
        return pairs

    for json_path in json_files:
        try:
            meta = FixtureMetadata.from_json(json_path)
        except Exception as exc:
            print(f"[harness] Skipping {json_path.name}: bad metadata — {exc}", file=sys.stderr)
            continue

        # Filter by name
        if fixture_name and meta.name != fixture_name:
            continue

        # Filter by tag
        if tag and tag not in meta.tags:
            continue

        c_path = fixtures_dir / meta.fixture_file
        if not c_path.exists():
            print(f"[harness] Skipping {meta.name}: .c file not found at {c_path}", file=sys.stderr)
            continue

        try:
            source = c_path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"[harness] Skipping {meta.name}: could not read .c file — {exc}", file=sys.stderr)
            continue

        pairs.append((meta, source))

    return pairs


# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────

def run_benchmark(
    fixtures:    list[tuple[FixtureMetadata, str]],
    systems:     list[str],
    llm_enabled: bool = True,
) -> list[RunResult]:
    """
    Run all specified systems on all fixtures.
    Returns flat list of RunResults (all systems, all fixtures).
    """
    runners = _build_runners(systems, llm_enabled)
    all_results: list[RunResult] = []
    n_total = len(fixtures) * len(runners)
    done    = 0

    for meta, source in fixtures:
        for runner in runners:
            done += 1
            print(
                f"[{done:3d}/{n_total}] {runner.system_name:14s} {meta.name}",
                end=" ... ",
                flush=True,
            )
            result = runner.run(meta, source)
            all_results.append(result)

            # Brief status line
            if result.error:
                if result.error == "not_collected":
                    print("skipped (no Copilot output)")
                else:
                    print(f"ERROR: {result.error[:60]}")
            elif result.detection.found:
                fix_note = ""
                if result.fix.attempted:
                    fix_note = " | fix: " + (
                        "✓ correct" if result.fix.correct
                        else "✓ valid" if result.fix.valid
                        else "✗ invalid"
                    )
                print(f"✓ found (line {result.detection.reported_line}){fix_note}")
            else:
                print("✗ missed")

    return all_results


def _build_runners(systems: list[str], llm_enabled: bool):
    runners = []
    if "ast_refactor" in systems:
        runners.append(AstRefactorRunner(llm_enabled=llm_enabled))
    if "clang_tidy" in systems:
        runners.append(ClangTidyRunner())
    if "copilot" in systems:
        runners.append(CopilotRunner())
    return runners


# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────

def save_results(
    results:  list[RunResult],
    summary:  EvalSummary,
    report:   str,
    out_dir:  Path,
) -> None:
    """Write results JSON, summary JSON, and markdown report to out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Raw results
    results_path = out_dir / f"results_{ts}.json"
    results_path.write_text(
        json.dumps([_result_to_dict(r) for r in results], indent=2),
        encoding="utf-8",
    )

    # Summary metrics
    summary_path = out_dir / f"summary_{ts}.json"
    summary_path.write_text(
        json.dumps(_summary_to_dict(summary), indent=2),
        encoding="utf-8",
    )

    # Markdown report
    report_path = out_dir / f"report_{ts}.md"
    report_path.write_text(report, encoding="utf-8")

    print(f"\n[harness] Results:  {results_path}")
    print(f"[harness] Summary:  {summary_path}")
    print(f"[harness] Report:   {report_path}")


def _result_to_dict(r: RunResult) -> dict:
    return {
        "system":       r.system,
        "fixture":      r.fixture,
        "elapsed_ms":   round(r.elapsed_ms, 1),
        "error":        r.error,
        "detection": {
            "found":           r.detection.found,
            "reported_line":   r.detection.reported_line,
            "line_delta":      r.detection.line_delta,
            "false_positives": r.detection.false_positives,
        },
        "fix": {
            "attempted": r.fix.attempted,
            "valid":     r.fix.valid,
            "correct":   r.fix.correct,
            "attempts":  r.fix.attempts,
        },
    }


def _fmt(value: float | None, as_pct: bool = True) -> str:
    if value is None:
        return "N/A"
    return f"{value:.0%}" if as_pct else f"{value:.3f}"


def _summary_to_dict(s: EvalSummary) -> dict:
    def sys_dict(sm):
        return {
            "system":           sm.system,
            "n_fixtures":       sm.n_fixtures,
            "skipped":          sm.skipped,
            "errors":           sm.errors,
            "precision":        _fmt(sm.detection.precision),
            "recall":           _fmt(sm.detection.recall),
            "f1":               _fmt(sm.detection.f1),
            "fix_validity":     _fmt(sm.fix.validity_rate),
            "fix_correctness":  _fmt(sm.fix.correctness_rate),
            "by_kind": {
                kind: {
                    "precision": _fmt(dm.precision),
                    "recall":    _fmt(dm.recall),
                }
                for kind, dm in sm.by_kind.items()
            },
        }
    return {
        "ast_refactor": sys_dict(s.ast_refactor),
        "clang_tidy":   sys_dict(s.clang_tidy),
        "copilot":      sys_dict(s.copilot),
    }


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ast-refactor benchmark harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--fixtures", type=Path, default=FIXTURES_DIR,
        help=f"Path to fixture directory (default: {FIXTURES_DIR})",
    )
    parser.add_argument(
        "--results", type=Path, default=RESULTS_DIR,
        help=f"Path to results output directory (default: {RESULTS_DIR})",
    )
    parser.add_argument(
        "--system", choices=["ast_refactor", "clang_tidy", "copilot", "all"],
        default="all",
        help="Which system(s) to run (default: all)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Disable LLM calls (detection only, faster for iteration)",
    )
    parser.add_argument(
        "--tag", type=str, default=None,
        help="Only run fixtures with this tag",
    )
    parser.add_argument(
        "--fixture", type=str, default=None,
        help="Run only this fixture by name (stem, no extension)",
    )
    args = parser.parse_args()

    systems = (
        ["ast_refactor", "clang_tidy", "copilot"]
        if args.system == "all"
        else [args.system]
    )

    print(f"[harness] Loading fixtures from {args.fixtures}")
    fixtures = load_fixtures(args.fixtures, tag=args.tag, fixture_name=args.fixture)
    if not fixtures:
        print("[harness] No fixtures loaded. Exiting.")
        sys.exit(1)

    print(f"[harness] Loaded {len(fixtures)} fixture(s). Systems: {systems}")
    if args.no_llm:
        print("[harness] LLM disabled — detection only.")

    print()
    start = time.monotonic()
    results = run_benchmark(fixtures, systems, llm_enabled=not args.no_llm)
    elapsed = time.monotonic() - start

    # Build metadata dict for per-kind breakdown
    metadata = {meta.name: meta for meta, _ in fixtures}

    print(f"\n[harness] Scoring {len(results)} result(s)...")
    summary = score_with_metadata(results, metadata)

    report = generate_report(summary, elapsed_secs=elapsed)
    print("\n" + report)

    save_results(results, summary, report, args.results)


if __name__ == "__main__":
    main()