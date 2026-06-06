"""
cli.py
───────
Command-line interface for ast-refactor.

Entry point for all user-facing functionality. Wires together:
    parser → cfg → pointer_state → detectors → context → llm → verifier → formatter

Subcommands:
    check   — run detectors only, no LLM calls. Fast, suitable for CI.
    fix     — run detectors + LLM suggestions + verification. Shows diffs.
    explain — deep explanation of a specific finding by line number.
    sarif   — emit SARIF 2.1.0 file for GitHub Code Scanning integration.

Usage examples:
    refactor check src/buffer.c
    refactor check src/ --recursive
    refactor fix   src/buffer.c --severity error
    refactor fix   src/buffer.c --detector use_after_free --json
    refactor explain src/buffer.c --line 42
    refactor sarif src/ --output results/findings.sarif

Global options (work on all subcommands):
    --severity   error|warning|note   filter findings by minimum severity
    --detector   detector_id          run only this detector
    --no-colour                       disable rich terminal colour
    --json                            machine-readable JSON output to stdout
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import click

from refactor.models import (
    CFG, Finding, FindingKind, Severity,
    VerificationStatus, VerifiedSuggestion,
)
from refactor.parser import ParsedFile, parse_directory, parse_file, parse_string
from refactor.cfg import build_cfg
from refactor.pointer_state import analyse
from refactor.detectors.base import Detector, DetectorRegistry
from refactor.context import build_context
from refactor import llm_client
from refactor.verifier import verify
from refactor import formatter
from refactor import sarif as sarif_module

# ─────────────────────────────────────────────
# SHARED OPTIONS
# Applied to every subcommand via @common_options decorator
# ─────────────────────────────────────────────

def common_options(f):
    """Decorator that attaches shared options to a command."""
    f = click.option(
        "--severity", "-s",
        type=click.Choice(["error", "warning", "note"], case_sensitive=False),
        default=None,
        help="Minimum severity to report (default: all).",
    )(f)
    f = click.option(
        "--detector", "-d",
        type=str,
        default=None,
        help="Run only this detector (e.g. use_after_free).",
    )(f)
    f = click.option(
        "--json", "output_json",
        is_flag=True,
        default=False,
        help="Output machine-readable JSON to stdout.",
    )(f)
    f = click.option(
        "--no-colour",
        is_flag=True,
        default=False,
        help="Disable terminal colour output.",
    )(f)
    return f


def _maybe_plain(coloured: str, plain: str) -> str:
    return plain if formatter.is_no_colour() else coloured


# ─────────────────────────────────────────────
# CLI GROUP
# ─────────────────────────────────────────────

@click.group()
@click.version_option(version="0.1.0", prog_name="ast-refactor")
def cli():
    """
    ast-refactor — AST-grounded static analysis with LLM-verified fixes.

    Detects memory safety issues in C source code using control flow
    analysis and pointer state tracking. Suggests fixes verified by
    re-parsing through tree-sitter before showing them to you.
    """
    pass


# ─────────────────────────────────────────────
# CHECK SUBCOMMAND
# ─────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, default=False,
              help="Recurse into subdirectories (when PATH is a directory).")
@common_options
def check(
    path:       str,
    recursive:  bool,
    severity:   Optional[str],
    detector:   Optional[str],
    output_json: bool,
    no_colour:  bool,
) -> None:
    """
    Run detectors on PATH and report findings. No LLM calls are made.

    PATH may be a single .c file or a directory.
    Exit code: 0 if no findings, 1 if findings exist, 2 on error.

    \b
    Examples:
        refactor check src/buf.c
        refactor check src/ --recursive --severity error
        refactor check src/buf.c --detector null_deref --json
    """
    start = time.monotonic()

    formatter.configure_output(no_colour=no_colour)

    parsed_files = _load_sources(path, recursive)
    if not parsed_files:
        formatter.print_error(f"No C source files found at: {path}")
        sys.exit(2)

    registry  = _build_registry(detector)
    min_sev   = _parse_severity(severity)
    all_findings: list[Finding] = []

    for file_path, parsed in parsed_files.items():
        findings = _run_detectors(parsed, registry)
        findings = _filter_severity(findings, min_sev)
        all_findings.extend(findings)

    elapsed = time.monotonic() - start

    if output_json:
        formatter.print_json(all_findings, [])
    else:
        formatter.print_findings(all_findings)
        formatter.print_summary(all_findings, [], elapsed)

    sys.exit(1 if all_findings else 0)


# ─────────────────────────────────────────────
# FIX SUBCOMMAND
# ─────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, default=False,
              help="Recurse into subdirectories.")
@click.option("--max-fixes", type=int, default=10,
              help="Maximum number of LLM fix attempts per run (default: 10).")
@common_options
def fix(
    path:       str,
    recursive:  bool,
    max_fixes:  int,
    severity:   Optional[str],
    detector:   Optional[str],
    output_json: bool,
    no_colour:  bool,
) -> None:
    """
    Run detectors and generate LLM-verified fix suggestions.

    For each finding, calls the configured LLM (see .env), re-parses
    the suggestion through tree-sitter, and shows a unified diff if
    the suggestion passes structural verification.

    \b
    Examples:
        refactor fix src/buf.c
        refactor fix src/ --recursive --severity error --max-fixes 5
        refactor fix src/buf.c --detector malloc_without_free
    """
    start = time.monotonic()
    llm_client.reset_usage()

    formatter.configure_output(no_colour=no_colour)
    console = formatter.stdout_console()

    parsed_files = _load_sources(path, recursive)
    if not parsed_files:
        formatter.print_error(f"No C source files found at: {path}")
        sys.exit(2)

    registry  = _build_registry(detector)
    min_sev   = _parse_severity(severity)
    all_findings:    list[Finding]             = []
    all_suggestions: list[VerifiedSuggestion]  = []
    fix_budget = max_fixes

    for file_path, parsed in parsed_files.items():
        findings = _run_detectors(parsed, registry)
        findings = _filter_severity(findings, min_sev)
        all_findings.extend(findings)

        if not output_json:
            formatter.print_findings(findings)

        for finding in findings:
            if fix_budget <= 0:
                console.print(
                    _maybe_plain(
                        f"[dim]Fix budget exhausted ({max_fixes} fixes). "
                        f"Remaining findings shown without suggestions.[/dim]",
                        f"Fix budget exhausted ({max_fixes} fixes). Remaining findings shown without suggestions.",
                    )
                )
                break

            suggestion = _generate_fix(finding, parsed, fix_budget)
            all_suggestions.append(suggestion)
            fix_budget -= 1

            if not output_json:
                formatter.print_verified_suggestion(suggestion)

    elapsed = time.monotonic() - start

    if output_json:
        formatter.print_json(all_findings, all_suggestions)
    else:
        formatter.print_summary(all_findings, all_suggestions, elapsed)

    has_errors = any(f.severity == Severity.ERROR for f in all_findings)
    sys.exit(1 if has_errors else 0)


# ─────────────────────────────────────────────
# EXPLAIN SUBCOMMAND
# ─────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--line", "-l", type=int, required=True,
              help="Line number of the finding to explain (1-indexed).")
@click.option("--detector", "-d", type=str, default=None,
              help="Detector to use (if multiple findings at this line).")
@click.option("--no-colour", is_flag=True, default=False)
def explain(
    path:     str,
    line:     int,
    detector: Optional[str],
    no_colour: bool,
) -> None:
    """
    Generate a detailed explanation of the finding at a specific line.

    Asks the LLM for a teaching explanation: what the bug is, what can
    go wrong at runtime, and why the suggested fix works. Useful for
    onboarding and code review.

    \b
    Examples:
        refactor explain src/buf.c --line 42
        refactor explain src/buf.c --line 42 --detector use_after_free
    """
    formatter.configure_output(no_colour=no_colour)
    console = formatter.stdout_console()

    parsed_files = _load_sources(path, recursive=False)
    if not parsed_files:
        formatter.print_error(f"No C source files found at: {path}")
        sys.exit(2)

    registry = _build_registry(detector)
    file_path, parsed = next(iter(parsed_files.items()))

    findings = _run_detectors(parsed, registry)

    # Find findings at or near the requested line (0-indexed internally)
    target_line = line - 1
    matching = [
        f for f in findings
        if abs(f.location.line - target_line) <= 2
    ]

    if not matching:
        formatter.print_error(
            f"No findings near line {line} in {path}. "
            f"Run 'refactor check {path}' to see all findings."
        )
        sys.exit(1)

    # Take the first matching finding (most severe if multiple)
    matching.sort(key=lambda f: (f.severity.value, f.location.line))
    finding = matching[0]

    formatter.print_findings([finding])

    # Build context and call LLM for explanation
    try:
        cfg    = _build_function_cfg(finding, parsed)
        result = analyse(cfg, parsed.source_bytes)
        pkg    = build_context(finding, parsed, cfg, result)
    except Exception as exc:
        formatter.print_error(f"Could not build context: {exc}")
        sys.exit(2)

    # Modify prompt to ask for teaching explanation, not just a fix
    explanation_prompt = (
        f"{pkg.prompt}\n\n"
        f"In addition to the JSON fix, provide a TEACHING EXPLANATION in the "
        f"'explanation' field that covers:\n"
        f"  1. What exactly is wrong and why it is dangerous\n"
        f"  2. A minimal scenario showing how this could be exploited or cause a crash\n"
        f"  3. Why the suggested fix prevents the issue\n"
        f"Write the explanation for a developer who understands C but may not know "
        f"memory safety internals."
    )

    from dataclasses import replace
    pkg_with_explanation = replace(pkg, prompt=explanation_prompt)

    console.print(_maybe_plain("\n[bold]Asking LLM for detailed explanation...[/bold]", "\nAsking LLM for detailed explanation..."))
    response = llm_client.call(pkg_with_explanation)

    if response is None:
        formatter.print_error(
            "LLM call failed. Check your API key and LLM_PROVIDER in .env"
        )
        sys.exit(2)

    console.print()
    console.print(_maybe_plain("[bold cyan]Explanation[/bold cyan]", "Explanation"))
    console.print("─" * 60)
    console.print(response.explanation)
    console.print()

    if response.corrected_code:
        console.print(_maybe_plain("[bold cyan]Suggested Fix[/bold cyan]", "Suggested Fix"))
        console.print("─" * 60)
        from rich.syntax import Syntax
        console.print(Syntax(response.corrected_code, "c", theme="monokai"))


# ─────────────────────────────────────────────
# SARIF SUBCOMMAND
# ─────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="results/findings.sarif",
              help="Output path for the SARIF file (default: results/findings.sarif).")
@click.option("--recursive", "-r", is_flag=True, default=False,
              help="Recurse into subdirectories.")
@click.option("--base-path", type=click.Path(), default=None,
              help="Repo root for relative URIs (default: current directory).")
@common_options
def sarif(
    path:       str,
    output:     str,
    recursive:  bool,
    base_path:  Optional[str],
    severity:   Optional[str],
    detector:   Optional[str],
    output_json: bool,
    no_colour:  bool,
) -> None:
    """
    Run detectors and write findings as a SARIF 2.1.0 file.

    SARIF files can be uploaded to GitHub Code Scanning to display
    findings as pull request annotations and in the Security tab.

    \b
    GitHub Actions usage:
        - run: refactor sarif src/ --output results/findings.sarif
        - uses: github/codeql-action/upload-sarif@v3
          with:
            sarif_file: results/findings.sarif

    \b
    Examples:
        refactor sarif src/ --output findings.sarif
        refactor sarif src/ --base-path /home/user/myrepo
    """
    formatter.configure_output(no_colour=no_colour)
    console = formatter.stdout_console()

    parsed_files = _load_sources(path, recursive)
    if not parsed_files:
        formatter.print_error(f"No C source files found at: {path}")
        sys.exit(2)

    registry  = _build_registry(detector)
    min_sev   = _parse_severity(severity)
    all_findings: list[Finding] = []

    for _, parsed in parsed_files.items():
        findings = _run_detectors(parsed, registry)
        findings = _filter_severity(findings, min_sev)
        all_findings.extend(findings)

    base = Path(base_path) if base_path else Path.cwd()
    output_path = Path(output)

    sarif_module.write_sarif(
        output_path  = output_path,
        suggestions  = [],
        findings     = all_findings,
        base_path    = base,
    )

    if not output_json:
        console.print(
            _maybe_plain(
                f"[green]✓[/green] SARIF written to [bold]{output_path}[/bold] "
                f"({len(all_findings)} finding(s))",
                f"SARIF written to {output_path} ({len(all_findings)} finding(s))",
            )
        )

    sys.exit(1 if all_findings else 0)


# ─────────────────────────────────────────────
# PIPELINE HELPERS
# ─────────────────────────────────────────────

def _load_sources(
    path:      str,
    recursive: bool,
) -> dict[Path, ParsedFile]:
    """
    Load and parse C source files from path.
    path may be a single file or a directory.
    """
    p = Path(path)
    if p.is_file():
        try:
            return {p: parse_file(p)}
        except Exception as exc:
            formatter.print_error(f"Could not parse {p}: {exc}")
            return {}
    elif p.is_dir():
        return parse_directory(p, recursive=recursive)
    return {}


def _build_registry(detector_id: Optional[str]) -> DetectorRegistry:
    """
    Build the detector registry.
    If detector_id is specified, build a single-detector registry.
    Otherwise return the full default registry.
    """
    if detector_id is None:
        return DetectorRegistry.default()

    full = DetectorRegistry.default()
    specific = full.get(detector_id)
    if specific is None:
        available = [d.detector_id for d in full]
        formatter.print_error(
            f"Unknown detector '{detector_id}'. "
            f"Available: {', '.join(available)}"
        )
        sys.exit(2)

    registry = DetectorRegistry()
    registry.register(specific)
    return registry


def _parse_severity(severity: Optional[str]) -> Optional[Severity]:
    """Convert severity string to Severity enum. None means no filter."""
    if severity is None:
        return None
    return {
        "error":   Severity.ERROR,
        "warning": Severity.WARNING,
        "note":    Severity.NOTE,
    }[severity.lower()]


def _filter_severity(
    findings: list[Finding],
    min_sev:  Optional[Severity],
) -> list[Finding]:
    """Filter findings to those at or above min_sev."""
    if min_sev is None:
        return findings
    order = {Severity.NOTE: 0, Severity.WARNING: 1, Severity.ERROR: 2}
    return [f for f in findings if order[f.severity] >= order[min_sev]]


def _run_detectors(
    parsed:   ParsedFile,
    registry: DetectorRegistry,
) -> list[Finding]:
    """
    Run all registered detectors on all functions in a parsed file.
    Builds a CFG and runs dataflow analysis per function, then runs
    each detector against the result.

    Errors in individual functions are caught and reported as warnings
    rather than crashing the entire run — partial results are more
    useful than no results.
    """
    from refactor.parser import iter_functions

    all_findings: list[Finding] = []

    for func_node in iter_functions(parsed):
        try:
            cfg    = build_cfg(func_node, parsed.source_bytes)
            result = analyse(cfg, parsed.source_bytes)
        except Exception as exc:
            from refactor.parser import get_function_name
            name = get_function_name(func_node, parsed.source_bytes) or "?"
            formatter.print_warning(
                f"Skipping function '{name}' in "
                f"{parsed.file_path or '<unknown>'}: {exc}"
            )
            continue

        for detector in registry:
            try:
                findings = detector.detect(parsed, cfg, result)
                all_findings.extend(findings)
            except Exception as exc:
                formatter.print_warning(
                    f"Detector '{detector.detector_id}' raised: {exc}"
                )

    return all_findings


def _build_function_cfg(finding: Finding, parsed: ParsedFile) -> CFG:
    """
    Build the CFG for the function containing a specific finding.
    Used by the explain subcommand.
    """
    from refactor.parser import iter_functions, get_function_name

    for func_node in iter_functions(parsed):
        if (func_node.start_point[0] <= finding.location.line
                <= func_node.end_point[0]):
            return build_cfg(func_node, parsed.source_bytes)

    raise ValueError(
        f"Could not find function containing line {finding.location.line + 1}"
    )


def _generate_fix(
    finding:  Finding,
    parsed:   ParsedFile,
    budget:   int,
) -> VerifiedSuggestion:
    """
    Generate and verify a fix for a single finding.
    Returns a VerifiedSuggestion regardless of outcome —
    failures are encoded in the status field, not as exceptions.
    """
    # Build CFG and dataflow result for this finding's function
    try:
        cfg    = _build_function_cfg(finding, parsed)
        result = analyse(cfg, parsed.source_bytes)
        pkg    = build_context(finding, parsed, cfg, result)
    except Exception as exc:
        formatter.print_warning(f"Could not build context for finding: {exc}")
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.NO_SUGGESTION,
        )

    # Call LLM
    llm_response = llm_client.call(pkg)
    if llm_response is None:
        return VerifiedSuggestion(
            finding=finding,
            status=VerificationStatus.NO_SUGGESTION,
        )

    # Verify the suggestion
    return verify(finding, llm_response, parsed, attempt=1)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cli()