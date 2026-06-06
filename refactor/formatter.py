"""
refactor/formatter.py
──────────────────────
Terminal output formatter for the CLI.

Consumes: list[VerifiedSuggestion] + list[Finding]
Produces: formatted strings printed to stdout

Responsibilities:
  - Render findings in a clang-tidy-style one-line format
  - Render verified suggestions as unified diffs with colour
  - Render a run summary (finding counts by severity, token usage)
  - Produce machine-readable JSON output (--json flag)
  - Never call the LLM, never read files, never do analysis

Uses the `rich` library for colour and formatting.
Falls back to plain text if rich is unavailable (CI environments,
pipes, non-TTY output) — rich detects this automatically via
Console(force_terminal=False) which is the default.
"""

from __future__ import annotations

import json
import sys
from typing import Optional

from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text
from rich import box
from rich.table import Table
from rich.panel import Panel

from refactor.models import (
    Finding, FindingKind, Severity,
    VerificationStatus, VerifiedSuggestion,
)
from refactor.llm_client import get_usage


# ─────────────────────────────────────────────
# CONSOLE INSTANCES
# stdout for normal output, stderr for diagnostics
# ─────────────────────────────────────────────

_console      = Console(highlight=False)
_err_console  = Console(stderr=True, highlight=False)


# ─────────────────────────────────────────────
# SEVERITY COLOURS
# ─────────────────────────────────────────────

_SEVERITY_COLOUR: dict[Severity, str] = {
    Severity.ERROR:   "bold red",
    Severity.WARNING: "bold yellow",
    Severity.NOTE:    "bold cyan",
}

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.ERROR:   "error",
    Severity.WARNING: "warning",
    Severity.NOTE:    "note",
}

_KIND_LABEL: dict[FindingKind, str] = {
    FindingKind.USE_AFTER_FREE:      "use-after-free",
    FindingKind.DOUBLE_FREE:         "double-free",
    FindingKind.MALLOC_WITHOUT_FREE: "memory-leak",
    FindingKind.NULL_DEREF:          "null-deref",
    FindingKind.BUFFER_OVERRUN:      "buffer-overrun",
    FindingKind.INTEGER_OVERFLOW:    "integer-overflow",
    FindingKind.API_MISUSE:          "api-misuse",
    FindingKind.TAINT_PROPAGATION:   "taint",
}


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def print_findings(findings: list[Finding]) -> None:
    """
    Print findings in clang-tidy-style one-line format:
        path/to/file.c:12:5: error [use-after-free] message text

    Grouped by file, sorted by line number within each file.
    Trace locations are printed as indented notes below each finding.
    """
    if not findings:
        return

    # Group by file
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.location.file or "<unknown>", []).append(f)

    for file_path in sorted(by_file):
        file_findings = sorted(by_file[file_path], key=lambda f: f.location.line)
        for finding in file_findings:
            _print_single_finding(finding)


def print_verified_suggestion(suggestion: VerifiedSuggestion) -> None:
    """
    Print a verified suggestion.

    ACCEPTED:  show the unified diff with syntax highlighting
    REJECTED:  show a brief rejection reason (not the full error, just a summary)
    NO_SUGGESTION: print nothing — the finding will have been shown already
    """
    if suggestion.status == VerificationStatus.ACCEPTED:
        _print_accepted(suggestion)
    elif suggestion.status in (
        VerificationStatus.REJECTED_PARSE_ERR,
        VerificationStatus.REJECTED_BAD_DIFF,
        VerificationStatus.REJECTED_MAX_RETRY,
    ):
        _print_rejected(suggestion)
    # NO_SUGGESTION: silent


def print_summary(
    findings:     list[Finding],
    suggestions:  list[VerifiedSuggestion],
    elapsed_secs: float,
) -> None:
    """
    Print a run summary table after all findings have been processed.
    Shows: finding counts by severity, suggestion acceptance rate,
    token usage, and elapsed time.
    """
    errors   = sum(1 for f in findings if f.severity == Severity.ERROR)
    warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
    notes    = sum(1 for f in findings if f.severity == Severity.NOTE)

    accepted = sum(1 for s in suggestions if s.accepted)
    total_s  = len(suggestions)

    usage = get_usage()

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="dim")
    table.add_column("Value", style="bold")

    table.add_row("Findings",
        f"[red]{errors} error(s)[/red]  "
        f"[yellow]{warnings} warning(s)[/yellow]  "
        f"[cyan]{notes} note(s)[/cyan]"
    )
    if total_s > 0:
        table.add_row("Suggestions",
            f"{accepted}/{total_s} accepted  "
            f"({100 * accepted // total_s}% acceptance rate)"
        )
    table.add_row("Tokens",  f"{usage.total_tokens:,} total  "
                             f"({usage.input_tokens:,} in / {usage.output_tokens:,} out)")
    table.add_row("Time",    f"{elapsed_secs:.1f}s")

    _console.print()
    _console.print(Panel(table, title="[bold]Run summary[/bold]", border_style="dim"))


def print_json(
    findings:    list[Finding],
    suggestions: list[VerifiedSuggestion],
) -> None:
    """
    Print machine-readable JSON to stdout.
    Used when the CLI is called with --json flag.
    Suitable for piping into other tools or CI systems.
    """
    output = {
        "findings": [_finding_to_dict(f) for f in findings],
        "suggestions": [_suggestion_to_dict(s) for s in suggestions],
        "usage": {
            "input_tokens":  get_usage().input_tokens,
            "output_tokens": get_usage().output_tokens,
            "total_tokens":  get_usage().total_tokens,
        },
    }
    # Use sys.stdout directly — bypasses rich so no colour codes in output
    print(json.dumps(output, indent=2))


def print_error(message: str) -> None:
    """Print a diagnostic error to stderr."""
    _err_console.print(f"[bold red]error:[/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a diagnostic warning to stderr."""
    _err_console.print(f"[bold yellow]warning:[/bold yellow] {message}")


# ─────────────────────────────────────────────
# INTERNAL RENDERERS
# ─────────────────────────────────────────────

def _print_single_finding(finding: Finding) -> None:
    """
    Render one finding in clang-tidy format:
        file.c:12:5: error [use-after-free]: message text  [confidence: 0.95]
    """
    loc      = finding.location
    display  = loc.display()   # "file.c:12:5" (1-indexed)
    sev_col  = _SEVERITY_COLOUR.get(finding.severity, "white")
    sev_lab  = _SEVERITY_LABEL.get(finding.severity, "note")
    kind_lab = _KIND_LABEL.get(finding.kind, finding.kind.value)

    # Main finding line
    line = Text()
    line.append(f"{display}: ", style="bold white")
    line.append(f"{sev_lab}", style=sev_col)
    line.append(f" [{kind_lab}]", style="dim")
    line.append(f" {finding.message}")
    if finding.confidence < 1.0:
        line.append(f"  [confidence: {finding.confidence:.0%}]", style="dim")
    _console.print(line)

    # Trace locations (indented)
    for i, trace_loc in enumerate(finding.trace):
        if trace_loc == loc:
            continue   # don't repeat the primary location
        trace_text = Text()
        trace_text.append("  note: ", style="bold cyan")
        trace_text.append(f"{trace_loc.display()} ", style="dim")
        _console.print(trace_text)


def _print_accepted(suggestion: VerifiedSuggestion) -> None:
    """
    Render an accepted suggestion as a syntax-highlighted unified diff.
    """
    if not suggestion.diff:
        return

    finding   = suggestion.finding
    kind_lab  = _KIND_LABEL.get(finding.kind, finding.kind.value)
    resp      = suggestion.llm_response

    _console.print()
    _console.print(
        f"[bold green]✓ Suggested fix[/bold green] "
        f"[dim]({kind_lab}, "
        f"attempt {suggestion.attempts}, "
        f"LLM confidence {resp.confidence:.0%})[/dim]"
    )

    # Diff as syntax-highlighted code block
    syntax = Syntax(
        suggestion.diff,
        "diff",
        theme="monokai",
        line_numbers=False,
        word_wrap=False,
    )
    _console.print(syntax)

    # Explanation (collapsed to first 2 sentences for terminal display)
    if resp and resp.explanation:
        explanation = _truncate_explanation(resp.explanation, max_sentences=2)
        _console.print(f"  [dim italic]{explanation}[/dim italic]")
        _console.print()


def _print_rejected(suggestion: VerifiedSuggestion) -> None:
    """
    Render a rejection notice — brief, not the full parse error.
    The full error is available in JSON output or debug mode.
    """
    finding  = suggestion.finding
    kind_lab = _KIND_LABEL.get(finding.kind, finding.kind.value)

    reason_map = {
        VerificationStatus.REJECTED_PARSE_ERR:  "fix produced invalid C",
        VerificationStatus.REJECTED_BAD_DIFF:   "fix changed function structure",
        VerificationStatus.REJECTED_MAX_RETRY:  "fix failed after retries",
    }
    reason = reason_map.get(suggestion.status, "fix rejected")

    _console.print(
        f"[bold yellow]⚠ No suggestion[/bold yellow] "
        f"[dim]({kind_lab}: {reason})[/dim]"
    )


# ─────────────────────────────────────────────
# JSON SERIALISATION HELPERS
# ─────────────────────────────────────────────

def _finding_to_dict(f: Finding) -> dict:
    return {
        "kind":       f.kind.value,
        "severity":   f.severity.value,
        "file":       f.location.file,
        "line":       f.location.line + 1,   # 1-indexed for consumers
        "col":        f.location.col  + 1,
        "message":    f.message,
        "confidence": f.confidence,
        "detector":   f.detector_id,
        "trace": [
            {
                "file": loc.file,
                "line": loc.line + 1,
                "col":  loc.col  + 1,
            }
            for loc in f.trace
        ],
    }


def _suggestion_to_dict(s: VerifiedSuggestion) -> dict:
    result: dict = {
        "status":   s.status.value,
        "finding":  _finding_to_dict(s.finding),
        "attempts": s.attempts,
    }
    if s.diff:
        result["diff"] = s.diff
    if s.llm_response:
        result["fix_kind"]    = s.llm_response.fix_kind.value
        result["explanation"] = s.llm_response.explanation
        result["confidence"]  = s.llm_response.confidence
    if s.parse_error:
        result["rejection_reason"] = s.parse_error
    return result


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def _truncate_explanation(text: str, max_sentences: int = 2) -> str:
    """
    Truncate an explanation to the first N sentences for terminal display.
    Full explanation is always available in JSON output.
    """
    import re
    # Split on sentence-ending punctuation followed by space or end
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    truncated = " ".join(sentences[:max_sentences])
    if len(sentences) > max_sentences:
        truncated += " …"
    return truncated