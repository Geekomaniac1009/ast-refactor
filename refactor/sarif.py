"""
refactor/sarif.py
──────────────────
SARIF 2.1.0 output emitter.

SARIF (Static Analysis Results Interchange Format) is the industry-standard
format for static analysis tool output. GitHub Code Scanning ingests SARIF
directly — uploading your results file makes findings appear as annotations
on pull requests and in the Security tab automatically.

Spec reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Consumes: list[VerifiedSuggestion] + tool metadata
Produces: a SARIF 2.1.0 JSON dict (caller writes it to a file)

Why SARIF matters for the portfolio:
  For any future work, a developer reviewing this repo will immediately see that you understand
  how real static analysis tools integrate into CI/CD pipelines. 
  GitHub's code scanning workflow requires only:
    - Upload the .sarif file as an artifact
    - One extra step in the GitHub Actions YAML
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from refactor.models import (
    Finding, FindingKind, Severity,
    VerificationStatus, VerifiedSuggestion,
)


# ─────────────────────────────────────────────
# TOOL METADATA
# ─────────────────────────────────────────────

TOOL_NAME    = "ast-refactor"
TOOL_VERSION = "0.1.0"
TOOL_URI     = "https://github.com/Geekomaniac1009/ast-refactor"
TOOL_INFO_URI = (
    "https://github.com/Geekomaniac1009/ast-refactor/blob/main/README.md"
)

# Maps our internal severity → SARIF level
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.ERROR:   "error",
    Severity.WARNING: "warning",
    Severity.NOTE:    "note",
}

# Maps FindingKind → short rule ID (used as SARIF ruleId)
_RULE_ID: dict[FindingKind, str] = {
    FindingKind.USE_AFTER_FREE:      "AR001",
    FindingKind.DOUBLE_FREE:         "AR002",
    FindingKind.MALLOC_WITHOUT_FREE: "AR003",
    FindingKind.NULL_DEREF:          "AR004",
    FindingKind.BUFFER_OVERRUN:      "AR005",
    FindingKind.INTEGER_OVERFLOW:    "AR006",
    FindingKind.API_MISUSE:          "AR007",
    FindingKind.TAINT_PROPAGATION:   "AR008",
}

_RULE_NAME: dict[FindingKind, str] = {
    FindingKind.USE_AFTER_FREE:      "UseAfterFree",
    FindingKind.DOUBLE_FREE:         "DoubleFree",
    FindingKind.MALLOC_WITHOUT_FREE: "MallocWithoutFree",
    FindingKind.NULL_DEREF:          "NullDereference",
    FindingKind.BUFFER_OVERRUN:      "BufferOverrun",
    FindingKind.INTEGER_OVERFLOW:    "IntegerOverflow",
    FindingKind.API_MISUSE:          "ApiMisuse",
    FindingKind.TAINT_PROPAGATION:   "TaintPropagation",
}

_RULE_DESC: dict[FindingKind, str] = {
    FindingKind.USE_AFTER_FREE: (
        "A pointer is dereferenced after being freed. "
        "This is undefined behaviour and a common source of memory corruption."
    ),
    FindingKind.DOUBLE_FREE: (
        "A pointer is freed more than once. "
        "This corrupts the heap allocator and is exploitable on most platforms."
    ),
    FindingKind.MALLOC_WITHOUT_FREE: (
        "Memory is allocated but not freed on all execution paths. "
        "The pointer exits scope without a corresponding free()."
    ),
    FindingKind.NULL_DEREF: (
        "A pointer returned from an allocation function may be NULL "
        "and is dereferenced without a null check on all paths."
    ),
    FindingKind.BUFFER_OVERRUN: (
        "An array is accessed at an index that may exceed its declared size."
    ),
    FindingKind.INTEGER_OVERFLOW: (
        "An arithmetic expression on narrow integer types is computed before "
        "being assigned to a wider type, causing overflow before widening."
    ),
    FindingKind.API_MISUSE: (
        "A C standard library function is called in a way that violates "
        "its documented contract, causing undefined behaviour or data corruption."
    ),
    FindingKind.TAINT_PROPAGATION: (
        "Data from an external input source reaches a sensitive sink "
        "without sanitisation."
    ),
}


# ─────────────────────────────────────────────
# PUBLIC ENTRYPOINT
# ─────────────────────────────────────────────

def build_sarif(
    suggestions: list[VerifiedSuggestion],
    findings:    list[Finding],
    base_path:   Path | None = None,
) -> dict[str, Any]:
    """
    Build a SARIF 2.1.0 document as a Python dict.
    Caller is responsible for writing it to disk as JSON.

    suggestions: verified suggestions (may include fixes)
    findings:    all findings including those without suggestions
    base_path:   if provided, file URIs are made relative to this path.
                 Pass the repo root for GitHub Code Scanning compatibility.

    The SARIF document structure:
        version
        $schema
        runs[]
            tool
                driver
                    name, version, rules[]
            results[]
                ruleId, level, message, locations[], fixes[]
    """
    rules   = _build_rules()
    results = _build_results(suggestions, findings, base_path)

    return {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            TOOL_NAME,
                        "version":         TOOL_VERSION,
                        "informationUri":  TOOL_INFO_URI,
                        "rules":           rules,
                    }
                },
                "results":          results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def write_sarif(
    output_path: Path,
    suggestions: list[VerifiedSuggestion],
    findings:    list[Finding],
    base_path:   Path | None = None,
) -> None:
    """
    Build and write the SARIF document to a file.
    Creates parent directories if needed.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = build_sarif(suggestions, findings, base_path)
    output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────
# RULES
# ─────────────────────────────────────────────

def _build_rules() -> list[dict[str, Any]]:
    """
    Build the SARIF rules array — one entry per FindingKind.
    Rules are declared at the tool level so SARIF consumers (GitHub,
    VS Code SARIF viewer) can display rule metadata alongside results.
    """
    rules = []
    for kind in FindingKind:
        rule_id   = _RULE_ID.get(kind, kind.value)
        rule_name = _RULE_NAME.get(kind, kind.value)
        rule_desc = _RULE_DESC.get(kind, "")
        severity  = _default_severity_for_kind(kind)

        rules.append({
            "id":   rule_id,
            "name": rule_name,
            "shortDescription": {
                "text": rule_name
            },
            "fullDescription": {
                "text": rule_desc
            },
            "defaultConfiguration": {
                "level": _SARIF_LEVEL.get(severity, "warning")
            },
            "helpUri": f"{TOOL_URI}/blob/main/docs/rules/{rule_id}.md",
            "properties": {
                "tags": ["security", "correctness", "c"],
            },
        })
    return rules


# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────

def _build_results(
    suggestions: list[VerifiedSuggestion],
    findings:    list[Finding],
    base_path:   Path | None,
) -> list[dict[str, Any]]:
    """
    Build the SARIF results array.
    Each Finding becomes one SARIF result.
    Accepted suggestions are attached as SARIF fixes.

    We merge findings and suggestions: for each finding, look up
    whether there's an accepted suggestion for it, and attach the fix.
    """
    # Map finding location → accepted suggestion for fast lookup
    accepted_map: dict[tuple, VerifiedSuggestion] = {}
    for s in suggestions:
        if s.accepted:
            key = _finding_key(s.finding)
            accepted_map[key] = s

    results = []
    for finding in findings:
        result = _build_result(finding, base_path)

        # Attach fix if available
        suggestion = accepted_map.get(_finding_key(finding))
        if suggestion and suggestion.diff:
            fix = _build_fix(suggestion, base_path)
            if fix:
                result["fixes"] = [fix]

        results.append(result)

    return results


def _build_result(finding: Finding, base_path: Path | None) -> dict[str, Any]:
    """Build a single SARIF result object from a Finding."""
    rule_id = _RULE_ID.get(finding.kind, finding.kind.value)
    level   = _SARIF_LEVEL.get(finding.severity, "warning")

    result: dict[str, Any] = {
        "ruleId":  rule_id,
        "level":   level,
        "message": {
            "text": finding.message
        },
        "locations": [
            _build_location(finding.location, base_path)
        ],
        "properties": {
            "confidence": finding.confidence,
            "detectorId": finding.detector_id,
        },
    }

    # Add related locations from the trace (excluding primary location)
    related = [
        {
            "message":           {"text": f"Trace location {i + 1}"},
            "physicalLocation":  _build_physical_location(loc, base_path),
        }
        for i, loc in enumerate(finding.trace)
        if loc != finding.location
    ]
    if related:
        result["relatedLocations"] = related

    return result


def _build_fix(
    suggestion: VerifiedSuggestion,
    base_path:  Path | None,
) -> dict[str, Any] | None:
    """
    Build a SARIF fix object from an accepted suggestion.

    SARIF fixes contain artifactChanges — a list of file edits.
    We represent our fix as a replacement of the entire flagged function
    with the corrected version. This is necessarily coarse — SARIF's
    fix model works best with precise character-offset replacements,
    which would require tracking exact byte positions of the original
    function in the file.

    For now we attach the fix description and corrected code as a
    replacement on the finding location. GitHub displays this as a
    suggested change on the PR annotation.
    """
    if not suggestion.llm_response:
        return None

    finding      = suggestion.finding
    corrected    = suggestion.llm_response.corrected_code
    explanation  = suggestion.llm_response.explanation

    file_uri = _to_uri(finding.location.file, base_path)

    return {
        "description": {
            "text": (
                f"{explanation[:200]}…"
                if len(explanation) > 200
                else explanation
            )
        },
        "artifactChanges": [
            {
                "artifactLocation": {"uri": file_uri},
                "replacements": [
                    {
                        "deletedRegion": {
                            "startLine":   finding.location.line + 1,
                            "startColumn": finding.location.col  + 1,
                            "endLine":     finding.location.end_line + 1,
                            "endColumn":   finding.location.end_col  + 1,
                        },
                        "insertedContent": {
                            "text": corrected
                        },
                    }
                ],
            }
        ],
    }


# ─────────────────────────────────────────────
# LOCATION HELPERS
# ─────────────────────────────────────────────

def _build_location(loc, base_path: Path | None) -> dict[str, Any]:
    return {"physicalLocation": _build_physical_location(loc, base_path)}


def _build_physical_location(loc, base_path: Path | None) -> dict[str, Any]:
    return {
        "artifactLocation": {
            "uri":       _to_uri(loc.file, base_path),
            "uriBaseId": "%SRCROOT%",
        },
        "region": {
            "startLine":   loc.line    + 1,
            "startColumn": loc.col     + 1,
            "endLine":     loc.end_line + 1,
            "endColumn":   loc.end_col  + 1,
        },
    }


def _to_uri(file_path: str, base_path: Path | None) -> str:
    """
    Convert a file path string to a URI suitable for SARIF.
    If base_path is provided, make the path relative to it.
    GitHub Code Scanning requires relative URIs from the repo root.
    """
    if not file_path:
        return "unknown"
    p = Path(file_path)
    if base_path is not None:
        try:
            p = p.relative_to(base_path)
        except ValueError:
            pass  # path outside base — use as-is
    # SARIF URIs use forward slashes even on Windows
    return str(p).replace("\\", "/")


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def _finding_key(finding: Finding) -> tuple:
    """Stable key for matching findings to suggestions."""
    return (
        finding.kind,
        finding.location.file,
        finding.location.line,
        finding.location.col,
    )


def _default_severity_for_kind(kind: FindingKind) -> Severity:
    """Default severity when no Finding instance is available (for rule metadata)."""
    error_kinds = {
        FindingKind.USE_AFTER_FREE,
        FindingKind.DOUBLE_FREE,
        FindingKind.NULL_DEREF,
    }
    return Severity.ERROR if kind in error_kinds else Severity.WARNING