"""
eval/runner.py
───────────────
Runs all three systems on every fixture and collects structured results.

Systems:
  AstRefactorRunner   — your tool: parser → CFG → detectors → LLM → verifier
  ClangTidyRunner     — clang-tidy via subprocess, output parsed into findings
  CopilotRunner       — reads pre-collected Copilot outputs from fixture metadata
                        (no live API calls — see eval/README.md for collection
                        instructions)

Design decision: runners are stateless classes with a single run() method.
Each takes a FixtureMetadata + .c source text and returns a RunResult.
This makes them independently testable and swappable — if you add a
fourth system (e.g. CodeQL), you add a fourth Runner subclass.

Design decision: CopilotRunner reads pre-collected outputs rather than
calling the API live. Live Copilot API calls at eval scale would cost
real money, require GitHub Copilot API access, and make the eval
non-reproducible (model updates change outputs). Pre-collecting on 20
representative fixtures and storing outputs in fixture JSON is the honest
approach — it's labelled clearly in the report as "n=20, manual collection".

Design decision: each RunResult stores the raw tool output alongside
the parsed finding, so failures can be diagnosed without re-running.
The raw field is the source of truth; the parsed fields are derived.
If parsing logic has a bug, you can re-derive without re-running tools.
"""

from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from eval.fixture_schema import ExpectedFinding, FixtureMetadata
from refactor.models import Finding, FindingKind, VerificationStatus, VerifiedSuggestion


# ─────────────────────────────────────────────
# RESULT TYPES
# ─────────────────────────────────────────────

@dataclass
class DetectionResult:
    """
    Whether a system found the expected finding on a fixture.

    found:           True if a finding matching expected kind was reported
    reported_line:   the line the system reported (may differ from expected)
    line_delta:      abs(reported_line - expected_line), None if not found
                     We allow ±3 lines tolerance because different tools
                     report different nodes for the same bug (e.g. clang-tidy
                     may report the malloc call while we report the return).
    false_positives: number of additional findings reported beyond the expected
    raw_output:      the tool's raw text output, for debugging
    """
    found:           bool
    reported_line:   Optional[int]   = None
    line_delta:      Optional[int]   = None
    false_positives: int             = 0
    raw_output:      str             = ""

    LINE_TOLERANCE = 3   # lines either side counts as a match

    @classmethod
    def match(cls, reported: int, expected: int, fp_count: int, raw: str) -> DetectionResult:
        delta = abs(reported - expected)
        return cls(
            found           = delta <= cls.LINE_TOLERANCE,
            reported_line   = reported,
            line_delta      = delta,
            false_positives = fp_count,
            raw_output      = raw,
        )

    @classmethod
    def miss(cls, fp_count: int = 0, raw: str = "") -> DetectionResult:
        return cls(found=False, false_positives=fp_count, raw_output=raw)


@dataclass
class FixResult:
    """
    Whether a system produced a valid, correct fix.

    attempted:       True if the system attempted to produce a fix
    valid:           True if the fix re-parsed and compiled without errors
    correct:         True if re-running the detector on the fix produces no finding
    raw_fix:         the raw fix text the system produced
    parse_error:     populated if valid=False due to a parse/compile error
    attempts:        how many LLM calls were needed (ast-refactor only)
    """
    attempted:   bool
    valid:       bool               = False
    correct:     bool               = False
    raw_fix:     Optional[str]      = None
    parse_error: Optional[str]      = None
    attempts:    int                = 0


@dataclass
class RunResult:
    """
    Complete result of running one system on one fixture.

    system:      "ast_refactor" | "clang_tidy" | "copilot"
    fixture:     the fixture name
    elapsed_ms:  wall-clock time for this run in milliseconds
    detection:   whether the system found the expected finding
    fix:         whether the system produced a valid/correct fix
    error:       populated if the system crashed or errored
    """
    system:     str
    fixture:    str
    elapsed_ms: float
    detection:  DetectionResult
    fix:        FixResult
    error:      Optional[str]   = None


# ─────────────────────────────────────────────
# ABSTRACT BASE
# ─────────────────────────────────────────────

class Runner(ABC):
    """Base class for all system runners."""

    @property
    @abstractmethod
    def system_name(self) -> str: ...

    @abstractmethod
    def run(self, meta: FixtureMetadata, source: str) -> RunResult: ...

    def _make_error_result(self, meta: FixtureMetadata, error: str, elapsed_ms: float) -> RunResult:
        return RunResult(
            system     = self.system_name,
            fixture    = meta.name,
            elapsed_ms = elapsed_ms,
            detection  = DetectionResult.miss(raw=error),
            fix        = FixResult(attempted=False),
            error      = error,
        )


# ─────────────────────────────────────────────
# AST-REFACTOR RUNNER
# ─────────────────────────────────────────────

class AstRefactorRunner(Runner):
    """
    Runs the full ast-refactor pipeline on a fixture.
    Calls parser → CFG → pointer_state → detectors → context → LLM → verifier.

    llm_enabled: if False, only runs detection (no LLM calls).
                 Use this for fast iteration on precision/recall metrics
                 without burning API tokens.
    """

    system_name = "ast_refactor"

    def __init__(self, llm_enabled: bool = True) -> None:
        self.llm_enabled = llm_enabled

    def run(self, meta: FixtureMetadata, source: str) -> RunResult:
        start = time.monotonic()
        try:
            return self._run_inner(meta, source)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return self._make_error_result(meta, str(exc), elapsed)

    def _run_inner(self, meta: FixtureMetadata, source: str) -> RunResult:
        from refactor.parser import parse_string, iter_functions
        from refactor.cfg import build_cfg
        from refactor.pointer_state import analyse
        from refactor.detectors.base import DetectorRegistry

        start = time.monotonic()

        parsed   = parse_string(source)
        registry = DetectorRegistry.default()

        all_findings: list[Finding] = []
        for func_node in iter_functions(parsed):
            cfg    = build_cfg(func_node, parsed.source_bytes)
            result = analyse(cfg, parsed.source_bytes)
            for detector in registry:
                all_findings.extend(detector.detect(parsed, cfg, result))

        # Find the finding that matches the expected kind
        expected = meta.expected
        matching = [
            f for f in all_findings
            if f.kind.value == expected.kind
        ]
        other    = [
            f for f in all_findings
            if f.kind.value != expected.kind
        ]

        if not matching:
            elapsed = (time.monotonic() - start) * 1000
            return RunResult(
                system     = self.system_name,
                fixture    = meta.name,
                elapsed_ms = elapsed,
                detection  = DetectionResult.miss(
                    fp_count = len(other),
                    raw      = f"{len(all_findings)} total findings, none matched {expected.kind}",
                ),
                fix = FixResult(attempted=False),
            )

        # Take the highest-confidence matching finding
        best = max(matching, key=lambda f: f.confidence)
        detection = DetectionResult.match(
            reported = best.location.line + 1,  # convert to 1-indexed
            expected = expected.line,
            fp_count = len(other),
            raw      = f"confidence={best.confidence:.2f}",
        )

        # Fix generation
        fix_result = FixResult(attempted=False)
        if self.llm_enabled and detection.found:
            fix_result = self._generate_fix(best, parsed, meta)

        elapsed = (time.monotonic() - start) * 1000
        return RunResult(
            system     = self.system_name,
            fixture    = meta.name,
            elapsed_ms = elapsed,
            detection  = detection,
            fix        = fix_result,
        )

    def _generate_fix(
        self,
        finding: Finding,
        parsed,
        meta: FixtureMetadata,
    ) -> FixResult:
        """
        Generate and verify a fix, then check correctness against the
        correct_fix in the fixture metadata using functional re-detection.
        """
        from refactor.parser import iter_functions
        from refactor.cfg import build_cfg
        from refactor.pointer_state import analyse
        from refactor.context import build_context
        from refactor import llm_client
        from refactor.verifier import verify

        # Find the CFG for the function containing this finding
        cfg = None
        for func_node in iter_functions(parsed):
            if (func_node.start_point[0] <= finding.location.line
                    <= func_node.end_point[0]):
                cfg = build_cfg(func_node, parsed.source_bytes)
                break

        if cfg is None:
            return FixResult(attempted=True, parse_error="Could not find enclosing function")

        result  = analyse(cfg, parsed.source_bytes)
        package = build_context(finding, parsed, cfg, result)

        llm_response = llm_client.call(package)
        if llm_response is None:
            return FixResult(attempted=True, parse_error="LLM call returned None")

        suggestion = verify(finding, llm_response, parsed, attempt=1)

        if not suggestion.accepted:
            return FixResult(
                attempted   = True,
                valid       = False,
                raw_fix     = llm_response.corrected_code,
                parse_error = suggestion.parse_error,
                attempts    = suggestion.attempts,
            )

        # Validity confirmed. Now check correctness:
        # re-run the detector on the corrected function.
        correct = self._check_fix_correctness(
            llm_response.corrected_code,
            finding.kind,
        )

        return FixResult(
            attempted = True,
            valid     = True,
            correct   = correct,
            raw_fix   = llm_response.corrected_code,
            attempts  = suggestion.attempts,
        )

    def _check_fix_correctness(self, corrected_code: str, kind: FindingKind) -> bool:
        """
        Re-run detection on the corrected function.
        If no finding of the same kind is produced, the fix is correct.

        Design decision: functional correctness check, not textual diff.
        We don't compare against correct_fix text because there may be
        multiple valid fixes for the same bug. If the detector no longer
        fires, the bug is fixed — that's the definition that matters.
        """
        from refactor.parser import parse_string, iter_functions
        from refactor.cfg import build_cfg
        from refactor.pointer_state import analyse
        from refactor.detectors.base import DetectorRegistry

        try:
            parsed   = parse_string(corrected_code)
            registry = DetectorRegistry.default()
            for func_node in iter_functions(parsed):
                cfg    = build_cfg(func_node, parsed.source_bytes)
                result = analyse(cfg, parsed.source_bytes)
                for detector in registry:
                    for f in detector.detect(parsed, cfg, result):
                        if f.kind == kind:
                            return False  # still finding the same bug
            return True
        except Exception:
            return False  # parse failure means we can't confirm correctness


# ─────────────────────────────────────────────
# CLANG-TIDY RUNNER
# ─────────────────────────────────────────────

class ClangTidyRunner(Runner):
    """
    Runs clang-tidy on a fixture via subprocess.

    clang-tidy is invoked with clang-analyzer-* checks enabled.
    These are the checks that correspond to our detector set:
      clang-analyzer-unix.Malloc        → malloc_without_free, use_after_free
      clang-analyzer-unix.MallocSizeof  → integer_overflow in allocation
      clang-analyzer-alpha.security.*   → various safety checks

    Design decision: we write the fixture to a temp file and invoke
    clang-tidy directly rather than using a compile database. This means
    clang-tidy runs without full type information — some checks are disabled
    or less precise without a compile DB. We document this in the report.
    The tradeoff is that our tool also runs without compilation, so the
    comparison is fair: both tools operate on raw source.

    Design decision: clang-tidy does not produce fixes for memory safety
    checks (only for style checks). FixResult is always attempted=False.
    This is accurately reflected in the comparison table as N/A for fix
    metrics, not as a failure.
    """

    system_name = "clang_tidy"

    # Maps clang-tidy warning category strings to our FindingKind values
    _KIND_MAP: dict[str, str] = {
        "unix.Malloc":             "malloc_without_free",
        "unix.MallocSizeof":       "integer_overflow",
        "cplusplus.NewDeleteLeaks":"malloc_without_free",
        "core.NullDereference":    "null_deref",
        "alpha.security.ArrayBound": "buffer_overrun",
        "security.insecureAPI":    "api_misuse",
    }

    def run(self, meta: FixtureMetadata, source: str) -> RunResult:
        import tempfile, os
        start = time.monotonic()

        try:
            # Write fixture to a temp .c file
            with tempfile.NamedTemporaryFile(
                suffix=".c", mode="w", delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(source)
                tmp_path = tmp.name

            result = self._invoke_clang_tidy(tmp_path)
            elapsed = (time.monotonic() - start) * 1000

            findings = self._parse_output(result.stdout + result.stderr)
            expected = meta.expected

            # Find findings matching expected kind
            matching = [
                f for f in findings
                if f["kind"] == expected.kind
            ]
            other = [
                f for f in findings
                if f["kind"] != expected.kind
            ]

            if not matching:
                return RunResult(
                    system     = self.system_name,
                    fixture    = meta.name,
                    elapsed_ms = elapsed,
                    detection  = DetectionResult.miss(
                        fp_count = len(other),
                        raw      = result.stdout + result.stderr,
                    ),
                    fix = FixResult(attempted=False),
                )

            best = min(matching, key=lambda f: abs(f["line"] - expected.line))
            return RunResult(
                system     = self.system_name,
                fixture    = meta.name,
                elapsed_ms = elapsed,
                detection  = DetectionResult.match(
                    reported = best["line"],
                    expected = expected.line,
                    fp_count = len(other),
                    raw      = result.stdout + result.stderr,
                ),
                fix = FixResult(attempted=False),  # clang-tidy never fixes memory bugs
            )

        except FileNotFoundError:
            elapsed = (time.monotonic() - start) * 1000
            return self._make_error_result(
                meta, "clang-tidy not found — install with: sudo apt install clang-tidy", elapsed
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            return self._make_error_result(meta, str(exc), elapsed)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _invoke_clang_tidy(self, path: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "clang-tidy",
                path,
                "--checks=clang-analyzer-*",
                "--",            # end of clang-tidy options; start of compiler options
                "-std=c11",
                "-w",            # suppress compiler warnings (not clang-tidy warnings)
            ],
            capture_output = True,
            text           = True,
            timeout        = 30,
        )

    def _parse_output(self, output: str) -> list[dict]:
        """
        Parse clang-tidy output lines into structured findings.
        Output format: path:line:col: warning: message [check-name]
        Example:
            /tmp/abc.c:14:5: warning: memory leak [clang-analyzer-unix.Malloc]
        """
        import re
        findings = []
        pattern  = re.compile(
            r".+:(\d+):\d+:\s+(?:warning|error):\s+.+\[clang-analyzer-([^\]]+)\]"
        )
        for line in output.splitlines():
            m = pattern.match(line)
            if not m:
                continue
            lineno    = int(m.group(1))
            check_key = m.group(2)  # e.g. "unix.Malloc"
            kind      = self._KIND_MAP.get(check_key, "unknown")
            if kind != "unknown":
                findings.append({"line": lineno, "kind": kind, "raw": line})
        return findings


# ─────────────────────────────────────────────
# COPILOT RUNNER
# ─────────────────────────────────────────────

class CopilotRunner(Runner):
    """
    Reads pre-collected Copilot outputs from fixture metadata.

    Copilot outputs must be collected manually:
      1. Open each fixture .c file in VS Code with Copilot enabled
      2. Use the chat prompt: "This C function has a memory safety bug.
         Fix it and return only the corrected function, no explanation."
      3. Copy the raw response into the fixture's JSON under "copilot_output"

    This runner then:
      - Checks if copilot_output is non-empty (detection proxy: Copilot
        produced a fix, implying it detected a problem)
      - Runs the corrected code through tree-sitter (fix validity)
      - Re-runs the detector on the corrected code (fix correctness)

    Design decision: we use fix production as a detection proxy for Copilot.
    Copilot doesn't emit structured findings with line numbers — it produces
    natural language + code. If it produced a fix, we treat that as "detected".
    This is conservative: Copilot may produce a fix that doesn't address
    the actual bug. The correctness check catches that case.

    Design decision: fixtures without copilot_output are skipped for the
    Copilot comparison, not counted as misses. The report labels this
    subset explicitly: "Copilot comparison: n=<collected>, subset of full
    benchmark." This is honest — skipping is not the same as missing.
    """

    system_name = "copilot"

    def run(self, meta: FixtureMetadata, source: str) -> RunResult:
        start = time.monotonic()

        if not meta.copilot_output:
            elapsed = (time.monotonic() - start) * 1000
            # Not a miss — just not collected. Caller filters these out.
            return RunResult(
                system     = self.system_name,
                fixture    = meta.name,
                elapsed_ms = elapsed,
                detection  = DetectionResult.miss(raw="copilot_output not collected"),
                fix        = FixResult(attempted=False),
                error      = "not_collected",
            )

        elapsed_ms = (time.monotonic() - start) * 1000
        fix_result = self._evaluate_fix(meta.copilot_output, meta.expected)

        # Detection proxy: Copilot produced a non-trivial response
        copilot_detected = (
            len(meta.copilot_output.strip()) > 20
            and "error" not in meta.copilot_output.lower()[:50]
        )

        detection = DetectionResult(
            found           = copilot_detected,
            reported_line   = None,   # Copilot doesn't give line numbers
            line_delta      = None,
            false_positives = 0,      # can't measure FP rate for Copilot
            raw_output      = meta.copilot_output[:500],
        )

        return RunResult(
            system     = self.system_name,
            fixture    = meta.name,
            elapsed_ms = elapsed_ms,
            detection  = detection,
            fix        = fix_result,
        )

    def _evaluate_fix(self, copilot_output: str, expected: ExpectedFinding) -> FixResult:
        """
        Extract the corrected function from Copilot output and evaluate it.
        Copilot often wraps code in markdown fences — strip them first.
        """
        from refactor.parser import parse_string
        import re

        # Strip markdown fences
        code = re.sub(r"^```[a-z]*\n?", "", copilot_output.strip(), flags=re.MULTILINE)
        code = re.sub(r"\n?```$",       "", code,                   flags=re.MULTILINE)
        code = code.strip()

        if not code:
            return FixResult(attempted=True, parse_error="Empty after stripping fences")

        # Validity: can tree-sitter parse it?
        try:
            parsed = parse_string(code)
            if parsed.has_errors:
                return FixResult(
                    attempted   = True,
                    valid       = False,
                    raw_fix     = code,
                    parse_error = f"{len(parsed.error_nodes)} parse error(s)",
                )
        except Exception as exc:
            return FixResult(attempted=True, valid=False, raw_fix=code, parse_error=str(exc))

        # Correctness: re-run detector on corrected code
        correct = self._check_fix_correctness(code, expected)
        return FixResult(attempted=True, valid=True, correct=correct, raw_fix=code)

    def _check_fix_correctness(self, code: str, expected: ExpectedFinding) -> bool:
        from refactor.parser import parse_string, iter_functions
        from refactor.cfg import build_cfg
        from refactor.pointer_state import analyse
        from refactor.detectors.base import DetectorRegistry
        from refactor.models import FindingKind

        try:
            kind     = FindingKind(expected.kind)
            parsed   = parse_string(code)
            registry = DetectorRegistry.default()
            for func_node in iter_functions(parsed):
                cfg    = build_cfg(func_node, parsed.source_bytes)
                result = analyse(cfg, parsed.source_bytes)
                for detector in registry:
                    for f in detector.detect(parsed, cfg, result):
                        if f.kind == kind:
                            return False
            return True
        except Exception:
            return False