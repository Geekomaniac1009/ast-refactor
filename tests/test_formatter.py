import io

from rich.console import Console

# tests/test_formatter.py
from refactor.formatter import _finding_to_dict, _truncate_explanation
from refactor import formatter
from refactor.models import Finding, FindingKind, Severity, SourceLocation

def _make_finding():
    return Finding(
        kind=FindingKind.USE_AFTER_FREE,
        severity=Severity.ERROR,
        location=SourceLocation(file="test.c", line=4, col=4,
                                end_line=4, end_col=10),
        message="Use-after-free: 'p'",
        confidence=1.0,
        detector_id="use_after_free",
    )

def test_finding_to_dict_1indexed():
    d = _finding_to_dict(_make_finding())
    assert d["line"] == 5   # 0-indexed line 4 → 1-indexed 5
    assert d["col"]  == 5

def test_finding_to_dict_fields():
    d = _finding_to_dict(_make_finding())
    assert d["kind"]     == "use_after_free"
    assert d["severity"] == "error"
    assert d["file"]     == "test.c"

def test_truncate_explanation_two_sentences():
    text = "First sentence. Second sentence. Third sentence."
    result = _truncate_explanation(text, max_sentences=2)
    assert "First" in result
    assert "Second" in result
    assert "Third" not in result
    assert result.endswith("…")

def test_truncate_explanation_no_truncation_needed():
    text = "Only one sentence."
    result = _truncate_explanation(text, max_sentences=2)
    assert result == text
    assert "…" not in result


def test_configure_output_disables_ansi_escape_codes():
    buffer = io.StringIO()
    original_err_console = formatter._err_console
    original_no_colour = formatter._no_colour

    try:
        formatter._no_colour = False
        formatter._err_console = Console(
            file=buffer,
            force_terminal=True,
            highlight=False,
        )
        formatter.print_error("boom")
        assert "\x1b[" in buffer.getvalue()

        buffer.seek(0)
        buffer.truncate(0)

        formatter._err_console = Console(
            file=buffer,
            force_terminal=True,
            highlight=False,
            no_color=True,
        )
        formatter._no_colour = True
        formatter.print_error("boom")
        assert "\x1b[" not in buffer.getvalue()
    finally:
        formatter._err_console = original_err_console
        formatter._no_colour = original_no_colour