# tests/test_sarif.py
from refactor.sarif import build_sarif, _to_uri, _finding_key
from refactor.models import Finding, FindingKind, Severity, SourceLocation
from pathlib import Path

def _make_finding():
    return Finding(
        kind=FindingKind.DOUBLE_FREE,
        severity=Severity.ERROR,
        location=SourceLocation(file="/repo/src/buf.c", line=10, col=4,
                                end_line=10, end_col=12),
        message="Double-free: 'p'",
        confidence=1.0,
        detector_id="double_free",
    )

def test_sarif_schema_version():
    doc = build_sarif([], [_make_finding()])
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc

def test_sarif_has_one_run():
    doc = build_sarif([], [_make_finding()])
    assert len(doc["runs"]) == 1

def test_sarif_result_rule_id():
    doc = build_sarif([], [_make_finding()])
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "AR002"   # DOUBLE_FREE

def test_sarif_location_is_1indexed():
    doc = build_sarif([], [_make_finding()])
    region = (doc["runs"][0]["results"][0]
              ["locations"][0]["physicalLocation"]["region"])
    assert region["startLine"]   == 11   # 0-indexed 10 → 1-indexed 11
    assert region["startColumn"] == 5

def test_to_uri_relative_path():
    uri = _to_uri("/repo/src/buf.c", base_path=Path("/repo"))
    assert uri == "src/buf.c"

def test_to_uri_no_base_path():
    uri = _to_uri("/repo/src/buf.c", base_path=None)
    assert "buf.c" in uri

def test_sarif_rules_cover_all_kinds():
    from refactor.models import FindingKind
    doc   = build_sarif([], [])
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    # Every FindingKind must have a corresponding rule
    from refactor.sarif import _RULE_ID
    for kind in FindingKind:
        assert _RULE_ID[kind] in rule_ids