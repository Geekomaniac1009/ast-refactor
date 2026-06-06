from refactor.parser import parse_string, iter_functions
from refactor.cfg import build_cfg
from refactor.pointer_state import analyse
from refactor.detectors.malloc_free import MallocWithoutFreeDetector
from refactor.models import FixKind, VerificationStatus, LLMResponse
from refactor.verifier import verify

def _make_llm_response(code: str, fix_kind=FixKind.ADD_FREE) -> LLMResponse:
    return LLMResponse(
        fix_kind=fix_kind,
        corrected_code=code,
        explanation="Test fix.",
        confidence=0.9,
        raw_response="{}",
    )

def _get_finding(c_source: str):
    parsed  = parse_string(c_source)
    func    = next(iter_functions(parsed))
    cfg     = build_cfg(func, parsed.source_bytes)
    result  = analyse(cfg, parsed.source_bytes)
    findings = MallocWithoutFreeDetector().detect(parsed, cfg, result)
    return findings[0], parsed

SRC = "void f() { int *p = malloc(8); }"

def test_valid_fix_accepted():
    finding, original = _get_finding(SRC)
    fix = _make_llm_response("void f() { int *p = malloc(8); free(p); }")
    result = verify(finding, fix, original)
    assert result.status == VerificationStatus.ACCEPTED
    assert result.diff is not None
    assert "+free" in result.diff or "+ free" in result.diff

def test_parse_error_rejected():
    finding, original = _get_finding(SRC)
    fix = _make_llm_response("void f( { int *p = malloc(8 free(p); }")
    result = verify(finding, fix, original)
    assert result.status == VerificationStatus.REJECTED_PARSE_ERR
    assert result.parse_error is not None

def test_name_change_rejected():
    finding, original = _get_finding(SRC)
    fix = _make_llm_response("void renamed_f() { int *p = malloc(8); free(p); }")
    result = verify(finding, fix, original)
    assert result.status == VerificationStatus.REJECTED_BAD_DIFF

def test_no_change_rejected():
    finding, original = _get_finding(SRC)
    # Return identical code — no fix applied
    fix = _make_llm_response("void f() { int *p = malloc(8); }")
    result = verify(finding, fix, original)
    assert result.status == VerificationStatus.REJECTED_BAD_DIFF
    assert "identical" in result.parse_error.lower()

def test_accepted_result_has_diff():
    finding, original = _get_finding(SRC)
    fix = _make_llm_response("void f() { int *p = malloc(8); free(p); }")
    result = verify(finding, fix, original)
    assert result.accepted
    assert result.diff
    assert result.attempts == 1