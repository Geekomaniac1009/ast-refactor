from refactor.parser import parse_string, iter_functions
from refactor.cfg import build_cfg
from refactor.pointer_state import analyse
from refactor.models import PointerStatus, FindingKind

def _analyse(c_source):
    parsed = parse_string(c_source)
    func = next(iter_functions(parsed))
    cfg = build_cfg(func, parsed.source_bytes)
    return analyse(cfg, parsed.source_bytes)

def test_malloc_marks_allocated():
    result = _analyse("""
    void f() {
        int *p = malloc(8);
        free(p);
    }
    """)
    assert not result.violations

def test_double_free_detected():
    result = _analyse("""
    void f() {
        int *p = malloc(8);
        free(p);
        free(p);
    }
    """)
    assert any(v.kind == FindingKind.DOUBLE_FREE for v in result.violations)

def test_use_after_free_detected():
    result = _analyse("""
    void f() {
        int *p = malloc(8);
        free(p);
        *p = 5;
    }
    """)
    assert any(v.kind == FindingKind.USE_AFTER_FREE for v in result.violations)

def test_clean_code_no_violations():
    result = _analyse("""
    void f() {
        int *p = malloc(8);
        p[0] = 1;
        free(p);
    }
    """)
    assert result.violations == []