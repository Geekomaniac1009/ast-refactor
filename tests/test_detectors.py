from refactor.parser import parse_string, iter_functions
from refactor.cfg import build_cfg
from refactor.pointer_state import analyse
from refactor.models import FindingKind
from refactor.detectors.use_after_free  import UseAfterFreeDetector
from refactor.detectors.double_free     import DoubleFreeDetector
from refactor.detectors.malloc_free     import MallocWithoutFreeDetector
from refactor.detectors.null_deref      import NullDerefDetector
from refactor.detectors.api_misuse      import ApiMisuseDetector

def _run(detector, c_source):
    parsed = parse_string(c_source)
    func   = next(iter_functions(parsed))
    cfg    = build_cfg(func, parsed.source_bytes)
    result = analyse(cfg, parsed.source_bytes)
    return detector.detect(parsed, cfg, result)

def test_use_after_free():
    findings = _run(UseAfterFreeDetector(), """
    void f() { int *p = malloc(8); free(p); *p = 5; }
    """)
    assert any(f.kind == FindingKind.USE_AFTER_FREE for f in findings)

def test_double_free():
    findings = _run(DoubleFreeDetector(), """
    void f() { int *p = malloc(8); free(p); free(p); }
    """)
    assert any(f.kind == FindingKind.DOUBLE_FREE for f in findings)

def test_malloc_no_free_on_one_branch():
    findings = _run(MallocWithoutFreeDetector(), """
    void f(int flag) {
        int *p = malloc(8);
        if (flag) { free(p); }
    }
    """)
    assert any(f.kind == FindingKind.MALLOC_WITHOUT_FREE for f in findings)

def test_null_deref_no_check():
    findings = _run(NullDerefDetector(), """
    void f() { int *p = malloc(8); *p = 5; }
    """)
    assert any(f.kind == FindingKind.NULL_DEREF for f in findings)

def test_null_deref_with_check_is_clean():
    findings = _run(NullDerefDetector(), """
    void f() {
        int *p = malloc(8);
        if (p == NULL) { return; }
        *p = 5;
    }
    """)
    assert not any(f.kind == FindingKind.NULL_DEREF for f in findings)

def test_gets_flagged():
    findings = _run(ApiMisuseDetector(), """
    void f() { char buf[64]; gets(buf); }
    """)
    assert any(f.kind == FindingKind.API_MISUSE for f in findings)