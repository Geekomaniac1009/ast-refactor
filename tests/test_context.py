from refactor.parser import parse_string, iter_functions
from refactor.cfg import build_cfg
from refactor.pointer_state import analyse
from refactor.detectors.malloc_free import MallocWithoutFreeDetector
from refactor.context import build_context

def test_context_package_has_prompt():
    src = """
    void f() {
        int *p = malloc(8);
    }
    """
    parsed  = parse_string(src)
    func    = next(iter_functions(parsed))
    cfg     = build_cfg(func, parsed.source_bytes)
    result  = analyse(cfg, parsed.source_bytes)
    findings = MallocWithoutFreeDetector().detect(parsed, cfg, result)

    assert findings, "expected at least one finding"
    pkg = build_context(findings[0], parsed, cfg, result)

    assert pkg.prompt           # non-empty prompt
    assert pkg.subtree_text     # function source extracted
    assert "corrected_code" in pkg.prompt   # schema present in prompt
    assert "HARD CONSTRAINTS"  in pkg.prompt

def test_context_includes_scope_variables():
    src = """
    void f(int n) {
        int *p = malloc(n * sizeof(int));
    }
    """
    parsed  = parse_string(src)
    func    = next(iter_functions(parsed))
    cfg     = build_cfg(func, parsed.source_bytes)
    result  = analyse(cfg, parsed.source_bytes)
    findings = MallocWithoutFreeDetector().detect(parsed, cfg, result)

    assert findings
    pkg = build_context(findings[0], parsed, cfg, result)

    var_names = [sv.name for sv in pkg.scope_variables]
    assert "n" in var_names    # function parameter captured
    assert "p" in var_names    # local pointer captured

def test_state_trace_populated():
    src = """
    void f() {
        int *p = malloc(8);
        free(p);
        *p = 5;
    }
    """
    from refactor.detectors.use_after_free import UseAfterFreeDetector
    parsed  = parse_string(src)
    func    = next(iter_functions(parsed))
    cfg     = build_cfg(func, parsed.source_bytes)
    result  = analyse(cfg, parsed.source_bytes)
    findings = UseAfterFreeDetector().detect(parsed, cfg, result)

    assert findings
    pkg = build_context(findings[0], parsed, cfg, result)
    assert len(pkg.state_trace) >= 1
    assert any("allocated" in t for t in pkg.state_trace)