from refactor.parser import parse_string, iter_functions
from refactor.cfg import build_cfg, all_paths

def _first_function_cfg(c_source: str):
    parsed = parse_string(c_source)
    func = next(iter_functions(parsed))
    return build_cfg(func, parsed.source_bytes)

def test_linear_function_has_two_paths():
    # entry → single block → exit: exactly 1 path
    cfg = _first_function_cfg("int add(int a, int b) { return a + b; }")
    paths = all_paths(cfg)
    assert len(paths) == 1

def test_if_else_has_two_paths():
    src = """
    int abs(int x) {
        if (x < 0) { return -x; }
        else { return x; }
    }
    """
    cfg = _first_function_cfg(src)
    paths = all_paths(cfg)
    assert len(paths) == 2

def test_if_without_else_has_two_paths():
    src = """
    void maybe_free(int *p, int flag) {
        if (flag) { free(p); }
    }
    """
    cfg = _first_function_cfg(src)
    assert len(all_paths(cfg)) == 2

def test_while_loop_has_two_paths():
    # Loop body executes or is skipped: 2 paths (enter loop / skip loop)
    src = """
    void count(int n) {
        int i = 0;
        while (i < n) { i++; }
    }
    """
    cfg = _first_function_cfg(src)
    assert len(all_paths(cfg)) == 2

def test_entry_and_exit_blocks_exist():
    cfg = _first_function_cfg("void noop(void) {}")
    assert cfg.nodes[cfg.entry_id].is_entry
    assert cfg.nodes[cfg.exit_id].is_exit