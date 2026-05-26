from refactor.parser import parse_string, get_function_name, node_text, iter_functions

SIMPLE_C = """
int add(int a, int b) {
    return a + b;
}

int *alloc_buf(int n) {
    return malloc(n * sizeof(int));
}
"""

def test_parses_without_errors():
    parsed = parse_string(SIMPLE_C)
    assert not parsed.has_errors

def test_finds_two_functions():
    parsed = parse_string(SIMPLE_C)
    fns = list(iter_functions(parsed))
    assert len(fns) == 2

def test_extracts_function_names():
    parsed = parse_string(SIMPLE_C)
    fns = list(iter_functions(parsed))
    names = [get_function_name(f, parsed.source_bytes) for f in fns]
    assert "add" in names
    assert "alloc_buf" in names   # pointer-returning — tests the pointer_declarator path

def test_node_text_roundtrip():
    parsed = parse_string("int x = 5;")
    # root → declaration → should be able to get text back
    decl = parsed.root.children[0]
    assert "int" in node_text(decl, parsed.source_bytes)