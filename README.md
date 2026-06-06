# ast-refactor

**AST-grounded static analysis with LLM-verified fixes for C memory safety.**

A production-oriented security scanner for C code that combines lightweight static analysis with LLM-powered code review. Detects memory safety bugs, suggests fixes, and *verifies* them before showing results to the user.

## 🎯 Problem Scope

Memory safety vulnerabilities account for the majority of security incidents in C/C++ codebases. Traditional static analyzers suffer from:

- **False positives** causing alert fatigue
- **Opaque detection logic** that developers don't trust
- **No actionable fix suggestions** — developers are left guessing how to remediate
- **Fixed rule sets** that miss nuanced bugs requiring domain knowledge

Modern LLM-based approaches solve some of these problems but introduce new risks:

- **Hallucinated fixes** that don't compile or change function signatures
- **No verifiability** — you have to manually review and test every suggestion
- **Expensive API calls** on every file change

**ast-refactor** bridges this gap with a hybrid approach: deterministic detection + LLM refinement + automatic verification.

## ✨ Solution Overview

```
SOURCE CODE
    ↓
[PARSER] (tree-sitter) → Abstract Syntax Tree
    ↓
[CFG BUILDER] → Control Flow Graph (intraprocedural)
    ↓
[POINTER STATE ANALYSIS] → Track allocation/free/use across paths
    ↓
[DETECTORS] → Pattern matching on CFG + dataflow
    ↓
[FINDINGS] (deterministic, zero false negatives on pattern)
    ↓
[LLM CONTEXT BUILDER] → Minimal structured prompt
    ↓
[LLM CLIENT] → Call configured LLM (OpenRouter/OpenAI/Anthropic)
    ↓
[VERIFIER] → Re-parse suggestion, verify signature, check diff
    ↓
[VERIFIED SUGGESTIONS] (unparseable/dangerous fixes rejected)
    ↓
[FORMATTER] → Pretty terminal output, JSON, SARIF
```

**Key architectural insight:** Each stage is a thin, testable layer. You can:
- Run just detection for fast CI (`refactor check`)
- Add LLM suggestions with verification (`refactor fix`)
- Export to GitHub Code Scanning via SARIF (`refactor sarif`)
- Get teaching explanations of vulnerabilities (`refactor explain`)

## 🔍 Detectors

| Detector | Kind | Severity | Pattern |
|----------|------|----------|---------|
| **use-after-free** | Memory Safety | ERROR | Pointer dereferenced after `free()` |
| **double-free** | Memory Safety | ERROR | `free()` called twice on same pointer |
| **memory-leak** | Resource | WARNING | `malloc()`/`calloc()` without matching `free()` |
| **null-deref** | Safety | ERROR | Dereference of pointer known to be NULL |
| **buffer-overrun** | Memory Safety | WARNING | Fixed-size array access out of bounds |
| **integer-overflow** | Arithmetic | WARNING | Integer multiplication/addition may overflow |
| **api-misuse** | Contract | WARNING | Violation of C stdlib function contracts (e.g., `strtok()` on string literal) |

Each detector is:
- **Deterministic** — uses pattern matching on AST/CFG
- **Conservative** — may miss complex cases, never invents false positives
- **LLM-grounded** — LLM suggests the fix, detector provides the facts
- **Traceable** — findings include source locations of allocation, free, use

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Geekomaniac1009/ast-refactor
cd ast-refactor
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the repo root:

```bash
# Choose a provider: openrouter (free tier), openai, or anthropic
LLM_PROVIDER=openrouter
LLM_MODEL=openrouter/free
LLM_API_KEY=your_api_key_here

# (Optional) For local/self-hosted LLM endpoints:
# LLM_BASE_URL=https://your-provider.example/v1
```

**Free tier options:**
- **OpenRouter** (`openrouter/free`): Free tier with rate limits
- **Anthropic Claude** (if you have credits)
- **OpenAI GPT-4o-mini** (cheap but not free)

### Usage

```bash
# 1. Fast analysis — no LLM calls, just detection
python cli.py check src/buffer.c
python cli.py check src/ --recursive

# 2. Suggest fixes with verification
python cli.py fix src/buffer.c
python cli.py fix src/ --recursive --max-fixes 5

# 3. Explain a specific finding
python cli.py explain src/buffer.c --line 42

# 4. Export for GitHub Code Scanning
python cli.py sarif src/ --output findings.sarif
```

### Global Flags

```bash
--severity error|warning|note    # Filter by minimum severity
--detector detector_id           # Run only one detector
--json                           # Machine-readable JSON output
--no-colour                      # Plain text (for CI/logging)
```

## 📊 Example Output

### Check subcommand (deterministic, fast)

```bash
$ python cli.py check examples/buffer_overflow.c
```

```
examples/buffer_overflow.c:15:5: error [buffer-overrun] Buffer overflow on fixed-size array 'buf'
examples/buffer_overflow.c:18:2: warning [use-after-free] Use-after-free: 'ptr' dereferenced after free()

Found 2 issues (1 error, 1 warning) in 0.12s
```

### Fix subcommand (with LLM suggestions and verification)

```bash
$ python cli.py fix examples/buffer_overflow.c
```

```
[FINDINGS]
examples/buffer_overflow.c:18:2: warning [use-after-free] Use-after-free: 'ptr' is dereferenced after being freed.

[SUGGESTED FIX] ✓ Verified
Reparse check: PASSED
Signature check: PASSED
─────────────────────────────────────────
--- examples/buffer_overflow.c (original)
+++ examples/buffer_overflow.c (fixed)
@@ -16,6 +16,7 @@
     free(ptr);
-    printf("%s\n", ptr);
+    ptr = NULL;
+    if (ptr != NULL) printf("%s\n", ptr);
─────────────────────────────────────────

LLM tokens used: 142 input, 89 output
Completed in 2.34s
```

### Explain subcommand (teaching mode)

```bash
$ python cli.py explain examples/buffer_overflow.c --line 18
```

```
[TEACHING EXPLANATION]
────────────────────────────────────────
What's wrong:
  After free(ptr) is called at line 16, 'ptr' still holds the address of
  the now-deallocated memory. When printf tries to dereference it at line 18,
  it's reading from invalid memory.

Why it's dangerous:
  - On some systems, the memory is reused immediately, so you read garbage
  - An attacker can control what's in that freed memory, leading to info leak
  - The OS may detect the access and crash the program (SIGSEGV)

How the fix prevents it:
  By setting ptr = NULL after free() and checking before use, we ensure
  any subsequent access is a null-pointer dereference (which is at least
  caught by a debugger or memory sanitizer).

[SUGGESTED FIX]
```

## 🏗️ Architecture Highlights

### 1. **Parser** (`refactor/parser.py`)
- Uses **tree-sitter-c** for robust, incremental parsing
- Caches parsed ASTs
- Exposes iterators for functions, variable declarations

### 2. **Control Flow Graph** (`refactor/cfg.py`)
- Intraprocedural CFG: one graph per function
- Handles loops, conditionals, gotos (with warnings)
- Approximations documented (e.g., switch/case, setjmp/longjmp)

### 3. **Pointer State Analysis** (`refactor/pointer_state.py`)
- Dataflow analysis: tracks pointer states across CFG paths
- States: UNKNOWN → UNALLOCATED/ALLOCATED/FREED → INVALID
- Detects state violations (use-after-free, double-free, memory leaks)
- Conservative: if path is too complex, reports path capacity capped (lowers confidence)

### 4. **Detectors** (`refactor/detectors/`)
- Thin pattern-matching layer on top of CFG + dataflow
- Each detector is independent, registered in a DetectorRegistry
- Easy to add new detectors (see `detectors/use_after_free.py` for template)

### 5. **Context Builder** (`refactor/context.py`)
- Transforms Finding → structured LLM prompt
- Includes function source, scope variables, pointer state trace
- Minimal context = fewer hallucinations

### 6. **LLM Client** (`refactor/llm_client.py`)
- Abstraction over OpenRouter, OpenAI, Anthropic
- Configurable via `.env`
- Retries with error feedback (up to MAX_RETRIES)
- Tracks token usage for cost reporting

### 7. **Verifier** (`refactor/verifier.py`)
- Three-stage verification:
  1. **Parse check**: Re-parse LLM output through tree-sitter (catches syntax errors)
  2. **Signature check**: Function name/params unchanged (catches dangerous refactorings)
  3. **Diff generation**: Unified diff for human review (catches no-ops)
- Rejects unsafe/unhelpful suggestions before they reach the user

### 8. **Formatter** (`refactor/formatter.py`)
- Terminal output (clang-tidy style)
- Pretty diffs with syntax highlighting (via `rich`)
- JSON output for CI/tooling
- Graceful fallback to plain text in non-TTY environments

### 9. **SARIF Exporter** (`refactor/sarif.py`)
- Exports findings to SARIF 2.1.0 format
- Integrates with GitHub Code Scanning in one workflow step
- Industry-standard format for static analysis interop

## 🧪 Testing & Development

```bash
# Run all tests with coverage
pytest tests/ --cov=refactor --cov-report=html

# Test a single detector
pytest tests/detectors/test_use_after_free.py -v

# Run CLI on a demo file
python cli.py check demo/
```

## 🔐 GitHub Actions Integration

Add this to your `.github/workflows/security.yml`:

```yaml
name: ast-refactor Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run ast-refactor
        env:
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
        run: python cli.py sarif src/ --output findings.sarif
        
      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

## 📈 Known Limitations

| Feature | Status | Reason |
|---------|--------|--------|
| Interprocedural analysis | ❌ Not implemented | Requires call graph + summary functions. Future work. |
| Path sensitivity beyond loops | ⚠️ Partial | Only tracks pointer states; other values approximated. |
| Function pointers | ❌ Not resolved | Would require pointer analysis. Treated as unknown calls. |
| `setjmp`/`longjmp` | ❌ Not modelled | Rare in modern C; treated as regular calls. |
| `goto` statements | ⚠️ Approximate | Wired conservatively; complex label chains may be inaccurate. |
| LLM hallucinations | ⚠️ Mitigated by verifier | Re-parsing catches most; some semantic changes may slip through. |

Each limitation is documented in findings and SARIF output. Detectors can lower confidence if a limitation affects their result.

## 🤝 Contributing

1. Add a test case in `tests/detectors/`
2. Implement a detector in `refactor/detectors/`
3. Register it in `DetectorRegistry.default()`
4. Run tests: `pytest tests/`
5. Open a PR

## 📝 License

[Specify your license here]

## 🎓 Portfolio Notes

This project demonstrates:

- **Static analysis fundamentals**: AST manipulation, CFG construction, dataflow analysis
- **Real-world verification**: Combining deterministic checks with probabilistic (LLM) reasoning
- **DevOps integration**: SARIF export, GitHub Actions, CI/CD best practices
- **Clean architecture**: Thin, testable layers; data contracts; dependency injection
- **Production mindset**: Error recovery, graceful degradation, detailed logging
- **Security domain knowledge**: Memory safety, pointer state machines, C semantics

The hybrid approach (deterministic + LLM + verification) is novel and directly applicable to production codebases where false positives are expensive and unverified suggestions are risky.

---

**Questions?** Open an issue or reach out. Contributions welcome!
