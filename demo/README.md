# Interactive Demo

This folder is a standalone demo surface for the GitHub README / product story.
It does not import the production analyzer, so UI changes stay isolated here.

## What it shows

- Live AST growth as code is typed
- A staged analysis timeline when you click Analyze
- AST annotations for suspicious patterns
- A mocked LLM response that streams in chunks
- A hard character cap so the demo stays readable

## Run locally

From the repository root:

```bash
cd demo
python -m http.server 4173
```

Then open `http://localhost:4173`.

## Design note

The demo is intentionally modular:

- `src/core.js` owns parsing, heuristics, and the mocked pipeline
- `src/renderer.js` owns DOM rendering
- `src/app.js` wires UI events and state

If you later replace the mock pipeline with the real backend, only the core adapter needs to change.