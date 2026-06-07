import assert from "assert";
import { createServer } from "http";
import { readFile } from "fs/promises";
import path from "path";
import { chromium } from "@playwright/test";
import { fileURLToPath } from "url";

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function buildLargeCodeSample() {
  return [
    "#include <stdlib.h>",
    "",
    "void alpha(void) {",
    "    int *a = malloc(sizeof(int));",
    "    if (a == NULL) {",
    "        return;",
    "    }",
    "    *a = 1;",
    "    free(a);",
    "}",
    "",
    "void beta(void) {",
    "    int *b = malloc(sizeof(int));",
    "    if (b == NULL) {",
    "        return;",
    "    }",
    "    *b = 2;",
    "    free(b);",
    "}",
    "",
    "void gamma(void) {",
    "    int *c = malloc(sizeof(int));",
    "    if (c == NULL) {",
    "        return;",
    "    }",
    "    *c = 3;",
    "    free(c);",
    "}",
    "",
    "void delta(void) {",
    "    int *d = malloc(sizeof(int));",
    "    if (d == NULL) {",
    "        return;",
    "    }",
    "    *d = 4;",
    "    free(d);",
    "}",
  ].join("\n");
}

async function run() {
  const testDir = path.dirname(fileURLToPath(import.meta.url));
  const demoDir = path.resolve(testDir, "..");

  const server = createServer(async (req, res) => {
    try {
      const rawPath = (req.url || "/").split("?")[0];
      const normalizedPath = rawPath === "/" ? "/index.html" : rawPath;
      const safePath = normalizedPath.replace(/^\/+/, "");
      const targetPath = path.resolve(demoDir, safePath);

      if (!targetPath.startsWith(demoDir)) {
        res.writeHead(403);
        res.end("Forbidden");
        return;
      }

      const body = await readFile(targetPath);
      const extension = path.extname(targetPath);
      const mimeType = MIME_TYPES[extension] || "application/octet-stream";
      res.writeHead(200, { "content-type": mimeType });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("Not found");
    }
  });

  await new Promise((resolve) => {
    server.listen(4173, "127.0.0.1", resolve);
  });

  const browser = await chromium.launch({ headless: true });

  try {
    const page = await browser.newPage();
    await page.goto("http://127.0.0.1:4173/");

    const sampleButtons = page.locator("#sample-strip .sample-button");
    assert.equal(await sampleButtons.count(), 4, "Expected 4 sample buttons");

    await sampleButtons.nth(1).click();
    const selectedCode = await page.locator("#code-input").inputValue();
    assert.match(selectedCode, /release_twice/, "Clicking sample button should load matching sample code");

    await sampleButtons.nth(0).click();
    const resetCode = await page.locator("#code-input").inputValue();
    assert.match(resetCode, /update_buffer/, "Clicking the first sample should restore default code");

    await page.click("#analyze-button");
    await page.waitForFunction(() => {
      const output = document.getElementById("llm-output");
      return !!output && !!output.querySelector(".diff-line");
    }, { timeout: 20_000 });

    const addLines = await page.locator("#llm-output .diff-line.diff-add").count();
    const removeLines = await page.locator("#llm-output .diff-line.diff-remove").count();
    const prefixes = await page.$$eval("#llm-output .diff-line", (rows) =>
      rows.map((row) => ((row.textContent || "").trimStart()[0] || "")),
    );
    assert.ok(prefixes.includes("+"), "Expected unified diff content with an added line");
    assert.ok(prefixes.includes("-"), "Expected unified diff content with a removed line");
    assert.ok(addLines + removeLines > 0, "Expected styled diff lines in output");

    await page.fill("#code-input", buildLargeCodeSample());
    await page.waitForTimeout(350);

    const astScrollable = await page.evaluate(() => {
      const node = document.getElementById("ast-view");
      return !!node && node.scrollHeight > node.clientHeight;
    });
    assert.equal(astScrollable, true, "AST panel should be scrollable with larger input");

    const selectionOutsideLlm = await page.evaluate(() => {
      const selection = document.getElementById("selection-view");
      const llm = document.getElementById("llm-output");
      return !!selection && !!llm && !llm.contains(selection);
    });
    assert.equal(selectionOutsideLlm, true, "Selection view should not be inside the LLM output panel");

    console.log("Smoke test passed.");
  } finally {
    await browser.close();
    await new Promise((resolve) => {
      server.close(() => resolve());
    });
  }
}

run()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
