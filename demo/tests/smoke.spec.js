import { expect, test } from "@playwright/test";

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

test("demo smoke flow", async ({ page }) => {
  await page.goto("/");

  const sampleButtons = page.locator("#sample-strip .sample-button");
  await expect(sampleButtons).toHaveCount(4);

  await sampleButtons.nth(1).click();
  await expect(page.locator("#code-input")).toContainText("release_twice");

  await page.locator("#analyze-button").click();
  await expect(page.locator("#llm-output")).toContainText("Unified diff:", { timeout: 20_000 });

  const addLines = page.locator("#llm-output .diff-line.diff-add");
  const removeLines = page.locator("#llm-output .diff-line.diff-remove");
  await expect(addLines.first()).toBeVisible();
  await expect(removeLines.first()).toBeVisible();

  await page.fill("#code-input", buildLargeCodeSample());
  await page.waitForTimeout(350);

  const astScrollable = await page.evaluate(() => {
    const node = document.getElementById("ast-view");
    if (!node) {
      return false;
    }
    return node.scrollHeight > node.clientHeight;
  });
  expect(astScrollable).toBeTruthy();

  const selectionOutsideLlm = await page.evaluate(() => {
    const selection = document.getElementById("selection-view");
    const llm = document.getElementById("llm-output");
    if (!selection || !llm) {
      return false;
    }
    return !llm.contains(selection);
  });
  expect(selectionOutsideLlm).toBeTruthy();
});
