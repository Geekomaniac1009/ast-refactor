const MAX_CODE_CHARS = 5000;
const MIN_ANALYSIS_CHARS = 40;

const STAGES = [
  { id: "parse", label: "Parse", copy: "Build a tree from the code you typed." },
  { id: "annotate", label: "Annotate AST", copy: "Mark the suspicious nodes and the surrounding context." },
  { id: "context", label: "Build Context", copy: "Extract the local slice that would be shown to the assistant." },
  { id: "llm", label: "Mock LLM", copy: "Stream a generated response with visible latency." },
  { id: "verify", label: "Verify", copy: "Summarize what would be accepted back to the user." },
];

let nextNodeId = 1;

function resetIds() {
  nextNodeId = 1;
}

function createNode(kind, label, startLine, endLine, children = [], meta = {}) {
  return {
    id: `node-${nextNodeId++}`,
    kind,
    label,
    startLine,
    endLine,
    children,
    annotations: [],
    meta,
  };
}

function trimComment(line) {
  return line.replace(/\/\/.*$/, "").trim();
}

function isFunctionStart(line) {
  const text = trimComment(line);
  if (!text || !text.includes("(") || !text.includes("{")) {
    return false;
  }

  if (/^(if|for|while|switch|else)\b/.test(text)) {
    return false;
  }

  return /[_A-Za-z]\w*\s*\([^;]*\)\s*\{/.test(text);
}

function extractFunctionName(signature) {
  const withoutBraces = signature.replace("{", "").trim();
  const match = withoutBraces.match(/([_A-Za-z]\w*)\s*\(/);
  if (!match) {
    return "function";
  }

  return match[1];
}

function countBraces(lines) {
  return lines.reduce((count, line) => {
    const cleaned = line.replace(/".*?"/g, "");
    return count + (cleaned.match(/\{/g) || []).length - (cleaned.match(/\}/g) || []).length;
  }, 0);
}

function splitParameters(text) {
  return text
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part, index) => createNode("parameter_declaration", part, 0, 0, [], { index }));
}

function buildStatementNode(line, lineNumber) {
  const compact = trimComment(line);
  if (!compact) {
    return null;
  }

  if (/^if\s*\(/.test(compact)) {
    return createNode("if_statement", compact, lineNumber, lineNumber);
  }

  if (/^else\s+if\s*\(/.test(compact)) {
    return createNode("else_if_statement", compact, lineNumber, lineNumber);
  }

  if (/^else\b/.test(compact)) {
    return createNode("else_clause", compact, lineNumber, lineNumber);
  }

  if (/^for\s*\(/.test(compact)) {
    return createNode("for_statement", compact, lineNumber, lineNumber);
  }

  if (/^while\s*\(/.test(compact)) {
    return createNode("while_statement", compact, lineNumber, lineNumber);
  }

  if (/^switch\s*\(/.test(compact)) {
    return createNode("switch_statement", compact, lineNumber, lineNumber);
  }

  if (/\breturn\b/.test(compact)) {
    return createNode("return_statement", compact, lineNumber, lineNumber);
  }

  if (/\bfree\s*\(/.test(compact)) {
    return createNode("call_expression", compact, lineNumber, lineNumber, [], { callee: "free" });
  }

  if (/\b(?:malloc|calloc|realloc)\s*\(/.test(compact)) {
    return createNode("call_expression", compact, lineNumber, lineNumber, [], { callee: "allocation" });
  }

  if (/\bgets\s*\(/.test(compact)) {
    return createNode("call_expression", compact, lineNumber, lineNumber, [], { callee: "gets" });
  }

  if (/\*\s*[_A-Za-z]\w*\s*=|->|\[[^\]]+\]/.test(compact)) {
    return createNode("expression_statement", compact, lineNumber, lineNumber, [], { kind: "pointer-operation" });
  }

  if (compact.endsWith(";")) {
    return createNode("statement", compact, lineNumber, lineNumber);
  }

  return createNode("fragment", compact, lineNumber, lineNumber);
}

function buildFunctionNode(lines, startIndex) {
  const headerLines = [];
  let braceBalance = 0;
  let index = startIndex;

  while (index < lines.length) {
    const current = lines[index];
    headerLines.push(current);
    braceBalance += countBraces([current]);
    if (current.includes("{")) {
      break;
    }
    index += 1;
  }

  const signature = headerLines.join(" ").replace(/\{.*$/, "{");
  const functionName = extractFunctionName(signature);
  const paramsMatch = signature.match(/\((.*)\)/);
  const paramsText = (paramsMatch && paramsMatch[1]) || "";

  const bodyLines = [];
  let endIndex = index;
  while (endIndex + 1 < lines.length && braceBalance > 0) {
    endIndex += 1;
    const current = lines[endIndex];
    bodyLines.push(current);
    braceBalance += countBraces([current]);
  }

  const parameterNodes = splitParameters(paramsText);
  const statementNodes = bodyLines
    .map((line, offset) => buildStatementNode(line, index + offset + 1))
    .filter(Boolean);

  const declaratorNode = createNode(
    "declarator",
    `${functionName}(${paramsText})`,
    startIndex + 1,
    endIndex + 1,
    [createNode("identifier", functionName, startIndex + 1, startIndex + 1), createNode("parameter_list", paramsText || "void", startIndex + 1, startIndex + 1, parameterNodes)],
  );

  const bodyNode = createNode(
    "compound_statement",
    "function body",
    index + 1,
    endIndex + 1,
    statementNodes,
  );

  const functionNode = createNode(
    "function_definition",
    functionName,
    startIndex + 1,
    endIndex + 1,
    [declaratorNode, bodyNode],
  );

  return { node: functionNode, endIndex };
}

export function buildAst(code) {
  resetIds();

  const lines = code.split(/\r?\n/);
  const root = createNode("translation_unit", "translation_unit", 1, Math.max(lines.length, 1));

  const children = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];
    const trimmed = trimComment(line);

    if (!trimmed) {
      index += 1;
      continue;
    }

    if (trimmed.startsWith("#")) {
      children.push(createNode("preprocessor_directive", trimmed, index + 1, index + 1));
      index += 1;
      continue;
    }

    if (isFunctionStart(line)) {
      const { node, endIndex } = buildFunctionNode(lines, index);
      children.push(node);
      index = endIndex + 1;
      continue;
    }

    children.push(createNode("declaration", trimmed, index + 1, index + 1));
    index += 1;
  }

  if (children.length === 0) {
    children.push(createNode("empty_translation_unit", "Start typing C code to see the tree build up.", 1, 1));
  }

  root.children = children;
  return root;
}

function findLineMatches(code, regex) {
  const lines = code.split(/\r?\n/);
  const matches = [];

  lines.forEach((line, index) => {
    if (regex.test(line)) {
      matches.push({ line: index + 1, text: trimComment(line) });
    }
    regex.lastIndex = 0;
  });

  return matches;
}

function getAllocationInfo(code) {
  const lines = code.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/([_A-Za-z]\w*)\s*=\s*(?:malloc|calloc|realloc)\s*\(/);
    if (match) {
      return { variable: match[1], line: index + 1 };
    }
  }

  return null;
}

function findFirstDerefLine(code, variable) {
  const lines = code.split(/\r?\n/);
  const derefRegex = new RegExp(`(?:\*\s*${variable}\b|${variable}\s*->|${variable}\s*\[)`);

  for (let index = 0; index < lines.length; index += 1) {
    if (derefRegex.test(lines[index])) {
      return index + 1;
    }
  }

  return null;
}

function hasNullCheckBeforeLine(code, variable, lineNumber) {
  const lines = code.split(/\r?\n/);
  const checkRegex = new RegExp(`if\s*\(\s*${variable}\s*==\s*NULL\s*\)`);

  for (let index = 0; index < Math.max(0, lineNumber - 1); index += 1) {
    if (checkRegex.test(lines[index])) {
      return true;
    }
  }

  return false;
}

function createFinding(kind, severity, message, line, nodeId) {
  return {
    id: `finding-${kind}-${line}`,
    kind,
    severity,
    message,
    line,
    nodeId,
  };
}

function findNodeAtLine(node, line) {
  if (!node || line < node.startLine || line > node.endLine) {
    return null;
  }

  for (const child of node.children || []) {
    const nested = findNodeAtLine(child, line);
    if (nested) {
      return nested;
    }
  }

  return node;
}

export function detectFindings(code, ast) {
  const findings = [];
  const allocation = getAllocationInfo(code);
  const freeCalls = findLineMatches(code, /\bfree\s*\(\s*([_A-Za-z]\w*)\s*\)/g);
  const getsCalls = findLineMatches(code, /\bgets\s*\(/g);

  if (allocation) {
    const freeForAllocation = freeCalls.filter((call) => call.text.includes(allocation.variable));
    if (freeForAllocation.length === 0) {
      const node = findNodeAtLine(ast, allocation.line);
      findings.push(
        createFinding(
          "malloc_without_free",
          "warning",
          `Allocated ${allocation.variable} is never freed in this function.`,
          allocation.line,
          node && node.id ? node.id : null,
        ),
      );
    }

    const nullDerefLine = findFirstDerefLine(code, allocation.variable);
    if (nullDerefLine && !hasNullCheckBeforeLine(code, allocation.variable, nullDerefLine)) {
      const node = findNodeAtLine(ast, nullDerefLine);
      findings.push(
        createFinding(
          "null_deref",
          "error",
          `Pointer ${allocation.variable} is dereferenced without a null check.`,
          nullDerefLine,
          node && node.id ? node.id : null,
        ),
      );
    }
  }

  if (freeCalls.length >= 2) {
    const freeCounts = new Map();
    for (const call of freeCalls) {
      const match = call.text.match(/free\s*\(\s*([_A-Za-z]\w*)\s*\)/);
      const variable = (match && match[1]) || "";
      if (!variable) {
        continue;
      }

      const count = freeCounts.get(variable) || 0;
      freeCounts.set(variable, count + 1);
      if (count + 1 === 2) {
        const node = findNodeAtLine(ast, call.line);
        findings.push(
          createFinding(
            "double_free",
            "error",
            `Variable ${variable} is released more than once.`,
            call.line,
            node && node.id ? node.id : null,
          ),
        );
      }
    }
  }

  for (const call of freeCalls) {
    const match = call.text.match(/free\s*\(\s*([_A-Za-z]\w*)\s*\)/);
    const variable = (match && match[1]) || "";
    if (!variable) {
      continue;
    }

    const lines = code.split(/\r?\n/);
    const laterUse = lines.findIndex((line, index) => {
      if (index + 1 <= call.line) {
        return false;
      }
      const pattern = new RegExp(`(?:\*\s*${variable}\b|${variable}\s*->|${variable}\s*\[)`);
      return pattern.test(line);
    });

    if (laterUse !== -1) {
      const node = findNodeAtLine(ast, laterUse + 1);
      findings.push(
        createFinding(
          "use_after_free",
          "error",
          `Variable ${variable} is used after it has been freed.`,
          laterUse + 1,
          node && node.id ? node.id : null,
        ),
      );
    }
  }

  for (const call of getsCalls) {
    const node = findNodeAtLine(ast, call.line);
    findings.push(
      createFinding(
        "api_misuse",
        "warning",
        "gets() is unsafe because it cannot bound input length.",
        call.line,
        node && node.id ? node.id : null,
      ),
    );
  }

  return findings;
}

function cloneAst(node) {
  return {
    ...node,
    annotations: (node.annotations || []).slice(),
    children: (node.children || []).map((child) => cloneAst(child)),
  };
}

function annotateNode(node, finding) {
  const copied = cloneAst(node);

  if (copied.startLine <= finding.line && finding.line <= copied.endLine) {
    copied.annotations = [...copied.annotations, finding.kind];
  }

  copied.children = copied.children.map((child) => annotateNode(child, finding));
  return copied;
}

export function annotateAst(ast, findings) {
  return findings.reduce((current, finding) => annotateNode(current, finding), ast);
}

export function createDemoModel(code) {
  const ast = buildAst(code);
  const findings = detectFindings(code, ast);
  const annotatedAst = annotateAst(ast, findings);

  return { ast, findings, annotatedAst };
}

function chunkText(text, chunkSize = 24) {
  const chunks = [];
  for (let index = 0; index < text.length; index += chunkSize) {
    chunks.push(text.slice(index, index + chunkSize));
  }
  return chunks;
}

function buildResponse(findings) {
  if (findings.length === 0) {
    return [
      "The analysis found no obvious memory-safety issues.",
      "",
      "Suggested next step: keep the current structure, and add one or two targeted tests to lock in the behavior.",
    ].join("\n");
  }

  const primary = findings[0];
  const kindToAdvice = {
    malloc_without_free: "Add a matching free() on every exit path, including early returns.",
    double_free: "Guard the release path and null the pointer after freeing it.",
    use_after_free: "Move the use before the free, or copy the needed value first.",
    null_deref: "Check the allocation result before dereferencing the pointer.",
    api_misuse: "Replace gets() with a bounded input API such as fgets().",
  };

  const advice = kindToAdvice[primary.kind] || "Make the change as small as possible and keep the function signature stable.";

  return [
    `I found ${findings.length} issue${findings.length > 1 ? "s" : ""} during the mock analysis.`,
    `Primary finding: ${primary.kind} at line ${primary.line}.`,
    "",
    `Suggested fix: ${advice}`,
    "",
    "The verifier would re-parse the suggestion, compare the function signature, and reject a no-op or structural drift before showing the fix.",
  ].join("\n");
}

export async function streamMockResponse(findings, handlers) {
  const response = buildResponse(findings);
  const chunks = chunkText(response);
  let output = "";

  for (const chunk of chunks) {
    await new Promise((resolve) => setTimeout(resolve, 45 + Math.random() * 55));
    output += chunk;
    handlers.onChunk(output);
  }

  return output;
}

export { MAX_CODE_CHARS, MIN_ANALYSIS_CHARS, STAGES };