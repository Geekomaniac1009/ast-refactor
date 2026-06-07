function stageClass(stageId, activeStageId, completedStageIds) {
  if (completedStageIds.has(stageId)) {
    return "stage done";
  }

  if (stageId === activeStageId) {
    return "stage active";
  }

  return "stage";
}

function severityLabel(severity) {
  return severity === "error" ? "error" : severity;
}

export function renderStages(container, stages, activeStageId, completedStageIds) {
  container.replaceChildren();

  for (const stage of stages) {
    const card = document.createElement("div");
    card.className = stageClass(stage.id, activeStageId, completedStageIds);

    const dot = document.createElement("div");
    dot.className = "dot";

    const text = document.createElement("div");

    const title = document.createElement("div");
    title.className = "stage-title";
    title.textContent = stage.label;

    const copy = document.createElement("div");
    copy.className = "stage-copy";
    copy.textContent = stage.copy;

    text.append(title, copy);
    card.append(dot, text);
    container.append(card);
  }
}

function renderAstNode(node, selectedNodeId, onSelectNode, depth = 0) {
  const wrapper = document.createElement("div");
  wrapper.className = "ast-node";
  wrapper.dataset.nodeId = node.id;
  wrapper.style.setProperty("--depth", depth.toString());

  if (node.annotations && node.annotations.length) {
    wrapper.classList.add("annotated");
  }

  if (node.id === selectedNodeId) {
    wrapper.classList.add("selected");
  }

  const header = document.createElement("button");
  header.type = "button";
  header.className = "ast-node-header";
  header.style.width = "100%";
  header.style.background = "transparent";
  header.style.border = "none";
  header.style.color = "inherit";
  header.style.font = "inherit";
  header.style.padding = "0";
  header.style.cursor = "pointer";

  const left = document.createElement("div");

  const kind = document.createElement("div");
  kind.className = "ast-kind";
  kind.textContent = node.kind;

  const label = document.createElement("div");
  label.className = "ast-label";
  label.textContent = node.label;

  left.append(kind, label);

  const meta = document.createElement("div");
  meta.className = "ast-meta";
  const annotationText = node.annotations && node.annotations.length ? ` • ${node.annotations.join(", ")}` : "";
  meta.textContent = `${node.startLine}-${node.endLine}${annotationText}`;

  header.append(left, meta);
  header.addEventListener("click", () => onSelectNode(node));

  wrapper.append(header);

  if (node.children && node.children.length) {
    const children = document.createElement("div");
    children.className = "ast-children";
    for (const child of node.children) {
      children.append(renderAstNode(child, selectedNodeId, onSelectNode, depth + 1));
    }
    wrapper.append(children);
  }

  return wrapper;
}

export function renderAst(container, ast, { selectedNodeId = null, onSelectNode = () => {} } = {}) {
  container.replaceChildren(renderAstNode(ast, selectedNodeId, onSelectNode));
}

export function renderFindings(container, findings, { selectedFindingId = null, onSelectFinding = () => {} } = {}) {
  container.replaceChildren();

  if (!findings.length) {
    const empty = document.createElement("div");
    empty.className = "finding-card";
    empty.textContent = "No findings yet. The annotations will appear here as soon as the parser spots a pattern.";
    container.append(empty);
    return;
  }

  for (const finding of findings) {
    const card = document.createElement("button");
    card.type = "button";
    card.className = "finding-card";
    if (finding.id === selectedFindingId) {
      card.classList.add("selected");
    }

    const head = document.createElement("div");
    head.className = "finding-head";

    const left = document.createElement("div");

    const kind = document.createElement("div");
    kind.className = "finding-kind";
    kind.textContent = finding.kind.replace(/_/g, " ");

    const meta = document.createElement("div");
    meta.className = "finding-meta";
    meta.textContent = `line ${finding.line} • ${severityLabel(finding.severity)}`;

    left.append(kind, meta);
    head.append(left);

    const body = document.createElement("div");
    body.className = "finding-copy";
    body.textContent = finding.message;

    card.append(head, body);
    card.addEventListener("click", () => onSelectFinding(finding));
    container.append(card);
  }
}

export function renderSelection(container, selection) {
  if (!selection) {
    container.textContent = "No AST node selected.";
    return;
  }

  const parts = [
    `Selected node: ${selection.kind}`,
    `Lines: ${selection.startLine}-${selection.endLine}`,
    selection.annotations && selection.annotations.length ? `Annotations: ${selection.annotations.join(", ")}` : "Annotations: none",
  ];

  container.textContent = parts.join(" • ");
}

export function renderSummary(container, findings) {
  if (!findings.length) {
    container.textContent = "No issues detected in the live preview.";
    return;
  }

  container.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"} annotated in the tree.`;
}

export function renderResponse(container, text) {
  container.textContent = text;
}

export function renderDiff(container, text) {
  const lines = text.split("\n");
  container.replaceChildren();

  for (const line of lines) {
    const row = document.createElement("span");
    row.className = "diff-line";
    row.textContent = line;

    if (line.startsWith("+") && !line.startsWith("+++")) {
      row.classList.add("diff-add");
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      row.classList.add("diff-remove");
    } else if (line.startsWith("@@")) {
      row.classList.add("diff-hunk");
    }

    container.append(row);
  }
}

export function setChipText(element, text) {
  element.textContent = text;
}