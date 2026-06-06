import {
  MAX_CODE_CHARS,
  MIN_ANALYSIS_CHARS,
  STAGES,
  createDemoModel,
  streamMockResponse,
} from "./core.js";
import {
  renderAst,
  renderFindings,
  renderResponse,
  renderSelection,
  renderStages,
  renderSummary,
  setChipText,
} from "./renderer.js";
import { SAMPLES, DEFAULT_SAMPLE } from "./samples.js";

const editor = document.getElementById("code-input");
const sampleSelect = document.getElementById("sample-select");
const charCount = document.getElementById("char-count");
const charLimit = document.getElementById("char-limit");
const statusChip = document.getElementById("status-chip");
const analyzeButton = document.getElementById("analyze-button");
const resetButton = document.getElementById("reset-button");
const pipelineList = document.getElementById("pipeline-list");
const astView = document.getElementById("ast-view");
const astSummary = document.getElementById("ast-summary");
const findingsView = document.getElementById("findings-view");
const findingCount = document.getElementById("finding-count");
const llmState = document.getElementById("llm-state");
const llmOutput = document.getElementById("llm-output");
const selectionView = document.getElementById("selection-view");

const state = {
  selectedNodeId: null,
  selectedFindingId: null,
  activeStageId: null,
  completedStages: new Set(),
  currentModel: null,
  busy: false,
};

charLimit.textContent = MAX_CODE_CHARS.toLocaleString();

function formatCount(value) {
  return `${value.toLocaleString()} / ${MAX_CODE_CHARS.toLocaleString()}`;
}

function debounce(fn, delayMs = 180) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), delayMs);
  };
}

function setStatus(text) {
  setChipText(statusChip, text);
}

function updateCharCount() {
  const count = editor.value.length;
  charCount.textContent = formatCount(count);
  charCount.style.borderColor = count > MAX_CODE_CHARS * 0.9 ? "rgba(255, 191, 105, 0.3)" : "rgba(123, 227, 255, 0.18)";
}

function selectNode(node) {
  state.selectedNodeId = node.id;
  state.selectedFindingId = null;
  renderAst(astView, state.currentModel ? (state.currentModel.annotatedAst || state.currentModel.ast) : null, {
    selectedNodeId: state.selectedNodeId,
    onSelectNode: selectNode,
  });
  renderFindings(findingsView, (state.currentModel && state.currentModel.findings) || [], {
    selectedFindingId: state.selectedFindingId,
    onSelectFinding: selectFinding,
  });
  renderSelection(selectionView, node);
}

function selectFinding(finding) {
  state.selectedFindingId = finding.id;
  state.selectedNodeId = finding.nodeId;
  renderFindings(findingsView, (state.currentModel && state.currentModel.findings) || [], {
    selectedFindingId: state.selectedFindingId,
    onSelectFinding: selectFinding,
  });
  renderAst(astView, state.currentModel ? (state.currentModel.annotatedAst || state.currentModel.ast) : null, {
    selectedNodeId: state.selectedNodeId,
    onSelectNode: selectNode,
  });
  const node = findNodeById(state.currentModel ? (state.currentModel.annotatedAst || state.currentModel.ast) : null, state.selectedNodeId);
  renderSelection(selectionView, node);
}

function findNodeById(node, id) {
  if (!node || !id) {
    return null;
  }

  if (node.id === id) {
    return node;
  }

  for (const child of node.children || []) {
    const result = findNodeById(child, id);
    if (result) {
      return result;
    }
  }

  return null;
}

function refreshPreview() {
  const code = editor.value.slice(0, MAX_CODE_CHARS);
  const model = createDemoModel(code);
  state.currentModel = model;

  renderAst(astView, model.annotatedAst, {
    selectedNodeId: state.selectedNodeId,
    onSelectNode: selectNode,
  });
  renderFindings(findingsView, model.findings, {
    selectedFindingId: state.selectedFindingId,
    onSelectFinding: selectFinding,
  });
  renderSummary(astSummary, model.findings);
  setChipText(findingCount, `${model.findings.length} finding${model.findings.length === 1 ? "" : "s"}`);

  if (code.trim().length < MIN_ANALYSIS_CHARS) {
    setStatus("Add a bit more code to unlock Analyze");
    analyzeButton.disabled = true;
  } else {
    setStatus(model.findings.length ? "Preview updated" : "Ready to analyze");
    analyzeButton.disabled = state.busy;
  }
}

const refreshPreviewDebounced = debounce(refreshPreview);

function setStageState(activeId, completedIds) {
  state.activeStageId = activeId;
  state.completedStages = completedIds;
  renderStages(pipelineList, STAGES, activeId, completedIds);
}

async function runAnalysis() {
  if (state.busy) {
    return;
  }

  const code = editor.value.slice(0, MAX_CODE_CHARS);
  if (code.trim().length < MIN_ANALYSIS_CHARS) {
    setStatus("Type a little more code before analyzing");
    return;
  }

  state.busy = true;
  analyzeButton.disabled = true;
  resetButton.disabled = true;
  editor.disabled = true;
  llmState.textContent = "Thinking...";
  renderResponse(llmOutput, "Running staged analysis...");

  const model = createDemoModel(code);
  state.currentModel = model;
  setStageState("parse", new Set());
  setStatus("Parsing code");
  await pause(320);

  renderAst(astView, model.annotatedAst, {
    selectedNodeId: state.selectedNodeId,
    onSelectNode: selectNode,
  });
  renderFindings(findingsView, model.findings, {
    selectedFindingId: state.selectedFindingId,
    onSelectFinding: selectFinding,
  });
  renderSummary(astSummary, model.findings);
  setChipText(findingCount, `${model.findings.length} finding${model.findings.length === 1 ? "" : "s"}`);

  const completed = new Set(["parse"]);
  setStageState("annotate", completed);
  setStatus("Annotating AST");
  await pause(320);

  completed.add("annotate");
  setStageState("context", completed);
  setStatus("Building context");
  await pause(280);

  completed.add("context");
  setStageState("llm", completed);
  setStatus("Mock LLM streaming");

  const streamed = await streamMockResponse(model.findings, {
    onChunk: (text) => {
      renderResponse(llmOutput, text);
    },
  });

  completed.add("llm");
  setStageState("verify", completed);
  llmState.textContent = "Verified";
  setStatus("Response generated");
  await pause(260);

  completed.add("verify");
  setStageState(null, completed);
  renderResponse(llmOutput, `${streamed}\n\nVerification: the suggestion keeps the shape of the function intact and reads like a stable, reviewable fix.`);

  state.busy = false;
  editor.disabled = false;
  resetButton.disabled = false;
  analyzeButton.disabled = editor.value.trim().length < MIN_ANALYSIS_CHARS;
  setStatus("Analysis complete");
}

function pause(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function populateSamples() {
  sampleSelect.replaceChildren();

  SAMPLES.forEach((sample, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = sample.label;
    sampleSelect.append(option);
  });

  sampleSelect.value = String(Math.max(0, SAMPLES.findIndex((sample) => sample.label === DEFAULT_SAMPLE.label)));
}

function loadDefaultSample() {
  editor.value = DEFAULT_SAMPLE.code;
  updateCharCount();
  refreshPreview();
}

sampleSelect.addEventListener("change", () => {
  const sample = SAMPLES[Number(sampleSelect.value)] || DEFAULT_SAMPLE;
  editor.value = sample.code;
  state.selectedNodeId = null;
  state.selectedFindingId = null;
  updateCharCount();
  refreshPreview();
});

editor.addEventListener("input", () => {
  updateCharCount();
  refreshPreviewDebounced();
});

analyzeButton.addEventListener("click", () => {
  void runAnalysis();
});

resetButton.addEventListener("click", () => {
  editor.value = DEFAULT_SAMPLE.code;
  state.selectedNodeId = null;
  state.selectedFindingId = null;
  updateCharCount();
  refreshPreview();
});

populateSamples();
renderStages(pipelineList, STAGES, null, new Set());
loadDefaultSample();
llmState.textContent = "Idle";