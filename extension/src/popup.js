import { sendRuntimeMessage } from "./webextension-api.js";

const prompt = document.querySelector("#prompt");
const analyze = document.querySelector("#analyze");
const feedback = document.querySelector("#feedback");
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const resultTitle = document.querySelector("#result-title");
const reason = document.querySelector("#reason");
const excerpt = document.querySelector("#excerpt");
const serverWarning = document.querySelector("#server-warning");
const runtimeWarning = document.querySelector("#runtime-warning");
const waitRegex = document.querySelector("#wait-regex");
const modelId = document.querySelector("#model-id");
const masterToggle = document.querySelector("#master-toggle");
const layerButtons = [...document.querySelectorAll(".layer-toggle")];

let settings;

analyze.addEventListener("click", inspectPrompt);
masterToggle.addEventListener("click", toggleMaster);
prompt.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") inspectPrompt();
});
prompt.addEventListener("input", clearManualResult);
for (const button of layerButtons) button.addEventListener("click", toggleLayer);
waitRegex.addEventListener("change", () => savePatch({ waitForRegex: waitRegex.checked }));
modelId.addEventListener("change", () => savePatch({ modelId: modelId.value }));

void initialise();

async function initialise() {
  const response = await sendMessage({ type: "GET_SETTINGS" });
  if (!response?.ok) {
    setStatus("Extension settings could not be loaded.", true);
    return;
  }
  settings = response.settings;
  renderSettings();

  if (settings.enabled) {
    const runtimeStatus = await sendMessage({ type: "GET_RUNTIME_STATUS" });
    if (!runtimeStatus?.ok || !runtimeStatus.runtime?.enabled) {
      showRuntimeWarning(
        runtimeStatus?.runtime?.message
          || "The client runtime is not running. Toggle PriVoke off and on to retry.",
      );
    }
  } else {
    const stopped = await sendMessage({ type: "SET_MASTER_ENABLED", enabled: false });
    if (stopped?.warning) showRuntimeWarning(stopped.warning);
  }
}

async function toggleMaster() {
  if (!settings) return;
  const enabled = !settings.enabled;
  masterToggle.disabled = true;
  runtimeWarning.hidden = true;
  const response = await sendMessage({ type: "SET_MASTER_ENABLED", enabled });
  masterToggle.disabled = false;

  if (response?.settings) settings = response.settings;
  renderSettings();
  if (!response?.ok || response.warning) {
    showRuntimeWarning(
      response?.error || response?.warning || "The client runtime could not be controlled.",
    );
  }
}

async function toggleLayer(event) {
  if (!settings) return;
  const button = event.currentTarget;
  const layer = button.dataset.layer;
  const enabled = !settings.layers[layer];

  if (layer === "llm" && enabled) {
    button.disabled = true;
    serverWarning.hidden = true;
    const health = await sendMessage({ type: "CHECK_STREAMING_HEALTH" });
    button.disabled = false;
    if (!health?.ok) {
      serverWarning.hidden = false;
      await savePatch({ layers: { llm: false } });
      return;
    }
  }

  serverWarning.hidden = true;
  await savePatch({ layers: { [layer]: enabled } });
}

async function savePatch(patch) {
  const response = await sendMessage({ type: "UPDATE_SETTINGS", patch });
  if (!response?.ok) {
    setStatus(response?.error || "Could not save settings.", true);
    return;
  }
  settings = response.settings;
  renderSettings();
}

function renderSettings() {
  for (const button of layerButtons) {
    button.setAttribute("aria-pressed", String(settings.layers[button.dataset.layer]));
    button.disabled = !settings.enabled;
  }
  waitRegex.checked = settings.waitForRegex;
  modelId.value = settings.modelId;
  masterToggle.setAttribute("aria-pressed", String(settings.enabled));
  masterToggle.setAttribute("aria-label", settings.enabled ? "Turn PriVoke off" : "Turn PriVoke on");
  masterToggle.querySelector(".master-label").textContent = settings.enabled ? "On" : "Off";
  document.body.classList.toggle("extension-off", !settings.enabled);
  prompt.disabled = !settings.enabled;
  analyze.disabled = !settings.enabled;
}

async function inspectPrompt() {
  if (!settings?.enabled) return;
  const text = prompt.value.trim();
  if (!text) {
    setFeedback("ERROR", "error");
    setStatus("Enter a prompt first.", true);
    return;
  }

  analyze.disabled = true;
  result.hidden = true;
  setFeedback("CHECKING", "checking");
  setStatus("");

  const resultMessage = await sendMessage({
    type: "ANALYZE_PROMPT",
    source: "manual",
    text,
    targetApp: "extension_popup",
  });

  analyze.disabled = !settings.enabled;
  if (!resultMessage?.ok) {
    setFeedback("ERROR", "error");
    setStatus(resultMessage?.error || "PriVoke could not analyse this prompt.", true);
    return;
  }

  const response = resultMessage.response;
  const action = String(response.action || "ALLOW").toUpperCase();
  if (response.disabled) setFeedback("ERROR", "error");
  else if (action === "BLOCK") setFeedback("ERROR", "error");
  else if (action === "WARN") setFeedback("WARN", "warn");
  else if (response.error) setFeedback("ERROR", "error");
  else setFeedback("PASS", "pass");

  if (response.masterDisabled) setStatus("Turn PriVoke on to analyse prompts.", true);
  else if (response.disabled) setStatus("Enable at least one protection layer.", true);
  else if (response.error) setStatus(response.error, true);
  else setStatus(`${Number(response.elapsedMs || 0).toFixed(1)} ms`);

  if (action === "WARN" || action === "BLOCK") renderResult(action, text, response);
}

function renderResult(action, text, response) {
  resultTitle.textContent = action === "BLOCK"
    ? "This prompt was blocked"
    : "Review this prompt before sending";
  reason.textContent = response.reason || "PriVoke detected sensitive information.";
  excerpt.replaceChildren();
  appendHighlightedText(excerpt, text, response.evidence);
  result.hidden = false;
}

function appendHighlightedText(container, text, evidence) {
  const match = evidence?.sectionOfText || spanText(text, evidence);
  if (!match) {
    appendSensitive(container, text.slice(0, 240));
    return;
  }

  const index = text.toLocaleLowerCase().indexOf(match.toLocaleLowerCase());
  if (index < 0) {
    appendSensitive(container, match);
    return;
  }

  const start = Math.max(0, index - 55);
  const end = Math.min(text.length, index + match.length + 55);
  if (start > 0) container.append("…");
  container.append(text.slice(start, index));
  appendSensitive(container, text.slice(index, index + match.length));
  container.append(text.slice(index + match.length, end));
  if (end < text.length) container.append("…");
}

function appendSensitive(container, value) {
  const sensitive = document.createElement("span");
  sensitive.className = "sensitive";
  sensitive.textContent = value;
  container.append(sensitive);
}

function spanText(text, evidence) {
  if (!evidence?.hasSpan) return "";
  const start = Number(evidence.spanStart);
  const end = Number(evidence.spanEnd);
  return Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start
    ? text.slice(start, end)
    : "";
}

function setFeedback(message, className) {
  feedback.textContent = message;
  feedback.className = `feedback ${className}`;
  feedback.hidden = false;
}

function clearManualResult() {
  feedback.hidden = true;
  result.hidden = true;
  setStatus("");
}

function setStatus(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function showRuntimeWarning(message) {
  runtimeWarning.querySelector("span").textContent = message;
  runtimeWarning.hidden = false;
}

async function sendMessage(message) {
  try {
    return await sendRuntimeMessage(message);
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}
