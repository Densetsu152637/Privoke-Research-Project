import { RuntimeClient } from "./runtime-client.js";

const client = new RuntimeClient();
const prompt = document.querySelector("#prompt");
const analyze = document.querySelector("#analyze");
const status = document.querySelector("#status");
const result = document.querySelector("#result");
const action = document.querySelector("#action");
const elapsed = document.querySelector("#elapsed");
const reason = document.querySelector("#reason");
const sensitivity = document.querySelector("#sensitivity");
const visibility = document.querySelector("#visibility");
const categories = document.querySelector("#categories");

analyze.addEventListener("click", inspectPrompt);
prompt.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    inspectPrompt();
  }
});

async function inspectPrompt() {
  const text = prompt.value.trim();
  if (!text) {
    setStatus("Enter a prompt first.", true);
    return;
  }

  analyze.disabled = true;
  result.hidden = true;
  setStatus("Inspecting on this computer…");

  try {
    const response = await client.analyzePrompt({
      text,
      source: "browser_extension",
      targetApp: "extension_popup",
      requestId: crypto.randomUUID(),
      layers: ["DETECTION_LAYER_RUNTIME"],
      metadata: { client: "privoke-local-extension", client_version: "0.1.0" },
    });
    if (response.error) {
      throw new Error(response.error);
    }
    renderResult(response);
    setStatus("Inspection complete.");
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    setStatus(`Could not reach the local runtime: ${detail}`, true);
  } finally {
    analyze.disabled = false;
  }
}

function renderResult(response) {
  const classification = response.classification ?? {};
  const actionName = response.action || "UNKNOWN";
  action.textContent = actionName;
  action.className = actionName.toLowerCase();
  elapsed.textContent = `${Number(response.elapsedMs || 0).toFixed(1)} ms`;
  reason.textContent = response.reason || "No reason supplied.";
  sensitivity.textContent = classification.sensitivity || "—";
  visibility.textContent = classification.visibility || "—";
  categories.textContent = classification.categories?.join(", ") || "None";
  result.hidden = false;
}

function setStatus(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}
