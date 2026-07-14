import { RuntimeClient } from "./runtime-client.js";
import { detectionLayers, loadSettings, updateSettings } from "./settings.js";

const client = new RuntimeClient();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: errorMessage(error) }));
  return true;
});

async function handleMessage(message, sender) {
  switch (message?.type) {
    case "GET_SETTINGS":
      return { ok: true, settings: await loadSettings() };
    case "UPDATE_SETTINGS":
      return { ok: true, settings: await updateSettings(message.patch ?? {}) };
    case "SET_MASTER_ENABLED":
      return setMasterEnabled(Boolean(message.enabled));
    case "GET_RUNTIME_STATUS":
      return getRuntimeStatus();
    case "CHECK_STREAMING_HEALTH":
      return checkStreamingHealth();
    case "ANALYZE_PROMPT":
      return analyzePrompt(message, sender);
    default:
      return { ok: false, error: "Unsupported extension message." };
  }
}

async function checkStreamingHealth() {
  try {
    const response = await client.streamingHealth({
      signal: AbortSignal.timeout(3_500),
    });
    const serving = response.status?.toUpperCase() === "SERVING";
    return {
      ok: serving,
      health: response,
      error: serving ? undefined : "PriVoke servers are offline.",
    };
  } catch (error) {
    return {
      ok: false,
      error: "PriVoke servers are offline.",
      detail: errorMessage(error),
    };
  }
}

async function setMasterEnabled(enabled) {
  if (!enabled) {
    const settings = await updateSettings({ enabled: false });
    try {
      const runtime = await client.setRuntimeEnabled(false, {
        signal: AbortSignal.timeout(15_000),
      });
      return { ok: true, settings, runtime };
    } catch (error) {
      return {
        ok: true,
        settings,
        warning: "The extension is off, but the client runtime could not be stopped.",
        detail: errorMessage(error),
      };
    }
  }

  try {
    const runtime = await client.setRuntimeEnabled(true, {
      signal: AbortSignal.timeout(36_000),
    });
    if (!runtime.enabled) {
      const settings = await updateSettings({ enabled: false });
      return {
        ok: false,
        settings,
        error: runtime.message || "The client runtime failed to start.",
        runtime,
      };
    }
    const settings = await updateSettings({ enabled: true });
    return { ok: true, settings, runtime };
  } catch (error) {
    const settings = await updateSettings({ enabled: false });
    return {
      ok: false,
      settings,
      error: "The client runtime could not be started.",
      detail: errorMessage(error),
    };
  }
}

async function getRuntimeStatus() {
  try {
    const runtime = await client.runtimeStatus({
      signal: AbortSignal.timeout(3_500),
    });
    return { ok: true, runtime };
  } catch (error) {
    return { ok: false, error: errorMessage(error) };
  }
}

async function analyzePrompt(message, sender) {
  const text = typeof message.text === "string" ? message.text.trim() : "";
  if (!text) return { ok: false, error: "Prompt text is required." };

  const settings = await loadSettings();
  if (!settings.enabled) {
    void client.setRuntimeEnabled(false, {
      signal: AbortSignal.timeout(15_000),
    }).catch(() => {});
    return { ok: true, response: disabledExtensionResponse() };
  }
  const layers = detectionLayers(settings);
  if (layers.length === 0) {
    return { ok: true, response: disabledLayersResponse() };
  }

  const targetApp = cleanText(message.targetApp, 80)
    || appFromUrl(sender?.url)
    || "unknown_web_app";
  const response = await client.analyzePrompt({
    text,
    source: message.source === "manual" ? "extension_popup" : "browser_interceptor",
    targetApp,
    requestId: crypto.randomUUID(),
    layers,
    regexExecutionOrder: settings.waitForRegex
      ? "REGEX_EXECUTION_ORDER_FIRST"
      : "REGEX_EXECUTION_ORDER_PARALLEL",
    semanticModelId: settings.modelId,
    metadata: {
      client: "privoke-local-extension",
      client_version: "0.1.0",
      intercepted: message.source === "manual" ? "false" : "true",
    },
  }, { signal: AbortSignal.timeout(30_000) });

  return { ok: true, response };
}

function disabledExtensionResponse() {
  return {
    disabled: true,
    masterDisabled: true,
    action: "ALLOW",
    allowed: true,
    reason: "PriVoke is turned off.",
    elapsedMs: 0,
  };
}

function disabledLayersResponse() {
  return {
    disabled: true,
    action: "ALLOW",
    allowed: true,
    reason: "No protection layers are enabled.",
    elapsedMs: 0,
    classification: {
      sensitivity: "S0",
      visibility: "PU",
      categories: [],
    },
    layers: [],
  };
}

function appFromUrl(rawUrl) {
  try {
    const host = new URL(rawUrl).hostname;
    if (host === "chatgpt.com" || host === "chat.openai.com") return "chatgpt";
    if (host === "claude.ai") return "claude";
    if (host === "gemini.google.com") return "gemini";
    if (host === "copilot.microsoft.com") return "copilot";
    if (host === "api.openai.com") return "openai_api";
  } catch {
    return "";
  }
  return "";
}

function cleanText(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
