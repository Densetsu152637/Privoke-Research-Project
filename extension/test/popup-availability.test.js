import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = (await readFile(new URL("../src/popup.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/gm, "");
const flush = () => new Promise((resolve) => setImmediate(resolve));

function harness({ enabled = true, llm = true, health = async () => ({ ok: false }) } = {}) {
  const elements = new Map();
  function element(key) {
    if (!elements.has(key)) elements.set(key, {
      dataset: {}, attributes: {}, listeners: {}, hidden: true, disabled: false,
      value: "", textContent: "", classList: { toggle() {} },
      setAttribute(name, value) { this.attributes[name] = value; },
      querySelector(selector) { return element(`${key} ${selector}`); },
      addEventListener(name, listener) { this.listeners[name] = listener; },
    });
    return elements.get(key);
  }
  const buttons = ["regex", "ner", "llm"].map((layer) => {
    const button = element(layer);
    button.dataset.layer = layer;
    return button;
  });
  let settings = {
    enabled, useLocalStack: false, layers: { regex: true, ner: true, llm },
    waitForRegex: true, modelQuality: "latest",
  };
  const messages = [];
  const timers = [];
  let analysis = {};
  vm.runInNewContext(source, {
    document: { querySelector: element, querySelectorAll: () => buttons,
      body: { classList: { toggle() {} } } },
    setInterval(callback) { timers.push(callback); },
    async sendRuntimeMessage(message) {
      messages.push(message);
      switch (message.type) {
        case "GET_SETTINGS": return { ok: true, settings: structuredClone(settings) };
        case "GET_RUNTIME_STATUS": return { ok: true, runtime: { enabled: true } };
        case "CHECK_STREAMING_HEALTH": return health();
        case "SET_MASTER_ENABLED":
          settings = { ...settings, enabled: message.enabled };
          return { ok: true, settings: structuredClone(settings), runtime: { enabled: message.enabled } };
        case "UPDATE_SETTINGS":
          settings = { ...settings, ...message.patch, layers: { ...settings.layers, ...message.patch.layers } };
          return { ok: true, settings: structuredClone(settings) };
        case "ANALYZE_PROMPT": return { ok: true, response: await analysis };
        default: assert.fail(`Unexpected message ${message.type}`);
      }
    },
  });
  return { element, messages, timers, settings: () => settings,
    click: (key) => element(key).listeners.click({ currentTarget: element(key) }),
    analyse: async (response) => { analysis = response; element("#prompt").value = "Example"; await element("#analyze").listeners.click(); },
  };
}

test("LLM stays disabled while health is pending and after an unavailable response", async () => {
  let resolveHealth;
  const ui = harness({ health: () => new Promise((resolve) => { resolveHealth = resolve; }) });
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  resolveHealth({ ok: false });
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  assert.equal(ui.element("llm .layer-copy small").textContent, "Unavailable");
  assert.equal(ui.element("regex").disabled, false);
  assert.equal(ui.settings().layers.llm, true);
  await ui.click("llm");
  assert.equal(ui.messages.some((message) => message.type === "UPDATE_SETTINGS"), false);
});

test("health errors disable an unselected LLM and a later successful check enables it", async () => {
  let available = false;
  const ui = harness({ llm: false, health: async () => {
    if (!available) throw new Error("connection failed");
    return { ok: true };
  } });
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  available = true;
  await ui.timers[0]();
  await flush();
  assert.equal(ui.element("llm").disabled, false);
  assert.equal(ui.element("llm .layer-copy small").textContent, "Streamed");
  await ui.click("llm");
  assert.equal(ui.settings().layers.llm, true);
});

test("master enable refreshes availability and health cannot re-enable controls after master off", async () => {
  let resolveHealth;
  const ui = harness({ enabled: false, health: () => new Promise((resolve) => { resolveHealth = resolve; }) });
  await flush();
  const enabling = ui.click("#master-toggle");
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  await ui.click("#master-toggle");
  resolveHealth({ ok: true });
  await enabling;
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  assert.equal(ui.settings().enabled, false);
});

test("stack changes discard pending checks for the previous destination", async () => {
  let resolveOld;
  let checks = 0;
  const ui = harness({ health: () => ++checks === 1
    ? new Promise((resolve) => { resolveOld = resolve; }) : { ok: false } });
  await flush();
  await ui.click("#stack-toggle");
  resolveOld({ ok: true });
  await flush();
  assert.equal(ui.element("llm").disabled, true);
  assert.equal(ui.element("#server-warning").hidden, false);
});

test("analysis outage disables LLM and renders the actual remaining protection", async () => {
  const ui = harness({ health: async () => ({ ok: true }) });
  await flush();
  assert.equal(ui.element("llm").disabled, false);
  await ui.analyse({ action: "ALLOW", semanticUnavailable: true,
    semanticFallbackLayers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"], semanticFailClosedOnly: false });
  assert.equal(ui.element("llm").disabled, true);
  assert.match(ui.element("#server-warning span").textContent, /regex and NER protection/);
});

test("analysis from the previous server cannot override the new server's health", async () => {
  const ui = harness({ health: async () => ({ ok: true }) });
  await flush();
  let resolveAnalysis;
  const analysing = ui.analyse(new Promise((resolve) => { resolveAnalysis = resolve; }));
  await ui.click("#stack-toggle");
  resolveAnalysis({ action: "ALLOW", semanticUnavailable: true, semanticFallbackLayers: [] });
  await analysing;
  assert.equal(ui.element("llm").disabled, false);
  assert.equal(ui.element("#server-warning").hidden, true);
});
