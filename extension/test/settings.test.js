import assert from "node:assert/strict";
import test from "node:test";
import {
  detectionLayers,
  loadSettings,
  mergeSettings,
  updateSettings,
} from "../src/settings.js";

function memoryStorage(initial = {}) {
  const values = { ...initial };
  return {
    async get(key) { return { [key]: values[key] }; },
    async set(patch) { Object.assign(values, patch); },
  };
}

test("uses safe defaults with streamed LLM disabled", async () => {
  const settings = await loadSettings(memoryStorage());
  assert.equal(settings.enabled, true);
  assert.deepEqual(settings.layers, { regex: true, ner: true, llm: false });
  assert.deepEqual(detectionLayers(settings), [
    "DETECTION_LAYER_REGEX",
    "DETECTION_LAYER_NER",
  ]);
});

test("persists the master enabled state", async () => {
  const storage = memoryStorage();
  await updateSettings({ enabled: false }, storage);
  assert.equal((await loadSettings(storage)).enabled, false);
});

test("merges partial layer settings without resetting other layers", () => {
  const settings = mergeSettings(
    { layers: { regex: true, ner: true, llm: false }, waitForRegex: true, modelId: "base" },
    { layers: { llm: true } },
  );
  assert.deepEqual(settings.layers, { regex: true, ner: true, llm: true });
});

test("persists model and regex ordering settings", async () => {
  const storage = memoryStorage();
  const settings = await updateSettings(
    { waitForRegex: false, modelId: "privoke-research-v2" },
    storage,
  );
  assert.equal(settings.waitForRegex, false);
  assert.equal(settings.modelId, "privoke-research-v2");
  assert.deepEqual(await loadSettings(storage), settings);
});
