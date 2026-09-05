import assert from "node:assert/strict";
import test from "node:test";
import {
  detectionLayers,
  loadSettings,
  mergeSettings,
  semanticModelId,
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
  assert.equal(settings.useLocalStack, false);
  assert.deepEqual(settings.layers, { regex: true, ner: true, llm: false });
  assert.equal(settings.modelQuality, "latest");
  assert.equal(semanticModelId(settings), "");
  assert.deepEqual(detectionLayers(settings), [
    "DETECTION_LAYER_REGEX",
    "DETECTION_LAYER_NER",
  ]);
});

test("persists the hidden stack switch and rejects non-boolean values", async () => {
  const storage = memoryStorage();
  await updateSettings({ useLocalStack: true }, storage);
  assert.equal((await loadSettings(storage)).useLocalStack, true);
  await updateSettings({ modelQuality: "quality" }, storage);
  assert.equal((await loadSettings(storage)).useLocalStack, true);
  await updateSettings({ useLocalStack: "true" }, storage);
  assert.equal((await loadSettings(storage)).useLocalStack, false);
});

test("persists the master enabled state", async () => {
  const storage = memoryStorage();
  await updateSettings({ enabled: false }, storage);
  assert.equal((await loadSettings(storage)).enabled, false);
});

test("merges partial layer settings without resetting other layers", () => {
  const settings = mergeSettings(
    { layers: { regex: true, ner: true, llm: false }, waitForRegex: true, modelQuality: "latest" },
    { layers: { llm: true } },
  );
  assert.deepEqual(settings.layers, { regex: true, ner: true, llm: true });
});

test("persists model quality and regex ordering settings", async () => {
  const storage = memoryStorage();
  const settings = await updateSettings(
    { waitForRegex: false, modelQuality: "quality" },
    storage,
  );
  assert.equal(settings.waitForRegex, false);
  assert.equal(settings.modelQuality, "quality");
  assert.equal(semanticModelId(settings), "privoke-quality");
  assert.deepEqual(await loadSettings(storage), settings);
});

test("migrates the old balanced model ID and rejects unknown qualities", async () => {
  const migrated = await loadSettings(memoryStorage({
    privokeSettings: { modelId: "privoke-balanced", modelQuality: "unknown" },
  }));
  assert.equal(migrated.modelQuality, "balanced");
  assert.equal(semanticModelId(migrated), "privoke-balanced");
});
