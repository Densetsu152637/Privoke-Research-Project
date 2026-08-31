import { localStorageArea, storageGet, storageSet } from "./webextension-api.js";

export const DEFAULT_SETTINGS = Object.freeze({
  enabled: true,
  layers: Object.freeze({ regex: true, ner: true, llm: false }),
  waitForRegex: true,
  modelId: "privoke-baseline",
});

const STORAGE_KEY = "privokeSettings";
const MAX_MODEL_ID_LENGTH = 128;

export function normaliseSettings(value = {}) {
  const layers = value.layers ?? {};
  const modelId = typeof value.modelId === "string"
    ? value.modelId.trim().slice(0, MAX_MODEL_ID_LENGTH)
    : "";

  return {
    enabled: booleanOrDefault(value.enabled, DEFAULT_SETTINGS.enabled),
    layers: {
      regex: booleanOrDefault(layers.regex, DEFAULT_SETTINGS.layers.regex),
      ner: booleanOrDefault(layers.ner, DEFAULT_SETTINGS.layers.ner),
      llm: booleanOrDefault(layers.llm, DEFAULT_SETTINGS.layers.llm),
    },
    waitForRegex: booleanOrDefault(
      value.waitForRegex,
      DEFAULT_SETTINGS.waitForRegex,
    ),
    modelId: modelId || DEFAULT_SETTINGS.modelId,
  };
}

export function mergeSettings(current, patch) {
  return normaliseSettings({
    ...current,
    ...patch,
    layers: { ...current?.layers, ...patch?.layers },
  });
}

export function detectionLayers(settings) {
  const layers = [];
  if (settings.layers.regex) layers.push("DETECTION_LAYER_REGEX");
  if (settings.layers.ner) layers.push("DETECTION_LAYER_NER");
  if (settings.layers.llm) layers.push("DETECTION_LAYER_SEMANTIC");
  return layers;
}

export async function loadSettings(storage = localStorageArea()) {
  const stored = await storageGet(storage, STORAGE_KEY);
  return normaliseSettings(stored[STORAGE_KEY]);
}

export async function updateSettings(patch, storage = localStorageArea()) {
  const current = await loadSettings(storage);
  const settings = mergeSettings(current, patch);
  await storageSet(storage, { [STORAGE_KEY]: settings });
  return settings;
}

function booleanOrDefault(value, fallback) {
  return typeof value === "boolean" ? value : fallback;
}
