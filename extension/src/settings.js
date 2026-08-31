import { localStorageArea, storageGet, storageSet } from "./webextension-api.js";

export const MODEL_QUALITY = Object.freeze({
  LATEST: "latest",
  EFFICIENT: "efficient",
  BALANCED: "balanced",
  QUALITY: "quality",
});

const MODEL_IDS = Object.freeze({
  // Empty means "do not pin"; the runtime follows its configured latest channel.
  [MODEL_QUALITY.LATEST]: "",
  [MODEL_QUALITY.EFFICIENT]: "privoke-efficient",
  [MODEL_QUALITY.BALANCED]: "privoke-balanced",
  [MODEL_QUALITY.QUALITY]: "privoke-quality",
});

export const DEFAULT_SETTINGS = Object.freeze({
  enabled: true,
  layers: Object.freeze({ regex: true, ner: true, llm: false }),
  waitForRegex: true,
  modelQuality: MODEL_QUALITY.LATEST,
});

const STORAGE_KEY = "privokeSettings";
const MODEL_QUALITIES = new Set(Object.values(MODEL_QUALITY));

export function normaliseSettings(value = {}) {
  const layers = value.layers ?? {};
  const modelQuality = normaliseModelQuality(value);

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
    modelQuality,
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

export function semanticModelId(settings) {
  return MODEL_IDS[settings.modelQuality] ?? MODEL_IDS[DEFAULT_SETTINGS.modelQuality];
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

function normaliseModelQuality(value) {
  if (MODEL_QUALITIES.has(value.modelQuality)) return value.modelQuality;

  // Migrate settings saved before model quality profiles were introduced.
  const legacyModelId = typeof value.modelId === "string" ? value.modelId.trim() : "";
  const migrated = Object.entries(MODEL_IDS).find(([, modelId]) => modelId === legacyModelId);
  return migrated?.[0] ?? DEFAULT_SETTINGS.modelQuality;
}
