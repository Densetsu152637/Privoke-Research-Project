const EXPLICIT_DETECTION_LAYERS = new Set([
  "DETECTION_LAYER_REGEX",
  "DETECTION_LAYER_NER",
  "DETECTION_LAYER_SEMANTIC",
]);

export function requireExplicitLayers(values) {
  if (!Array.isArray(values?.layers) || values.layers.length === 0) {
    throw new Error("Analysis requests must explicitly specify at least one detection layer.");
  }
  const unsupported = values.layers.find((layer) => !EXPLICIT_DETECTION_LAYERS.has(layer));
  if (unsupported) {
    throw new Error(`Analysis request contains an unsupported detection layer: ${unsupported}.`);
  }
}
