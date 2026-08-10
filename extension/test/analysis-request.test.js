import assert from "node:assert/strict";
import test from "node:test";
import { requireExplicitLayers } from "../src/analysis-request.js";

test("requires analysis requests to name concrete layers", () => {
  assert.doesNotThrow(() => requireExplicitLayers({
    layers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"],
  }));
  assert.throws(
    () => requireExplicitLayers({}),
    /explicitly specify at least one detection layer/,
  );
  assert.throws(
    () => requireExplicitLayers({ layers: ["DETECTION_LAYER_RUNTIME"] }),
    /unsupported detection layer/,
  );
});
