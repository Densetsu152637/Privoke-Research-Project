import assert from "node:assert/strict";
import test from "node:test";
import { SemanticAvailability } from "../src/semantic-availability.js";

test("temporarily omits unavailable semantic analysis and restores it after reconnect", async () => {
  let now = 0;
  let available = false;
  let checks = 0;
  const state = new SemanticAvailability(async () => {
    checks += 1;
    return { ok: available };
  }, () => now);
  const layers = ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER", "DETECTION_LAYER_SEMANTIC"];

  const offline = await state.selectLayers(layers);
  assert.deepEqual(offline.layers, layers.slice(0, 2));
  assert.equal(offline.unavailable, true);
  assert.equal(offline.transition, "unavailable");
  assert.deepEqual(offline.fallbackLayers, layers.slice(0, 2));
  assert.equal(offline.failClosedOnly, false);

  const cached = await state.selectLayers(layers);
  assert.deepEqual(cached.layers, layers.slice(0, 2));
  assert.equal(cached.transition, null);
  assert.equal(checks, 1);

  available = true;
  now = 5_001;
  const recovered = await state.selectLayers(layers);
  assert.deepEqual(recovered.layers, layers);
  assert.equal(recovered.unavailable, false);
  assert.equal(recovered.transition, "available");
  assert.equal(checks, 2);
});

test("does not probe or change an explicitly disabled semantic layer", async () => {
  let checks = 0;
  const state = new SemanticAvailability(async () => {
    checks += 1;
    return { ok: false };
  });

  const result = await state.selectLayers(["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"]);
  assert.deepEqual(result.layers, ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"]);
  assert.equal(result.unavailable, false);
  assert.equal(checks, 0);
});

test("keeps semantic as the only selected layer when unavailable to preserve fail-closed behavior", async () => {
  const state = new SemanticAvailability(async () => ({ ok: false }));
  const layers = ["DETECTION_LAYER_SEMANTIC"];

  const result = await state.selectLayers(layers);
  assert.deepEqual(result.layers, layers);
  assert.equal(result.unavailable, true);
  assert.deepEqual(result.fallbackLayers, []);
  assert.equal(result.failClosedOnly, true);
});
