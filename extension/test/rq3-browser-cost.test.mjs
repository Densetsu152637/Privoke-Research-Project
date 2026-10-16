import test from "node:test";
import assert from "node:assert/strict";
import { summarizeTiming, RQ3_MODES } from "./rq3-browser-cost.mjs";

test("timing summaries retain blocking and forwarding denominators", () => {
  const summary = summarizeTiming([
    { totalMs: 4, receiverCaptures: [{}], action: "ALLOW" },
    { totalMs: 2, receiverCaptures: [], action: "BLOCK" },
    { totalMs: 8, receiverCaptures: [{}], action: "WARN" },
  ]);
  assert.deepEqual(summary, { n: 3, p50: 4, p95: 8, max: 8, forwarded: 2, blocked: 1 });
  assert.throws(() => summarizeTiming([{ totalMs: NaN }]));
});

test("detector bypass is explicit and selected arms never use empty runtime layer lists", () => {
  assert.equal(RQ3_MODES[0].expected, null);
  assert.deepEqual(Object.values(RQ3_MODES[0].layers), [false, false, false]);
  assert.equal(RQ3_MODES.slice(1).every((mode) => mode.expected.length > 0), true);
  assert.deepEqual(RQ3_MODES[2].expected, ["DETECTION_LAYER_SEMANTIC"]);
});
