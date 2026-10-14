import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { assertAdditionalProbe, assertSequentialRpc } from "./installed-browser-additional.mjs";
const layers = ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER", "DETECTION_LAYER_SEMANTIC"];
const text = "Please explain the steps in this process.";
const body = JSON.stringify({ messages: [{ role: "user", content: text }] });
function fixture() {
  return { record: { caseId: "case", url: "https://chatgpt.com/backend-api/conversation?case_id=case", body,
    analyses: [{ phase: "start" }, { phase: "result", action: "ALLOW" }] },
    captures: [{ path: "/backend-api/conversation?case_id=case", bodyBase64: Buffer.from(body).toString("base64"),
      bodySha256: createHash("sha256").update(body).digest("hex") }],
    rpc: { request: { layers, text, source: "browser_interceptor", targetApp: "chatgpt", requestId: "runtime" },
      grpcStatus: 0, response: { decoded: { requestId: "runtime", action: "ALLOW", error: "",
        layers: layers.map((layer) => ({ layer, status: "ok", error: "" })) } } },
    expectedLayers: layers, expectedForwarded: true, requireSuccess: true };
}
test("additional full path requires actual complete layer execution and unchanged receiver bytes", () => {
  assertAdditionalProbe(fixture());
  const omitted = fixture(); omitted.rpc.request.layers = [];
  assert.throws(() => assertAdditionalProbe(omitted), /requested layers/);
  const fallback = fixture(); fallback.rpc.response.decoded.layers.pop();
  assert.throws(() => assertAdditionalProbe(fallback));
  const failed = fixture(); failed.rpc.response.decoded.layers[2].status = "error";
  assert.throws(() => assertAdditionalProbe(failed), /successfully/);
  const modified = fixture(); modified.captures[0].bodyBase64 = Buffer.from("changed").toString("base64");
  assert.throws(() => assertAdditionalProbe(modified), /deep-equal/);
});
test("zero forwarding assertion rejects a delayed post-cancellation receiver send", () => {
  const cancelled = fixture(); cancelled.requireSuccess = false; cancelled.expectedForwarded = false;
  cancelled.captures = [];
  assertAdditionalProbe(cancelled);
  cancelled.captures = fixture().captures;
  assert.throws(() => assertAdditionalProbe(cancelled), /receiver count/);
});

test("sequential probe binding rejects earlier, pending and reused actual RPC identities", () => {
  const record = { preProbeQuiescentAtMonotonicMs: 10, postProbeQuiescentAtMonotonicMs: 30 };
  const rpc = { request: { requestId: "runtime-1" }, networkRequestId: "network-1",
    requestObservedAtMonotonicMs: 12, terminalObservedAtMonotonicMs: 20 };
  const runtimeIds = new Set(); const networkIds = new Set();
  assertSequentialRpc(rpc, record, runtimeIds, networkIds);
  assert.throws(() => assertSequentialRpc(rpc, record, runtimeIds, networkIds), /unique/);
  assert.throws(() => assertSequentialRpc({ ...rpc, requestObservedAtMonotonicMs: 9 }, record, new Set(), new Set()), /before/);
  assert.throws(() => assertSequentialRpc({ ...rpc, terminalObservedAtMonotonicMs: 31 }, record, new Set(), new Set()), /outside/);
  assert.throws(() => assertSequentialRpc({ ...rpc, terminalObservedAtMonotonicMs: 11 }, record, new Set(), new Set()), /outside/);
});
