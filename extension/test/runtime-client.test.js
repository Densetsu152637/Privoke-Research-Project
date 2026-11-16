import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { privoke } from "../src/generated/runtime.js";
import { ANALYSIS_TIMEOUT_MS, RESPONSE_TIMEOUT_MS, STREAMING_HEALTH_TIMEOUT_MS } from "../src/analysis-timeouts.js";
import { NativePortTransport, fromBase64, toBase64 } from "../src/native-port-transport.js";
import { collectMaskSpans } from "../src/redaction.js";
import { RuntimeClient } from "../src/runtime-client.js";

const v1 = privoke.v1;

// A controller in miniature: a port that decodes the envelope with the extension's own codec and answers with real
// runtime messages, the way the Rust controller does.
function controllerPort(answer) {
  const port = {
    requests: [],
    messageListeners: [],
    disconnectListeners: [],
    onMessage: { addListener: (listener) => port.messageListeners.push(listener) },
    onDisconnect: { addListener: (listener) => port.disconnectListeners.push(listener) },
    disconnect() {},
    postMessage(message) {
      port.requests.push(message);
      const reply = answer(message, fromBase64(message.payload));
      if (reply === undefined) return;
      queueMicrotask(() => {
        for (const listener of port.messageListeners) listener({ v: 1, id: message.id, ...reply });
      });
    },
  };
  return port;
}

function clientFor(port) {
  return new RuntimeClient(new NativePortTransport({ connect: () => port }));
}

const ok = (type, values) => ({ ok: true, payload: toBase64(type.encode(type.fromObject(values)).finish()) });

test("analyzePrompt sends the same AnalyzePromptRequest message and decodes the same response shape", async () => {
  const port = controllerPort((message, payload) => {
    assert.equal(message.method, "AnalyzePrompt");
    const request = v1.AnalyzePromptRequest.decode(payload);
    assert.equal(request.text, "email me at a@b.example");
    assert.deepEqual(request.layers, [v1.DetectionLayer.DETECTION_LAYER_REGEX, v1.DetectionLayer.DETECTION_LAYER_NER]);
    assert.equal(request.requestId, "req-1");
    return ok(v1.AnalyzePromptResponse, { requestId: request.requestId, action: "BLOCK", allowed: false, elapsedMs: 12.5 });
  });
  const response = await clientFor(port).analyzePrompt({
    text: "email me at a@b.example",
    requestId: "req-1",
    layers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"],
    regexExecutionOrder: "REGEX_EXECUTION_ORDER_PARALLEL",
  });
  assert.equal(response.action, "BLOCK");
  assert.equal(response.allowed, false);
  assert.equal(response.requestId, "req-1");
  assert.equal(response.elapsedMs, 12.5);
  assert.deepEqual(response.layers, [], "defaults and empty arrays are present, as the gRPC-Web client returned them");
});

test("WARN with located findings keeps its spans through the native transport, so WARN+MASK still masks", async () => {
  const located = (start, end) => ({
    classification: { sensitivity: "S2", visibility: "PR", categories: ["CONTACT"] },
    action: "WARN",
    hasSpan: true,
    spanStart: start,
    spanEnd: end,
  });
  const port = controllerPort(() => ok(v1.AnalyzePromptResponse, {
    action: "WARN",
    allowed: true,
    layers: [{ layer: "DETECTION_LAYER_REGEX", status: "ok", results: [located(11, 22)] }],
  }));
  const response = await clientFor(port).analyzePrompt({ text: "write to me a@b.example", layers: ["DETECTION_LAYER_REGEX"] });
  assert.equal(response.action, "WARN");
  assert.deepEqual(collectMaskSpans(response), [{ start: 11, end: 22, categories: ["CONTACT"] }]);
});

test("an analysis without an explicit layer selection is refused before anything is sent", async () => {
  const port = controllerPort(() => assert.fail("nothing may be sent"));
  const client = clientFor(port);
  await assert.rejects(client.analyzePrompt({ text: "x" }), /explicitly specify at least one detection layer/);
  await assert.rejects(client.analyzePrompt({ text: "x", layers: [] }), /explicitly specify/);
  await assert.rejects(client.analyzePrompt({ text: "x", layers: ["DETECTION_LAYER_RUNTIME"] }), /unsupported detection layer/);
  assert.deepEqual(port.requests, []);
});

test("control calls use the runtime control messages and the same method semantics", async () => {
  const port = controllerPort((message, payload) => {
    if (message.method === "SetRuntimeEnabled") {
      const request = v1.SetRuntimeEnabledRequest.decode(payload);
      assert.equal(request.enabled, true);
      assert.equal(request.useLocalStack, true);
      return ok(v1.RuntimeControlStatus, { enabled: true, status: "RUNNING", message: "Client runtime started.", processId: 77 });
    }
    if (message.method === "Status") return ok(v1.RuntimeControlStatus, { enabled: false, status: "STOPPED" });
    if (message.method === "ModelStreamingHealth") return ok(v1.RuntimeHealthResponse, { service: "model-streaming-service", status: "SERVING" });
    return { ok: false, code: "UNIMPLEMENTED", message: message.method };
  });
  const client = clientFor(port);
  const started = await client.setRuntimeEnabled(true, { useLocalStack: true });
  assert.deepEqual({ enabled: started.enabled, status: started.status, processId: started.processId }, { enabled: true, status: "RUNNING", processId: 77 });
  assert.equal((await client.runtimeStatus()).status, "STOPPED");
  assert.deepEqual(await client.streamingHealth(), { service: "model-streaming-service", status: "SERVING" });
  assert.deepEqual(port.requests.map((request) => request.method), ["SetRuntimeEnabled", "Status", "ModelStreamingHealth"]);
});

test("the stack choice is only sent when the caller makes one", async () => {
  const port = controllerPort((message, payload) => {
    const request = v1.SetRuntimeEnabledRequest.decode(payload);
    assert.equal(Object.hasOwn(request, "useLocalStack") && request.useLocalStack !== null, false);
    return ok(v1.RuntimeControlStatus, { enabled: false });
  });
  await clientFor(port).setRuntimeEnabled(false);
});

test("a controller error fails the call with the controller's message", async () => {
  const port = controllerPort(() => ({ ok: false, code: "INVALID_ARGUMENT", message: "INVALID_LAYERS: an empty layer list is refused" }));
  await assert.rejects(clientFor(port).analyzePrompt({ text: "x", layers: ["DETECTION_LAYER_REGEX"] }), /INVALID_LAYERS/);
});

test("a response that is not a runtime message fails the call instead of decoding to a decision", async () => {
  const port = controllerPort(() => ({ ok: true, payload: toBase64(Uint8Array.of(0xff, 0xff, 0xff, 0xff)) }));
  await assert.rejects(clientFor(port).analyzePrompt({ text: "x", layers: ["DETECTION_LAYER_REGEX"] }));
});

test("a controller that never answers ends at the caller's 30 s analysis deadline value, with a TimeoutError", async () => {
  const port = controllerPort(() => undefined);
  const client = clientFor(port);
  // The deadlines themselves are unchanged from the gRPC-Web client; a short signal stands in for them here.
  await assert.rejects(
    client.analyzePrompt({ text: "x", layers: ["DETECTION_LAYER_REGEX"] }, { signal: AbortSignal.timeout(40) }),
    (error) => error.name === "TimeoutError",
  );
  assert.equal(ANALYSIS_TIMEOUT_MS, 30_000);
  assert.equal(RESPONSE_TIMEOUT_MS, STREAMING_HEALTH_TIMEOUT_MS + ANALYSIS_TIMEOUT_MS + 2_000);
  assert.equal(RESPONSE_TIMEOUT_MS, 35_500);
});

test("the background applies the unchanged deadlines to every call it makes", async () => {
  const source = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
  assert.match(source, /analyzePrompt\([\s\S]*AbortSignal\.timeout\(ANALYSIS_TIMEOUT_MS\)/);
  assert.match(source, /streamingHealth\(\{\s*signal: AbortSignal\.timeout\(STREAMING_HEALTH_TIMEOUT_MS\)/);
  assert.match(source, /AbortSignal\.timeout\(15_000\)/);
});

test("the extension no longer speaks to any loopback address", async () => {
  for (const name of ["runtime-client.js", "native-port-transport.js", "background.js", "supervisor-launcher.js"]) {
    const source = await readFile(new URL(`../src/${name}`, import.meta.url), "utf8");
    assert.doesNotMatch(source, /127\.0\.0\.1|localhost|:8080|fetch\(/, name);
  }
  const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
  assert.deepEqual(manifest.host_permissions.filter((pattern) => /127\.0\.0\.1|localhost/.test(pattern)), []);
  assert.ok(manifest.permissions.includes("nativeMessaging"));
});
