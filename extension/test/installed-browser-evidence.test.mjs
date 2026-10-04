import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  assertNativeParentBinding,
  assertCompleteResourceEvidence,
  assertPreservedControlSupervisor,
  assertReceiverCapture,
  frameGrpcWebMessage,
  parseGrpcWebFrames,
  preserveResourceEvidenceFailure,
  summarizeSupervisorStartupLog,
  mountEvidenceForPath,
  validateAnalyzeRequest,
  validateAnalyzeResponse,
  validateDecodedOutcome,
  validatePageAnalysis,
  waitForProcessesToDisappear,
} from "./installed-browser-evidence.mjs";

test("supervisor startup diagnostics retain bounded traceback identity without exception text", () => {
  const log = Buffer.from([
    "Traceback (most recent call last):",
    '  File "/workspace/extension/runtime-supervisor/src/main.py", line 17, in <module>',
    "    import private_fake_prompt_value",
    "ModuleNotFoundError: No module named 'fake_dependency'",
    "private_fake_prompt_value",
  ].join("\n"));
  const summary = summarizeSupervisorStartupLog(log);
  assert.equal(summary.containsTraceback, true);
  assert.equal(summary.exceptionType, "ModuleNotFoundError");
  assert.equal(summary.missingModule, "fake_dependency");
  assert.deepEqual(summary.tracebackFrames, [{ file: "main.py", line: 17, function: "<module>" }]);
  assert.equal(summary.sha256.length, 64);
  assert.equal(JSON.stringify(summary).includes("private_fake_prompt_value"), false);
  assert.equal(JSON.stringify(summary).includes("No module named"), false);

  const bounded = summarizeSupervisorStartupLog(Buffer.alloc(40, 65), 16);
  assert.equal(bounded.capturedBytes, 16);
  assert.equal(bounded.truncated, true);
  assert.equal(bounded.exceptionType, null);
});

test("native launcher mount evidence identifies noexec without exposing mount sources", () => {
  const mounts = "42 1 0:1 / / rw,relatime - overlay overlay rw\n"
    + "43 42 0:2 / /tmp rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw";
  assert.deepEqual(mountEvidenceForPath("/tmp/privoke/native/launcher", mounts), {
    mountPoint: "/tmp", fsType: "tmpfs", noExec: true, readOnly: false,
  });
  assert.deepEqual(mountEvidenceForPath("/workspace/host", mounts), {
    mountPoint: "/", fsType: "overlay", noExec: false, readOnly: false,
  });
});

test("strict gRPC-Web framing accepts one request and one response plus final trailers", () => {
  const request = Buffer.from("request");
  const response = Buffer.from("response");
  const trailer = Buffer.from("grpc-status: 0\r\n");
  const trailerFrame = Buffer.concat([Buffer.from([0x80]), Buffer.from([0, 0, 0, trailer.length]), trailer]);
  assert.deepEqual(parseGrpcWebFrames(frameGrpcWebMessage(request), "request").data, [request]);
  const parsed = parseGrpcWebFrames(Buffer.concat([frameGrpcWebMessage(response), trailerFrame]), "response");
  assert.deepEqual(parsed.data, [response]);
  assert.equal(parsed.grpcStatus, 0);
  const status16 = Buffer.from("grpc-status: 16\r\n");
  const status16Frame = Buffer.concat([Buffer.from([0x80, 0, 0, 0, status16.length]), status16]);
  assert.equal(parseGrpcWebFrames(status16Frame, "response").grpcStatus, 16);
});

test("strict gRPC-Web framing rejects truncation, duplicate/extra frames, and malformed trailers", () => {
  const trailer = Buffer.from("grpc-status: 0\r\n");
  const frame = Buffer.concat([Buffer.from([0x80, 0, 0, 0, trailer.length]), trailer]);
  assert.throws(() => parseGrpcWebFrames(Buffer.from([0, 0, 0]), "request"), /truncated/);
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([frameGrpcWebMessage(Buffer.from("x")), frameGrpcWebMessage(Buffer.from("y"))]), "request"), /exactly one/);
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([frame, frame]), "response"), /final frame/);
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([frame, frameGrpcWebMessage(Buffer.from("x"))]), "response"), /final frame/);
  const dataThenTrailer = Buffer.concat([frameGrpcWebMessage(Buffer.from("x")), frameGrpcWebMessage(Buffer.from("y")), frame]);
  assert.throws(() => parseGrpcWebFrames(dataThenTrailer, "response"), /extra data frames/);
  const duplicate = Buffer.from("grpc-status: 0\r\ngrpc-status: 0\r\n");
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([Buffer.from([0x80, 0, 0, 0, duplicate.length]), duplicate]), "response"), /duplicate/);
  const missing = Buffer.from("content-type: application/grpc-web+proto\r\n");
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([Buffer.from([0x80, 0, 0, 0, missing.length]), missing]), "response"), /omitted grpc-status/);
  const outOfRange = Buffer.from("grpc-status: 17\r\n");
  assert.throws(() => parseGrpcWebFrames(Buffer.concat([Buffer.from([0x80, 0, 0, 0, outOfRange.length]), outOfRange]), "response"), /canonical gRPC status range/);
});

test("decoded response validation requires concrete request, response, layer and timing evidence", () => {
  const request = { requestId: "rpc-1", text: "fake prompt", source: "browser_interceptor", targetApp: "chatgpt",
    layers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"] };
  const response = { requestId: "rpc-1", action: "ALLOW", error: "", elapsedMs: 0,
    layers: [{ layer: "DETECTION_LAYER_REGEX", status: "ok", error: "" },
      { layer: "DETECTION_LAYER_NER", status: "ok", error: "" }] };
  validateAnalyzeRequest(request, { text: request.text });
  validateAnalyzeResponse(response, request, "ALLOW");
  const rpc = { request, response: { decoded: response }, responseBytesPresent: true, grpcStatus: 0,
    loadingFailure: null, decodeError: null };
  validateDecodedOutcome(rpc, { prompt: request.text, action: "ALLOW" });
  assert.throws(() => validateDecodedOutcome({ ...rpc, responseBytesPresent: false }, { prompt: request.text, action: "ALLOW" }), /bytes are missing/);
  assert.throws(() => validateDecodedOutcome({ ...rpc, response: null }, { prompt: request.text, action: "ALLOW" }), /did not decode/);
  assert.throws(() => validateDecodedOutcome({ ...rpc, response: null, grpcStatus: 14,
    responseBytesPresent: false }, { prompt: request.text, action: "BLOCK", allowGrpcError: true }), /trailer bytes are missing/);
  assert.throws(() => validateAnalyzeResponse({ ...response, elapsedMs: Number.NaN }, request, "ALLOW"), /finite/);
  const missingElapsed = { ...response };
  delete missingElapsed.elapsedMs;
  assert.throws(() => validateAnalyzeResponse(missingElapsed, request, "ALLOW"), /finite/);
  assert.throws(() => validateAnalyzeResponse({ ...response, error: "failure" }, request, "ALLOW"), /application error/);
});

test("only the runtime's documented regex BLOCK skip can omit NER", () => {
  const request = { requestId: "rpc-block", text: "fake prompt", source: "browser_interceptor", targetApp: "chatgpt",
    layers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"] };
  const valid = { requestId: request.requestId, action: "BLOCK", error: "", elapsedMs: 0, layers: [
    { layer: "DETECTION_LAYER_REGEX", status: "ok", error: "", results: [{ action: "BLOCK" }] },
    { layer: "DETECTION_LAYER_NER", status: "skipped", error: "Skipped after regex returned BLOCK.", results: [] },
  ] };
  validateAnalyzeResponse(valid, request, "BLOCK");
  assert.throws(() => validateAnalyzeResponse({ ...valid, layers: [valid.layers[0],
    { ...valid.layers[1], error: "some other skip" }] }, request, "BLOCK"), /documented regex/);
  assert.throws(() => validateAnalyzeResponse({ ...valid, layers: [
    { ...valid.layers[0], results: [{ action: "WARN" }] }, valid.layers[1]] }, request, "BLOCK"), /concrete BLOCK/);
  assert.throws(() => validateAnalyzeResponse({ ...valid, action: "ALLOW" }, request, "BLOCK"), /strictly equal/);
});

test("master-off preserves the known control supervisor and exactly its control listeners", () => {
  const expected = { pid: 20, startTicks: 200, commandSha256: "supervisor" };
  assertPreservedControlSupervisor(expected, { ...expected }, [50056, 8080]);
  assert.throws(() => assertPreservedControlSupervisor(expected, { ...expected, pid: 21 }, [8080, 50056]), /PID changed/);
  assert.throws(() => assertPreservedControlSupervisor(expected, { ...expected, startTicks: 201 }, [8080, 50056]), /reused/);
  assert.throws(() => assertPreservedControlSupervisor(expected, { ...expected }, [8080, 50056, 50057]), /listeners/);
});

test("required resource evidence rejects partial RSS, CPU, and start-tick samples but keeps PSS optional", () => {
  const valid = {
    cgroupMemorySampledPeakBytes: 1024,
    cgroupCpuSampledDeltaUsec: 50,
    cgroupMemoryMissingSamples: 0,
    cgroupCpuMissingSamples: 0,
    processes: ["xvfb", "chromium", "supervisor_bridge", "detector"].map((role) => ({
      role, startTicks: 100, sampledPeakRssBytes: 4096, sampledPeakPssBytes: null, cpuDeltaSeconds: 0.1,
      missingRssSamples: 0, missingCpuSamples: 0, missingStartTicksSamples: 0,
    })),
  };
  assert.equal(assertCompleteResourceEvidence(valid), valid);
  for (const field of ["missingRssSamples", "missingCpuSamples", "missingStartTicksSamples"]) {
    const partial = structuredClone(valid);
    partial.processes[0][field] = 1;
    assert.throws(() => assertCompleteResourceEvidence(partial), /missing/);
  }
  const missingCgroupCpu = structuredClone(valid);
  missingCgroupCpu.cgroupCpuMissingSamples = 1;
  assert.throws(() => assertCompleteResourceEvidence(missingCgroupCpu), /cgroup CPU samples are incomplete/);
});

test("resource validation failure preserves partial aggregates, counters, and construction fallback", () => {
  const partial = {
    cgroupMemorySampledPeakBytes: 1024,
    cgroupCpuSampledDeltaUsec: 50,
    cgroupMemoryMissingSamples: 0,
    cgroupCpuMissingSamples: 0,
    processes: [{ role: "chromium", pid: 33, sampledPeakRssBytes: 4096, sampledPeakPssBytes: null,
      missingRssSamples: 2, missingCpuSamples: 1, missingStartTicksSamples: 0 }],
  };
  const failure = { type: "AssertionError", message: "chromium has missing RSS samples" };
  const receiptEvidence = preserveResourceEvidenceFailure(partial, failure);
  assert.deepEqual(receiptEvidence.cgroupMemorySampledPeakBytes, 1024);
  assert.deepEqual(receiptEvidence.cgroupCpuSampledDeltaUsec, 50);
  assert.deepEqual(receiptEvidence.processes, partial.processes);
  assert.equal(receiptEvidence.processes[0].sampledPeakPssBytes, null);
  assert.equal(receiptEvidence.processes[0].missingRssSamples, 2);
  assert.equal(receiptEvidence.processes[0].missingCpuSamples, 1);
  assert.deepEqual(receiptEvidence.validationError, failure);

  const constructionFailure = preserveResourceEvidenceFailure(undefined, failure);
  assert.deepEqual(constructionFailure, { error: failure });
});

test("profile cleanup waiter observes disappearance and fails closed on timeout", async () => {
  let now = 0;
  let scans = 0;
  const didDisappear = await waitForProcessesToDisappear(async () => {
    scans += 1;
    return scans === 1 ? [{ pid: 23, startTicks: 55, commandSha256: "known-profile" }] : [];
  }, { timeoutMs: 100, intervalMs: 50, now: () => now, sleep: async (ms) => { now += ms; } });
  assert.equal(didDisappear, true);
  assert.equal(scans, 2);

  now = 0;
  await assert.rejects(waitForProcessesToDisappear(async () => [{ pid: 23, startTicks: 55 }], {
    timeoutMs: 100, intervalMs: 50, now: () => now, sleep: async (ms) => { now += ms; },
  }), /identities remained/);
});

test("study starts only after the CDP observer class has initialized", async () => {
  const runnerUrl = new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url);
  const source = await readFile(runnerUrl, "utf8");
  const observerPosition = source.indexOf("class CdpObserver");
  const startupPosition = source.lastIndexOf("await runStudy();");
  assert.ok(observerPosition >= 0);
  assert.ok(startupPosition > observerPosition, "study invocation must follow lexical class initialization");
  assert.equal((source.match(/await runStudy\(\);/g) || []).length, 1, "study must start exactly once");
});

test("page result and receiver body must bind to the frozen case", () => {
  const seen = new Set();
  const entries = [
    { phase: "start", caseId: "case-1", requestId: "page-1", prompt: "fake prompt" },
    { phase: "result", caseId: "case-1", requestId: "page-1", prompt: "fake prompt", action: "ALLOW", decisionMs: 0 },
  ];
  assert.equal(validatePageAnalysis(entries, { caseId: "case-1", prompt: "fake prompt", expectedAction: "ALLOW", seenIds: seen }).requestId, "page-1");
  assert.throws(() => validatePageAnalysis(entries.map((item) => item.phase === "result"
    ? { ...item, requestId: "wrong" } : item),
    { caseId: "case-1", prompt: "fake prompt", expectedAction: "ALLOW", seenIds: new Set() }), /request ID differs/);
  const expectedUrl = "https://chatgpt.com:8443/?case=1";
  const bytes = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: "fake prompt" }] }));
  const capture = { method: "POST", path: "/?case=1", bodyBase64: bytes.toString("base64"),
    bodySha256: createHash("sha256").update(bytes).digest("hex") };
  assertReceiverCapture(capture, { expectedUrl, prompt: "fake prompt" });
  assert.throws(() => assertReceiverCapture({ ...capture, path: "/?case=2" }, { expectedUrl, prompt: "fake prompt" }), /path\/query/);
});

test("native host parent evidence matches browser PID and start ticks", () => {
  assert.equal(assertNativeParentBinding([{ pid: 10, ppid: 1, parent_start_ticks: 4 }],
    [{ pid: 1, start_ticks: 4 }]), true);
  assert.equal(assertNativeParentBinding([{ pid: 10, ppid: 1, parent_start_ticks: 5 }],
    [{ pid: 1, start_ticks: 4 }]), false);
});

test("generated runtime protobuf exposes the actual camelCase request and response fields", async (context) => {
  const generatedPath = new URL("../src/generated/runtime.js", import.meta.url);
  if (!existsSync(generatedPath)) {
    if (process.env.PRIVOKE_INSTALLED_EVIDENCE_IN_CONTAINER === "true") {
      assert.fail("Docker build did not generate the runtime protobuf codec");
    }
    context.skip("generated runtime protobuf is omitted from the source checkout");
    return;
  }
  let generated;
  try { generated = await import(generatedPath.href); }
  catch (error) {
    if (process.env.PRIVOKE_INSTALLED_EVIDENCE_IN_CONTAINER === "true") throw error;
    if (error?.code === "ERR_MODULE_NOT_FOUND") {
      context.skip("extension npm dependencies are omitted from the source checkout");
      return;
    }
    throw error;
  }
  const api = generated.privoke.v1;
  const request = api.AnalyzePromptRequest.fromObject({ requestId: "rpc-2", text: "fake prompt",
    source: "browser_interceptor", targetApp: "chatgpt", layers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"] });
  const decodedRequest = api.AnalyzePromptRequest.toObject(api.AnalyzePromptRequest.decode(api.AnalyzePromptRequest.encode(request).finish()),
    { enums: String, defaults: true, arrays: true });
  assert.equal(decodedRequest.requestId, "rpc-2");
  assert.equal(decodedRequest.targetApp, "chatgpt");
  const response = api.AnalyzePromptResponse.fromObject({ requestId: "rpc-2", action: "ALLOW", elapsedMs: 0,
    layers: [{ layer: "DETECTION_LAYER_REGEX", status: "ok" }, { layer: "DETECTION_LAYER_NER", status: "ok" }] });
  const decodedResponse = api.AnalyzePromptResponse.toObject(api.AnalyzePromptResponse.decode(api.AnalyzePromptResponse.encode(response).finish()),
    { enums: String, defaults: true, arrays: true });
  assert.equal(decodedResponse.requestId, "rpc-2");
  assert.equal(decodedResponse.elapsedMs, 0);
  assert.equal(decodedResponse.action, "ALLOW");
  const control = api.RuntimeControlStatus.fromObject({ enabled: true, status: "RUNNING", message: "ready", processId: 42 });
  const decodedControl = api.RuntimeControlStatus.toObject(
    api.RuntimeControlStatus.decode(api.RuntimeControlStatus.encode(control).finish()), { defaults: true });
  assert.equal(decodedControl.processId, 42);
});
