import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import test from "node:test";
import {
  assertNativeParentBinding,
  assertReceiverCapture,
  frameGrpcWebMessage,
  parseGrpcWebFrames,
  validateAnalyzeRequest,
  validateAnalyzeResponse,
  validateDecodedOutcome,
  validatePageAnalysis,
} from "./installed-browser-evidence.mjs";

test("strict gRPC-Web framing accepts one request and one response plus final trailers", () => {
  const request = Buffer.from("request");
  const response = Buffer.from("response");
  const trailer = Buffer.from("grpc-status: 0\r\n");
  const trailerFrame = Buffer.concat([Buffer.from([0x80]), Buffer.from([0, 0, 0, trailer.length]), trailer]);
  assert.deepEqual(parseGrpcWebFrames(frameGrpcWebMessage(request), "request").data, [request]);
  const parsed = parseGrpcWebFrames(Buffer.concat([frameGrpcWebMessage(response), trailerFrame]), "response");
  assert.deepEqual(parsed.data, [response]);
  assert.equal(parsed.grpcStatus, 0);
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
