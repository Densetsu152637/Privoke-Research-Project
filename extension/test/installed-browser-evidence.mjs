import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export function parseGrpcWebFrames(body, kind) {
  assert.ok(Buffer.isBuffer(body), `${kind} body must be bytes`);
  const data = [];
  let trailers = null;
  for (let offset = 0; offset < body.length;) {
    assert.ok(offset + 5 <= body.length, `${kind} frame header is truncated`);
    const flag = body[offset];
    const size = body.readUInt32BE(offset + 1);
    offset += 5;
    assert.ok(offset + size <= body.length, `${kind} frame payload is truncated`);
    const payload = body.subarray(offset, offset + size);
    offset += size;
    if (flag === 0) {
      assert.equal(trailers, null, "data frame cannot follow response trailers");
      data.push(payload);
    } else if (flag === 0x80) {
      assert.equal(kind, "response", "request cannot contain a trailer frame");
      assert.equal(trailers, null, "response contains duplicate trailer frames");
      assert.equal(offset, body.length, "response trailer must be the final frame");
      trailers = parseTrailerBlock(payload);
    } else {
      throw new Error(`${kind} has unsupported gRPC-Web frame flag ${flag}`);
    }
  }
  if (kind === "request") {
    assert.equal(data.length, 1, "request must contain exactly one data frame");
    return { data, trailers: null, grpcStatus: null, grpcMessage: null };
  }
  assert.equal(kind, "response", "unknown gRPC-Web message kind");
  assert.ok(trailers, "response omitted its final trailer frame");
  assert.ok(data.length <= 1, "response contains extra data frames");
  return { data, trailers: trailers.raw, grpcStatus: trailers.status, grpcMessage: trailers.message };
}

function parseTrailerBlock(payload) {
  const text = payload.toString("ascii");
  assert.equal(Buffer.from(text, "ascii").compare(payload), 0, "trailers must be ASCII");
  const fields = new Map();
  for (const line of text.split("\r\n")) {
    if (!line) continue;
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \t]*(.*)$/.exec(line);
    assert.ok(match, "malformed gRPC-Web trailer field");
    const key = match[1].toLowerCase();
    assert.ok(!fields.has(key), `duplicate gRPC-Web trailer ${key}`);
    fields.set(key, match[2]);
  }
  assert.ok(fields.has("grpc-status"), "response omitted grpc-status");
  assert.match(fields.get("grpc-status"), /^(0|[1-9][0-9]*)$/, "grpc-status must be a canonical integer");
  assert.ok(Number.isSafeInteger(Number(fields.get("grpc-status"))), "grpc-status is outside the safe integer range");
  let message = fields.get("grpc-message") ?? null;
  if (message !== null) {
    try { message = decodeURIComponent(message); }
    catch { throw new Error("grpc-message has invalid percent encoding"); }
  }
  return { raw: Object.fromEntries(fields), status: Number(fields.get("grpc-status")), message };
}

export function frameGrpcWebMessage(bytes) {
  const payload = Buffer.from(bytes);
  const header = Buffer.alloc(5);
  header[0] = 0;
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

export function validateAnalyzeRequest(request, expected) {
  assert.ok(request && typeof request === "object", "AnalyzePrompt request did not decode");
  assert.equal(request.requestId, expected.requestId ?? request.requestId);
  assert.ok(typeof request.requestId === "string" && request.requestId.length > 0,
    "AnalyzePrompt request ID is missing");
  assert.equal(request.text, expected.text, "decoded runtime prompt differs from frozen fixture");
  assert.equal(request.source, "browser_interceptor");
  assert.equal(request.targetApp, "chatgpt");
  assert.deepEqual(request.layers, ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"]);
  return request;
}

export function validateAnalyzeResponse(response, request, expectedAction, { allowErrorStatus = false } = {}) {
  assert.ok(response && typeof response === "object", "AnalyzePrompt response did not decode");
  assert.equal(response.requestId, request.requestId, "runtime request/response IDs do not match");
  assert.equal(response.action, expectedAction);
  assert.equal(response.error, "", "runtime returned an application error");
  assert.ok(Array.isArray(response.layers), "runtime omitted layer results");
  assert.deepEqual(response.layers.map((item) => item.layer), ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"]);
  for (const layer of response.layers) {
    assert.ok(["ok", "skipped"].includes(layer.status), `unexpected ${layer.layer} status ${layer.status}`);
    if (layer.status === "skipped") {
      assert.equal(expectedAction, "BLOCK", "only regex BLOCK may short-circuit a detector request");
      assert.equal(layer.layer, "DETECTION_LAYER_NER");
      assert.equal(layer.error, "", "skipped NER must not carry an error");
    } else assert.equal(layer.error, "", `${layer.layer} reported an error`);
  }
  assert.ok(Number.isFinite(response.elapsedMs) && response.elapsedMs >= 0,
    "runtime elapsed time must be finite and nonnegative");
  return response;
}

export function validateDecodedOutcome(rpc, { prompt, action, allowGrpcError = false, allowNetworkFailure = false } = {}) {
  assert.ok(rpc && !rpc.decodeError, "runtime wire response failed decoding");
  assert.ok(rpc.request, "runtime wire request is missing");
  validateAnalyzeRequest(rpc.request, { text: prompt });
  if (allowGrpcError) {
    assert.equal(rpc.responseBytesPresent, true, "gRPC error trailer bytes are missing");
    assert.ok(Number.isInteger(rpc.grpcStatus) && rpc.grpcStatus > 0,
      "expected a nonzero gRPC status for the detector outage");
    assert.equal(rpc.loadingFailure, null, "gRPC outage was reported as a network failure");
    assert.equal(rpc.response, null, "failed gRPC outcome must not carry an application response");
    return rpc;
  }
  if (allowNetworkFailure) {
    assert.ok(rpc.loadingFailure, "expected a browser-observed network failure");
    assert.equal(rpc.response, null);
    assert.equal(rpc.grpcStatus, null);
    return rpc;
  }
  assert.equal(rpc.loadingFailure, null, "runtime request ended with a network failure");
  assert.equal(rpc.responseBytesPresent, true, "runtime response bytes are missing");
  assert.equal(rpc.grpcStatus, 0, "runtime response must have status zero");
  validateAnalyzeResponse(rpc.response?.decoded, rpc.request, action);
  return rpc;
}

export function validatePageAnalysis(analyses, { caseId, prompt, expectedAction, seenIds }) {
  const starts = analyses.filter((item) => item.phase === "start" && item.caseId === caseId);
  const results = analyses.filter((item) => item.phase === "result" && item.caseId === caseId);
  assert.equal(starts.length, 1, `${caseId} must have exactly one ANALYZE_PROMPT`);
  assert.equal(results.length, 1, `${caseId} must have exactly one matching ANALYZE_RESULT`);
  const [start] = starts;
  const [result] = results;
  assert.equal(start.requestId, result.requestId, "page result request ID differs from its prompt");
  assert.equal(start.prompt, prompt);
  assert.equal(result.prompt, prompt);
  assert.equal(result.action, expectedAction, "page result action changed");
  assert.ok(Number.isFinite(result.decisionMs) && result.decisionMs >= 0);
  assert.ok(!seenIds.has(result.requestId), "page request IDs must be unique");
  seenIds.add(result.requestId);
  return result;
}

export function assertReceiverCapture(capture, { expectedUrl, prompt }) {
  assert.ok(capture, "expected provider receiver capture is missing");
  assert.equal(capture.method, "POST");
  assert.equal(capture.path, new URL(expectedUrl).pathname + new URL(expectedUrl).search,
    "receiver path/query differs from this synthetic case");
  const expectedBytes = Buffer.from(JSON.stringify({ messages: [{ role: "user", content: prompt }] }));
  const body = Buffer.from(capture.bodyBase64, "base64");
  assert.deepEqual(body, expectedBytes, "provider receiver bytes changed");
  assert.equal(capture.bodySha256, createHash("sha256").update(expectedBytes).digest("hex"));
}

export function assertNativeParentBinding(nativeSamples, browserSamples) {
  const browser = new Map(browserSamples.map((item) => [`${item.pid}/${item.start_ticks}`, item]));
  return nativeSamples.some((native) => browser.has(`${native.ppid}/${native.parent_start_ticks}`));
}
