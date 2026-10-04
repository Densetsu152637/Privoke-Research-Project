import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { TextDecoder } from "node:util";

const REGEX_BLOCK_SKIP_REASON = "Skipped after regex returned BLOCK.";
const SAMPLER_TERMINAL_MAX_BYTES = 8 * 1024;

function assertUniqueJsonObjectKeys(text) {
  let offset = 0;
  const whitespace = () => { while (/\s/.test(text[offset] ?? "")) offset += 1; };
  function stringToken() {
    assert.equal(text[offset], '"', "sampler sidecar JSON string is invalid");
    const start = offset++;
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '"') return JSON.parse(text.slice(start, offset));
      if (character === "\\") offset += 1;
    }
    throw new Error("sampler sidecar JSON string is truncated");
  }
  function value() {
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set();
      if (text[offset] === "}") { offset += 1; return; }
      while (offset < text.length) {
        whitespace();
        const key = stringToken();
        assert.ok(!keys.has(key), "sampler sidecar contains duplicate fields");
        keys.add(key);
        whitespace();
        assert.equal(text[offset++], ":", "sampler sidecar JSON object is invalid");
        value();
        whitespace();
        const delimiter = text[offset++];
        if (delimiter === "}") return;
        assert.equal(delimiter, ",", "sampler sidecar JSON object is invalid");
      }
      throw new Error("sampler sidecar JSON object is truncated");
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") { offset += 1; return; }
      while (offset < text.length) {
        value();
        whitespace();
        const delimiter = text[offset++];
        if (delimiter === "]") return;
        assert.equal(delimiter, ",", "sampler sidecar JSON array is invalid");
      }
      throw new Error("sampler sidecar JSON array is truncated");
    }
    if (text[offset] === '"') { stringToken(); return; }
    const start = offset;
    while (offset < text.length && !/[\s,\]}]/.test(text[offset])) offset += 1;
    assert.ok(offset > start, "sampler sidecar JSON value is missing");
    JSON.parse(text.slice(start, offset));
  }
  value();
  whitespace();
  assert.equal(offset, text.length, "sampler sidecar has trailing JSON data");
}

export async function readSamplerTerminalSidecar(path) {
  let handle;
  try {
    const pathInfo = await lstat(path);
    assert.ok(!pathInfo.isSymbolicLink(), "sampler terminal sidecar must not be a symbolic link");
    const noFollow = fsConstants.O_NOFOLLOW ?? 0;
    handle = await open(path, fsConstants.O_RDONLY | noFollow);
    const info = await handle.stat();
    assert.ok(info.isFile(), "sampler terminal sidecar is not a regular file");
    assert.ok(info.size <= SAMPLER_TERMINAL_MAX_BYTES, "sampler terminal sidecar exceeds 8 KiB");
    const buffer = Buffer.alloc(SAMPLER_TERMINAL_MAX_BYTES + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    assert.ok(bytesRead <= SAMPLER_TERMINAL_MAX_BYTES, "sampler terminal sidecar exceeds 8 KiB");
    const raw = buffer.subarray(0, bytesRead);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(raw); }
    catch { throw new Error("sampler terminal sidecar is not valid UTF-8"); }
    assertUniqueJsonObjectKeys(text);
    let value;
    try { value = JSON.parse(text); }
    catch { throw new Error("sampler terminal sidecar is invalid JSON"); }
    const diagnostic = validateSamplerTerminalDiagnostic(value);
    return { diagnostic, byteLength: raw.length, sha256: createHash("sha256").update(raw).digest("hex") };
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error?.message?.startsWith("sampler ")) throw error;
    throw new Error("sampler terminal sidecar could not be read safely");
  } finally {
    await handle?.close().catch(() => {});
  }
}

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
  assert.ok(Number(fields.get("grpc-status")) <= 16, "grpc-status is outside the canonical gRPC status range");
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

export function summarizeSupervisorStartupLog(input, maxBytes = 128 * 1024) {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input ?? "");
  assert.ok(Number.isSafeInteger(maxBytes) && maxBytes > 0, "startup-log bound must be positive");
  const bytes = raw.subarray(Math.max(0, raw.length - maxBytes));
  const text = bytes.toString("utf8");
  const tracebackFrames = [];
  for (const line of text.split(/\r?\n/)) {
    const frame = /^\s*File "([^"\r\n]+)", line ([0-9]+), in ([A-Za-z0-9_<>.-]+)\s*$/.exec(line);
    if (frame) {
      tracebackFrames.push({ file: frame[1].split(/[\\/]/).at(-1), line: Number(frame[2]), function: frame[3] });
    }
  }
  const exceptionLine = text.split(/\r?\n/).reverse().find((line) => /^[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception):/.test(line));
  const exceptionType = exceptionLine?.split(":", 1)[0] ?? null;
  const missingModule = exceptionLine
    ? /No module named ['"]([A-Za-z_][A-Za-z0-9_.]*)['"]/.exec(exceptionLine)?.[1] ?? null
    : null;
  return {
    capturedBytes: bytes.length,
    truncated: bytes.length < raw.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    containsTraceback: text.includes("Traceback (most recent call last):"),
    exceptionType,
    missingModule,
    tracebackFrames,
    controlListening: text.includes("PriVoke runtime supervisor listening on 127.0.0.1:50056"),
    bridgeListening: text.includes("PriVoke gRPC-Web bridge listening on 127.0.0.1:8080"),
    detectorDependencyUnavailable: text.includes("Client runtime dependencies are unavailable:"),
  };
}

export function mountEvidenceForPath(path, mountInfoText) {
  const target = String(path ?? "").replace(/\\/g, "/").replace(/\/$/, "");
  const matches = [];
  for (const line of String(mountInfoText ?? "").split(/\r?\n/)) {
    const [left, right] = line.split(" - ", 2);
    if (!right) continue;
    const fields = left.split(" ");
    const mountPoint = fields[4]?.replace(/\\([0-7]{3})/g, (_, octal) => String.fromCharCode(Number.parseInt(octal, 8)));
    if (!mountPoint) continue;
    const convertedMount = mountPoint.replace(/\\/g, "/");
    const normalizedMount = convertedMount === "/" ? "/" : convertedMount.replace(/\/$/, "");
    if (target !== normalizedMount && !(normalizedMount === "/" ? target.startsWith("/") : target.startsWith(`${normalizedMount}/`))) continue;
    const options = fields[5]?.split(",") ?? [];
    const fsType = right.split(" ", 1)[0] ?? null;
    matches.push({ mountPoint, fsType, noExec: options.includes("noexec"), readOnly: options.includes("ro"), depth: normalizedMount.length });
  }
  matches.sort((a, b) => b.depth - a.depth);
  if (!matches.length) return null;
  const { depth, ...evidence } = matches[0];
  return evidence;
}

export function assertNativeLauncherExecutableMount({ executable, mount }) {
  assert.equal(executable, true, "installer-generated native launcher is not executable");
  assert.ok(mount, "native launcher mount options are unavailable");
  assert.equal(mount.noExec, false, "native launcher is on a noexec mount");
  return { executable, mount };
}

export function isBeforeFirstFixtureRequest(fixtureRequestAttempted) {
  assert.equal(typeof fixtureRequestAttempted, "boolean", "fixture request attempt state must be explicit");
  return !fixtureRequestAttempted;
}

export function classifyLinuxProcessStat(statLine, expectedIdentity) {
  assert.equal(typeof statLine, "string", "Linux process stat must be text");
  assert.ok(Number.isSafeInteger(expectedIdentity?.pid) && expectedIdentity.pid > 1,
    "expected process PID must be valid");
  assert.ok(Number.isSafeInteger(expectedIdentity?.startTicks) && expectedIdentity.startTicks >= 0,
    "expected process start ticks must be a nonnegative integer");
  const pid = Number(/^(\d+) \(/.exec(statLine)?.[1]);
  assert.ok(Number.isSafeInteger(pid) && pid > 1, "Linux process PID is missing");
  const rest = statLine.slice(statLine.lastIndexOf(")") + 2).split(/\s+/);
  const state = rest[0];
  const startTicks = Number(rest[19]);
  assert.match(state ?? "", /^[A-Z]$/, "Linux process state is missing");
  assert.ok(Number.isSafeInteger(startTicks) && startTicks >= 0, "Linux process start ticks are invalid");
  if (pid !== expectedIdentity.pid || startTicks !== expectedIdentity.startTicks) return "different_process";
  if (state === "Z" || state === "X") return "exited";
  return "running";
}

export function isLinuxProcessIdentityReaped(statLine, expectedIdentity) {
  return classifyLinuxProcessStat(statLine, expectedIdentity) === "different_process";
}

export function sessionCleanupProcessDisposition(statLine, expectedIdentity) {
  const state = classifyLinuxProcessStat(statLine, expectedIdentity);
  if (state === "different_process") return "identity_gone_or_reused";
  if (state === "exited") return "zombie_must_be_reaped";
  return "refuse_still_running";
}

export function assertOwnedDetectorIdentity(identity, expected) {
  assert.ok(expected, "detector PID is not owned by this experiment");
  assert.equal(identity.pid, expected.pid);
  assert.equal(identity.startTicks, expected.startTicks, "detector PID was reused");
  assert.equal(identity.parentPid, expected.parentPid);
  assert.ok(identity.command.includes("extension/client-runtime/src/grpc_main.py"));
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

export function validateAnalyzeResponse(response, request, expectedAction) {
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
      assert.equal(layer.error, REGEX_BLOCK_SKIP_REASON, "skipped NER reason differs from the documented regex short-circuit");
      const regex = response.layers.find((item) => item.layer === "DETECTION_LAYER_REGEX");
      assert.equal(regex.status, "ok", "regex layer must have completed before NER is skipped");
      assert.equal(regex.error, "", "regex layer reported an error before NER skip");
      assert.ok(regex.results.some((item) => item.action === "BLOCK"),
        "skipped NER requires a concrete BLOCK result from the regex layer");
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

export function assertPreservedControlSupervisor(expected, actual, openPorts) {
  assert.equal(actual.pid, expected.pid, "control supervisor PID changed during master-off");
  assert.equal(actual.startTicks, expected.startTicks, "control supervisor PID was reused during master-off");
  assert.equal(actual.commandSha256, expected.commandSha256, "control supervisor command changed during master-off");
  assert.deepEqual([...openPorts].sort((a, b) => a - b), [8080, 50056],
    "master-off must retain only the expected control-plane listeners");
}

export function assertCompleteResourceEvidence(summary) {
  assert.ok(Number.isSafeInteger(summary.cgroupMemorySampledPeakBytes) && summary.cgroupMemorySampledPeakBytes > 0,
    "cgroup memory sampling was unavailable");
  assert.ok(Number.isFinite(summary.cgroupCpuSampledDeltaUsec) && summary.cgroupCpuSampledDeltaUsec >= 0,
    "cgroup CPU sampling was unavailable");
  assert.equal(summary.cgroupMemoryMissingSamples, 0, "cgroup memory samples are incomplete");
  assert.equal(summary.cgroupCpuMissingSamples, 0, "cgroup CPU samples are incomplete");
  assert.ok(Array.isArray(summary.windows) && summary.windows.length > 0,
    "resource windows are missing");
  for (const window of summary.windows) {
    assert.ok(Number.isSafeInteger(window.sampleCount) && window.sampleCount >= 2,
      "resource window lacks two cgroup observations");
    assert.ok(Number.isSafeInteger(window.observedSampleSpanNs) && window.observedSampleSpanNs > 0,
      "resource window lacks an observed time span");
    assert.ok(Number.isSafeInteger(window.maximumObservedSampleGapNs)
        && window.maximumObservedSampleGapNs <= 500_000_000,
    "resource window cadence exceeds 500 ms");
    for (const role of ["xvfb", "chromium", "supervisor_bridge", "detector"]) {
      assert.ok(Number.isSafeInteger(window.roleCpuIntervals?.[role])
          && window.roleCpuIntervals[role] >= 1,
      `${role} lacks a multi-observation CPU interval in every resource window`);
    }
    assert.equal(window.startupTransition?.status, "committed",
      "resource window lacks a committed detector startup transition");
    assert.equal(window.startupTransition?.samplerEvidence?.status, "verified",
      "resource window startup-transition evidence was not verified");
    assert.ok(Number.isSafeInteger(window.startupTransition?.samplerEvidence?.finalDetectorCpuSampleCount)
        && window.startupTransition.samplerEvidence.finalDetectorCpuSampleCount >= 2,
    "final detector identity lacks its own measured startup-window interval");
  }
  assert.ok(Number.isSafeInteger(summary.maximumObservedSampleGapNs)
      && summary.maximumObservedSampleGapNs <= 500_000_000,
  "resource sampling cadence exceeds 500 ms");
  const requiredRoles = new Set(["xvfb", "chromium", "supervisor_bridge", "detector"]);
  for (const [role, count] of Object.entries(summary.processIdentityRaceDropsByRole || {})) {
    assert.ok(Number.isSafeInteger(count) && count >= 0, "process identity race counts are invalid");
    assert.equal(role, "chromium", `${role} process identity races cannot be silently omitted`);
  }
  const roles = new Set(summary.processes.map((item) => item.role));
  for (const role of requiredRoles) assert.ok(roles.has(role), `resource samples omitted required ${role} process role`);
  for (const role of requiredRoles) {
    assert.ok(summary.processes.some((item) => item.role === role && item.cpuIntervalCount >= 1
        && Number.isFinite(item.cpuDeltaSeconds) && item.cpuDeltaSeconds >= 0),
    `${role} lacks a valid multi-observation CPU interval`);
  }
  for (const item of summary.processes.filter((record) => requiredRoles.has(record.role))) {
    assert.ok(Number.isSafeInteger(item.startTicks), `${item.role} lacks start-tick identity`);
    assert.ok(Number.isSafeInteger(item.sampledPeakRssBytes), `${item.role} lacks RSS samples`);
    assert.ok(Number.isSafeInteger(item.cpuSampleCount) && item.cpuSampleCount > 0,
      `${item.role} lacks CPU observation counts`);
    assert.ok(Number.isSafeInteger(item.cpuIntervalCount) && item.cpuIntervalCount >= 0,
      `${item.role} has invalid CPU interval counts`);
    if (item.cpuIntervalCount === 0) assert.equal(item.cpuDeltaSeconds, null,
      `${item.role} singleton CPU must be unmeasured, not zero`);
    else {
      assert.ok(Number.isFinite(item.cpuDeltaSeconds) && item.cpuDeltaSeconds >= 0,
        `${item.role} lacks valid CPU samples`);
      assert.ok(Number.isSafeInteger(item.cpuSampledSpanNs) && item.cpuSampledSpanNs > 0,
        `${item.role} CPU interval lacks an observed span`);
    }
    assert.equal(item.missingRssSamples, 0, `${item.role} has missing RSS samples`);
    assert.equal(item.missingCpuSamples, 0, `${item.role} has missing CPU samples`);
    assert.equal(item.missingStartTicksSamples, 0, `${item.role} has missing start-tick samples`);
  }
  return summary;
}

export function buildStartupIdentityDiagnostic(identities, samples) {
  if (!Array.isArray(identities) || !Array.isArray(samples)) {
    throw new TypeError("startup identity evidence must be arrays");
  }
  const expectedIdentities = identities.map((item) => {
    if (!item || typeof item.role !== "string" || !item.role
        || !Number.isSafeInteger(item.pid) || item.pid <= 0
        || !Number.isSafeInteger(item.startTicks) || item.startTicks < 0) {
      throw new TypeError("expected startup identity is invalid");
    }
    const observed = new Map();
    let exactPairSampleCount = 0;
    let exactPairFiniteStartTimeSampleCount = 0;
    for (const sample of samples) {
      for (const row of Array.isArray(sample?.roles) ? sample.roles : []) {
        if (row?.role !== item.role || !Number.isSafeInteger(row.pid)
            || !Number.isSafeInteger(row.start_ticks) || row.pid <= 0 || row.start_ticks < 0) continue;
        const key = `${row.pid}/${row.start_ticks}`;
        const record = observed.get(key) || {
          pid: row.pid,
          startTicks: row.start_ticks,
          sampleCount: 0,
          finiteStartTimeSampleCount: 0,
        };
        record.sampleCount += 1;
        if (Number.isFinite(row.start_time_epoch_seconds)) record.finiteStartTimeSampleCount += 1;
        observed.set(key, record);
        if (row.pid === item.pid && row.start_ticks === item.startTicks) {
          exactPairSampleCount += 1;
          if (Number.isFinite(row.start_time_epoch_seconds)) exactPairFiniteStartTimeSampleCount += 1;
        }
      }
    }
    const observedRoleIdentities = [...observed.values()].sort((a, b) => a.pid - b.pid || a.startTicks - b.startTicks);
    return {
      role: item.role,
      pid: item.pid,
      startTicks: item.startTicks,
      exactPairSampleCount,
      exactPairFiniteStartTimeSampleCount,
      observedRoleIdentityCount: observedRoleIdentities.length,
      observedRoleIdentities: observedRoleIdentities.slice(0, 64),
      observedRoleIdentitiesTruncated: observedRoleIdentities.length > 64,
    };
  });
  return {
    sampleRowCount: samples.length,
    expectedIdentities,
  };
}

export function validateSamplerTerminalDiagnostic(value) {
  const keys = ["schema_version", "status", "samples_written", "exception_type", "frames"];
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")
      || value.schema_version !== 1
      || !["stopped", "error"].includes(value.status)
      || !Number.isSafeInteger(value.samples_written) || value.samples_written < 0
      || !Array.isArray(value.frames) || value.frames.length > 12) {
    throw new TypeError("sampler terminal diagnostic has an invalid schema");
  }
  if (value.status === "stopped") {
    if (value.exception_type !== null || value.frames.length !== 0) {
      throw new TypeError("successful sampler diagnostic must not contain an exception");
    }
  } else if (typeof value.exception_type !== "string"
      || !/^[A-Za-z_][A-Za-z0-9_]{0,79}$/.test(value.exception_type)) {
    throw new TypeError("sampler exception type is invalid");
  }
  for (const frame of value.frames) {
    const frameKeys = ["file", "function", "line"];
    if (!frame || typeof frame !== "object" || Array.isArray(frame)
        || Object.keys(frame).sort().join("\0") !== [...frameKeys].sort().join("\0")
        || typeof frame.file !== "string" || !/^(?:[A-Za-z0-9_.-]{1,128}|<unavailable>)$/.test(frame.file)
        || typeof frame.function !== "string" || !/^[A-Za-z0-9_<>.-]{1,128}$/.test(frame.function)
        || !Number.isSafeInteger(frame.line) || frame.line <= 0) {
      throw new TypeError("sampler traceback frame is invalid");
    }
  }
  return value;
}

export function preserveResourceEvidenceFailure(summary, error) {
  if (summary && typeof summary === "object" && !Array.isArray(summary)) {
    return { ...summary, validationError: error };
  }
  return { error };
}

export function createResourceWindowFinalizer(finalize) {
  assert.equal(typeof finalize, "function", "resource-window finalizer must be callable");
  let finalization;
  return () => {
    if (!finalization) finalization = Promise.resolve().then(finalize);
    return finalization;
  };
}

const MAX_STARTUP_CONTROL_BYTES = 4096;

function stableControlJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableControlJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableControlJson(value[key])}`).join(",")}}`;
  }
  if (value === null || typeof value === "string" || typeof value === "boolean"
      || (typeof value === "number" && Number.isFinite(value))) return JSON.stringify(value);
  throw new TypeError("startup control record contains an unsupported value");
}

export function startupControlDigest(record) {
  return createHash("sha256").update(stableControlJson(record)).digest("hex");
}

export function validateStartupTransitionAck(value, request) {
  const keys = ["schema_version", "type", "sequence", "transition_id", "request_sha256", "status",
    "observed_at_ns", "predecessor", "supervisor", "successor"];
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")
      || value.schema_version !== 1 || value.type !== "ack" || value.sequence !== request.type
      || value.transition_id !== request.transition_id || value.request_sha256 !== startupControlDigest(request)
      || value.status !== "accepted" || !/^\d{1,20}$/.test(value.observed_at_ns)) {
    throw new TypeError("sampler startup-transition acknowledgement is invalid");
  }
  if (!Number.isSafeInteger(request.expires_at_ns)
      || BigInt(value.observed_at_ns) >= BigInt(request.expires_at_ns)) {
    throw new TypeError("sampler startup-transition acknowledgement arrived after expiry");
  }
  for (const name of ["predecessor", "supervisor"]) {
    const identity = value[name];
    if (!identity || Object.keys(identity).sort().join("\0") !== ["pid", "start_ticks"].sort().join("\0")
        || !Number.isSafeInteger(identity.pid) || identity.pid <= 0
        || !Number.isSafeInteger(identity.start_ticks) || identity.start_ticks < 0) {
      throw new TypeError("sampler startup-transition acknowledgement identity is invalid");
    }
  }
  if (value.predecessor.pid !== request.predecessor.pid
      || value.predecessor.start_ticks !== request.predecessor.start_ticks
      || value.supervisor.pid !== request.supervisor.pid
      || value.supervisor.start_ticks !== request.supervisor.start_ticks) {
    throw new TypeError("sampler startup-transition acknowledgement identity differs");
  }
  if (request.type === "commit") {
    if (!value.successor || value.successor.pid !== request.successor.pid
        || value.successor.start_ticks !== request.successor.start_ticks) {
      throw new TypeError("sampler startup-transition commit acknowledgement differs");
    }
  } else if (value.successor !== null) {
    throw new TypeError("sampler startup-transition acknowledgement has an unexpected successor");
  }
  return value;
}

export function createSamplerStartupTransitionClient(child, { timeoutMs = 5_000 } = {}) {
  assert.ok(child?.stdin && child?.stdout, "sampler transition requires bounded child pipes");
  let lineBuffer = Buffer.alloc(0);
  let pending;
  let failed = null;
  const onData = (chunk) => {
    lineBuffer = Buffer.concat([lineBuffer, chunk]);
    if (lineBuffer.length > MAX_STARTUP_CONTROL_BYTES) {
      failed = new Error("sampler transition acknowledgement exceeded its byte bound");
      pending?.reject(failed);
      pending = null;
      return;
    }
    const newline = lineBuffer.indexOf(10);
    if (newline < 0) return;
    const rest = lineBuffer.subarray(newline + 1);
    if (rest.length) {
      failed = new Error("sampler emitted more than one transition acknowledgement");
      pending?.reject(failed);
      pending = null;
      return;
    }
    const line = lineBuffer.subarray(0, newline);
    lineBuffer = Buffer.alloc(0);
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(line);
      const value = JSON.parse(text);
      if (!pending) throw new Error("sampler emitted an unsolicited transition acknowledgement");
      pending.resolve(value);
      pending = null;
    } catch (error) {
      failed = new Error("sampler transition acknowledgement could not be decoded");
      pending?.reject(failed);
      pending = null;
    }
  };
  child.stdout.on("data", onData);
  child.once("close", () => {
    if (pending) pending.reject(new Error("sampler closed during startup transition"));
    pending = null;
  });
  let sequence = 0;
  return {
    async exchange(record) {
      if (failed) throw failed;
      if (sequence >= 3 || record?.type !== ["prepare", "dispatch", "commit"][sequence]) {
        throw new Error("sampler startup transition control sequence is invalid");
      }
      sequence += 1;
      const bytes = Buffer.from(`${stableControlJson(record)}\n`, "utf8");
      if (bytes.length > MAX_STARTUP_CONTROL_BYTES) throw new Error("sampler startup control record exceeded its byte bound");
      if (pending) throw new Error("sampler startup transition already has a pending acknowledgement");
      const response = new Promise((resolvePromise, reject) => { pending = { resolve: resolvePromise, reject }; });
      child.stdin.write(bytes);
      let timer;
      try {
        const value = await Promise.race([response, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("sampler startup-transition acknowledgement timed out")), timeoutMs);
        })]);
        return validateStartupTransitionAck(value, record);
      } finally {
        clearTimeout(timer);
        if (pending) pending = null;
      }
    },
    close() {
      child.stdout.off("data", onData);
      child.stdin.end();
    },
  };
}

export async function runBoundedStartupTransition({
  sessionId, sourceRevision, protocolSha256, exchange, getSettings, waitReady,
  captureRuntime, waitSampled, waitPredecessorReaped, updateSettings,
  nowNs = () => process.hrtime.bigint().toString(),
}) {
  const started = BigInt(nowNs());
  const elapsedMs = (from) => Number(BigInt(nowNs()) - from) / 1_000_000;
  let mark = BigInt(nowNs());
  const settings = await getSettings();
  const settingsReadElapsedMs = elapsedMs(mark);
  assert.equal(settings?.ok, true, "fresh profile settings could not be read");
  assert.equal(settings.settings?.enabled, true, "fresh profile runtime must begin enabled");
  assert.equal(settings.settings?.useLocalStack, false, "fresh profile must begin on the declared cloud runtime");
  mark = BigInt(nowNs());
  const priorStatus = await waitReady();
  const priorStatusElapsedMs = elapsedMs(mark);
  mark = BigInt(nowNs());
  const prior = await captureRuntime(priorStatus);
  const predecessorCaptureElapsedMs = elapsedMs(mark);
  assert.equal(prior.detector.parentPid, prior.supervisor.pid, "predecessor is not a child of the live supervisor");
  assert.equal(prior.detector.parentStartTicks, prior.supervisor.startTicks,
    "predecessor supervisor identity is not bound");
  assert.notDeepEqual(prior.listeners, null, "predecessor listeners were not verified");
  mark = BigInt(nowNs());
  const priorSamples = await waitSampled([prior.supervisor, prior.detector]);
  const predecessorSamplingWaitElapsedMs = elapsedMs(mark);

  const transitionId = randomUUID().replaceAll("-", "");
  const expiry = (BigInt(nowNs()) + 90_000_000_000n).toString();
  assert.ok(Number.isSafeInteger(Number(expiry)), "startup transition expiry is not exactly representable");
  const predecessor = {
    pid: prior.detector.pid, start_ticks: prior.detector.startTicks,
    command_sha256: prior.detector.commandSha256, parent_pid: prior.detector.parentPid,
    parent_start_ticks: prior.detector.parentStartTicks,
  };
  const supervisor = { pid: prior.supervisor.pid, start_ticks: prior.supervisor.startTicks,
    command_sha256: prior.supervisor.commandSha256 };
  const common = { schema_version: 1, transition_id: transitionId, session_id: sessionId,
    expires_at_ns: Number(expiry), predecessor, supervisor, source_revision: sourceRevision,
    protocol_sha256: protocolSha256 };
  const prepare = { ...common, type: "prepare" };
  mark = BigInt(nowNs());
  const prepareAck = await exchange(prepare);
  const prepareAckElapsedMs = elapsedMs(mark);
  const dispatch = { ...common, type: "dispatch", operation: "cloud_to_local_startup" };
  mark = BigInt(nowNs());
  const dispatchAck = await exchange(dispatch);
  const dispatchAckElapsedMs = elapsedMs(mark);
  const dispatchStartedAtNs = nowNs();
  mark = BigInt(nowNs());
  const configured = await updateSettings();
  const settingsUpdateElapsedMs = elapsedMs(mark);
  assert.equal(configured?.ok, true, "local browser settings update failed");
  assert.equal(configured.settings?.useLocalStack, true);
  assert.equal(configured.settings?.enabled, true);
  assert.deepEqual(configured.settings?.layers, { regex: true, ner: true, llm: false });
  assert.equal(configured.settings?.waitForRegex, true);
  mark = BigInt(nowNs());
  const status = await waitReady();
  const finalStatusElapsedMs = elapsedMs(mark);
  mark = BigInt(nowNs());
  const current = await captureRuntime(status);
  const finalIdentityAndListenersElapsedMs = elapsedMs(mark);
  assert.equal(current.supervisor.pid, prior.supervisor.pid, "startup transition changed supervisor PID");
  assert.equal(current.supervisor.startTicks, prior.supervisor.startTicks, "startup transition changed supervisor identity");
  assert.notEqual(current.detector.pid, prior.detector.pid, "startup transition did not create a distinct detector");
  assert.notEqual(current.detector.startTicks, prior.detector.startTicks, "startup transition detector identity did not change");
  assert.equal(current.detector.parentPid, current.supervisor.pid);
  assert.equal(current.detector.parentStartTicks, current.supervisor.startTicks);
  mark = BigInt(nowNs());
  await waitPredecessorReaped(prior.detector);
  const predecessorReapElapsedMs = elapsedMs(mark);
  mark = BigInt(nowNs());
  const currentSamples = await waitSampled([current.supervisor, current.detector]);
  const successorSamplingWaitElapsedMs = elapsedMs(mark);
  const successor = {
    pid: current.detector.pid, start_ticks: current.detector.startTicks,
    command_sha256: current.detector.commandSha256, parent_pid: current.detector.parentPid,
    parent_start_ticks: current.detector.parentStartTicks,
  };
  const commit = { ...common, type: "commit", successor };
  mark = BigInt(nowNs());
  const commitAck = await exchange(commit);
  const commitAckElapsedMs = elapsedMs(mark);
  return {
    transitionId, predecessor, successor, supervisor,
    prepareAck, dispatchAck, commitAck,
    prior, current, status, priorSamples, currentSamples,
    dispatchStartedAtNs,
    totalElapsedMs: elapsedMs(started), settingsReadElapsedMs, priorStatusElapsedMs,
    predecessorCaptureElapsedMs, predecessorSamplingWaitElapsedMs, prepareAckElapsedMs,
    dispatchAckElapsedMs, settingsUpdateElapsedMs, finalStatusElapsedMs,
    finalIdentityAndListenersElapsedMs, predecessorReapElapsedMs,
    successorSamplingWaitElapsedMs, commitAckElapsedMs,
    listeners: current.listeners,
    settings: configured.settings,
  };
}

export function validateStartupTransitionWindow(samples, transition) {
  if (!Array.isArray(samples) || !transition || transition.status !== "committed"
      || !/^[0-9a-f]{32}$/.test(transition.transitionId || "")) {
    throw new TypeError("startup transition receipt is not committed");
  }
  const events = samples.flatMap((sample) => sample.startup_transition_events || []);
  const selected = events.filter((event) => event.transition_id === transition.transitionId);
  assert.deepEqual(selected.map((event) => event.type),
    ["prepare", "dispatch", "predecessor_retired", "commit"],
    "sampler did not record the exact bounded startup-transition lifecycle");
  assert.equal(selected[2].pid, transition.predecessor.pid);
  assert.equal(selected[2].start_ticks, transition.predecessor.start_ticks);
  assert.equal(selected[2].role, "detector");
  assert.equal(selected[2].reason, "authorized_startup_transition");
  assert.equal(selected[2].command_sha256, transition.predecessor.command_sha256);
  assert.equal(selected[2].parent_pid, transition.predecessor.parent_pid);
  assert.equal(selected[2].parent_start_ticks, transition.predecessor.parent_start_ticks);
  assert.ok(["absent", "Z", "X", "x"].includes(selected[2].state));
  const retirementSampleIndex = samples.findIndex((sample) =>
    (sample.startup_transition_events || []).includes(selected[2]));
  assert.ok(retirementSampleIndex >= 0, "predecessor retirement event is not bound to a sample");
  for (const sample of samples.slice(retirementSampleIndex)) {
    assert.ok(!sample.roles.some((row) => row.role === "detector"
      && row.pid === transition.predecessor.pid && row.start_ticks === transition.predecessor.start_ticks),
    "predecessor was still reported after its retirement event");
  }
  for (const event of [selected[0], selected[1], selected[3]]) {
    assert.match(event.request_sha256 || "", /^[0-9a-f]{64}$/);
    assert.match(event.observed_at_ns || "", /^\d{1,20}$/);
    assert.deepEqual(event.predecessor, { pid: transition.predecessor.pid,
      start_ticks: transition.predecessor.start_ticks });
    assert.deepEqual(event.supervisor, { pid: transition.supervisor.pid,
      start_ticks: transition.supervisor.start_ticks });
  }
  assert.deepEqual(selected[3].successor, { pid: transition.successor.pid,
    start_ticks: transition.successor.start_ticks });
  assert.ok(Array.isArray(transition.controlAcknowledgements)
      && transition.controlAcknowledgements.length === 3,
  "startup transition receipt is missing its bounded control acknowledgements");
  assert.deepEqual(transition.controlAcknowledgements.map((ack) => ({
    sequence: ack.sequence, requestSha256: ack.requestSha256, observedAtNs: ack.observedAtNs,
  })), [selected[0], selected[1], selected[3]].map((event) => ({
    sequence: event.type, requestSha256: event.request_sha256, observedAtNs: event.observed_at_ns,
  })), "sampler lifecycle records do not match the runner acknowledgements");
  assert.notDeepEqual(transition.predecessor, transition.successor,
    "startup predecessor and final detector must be distinct identities");
  const cpu = summarizeResourceCpuWindows([{ file: "startup-transition.jsonl", samples }]);
  const final = cpu.processes.get(`detector/${transition.successor.pid}/${transition.successor.start_ticks}`);
  assert.ok(final && final.cpuIntervalCount >= 1 && final.cpuSampledSpanNs > 0,
    "committed final detector lacks its own multi-observation CPU interval");
  return { status: "verified", eventCount: selected.length,
    finalDetectorCpuSampleCount: final.cpuSampleCount,
    finalDetectorCpuSampledSpanNs: final.cpuSampledSpanNs };
}

export async function runAfterResourceWindow(finalize, nextPhase) {
  assert.equal(typeof finalize, "function", "resource-window finalizer must be callable");
  assert.equal(typeof nextPhase, "function", "next phase must be callable");
  await finalize();
  return nextPhase();
}

export async function finalizeResourceWindowBeforeCleanup(finalize, cleanup) {
  assert.equal(typeof finalize, "function", "resource-window finalizer must be callable");
  assert.equal(typeof cleanup, "function", "cleanup phase must be callable");
  let finalizationError = null;
  let cleanupError = null;
  try { await finalize(); } catch (error) { finalizationError = error; }
  const cleanupSkipped = finalizationError?.preventMonitoredTeardown === true;
  if (!cleanupSkipped) {
    try { await cleanup(); } catch (error) { cleanupError = error; }
  }
  return { finalizationError, cleanupError, cleanupSkipped };
}

export function summarizeResourceCpuWindows(windows) {
  if (!Array.isArray(windows)) throw new TypeError("resource CPU windows must be an array");
  const processes = new Map();
  const windowSummaries = [];
  let cgroupCpuSampledDeltaUsec = 0;
  let cgroupMemorySampledPeakBytes = null;
  let cgroupMemoryMissingSamples = 0;
  let maximumObservedSampleGapNs = 0;

  for (const window of windows) {
    if (!window || typeof window.file !== "string" || !Array.isArray(window.samples) || window.samples.length < 2) {
      throw new TypeError("resource CPU window needs at least two distinct observations");
    }
    let previousSampleMonotonicNs = null;
    let firstCgroupCpuUsec = null;
    let previousCgroupCpuUsec = null;
    const processCounters = new Map();
    for (const sample of window.samples) {
      if (!Number.isSafeInteger(sample?.sample_monotonic_ns) || sample.sample_monotonic_ns < 0
          || (previousSampleMonotonicNs !== null && sample.sample_monotonic_ns <= previousSampleMonotonicNs)) {
        throw new TypeError("resource window sample timestamps must increase and remain exactly representable");
      }
      if (previousSampleMonotonicNs !== null) {
        const gap = sample.sample_monotonic_ns - previousSampleMonotonicNs;
        if (gap > 500_000_000) throw new TypeError("resource window sample gap exceeds 500 ms");
        maximumObservedSampleGapNs = Math.max(maximumObservedSampleGapNs, gap);
      }
      previousSampleMonotonicNs = sample.sample_monotonic_ns;
      const cgroupCpuUsec = sample.cgroup?.cpu_usage_usec;
      if (!Number.isSafeInteger(cgroupCpuUsec) || cgroupCpuUsec < 0
          || (previousCgroupCpuUsec !== null && cgroupCpuUsec < previousCgroupCpuUsec)) {
        throw new TypeError("resource window cgroup CPU counters are missing, negative or decreasing");
      }
      firstCgroupCpuUsec ??= cgroupCpuUsec;
      previousCgroupCpuUsec = cgroupCpuUsec;
      const cgroupMemory = sample.cgroup?.memory_current_bytes;
      if (Number.isSafeInteger(cgroupMemory) && cgroupMemory >= 0) {
        cgroupMemorySampledPeakBytes = cgroupMemorySampledPeakBytes === null
          ? cgroupMemory : Math.max(cgroupMemorySampledPeakBytes, cgroupMemory);
      } else cgroupMemoryMissingSamples += 1;
      if (!Array.isArray(sample.roles)) throw new TypeError("resource window process rows are missing");
      const sampleProcessIdentities = new Set();
      for (const row of sample.roles) {
        if (typeof row?.role !== "string" || !row.role
            || !Number.isSafeInteger(row.pid) || row.pid <= 0
            || !Number.isSafeInteger(row.start_ticks) || row.start_ticks < 0) {
          throw new TypeError("resource window process identity is invalid");
        }
        const cpuSeconds = row.cpu_seconds;
        if (typeof cpuSeconds !== "number" || !Number.isFinite(cpuSeconds) || cpuSeconds < 0) {
          throw new TypeError("resource window process CPU counter is missing or invalid");
        }
        const key = `${row.role}/${row.pid}/${row.start_ticks}`;
        const processIdentity = `${row.pid}/${row.start_ticks}`;
        if (sampleProcessIdentities.has(processIdentity)) {
          throw new TypeError("duplicate process identity in one resource sample");
        }
        sampleProcessIdentities.add(processIdentity);
        const counter = processCounters.get(key) || { first: cpuSeconds, last: cpuSeconds,
          count: 0, firstMonotonicNs: sample.sample_monotonic_ns,
          lastMonotonicNs: sample.sample_monotonic_ns };
        if (cpuSeconds < counter.last) throw new TypeError("resource window process CPU counter decreased");
        counter.last = cpuSeconds;
        counter.lastMonotonicNs = sample.sample_monotonic_ns;
        counter.count += 1;
        processCounters.set(key, counter);
        const aggregate = processes.get(key) || {
          role: row.role, pid: row.pid, startTicks: row.start_ticks,
          cpuDeltaSeconds: null, cpuSampleCount: 0, cpuIntervalCount: 0,
          cpuSampledSpanNs: 0, sampledPeakRssBytes: null, sampledPeakPssBytes: null,
        };
        aggregate.cpuSampleCount += 1;
        if (Number.isSafeInteger(row.rss_bytes) && row.rss_bytes >= 0) {
          aggregate.sampledPeakRssBytes = aggregate.sampledPeakRssBytes === null
            ? row.rss_bytes : Math.max(aggregate.sampledPeakRssBytes, row.rss_bytes);
        }
        if (Number.isSafeInteger(row.pss_bytes) && row.pss_bytes >= 0) {
          aggregate.sampledPeakPssBytes = aggregate.sampledPeakPssBytes === null
            ? row.pss_bytes : Math.max(aggregate.sampledPeakPssBytes, row.pss_bytes);
        }
        processes.set(key, aggregate);
      }
    }
    const cgroupDelta = previousCgroupCpuUsec - firstCgroupCpuUsec;
    cgroupCpuSampledDeltaUsec += cgroupDelta;
    const roleCpuIntervals = Object.create(null);
    for (const [key, counter] of processCounters) {
      const aggregate = processes.get(key);
      if (counter.count >= 2) {
        const span = counter.lastMonotonicNs - counter.firstMonotonicNs;
        if (!Number.isSafeInteger(span) || span <= 0) {
          throw new TypeError("resource process CPU interval lacks distinct observation times");
        }
        const delta = counter.last - counter.first;
        const total = (aggregate.cpuDeltaSeconds ?? 0) + delta;
        if (!Number.isFinite(total) || total < 0) throw new TypeError("resource process CPU delta is not finite");
        aggregate.cpuDeltaSeconds = total;
        aggregate.cpuIntervalCount += 1;
        aggregate.cpuSampledSpanNs += span;
        roleCpuIntervals[aggregate.role] = (roleCpuIntervals[aggregate.role] || 0) + 1;
      }
    }
    windowSummaries.push({
      file: window.file,
      ...(typeof window.sessionId === "string" ? { sessionId: window.sessionId } : {}),
      ...(typeof window.requestedStartMonotonicNs === "string"
        ? { requestedStartMonotonicNs: window.requestedStartMonotonicNs } : {}),
      ...(typeof window.requestedEndMonotonicNs === "string"
        ? { requestedEndMonotonicNs: window.requestedEndMonotonicNs } : {}),
      ...(window.phaseRequestCounts ? { phaseRequestCounts: { ...window.phaseRequestCounts } } : {}),
      ...(window.startupTransition ? { startupTransition: window.startupTransition } : {}),
      sampleCount: window.samples.length,
      firstSampleMonotonicNs: window.samples[0].sample_monotonic_ns,
      lastSampleMonotonicNs: previousSampleMonotonicNs,
      observedSampleSpanNs: previousSampleMonotonicNs - window.samples[0].sample_monotonic_ns,
      maximumObservedSampleGapNs: window.samples.slice(1).reduce((maximum, sample, index) =>
        Math.max(maximum, sample.sample_monotonic_ns - window.samples[index].sample_monotonic_ns), 0),
      roleCpuIntervals,
      cgroupCpuSampledDeltaUsec: cgroupDelta,
    });
  }

  return { cgroupCpuSampledDeltaUsec, cgroupMemorySampledPeakBytes,
    cgroupMemoryMissingSamples, maximumObservedSampleGapNs, processes, windows: windowSummaries };
}

export async function waitForProcessesToDisappear(scanMatches, {
  timeoutMs,
  intervalMs = 50,
  now = Date.now,
  sleep,
}) {
  assert.equal(typeof scanMatches, "function", "process scanner must be callable");
  assert.ok(Number.isFinite(timeoutMs) && timeoutMs >= 0, "process wait timeout must be nonnegative");
  assert.ok(Number.isFinite(intervalMs) && intervalMs > 0, "process wait interval must be positive");
  assert.equal(typeof now, "function", "clock must be callable");
  assert.equal(typeof sleep, "function", "sleep function must be callable");
  const deadline = now() + timeoutMs;
  while (true) {
    const matches = await scanMatches();
    assert.ok(Array.isArray(matches), "process scanner must return an array of identities");
    if (matches.length === 0) return true;
    const remaining = deadline - now();
    if (remaining <= 0) throw new Error("Known profile process identities remained after the cleanup deadline");
    await sleep(Math.min(intervalMs, remaining));
  }
}
