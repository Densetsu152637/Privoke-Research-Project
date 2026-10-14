import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, execFile } from "node:child_process";
import { open, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { performance } from "node:perf_hooks";

const exec = promisify(execFile);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const REGEX_NER = ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"];
const FULL = [...REGEX_NER, "DETECTION_LAYER_SEMANTIC"];
const SEMANTIC = ["DETECTION_LAYER_SEMANTIC"];
const PROMPT = "Please explain the steps in this process.";

export function assertSequentialRpc(rpc, record, runtimeIds, networkIds) {
  assert.ok(rpc.request?.requestId && !runtimeIds.has(rpc.request.requestId), "runtime request ID must be unique");
  assert.ok(rpc.networkRequestId && !networkIds.has(rpc.networkRequestId), "browser network request ID must be unique");
  assert.ok(rpc.requestObservedAtMonotonicMs >= record.preProbeQuiescentAtMonotonicMs,
    "runtime request was observed before this probe's quiescence barrier");
  assert.ok(rpc.terminalObservedAtMonotonicMs >= rpc.requestObservedAtMonotonicMs
    && rpc.terminalObservedAtMonotonicMs <= record.postProbeQuiescentAtMonotonicMs,
    "runtime terminal event is outside this probe's sequential interval");
  runtimeIds.add(rpc.request.requestId);
  networkIds.add(rpc.networkRequestId);
}

export function assertAdditionalProbe({ record, captures, rpc, expectedLayers, expectedForwarded,
  requireSuccess = false, expectedAction }) {
  assert.equal(captures.length, Number(expectedForwarded), `${record.caseId} receiver count`);
  if (expectedForwarded) {
    assert.equal(captures[0].path, new URL(record.url).pathname + new URL(record.url).search);
    assert.deepEqual(Buffer.from(captures[0].bodyBase64, "base64"), Buffer.from(record.body));
    assert.equal(captures[0].bodySha256, createHash("sha256").update(record.body).digest("hex"));
  }
  const starts = record.analyses.filter((entry) => entry.phase === "start");
  assert.equal(starts.length, 1, "exactly one actual page analysis request is required");
  if (expectedAction) assert.equal(record.analyses.find((entry) => entry.phase === "result")?.action, expectedAction);
  if (expectedLayers) {
    assert.ok(rpc?.request && !rpc.decodeError, "actual decoded runtime request is required");
    assert.deepEqual(rpc.request.layers, expectedLayers, "actual requested layers differ from the declared mode");
    assert.equal(rpc.request.text, PROMPT);
    assert.equal(rpc.request.source, "browser_interceptor");
    assert.equal(rpc.request.targetApp, "chatgpt");
  }
  if (requireSuccess) {
    const response = rpc?.response?.decoded;
    assert.equal(rpc.grpcStatus, 0);
    assert.equal(response?.error, "");
    assert.equal(response.requestId, rpc.request.requestId);
    assert.deepEqual(response.layers.map((entry) => entry.layer), expectedLayers);
    assert.ok(response.layers.every((entry) => entry.status === "ok" && !entry.error),
      "the safe probe must execute every selected layer successfully");
    assert.equal(response.action, record.analyses.find((entry) => entry.phase === "result")?.action);
    assert.equal(expectedForwarded, response.action !== "BLOCK");
  }
  return record;
}

export async function runAdditionalMatrix(api) {
  const { page, popup, cdp, providerCaptures, rpcEvents, fixtureUrl, output,
    sendExtensionMessage, runtimeStatus, processIdentity, verifyOwnedSupervisor,
    expectedSupervisor, signal, restoreRuntimeAndObserve } = api;
  const records = [];
  const runtimeIds = new Set();
  const networkIds = new Set();
  const waitQuiescence = async () => {
    const deadline = Date.now() + 8_000;
    let quietSince = null;
    while (Date.now() < deadline) {
      if (cdp.network.size === 0) {
        quietSince ??= Date.now();
        if (Date.now() - quietSince >= 150) return performance.now();
      } else quietSince = null;
      await delay(25);
    }
    throw new Error("runtime RPC observer did not reach bounded terminal quiescence");
  };
  let model;
  let modelLog;
  let pausedSupervisor;
  let workerPaused = false;
  const saved = async () => writeFile(join(output, "additional-matrix.json"), JSON.stringify({
    protocol: "installed-browser-additional-v1", records,
  }, null, 2));
  const probe = async (transport, id, operation = "normal") => {
    const caseId = `additional-${transport}-${id}`;
    const preProbeQuiescentAtMonotonicMs = await waitQuiescence();
    const beforeRpc = rpcEvents.length;
    const url = `${fixtureUrl}/backend-api/conversation?case_id=${encodeURIComponent(caseId)}`;
    const record = await page.evaluate(async ({ transport, caseId, url, operation, prompt }) => {
      window.__privokeCaptureCase = caseId;
      const body = JSON.stringify({ messages: [{ role: "user", content: prompt }] });
      const started = performance.now();
      let outcome;
      if (transport === "fetch") {
        const controller = new AbortController();
        if (operation === "cancel") setTimeout(() => controller.abort(), 150);
        try { const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
          body, signal: controller.signal }); await response.arrayBuffer(); outcome = { status: response.status }; }
        catch (error) { outcome = { errorName: error?.name || "Error" }; }
      } else {
        outcome = await new Promise((resolve) => {
          const xhr = new XMLHttpRequest();
          const events = [];
          for (const name of ["readystatechange", "error", "abort", "timeout", "load", "loadend"])
            xhr.addEventListener(name, () => events.push(name));
          xhr.open("POST", url, true);
          xhr.setRequestHeader("content-type", "application/json");
          if (operation === "xhr-timeout") xhr.timeout = 150;
          xhr.addEventListener("loadend", () => resolve({ status: xhr.status, readyState: xhr.readyState, events }), { once: true });
          xhr.send(body);
          if (operation === "cancel") setTimeout(() => xhr.abort(), 150);
        });
      }
      return { caseId, transport, operation, url, body, outcome, totalMs: performance.now() - started,
        analyses: window.__privokeAnalyses.filter((entry) => entry.caseId === caseId) };
    }, { transport, caseId, url, operation, prompt: PROMPT });
    record.preProbeQuiescentAtMonotonicMs = preProbeQuiescentAtMonotonicMs;
    return { record, beforeRpc };
  };
  const complete = async (pending, options) => {
    const deadline = Date.now() + 8_000;
    if (options.expectedLayers) {
      while (rpcEvents.length <= pending.beforeRpc && Date.now() < deadline) await delay(25);
    }
    pending.record.postProbeQuiescentAtMonotonicMs = await waitQuiescence();
    pending.record.analyses = await page.evaluate((id) => window.__privokeAnalyses.filter((entry) => entry.caseId === id), pending.record.caseId);
    const captures = providerCaptures.filter((entry) => new URL(`https://fixture${entry.path}`).searchParams.get("case_id") === pending.record.caseId);
    const rpcs = rpcEvents.slice(pending.beforeRpc).filter((entry) => entry.method === "AnalyzePrompt");
    if (options.expectedLayers) {
      assert.equal(rpcs.length, 1, "one decoded actual runtime RPC is required");
      assertSequentialRpc(rpcs[0], pending.record, runtimeIds, networkIds);
    }
    pending.record.receiverCaptures = captures;
    pending.record.runtimeRpc = rpcs[0] ?? null;
    pending.record.declared = options;
    assertAdditionalProbe({ record: pending.record, captures, rpc: rpcs[0], ...options });
    records.push(pending.record);
    await saved();
  };
  const pauseSupervisor = async () => {
    const status = await runtimeStatus(popup);
    const detector = await processIdentity(Number(status.processId));
    const supervisor = await processIdentity(detector.parentPid);
    verifyOwnedSupervisor(supervisor, expectedSupervisor());
    await signal(supervisor, "SIGSTOP");
    pausedSupervisor = supervisor;
  };
  const resumeSupervisor = async () => {
    if (pausedSupervisor) { await signal(pausedSupervisor, "SIGCONT"); pausedSupervisor = null; }
  };
  const startModel = async () => {
    modelLog = await open(join(output, `parameter-server-${records.length}.log`), "wx");
    model = spawn("/usr/local/bin/privoke-model-streaming", [], {
      env: { ...process.env, MODEL_ARTIFACT_DIR: "/workspace/models", MODEL_LATEST_ID: "privoke-balanced", MODEL_STREAMING_PORT: "50051" },
      stdio: ["ignore", modelLog.fd, modelLog.fd],
    });
    model.once("error", () => {});
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (model.exitCode !== null) throw new Error("isolated parameter server exited during startup");
      try { await exec("/usr/local/bin/privoke-model-streaming", ["healthcheck"], {
        env: { ...process.env, MODEL_STREAMING_PORT: "50051" }, timeout: 2_000 }); return; }
      catch { await delay(100); }
    }
    throw new Error("isolated parameter server failed health readiness");
  };
  const stopModel = async () => {
    if (model && model.exitCode === null && model.signalCode === null) {
      const closed = new Promise((resolve) => model.once("close", resolve));
      model.kill("SIGTERM");
      await Promise.race([closed, delay(5_000).then(() => { throw new Error("parameter server cleanup timed out"); })]);
    }
    model = null;
    await modelLog?.close(); modelLog = null;
  };
  const settings = async (layers) => {
    const result = await sendExtensionMessage(popup, { type: "UPDATE_SETTINGS", patch: { layers, modelQuality: "balanced" } });
    assert.equal(result.ok, true);
    await delay(5_100); // The actual extension health cache expires after five seconds.
  };
  try {
    for (const transport of ["fetch", "xhr"]) {
      await pauseSupervisor();
      const timeout = await probe(transport, "bridge-silent-rpc-timeout");
      await resumeSupervisor();
      assert.ok(timeout.record.totalMs >= 29_000 && timeout.record.totalMs <= 36_000);
      await complete(timeout, { expectedLayers: REGEX_NER, expectedForwarded: false, expectedAction: "BLOCK" });
      await restoreRuntimeAndObserve();
      for (const operation of transport === "xhr" ? ["cancel", "xhr-timeout"] : ["cancel"]) {
        await pauseSupervisor();
        const cancelled = await probe(transport, operation, operation);
        await resumeSupervisor();
        if (transport === "fetch") assert.equal(cancelled.record.outcome.errorName, "AbortError");
        else assert.ok(cancelled.record.outcome.events.includes(operation === "cancel" ? "abort" : "timeout"));
        await complete(cancelled, { expectedLayers: REGEX_NER, expectedForwarded: false });
        await restoreRuntimeAndObserve();
      }
      await cdp.command("Debugger.enable");
      await cdp.command("Debugger.pause"); workerPaused = true;
      const missing = await probe(transport, "missing-analysis-worker-paused");
      assert.ok(missing.record.totalMs >= 31_000 && missing.record.totalMs <= 36_000);
      assert.equal(missing.record.analyses.filter((entry) => entry.phase === "result").length, 0,
        "missing-analysis probe must terminate before any analysis result arrives");
      missing.record.terminalAnalyses = [...missing.record.analyses];
      await cdp.command("Debugger.resume"); workerPaused = false;
      await delay(500);
      await complete(missing, { expectedLayers: REGEX_NER, expectedForwarded: false });
      const recovered = await probe(transport, "post-fault-recovery");
      await complete(recovered, { expectedLayers: REGEX_NER, expectedForwarded: true, expectedAction: "ALLOW", requireSuccess: true });
    }
    await startModel();
    for (const mode of ["full", "semantic-only"]) {
      const expectedLayers = mode === "full" ? FULL : SEMANTIC;
      await settings({ regex: mode === "full", ner: mode === "full", llm: true });
      for (const transport of ["fetch", "xhr"]) {
        const result = await probe(transport, mode);
        const action = result.record.analyses.find((entry) => entry.phase === "result")?.action;
        assert.ok(["ALLOW", "WARN", "BLOCK"].includes(action));
        await complete(result, { expectedLayers, expectedForwarded: action !== "BLOCK", requireSuccess: true,
          policy: "predeclared decision-driven forwarding; no semantic accuracy score" });
      }
    }
    await stopModel();
    await settings({ regex: false, ner: false, llm: true });
    for (const transport of ["fetch", "xhr"]) {
      const result = await probe(transport, "semantic-stream-unavailable");
      await complete(result, { expectedLayers: SEMANTIC, expectedForwarded: false, expectedAction: "BLOCK" });
      assert.ok(result.record.runtimeRpc.response?.decoded?.error
        || result.record.runtimeRpc.response?.decoded?.layers?.some((entry) => entry.status === "error"),
      "semantic-only outage must retain actual runtime error evidence");
    }
    await settings({ regex: true, ner: true, llm: true });
    for (const transport of ["fetch", "xhr"]) {
      const result = await probe(transport, "full-stream-unavailable-fallback");
      await complete(result, { expectedLayers: REGEX_NER, expectedForwarded: true, expectedAction: "ALLOW", requireSuccess: true });
    }
    await startModel();
    await delay(5_100);
    for (const transport of ["fetch", "xhr"]) {
      const result = await probe(transport, "stream-recovery-full");
      const action = result.record.analyses.find((entry) => entry.phase === "result")?.action;
      await complete(result, { expectedLayers: FULL, expectedForwarded: action !== "BLOCK", requireSuccess: true });
    }
    assert.equal(records.length, 19, "frozen additional matrix count changed");
    await waitQuiescence();
    await delay(500);
    await waitQuiescence();
    assert.equal(cdp.network.size, 0, "late runtime requests must reach observed terminal quiescence");
    for (const record of records) {
      const captures = providerCaptures.filter((entry) => new URL(`https://fixture${entry.path}`).searchParams.get("case_id") === record.caseId);
      assertAdditionalProbe({ record, captures, rpc: record.runtimeRpc, ...record.declared });
      record.lateReceiverRecheck = { count: captures.length, afterAllFaultsAndRecovery: true };
    }
    await saved();
    return { status: "complete", count: records.length, records,
      resourceCostScope: "excluded from the twelve regex+NER cost windows",
      compatibilityScope: "pinned Linux Chromium, chatgpt-shaped local HTTPS JSON fixture only" };
  } finally {
    if (workerPaused) await cdp.command("Debugger.resume");
    await resumeSupervisor();
    await stopModel();
    await sendExtensionMessage(popup, { type: "UPDATE_SETTINGS", patch: { layers: { regex: true, ner: true, llm: false } } });
    await saved();
  }
}
