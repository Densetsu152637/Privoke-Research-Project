// Actual installed-browser timing using the existing native launch/capture harness.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open, writeFile } from "node:fs/promises";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { assertAdditionalProbe, assertSequentialRpc } from "./installed-browser-additional.mjs";

const exec = promisify(execFile);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const RQ3_PROMPT = "Please explain the steps in this process.";
export const RQ3_MODEL_IDENTITY = Object.freeze({
  model_id: "privoke-balanced", model_version: "v0.3.0",
  artifact_checksum: "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c",
  parameter_fingerprint: "fec1a27b2252e01f659b5b856e5bdb124ef79b72f28995c7b3599f5ce0bd44c6",
});
export const RQ3_MODES = [
  { id: "detectors-off", layers: { regex: false, ner: false, llm: false }, expected: null },
  { id: "regex-ner", layers: { regex: true, ner: true, llm: false }, expected: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"] },
  { id: "semantic", layers: { regex: false, ner: false, llm: true }, expected: ["DETECTION_LAYER_SEMANTIC"] },
  { id: "full", layers: { regex: true, ner: true, llm: true }, expected: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER", "DETECTION_LAYER_SEMANTIC"] },
];

export function summarizeTiming(records) {
  const values = records.map((r) => r.totalMs).sort((a, b) => a - b);
  assert.ok(values.length && values.every((x) => Number.isFinite(x) && x >= 0));
  const rank = (q) => values[Math.ceil(q * values.length) - 1];
  return { n: values.length, p50: rank(.5), p95: rank(.95), max: rank(1),
    forwarded: records.filter((r) => r.receiverCaptures.length === 1).length,
    blocked: records.filter((r) => r.action === "BLOCK").length };
}

export async function startRq3Model(output) {
  const log = await open(join(output, "rq3-model.log"), "wx");
  const env = { ...process.env, MODEL_ARTIFACT_DIR: "/workspace/models", MODEL_LATEST_ID: "privoke-balanced", MODEL_STREAMING_PORT: "50051" };
  const model = spawn("/usr/local/bin/privoke-model-streaming", [], { env, stdio: ["ignore", log.fd, log.fd] });
  let stopped = false;
  const stop = async () => {
    if (stopped) return;
    stopped = true;
    if (model.exitCode === null && model.signalCode === null) {
      const close = new Promise((resolve) => model.once("close", resolve));
      model.kill("SIGTERM");
      await Promise.race([close, delay(5_000).then(() => { throw new Error("owned model cleanup timed out"); })]);
    }
    await log.close();
  };
  try {
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      try { await exec("/usr/local/bin/privoke-model-streaming", ["healthcheck"], { env, timeout: 2_000 }); return stop; }
      catch { if (model.exitCode !== null) break; await delay(100); }
    }
    throw new Error("owned model service not ready");
  } catch (error) { await stop(); throw error; }
}

export async function runRq3Session({ page, popup, cdp, providerCaptures, rpcEvents, fixtureUrl,
  output, sessionId, transport, replicate, sendExtensionMessage, verifyBoundary }) {
  const records = [];
  const runtimeIds = new Set(), networkIds = new Set();
  const path = join(output, `rq3-${sessionId}.json`);
  const state = { sessionId, transport, replicate, status: "running", records, boundaryRecords: [],
    baseline: "all detector layers disabled, extension and native infrastructure remain resident" };
  const save = () => writeFile(path, JSON.stringify(state, null, 2));
  const quiet = async () => {
    const deadline = Date.now() + 8_000;
    let since;
    while (Date.now() < deadline) {
      if (!cdp.network.size) { since ??= Date.now(); if (Date.now() - since >= 150) return performance.now(); }
      else since = undefined;
      await delay(25);
    }
    throw new Error("RQ3 observer failed terminal quiescence");
  };
  try {
    const modes = replicate === 1 ? RQ3_MODES : [...RQ3_MODES].reverse();
    for (const mode of modes) {
      const setting = await sendExtensionMessage(popup, { type: "UPDATE_SETTINGS", patch: {
        enabled: true, useLocalStack: true, modelQuality: "balanced", waitForRegex: true, layers: mode.layers } });
      assert.equal(setting.ok, true);
      await delay(5_100); // Actual model health cache must expire before the next arm.
      state.boundaryRecords.push({ mode: mode.id, phase: "before", identity: await verifyBoundary() });
      await save();
      for (let index = 0; index < 35; index++) {
        const phase = index < 5 ? "warmup" : "measured";
        const caseId = `rq3-${sessionId}-${mode.id}-${index}`;
        const preProbeQuiescentAtMonotonicMs = await quiet();
        const beforeRpc = rpcEvents.length;
        const url = `${fixtureUrl}/backend-api/conversation?case_id=${encodeURIComponent(caseId)}`;
        const record = await page.evaluate(async ({ transport, url, caseId, prompt }) => {
          window.__privokeCaptureCase = caseId;
          const body = JSON.stringify({ messages: [{ role: "user", content: prompt }] });
          const started = performance.now();
          let outcome;
          if (transport === "fetch") {
            try {
              const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
              await response.arrayBuffer(); outcome = { status: response.status };
            } catch (error) { outcome = { errorName: error?.name || "Error" }; }
          } else {
            outcome = await new Promise((resolve) => {
              const xhr = new XMLHttpRequest();
              const events = [];
              for (const name of ["error", "abort", "timeout", "load", "loadend"]) xhr.addEventListener(name, () => events.push(name));
              xhr.open("POST", url, true); xhr.setRequestHeader("content-type", "application/json");
              xhr.addEventListener("loadend", () => resolve({ status: xhr.status, events }), { once: true });
              xhr.send(body);
            });
          }
          return { caseId, url, body, transport, outcome, totalMs: performance.now() - started };
        }, { transport, url, caseId, prompt: RQ3_PROMPT });
        Object.assign(record, { mode: mode.id, phase, index, preProbeQuiescentAtMonotonicMs });
        records.push(record); // Preserve the attempted probe even if a subsequent gate fails.
        await save();
        record.postProbeQuiescentAtMonotonicMs = await quiet();
        record.analyses = await page.evaluate((id) => window.__privokeAnalyses.filter((r) => r.caseId === id), caseId);
        record.receiverCaptures = providerCaptures.filter((r) => new URL(`https://fixture${r.path}`).searchParams.get("case_id") === caseId);
        const rpcs = rpcEvents.slice(beforeRpc).filter((r) => r.method === "AnalyzePrompt");
        assert.equal(rpcs.length, Number(Boolean(mode.expected)));
        record.runtimeRpc = rpcs[0] ?? null;
        record.action = record.analyses.find((r) => r.phase === "result")?.action;
        assert.ok(["ALLOW", "WARN", "BLOCK"].includes(record.action));
        if (mode.expected) {
          assertSequentialRpc(rpcs[0], record, runtimeIds, networkIds);
          assertAdditionalProbe({ record, captures: record.receiverCaptures, rpc: rpcs[0],
            expectedLayers: mode.expected, expectedForwarded: record.action !== "BLOCK", requireSuccess: true });
          if (mode.layers.llm) {
            const metadata = rpcs[0].response.decoded.metadata;
            for (const [key, expected] of Object.entries(RQ3_MODEL_IDENTITY))
              assert.equal(metadata[`privoke.semantic.${key}`], expected, `pinned semantic identity differs: ${key}`);
          }
        } else {
          assert.equal(record.action, "ALLOW");
          assert.equal(record.receiverCaptures.length, 1);
          assert.equal(record.outcome.status, 200);
        }
        for (const capture of record.receiverCaptures) {
          assert.equal(capture.body, record.body);
          assert.equal(capture.bodySha256, createHash("sha256").update(record.body).digest("hex"));
        }
        record.integrity = "passed";
        await save();
      }
      state.boundaryRecords.push({ mode: mode.id, phase: "after", identity: await verifyBoundary() });
      await save();
    }
    assert.equal(records.filter((r) => r.phase === "measured").length, 120);
    state.summary = Object.fromEntries(RQ3_MODES.map((mode) => [mode.id,
      summarizeTiming(records.filter((r) => r.mode === mode.id && r.phase === "measured"))]));
    state.matchedReceiverCompletion = records.every((r) => r.receiverCaptures?.length === 1 && r.outcome.status === 200);
    if (state.matchedReceiverCompletion) {
      state.pairedProfileMedianDeltaMs = Object.fromEntries(RQ3_MODES.slice(1).map((mode) => [mode.id,
        state.summary[mode.id].p50 - state.summary["detectors-off"].p50]));
    }
    state.status = "complete";
    return state;
  } catch (error) {
    state.status = "failed";
    state.failure = { type: error.name, message: error.message.slice(0, 500) };
    throw error;
  } finally { await save(); }
}
