import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import vm from "node:vm";
import {
  assertNativeParentBinding,
  assertNativeLauncherExecutableMount,
  assertCompleteResourceEvidence,
  buildStartupIdentityDiagnostic,
  assertPreservedControlSupervisor,
  assertReceiverCapture,
  frameGrpcWebMessage,
  parseGrpcWebFrames,
  preserveResourceEvidenceFailure,
  summarizeSupervisorStartupLog,
  mountEvidenceForPath,
  isBeforeFirstFixtureRequest,
  classifyLinuxProcessStat,
  isLinuxProcessIdentityReaped,
  assertOwnedDetectorIdentity,
  sessionCleanupProcessDisposition,
  validateAnalyzeRequest,
  validateAnalyzeResponse,
  validateDecodedOutcome,
  validatePageAnalysis,
  waitForProcessesToDisappear,
  validateSamplerTerminalDiagnostic,
  readSamplerTerminalSidecar,
  createResourceWindowFinalizer,
  runAfterResourceWindow,
  finalizeResourceWindowBeforeCleanup,
  assertStartupLifecycleKnown,
  summarizeResourceCpuWindows,
  createSamplerStartupTransitionClient,
  startupControlDigest,
  validateStartupTransitionWindow,
  runBoundedStartupTransition,
} from "./installed-browser-evidence.mjs";

test("runner startup transition waits for PREPARE and dispatch acknowledgements before settings", async () => {
  const order = [];
  const supervisor = { pid: 20, startTicks: 200, commandSha256: "a".repeat(64) };
  const detector = (pid, ticks) => ({ pid, startTicks: ticks, commandSha256: "b".repeat(64),
    parentPid: supervisor.pid, parentStartTicks: supervisor.startTicks });
  const statuses = [{ processId: "21" }, { processId: "22" }];
  const result = await runBoundedStartupTransition({
    sessionId: "01-fetch-allow-r1", sourceRevision: "c".repeat(40), protocolSha256: "d".repeat(64),
    getSettings: async () => ({ ok: true, settings: { enabled: true, useLocalStack: false } }),
    waitReady: async () => { order.push("status"); return statuses.shift(); },
    captureRuntime: async (status) => ({ status,
      detector: detector(Number(status.processId), Number(status.processId) * 10), supervisor, listeners: { 50057: [Number(status.processId)] } }),
    waitSampled: async (ids) => { order.push(`sample:${ids.at(-1).pid}`); return new Map(); },
    waitPredecessorReaped: async () => { order.push("reaped"); },
    exchange: async (record) => {
      assert.equal(record.type, ["prepare", "dispatch", "commit"][order.filter((item) => item.startsWith("ack:")).length]);
      order.push(`ack:${record.type}`);
      return { schema_version: 1, type: "ack", sequence: record.type, status: "accepted",
        transition_id: record.transition_id,
        observed_at_ns: "123456", predecessor: { pid: record.predecessor.pid, start_ticks: record.predecessor.start_ticks },
        supervisor: { pid: record.supervisor.pid, start_ticks: record.supervisor.start_ticks },
        successor: record.type === "commit" ? { pid: record.successor.pid, start_ticks: record.successor.start_ticks } : null,
        request_sha256: startupControlDigest(record) };
    },
    updateSettings: async () => {
      assert.deepEqual(order.slice(-2), ["ack:prepare", "ack:dispatch"]);
      order.push("settings");
      return { ok: true, settings: { enabled: true, useLocalStack: true,
        layers: { regex: true, ner: true, llm: false }, waitForRegex: true } };
    },
    nowNs: (() => { let value = 1000n; return () => (value += 100n).toString(); })(),
  });
  assert.deepEqual(order, ["status", "sample:21", "ack:prepare", "ack:dispatch", "settings",
    "status", "reaped", "sample:22", "ack:commit"]);
  assert.equal(result.current.detector.pid, 22);
  assert.equal(result.successor.start_ticks, 220);
  assert.ok(result.totalElapsedMs >= 0);
});

test("sampler transition pipe validates bounded acknowledged records", async () => {
  const child = { stdin: new PassThrough(), stdout: new PassThrough(), once() {} };
  child.stdin.on("data", (bytes) => {
    const request = JSON.parse(bytes.toString("utf8"));
    child.stdout.write(`${JSON.stringify({ schema_version: 1, type: "ack", sequence: request.type,
      transition_id: request.transition_id, request_sha256: startupControlDigest(request),
      status: "accepted", observed_at_ns: "123", predecessor: { pid: 20, start_ticks: 200 },
      supervisor: { pid: 10, start_ticks: 100 }, successor: null })}\n`);
  });
  const client = createSamplerStartupTransitionClient(child);
  const request = { schema_version: 1, type: "prepare", transition_id: "f".repeat(32),
    expires_at_ns: 1000,
    predecessor: { pid: 20, start_ticks: 200 }, supervisor: { pid: 10, start_ticks: 100 } };
  const ack = await client.exchange(request);
  assert.equal(ack.status, "accepted");
  client.close();

  const mismatched = { stdin: new PassThrough(), stdout: new PassThrough(), once() {} };
  mismatched.stdin.on("data", () => mismatched.stdout.write(`${JSON.stringify({ schema_version: 1,
    type: "ack", sequence: "prepare", transition_id: request.transition_id,
    request_sha256: "0".repeat(64), status: "accepted", observed_at_ns: "123",
    predecessor: { pid: 20, start_ticks: 200 }, supervisor: { pid: 10, start_ticks: 100 },
    successor: null })}\n`));
  const mismatchedClient = createSamplerStartupTransitionClient(mismatched);
  await assert.rejects(mismatchedClient.exchange(request), /acknowledgement is invalid/);
  mismatchedClient.close();

  const oversized = { stdin: new PassThrough(), stdout: new PassThrough(), once() {} };
  oversized.stdin.on("data", () => oversized.stdout.write(`${"x".repeat(4097)}\n`));
  const rejectingClient = createSamplerStartupTransitionClient(oversized);
  await assert.rejects(rejectingClient.exchange(request), /exceeded its byte bound/);
  rejectingClient.close();
});

test("startup settings are never dispatched if preparation acknowledgement fails", async () => {
  let dispatched = false;
  const supervisor = { pid: 20, startTicks: 200, commandSha256: "a".repeat(64) };
  await assert.rejects(runBoundedStartupTransition({
    sessionId: "01-fetch-allow-r1", sourceRevision: "c".repeat(40), protocolSha256: "d".repeat(64),
    getSettings: async () => ({ ok: true, settings: { enabled: true, useLocalStack: false } }),
    waitReady: async () => ({ processId: "21" }),
    captureRuntime: async () => ({ detector: { pid: 21, startTicks: 210, commandSha256: "b".repeat(64),
      parentPid: 20, parentStartTicks: 200 }, supervisor, listeners: {} }),
    waitSampled: async () => new Map(), waitPredecessorReaped: async () => {},
    exchange: async () => { throw new Error("unacknowledged"); },
    updateSettings: async () => { dispatched = true; },
  }), /unacknowledged/);
  assert.equal(dispatched, false);
});

test("one absolute startup deadline bounds settings, status, dispatch and commit awaits", async () => {
  async function startCase(targetPhase, { trackSamplerExit = false, autoFire = true } = {}) {
    const timers = [];
    const order = [];
    const supervisor = { pid: 20, startTicks: 200, commandSha256: "a".repeat(64) };
    const statuses = [{ processId: "21" }, { processId: "22" }];
    let finalStatusCalls = 0;
    let resolveLateSettings;
    let resolveSamplerExit;
    let fakeNow = 1_000n;
    const pendingSettings = new Promise((resolvePromise) => { resolveLateSettings = resolvePromise; });
    const samplerClosed = trackSamplerExit ? new Promise((resolvePromise) => { resolveSamplerExit = resolvePromise; }) : undefined;
    const start = runBoundedStartupTransition({
      sessionId: "01-fetch-allow-r1", sourceRevision: "c".repeat(40), protocolSha256: "d".repeat(64),
      nowNs: () => (fakeNow += 100n).toString(),
      scheduleTimeout: (callback, delayMs, phase) => {
        const timer = { phase, cancelled: false, fire() {
          fakeNow += BigInt(delayMs) * 1_000_000n;
          callback();
        } };
        timers.push(timer);
        return timer;
      },
      cancelTimeout: (timer) => { timer.cancelled = true; },
      getSettings: async () => {
        if (targetPhase === "initial settings read") return new Promise(() => {});
        return { ok: true, settings: { enabled: true, useLocalStack: false } };
      },
      waitReady: async () => {
        if (statuses.length === 2 && targetPhase === "initial runtime status") return new Promise(() => {});
        finalStatusCalls += 1;
        return statuses.shift();
      },
      captureRuntime: async (status) => ({ status,
        detector: { pid: Number(status.processId), startTicks: Number(status.processId) * 10,
          commandSha256: "b".repeat(64), parentPid: supervisor.pid, parentStartTicks: supervisor.startTicks },
        supervisor, listeners: { 50057: [Number(status.processId)] } }),
      waitSampled: async () => new Map(),
      waitPredecessorReaped: async () => {},
      exchange: async (record) => {
        order.push(record.type);
        if (targetPhase === `${record.type.toUpperCase()} acknowledgement`) return new Promise(() => {});
        return { schema_version: 1, type: "ack", sequence: record.type, status: "accepted",
          transition_id: record.transition_id, observed_at_ns: "123456",
          request_sha256: startupControlDigest(record),
          predecessor: { pid: record.predecessor.pid, start_ticks: record.predecessor.start_ticks },
          supervisor: { pid: record.supervisor.pid, start_ticks: record.supervisor.start_ticks },
          successor: record.type === "commit" ? { pid: record.successor.pid, start_ticks: record.successor.start_ticks } : null };
      },
      updateSettings: async () => {
        order.push("settings");
        return targetPhase === "settings update" ? pendingSettings : { ok: true,
        settings: { enabled: true, useLocalStack: true,
            layers: { regex: true, ner: true, llm: false }, waitForRegex: true } };
      },
      samplerClosed,
    });
    while (!timers.some((timer) => !timer.cancelled && timer.phase === targetPhase)) {
      await new Promise((resolvePromise) => setImmediate(resolvePromise));
    }
    if (autoFire) timers.findLast((timer) => !timer.cancelled && timer.phase === targetPhase).fire();
    return { start, order, getFinalStatusCalls: () => finalStatusCalls,
      resolveLateSettings: () => resolveLateSettings({ ok: true,
      settings: { enabled: true, useLocalStack: true,
        layers: { regex: true, ner: true, llm: false }, waitForRegex: true } }),
      resolveSamplerExit: () => resolveSamplerExit?.({ code: 1, signal: null }) };
  }

  for (const phase of ["initial settings read", "initial runtime status", "DISPATCH acknowledgement"]) {
    const result = await startCase(phase);
    await assert.rejects(result.start, (error) => error.name === "StartupTransitionDeadlineExceeded"
      && error.startupLifecycleUnknown !== true);
  }
  const late = await startCase("settings update");
  await assert.rejects(late.start, (error) => error.name === "StartupTransitionDeadlineExceeded"
    && error.startupLifecycleUnknown === true && error.preventMonitoredTeardown === true);
  late.resolveLateSettings();
  await new Promise((resolvePromise) => setImmediate(resolvePromise));
  assert.equal(late.getFinalStatusCalls(), 1, "late settings callback advanced to replacement status");

  const samplerExit = await startCase("settings update", { trackSamplerExit: true, autoFire: false });
  samplerExit.resolveSamplerExit();
  await assert.rejects(samplerExit.start, (error) => error.name === "StartupTransitionSamplerExited"
    && error.startupLifecycleUnknown === true && error.preventMonitoredTeardown === true);

  const commit = await startCase("COMMIT acknowledgement");
  await assert.rejects(commit.start, (error) => error.name === "StartupTransitionDeadlineExceeded"
    && error.startupLifecycleUnknown === true && error.preventMonitoredTeardown === true);
});

test("extension message callbacks and readiness status awaits have finite bounds", async () => {
  const runner = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const from = runner.indexOf("async function runtimeStatus(page,");
  const stop = runner.indexOf("async function processIdentity(pid)", from);
  assert.ok(from >= 0 && stop > from, "bounded runtime status and extension-message helpers must remain extractable");
  const helpers = `${runner.slice(from, stop)}\nglobalThis.__test = { sendExtensionMessage, waitRuntimeReady };`;
  const context = vm.createContext({
    assert,
    chrome: { runtime: { lastError: null, sendMessage() {} } },
    delay: (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
    safeError: () => ({ type: "Timeout" }),
    setTimeout,
    clearTimeout,
  });
  vm.runInContext(helpers, context);
  const helpersApi = context.__test;
  const page = { evaluate: (callback, payload) => callback(payload) };
  await assert.rejects(helpersApi.sendExtensionMessage(page, { type: "GET_SETTINGS" }, { timeoutMs: 5 }),
    /extension response callback timed out/);
  await assert.rejects(helpersApi.waitRuntimeReady(page, { timeoutMs: 5 }),
    /Browser-launched detector did not become ready/);
});

test("final startup detector requires its own interval, not the predecessor's earlier interval", () => {
  const predecessor = { pid: 12, start_ticks: 120, command_sha256: "a".repeat(64),
    parent_pid: 11, parent_start_ticks: 110 };
  const successor = { pid: 13, start_ticks: 130, command_sha256: "a".repeat(64),
    parent_pid: 11, parent_start_ticks: 110 };
  const supervisor = { pid: 11, start_ticks: 110, command_sha256: "b".repeat(64) };
  const transition = { status: "committed", transitionId: "f".repeat(32), predecessor, successor, supervisor,
    controlAcknowledgements: [
      { sequence: "prepare", requestSha256: "a".repeat(64), observedAtNs: "100" },
      { sequence: "dispatch", requestSha256: "b".repeat(64), observedAtNs: "200" },
      { sequence: "commit", requestSha256: "c".repeat(64), observedAtNs: "300" },
    ] };
  const events = [
    { type: "prepare", transition_id: transition.transitionId,
      predecessor: { pid: predecessor.pid, start_ticks: predecessor.start_ticks },
      supervisor: { pid: supervisor.pid, start_ticks: supervisor.start_ticks }, successor: null,
      request_sha256: "a".repeat(64), observed_at_ns: "100" },
    { type: "dispatch", transition_id: transition.transitionId,
      predecessor: { pid: predecessor.pid, start_ticks: predecessor.start_ticks },
      supervisor: { pid: supervisor.pid, start_ticks: supervisor.start_ticks }, successor: null,
      request_sha256: "b".repeat(64), observed_at_ns: "200" },
    { type: "predecessor_retired", transition_id: transition.transitionId,
      role: "detector", reason: "authorized_startup_transition", pid: predecessor.pid,
      start_ticks: predecessor.start_ticks, command_sha256: predecessor.command_sha256, parent_pid: supervisor.pid,
      parent_start_ticks: supervisor.start_ticks, state: "absent" },
    { type: "commit", transition_id: transition.transitionId,
      predecessor: { pid: predecessor.pid, start_ticks: predecessor.start_ticks },
      supervisor: { pid: supervisor.pid, start_ticks: supervisor.start_ticks },
      successor: { pid: successor.pid, start_ticks: successor.start_ticks },
      request_sha256: "c".repeat(64), observed_at_ns: "300" },
  ];
  const row = (role, pid, start_ticks, cpu_seconds) => ({ role, pid, start_ticks, cpu_seconds, rss_bytes: 10, pss_bytes: null });
  const sample = (time, cpuUsec, roles, startupEvents = []) => ({ sample_monotonic_ns: time,
    cgroup: { cpu_usage_usec: cpuUsec, memory_current_bytes: 100 },
    roles: [row("xvfb", 10, 100, time / 1e9), row("chromium", 14, 140, time / 1e9),
      row("supervisor_bridge", 11, 110, time / 1e9), ...roles], startup_transition_events: startupEvents });
  const samples = [
    sample(1_000_000_000, 100, [row("detector", 12, 120, 0.1)], [events[0]]),
    sample(1_500_000_000, 150, [row("detector", 13, 130, 0.2)], events.slice(1, 3)),
    sample(2_000_000_000, 200, [row("detector", 13, 130, 0.3)], [events[3]]),
  ];
  samples[2].roles.splice(3, 1);
  assert.throws(() => validateStartupTransitionWindow(samples, transition), /final detector lacks its own/);
  samples[2].roles.splice(3, 0, row("detector", 13, 130, 0.3));
  const evidence = validateStartupTransitionWindow(samples, transition);
  assert.equal(evidence.status, "verified");
  assert.equal(evidence.finalDetectorCpuSampleCount, 2);
});

test("resource windows finalize and validate before matrix work, exactly once", async () => {
  const events = [];
  const finalize = createResourceWindowFinalizer(async () => { events.push("close-reap-hash-validate"); });
  await runAfterResourceWindow(finalize, async () => { events.push("matrix"); });
  await finalize();
  assert.deepEqual(events, ["close-reap-hash-validate", "matrix"]);
});

test("resource finalization failures block matrix and still permit cleanup without retry", async () => {
  const events = [];
  const failure = new Error("synthetic unreaped sampler");
  const finalize = createResourceWindowFinalizer(async () => { events.push("finalize"); throw failure; });
  await assert.rejects(runAfterResourceWindow(finalize, async () => { events.push("matrix"); }), failure);
  const cleanup = await finalizeResourceWindowBeforeCleanup(finalize, async () => { events.push("cleanup"); });
  assert.equal(cleanup.finalizationError, failure);
  assert.equal(cleanup.cleanupError, null);
  assert.deepEqual(events, ["finalize", "cleanup"]);
});

test("uncommitted startup lifecycle prevents monitored session cleanup", async () => {
  const events = [];
  const result = await finalizeResourceWindowBeforeCleanup(
    async () => assertStartupLifecycleKnown(true),
    async () => { events.push("cleanup"); },
  );
  assert.equal(result.cleanupSkipped, true);
  assert.equal(result.finalizationError?.name, "StartupLifecycleQuiescenceUnknown");
  assert.deepEqual(events, []);
  assert.doesNotThrow(() => assertStartupLifecycleKnown(false));
});

test("unknown sampler quiescence blocks actual runner cleanup until an inert close arrives", async () => {
  const runner = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const from = runner.indexOf("async function finishSession() {");
  const stop = runner.indexOf("function stopSampler() {", from);
  const runtime = runner.indexOf("async function runtimeStatus(page,", stop);
  assert.ok(from >= 0 && stop > from && runtime > stop, "runner lifecycle functions must remain extractable");
  const lifecycleSource = `${runner.slice(from, stop)}\n${runner.slice(stop, runtime)}\nglobalThis.__test = { finishSession, stopSampler };`;
  const events = [];
  let resolveClose;
  const samplerClosed = new Promise((resolvePromise) => { resolveClose = resolvePromise; });
  const child = { exitCode: null, signalCode: null, kill(signal) { events.push(`signal:${signal}`); } };
  const context = vm.createContext({
    sampler: child,
    samplerClosed,
    samplerStopPromise: null,
    samplerPath: "resources/session.jsonl",
    samplerTerminalPath: "resources/session.jsonl.terminal.json",
    samplerSpawnError: null,
    samplerCloseState: "running",
    samplerClosureUnknown: false,
    samplerTerminalDiagnostics: [],
    sampleEndFailure: null,
    resourceFiles: [],
    receipt: null,
    OUTPUT: "/synthetic",
    currentResourceWindow: { sampledBrowserIdentities: [{ pid: 41, startTicks: 8 }] },
    startedProcesses: new Map([[41, { pid: 41, startTicks: 8 }]]),
    processTerminationEvidence: [],
    popup: {}, browserContext: {}, cdp: {}, testPage: {}, profilePath: "/synthetic/profile",
    finalizeCurrentResourceWindow: null,
    finalizeResourceWindowBeforeCleanup,
    createResourceWindowFinalizer,
    relative: (_root, file) => file,
    waitForSamplerClose: undefined,
    hashFile: async () => "synthetic-hash",
    readSamplerTerminalSidecar: async () => { throw new Error("synthetic sidecar unavailable"); },
    readFile: async () => "",
    parseJsonl: () => [],
    sendExtensionMessage: async () => { events.push("disable-detector"); return { ok: true }; },
    stopOwnedProcess: async () => { events.push("stop-runtime"); },
    waitOwnedProcessReaped: async () => {},
    waitSampledBrowserProcessesAbsent: async (ids) => { events.push(`wait-browser:${ids.length}`); },
    waitNoProcessContains: async () => {},
    rm: async () => {},
    assertPortsClosed: async () => {},
    assertNoOwnedProcesses: async () => {},
    setTimeout: (callback, milliseconds) => {
      events.push(`timeout:${milliseconds}`);
      queueMicrotask(callback);
      return milliseconds;
    },
    clearTimeout: () => {},
  });
  vm.runInContext(lifecycleSource, context);
  vm.runInContext(`finalizeCurrentResourceWindow = createResourceWindowFinalizer(async () => { await stopSampler(); });`, context);
  await assert.rejects(vm.runInContext(`finishSession()`, context), /quiescence remains unconfirmed/);
  assert.equal(context.samplerClosureUnknown, true);
  assert.equal(context.sampler, child, "unknown sampler identity must remain retained");
  assert.equal(context.samplerPath, "resources/session.jsonl", "unknown sampler path must remain retained");
  assert.deepEqual(events, ["signal:SIGTERM", "timeout:10000", "signal:SIGKILL", "timeout:2000"]);
  assert.equal(context.samplerTerminalDiagnostics.at(-1).closeState, "unknown");
  await assert.rejects(vm.runInContext(`finishSession()`, context), /quiescence remains unconfirmed/);
  assert.deepEqual(events, ["signal:SIGTERM", "timeout:10000", "signal:SIGKILL", "timeout:2000"],
    "a repeated cleanup must neither retry sampler termination nor run monitored teardown");
  assert.equal(resolveClose instanceof Function, true);
});

test("late sampler close is reaped before monitored cleanup and preserves timeout failure", async () => {
  const runner = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const from = runner.indexOf("async function finishSession() {");
  const stop = runner.indexOf("function stopSampler() {", from);
  const runtime = runner.indexOf("async function runtimeStatus(page,", stop);
  const lifecycleSource = `${runner.slice(from, stop)}\n${runner.slice(stop, runtime)}\nglobalThis.__test = { finishSession };`;
  const events = [];
  let closeResolve;
  const closed = new Promise((resolvePromise) => { closeResolve = resolvePromise; });
  const child = { exitCode: null, signalCode: null, kill(signal) {
    events.push(`signal:${signal}`);
    if (signal === "SIGKILL") queueMicrotask(() => closeResolve({ code: null, signal: "SIGKILL" }));
  } };
  const context = vm.createContext({
    sampler: child, samplerClosed: closed, samplerStopPromise: null,
    samplerPath: "resources/session.jsonl", samplerTerminalPath: "resources/session.jsonl.terminal.json",
    samplerSpawnError: null, samplerCloseState: "running", samplerClosureUnknown: false,
    samplerTerminalDiagnostics: [], sampleEndFailure: null, resourceFiles: [{ file: "resources/session.jsonl" }],
    receipt: null, OUTPUT: "/synthetic", currentResourceWindow: { sampledBrowserIdentities: [{ pid: 41, startTicks: 8 }] },
    startedProcesses: new Map([[41, { pid: 41, startTicks: 8 }]]), processTerminationEvidence: [],
    popup: {}, browserContext: {}, cdp: {}, testPage: {}, profilePath: "/synthetic/profile",
    finalizeCurrentResourceWindow: null, finalizeResourceWindowBeforeCleanup, createResourceWindowFinalizer,
    relative: (_root, file) => file, hashFile: async () => "synthetic-hash",
    readSamplerTerminalSidecar: async () => { throw new Error("synthetic sidecar unavailable"); },
    readFile: async () => "", parseJsonl: () => [],
    sendExtensionMessage: async () => { events.push("disable-detector"); return { ok: true }; },
    stopOwnedProcess: async () => { events.push("stop-runtime"); }, waitOwnedProcessReaped: async () => {},
    waitSampledBrowserProcessesAbsent: async () => {}, waitNoProcessContains: async () => {},
    rm: async () => {}, assertPortsClosed: async () => {}, assertNoOwnedProcesses: async () => {},
    setTimeout: (callback, milliseconds) => {
      events.push(`timeout:${milliseconds}`);
      if (milliseconds === 10_000) queueMicrotask(callback);
      else setTimeout(callback, 50);
      return milliseconds;
    },
    clearTimeout: () => {},
  });
  vm.runInContext(lifecycleSource, context);
  vm.runInContext(`finalizeCurrentResourceWindow = createResourceWindowFinalizer(async () => {
    await stopSampler();
    if (sampleEndFailure) throw new Error("resource capture window did not finalize cleanly");
  });`, context);
  await assert.rejects(vm.runInContext(`finishSession()`, context), /resource capture window did not finalize cleanly/);
  assert.match(context.sampleEndFailure.message, /did not close and reap/);
  assert.equal(context.samplerCloseState, "emergency_reaped");
  assert.equal(context.samplerClosureUnknown, false);
  assert.ok(events.indexOf("signal:SIGKILL") < events.indexOf("disable-detector"),
    "runtime teardown must follow the sampler close event");
  assert.ok(events.includes("stop-runtime"), "known quiescence permits normal cleanup despite failed measurement");
  assert.equal(context.samplerTerminalDiagnostics.at(-1).closeState, "emergency_reaped");
});

test("a startup/request failure can close its resource window before session cleanup", async () => {
  const events = [];
  const finalizer = createResourceWindowFinalizer(async () => { events.push("close-reap-hash-validate"); });
  const requestFailure = new Error("synthetic first decision failure");
  try {
    await Promise.reject(requestFailure);
  } catch (error) {
    assert.equal(error, requestFailure);
    const cleanup = await finalizeResourceWindowBeforeCleanup(finalizer, async () => { events.push("cleanup"); });
    assert.equal(cleanup.finalizationError, null);
  }
  assert.deepEqual(events, ["close-reap-hash-validate", "cleanup"]);
});

test("resource CPU uses per-window deltas and memory uses sampled maxima", () => {
  const row = (cpu, rss, pss = null) => ({ role: "detector", pid: 20, start_ticks: 500,
    cpu_seconds: cpu, rss_bytes: rss, pss_bytes: pss });
  const sample = (time, cpu, memory, process) => ({ sample_monotonic_ns: time,
    cgroup: { cpu_usage_usec: cpu, memory_current_bytes: memory }, roles: [process] });
  const result = summarizeResourceCpuWindows([
    { file: "window-a.jsonl", sessionId: "synthetic-a", requestedStartMonotonicNs: "0",
      requestedEndMonotonicNs: "2", phaseRequestCounts: { firstDecision: 1, warmup: 5, measured: 30 },
      samples: [sample(1, 100, 700, row(1, 600, 250)), sample(2, 110, 800, row(1.1, 650, null))] },
    { file: "window-b.jsonl", sessionId: "synthetic-b", requestedStartMonotonicNs: "2",
      requestedEndMonotonicNs: "4", phaseRequestCounts: { firstDecision: 1, warmup: 5, measured: 30 },
      samples: [sample(3, 300, 850, row(3, 640, 275)), sample(4, 310, 900, row(3.1, 700, null))] },
  ]);
  assert.equal(result.cgroupCpuSampledDeltaUsec, 20);
  assert.equal(result.cgroupMemorySampledPeakBytes, 900);
  const process = result.processes.get("detector/20/500");
  assert.ok(Math.abs(process.cpuDeltaSeconds - 0.2) < 1e-9);
  assert.equal(process.sampledPeakRssBytes, 700);
  assert.equal(process.sampledPeakPssBytes, 275);
  assert.deepEqual(result.windows.map((window) => window.cgroupCpuSampledDeltaUsec), [10, 10]);
  assert.deepEqual(result.windows.map((window) => window.sessionId), ["synthetic-a", "synthetic-b"]);
  assert.equal(result.windows[0].requestedEndMonotonicNs, "2");
  assert.equal(result.windows[0].firstSampleMonotonicNs, 1);
});

test("resource CPU deltas reject missing, negative, and decreasing counters", () => {
  const process = { role: "detector", pid: 20, start_ticks: 500, cpu_seconds: 1, rss_bytes: 10, pss_bytes: null };
  const row = (cpu) => ({ ...process, cpu_seconds: cpu });
  const sample = (time, cpu, processRows = [row(1)]) => ({ sample_monotonic_ns: time,
    cgroup: { cpu_usage_usec: cpu, memory_current_bytes: null }, roles: processRows });
  const one = (samples) => summarizeResourceCpuWindows([{ file: "synthetic.jsonl", samples }]);
  assert.throws(() => one([sample(1, 1), sample(2, undefined)]), /cgroup CPU counters/);
  assert.throws(() => one([sample(1, -1), sample(2, 1)]), /cgroup CPU counters/);
  assert.throws(() => one([sample(1, 1), sample(2, 2, [row(0.5)])]), /process CPU counter decreased/);
  assert.throws(() => one([sample(1, 1, [{ ...process, cpu_seconds: undefined }]), sample(2, 2, [])]), /process CPU counter/);
  const optionalPss = one([sample(1, 1, [process]), sample(2, 2, [])]);
  assert.equal(optionalPss.processes.get("detector/20/500").sampledPeakPssBytes, null);
  assert.equal(optionalPss.processes.get("detector/20/500").cpuDeltaSeconds, null,
    "a process observed once has no measured CPU interval");
});

test("resource windows reject singleton, empty, unsafe, equal, reversed, and over-cadence observations", () => {
  const row = { role: "detector", pid: 20, start_ticks: 500, cpu_seconds: 1, rss_bytes: 10, pss_bytes: null };
  const sample = (time, cpu) => ({ sample_monotonic_ns: time,
    cgroup: { cpu_usage_usec: cpu, memory_current_bytes: 100 }, roles: [row] });
  const one = (samples) => summarizeResourceCpuWindows([{ file: "synthetic.jsonl", samples }]);
  assert.throws(() => one([]), /at least two distinct observations/);
  assert.throws(() => one([sample(1, 1)]), /at least two distinct observations/);
  assert.throws(() => one([sample(1, 1), sample(1, 2)]), /timestamps must increase/);
  assert.throws(() => one([sample(2, 1), sample(1, 2)]), /timestamps must increase/);
  assert.throws(() => one([sample(Number.MAX_SAFE_INTEGER + 1, 1), sample(Number.MAX_SAFE_INTEGER + 2, 2)]), /exactly representable/);
  assert.throws(() => one([sample(0, 1), sample(500_000_001, 2)]), /gap exceeds 500 ms/);
  const boundary = one([sample(0, 1), sample(500_000_000, 2)]);
  assert.equal(boundary.maximumObservedSampleGapNs, 500_000_000);
});

async function productionResourceSummary(inputWindows) {
  const windows = inputWindows.length && inputWindows[0].sample_monotonic_ns !== undefined
    ? [inputWindows] : inputWindows;
  const source = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function resourceSummary(files) {");
  const end = source.indexOf("async function nativeHostEvidence(files, registration) {", start);
  assert.ok(start >= 0 && end > start, "production resource summary must remain extractable");
  const jsonlByPath = new Map(windows.map((samples, index) => [`window-${index}.jsonl`,
    `${samples.map((sample) => JSON.stringify(sample)).join("\n")}\n`]));
  const summarize = vm.runInNewContext(`(${source.slice(start, end)})`, {
    OUTPUT: "/synthetic",
    join: (_root, file) => file,
    readFile: async (_path) => jsonlByPath.get(_path),
    parseJsonl: (text) => text.split("\n").filter(Boolean).map((line) => JSON.parse(line)),
    summarizeResourceCpuWindows,
  });
  return summarize(windows.map((samples, index) => ({ file: `window-${index}.jsonl`,
    sha256: `synthetic-sha-${index}`, sessionId: `synthetic-session-${index}`,
    requestedStartMonotonicNs: "0", requestedEndMonotonicNs: "600000000",
    phaseRequestCounts: { firstDecision: 1, warmup: 5, measured: 30 },
    startupTransition: { status: "committed", samplerEvidence: { status: "verified",
      finalDetectorCpuSampleCount: 2 } } })));
}

function resourceSample(timestamp, cgroupCpu, coreCpu, { detectorSecond = true, nativeSingleton = true, chromiumChild = true } = {}) {
  const roles = ["xvfb", "chromium", "supervisor_bridge", "detector"].map((role, index) => ({
    role, pid: index + 10, start_ticks: index + 100, start_time_epoch_seconds: 1,
    cpu_seconds: coreCpu + index, rss_bytes: 4096 + index, pss_bytes: null,
  }));
  if (!detectorSecond && timestamp > 0) roles.splice(3, 1);
  if (nativeSingleton && timestamp === 0) roles.push({ role: "native_host", pid: 40,
    start_ticks: 400, start_time_epoch_seconds: 1, cpu_seconds: 0.1, rss_bytes: 100, pss_bytes: null });
  if (chromiumChild && timestamp === 0) roles.push({ role: "chromium", pid: 41,
    start_ticks: 410, start_time_epoch_seconds: 1, cpu_seconds: 0.2, rss_bytes: 200, pss_bytes: null });
  return { sample_monotonic_ns: timestamp, roles, process_identity_races: {},
    cgroup: { cpu_usage_usec: cgroupCpu, memory_current_bytes: 8192 } };
}

test("production resource summary accepts measured required intervals and leaves singleton native CPU null", async () => {
  const first = [
    resourceSample(0, 100, 1), resourceSample(500_000_000, 110, 1.5),
  ];
  const second = [
    resourceSample(600_000_000, 200, 2), resourceSample(1_100_000_000, 210, 2.5),
  ];
  second[0].roles.push({ role: "native_host", pid: 40, start_ticks: 400,
    cpu_seconds: 0.2, rss_bytes: 110, pss_bytes: null });
  const summary = await productionResourceSummary([first, second]);
  assertCompleteResourceEvidence(summary);
  assert.equal(summary.cgroupCpuSampledDeltaUsec, 20);
  assert.deepEqual(summary.windows.map((window) => window.cgroupCpuSampledDeltaUsec), [10, 10]);
  const native = summary.processes.find((process) => process.role === "native_host");
  assert.equal(native.cpuSampleCount, 2, "one singleton observation is retained from each resource window");
  assert.equal(native.cpuDeltaSeconds, null);
  assert.equal(native.cpuSampledSpanNs, 0);
  assert.equal(native.cpuUnmeasuredReason, "fewer_than_two_samples_in_any_window");
  const shortChromiumChild = summary.processes.find((process) => process.pid === 41);
  assert.equal(shortChromiumChild.cpuDeltaSeconds, null);
  assert.equal(summary.windows[0].maximumObservedSampleGapNs, 500_000_000);
  assert.equal(summary.windows[1].roleCpuIntervals.detector, 1);
});

test("production completeness guard requires every required role in every resource window", async () => {
  const validWindow = [resourceSample(0, 100, 1), resourceSample(500_000_000, 110, 1.5)];
  for (const role of ["xvfb", "detector"]) {
    const partialWindow = [resourceSample(600_000_000, 200, 2), resourceSample(1_100_000_000, 210, 2.5)];
    partialWindow[1].roles = partialWindow[1].roles.filter((item) => item.role !== role);
    const summary = await productionResourceSummary([validWindow, partialWindow]);
    assert.equal(summary.processes.some((item) => item.role === role && item.cpuIntervalCount >= 1), true,
      "a prior-window aggregate interval must not mask the partial later window");
    assert.equal(summary.processes.find((item) => item.role === role).cpuUnmeasuredReason,
      "required_role_missing_window_interval");
    assert.throws(() => assertCompleteResourceEvidence(summary), new RegExp(`${role} lacks a multi-observation CPU interval in every resource window`));
  }
});

test("production resource summary rejects duplicate process identity rows in one sample", async () => {
  const samples = [resourceSample(0, 100, 1), resourceSample(500_000_000, 110, 1.5)];
  samples[0].roles.push({ ...samples[0].roles[0], role: "native_host" });
  await assert.rejects(productionResourceSummary(samples), /duplicate process identity in one resource sample/);
});

test("sampler sidecar reader bounds bytes before parsing and rejects unsafe JSON privately", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sampler-terminal-"));
  const path = join(directory, "terminal.json");
  const valid = JSON.stringify({ schema_version: 1, status: "stopped", samples_written: 3,
    exception_type: null, frames: [] });
  try {
    await writeFile(path, valid, { flag: "wx" });
    const summary = await readSamplerTerminalSidecar(path);
    assert.equal(summary.diagnostic.samples_written, 3);
    assert.equal(summary.byteLength, Buffer.byteLength(valid));

    const invalidBodies = [
      [Buffer.alloc(8193, 0x78), /exceeds 8 KiB/],
      [Buffer.from([0xff, 0xfe]), /valid UTF-8/],
      [Buffer.from('{"schema_version":1,"schema_version":1,"status":"stopped","samples_written":0,"exception_type":null,"frames":[]}'), /duplicate/],
      [Buffer.from('{"schema_version":1,"status":"error","samples_written":0,"exception_type":"RuntimeError","frames":[{"file":"a.py","file":"b.py","function":"main","line":1}]}'), /duplicate/],
      [Buffer.from('{"schema_version":1,"status":"stopped","samples_written":0,"exception_type":null,"frames":[],"private":"synthetic-secret"}'), /invalid schema/],
    ];
    for (const [body, expectedError] of invalidBodies) {
      await rm(path);
      await writeFile(path, body, { flag: "wx" });
      await assert.rejects(readSamplerTerminalSidecar(path), (error) => {
        assert.match(error.message, expectedError);
        assert.equal(error.message.includes("synthetic-secret"), false);
        return true;
      });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

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
  const executableMount = mountEvidenceForPath("/tmp/launcher", mounts);
  assert.throws(() => assertNativeLauncherExecutableMount({ executable: true, mount: executableMount }), /noexec/);
  assert.throws(() => assertNativeLauncherExecutableMount({ executable: false,
    mount: { mountPoint: "/tmp", fsType: "tmpfs", noExec: false, readOnly: false } }), /not executable/);
  assert.throws(() => assertNativeLauncherExecutableMount({ executable: true, mount: null }), /unavailable/);
  assert.deepEqual(assertNativeLauncherExecutableMount({ executable: true,
    mount: { mountPoint: "/tmp", fsType: "tmpfs", noExec: false, readOnly: false } }), {
    executable: true, mount: { mountPoint: "/tmp", fsType: "tmpfs", noExec: false, readOnly: false },
  });
});

test("startup diagnostics are disabled as soon as fixture dispatch begins, even before outcomes exist", () => {
  const outcomeArrays = { coldRecords: [], caseRecords: [], rpcEvents: [], providerCaptures: [] };
  assert.equal(isBeforeFirstFixtureRequest(false), true);
  const fixtureRequestAttempted = true;
  assert.equal(Object.values(outcomeArrays).every((records) => records.length === 0), true);
  assert.equal(isBeforeFirstFixtureRequest(fixtureRequestAttempted), false);
});

test("owned process termination accepts only the expected identity's zombie/dead proc state", () => {
  const expected = { pid: 452, startTicks: 100 };
  const stat = (pid, state, ticks) => `${pid} (python3) ${state} ${Array(18).fill("0").join(" ")} ${ticks}`;
  assert.equal(classifyLinuxProcessStat(stat(452, "S", 100), expected), "running");
  assert.equal(classifyLinuxProcessStat(stat(452, "Z", 100), expected), "exited");
  assert.equal(classifyLinuxProcessStat(stat(452, "X", 100), expected), "exited");
  assert.equal(classifyLinuxProcessStat(stat(453, "Z", 100), expected), "different_process");
  assert.equal(classifyLinuxProcessStat(stat(452, "Z", 101), expected), "different_process");
  assert.equal(isLinuxProcessIdentityReaped(stat(452, "Z", 100), expected), false);
  assert.equal(isLinuxProcessIdentityReaped(stat(452, "S", 100), expected), false);
  assert.equal(isLinuxProcessIdentityReaped(stat(452, "S", 101), expected), true);
  assert.throws(() => classifyLinuxProcessStat("malformed", expected), /PID is missing/);
  assert.equal(sessionCleanupProcessDisposition(stat(452, "Z", 100), expected), "zombie_must_be_reaped");
  assert.equal(sessionCleanupProcessDisposition(stat(453, "Z", 100), expected), "identity_gone_or_reused");
  assert.equal(sessionCleanupProcessDisposition(stat(452, "S", 100), expected), "refuse_still_running");
});

test("detector stop identity retains exact child PID, start ticks and supervisor parent", () => {
  const expected = { pid: 452, parentPid: 324, startTicks: 100, command: "/workspace/extension/client-runtime/src/grpc_main.py" };
  assert.doesNotThrow(() => assertOwnedDetectorIdentity({ ...expected }, expected));
  assert.throws(() => assertOwnedDetectorIdentity({ ...expected, parentPid: 325 }, expected), /strictly equal/);
  assert.throws(() => assertOwnedDetectorIdentity({ ...expected, startTicks: 101 }, expected), /reused/);
  assert.throws(() => assertOwnedDetectorIdentity({ ...expected, command: "python worker.py" }, expected));
});

test("session cleanup requires reaping a same-identity zombie but accepts PID reuse and refuses live state", () => {
  const expected = { pid: 452, startTicks: 100 };
  const stat = (pid, state, ticks) => `${pid} (python3) ${state} ${Array(18).fill("0").join(" ")} ${ticks}`;
  assert.equal(sessionCleanupProcessDisposition(stat(452, "Z", 100), expected), "zombie_must_be_reaped");
  assert.equal(sessionCleanupProcessDisposition(stat(453, "Z", 100), expected), "identity_gone_or_reused");
  assert.equal(sessionCleanupProcessDisposition(stat(452, "S", 100), expected), "refuse_still_running");
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
    maximumObservedSampleGapNs: 100_000_000,
    windows: [{ sampleCount: 2, observedSampleSpanNs: 100_000_000,
      maximumObservedSampleGapNs: 100_000_000,
      roleCpuIntervals: { xvfb: 1, chromium: 1, supervisor_bridge: 1, detector: 1 },
      startupTransition: { status: "committed", samplerEvidence: { status: "verified",
        finalDetectorCpuSampleCount: 2 } } }],
    processes: ["xvfb", "chromium", "supervisor_bridge", "detector"].map((role) => ({
      role, startTicks: 100, sampledPeakRssBytes: 4096, sampledPeakPssBytes: null, cpuDeltaSeconds: 0.1,
      cpuSampleCount: 2, cpuIntervalCount: 1, cpuSampledSpanNs: 100_000_000,
      missingRssSamples: 0, missingCpuSamples: 0, missingStartTicksSamples: 0,
    })),
  };
  assert.equal(assertCompleteResourceEvidence(valid), valid);
  const chromiumChurn = structuredClone(valid);
  chromiumChurn.processIdentityRaceDropsByRole = { chromium: 11 };
  assert.equal(assertCompleteResourceEvidence(chromiumChurn), chromiumChurn);
  const requiredRoleChurn = structuredClone(valid);
  requiredRoleChurn.processIdentityRaceDropsByRole = { detector: 1 };
  assert.throws(() => assertCompleteResourceEvidence(requiredRoleChurn), /cannot be silently omitted/);
  for (const field of ["missingRssSamples", "missingCpuSamples", "missingStartTicksSamples"]) {
    const partial = structuredClone(valid);
    partial.processes[0][field] = 1;
    assert.throws(() => assertCompleteResourceEvidence(partial), /missing/);
  }
  const missingCgroupCpu = structuredClone(valid);
  missingCgroupCpu.cgroupCpuMissingSamples = 1;
  assert.throws(() => assertCompleteResourceEvidence(missingCgroupCpu), /cgroup CPU samples are incomplete/);
  const overCadence = structuredClone(valid);
  overCadence.windows[0].maximumObservedSampleGapNs = 500_000_001;
  assert.throws(() => assertCompleteResourceEvidence(overCadence), /cadence exceeds 500 ms/);
  const singletonRole = structuredClone(valid);
  singletonRole.processes.find((item) => item.role === "detector").cpuDeltaSeconds = null;
  singletonRole.processes.find((item) => item.role === "detector").cpuIntervalCount = 0;
  singletonRole.processes.find((item) => item.role === "detector").cpuSampledSpanNs = 0;
  assert.throws(() => assertCompleteResourceEvidence(singletonRole), /detector lacks a valid multi-observation CPU interval/);
});

test("startup identity timeout evidence counts exact role PID/tick matches without process text", () => {
  const rows = [
    { roles: [
      { role: "supervisor_bridge", pid: 10, start_ticks: 100, start_time_epoch_seconds: 12.5, command_sha256: "ignored" },
      { role: "detector", pid: 20, start_ticks: 202, start_time_epoch_seconds: 13.5 },
    ] },
    { roles: [
      { role: "supervisor_bridge", pid: 10, start_ticks: 100, start_time_epoch_seconds: null },
      { role: "detector", pid: 20, start_ticks: 203, start_time_epoch_seconds: 13.6 },
    ] },
  ];
  const result = buildStartupIdentityDiagnostic([
    { role: "supervisor_bridge", pid: 10, startTicks: 100 },
    { role: "detector", pid: 20, startTicks: 201 },
  ], rows);
  assert.equal(result.sampleRowCount, 2);
  assert.deepEqual(result.expectedIdentities.map(({ exactPairSampleCount, exactPairFiniteStartTimeSampleCount }) =>
    ({ exactPairSampleCount, exactPairFiniteStartTimeSampleCount })), [
    { exactPairSampleCount: 2, exactPairFiniteStartTimeSampleCount: 1 },
    { exactPairSampleCount: 0, exactPairFiniteStartTimeSampleCount: 0 },
  ]);
  assert.deepEqual(result.expectedIdentities[1].observedRoleIdentities.map(({ pid, startTicks, sampleCount }) =>
    ({ pid, startTicks, sampleCount })), [
    { pid: 20, startTicks: 202, sampleCount: 1 },
    { pid: 20, startTicks: 203, sampleCount: 1 },
  ]);
  assert.equal(JSON.stringify(result).includes("command_sha256"), false);
  assert.throws(() => buildStartupIdentityDiagnostic([{ role: "detector", pid: 0, startTicks: 1 }], rows), /invalid/);
});

test("sampler terminal diagnostics accept bounded frames and reject messages or paths", () => {
  const stopped = { schema_version: 1, status: "stopped", samples_written: 12, exception_type: null, frames: [] };
  assert.equal(validateSamplerTerminalDiagnostic(stopped), stopped);
  const failed = { schema_version: 1, status: "error", samples_written: 3, exception_type: "RuntimeError",
    frames: [{ file: "installed-browser-resources.py", function: "_processes", line: 177 }] };
  assert.equal(validateSamplerTerminalDiagnostic(failed), failed);
  assert.throws(() => validateSamplerTerminalDiagnostic({ ...failed, message: "synthetic prompt secret" }), /schema/);
  assert.throws(() => validateSamplerTerminalDiagnostic({ ...failed,
    frames: [{ ...failed.frames[0], file: "/private/path.py" }] }), /frame/);
  const processFailure = { schema_version: 1, role: "detector", reason: "predecessor_absent_before_dispatch",
    requested_identity: { pid: 321, state: null, start_ticks: 300, command_sha256: "a".repeat(64),
      parent_pid: 123, parent_start_ticks: 200 },
    observed_identity: { pid: 321, state: null, start_ticks: null, command_sha256: null,
      parent_pid: null, parent_start_ticks: null }, transition_state: "prepared", observed_at_ns: "123456" };
  const typedFailure = { ...failed, process_failure: processFailure };
  assert.equal(validateSamplerTerminalDiagnostic(typedFailure), typedFailure);
  assert.throws(() => validateSamplerTerminalDiagnostic({ ...typedFailure,
    process_failure: { ...processFailure, raw_command: "synthetic private command" } }), /process failure/);
  assert.throws(() => validateSamplerTerminalDiagnostic({ ...typedFailure,
    process_failure: { ...processFailure, reason: "private arbitrary message" } }), /process failure/);
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
