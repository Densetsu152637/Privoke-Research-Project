import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { summarizeContainerWindow, summarizeContainerStudy, assertStableBoundary, runDirectStartupTransition } from "./installed-browser-container-evidence.mjs";
const binding = { sourceRevision: "a".repeat(40), protocolSha256: "b".repeat(64) };
const identity = { membership_sha256: "c".repeat(64), mount_sha256: "d".repeat(64), namespace_inode: 100, files: [1,2,3].map((inode) => ({ device: 1, inode })) };
const row = (index = 0) => ({ schema_version: 1, sample_monotonic_ns: 1_000_000_000 + index * 100_000_000,
  observer_cpu_ns: 1_000 + index * 100, requested_interval_ms: 100,
  source_revision: binding.sourceRevision, protocol_sha256: binding.protocolSha256, cgroup_identity: structuredClone(identity),
  cpu_usage_usec: 10_000 + index * 2_000, memory_current_bytes: 400 + index * 100 });
const processIdentity = (pid, parentPid, startTicks) => ({ pid, parentPid, startTicks, parentStartTicks: parentPid * 10, commandSha256: "d".repeat(64) });
const boundary = (replacement = false) => ({ browser: processIdentity(10, 2, 100), supervisor: processIdentity(20, 1, 200),
  detector: processIdentity(replacement ? 31 : 30, 20, replacement ? 310 : 300), runtimeStatus: "RUNNING", verifiedAtMonotonicNs: 100,
  listeners: { 8080: [{ pid: 20, inode: "1" }], 50056: [{ pid: 20, inode: "2" }], 50057: [{ pid: replacement ? 31 : 30, inode: "3" }] } });

test("whole-container consumer retains CPU units, charged-memory max and actual gaps", () => {
  const result = summarizeContainerWindow([row(), row(1), row(2)], binding);
  assert.equal(result.cpuUsageSeconds, 0.004);
  assert.equal(result.observerCpuSeconds, 200 / 1e9);
  assert.equal(result.sampledMaximumChargedMemoryBytes, 600);
  assert.equal(result.maximumObservedGapMs, 100);
  assert.ok(!Object.hasOwn(result, "processes"));
});

test("closed container consumer rejects incomplete, corrupted, foreign and reset rows", () => {
  assert.throws(() => summarizeContainerWindow([row()], binding));
  for (const change of [{ roles: [] }, { cpu_usage_usec: -1 }, { cpu_usage_usec: 1 }, { observer_cpu_ns: 0 },
    { sample_monotonic_ns: 1_000_000_000 }, { sample_monotonic_ns: 1_500_000_001 }, { memory_current_bytes: null },
    { requested_interval_ms: 5 }, { schema_version: 2 }, { source_revision: "f".repeat(40) }, { protocol_sha256: "e".repeat(64) },
    { cgroup_identity: { ...identity, membership_sha256: "e".repeat(64) } },
    { cgroup_identity: { ...identity, files: [{ device: 0, inode: 1 }] } }]) {
    assert.throws(() => summarizeContainerWindow([row(), { ...row(1), ...change }], binding));
  }
});

function windows() {
  return Array.from({ length: 12 }, (_, index) => ({ sessionId: `session${index}`, finalized: true, terminalValidated: true,
    sha256: "f".repeat(64), phaseRequestCounts: { firstDecision: 1, warmup: 5, measured: 30 },
    startBoundary: { ...boundary(true), verifiedAtMonotonicNs: row(index * 3).sample_monotonic_ns }, endBoundary: { ...boundary(true), verifiedAtMonotonicNs: row(index * 3 + 1).sample_monotonic_ns }, requestedStartMonotonicNs: String(row(index * 3).sample_monotonic_ns),
    requestedEndMonotonicNs: String(row(index * 3 + 1).sample_monotonic_ns),
    containerObservation: summarizeContainerWindow([row(index * 3), row(index * 3 + 1)], binding) }));
}
test("twelve-window aggregate excludes gaps and requires finalized complete phase counts", () => {
  const full = windows();
  assert.ok(Math.abs(summarizeContainerStudy(full).cpuUsageSecondsWithinObservedWindows - 0.024) < 1e-12);
  assert.throws(() => summarizeContainerStudy(full.slice(1)));
  for (const change of [{ finalized: false }, { terminalValidated: false }, { sha256: null },
    { startBoundary: null }, { phaseRequestCounts: { firstDecision: 1, warmup: 5, measured: 29 } },
    { requestedStartMonotonicNs: "999999999999" }, { requestedEndMonotonicNs: "0" }]) {
    assert.throws(() => summarizeContainerStudy([{ ...full[0], ...change }, ...full.slice(1)]));
  }
  assert.throws(() => summarizeContainerStudy([full[0], full[0], ...full.slice(2)]));
});

test("direct boundary rejects reuse, role command drift and changed parents", () => {
  for (const role of ["browser", "supervisor", "detector"]) for (const key of ["pid", "startTicks", "commandSha256", "parentPid", "parentStartTicks"]) {
    const changed = boundary(); changed[role][key] = key === "commandSha256" ? "e".repeat(64) : 999;
    assert.throws(() => assertStableBoundary(changed, boundary()));
  }
});
function transition(overrides = {}) {
  let ready = 0;
  const config = { enabled: true, useLocalStack: true, layers: { regex: true, ner: true, llm: false }, waitForRegex: true };
  return runDirectStartupTransition({
    getSettings: async () => ({ ok: true, settings: { enabled: true, useLocalStack: false } }),
    waitReady: async () => ({ status: "RUNNING", replacement: ready++ > 0 }),
    captureRuntime: async (status) => boundary(status.replacement),
    updateSettings: async () => ({ ok: true, settings: config }), waitPredecessorReaped: async () => {},
    collectorClosed: new Promise(() => {}), ...overrides,
  });
}
test("direct startup executes real settings lifecycle without sampler RPC or enumeration", async () => {
  const result = await transition();
  assert.equal(result.current.detector.pid, 31);
  assert.equal(result.prior.detector.pid, 30);
  assert.ok(!Object.hasOwn(result, "prepareAck"));
});
test("direct startup blocks dispatch after bad initial settings/identity and marks postdispatch failures unknown", async () => {
  await assert.rejects(transition({ getSettings: async () => ({ ok: false }) }));
  await assert.rejects(transition({ updateSettings: async () => ({ ok: false }) }), (e) => e.startupLifecycleUnknown === true);
  await assert.rejects(transition({ waitPredecessorReaped: async () => { throw new Error("still alive"); } }), (e) => e.startupLifecycleUnknown === true);
  await assert.rejects(transition({ collectorClosed: Promise.resolve({ code: 1 }) }), /collector exited/);
  let clock = 0;
  await assert.rejects(transition({ now: () => clock += 50_000 }), /deadline/);
});

test("production pre-first boundary call executes in actual outer binding", async () => {
  const source = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const start = source.indexOf("  const firstBoundary = await captureDirectBoundary(");
  const end = source.indexOf("\n  const coldDecision =", start);
  const execute = (first) => vm.runInNewContext(`(async () => { ${source.slice(start, end)} })()`, {
    popup: {}, actualBrowser: {}, waitRuntimeReady: async () => ({}), captureDirectBoundary: async () => first,
    assertStableBoundary, transition: { current: boundary(true) }, currentResourceWindow: {}, publicBoundary: (b) => b,
  });
  await execute(boundary(true));
  await assert.rejects(execute(boundary(false)));
});


test("actual production known-PID boundary checks reject changed executables, parents, reuse and listeners", async () => {
  const source = await readFile(new URL("../../evaluation/run-installed-browser-capture.mjs", import.meta.url), "utf8");
  const text = source.slice(source.indexOf("async function captureDirectBoundary("), source.indexOf("async function waitForCondition("));
  const { createHash } = await import("node:crypto");
  const { join } = await import("node:path");
  const hash = (value) => createHash("sha256").update(value).digest("hex");
  const root = "/workspace";
  const command = (role) => [join(root, "extension/client-runtime/.venv/bin/python"), join(root,
    role === "supervisor" ? "extension/runtime-supervisor/src/main.py" : "extension/client-runtime/src/grpc_main.py")];
  const execute = async (mutate = () => {}, failListeners = false) => {
    const identities = new Map([[1, { pid: 1, startTicks: 10 }], [2, { pid: 2, startTicks: 20 }],
      [10, { ...processIdentity(10, 2, 100), parentStartTicks: 20 }],
      [20, { ...processIdentity(20, 1, 200), commandSha256: hash(command("supervisor").join(" ")) }],
      [31, { ...processIdentity(31, 20, 310), commandSha256: hash(command("detector").join(" ")) }]]);
    const expected = structuredClone(identities.get(10));
    const argv = new Map([[20, command("supervisor")], [31, command("detector")]]);
    mutate(identities, argv);
    const fn = vm.runInNewContext(`(${text})`, {
      assert, ROOT: root, join, sha256: hash, process: { pid: 2, hrtime: { bigint: () => 500n } },
      processIdentity: async (pid) => { assert.ok(identities.has(pid)); return { ...identities.get(pid) }; },
      readFile: async (path) => argv.get(Number(path.split(/[\\/]/)[2])).join("\0") + "\0",
      assertOwnedListeners: async () => { if (failListeners) throw new Error("missing owned listener"); return boundary(true).listeners; },
    });
    return fn({ enabled: true, status: "RUNNING", processId: 31 }, expected);
  };
  assert.equal((await execute()).detector.parentPid, 20);
  for (const mutate of [(ids) => { ids.get(10).startTicks++; },
    (ids) => { ids.get(10).parentPid = 9; }, (ids) => { ids.get(20).parentPid = 9; },
    (ids, argv) => { argv.get(31)[1] = "/foreign/grpc_main.py"; },
    (ids, argv) => { argv.get(20).push("--foreign"); }, (ids) => { ids.get(31).commandSha256 = "f".repeat(64); }]) {
    await assert.rejects(execute(mutate));
  }
  await assert.rejects(execute(() => {}, true), /listener/);
});
