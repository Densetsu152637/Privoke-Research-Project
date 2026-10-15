import assert from "node:assert/strict";
import { validateSamplerTerminalDiagnostic } from "./installed-browser-evidence.mjs";

const exact = (value, keys, label) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} schema is closed`);
const natural = (value) => assert.ok(Number.isSafeInteger(value) && value >= 0, "invalid nonnegative exact counter");

export function summarizeContainerWindow(rows, { sourceRevision, protocolSha256 }) {
  assert.ok(Array.isArray(rows) && rows.length >= 2, "container window needs two observations");
  let prior;
  const gaps = [];
  for (const row of rows) {
    exact(row, ["schema_version", "read_started_monotonic_ns", "final_observation", "sample_monotonic_ns", "observer_cpu_ns", "requested_interval_ms", "source_revision", "protocol_sha256", "cgroup_identity", "cpu_usage_usec", "memory_current_bytes"], "container row");
    assert.equal(row.schema_version, 1);
    assert.equal(row.requested_interval_ms, 100);
    assert.equal(row.source_revision, sourceRevision);
    assert.equal(row.protocol_sha256, protocolSha256);
    for (const key of ["read_started_monotonic_ns", "sample_monotonic_ns", "observer_cpu_ns", "cpu_usage_usec", "memory_current_bytes"]) natural(row[key]);
    assert.equal(typeof row.final_observation, "boolean");
    assert.ok(row.sample_monotonic_ns >= row.read_started_monotonic_ns, "sample read time reversed");
    if (row.final_observation) assert.equal(row, rows.at(-1), "terminal observation must be last");
    const identity = row.cgroup_identity;
    exact(identity, ["membership_sha256", "mount_sha256", "namespace_inode", "files"], "cgroup identity");
    assert.match(identity.membership_sha256, /^[a-f0-9]{64}$/);
    assert.match(identity.mount_sha256, /^[a-f0-9]{64}$/); natural(identity.namespace_inode);
    assert.equal(identity.files.length, 3);
    for (const file of identity.files) {
      exact(file, ["device", "inode"], "cgroup file identity");
      natural(file.device); natural(file.inode);
    }
    if (prior) {
      assert.deepEqual(identity, prior.cgroup_identity, "cgroup identity changed");
      const gap = row.sample_monotonic_ns - prior.sample_monotonic_ns;
      assert.ok(gap > 0 && row.read_started_monotonic_ns > prior.sample_monotonic_ns, "nonpositive sample time");
      assert.ok(row.cpu_usage_usec >= prior.cpu_usage_usec, "cgroup CPU reset");
      assert.ok(row.observer_cpu_ns >= prior.observer_cpu_ns, "observer CPU reset");
      gaps.push(gap);
    }
    prior = row;
  }
  const first = rows[0], last = rows.at(-1);
  const sortedGaps = [...gaps].sort((a, b) => a - b);
  const quantile = (p) => sortedGaps[Math.max(0, Math.ceil(p * sortedGaps.length) - 1)] / 1e6;
  return { sampleCount: rows.length, requestedIntervalMs: 100,
    finalObservation: last.final_observation, lastReadStartedMonotonicNs: last.read_started_monotonic_ns,
    observedGapP50Ms: quantile(0.5), observedGapP95Ms: quantile(0.95), observedGapP99Ms: quantile(0.99),
    gapsOver200Ms: gaps.filter((gap) => gap > 200e6).length,
    gapsOver500Ms: gaps.filter((gap) => gap > 500e6).length,
    gapsOver1000Ms: gaps.filter((gap) => gap > 1000e6).length,
    firstReadStartedMonotonicNs: first.read_started_monotonic_ns, firstObservedMonotonicNs: first.sample_monotonic_ns, lastObservedMonotonicNs: last.sample_monotonic_ns,
    observedSpanMs: (last.sample_monotonic_ns - first.sample_monotonic_ns) / 1e6,
    minimumObservedGapMs: Math.min(...gaps) / 1e6, maximumObservedGapMs: Math.max(...gaps) / 1e6,
    meanObservedGapMs: gaps.reduce((a, b) => a + b, 0) / gaps.length / 1e6,
    cpuUsageSeconds: (last.cpu_usage_usec - first.cpu_usage_usec) / 1e6,
    observerCpuSeconds: (last.observer_cpu_ns - first.observer_cpu_ns) / 1e9,
    sampledMaximumChargedMemoryBytes: rows.reduce((max, row) => Math.max(max, row.memory_current_bytes), 0),
    cgroupIdentity: first.cgroup_identity, firstCpuUsageUsec: first.cpu_usage_usec, lastCpuUsageUsec: last.cpu_usage_usec };
}

export function summarizeContainerStudy(windows) {
  assert.equal(windows.length, 12, "twelve container windows required");
  let prior;
  const sessions = new Set();
  for (const window of windows) {
    assert.ok(typeof window.sessionId === "string" && window.sessionId && !sessions.has(window.sessionId), "unique session required");
    sessions.add(window.sessionId);
    assert.equal(window.finalized, true);
    assert.equal(window.terminalValidated, true);
    assert.match(window.sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(window.phaseRequestCounts, { firstDecision: 1, warmup: 5, measured: 30 });
    assert.ok(window.startBoundary && window.endBoundary, "direct boundary identities missing");
    validateDirectBoundary(window.startBoundary); validateDirectBoundary(window.endBoundary);
    assertStableBoundary(window.endBoundary, window.startBoundary);
    assert.ok(window.endBoundary.verifiedAtMonotonicNs >= window.startBoundary.verifiedAtMonotonicNs);
    const requestedStart = Number(window.requestedStartMonotonicNs), requestedEnd = Number(window.requestedEndMonotonicNs);
    natural(requestedStart); natural(requestedEnd);
    assert.ok(requestedStart <= window.startBoundary.verifiedAtMonotonicNs && window.endBoundary.verifiedAtMonotonicNs <= requestedEnd);
    const summary = window.containerObservation;
    assert.ok(summary && summary.sampleCount >= 2);
    for (const key of ["observedSpanMs", "minimumObservedGapMs", "maximumObservedGapMs", "meanObservedGapMs", "cpuUsageSeconds", "observerCpuSeconds", "sampledMaximumChargedMemoryBytes"])
      assert.ok(Number.isFinite(summary[key]) && summary[key] >= 0);
    assert.ok(summary.minimumObservedGapMs > 0);
    assert.equal(summary.finalObservation, true, "fresh stop-triggered terminal observation required");
    natural(window.stopRequestedMonotonicNs); natural(window.browserLaunchRequestedMonotonicNs);
    assert.ok(window.stopRequestedMonotonicNs > window.endBoundary.verifiedAtMonotonicNs);
    assert.ok(summary.lastReadStartedMonotonicNs >= window.stopRequestedMonotonicNs);
    assert.ok(summary.firstObservedMonotonicNs <= window.browserLaunchRequestedMonotonicNs, "first observation must precede browser launch");
    assert.ok(summary.lastReadStartedMonotonicNs > window.endBoundary.verifiedAtMonotonicNs,
      "terminal resource read must start after last measured request and final boundary");
    assert.ok(Number(window.requestedStartMonotonicNs) <= summary.firstReadStartedMonotonicNs);
    assert.ok(Number(window.requestedEndMonotonicNs) >= summary.lastObservedMonotonicNs);
    if (prior) {
      assert.deepEqual(summary.cgroupIdentity, prior.cgroupIdentity);
      assert.ok(summary.firstObservedMonotonicNs > prior.lastObservedMonotonicNs, "container windows overlap");
      assert.ok(summary.firstCpuUsageUsec >= prior.lastCpuUsageUsec, "cross-window cgroup CPU reset");
    }
    prior = summary;
  }
  return { scope: "instrumented_whole_container", requestedIntervalMs: 100, windowCount: windows.length,
    cpuUsageSecondsWithinObservedWindows: windows.reduce((sum, w) => sum + w.containerObservation.cpuUsageSeconds, 0),
    observerCpuSecondsWithinObservedWindows: windows.reduce((sum, w) => sum + w.containerObservation.observerCpuSeconds, 0),
    sampledMaximumChargedMemoryBytes: Math.max(...windows.map((w) => w.containerObservation.sampledMaximumChargedMemoryBytes)),
    windows: windows.map((w) => ({ sessionId: w.sessionId, ...w.containerObservation })),
    interpretation: "Whole cgroup and descendants, including browser, runtime, receiver, display, harness and observer. CPU sums only within-window counter deltas. memory.current is charged memory, not RSS/PSS or memory.peak. All positive sampling gaps retained/reported; sampled maximum may miss spikes. No incremental protection overhead or continuous per-process attribution." };
}

export function validateDirectBoundary(boundary) {
  exact(boundary, ["verifiedAtMonotonicNs", "runtimeStatus", "browser", "supervisor", "detector", "listeners"], "direct boundary");
  natural(boundary.verifiedAtMonotonicNs); assert.equal(boundary.runtimeStatus, "RUNNING");
  for (const role of ["browser", "supervisor", "detector"]) {
    exact(boundary[role], ["pid", "parentPid", "startTicks", "commandSha256", "parentStartTicks"], "direct identity");
    for (const key of ["pid", "parentPid", "startTicks", "parentStartTicks"]) natural(boundary[role][key]);
    assert.ok(boundary[role].pid > 1 && boundary[role].startTicks > 0 && boundary[role].parentStartTicks > 0);
    assert.match(boundary[role].commandSha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(new Set([boundary.browser.pid, boundary.supervisor.pid, boundary.detector.pid]).size, 3);
  assert.ok(boundary.browser.parentPid > 1);
  assert.equal(boundary.supervisor.parentPid, 1);
  assert.equal(boundary.detector.parentPid, boundary.supervisor.pid);
  assert.equal(boundary.detector.parentStartTicks, boundary.supervisor.startTicks);
  exact(boundary.listeners, ["8080", "50056", "50057"], "boundary listeners");
  for (const port of [8080, 50056, 50057]) {
    assert.equal(boundary.listeners[port].length, 1);
    const owner = boundary.listeners[port][0];
    exact(owner, ["pid", "inode"], "listener owner");
    assert.equal(owner.pid, port === 50057 ? boundary.detector.pid : boundary.supervisor.pid);
    assert.match(owner.inode, /^[0-9]+$/);
  }
}

export function assertStableBoundary(actual, expected) {
  for (const role of ["browser", "supervisor", "detector"]) {
    for (const key of ["pid", "startTicks", "commandSha256", "parentPid", "parentStartTicks"]) {
      assert.equal(actual[role][key], expected[role][key], `${role} boundary identity changed: ${key}`);
    }
  }
}

export async function runDirectStartupTransition({ getSettings, waitReady, captureRuntime, updateSettings, waitPredecessorReaped, collectorClosed, now = () => performance.now(), timeoutMs = 90_000 }) {
  const start = now(), deadline = start + timeoutMs;
  let dispatched = false, committed = false, collectorExited = false;
  const collectorExit = collectorClosed.then(() => { collectorExited = true; });
  const bounded = async (phase, operation) => {
    assert.equal(collectorExited, false, "container collector exited during startup");
    const remaining = deadline - now();
    assert.ok(remaining > 0, `startup deadline exceeded: ${phase}`);
    let timer;
    try {
      const result = await Promise.race([Promise.resolve().then(() => operation(Math.ceil(remaining))), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`startup deadline exceeded: ${phase}`)), remaining);
      }), collectorExit.then(() => { throw new Error("container collector exited during startup"); })]);
      assert.equal(collectorExited, false, "container collector exited during startup");
      assert.ok(now() < deadline, `startup deadline exceeded: ${phase}`);
      return result;
    } finally { clearTimeout(timer); }
  };
  const timings = {};
  const timed = async (name, op) => { const mark = now(); const value = await bounded(name, op); timings[name] = now() - mark; return value; };
  try {
    const settings = await timed("settingsReadMs", getSettings);
    assert.equal(settings?.ok, true); assert.equal(settings.settings.enabled, true); assert.equal(settings.settings.useLocalStack, false);
    const priorStatus = await timed("priorStatusMs", waitReady);
    const prior = await timed("priorIdentityMs", () => captureRuntime(priorStatus));
    // Recheck immediately before the only settings dispatch.
    assertStableBoundary(await timed("priorRecheckMs", () => captureRuntime(priorStatus)), prior);
    dispatched = true;
    const configured = await timed("settingsUpdateMs", updateSettings);
    assert.equal(configured?.ok, true);
    assert.equal(configured.settings.useLocalStack, true); assert.equal(configured.settings.enabled, true);
    assert.deepEqual(configured.settings.layers, { regex: true, ner: true, llm: false });
    assert.equal(configured.settings.waitForRegex, true);
    const status = await timed("finalStatusMs", waitReady);
    const current = await timed("finalIdentityMs", () => captureRuntime(status));
    assertStableBoundary({ ...current, detector: prior.detector }, prior);
    assert.notEqual(current.detector.pid, prior.detector.pid);
    assert.notEqual(current.detector.startTicks, prior.detector.startTicks);
    await timed("predecessorReapMs", () => waitPredecessorReaped(prior.detector));
    assertStableBoundary(await timed("finalRecheckMs", () => captureRuntime(status)), current);
    committed = true;
    return { status, prior, current, settings: configured.settings, timings, totalElapsedMs: now() - start };
  } catch (error) {
    if (dispatched && !committed) { error.startupLifecycleUnknown = true; error.preventMonitoredTeardown = true; }
    throw error;
  }
}


export function validateContainerTerminalDiagnostic(value) {
  const { observation_failure: failure, ...base } = value;
  exact(base, ["schema_version", "status", "samples_written", "exception_type", "frames"], "container terminal");
  validateSamplerTerminalDiagnostic(base);
  if (failure !== undefined) {
    assert.equal(base.status, "error");
    exact(failure, ["reason", "previous", "current"], "observation failure");
    assert.ok(["read_time_reversed", "cgroup_identity_changed", "nonpositive_sample_time", "counter_decreased"].includes(failure.reason));
    for (const row of [failure.previous, failure.current]) {
      exact(row, ["read_started_monotonic_ns", "sample_monotonic_ns", "observer_cpu_ns", "cpu_usage_usec", "cgroup_identity_sha256"], "failed observation");
      for (const key of ["read_started_monotonic_ns", "sample_monotonic_ns", "observer_cpu_ns", "cpu_usage_usec"]) natural(row[key]);
      assert.match(row.cgroup_identity_sha256, /^[0-9a-f]{64}$/);
    }
  }
  return value;
}
