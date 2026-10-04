import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:https";
import { execFile, execFileSync, spawn } from "node:child_process";
import { promisify } from "node:util";
import {
  mkdir,
  readFile,
  readlink,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { dirname, join, resolve, relative } from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import {
  assertAnalysisMessage,
  assertForwarding,
  CASES,
  DECISION_CELLS,
  TRANSPORTS,
} from "../extension/test/installed-browser-capture.mjs";
import {
  assertNativeParentBinding,
  assertPreservedControlSupervisor,
  assertCompleteResourceEvidence,
  preserveResourceEvidenceFailure,
  parseGrpcWebFrames,
  validateDecodedOutcome,
  validatePageAnalysis,
} from "../extension/test/installed-browser-evidence.mjs";

const execFileAsync = promisify(execFile);
const require = createRequire("/opt/privoke-browser-test/package.json");
const playwrightRoot = "/opt/privoke-browser-test/node_modules/playwright";
const { chromium } = require(playwrightRoot);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXTENSION_ID = "hmlhjfklebbbhpjdjodegbjnbamlkonp";
const NATIVE_HOST_NAME = "org.privoke.runtime_launcher";
const PORTS = [8080, 50056, 50057];
const PROTOCOL_VERSION = "installed-browser-enforcement-cost-v1";
const RATE_REPS = positiveInteger(process.env.PRIVOKE_INSTALLED_EVIDENCE_REPS, 30);
const WARMUPS = positiveInteger(process.env.PRIVOKE_INSTALLED_EVIDENCE_WARMUPS, 5);
const COLD_SESSIONS = positiveInteger(process.env.PRIVOKE_INSTALLED_EVIDENCE_SESSIONS, 12);
const args = parseArgs(process.argv.slice(2));
const SOURCE_REVISION = args["source-revision"] || process.env.PRIVOKE_SOURCE_REVISION || "";
const IMAGE_ID = args["image-id"] || process.env.PRIVOKE_INSTALLED_IMAGE_ID || "";
const ALLOWED_OUTPUT_ROOT = resolve("/workspace/evaluation/results/installed-browser-results");
const OUTPUT_PARENT = resolve(args.output || process.env.PRIVOKE_INSTALLED_EVIDENCE_OUTPUT
  || ALLOWED_OUTPUT_ROOT);
const runId = `${new Date().toISOString().replaceAll(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
const OUTPUT = join(OUTPUT_PARENT, `run-${runId}`);
const XDG_CONFIG_HOME = process.env.XDG_CONFIG_HOME || "/tmp/privoke-xdg";
const XDG_DATA_HOME = process.env.XDG_DATA_HOME || "/tmp/privoke-data";
const BROWSER_CONFIG_ROOT = join(XDG_CONFIG_HOME, "chromium");
const EXTENSION_ROOT = join(ROOT, "extension", "dist");
const RESOURCE_SAMPLER = join(ROOT, "extension", "test", "installed-browser-resources.py");
const SOURCE_FILES = [
  "evaluation/Dockerfile.browser-installed",
  "evaluation/compose.browser-installed.yml",
  "evaluation/run-installed-browser-capture.mjs",
  "extension/test/installed-browser-capture.mjs",
  "extension/test/installed-browser-evidence.mjs",
  "extension/test/installed-browser-evidence.test.mjs",
  "evaluation/run-installed-browser-unit-tests.mjs",
  "extension/test/installed-browser-resources.py",
  "extension/package.json",
  "extension/package-lock.json",
  "extension/manifest.json",
  "extension/extension-identities.json",
  "extension/src/background.js",
  "extension/src/settings.js",
  "extension/src/runtime-client.js",
  "extension/src/runtime-lifecycle.js",
  "extension/src/supervisor-launcher.js",
  "extension/src/page-interceptor.js",
  "extension/src/content-script.js",
  "extension/runtime-supervisor/scripts/install-native-host.sh",
  "extension/runtime-supervisor/src/native_messaging_host.py",
  "extension/runtime-supervisor/src/main.py",
  "extension/runtime-supervisor/src/runtime_supervisor.py",
  "extension/runtime-supervisor/src/grpc_web_bridge.py",
  "extension/client-runtime/src/grpc_main.py",
  "extension/client-runtime/src/hosting/grpc_server.py",
  "extension/client-runtime/src/pipeline.py",
  "extension/client-runtime/src/regex/rules_identity.py",
  "shared/proto/privoke/v1/runtime.proto",
  "paper/research/installed-browser-protocol.md",
];

let server;
let browserContext;
let cdp;
let sampler;
let samplerPath;
let samplerClosed;
let startedProcesses = new Map();
let receipt;
let sampleEndFailure;
let runFailure;
let captureSequence = 0;
let certificateDirectory;
const externalRequests = [];
const providerCaptures = [];
const caseRecords = [];
const rpcEvents = [];
const coldRecords = [];
const resourceFiles = [];
const pageRequestIds = new Set();
const runtimeRequestIds = new Set();
const phaseCounts = { firstDecision: 0, warmup: 0, measured: 0, matrix: 0 };
const timestamps = { started: new Date().toISOString() };
let hostRegistration;
let popup;
let testPage;
let profilePath;

try {
  assert.ok(/^[0-9a-f]{40}$/i.test(SOURCE_REVISION), "a full declared source revision is required");
  assert.ok(IMAGE_ID && IMAGE_ID !== "unreported", "the root-verified image ID is required");
  assert.ok(isWithin(ALLOWED_OUTPUT_ROOT, OUTPUT_PARENT), "output must stay under the dedicated installed-browser results mount");
  assert.equal(RATE_REPS, 30, "the protocol fixes 30 measured warm requests");
  assert.equal(WARMUPS, 5, "the protocol fixes five warmup requests");
  assert.equal(COLD_SESSIONS, 12, "the protocol fixes twelve fresh cold sessions");
  await mkdir(OUTPUT_PARENT, { recursive: true });
  await mkdir(OUTPUT, { recursive: false });
  await mkdir(join(OUTPUT, "captures"), { recursive: false });
  await writeFile(join(OUTPUT, "status.json"), JSON.stringify({ status: "running", runId }, null, 2), { flag: "wx" });
  await mkdir(dirname(process.env.PRIVOKE_ENV_FILE || "/tmp/privoke-client-config/.env"), { recursive: true });
  await writeFile(process.env.PRIVOKE_ENV_FILE || "/tmp/privoke-client-config/.env",
    "TELEMETRY_ENABLED=false\nPRIVOKE_MODEL_DEVICE=cpu\nPRIVOKE_USE_LOCAL_STACK=true\n", { flag: "wx" });

  receipt = await createInitialReceipt();
  await assertPortsClosed("before-native-registration");
  await installNativeHost();
  const { tls, fixtureUrl } = await startProviderFixture();
  receipt.fakeProvider = { origin: new URL(fixtureUrl).origin, certificateSha256: tls.certificateSha256 };
  const fixtureTargets = await import("../extension/src/generated/runtime.js");
  const protobuf = fixtureTargets.privoke.v1;
  const extensionTree = await hashTree(EXTENSION_ROOT);
  const sourceManifestBytes = await readFile(join(ROOT, "extension/manifest.json"));
  const builtManifestBytes = await readFile(join(EXTENSION_ROOT, "manifest.json"));
  const sourceManifest = JSON.parse(sourceManifestBytes.toString("utf8"));
  const builtManifest = JSON.parse(builtManifestBytes.toString("utf8"));
  const identities = JSON.parse(await readFile(join(ROOT, "extension/extension-identities.json"), "utf8"));
  assert.deepStrictEqual(builtManifest, sourceManifest, "built Chromium manifest semantics differ from source");
  assert.equal(sourceManifest.key, identities.chromium_public_key, "extension manifest key differs from pinned identity");
  receipt.extension = {
    id: EXTENSION_ID,
    loadedFrom: "/workspace/extension/dist",
    sourceManifestSha256: sha256(sourceManifestBytes),
    builtManifestSha256: sha256(builtManifestBytes),
    manifestSemanticsMatch: true,
    treeSha256: extensionTree.sha256,
    files: extensionTree.files,
  };

  for (let index = 0; index < COLD_SESSIONS; index += 1) {
    const cell = DECISION_CELLS[index % DECISION_CELLS.length];
    const replicate = Math.floor(index / DECISION_CELLS.length) + 1;
    const cold = await runColdSession({ index, cell, replicate, fixtureUrl, protobuf });
    coldRecords.push(cold.cold);
    if (index === 0) {
      const matrix = await runEnforcementMatrix({ fixtureUrl, protobuf });
      receipt.enforcementMatrix = matrix;
    }
    await finishSession();
  }

  await assertPortsClosed("after-last-session");
    await assertNoOwnedProcesses("after-last-session");
  await stopProviderFixture();
  await verifyNoExternalRequests();
  receipt.status = "complete";
  assert.deepEqual(phaseCounts, { firstDecision: 12, warmup: 60, measured: 360, matrix: 14 },
    "fixed request phase counts changed");
  receipt.completedAt = new Date().toISOString();
} catch (error) {
  runFailure = safeError(error);
  if (!receipt) receipt = await createInitialReceipt().catch(() => ({ protocolVersion: PROTOCOL_VERSION }));
  receipt.status = "failed";
  receipt.failure = runFailure;
  receipt.completedAt = new Date().toISOString();
  receipt.coldStarts = coldRecords;
  receipt.caseRecords = caseRecords;
  receipt.rpcEvents = rpcEvents;
  receipt.providerCaptures = providerCaptures;
  receipt.externalRequests = externalRequests.map((item) => ({ url: item.url, method: item.method }));
  console.error(`Installed-browser evidence failed (${runFailure.type}).`);
  process.exitCode = 1;
} finally {
  const cleanupFailures = [];
  let certificateDirectoryRemoved = !certificateDirectory;
  try { await finishSession(); } catch (error) { cleanupFailures.push(safeError(error)); }
  try { await stopProviderFixture(); } catch (error) { cleanupFailures.push(safeError(error)); }
  if (certificateDirectory) {
    try {
      await rm(certificateDirectory, { recursive: true, force: false });
      certificateDirectoryRemoved = true;
    }
    catch (error) { cleanupFailures.push(safeError(error)); }
    certificateDirectory = null;
  }
  if (receipt) {
    const sessionCleanupVerified = cleanupFailures.length === 0;
    const evidenceFailures = [];
    receipt.coldStarts = coldRecords;
    receipt.warmCosts = summariseCosts(caseRecords);
    receipt.caseRecords = caseRecords;
    receipt.rpcEvents = rpcEvents;
    receipt.providerCaptures = providerCaptures;
    receipt.externalRequests = externalRequests.map((item) => ({ url: item.url, method: item.method }));
    receipt.resourceSampleFiles = resourceFiles;
    try {
      receipt.resourceSampling = await resourceSummary(resourceFiles);
      assert.equal(resourceFiles.length, COLD_SESSIONS, "one resource sample file is required per cold session");
      assert.ok(resourceFiles.every((item) => item.sha256), "every resource sample must have a finalized digest");
      assert.ok(receipt.resourceSampling.processes.length > 0, "resource samples contain no tracked processes");
      assertCompleteResourceEvidence(receipt.resourceSampling);
    } catch (error) {
      const detail = safeError(error);
      evidenceFailures.push(detail);
      receipt.resourceSampling = preserveResourceEvidenceFailure(receipt.resourceSampling, detail);
    }
    if (hostRegistration) {
      try { receipt.nativeHostCapture = await nativeHostEvidence(resourceFiles, hostRegistration); }
      catch (error) {
        evidenceFailures.push(safeError(error));
        receipt.nativeHostCapture = { error: safeError(error) };
      }
    } else receipt.nativeHostCapture = null;
    if (cleanupFailures.length || evidenceFailures.length) {
      receipt.status = "failed";
      receipt.cleanupFailures = cleanupFailures;
      receipt.resourceEvidenceFailures = evidenceFailures;
      if (!receipt.failure) receipt.failure = { type: "required_cleanup_or_resource_evidence_missing" };
      process.exitCode = 1;
    }
    receipt.cleanup = {
      sessionProcessesAndListenersVerified: sessionCleanupVerified,
      externalRequests: externalRequests.length,
      providerFixtureClosed: server === null,
      certificateDirectoryRemoved,
    };
    receipt.completedAt = new Date().toISOString();
    await finalize().catch((error) => {
      console.error(`Failed to write final receipt (${safeError(error).type}).`);
      process.exitCode = 1;
    });
  }
}

async function createInitialReceipt() {
  const sourceHashes = {};
  for (const relativePath of SOURCE_FILES) {
    sourceHashes[relativePath] = await hashFile(join(ROOT, relativePath));
  }
  const identities = JSON.parse(await readFile(join(ROOT, "extension/extension-identities.json"), "utf8"));
  assert.equal(identities.chromium_extension_id, EXTENSION_ID, "frozen Chromium extension ID changed");
  const python = await runtimePackageVersions();
  const resourceLimits = await readResourceLimits();
  return {
    protocolVersion: PROTOCOL_VERSION,
    status: "running",
    runId,
    declaredSourceRevision: SOURCE_REVISION,
    rootVerifiedImageId: IMAGE_ID,
    startedAt: timestamps.started,
    versions: {
      chromium: null,
      playwright: JSON.parse(await readFile(join(playwrightRoot, "package.json"), "utf8")).version,
      node: process.version,
      python: python.python,
      pythonPackages: python.packages,
      spaCyModel: { name: "en_core_web_sm", version: python.packages["en-core-web-sm"] ?? null },
      inferenceDevice: "cpu",
      telemetryEnabled: false,
    },
    configuredLayers: ["DETECTION_LAYER_REGEX", "DETECTION_LAYER_NER"],
    externalRequestObservation: {
      http: "BrowserContext request events after context creation",
      websocket: "Page websocket events for existing and later pages",
      gaps: ["service-worker websocket attempts", "attempts before the context hook"],
      egressControl: "Compose network_mode none",
    },
    sourceHashes,
    settings: { enabled: true, useLocalStack: true, layers: { regex: true, ner: true, llm: false }, waitForRegex: true },
    expectedColdSessions: COLD_SESSIONS,
    expectedWarmMeasuredPerSession: RATE_REPS,
    expectedWarmupsPerSession: WARMUPS,
    resourceLimits,
  };
}

async function runtimePackageVersions() {
  const code = [
    "import importlib.metadata as m, json, platform",
    "names = ['spacy', 'en-core-web-sm', 'presidio-analyzer', 'grpcio', 'protobuf', 'psutil']",
    "versions = {}",
    "for name in names:",
    "  try: versions[name] = m.version(name)",
    "  except m.PackageNotFoundError: versions[name] = None",
    "print(json.dumps({'python': platform.python_version(), 'packages': versions}))",
  ].join("\n");
  const { stdout } = await execFileAsync("/workspace/extension/client-runtime/.venv/bin/python", ["-c", code], {
    cwd: ROOT,
    timeout: 10_000,
  });
  return JSON.parse(stdout);
}

async function readResourceLimits() {
  const read = async (path) => (await readFile(path, "utf8").catch(() => "unknown")).trim();
  return {
    visibleProcessorCount: os.availableParallelism?.() ?? os.cpus().length,
    cpuMax: await read("/sys/fs/cgroup/cpu.max"),
    memoryMaxBytes: await read("/sys/fs/cgroup/memory.max"),
  };
}

async function installNativeHost() {
  await mkdir(XDG_CONFIG_HOME, { recursive: true });
  await mkdir(XDG_DATA_HOME, { recursive: true });
  await execFileAsync("sh", [join(ROOT, "extension/runtime-supervisor/scripts/install-native-host.sh"), "chromium"], {
    cwd: join(ROOT, "extension/runtime-supervisor"),
    env: process.env,
    timeout: 15_000,
  });
  const manifestPath = join(BROWSER_CONFIG_ROOT, "NativeMessagingHosts", `${NATIVE_HOST_NAME}.json`);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  assert.equal(manifest.name, NATIVE_HOST_NAME);
  assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${EXTENSION_ID}/`]);
  const launcherPath = manifest.path;
  const launcherText = await readFile(launcherPath, "utf8");
  assert.ok(launcherText.includes("native_messaging_host.py"), "registered launcher must invoke shipped native host");
  hostRegistration = {
    manifestPath,
    launcherPath,
    manifestSha256: await hashFile(manifestPath),
    launcherSha256: await hashFile(launcherPath),
    hostSha256: await hashFile(join(XDG_DATA_HOME, "privoke/native-host/native_messaging_host.py")),
    manifest,
  };
}

async function startProviderFixture() {
  certificateDirectory = join("/tmp", `privoke-installed-cert-${runId}`);
  await mkdir(certificateDirectory, { recursive: false });
  const keyPath = join(certificateDirectory, "key.pem");
  const certPath = join(certificateDirectory, "cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
    "-subj", "/CN=chatgpt.com", "-keyout", keyPath, "-out", certPath], { stdio: "ignore" });
  const key = await readFile(keyPath);
  const certificate = await readFile(certPath);
  server = createServer({ key, cert: certificate }, async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    if (request.method === "POST" && request.url?.startsWith("/backend-api/conversation")) {
      const capture = {
        sequence: providerCaptures.length,
        method: request.method,
        path: request.url,
        headers: sanitizeHeaders(request.headers),
        bodyBase64: body.toString("base64"),
        body: body.toString("utf8"),
        bodySha256: sha256(body),
        at: new Date().toISOString(),
      };
      providerCaptures.push(capture);
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true,"fixture":true}');
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><meta charset=utf-8><title>Local PriVoke test fixture</title>");
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const port = server.address().port;
  return {
    tls: { certificateSha256: sha256(certificate) },
    fixtureUrl: `https://chatgpt.com:${port}`,
    certDir: certificateDirectory,
  };
}

async function runColdSession({ index, cell, replicate, fixtureUrl, protobuf }) {
  await assertPortsClosed(`cold-session-${index}-before`);
  await assertNoOwnedProcesses(`cold-session-${index}-before`);
  const sessionId = `${String(index + 1).padStart(2, "0")}-${cell.transport}-${cell.example.id}-r${replicate}`;
  profilePath = join(BROWSER_CONFIG_ROOT, `profile-${sessionId}`);
  await mkdir(profilePath, { recursive: false });
  const activeNativeRegistration = await registerNativeHostForProfile(profilePath);
  samplerPath = join(OUTPUT, `resources-${sessionId}.jsonl`);
  sampler = spawnSampler(samplerPath);
  resourceFiles.push({ file: relative(OUTPUT, samplerPath), sha256: null });

  const times = {};
  const launchWall = Date.now();
  const launchMonotonic = performance.now();
  browserContext = await chromium.launchPersistentContext(profilePath, {
    channel: "chromium",
    headless: false,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${EXTENSION_ROOT}`,
      `--load-extension=${EXTENSION_ROOT}`,
      "--remote-debugging-port=9333",
      "--no-proxy-server",
      "--host-resolver-rules=MAP chatgpt.com 127.0.0.1,EXCLUDE localhost",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
    ],
  });
  times.browserLaunchToContextMs = performance.now() - launchMonotonic;
  observeContextRequests(browserContext, sessionId, new URL(fixtureUrl).origin);
  const workers = browserContext.serviceWorkers();
  const worker = workers.find((item) => item.url() === `chrome-extension://${EXTENSION_ID}/background.js`)
    || await browserContext.waitForEvent("serviceworker", {
      predicate: (candidate) => candidate.url() === `chrome-extension://${EXTENSION_ID}/background.js`,
      timeout: 30_000,
    });
  const workerWall = Date.now();
  const workerMonotonic = performance.now();
  assert.ok(worker.url().startsWith(`chrome-extension://${EXTENSION_ID}/`), "loaded extension ID mismatch");
  cdp = await CdpObserver.connect();
  await cdp.attach(protobuf);
  popup = await browserContext.newPage();
  await popup.goto(`chrome-extension://${EXTENSION_ID}/popup.html`);
  const configStart = performance.now();
  const configured = await sendExtensionMessage(popup, {
    type: "UPDATE_SETTINGS",
    patch: { useLocalStack: true, enabled: true, layers: { regex: true, ner: true, llm: false }, waitForRegex: true },
  });
  assert.equal(configured.ok, true, `local browser settings failed: ${configured.error || "unknown"}`);
  assert.deepEqual(configured.settings.layers, { regex: true, ner: true, llm: false });
  assert.equal(configured.settings.useLocalStack, true);
  assert.equal(configured.settings.enabled, true);
  times.settingsUpdateElapsedMs = performance.now() - configStart;

  const readinessProbeStart = performance.now();
  const status = await waitRuntimeReady(popup);
  const runtimeReadyMonotonic = performance.now();
  const readyWall = Date.now();
  const statusProbeElapsedMs = performance.now() - readinessProbeStart;
  const detectorPid = Number(status.processId);
  assert.ok(detectorPid > 1, "supervisor status must expose the detector child PID");
  const detectorIdentity = await processIdentity(detectorPid);
  assert.equal(detectorIdentity.command.includes("extension/client-runtime/src/grpc_main.py"), true,
    "runtime status PID is not the expected detector executable");
  const supervisorPid = detectorIdentity.parentPid;
  const supervisorIdentity = await processIdentity(supervisorPid);
  assert.equal(supervisorIdentity.command.includes("extension/runtime-supervisor/src/main.py"), true,
    "detector parent is not the expected supervisor entry point");
  startedProcesses = new Map([[supervisorPid, supervisorIdentity], [detectorPid, detectorIdentity]]);
  const listenerOwnership = await assertOwnedListeners(supervisorPid, detectorPid);
  times.ownedListenerVerificationElapsedAfterStatusMs = performance.now() - runtimeReadyMonotonic;
  const nativeEvidence = await waitForNativeHostSample(samplerPath, 2_000);
  const extensionManifest = JSON.parse(await readFile(join(EXTENSION_ROOT, "manifest.json"), "utf8"));
  assert.equal(extensionManifest.background.service_worker, "background.js");

  testPage = await browserContext.newPage();
  await installPageObserver(testPage);
  await testPage.goto(`${fixtureUrl}/?session=${encodeURIComponent(sessionId)}`, { waitUntil: "domcontentloaded" });
  const browserVersion = browserContext.browser()?.version?.() || "unknown";
  receipt.versions.chromium = browserVersion;
  const cold = {
    sessionId,
    replicate,
    transport: cell.transport,
    action: cell.example.expectedAction,
    profileFresh: true,
    profilePath: profilePath,
    activeNativeManifest: activeNativeRegistration,
    browserVersion,
    browserLaunchToContextMs: times.browserLaunchToContextMs,
    browserLaunchToExtensionWorkerObservationMs: workerMonotonic - launchMonotonic,
    settingsUpdateElapsedMs: times.settingsUpdateElapsedMs,
    runtimeStatusProbeElapsedAfterSettingsMs: statusProbeElapsedMs,
    ownedListenerVerificationElapsedAfterStatusMs: times.ownedListenerVerificationElapsedAfterStatusMs,
    supervisorProcessBirthOffsetFromWorkerReadyMs: null,
    detectorProcessBirthOffsetFromSupervisorBirthMs: null,
    detectorProcessBirthOffsetFromContextMs: null,
    processBirthOffsetBasis: "psutil create_time wall clock minus Date.now event timestamps; signed; not readiness",
    processBirthOffsetsAreNotReadinessIntervals: true,
    detectorPid: detectorIdentity.pid,
    detectorStartTicks: detectorIdentity.startTicks,
    supervisorPid: supervisorIdentity.pid,
    supervisorStartTicks: supervisorIdentity.startTicks,
    nativeHostLaunchAttestation: nativeLaunchAttestation({
      nativeEvidence,
      activeNativeRegistration,
      supervisorIdentity,
      detectorIdentity,
      sessionId,
    }),
    listenerOwnership,
    startedAtWall: new Date(launchWall).toISOString(),
    readyAtWall: new Date(readyWall).toISOString(),
  };

  const processSamples = await sampledProcessTimes(samplerPath, [supervisorIdentity, detectorIdentity]);
  cold.supervisorProcessBirthOffsetFromWorkerReadyMs = processSamples.get(supervisorPid).startedAtEpochMs - workerWall;
  cold.detectorProcessBirthOffsetFromSupervisorBirthMs =
    processSamples.get(detectorPid).startedAtEpochMs - processSamples.get(supervisorPid).startedAtEpochMs;
  cold.detectorProcessBirthOffsetFromContextMs = processSamples.get(detectorPid).startedAtEpochMs - launchWall;

  const coldDecision = await performAndValidate({
    transport: cell.transport,
    caseId: `${sessionId}-first-decision`,
    prompt: cell.example.prompt,
    expectedAction: cell.example.expectedAction,
    expectedForwarded: cell.example.expectedForwarded,
    fixtureUrl,
    expectRuntimeRpc: true,
  });
  cold.firstRequestDecisionMs = coldDecision.decisionMs;
  cold.firstRequestPageId = coldDecision.pageRequestId;
  cold.firstRequestRuntimeId = coldDecision.runtimeRequestId;
  phaseCounts.firstDecision += 1;

  await runWarmCell({ sessionId, cell, fixtureUrl, replicates: WARMUPS, phase: "warmup" });
  const measured = await runWarmCell({ sessionId, cell, fixtureUrl, replicates: RATE_REPS, phase: "measured" });
  caseRecords.push(...measured);
  receipt = receipt || {};
  return { cold, measured };
}

async function runWarmCell({ sessionId, cell, fixtureUrl, replicates, phase }) {
  const records = [];
  for (let index = 0; index < replicates; index += 1) {
    const uniqueId = `${sessionId}-${phase}-${String(index + 1).padStart(2, "0")}`;
    const beforeCapture = providerCaptures.length;
    const rpcStart = rpcEvents.length;
    const outcome = await executePageRequest({
      testPage,
      transport: cell.transport,
      caseId: uniqueId,
      prompt: cell.example.prompt,
      expectedAction: cell.example.expectedAction,
      fixtureUrl,
    });
    const rpc = await waitForAnalyzeEvent(rpcStart);
    const captures = providerCaptures.slice(beforeCapture);
    assertForwarding({
      example: { id: uniqueId, prompt: cell.example.prompt,
        expectedAction: cell.example.expectedAction, expectedForwarded: cell.example.expectedForwarded },
      outcome: outcome.transportOutcome,
      captures,
      transport: cell.transport,
      expectedUrl: outcome.requestUrl,
    });
    assertAnalysisMessage({ expectedAction: cell.example.expectedAction, outcome, prompt: cell.example.prompt });
    const newRpc = rpcEvents.slice(rpcStart).filter((entry) => entry.method === "AnalyzePrompt");
    assert.equal(newRpc.length, 1, `${uniqueId} must have one actual runtime AnalyzePrompt RPC`);
    validateDecodedOutcome(rpc, { prompt: cell.example.prompt, action: cell.example.expectedAction });
    assert.ok(!runtimeRequestIds.has(rpc.request.requestId), "runtime request IDs must be unique");
    runtimeRequestIds.add(rpc.request.requestId);
    phaseCounts[phase] += 1;
    const item = {
      sessionId,
      phase,
      caseId: uniqueId,
      transport: cell.transport,
      fixedAction: cell.example.expectedAction,
      fixedPrompt: cell.example.prompt,
      expectedForwarded: cell.example.expectedForwarded,
      pageRequestId: outcome.analysis.requestId,
      runtimeRequestId: rpc.request.requestId,
      decisionMs: outcome.analysis.decisionMs,
      browserObservedTotalMs: outcome.totalMs,
      runtimeElapsedMs: rpc.response?.decoded?.elapsedMs ?? null,
      rpc: minimalRpc(rpc),
      forwardedCount: captures.length,
      forwardedBodySha256: captures[0]?.bodySha256 ?? null,
      outcome: outcome.transportOutcome,
    };
    if (phase === "measured") records.push(item);
    await appendCapture(item, captures, rpc);
  }
  return records;
}

async function runEnforcementMatrix({ fixtureUrl, protobuf }) {
  const results = [];
  for (const transport of TRANSPORTS) {
    for (const key of Object.keys(CASES)) {
      const example = CASES[key];
      results.push(await runMatrixCase({ transport, example, fixtureUrl }));
    }
    results.push(await runOutageCase({ transport, type: "detector-outage", fixtureUrl }));
    results.push(await runOutageCase({ transport, type: "bridge-supervisor-outage", fixtureUrl }));
    results.push(await runBypassCase({ transport, type: "master-off", fixtureUrl }));
    results.push(await runBypassCase({ transport, type: "all-layers-off", fixtureUrl }));
  }
  assert.equal(results.length, 14);
  return results;
}

async function runMatrixCase({ transport, example, fixtureUrl }) {
  const record = await performAndValidate({
    transport,
    caseId: `matrix-${transport}-${example.id}`,
    prompt: example.prompt,
    expectedAction: example.expectedAction,
    expectedForwarded: example.expectedForwarded,
    fixtureUrl,
    expectRuntimeRpc: true,
  });
  phaseCounts.matrix += 1;
  return record;
}

async function runOutageCase({ transport, type, fixtureUrl }) {
  const prompt = CASES.allow.prompt;
  if (type === "detector-outage") {
    const current = await runtimeStatus(popup);
    const detector = await processIdentity(Number(current.processId));
    verifyOwnedDetector(detector, startedProcesses.get(detector.pid));
    await signalVerified(detector, "SIGTERM");
    startedProcesses.delete(detector.pid);
  } else {
    const current = await runtimeStatus(popup);
    const detector = await processIdentity(Number(current.processId));
    const supervisor = await processIdentity(detector.parentPid);
    verifyOwnedSupervisor(supervisor, startedProcesses.get(supervisor.pid));
    verifyOwnedDetector(detector, startedProcesses.get(detector.pid));
    await signalVerified(supervisor, "SIGTERM");
    startedProcesses.delete(detector.pid);
    startedProcesses.delete(supervisor.pid);
  }
  await waitPortsState(type === "detector-outage" ? [8080, 50056] : [], type === "detector-outage" ? [50057] : PORTS, 10_000);
  const record = await performAndValidate({
    transport,
    caseId: `matrix-${transport}-${type}`,
    prompt,
    expectedAction: "BLOCK",
    expectedForwarded: false,
    fixtureUrl,
    expectRuntimeRpc: true,
    expectedRpcOutcome: type === "detector-outage" ? "grpc-error" : "network-failure",
  });
  const recovery = await restoreRuntimeAndObserve();
  record.recovery = recovery;
  phaseCounts.matrix += 1;
  return record;
}

async function runBypassCase({ transport, type, fixtureUrl }) {
  const prompt = CASES.allow.prompt;
  let retainedSupervisor = null;
  if (type === "master-off") {
    const expectedDetector = [...startedProcesses.values()].find((identity) =>
      identity.command.includes("extension/client-runtime/src/grpc_main.py"));
    retainedSupervisor = [...startedProcesses.values()].find((identity) =>
      identity.command.includes("extension/runtime-supervisor/src/main.py"));
    assert.ok(expectedDetector && retainedSupervisor, "master-off requires known detector and supervisor identities");
    const response = await sendExtensionMessage(popup, { type: "SET_MASTER_ENABLED", enabled: false });
    assert.equal(response.ok, true);
    assert.equal(response.runtime.enabled, false);
    await waitOwnedProcessesGone([expectedDetector], 10_000);
    await waitPortsState([8080, 50056], [50057], 10_000);
    const currentSupervisor = await processIdentity(retainedSupervisor.pid);
    verifyOwnedSupervisor(currentSupervisor, retainedSupervisor);
    const controlListeners = await assertOwnedControlListeners(currentSupervisor.pid);
    assertPreservedControlSupervisor(retainedSupervisor, currentSupervisor, Object.keys(controlListeners).map(Number));
    startedProcesses = new Map([[currentSupervisor.pid, currentSupervisor]]);
  } else {
    const response = await sendExtensionMessage(popup, {
      type: "UPDATE_SETTINGS",
      patch: { layers: { regex: false, ner: false, llm: false } },
    });
    assert.equal(response.ok, true);
  }
  const record = await performAndValidate({
    transport,
    caseId: `matrix-${transport}-${type}`,
    prompt,
    expectedAction: "ALLOW",
    expectedForwarded: true,
    fixtureUrl,
    expectRuntimeRpc: false,
  });
  if (type === "master-off") {
    const restored = await sendExtensionMessage(popup, { type: "SET_MASTER_ENABLED", enabled: true });
    assert.equal(restored.ok, true);
  } else {
    const restored = await sendExtensionMessage(popup, {
      type: "UPDATE_SETTINGS",
      patch: { layers: { regex: true, ner: true, llm: false } },
    });
    assert.equal(restored.ok, true);
  }
  record.recovery = await restoreRuntimeAndObserve(retainedSupervisor);
  phaseCounts.matrix += 1;
  return record;
}

async function performAndValidate({ transport, caseId, prompt, expectedAction, expectedForwarded,
  fixtureUrl, expectRuntimeRpc, expectedRpcOutcome = "success" }) {
  const beforeCapture = providerCaptures.length;
  const beforeRpc = rpcEvents.length;
  const outcome = await executePageRequest({ testPage, transport, caseId, prompt, expectedAction, fixtureUrl });
  if (expectRuntimeRpc) await waitForAnalyzeEvent(beforeRpc);
  const captures = providerCaptures.slice(beforeCapture);
  assertForwarding({
    example: { id: caseId, prompt, expectedAction, expectedForwarded },
    outcome: outcome.transportOutcome,
    captures,
    transport,
    expectedUrl: outcome.requestUrl,
  });
  assertAnalysisMessage({ expectedAction, outcome, prompt });
  const newRpc = rpcEvents.slice(beforeRpc).filter((entry) => entry.method === "AnalyzePrompt");
  assert.equal(newRpc.length, Number(expectRuntimeRpc), `${caseId} runtime AnalyzePrompt count`);
  let rpc;
  if (expectRuntimeRpc) {
    rpc = newRpc[0];
    validateDecodedOutcome(rpc, {
      prompt,
      action: expectedAction,
      allowGrpcError: expectedRpcOutcome === "grpc-error",
      allowNetworkFailure: expectedRpcOutcome === "network-failure",
    });
    assert.ok(!runtimeRequestIds.has(rpc.request.requestId), "runtime request IDs must be unique");
    runtimeRequestIds.add(rpc.request.requestId);
  }
  const item = {
    caseId,
    transport,
    expectedAction,
    expectedForwarded,
    pageRequestId: outcome.analysis.requestId,
    runtimeRequestId: rpc?.request?.requestId ?? null,
    decisionMs: outcome.analysis.decisionMs,
    browserObservedTotalMs: outcome.totalMs,
    runtimeElapsedMs: rpc?.response?.decoded?.elapsedMs ?? null,
    forwardedCount: captures.length,
    forwardedBodySha256: captures[0]?.bodySha256 ?? null,
    outcome: outcome.transportOutcome,
    rpc: rpc ? minimalRpc(rpc) : null,
  };
  await appendCapture(item, captures, rpc);
  return item;
}

async function executePageRequest({ testPage: page, transport, caseId, prompt, expectedAction, fixtureUrl }) {
  const url = `${fixtureUrl}/backend-api/conversation?case_id=${encodeURIComponent(caseId)}`;
  const outcome = await page.evaluate(async ({ transport, url, caseId, prompt, expectedAction }) => {
    window.__privokeCaptureCase = caseId;
    window.__privokeExpectedAction = expectedAction;
    const body = JSON.stringify({ messages: [{ role: "user", content: prompt }] });
    const start = performance.now();
    let transportOutcome;
    if (transport === "fetch") {
      try {
        const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
        transportOutcome = { status: response.status };
        await response.arrayBuffer();
      } catch (error) {
        transportOutcome = { errorName: error?.name || "Error", errorMessage: error?.message || "" };
      }
    } else {
      transportOutcome = await new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        const events = [];
        for (const eventName of ["readystatechange", "error", "loadend", "load", "timeout"]) {
          xhr.addEventListener(eventName, () => events.push(eventName));
        }
        xhr.open("POST", url, true);
        xhr.setRequestHeader("content-type", "application/json");
        xhr.addEventListener("loadend", () => resolve({
          status: xhr.status,
          readyState: xhr.readyState,
          responseText: xhr.responseText,
          events,
        }), { once: true });
        xhr.send(body);
      });
    }
    const totalMs = performance.now() - start;
    const deadline = performance.now() + 35_000;
    let analysis;
    while (performance.now() < deadline) {
      analysis = window.__privokeAnalyses?.find((entry) => entry.phase === "result" && entry.caseId === caseId);
      if (analysis) break;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return {
      caseId,
      transportOutcome,
      totalMs,
      analysisEvents: window.__privokeAnalyses?.filter((entry) => entry.caseId === caseId) || [],
      requestUrl: url,
    };
  }, { transport, url, caseId, prompt, expectedAction });
  outcome.analysis = validatePageAnalysis(outcome.analysisEvents, {
    caseId, prompt, expectedAction, seenIds: pageRequestIds,
  });
  return outcome;
}

async function installPageObserver(page) {
  await page.addInitScript(() => {
    window.__privokeAnalyses = [];
    window.__privokeAnalysisStarted = new Map();
    window.addEventListener("message", (event) => {
      if (event.source !== window || event.data?.channel !== "privoke-extension-v1") return;
      const data = event.data;
      if (data.type === "ANALYZE_PROMPT") {
        const started = {
          at: performance.now(),
          prompt: data.text,
          caseId: window.__privokeCaptureCase,
          expectedAction: window.__privokeExpectedAction,
        };
        window.__privokeAnalysisStarted.set(data.requestId, started);
        window.__privokeAnalyses.push({ phase: "start", requestId: data.requestId,
          caseId: started.caseId, prompt: started.prompt, expectedAction: started.expectedAction });
      } else if (data.type === "ANALYZE_RESULT") {
        const started = window.__privokeAnalysisStarted.get(data.requestId);
        if (!started) return;
        window.__privokeAnalyses.push({
          phase: "result",
          requestId: data.requestId,
          caseId: started.caseId,
          prompt: started.prompt,
          expectedAction: started.expectedAction,
          action: data.action,
          decisionMs: performance.now() - started.at,
        });
      }
    });
  });
}

function observeContextRequests(context, sessionId, fixtureOrigin) {
  const record = (url, method, channel) => {
    let parsed;
    try { parsed = new URL(url); } catch { return; }
    if (!["http:", "https:", "ws:", "wss:"].includes(parsed.protocol)) return;
    if (parsed.origin === fixtureOrigin) return;
    if (["127.0.0.1", "localhost"].includes(parsed.hostname)
      && [8080, 50056, 50057].includes(Number(parsed.port))) return;
    externalRequests.push({ url, method, channel, sessionId });
  };
  context.on("request", (request) => record(request.url(), request.method(), "browser-context-request"));
  const observePage = (page) => page.on("websocket", (socket) =>
    record(socket.url(), "WEBSOCKET", "page-websocket"));
  for (const page of context.pages()) observePage(page);
  context.on("page", observePage);
}

class CdpObserver {
  constructor() {
    this.socket = null;
    this.pending = new Map();
    this.nextId = 1;
    this.network = new Map();
    this.events = [];
    this.protobuf = null;
  }

  static async connect() {
    const targets = await fetch("http://127.0.0.1:9333/json/list").then((response) => response.json());
    const target = targets.find((entry) => entry.type === "service_worker"
      && entry.url === `chrome-extension://${EXTENSION_ID}/background.js`);
    assert.ok(target?.webSocketDebuggerUrl, "extension background service worker target not found over CDP");
    const observer = new CdpObserver();
    observer.socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolvePromise, reject) => {
      observer.socket.addEventListener("open", resolvePromise, { once: true });
      observer.socket.addEventListener("error", () => reject(new Error("CDP worker websocket failed")), { once: true });
    });
    observer.socket.addEventListener("message", (event) => observer.#message(JSON.parse(event.data)));
    return observer;
  }

  async attach(protobuf) {
    this.protobuf = protobuf;
    await this.command("Network.enable", { maxTotalBufferSize: 16 * 1024 * 1024, maxResourceBufferSize: 8 * 1024 * 1024 });
  }

  command(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, { resolve: resolvePromise, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        const item = this.pending.get(id);
        if (!item) return;
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timeout`));
      }, 20_000).unref?.();
    });
  }

  close() {
    this.socket?.close();
  }

  #message(message) {
    if (message.id) {
      const item = this.pending.get(message.id);
      if (!item) return;
      this.pending.delete(message.id);
      if (message.error) item.reject(new Error(message.error.message));
      else item.resolve(message.result);
      return;
    }
    const params = message.params || {};
    if (message.method === "Network.requestWillBeSent" && params.request?.url?.includes("/privoke.v1.PrivokeRuntimeService/AnalyzePrompt")) {
      this.network.set(params.requestId, {
        method: "AnalyzePrompt",
        url: params.request.url,
        request: params.request,
        requestWallTime: params.wallTime,
        loadingFailure: null,
      });
    } else if (message.method === "Network.loadingFailed") {
      const record = this.network.get(params.requestId);
      if (record) {
        record.loadingFailure = { errorText: params.errorText, canceled: params.canceled === true };
        void this.#readFailedRequest(params.requestId, record);
      }
    } else if (message.method === "Network.loadingFinished") {
      const record = this.network.get(params.requestId);
      if (record) void this.#readResponse(params.requestId, record);
    }
  }

  async #readResponse(id, record) {
    try {
      const [requestData, responseData] = await Promise.all([
        this.command("Network.getRequestPostData", { requestId: id }).catch(() => null),
        this.command("Network.getResponseBody", { requestId: id }).catch((error) => ({ error: error.message })),
      ]);
      record.requestBytes = decodeCdpPostData(record.request, requestData);
      if (responseData?.body !== undefined) {
        record.responseBytes = responseData.base64Encoded
          ? Buffer.from(responseData.body, "base64")
          : Buffer.from(responseData.body, "latin1");
      }
      this.#decode(record);
      this.#finish(id, record);
    } catch (error) {
      record.decodeError = error.message;
      this.#finish(id, record);
    }
  }

  async #readFailedRequest(id, record) {
    try {
      const requestData = await this.command("Network.getRequestPostData", { requestId: id }).catch(() => null);
      record.requestBytes = decodeCdpPostData(record.request, requestData);
      const requestFrames = parseGrpcWebFrames(record.requestBytes, "request");
      const request = this.protobuf.AnalyzePromptRequest.decode(requestFrames.data[0]);
      record.requestDecoded = this.protobuf.AnalyzePromptRequest.toObject(request, {
        enums: String, defaults: true, arrays: true, objects: true,
      });
    } catch (error) {
      record.decodeError = error.message;
    }
    this.#finish(id, record);
  }

  #decode(record) {
    const requestFrames = parseGrpcWebFrames(record.requestBytes, "request");
    const requestMessage = this.protobuf.AnalyzePromptRequest.decode(requestFrames.data[0]);
    record.requestDecoded = this.protobuf.AnalyzePromptRequest.toObject(requestMessage, {
      enums: String, defaults: true, arrays: true, objects: true,
    });
    if (record.responseBytes) {
      const responseFrames = parseGrpcWebFrames(record.responseBytes, "response");
      record.grpcStatus = responseFrames.grpcStatus;
      record.grpcMessage = responseFrames.grpcMessage;
      if (responseFrames.data.length === 1 && responseFrames.grpcStatus === 0) {
        const message = this.protobuf.AnalyzePromptResponse.decode(responseFrames.data[0]);
        record.responseDecoded = this.protobuf.AnalyzePromptResponse.toObject(message, {
          enums: String, defaults: true, arrays: true, objects: true,
        });
      }
    }
  }

  #finish(id, record) {
    if (!this.network.has(id)) return;
    this.network.delete(id);
    const out = {
      method: record.method,
      url: record.url,
      request: record.requestDecoded ?? null,
      response: record.responseDecoded ? { decoded: record.responseDecoded } : null,
      grpcStatus: record.grpcStatus ?? null,
      grpcMessage: record.grpcMessage ?? null,
      loadingFailure: record.loadingFailure,
      decodeError: record.decodeError ?? null,
      requestBodyBase64: record.requestBytes?.toString("base64") ?? null,
      responseBodyBase64: record.responseBytes?.toString("base64") ?? null,
      responseBytesPresent: Buffer.isBuffer(record.responseBytes),
      requestWallTime: record.requestWallTime,
    };
    this.events.push(out);
    rpcEvents.push(out);
  }
}

function decodeCdpPostData(request, result) {
  const entries = request?.postDataEntries;
  if (Array.isArray(entries) && entries.length) return Buffer.concat(entries.map((entry) => Buffer.from(entry.bytes, "base64")));
  if (result?.postData !== undefined) {
    const text = result.postData;
    if ([...text].some((character) => character.codePointAt(0) > 255)) {
      throw new Error("CDP post data cannot be reconstructed losslessly");
    }
    return Buffer.from(text, "latin1");
  }
  const raw = request?.postData;
  if (typeof raw === "string" && ![...raw].some((character) => character.codePointAt(0) > 255)) {
    return Buffer.from(raw, "latin1");
  }
  throw new Error("CDP omitted lossless AnalyzePrompt request bytes");
}

function minimalRpc(rpc) {
  return {
    requestId: rpc.request?.requestId ?? null,
    source: rpc.request?.source ?? null,
    targetApp: rpc.request?.targetApp ?? null,
    text: rpc.request?.text ?? null,
    requestedLayers: rpc.request?.layers ?? null,
    responseRequestId: rpc.response?.decoded?.requestId ?? null,
    action: rpc.response?.decoded?.action ?? null,
    elapsedMs: rpc.response?.decoded?.elapsedMs ?? null,
    error: rpc.response?.decoded?.error ?? rpc.grpcMessage ?? rpc.loadingFailure?.errorText ?? null,
    grpcStatus: rpc.grpcStatus,
    layerStatuses: rpc.response?.decoded?.layers?.map((item) => ({ layer: item.layer, status: item.status, error: item.error })) ?? [],
    requestBytesBase64: rpc.requestBodyBase64,
    responseBytesBase64: rpc.responseBodyBase64,
    decodeError: rpc.decodeError,
  };
}

async function waitForNativeHostSample(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rows = parseJsonl(await readFile(path, "utf8").catch(() => ""));
    const evidence = collectNativeSamples(rows);
    if (evidence.nativeSamples.length) return evidence;
    await delay(100);
  }
  const rows = parseJsonl(await readFile(path, "utf8").catch(() => ""));
  return collectNativeSamples(rows);
}

function collectNativeSamples(rows) {
  const nativeSamples = [];
  const browserSamples = [];
  for (const sample of rows) {
    const browser = (sample.roles || []).filter((item) => item.role === "chromium");
    const native = (sample.roles || []).filter((item) => item.role === "native_host");
    browserSamples.push(...browser);
    nativeSamples.push(...native);
  }
  return {
    observed: nativeSamples.length > 0,
    count: nativeSamples.length,
    nativeSamples,
    browserSamples,
    browserParentBound: assertNativeParentBinding(nativeSamples, browserSamples),
  };
}

function nativeLaunchAttestation({ nativeEvidence, activeNativeRegistration, supervisorIdentity,
  detectorIdentity, sessionId }) {
  const direct = nativeEvidence.observed && nativeEvidence.browserParentBound;
  return {
    mode: direct ? "direct_native_process_parent_observed" : "native_launch_inferred_from_fresh_extension_lifecycle",
    directNativeProcessObserved: nativeEvidence.observed,
    nativeProcessParentWasSampledChromium: nativeEvidence.browserParentBound,
    nativeProcessSamples: nativeEvidence.nativeSamples,
    browserProcessSamples: nativeEvidence.browserSamples.map((item) => ({
      pid: item.pid, start_ticks: item.start_ticks, browser_profile_root: item.browser_profile_root,
    })),
    browserSessionId: sessionId,
    nativeRegistration: activeNativeRegistration,
    supervisorIdentity: { pid: supervisorIdentity.pid, startTicks: supervisorIdentity.startTicks,
      commandSha256: supervisorIdentity.commandSha256 },
    detectorIdentity: { pid: detectorIdentity.pid, startTicks: detectorIdentity.startTicks,
      commandSha256: detectorIdentity.commandSha256 },
    lifecycleInferenceBasis: direct ? null : [
      "run-specific Chromium user-data directory was fresh and serving ports/processes were verified absent before launch",
      "the installer-generated native host manifest was bound into that active user-data directory before launch",
      "the built extension worker was loaded and its real lifecycle/settings message caused a new supervisor and detector identity",
      "no harness path starts the supervisor directly",
    ],
    sampledNativeHostPeakClaim: nativeEvidence.observed ? "sampled evidence only; 100ms may miss shorter use" : "unavailable; no native-host resource peak claim",
  };
}

async function registerNativeHostForProfile(activeUserDataPath) {
  assert.ok(hostRegistration, "standard native host registration has not been installed");
  const directory = join(activeUserDataPath, "NativeMessagingHosts");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `${NATIVE_HOST_NAME}.json`);
  await writeFile(path, await readFile(hostRegistration.manifestPath), { flag: "wx" });
  const bytes = await readFile(path);
  const manifest = JSON.parse(bytes.toString("utf8"));
  assert.deepStrictEqual(manifest, hostRegistration.manifest, "active profile native manifest differs from installer output");
  assert.equal(manifest.allowed_origins[0], `chrome-extension://${EXTENSION_ID}/`);
  assert.equal(manifest.path, hostRegistration.manifest.path);
  assert.equal(await hashFile(path), hostRegistration.manifestSha256,
    "active profile native manifest bytes differ from installer output");
  return {
    activeUserDataPath,
    activeManifestPath: path,
    activeManifestSha256: sha256(bytes),
    installedManifestPath: hostRegistration.manifestPath,
    installedManifestSha256: hostRegistration.manifestSha256,
    launcherPath: hostRegistration.launcherPath,
    launcherSha256: hostRegistration.launcherSha256,
    nativeHostSha256: hostRegistration.hostSha256,
  };
}

async function sampledProcessTimes(path, identities) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const rows = parseJsonl(await readFile(path, "utf8").catch(() => ""));
    const found = new Map();
    for (const row of rows) for (const process of row.roles || []) {
      const expected = identities.find((item) => item.pid === process.pid
        && item.startTicks === process.start_ticks);
      if (expected && Number.isFinite(process.start_time_epoch_seconds)) {
        found.set(process.pid, { startedAtEpochMs: process.start_time_epoch_seconds * 1000,
          startTicks: process.start_ticks });
      }
    }
    if (identities.every((identity) => found.has(identity.pid))) return found;
    await delay(50);
  }
  throw new Error("resource sampler did not capture owned runtime process startup identities");
}

async function finishSession() {
  let cleanupError;
  const browserIdentities = samplerPath ? await sampledBrowserIdentities(samplerPath) : [];
  if (popup && browserContext) {
    const response = await sendExtensionMessage(popup, { type: "SET_MASTER_ENABLED", enabled: false }).catch((error) => ({ ok: false, error: error.message }));
    if (!response.ok) cleanupError = new Error("could not disable detector through extension lifecycle");
  }
  const current = [...startedProcesses.entries()];
  for (const [pid, identity] of current) {
    await stopOwnedProcess(identity).catch(() => {});
    startedProcesses.delete(pid);
  }
  cdp?.close();
  cdp = null;
  if (browserContext) await browserContext.close().catch(() => {});
  browserContext = null;
  popup = null;
  testPage = null;
  await waitSampledBrowserProcessesAbsent(browserIdentities, 10_000);
  await stopSampler();
  if (sampleEndFailure && !cleanupError) cleanupError = new Error("resource capture did not finish cleanly");
  if (profilePath) {
    await waitNoProcessContains(profilePath, 10_000);
    await rm(profilePath, { recursive: true, force: false });
    profilePath = null;
  }
  await assertPortsClosed("session-cleanup");
  await assertNoOwnedProcesses("session-cleanup");
  if (cleanupError) throw cleanupError;
}

async function stopSampler() {
  if (!sampler) return;
  const child = sampler;
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  const closed = await Promise.race([
    samplerClosed,
    delay(10_000).then(() => { throw new Error("resource sampler did not close and reap within 10 seconds"); }),
  ]);
  if (closed.code !== 0 || (closed.signal && closed.signal !== "SIGTERM")) {
    sampleEndFailure = new Error("resource sampler exited unsuccessfully");
  }
  const finishedPath = samplerPath;
  const fileRecord = resourceFiles.find((entry) => entry.file === relative(OUTPUT, finishedPath));
  if (fileRecord) fileRecord.sha256 = await hashFile(finishedPath).catch(() => null);
  if (fileRecord && !fileRecord.sha256 && !sampleEndFailure) {
    sampleEndFailure = new Error("resource sample file could not be finalized");
  }
  sampler = null;
  samplerPath = null;
  samplerClosed = null;
}

async function runtimeStatus(page) {
  const result = await sendExtensionMessage(page, { type: "GET_RUNTIME_STATUS" });
  assert.equal(result.ok, true, `runtime status failed: ${result.error || "unknown"}`);
  return result.runtime;
}

async function waitRuntimeReady(page) {
  let last;
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      last = await runtimeStatus(page);
      if (last.enabled && last.status === "RUNNING" && Number(last.processId) > 0) return last;
    } catch (error) { last = error; }
    await delay(250);
  }
  throw new Error(`Browser-launched detector did not become ready (${safeError(last).type}).`);
}

async function restoreRuntimeAndObserve(expectedSupervisor = null) {
  const runtime = await waitRuntimeReady(popup);
  const identity = await processIdentity(Number(runtime.processId));
  const supervisor = await processIdentity(identity.parentPid);
  assert.ok(identity.command.includes("extension/client-runtime/src/grpc_main.py"));
  assert.ok(supervisor.command.includes("extension/runtime-supervisor/src/main.py"));
  if (expectedSupervisor) verifyOwnedSupervisor(supervisor, expectedSupervisor);
  startedProcesses = new Map([[supervisor.pid, supervisor], [identity.pid, identity]]);
  const sockets = await assertOwnedListeners(supervisor.pid, identity.pid);
  return { runtime, detectorPid: identity.pid, detectorStartTicks: identity.startTicks,
    supervisorPid: supervisor.pid, supervisorStartTicks: supervisor.startTicks, sockets };
}

async function waitOwnedProcessesGone(identities, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let stillOwned = false;
    for (const identity of identities) {
      const current = await processIdentity(identity.pid).catch(() => null);
      if (current?.startTicks === identity.startTicks) stillOwned = true;
    }
    if (!stillOwned) return;
    await delay(50);
  }
  throw new Error("extension lifecycle did not stop the previously owned runtime identities");
}

async function sendExtensionMessage(page, message) {
  return page.evaluate((payload) => new Promise((resolvePromise) => {
    chrome.runtime.sendMessage(payload, (response) => resolvePromise({
      response,
      error: chrome.runtime.lastError?.message || null,
    }));
  }).then((result) => result.error ? { ok: false, error: result.error } : result.response), message);
}

async function processIdentity(pid) {
  const root = join("/proc", String(pid));
  const command = (await readFile(join(root, "cmdline"), "utf8")).replaceAll("\0", " ").trim();
  const status = await readFile(join(root, "status"), "utf8");
  const ppid = Number(/^PPid:\s+(\d+)/m.exec(status)?.[1]);
  const statLine = await readFile(join(root, "stat"), "utf8");
  const statRest = statLine.slice(statLine.lastIndexOf(")") + 2).split(/\s+/);
  const startTicks = Number(statRest[19]);
  assert.ok(command && Number.isInteger(ppid) && Number.isFinite(startTicks));
  return { pid: Number(pid), parentPid: ppid, startTicks, command, commandSha256: sha256(command) };
}

function verifyOwnedDetector(identity, expected) {
  assert.ok(expected, "detector PID is not owned by this experiment");
  assert.equal(identity.pid, expected.pid);
  assert.equal(identity.startTicks, expected.startTicks, "detector PID was reused");
  assert.equal(identity.parentPid, expected.parentPid);
  assert.ok(identity.command.includes("extension/client-runtime/src/grpc_main.py"));
}

function verifyOwnedSupervisor(identity, expected) {
  assert.ok(expected, "supervisor PID is not owned by this experiment");
  assert.equal(identity.pid, expected.pid);
  assert.equal(identity.startTicks, expected.startTicks, "supervisor PID was reused");
  assert.ok(identity.command.includes("extension/runtime-supervisor/src/main.py"));
}

async function signalVerified(identity, signalName) {
  const current = await processIdentity(identity.pid);
  assert.equal(current.startTicks, identity.startTicks, "refusing process signal after PID reuse");
  assert.equal(current.commandSha256, identity.commandSha256, "refusing process signal after command change");
  if (signalName === "SIGTERM") process.kill(identity.pid, "SIGTERM");
  else if (signalName === "SIGSTOP") process.kill(identity.pid, "SIGSTOP");
  else if (signalName === "SIGCONT") process.kill(identity.pid, "SIGCONT");
  else throw new Error("unsupported controlled process signal");
  if (signalName === "SIGTERM") await waitPidAbsent(identity.pid, 15_000);
}

async function stopOwnedProcess(identity) {
  const current = await processIdentity(identity.pid).catch(() => null);
  if (!current) return;
  assert.equal(current.startTicks, identity.startTicks, "cleanup PID reuse mismatch");
  assert.equal(current.commandSha256, identity.commandSha256, "cleanup command mismatch");
  if (current.command.includes("extension/runtime-supervisor/src/main.py")) {
    assert.ok(current.command.includes("/workspace/extension/runtime-supervisor/src/main.py"));
  } else if (current.command.includes("extension/client-runtime/src/grpc_main.py")) {
    assert.ok(current.command.includes("/workspace/extension/client-runtime/src/grpc_main.py"));
  } else throw new Error("cleanup refused an unrecognized PID");
  process.kill(current.pid, "SIGTERM");
  await waitPidAbsent(current.pid, 15_000);
}

async function assertOwnedListeners(supervisorPid, detectorPid) {
  const ownership = {};
  for (const port of PORTS) {
    const owners = await listenerOwners(port);
    ownership[port] = owners;
    const expected = port === 50057 ? detectorPid : supervisorPid;
    assert.ok(owners.some((owner) => owner.pid === expected), `port ${port} is not owned by expected process ${expected}`);
    assert.equal(owners.length, 1, `port ${port} has unexpected listener ownership`);
  }
  return ownership;
}

async function assertOwnedControlListeners(supervisorPid) {
  const ownership = {};
  for (const port of [8080, 50056]) {
    const owners = await listenerOwners(port);
    ownership[port] = owners;
    assert.ok(owners.some((owner) => owner.pid === supervisorPid),
      `control port ${port} is not owned by expected supervisor ${supervisorPid}`);
    assert.equal(owners.length, 1, `control port ${port} has unexpected listener ownership`);
  }
  return ownership;
}

async function listenerOwners(port) {
  const inodes = new Set();
  for (const table of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    const rows = (await readFile(table, "utf8")).split("\n").slice(1);
    for (const line of rows) {
      const columns = line.trim().split(/\s+/);
      if (columns.length < 10) continue;
      const localPort = Number.parseInt(columns[1].split(":").at(-1), 16);
      if (localPort === port && columns[3] === "0A") inodes.add(columns[9]);
    }
  }
  const owners = [];
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let fds;
    try { fds = await readdir(join("/proc", entry, "fd")); } catch { continue; }
    for (const fd of fds) {
      let target;
      try { target = await readlink(join("/proc", entry, "fd", fd)); } catch { continue; }
      const inode = /^socket:\[(\d+)\]$/.exec(target)?.[1];
      if (inode && inodes.has(inode)) {
        owners.push({ pid: Number(entry), inode });
        break;
      }
    }
  }
  return owners;
}

async function assertPortsClosed(phase) {
  for (const port of PORTS) {
    const owners = await listenerOwners(port);
    assert.equal(owners.length, 0, `${phase}: unexpected listener on loopback port ${port}`);
  }
}

async function waitPortsState(openPorts, closedPorts, timeout) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    let ready = true;
    for (const port of openPorts) if ((await listenerOwners(port)).length === 0) ready = false;
    for (const port of closedPorts) if ((await listenerOwners(port)).length !== 0) ready = false;
    if (ready) return;
    await delay(100);
  }
  throw new Error("Owned listener state did not reach the requested outage state.");
}

async function assertNoOwnedProcesses(phase) {
  const processes = await scanOwnedProcesses();
  assert.deepEqual(processes, [], `${phase}: owned browser/native/supervisor/detector processes remain`);
}

async function scanOwnedProcesses() {
  const found = [];
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let command;
    try { command = (await readFile(join("/proc", entry, "cmdline"), "utf8")).replaceAll("\0", " "); } catch { continue; }
    if (["extension/runtime-supervisor/src/main.py", "extension/client-runtime/src/grpc_main.py", "native_messaging_host.py", "privoke-native-host"].some((part) => command.includes(part))) {
      found.push({ pid: Number(entry), commandSha256: sha256(command) });
    }
  }
  return found;
}

async function sampledBrowserIdentities(path) {
  const rows = parseJsonl(await readFile(path, "utf8").catch(() => ""));
  const identities = new Map();
  for (const row of rows) for (const process of row.roles || []) {
    if (process.role === "chromium") identities.set(`${process.pid}/${process.command_sha256}`, {
      pid: process.pid,
      commandSha256: process.command_sha256,
      startTicks: process.start_ticks,
    });
  }
  return [...identities.values()];
}

async function waitSampledBrowserProcessesAbsent(identities, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let remaining = false;
    for (const identity of identities) {
      let command;
      try {
      command = (await readFile(join("/proc", String(identity.pid), "cmdline"), "utf8"))
          .replaceAll("\0", " ").trim();
      } catch { continue; }
      if (sha256(command) !== identity.commandSha256) continue;
      try {
        const statLine = await readFile(join("/proc", String(identity.pid), "stat"), "utf8");
        const fields = statLine.slice(statLine.lastIndexOf(")") + 2).split(/\s+/);
        if (Number(fields[19]) === identity.startTicks) remaining = true;
      } catch { /* the sampled PID exited during the check */ }
    }
    if (!remaining) return;
    await delay(100);
  }
  throw new Error("sampled Chromium process identities remain after browser cleanup");
}

async function waitPidAbsent(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!(await stat(join("/proc", String(pid))).then(() => true, () => false))) return;
    await delay(50);
  }
  throw new Error(`owned process ${pid} did not exit in time`);
}

async function waitForAnalyzeEvent(startIndex, timeoutMs = 35_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const events = rpcEvents.slice(startIndex).filter((item) => item.method === "AnalyzePrompt");
    if (events.length) {
      if (events[0].loadingFailure || events[0].response || events[0].grpcStatus !== null) return events[0];
    }
    await delay(25);
  }
  throw new Error("CDP did not observe terminal evidence for the runtime AnalyzePrompt request");
}

async function appendCapture(item, captures, rpc) {
  const filename = `${String(caseRecords.length + 1).padStart(5, "0")}-${safeFilename(item.caseId)}.json`;
  const payload = {
    case: item,
    prompt: item.fixedPrompt ?? null,
    providerCaptures: captures,
    runtimeRpc: rpc ? {
      method: rpc.method,
      request: rpc.request,
      response: rpc.response,
      grpcStatus: rpc.grpcStatus,
      grpcMessage: rpc.grpcMessage,
      loadingFailure: rpc.loadingFailure,
      requestBodyBase64: rpc.requestBodyBase64,
      responseBodyBase64: rpc.responseBodyBase64,
      decodeError: rpc.decodeError,
    } : null,
  };
  await writeFile(join(OUTPUT, "captures", filename), JSON.stringify(payload, null, 2), { flag: "wx" });
  item.captureFile = `captures/${filename}`;
  item.captureSha256 = await hashFile(join(OUTPUT, "captures", filename));
}

function summariseCosts(records) {
  const groups = new Map();
  for (const record of records) {
    const key = `${record.transport}/${record.fixedAction}`;
    const values = groups.get(key) || [];
    values.push(record);
    groups.set(key, values);
  }
  return Object.fromEntries([...groups].map(([key, rows]) => [key, {
    observations: rows.length,
    decisionMs: summarize(rows.map((row) => row.decisionMs)),
    browserObservedTotalMs: summarize(rows.map((row) => row.browserObservedTotalMs)),
    runtimeElapsedMs: summarize(rows.map((row) => row.runtimeElapsedMs).filter(Number.isFinite)),
    p99Qualification: "60 observations across two fresh profiles; empirical order statistic, not a stable tail guarantee",
  }]));
}

function summarize(values) {
  if (!values.length) return { n: 0, p50: null, p95: null, p99: null };
  const sorted = [...values].sort((a, b) => a - b);
  const quantile = (q) => sorted[Math.ceil(q * sorted.length) - 1];
  return { n: sorted.length, p50: quantile(0.50), p95: quantile(0.95), p99: quantile(0.99) };
}

async function resourceSummary(files) {
  const byRole = new Map();
  let cgroupPeak = null;
  let cgroupCpuStart = null;
  let cgroupCpuEnd = null;
  let cgroupMemoryMissing = 0;
  let cgroupCpuMissing = 0;
  let nativeObserved = false;
  for (const file of files) {
    if (!file.sha256) continue;
    const samples = parseJsonl(await readFile(join(OUTPUT, file.file), "utf8"));
    for (const sample of samples) {
      if (Number.isSafeInteger(sample.cgroup.memory_current_bytes) && sample.cgroup.memory_current_bytes >= 0) {
        cgroupPeak = cgroupPeak === null ? sample.cgroup.memory_current_bytes
          : Math.max(cgroupPeak, sample.cgroup.memory_current_bytes);
      } else cgroupMemoryMissing += 1;
      if (Number.isSafeInteger(sample.cgroup.cpu_usage_usec) && sample.cgroup.cpu_usage_usec >= 0) {
        cgroupCpuStart ??= sample.cgroup.cpu_usage_usec;
        cgroupCpuEnd = sample.cgroup.cpu_usage_usec;
      } else cgroupCpuMissing += 1;
      for (const row of sample.roles) {
        if (row.role === "native_host") nativeObserved = true;
        const key = `${row.role}/${row.pid}/${row.start_ticks}`;
        const record = byRole.get(key) || { role: row.role, pid: row.pid, startTicks: row.start_ticks,
          startTimeEpochSeconds: row.start_time_epoch_seconds,
          sampledPeakRssBytes: null, sampledPeakPssBytes: null, firstCpuSeconds: null, lastCpuSeconds: null,
          missingRssSamples: 0, missingPssSamples: 0, missingCpuSamples: 0, missingStartTicksSamples: 0,
          samples: 0 };
        if (Number.isSafeInteger(row.start_ticks) && row.start_ticks >= 0) record.startTicks = row.start_ticks;
        else record.missingStartTicksSamples += 1;
        if (Number.isSafeInteger(row.rss_bytes) && row.rss_bytes >= 0) {
          record.sampledPeakRssBytes = record.sampledPeakRssBytes === null ? row.rss_bytes
            : Math.max(record.sampledPeakRssBytes, row.rss_bytes);
        } else record.missingRssSamples += 1;
        if (Number.isSafeInteger(row.pss_bytes) && row.pss_bytes >= 0) {
          record.sampledPeakPssBytes = record.sampledPeakPssBytes === null ? row.pss_bytes
            : Math.max(record.sampledPeakPssBytes, row.pss_bytes);
        } else record.missingPssSamples += 1;
        if (Number.isFinite(row.cpu_seconds) && row.cpu_seconds >= 0) {
          record.firstCpuSeconds ??= row.cpu_seconds;
          record.lastCpuSeconds = row.cpu_seconds;
        } else record.missingCpuSamples += 1;
        record.samples += 1;
        byRole.set(key, record);
      }
    }
  }
  const processes = [...byRole.values()].map((record) => ({
    ...record,
    cpuDeltaSeconds: record.firstCpuSeconds === null || record.lastCpuSeconds === null
      ? null : record.lastCpuSeconds - record.firstCpuSeconds,
  }));
  return {
    intervalMs: 100,
    cgroupMemorySampledPeakBytes: cgroupPeak,
    cgroupCpuSampledDeltaUsec: cgroupCpuStart === null ? null : cgroupCpuEnd - cgroupCpuStart,
    cgroupMemoryMissingSamples: cgroupMemoryMissing,
    cgroupCpuMissingSamples: cgroupCpuMissing,
    processes,
    nativeHostObserved: nativeObserved,
    qualification: "Sampled peaks may miss shorter spikes; bridge and supervisor share one process and are counted once; role peaks are not summed across timestamps.",
  };
}

async function nativeHostEvidence(files, registration) {
  let count = 0;
  let identities = new Map();
  for (const file of files) {
    if (!file.sha256) continue;
    const text = await readFile(join(OUTPUT, file.file), "utf8");
    for (const sample of parseJsonl(text)) {
      for (const row of sample.roles) if (row.role === "native_host") {
        count += 1;
        identities.set(`${row.pid}/${row.start_time_epoch_seconds}`, row);
      }
    }
  }
  return {
    registeredManifestSha256: registration.manifestSha256,
    launcherSha256: registration.launcherSha256,
    installedHostSha256: registration.hostSha256,
    observedSampleCount: count,
    sampledProcessIdentities: [...identities.keys()],
    status: count ? "observed by 100ms process sampler" : "not observed; no native host peak claim",
  };
}

async function finalize() {
  if (!receipt) return;
  receipt.externalRequestCount = externalRequests.length;
  receipt.externalRequests = externalRequests.map(({ url, method }) => ({ url, method }));
  receipt.finalSourceHashes = {};
  for (const relativePath of SOURCE_FILES) receipt.finalSourceHashes[relativePath] = await hashFile(join(ROOT, relativePath)).catch(() => null);
  const changed = Object.keys(receipt.sourceHashes || {}).filter((path) => receipt.sourceHashes[path] !== receipt.finalSourceHashes[path]);
  if (changed.length) {
    receipt.status = "failed";
    receipt.failure = { type: "source_changed_during_run", changedFiles: changed };
    process.exitCode = 1;
  }
  const temp = join(OUTPUT, `.receipt-${randomUUID()}.tmp`);
  await writeFile(temp, JSON.stringify(receipt, null, 2), { flag: "wx" });
  await import("node:fs/promises").then(({ rename }) => rename(temp, join(OUTPUT, "receipt.json")));
  await writeFile(join(OUTPUT, "status.json"), JSON.stringify({
    status: receipt.status,
    runId,
    receiptSha256: await hashFile(join(OUTPUT, "receipt.json")),
    completedAt: receipt.completedAt || new Date().toISOString(),
  }, null, 2));
}

async function stopProviderFixture() {
  if (!server) return;
  await new Promise((resolvePromise) => server.close(() => resolvePromise()));
  server = null;
}

async function verifyNoExternalRequests() {
  assert.deepEqual(externalRequests, [], "browser attempted a request outside the fake chatgpt.com fixture");
}

async function assertPortsClosedAfterRecovery() { await assertPortsClosed("post-recovery"); }

function spawnSampler(outputPath) {
  const child = spawn("/workspace/extension/client-runtime/.venv/bin/python", [
    RESOURCE_SAMPLER, "--output", outputPath, "--interval-ms", "100",
  ], { cwd: ROOT, env: process.env, stdio: "ignore" });
  samplerClosed = new Promise((resolvePromise) => {
    child.once("error", (error) => resolvePromise({ code: null, signal: null, error: safeError(error) }));
    child.once("close", (code, signal) => resolvePromise({ code, signal }));
  });
  return child;
}

function parseArgs(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    if (!values[index].startsWith("--")) continue;
    const [key, inline] = values[index].slice(2).split("=", 2);
    result[key] = inline ?? values[index + 1];
    if (inline === undefined) index += 1;
  }
  return result;
}

function positiveInteger(value, fallback) {
  const number = Number(value ?? fallback);
  if (!Number.isInteger(number) || number <= 0) throw new Error("session and repetition controls must be positive integers");
  return number;
}

function safeError(error) {
  let message = String(error?.message || error);
  for (const example of Object.values(CASES)) {
    message = message.replaceAll(example.prompt, `<synthetic-prompt:${example.id}>`);
  }
  return { type: error?.name || "Error", message: message.slice(0, 500) };
}

function safeFilename(value) { return value.replace(/[^a-z0-9_-]+/gi, "_").slice(0, 100); }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
async function hashFile(path) { return sha256(await readFile(path)); }
function parseJsonl(text) {
  const lines = text.split("\n");
  if (lines.at(-1) !== "") lines.pop();
  return lines.filter(Boolean).map((line) => JSON.parse(line));
}

async function hashTree(root) {
  const files = {};
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files[relative(root, path).replaceAll("\\", "/")] = await hashFile(path);
    }
  }
  await visit(root);
  return { files, sha256: sha256(JSON.stringify(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)))) };
}

function sanitizeHeaders(headers) {
  const output = {};
  for (const [key, value] of Object.entries(headers || {})) {
    if (["authorization", "cookie", "set-cookie"].includes(key.toLowerCase())) continue;
    output[key] = value;
  }
  return output;
}

function safeHost(rawUrl) { try { return new URL(rawUrl).hostname; } catch { return null; } }
function delay(ms) { return new Promise((resolvePromise) => setTimeout(resolvePromise, ms)); }
function isWithin(root, path) {
  const relativePath = relative(root, path);
  return relativePath === "" || (!relativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`)
    && relativePath !== "..");
}
async function childStartDeltaMs(supervisor, detector) {
  return Math.max(0, detector.startTicks - supervisor.startTicks) * 10;
}
