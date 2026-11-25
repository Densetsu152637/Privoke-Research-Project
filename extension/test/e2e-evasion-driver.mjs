// Browser driver for the Stage 13b end-to-end evasion study (E2EEVADE).
//
// Derived from cross-platform-driver.mjs (Stage 11), which is left unedited. It speaks
// newline-delimited JSON on stdin/stdout so the Python orchestrator (evaluation/e2e_evasion.py)
// can drive one installed-extension browser. Chromium-family browsers are driven over their
// `--remote-debugging-pipe` CDP pipe and Firefox over Marionette. The extension is loaded as an
// unpacked/temporary add-on. Differences from Stage 11:
//   * the `send` operation builds the provider request body in this process with the shared
//     fixture builder and returns the hash of the exact body the page sent;
//   * a Chromium page session counts requests to hosts outside the fixture set (`foreign`);
//   * the fault, XHR and probe-catalogue operations are not needed and are not provided.
//
// Safety: every hostname outside the synthetic fixture hosts resolves to NOTFOUND inside the
// browser (proxied to a dead loopback port in Firefox), so no request can reach a real provider.
import { spawn } from "node:child_process";
import net from "node:net";
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";
import { FIXTURE, buildBody } from "./fixtures/provider-shapes.mjs";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const reply = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

// The function body evaluated inside the page's main world for each probe.
const PAGE_PROBE = String.raw`(async (spec) => {
  const key = "__e2e_log";
  if (!window[key]) {
    const entries = [];
    window.addEventListener("message", (event) => {
      const data = event.data;
      if (event.source !== window || !data || data.channel !== "privoke-extension-v1") return;
      entries.push({ type: data.type, requestId: data.requestId ?? null, action: data.action ?? null,
        targetApp: data.targetApp ?? null, text: data.text ?? null,
        disposition: data.observation?.request_disposition ?? null,
        noticeStatus: data.observation?.notice_status ?? null,
        inspectionUnavailable: data.inspectionUnavailable ?? null });
    });
    window[key] = entries;
  }
  const log = window[key];
  const mark = log.length;
  // The page's own "analysis unavailable" notice persists between sends; clear it so a send sees only its own.
  document.getElementById("privoke-inspection-unavailable")?.remove();
  const out = { transport: spec.transport, pageUrl: location.href };
  const started = performance.now();
  if (spec.transport === "fetch") {
    try {
      const controller = new AbortController();
      if (spec.abortAfterMs != null) setTimeout(() => controller.abort(), spec.abortAfterMs);
      const response = await fetch(spec.url, { method: "POST", headers: spec.headers, body: spec.body, signal: controller.signal });
      out.status = response.status;
      out.responseText = (await response.text()).slice(0, 80);
    } catch (error) {
      out.errorName = error?.name ?? "Error";
      out.errorMessage = String(error?.message ?? error).slice(0, 120);
    }
  } else {
    out.events = [];
    await new Promise((resolve) => {
      const xhr = new XMLHttpRequest();
      for (const type of ["load", "error", "abort", "timeout"]) {
        xhr.addEventListener(type, () => out.events.push(type));
      }
      xhr.addEventListener("loadend", () => {
        out.events.push("loadend");
        out.status = xhr.status;
        out.readyState = xhr.readyState;
        out.responseText = xhr.status ? String(xhr.responseText).slice(0, 80) : "";
        resolve();
      });
      xhr.open("POST", spec.url, true);
      if (spec.abortAfterMs != null) setTimeout(() => xhr.abort(), spec.abortAfterMs);
      for (const [name, value] of Object.entries(spec.headers ?? {})) xhr.setRequestHeader(name, value);
      xhr.send(spec.body);
    });
  }
  out.elapsedMs = performance.now() - started;
  await new Promise((resolve) => setTimeout(resolve, spec.settleMs ?? 80));
  out.messages = log.slice(mark);
  out.unavailableNotice = Boolean(document.getElementById("privoke-inspection-unavailable"));
  return out;
})`;

class ChromiumSession {
  async launch(options) {
    const hostRules = [
      ...options.hosts.map((host) => `MAP ${host} 127.0.0.1`),
      "MAP * ~NOTFOUND",
      "EXCLUDE 127.0.0.1",
      "EXCLUDE localhost",
    ].join(", ");
    const args = [
      `--user-data-dir=${options.userDataDir}`,
      "--remote-debugging-pipe",
      "--enable-unsafe-extension-debugging",
      "--headless=new",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      `--host-resolver-rules=${hostRules}`,
      `--ignore-certificate-errors-spki-list=${options.spki}`,
      ...(options.extraArgs ?? []),
      "about:blank",
    ];
    this.child = spawn(options.exe, args, { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
    this.child.on("exit", (code) => { this.exitCode = code; });
    this.write = this.child.stdio[3];
    this.pending = new Map();
    this.listeners = [];
    this.nextId = 0;
    let buffer = "";
    this.child.stdio[4].on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      for (let end = buffer.indexOf("\0"); end >= 0; end = buffer.indexOf("\0")) {
        const message = JSON.parse(buffer.slice(0, end));
        buffer = buffer.slice(end + 1);
        if (message.id && this.pending.has(message.id)) {
          this.pending.get(message.id)(message);
          this.pending.delete(message.id);
        } else if (message.method) {
          for (const listener of this.listeners) listener(message);
        }
      }
    });
    this.fixtureHosts = new Set(options.hosts);
    this.foreign = [];
    this.listeners.push((message) => {
      if (message.method !== "Network.requestWillBeSent") return;
      let host = "";
      try { host = new URL(message.params.request.url).hostname; } catch { host = "unparseable"; }
      if (!this.fixtureHosts.has(host) && !LOOPBACK.has(host)) this.foreign.push(host);
    });
    const version = (await this.send("Browser.getVersion")).result;
    const loaded = await this.send("Extensions.loadUnpacked", { path: options.extensionDir });
    if (loaded.error) return { ok: false, error: `Extensions.loadUnpacked: ${loaded.error.message}`, product: version.product };
    this.extensionId = loaded.result.id;
    await sleep(1500);
    return { ok: true, product: version.product, userAgent: version.userAgent, extensionId: this.extensionId };
  }

  send(method, params = {}, sessionId = undefined, timeoutMs = 120_000) {
    return new Promise((resolve, reject) => {
      const id = ++this.nextId;
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, timeoutMs);
      this.pending.set(id, (message) => { clearTimeout(timer); resolve(message); });
      this.write.write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`);
    });
  }

  async open(url) {
    if (this.sessionId) {
      await this.send("Target.closeTarget", { targetId: this.targetId });
    }
    const created = (await this.send("Target.createTarget", { url: "about:blank" })).result;
    this.targetId = created.targetId;
    this.sessionId = (await this.send("Target.attachToTarget", { targetId: this.targetId, flatten: true })).result.sessionId;
    await this.send("Page.enable", {}, this.sessionId);
    await this.send("Network.enable", {}, this.sessionId);
    const loaded = new Promise((resolve) => {
      const listener = (message) => {
        if (message.sessionId === this.sessionId && message.method === "Page.loadEventFired") {
          this.listeners = this.listeners.filter((entry) => entry !== listener);
          resolve();
        }
      };
      this.listeners.push(listener);
    });
    const navigated = (await this.send("Page.navigate", { url }, this.sessionId)).result;
    if (navigated.errorText) return { ok: false, error: navigated.errorText };
    await Promise.race([loaded, sleep(15_000)]);
    await sleep(300);
    return { ok: true };
  }

  async run(spec, timeoutMs) {
    const expression = `${PAGE_PROBE}(${JSON.stringify(spec)})`;
    const result = await this.send("Runtime.evaluate",
      { expression, awaitPromise: true, returnByValue: true }, this.sessionId, timeoutMs);
    if (result.error || result.result?.exceptionDetails) {
      return { harnessError: result.error?.message ?? result.result.exceptionDetails.text };
    }
    return result.result.result.value;
  }

  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, this.sessionId);
    return result.result?.result?.value;
  }

  drainForeign() {
    const requests = this.foreign.splice(0);
    return { measured: true, requests };
  }

  // Evaluates `expression` in the extension's background service worker, for example to
  // read the per-tab action badge that reports a coverage gap.
  async extensionEvaluate(expression) {
    if (!this.workerSession) {
      const targets = (await this.send("Target.getTargets")).result.targetInfos;
      const worker = targets.find((target) => target.type === "service_worker"
        && target.url.startsWith(`chrome-extension://${this.extensionId}/`));
      if (!worker) return { harnessError: "extension service worker not found" };
      this.workerSession = (await this.send("Target.attachToTarget",
        { targetId: worker.targetId, flatten: true })).result.sessionId;
    }
    const result = await this.send("Runtime.evaluate",
      { expression, awaitPromise: true, returnByValue: true }, this.workerSession);
    if (result.error || result.result?.exceptionDetails) {
      this.workerSession = undefined;
      return { harnessError: result.error?.message ?? result.result.exceptionDetails.text };
    }
    return result.result?.result?.value;
  }

  async close() {
    try { await this.send("Browser.close", {}, undefined, 5000); } catch { /* browser exits */ }
    await sleep(500);
    if (this.exitCode === undefined) this.child.kill();
  }
}

class FirefoxSession {
  async launch(options) {
    const prefs = [
      'user_pref("network.dns.localDomains", "' + options.hosts.join(",") + '");',
      // Everything except the fixture hosts goes to a dead loopback proxy (discard port).
      'user_pref("network.proxy.type", 1);',
      'user_pref("network.proxy.http", "127.0.0.1");',
      'user_pref("network.proxy.http_port", 9);',
      'user_pref("network.proxy.ssl", "127.0.0.1");',
      'user_pref("network.proxy.ssl_port", 9);',
      'user_pref("network.proxy.no_proxies_on", "' + options.hosts.join(",") + ',localhost,127.0.0.1");',
      'user_pref("network.proxy.allow_hijacking_localhost", true);',
      'user_pref("app.update.auto", false);',
      'user_pref("app.update.enabled", false);',
      'user_pref("datareporting.policy.dataSubmissionEnabled", false);',
      'user_pref("browser.shell.checkDefaultBrowser", false);',
      'user_pref("extensions.autoDisableScopes", 0);',
      'user_pref("extensions.webextensions.userScripts.enabled", true);',
      'user_pref("network.captive-portal-service.enabled", false);',
      'user_pref("network.connectivity-service.enabled", false);',
      'user_pref("browser.safebrowsing.malware.enabled", false);',
      'user_pref("browser.safebrowsing.phishing.enabled", false);',
      'user_pref("services.settings.server", "http://127.0.0.1:9/");',
      'user_pref("toolkit.telemetry.enabled", false);',
    ].join("\n");
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(options.userDataDir, { recursive: true });
    writeFileSync(`${options.userDataDir}/user.js`, prefs);
    this.child = spawn(options.exe, ["-headless", "-marionette", "-no-remote", "-profile", options.userDataDir, "about:blank"],
      { stdio: "ignore" });
    this.child.on("exit", (code) => { this.exitCode = code; });
    this.pending = new Map();
    this.nextId = 0;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      try { this.socket = await connect(2828); break; } catch { await sleep(500); }
    }
    if (!this.socket) return { ok: false, error: "Marionette did not start" };
    let buffer = Buffer.alloc(0);
    this.socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const colon = buffer.indexOf(":");
        if (colon < 0) return;
        const length = Number(buffer.subarray(0, colon).toString());
        if (buffer.length < colon + 1 + length) return;
        const message = JSON.parse(buffer.subarray(colon + 1, colon + 1 + length).toString("utf8"));
        buffer = buffer.subarray(colon + 1 + length);
        if (Array.isArray(message) && this.pending.has(message[1])) {
          this.pending.get(message[1])(message);
          this.pending.delete(message[1]);
        }
      }
    });
    await sleep(500);
    const session = await this.command("WebDriver:NewSession", { acceptInsecureCerts: true });
    const caps = session[3]?.capabilities ?? {};
    const installed = await this.command("Addon:Install", { path: options.extensionDir, temporary: true });
    if (installed[2]) {
      return { ok: false, error: `Addon:Install: ${installed[2].message}`, product: `Firefox/${caps.browserVersion}`,
        userAgent: caps.userAgent };
    }
    await this.command("WebDriver:SetTimeouts", { script: 180_000, pageLoad: 30_000 });
    return { ok: true, product: `Firefox/${caps.browserVersion}`, userAgent: caps.userAgent, extensionId: installed[3]?.value };
  }

  command(name, params = {}) {
    return new Promise((resolve) => {
      const id = ++this.nextId;
      this.pending.set(id, resolve);
      const json = JSON.stringify([0, id, name, params]);
      this.socket.write(`${Buffer.byteLength(json)}:${json}`);
    });
  }

  async open(url) {
    const result = await this.command("WebDriver:Navigate", { url });
    if (result[2]) return { ok: false, error: `${result[2].error}: ${result[2].message}` };
    await sleep(500);
    return { ok: true };
  }

  // Runs `source` (an expression yielding a value or promise) in the page's main world and
  // returns its JSON result through a DOM attribute, which the sandbox can read.
  async mainWorld(source) {
    const script = `
      const done = arguments[arguments.length - 1];
      const attribute = "data-e2e-" + Math.random().toString(16).slice(2);
      const element = document.createElement("script");
      element.textContent = "Promise.resolve(" + ${JSON.stringify(source)} + ").then((v) => document.documentElement.setAttribute('" + attribute + "', JSON.stringify(v === undefined ? null : v)), (e) => document.documentElement.setAttribute('" + attribute + "', JSON.stringify({ harnessError: String(e) })));";
      document.documentElement.appendChild(element);
      element.remove();
      const poll = () => {
        const value = document.documentElement.getAttribute(attribute);
        if (value !== null) { document.documentElement.removeAttribute(attribute); done(value); }
        else window.setTimeout(poll, 25);
      };
      poll();`;
    const result = await this.command("WebDriver:ExecuteAsyncScript", { script, args: [], newSandbox: true });
    if (result[2]) return { harnessError: result[2].message };
    return JSON.parse(result[3].value);
  }

  async run(spec) {
    return this.mainWorld(`${PAGE_PROBE}(${JSON.stringify(spec)})`);
  }

  async evaluate(expression) {
    return this.mainWorld(expression);
  }

  drainForeign() {
    return { measured: false, requests: [] };
  }

  async close() {
    try { await this.command("Marionette:Quit", { flags: ["eForceQuit"] }); } catch { /* quits */ }
    await sleep(1000);
    if (this.exitCode === undefined) this.child.kill();
  }
}

function connect(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => resolve(socket));
    socket.on("error", reject);
  });
}

// Builds the provider body from the shared fixture, sends it from the page main world, and
// returns what the page observed together with the hash of the exact body it sent.
async function send(request) {
  const shape = FIXTURE.shapes.find((entry) => entry.id === (request.shape ?? "chatgpt-conversation"));
  if (!shape) return { error: `unknown provider shape ${request.shape}` };
  const built = buildBody(shape, request.prompt);
  const url = `${shape.url}${shape.url.includes("?") ? "&" : "?"}xp=${encodeURIComponent(request.sendId)}`;
  const spec = { transport: "fetch", url, headers: { "content-type": built.contentType }, body: built.text, settleMs: request.settleMs };
  const outcome = await session.run(spec, request.timeoutMs ?? 120_000);
  return {
    outcome,
    url,
    expectedBodySha256: createHash("sha256").update(built.text, "utf8").digest("hex"),
  };
}

let session;
const input = createInterface({ input: process.stdin });
for await (const line of input) {
  if (!line.trim()) continue;
  const request = JSON.parse(line);
  try {
    if (request.op === "launch") {
      session = request.family === "firefox" ? new FirefoxSession() : new ChromiumSession();
      reply({ id: request.id, ...(await session.launch(request)) });
    } else if (request.op === "open") {
      reply({ id: request.id, ...(await session.open(request.url)) });
    } else if (request.op === "send") {
      reply({ id: request.id, ...(await send(request)) });
    } else if (request.op === "extension-eval") {
      reply({ id: request.id, value: session.extensionEvaluate
        ? await session.extensionEvaluate(request.expression)
        : { harnessError: "extension evaluation is only implemented for Chromium" } });
    } else if (request.op === "foreign") {
      reply({ id: request.id, ...session.drainForeign() });
    } else if (request.op === "eval") {
      reply({ id: request.id, value: await session.evaluate(request.expression) });
    } else if (request.op === "close") {
      await session?.close();
      reply({ id: request.id, ok: true });
      break;
    } else {
      reply({ id: request.id, error: `unknown op ${request.op}` });
    }
  } catch (error) {
    reply({ id: request.id, error: String(error?.message ?? error) });
  }
}
process.exit(0);
