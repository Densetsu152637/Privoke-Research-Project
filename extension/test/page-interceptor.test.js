import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { extractPrompt, promptTarget } from "../src/prompt-interception.js";

const source = (await readFile(new URL("../src/page-interceptor.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/gm, "");
const url = "https://chatgpt.com/backend-api/conversation";
const body = JSON.stringify({ prompt: "My private prompt" });
const flush = () => new Promise((resolve) => setImmediate(resolve));

function harness() {
  const messages = [];
  const listeners = new Set();
  const timers = new Map();
  const sent = [];
  const response = new Response("AI reply");
  class Xhr extends EventTarget {
    static UNSENT = 0;
    static OPENED = 1;
    static DONE = 4;
    state = 0;
    status = 0;
    timeout = 0;
    get readyState() { return this.state; }
    open() { this.state = 1; }
    send(value) {
      sent.push({ xhr: this, body: value });
      if (this.failSend) throw new Error("native send failed");
    }
    // Native abort before native send leaves an OPENED XHR in OPENED.
    abort() { if (this.state !== 1) this.state = 0; }
    dispatchEvent(event) {
      super.dispatchEvent(event);
      this[`on${event.type}`]?.(event);
      return true;
    }
  }
  const window = {
    fetch(...args) { sent.push({ args, receiver: this }); return Promise.resolve(response); },
    addEventListener(type, listener) { if (type === "message") listeners.add(listener); },
    removeEventListener(type, listener) { listeners.delete(listener); },
    postMessage(data) { messages.push(data); },
  };
  vm.runInNewContext(source, {
    runtimeFailureResponse: () => ({ action: "BLOCK" }), window, location: { href: url }, XMLHttpRequest: Xhr,
    Request, URL, URLSearchParams, FormData, DOMException, AbortController,
    Event, ProgressEvent: Event, TypeError, crypto, extractPrompt, promptTarget,
    setTimeout(callback, ms) { const id = Symbol(); timers.set(id, { callback, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  function decide(action, requestId = messages.at(-1).requestId) {
    for (const listener of [...listeners]) listener({
      source: window,
      data: { channel: "privoke-extension-v1", type: "ANALYZE_RESULT", requestId, action },
    });
  }
  function expire(ms) {
    for (const [id, timer] of [...timers]) {
      if (timer.ms === ms) { timers.delete(id); timer.callback(); }
    }
  }
  return { window, Xhr, response, sent, messages, listeners, timers, decide, expire };
}

test("blocked fetch rejects as a visible failure without sending the prompt", async () => {
  const h = harness();
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.decide("BLOCK");
  await assert.rejects(request, { name: "TypeError", message: "Prompt blocked by PriVoke." });
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

for (const action of ["ALLOW", "WARN"]) {
  test(`fetch forwards the original request after ${action ?? "analysis timeout"}`, async () => {
    const h = harness();
    const init = { method: "POST", body };
    const request = h.window.fetch(url, init);
    await flush();
    if (action) h.decide(action);
    else h.expire(32_000);
    assert.equal(await request, h.response);
    assert.deepEqual(h.sent[0].args, [url, init]);
    assert.equal(h.listeners.size, 0);
    assert.equal(h.timers.size, 0);
  });
}

test("fetch cancellation while checking settles immediately and ignores late decisions", async () => {
  const h = harness();
  const controller = new AbortController();
  const request = new Request(url, { method: "POST", body, signal: controller.signal });
  const result = h.window.fetch(request);
  await flush();
  controller.abort();
  await assert.rejects(result, { name: "AbortError" });
  h.decide("ALLOW");
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

test("fetch preserves an explicit cancellation reason and skips already cancelled requests", async () => {
  const h = harness();
  const controller = new AbortController();
  const reason = new Error("caller cancelled");
  controller.abort(reason);
  await assert.rejects(h.window.fetch(url, { method: "POST", body, signal: controller.signal }),
    (error) => error === reason);
  assert.equal(h.messages.length, 0);
  assert.equal(h.sent.length, 0);
});

function startXhr(h) {
  const xhr = new h.Xhr();
  const events = [];
  for (const type of ["readystatechange", "error", "abort", "timeout", "loadend", "load"]) {
    xhr.addEventListener(type, () => events.push([type, xhr.readyState, xhr.status]));
  }
  xhr.open("POST", url);
  return { xhr, events };
}

test("blocked XHR settles event listeners and onerror clients exactly once", async () => {
  const h = harness();
  const { xhr, events } = startXhr(h);
  const settled = new Promise((resolve) => { xhr.onerror = resolve; });
  xhr.send(body);
  h.decide("BLOCK");
  await settled;
  await flush();
  assert.deepEqual(events, [["readystatechange", 4, 0], ["error", 4, 0], ["loadend", 4, 0]]);
  assert.equal(xhr.readyState, 4);
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

for (const type of ["abort", "timeout"]) {
  test(`XHR ${type} during the privacy check settles and prevents a late send`, async () => {
    const h = harness();
    const { xhr, events } = startXhr(h);
    xhr.timeout = 50;
    xhr.send(body);
    if (type === "abort") xhr.abort();
    else h.expire(50);
    h.decide("ALLOW");
    await flush();
    assert.deepEqual(events, [["readystatechange", 4, 0], [type, 4, 0], ["loadend", 4, 0]]);
    assert.equal(xhr.readyState, type === "abort" ? 0 : 4);
    assert.equal(h.sent.length, 0);
    assert.equal(h.listeners.size, 0);
    assert.equal(h.timers.size, 0);
  });
}

test("XHR can be reopened after a block and sent normally", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  xhr.send(body);
  h.decide("BLOCK");
  await flush();
  xhr.open("POST", url);
  assert.equal(xhr.readyState, 1);
  xhr.send(body);
  h.decide("ALLOW");
  await flush();
  assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].body, body);
});

test("reopening XHR during analysis discards the previous decision", async () => {
  const h = harness();
  const { xhr, events } = startXhr(h);
  xhr.send(body);
  const oldId = h.messages.at(-1).requestId;
  xhr.open("POST", url);
  xhr.send(body);
  h.decide("BLOCK", oldId);
  h.decide("WARN");
  await flush();
  assert.equal(h.sent.length, 1);
  assert.deepEqual(events, []);
  assert.equal(h.listeners.size, 0);
});

test("XHR native send failures emit error once and are never retried", async () => {
  const h = harness();
  const { xhr, events } = startXhr(h);
  xhr.failSend = true;
  xhr.send(body);
  h.decide("ALLOW");
  await flush();
  assert.equal(h.sent.length, 1);
  assert.deepEqual(events.map(([type]) => type), ["readystatechange", "error", "loadend"]);
});

test("page messaging failures block immediately and clean up the check", async () => {
  const h = harness();
  h.window.postMessage = () => { throw new Error("messaging unavailable"); };
  await assert.rejects(h.window.fetch(url, { method: "POST", body }), { name: "TypeError" });
  const { xhr } = startXhr(h);
  xhr.send(body);
  await flush();
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

test("XHR analysis timeout blocks and duplicate pending sends fail synchronously", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  xhr.send(body);
  assert.throws(() => xhr.send(body), { name: "InvalidStateError" });
  h.expire(32_000);
  await flush();
  assert.equal(h.sent.length, 0);
  assert.equal(xhr.readyState, h.Xhr.DONE);
});

test("unmatched requests bypass analysis and synchronous prompt requests fail immediately", async () => {
  const h = harness();
  await h.window.fetch("https://example.com", { method: "POST", body });
  const xhr = new h.Xhr();
  xhr.open("POST", "https://example.com");
  xhr.send(body);
  xhr.open("POST", url, false);
  assert.throws(() => xhr.send(body), { name: "NetworkError" });
  assert.equal(h.messages.length, 0);
  assert.equal(h.sent.length, 2);
});
