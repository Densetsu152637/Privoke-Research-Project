import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { extractPrompt, promptTarget } from "../src/prompt-interception.js";
import { ANALYSIS_TIMEOUT_MS, STREAMING_HEALTH_TIMEOUT_MS, RESPONSE_TIMEOUT_MS } from "../src/analysis-timeouts.js";
import { runtimeFailureResponse } from "../src/interception-failure.js";

const source = (await readFile(new URL("../src/page-interceptor.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/gm, "");
const url = "https://chatgpt.com/backend-api/conversation";
const body = JSON.stringify({ prompt: "My private prompt" });
const flush = () => new Promise((resolve) => setImmediate(resolve));
async function flushUntil(predicate) {
  for (let attempt = 0; attempt < 20 && !predicate(); attempt += 1) await flush();
  assert.equal(predicate(), true);
}

function harness(RequestClass = Request, nativeError = null) {
  const messages = [];
  const listeners = new Set();
  const timers = new Map();
  const sent = [];
  const order = [];
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
      order.push("xhr-send");
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
    fetch(...args) {
      if (args[0] instanceof Request && args[0].bodyUsed) return Promise.reject(new TypeError("Body already consumed"));
      sent.push({ args, receiver: this }); order.push("fetch");
      if (nativeError) throw nativeError;
      return Promise.resolve(response);
    },
    addEventListener(type, listener) { if (type === "message") listeners.add(listener); },
    removeEventListener(type, listener) { listeners.delete(listener); },
    postMessage(data) { messages.push(data); if (data.type === "ANALYZE_OUTCOME") order.push("outcome"); },
  };
  vm.runInNewContext(source, {
    RESPONSE_TIMEOUT_MS, runtimeFailureResponse, window, location: { href: url }, XMLHttpRequest: Xhr,
    Request: RequestClass, Response, URL, URLSearchParams, FormData, Blob, ReadableStream,
    Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, DOMException, AbortController,
    Event, ProgressEvent: Event, TypeError, crypto, extractPrompt, promptTarget,
    setTimeout(callback, ms) { const id = Symbol(); timers.set(id, { callback, ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  function decide(action, requestId = messages.filter((message) => message.type === "ANALYZE_PROMPT").at(-1).requestId,
    { legacy = false } = {}) {
    for (const listener of [...listeners]) listener({
      source: window,
      data: {
        channel: "privoke-extension-v1", type: "ANALYZE_RESULT", requestId, action,
        ...(!legacy ? { observation: {
          schema_version: 1,
          notice_status: action === "ALLOW" ? "NOT_REQUESTED" : "RENDERED",
        } } : {}),
      },
    });
  }
  function expire(ms) {
    for (const [id, timer] of [...timers]) {
      if (timer.ms === ms) { timers.delete(id); timer.callback(); }
    }
  }
  return { window, Xhr, response, sent, messages, listeners, timers, order, decide, expire };
}

const outcomes = (h) => h.messages.filter((message) => message.type === "ANALYZE_OUTCOME");

test("page deadline leaves the full health and analysis budgets for a late safe decision", async () => {
  const h = harness();
  const result = h.window.fetch(url, { method: "POST", body });
  await flush();
  const analysisTimer = [...h.timers.values()].find(({ ms }) => ms > 5_000);
  assert.ok(analysisTimer.ms > STREAMING_HEALTH_TIMEOUT_MS + ANALYSIS_TIMEOUT_MS);
  // At the old deadline a valid result could still be pending in background.
  h.expire(32_000);
  assert.equal(h.sent.length, 0);
  h.decide("ALLOW");
  assert.equal(await result, h.response);
  assert.equal(h.sent.length, 1);
  assert.equal(h.timers.size, 0);
});

test("ChatGPT metadata bypasses analysis while prompt-bearing requests on the same path stay gated", async () => {
  const endpoint = "https://chatgpt.com/backend-api/f/conversation/fixture-subpath";
  const h = harness();
  const metadata = { method: "POST", body: JSON.stringify({ action: "next", model: "gpt-4o" }) };
  assert.equal(await h.window.fetch(endpoint, metadata), h.response);
  assert.deepEqual(h.sent[0].args, [endpoint, metadata]);
  assert.equal(h.messages.length, 0);
  for (const action of ["ALLOW", "BLOCK"]) {
    const init = { method: "POST", body: JSON.stringify({ messages: [
      { author: { role: "user" }, content: { parts: ["Actual user prompt"] } },
    ] }) };
    const result = h.window.fetch(endpoint, init);
    await flush();
    assert.equal(h.messages.filter(({ type }) => type === "ANALYZE_PROMPT").at(-1).text, "Actual user prompt");
    h.decide(action);
    if (action === "ALLOW") assert.equal(await result, h.response);
    else await assert.rejects(result, /Prompt blocked by PriVoke/);
  }
  assert.equal(h.sent.length, 2);
});

test("XHR and encoded ChatGPT metadata produce no analysis or synthetic error", async () => {
  const h = harness();
  const metadata = JSON.stringify({ action: "next", model: "gpt-4o" });
  const { xhr, events } = startXhr(h);
  xhr.send(metadata);
  assert.equal(h.sent.length, 1);
  assert.equal(h.messages.length, 0);
  assert.deepEqual(events, []);
  assert.equal(await h.window.fetch(url, { method: "POST", body: new Blob([metadata]) }), h.response);
  assert.equal(h.sent.length, 2);
  assert.equal(h.messages.length, 0);
});

test("blocked fetch rejects as a visible failure without sending the prompt", async () => {
  const h = harness();
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.decide("BLOCK");
  await assert.rejects(request, { name: "TypeError", message: "Prompt blocked by PriVoke." });
  assert.equal(h.sent.length, 0);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "BLOCKED_LOCALLY");
  assert.equal(outcomes(h)[0].observation.notice_status, "RENDERED");
  assert.equal(JSON.stringify(outcomes(h)[0]).includes("My private prompt"), false);
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
    else h.expire(RESPONSE_TIMEOUT_MS);
    assert.equal(await request, h.response);
    assert.deepEqual(h.sent[0].args, [url, init]);
    assert.equal(outcomes(h).length, 1);
    assert.equal(outcomes(h)[0].action, action);
    assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
    assert.deepEqual(h.order, ["fetch", "outcome"]);
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
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "UNKNOWN");
  assert.equal(Object.hasOwn(outcomes(h)[0], "action"), false);
  h.decide("ALLOW");
  assert.equal(outcomes(h).length, 1);
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

test("outcome event failures do not change successful request handoff", async () => {
  const h = harness();
  const postMessage = h.window.postMessage;
  h.window.postMessage = (message) => {
    if (message.type === "ANALYZE_OUTCOME") throw new Error("observation listener failed");
    postMessage(message);
  };
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.decide("ALLOW");
  assert.equal(await request, h.response);
  assert.equal(h.sent.length, 1);
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
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "BLOCKED_LOCALLY");
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
    assert.equal(outcomes(h).length, 1);
    assert.equal(outcomes(h)[0].observation.request_disposition, "UNKNOWN");
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
  assert.equal(outcomes(h).length, 2);
  assert.deepEqual(outcomes(h).map((message) => message.observation.request_disposition),
    ["BLOCKED_LOCALLY", "ORIGINAL_REQUEST_HANDED_OFF"]);
  assert.deepEqual(h.order, ["outcome", "xhr-send", "outcome"]);
  assert.equal(h.sent[0].body, body);
});

test("WARN result stays intact through XHR while observation records local handoff", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  xhr.send(body);
  h.decide("WARN");
  await flush();
  assert.equal(h.sent.length, 1);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].action, "WARN");
  assert.equal(outcomes(h)[0].observation.notice_status, "RENDERED");
  assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
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
  assert.equal(outcomes(h).length, 2);
  assert.equal(outcomes(h)[0].observation.request_disposition, "UNKNOWN");
  assert.equal(outcomes(h)[1].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
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
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "UNKNOWN");
  assert.deepEqual(h.order, ["xhr-send", "outcome"]);
});

test("page messaging failures permit handoff and clean up even when warning rendering fails", async () => {
  const h = harness();
  h.window.postMessage = () => { throw new Error("messaging unavailable"); };
  assert.equal(await h.window.fetch(url, { method: "POST", body }), h.response);
  const { xhr } = startXhr(h);
  xhr.send(body);
  await flush();
  assert.equal(h.sent.length, 2);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

test("XHR analysis timeout permits handoff and duplicate pending sends fail synchronously", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  xhr.send(body);
  assert.throws(() => xhr.send(body), { name: "InvalidStateError" });
  h.expire(RESPONSE_TIMEOUT_MS);
  await flush();
  assert.equal(h.sent.length, 1);
  assert.equal(xhr.readyState, h.Xhr.OPENED);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
  assert.equal(outcomes(h)[0].observation.notice_status, "UNKNOWN");
});

test("unmatched requests and uninspectable synchronous prompts reach the native API", async () => {
  const h = harness();
  await h.window.fetch("https://example.com", { method: "POST", body });
  const xhr = new h.Xhr();
  xhr.open("POST", "https://example.com");
  xhr.send(body);
  xhr.open("POST", url, false);
  xhr.send(body);
  assert.equal(h.messages.length, 0);
  assert.equal(h.sent.length, 3);
});

test("legacy action-only result remains compatible and marks notice state unknown", async () => {
  const h = harness();
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.decide("ALLOW", undefined, { legacy: true });
  assert.equal(await request, h.response);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.notice_status, "UNKNOWN");
  assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
});

test("invalid actions permit handoff and observations do not expose prompt text", async () => {
  const h = harness();
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.decide("MAYBE");
  assert.equal(await request, h.response);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].action, "WARN");
  assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
  assert.equal(outcomes(h)[0].observation.notice_status, "UNKNOWN");
  assert.equal(JSON.stringify(outcomes(h)[0]).includes("My private prompt"), false);
});


for (const encodedBody of [new Blob([body]), new TextEncoder().encode(body)]) {
  test(`encoded fetch body (${encodedBody.constructor.name}) is checked before network dispatch`, async () => {
    const h = harness();
    const result = h.window.fetch(url, { method: "POST", body: encodedBody });
    await flushUntil(() => h.messages.some((message) => message.type === "ANALYZE_PROMPT"));
    assert.equal(h.messages[0].text, "My private prompt");
    h.decide("BLOCK");
    await assert.rejects(result, { name: "TypeError" });
    assert.equal(h.sent.length, 0);
  });
  test(`encoded XHR body (${encodedBody.constructor.name}) is checked and settles after a block`, async () => {
    const h = harness();
    const { xhr, events } = startXhr(h);
    xhr.send(encodedBody);
    await flushUntil(() => h.messages.some((message) => message.type === "ANALYZE_PROMPT"));
    assert.equal(h.messages[0].text, "My private prompt");
    h.decide("BLOCK");
    await flush();
    assert.equal(h.sent.length, 0);
    assert.deepEqual(events.map(([type]) => type), ["readystatechange", "error", "loadend"]);
  });
}

test("aborting XHR while its Blob is decoding prevents a late analysis or send", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  let cancelled = false;
  const pendingBody = new Blob([body]);
  pendingBody.stream = () => new ReadableStream({ cancel() { cancelled = true; } });
  xhr.send(pendingBody);
  xhr.abort();
  await flush();
  assert.equal(cancelled, true);
  assert.equal(h.messages.filter((message) => message.type === "ANALYZE_PROMPT").length, 0);
  assert.equal(outcomes(h).length, 0);
  assert.equal(h.sent.length, 0);
  assert.equal(h.timers.size, 0);
});


test("fetch analysis timeout forwards the original request and releases listeners", async () => {
  const h = harness();
  const result = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.expire(RESPONSE_TIMEOUT_MS);
  assert.equal(await result, h.response);
  assert.equal(h.sent.length, 1);
  assert.equal(outcomes(h).length, 1);
  assert.equal(outcomes(h)[0].observation.request_disposition, "ORIGINAL_REQUEST_HANDED_OFF");
  assert.equal(outcomes(h)[0].observation.notice_status, "UNKNOWN");
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});

test("an unreadable XHR Blob is handed to native send unchanged", async () => {
  const h = harness();
  const { xhr, events } = startXhr(h);
  const unreadable = new Blob([body]);
  unreadable.stream = () => new ReadableStream({ start(controller) { controller.error(new Error("body cannot be decoded")); } });
  xhr.send(unreadable);
  await flush();
  assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].body, unreadable);
  assert.deepEqual(events, []);
  assert.equal(outcomes(h).length, 0);
  assert.equal(h.timers.size, 0);
});

test("allowed encoded XHR forwards the original Blob exactly once", async () => {
  const h = harness();
  const { xhr } = startXhr(h);
  const original = new Blob([body]);
  xhr.send(original);
  await flushUntil(() => h.messages.some((message) => message.type === "ANALYZE_PROMPT"));
  h.decide("ALLOW");
  await flush();
  assert.equal(h.sent.length, 1);
  assert.equal(h.sent[0].body, original);
});


function uploadStream(text) {
  const encoded = new TextEncoder().encode(text);
  return new ReadableStream({ start(controller) { controller.enqueue(encoded); controller.close(); } });
}

test("stream uploads are inspected and the intact branch is forwarded with native request options", async () => {
  const h = harness();
  const init = { method: "POST", body: uploadStream(body), duplex: "half", credentials: "include", headers: { "X-Test": "kept" } };
  const result = h.window.fetch(url, init);
  await flush();
  assert.equal(h.messages[0].text, "My private prompt");
  h.decide("ALLOW");
  assert.equal(await result, h.response);
  const forwarded = h.sent[0].args[0];
  assert.equal(forwarded.url, url);
  assert.equal(forwarded.method, "POST");
  assert.equal(forwarded.credentials, "include");
  assert.equal(forwarded.headers.get("X-Test"), "kept");
  assert.equal(await forwarded.text(), body);
});

test("blocked stream uploads never reach native fetch", async () => {
  const h = harness();
  const result = h.window.fetch(url, { method: "POST", body: uploadStream(body), duplex: "half" });
  await flush();
  h.decide("BLOCK");
  await assert.rejects(result, { name: "TypeError" });
  assert.equal(h.sent.length, 0);
});

for (const mode of ["timeout", "abort", "oversize", "unreadable"]) {
  test(`stream inspection ${mode} preserves native handoff except cancellation`, async () => {
    const h = harness();
    const controller = new AbortController();
    let cancelled = false;
    const stream = new ReadableStream({
      start(source) {
        if (mode === "oversize") source.enqueue(new Uint8Array(1_048_577));
        if (mode === "unreadable") source.error(new Error("upload unavailable"));
      },
      cancel() { cancelled = true; },
    });
    const result = h.window.fetch(url, { method: "POST", body: stream, duplex: "half", signal: controller.signal });
    const settled = mode === "abort" ? assert.rejects(result, { name: "AbortError" }) : result;
    await flush();
    if (mode === "timeout") h.expire(5_000);
    if (mode === "abort") controller.abort();
    await settled;
    await flush();
    assert.equal(h.sent.length, mode === "abort" ? 0 : 1);
    assert.equal(h.messages.length, 0);
    assert.equal(h.timers.size, 0);
    if (mode === "abort") assert.equal(cancelled, true);
  });
}

test("consumed Request bodies retain native fetch failure", async () => {
  const h = harness();
  const request = new Request(url, { method: "POST", body });
  await request.text();
  await assert.rejects(h.window.fetch(request), { name: "TypeError" });
  assert.equal(h.sent.length, 0);
});

test("oversized upload inspection preserves every byte on the forwarded stream branch", async () => {
  const h = harness();
  const original = "x".repeat(1_048_577);
  const init = { method: "POST", body: uploadStream(original), duplex: "half", credentials: "include" };
  assert.equal(await h.window.fetch(url, init), h.response);
  assert.equal(h.sent.length, 1);
  const forwarded = h.sent[0].args[0];
  assert.equal(forwarded.credentials, "include");
  assert.equal(await forwarded.text(), original);
  assert.equal(h.messages.length, 0);
});

test("unavailable analysis preserves native fetch rejection without retrying", async () => {
  const nativeError = new Error("native network failure");
  const h = harness(Request, nativeError);
  const request = h.window.fetch(url, { method: "POST", body });
  await flush();
  h.expire(RESPONSE_TIMEOUT_MS);
  await assert.rejects(request, (error) => error === nativeError);
  assert.equal(h.sent.length, 1);
});

test("a null init body still checks the existing Request body", async () => {
  const h = harness();
  const request = new Request(url, { method: "POST", body });
  const result = h.window.fetch(request, { body: null });
  await flush();
  assert.equal(h.messages[0].text, "My private prompt");
  h.decide("BLOCK");
  await assert.rejects(result, { name: "TypeError" });
  assert.equal(h.sent.length, 0);
});

for (const bodyType of ["FormData", "URLSearchParams", "multipart Request"]) {
  test(`${bodyType} preserves structured latest-user prompt extraction`, async () => {
    const h = harness();
    const messages = JSON.stringify([
      { role: "user", content: "My private prompt" },
      { role: "assistant", content: "A longer assistant answer that must never replace the user prompt" },
    ]);
    const fields = bodyType === "URLSearchParams" ? new URLSearchParams() : new FormData();
    fields.set("messages", messages);
    const result = bodyType === "multipart Request"
      ? h.window.fetch(new Request(url, { method: "POST", body: fields }))
      : h.window.fetch(url, { method: "POST", body: fields });
    await flush();
    assert.equal(h.messages[0].text, "My private prompt");
    h.decide("BLOCK");
    await assert.rejects(result, { name: "TypeError" });
    assert.equal(h.sent.length, 0);
  });
}


test("aborting streamed fetch during analysis cancels its unforwarded upload branch", async () => {
  const prepared = [];
  class TrackedRequest extends Request {
    constructor(...args) { super(...args); prepared.push(this); }
  }
  const h = harness(TrackedRequest);
  const controller = new AbortController();
  const result = h.window.fetch(url, { method: "POST", body: uploadStream(body), duplex: "half", signal: controller.signal });
  await flush();
  assert.equal(prepared.length, 1);
  assert.equal(prepared[0].bodyUsed, false);
  controller.abort();
  await assert.rejects(result, { name: "AbortError" });
  assert.equal(prepared[0].bodyUsed, true);
  h.decide("ALLOW");
  assert.equal(h.sent.length, 0);
  assert.equal(h.listeners.size, 0);
  assert.equal(h.timers.size, 0);
});
