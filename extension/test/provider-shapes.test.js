// Provider request-shape compatibility through the real page-interceptor source.
// Bodies are synthetic fixtures (fixtures/provider-shapes.json), never captured
// from a provider. The analysis decision is injected, so this test establishes
// prompt extraction and the hook's enforcement of each shape, not detector output.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { extractPrompt, promptTarget } from "../src/prompt-interception.js";
import { RESPONSE_TIMEOUT_MS } from "../src/analysis-timeouts.js";
import { runtimeFailureResponse } from "../src/interception-failure.js";
import { maskText, rewritePromptBody } from "../src/redaction.js";
import { FIXTURE, buildBody } from "./fixtures/provider-shapes.mjs";

const source = (await readFile(new URL("../src/page-interceptor.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/gm, "");
const flush = () => new Promise((resolve) => setImmediate(resolve));
// Blob and stream bodies resolve on later turns than plain strings.
async function settle(h) {
  for (let attempt = 0; attempt < 200 && h.analyses().length === 0; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}
const PROMPT = "Contact alex@example.com about the draft.";
const SUPPORTED_HOSTS = new Set(["chatgpt.com", "chat.openai.com", "claude.ai",
  "gemini.google.com", "copilot.microsoft.com", "api.openai.com"]);

function harness(pageUrl) {
  const messages = [];
  const listeners = new Set();
  const sent = [];
  const response = new Response("synthetic reply");
  class Xhr extends EventTarget {
    static UNSENT = 0;
    static OPENED = 1;
    static DONE = 4;
    state = 0;
    status = 0;
    timeout = 0;
    get readyState() { return this.state; }
    open() { this.state = 1; }
    send(value) { sent.push({ xhr: this, body: value }); }
    abort() { if (this.state !== 1) this.state = 0; }
    dispatchEvent(event) { super.dispatchEvent(event); this[`on${event.type}`]?.(event); return true; }
  }
  const window = {
    fetch(...args) { sent.push({ args }); return Promise.resolve(response); },
    addEventListener(type, listener) { if (type === "message") listeners.add(listener); },
    removeEventListener(type, listener) { listeners.delete(listener); },
    postMessage(data) { messages.push(data); },
  };
  vm.runInNewContext(source, {
    RESPONSE_TIMEOUT_MS, runtimeFailureResponse, window, location: { href: pageUrl }, XMLHttpRequest: Xhr,
    Request, Response, URL, URLSearchParams, FormData, Blob, ReadableStream,
    Uint8Array, ArrayBuffer, TextEncoder, TextDecoder, DOMException, AbortController,
    Event, ProgressEvent: Event, TypeError, crypto, extractPrompt, promptTarget, maskText, rewritePromptBody,
    setTimeout() { return Symbol(); }, clearTimeout() {},
  });
  const analyses = () => messages.filter((message) => message.type === "ANALYZE_PROMPT");
  function decide(action) {
    const { requestId } = analyses().at(-1);
    for (const listener of [...listeners]) listener({
      source: window,
      data: {
        channel: "privoke-extension-v1", type: "ANALYZE_RESULT", requestId, action,
        observation: { schema_version: 1, notice_status: action === "ALLOW" ? "NOT_REQUESTED" : "RENDERED" },
      },
    });
  }
  return { window, Xhr, response, sent, messages, analyses, decide };
}

const asString = (text) => text;
const asBlob = (text) => new Blob([text]);
const asBytes = (text) => new TextEncoder().encode(text);
const asBuffer = (text) => asBytes(text).buffer;
const BODY_KINDS = { string: asString, blob: asBlob, uint8array: asBytes, arraybuffer: asBuffer };

test("fixture file is synthetic, covers every supported host, and records its provenance", () => {
  assert.match(FIXTURE.provenance, /Synthetic/);
  assert.match(FIXTURE.provenance, /None was captured/);
  const hosts = new Set(FIXTURE.shapes.map((shape) => new URL(shape.url).hostname));
  assert.deepEqual([...hosts].sort(), [...SUPPORTED_HOSTS].sort());
  const targets = new Set(FIXTURE.shapes.map((shape) => shape.targetApp));
  assert.deepEqual([...targets].sort(), ["chatgpt", "claude", "copilot", "gemini", "openai_api"]);
  for (const shape of FIXTURE.shapes) {
    assert.equal(JSON.stringify(shape).includes("{{PROMPT}}"), true, `${shape.id} carries the placeholder`);
    assert.equal(promptTarget(shape.url, "POST"), shape.targetApp, `${shape.id} target`);
    assert.equal(promptTarget(shape.url, "GET"), null, `${shape.id} GET is not a prompt`);
  }
});

for (const shape of FIXTURE.shapes) {
  const { text, contentType } = buildBody(shape, PROMPT);
  const kinds = shape.encoding === "form" ? { string: asString } : BODY_KINDS;

  test(`${shape.id}: extractor recovers the exact prompt for the declared target`, () => {
    assert.equal(extractPrompt(text, shape.targetApp), PROMPT);
    assert.ok(contentType.length > 0);
  });

  for (const [kind, convert] of Object.entries(kinds)) {
    for (const action of ["ALLOW", "WARN", "BLOCK"]) {
      test(`${shape.id}: fetch ${kind} body is analysed and ${action} is enforced`, async () => {
        const h = harness(new URL(shape.url).origin + "/");
        const init = { method: "POST", headers: { "content-type": contentType }, body: convert(text) };
        const request = h.window.fetch(shape.url, init);
        await settle(h);
        assert.equal(h.analyses().length, 1, "exactly one analysis request");
        assert.equal(h.analyses()[0].text, PROMPT);
        assert.equal(h.analyses()[0].targetApp, shape.targetApp);
        assert.equal(h.sent.length, 0, "nothing is sent before the decision");
        h.decide(action);
        if (action === "BLOCK") {
          await assert.rejects(request, { name: "TypeError", message: "Prompt blocked by PriVoke." });
          assert.equal(h.sent.length, 0);
        } else {
          assert.equal(await request, h.response);
          assert.equal(h.sent.length, 1);
          assert.equal(h.sent[0].args[0], shape.url);
          assert.equal(h.sent[0].args[1].body, init.body, "original body object is forwarded unchanged");
        }
      });
    }
  }

  for (const action of ["ALLOW", "WARN", "BLOCK"]) {
    test(`${shape.id}: asynchronous XHR is analysed and ${action} is enforced`, async () => {
      const h = harness(new URL(shape.url).origin + "/");
      const xhr = new h.Xhr();
      const events = [];
      for (const type of ["error", "loadend"]) xhr.addEventListener(type, () => events.push(type));
      xhr.open("POST", shape.url);
      xhr.send(text);
      await flush();
      assert.equal(h.analyses().length, 1);
      assert.equal(h.analyses()[0].text, PROMPT);
      assert.equal(h.analyses()[0].targetApp, shape.targetApp);
      assert.equal(h.sent.length, 0);
      h.decide(action);
      await flush();
      if (action === "BLOCK") {
        assert.equal(h.sent.length, 0);
        assert.equal(xhr.readyState, 4);
        assert.equal(xhr.status, 0);
        assert.deepEqual(events, ["error", "loadend"]);
      } else {
        assert.equal(h.sent.length, 1);
        assert.equal(h.sent[0].body, text);
      }
    });
  }

  test(`${shape.id}: Request-object input is analysed and BLOCK sends nothing`, async () => {
    const h = harness(new URL(shape.url).origin + "/");
    const request = h.window.fetch(new Request(shape.url, {
      method: "POST", headers: { "content-type": contentType }, body: text,
    }));
    await settle(h);
    assert.equal(h.analyses().at(-1).text, PROMPT);
    h.decide("BLOCK");
    await assert.rejects(request, { name: "TypeError" });
    assert.equal(h.sent.length, 0);
  });
}

for (const control of FIXTURE.negativeControls) {
  test(`negative control ${control.id}: no analysis and the request passes through untouched`, async () => {
    const { text } = buildBody(control, PROMPT);
    const h = harness("https://chatgpt.com/");
    const init = { method: "POST", body: text };
    assert.equal(await h.window.fetch(control.url, init), h.response);
    assert.equal(h.analyses().length, 0);
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].args[1], init);
  });
}

test("a non-POST request to a supported endpoint is not analysed", async () => {
  const h = harness("https://chatgpt.com/");
  assert.equal(await h.window.fetch("https://chatgpt.com/backend-api/conversation"), h.response);
  assert.equal(h.analyses().length, 0);
});
