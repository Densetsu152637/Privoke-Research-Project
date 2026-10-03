import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = (await readFile(new URL("../src/content-script.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/, "");
const flush = () => new Promise((resolve) => setImmediate(resolve));

function relay(sendRuntimeMessage) {
  let listener;
  const results = [];
  const window = {
    addEventListener(type, handler) { if (type === "message") listener = handler; },
    postMessage(data) { results.push(data); },
  };
  vm.runInNewContext(source, {
    window, sendRuntimeMessage,
    document: { getElementById() { throw new Error("notice rendering failed"); } },
  });
  listener({ source: window, data: {
    channel: "privoke-extension-v1", type: "ANALYZE_PROMPT",
    requestId: "request-1", text: "My private prompt", targetApp: "chatgpt",
  } });
  return results;
}

for (const action of ["BLOCK", "WARN"]) {
  test(`notice rendering errors preserve ${action} and deliver one decision`, async () => {
    const results = relay(async () => ({ ok: true, response: { action } }));
    await flush();
    assert.equal(results.length, 1);
    assert.equal(results[0].action, action);
    assert.equal(results[0].requestId, "request-1");
  });
}

for (const mode of ["sync", "async", "response"]) {
  test(`${mode} runtime failure still returns the existing fail-open decision`, async () => {
    const results = relay(() => {
      if (mode === "sync") throw new Error("extension context invalidated");
      if (mode === "async") return Promise.reject(new Error("runtime unavailable"));
      return Promise.resolve({ ok: false, error: "runtime unavailable" });
    });
    await flush();
    assert.equal(results.length, 1);
    assert.equal(results[0].action, "ALLOW");
  });
}
