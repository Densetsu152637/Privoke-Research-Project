import assert from "node:assert/strict";
import test from "node:test";

import {
  addRuntimeLifecycleListeners,
  addRuntimeMessageListener,
  sendNativeMessage,
  sendRuntimeMessage,
  storageGet,
  storageSet,
  webExtensionApi,
} from "../src/webextension-api.js";

test("registers background restoration for browser startup and installation", () => {
  const listeners = [];
  const handler = () => {};
  const runtime = {
    onStartup: { addListener(listener) { listeners.push(["startup", listener]); } },
    onInstalled: { addListener(listener) { listeners.push(["installed", listener]); } },
  };

  addRuntimeLifecycleListeners(handler, { chrome: { runtime } });

  assert.deepEqual(listeners, [["startup", handler], ["installed", handler]]);
});

test("prefers the standard browser namespace", () => {
  const browser = { runtime: {} };
  const chrome = { runtime: {} };
  assert.equal(webExtensionApi({ browser, chrome }), browser);
});

test("uses promise messaging through the browser namespace", async () => {
  const root = {
    browser: {
      runtime: {
        sendMessage: async (message) => ({ echoed: message }),
        sendNativeMessage: async (host, message) => ({ host, message }),
      },
    },
  };

  assert.deepEqual(await sendRuntimeMessage({ value: 1 }, root), { echoed: { value: 1 } });
  assert.deepEqual(await sendNativeMessage("test.host", { value: 2 }, root), {
    host: "test.host",
    message: { value: 2 },
  });
});

test("adapts callback messaging through the chrome-compatible namespace", async () => {
  const runtime = {
    lastError: null,
    sendMessage(message, callback) {
      callback({ echoed: message });
    },
    sendNativeMessage(host, message, callback) {
      callback({ host, message });
    },
  };
  const root = { chrome: { runtime } };

  assert.deepEqual(await sendRuntimeMessage({ value: 1 }, root), { echoed: { value: 1 } });
  assert.deepEqual(await sendNativeMessage("test.host", { value: 2 }, root), {
    host: "test.host",
    message: { value: 2 },
  });
});

for (const namespace of ["browser", "chrome", "both"]) {
  test(`keeps asynchronous callback replies open with ${namespace} namespace`, async () => {
    let listener;
    const runtime = { onMessage: { addListener(value) { listener = value; } } };
    const root = namespace === "both"
      ? { browser: { runtime }, chrome: { runtime } }
      : { [namespace]: { runtime } };
    addRuntimeMessageListener(async (message) => ({ value: message.value + 1 }), root);

    const responses = [];
    // Callback-only hosts ignore returned promises and close the port unless
    // the listener returns the literal boolean true.
    assert.equal(listener({ value: 1 }, {}, (value) => responses.push(value)), true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(responses, [{ value: 2 }]);
  });
}

for (const synchronous of [false, true]) {
  test(`normalizes ${synchronous ? "thrown" : "rejected"} background handler errors`, async () => {
    let listener;
    const runtime = { onMessage: { addListener(value) { listener = value; } } };
    const handler = synchronous
      ? () => { throw new Error("Analysis unavailable"); }
      : async () => { throw new Error("Analysis unavailable"); };
    addRuntimeMessageListener(handler, { browser: { runtime }, chrome: { runtime } });
    const responses = [];
    assert.equal(listener({}, {}, (value) => responses.push(value)), true);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(responses, [{ ok: false, error: "Analysis unavailable" }]);
  });
}

test("uses injected promise storage without a browser global", async () => {
  const values = {};
  const storage = {
    async get(key) { return { [key]: values[key] }; },
    async set(update) { Object.assign(values, update); },
  };

  await storageSet(storage, { setting: true }, {});
  assert.deepEqual(await storageGet(storage, "setting", {}), { setting: true });
});
