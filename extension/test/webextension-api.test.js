import assert from "node:assert/strict";
import test from "node:test";

import {
  addRuntimeMessageListener,
  sendNativeMessage,
  sendRuntimeMessage,
  storageGet,
  storageSet,
  webExtensionApi,
} from "../src/webextension-api.js";

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

test("adapts asynchronous listeners for both namespace styles", async () => {
  let browserListener;
  addRuntimeMessageListener(async (message) => ({ value: message.value + 1 }), {
    browser: { runtime: { onMessage: { addListener(listener) { browserListener = listener; } } } },
  });
  assert.deepEqual(await browserListener({ value: 1 }, {}), { value: 2 });

  let chromeListener;
  addRuntimeMessageListener(async (message) => ({ value: message.value + 1 }), {
    chrome: { runtime: { onMessage: { addListener(listener) { chromeListener = listener; } } } },
  });
  const response = await new Promise((resolve) => {
    assert.equal(chromeListener({ value: 2 }, {}, resolve), true);
  });
  assert.deepEqual(response, { value: 3 });
});

test("uses injected promise storage without a browser global", async () => {
  const values = {};
  const storage = {
    async get(key) { return { [key]: values[key] }; },
    async set(update) { Object.assign(values, update); },
  };

  await storageSet(storage, { setting: true }, {});
  assert.deepEqual(await storageGet(storage, "setting", {}), { setting: true });
});
