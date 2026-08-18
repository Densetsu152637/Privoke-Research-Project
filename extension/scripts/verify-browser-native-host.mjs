import { readFile } from "node:fs/promises";

const debugPort = argument("debug-port", "9333");
const identities = JSON.parse(
  await readFile(new URL("../extension-identities.json", import.meta.url)),
);
const workerUrl = `chrome-extension://${identities.chromium_extension_id}/background.js`;
const targets = await fetch(`http://127.0.0.1:${debugPort}/json/list`).then((response) => {
  if (!response.ok) throw new Error(`Browser debugger returned HTTP ${response.status}.`);
  return response.json();
});
let extensionTarget = targets.find((target) => target.url === workerUrl);
if (!extensionTarget?.webSocketDebuggerUrl) {
  const popupUrl = `chrome-extension://${identities.chromium_extension_id}/popup.html`;
  extensionTarget = await fetch(
    `http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(popupUrl)}`,
    { method: "PUT" },
  ).then((response) => {
    if (!response.ok) throw new Error(`Could not open the PriVoke extension page.`);
    return response.json();
  });
}

const browserContext = await evaluate(
  extensionTarget.webSocketDebuggerUrl,
  `({
    browserNamespace: typeof globalThis.browser,
    browserRuntime: typeof globalThis.browser?.runtime,
    browserOnMessage: typeof globalThis.browser?.runtime?.onMessage?.addListener,
    browserStorage: typeof globalThis.browser?.storage?.local,
    chromeNamespace: typeof globalThis.chrome,
    chromeOnMessage: typeof globalThis.chrome?.runtime?.onMessage?.addListener,
    contextUrl: globalThis.location?.href || "service-worker",
    manifestBackground: chrome.runtime.getManifest().background,
  })`,
);
console.error(`Browser context: ${JSON.stringify(browserContext)}`);

const expression = `new Promise((resolve) => {
  chrome.runtime.sendNativeMessage(
    "org.privoke.runtime_launcher",
    { action: "ensure_supervisor" },
    (response) => resolve({
      response,
      error: chrome.runtime.lastError?.message || null,
    }),
  );
})`;
const result = await evaluate(extensionTarget.webSocketDebuggerUrl, expression);
if (result.error) throw new Error(result.error);
if (!result.response?.ok) {
  throw new Error(result.response?.message || "Native launcher returned an error.");
}

const popupUrl = `chrome-extension://${identities.chromium_extension_id}/popup.html`;
let messageTarget = targets.find((target) => target.url === popupUrl);
if (!messageTarget?.webSocketDebuggerUrl) {
  messageTarget = await fetch(
    `http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(popupUrl)}`,
    { method: "PUT" },
  ).then((response) => response.json());
}
await delay(500);

const enabled = await sendExtensionMessageWithRetry(messageTarget.webSocketDebuggerUrl, {
  type: "SET_MASTER_ENABLED",
  enabled: true,
});
if (enabled.error) throw new Error(enabled.error);
if (!enabled.response?.ok || !enabled.response?.runtime?.enabled) {
  throw new Error(enabled.response?.error || "The detector runtime did not start.");
}

const disabled = await sendExtensionMessageWithRetry(messageTarget.webSocketDebuggerUrl, {
  type: "SET_MASTER_ENABLED",
  enabled: false,
});
if (disabled.error) throw new Error(disabled.error);
if (!disabled.response?.ok || disabled.response?.runtime?.enabled) {
  throw new Error(disabled.response?.error || "The detector runtime did not stop.");
}

console.log(JSON.stringify({
  extensionContext: extensionTarget.url,
  messageContext: messageTarget.url,
  browserContext,
  nativeHost: result.response,
  detectorStarted: enabled.response.runtime,
  detectorStopped: disabled.response.runtime,
}));

function argument(name, fallback) {
  const prefix = `--${name}=`;
  return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length) || fallback;
}

function evaluate(webSocketUrl, source) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(webSocketUrl);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error("Browser debugger evaluation timed out."));
    }, 30_000);

    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({
        id: 1,
        method: "Runtime.evaluate",
        params: {
          expression: source,
          awaitPromise: true,
          returnByValue: true,
        },
      }));
    });
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== 1) return;
      clearTimeout(timer);
      socket.close();
      if (message.error) {
        reject(new Error(message.error.message));
        return;
      }
      if (message.result?.exceptionDetails) {
        reject(new Error(message.result.exceptionDetails.text));
        return;
      }
      resolve(message.result?.result?.value);
    });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("Could not connect to the browser debugger."));
    });
  });
}

function sendExtensionMessage(webSocketUrl, message) {
  const source = `new Promise((resolve) => {
    chrome.runtime.sendMessage(
      ${JSON.stringify(message)},
      (response) => resolve({
        response,
        error: chrome.runtime.lastError?.message || null,
      }),
    );
  })`;
  return evaluate(webSocketUrl, source);
}

async function sendExtensionMessageWithRetry(webSocketUrl, message) {
  let result;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    result = await sendExtensionMessage(webSocketUrl, message);
    if (!result.error?.includes("Receiving end does not exist")) return result;
    await delay(200);
  }
  return result;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
