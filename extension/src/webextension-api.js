export function webExtensionApi(root = globalThis) {
  const api = root.browser ?? root.chrome;
  if (!api?.runtime) {
    throw new Error("WebExtensions runtime API is unavailable.");
  }
  return api;
}

export function addRuntimeMessageListener(handler, root = globalThis) {
  const api = webExtensionApi(root);
  if (root.browser) {
    api.runtime.onMessage.addListener((message, sender) => handler(message, sender));
    return;
  }

  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    Promise.resolve(handler(message, sender)).then(
      sendResponse,
      (error) => sendResponse({ ok: false, error: errorMessage(error) }),
    );
    return true;
  });
}

export function addRuntimeLifecycleListeners(handler, root = globalThis) {
  const runtime = webExtensionApi(root).runtime;
  runtime.onStartup?.addListener(handler);
  runtime.onInstalled?.addListener(handler);
}

export function sendRuntimeMessage(message, root = globalThis) {
  const api = webExtensionApi(root);
  if (root.browser) return api.runtime.sendMessage(message);
  return callbackResult(api.runtime, (callback) => api.runtime.sendMessage(message, callback));
}

export function sendNativeMessage(hostName, message, root = globalThis) {
  const api = webExtensionApi(root);
  if (root.browser) return api.runtime.sendNativeMessage(hostName, message);
  return callbackResult(
    api.runtime,
    (callback) => api.runtime.sendNativeMessage(hostName, message, callback),
  );
}

export function localStorageArea(root = globalThis) {
  const storage = webExtensionApi(root).storage?.local;
  if (!storage) throw new Error("WebExtensions local storage API is unavailable.");
  return storage;
}

export function storageGet(storage, key, root = globalThis) {
  if (root.browser || storage !== root.chrome?.storage?.local) return storage.get(key);
  return callbackResult(root.chrome.runtime, (callback) => storage.get(key, callback));
}

export function storageSet(storage, values, root = globalThis) {
  if (root.browser || storage !== root.chrome?.storage?.local) return storage.set(values);
  return callbackResult(root.chrome.runtime, (callback) => storage.set(values, callback));
}

function callbackResult(runtime, invoke) {
  return new Promise((resolve, reject) => {
    invoke((result) => {
      const runtimeError = runtime.lastError;
      if (runtimeError) {
        reject(new Error(runtimeError.message));
        return;
      }
      resolve(result);
    });
  });
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
