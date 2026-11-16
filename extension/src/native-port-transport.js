// The extension's transport to the PriVoke controller: one native-messaging port.
//
// It replaces the gRPC-Web bridge on a loopback HTTP port. The request and response messages are the same protobuf
// messages (`runtime.proto`); this module only carries their bytes, base64-encoded, inside a small JSON envelope:
//
//   request  {"v":1,"id":7,"method":"AnalyzePrompt","payload":"<base64>"}
//   success  {"v":1,"id":7,"ok":true,"payload":"<base64>"}
//   failure  {"v":1,"id":7,"ok":false,"code":"UNAVAILABLE","message":"..."}
//
// Failure policy (fail closed): the only way a request resolves is a well-formed success reply for its id.
// Every other outcome rejects: an error reply, a malformed reply for the id, a disconnect, a caller's abort or
// timeout, a host that cannot be started, a port that cannot be written. Nothing is ever turned into a
// decision, and nothing is retried: a request sent on a port that then closes is rejected, not replayed.
//
// The browser starts the controller when the port connects and ends it when the port closes or the browser
// exits; a request after a disconnect opens a fresh port.

import { connectNative, webExtensionApi } from "./webextension-api.js";

export const NATIVE_HOST = "org.privoke.runtime_controller";
export const PROTOCOL_VERSION = 1;
// A request made without a signal still ends. Callers set their own, shorter, deadlines (30 s for analysis).
export const UNSIGNALLED_TIMEOUT_MS = 60_000;

export class NativeTransportError extends Error {
  constructor(message, { code = "UNAVAILABLE", permanent = false } = {}) {
    super(message);
    this.name = "NativeTransportError";
    this.code = code;
    // True when retrying cannot help, for example the host is not installed.
    this.permanent = permanent;
  }
}

export function toBase64(bytes) {
  let text = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(text);
}

export function fromBase64(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

// What Chromium and Firefox say when the host cannot be used at all.
const PERMANENT_FAILURE = /not found|no such native application|forbidden|invalid native messaging host name/i;

export class NativePortTransport {
  #hostName;
  #connect;
  #lastError;
  #onReconnect;
  #port = null;
  #pending = new Map();
  #nextId = 1;
  #connections = 0;

  // `connect(hostName)` returns a runtime.Port. `lastError(port)` reads why it disconnected: Chromium reports
  // it through runtime.lastError inside the listener, Firefox on port.error.
  constructor({
    hostName = NATIVE_HOST,
    connect = (name) => connectNative(name),
    lastError = (port) => port.error?.message ?? readRuntimeLastError(),
    onReconnect = null,
  } = {}) {
    this.#hostName = hostName;
    this.#connect = connect;
    this.#lastError = lastError;
    this.#onReconnect = onReconnect;
  }

  get connected() {
    return this.#port !== null;
  }

  get pendingCount() {
    return this.#pending.size;
  }

  // Resolves with the response message's bytes.
  request(method, payload, { signal } = {}) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(abortReason(signal));
        return;
      }
      let port;
      try {
        port = this.#ensurePort();
      } catch (error) {
        reject(error);
        return;
      }
      const id = this.#nextId;
      this.#nextId += 1;
      const entry = { resolve, reject, cleanup: () => {} };
      const timer = signal ? null : setTimeout(() => {
        this.#settle(id)?.reject(new NativeTransportError("The PriVoke controller did not answer in time.", { code: "DEADLINE_EXCEEDED" }));
      }, UNSIGNALLED_TIMEOUT_MS);
      const onAbort = () => this.#settle(id)?.reject(abortReason(signal));
      signal?.addEventListener("abort", onAbort, { once: true });
      entry.cleanup = () => {
        if (timer) clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      this.#pending.set(id, entry);
      try {
        port.postMessage({ v: PROTOCOL_VERSION, id, method, payload: toBase64(payload) });
      } catch (error) {
        this.#settle(id)?.reject(new NativeTransportError(`Could not send to the PriVoke controller: ${messageOf(error)}`));
        this.#drop(port);
      }
    });
  }

  close() {
    const port = this.#port;
    if (port) {
      this.#drop(port);
      try {
        port.disconnect();
      } catch {
        // Already gone.
      }
    }
  }

  #ensurePort() {
    if (this.#port) return this.#port;
    let port;
    try {
      port = this.#connect(this.#hostName);
    } catch (error) {
      throw new NativeTransportError(`Could not reach the PriVoke controller: ${messageOf(error)}`);
    }
    if (!port) throw new NativeTransportError("Could not reach the PriVoke controller.");
    port.onMessage.addListener((message) => this.#onMessage(port, message));
    port.onDisconnect.addListener(() => this.#onDisconnect(port));
    this.#port = port;
    this.#connections += 1;
    if (this.#connections > 1 && this.#onReconnect) {
      // The controller lost its state with its process. Let the owner restore it, without waiting here.
      queueMicrotask(() => {
        try {
          this.#onReconnect();
        } catch {
          // The owner reports its own failures.
        }
      });
    }
    return port;
  }

  #settle(id) {
    const entry = this.#pending.get(id);
    if (!entry) return null;
    this.#pending.delete(id);
    entry.cleanup();
    return entry;
  }

  #drop(port) {
    if (this.#port === port) this.#port = null;
  }

  #onMessage(port, message) {
    if (port !== this.#port) return;
    if (!message || typeof message !== "object" || !Number.isSafeInteger(message.id)) return;
    const entry = this.#settle(message.id);
    // A reply for a request that was aborted or timed out is dropped.
    if (!entry) return;
    if (message.v !== PROTOCOL_VERSION) {
      entry.reject(new NativeTransportError(`The PriVoke controller answered with protocol version ${message.v}.`, { code: "INTERNAL" }));
      return;
    }
    if (message.ok === true) {
      if (typeof message.payload !== "string") {
        entry.reject(new NativeTransportError("The PriVoke controller sent a reply without a payload.", { code: "INTERNAL" }));
        return;
      }
      try {
        entry.resolve(fromBase64(message.payload));
      } catch {
        entry.reject(new NativeTransportError("The PriVoke controller sent a payload that is not base64.", { code: "INTERNAL" }));
      }
      return;
    }
    entry.reject(new NativeTransportError(
      typeof message.message === "string" && message.message ? message.message : `PriVoke controller error ${message.code ?? ""}`.trim(),
      { code: typeof message.code === "string" ? message.code : "UNKNOWN" },
    ));
  }

  #onDisconnect(port) {
    let reason;
    try {
      reason = this.#lastError(port);
    } catch {
      reason = undefined;
    }
    this.#drop(port);
    const detail = reason ? `: ${reason}` : "";
    const permanent = Boolean(reason) && PERMANENT_FAILURE.test(reason);
    for (const id of [...this.#pending.keys()]) {
      this.#settle(id)?.reject(new NativeTransportError(`The PriVoke controller disconnected${detail}`, { permanent }));
    }
  }
}

function abortReason(signal) {
  return signal.reason ?? new DOMException("The operation was aborted.", "AbortError");
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error);
}

function readRuntimeLastError() {
  try {
    return webExtensionApi().runtime.lastError?.message;
  } catch {
    return undefined;
  }
}
