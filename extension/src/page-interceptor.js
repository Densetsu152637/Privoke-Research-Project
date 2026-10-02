import { extractPrompt, promptTarget } from "./prompt-interception.js";
import { runtimeFailureResponse } from "./interception-failure.js";

const CHANNEL = "privoke-extension-v1";
const RESPONSE_TIMEOUT_MS = 32_000;
const nativeFetch = window.fetch;

window.fetch = async function privokeFetch(input, init) {
  const method = init?.method ?? (input instanceof Request ? input.method : "GET");
  const rawUrl = input instanceof Request ? input.url : String(input);
  const targetApp = promptTarget(rawUrl, method, location.href);
  if (!targetApp) return nativeFetch.apply(this, arguments);
  const signal = init?.signal !== undefined
    ? init.signal
    : (input instanceof Request ? input.signal : undefined);
  signal?.throwIfAborted();

  const body = await requestBody(input, init);
  const text = extractPrompt(body);
  if (!text) return nativeFetch.apply(this, arguments);

  const decision = await analyze(text, targetApp, signal);
  if (decision?.action === "BLOCK") {
    // Sites often suppress AbortError as an intentional user cancellation.
    throw new TypeError("Prompt blocked by PriVoke.");
  }
  return nativeFetch.apply(this, arguments);
};

installXhrInterceptor();

async function requestBody(input, init) {
  if (init && Object.hasOwn(init, "body")) {
    return init.body instanceof Blob ? init.body.text() : init.body;
  }
  if (input instanceof Request) {
    try {
      return await input.clone().text();
    } catch {
      return null;
    }
  }
  return null;
}

function analyze(text, targetApp, signal) {
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timeout = setTimeout(() => finish(runtimeFailureResponse()), RESPONSE_TIMEOUT_MS);

    function onMessage(event) {
      const data = event.data;
      if (
        event.source === window
        && data?.channel === CHANNEL
        && data?.type === "ANALYZE_RESULT"
        && data.requestId === requestId
      ) finish(data);
    }

    function onAbort() {
      finish(null, signal.reason);
    }

    function finish(value, error) {
      clearTimeout(timeout);
      window.removeEventListener("message", onMessage);
      signal?.removeEventListener("abort", onAbort);
      if (error !== undefined) reject(error);
      else resolve(value);
    }

    window.addEventListener("message", onMessage);
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      window.postMessage({
        channel: CHANNEL,
        type: "ANALYZE_PROMPT",
        requestId,
        text,
        targetApp,
      }, "*");
    } catch {
      finish(runtimeFailureResponse());
    }
  });
}

function installXhrInterceptor() {
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  const abort = XMLHttpRequest.prototype.abort;
  const requests = new WeakMap();

  XMLHttpRequest.prototype.open = function privokeOpen(method, url) {
    const previous = requests.get(this);
    if (previous) {
      clearTimeout(previous.timeout);
      previous.controller?.abort();
      if (previous.failed) delete this.readyState;
    }
    requests.set(this, {
      method,
      url: String(url),
      targetApp: promptTarget(String(url), method, location.href),
      cancelled: false,
      synchronous: arguments[2] === false,
    });
    return open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.abort = function privokeAbort() {
    const request = requests.get(this);
    if (request?.pending) {
      finishPending(this, request, "abort");
      if (requests.get(this) === request) {
        abort.apply(this, arguments);
        Object.defineProperty(this, "readyState", { configurable: true, value: XMLHttpRequest.UNSENT });
      }
      return;
    }
    if (request) {
      request.cancelled = true;
      if (request.failed) {
        abort.apply(this, arguments);
        Object.defineProperty(this, "readyState", { configurable: true, value: XMLHttpRequest.UNSENT });
        return;
      }
    }
    return abort.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function privokeSend(body) {
    const xhr = this;
    const request = requests.get(xhr);
    const blob = body instanceof Blob;
    const text = request?.targetApp ? extractPrompt(body) : "";
    if (!request?.targetApp || (!text && !blob)) return send.apply(xhr, arguments);
    if (request.synchronous) {
      throw new DOMException("PriVoke cannot check a synchronous prompt request.", "NetworkError");
    }
    if (request.pending || xhr.readyState !== XMLHttpRequest.OPENED) {
      throw new DOMException("The request is already sent or is not open.", "InvalidStateError");
    }
    request.pending = true;
    request.controller = new AbortController();
    if (xhr.timeout > 0) {
      request.timeout = setTimeout(() => finishPending(xhr, request, "timeout"), xhr.timeout);
    }

    const decision = blob
      ? body.text().then((raw) => {
        if (request.cancelled || requests.get(xhr) !== request) return null;
        const decodedText = extractPrompt(raw);
        return decodedText ? analyze(decodedText, request.targetApp, request.controller.signal) : null;
      })
      : analyze(text, request.targetApp, request.controller.signal);
    void decision.then((decision) => {
      if (request.cancelled || requests.get(xhr) !== request) return;
      if (decision?.action === "BLOCK") {
        finishPending(xhr, request, "error");
        return;
      }
      request.pending = false;
      clearTimeout(request.timeout);
      try {
        send.call(xhr, body);
      } catch {
        // An asynchronous native send failure must also settle the caller.
        request.pending = true;
        finishPending(xhr, request, "error");
      }
    }, () => {
      // Cancellation already emitted its terminal events; unreadable bodies
      // must settle as a failure instead of bypassing prompt protection.
      if (!request.cancelled && requests.get(xhr) === request) finishPending(xhr, request, "error");
    });
    return undefined;
  };

  function finishPending(xhr, request, type) {
    if (!request.pending || requests.get(xhr) !== request) return;
    request.pending = false;
    request.cancelled = true;
    clearTimeout(request.timeout);
    request.controller.abort();
    // Native abort() emits nothing before send(). Expose a network failure's
    // DONE state and terminal events so XHR clients can clear their loading UI.
    request.failed = true;
    Object.defineProperty(xhr, "readyState", { configurable: true, value: XMLHttpRequest.DONE });
    xhr.dispatchEvent(new Event("readystatechange"));
    xhr.dispatchEvent(new ProgressEvent(type));
    xhr.dispatchEvent(new ProgressEvent("loadend"));
  }
}
