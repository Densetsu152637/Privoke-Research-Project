import { extractPrompt, promptTarget } from "./prompt-interception.js";
import { runtimeFailureResponse } from "./interception-failure.js";

const CHANNEL = "privoke-extension-v1";
const RESPONSE_TIMEOUT_MS = 32_000;
const BODY_READ_TIMEOUT_MS = 5_000;
const MAX_BODY_BYTES = 1_048_576;
const NOTICE_STATUSES = new Set(["NOT_REQUESTED", "RENDERED", "FAILED", "UNKNOWN"]);
const REQUEST_DISPOSITIONS = new Set([
  "BLOCKED_LOCALLY", "ORIGINAL_REQUEST_HANDED_OFF", "UNKNOWN",
]);
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

  const { body, request } = await requestBody(input, init, signal);
  let forwarded = false;
  let decision;
  let outcomeEmitted = false;
  let requestId;
  const reportOutcome = (disposition) => {
    if (!requestId || outcomeEmitted) return;
    outcomeEmitted = true;
    emitOutcome(requestId, decision?.action ?? null, decision?.observation, disposition);
  };
  try {
    const text = extractPrompt(body);
    if (text) requestId = crypto.randomUUID();
    const forward = () => {
      forwarded = true;
      try {
        const result = request ? nativeFetch.call(this, request) : nativeFetch.apply(this, arguments);
        reportOutcome("ORIGINAL_REQUEST_HANDED_OFF");
        return result;
      } catch (error) {
        reportOutcome("UNKNOWN");
        throw error;
      }
    };
    if (!text) return forward();

    decision = await analyze(text, targetApp, signal, requestId);
    if (decision?.action === "BLOCK") {
      reportOutcome("BLOCKED_LOCALLY");
      // Sites often suppress AbortError as an intentional user cancellation.
      throw new TypeError("Prompt blocked by PriVoke.");
    }
    return forward();
  } catch (error) {
    reportOutcome("UNKNOWN");
    if (!forwarded && request?.body) void request.body.cancel().catch(() => {});
    throw error;
  }
};

installXhrInterceptor();

async function requestBody(input, init, signal) {
  if (init?.body != null) {
    if (init.body instanceof ReadableStream) {
      // Cloning tees the upload. Forward the prepared Request's untouched
      // branch so checking never drains the bytes native fetch will send.
      const request = new Request(input, init);
      try {
        return { body: await readRequestBody(request, signal), request };
      } catch (error) {
        if (request.body) void request.body.cancel().catch(() => {});
        throw error;
      }
    }
    return { body: await inspectBody(init.body, signal) };
  }
  if (input instanceof Request) {
    return { body: await readRequestBody(input, signal) };
  }
  return { body: null };
}

async function readRequestBody(request, signal) {
  const clone = request.clone();
  if (!clone.body) return null;
  const bytes = await readBodyStream(clone.body, signal);
  if (clone.headers.get("content-type")?.toLowerCase().startsWith("multipart/form-data")) {
    return new Response(bytes, { headers: clone.headers }).formData();
  }
  return new TextDecoder().decode(bytes);
}

async function inspectBody(body, signal) {
  signal?.throwIfAborted();
  if (body instanceof Blob) {
    if (body.size > MAX_BODY_BYTES) throw new TypeError("PriVoke prompt body exceeds the inspection limit.");
    return new TextDecoder().decode(await readBodyStream(body.stream(), signal));
  }
  const size = body instanceof ArrayBuffer || ArrayBuffer.isView(body)
    ? body.byteLength
    : typeof body === "string" || body instanceof URLSearchParams
      ? new TextEncoder().encode(String(body)).byteLength
      : 0;
  if (size > MAX_BODY_BYTES) throw new TypeError("PriVoke prompt body exceeds the inspection limit.");
  return body;
}

async function readBodyStream(stream, signal) {
  signal?.throwIfAborted();
  const reader = stream.getReader();
  let rejectStopped;
  const stopped = new Promise((resolve, reject) => { rejectStopped = reject; });
  const stop = (error) => {
    rejectStopped(error);
    // Cancellation of a tee can wait for its other branch. Never await it.
    void reader.cancel(error).catch(() => {});
  };
  const onAbort = () => stop(signal.reason);
  const timeout = setTimeout(
    () => stop(new TypeError("PriVoke prompt body inspection timed out.")),
    BODY_READ_TIMEOUT_MS,
  );
  signal?.addEventListener("abort", onAbort, { once: true });
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), stopped]);
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new TypeError("PriVoke cannot inspect this upload stream.");
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) throw new TypeError("PriVoke prompt body exceeds the inspection limit.");
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } catch (error) {
    void reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
}

function analyze(text, targetApp, signal, requestId) {
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
      ) {
        const validAction = typeof data.action === "string"
          && ["ALLOW", "WARN", "BLOCK"].includes(data.action.toUpperCase());
        const action = validAction ? data.action.toUpperCase() : "BLOCK";
        const observation = validAction
          ? normalizeObservation(data.observation)
          : { schema_version: 1, notice_status: "UNKNOWN" };
        finish({ action, observation });
      }
    }

    function onAbort() {
      finish(null, signal.reason);
    }

    function finish(value, error) {
      clearTimeout(timeout);
      window.removeEventListener("message", onMessage);
      signal?.removeEventListener("abort", onAbort);
      if (error !== undefined) reject(error);
      else resolve({
        ...(value ?? runtimeFailureResponse()),
        requestId,
        observation: normalizeObservation(value?.observation),
      });
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

function normalizeObservation(value) {
  const noticeStatus = value?.schema_version === 1 && NOTICE_STATUSES.has(value.notice_status)
    ? value.notice_status
    : "UNKNOWN";
  return { schema_version: 1, notice_status: noticeStatus };
}

function emitOutcome(requestId, action, observation, requestDisposition) {
  if (!REQUEST_DISPOSITIONS.has(requestDisposition)) requestDisposition = "UNKNOWN";
  const normalizedAction = ["ALLOW", "WARN", "BLOCK"].includes(action) ? action : null;
  try {
    window.postMessage({
      channel: CHANNEL,
      type: "ANALYZE_OUTCOME",
      requestId,
      ...(normalizedAction ? { action: normalizedAction } : {}),
      observation: {
        ...normalizeObservation(observation),
        request_disposition: requestDisposition,
      },
    }, "*");
  } catch {
    // Observation delivery must never change the intercepted request outcome.
  }
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
      reportXhrOutcome(previous, null, null, "UNKNOWN");
      previous.controller?.abort();
      if (previous.failed) delete this.readyState;
    }
    requests.set(this, {
      method,
      url: String(url),
      targetApp: promptTarget(String(url), method, location.href),
      cancelled: false,
      synchronous: arguments[2] === false,
      outcomeEmitted: false,
    });
    return open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.abort = function privokeAbort() {
    const request = requests.get(this);
    if (request?.pending) {
      reportXhrOutcome(request, null, null, "UNKNOWN");
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

    let decision;
    if (blob) {
      decision = inspectBody(body, request.controller.signal).then((raw) => {
        if (request.cancelled || requests.get(xhr) !== request) return null;
        const decodedText = extractPrompt(raw);
        if (!decodedText) return null;
        request.analysisStarted = true;
        request.requestId = crypto.randomUUID();
        return analyze(decodedText, request.targetApp, request.controller.signal, request.requestId);
      });
    } else {
      request.analysisStarted = true;
      request.requestId = crypto.randomUUID();
      decision = analyze(text, request.targetApp, request.controller.signal, request.requestId);
    }
    void decision.then((decision) => {
      if (request.cancelled || requests.get(xhr) !== request) return;
      if (decision?.action === "BLOCK") {
        reportXhrOutcome(request, decision.action, decision.observation, "BLOCKED_LOCALLY");
        finishPending(xhr, request, "error");
        return;
      }
      request.pending = false;
      clearTimeout(request.timeout);
      try {
        send.call(xhr, body);
        reportXhrOutcome(request, decision?.action ?? null, decision?.observation, "ORIGINAL_REQUEST_HANDED_OFF");
      } catch {
        // An asynchronous native send failure must also settle the caller.
        reportXhrOutcome(request, decision?.action ?? null, decision?.observation, "UNKNOWN");
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
    reportXhrOutcome(request, null, null, "UNKNOWN");
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

function reportXhrOutcome(request, action, observation, disposition) {
  if (!request.analysisStarted || !request.requestId || request.outcomeEmitted) return;
  request.outcomeEmitted = true;
  emitOutcome(request.requestId, action, observation, disposition);
}
