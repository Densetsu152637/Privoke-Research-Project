import { extractPrompt, promptTarget } from "./prompt-interception.js";

const CHANNEL = "privoke-extension-v1";
const RESPONSE_TIMEOUT_MS = 32_000;
const nativeFetch = window.fetch;

window.fetch = async function privokeFetch(input, init) {
  const method = init?.method ?? (input instanceof Request ? input.method : "GET");
  const rawUrl = input instanceof Request ? input.url : String(input);
  const targetApp = promptTarget(rawUrl, method, location.href);
  if (!targetApp) return nativeFetch.apply(this, arguments);

  const body = await requestBody(input, init);
  const text = extractPrompt(body);
  if (!text) return nativeFetch.apply(this, arguments);

  const decision = await analyze(text, targetApp);
  if (decision?.action === "BLOCK") {
    throw new DOMException("Prompt blocked by PriVoke.", "AbortError");
  }
  return nativeFetch.apply(this, arguments);
};

installXhrInterceptor();

async function requestBody(input, init) {
  if (init && Object.hasOwn(init, "body")) return init.body;
  if (input instanceof Request) {
    try {
      return await input.clone().text();
    } catch {
      return null;
    }
  }
  return null;
}

function analyze(text, targetApp) {
  const requestId = crypto.randomUUID();
  return new Promise((resolve) => {
    const timeout = setTimeout(() => finish(null), RESPONSE_TIMEOUT_MS);

    function onMessage(event) {
      const data = event.data;
      if (
        event.source === window
        && data?.channel === CHANNEL
        && data?.type === "ANALYZE_RESULT"
        && data.requestId === requestId
      ) finish(data);
    }

    function finish(value) {
      clearTimeout(timeout);
      window.removeEventListener("message", onMessage);
      resolve(value);
    }

    window.addEventListener("message", onMessage);
    window.postMessage({
      channel: CHANNEL,
      type: "ANALYZE_PROMPT",
      requestId,
      text,
      targetApp,
    }, "*");
  });
}

function installXhrInterceptor() {
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  const abort = XMLHttpRequest.prototype.abort;
  const requests = new WeakMap();

  XMLHttpRequest.prototype.open = function privokeOpen(method, url) {
    requests.set(this, {
      method,
      url: String(url),
      targetApp: promptTarget(String(url), method, location.href),
      cancelled: false,
    });
    return open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.abort = function privokeAbort() {
    const request = requests.get(this);
    if (request) request.cancelled = true;
    return abort.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function privokeSend(body) {
    const xhr = this;
    const request = requests.get(xhr);
    const text = request?.targetApp ? extractPrompt(body) : "";
    if (!request?.targetApp || !text) return send.apply(xhr, arguments);

    void analyze(text, request.targetApp).then((decision) => {
      if (request.cancelled || requests.get(xhr) !== request) return;
      if (decision?.action === "BLOCK") {
        abort.call(xhr);
        return;
      }
      send.call(xhr, body);
    }).catch(() => {
      if (!request.cancelled && requests.get(xhr) === request) send.call(xhr, body);
    });
    return undefined;
  };
}
