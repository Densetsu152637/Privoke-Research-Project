(() => {
  // src/prompt-interception.js
  var JSON_KEYS = /* @__PURE__ */ new Set([
    "content",
    "input",
    "message",
    "parts",
    "prompt",
    "query",
    "text"
  ]);
  function promptTarget(rawUrl, method = "POST", baseUrl = void 0) {
    if (String(method).toUpperCase() !== "POST") return null;
    let url;
    try {
      url = new URL(rawUrl, baseUrl);
    } catch {
      return null;
    }
    const path = url.pathname;
    if (["chatgpt.com", "chat.openai.com"].includes(url.hostname) && /\/backend-api\/(?:f\/)?conversation(?:\/|$)/.test(path)) return "chatgpt";
    if (url.hostname === "claude.ai" && /\/api\/.*(?:completion|message|chat_conversations)/.test(path)) return "claude";
    if (url.hostname === "gemini.google.com" && /(?:StreamGenerate|BardFrontendService)/.test(path)) return "gemini";
    if (url.hostname === "copilot.microsoft.com" && /\/(?:c\/)?api\/.*(?:chat|conversation|message)/.test(path)) return "copilot";
    if (url.hostname === "api.openai.com" && /^\/v1\/(?:chat\/completions|responses)(?:\/|$)/.test(path)) return "openai_api";
    return null;
  }
  function extractPrompt(body) {
    const parsed = parseBody(body);
    if (parsed == null) return "";
    if (typeof parsed === "string") return looksLikePrompt(parsed) ? parsed.trim() : "";
    const messageText = latestUserText(parsed.messages);
    if (messageText) return messageText;
    const inputText = latestUserText(parsed.input);
    if (inputText) return inputText;
    for (const key of ["prompt", "input", "query", "message", "content"]) {
      if (Object.hasOwn(parsed, key)) {
        const text = textFromValue(parsed[key]);
        if (looksLikePrompt(text)) return text.trim();
      }
    }
    const candidates = [];
    collectCandidates(parsed, "", candidates);
    candidates.sort((left, right) => right.score - left.score || right.order - left.order);
    return candidates[0]?.text.trim() ?? "";
  }
  function parseBody(body) {
    if (body == null) return null;
    if (typeof FormData !== "undefined" && body instanceof FormData) {
      return Object.fromEntries(body.entries());
    }
    if (typeof body === "object" && !(body instanceof URLSearchParams)) return body;
    const raw = body instanceof URLSearchParams ? body.toString() : String(body);
    const trimmed = raw.trim();
    if (!trimmed) return null;
    try {
      return JSON.parse(trimmed);
    } catch {
      const params = new URLSearchParams(trimmed);
      if ([...params.keys()].length > 0 && trimmed.includes("=")) {
        const object = Object.fromEntries(params.entries());
        for (const [key, value] of Object.entries(object)) {
          try {
            object[key] = JSON.parse(value);
          } catch {
          }
        }
        return object;
      }
      return trimmed;
    }
  }
  function latestUserText(value) {
    if (!Array.isArray(value)) return "";
    const hasRoles = value.some((item) => item && typeof item === "object" && (Object.hasOwn(item, "role") || Object.hasOwn(item, "author")));
    if (!hasRoles) return "";
    for (let index = value.length - 1; index >= 0; index -= 1) {
      const message = value[index];
      const role = String(message?.role ?? message?.author?.role ?? "").toLowerCase();
      if (role === "user" || role === "human") {
        const text = textFromValue(message?.content ?? message?.text ?? message);
        if (looksLikePrompt(text)) return text.trim();
      }
    }
    return "";
  }
  function textFromValue(value) {
    if (typeof value === "string") return value;
    if (Array.isArray(value)) {
      return value.map(textFromValue).filter(Boolean).join("\n");
    }
    if (!value || typeof value !== "object") return "";
    for (const key of ["parts", "text", "content", "value"]) {
      if (Object.hasOwn(value, key)) {
        const text = textFromValue(value[key]);
        if (text) return text;
      }
    }
    return "";
  }
  function collectCandidates(value, key, candidates) {
    if (typeof value === "string") {
      let nested;
      try {
        nested = JSON.parse(value);
      } catch {
        nested = null;
      }
      if (nested && typeof nested === "object") {
        collectCandidates(nested, key, candidates);
        return;
      }
      if (looksLikePrompt(value)) {
        candidates.push({
          text: value,
          order: candidates.length,
          score: value.length + (JSON_KEYS.has(key) ? 1e4 : 0)
        });
      }
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) collectCandidates(item, key, candidates);
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [childKey, child] of Object.entries(value)) {
      collectCandidates(child, childKey.toLowerCase(), candidates);
    }
  }
  function looksLikePrompt(value) {
    if (typeof value !== "string") return false;
    const trimmed = value.trim();
    if (trimmed.length < 2) return false;
    if (/^[a-f\d-]{16,}$/i.test(trimmed)) return false;
    return /[a-z\d]/i.test(trimmed);
  }

  // src/page-interceptor.js
  var CHANNEL = "privoke-extension-v1";
  var RESPONSE_TIMEOUT_MS = 32e3;
  var nativeFetch = window.fetch;
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
        if (event.source === window && data?.channel === CHANNEL && data?.type === "ANALYZE_RESULT" && data.requestId === requestId) finish(data);
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
        targetApp
      }, "*");
    });
  }
  function installXhrInterceptor() {
    const open = XMLHttpRequest.prototype.open;
    const send = XMLHttpRequest.prototype.send;
    const abort = XMLHttpRequest.prototype.abort;
    const requests = /* @__PURE__ */ new WeakMap();
    XMLHttpRequest.prototype.open = function privokeOpen(method, url) {
      requests.set(this, {
        method,
        url: String(url),
        targetApp: promptTarget(String(url), method, location.href),
        cancelled: false
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
      return void 0;
    };
  }
})();
//# sourceMappingURL=page-interceptor.js.map
