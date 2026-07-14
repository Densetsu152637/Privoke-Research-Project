const CHANNEL = "privoke-extension-v1";
const NOTICE_ID = "privoke-page-notice";

window.addEventListener("message", (event) => {
  const data = event.data;
  if (
    event.source !== window
    || data?.channel !== CHANNEL
    || data?.type !== "ANALYZE_PROMPT"
    || typeof data.text !== "string"
  ) return;

  chrome.runtime.sendMessage({
    type: "ANALYZE_PROMPT",
    source: "intercepted",
    text: data.text,
    targetApp: data.targetApp,
  }).then((result) => {
    const response = result?.ok ? result.response : null;
    const action = response?.action?.toUpperCase();
    if (action === "WARN" || action === "BLOCK") {
      showNotice(action, data.text, response);
    }
    postResult(data.requestId, action ?? "ALLOW");
  }).catch(() => postResult(data.requestId, "ALLOW"));
});

function postResult(requestId, action) {
  window.postMessage({
    channel: CHANNEL,
    type: "ANALYZE_RESULT",
    requestId,
    action,
  }, "*");
}

function showNotice(action, text, response) {
  document.getElementById(NOTICE_ID)?.remove();

  const host = document.createElement("div");
  host.id = NOTICE_ID;
  const shadow = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    .notice { position: fixed; z-index: 2147483647; top: 20px; right: 20px;
      width: min(380px, calc(100vw - 40px)); padding: 16px; border: 1px solid #efc4c0;
      border-left: 4px solid #ba3429; border-radius: 12px; color: #251c1a;
      background: #fffaf8; box-shadow: 0 16px 42px rgba(55, 26, 21, .2);
      font: 14px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; }
    .heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    strong { font-size: 15px; }
    button { border: 0; padding: 2px 5px; color: #645753; background: transparent;
      font: 20px/1 system-ui, sans-serif; cursor: pointer; }
    p { margin: 9px 0 0; }
    .excerpt { padding: 9px 10px; border-radius: 8px; background: #f7efec;
      color: #514440; overflow-wrap: anywhere; }
    .sensitive { color: #c5271c; font-weight: 750; }
  `;

  const notice = document.createElement("aside");
  notice.className = "notice";
  notice.setAttribute("role", action === "BLOCK" ? "alert" : "status");
  const heading = document.createElement("div");
  heading.className = "heading";
  const title = document.createElement("strong");
  title.textContent = action === "BLOCK" ? "Prompt blocked" : "Sensitive prompt warning";
  const close = document.createElement("button");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss PriVoke notice");
  close.textContent = "×";
  close.addEventListener("click", () => host.remove());
  heading.append(title, close);

  const reason = document.createElement("p");
  reason.textContent = response.reason || "PriVoke detected sensitive information.";
  const excerpt = document.createElement("p");
  excerpt.className = "excerpt";
  appendHighlightedText(excerpt, text, response.evidence);
  notice.append(heading, reason, excerpt);
  shadow.append(style, notice);
  (document.documentElement || document).append(host);
}

function appendHighlightedText(container, text, evidence) {
  const match = evidence?.sectionOfText || spanText(text, evidence);
  if (!match) {
    const sensitive = document.createElement("span");
    sensitive.className = "sensitive";
    sensitive.textContent = text.slice(0, 240);
    container.append(sensitive);
    return;
  }

  const index = text.toLocaleLowerCase().indexOf(match.toLocaleLowerCase());
  if (index < 0) {
    const sensitive = document.createElement("span");
    sensitive.className = "sensitive";
    sensitive.textContent = match;
    container.append(sensitive);
    return;
  }

  const contextStart = Math.max(0, index - 70);
  const contextEnd = Math.min(text.length, index + match.length + 70);
  if (contextStart > 0) container.append("…");
  container.append(text.slice(contextStart, index));
  const sensitive = document.createElement("span");
  sensitive.className = "sensitive";
  sensitive.textContent = text.slice(index, index + match.length);
  container.append(sensitive, text.slice(index + match.length, contextEnd));
  if (contextEnd < text.length) container.append("…");
}

function spanText(text, evidence) {
  if (!evidence?.hasSpan) return "";
  const start = Number(evidence.spanStart);
  const end = Number(evidence.spanEnd);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start) {
    return "";
  }
  return text.slice(start, end);
}
