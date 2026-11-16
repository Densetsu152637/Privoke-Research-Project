// Coverage check for supported provider pages.
//
// Some browsers refuse every extension script on particular hosts regardless of the
// manifest. Edge 157 treats copilot.microsoft.com like its add-on gallery ("The
// extensions gallery cannot be scripted."), so neither content script runs there and
// prompts leave the page uninspected. The page itself cannot report that, so the
// background and popup ping the tab's content script and surface the gap.
import { webExtensionApi } from "./webextension-api.js";

export const SUPPORTED_PROVIDER_HOSTS = Object.freeze([
  "chatgpt.com",
  "chat.openai.com",
  "claude.ai",
  "gemini.google.com",
  "copilot.microsoft.com",
  "api.openai.com",
]);

export const COVERAGE_PING = "PRIVOKE_PAGE_COVERAGE_PING";
export const COVERAGE_GAP_TITLE = "PriVoke cannot inspect this page.";
export const COVERAGE_GAP_MESSAGE =
  "This browser does not let extensions run on this page, so prompts sent here are not checked, warned or blocked.";
const DEFAULT_ACTION_TITLE = "Inspect with PriVoke";

export function supportedProviderUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return url.protocol === "https:" && SUPPORTED_PROVIDER_HOSTS.includes(url.hostname);
  } catch {
    return false;
  }
}

// Returns { supported, covered }. A supported page is covered only when its content
// script answers; any error or silence after the retries counts as uncovered.
export async function probePageCoverage(rawUrl, ping, {
  attempts = 3,
  delayMs = 500,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  if (!supportedProviderUrl(rawUrl)) return { supported: false, covered: false };
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const answer = await ping();
      if (answer?.type === COVERAGE_PING && answer.covered === true) {
        return { supported: true, covered: true };
      }
    } catch {
      // No receiver in the tab yet, or the browser blocked the content script.
    }
    if (attempt + 1 < attempts) await sleep(delayMs);
  }
  return { supported: true, covered: false };
}

export function coverageBadge(state) {
  if (state?.supported && !state.covered) {
    return { text: "!", color: "#b3261e", title: `${COVERAGE_GAP_TITLE} ${COVERAGE_GAP_MESSAGE}` };
  }
  return { text: "", color: undefined, title: DEFAULT_ACTION_TITLE };
}

export function pingTab(tabId, root = globalThis) {
  const api = webExtensionApi(root);
  if (root.browser) return api.tabs.sendMessage(tabId, { type: COVERAGE_PING });
  return new Promise((resolve, reject) => {
    api.tabs.sendMessage(tabId, { type: COVERAGE_PING }, (answer) => {
      const error = api.runtime.lastError;
      if (error) reject(new Error(error.message));
      else resolve(answer);
    });
  });
}

// Content-script side: answer coverage pings from the background or popup.
export function answerCoveragePings(root = globalThis) {
  webExtensionApi(root).runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type !== COVERAGE_PING) return false;
    sendResponse({ type: COVERAGE_PING, covered: true });
    return false;
  });
}

// Background side: mark supported provider tabs whose content script is missing.
export function watchTabCoverage(root = globalThis, options = {}) {
  const api = webExtensionApi(root);
  if (!api.tabs?.onUpdated || !api.action) return;
  api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete") return;
    void refreshTabCoverage(tabId, tab?.url, root, options).catch(() => {});
  });
}

export async function refreshTabCoverage(tabId, rawUrl, root = globalThis, options = {}) {
  const api = webExtensionApi(root);
  const state = await probePageCoverage(rawUrl, () => pingTab(tabId, root), options);
  const badge = coverageBadge(state);
  await api.action.setBadgeText({ tabId, text: badge.text });
  if (badge.color) await api.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  await api.action.setTitle({ tabId, title: badge.title });
  return state;
}

// Popup side: coverage of the active tab.
export async function activeTabCoverage(root = globalThis, options = {}) {
  const api = webExtensionApi(root);
  const query = { active: true, currentWindow: true };
  const tabs = root.browser
    ? await api.tabs.query(query)
    : await new Promise((resolve) => api.tabs.query(query, resolve));
  const tab = tabs?.[0];
  if (!tab?.id || !tab.url) return { supported: false, covered: false };
  return probePageCoverage(tab.url, () => pingTab(tab.id, root), options);
}
