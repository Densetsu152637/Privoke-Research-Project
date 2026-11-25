import assert from "node:assert/strict";
import test from "node:test";

import {
  COVERAGE_PING,
  SUPPORTED_PROVIDER_HOSTS,
  activeTabCoverage,
  answerCoveragePings,
  coverageBadge,
  probePageCoverage,
  refreshTabCoverage,
  supportedProviderUrl,
} from "../src/page-coverage.js";

const noSleep = async () => {};
const manifest = JSON.parse(await (await import("node:fs/promises"))
  .readFile(new URL("../manifest.json", import.meta.url)));

test("supported provider hosts match every content-script host", () => {
  for (const script of manifest.content_scripts) {
    const hosts = script.matches.map((pattern) => new URL(pattern.replace("/*", "/")).hostname);
    assert.deepEqual([...hosts].sort(), [...SUPPORTED_PROVIDER_HOSTS].sort());
  }
  assert.equal(supportedProviderUrl("https://copilot.microsoft.com/chats/1"), true);
  assert.equal(supportedProviderUrl("http://copilot.microsoft.com/"), false);
  assert.equal(supportedProviderUrl("https://copilot.cloud.microsoft/"), false);
  assert.equal(supportedProviderUrl("not a url"), false);
});

test("a supported page whose content script answers is covered", async () => {
  const state = await probePageCoverage("https://chatgpt.com/", async () => ({ type: COVERAGE_PING, covered: true }),
    { sleep: noSleep });
  assert.deepEqual(state, { supported: true, covered: true });
});

// Regression for EDGE-COPILOT-1: Edge 157 refuses every extension script on
// copilot.microsoft.com, so tabs.sendMessage has no receiver.
test("a supported page whose content script never answers is an uncovered gap", async () => {
  let pings = 0;
  const state = await probePageCoverage("https://copilot.microsoft.com/", async () => {
    pings += 1;
    throw new Error("Could not establish connection. Receiving end does not exist.");
  }, { attempts: 3, sleep: noSleep });
  assert.deepEqual(state, { supported: true, covered: false });
  assert.equal(pings, 3);
  assert.deepEqual(coverageBadge(state).text, "!");
});

test("a late content script within the retries counts as covered", async () => {
  let pings = 0;
  const state = await probePageCoverage("https://claude.ai/", async () => {
    pings += 1;
    if (pings < 2) throw new Error("not yet");
    return { type: COVERAGE_PING, covered: true };
  }, { sleep: noSleep });
  assert.equal(state.covered, true);
});

test("an unexpected answer is not mistaken for coverage", async () => {
  const state = await probePageCoverage("https://claude.ai/", async () => ({ ok: true }), { attempts: 1 });
  assert.equal(state.covered, false);
});

test("unsupported pages are never pinged and never badged", async () => {
  const state = await probePageCoverage("https://example.com/", () => assert.fail("pinged"));
  assert.deepEqual(state, { supported: false, covered: false });
  assert.equal(coverageBadge(state).text, "");
});

function chromeRoot({ answer, url = "https://copilot.microsoft.com/" } = {}) {
  const calls = [];
  const runtime = { lastError: undefined };
  const chrome = {
    runtime,
    tabs: {
      query(_query, callback) { callback([{ id: 7, url }]); },
      sendMessage(tabId, message, callback) {
        calls.push(["sendMessage", tabId, message.type]);
        if (answer) { callback(answer); return; }
        runtime.lastError = { message: "Could not establish connection. Receiving end does not exist." };
        callback(undefined);
        runtime.lastError = undefined;
      },
    },
    action: {
      async setBadgeText(details) { calls.push(["text", details.tabId, details.text]); },
      async setBadgeBackgroundColor(details) { calls.push(["color", details.tabId, details.color]); },
      async setTitle(details) { calls.push(["title", details.tabId, details.title]); },
    },
  };
  return { root: { chrome }, calls };
}

test("the background badges an uncovered supported tab", async () => {
  const { root, calls } = chromeRoot();
  const state = await refreshTabCoverage(7, "https://copilot.microsoft.com/", root, { attempts: 2, sleep: noSleep });
  assert.equal(state.covered, false);
  assert.deepEqual(calls.filter(([kind]) => kind === "text"), [["text", 7, "!"]]);
  assert.match(calls.find(([kind]) => kind === "title")[2], /cannot inspect this page/);
});

test("the background clears the badge on a covered tab", async () => {
  const { root, calls } = chromeRoot({ answer: { type: COVERAGE_PING, covered: true } });
  await refreshTabCoverage(7, "https://chatgpt.com/", root, { sleep: noSleep });
  assert.deepEqual(calls.filter(([kind]) => kind === "text"), [["text", 7, ""]]);
});

test("the popup reports the active tab's coverage gap", async () => {
  const { root } = chromeRoot();
  assert.deepEqual(await activeTabCoverage(root, { attempts: 1 }), { supported: true, covered: false });
});

test("the content script answers only coverage pings", () => {
  let listener;
  answerCoveragePings({ chrome: { runtime: { onMessage: { addListener(handler) { listener = handler; } } } } });
  const answers = [];
  assert.equal(listener({ type: "OTHER" }, {}, (value) => answers.push(value)), false);
  listener({ type: COVERAGE_PING }, {}, (value) => answers.push(value));
  assert.deepEqual(answers, [{ type: COVERAGE_PING, covered: true }]);
});

// Chromium exposes tab.url to the background only for explicit host permissions, not
// for content-script matches, so the coverage check needs every provider host here.
test("every supported provider host is an explicit host permission", () => {
  for (const host of SUPPORTED_PROVIDER_HOSTS) {
    assert.ok(manifest.host_permissions.includes(`https://${host}/*`), host);
  }
});
