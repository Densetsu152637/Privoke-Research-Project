import assert from "node:assert/strict";
import { assertReceiverCapture } from "./installed-browser-evidence.mjs";

export const CASES = Object.freeze({
  allow: Object.freeze({
    id: "allow",
    prompt: "Please explain the steps in this process.",
    expectedAction: "ALLOW",
    expectedForwarded: true,
  }),
  warn: Object.freeze({
    id: "warn",
    prompt: "My profile handle is @privoke_fixture.",
    expectedAction: "WARN",
    expectedForwarded: true,
  }),
  block: Object.freeze({
    id: "block",
    prompt: "Contact alex@example.com about the draft.",
    expectedAction: "BLOCK",
    expectedForwarded: false,
  }),
});

export const TRANSPORTS = Object.freeze(["fetch", "xhr"]);
export const DECISION_CELLS = Object.freeze(
  TRANSPORTS.flatMap((transport) => Object.values(CASES).map((example) => ({
    transport,
    example,
  }))),
);

export function requestBody(prompt) {
  return JSON.stringify({ messages: [{ role: "user", content: prompt }] });
}

export function assertForwarding({ example, outcome, captures, transport, expectedUrl }) {
  assert.equal(captures.length, Number(example.expectedForwarded),
    `${transport}/${example.id} provider request count`);
  if (example.expectedForwarded) {
    assertReceiverCapture(captures[0], { expectedUrl, prompt: example.prompt });
    return;
  }
  if (transport === "fetch") {
    assert.equal(outcome.errorName, "TypeError", `${transport}/${example.id} cancellation`);
  } else {
    assert.equal(outcome.status, 0, `${transport}/${example.id} XHR status`);
    assert.equal(outcome.readyState, 4, `${transport}/${example.id} XHR terminal state`);
    assert.ok(outcome.events.includes("error"), "blocked XHR must emit error");
    assert.ok(outcome.events.includes("loadend"), "blocked XHR must emit loadend");
  }
}

export function assertAnalysisMessage({ expectedAction, outcome, prompt }) {
  assert.equal(outcome.analysis?.action, expectedAction,
    `${outcome.caseId} page action`);
  assert.ok(outcome.analysis?.requestId, `${outcome.caseId} page request ID`);
  assert.equal(outcome.analysis.prompt, prompt, `${outcome.caseId} analyzed prompt`);
  assert.ok(Number.isFinite(outcome.analysis.decisionMs),
    `${outcome.caseId} decision timing`);
}
