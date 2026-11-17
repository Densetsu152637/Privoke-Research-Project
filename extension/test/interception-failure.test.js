import test from "node:test";
import assert from "node:assert/strict";
import { interceptionResponse, runtimeFailureResponse } from "../src/interception-failure.js";

test("runtime failure warns and permits website handoff", () => {
  assert.deepEqual(runtimeFailureResponse(), {
    action: "WARN",
    inspectionUnavailable: true,
    reason: "PriVoke could not complete analysis. Your prompt will be sent without a complete privacy check.",
  });
});

for (const [error, expected] of [
  [new DOMException("The operation was aborted due to timeout", "TimeoutError"), "analysis timed out"],
  ["Deadline exceeded", "analysis timed out"],
  [new Error("Extension context invalidated."), "Reload this AI page"],
  ["Could not establish connection. Receiving end does not exist.", "Reload this AI page"],
  [new TypeError("Failed to fetch"), "could not reach its local runtime"],
  ["Runtime bridge returned HTTP 503.", "could not reach its local runtime"],
  ["The PriVoke controller disconnected: Native host has exited.", "could not reach its local runtime"],
  ["Could not reach the PriVoke controller: no such host", "could not reach its local runtime"],
  ["The PriVoke native messaging host is not available: Install the PriVoke native messaging host", "could not reach its local runtime"],
  ["The PriVoke client runtime is not running.", "could not reach its local runtime"],
  ["the request missed its 27s deadline", "analysis timed out"],
  ["DEADLINE_EXCEEDED: handler finished late", "analysis timed out"],
]) {
  test(`known runtime failure gives fixed actionable guidance: ${expected}`, () => {
    const response = runtimeFailureResponse(error);
    assert.equal(response.action, "WARN");
    assert.ok(response.reason.includes(expected));
  });
}

test("failure details and prompt text are never reflected in notice reasons", () => {
  for (const error of ["secret prompt", "Failed to fetch: secret prompt", { message: "timeout: secret prompt" }, null, {}]) {
    const response = runtimeFailureResponse(error);
    assert.equal(response.action, "WARN");
    assert.equal(response.reason.includes("secret prompt"), false);
  }
  assert.equal(runtimeFailureResponse("unknown server failure").reason, runtimeFailureResponse().reason);
});

test("missing, invalid, and detector-error-only responses permit website handoff", () => {
  for (const response of [null, {}, { action: "MAYBE" },
    { action: "BLOCK", error: "classifier unavailable", layers: [{ status: "error", results: [] }] },
    { action: "BLOCK", layers: [{ status: "error", error: "classifier unavailable" }] },
    { action: "BLOCK", error: "partial failure", evidence: { action: "ALLOW" } },
  ]) {
    assert.equal(interceptionResponse(response).action, "WARN");
    assert.equal(interceptionResponse(response).inspectionUnavailable, true);
  }
});

test("genuine detector BLOCK survives independent layer failure and aggregate evidence", () => {
  for (const response of [
    { action: "BLOCK" },
    { action: "BLOCK", error: "semantic unavailable", layers: [
      { status: "ok", results: [{ action: "BLOCK" }] }, { status: "error", results: [] },
    ] },
    { action: "BLOCK", error: "semantic unavailable", evidence: { action: "BLOCK" },
      layers: [{ status: "ok", results: [{ action: "WARN" }] }, { status: "error", results: [] }] },
  ]) assert.equal(interceptionResponse(response).action, "BLOCK");
});
