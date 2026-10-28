import test from "node:test";
import assert from "node:assert/strict";
import { runtimeFailureResponse } from "../src/interception-failure.js";

test("runtime failure produces a blocking decision", () => {
  assert.deepEqual(runtimeFailureResponse(), {
    action: "BLOCK",
    reason: "PriVoke could not analyze this prompt safely.",
  });
});

for (const [error, expected] of [
  [new DOMException("The operation was aborted due to timeout", "TimeoutError"), "analysis timed out"],
  ["Deadline exceeded", "analysis timed out"],
  [new Error("Extension context invalidated."), "Reload this AI page"],
  ["Could not establish connection. Receiving end does not exist.", "Reload this AI page"],
  [new TypeError("Failed to fetch"), "could not reach its local runtime"],
  ["Runtime bridge returned HTTP 503.", "could not reach its local runtime"],
]) {
  test(`known runtime failure gives fixed actionable guidance: ${expected}`, () => {
    const response = runtimeFailureResponse(error);
    assert.equal(response.action, "BLOCK");
    assert.ok(response.reason.includes(expected));
  });
}

test("failure details and prompt text are never reflected in notice reasons", () => {
  for (const error of ["secret prompt", "Failed to fetch: secret prompt", { message: "timeout: secret prompt" }, null, {}]) {
    const response = runtimeFailureResponse(error);
    assert.equal(response.action, "BLOCK");
    assert.equal(response.reason.includes("secret prompt"), false);
  }
  assert.equal(runtimeFailureResponse("unknown server failure").reason, runtimeFailureResponse().reason);
});
