import test from "node:test";
import assert from "node:assert/strict";
import { runtimeFailureResponse } from "../src/interception-failure.js";

test("runtime failure produces a blocking decision", () => {
  assert.deepEqual(runtimeFailureResponse(), {
    action: "BLOCK",
    reason: "PriVoke could not analyze this prompt safely.",
  });
});