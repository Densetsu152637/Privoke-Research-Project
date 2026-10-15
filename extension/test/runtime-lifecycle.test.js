import assert from "node:assert/strict";
import test from "node:test";

import { restoreConfiguredRuntime } from "../src/runtime-lifecycle.js";

test("does nothing when PriVoke is configured off", async () => {
  let supervisorChecks = 0;
  const client = {
    async setRuntimeEnabled() {
      assert.fail("the disabled runtime must not be started");
    },
  };

  const runtime = await restoreConfiguredRuntime(client, { enabled: false }, {
    ensureSupervisor: async () => { supervisorChecks += 1; },
  });

  assert.equal(runtime, null);
  assert.equal(supervisorChecks, 0);
});

test("starts the configured runtime through the supervisor", async () => {
  const calls = [];
  const expected = { enabled: true, status: "RUNNING", processId: 42 };
  const client = {
    async setRuntimeEnabled(enabled) {
      calls.push(["runtime", enabled]);
      return expected;
    },
  };

  const runtime = await restoreConfiguredRuntime(client, { enabled: true }, {
    ensureSupervisor: async (actualClient) => {
      assert.equal(actualClient, client);
      calls.push(["supervisor"]);
    },
  });

  assert.equal(runtime, expected);
  assert.deepEqual(calls, [["supervisor"], ["runtime", true]]);
});

test("rejects a supervisor response that leaves the runtime stopped", async () => {
  const client = {
    async setRuntimeEnabled() {
      return { enabled: false, status: "STOPPED", message: "dependency failed" };
    },
  };

  await assert.rejects(
    restoreConfiguredRuntime(client, { enabled: true }, {
      ensureSupervisor: async () => {},
    }),
    /dependency failed/,
  );
});

test("restores the persisted stack choice on every runtime start", async () => {
  for (const useLocalStack of [true, false]) {
    await restoreConfiguredRuntime({
      async setRuntimeEnabled(enabled, options) {
        assert.equal(enabled, true);
        assert.equal(options.useLocalStack, useLocalStack);
        return { enabled: true };
      },
    }, { enabled: true, useLocalStack }, { ensureSupervisor: async () => {} });
  }
});
