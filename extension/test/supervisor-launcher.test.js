import assert from "node:assert/strict";
import test from "node:test";

import { ensureSupervisorRunning } from "../src/supervisor-launcher.js";

test("does not invoke the native launcher when the supervisor responds", async () => {
  let launches = 0;
  const expected = { enabled: false, status: "STOPPED" };
  const client = {
    async runtimeStatus() {
      return expected;
    },
  };

  const actual = await ensureSupervisorRunning(client, {
    launch: async () => {
      launches += 1;
      return { ok: true };
    },
  });

  assert.equal(actual, expected);
  assert.equal(launches, 0);
});

test("launches and waits for the supervisor after an initial fetch failure", async () => {
  let statusCalls = 0;
  let launches = 0;
  const client = {
    async runtimeStatus() {
      statusCalls += 1;
      if (statusCalls < 3) throw new TypeError("Failed to fetch");
      return { enabled: false, status: "STOPPED" };
    },
  };

  const result = await ensureSupervisorRunning(client, {
    launch: async () => {
      launches += 1;
      return { ok: true, started: true };
    },
    attempts: 2,
    retryDelayMs: 0,
  });

  assert.equal(result.status, "STOPPED");
  assert.equal(launches, 1);
  assert.equal(statusCalls, 3);
});

test("reports when the native host is not installed", async () => {
  const client = {
    async runtimeStatus() {
      throw new TypeError("Failed to fetch");
    },
  };

  await assert.rejects(
    ensureSupervisorRunning(client, {
      launch: async () => {
        throw new Error("Specified native messaging host not found.");
      },
    }),
    /Install the PriVoke native messaging host/,
  );
});

test("propagates a launcher startup failure", async () => {
  const client = {
    async runtimeStatus() {
      throw new TypeError("Failed to fetch");
    },
  };

  await assert.rejects(
    ensureSupervisorRunning(client, {
      launch: async () => ({ ok: false, message: "Supervisor executable is missing." }),
    }),
    /Supervisor executable is missing/,
  );
});
