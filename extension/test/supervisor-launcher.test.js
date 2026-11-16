import assert from "node:assert/strict";
import test from "node:test";

import { NativeTransportError } from "../src/native-port-transport.js";
import { ensureSupervisorRunning } from "../src/supervisor-launcher.js";

test("asks the controller for its status over the port and returns it", async () => {
  const expected = { enabled: false, status: "STOPPED" };
  let calls = 0;
  const client = {
    async runtimeStatus() {
      calls += 1;
      return expected;
    },
  };

  assert.equal(await ensureSupervisorRunning(client), expected);
  assert.equal(calls, 1);
});

test("retries while the controller is still starting", async () => {
  let calls = 0;
  const client = {
    async runtimeStatus() {
      calls += 1;
      if (calls < 3) throw new NativeTransportError("The PriVoke controller disconnected: Native host has exited.");
      return { enabled: false, status: "STOPPED" };
    },
  };

  const result = await ensureSupervisorRunning(client, { attempts: 4, retryDelayMs: 0 });

  assert.equal(result.status, "STOPPED");
  assert.equal(calls, 3);
});

test("a host that is not installed fails at once with the install hint, without retrying", async () => {
  let calls = 0;
  const client = {
    async runtimeStatus() {
      calls += 1;
      throw new NativeTransportError("The PriVoke controller disconnected: Specified native messaging host not found.", { permanent: true });
    },
  };

  await assert.rejects(
    ensureSupervisorRunning(client, { attempts: 10, retryDelayMs: 0 }),
    /Install the PriVoke native messaging host/,
  );
  assert.equal(calls, 1);
});

test("gives up after the attempts and says the controller could not be reached", async () => {
  let calls = 0;
  const client = {
    async runtimeStatus() {
      calls += 1;
      throw new NativeTransportError("The PriVoke controller disconnected");
    },
  };

  await assert.rejects(
    ensureSupervisorRunning(client, { attempts: 3, retryDelayMs: 0 }),
    /could not be reached: The PriVoke controller disconnected/,
  );
  assert.equal(calls, 3);
});
