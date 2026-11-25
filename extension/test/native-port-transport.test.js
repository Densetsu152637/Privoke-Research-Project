import assert from "node:assert/strict";
import test from "node:test";

import {
  NATIVE_HOST,
  NativePortTransport,
  NativeTransportError,
  PROTOCOL_VERSION,
  UNSIGNALLED_TIMEOUT_MS,
  fromBase64,
  toBase64,
} from "../src/native-port-transport.js";

class FakePort {
  constructor() {
    this.sent = [];
    this.disconnected = false;
    this.failPost = false;
    this.error = undefined;
    this.messageListeners = [];
    this.disconnectListeners = [];
    this.onMessage = { addListener: (listener) => this.messageListeners.push(listener) };
    this.onDisconnect = { addListener: (listener) => this.disconnectListeners.push(listener) };
  }

  postMessage(message) {
    if (this.failPost) throw new Error("Attempt to postMessage on disconnected port");
    this.sent.push(message);
  }

  disconnect() {
    this.disconnected = true;
  }

  reply(message) {
    for (const listener of this.messageListeners) listener(message);
  }

  drop(error) {
    this.error = error === undefined ? undefined : { message: error };
    for (const listener of this.disconnectListeners) listener();
  }
}

function harness(options = {}) {
  const ports = [];
  const hosts = [];
  const transport = new NativePortTransport({
    connect: (hostName) => {
      hosts.push(hostName);
      const port = new FakePort();
      ports.push(port);
      return port;
    },
    lastError: (port) => port.error?.message,
    ...options,
  });
  return { transport, ports, hosts };
}

const bytes = (...values) => Uint8Array.from(values);
const success = (request, payload) => ({ v: PROTOCOL_VERSION, id: request.id, ok: true, payload: toBase64(payload) });

test("opens a port to the controller host and sends the versioned envelope", async () => {
  const { transport, ports, hosts } = harness();
  const pending = transport.request("AnalyzePrompt", bytes(1, 2, 3));
  assert.deepEqual(hosts, [NATIVE_HOST]);
  assert.equal(NATIVE_HOST, "org.privoke.runtime_controller");
  const [request] = ports[0].sent;
  assert.deepEqual(request, { v: 1, id: request.id, method: "AnalyzePrompt", payload: "AQID" });
  ports[0].reply(success(request, bytes(9, 8)));
  assert.deepEqual([...await pending], [9, 8]);
  assert.equal(transport.pendingCount, 0);
});

test("reuses one port and matches replies to requests by id, in any order", async () => {
  const { transport, ports } = harness();
  const first = transport.request("Status", bytes(1));
  const second = transport.request("Status", bytes(2));
  assert.equal(ports.length, 1);
  const [a, b] = ports[0].sent;
  assert.notEqual(a.id, b.id);
  ports[0].reply(success(b, bytes(22)));
  ports[0].reply(success(a, bytes(11)));
  assert.deepEqual([...await first], [11]);
  assert.deepEqual([...await second], [22]);
});

test("round-trips a maximum-size analysis payload", async () => {
  const { transport, ports } = harness();
  const payload = new Uint8Array(262_144).map((_, index) => index % 251);
  const pending = transport.request("AnalyzePrompt", payload);
  const [request] = ports[0].sent;
  assert.deepEqual(fromBase64(request.payload), payload);
  ports[0].reply(success(request, payload));
  assert.deepEqual(await pending, payload);
});

test("an error reply rejects with the controller's code and message and is never a result", async () => {
  const { transport, ports } = harness();
  const pending = transport.request("AnalyzePrompt", bytes(1));
  ports[0].reply({ v: 1, id: ports[0].sent[0].id, ok: false, code: "INVALID_ARGUMENT", message: "INVALID_LAYERS: an empty layer list is refused" });
  await assert.rejects(pending, (error) => {
    assert.ok(error instanceof NativeTransportError);
    assert.equal(error.code, "INVALID_ARGUMENT");
    assert.match(error.message, /INVALID_LAYERS/);
    return true;
  });
});

test("malformed replies for a request reject it, and stray messages are ignored", async () => {
  for (const reply of [
    (request) => ({ v: 1, id: request.id, ok: true }),
    (request) => ({ v: 1, id: request.id, ok: true, payload: "***" }),
    (request) => ({ v: 2, id: request.id, ok: true, payload: "AQ==" }),
    (request) => ({ v: 1, id: request.id, ok: "yes", payload: "AQ==" }),
    (request) => ({ v: 1, id: request.id }),
  ]) {
    const { transport, ports } = harness();
    const pending = transport.request("Status", bytes());
    for (const stray of [null, "text", 5, [], {}, { id: "x" }, { v: 1, id: 9999, ok: true, payload: "AQ==" }]) ports[0].reply(stray);
    assert.equal(transport.pendingCount, 1, "stray messages settle nothing");
    ports[0].reply(reply(ports[0].sent[0]));
    await assert.rejects(pending, NativeTransportError);
  }
});

test("a disconnect rejects every pending request, none is replayed, and the next request opens a fresh port", async () => {
  const { transport, ports } = harness();
  const first = transport.request("AnalyzePrompt", bytes(1));
  const second = transport.request("Status", bytes(2));
  ports[0].drop("Native host has exited.");
  for (const pending of [first, second]) {
    await assert.rejects(pending, (error) => {
      assert.match(error.message, /disconnected: Native host has exited/);
      assert.equal(error.permanent, false);
      return true;
    });
  }
  assert.equal(transport.connected, false);
  const third = transport.request("Status", bytes(3));
  assert.equal(ports.length, 2);
  assert.deepEqual(ports[0].sent.map((message) => message.method), ["AnalyzePrompt", "Status"]);
  assert.deepEqual(ports[1].sent.map((message) => message.method), ["Status"], "the rejected requests are not resent");
  ports[1].reply(success(ports[1].sent[0], bytes(7)));
  assert.deepEqual([...await third], [7]);
});

test("a host that is not installed is a permanent failure, in both browsers' wording", async () => {
  for (const reason of ["Specified native messaging host not found.", "No such native application org.privoke.runtime_controller",
    "Access to the specified native messaging host is forbidden."]) {
    const { transport, ports } = harness();
    const pending = transport.request("Status", bytes());
    ports[0].drop(reason);
    await assert.rejects(pending, (error) => error.permanent === true && error.message.includes(reason));
  }
});

test("a port that cannot be opened or written to fails the request", async () => {
  const refusing = new NativePortTransport({ connect: () => { throw new Error("no such host"); } });
  await assert.rejects(refusing.request("Status", bytes()), /Could not reach the PriVoke controller: no such host/);
  await assert.rejects(new NativePortTransport({ connect: () => null }).request("Status", bytes()), /Could not reach/);

  const { transport, ports } = harness();
  const warm = transport.request("Status", bytes());
  ports[0].reply(success(ports[0].sent[0], bytes()));
  await warm;
  ports[0].failPost = true;
  await assert.rejects(transport.request("Status", bytes()), /Could not send to the PriVoke controller/);
  assert.equal(transport.connected, false);
  const recovered = transport.request("Status", bytes());
  assert.equal(ports.length, 2);
  ports[1].reply(success(ports[1].sent[0], bytes(1)));
  await recovered;
});

test("the caller's deadline ends the request with the signal's own reason, and a late reply is dropped", async () => {
  const { transport, ports } = harness();
  const pending = transport.request("AnalyzePrompt", bytes(1), { signal: AbortSignal.timeout(30) });
  await assert.rejects(pending, (error) => error.name === "TimeoutError");
  assert.equal(transport.pendingCount, 0);
  ports[0].reply(success(ports[0].sent[0], bytes(1)));
  assert.equal(transport.pendingCount, 0);
});

test("an abort rejects at once, and an already aborted signal sends nothing", async () => {
  const { transport, ports } = harness();
  const controller = new AbortController();
  const pending = transport.request("AnalyzePrompt", bytes(1), { signal: controller.signal });
  controller.abort(new DOMException("caller gave up", "AbortError"));
  await assert.rejects(pending, (error) => error.name === "AbortError");

  const aborted = AbortSignal.abort();
  await assert.rejects(transport.request("AnalyzePrompt", bytes(1), { signal: aborted }), (error) => error.name === "AbortError");
  assert.equal(ports[0].sent.length, 1, "the aborted request never reached the port");
});

test("a request with no signal still ends at the transport's ceiling", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  const { transport } = harness();
  const pending = transport.request("Status", bytes());
  context.mock.timers.tick(UNSIGNALLED_TIMEOUT_MS);
  await assert.rejects(pending, (error) => error.code === "DEADLINE_EXCEEDED");
});

test("the owner is told about a later connection but not the first", async () => {
  const reconnects = [];
  const { transport, ports } = harness({ onReconnect: () => reconnects.push(ports.length) });
  const first = transport.request("Status", bytes());
  await Promise.resolve();
  assert.deepEqual(reconnects, []);
  ports[0].drop("gone");
  await assert.rejects(first, NativeTransportError);
  const second = transport.request("Status", bytes());
  await Promise.resolve();
  assert.deepEqual(reconnects, [2]);
  ports[1].reply(success(ports[1].sent[0], bytes()));
  await second;
});

test("closing the transport disconnects the port and rejects what is waiting", async () => {
  const { transport, ports } = harness();
  const pending = transport.request("Status", bytes());
  transport.close();
  assert.equal(ports[0].disconnected, true);
  assert.equal(transport.connected, false);
  ports[0].drop();
  await assert.rejects(pending, NativeTransportError);
});

test("a port that is no longer current cannot answer", async () => {
  const { transport, ports } = harness();
  const first = transport.request("Status", bytes());
  ports[0].drop("gone");
  await assert.rejects(first, NativeTransportError);
  const second = transport.request("Status", bytes());
  const staleId = ports[0].sent[0].id;
  ports[0].reply({ v: 1, id: staleId, ok: true, payload: "AQ==" });
  assert.equal(transport.pendingCount, 1);
  ports[1].reply(success(ports[1].sent[0], bytes(5)));
  assert.deepEqual([...await second], [5]);
});

// The two browsers deliver the same port interface but report a failed host differently: Chromium sets
// runtime.lastError while the disconnect listeners run, Firefox sets port.error. These tests use the real
// connectNative adapter and the default error reader against each browser's shape.
for (const dialect of ["chromium", "firefox"]) {
  test(`native messaging through the ${dialect} namespace: connect, answer, report a missing host`, async () => {
    const saved = { chrome: globalThis.chrome, browser: globalThis.browser };
    const ports = [];
    const runtime = {
      connectNative(hostName) {
        const port = new FakePort();
        port.hostName = hostName;
        ports.push(port);
        return port;
      },
      lastError: null,
    };
    try {
      if (dialect === "firefox") {
        globalThis.browser = { runtime };
        delete globalThis.chrome;
      } else {
        globalThis.chrome = { runtime };
        delete globalThis.browser;
      }
      const transport = new NativePortTransport();
      const answered = transport.request("Status", bytes(4));
      assert.equal(ports[0].hostName, "org.privoke.runtime_controller");
      ports[0].reply(success(ports[0].sent[0], bytes(6)));
      assert.deepEqual([...await answered], [6]);

      const missing = transport.request("Status", bytes());
      const failure = dialect === "firefox" ? "No such native application org.privoke.runtime_controller" : "Specified native messaging host not found.";
      if (dialect === "firefox") {
        ports[0].error = { message: failure };
        for (const listener of ports[0].disconnectListeners) listener();
      } else {
        runtime.lastError = { message: failure };
        for (const listener of ports[0].disconnectListeners) listener();
        runtime.lastError = null;
      }
      await assert.rejects(missing, (error) => error.permanent === true && error.message.includes(failure));
    } finally {
      for (const [name, value] of Object.entries(saved)) {
        if (value === undefined) delete globalThis[name];
        else globalThis[name] = value;
      }
    }
  });
}
