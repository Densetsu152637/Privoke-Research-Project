import assert from "node:assert/strict";
import test from "node:test";

test("static runtime codecs work when dynamic code evaluation is blocked", async () => {
  const OriginalFunction = globalThis.Function;
  globalThis.Function = () => {
    throw new Error("Dynamic code evaluation is blocked by extension CSP.");
  };

  try {
    const { privoke } = await import("../src/generated/runtime.js");
    const type = privoke.v1.SetRuntimeEnabledRequest;
    const encoded = type.encode(type.fromObject({ enabled: true })).finish();
    assert.equal(type.decode(encoded).enabled, true);
  } finally {
    globalThis.Function = OriginalFunction;
  }
});

test("stack profile presence survives protobuf encoding, including explicit cloud mode", async () => {
  const { privoke } = await import("../src/generated/runtime.js");
  const type = privoke.v1.SetRuntimeEnabledRequest;
  for (const useLocalStack of [true, false]) {
    const decoded = type.decode(type.encode(type.fromObject({ enabled: true, useLocalStack })).finish());
    assert.equal(decoded.useLocalStack, useLocalStack);
    assert.equal(Object.hasOwn(decoded, "useLocalStack"), true);
  }
  const legacy = type.decode(type.encode(type.fromObject({ enabled: true })).finish());
  assert.equal(Object.hasOwn(legacy, "useLocalStack"), false);
});
