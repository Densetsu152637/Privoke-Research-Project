import assert from "node:assert/strict";
import test from "node:test";
import { extractPrompt, promptTarget } from "../src/prompt-interception.js";

test("recognises supported AI prompt endpoints only for POST requests", () => {
  assert.equal(
    promptTarget("https://chatgpt.com/backend-api/conversation", "POST"),
    "chatgpt",
  );
  assert.equal(
    promptTarget("https://api.openai.com/v1/responses", "POST"),
    "openai_api",
  );
  assert.equal(
    promptTarget("https://chatgpt.com/backend-api/conversation", "GET"),
    null,
  );
  assert.equal(promptTarget("https://example.com/api/chat", "POST"), null);
});

test("extracts the latest user message from ChatGPT-style JSON", () => {
  const body = JSON.stringify({
    messages: [
      { role: "user", content: { parts: ["Earlier context"] } },
      { role: "assistant", content: { parts: ["Earlier reply"] } },
      { role: "user", content: { parts: ["My card is 4111 1111 1111 1111"] } },
    ],
  });

  assert.equal(extractPrompt(body), "My card is 4111 1111 1111 1111");
});

test("extracts prompts from OpenAI and form-encoded request bodies", () => {
  assert.equal(
    extractPrompt(JSON.stringify({ input: "Summarise my private medical record" })),
    "Summarise my private medical record",
  );
  assert.equal(
    extractPrompt("prompt=Please+remember+my+passport+number"),
    "Please remember my passport number",
  );
});

test("extracts the latest user item from Responses API input", () => {
  assert.equal(extractPrompt({
    input: [
      { role: "user", content: [{ type: "input_text", text: "Old prompt" }] },
      { role: "assistant", content: [{ type: "output_text", text: "Old reply" }] },
      { role: "user", content: [{ type: "input_text", text: "New private prompt" }] },
    ],
  }), "New private prompt");
});


test("decodes UTF-8 buffers and respects typed-view boundaries", () => {
  const encoded = new TextEncoder().encode(JSON.stringify({ prompt: "My medical record — private" }));
  assert.equal(extractPrompt(encoded.buffer), "My medical record — private");
  assert.equal(extractPrompt(encoded), "My medical record — private");
  const padded = new Uint8Array(encoded.length + 8);
  padded.set(encoded, 4);
  assert.equal(extractPrompt(new DataView(padded.buffer, 4, encoded.length)), "My medical record — private");
  assert.equal(extractPrompt(new Uint8Array(0)), "");
});


for (const [endpoint, target, payload] of [
  ["https://chatgpt.com/backend-api/f/conversation", "chatgpt", { messages: [{ author: { role: "user" }, content: { parts: ["My private prompt"] } }] }],
  ["https://chat.openai.com/backend-api/conversation", "chatgpt", { prompt: "My private prompt" }],
  ["https://claude.ai/api/organizations/org/chat_conversations/id/completion", "claude", { prompt: "My private prompt" }],
  ["https://gemini.google.com/_/BardChatUi/data/BardFrontendService/StreamGenerate", "gemini", new URLSearchParams({ "f.req": JSON.stringify([null, JSON.stringify([["My private prompt"]])]) })],
  ["https://copilot.microsoft.com/c/api/chat", "copilot", { message: { content: "My private prompt" } }],
  ["https://api.openai.com/v1/chat/completions", "openai_api", { messages: [{ role: "user", content: "My private prompt" }] }],
  ["https://api.openai.com/v1/responses", "openai_api", { input: [{ role: "user", content: [{ type: "input_text", text: "My private prompt" }] }] }],
]) {
  test(`supported ${target} endpoint extracts its prompt payload: ${endpoint}`, () => {
    assert.equal(promptTarget(endpoint), target);
    assert.equal(extractPrompt(payload), "My private prompt");
  });
}

test("non-ASCII and single-character user prompts are inspected", () => {
  assert.equal(extractPrompt({ prompt: "\u79c1\u306e\u533b\u7642\u8a18\u9332" }), "\u79c1\u306e\u533b\u7642\u8a18\u9332");
  assert.equal(extractPrompt({ prompt: "x" }), "x");
});
