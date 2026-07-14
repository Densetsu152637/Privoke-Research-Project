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
