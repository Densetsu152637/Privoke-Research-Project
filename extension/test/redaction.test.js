import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  collectMaskSpans,
  maskText,
  normalizeSpans,
  rewritePromptBody,
} from "../src/redaction.js";

const { vectors } = JSON.parse(
  await readFile(new URL("./fixtures/mask-vectors.json", import.meta.url), "utf8"),
);

for (const vector of vectors) {
  test(`mask vector: ${vector.name}`, () => {
    const result = maskText(vector.text, vector.spans);
    assert.equal(result.text, vector.masked);
    assert.equal(result.maskedChars, vector.masked_chars);
  });
}

test("masking does not mutate its input and tolerates absent spans", () => {
  const spans = [{ start: 1, end: 3, categories: ["CONTACT"] }];
  const frozen = Object.freeze(spans.map((span) => Object.freeze({ ...span })));
  assert.equal(maskText("abcdef", frozen).text, "a[PRIVOKE_CONTACT]def");
  assert.deepEqual(normalizeSpans([], 5), []);
  assert.deepEqual(normalizeSpans(null, 5), []);
});

test("collects only positive, located, successfully executed findings", () => {
  const found = (start, end, sensitivity = "S2", categories = ["IDENTITY"]) => ({
    hasSpan: true, spanStart: start, spanEnd: end, classification: { sensitivity, categories },
  });
  const spans = collectMaskSpans({
    layers: [
      {
        status: "ok",
        results: [
          found(0, 3),
          found(5, 7, "S0", []),
          { hasSpan: false, classification: { sensitivity: "S2", categories: ["IDENTITY"] } },
        ],
      },
      { status: "error", results: [found(8, 9)] },
      { status: "ok", results: [found(10, 12, "S0", ["CONTACT"])] },
    ],
    evidence: found(0, 3),
  });
  assert.deepEqual(spans.map(({ start, end }) => [start, end]), [[0, 3], [10, 12], [0, 3]]);
  assert.deepEqual(collectMaskSpans({}), []);
  assert.deepEqual(collectMaskSpans(undefined), []);
});

test("rewrites the analysed prompt inside JSON bodies and leaves other bodies alone", () => {
  const text = "My SSN is 123";
  const masked = "My SSN is [PRIVOKE_GOV_ID]";
  const json = JSON.stringify({ model: "m", messages: [{ role: "user", content: text }], n: 1 });
  const rewritten = JSON.parse(rewritePromptBody(json, text, masked));
  assert.equal(rewritten.messages[0].content, masked);
  assert.equal(rewritten.n, 1);
  assert.notEqual(rewritePromptBody(JSON.stringify({ prompt: `  ${text}\n` }), text, masked), null);
  assert.equal(rewritePromptBody(`  ${text}\n`, text, masked), masked);
  assert.notEqual(rewritePromptBody(new TextEncoder().encode(json), text, masked), null);
  assert.equal(rewritePromptBody(JSON.stringify({ prompt: "other" }), text, masked), null);
  assert.equal(rewritePromptBody("a=1&b=2", text, masked), null);
  assert.equal(rewritePromptBody(new URLSearchParams({ a: text }), text, masked), null);
  assert.equal(rewritePromptBody(null, text, masked), null);
});
