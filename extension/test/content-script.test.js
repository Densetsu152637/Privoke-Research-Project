import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = (await readFile(new URL("../src/content-script.js", import.meta.url), "utf8"))
  .replace(/^import .*;\r?\n/gm, "");
const flush = () => new Promise((resolve) => setImmediate(resolve));

function relay(sendRuntimeMessage) {
  let listener;
  const results = [];
  const window = {
    addEventListener(type, handler) { if (type === "message") listener = handler; },
    postMessage(data) { results.push(data); },
  };
  vm.runInNewContext(source, {
    runtimeFailureResponse: () => ({ action: "BLOCK" }), window, sendRuntimeMessage,
    document: { getElementById() { throw new Error("notice rendering failed"); } },
  });
  listener({ source: window, data: {
    channel: "privoke-extension-v1", type: "ANALYZE_PROMPT",
    requestId: "request-1", text: "My private prompt", targetApp: "chatgpt",
  } });
  return results;
}

for (const action of ["BLOCK", "WARN"]) {
  test(`notice rendering errors preserve ${action} and deliver one decision`, async () => {
    const results = relay(async () => ({ ok: true, response: { action } }));
    await flush();
    assert.equal(results.length, 1);
    assert.equal(results[0].action, action);
    assert.equal(results[0].requestId, "request-1");
  });
}

for (const mode of ["sync", "async", "response"]) {
  test(`${mode} runtime failure still delivers a block decision when notice rendering fails`, async () => {
    const results = relay(() => {
      if (mode === "sync") throw new Error("extension context invalidated");
      if (mode === "async") return Promise.reject(new Error("runtime unavailable"));
      return Promise.resolve({ ok: false, error: "runtime unavailable" });
    });
    await flush();
    assert.equal(results.length, 1);
    assert.equal(results[0].action, "BLOCK");
  });
}


function highlight(text, evidence) {
  const container = { children: [], append(...items) { this.children.push(...items); } };
  const context = vm.createContext({
    window: { addEventListener() {} },
    document: { createElement(tag) { return { tag, className: "", textContent: "" }; } },
  });
  vm.runInContext(source, context);
  context.appendHighlightedText(container, text, evidence);
  return container.children;
}

const rendered = (children) => children.map((item) => (
  typeof item === "string" ? item : item.textContent
)).join("");
const highlighted = (children) => children.filter((item) => item?.className === "sensitive");

test("reported span selects the second identical occurrence", () => {
  const children = highlight("alex and alex", {
    hasSpan: true, spanStart: 9, spanEnd: 13, sectionOfText: "alex",
  });
  assert.equal(children[0], "alex and ");
  assert.equal(highlighted(children)[0].textContent, "alex");
  assert.equal(rendered(children), "alex and alex");
});

test("runtime code point offsets preserve emoji before and inside evidence", () => {
  const children = highlight("😀 Hi A🧑B end", {
    hasSpan: true, spanStart: 5, spanEnd: 8, sectionOfText: "A🧑B",
  });
  assert.equal(children[0], "😀 Hi ");
  assert.equal(highlighted(children)[0].textContent, "A🧑B");
  assert.equal(rendered(children), "😀 Hi A🧑B end");
});

test("valid code point span works without section text", () => {
  const children = highlight("😀 Alex", { hasSpan: true, spanStart: 2, spanEnd: 6 });
  assert.equal(children[0], "😀 ");
  assert.equal(highlighted(children)[0].textContent, "Alex");
});

test("protobuf empty section text does not discard a valid reported span", () => {
  const children = highlight("😀 Alex", {
    hasSpan: true, spanStart: 2, spanEnd: 6, sectionOfText: "",
  });
  assert.equal(children[0], "😀 ");
  assert.equal(highlighted(children)[0].textContent, "Alex");
});

test("invalid reported spans fall back to a unique exact source section", () => {
  for (const [spanStart, spanEnd] of [[-1, 3], [1, 100], [3, 1], [1.5, 3], ["3", "7"]]) {
    const children = highlight("Hi Alex", {
      hasSpan: true, spanStart, spanEnd, sectionOfText: "Alex",
    });
    assert.equal(children[0], "Hi ");
    assert.equal(highlighted(children)[0].textContent, "Alex");
  }
});

test("mismatched reported span falls back only when exact section is unique", () => {
  const children = highlight("Hi Alex", {
    hasSpan: true, spanStart: 0, spanEnd: 2, sectionOfText: "Alex",
  });
  assert.equal(children[0], "Hi ");
  assert.equal(rendered(children), "Hi Alex");
});

test("ambiguous absent or mismatched spans display evidence separately", () => {
  for (const evidence of [
    { sectionOfText: "alex" },
    { hasSpan: true, spanStart: 0, spanEnd: 99, sectionOfText: "alex" },
    { hasSpan: true, spanStart: 4, spanEnd: 7, sectionOfText: "alex" },
  ]) {
    const children = highlight("alex and alex", evidence);
    assert.equal(children.length, 1);
    assert.equal(rendered(children), "alex");
  }
});

test("fallback does not case-fold source offsets or guess a different case", () => {
  const children = highlight("İ and Alex", { sectionOfText: "alex" });
  assert.equal(children.length, 1);
  assert.equal(rendered(children), "alex");
});

test("invalid unlocated evidence leaves source excerpt unhighlighted", () => {
  const children = highlight("😀 original prompt", { hasSpan: true, spanStart: 0, spanEnd: 99 });
  assert.equal(highlighted(children).length, 0);
  assert.equal(rendered(children), "😀 original prompt");
});
