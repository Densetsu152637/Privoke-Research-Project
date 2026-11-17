import { readFileSync } from "node:fs";

export const FIXTURE = JSON.parse(readFileSync(new URL("./provider-shapes.json", import.meta.url), "utf8"));

function fill(node, prompt) {
  if (typeof node === "string") return node.split(FIXTURE.placeholder).join(prompt);
  if (Array.isArray(node)) return node.map((item) => fill(item, prompt));
  if (node && typeof node === "object") {
    if (Object.hasOwn(node, "$json")) return JSON.stringify(fill(node.$json, prompt));
    return Object.fromEntries(Object.entries(node).map(([key, value]) => [key, fill(value, prompt)]));
  }
  return node;
}

/** Returns the request body text and content type for a fixture entry. */
export function buildBody(entry, prompt) {
  const filled = fill(entry.body, prompt);
  if (entry.encoding === "form") {
    return {
      text: new URLSearchParams({ [entry.field]: JSON.stringify(filled) }).toString(),
      contentType: "application/x-www-form-urlencoded;charset=UTF-8",
    };
  }
  return { text: JSON.stringify(filled), contentType: "application/json" };
}

// `node provider-shapes.mjs --dump '{"ALLOW":"...","BLOCK":"..."}'` prints every
// shape x prompt body, so the Python study uses this builder as its single source.
if (process.argv[2] === "--dump") {
  const prompts = JSON.parse(process.argv[3]);
  const out = { shapes: {}, negativeControls: {} };
  for (const shape of FIXTURE.shapes) {
    out.shapes[shape.id] = Object.fromEntries(
      Object.entries(prompts).map(([action, prompt]) => [action, buildBody(shape, prompt)]),
    );
  }
  for (const control of FIXTURE.negativeControls) out.negativeControls[control.id] = buildBody(control, prompts.BLOCK);
  process.stdout.write(JSON.stringify(out));
}
