// WARN+MASK: replace detected sensitive spans with typed placeholders before a
// prompt request leaves the page. Offsets count Unicode code points, as the
// client runtime reports them. The measurement port in
// evaluation/warn_intervention.py implements the same algorithm; both are
// checked against extension/test/fixtures/mask-vectors.json.

const GENERIC_TYPE = "SENSITIVE";

function placeholderType(categories) {
  return categories.length === 1 ? categories[0] : GENERIC_TYPE;
}

function cleanCategory(value) {
  if (typeof value !== "string") return "";
  return value.toUpperCase().replace(/[^A-Z0-9_]/g, "_").slice(0, 32);
}

// Validate, sort and merge overlapping spans. Adjacent spans stay separate.
// Invalid spans (non-integer, empty, out of range) are dropped.
export function normalizeSpans(spans, length) {
  const valid = [];
  for (const span of Array.isArray(spans) ? spans : []) {
    const { start, end } = span ?? {};
    if (!Number.isInteger(start) || !Number.isInteger(end)) continue;
    if (start < 0 || end <= start || end > length) continue;
    const categories = (Array.isArray(span.categories) ? span.categories : [])
      .map(cleanCategory).filter(Boolean);
    valid.push({ start, end, categories });
  }
  valid.sort((a, b) => a.start - b.start || a.end - b.end);
  const merged = [];
  for (const span of valid) {
    const last = merged.at(-1);
    if (last && span.start < last.end) {
      last.end = Math.max(last.end, span.end);
      last.categories = [...new Set([...last.categories, ...span.categories])];
    } else {
      merged.push({ ...span, categories: [...new Set(span.categories)] });
    }
  }
  for (const span of merged) span.categories.sort();
  return merged;
}

export function placeholderFor(categories) {
  return `[PRIVOKE_${placeholderType(categories)}]`;
}

// Returns { text, spans, maskedChars }; maskedChars counts original code
// points replaced. With no valid spans the text is returned unchanged.
export function maskText(text, spans) {
  const characters = Array.from(text);
  const merged = normalizeSpans(spans, characters.length);
  let output = "";
  let cursor = 0;
  let maskedChars = 0;
  for (const span of merged) {
    output += characters.slice(cursor, span.start).join("");
    output += placeholderFor(span.categories);
    maskedChars += span.end - span.start;
    cursor = span.end;
  }
  output += characters.slice(cursor).join("");
  return { text: output, spans: merged, maskedChars };
}

// Positive detector findings with a character span, from a decoded
// AnalyzePromptResponse. Spanless findings cannot be masked.
export function collectMaskSpans(response) {
  const results = [];
  for (const layer of Array.isArray(response?.layers) ? response.layers : []) {
    if (layer?.status !== "ok" || !Array.isArray(layer.results)) continue;
    results.push(...layer.results);
  }
  if (response?.evidence) results.push(response.evidence);
  const spans = [];
  for (const result of results) {
    if (!result?.hasSpan) continue;
    const categories = Array.isArray(result.classification?.categories)
      ? result.classification.categories : [];
    const sensitivity = String(result.classification?.sensitivity ?? "S0");
    if (sensitivity === "S0" && categories.length === 0) continue;
    spans.push({ start: result.spanStart, end: result.spanEnd, categories });
  }
  return spans;
}

// Replace the analysed prompt text inside a request body. Returns the new body
// string, or null when the prompt is not a single recognisable string value
// (for example a form-encoded or multi-part prompt), in which case the caller
// must not claim masking.
export function rewritePromptBody(body, text, maskedText) {
  let raw = body;
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) {
    const bytes = body instanceof ArrayBuffer
      ? new Uint8Array(body)
      : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    raw = new TextDecoder().decode(bytes);
  }
  if (typeof raw !== "string" || !text) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return raw.trim() === text ? maskedText : null;
  }
  let replaced = false;
  const walk = (value) => {
    if (typeof value === "string") {
      if (!value.includes(text)) return value;
      replaced = true;
      return value.split(text).join(maskedText);
    }
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, walk(child)]));
    }
    return value;
  };
  const rewritten = walk(parsed);
  return replaced ? JSON.stringify(rewritten) : null;
}
