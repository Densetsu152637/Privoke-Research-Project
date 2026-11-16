# WARN intervention: WARN+MASK versus WARN+CONFIRM versus BLOCK (2026-11-16)

**Scope: product detector pipeline (regex and NER layers) on development data, plus extension behaviour tests. Not LLM-only or semantic evidence. WARNINT-20261116.**

## Goal and instruction

Goal G9 of the [ASIACCS revision plan](../plans/asiaccs-2027-revision.md) (Stage 5). The supervisor asked for a WARN intervention experiment that implements either WARN+CONFIRM or WARN+MASK/EDIT and compares how much sensitive transmission is actually prevented. Authorization: the 16 November 2026 entry of `paper/REWRITE_SCOPE.md`. No download was needed and Docker was not used.

## What was built

- **WARN+MASK** in the extension, behind `settings.warnMasking` (default `false`): on a WARN, all located detector spans replace the prompt text in the outgoing fetch or XHR body with typed placeholders (`[PRIVOKE_<CATEGORY>]`). It was feasible because every runtime detection result carries `span_start`, `span_end` and `has_span` in code points; the existing `masked_text` covers only one span and is not used. Code: `extension/src/redaction.js`, with hooks in `background.js`, `content-script.js`, `page-interceptor.js` and `settings.js`. Documented in [browser extension](../runtime/browser-extension.md).
- **WARN+CONFIRM** is evaluated analytically only, as a function of the unknown compliance rate `c`.
- **Measurement**: `evaluation/warn_intervention.py` runs the pipeline and scores four arms (plain WARN, WARN+MASK, WARN+CONFIRM, BLOCK). Its `mask_text` is a port of `redaction.js`, checked on the shared vectors `extension/test/fixtures/mask-vectors.json` by both test suites.

## Method summary

All 502 development rows of `dev_spans.jsonl` (264 sensitive with 561 gold spans, 238 clean; LF-normalised sha256 `43e1d382da6b9ae29d6cb6e76ae16876388b430f1476e1ef32bcc107a109a4fe`, verified before scoring). `analyse_text(layers=["regex","ner"], regex_first=True)` at base revision `742438c`, executed layers asserted. Wilson 95 % intervals, exact sign test, no random step (deterministic; seed 20261116 recorded). Full method, tables and limitations: [`paper/research/warn-intervention-20261116.md`](../../paper/research/warn-intervention-20261116.md); data: [`.json`](../../paper/research/warn-intervention-20261116.json).

## Headline results (scope all)

| Arm | Sensitive prompts sent with an intact gold span (of 264) | Prevented | Over-redaction |
|---|---|---|---|
| plain WARN | 155 = 0.587 [0.527, 0.645] | 0.413 [0.355, 0.473] | none |
| WARN+MASK | 120 = 0.455 [0.396, 0.515] | 0.545 [0.485, 0.604] | 41.7 % of masked characters outside gold; 10/238 clean prompts altered |
| WARN+CONFIRM | 0.587 at c=0 down to 0.348 at c=1 (analytic bound, not a measurement) | 0.413 to 0.652 | 10/238 clean prompts interrupted |
| BLOCK | 92 = 0.348 [0.294, 0.408] | 0.652 [0.592, 0.706] | 11/238 clean prompts not sent |

- The MASK residual is bounded by detector span recall: of the 63 sensitive prompts the pipeline WARNs, 28 still carry an intact gold span; only 92/153 gold spans in those prompts are fully covered. ALLOWed sensitive prompts (92) are never touched by MASK or CONFIRM.
- CONFIRM matches MASK at a compliance rate of `c* = 0.556` (analytic).

## Checks

`npm test` in `extension/`: 155/155 (baseline 130). `evaluation/tests/test_warn_intervention.py`: 16 pass. `warn_intervention.py rederive` reproduces every stored number from the JSON. Default-off is asserted by settings, content-script and page-interceptor tests.

## Limitations

Regex and NER only (no semantic layer); development data; offline masking assumes the body rewrite succeeds (form-encoded, multi-part, Blob and nested-JSON bodies fall back to the original request); no live-site or user study; utility is a character-level proxy. See the research record for the full list.
