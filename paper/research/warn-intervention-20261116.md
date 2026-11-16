# WARN intervention experiment (WARNINT-20261116)

**Scope: product detector pipeline (regex and NER layers, explicit layer list) on development data, plus the shipped-extension behaviour tests. This is product/intervention evidence. It is not LLM-only or semantic evidence, and the semantic layer was not run. Development data only; no held-out set and no protected endpoint was read.**

Stable ID: `WARNINT-20261116`. Machine-readable record with per-prompt data: [`warn-intervention-20261116.json`](warn-intervention-20261116.json). Experiment write-up: [`docs/experiments/warn-intervention-20261116.md`](../../docs/experiments/warn-intervention-20261116.md).

## Goal and authority

Goal G9 of the [ASIACCS revision plan](../../docs/plans/asiaccs-2027-revision.md), Stage 5: compare how much sensitive transmission each post-WARN intervention actually prevents, and the utility cost (over-redaction). The supervisor asked to "run a WARN intervention experiment that implements either WARN+CONFIRM or WARN+MASK/EDIT and compares how much sensitive transmission is actually prevented". The 16 November 2026 entry of `paper/REWRITE_SCOPE.md` authorizes the experiment. This record has a new evidence-unit number to be assigned after unit 8 by the claims ledger owner.

## Which intervention was implemented, and why

**WARN+MASK was implemented** (extension option `warnMasking`, off by default). The runtime already returns character spans: every `RuntimeDetectionResult` in `layers[].results[]` carries `has_span`, `span_start` and `span_end` (Unicode code points into the analysed text), so spans are usable. The existing `masked_text` field masks only the single evidence span and is therefore unsuitable. The extension rewrites the prompt in the outgoing request with all located spans. WARN+CONFIRM was not built as a UI; it is measured analytically as a function of the unknown user-compliance rate `c`.

## Method

- **Set.** `evaluation/results/fresh_sets_20261024/dev_spans.jsonl`: the 502 locked development rows joined with PIIMB character spans (264 prompts with at least one gold span, 238 without; 561 gold spans). All 502 rows are used; no split was drawn. File sha256 (LF-normalised) `43e1d382da6b9ae29d6cb6e76ae16876388b430f1476e1ef32bcc107a109a4fe`, equal to the manifest `output_sha256`; on-disk (CRLF) sha256 `a1aad47080fed04aecb1e82345f4883b869ac97a0c75dd18ba4abde0cb4e41fc`. The script refuses to score if the LF-normalised hash differs. The file is gitignored and read from the main checkout. Provenance and label mapping: [span-scoring record](../../docs/experiments/span-scoring-20261024.md).
- **Pipeline.** `pipeline.analyse_text(text, layers=["regex","ner"], regex_first=True)` for each prompt at base revision `742438c` (product default `waitForRegex`). The script asserts the executed layer list equals the requested list, and that every layer is `ok` (a non-regex layer may be `skipped` only after a regex BLOCK). 392 prompts ran both layers; 110 had NER skipped after a regex BLOCK. The prompt-level action (ALLOW, WARN or BLOCK) is the pipeline's own. The semantic layer needs the model-streaming service and was not run, so actions reflect regex and NER only.
- **Predicted spans.** Every positive result (sensitivity not S0 or any category) with a span, from every executed layer; 0 positive results lacked a span.
- **Arms.** Each prompt is transmitted or not, and possibly altered:
  - `plain_warn`: ALLOW and WARN send the original; BLOCK is not sent (shipped behaviour).
  - `warn_mask`: as plain WARN, but a WARN prompt is sent with every merged predicted span replaced by a typed placeholder.
  - `warn_confirm`: BLOCK not sent, ALLOW sent, a WARN is cancelled with probability `c` (not sent) or confirmed (original sent). `c` is unknown.
  - `block`: WARN and BLOCK are both not sent.
- **Metrics (sensitive prompts, denominator 264).** "Transmitted with an intact gold span" = the prompt is sent and at least one gold span has no masked character. "Any unmasked gold character" is the stricter leak definition. Prevented fraction = 1 minus the intact-transmission fraction (the unprotected baseline sends every sensitive prompt intact). Span-level: gold spans transmitted intact, fully removed, and gold characters transmitted. Over-redaction: masked characters outside every gold span, as a share of masked characters and per 1000 prompt characters; clean prompts altered, and clean prompts not sent. Scope `all` counts every gold span; scope `core` drops 65 attribute-only gold spans (titles, genders, ages, occupations, education, languages) for which PriVoke has no detector category, as in the span-scoring record.
- **Statistics.** Wilson 95 % intervals for every measured proportion (prompt or span as the unit; prompts from one source document are not independent, so intervals are somewhat optimistic). Paired exact sign (McNemar) test for MASK against plain WARN. No random step exists: runs are deterministic, `SEED=20261116` is recorded for any future sampling, and two complete extractions produced byte-identical output.
- **Analytic WARN+CONFIRM.** A WARN prompt is sent with probability `1-c`; ALLOW is sent whatever `c` is; BLOCK is never sent. The result is linear in `c`, equals plain WARN at `c=0` and BLOCK at `c=1`. **It is an analytic bound under an assumed user behaviour, not a measurement.** The critical `c*` at which CONFIRM matches MASK is `1 - (mask_intact - allow_intact) / warn_intact`.
- **One algorithm.** `mask_text` and `normalize_spans` in `evaluation/warn_intervention.py` port `extension/src/redaction.js` line for line. Both are run against the same 12 vectors in `extension/test/fixtures/mask-vectors.json` (including code-point offsets for astral characters, overlap merging and invalid spans).

## Results (scope all: 264 sensitive prompts, 561 gold spans, 238 clean prompts)

Pipeline actions: sensitive prompts ALLOW 92, WARN 63, BLOCK 109; clean prompts ALLOW 227, WARN 10, BLOCK 1. Only the 63 WARN prompts can be changed by WARN+MASK or WARN+CONFIRM. The 92 ALLOW prompts are detector misses (33 of them carry a positive but ALLOWed finding), and the 109 BLOCK prompts are not sent in any arm.

| Measure | plain WARN | WARN+MASK | BLOCK |
|---|---|---|---|
| Sensitive prompts sent | 155/264 = 0.587 [0.527, 0.645] | 155/264 = 0.587 [0.527, 0.645] | 92/264 = 0.348 [0.294, 0.408] |
| Sent with an intact gold span | 155/264 = 0.587 [0.527, 0.645] | 120/264 = 0.455 [0.396, 0.515] | 92/264 = 0.348 [0.294, 0.408] |
| Sent with any unmasked gold character | 155/264 = 0.587 [0.527, 0.645] | 127/264 = 0.481 [0.421, 0.541] | 92/264 = 0.348 [0.294, 0.408] |
| Prevented fraction (intact definition) | 109/264 = 0.413 [0.355, 0.473] | 144/264 = 0.545 [0.485, 0.604] | 172/264 = 0.652 [0.592, 0.706] |
| Gold spans transmitted intact | 277/561 = 0.494 [0.453, 0.535] | 174/561 = 0.310 [0.273, 0.350] | 124/561 = 0.221 [0.189, 0.257] |
| Gold spans removed, among all spans | 0/561 | 92/561 = 0.164 [0.136, 0.197] | 0/561 |
| Gold characters transmitted | 3223/6783 = 0.475 [0.463, 0.487] | 2174/6783 = 0.321 [0.310, 0.332] | 1661/6783 = 0.245 [0.235, 0.255] |
| Sensitive prompts altered | 0/264 | 63/264 = 0.239 [0.191, 0.294] | 0/264 |
| Masked characters outside gold / all masked | 0 | 749/1798 = 0.417 [0.394, 0.440] | 0 |
| Over-masked characters per 1000 sensitive-prompt characters | 0 | 28.4 | 0 |
| Clean prompts altered | 0/238 [0.000, 0.016] | 10/238 = 0.042 [0.023, 0.076] | 0/238 |
| Clean prompts not sent | 1/238 = 0.004 [0.001, 0.023] | 1/238 = 0.004 [0.001, 0.023] | 11/238 = 0.046 [0.026, 0.081] |

Within the 63 sensitive WARN prompts, the prompts sent with an intact gold span are 63/63 [0.943, 1.000] for plain WARN, 28/63 = 0.444 [0.328, 0.567] for WARN+MASK, and 0/63 [0.000, 0.057] for BLOCK.

Paired against plain WARN, MASK removes the intact exposure of 35 prompts and creates none (exact sign test p = 5.8e-11).

### WARN+CONFIRM: analytic bound (not a measurement)

Fraction of the 264 sensitive prompts transmitted with an intact gold span, as a function of the assumed compliance `c`:

| c | 0.0 | 0.1 | 0.2 | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 | 0.8 | 0.9 | 1.0 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Transmitted intact | 0.587 | 0.563 | 0.539 | 0.516 | 0.492 | 0.468 | 0.444 | 0.420 | 0.396 | 0.372 | 0.348 |
| Prevented | 0.413 | 0.437 | 0.461 | 0.484 | 0.508 | 0.532 | 0.556 | 0.580 | 0.604 | 0.628 | 0.652 |

The endpoints are measured (they coincide with plain WARN and BLOCK, with the Wilson intervals above); the interior is analytic. CONFIRM matches WARN+MASK's prevented fraction (0.545) at `c* = 0.556`: below that compliance MASK prevents more, above it CONFIRM prevents more. CONFIRM interrupts 10/238 = 0.042 [0.023, 0.076] of clean prompts, and a user who cancels each warning with probability `c` loses a fraction `0.042 * c` of clean prompts.

### Scope core (251 sensitive prompts, 496 gold spans)

| Measure | plain WARN | WARN+MASK | BLOCK |
|---|---|---|---|
| Sent with an intact gold span | 142/251 = 0.566 [0.504, 0.626] | 101/251 = 0.402 [0.344, 0.464] | 81/251 = 0.323 [0.268, 0.383] |
| Prevented fraction | 109/251 = 0.434 [0.374, 0.496] | 150/251 = 0.598 [0.536, 0.656] | 170/251 = 0.677 [0.617, 0.732] |
| Gold spans transmitted intact | 231/496 = 0.466 [0.422, 0.510] | 133/496 = 0.268 [0.231, 0.309] | 105/496 = 0.212 [0.178, 0.250] |
| Masked characters outside gold / all masked | 0 | 734/1781 = 0.412 [0.389, 0.435] | 0 |

Core-scope MASK sends 20/61 = 0.328 [0.223, 0.453] of WARN prompts with an intact span; the CONFIRM match point is `c* = 0.672`; the paired test gives 41 prompts improved, 0 worsened (p = 9.1e-13).

## Interpretation

1. **The MASK residual is bounded by span recall.** In the 63 WARN prompts the detectors fully cover only 92/153 = 0.601 [0.522, 0.675] of gold spans (0.690 [0.605, 0.765] in core scope) and 1049/1562 = 0.672 of gold characters. What remains after masking is exactly what the detectors miss; 28 of 63 WARN prompts still carry an intact span. MASK cannot touch ALLOW prompts, which hold 92 of the 155 sensitive prompts that leave the browser under plain WARN.
2. **MASK prevents more than plain WARN and costs utility.** It lowers intact-span transmissions from 0.587 to 0.455 of sensitive prompts, but 41.7 % of the masked characters lie outside any gold span, and 10/238 clean prompts are altered. The over-redaction is dominated by the wide regex rules documented in the span-scoring record.
3. **CONFIRM versus MASK depends on user behaviour.** At full compliance CONFIRM equals BLOCK for WARN prompts (prevented 0.652) and beats MASK; below `c* = 0.556` MASK beats it. Neither modifies ALLOW prompts, so all arms are capped by the pipeline's recall: 92/264 sensitive prompts are sent intact in every arm.
4. BLOCK prevents most but also stops 11/238 clean prompts.

## Limitations

- Regex and NER layers only; the semantic layer, and hence the production action mix, was not run. A semantic layer could convert some ALLOW into WARN or BLOCK and change every proportion.
- Development data, not a held-out set. The gold spans come from PIIMB annotation schemes; 65 attribute-only spans have no PriVoke category (see scope `core`).
- The transmission model is offline: it applies the mask algorithm to detector spans and scores character overlap. The browser rewrite is verified by harness tests, not against live ChatGPT, Claude, Gemini or Copilot traffic. Bodies that are form-encoded, multi-part, Blob or nested-JSON envelopes cannot be rewritten and fall back to the original request, and a layer error also falls back (documented extension availability policy); the offline numbers assume the rewrite succeeds.
- A masked prompt changes what the model answers; response quality, user acceptance and task utility were not measured. Over-redaction is a character-level proxy.
- WARN+CONFIRM has no UI and no user study: its numbers are an analytic bound in the compliance rate. It assumes the user's decision is independent of the prompt, and that a cancelled prompt is not retyped elsewhere.
- Prompts from one source document are clustered, so Wilson intervals are slightly narrow. Each prompt is a single turn; no multi-turn leakage was tested.
- The extension option has no popup control: it is set by settings message or storage.

## Reproduce

Host Python, no Docker. In the worktree at the revision below:

```
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/setup-host.py
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/warn_intervention.py extract --gold <dev_spans.jsonl> --out evaluation/results/warn_intervention_20261116/results.json
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/warn_intervention.py rederive paper/research/warn-intervention-20261116.json
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe -m unittest evaluation/tests/test_warn_intervention.py
cd extension && npm test
```

`rederive` recomputes every number from the per-prompt data in the JSON and compares it to the stored scores (output: "rederived scores identical to stored scores"). Extraction output sha256 before the record wrapper was added: `ae4f2784e388faad676b4d0418d748c0296bde894b329a0e39116c75b9f7fe99`. Base revision `742438c`; extension change commit `5d5d234`; measurement code commit `71eeecd`. Environment: Python 3.11.9, spaCy 3.7.5, `en_core_web_sm` 3.7.1.

## Verification

- `npm test` in `extension/`: 155/155 pass (baseline 130; 25 new tests: shared vectors, span collection, body rewriting, masked fetch/XHR/Request handoff, no change for ALLOW and BLOCK, original-request fallback, content-script relay, and default-off settings).
- `python -m unittest evaluation/tests/test_warn_intervention.py`: 16 tests pass, including the shared vectors, hand-computed arm outcomes, the analytic endpoints, and the input-hash refusal.
- Default off: `settings.test.js` asserts `warnMasking === false` by default and for stored settings without the key; `content-script.test.js` and `page-interceptor.test.js` assert that a WARN without spans hands the identical `init` object to native fetch.
