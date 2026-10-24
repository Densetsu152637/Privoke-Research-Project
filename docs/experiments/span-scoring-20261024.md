# Span-level scoring of regex and NER on development data (2026-10-24)

**Scope: detector layers only (regex, NER, and unions of their spans). This is not LLM-only or semantic evidence and not a full-pipeline measurement. Development data only; no held-out or fresh set was read.**

## Goal and instruction

Prompt-level "any hit" scoring cannot show whether the detectors find the right text. This experiment builds span-level scoring (`evaluation/span_scoring.py`) and applies it to the 502 locked development prompts to compare the old and new detector defaults, and to score the "P4" idea (NER used only to extend regex masking).

User instruction (24 Oct 2026, follow-ups to PR #5, item 3): "Test all of these in parallel and integrate promising ones", with "Ask me before any downloads". No download was needed.

## Method

- **Gold spans**: `evaluation/results/fresh_sets_20261024/dev_spans.jsonl`, the 502 locked development rows re-joined with PIIMB character spans by `evaluation/build_fresh_sets.py dev-spans` (264 prompts with PII, 561 gold spans that never overlap, 238 PII-free prompts). Manifest: 502 joined, 0 not found, 0 text mismatches, 0 label mismatches, 0 ambiguous. Twelve uids occur more than once in the PIIMB file; the builder resolves each by keeping only the PIIMB row whose normalised text equals the locked development text, and refuses the row if the surviving candidates carry different spans. None was refused, so all 12 are resolved by exact text identity and no row was dropped. Gold offsets index the (normalised) locked text, which is the text the detectors received. `dev_spans.jsonl` sha256 on disk `a1aad47080fed04aecb1e82345f4883b869ac97a0c75dd18ba4abde0cb4e41fc` (CRLF, as written on Windows); with CRLF normalised to LF it equals the manifest hash `43e1d382da6b9ae29d6cb6e76ae16876388b430f1476e1ef32bcc107a109a4fe`. Development file sha256 `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`.
- **Predicted spans**: `pipeline.analyse_text(text, layers=["regex","ner"], regex_first=False)` per prompt (explicit layer list, never empty, no semantic layer; host Python `evaluation/.venv-v1-v3-pipeline`, spaCy `en_core_web_sm`; no Docker). Spans are the pipeline's original-text offsets (remapped through `NormalizedText.original_span`). Every positive result (sensitivity != S0 or any category) is a predicted span; there were 0 positive results without a span in either tree. **old** = clean export of `e6c177ff` (byte-identical to `git archive e6c177ff` for `extension/client-runtime/src` and `shared/python`; original regex rules, lowercased detector input, no post-filter). **new** = `fix/regex-fp-reduction` head `e70e3a2e` (case-preserving detectors and NER post-filter on by default; regex precision repairs). Prediction files sha256: old `8c0b12745f5ad063bebff1f9cc137217c80ec0cb55b5d6bb72418ce266f30161`, new `235f7a6b4126c3922345c2bad03dd3197c3dc54149d69a4a8c0473ddb4aad94b`. The regex-fired and NER-fired prompt counts match the earlier prompt-level evaluation (regex 179/173, NER 61/73 for old/new).
- **Span sources**: `regex`, `NER`, `union` (regex spans plus NER spans), and `P4` = regex spans plus NER spans only in prompts where the regex layer fired.
- **Entity matching** (unique predicted `(start, end)` intervals): one-to-one maximum matching under `exact` (identical offsets), `IoU>=0.5` (character IoU) and `overlap` (any shared character). Precision = matches / predicted, recall = matches / gold. `Lenient` drops the one-to-one constraint: precision = share of predicted spans overlapping any gold span, recall = share of gold spans overlapped by any predicted span (the fair view when one NER span covers GIVENNAME + SURNAME gold spans).
- **Character level**: masking recall = gold characters covered by the union of predicted spans / gold characters. Over-masking share = predicted characters outside gold / predicted characters; also reported per 1000 prompt characters. **All mentions masked** = per prompt with gold, every gold span fully covered; **all touched** = every gold span has at least one covered character. "PII-free prompts masked" = prompts without gold that received any predicted span.
- **Label mapping** (`LABEL_FAMILY`, `FAMILY_CATEGORIES` in `span_scoring.py`): PIIMB labels come from different annotation schemes (Nemotron-PII lowercase snake case, ai4privacy UPPERCASE, gretel snake case, presidio-style names), normalised by lowercasing and removing non-alphanumerics, then mapped to 14 families. The 561 gold spans use 83 label strings (76 after normalisation); **0 are unmapped**. Families with a PriVoke detector category: NAME, CONTACT, GOV_ID, ACCOUNT_ID, DOB, TEMPORAL (dates, times) and ORG (the runtime files dates and organisations under IDENTITY at S1), LOCATION, FINANCIAL, HEALTH, POLITICS, RELIGION. Attribute families with **no** PriVoke category: DEMOGRAPHIC (title, gender/sex, age, NRP, language) and OCCUPATION (occupation, education level, employment status); 65 gold spans (11.6 %). Scope `all` scores every gold span; scope `core` treats attribute-only gold as don't-care (removed from gold, predicted spans touching only them dropped, their characters removed from the predicted union). Typed matching requires the predicted PriVoke categories to intersect the gold family's categories; it is indicative only because PriVoke's ten categories are coarser than PIIMB's types.
- **Statistics**: grouped paired bootstrap (clusters = `group_id`, 10 000 resamples, seed 20261024, 95 % percentile CI, shared resamples for the two configurations) via `detector_stats.py`; exact McNemar and a cluster sign test on the per-prompt "all mentions masked" outcome over prompts with gold. dev-TUNE / dev-CHECK are the halves by `sha256(group_id)` parity (as in `compare_ner_postfilter.py`); dev-CHECK is post-review, not held out. Nothing was tuned to these spans: the label mapping was settled from the runtime's rule and NER category tables and the gold label list before any score was computed, and neither tree's rules were touched. The S2+ variant and the per-source breakdown were added after a first look at the span-source counts and are labelled as sensitivity analyses.
- **Reproduce**: `span_scoring.py extract --tree <tree> --gold dev_spans.jsonl --generated <protobuf dir> --label <old|new> --out pred.jsonl`, then `span_scoring.py study --gold dev_spans.jsonl --old pred-old.jsonl --new pred-new.jsonl --out study.json`. Tests: `evaluation/tests/test_span_scoring.py` (30 hand-built cases).
- Aggregates: `span-scoring-20261024.json` (beside this file; per-family, per-category and per-source detail only for all-dev with every finding).

## Headline results

1. **Prompt-level hit rates overstate masking.** On all-dev the new union flags 201 of 264 PII prompts (0.761 any-hit recall, from the earlier prompt-level evaluation) but masks every gold mention in only 107 (0.405) and covers 0.625 of gold characters; regex alone flags 169 (0.640) but masks every mention in 93 (0.352). Even "every gold span at least touched" is only 0.496 for the union.
2. **Old to new changes the picture differently from the prompt-level view.** Regex: overlap precision +0.036 [+0.020, +0.054], overlap recall -0.007 [-0.015, -0.002], character recall -0.008 [-0.018, -0.001], overlap F1 +0.008 [+0.000, +0.016]; two prompts lost "all mentions masked", none gained (McNemar p=0.50). NER: overlap recall +0.041 [+0.013, +0.070] and F1 +0.058 [+0.015, +0.102], but over-masking share +0.163 [+0.015, +0.304] (more person and organisation spans that miss gold). Union: overlap recall +0.052 [+0.025, +0.079], precision +0.033 [+0.001, +0.062], F1 +0.044 [+0.020, +0.067], character recall +0.047 [+0.021, +0.075]; all-mentions-masked 8 gained / 3 lost (p=0.23, not significant). dev-TUNE and dev-CHECK agree in direction for union recall, F1, character recall and all-mentions-masked (CHECK: F1 +0.040 [+0.015, +0.066], character recall +0.044 [+0.007, +0.081]); the union over-masking share differs in sign between the halves (-0.132 and +0.009) with both CIs including 0.
3. **P4 recovers about 40 % of the union's masking gain at lower cost.** New tree, all-dev: character masking recall regex 0.500, P4 0.552, union 0.625. P4 minus regex: +0.052 [+0.031, +0.075] character recall, +0.034 [+0.015, +0.058] all-mentions-masked (9 prompts gained, 0 lost, McNemar p=0.004), over-masked characters per 1k +1.9 [+0.4, +4.0] (60.1 to 62.0), over-masking share -0.016 [-0.028, -0.003], PII-free prompts masked unchanged (4/238). The full union adds a further +0.073 [+0.046, +0.103] character recall and 5 more prompts, at +8.2 [+2.9, +15.3] over-masked characters per 1k and 12/238 PII-free prompts masked. dev-CHECK: P4 minus regex +0.058 [+0.028, +0.095] character recall, 5 gained / 0 lost (p=0.062). Under the old defaults the P4 gain is smaller (+0.029 [+0.014, +0.046]).
4. **Exact precision is low because of boundaries and a few wide rules, not because most findings miss PII.** New regex: exact precision 0.426 and IoU>=0.5 precision 0.549, but lenient precision 0.935. Three wide rules (`concentrated_sensitive_data`, `multiple_identity_fields`, `structured_identity`) account for 82 % of regex characters outside gold in the new tree (old: 85 % for the same three plus a 922-character `personal_narrative` span that the new regex no longer emits; per-span counts, so overlapping spans are counted twice). The old-to-new change in regex over-masking share (-0.078 [-0.214, +0.004]) is therefore dominated by a handful of spans and not distinguishable from zero.
5. **Coverage by entity family** (T5): regex touches 0.91 of contact-detail gold spans, 0.86 of government IDs, 1.00 of dates of birth, 0.76 of financial and 0.80 of health identifiers, but only 0.10 of names and 0.35 of locations. NER touches 0.75 of name spans (only 0.18 exactly, and 0.48 under one-to-one overlap because gold splits GIVENNAME and SURNAME) and 0.30 of locations; it touches no identifier family. The union touches 0.20 of DEMOGRAPHIC and 0.00 of OCCUPATION gold spans, which PriVoke has no category for.

## Tables

All numbers are on development data, scope `all` and every positive finding unless the heading says otherwise. dev-TUNE n=267 (148 with PII), dev-CHECK n=235 (116 with PII). Bracketed intervals are 95 % grouped-bootstrap CIs; * marks an interval excluding 0.

### T1. Entity-level scores, all-dev (502 prompts, 561 gold spans), scope all, every positive finding

| Layer | Config | Pred spans | Exact P / R | IoU>=0.5 P / R | Overlap P / R / F1 | Lenient P / R |
|---|---|---:|---|---|---|---|
| regex | old | 432 | 0.403 / 0.310 | 0.514 / 0.396 | 0.590 / 0.455 / 0.514 | 0.917 / 0.478 |
| regex | new | 401 | 0.426 / 0.305 | 0.549 / 0.392 | 0.626 / 0.447 / 0.522 | 0.935 / 0.471 |
| NER | old | 69 | 0.420 / 0.052 | 0.696 / 0.086 | 0.783 / 0.096 / 0.171 | 0.797 / 0.123 |
| NER | new | 111 | 0.297 / 0.059 | 0.631 / 0.125 | 0.694 / 0.137 / 0.229 | 0.730 / 0.194 |
| regex+NER union | old | 492 | 0.400 / 0.351 | 0.533 / 0.467 | 0.602 / 0.528 / 0.562 | 0.898 / 0.572 |
| regex+NER union | new | 512 | 0.398 / 0.364 | 0.557 / 0.508 | 0.635 / 0.579 / 0.606 | 0.891 / 0.638 |
| P4 (NER only where regex fires) | old | 463 | 0.408 / 0.337 | 0.523 / 0.431 | 0.594 / 0.490 / 0.537 | 0.909 / 0.522 |
| P4 (NER only where regex fires) | new | 447 | 0.423 / 0.337 | 0.562 / 0.447 | 0.642 / 0.512 / 0.569 | 0.928 / 0.545 |

### T2. Character- and prompt-level scores, all-dev, scope all

| Layer | Config | Char masking recall | Over-masking share | Over-masked chars / 1k | All mentions masked (264) | All touched (264) | PII-free prompts masked (238) |
|---|---|---:|---:|---:|---:|---:|---:|
| regex | old | 0.509 | 0.498 | 83.7 | 95 (0.360) | 113 (0.428) | 7 (0.029) |
| regex | new | 0.500 | 0.420 | 60.1 | 93 (0.352) | 111 (0.420) | 4 (0.017) |
| NER | old | 0.108 | 0.138 | 2.9 | 7 (0.027) | 12 (0.045) | 6 (0.025) |
| NER | new | 0.146 | 0.301 | 10.4 | 9 (0.034) | 16 (0.061) | 8 (0.034) |
| regex+NER union | old | 0.578 | 0.472 | 85.8 | 102 (0.386) | 125 (0.473) | 13 (0.055) |
| regex+NER union | new | 0.625 | 0.403 | 70.2 | 107 (0.405) | 131 (0.496) | 12 (0.050) |
| P4 (NER only where regex fires) | old | 0.537 | 0.486 | 84.5 | 99 (0.375) | 119 (0.451) | 7 (0.029) |
| P4 (NER only where regex fires) | new | 0.552 | 0.403 | 62.0 | 102 (0.386) | 121 (0.458) | 4 (0.017) |

### T3. Headline metrics by subset (scope all, every positive finding)

| Subset | Layer | Config | Overlap F1 | IoU>=0.5 F1 | Char masking recall | Over-masking share | All mentions masked |
|---|---|---|---:|---:|---:|---:|---:|
| all-dev (502 / 264 with gold) | regex | old | 0.514 | 0.447 | 0.509 | 0.498 | 95/264 (0.360) |
| all-dev (502 / 264 with gold) | regex | new | 0.522 | 0.457 | 0.500 | 0.420 | 93/264 (0.352) |
| all-dev (502 / 264 with gold) | NER | old | 0.171 | 0.152 | 0.108 | 0.138 | 7/264 (0.027) |
| all-dev (502 / 264 with gold) | NER | new | 0.229 | 0.208 | 0.146 | 0.301 | 9/264 (0.034) |
| all-dev (502 / 264 with gold) | regex+NER union | old | 0.562 | 0.498 | 0.578 | 0.472 | 102/264 (0.386) |
| all-dev (502 / 264 with gold) | regex+NER union | new | 0.606 | 0.531 | 0.625 | 0.403 | 107/264 (0.405) |
| all-dev (502 / 264 with gold) | P4 (NER only where regex fires) | old | 0.537 | 0.473 | 0.537 | 0.486 | 99/264 (0.375) |
| all-dev (502 / 264 with gold) | P4 (NER only where regex fires) | new | 0.569 | 0.498 | 0.552 | 0.403 | 102/264 (0.386) |
| dev-TUNE (267 / 148 with gold) | regex | old | 0.487 | 0.396 | 0.454 | 0.565 | 52/148 (0.351) |
| dev-TUNE (267 / 148 with gold) | regex | new | 0.495 | 0.405 | 0.451 | 0.423 | 52/148 (0.351) |
| dev-TUNE (267 / 148 with gold) | NER | old | 0.201 | 0.189 | 0.109 | 0.141 | 5/148 (0.034) |
| dev-TUNE (267 / 148 with gold) | NER | new | 0.266 | 0.255 | 0.174 | 0.248 | 5/148 (0.034) |
| dev-TUNE (267 / 148 with gold) | regex+NER union | old | 0.555 | 0.475 | 0.543 | 0.526 | 56/148 (0.378) |
| dev-TUNE (267 / 148 with gold) | regex+NER union | new | 0.602 | 0.509 | 0.594 | 0.394 | 58/148 (0.392) |
| dev-TUNE (267 / 148 with gold) | P4 (NER only where regex fires) | old | 0.514 | 0.434 | 0.482 | 0.552 | 54/148 (0.365) |
| dev-TUNE (267 / 148 with gold) | P4 (NER only where regex fires) | new | 0.550 | 0.457 | 0.497 | 0.405 | 56/148 (0.378) |
| dev-CHECK (235 / 116 with gold) | regex | old | 0.544 | 0.505 | 0.572 | 0.414 | 43/116 (0.371) |
| dev-CHECK (235 / 116 with gold) | regex | new | 0.552 | 0.517 | 0.558 | 0.417 | 41/116 (0.353) |
| dev-CHECK (235 / 116 with gold) | NER | old | 0.135 | 0.107 | 0.106 | 0.135 | 2/116 (0.017) |
| dev-CHECK (235 / 116 with gold) | NER | new | 0.182 | 0.149 | 0.113 | 0.379 | 4/116 (0.034) |
| dev-CHECK (235 / 116 with gold) | regex+NER union | old | 0.570 | 0.525 | 0.618 | 0.404 | 46/116 (0.397) |
| dev-CHECK (235 / 116 with gold) | regex+NER union | new | 0.610 | 0.557 | 0.662 | 0.413 | 49/116 (0.422) |
| dev-CHECK (235 / 116 with gold) | P4 (NER only where regex fires) | old | 0.564 | 0.518 | 0.602 | 0.406 | 45/116 (0.388) |
| dev-CHECK (235 / 116 with gold) | P4 (NER only where regex fires) | new | 0.591 | 0.545 | 0.616 | 0.402 | 46/116 (0.397) |

### T4. Paired old -> new deltas (new minus old), 95% grouped bootstrap CI (10 000 resamples of group_id clusters); * = CI excludes 0

| Subset | Layer | Overlap recall | Overlap precision | Overlap F1 | Char masking recall | Over-masking share | All-masked rate | Prompts gained / lost, McNemar p |
|---|---|---|---|---|---|---|---|---|
| all-dev | regex | -0.007 [-0.015, -0.002]* | +0.036 [+0.020, +0.054]* | +0.008 [+0.000, +0.016]* | -0.008 [-0.018, -0.001]* | -0.078 [-0.214, +0.004] | -0.008 [-0.019, +0.000] | 0 / 2, p=0.500 |
| all-dev | NER | +0.041 [+0.013, +0.070]* | -0.089 [-0.234, +0.059] | +0.058 [+0.015, +0.102]* | +0.038 [-0.008, +0.079] | +0.163 [+0.015, +0.304]* | +0.008 [-0.011, +0.027] | 4 / 2, p=0.688 |
| all-dev | regex+NER union | +0.052 [+0.025, +0.079]* | +0.033 [+0.001, +0.062]* | +0.044 [+0.020, +0.067]* | +0.047 [+0.021, +0.075]* | -0.069 [-0.200, +0.029] | +0.019 [-0.004, +0.045] | 8 / 3, p=0.227 |
| dev-TUNE | regex | -0.006 [-0.017, +0.000] | +0.038 [+0.018, +0.062]* | +0.008 [-0.002, +0.019] | -0.004 [-0.010, +0.000] | -0.142 [-0.345, +0.002] | +0.000 [+0.000, +0.000] | 0 / 0, p=1.000 |
| dev-TUNE | NER | +0.049 [+0.006, +0.092]* | -0.118 [-0.322, +0.083] | +0.065 [+0.000, +0.131]* | +0.066 [+0.019, +0.114]* | +0.108 [-0.082, +0.309] | +0.000 [-0.020, +0.020] | 1 / 1, p=1.000 |
| dev-TUNE | regex+NER union | +0.055 [+0.013, +0.098]* | +0.036 [-0.016, +0.078] | +0.047 [+0.009, +0.084]* | +0.050 [+0.012, +0.092]* | -0.132 [-0.327, +0.037] | +0.014 [-0.013, +0.042] | 3 / 1, p=0.625 |
| dev-CHECK | regex | -0.008 [-0.020, +0.000] | +0.033 [+0.011, +0.061]* | +0.008 [-0.003, +0.020] | -0.014 [-0.034, +0.000] | +0.003 [-0.006, +0.012] | -0.017 [-0.044, +0.000] | 0 / 2, p=0.500 |
| dev-CHECK | NER | +0.032 [-0.004, +0.068] | -0.051 [-0.226, +0.154] | +0.047 [-0.009, +0.103] | +0.006 [-0.074, +0.074] | +0.244 [+0.012, +0.430]* | +0.017 [-0.017, +0.054] | 3 / 1, p=0.625 |
| dev-CHECK | regex+NER union | +0.047 [+0.016, +0.081]* | +0.030 [-0.002, +0.062] | +0.040 [+0.015, +0.066]* | +0.044 [+0.007, +0.081]* | +0.009 [-0.017, +0.049] | +0.026 [-0.017, +0.072] | 5 / 2, p=0.453 |

### T5. Gold-span recall by entity family, all-dev (new unless stated). 'Touched' = predicted span overlaps the gold span; char = fraction of the family's gold characters masked

| Family (PriVoke category) | Gold spans | regex touched | NER touched | union touched (old) | union touched (new) | union exact (new) | union char recall (new) |
|---|---:|---:|---:|---:|---:|---:|---:|
| NAME (IDENTITY) | 108 | 0.10 | 0.75 | 0.50 | 0.78 | 0.18 | 0.78 |
| LOCATION (LOCATION) | 80 | 0.35 | 0.30 | 0.44 | 0.56 | 0.23 | 0.51 |
| TEMPORAL (IDENTITY) | 73 | 0.47 | 0.00 | 0.48 | 0.47 | 0.40 | 0.35 |
| CONTACT (IDENTITY) | 70 | 0.91 | 0.00 | 0.91 | 0.91 | 0.70 | 0.90 |
| DEMOGRAPHIC (none) | 51 | 0.14 | 0.06 | 0.14 | 0.20 | 0.04 | 0.21 |
| GOV_ID (IDENTITY) | 42 | 0.86 | 0.00 | 0.88 | 0.86 | 0.62 | 0.78 |
| ACCOUNT_ID (IDENTITY) | 40 | 0.60 | 0.00 | 0.65 | 0.60 | 0.50 | 0.60 |
| FINANCIAL (FINANCIAL) | 29 | 0.76 | 0.00 | 0.79 | 0.76 | 0.66 | 0.87 |
| HEALTH (HEALTH) | 25 | 0.80 | 0.00 | 0.84 | 0.80 | 0.20 | 0.63 |
| DOB (IDENTITY) | 16 | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| OCCUPATION (none) | 14 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |
| ORG (IDENTITY) | 9 | 0.11 | 0.11 | 0.22 | 0.22 | 0.11 | 0.13 |
| POLITICS (POLITICS) | 3 | 0.33 | 0.00 | 0.33 | 0.33 | 0.00 | 0.28 |
| RELIGION (RELIGION) | 1 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 |

### T6. P4: NER spans added to regex spans only in prompts where the regex layer fired (scope all, every positive finding)

| Subset | Tree | Source | Char masking recall | Over-masking share | Over-masked chars / 1k | Overlap F1 | All mentions masked | PII-free prompts masked |
|---|---|---|---:|---:|---:|---:|---:|---:|
| all-dev | old | regex | 0.509 | 0.498 | 83.7 | 0.514 | 95/264 | 7/238 |
| all-dev | old | P4 (NER only where regex fires) | 0.537 | 0.486 | 84.5 | 0.537 | 99/264 | 7/238 |
| all-dev | old | regex+NER union | 0.578 | 0.472 | 85.8 | 0.562 | 102/264 | 13/238 |
| all-dev | new | regex | 0.500 | 0.420 | 60.1 | 0.522 | 93/264 | 4/238 |
| all-dev | new | P4 (NER only where regex fires) | 0.552 | 0.403 | 62.0 | 0.569 | 102/264 | 4/238 |
| all-dev | new | regex+NER union | 0.625 | 0.403 | 70.2 | 0.606 | 107/264 | 12/238 |
| dev-TUNE | old | regex | 0.454 | 0.565 | 98.2 | 0.487 | 52/148 | 4/119 |
| dev-TUNE | old | P4 (NER only where regex fires) | 0.482 | 0.552 | 98.6 | 0.514 | 54/148 | 4/119 |
| dev-TUNE | old | regex+NER union | 0.543 | 0.526 | 100.0 | 0.555 | 56/148 | 6/119 |
| dev-TUNE | new | regex | 0.451 | 0.423 | 54.9 | 0.495 | 52/148 | 2/119 |
| dev-TUNE | new | P4 (NER only where regex fires) | 0.497 | 0.405 | 56.1 | 0.550 | 56/148 | 2/119 |
| dev-TUNE | new | regex+NER union | 0.594 | 0.394 | 64.1 | 0.602 | 58/148 | 6/119 |
| dev-CHECK | old | regex | 0.572 | 0.414 | 67.0 | 0.544 | 43/116 | 3/119 |
| dev-CHECK | old | P4 (NER only where regex fires) | 0.602 | 0.406 | 68.1 | 0.564 | 45/116 | 3/119 |
| dev-CHECK | old | regex+NER union | 0.618 | 0.404 | 69.4 | 0.570 | 46/116 | 7/119 |
| dev-CHECK | new | regex | 0.558 | 0.417 | 66.1 | 0.552 | 41/116 | 2/119 |
| dev-CHECK | new | P4 (NER only where regex fires) | 0.616 | 0.402 | 68.8 | 0.591 | 46/116 | 2/119 |
| dev-CHECK | new | regex+NER union | 0.662 | 0.413 | 77.2 | 0.610 | 49/116 | 6/119 |

### T7. P4 paired deltas (95% grouped bootstrap CI; * excludes 0)

| Subset | Tree | Comparison | Char masking recall | Over-masking share | Over-masked chars / 1k | All-masked rate | Prompts gained / lost, McNemar p |
|---|---|---|---|---|---|---|---|
| all-dev | old | P4 minus regex | +0.029 [+0.014, +0.046]* | -0.011 [-0.019, -0.004]* | +0.8 [+0.1, +1.6]* | +0.015 [+0.004, +0.032]* | 4 / 0, p=0.125 |
| all-dev | old | union minus P4 | +0.041 [+0.023, +0.061]* | -0.014 [-0.024, -0.004]* | +1.3 [+0.5, +2.6]* | +0.011 [+0.000, +0.026] | 3 / 0, p=0.250 |
| all-dev | new | P4 minus regex | +0.052 [+0.031, +0.075]* | -0.016 [-0.028, -0.003]* | +1.9 [+0.4, +4.0]* | +0.034 [+0.015, +0.058]* | 9 / 0, p=0.004 |
| all-dev | new | union minus P4 | +0.073 [+0.046, +0.103]* | -0.000 [-0.023, +0.031] | +8.2 [+2.9, +15.3]* | +0.019 [+0.004, +0.037]* | 5 / 0, p=0.062 |
| dev-TUNE | old | P4 minus regex | +0.027 [+0.011, +0.046]* | -0.013 [-0.023, -0.004]* | +0.4 [+0.0, +1.1] | +0.014 [+0.000, +0.035] | 2 / 0, p=0.500 |
| dev-TUNE | old | union minus P4 | +0.061 [+0.033, +0.096]* | -0.026 [-0.044, -0.008]* | +1.4 [+0.2, +3.5]* | +0.014 [+0.000, +0.035] | 2 / 0, p=0.500 |
| dev-TUNE | new | P4 minus regex | +0.046 [+0.019, +0.077]* | -0.018 [-0.035, -0.001]* | +1.2 [+0.1, +3.2]* | +0.027 [+0.006, +0.056]* | 4 / 0, p=0.125 |
| dev-TUNE | new | union minus P4 | +0.097 [+0.056, +0.144]* | -0.011 [-0.046, +0.041] | +8.0 [+1.6, +18.3]* | +0.014 [+0.000, +0.035] | 2 / 0, p=0.500 |
| dev-CHECK | old | P4 minus regex | +0.030 [+0.008, +0.061]* | -0.008 [-0.019, +0.002] | +1.2 [+0.1, +2.8]* | +0.017 [+0.000, +0.045] | 2 / 0, p=0.500 |
| dev-CHECK | old | union minus P4 | +0.017 [+0.003, +0.035]* | -0.002 [-0.010, +0.005] | +1.3 [+0.3, +2.5]* | +0.009 [+0.000, +0.028] | 1 / 0, p=1.000 |
| dev-CHECK | new | P4 minus regex | +0.058 [+0.028, +0.095]* | -0.014 [-0.031, +0.006] | +2.6 [+0.4, +6.7]* | +0.043 [+0.009, +0.084]* | 5 / 0, p=0.062 |
| dev-CHECK | new | union minus P4 | +0.046 [+0.016, +0.086]* | +0.011 [-0.015, +0.051] | +8.5 [+1.5, +18.7]* | +0.026 [+0.000, +0.059] | 3 / 0, p=0.250 |

### T8. Sensitivity analyses, all-dev: core scope (attribute-only gold ignored) and S2+ findings only

| Variant | Layer | Config | Overlap F1 | Char masking recall | Over-masking share | All mentions masked |
|---|---|---|---:|---:|---:|---:|
| core scope, all findings | regex | old | 0.545 | 0.545 | 0.499 | 97/251 (0.386) |
| core scope, all findings | regex | new | 0.555 | 0.536 | 0.421 | 95/251 (0.378) |
| core scope, all findings | NER | old | 0.191 | 0.116 | 0.138 | 10/251 (0.040) |
| core scope, all findings | NER | new | 0.248 | 0.153 | 0.306 | 12/251 (0.048) |
| core scope, all findings | regex+NER union | old | 0.595 | 0.620 | 0.473 | 108/251 (0.430) |
| core scope, all findings | regex+NER union | new | 0.636 | 0.667 | 0.405 | 114/251 (0.454) |
| core scope, all findings | P4 (NER only where regex fires) | old | 0.569 | 0.576 | 0.487 | 102/251 (0.406) |
| core scope, all findings | P4 (NER only where regex fires) | new | 0.601 | 0.591 | 0.405 | 106/251 (0.422) |
| scope all, S2+ findings | regex | old | 0.477 | 0.397 | 0.468 | 72/264 (0.273) |
| scope all, S2+ findings | regex | new | 0.478 | 0.389 | 0.469 | 70/264 (0.265) |
| scope all, S2+ findings | NER | old | 0.144 | 0.077 | 0.121 | 5/264 (0.019) |
| scope all, S2+ findings | NER | new | 0.192 | 0.129 | 0.324 | 9/264 (0.034) |
| scope all, S2+ findings | regex+NER union | old | 0.540 | 0.462 | 0.438 | 76/264 (0.288) |
| scope all, S2+ findings | regex+NER union | new | 0.559 | 0.497 | 0.448 | 78/264 (0.295) |
| scope all, S2+ findings | P4 (NER only where regex fires) | old | 0.503 | 0.421 | 0.457 | 73/264 (0.277) |
| scope all, S2+ findings | P4 (NER only where regex fires) | new | 0.516 | 0.424 | 0.452 | 72/264 (0.273) |
| core scope, S2+ findings | regex | old | 0.511 | 0.425 | 0.470 | 73/251 (0.291) |
| core scope, S2+ findings | regex | new | 0.513 | 0.416 | 0.471 | 71/251 (0.283) |
| core scope, S2+ findings | NER | old | 0.161 | 0.083 | 0.121 | 8/251 (0.032) |
| core scope, S2+ findings | NER | new | 0.207 | 0.135 | 0.330 | 12/251 (0.048) |
| core scope, S2+ findings | regex+NER union | old | 0.578 | 0.495 | 0.439 | 80/251 (0.319) |
| core scope, S2+ findings | regex+NER union | new | 0.591 | 0.529 | 0.451 | 82/251 (0.327) |
| core scope, S2+ findings | P4 (NER only where regex fires) | old | 0.539 | 0.451 | 0.458 | 74/251 (0.295) |
| core scope, S2+ findings | P4 (NER only where regex fires) | new | 0.549 | 0.453 | 0.454 | 73/251 (0.291) |

### T8b. Paired old -> new deltas in the sensitivity variants, all-dev (95% CI)

| Variant | Layer | Overlap F1 | Char masking recall | Over-masking share | All-masked rate | Gained / lost, McNemar p |
|---|---|---|---|---|---|---|
| core scope, all findings | regex | +0.010 [+0.001, +0.019]* | -0.009 [-0.020, -0.001]* | -0.078 [-0.215, +0.004] | -0.008 [-0.020, +0.000] | 0 / 2, p=0.500 |
| core scope, all findings | NER | +0.057 [+0.011, +0.104]* | +0.037 [-0.012, +0.081] | +0.169 [+0.019, +0.310]* | +0.008 [-0.013, +0.031] | 5 / 3, p=0.727 |
| core scope, all findings | regex+NER union | +0.041 [+0.017, +0.065]* | +0.047 [+0.019, +0.076]* | -0.068 [-0.199, +0.030] | +0.024 [-0.004, +0.054] | 10 / 4, p=0.180 |
| scope all, S2+ findings | regex | +0.001 [-0.006, +0.008] | -0.008 [-0.018, -0.001]* | +0.001 [-0.008, +0.008] | -0.008 [-0.019, +0.000] | 0 / 2, p=0.500 |
| scope all, S2+ findings | NER | +0.048 [+0.009, +0.088]* | +0.052 [+0.024, +0.081]* | +0.202 [+0.044, +0.350]* | +0.015 [+0.004, +0.032]* | 4 / 0, p=0.125 |
| scope all, S2+ findings | regex+NER union | +0.019 [-0.006, +0.044] | +0.035 [+0.011, +0.062]* | +0.010 [-0.015, +0.044] | +0.008 [-0.011, +0.027] | 4 / 2, p=0.688 |
| core scope, S2+ findings | regex | +0.002 [-0.006, +0.010] | -0.009 [-0.020, -0.001]* | +0.001 [-0.008, +0.008] | -0.008 [-0.020, +0.000] | 0 / 2, p=0.500 |
| core scope, S2+ findings | NER | +0.046 [+0.005, +0.088]* | +0.052 [+0.023, +0.083]* | +0.209 [+0.049, +0.357]* | +0.016 [+0.000, +0.036] | 5 / 1, p=0.219 |
| core scope, S2+ findings | regex+NER union | +0.014 [-0.012, +0.039] | +0.034 [+0.009, +0.061]* | +0.012 [-0.013, +0.046] | +0.008 [-0.013, +0.031] | 5 / 3, p=0.727 |

### T9. Where predicted characters fall outside gold, all-dev (top regex sources by characters outside gold; NER by label)

| Layer | Config | Source | Spans | Overlapping gold | Chars | Chars outside gold |
|---|---|---|---:|---:|---:|---:|
| regex | old | concentrated_sensitive_data | 39 | 39 | 2413 | 1570 |
| regex | old | personal_narrative | 1 | 0 | 922 | 922 |
| regex | old | multiple_identity_fields | 3 | 3 | 574 | 459 |
| regex | old | structured_identity | 22 | 20 | 546 | 187 |
| regex | old | date_field | 15 | 8 | 178 | 122 |
| regex | new | concentrated_sensitive_data | 38 | 38 | 2384 | 1550 |
| regex | new | multiple_identity_fields | 3 | 3 | 574 | 459 |
| regex | new | structured_identity | 22 | 21 | 560 | 188 |
| regex | new | date_field | 15 | 8 | 178 | 122 |
| regex | new | bank_account | 3 | 3 | 87 | 52 |
| ner | old | PERSON | 39 | 36 | 474 | 47 |
| ner | old | ORG | 19 | 11 | 255 | 45 |
| ner | old | GPE | 10 | 8 | 115 | 21 |
| ner | old | LOC | 1 | 0 | 4 | 4 |
| ner | new | PERSON | 77 | 62 | 995 | 230 |
| ner | new | ORG | 18 | 6 | 227 | 149 |
| ner | new | GPE | 5 | 4 | 61 | 21 |
| ner | new | LOC | 5 | 3 | 46 | 20 |
| ner | new | FAC | 6 | 6 | 87 | 6 |

### T10. Precision by predicted PriVoke category, union, all-dev (new)

| Predicted category | Spans | Overlap any gold | Overlap gold of the same category |
|---|---:|---:|---:|
| IDENTITY | 457 | 0.89 | 0.73 |
| FINANCIAL | 73 | 0.99 | 0.38 |
| LOCATION | 31 | 0.90 | 0.81 |
| HEALTH | 10 | 1.00 | 0.70 |
| POLITICS | 3 | 0.33 | 0.33 |
| THIRD_PARTY | 1 | 0.00 | 0.00 |

## Limitations and negative results

- **Label-scheme mismatch.** PIIMB labels are PII types from heterogeneous source annotators; PriVoke classifies by sensitivity category. The family mapping is a declared judgement (listed in `span_scoring.py`), not ground truth, and the typed scores (T10; `overlap_typed` in the JSON) are only indicative: 38 % of FINANCIAL predictions overlap FINANCIAL gold because the card and bank-account rules also fire on numbers that PIIMB labels as identifiers.
- **Gold is incomplete and inconsistent.** Annotators differ per source dataset (a title label applied to a gender word; occupations labelled in one source and not in another), so unlabelled true PII inflates apparent over-masking and false-positive spans. Recall against attribute labels (DEMOGRAPHIC, OCCUPATION) measures nothing PriVoke aims to detect, which is why scope `core` is reported (T8: the old-to-new conclusions keep their direction).
- **PIIMB span conventions.** Names are split (GIVENNAME and SURNAME, first_name and last_name) while spaCy returns the full name, so one-to-one exact and overlap scores undercount NER; the lenient and character views are fairer. Dates may include time parts, and addresses are split into street, city, zip and building number in some sources and one span in others. Offsets refer to normalised text; any normalisation shift is baked into the gold by the builder.
- **Every positive finding counts as a mask.** The runtime applies policy actions by sensitivity, and weak S1 findings (presidio date and low-confidence recognisers) would not necessarily be masked. T8 repeats the analysis with S2+ findings only: regex and union character recall fall (new 0.389 and 0.497), the old-to-new union character-recall gain stays positive (+0.035 [+0.011, +0.062]) but its F1 and all-mentions-masked deltas are no longer distinguishable from zero.
- **Small paired counts.** The all-mentions-masked McNemar tests rest on 2 to 11 discordant prompts; only P4-versus-regex for the new tree on all-dev is significant (p=0.004). The bootstrap resamples whole `group_id` clusters; McNemar does not, so the cluster sign test (stored in the JSON) is its conservative companion.
- **dev-CHECK is post-review, not held out**, and the whole development set was used by earlier work, so these numbers are descriptive and not an unbiased estimate. The same harness is to be run once on the fresh sets.
- **Negative results.** The new regex lost a little recall and character masking against old (significant but about 0.01) and masked every mention in two fewer prompts; the new NER trades precision for recall (more spans, over-masking share up 0.163); P4 does not reach the union's masking, and its small over-masked-character cost is statistically distinguishable from zero; no old-to-new all-mentions-masked change is significant for any layer.
- **Not done.** No semantic-layer, full-pipeline or latency evidence; no held-out or fresh data; no rule changes.

## Use on fresh sets (Wave 3)

Provide rows `{id, group_id, text, entities:[{start,end,label}]}` (end exclusive, offsets into `text`), run `extract_predictions(tree, rows, generated)` once per tree, then `run_study(gold_rows, old_preds, new_preds)`, or `score_layer` / `paired_comparison` individually. `load_jsonl` refuses a file named `final.jsonl`. Add any label reported by `unmapped_labels(rows)` to `LABEL_FAMILY` before scoring; unmapped labels fall in the attribute family `UNMAPPED`, which is don't-care in scope `core`.
