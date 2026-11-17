# Regex rework: labelled identifiers and validator downgrades (development evidence)

Date: 25 Oct 2026. Scope label: **detector-layer** (regex layer and union = regex OR NER, `pipeline.analyse_text(layers=["regex","ner"], regex_first=False)`). This is not LLM-only or semantic-layer evidence and not a full-product result. Machine-readable aggregate: [`regex-rework-20261025.json`](regex-rework-20261025.json).

## Goal and instruction

Owner decision (25 Oct 2026, choice "Rework"): "Rework the regex rules that cost recall (validators that dropped real identifiers, driver-licence gate, child/family) with a general labelled-identifier rule, then test on a new registered draw of fresh positives."

This document covers the first half only: the rework, frozen and measured on development data. The fresh draw is not read, scored or used here. The motivation (a regex-layer union-recall loss concentrated in the Presidio alphanumeric driver-licence pattern, the IBAN and card validators, child/family and the heuristics that depend on them) comes from the owner's summary of the exploratory fresh analysis; the fresh set and that analysis were not opened, so no rule or test was derived from them.

## Changes (code freeze `b7e716c3`)

| Change | Principle |
|---|---|
| `labelled_identifier_sensitive` (S3, IDENTITY) and `labelled_identifier_generic` (S2, IDENTITY), `rules_identifiers.py` | A value of identifier shape introduced by an explicit label noun phrase (`<qualifier> id/number/no./#/code`, `snake_case`/`camelCase`/key-value forms, `Passport:`-style self-labelling documents, `SSN`/`MRN`-style acronyms) is an identifier whatever its format. The label, not a checksum or country pattern, is the evidence. Class sets sensitivity: government, health-insurance and payment qualifiers S3; customer, account, member, employee, user, policy, claim, registration, plate, store-card and reference qualifiers S2. |
| `Downgrade` on `credit_card`, `iban`, `ssn_formatted` (`rule_types.py`, `rule_detector.py`, `rule_validators.py`) | A checksum failure shows the value is not a valid number, not that it is not an identifier. Failed Luhn plus a card word, failed mod-97 plus a banking word, and failed SSN range plus an SSN word stay S3 under `credit_card_unverified`, `iban_unverified`, `ssn_unverified`; a failed IBAN-shaped long number-like token (8+ characters, 5+ digits, a letter) is kept as S2 `unverified_number_identifier`. Short or mostly-letter tokens (`ab12cd`) are still dropped. |
| Driver-licence alphanumeric gate | Unchanged (five digits or a whole-word licence term). A licence/ID value that the gate would have missed is now recovered by the label, not by restoring the weak pattern. |
| `child`, `family_disclosure` | Unchanged. No development row contains a first-person parenthood statement ("I have two kids") or a person-subject age statement that the possessive and `N-year-old <person noun>` cues miss (checked on dev-TUNE and personalized), so no rubric-supported restoration was measurable; restoring bare kin or child nouns would bring back the hits that were attributed to the wrong category. |

Detector input note: spaces between digits are removed by normalisation before the rules run, so a spaced card number reaches the card rule as a single digit run. Because the Presidio US bank-number pattern already flags contiguous 8-17 digit runs (S3), the card downgrade is measurement-neutral on these data; it keeps the correct rule and category, nothing more. A planned unlabelled "card-shaped" S2 tier was dropped for that reason.

## Method

- Source trees: K = this branch at `b7e716c3` (base 42f8f529 + rework); N = 42f8f529 (PR #5 head, exported with `git archive`); O = clean export of e6c177ff (pre-repair, `scratchpad/install/old`). Case-preserving detectors and the NER post-filter are at their defaults for K and N (on) and absent for O, as in the earlier installed-detector study.
- Harness: `evaluate_installed_detectors.py --per-row-dir` (A, `research/wt-a-stats`) for K, N and O on dev, personalized and openai, then `detector_stats.compare_runs` (paired grouped bootstrap, seed 20261024, 10 000 replicates; dev clustered by `group_id`, synthetic sets by row; exact McNemar on discordant pairs). NER is identical for K and N, so K-N isolates the regex change; K-O additionally contains the NER and preprocessing changes since O.
- Splits: dev-TUNE and personalized were the design splits (rules, tests and the fast loop were built on them). dev-CHECK and openai are post-review, not strictly held out: during iteration I looked at aggregate counts on them and at rule names and matched snippets of changed rows, but no rule was added, removed or tuned in response to a dev-CHECK or openai row. `final.jsonl` and every fresh set were never read.
- Fast loop: a regex-only runner reusing cached NER results; its predictions equal the official harness exactly for K, N and O (0 mismatches over 3 502 rows x 3 layers).
- Dataset sha256: dev `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`, personalized `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281`, openai `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b`.
- "Any finding" is the benchmark definition (sensitivity above S0 or a category); WARN-or-BLOCK and BLOCK-only use the runtime policy action from the pipeline's own `strongest_result`.

## Results

Design splits (dev-TUNE, personalized) then post-review splits (dev-CHECK, openai). K-N is the regex change alone; the CI is the paired bootstrap 95% interval on the difference. Where the interval and p are degenerate the effect is one or a few rows; read the counts, not the p-values.

#### dev-TUNE (n=267, positives=148)

| Layer | Decision | O recall (TP/P) | N recall | K recall | O FP/neg | N FP/neg | K FP/neg | K-N d recall [95% CI] | K-N d spec [95% CI] | exact McNemar p (pos; gained/lost) |
|---|---|---|---|---|---|---|---|---|---|---|
| regex | any finding | 0.6486 (96/148) | 0.6419 (95/148) | 0.6486 (96/148) | 4/119 | 2/119 | 2/119 | +0.0068 [+0.0000, +0.0214] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| regex | WARN or BLOCK | 0.5338 (79/148) | 0.5270 (78/148) | 0.5405 (80/148) | 2/119 | 1/119 | 1/119 | +0.0135 [+0.0000, +0.0347] | +0.0000 [+0.0000, +0.0000] | 0.500 (2/0) |
| regex | BLOCK only | 0.3514 (52/148) | 0.3446 (51/148) | 0.3784 (56/148) | 1/119 | 1/119 | 1/119 | +0.0338 [+0.0069, +0.0649] | +0.0000 [+0.0000, +0.0000] | 0.062 (5/0) |
| union | any finding | 0.7635 (113/148) | 0.7973 (118/148) | 0.8041 (119/148) | 6/119 | 6/119 | 6/119 | +0.0068 [+0.0000, +0.0214] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| union | WARN or BLOCK | 0.6554 (97/148) | 0.6622 (98/148) | 0.6689 (99/148) | 2/119 | 5/119 | 5/119 | +0.0068 [+0.0000, +0.0214] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| union | BLOCK only | 0.3514 (52/148) | 0.3446 (51/148) | 0.3784 (56/148) | 1/119 | 1/119 | 1/119 | +0.0338 [+0.0069, +0.0649] | +0.0000 [+0.0000, +0.0000] | 0.062 (5/0) |

#### dev-CHECK (n=235, positives=116)

| Layer | Decision | O recall (TP/P) | N recall | K recall | O FP/neg | N FP/neg | K FP/neg | K-N d recall [95% CI] | K-N d spec [95% CI] | exact McNemar p (pos; gained/lost) |
|---|---|---|---|---|---|---|---|---|---|---|
| regex | any finding | 0.6552 (76/116) | 0.6379 (74/116) | 0.6638 (77/116) | 3/119 | 2/119 | 2/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| regex | WARN or BLOCK | 0.5431 (63/116) | 0.5172 (60/116) | 0.5431 (63/116) | 3/119 | 2/119 | 2/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| regex | BLOCK only | 0.4569 (53/116) | 0.4310 (50/116) | 0.4569 (53/116) | 0/119 | 0/119 | 0/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| union | any finding | 0.6897 (80/116) | 0.7155 (83/116) | 0.7414 (86/116) | 7/119 | 6/119 | 6/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| union | WARN or BLOCK | 0.5862 (68/116) | 0.6034 (70/116) | 0.6293 (73/116) | 4/119 | 6/119 | 6/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| union | BLOCK only | 0.4569 (53/116) | 0.4310 (50/116) | 0.4569 (53/116) | 0/119 | 0/119 | 0/119 | +0.0259 [+0.0000, +0.0583] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |

#### personalized (n=2000, positives=1000)

| Layer | Decision | O recall (TP/P) | N recall | K recall | O FP/neg | N FP/neg | K FP/neg | K-N d recall [95% CI] | K-N d spec [95% CI] | exact McNemar p (pos; gained/lost) |
|---|---|---|---|---|---|---|---|---|---|---|
| regex | any finding | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 23/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |
| regex | WARN or BLOCK | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 23/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |
| regex | BLOCK only | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 0/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |
| union | any finding | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 23/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |
| union | WARN or BLOCK | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 23/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |
| union | BLOCK only | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 1.0000 (1000/1000) | 0/1000 | 0/1000 | 0/1000 | +0.0000 [+0.0000, +0.0000] | +0.0000 [+0.0000, +0.0000] | 1.000 (0/0) |

#### openai (n=1000, positives=500)

| Layer | Decision | O recall (TP/P) | N recall | K recall | O FP/neg | N FP/neg | K FP/neg | K-N d recall [95% CI] | K-N d spec [95% CI] | exact McNemar p (pos; gained/lost) |
|---|---|---|---|---|---|---|---|---|---|---|
| regex | any finding | 0.9200 (460/500) | 0.8960 (448/500) | 0.8980 (449/500) | 154/500 | 34/500 | 34/500 | +0.0020 [+0.0000, +0.0063] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| regex | WARN or BLOCK | 0.8960 (448/500) | 0.8780 (439/500) | 0.8800 (440/500) | 95/500 | 34/500 | 34/500 | +0.0020 [+0.0000, +0.0063] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| regex | BLOCK only | 0.7540 (377/500) | 0.7460 (373/500) | 0.7520 (376/500) | 35/500 | 30/500 | 30/500 | +0.0060 [+0.0000, +0.0138] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |
| union | any finding | 0.9420 (471/500) | 0.9180 (459/500) | 0.9200 (460/500) | 157/500 | 37/500 | 37/500 | +0.0020 [+0.0000, +0.0063] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| union | WARN or BLOCK | 0.9120 (456/500) | 0.9000 (450/500) | 0.9020 (451/500) | 100/500 | 34/500 | 34/500 | +0.0020 [+0.0000, +0.0063] | +0.0000 [+0.0000, +0.0000] | 1.000 (1/0) |
| union | BLOCK only | 0.7540 (377/500) | 0.7460 (373/500) | 0.7520 (376/500) | 35/500 | 30/500 | 30/500 | +0.0060 [+0.0000, +0.0138] | +0.0000 [+0.0000, +0.0000] | 0.250 (3/0) |

### Where the flips come from (regex layer, rows)

| Split | K vs N: positives gained (rule) | K vs N: positives lost | K vs N: new FP rows | K vs O: positives lost (rule) |
|---|---|---|---|---|
| dev-TUNE | 1 any finding / 5 BLOCK (`labelled_identifier_sensitive`; the S3 hit also re-enables `concentrated_sensitive_data` on short prompts) | 0 | 0 | 0 any finding / 1 BLOCK (`iban` on an invoice number) |
| dev-CHECK | 3 / 3 (`labelled_identifier_sensitive` x2, `labelled_identifier_generic` x1) | 0 | 0 | 2 (`iban` on a random token and on UK postcodes) / 3 BLOCK (those plus a phone number read as an NHS number) |
| personalized | 0 / 0 | 0 | 0 | 0 |
| openai | 1 / 3 (`labelled_identifier_generic`; `labelled_identifier_sensitive` on VIN-labelled values) | 0 | 0 | 12 (`financial_keyword` on generic "my account/bank" x8, `personal_narrative` x3, `child` on the word student x1) / 4 BLOCK (`child` on the word student) |

The remaining K-O losses are the intended precision repairs, not recall the rework should return.

## False-positive cost

- Zero new false-positive rows in all four splits for K versus N (regex and union, every decision rule). The new rules fire on no negative row in dev (both halves), personalized or openai (checked per rule: `labelled_identifier_*`, `credit_card_unverified`, `iban_unverified`, `unverified_number_identifier`, `ssn_unverified`).
- A separate author-written bank of 42 benign sentences using identifier vocabulary (API docs, schema notes, "tax file number" questions, `License: Apache-2.0`, "member 4417 joined in 2019", build and port numbers) fired a new rule on one sentence: a policy number given as an explicit placeholder example (`HX-0000-DEMO`). Such a placeholder is indistinguishable from a real value by shape.
- Development negatives are few (119 per half, 1 000 templated personalized, 500 openai), so this bounds the cost only on these data. The labelled rules are the main out-of-distribution risk: technical text with `user id 12345`, `reference id abc12345` or `client id` values will fire at S2 (WARN).

## Tests

New `extension/client-runtime/test/test_regex_identifier_rework.py` (14 tests, author-written sentences, both directions, including the earlier false-positive repairs as negatives). Run with the host environment `evaluation/.venv-v1-v3-pipeline`: `test_detector_quality` (26), `test_detector_contract` (18), `test_ner_postfilter` (36), `test_case_preserving_detectors` (11), `test_pipeline` (3), `test_gitleaks_rules` (4) and the new file all pass.

## Limitations and negative results

- The development data hardly contain the lost classes. Personalized is saturated at recall 1.000 for N already (templated, many redundant rules per row). dev-TUNE regex "any finding" moves by one row (95 to 96); the K-N difference is not distinguishable from zero on any "any finding" cell. The BLOCK-only gains (dev-TUNE +5, dev-CHECK +3, openai +3 rows) are the clearest signal, and these are S3 labelled health, licence and VIN identifiers. The size of the rework's effect on the fresh draw is untested here; it is a hypothesis, not a result.
- The IBAN downgrade tiers, the SSN downgrade and the card downgrade each add no flips on development data beyond what labelled identifiers add (dev-TUNE: `unverified_number_identifier` and `credit_card_unverified` fire on rows already positive). They are principle-based; if the fresh draw shows no benefit they can be removed without losing the labelled rule.
- K does not recover unlabelled identifier-like tokens in prose, random tokens, UK postcodes or phone numbers that old rules reported as IBAN/NHS: those are not identifiers by any label and are the cost of the precision repairs.
- Child/family were not changed (see above), so any fresh-set recall they cost is not addressed by this rework.
- K-O union cells also contain NER and preprocessing differences since O and so are not attributable to the regex layer; a few K-O union flips on dev come from NER changes, not regex.

## Next step

Register the fresh draw of positives and the primary analysis (K vs N, regex and union, BLOCK and any-finding) before scoring it once; this document's JSON and the frozen commit are the pre-registered input.
