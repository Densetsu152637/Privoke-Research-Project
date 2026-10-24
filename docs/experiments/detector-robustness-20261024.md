# Detector-layer robustness to input perturbations (old vs new defaults)

Scope: **detector-layer only** (regex and spaCy NER; union = regex OR NER). Every prompt goes through
`pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)` with an explicit layer list (never empty, never semantic);
the harness asserts the executed layers. This is not LLM-only or semantic evidence and not a full-product measurement.

Exact user instruction (24 Oct 2026): "Test all of these in parallel and integrate promising ones" (research follow-ups to PR #5;
this is item 6, robustness) and "Ask me before any downloads". No downloads or installs were made.

## Method

- **old** = clean export of `e6c177ff` (original regex rules, lowercased input to every detector, no post-filter; flags absent).
  **new** = base `55cbd1e5` of this branch (precision-repaired regex, case-preserving regex/NER input, NER post-filter; observed
  flags both `true`). Harness: `evaluation/robustness_probe.py` (`run` per tree, `report` merges); mechanics tests:
  `evaluation/tests/test_robustness_probe.py` (15 tests, synthetic strings only).
- Datasets (never `final`): `development.jsonl` sha256 `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`
  (502 rows, 264 positive; whole file plus dev-TUNE and dev-CHECK by `sha256(group_id)` parity),
  `privoke_personalized_synthetic.jsonl` `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281` (2000 rows, 1000 positive),
  `privoke_openai_synthetic.jsonl` `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b` (1000 rows, 500 positive).
- Positive = any hit with sensitivity != S0 or categories (as in `evaluate_installed_detectors.py`). Recall is over positives and FP rate over
  negatives, **after transforming every row**. A row a transform leaves unchanged reuses its unperturbed outcome. Point estimates plus
  Wilson 95% CIs (CIs are in the JSON; a later step reruns with the shared stats module). Differences below about 6 points on dev
  (264 positives) are within noise.
- Transforms are pure, seeded (`sha256(seed 20261024, transform, row id)`) functions with no detector input and no dataset phrases:
  `lowercase`, `uppercase`; `digits_space|dot|dash` (separator between every digit of runs of 4+ digits); `digits_words` (digit groups of
  7+ digits, one `-`/`.`/space allowed between digits, spelled as English words); `email_bracket` (`[at]`+`[dot]`), `email_paren`
  (`(at)`+`(dot)`), `email_word` (` at `+` dot `), `email_bracket_at_only` (`[at]`, real dots); `homoglyph` (30% of eligible Latin letters
  to Cyrillic/Greek lookalikes); `zero_width` (one U+200B/200C/200D/2060/FEFF inside half of the 4+ character tokens);
  `fullwidth_digits`; `label_leet` (ph0ne, e-mail, S.S.N., passw0rd ...) and `label_typo` (adjacent-letter swap) over a generic PII label
  lexicon.
- **Skipped: names-lowercased-only.** The datasets carry no span offsets, so isolating names would need a detector (NER) and be circular.
  The all-lowercase transform bounds it (it lowercases names and everything else).
- The "defence" and "pfoff" variants below are **simulations**: a candidate canonicalisation function applied to the probe input only
  (`candidate_canonicalise` in the probe), and the new tree with `ner_postfilter=false`. No detection rule or source file was changed.

## What the shipped preprocessing already neutralises (`src/detection/preprocessing.py`, `normalize_with_offsets`)

| Transform | Neutralised? | Evidence (new tree) |
|---|---|---|
| digits_space | yes (digit-space collapse) | 0.0 change in every cell |
| fullwidth_digits | yes (NFKC) | 0.0 change in every cell |
| email_bracket_at_only (`[at]`) | yes (`[at]`/`(at)` becomes `@`) | 0.0 change in every cell |
| lowercase / uppercase | regex yes (rules are case-insensitive); **NER no** (case-preserving input) | regex 0.0; NER recall -12.1 / -14.4 on dev |
| e-mail `[dot]`, `(dot)`, ` at `/` dot ` | no (only `[at]`/`(at)` handled) | union recall -6.4 on dev |
| digits_dot, digits_dash, digits_words | no | below |
| zero_width | no (NFKC keeps format characters) | regex -10.6, union -11.4 on dev |
| homoglyph | no (NFKC does not fold confusables) | regex -4.9 dev, -11.6 openai |
| label_leet / label_typo | no | union -2.3 / -2.7 on dev |

## Results (percent; union = regex OR NER; `new (old)`; deltas are in points versus each tree's own unperturbed result)

Full per-layer tables (regex, NER, union; recall and FP; all five groups) are in the appendix and the JSON. Headline rows:

| Transform | Group | Union recall | Delta new / old | Union FP | Regex recall | NER recall |
|---|---|---|---|---|---|---|
| unperturbed | dev | 76.1 (73.1) | | 5.0 (5.5) | 64.0 (65.2) | 24.6 (20.8) |
| unperturbed | openai | 91.8 (94.2) | | 7.4 (31.4) | 89.6 (92.0) | 17.0 (29.0) |
| lowercase | dev | 70.5 (73.1) | -5.7 / 0.0 | 2.1 (5.5) | 64.0 (65.2) | 12.5 (20.8) |
| lowercase | personalized | 100 (100) | 0 / 0 | 0.0 (2.3) | 100 (100) | 55.5 (80.0) |
| uppercase | dev | 68.6 (73.1) | -7.6 / 0.0 | 5.0 (5.5) | 64.0 (65.2) | 10.2 (20.8) |
| uppercase | openai | 91.0 (94.2) | -0.8 / 0.0 | 11.0 (31.4) | 89.6 (92.0) | 10.4 (29.0) |
| digits_dash | dev | 54.9 (56.4) | -21.2 / -16.7 | 4.2 (4.6) | 40.5 (45.8) | 25.4 (21.2) |
| digits_dash | openai | 63.2 (82.6) | -28.6 / -11.6 | 7.4 (31.4) | 55.2 (76.8) | 15.8 (26.4) |
| digits_words | dev | 56.4 (53.8) | -19.7 / -19.3 | 4.2 (4.6) | 41.3 (43.2) | 25.4 (22.0) |
| digits_words | personalized | 89.4 (94.4) | -10.6 / -5.6 | 0.0 (2.3) | 75.9 (75.9) | 69.4 (80.3) |
| digits_words | openai | 66.0 (78.8) | -25.8 / -15.4 | 7.4 (31.4) | 58.6 (75.0) | 18.2 (22.4) |
| email_word (bracket, paren alike) | dev | 69.7 (68.2) | -6.4 / -4.9 | 5.0 (5.5) | 57.2 (58.7) | 25.0 (22.0) |
| zero_width | dev | 64.8 (72.0) | -11.4 / -1.1 | 6.3 (16.8) | 53.4 (55.3) | 20.8 (36.4) |
| zero_width | personalized | 95.9 (99.1) | -4.1 / -0.9 | 19.0 (39.6) | 89.9 (90.3) | 57.1 (74.2) |
| zero_width | openai | 84.8 (93.8) | -7.0 / -0.4 | 33.2 (66.8) | 76.8 (82.6) | 33.4 (67.0) |
| homoglyph | dev | 76.5 (74.6) | +0.4 / +1.5 | 16.4 (17.6) | 59.1 (60.2) | 34.5 (32.6) |
| homoglyph | openai | 86.2 (92.8) | -5.6 / -1.4 | 39.2 (61.4) | 78.0 (82.2) | 43.6 (69.2) |
| label_leet | dev | 73.9 (70.5) | -2.3 / -2.7 | 5.0 (5.5) | 59.1 (61.0) | 25.8 (22.0) |

Key readings:

1. **Digit obfuscation is the largest recall gap.** Dash-split or spelled-out digits cost the new union 20 to 29 points on dev and openai
   (dash on personalized: 1.3; spelled: 10.6). On personalized every SSN/employee-ID row, every bank-account/phone row and every
   API-key/password row loses its regex hit under spelled digits, and every SSN row under dashes. NER does not compensate. On openai the
   precision repairs make it **worse than old**: regex recall falls 34.4 points (new) versus 15.2 (old) under dashes and 31.0 versus 17.0
   under spelled digits, because old's looser digit patterns still matched. Digit spacing and full-width digits are fully neutralised
   by the shipped preprocessing. Dotted digits look like a gain (+11.7 regex on dev) only because a dotted digit string matches the
   IP rule: a spurious hit (negative FP also rises 1.7 to 2.4 points).
2. **Zero-width characters cost 11 points of union recall (dev) and inflate NER false positives**: on negatives NER FP goes from 0 to
   17.6% (personalized) and 0.6% to 29.6% (openai) in new; 0 to 38.2% and 1.6% to 59.6% in old. Homoglyphs do likewise (NER FP 24.3%
   personalized, 37.4% openai in new). NER recall "increases" under these transforms are not real detections: garbled tokens are tagged
   as entities, which is why FP rises in lockstep. Case preservation plus the post-filter roughly halves this noise relative to old.
3. **Caseless input removes the NER layer's benefit and makes it worse than old.** Old lowercases everything and is invariant by
   construction. New's NER on all-lowercase text falls to 12.5% recall on dev (old 20.8) and 55.5% on personalized (old 80.0); on all-caps
   to 10.2% dev and 20.5% personalized (with 2.0% FP there). Regex is case-insensitive and unaffected. Union loss is 5.7 (lowercase) and
   7.6 points (uppercase) on dev and about 0 on personalized/openai (regex carries those). The post-filter, not case preservation,
   causes the lowercase loss: with the post-filter off, lowercase NER returns to old's numbers (simulation below).
4. **E-mail obfuscation**: the shipped `[at]`/`(at)` handling is half the job; `[dot]`, `(dot)` and ` at `/` dot ` cost 6.4 union points on
   dev (regex 6.8; wide CI) and nothing on the synthetic sets.
5. **Label leetspeak/typos**: small (2 to 3 points union on dev, 1 to 2 on openai); personalized is unaffected because its PII is
   structurally detectable without labels.
6. Old versus new: new keeps its specificity advantage under every perturbation (openai union FP under homoglyph 39.2 vs 61.4, under
   zero-width 33.2 vs 66.8) but loses more recall than old under digit obfuscation, zero-width and caseless input.

## Simulated general fixes (new tree, input-side shim only; not shipped)

`newdef` applies `candidate_canonicalise` (strip Unicode format characters Cf; join chains of single digits separated by `.` or `-`; read
runs of 7+ spelled digits as digits; rewrite ` at `/` dot ` e-mail spellings and `[dot]`/`(dot)`). Its result on unperturbed text is
identical to new in every cell (no side effects on clean text). `newpfoff` is new with `ner_postfilter=false`. Cells: variant (unmodified new).

| Transform | Group | Union recall | Union FP | Regex recall | NER (where noted) |
|---|---|---|---|---|---|
| zero_width + strip Cf | dev | 76.1 (64.8) | 5.0 (6.3) | 64.0 (53.4) | NER FP 3.4 (5.9) |
| zero_width + strip Cf | personalized | 100 (95.9) | 0.0 (19.0) | 100 (89.9) | NER FP 0.0 (17.6) |
| zero_width + strip Cf | openai | 91.8 (84.8) | 7.4 (33.2) | 89.6 (76.8) | NER FP 0.6 (29.6) |
| digits_dash + join digit chains | dev | 72.3 (54.9) | 5.0 (4.2) | 59.8 (40.5) | |
| digits_dash + join digit chains | openai | 80.6 (63.2) | 7.4 (7.4) | 75.4 (55.2) | |
| digits_words + read spelled digits | dev | 76.9 (56.4) | 5.0 (4.2) | 66.7 (41.3) | |
| digits_words + read spelled digits | personalized | 100 (89.4) | 2.4 (0.0) | 100 (75.9) | |
| digits_words + read spelled digits | openai | 89.2 (66.0) | 7.4 (7.4) | 86.8 (58.6) | |
| e-mail spellings rewritten (word/bracket/paren) | dev | 76.1 (69.7) | 5.0 (5.0) | 64.0 (57.2) | |
| lowercase, post-filter off | dev | 72.3 (70.5) | 4.2 (2.1) | 64.0 (64.0) | NER recall 20.8 (12.5), FP 2.5 (0.4) |
| lowercase, post-filter off | personalized | 100 (100) | 0.0 (0.0) | 100 (100) | NER recall 80.0 (55.5), FP 0.0 (0.0) |
| lowercase, post-filter off | openai | 92.6 (91.4) | 8.4 (7.4) | 89.6 (89.6) | NER recall 29.0 (12.8), FP 1.6 (0.6) |
| caseless handled as lowercase vs raw uppercase | dev | 72.3 (68.6) | 4.2 (5.0) | 64.0 (64.0) | NER recall 20.8 (10.2), FP 2.5 (3.4) |
| caseless handled as lowercase vs raw uppercase | openai | 92.6 (91.0) | 8.4 (11.0) | 89.6 (89.6) | NER recall 29.0 (10.4), FP 1.6 (4.6) |
| uppercase, post-filter off, no case gate | dev | 82.6 (68.6) | 35.7 (5.0) | 64.0 (64.0) | NER FP 34.5 (3.4): not a fix |

Caveats: the digit re-reading drops the original grouping, so 24 affected negatives on personalized become regex FPs (0.0 to 2.4%); the
` at `/` dot ` rewrite also rewrites prose of that shape (unit-tested; no FP increase on these sets, which hold few such sentences). The
caseless-as-lowercase row reuses the lowercase post-filter-off run (the lowercase text of an all-caps input is exactly the lowercase
transform's input; regex is case-insensitive). Homoglyph folding needs a confusables table and was not simulated (a hand-made inverse
of the transform's own map would be circular).

## Ranked, general (non-dataset-specific) fixes proposed, not implemented

| Rank | Fix | Where | Expected effect (from the simulations) | Risk / cost |
|---|---|---|---|---|
| 1 | Strip Unicode format characters (category Cf: zero-width, BOM, bidi marks) in `normalize_with_offsets`, keeping the offset map | `src/detection/preprocessing.py` | zero-width union recall 64.8 to 76.1 (dev, equal to clean), NER FP on negatives 17.6 to 0.0 (personalized), 29.6 to 0.6 (openai); no clean-text effect | negligible |
| 2 | Canonicalise digit obfuscation before detection: single-digit chains split by `.`/`-`, runs of 7+ spelled digits; keep the grouping, or let the digit rules also accept ungrouped runs | preprocessing + digit validators | dash: union 54.9 to 72.3 dev, 63.2 to 80.6 openai; spelled: 56.4 to 76.9 dev, 66.0 to 89.2 openai, 89.4 to 100 personalized; recovers new to old's level on openai | grouping loss caused +2.4% FP on 24 personalized negatives; validate on a fresh set |
| 3 | Case-signal gate for NER: when the text has no lowercase (or no uppercase) letters, lowercase it and skip case-dependent post-filter rules (old behaviour) | `src/pipeline.py`, `src/NER/ner_postfilter.py` | lowercase NER recall 12.5 to 20.8 dev, 55.5 to 80.0 personalized, 12.8 to 29.0 openai; all-caps NER 10.2 to 20.8 dev, FP 4.6 to 1.6 openai; union +1.8 (lowercase) to +3.7 (uppercase) dev | NER FP rises to old's level on caseless text (dev 0.4 to 2.5); a truecaser might keep more specificity (untested) |
| 4 | Confusable folding (Cyrillic/Greek/mathematical lookalikes to Latin) before NFKC | preprocessing | not simulated; would remove the NER garbage FP (24 to 37% on negatives under homoglyphs) and the regex loss (-4.9 dev, -11.6 openai) | needs a confusables table (Unicode `confusables.txt` is a download: ask first) or a curated map of about 100 entries |
| 5 | E-mail spellings: `[dot]`, `(dot)`, ` at `/` dot ` inside an e-mail-shaped token | preprocessing | e-mail union recall 69.7 to 76.1 dev (equal to clean) | prose shaped "x at y dot z" is rewritten too |
| 6 | Fuzzy label lexicon (edit distance 1, leet map) for label-anchored rules | regex rule labels | at most the 2 to 3 points seen on dev | more FP surface; lowest priority |

## Limitations and negative results

- Recall counts any positive hit in a row, not a span match: after obfuscation a row can stay positive because another item (a name) is
  still found, so recall deltas understate the loss on the obfuscated item itself, and dotted-digit and garbled-token "gains" are artefacts.
- Transforms act on the whole text, not only on PII, so FP effects mix PII-adjacent and ordinary text; homoglyph/zero-width rates (30%,
  50%) are arbitrary but fixed and seeded. Real adversaries obfuscate selectively; rates scale effects, not their direction.
- Digit transforms leave rows without 4+ (or 7+) digit runs unchanged; dev has 167 (dash) and 110 (words) affected positives
  (`affected` blocks in the JSON).
- dev-TUNE/dev-CHECK, personalized and openai were all used in earlier rule design as `docs/experiments` states; none of these numbers is
  held-out evidence. `final.jsonl` was not touched. The simulations ran once with fixed shims (one regex bug in the shim was fixed by
  unit test before the runs).
- One NER backend (`en_core_web_sm`); results do not generalise to other NER models.
- Negative results: regex and union are insensitive to case (0.0 change) and to digit spacing, full-width digits and `[at]`, so those user
  behaviours are already safe; the dot-separator and homoglyph/zero-width NER recall increases are not improvements.

## Reproduction

```
python evaluation/robustness_probe.py run --tree <tree> --label old|new --data-root <checkout> --generated <protobuf dir> --out <dir>
python evaluation/robustness_probe.py report --old <old files> --new <new files> [--variants <files>] --data-root <checkout> --out-md ... --out-json ...
```
Variants: `run ... --label newdef --defence` and `run ... --label newpfoff --set-flag ner_postfilter=false --transforms identity lowercase uppercase`.
Per-row run files are in the scratch directory, not committed; the JSON holds all aggregates (counts, Wilson CIs, affected-row counts).

## Appendix: full tables (generated by `report`)

#### regex: Recall on positives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 64.0 (65.2) | 64.2 (64.9) | 63.8 (65.5) | 100.0 (100.0) | 89.6 (92.0) |
| lowercase | 64.0 (65.2) d +0.0 / +0.0 | 64.2 (64.9) d +0.0 / +0.0 | 63.8 (65.5) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 89.6 (92.0) d +0.0 / +0.0 |
| uppercase | 64.0 (65.2) d +0.0 / +0.0 | 64.2 (64.9) d +0.0 / +0.0 | 63.8 (65.5) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 89.6 (92.0) d +0.0 / +0.0 |
| digits_space | 64.0 (65.2) d +0.0 / +0.0 | 64.2 (64.9) d +0.0 / +0.0 | 63.8 (65.5) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 89.6 (92.0) d +0.0 / +0.0 |
| digits_dot | 75.8 (76.9) d +11.7 / +11.7 | 77.0 (77.7) d +12.8 / +12.8 | 74.1 (75.9) d +10.3 / +10.3 | 100.0 (100.0) d +0.0 / +0.0 | 90.4 (92.8) d +0.8 / +0.8 |
| digits_dash | 40.5 (45.8) d -23.5 / -19.3 | 39.9 (43.2) d -24.3 / -21.6 | 41.4 (49.1) d -22.4 / -16.4 | 91.5 (91.5) d -8.5 / -8.5 | 55.2 (76.8) d -34.4 / -15.2 |
| digits_words | 41.3 (43.2) d -22.7 / -22.0 | 43.9 (45.3) d -20.3 / -19.6 | 37.9 (40.5) d -25.9 / -25.0 | 75.9 (75.9) d -24.1 / -24.1 | 58.6 (75.0) d -31.0 / -17.0 |
| email_bracket | 57.2 (58.7) d -6.8 / -6.4 | 59.5 (60.8) d -4.7 / -4.1 | 54.3 (56.0) d -9.5 / -9.5 | 100.0 (100.0) d +0.0 / +0.0 | 89.4 (91.8) d -0.2 / -0.2 |
| email_paren | 57.2 (58.7) d -6.8 / -6.4 | 59.5 (60.8) d -4.7 / -4.1 | 54.3 (56.0) d -9.5 / -9.5 | 100.0 (100.0) d +0.0 / +0.0 | 89.4 (91.8) d -0.2 / -0.2 |
| email_word | 57.2 (58.7) d -6.8 / -6.4 | 59.5 (60.8) d -4.7 / -4.1 | 54.3 (56.0) d -9.5 / -9.5 | 100.0 (100.0) d +0.0 / +0.0 | 89.4 (91.8) d -0.2 / -0.2 |
| email_bracket_at_only | 64.0 (65.2) d +0.0 / +0.0 | 64.2 (64.9) d +0.0 / +0.0 | 63.8 (65.5) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 89.6 (92.0) d +0.0 / +0.0 |
| homoglyph | 59.1 (60.2) d -4.9 / -4.9 | 58.8 (60.1) d -5.4 / -4.7 | 59.5 (60.3) d -4.3 / -5.2 | 97.8 (97.8) d -2.2 / -2.2 | 78.0 (82.2) d -11.6 / -9.8 |
| zero_width | 53.4 (55.3) d -10.6 / -9.8 | 48.6 (49.3) d -15.5 / -15.5 | 59.5 (62.9) d -4.3 / -2.6 | 89.9 (90.3) d -10.1 / -9.7 | 76.8 (82.6) d -12.8 / -9.4 |
| fullwidth_digits | 64.0 (65.2) d +0.0 / +0.0 | 64.2 (64.9) d +0.0 / +0.0 | 63.8 (65.5) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 89.6 (92.0) d +0.0 / +0.0 |
| label_leet | 59.1 (61.0) d -4.9 / -4.2 | 57.4 (58.8) d -6.8 / -6.1 | 61.2 (63.8) d -2.6 / -1.7 | 100.0 (100.0) d +0.0 / +0.0 | 88.4 (89.2) d -1.2 / -2.8 |
| label_typo | 59.1 (61.0) d -4.9 / -4.2 | 57.4 (58.8) d -6.8 / -6.1 | 61.2 (63.8) d -2.6 / -1.7 | 100.0 (100.0) d +0.0 / +0.0 | 88.4 (89.8) d -1.2 / -2.2 |

#### regex: FP rate on negatives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 1.7 (2.9) | 1.7 (3.4) | 1.7 (2.5) | 0.0 (2.3) | 6.8 (30.8) |
| lowercase | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| uppercase | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| digits_space | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| digits_dot | 3.4 (4.2) d +1.7 / +1.3 | 3.4 (4.2) d +1.7 / +0.8 | 3.4 (4.2) d +1.7 / +1.7 | 2.4 (4.7) d +2.4 / +2.4 | 6.8 (30.8) d +0.0 / +0.0 |
| digits_dash | 0.8 (2.1) d -0.8 / -0.8 | 0.8 (2.5) d -0.8 / -0.8 | 0.8 (1.7) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| digits_words | 0.8 (2.1) d -0.8 / -0.8 | 0.8 (2.5) d -0.8 / -0.8 | 0.8 (1.7) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| email_bracket | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| email_paren | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| email_word | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| email_bracket_at_only | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| homoglyph | 0.8 (2.1) d -0.8 / -0.8 | 0.8 (2.5) d -0.8 / -0.8 | 0.8 (1.7) d -0.8 / -0.8 | 0.0 (0.5) d +0.0 / -1.8 | 3.0 (22.0) d -3.8 / -8.8 |
| zero_width | 0.4 (2.1) d -1.3 / -0.8 | 0.0 (1.7) d -1.7 / -1.7 | 0.8 (2.5) d -0.8 / +0.0 | 1.8 (3.2) d +1.8 / +0.9 | 5.4 (26.0) d -1.4 / -4.8 |
| fullwidth_digits | 1.7 (2.9) d +0.0 / +0.0 | 1.7 (3.4) d +0.0 / +0.0 | 1.7 (2.5) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (30.8) d +0.0 / +0.0 |
| label_leet | 1.3 (2.5) d -0.4 / -0.4 | 1.7 (3.4) d +0.0 / +0.0 | 0.8 (1.7) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (21.6) d +0.0 / -9.2 |
| label_typo | 1.3 (2.5) d -0.4 / -0.4 | 1.7 (3.4) d +0.0 / +0.0 | 0.8 (1.7) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 6.8 (24.0) d +0.0 / -6.8 |

#### ner: Recall on positives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 24.6 (20.8) | 27.7 (23.6) | 20.7 (17.2) | 69.5 (80.0) | 17.0 (29.0) |
| lowercase | 12.5 (20.8) d -12.1 / +0.0 | 14.9 (23.6) d -12.8 / +0.0 | 9.5 (17.2) d -11.2 / +0.0 | 55.5 (80.0) d -14.0 / +0.0 | 12.8 (29.0) d -4.2 / +0.0 |
| uppercase | 10.2 (20.8) d -14.4 / +0.0 | 10.1 (23.6) d -17.6 / +0.0 | 10.3 (17.2) d -10.3 / +0.0 | 20.5 (80.0) d -49.0 / +0.0 | 10.4 (29.0) d -6.6 / +0.0 |
| digits_space | 24.6 (20.8) d +0.0 / +0.0 | 27.7 (23.6) d +0.0 / +0.0 | 20.7 (17.2) d +0.0 / +0.0 | 69.5 (80.0) d +0.0 / +0.0 | 17.0 (29.0) d +0.0 / +0.0 |
| digits_dot | 25.4 (22.7) d +0.8 / +1.9 | 28.4 (25.7) d +0.7 / +2.0 | 21.6 (19.0) d +0.9 / +1.7 | 69.3 (73.7) d -0.2 / -6.3 | 17.0 (32.6) d +0.0 / +3.6 |
| digits_dash | 25.4 (21.2) d +0.8 / +0.4 | 27.7 (22.3) d +0.0 / -1.4 | 22.4 (19.8) d +1.7 / +2.6 | 69.3 (75.3) d -0.2 / -4.7 | 15.8 (26.4) d -1.2 / -2.6 |
| digits_words | 25.4 (22.0) d +0.8 / +1.1 | 27.7 (23.6) d +0.0 / +0.0 | 22.4 (19.8) d +1.7 / +2.6 | 69.4 (80.3) d -0.1 / +0.3 | 18.2 (22.4) d +1.2 / -6.6 |
| email_bracket | 24.6 (21.6) d +0.0 / +0.8 | 27.7 (25.0) d +0.0 / +1.4 | 20.7 (17.2) d +0.0 / +0.0 | 69.6 (80.1) d +0.1 / +0.1 | 17.0 (28.6) d +0.0 / -0.4 |
| email_paren | 24.6 (21.6) d +0.0 / +0.8 | 27.7 (23.6) d +0.0 / +0.0 | 20.7 (19.0) d +0.0 / +1.7 | 69.5 (80.9) d +0.0 / +0.9 | 17.0 (28.4) d +0.0 / -0.6 |
| email_word | 25.0 (22.0) d +0.4 / +1.1 | 27.7 (26.4) d +0.0 / +2.7 | 21.6 (16.4) d +0.9 / -0.9 | 69.6 (79.3) d +0.1 / -0.7 | 17.0 (29.0) d +0.0 / +0.0 |
| email_bracket_at_only | 24.6 (20.8) d +0.0 / +0.0 | 27.7 (23.6) d +0.0 / +0.0 | 20.7 (17.2) d +0.0 / +0.0 | 69.5 (80.0) d +0.0 / +0.0 | 17.0 (29.0) d +0.0 / +0.0 |
| homoglyph | 34.5 (32.6) d +9.8 / +11.7 | 37.2 (35.1) d +9.5 / +11.5 | 31.0 (29.3) d +10.3 / +12.1 | 71.7 (73.8) d +2.2 / -6.2 | 43.6 (69.2) d +26.6 / +40.2 |
| zero_width | 20.8 (36.4) d -3.8 / +15.5 | 20.9 (39.9) d -6.8 / +16.2 | 20.7 (31.9) d +0.0 / +14.7 | 57.1 (74.2) d -12.4 / -5.8 | 33.4 (67.0) d +16.4 / +38.0 |
| fullwidth_digits | 24.6 (20.8) d +0.0 / +0.0 | 27.7 (23.6) d +0.0 / +0.0 | 20.7 (17.2) d +0.0 / +0.0 | 69.5 (80.0) d +0.0 / +0.0 | 17.0 (29.0) d +0.0 / +0.0 |
| label_leet | 25.8 (22.0) d +1.1 / +1.1 | 28.4 (23.6) d +0.7 / +0.0 | 22.4 (19.8) d +1.7 / +2.6 | 70.7 (79.7) d +1.2 / -0.3 | 16.8 (31.2) d -0.2 / +2.2 |
| label_typo | 27.3 (22.0) d +2.7 / +1.1 | 29.1 (23.6) d +1.4 / +0.0 | 25.0 (19.8) d +4.3 / +2.6 | 69.9 (81.3) d +0.4 / +1.3 | 17.2 (29.4) d +0.2 / +0.4 |

#### ner: FP rate on negatives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 3.4 (2.5) | 3.4 (1.7) | 3.4 (3.4) | 0.0 (0.0) | 0.6 (1.6) |
| lowercase | 0.4 (2.5) d -2.9 / +0.0 | 0.0 (1.7) d -3.4 / +0.0 | 0.8 (3.4) d -2.5 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| uppercase | 3.4 (2.5) d +0.0 / +0.0 | 5.0 (1.7) d +1.7 / +0.0 | 1.7 (3.4) d -1.7 / +0.0 | 2.0 (0.0) d +2.0 / +0.0 | 4.6 (1.6) d +4.0 / +0.0 |
| digits_space | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| digits_dot | 3.8 (2.9) d +0.4 / +0.4 | 4.2 (2.5) d +0.8 / +0.8 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| digits_dash | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| digits_words | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| email_bracket | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| email_paren | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| email_word | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| email_bracket_at_only | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| homoglyph | 15.5 (16.4) d +12.2 / +13.9 | 19.3 (17.6) d +16.0 / +16.0 | 11.8 (15.1) d +8.4 / +11.8 | 24.3 (34.1) d +24.3 / +34.1 | 37.4 (56.6) d +36.8 / +55.0 |
| zero_width | 5.9 (15.1) d +2.5 / +12.6 | 5.9 (15.1) d +2.5 / +13.4 | 5.9 (15.1) d +2.5 / +11.8 | 17.6 (38.2) d +17.6 / +38.2 | 29.6 (59.6) d +29.0 / +58.0 |
| fullwidth_digits | 3.4 (2.5) d +0.0 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 3.4 (3.4) d +0.0 / +0.0 | 0.0 (0.0) d +0.0 / +0.0 | 0.6 (1.6) d +0.0 / +0.0 |
| label_leet | 3.8 (2.9) d +0.4 / +0.4 | 3.4 (1.7) d +0.0 / +0.0 | 4.2 (4.2) d +0.8 / +0.8 | 0.0 (2.4) d +0.0 / +2.4 | 1.6 (3.6) d +1.0 / +2.0 |
| label_typo | 3.8 (2.5) d +0.4 / +0.0 | 3.4 (1.7) d +0.0 / +0.0 | 4.2 (3.4) d +0.8 / +0.0 | 0.0 (2.0) d +0.0 / +2.0 | 2.6 (3.8) d +2.0 / +2.2 |

#### union: Recall on positives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 76.1 (73.1) | 79.7 (76.4) | 71.6 (69.0) | 100.0 (100.0) | 91.8 (94.2) |
| lowercase | 70.5 (73.1) d -5.7 / +0.0 | 73.6 (76.4) d -6.1 / +0.0 | 66.4 (69.0) d -5.2 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 91.4 (94.2) d -0.4 / +0.0 |
| uppercase | 68.6 (73.1) d -7.6 / +0.0 | 68.9 (76.4) d -10.8 / +0.0 | 68.1 (69.0) d -3.4 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 91.0 (94.2) d -0.8 / +0.0 |
| digits_space | 76.1 (73.1) d +0.0 / +0.0 | 79.7 (76.4) d +0.0 / +0.0 | 71.6 (69.0) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 91.8 (94.2) d +0.0 / +0.0 |
| digits_dot | 83.3 (82.6) d +7.2 / +9.5 | 86.5 (85.8) d +6.8 / +9.5 | 79.3 (78.4) d +7.8 / +9.5 | 100.0 (100.0) d +0.0 / +0.0 | 92.4 (94.8) d +0.6 / +0.6 |
| digits_dash | 54.9 (56.4) d -21.2 / -16.7 | 58.1 (57.4) d -21.6 / -18.9 | 50.9 (55.2) d -20.7 / -13.8 | 98.7 (99.1) d -1.3 / -0.9 | 63.2 (82.6) d -28.6 / -11.6 |
| digits_words | 56.4 (53.8) d -19.7 / -19.3 | 61.5 (58.8) d -18.2 / -17.6 | 50.0 (47.4) d -21.6 / -21.6 | 89.4 (94.4) d -10.6 / -5.6 | 66.0 (78.8) d -25.8 / -15.4 |
| email_bracket | 69.7 (68.2) d -6.4 / -4.9 | 75.7 (73.6) d -4.1 / -2.7 | 62.1 (61.2) d -9.5 / -7.8 | 100.0 (100.0) d +0.0 / +0.0 | 91.6 (94.0) d -0.2 / -0.2 |
| email_paren | 69.7 (67.4) d -6.4 / -5.7 | 75.7 (72.3) d -4.1 / -4.1 | 62.1 (61.2) d -9.5 / -7.8 | 100.0 (100.0) d +0.0 / +0.0 | 91.6 (94.0) d -0.2 / -0.2 |
| email_word | 69.7 (68.2) d -6.4 / -4.9 | 75.7 (75.0) d -4.1 / -1.4 | 62.1 (59.5) d -9.5 / -9.5 | 100.0 (100.0) d +0.0 / +0.0 | 91.6 (94.2) d -0.2 / +0.0 |
| email_bracket_at_only | 76.1 (73.1) d +0.0 / +0.0 | 79.7 (76.4) d +0.0 / +0.0 | 71.6 (69.0) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 91.8 (94.2) d +0.0 / +0.0 |
| homoglyph | 76.5 (74.6) d +0.4 / +1.5 | 79.1 (77.0) d -0.7 / +0.7 | 73.3 (71.6) d +1.7 / +2.6 | 98.1 (99.0) d -1.9 / -1.0 | 86.2 (92.8) d -5.6 / -1.4 |
| zero_width | 64.8 (72.0) d -11.4 / -1.1 | 60.1 (70.9) d -19.6 / -5.4 | 70.7 (73.3) d -0.9 / +4.3 | 95.9 (99.1) d -4.1 / -0.9 | 84.8 (93.8) d -7.0 / -0.4 |
| fullwidth_digits | 76.1 (73.1) d +0.0 / +0.0 | 79.7 (76.4) d +0.0 / +0.0 | 71.6 (69.0) d +0.0 / +0.0 | 100.0 (100.0) d +0.0 / +0.0 | 91.8 (94.2) d +0.0 / +0.0 |
| label_leet | 73.9 (70.5) d -2.3 / -2.7 | 77.0 (72.3) d -2.7 / -4.1 | 69.8 (68.1) d -1.7 / -0.9 | 100.0 (100.0) d +0.0 / +0.0 | 90.4 (92.0) d -1.4 / -2.2 |
| label_typo | 73.5 (70.1) d -2.7 / -3.0 | 76.4 (71.6) d -3.4 / -4.7 | 69.8 (68.1) d -1.7 / -0.9 | 100.0 (100.0) d +0.0 / +0.0 | 90.6 (92.6) d -1.2 / -1.6 |

#### union: FP rate on negatives (percent; each cell is `new (old)`; delta in points vs unperturbed `new / old`)

| Transform | dev | dev-TUNE | dev-CHECK | personalized | openai |
|---|---|---|---|---|---|
| identity | 5.0 (5.5) | 5.0 (5.0) | 5.0 (5.9) | 0.0 (2.3) | 7.4 (31.4) |
| lowercase | 2.1 (5.5) d -2.9 / +0.0 | 1.7 (5.0) d -3.4 / +0.0 | 2.5 (5.9) d -2.5 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| uppercase | 5.0 (5.5) d +0.0 / +0.0 | 6.7 (5.0) d +1.7 / +0.0 | 3.4 (5.9) d -1.7 / +0.0 | 2.0 (2.3) d +2.0 / +0.0 | 11.0 (31.4) d +3.6 / +0.0 |
| digits_space | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| digits_dot | 6.7 (6.7) d +1.7 / +1.3 | 6.7 (5.9) d +1.7 / +0.8 | 6.7 (7.6) d +1.7 / +1.7 | 2.4 (4.7) d +2.4 / +2.4 | 7.4 (31.4) d +0.0 / +0.0 |
| digits_dash | 4.2 (4.6) d -0.8 / -0.8 | 4.2 (4.2) d -0.8 / -0.8 | 4.2 (5.0) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| digits_words | 4.2 (4.6) d -0.8 / -0.8 | 4.2 (4.2) d -0.8 / -0.8 | 4.2 (5.0) d -0.8 / -0.8 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| email_bracket | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| email_paren | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| email_word | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| email_bracket_at_only | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| homoglyph | 16.4 (17.6) d +11.3 / +12.2 | 20.2 (19.3) d +15.1 / +14.3 | 12.6 (16.0) d +7.6 / +10.1 | 24.3 (34.3) d +24.3 / +32.0 | 39.2 (61.4) d +31.8 / +30.0 |
| zero_width | 6.3 (16.8) d +1.3 / +11.3 | 5.9 (16.8) d +0.8 / +11.8 | 6.7 (16.8) d +1.7 / +10.9 | 19.0 (39.6) d +19.0 / +37.3 | 33.2 (66.8) d +25.8 / +35.4 |
| fullwidth_digits | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (2.3) d +0.0 / +0.0 | 7.4 (31.4) d +0.0 / +0.0 |
| label_leet | 5.0 (5.5) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.9) d +0.0 / +0.0 | 0.0 (4.7) d +0.0 / +2.4 | 8.4 (24.4) d +1.0 / -7.0 |
| label_typo | 5.0 (5.0) d +0.0 / -0.4 | 5.0 (5.0) d +0.0 / +0.0 | 5.0 (5.0) d +0.0 / -0.8 | 0.0 (4.3) d +0.0 / +2.0 | 9.2 (26.8) d +1.8 / -4.6 |

#### Variant `newdef` versus the unmodified new tree (percent; `variant (new)`)

| Transform | Layer | dev recall | dev FP | personalized recall | personalized FP | openai recall | openai FP |
|---|---|---|---|---|---|---|---|
| digits_dash | regex | 59.8 (40.5) | 1.7 (0.8) | 91.5 (91.5) | 0.0 (0.0) | 75.4 (55.2) | 6.8 (6.8) |
| digits_dash | ner | 25.4 (25.4) | 3.4 (3.4) | 69.5 (69.3) | 0.0 (0.0) | 17.2 (15.8) | 0.6 (0.6) |
| digits_dash | union | 72.3 (54.9) | 5.0 (4.2) | 98.7 (98.7) | 0.0 (0.0) | 80.6 (63.2) | 7.4 (7.4) |
| digits_dot | regex | 66.3 (75.8) | 1.7 (3.4) | 100.0 (100.0) | 2.4 (2.4) | 90.4 (90.4) | 6.8 (6.8) |
| digits_dot | ner | 24.6 (25.4) | 3.4 (3.8) | 69.4 (69.3) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| digits_dot | union | 77.7 (83.3) | 5.0 (6.7) | 100.0 (100.0) | 2.4 (2.4) | 92.4 (92.4) | 7.4 (7.4) |
| digits_space | regex | 64.0 (64.0) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.6) | 6.8 (6.8) |
| digits_space | ner | 24.6 (24.6) | 3.4 (3.4) | 69.5 (69.5) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| digits_space | union | 76.1 (76.1) | 5.0 (5.0) | 100.0 (100.0) | 0.0 (0.0) | 91.8 (91.8) | 7.4 (7.4) |
| digits_words | regex | 66.7 (41.3) | 1.7 (0.8) | 100.0 (75.9) | 2.4 (0.0) | 86.8 (58.6) | 6.8 (6.8) |
| digits_words | ner | 25.4 (25.4) | 3.4 (3.4) | 69.5 (69.4) | 0.0 (0.0) | 19.0 (18.2) | 0.6 (0.6) |
| digits_words | union | 76.9 (56.4) | 5.0 (4.2) | 100.0 (89.4) | 2.4 (0.0) | 89.2 (66.0) | 7.4 (7.4) |
| email_bracket | regex | 64.0 (57.2) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.4) | 6.8 (6.8) |
| email_bracket | ner | 24.6 (24.6) | 3.4 (3.4) | 69.5 (69.6) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| email_bracket | union | 76.1 (69.7) | 5.0 (5.0) | 100.0 (100.0) | 0.0 (0.0) | 91.8 (91.6) | 7.4 (7.4) |
| email_paren | regex | 64.0 (57.2) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.4) | 6.8 (6.8) |
| email_paren | ner | 24.6 (24.6) | 3.4 (3.4) | 69.5 (69.5) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| email_paren | union | 76.1 (69.7) | 5.0 (5.0) | 100.0 (100.0) | 0.0 (0.0) | 91.8 (91.6) | 7.4 (7.4) |
| email_word | regex | 64.0 (57.2) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.4) | 6.8 (6.8) |
| email_word | ner | 24.6 (25.0) | 3.4 (3.4) | 69.5 (69.6) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| email_word | union | 76.1 (69.7) | 5.0 (5.0) | 100.0 (100.0) | 0.0 (0.0) | 91.8 (91.6) | 7.4 (7.4) |
| identity | regex | 64.0 (64.0) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.6) | 6.8 (6.8) |
| identity | ner | 24.6 (24.6) | 3.4 (3.4) | 69.5 (69.5) | 0.0 (0.0) | 17.0 (17.0) | 0.6 (0.6) |
| identity | union | 76.1 (76.1) | 5.0 (5.0) | 100.0 (100.0) | 0.0 (0.0) | 91.8 (91.8) | 7.4 (7.4) |
| zero_width | regex | 64.0 (53.4) | 1.7 (0.4) | 100.0 (89.9) | 0.0 (1.8) | 89.6 (76.8) | 6.8 (5.4) |
| zero_width | ner | 24.6 (20.8) | 3.4 (5.9) | 69.5 (57.1) | 0.0 (17.6) | 17.0 (33.4) | 0.6 (29.6) |
| zero_width | union | 76.1 (64.8) | 5.0 (6.3) | 100.0 (95.9) | 0.0 (19.0) | 91.8 (84.8) | 7.4 (33.2) |

#### Variant `newpfoff` versus the unmodified new tree (percent; `variant (new)`)

| Transform | Layer | dev recall | dev FP | personalized recall | personalized FP | openai recall | openai FP |
|---|---|---|---|---|---|---|---|
| identity | regex | 64.0 (64.0) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.6) | 6.8 (6.8) |
| identity | ner | 45.8 (24.6) | 15.5 (3.4) | 87.1 (69.5) | 8.1 (0.0) | 48.2 (17.0) | 13.2 (0.6) |
| identity | union | 84.1 (76.1) | 17.2 (5.0) | 100.0 (100.0) | 8.1 (0.0) | 94.2 (91.8) | 18.6 (7.4) |
| lowercase | regex | 64.0 (64.0) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.6) | 6.8 (6.8) |
| lowercase | ner | 20.8 (12.5) | 2.5 (0.4) | 80.0 (55.5) | 0.0 (0.0) | 29.0 (12.8) | 1.6 (0.6) |
| lowercase | union | 72.3 (70.5) | 4.2 (2.1) | 100.0 (100.0) | 0.0 (0.0) | 92.6 (91.4) | 8.4 (7.4) |
| uppercase | regex | 64.0 (64.0) | 1.7 (1.7) | 100.0 (100.0) | 0.0 (0.0) | 89.6 (89.6) | 6.8 (6.8) |
| uppercase | ner | 48.9 (10.2) | 34.5 (3.4) | 74.5 (20.5) | 14.8 (2.0) | 62.6 (10.4) | 49.8 (4.6) |
| uppercase | union | 82.6 (68.6) | 35.7 (5.0) | 100.0 (100.0) | 14.8 (2.0) | 95.2 (91.0) | 52.6 (11.0) |
