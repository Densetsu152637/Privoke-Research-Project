# Input-robustness canonicalisations (default-off flags): evaluation

Scope: **detector-layer only** (regex and spaCy NER; union = regex OR NER). Every prompt goes through
`pipeline.analyse_text(layers=["regex", "ner"], regex_first=False)` with an explicit layer list (never empty, never
semantic); the harness asserts the executed layers. This is not LLM-only or semantic evidence and not a full-product
measurement. No final (held-out) data was touched; nothing was downloaded or installed.

Exact user instruction (24 Oct 2026): "Test all of these in parallel and integrate promising ones" (research follow-ups
to PR #5; this is the robustness-fix round that follows `detector-robustness-20261024.md`) and "Ask me before any
downloads".

## What was implemented (all default OFF)

| Flag | Where | Behaviour |
| --- | --- | --- |
| `PRIVOKE_STRIP_FORMAT_CHARS` | `src/detection/preprocessing.py` | Drops Unicode `Cf` characters (zero-width space/joiner/non-joiner, word joiner, BOM, soft hyphen, bidi marks, tag characters) in `normalize_with_offsets`; the neighbouring cluster's source interval covers them. |
| `PRIVOKE_CANONICALISE_DIGITS` | same | (a) joins a chain of single digits with one repeated separator (`-`: 4+ digits; `.` and `/`: 7+) and nothing else, so grouped numbers, dates, decimals, versions and IPv4 addresses keep their grouping (`1-9-7-3-01-29` -> `1973-01-29`); (b) reads 7+ spelled digit words (`zero`/`oh`/`one`..`nine`, spaces or a hyphen between) as digits, keeping a hyphen as a group separator; counting sequences and runs of mostly `oh` are skipped. |
| `PRIVOKE_CANONICALISE_EMAIL_WORDS` | same | `[dot]`, `(dot)`, ` dot ` -> `.` inside an e-mail-shaped token (local part, at-sign, domain, letters-only final label); ` at ` -> `@` only with a two-letter or common TLD and a local part that is not a function word or an `at`-taking verb. Real addresses and prose are untouched. |
| `PRIVOKE_NER_CASELESS_GATE` | `src/NER/ner_detector.py`, `ner_postfilter.py` | A prompt with no case signal (all lower-case or all upper-case, pronoun "I" ignored) is lower-cased (length-preserving) before spaCy; mixed-case prompts are never changed. `CASELESS_DISABLED_RULES` (empty) is the hook for skipping post-filter rules. |

The three preprocessing flags apply to the case-preserved detector view only (`lowercase=False`); the lowercased
semantic view, semantic training and the reference preprocessing never see them. Consequence: with
`PRIVOKE_CASE_PRESERVING_DETECTORS=0` they have no effect (a later change could pass an explicit option from
`pipeline.py`). Every rewrite maps back to the exact original interval (unit-tested).

## Source and data

- Base `55cbd1e5` (head of `fix/regex-fp-reduction`). **Freeze commit `b1975bc2`** (`feat(detectors): optional input-robustness
  canonicalisations ...`): code, flags and unit tests; every number below was produced from this tree after the freeze.
  Documentation and the evaluation tools are added in later commits that do not change `src/`.
- Datasets (never `final`): `development.jsonl` sha256 `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095` (502 rows, 264
  positive; dev-TUNE 148 pos / 119 neg and dev-CHECK 116 pos / 119 neg by `sha256(group_id)` parity),
  `privoke_personalized_synthetic.jsonl` `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281` (2000 rows, 1000 positive),
  `privoke_openai_synthetic.jsonl` `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b` (1000 rows, 500 positive).
- Perturbations are the seeded, dataset-phrase-free transforms of `evaluation/robustness_probe.py` (branch `research/wt-c-robust`, imported
  read-only): `zero_width`, `digits_space|dot|dash|words`, `email_bracket|paren|word`, `lowercase`, `uppercase`. Positive = any hit with
  sensitivity != S0 or categories (as in `evaluate_installed_detectors.py`).

## Protocol (anti-overfitting)

Design and thresholds were set on **dev-TUNE + personalized** only (clean and perturbed). The code was then frozen and committed. dev-CHECK and
openai were evaluated once after the freeze and are post-review (not strictly held out: earlier rule work used them). dev-CHECK rows
were present in files written during design but were never summarised or inspected; no rule, list or test uses text from any dataset row. Design
choices made on the design sets, all visible in the unit tests:

- single-digit chains: thresholds (4 for `-`, 7 for `.`/`/`) chosen so IPv4 shapes, versions and short numbers stay out (the dotted
  transform mostly produces 4-6 digit chains, which is therefore left alone, see negative results); a chain may sit beside longer groups and
  only the chain is joined (initial version required whole-token chains and recovered only 47% of canonical text on dev-TUNE; this version 92%);
- e-mail ` at `: first version used a short TLD list and missed two country-code TLDs; changed to "any two-letter code or a common TLD";
  a stoplist of function words and `at`-taking verbs for the local part was added after a hand check of prose such as "look at ... dot ...";
- caseless gate: six rule-skipping variants were compared on dev-TUNE + personalized (below); the principled "lower-case only" variant was kept.

## Clean-text side effects

Preprocessing level (no detector): the number of clean rows whose canonical text differs when a flag is on is **0** for every flag on
dev (502), personalized (2000) and openai (1000). Detector level (base vs each of strip, digits, email, caseless and all-on on **unperturbed** text; regex, NER and union; four subsets; per-row
paired flips among positives and among negatives): all 60 cells are `+0/-0`, i.e. clean-text outcomes are identical to base (flip counts are in
the JSON, `comparisons["<fix>|identity|<subset>|<layer>"]`). The caseless gate leaves clean all-lower-case and mixed-case prompts untouched (lower-casing a lower-case prompt is
the identity), and only prompts with no lower-case letters are actually changed: dev has 4 such clean rows and openai has none (30 openai and
23 dev rows lack a case signal, mostly lower-case-only); none changed outcome.

## Results per fix (paired against base on the same perturbed rows)

Cell format: `R base->fix (delta points)`, recall over positives of that subset; `FP base->fix`, false-positive rate over negatives.
`*` = exact two-sided McNemar p < 0.05 on the paired flips (positives for R, negatives for FP; rows are the unit, which is exact for the
synthetic sets and optimistic for dev, whose rows cluster by `group_id`; the JSON also carries grouped-bootstrap 95% CIs and cluster
sign tests from `detector_stats`). Union = regex OR NER. dev-TUNE and personalized are design sets; dev-CHECK and openai are post-review.

### 1. Strip format characters

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| zero_width | R 60.1->79.7 (+19.6)*; FP 5.9->5.0 | R 95.9->100.0 (+4.1)*; FP 19.0->0.0* | R 70.7->71.6 (+0.9); FP 6.7->5.0 | R 84.8->91.8 (+7.0)*; FP 33.2->7.4* |

NER layer only:

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| zero_width | R 20.9->27.7 (+6.8); FP 5.9->3.4 | R 57.1->69.5 (+12.4)*; FP 17.6->0.0* | R 20.7->20.7 (+0.0); FP 5.9->3.4 | R 33.4->17.0 (-16.4)*; FP 29.6->0.6* |

Recall returns to the clean level (dev-TUNE 79.7, personalized 100, openai 91.8) and NER false positives caused by garbled tokens
disappear (personalized union FP 19.0 -> 0.0, openai 33.2 -> 7.4). NER *recall* falls on openai (33.4 -> 17.0) because the base NER "hit"
rows there were garbage tags on split tokens (the study's NER recall inflation artefact); the union recall rises. dev-CHECK shows the
smallest effect (base loses only 0.9 there, as in the study).

### 2. Canonicalise digits (grouping-preserving)

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| digits_dash | R 58.1->79.7 (+21.6)*; FP 4.2->5.0 | R 98.7->100.0 (+1.3)*; FP 0.0->0.0 | R 50.9->71.6 (+20.7)*; FP 4.2->5.0 | R 63.2->90.8 (+27.6)*; FP 7.4->7.4 |
| digits_words | R 61.5->80.4 (+18.9)*; FP 4.2->5.0 | R 89.4->100.0 (+10.6)*; FP 0.0->2.4* | R 50.0->72.4 (+22.4)*; FP 4.2->5.0 | R 66.0->89.2 (+23.2)*; FP 7.4->7.4 |
| digits_dot | R 86.5->86.5 (+0.0); FP 6.7->6.7 | R 100.0->100.0 (+0.0); FP 2.4->2.4 | R 79.3->79.3 (+0.0); FP 6.7->6.7 | R 92.4->92.4 (+0.0); FP 7.4->7.4 |
| digits_space | R 79.7->79.7 (+0.0); FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 71.6->71.6 (+0.0); FP 5.0->5.0 | R 91.8->91.8 (+0.0); FP 7.4->7.4 |

Regex layer only:

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| digits_dash | R 39.9->64.9 (+25.0)*; FP 0.8->1.7 | R 91.5->100.0 (+8.5)*; FP 0.0->0.0 | R 41.4->63.8 (+22.4)*; FP 0.8->1.7 | R 55.2->88.0 (+32.8)*; FP 6.8->6.8 |
| digits_words | R 43.9->67.6 (+23.6)*; FP 0.8->1.7 | R 75.9->100.0 (+24.1)*; FP 0.0->2.4* | R 37.9->65.5 (+27.6)*; FP 0.8->1.7 | R 58.6->86.8 (+28.2)*; FP 6.8->6.8 |

Dash-split and spelled digits are recovered to within about 3 points of the clean level on every subset (dev-TUNE 79.7 and 80.4 against 79.7 clean; openai
63.2 -> 90.8 and 66.0 -> 89.2 against 91.8 clean). `digits_dot` shows **no change by design** (the dotted transform mostly yields chains of 4-6 digits, below the 7-digit
threshold needed to keep IPv4 addresses and versions safe; the earlier "gain" under dotted digits in the study was a spurious IP-rule hit).
`digits_space` was already neutralised by the shipped collapse.

False positives: the only increase is **personalized spelled digits, 0.0 -> 2.4% (+24 negatives)**. All 24 are one fixed template that asks for
the *format* of a US phone number with the placeholder `555-0100` spelled out; the 7-word run becomes the 7-digit string `5550100`, which
the (separately owned) "very weak" 7-digit rule flags, exactly as it flags the same string typed without a dash on clean text
(`555-0100` itself is not flagged). The spelled form carries no grouping to preserve, so no grouping-preserving rule can avoid it; the dev
FP changes (+1 row in each half) are the fixed text restoring the clean outcome (the clean text of both rows is already a false positive).
Ablation (post hoc, not selected on; `--spelled-min 8`): requiring 8 spelled digits removes the 24 personalized FPs and keeps personalized
recall 100, but costs recall elsewhere:

| spelled-run minimum | dev-TUNE R / FP | dev-CHECK R / FP | personalized R / FP | openai R / FP |
|---|---|---|---|---|
| none (base) | 61.5 / 4.2 | 50.0 / 4.2 | 89.4 / 0.0 | 66.0 / 7.4 |
| 7 words (frozen default) | 80.4 / 5.0 | 72.4 / 5.0 | 100.0 / 2.4 | 89.2 / 7.4 |
| 8 words (ablation) | 79.1 / 5.0 | 68.1 / 4.2 | 100.0 / 0.0 | 86.8 / 7.4 |

### 3. E-mail word spellings

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| email_bracket | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |
| email_paren | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |
| email_word | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |

All three e-mail spellings recover dev recall to the clean level (dev-CHECK 62.1 -> 71.6, p < 0.001 after freeze), with zero FP change and
no effect on the synthetic sets (their e-mails are structurally caught). Preprocessing-level check: the canonical perturbed text equals the
canonical clean text for 19/19 changed dev-TUNE rows, 369/369 personalized and 22/22 openai rows.

### 4. NER caseless gate

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| uppercase | R 68.9->73.6 (+4.7); FP 6.7->1.7* | R 100.0->100.0 (+0.0); FP 2.0->0.0* | R 68.1->66.4 (-1.7); FP 3.4->2.5 | R 91.0->91.4 (+0.4); FP 11.0->7.4* |
| lowercase | R 73.6->73.6 (+0.0); FP 1.7->1.7 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 66.4->66.4 (+0.0); FP 2.5->2.5 | R 91.4->91.4 (+0.0); FP 7.4->7.4 |

NER layer only:

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| uppercase | R 10.1->14.9 (+4.7); FP 5.0->0.0* | R 20.5->55.5 (+35.0)*; FP 2.0->0.0* | R 10.3->9.5 (-0.9); FP 1.7->0.8 | R 10.4->12.8 (+2.4); FP 4.6->0.6* |
| lowercase | R 14.9->14.9 (+0.0); FP 0.0->0.0 | R 55.5->55.5 (+0.0); FP 0.0->0.0 | R 9.5->9.5 (+0.0); FP 0.8->0.8 | R 12.8->12.8 (+0.0); FP 0.6->0.6 |

The gate fixes **all-caps** prompts: NER recall returns to its lower-case level (personalized 20.5 -> 55.5) and the garbage-entity false
positives of upper-case text disappear (openai union FP 11.0 -> 7.4, personalized 2.0 -> 0.0). It is a no-op on all-lower-case prompts
(lowercase column: identical outcomes), so it does **not** restore the old pipeline's lower-case NER recall (old, from the
robustness study: 20.8 on whole dev / 80.0 personalized; now 14.9 on dev-TUNE / 55.5 personalized): that loss comes from the post-filter's non-case rules (lone place/organisation, weak person),
not from case. dev-CHECK uppercase shows a small non-significant union recall decrease (-1.7, +1/-3 rows) against a -0.9 FP change.

Design-set comparison of rule-skipping variants in caseless mode (NER layer, `recall / FP`, dev-TUNE and personalized; tuning-phase run
with the same gate code; "lower-case only" is the frozen default):

| caseless-mode rules skipped | lowercase dev-TUNE | lowercase personalized | uppercase dev-TUNE | clean dev-TUNE NER FP |
|---|---|---|---|---|
| none (gate = lower-case only) | 14.9 / 0.0 | 55.5 / 0.0 | 14.9 / 0.0 | 3.4 |
| `short_acronym`, `structural` | 14.9 / 0.0 | 55.5 / 0.0 | 14.9 / 0.0 | 3.4 |
| + `common_phrase` | 14.9 / 0.0 | 56.8 / 0.0 | 14.9 / 0.0 | 3.4 |
| all span rules (stage 1) | 15.5 / 0.0 | 61.7 / 0.0 | 15.5 / 0.0 | 3.4 |
| `lone_place_org`, `weak_person`, `short_acronym`, `structural` | 19.6 / 1.7 | 68.7 / 0.0 | 19.6 / 1.7 | 4.2 |
| every rule (= no post-filter) | 23.6 / 1.7 | 80.0 / 0.0 | 23.6 / 1.7 | 4.2 |
| base (no gate) | 14.9 / 0.0 | 55.5 / 0.0 | 10.1 / 5.0 | 3.4 |

Skipping the combination rules buys NER recall (up to the old pipeline's level) at a false-positive cost on dev-TUNE negatives (union FP
1.7 -> 3.4, i.e. two rows of 119) and on clean text with no case signal (NER FP 3.4 -> 4.2). That is a precision trade, not a case
effect, so it is not enabled; the case-dependent rules (title-case heading, pluralised capital run) are inert on lower-cased text anyway.

### All four flags together

| condition | dev-TUNE | personalized | dev-CHECK | openai |
|---|---|---|---|---|
| zero_width | R 60.1->79.7 (+19.6)*; FP 5.9->5.0 | R 95.9->100.0 (+4.1)*; FP 19.0->0.0* | R 70.7->71.6 (+0.9); FP 6.7->5.0 | R 84.8->91.8 (+7.0)*; FP 33.2->7.4* |
| digits_dash | R 58.1->79.7 (+21.6)*; FP 4.2->5.0 | R 98.7->100.0 (+1.3)*; FP 0.0->0.0 | R 50.9->71.6 (+20.7)*; FP 4.2->5.0 | R 63.2->90.8 (+27.6)*; FP 7.4->7.4 |
| digits_words | R 61.5->80.4 (+18.9)*; FP 4.2->5.0 | R 89.4->100.0 (+10.6)*; FP 0.0->2.4* | R 50.0->72.4 (+22.4)*; FP 4.2->5.0 | R 66.0->89.2 (+23.2)*; FP 7.4->7.4 |
| digits_dot | R 86.5->86.5 (+0.0); FP 6.7->6.7 | R 100.0->100.0 (+0.0); FP 2.4->2.4 | R 79.3->79.3 (+0.0); FP 6.7->6.7 | R 92.4->92.4 (+0.0); FP 7.4->7.4 |
| digits_space | R 79.7->79.7 (+0.0); FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 71.6->71.6 (+0.0); FP 5.0->5.0 | R 91.8->91.8 (+0.0); FP 7.4->7.4 |
| email_bracket | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |
| email_paren | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |
| email_word | R 75.7->79.7 (+4.1)*; FP 5.0->5.0 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 62.1->71.6 (+9.5)*; FP 5.0->5.0 | R 91.6->91.8 (+0.2); FP 7.4->7.4 |
| uppercase | R 68.9->73.6 (+4.7); FP 6.7->1.7* | R 100.0->100.0 (+0.0); FP 2.0->0.0* | R 68.1->66.4 (-1.7); FP 3.4->2.5 | R 91.0->91.4 (+0.4); FP 11.0->7.4* |
| lowercase | R 73.6->73.6 (+0.0); FP 1.7->1.7 | R 100.0->100.0 (+0.0); FP 0.0->0.0 | R 66.4->66.4 (+0.0); FP 2.5->2.5 | R 91.4->91.4 (+0.0); FP 7.4->7.4 |

All-on results equal the per-fix results in every cell (the fixes act on disjoint perturbations) and clean-text outcomes are unchanged.

## Limitations and negative results

- Recall counts any positive hit in a row, not a span match; the perturbations are whole-text, seeded, and not adaptive adversaries.
  Fixes that undo exactly the perturbations they were designed for are expected to recover them; this is a consistency check, not a
  robustness guarantee against other obfuscations (homoglyphs, leetspeak labels and fuzzy labels are out of scope this round).
- No clean-text effect was observed, but the clean sets contain very few obfuscation-shaped strings, so FP risk on real traffic is
  bounded by the unit tests (dates, ratios, versions, IPv4, phone/SSN/card groupings, prose with "at"/"dot"), not by these corpora.
- `digits_dot` is not recovered (see above); `digits_words` costs 24 personalized FPs from one placeholder template; an 8-word minimum
  trades them for recall.
- The caseless gate does not recover lower-case NER recall; recovering it needs a precision trade-off in the post-filter that the data
  here cannot justify. One NER backend (`en_core_web_sm`).
- The e-mail ` at ` form uses a function-word/verb stoplist and a TLD rule rather than a classifier; unusual prose could still be rewritten.
- dev-CHECK and openai are post-review sets; the freeze preceded their evaluation, but earlier work used them.
- The fixes apply to the case-preserved detector view only; the semantic layer sees none of them.

## Recommendation (for the fresh held-out scoring in Wave 3)

- Promote: `PRIVOKE_STRIP_FORMAT_CHARS` (large, significant gains on every subset, removes NER garbage false positives, no clean effect) and
  `PRIVOKE_CANONICALISE_EMAIL_WORDS` (restores dev e-mail recall, no FP change), and `PRIVOKE_CANONICALISE_DIGITS` (+19 to +28 union
  recall points on dash/spelled digits) with the disclosed personalized placeholder FP.
- Promote with a note: `PRIVOKE_NER_CASELESS_GATE` helps only all-caps prompts; it is harmless otherwise and fixes a clear bug-shaped
  asymmetry (upper-case NER worse than lower-case).
- All four are default-off now; enabling them by default is a separate decision after the held-out check.

## Reproduction

Tools (committed beside this file in `robustness-fixes-20261024-tools/`; they import the probe and statistics modules read-only from the
sibling research worktrees and use the host Python environment):

```
python robust_eval.py --tree <worktree> --config base|strip|digits|email|caseless|all --splits dev personalized openai \
    --conditions identity zero_width digits_dash ... --out <dir>      # per-row JSONL in the evaluate_installed_detectors format
python analyze.py <dir> robustness-fixes-20261024.json 3000        # detector_stats paired McNemar / grouped bootstrap
python render.py robustness-fixes-20261024.json union all           # tables
python clean_effect.py 7 0 ; python inv.py <transform> dev 0         # preprocessing-level checks
```
Unit tests: `python -m unittest discover -s extension/client-runtime/test -p test_robustness_fixes.py` (35 tests, synthetic strings only).
Per-row files are in the scratch directory and not committed; the JSON holds the aggregates, flips and tests.
