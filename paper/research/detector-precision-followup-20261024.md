# Detector precision follow-up: paired uncertainty, action-level repair and full-product rerun

**Record:** DETPREC-FOLLOWUP-20261024. **Date opened:** 24 October 2026. **Status:** results recorded (task `paper-4`, same day). **Paper input:** branch `docs/paper` at `98795606`. **Extends:** [DETPREC-20261024](detector-precision-20261024.md); that record is not overwritten. **Scope:** evidence units 1, 2 and 8 of [REWRITE_SCOPE](../REWRITE_SCOPE.md#authorized-follow-up-integration-24-october-2026). Nothing here is a semantic-only or LLM-only result.

## Goal and exact prompt

Integrate three settled follow-up findings on the installed detector configuration into the paper without changing any retained number. The user's instruction of 24 October 2026, verbatim as recorded in both source documents:

> Test all of these in parallel and integrate promising ones

The product-rerun record additionally quotes the user as including "the full-product rerun" in the authorization; the uncertainty record quotes the instruction together with "a one-time authorized re-derivation of per-row results for the two frozen configurations on the held-out final file". The paper task prompt (root, 24 October 2026) assigned `paper-4` as the documentation half; all numbers below were produced by the cited source tasks, none by the documentation task.

## Sources and revisions

| Finding | Branch | Commit | Document |
| --- | --- | --- | --- |
| Paired uncertainty for the detector layers | `research/wt-a-stats` | `bf5e24c1` (tooling `b1a5885e`) | `docs/experiments/detector-uncertainty-20261024.md` and `.json` |
| Full-product rerun of units 1 and 2 | `research/wt-h-product` | `91b4ee83` | `docs/experiments/product-rerun-20261024.md` and `.json` |
| `student_id` S3 IDENTITY rule | `fix/regex-fp-reduction` (PR #5) | `e70e3a2e3910b9e4833188cec711d0edb6d99583` | commit message and `docs/detectors/regex.md` |

Both experiment branches build on `55cbd1e5` (the detector defaults; its `test(smoke)` commit is the shared parent). Source worktrees: `D:/Git-Worktrees/Privoke-Research-Project/wt-a-stats` and `.../wt-h-product`. "New" in both experiments is `55cbd1e5`, which does not include the `student_id` rule. "Old" is a clean export of `e6c177ff`.

## 1. Paired uncertainty (detector layers only)

Method (source record): per-row outcomes for old and new on dev, dev-TUNE, dev-CHECK, personalized, openai and the held-out final (`--per-row-dir`, hashed ids for the final); exact two-sided McNemar on discordant rows (positives and negatives separately); seeded grouped paired percentile bootstrap (10,000 replicates, seed 20261024; dev and final cluster by source `group_id`, synthetic sets by row, with a conservative scenario-cluster sensitivity of 20 and 10 clusters); cluster-level exact sign test; cost-weighted error at FN:FP 2, 4, 9. Layers `["regex","ner"]`, `regex_first=False`, explicit selection, no semantic layer, no Docker. Re-derived confusion counts equal [DETPREC-20261024](detector-precision-20261024.md) exactly and dataset hashes match. No multiplicity correction; exploratory.

Held-out final (498 rows, 236 positive), gained/lost = rows newly correct/newly incorrect under the new configuration:

| Layer and measure | Estimate old to new | Gained / lost | Exact McNemar p | 95% CI of the difference |
| --- | --- | --- | --- | --- |
| Regex specificity | .985 to .996 | 3 / 0 | 0.25 | [0.000, 0.026] |
| Regex recall | .653 to .640 | 0 / 3 | 0.25 | [-0.029, 0.000] |
| Union recall | .767 to .763 | 13 / 14 | 1.0 | [-0.047, 0.039] |
| Union specificity | .958 to .962 | 7 / 6 | 1.0 | [-0.023, 0.031] |
| Union F2 | .797 to .794 | | | [-0.040, 0.035] |
| NER recall | .237 to .212 | 23 / 29 | 0.488 | [-0.084, 0.036] |
| NER specificity | .973 to .966 | 4 / 6 | 0.754 | [-0.031, 0.015] |

Other splits (gained / lost, exact p): dev regex specificity 3 / 0 (0.25), dev regex recall 0 / 3 (0.25); dev union recall .731 to .761, 12 / 4 (0.077, cluster sign test 0.077; the percentile interval [0.004, 0.061] only just excludes zero and is optimistic at these counts); dev NER recall 26 / 16 (0.164). Personalized regex specificity 23 / 0 (< 0.001; scenario-cluster interval [0.000, 0.073] touches zero); personalized NER recall .800 to .695, 52 / 157 (< 0.001). OpenAI regex specificity 121 / 1 (< 0.001; scenario-cluster interval [0.174, 0.329]); OpenAI regex recall .920 to .896, 0 / 12 (< 0.001); OpenAI NER recall .290 to .170, 11 / 71 (< 0.001). With only one-sided flips, six or more discordant rows are needed for exact p < 0.05.

Action level (union, `PipelineAnalysis.action`): on the final no WARN-or-BLOCK difference is distinguishable from zero (recall -0.004, specificity -0.004); BLOCK-only recall falls 0.398 to 0.386 (0 / 3, p = 0.25). On personalized, BLOCK-only recall falls 1.000 to 0.928 (0 / 72, p < 0.001), the largest single action-level change: all 72 personalized positives moved BLOCK to WARN after losing the regex `CHILD` category. Cost-weighted error at FN:FP 2, 4, 9 shows no difference distinguishable from zero on the final for any rule.

Interpretation (source verdict, adopted): the held-out regex specificity gain and recall cost are consistent in direction but rest on three rows each and are not individually distinguishable from chance; the held-out union supports "no detectable change", not equivalence, and cannot exclude changes of three to five points in either direction; the dev union gain is not supported at the 5 percent level and did not reproduce on the final; the synthetic-set regex specificity gains and recall losses and the synthetic NER recall losses are statistically solid, with the caveat that synthetic rows lack template identifiers.

Final endpoint: this was a second authorized use of `final.jsonl` for the same frozen pair, run once, statistics only, per-row outcomes stored locally (hashed ids, gitignored). The endpoint is consumed for this pair and must not inform further decisions.

## 2. Action-level finding and the `student_id` repair

Task A's analysis (reported to the root; the transition counts above are in the uncertainty record) found 72 personalized positives whose union action moved BLOCK to WARN under the new defaults because the child-rule repair removed a regex `CHILD` hit. Diagnosis (per the assignment brief; no standalone diagnosis record was available to the documentation task): these are adult student records where the old CHILD hit was accidental, and bare "student" is not a CHILD cue. PR #5, commit `e70e3a2e` on `fix/regex-fp-reduction`, adds a `student_id` S3 IDENTITY rule requiring a value of four or more characters containing a digit tied to "student", so generic student and ID mentions remain negative. Reported effect: BLOCK is restored on the 72 rows with no new false positives. The evidence is a single template: the mechanism is confirmed, generalisation is not established.

Consequence for the paper: the shipped configuration now includes this rule, added after the endpoint scoring. The held-out, split and rerun numbers describe the configuration before it (`55cbd1e5`).

## 3. Full-product rerun of units 1 and 2 (FULL-PRODUCT evidence)

Scope: regex + NER + semantic cascade, actual execution recorded; not semantic-only, not detector-layer-only. Separately authorized product scope (`--allow-product-pipeline` for this purpose only). Frozen historical PIPE3/AB14 inputs: 1,560 authored cases (810 sensitive, 750 clean), six packages, balanced V3 seven layer sets, regex first, one first pass per cell. Old arm = clean export of `e6c177ff`; new arm = `55cbd1e5`. Host-native in-process loopback runtime (no Docker, matching the historical runs); 2 x 13 x 1,560 = 40,560 scored requests, all status `ok`. Paired exact McNemar and family-cluster (`family_id`, 35 clusters, 2,000 draws, seed 42) intervals.

Validity: the old arm reproduces the historical outcome and action on every one of 1,560 cases for all six packages and seven layer sets (zero discordant pairs). Semantic-only outcomes are identical across arms because the semantic input is lowercased in both.

Unit 1 (historical = old / new): shared unnecessary restrictions of the V3 tiers 139 to 108 (union 112; 103 of the 108 lie among the historical 139). V3 balanced: allowed action 1409 to 1438 (36 improved, 7 regressed, p < 0.001), binary 1433 to 1457, binary false positives 119 to 95 with false negatives unchanged at 8, joint 717 to 720 (28 / 25, p = 0.78), over-enforced 139 to 110, under-enforced 12 to 12. Efficient and quality are in the paper table. Joint agreement is flat for V3 (p .26 to .81) and V1 balanced falls 160 to 155 (2 / 7, p = 0.18) because two effects cancel: regex repairs alone add 28 joint-correct cases (28 / 0) while the new NER findings alter the label set on 25 cases (25 / 0 in favour of no-NER). Mechanism: 36 BLOCK to ALLOW moves (regex early-BLOCK skips 289 to 253) and 7 clean cases ALLOW to WARN from new NER findings; converted NER findings 0 to 48 (all IDENTITY, name); regex findings 1,364 to 1,328. Paired V3 versus V1 allowed-action improved/regressed, historical to new: efficient 389/3 to 388/5, balanced 389/6 to 413/12, quality 348/0 to 337/3; the package ranking is essentially unchanged.

Unit 2 (balanced V3, action / joint / under / over; historical = old, then new): full 1409 / 717 / 12 / 139 to 1438 / 720 / 12 / 110; no rules [3,4] 1530 / 972 / 30 / 0 to 1523 / 942 / 30 / 7; no NER [2,4] 1409 / 717 / 12 / 139 to 1445 / 745 / 12 / 103. Removing regex versus the full product (improved / regressed): historical 139 / 18 (net +121, p = 2.4e-24, family interval [0.035, 0.127]); new 103 / 18 (net +85, p = 1.2e-15, [0.024, 0.089]); the same 18 correct actions are lost, under-enforcement still 12 to 30. NER-only: 36 of 810 sensitive-labelled cases and 12 of 750 clean cases carry a positive (historically 0 and 0). No-NER equals the full product on 1,560 of 1,560 cases historically but on 1,526 of 1,560 now: removing NER gains 7 action outcomes and 25 joint outcomes with 0 losses.

Changed conclusions: the 139 figure and the zero-converted-NER statement are historical measurements of the pre-change configuration; the current default leaves 108 shared restrictions and its NER layer converts 48 findings, making NER removal slightly beneficial on this fixture. Unchanged: removing regex still improves allowed-action agreement at the cost of the same 18 lost actions and the same under-enforcement rise, and V3 beats V1 in every tier.

## Limitations

Unit 8 numbers: single small English spaCy model, annotation-presence label noise, S1 counted positive, bootstrap percentile intervals optimistic for few discordant rows, no multiplicity correction, synthetic rows lack template ids (row-level inference anti-conservative), final endpoint consumed. Rerun: reused assistant-provisional AU3 labels without independent adjudication, correlated families (35 clusters, `family_id` only; the corrected audience-expression grouping used historically was not recomputed), one first pass per cell, one balanced package for the ablation; the detector changes were tuned on development and personalized sets but AU3 FRESH has now been scored twice, so it is not a fresh confirmation; Windows host, CPU, Python 3.11. The `student_id` rule is not in any recorded measurement. Installed probes and cost studies (units 4 and 6) were not rerun and remain pre-change measurements. Wave 3 fresh held-out results, robustness fixes, NER-model alternatives, span scoring and the annotation study are pending and are not part of this record.

## Paper passages affected

Abstract (regex specificity sentence; rerun clause); Section "Detector Precision Controls" (shipping note, `student_id` rule); "Questions and Evidence Units" (question map); "Detector Precision Protocol" (installed-configuration caveat, endpoint re-use, paired-statistics method); "Comparison and Retention Protocols" (revalidation pointer); "Contextual Policy Agreement" (139 and zero-NER statements marked historical, ablation sentence); "Detector-Layer Precision Revision" (significance statements, new Table `tab:detprec_paired`, action-level paragraph, revalidation sentence); new subsection "Full-Product Rerun with the Revised Detectors" with Tables `tab:rerun_units` and `tab:rerun_ablation`; Discussion (placement paragraph); limitations (detector-precision paragraph); Conclusion; Appendix "Detector Precision Rules and Reproduction". No bibliography change. Claims C44 updated; C45 to C47 added in [claims.md](claims.md).
