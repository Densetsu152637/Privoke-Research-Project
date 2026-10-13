# Audience coverage and V3 continuation (AU3)

Status: automatic coverage integration and network pilots are audited. All three continuation fits, selected/terminal exports and native audits passed. All six selected before/after packages are sealed. The fresh six-package comparison and independent raw/paired/interval audit passed. Joint and audience correctness improved in every tier, with material component and action regressions retained below. No universal tier-ranking or production-safety claim follows.

Exact request: “Go ahead and improve the audience training data according to your priorities and integrate this into the automatic fuzzer training pipeline for better case coverage for random training, fine tune all three v3 tiers again, and compare them against the current checkpoints on a fresh test set. Keep the originals and document the epochs for each component.”

## Data and automatic training

The [audience data guide](audience-v3-data.md) documents the maintained generator and runtime configuration. Normal automatic contextual training now resolves to the pinned `audience_coverage_v1` TRAIN release. Each 32-original block contains 24 audience cases and eight unchanged PH3 rehearsal rows. Each of the six audience labels contributes two actual disclosures, one hard-clean control and one mild-source case; rehearsal contributes four sensitive and four clean rows. The twelve actual-disclosure slots cover all ten primary categories. One invariant transformation produces 64 training exposures, with a separate fixed 16-row validation guard. A different random seed changes selection; it does not prove novel coverage.

Actual selected IDs, audience/expression counts, source pins and transformed exposures are retained in durable evidence. The implementation closure enters the fingerprint before replay lookup or reservation. Explicit legacy sources and frozen BC01 routes retain their own contracts. The normal source/catalog bundle contains TRAIN and its pinned guard, not the held-out authoring catalogs.

The offline AU3 study is a separate full-model continuation: 9,360 TRAIN rows combine byte-identical PH3 rehearsal 6,240 with new audience TRAIN 3,120. NEW validation and sealed FRESH each contain 1,560 rows. Authoring and independent review used no model predictions. Labels remain **assistant-provisional, not human annotated**. Failed R1/R2 candidates and their repairs are preserved. Bounded assertion, expression, text/skeleton and historical-overlap checks address concrete leakage; unique IDs do not establish universal semantic novelty. Scenario families and reused audience expressions make rows dependent.

FRESH is a new V3-only synthetic workload. All V3 inputs fit the 512-token cap, with maximum WordPiece length 73. Three fresh originals exceed Tiny64, reaching 67 tokens; no Tiny fresh comparison is implied. Runtime TRAIN inputs and their augmentation remain within the checked Tiny64 cap. The fixed guard is a validation subset, not an independent test.

Actual normal automatic HEADS/FULL pilots passed source, physical execution and publication checks. Separate V3 HEADS/FULL pilots performed real bounded fits, but both candidates were guard-rejected and were not published. The [independent pilot review](../evaluation/results/audience_v3_20261013/planning/pilot-review-01.md) establishes mechanics, not detection improvement or promotion.

## Fixed continuation method

Each tier starts from its corresponding [EN3 selected package](privacy-encoder-training-v3.md), with independently pinned parent and linguistic ORIGINAL copies. Encoder, dense/tanh pooler and all three privacy heads are jointly trainable. Old PH3/EN3 weights, checkpoints, protocols and source records are retained.

Host [run-audience-v3.py](../evaluation/run-audience-v3.py) owns the versioned preparation, probes, fitting, exports, audits and comparison. The admitted run uses four CPU threads, deterministic float32 and the Torch 2.12 CUDA-build host environment **on CPU**. AdamW uses encoder/pooler learning rate 0.00002, head learning rate 0.0001, weight decay 0.01, dropout 0.1 and gradient-norm clipping at 1. Effective batches of 64 accumulate microbatches of 16. The loss combines weighted sensitivity/visibility cross-entropy and mean positive-weighted category binary cross-entropy; the category threshold stays fixed at 0.5.

There are 147 updates per complete epoch, with a final 16-row batch: 9,360 exposures, not 147×64. The fixed schedule has 147 warmup updates and 4,410 maximum updates. Fits require at least five epochs, stop after five validation epochs without a strict 0.0001 improvement, and permit at most 30 epochs. Selection uses NEW validation loss among trained epochs; epoch zero is a retained reference. Full model/optimizer/scheduler and CPU RNG checkpoints support audited resume. FRESH cannot select checkpoints or trigger a refit.

## Component epochs and actual work

PH3 selected head-only ancestry is 12/7/4 epochs; EN3 selected joint ancestry is 19/14/4 for efficient/balanced/quality. Earlier EN3 completed fits were 24/19/9, which is historical work rather than the ancestry of the selected packages. Upstream language-pretraining epochs and steps remain unknown.

| Tier | AU3 joint epochs completed / selected | AU3 updates completed / selected | TRAIN exposures completed / selected | Best validation loss | Fit-loop seconds |
|---|---:|---:|---:|---:|---:|
| Efficient | 16 / 11 | 2,352 / 1,617 | 149,760 / 102,960 | 1.1933569163 | 579.641 |
| Balanced | 11 / 6 | 1,617 / 882 | 102,960 / 56,160 | 0.7234435230 | 535.328 |
| Quality | 9 / 4 | 1,323 / 588 | 84,240 / 37,440 | 0.5084240213 | 1,974.188 |

All three fits stopped under validation patience. The combined work is 36 new joint epochs, 5,292 optimizer updates, 336,960 TRAIN exposures and 3,089.157 fit-loop seconds. Fit-loop time includes in-loop validation and checkpointing, not all loading/export/audit/scoring costs. [Efficient](../evaluation/results/audience_v3_20261013/planning/training-results-review-01-efficient.json) and [balanced](../evaluation/results/audience_v3_20261013/planning/training-results-review-01-balanced.json) independent reviews, together with [quality](../evaluation/results/audience_v3_20261013/planning/training-results-review-01-quality.json), reconcile actual history, work, checkpoints and exports. The [immutable all-tier review](../evaluation/results/audience_v3_20261013/planning/training-results-review-01.md) binds all three completed fits and all six exports.

| Tier | Inherited encoder / pooler epochs | Inherited privacy-head epochs | Selected cumulative encoder / pooler epochs | Selected cumulative privacy-head epochs |
|---|---:|---:|---:|---:|
| Efficient | 19 / 19 | 31 | 30 / 30 | 42 |
| Balanced | 14 / 14 | 21 | 20 / 20 | 27 |
| Quality | 4 / 4 | 8 | 8 / 8 | 12 |

Cumulative selected counts describe the saved package, not discarded optimizer work. Each new AU3 epoch updates encoder, pooler and heads together. Terminal package histories instead add completed AU3 epochs to the inherited counts; head-only PH3 epochs never count as encoder epochs.

All six selected and terminal exports match their retained checkpoints, with finite float32 native tensors and changed full-model components. Parent and ORIGINAL packages remain unchanged. Direct Torch 2.12 CPU versus Torch 2.11 native captures on the first 16 NEW validation rows per asset match discrete classifications and actions exactly within the fixed numerical tolerances: logits `atol=1e-5, rtol=1e-4`, confidence `atol=0.001`. Maximum observed logit error across all six assets is 0.00000190735. This is bounded numerical compatibility, not exact floating-point equality or quality evidence. The all-tier review SHA256 is `207cfa1678a641d333aa7ef0705468f5502615245faaacd4420151bb0fea2192`.

## Fresh six-package comparison

All six native runs completed with zero errors: 1,560 new accuracy RPCs per selected package, 9,360 total, no imported accuracy cases and 24 separate warmups. The frozen controller audit and independent final six-entry/paired/294-interval audit passed. Individual before/after entry reviews also passed. Both sides were newly scored on the same FRESH cases, not imported from the earlier EN3 development comparison.

All three fits, selected/terminal exports and native audits were sealed before model-side FRESH access. The six-package registry SHA256 is `cb0529d59261d9bcc0d8450a0f6739f66ffeabde0fd1ad20bbae1cd0bef67a37`. Every accuracy request explicitly selected sole semantic layer `[4]`, and responses were checked for actual sole `[4]` and pinned native identity, with empty audience hints. Errors would count incorrect in the full denominators. Fresh performance selected no checkpoint, epoch, recipe, threshold or tier and triggered no refit.

The following tables show CURRENT EN3 selected → AU3 selected. Full joint correctness requires the complete packed sensitivity/visibility/category result, not merely a correct policy action.

| Tier | Joint / 1,560 (percent) | Visibility / 1,560 | Category macro F1 | Category micro F1 |
|---|---|---|---|---|
| Efficient | 262 (16.79%) → 922 (59.10%) | 660 → 1265 | 0.5869 → 0.7256 | 0.6069 → 0.7554 |
| Balanced | 267 (17.12%) → 972 (62.31%) | 718 → 1269 | 0.6038 → 0.7932 | 0.6219 → 0.8154 |
| Quality | 429 (27.50%) → 1209 (77.50%) | 712 → 1445 | 0.7323 → 0.8735 | 0.7415 → 0.8779 |

| Tier | Sensitivity exact / 1,560 | Category exact / 1,560 | Sensitive recall / 810 | Clean specificity / 750 | Clean false positives / 750 |
|---|---|---|---|---|---|
| Efficient | 1174 → 1495 | 776 → 1149 | 794 → 791 | 468 → 738 | 282 → 12 |
| Balanced | 1069 → 1498 | 793 → 1206 | 783 → 794 | 427 → 740 | 323 → 10 |
| Quality | 1401 → 1540 | 1056 → 1308 | 805 → 810 | 640 → 749 | 110 → 1 |

Quality has the highest joint correctness, visibility accuracy, category macro/micro F1, sensitive recall and clean specificity on this fresh workload. This ranking is specific to the measured packages and fixture; unequal capacities and histories do not isolate a causal architecture effect. Efficient sensitive recall falls from 794 to 791 of 810 despite its aggregate gains. Its CHILD-category F1 also falls from 0.683673 to 0.641509. S3 severity recall falls for efficient from 570 to 544 of 576 (98.9583% → 94.4444%) and for balanced from 569 to 554 of 576 (98.7847% → 96.1806%). Higher overall sensitivity accuracy therefore does not mean every severity class improved.

### Audience recall and remaining confusions

Each audience has 260 true cases; entries below are correct counts, equivalent to recall numerators. P3 means an actual closed invited group with other readers; P4 requires affirmative sole-self access with no other reader. PU means the audience is undetermined.

| Audience | Efficient | Balanced | Quality |
|---|---|---|---|
| P0 | 107 → 169 | 81 → 164 | 45 → 216 |
| P1 | 200 → 260 | 215 → 260 | 206 → 260 |
| P2 | 104 → 248 | 44 → 200 | 90 → 260 |
| P3 | 118 → 208 | 216 → 235 | 105 → 222 |
| P4 | 54 → 213 | 78 → 243 | 105 → 256 |
| PU | 77 → 167 | 84 → 167 | 161 → 231 |

P4 recognition improves substantially in every tier, but audience errors remain: after-quality misclassifies 28 P3 cases as P0; its PU errors include 14 each predicted P0 and P4. After-balanced and after-efficient each recognize only 167/260 PU cases. Full before/after sensitivity and visibility confusion matrices, including explicit ERROR columns, remain in the frozen analysis linked below.

### Same-case changes and policy tradeoffs

All pairs have 1,560 comparable cases and zero error pairs. Improvements/regressions are case counts, not uncertainty bounds.

| Tier | Joint improved / regressed | Visibility improved / regressed | Category-exact regressions | Contextual-sensitive regressions |
|---|---|---|---|---|
| Efficient | 680 / 20 | 639 / 34 | 22 | 14 |
| Balanced | 732 / 27 | 586 / 35 | 21 | 7 |
| Quality | 792 / 12 | 739 / 6 | 19 | 1 |

| Tier | Over-distance / affected cases, before → after | Under-distance / affected cases, before → after | Paired over / under worsenings | Allowed action / 1,560 |
|---|---|---|---|---|
| Efficient | 545 / 275 → 0 / 0 | 10 / 10 → 31 / 31 | 0 / 24 | 1275 → 1529 |
| Balanced | 656 / 330 → 0 / 0 | 17 / 17 → 30 / 30 | 0 / 20 | 1213 → 1530 |
| Quality | 166 / 84 → 0 / 0 | 13 / 13 → 0 / 0 | 0 / 0 | 1463 → 1560 |

Efficient and balanced eliminate observed over-restriction but increase under-restriction, with 24 and 20 paired worsenings respectively. Quality has zero observed policy-action distance and zero paired action worsenings, yet still has 12 joint regressions, 19 category-exact regressions and one contextual-sensitive regression. Its 1,560/1,560 allowed actions do not mean perfect privacy classifications: joint correctness is 1,209/1,560 and there is one clean false positive. Policy distance sums, affected-case counts and paired worsened counts are separate measures even when some values happen to agree.

| Joint slice (support) | Efficient | Balanced | Quality |
|---|---|---|---|
| Category-bearing disclosures (720) | 66 → 257 | 76 → 297 | 120 → 441 |
| Multilabel disclosures (456) | 32 → 99 | 29 → 131 | 47 → 218 |
| Clean S0 (750) | 181 → 589 | 169 → 598 | 260 → 681 |
| Sensitive including S1 (810) | 81 → 333 | 98 → 374 | 169 → 528 |

### Cluster sensitivity intervals

The predeclared percentile bootstrap uses 2,000 resamples, seed 42, separately clustering by 35 scenario families and 24 audience-expression groups. The table reports after-minus-before percentage-point changes and 2.5th–97.5th percentile bounds. These are separate dependence sensitivities, not proof that crossed family/expression dependence has been removed or population-level confidence guarantees. Each per-audience expression analysis has only four expression clusters; complete per-audience and component intervals are retained in the analysis.

| Tier | Metric | Change (pp) | Family bounds (pp) | Expression bounds (pp) |
|---|---|---|---|---|
| Efficient | joint | +42.31 | [39.25, 45.76] | [35.71, 48.46] |
| Efficient | visibility | +38.78 | [36.44, 41.15] | [29.68, 47.82] |
| Balanced | joint | +45.19 | [41.97, 48.49] | [37.24, 53.72] |
| Balanced | visibility | +35.32 | [33.33, 37.44] | [24.23, 47.05] |
| Quality | joint | +50.00 | [46.01, 53.78] | [42.11, 57.95] |
| Quality | visibility | +46.99 | [45.08, 49.01] | [36.34, 58.08] |

### Per-category precision, recall and F1

Each cell is precision / recall / F1, rounded to four decimals. Support is the number of true category memberships among the same 1,560 cases; multilabel supports do not sum to a case count. Full TP/FP/FN and micro totals remain in the analysis.

**Efficient**

| Category | Support | CURRENT P / R / F1 | AU3 P / R / F1 |
|---|---|---|---|
| CHILD | 108 | 0.7614 / 0.6204 / 0.6837 | 1.0000 / 0.4722 / 0.6415 |
| CRIMINAL | 108 | 0.4745 / 0.8611 / 0.6118 | 0.7387 / 0.7593 / 0.7489 |
| FINANCIAL | 144 | 0.4960 / 0.8681 / 0.6313 | 0.8227 / 0.8056 / 0.8140 |
| HEALTH | 240 | 0.5695 / 0.7167 / 0.6347 | 0.8966 / 0.6500 / 0.7536 |
| IDENTITY | 108 | 0.3150 / 0.9537 / 0.4736 | 0.7132 / 0.8519 / 0.7764 |
| LOCATION | 108 | 0.7733 / 0.5370 / 0.6339 | 0.9062 / 0.5370 / 0.6744 |
| POLITICS | 108 | 0.6559 / 0.5648 / 0.6070 | 0.8173 / 0.7870 / 0.8019 |
| RELIGION | 108 | 0.4651 / 0.1852 / 0.2649 | 0.7812 / 0.2315 / 0.3571 |
| SEXUAL | 108 | 0.4069 / 0.7685 / 0.5321 | 0.7759 / 0.8333 / 0.8036 |
| THIRD_PARTY | 204 | 0.7148 / 0.8971 / 0.7957 | 0.9820 / 0.8039 / 0.8841 |

**Balanced**

| Category | Support | CURRENT P / R / F1 | AU3 P / R / F1 |
|---|---|---|---|
| CHILD | 108 | 0.8889 / 0.3704 / 0.5229 | 0.9733 / 0.6759 / 0.7978 |
| CRIMINAL | 108 | 0.6000 / 0.7778 / 0.6774 | 0.8673 / 0.7870 / 0.8252 |
| FINANCIAL | 144 | 0.5104 / 0.8542 / 0.6390 | 0.7899 / 0.7569 / 0.7730 |
| HEALTH | 240 | 0.5858 / 0.8250 / 0.6851 | 0.8505 / 0.7583 / 0.8018 |
| IDENTITY | 108 | 0.2688 / 0.9907 / 0.4229 | 0.7067 / 0.9815 / 0.8217 |
| LOCATION | 108 | 0.8226 / 0.4722 / 0.6000 | 0.9821 / 0.5093 / 0.6707 |
| POLITICS | 108 | 0.5902 / 0.6667 / 0.6261 | 0.8762 / 0.8519 / 0.8638 |
| RELIGION | 108 | 0.6458 / 0.2870 / 0.3974 | 0.8913 / 0.3796 / 0.5325 |
| SEXUAL | 108 | 0.4286 / 0.9722 / 0.5949 | 0.8175 / 0.9537 / 0.8803 |
| THIRD_PARTY | 204 | 0.8409 / 0.9069 / 0.8726 | 0.9897 / 0.9412 / 0.9648 |

**Quality**

| Category | Support | CURRENT P / R / F1 | AU3 P / R / F1 |
|---|---|---|---|
| CHILD | 108 | 0.9375 / 0.6944 / 0.7979 | 0.9725 / 0.9815 / 0.9770 |
| CRIMINAL | 108 | 0.7034 / 0.9444 / 0.8063 | 0.8818 / 0.8981 / 0.8899 |
| FINANCIAL | 144 | 0.7085 / 0.9792 / 0.8222 | 0.9840 / 0.8542 / 0.9145 |
| HEALTH | 240 | 0.6703 / 0.7708 / 0.7171 | 0.8086 / 0.8625 / 0.8347 |
| IDENTITY | 108 | 0.4339 / 0.9722 / 0.6000 | 0.7248 / 1.0000 / 0.8405 |
| LOCATION | 108 | 0.6503 / 0.8611 / 0.7410 | 0.9588 / 0.8611 / 0.9073 |
| POLITICS | 108 | 0.4919 / 0.8426 / 0.6212 | 0.7034 / 0.9444 / 0.8063 |
| RELIGION | 108 | 0.6023 / 0.4907 / 0.5408 | 0.8462 / 0.6111 / 0.7097 |
| SEXUAL | 108 | 0.6233 / 0.8426 / 0.7165 | 0.8879 / 0.8796 / 0.8837 |
| THIRD_PARTY | 204 | 0.9700 / 0.9510 / 0.9604 | 0.9444 / 1.0000 / 0.9714 |

### Descriptive runtime observations

| Tier | Median RPC ms, before → after | p95 RPC ms, before → after |
|---|---|---|
| Efficient | 3.181 → 3.177 | 3.956 → 4.192 |
| Balanced | 3.128 → 3.191 | 4.229 → 4.429 |
| Quality | 7.991 → 8.359 | 10.700 → 12.140 |

These batch-one observations come from serial accuracy loops, not replicated matched performance experiments or an SLA. They do not establish a speedup.

The [frozen full analysis](../evaluation/results/audience_v3_20261013/runs/cpu-02/comparison/analysis.json), SHA256 `c2b37a412cb7053c68c7d125fee35bebce61726a872bb52889d0135e49e32cb3`, retains every declared component/slice, per-class confusion, paired tradeoff and interval. Its [raw inventory](../evaluation/results/audience_v3_20261013/runs/cpu-02/comparison/raw-inventory.json), SHA256 `357608b141a57916e8a5aa8a933bb40931efa0e899e10c55697e8f450b00d801`, binds 37,554 files. The [independent final review](../evaluation/results/audience_v3_20261013/planning/fresh-results-review-01.json), SHA256 `91c8524c21d7ca9bb641b4ea41f3e30bd193000dae11373f393b10ec92731ea6`, reconciles all six raw entries, paired counts and 294 intervals.

### Selected package identity

| Tier | AU3 selected manifest SHA256 | Selected/terminal evidence |
|---|---|---|
| Efficient | [1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd](../models/experiments/audience_v3_20261013/runs/cpu-02/exports/efficient/selected/manifest.json) | [Export/evidence index](../evaluation/results/audience_v3_20261013/runs/cpu-02/exports/efficient.json) |
| Balanced | [99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589](../models/experiments/audience_v3_20261013/runs/cpu-02/exports/balanced/selected/manifest.json) | [Export/evidence index](../evaluation/results/audience_v3_20261013/runs/cpu-02/exports/balanced.json) |
| Quality | [bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39](../models/experiments/audience_v3_20261013/runs/cpu-02/exports/quality/selected/manifest.json) | [Export/evidence index](../evaluation/results/audience_v3_20261013/runs/cpu-02/exports/quality.json) |

The sealed registry also pins the unchanged CURRENT EN3 selected parent manifests: efficient `4850180c40710949c91e37f8bfad5787eb00a43992b419e23bfb8fd24e8c703e`, balanced `141dcd99e58becb0d1ee463da1bfdea9d31b92b1422b619777ee65be20954318`, quality `1c5a962761b0699ac1bcf5b3753525819d7d4725e499f5a9f2eff295a06dccba`. Linguistic ORIGINALs and inherited PH3/EN3 records remain retained.

## Provenance and reproduction

Study ID: `audience_v3_20261013`. Admitted run: `evaluation/results/audience_v3_20261013/runs/cpu-02/`; model assets: `models/experiments/audience_v3_20261013/runs/cpu-02/`.

| Evidence | SHA256 or revision |
|---|---|
| Reviewed data/fuzzer prerequisite commit | `8e414f07b37e12f66984f0737c6d75c9fce72e57` |
| Reviewed AU3 controller commit | `965005646a5874dde60232e5f3dd0d53e52eb786` |
| Integrated tested Git tree | `e9241f920bbebf9e3328b3abf2137804d5509d28` |
| [Release-07 manifest](../evaluation/results/audience_v3_20261013/data/release-07/manifest.json) | `41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0` |
| [cpu-02 protocol](../evaluation/results/audience_v3_20261013/runs/cpu-02/protocol.json) | `ba7f39909edeb404b233df8a9ae5871d43ade43a4ac62a11a66640c830afc71d` |
| Retained 175-file source closure | `d5230944e2fc2f747d70e5a26cfbfccd603ec6636c35ecdd50d6ba307e321f47` |
| Final independent pilot audit | `ebde2c9d281f11093b2baac5cc18a031fdb08f68a647a01126422f2e0d0fe471` |

Exact replay requires the retained working-source bytes and protocol. Unrelated dirty dependencies were preserved outside the scoped commits; Git HEAD alone does not reproduce the full tested closure. The accepted preparation pins immutable evidence copies under `planning/preparation-evidence-02/`. Earlier cpu-01 preparation was blocked before model work and remains preserved; cpu-02 keeps the same fixed recipe.

Run Python tests, fitting, audits and dataset scoring in the host environment; containers may host loopback servers. Existing immutable paths must not be overwritten. Reproduction requires fresh assigned paths and protocol-bound acceptances. The focused synthetic mechanics tests are `evaluation.tests.test_audience_v3` and `evaluation.tests.test_audience_v3_comparison`; they passed 20 tests in each supported host environment on the integrated tree. These Toy/mocked tests are separate from real-model fits and FRESH scoring.

The evidence establishes automatic coverage integration, all three audited continuation fits and the fresh paired synthetic comparison. Synthetic provisional labels, dependent authored families/expressions and shared broad concepts limit later generalization claims. A before/after package comparison will not isolate the causal effect of audience data from additional optimization. No production promotion, real-world safety claim or improvement guarantee follows from these records.
