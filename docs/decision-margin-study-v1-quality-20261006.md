# Decision-margin fuzzer model quality

complete reconciled study

All six attempts start independently from exact live balanced train.2 with identical quota rows, heads-only one-step .003 optimization and paired mean/margin objectives.

| Attempt | Strategy / objective | Rate / seed | Outcome | Pipeline recall / specificity / balanced accuracy |
| ---: | --- | --- | --- | ---: |
| 0 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 1 | heads / class_balanced_contextual_decision_margin_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 2 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 3 | heads / class_balanced_contextual_decision_margin_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 4 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 5 | heads / class_balanced_contextual_decision_margin_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.41% / 59.65% |

Validation contains 475 positive and 493 negative rows. Undefined class rates remain unavailable.

| Model / source | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 | Balanced accuracy |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| live balanced baseline / pooled | semantic | 475 / 493 | 246 / 155 / 338 / 229 | 51.79% | 31.44% | 42.12% | 46.46% | 41.61% |
| live balanced baseline / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| live balanced baseline / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| live balanced baseline / nemotron-pii | semantic | 206 / 384 | 102 / 118 / 266 / 104 | 49.51% | 30.73% | 27.72% | 35.54% | 40.12% |
| live balanced baseline / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| live balanced baseline / pooled | pipeline | 475 / 493 | 427 / 143 / 350 / 48 | 89.89% | 29.01% | 54.95% | 68.21% | 59.45% |
| live balanced baseline / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| live balanced baseline / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| live balanced baseline / nemotron-pii | pipeline | 206 / 384 | 175 / 112 / 272 / 31 | 84.95% | 29.17% | 39.15% | 53.60% | 57.06% |
| live balanced baseline / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 0 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 0 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 0 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 0 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 0 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 0 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 0 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 0 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 0 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 0 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 1 / pooled | semantic | 475 / 493 | 245 / 157 / 336 / 230 | 51.58% | 31.85% | 42.17% | 46.40% | 41.71% |
| attempt 1 / AI4Privacy/OpenPII | semantic | 133 / 39 | 61 / 14 / 25 / 72 | 45.86% | 35.90% | 70.93% | 55.71% | 40.88% |
| attempt 1 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 1 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 1 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 1 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 1 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 1 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 1 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 1 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 2 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 2 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 2 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 2 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 2 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 2 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 2 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 2 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 2 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 2 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 3 / pooled | semantic | 475 / 493 | 246 / 157 / 336 / 229 | 51.79% | 31.85% | 42.27% | 46.55% | 41.82% |
| attempt 3 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 3 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 3 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 3 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 3 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 3 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 3 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 3 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 3 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 4 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 4 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 4 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 4 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 4 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 4 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 4 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 4 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 4 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 4 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 5 / pooled | semantic | 475 / 493 | 245 / 157 / 336 / 230 | 51.58% | 31.85% | 42.17% | 46.40% | 41.71% |
| attempt 5 / AI4Privacy/OpenPII | semantic | 133 / 39 | 61 / 14 / 25 / 72 | 45.86% | 35.90% | 70.93% | 55.71% | 40.88% |
| attempt 5 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 5 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 5 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 5 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 5 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 5 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 5 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 5 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |

| Model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |
| --- | --- | ---: | --- | --- |
| live balanced baseline | v0.3.0+train.2 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 0 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 1 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 2 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 3 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 4 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 5 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |

| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5072279681103204 | 1.9704265463529917 |
| 1 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5072279681103204 | 3.0241548300910677 |
| 2 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.5137752525252526 | 2.355927428490806 |
| 3 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.5137752525252526 | 3.3986396907354006 |
| 4 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.43425017483236644 | 2.07796231142592 |
| 5 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.43425017483236644 | 3.0284732225852116 |

Legacy average_loss measures weighted classification distance. Both objectives use sensitivity CE + visibility CE + mean-per-label category BCE. The margin objective also adds fixed-coefficient auxiliary BCE. Full totals from these different objectives are not directly comparable quality; the classification-distance diagnostic measures a different quantity.

| Accepted attempt | Actual training class rows | Raw class weights | Effective class weights | Clean / sensitive objective mass |
| ---: | --- | --- | --- | --- |
| 0 | 221 / 35 | 221.0 / 35.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 1 | 221 / 35 | 221.0 / 35.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 2 | 220 / 36 | 220.0 / 36.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 3 | 220 / 36 | 220.0 / 36.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 4 | 219 / 37 | 219.0 / 37.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 5 | 219 / 37 | 219.0 / 37.0 | 128.0 / 128.0 | 0.5 / 0.5 |

No eligible frozen winner; no candidate development/fixture score claimed. Retained: False.

Model and training identities, parameter dimensions/counts, trainable/frozen tensors, publication changes, held-out guards, loss definitions, paired predictions, sampling inventories and immutable source/report commitments are retained in the JSON evidence. Service timings exclude browser overhead and do not establish production latency.

- All six objective attempts are freshly fitted; matched seed pairs use identical training/held-out targets, weights and optimizer settings.
- Quota roles use provisional existing contextual targets, not independent human contextual labels or external annotation-presence truth.
- Sparse authored families can receive increased row exposure and half the class objective mass; this supplies no new supervision or broad coverage guarantee.
- All attempts start from the same seeded encoder/live train.2 base; parameter counts and profile names do not rank measured quality.
- Validation and development are reused exploratory evidence; untouched generalization and statistical superiority remain unestablished.
- The optimized CE/mean-BCE objective and legacy weighted classification-distance diagnostic have different meanings/scales.
- Optimizer trajectory losses and intermediate shape-aware state fingerprints are runtime-recorded; raw scalar trace does not independently reconstruct intermediate states.
- The fixed decision margin is a union-predicate surrogate away from boundaries/ties; severity argmax ties, category >= threshold, sigmoid clipping and float32 rounding preclude universal exact decoder equivalence.
- Severity/visibility/action privacy truth cannot be inferred from validation annotation presence; fixture gates are separately provisional.
- Confidence calibration and representative production latency remain unmeasured; timings describe only observed service calls.
- Previous studies remain separate archived evidence; no prior candidate endpoint or protected final rows/labels are opened.

| Fresh original development | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |
| --- | --- | ---: | ---: | ---: | ---: |
| semantic | 146 / 76 / 162 / 118 | 55.30% | 31.93% | 47.40% | 51.05% |
| pipeline | 242 / 69 / 169 / 22 | 91.67% | 28.99% | 58.88% | 71.70% |

Fresh original development is a reference measurement before the grid; it supplies no candidate selection evidence.

| Attempt | Sampling mode | Actual authored sensitive / clean | Public / bootstrap | Unique train rows | Authored families |
| ---: | --- | ---: | ---: | ---: | ---: |
| 0 | role quota | 32 / 32 | 189 / 3 | 256 | 10 |
| 1 | role quota | 32 / 32 | 189 / 3 | 256 | 10 |
| 2 | role quota | 32 / 32 | 187 / 5 | 256 | 9 |
| 3 | role quota | 32 / 32 | 187 / 5 | 256 | 9 |
| 4 | role quota | 32 / 32 | 185 / 7 | 256 | 11 |
| 5 | role quota | 32 / 32 | 185 / 7 | 256 | 11 |

Quota preflight inventories describe the exact source-bound selection before RPC. Accepted response audits must match; rejected updates receive no invented model score.

| Attempt | Initial sensitivity CE | Initial visibility CE | Initial mean category BCE | Initial optimized objective |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 1.433733586836074 | 0.27225647996916075 | 0.26443647954775695 | 1.9704265463529917 |
| 1 | 1.433733586836074 | 0.27225647996916075 | 0.26443647954775695 | 3.0241548300910677 |
| 2 | 1.375926528514175 | 0.6844956397562441 | 0.29550526022038653 | 2.355927428490806 |
| 3 | 1.375926528514175 | 0.6844956397562441 | 0.29550526022038653 | 3.3986396907354006 |
| 4 | 1.241070021700417 | 0.6048539983570901 | 0.23203829136841317 | 2.07796231142592 |
| 5 | 1.241070021700417 | 0.6048539983570901 | 0.23203829136841317 | 3.0284732225852116 |

| Attempt | Objective | Steps × rate | Runtime-recorded objective before / after | Clipped coordinates per step | Final transported maximum |
| ---: | --- | --- | --- | --- | --- |
| 0 | class_balanced_contextual_mean_category_v1 | 1 × 0.003 | 1.9704265463529917 / 1.9687754845645433 | [0] | 0.0005573584930971265 |
| 1 | class_balanced_contextual_decision_margin_v1 | 1 × 0.003 | 3.0241548300910677 / 3.0199181716552563 | [0] | 0.0009660703362897038 |
| 2 | class_balanced_contextual_mean_category_v1 | 1 × 0.003 | 2.355927428490806 / 2.353142975747468 | [0] | 0.0007438347674906254 |
| 3 | class_balanced_contextual_decision_margin_v1 | 1 × 0.003 | 3.3986396907354006 / 3.393103897705722 | [0] | 0.0010113522876054049 |
| 4 | class_balanced_contextual_mean_category_v1 | 1 × 0.003 | 2.07796231142592 / 2.0759988306467427 | [0] | 0.0006486925412900746 |
| 5 | class_balanced_contextual_decision_margin_v1 | 1 × 0.003 | 3.0284732225852116 / 3.023090874290589 | [0] | 0.0010753655806183815 |

| Margin attempt | Initial auxiliary BCE | Final auxiliary BCE | Fixed coefficient |
| ---: | ---: | ---: | ---: |
| 1 | 1.053728283738076 | 1.0520744735856469 | 1.0 |
| 3 | 1.0427122622445948 | 1.041054380357984 | 1.0 |
| 5 | 0.9505109111592912 | 0.9483412122151241 | 1.0 |

Trace losses are runtime-recorded on each shared batch; full totals from different objectives are not directly comparable quality. The union-margin surrogate does not imply exact decoder equivalence at ties/threshold/float32 boundaries. Decoder and guards remain unchanged. Transported deltas and rounded parameter displacement can differ.

Fresh objective paired prediction changes, metric differences, immutable inventories, raw/report/response/model identities and service latency summaries remain in JSON. Archived phase05 controls prove selected-input continuity and do not rank this study.

