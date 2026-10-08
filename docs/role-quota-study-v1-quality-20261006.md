# Role-quota fuzzer model quality

complete reconciled study

All 12 attempts start independently from exact live balanced train.2. Both modes use the class-balanced mean-category objective; quota intentionally changes training-row exposure.

| Attempt | Strategy / objective | Rate / seed | Outcome | Pipeline recall / specificity / balanced accuracy |
| ---: | --- | --- | --- | ---: |
| 0 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 1 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 2 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 3 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 4 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 5 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 6 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | rejected; no scored model quality | — / — / — |
| 7 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | rejected; no scored model quality | — / — / — |
| 8 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | rejected; no scored model quality | — / — / — |
| 9 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | rejected; no scored model quality | — / — / — |
| 10 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | rejected; no scored model quality | — / — / — |
| 11 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | rejected; no scored model quality | — / — / — |

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
| attempt 0 / pooled | semantic | 475 / 493 | 245 / 156 / 337 / 230 | 51.58% | 31.64% | 42.10% | 46.36% | 41.61% |
| attempt 0 / AI4Privacy/OpenPII | semantic | 133 / 39 | 61 / 14 / 25 / 72 | 45.86% | 35.90% | 70.93% | 55.71% | 40.88% |
| attempt 0 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 0 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 0 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 0 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 0 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 0 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 0 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 0 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 1 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 1 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 1 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 1 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 1 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 1 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 1 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 1 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 1 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 1 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 2 / pooled | semantic | 475 / 493 | 246 / 157 / 336 / 229 | 51.79% | 31.85% | 42.27% | 46.55% | 41.82% |
| attempt 2 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 2 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 2 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 2 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 2 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 2 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 2 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 2 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 2 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 3 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 3 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 3 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 3 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 3 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 3 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 3 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 3 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 3 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 3 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 4 / pooled | semantic | 475 / 493 | 246 / 157 / 336 / 229 | 51.79% | 31.85% | 42.27% | 46.55% | 41.82% |
| attempt 4 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 4 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 4 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 4 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 4 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 4 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 4 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 4 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 4 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 5 / pooled | semantic | 475 / 493 | 246 / 156 / 337 / 229 | 51.79% | 31.64% | 42.20% | 46.50% | 41.72% |
| attempt 5 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 5 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 5 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 5 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 5 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 5 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 5 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 5 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
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
| 0 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.39492777777777827 | 1.7849373482587683 |
| 1 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5072279681103204 | 1.9704265463529917 |
| 2 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.3897513440860216 | 1.7888107909533653 |
| 3 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.5137752525252526 | 2.355927428490806 |
| 4 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.4585751237067034 | 1.8292780618530662 |
| 5 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.43425017483236644 | 2.07796231142592 |
| 6 | — → — | — → — | — → — | — | — | — |
| 7 | — → — | — → — | — → — | — | — | — |
| 8 | — → — | — → — | — → — | — | — | — |
| 9 | — → — | — → — | — → — | — | — | — |
| 10 | — → — | — → — | — → — | — | — | — |
| 11 | — → — | — → — | — → — | — | — | — |

Legacy average_loss measures weighted classification distance. The optimized objective uses sensitivity CE + visibility CE + category BCE averaged across labels, preserving class balance and original total weight. The classification-distance diagnostic measures a different quantity.

| Accepted attempt | Actual training class rows | Raw class weights | Effective class weights | Clean / sensitive objective mass |
| ---: | --- | --- | --- | --- |
| 0 | 250 / 6 | 250.0 / 6.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 1 | 221 / 35 | 221.0 / 35.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 2 | 248 / 8 | 248.0 / 8.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 3 | 220 / 36 | 220.0 / 36.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 4 | 247 / 9 | 247.0 / 9.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 5 | 219 / 37 | 219.0 / 37.0 | 128.0 / 128.0 | 0.5 / 0.5 |

No eligible frozen winner; no candidate development/fixture score claimed. Retained: False.

Model and training identities, parameter dimensions/counts, trainable/frozen tensors, publication changes, held-out guards, loss definitions, paired predictions, sampling inventories and immutable source/report commitments are retained in the JSON evidence. Service timings exclude browser overhead and do not establish production latency.

- Both sampling modes are freshly fitted; representation/seed pairs retain identical held-out examples while training exposure intentionally differs.
- Quota roles use provisional existing contextual targets, not independent human contextual labels or external annotation-presence truth.
- Sparse authored families can receive increased row exposure and half the class objective mass; this supplies no new supervision or broad coverage guarantee.
- All attempts start from the same seeded encoder/live train.2 base; parameter counts and profile names do not rank measured quality.
- Validation and development are reused exploratory evidence; untouched generalization and statistical superiority remain unestablished.
- The optimized CE/mean-BCE objective and legacy weighted classification-distance diagnostic have different meanings/scales.
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
| 0 | uniform | not individually audited; authored total 8 | 244 / 4 | no quota uniqueness claim | see inventory |
| 1 | role quota | 32 / 32 | 189 / 3 | 256 | 10 |
| 2 | uniform | not individually audited; authored total 8 | 243 / 5 | no quota uniqueness claim | see inventory |
| 3 | role quota | 32 / 32 | 187 / 5 | 256 | 9 |
| 4 | uniform | not individually audited; authored total 8 | 240 / 8 | no quota uniqueness claim | see inventory |
| 5 | role quota | 32 / 32 | 185 / 7 | 256 | 11 |
| 6 | uniform | not individually audited; authored total 8 | 244 / 4 | no quota uniqueness claim | see inventory |
| 7 | role quota | 32 / 32 | 189 / 3 | 256 | 10 |
| 8 | uniform | not individually audited; authored total 8 | 243 / 5 | no quota uniqueness claim | see inventory |
| 9 | role quota | 32 / 32 | 187 / 5 | 256 | 9 |
| 10 | uniform | not individually audited; authored total 8 | 240 / 8 | no quota uniqueness claim | see inventory |
| 11 | role quota | 32 / 32 | 185 / 7 | 256 | 11 |

Quota preflight inventories describe the exact source-bound selection before RPC. Accepted response audits must match; rejected updates receive no invented model score.

| Attempt | Sensitivity CE | Visibility CE | Mean category BCE | Optimized objective |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 1.4107177411864749 | 0.1643719675710923 | 0.20984763950120103 | 1.7849373482587683 |
| 1 | 1.433733586836074 | 0.27225647996916075 | 0.26443647954775695 | 1.9704265463529917 |
| 2 | 1.329871451442185 | 0.19941289805300944 | 0.2595264414581709 | 1.7888107909533653 |
| 3 | 1.375926528514175 | 0.6844956397562441 | 0.29550526022038653 | 2.355927428490806 |
| 4 | 1.1532169342161578 | 0.5313415962828564 | 0.144719531354052 | 1.8292780618530662 |
| 5 | 1.241070021700417 | 0.6048539983570901 | 0.23203829136841317 | 2.07796231142592 |

Fresh uniform/quota paired prediction changes, metric differences, immutable inventories, raw/report/response/model identities and service latency summaries remain in JSON. Historical phase03 evidence proves default-sampling continuity and does not rank this study.

