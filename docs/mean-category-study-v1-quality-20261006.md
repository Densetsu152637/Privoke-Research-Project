# Mean-category fuzzer model quality

complete reconciled study

All 12 mean-category attempts start independently from the same exact live balanced train.2 model. Each target class receives half the original total training weight, preserving within-class relative weights.

| Attempt | Strategy / objective | Rate / seed | Outcome | Pipeline recall / specificity / balanced accuracy |
| ---: | --- | --- | --- | ---: |
| 0 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 1 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 2 | heads / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 3 | heads / class_balanced_contextual_mean_category_v1 | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 4 | heads / class_balanced_contextual_mean_category_v1 | 0.01 / 1337 | accepted/scored | 89.68% / 29.61% / 59.65% |
| 5 | heads / class_balanced_contextual_mean_category_v1 | 0.01 / 2026 | accepted/scored | 89.68% / 29.82% / 59.75% |
| 6 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 42 | rejected; no scored model quality | — / — / — |
| 7 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 1337 | rejected; no scored model quality | — / — / — |
| 8 | last_block / class_balanced_contextual_mean_category_v1 | 0.003 / 2026 | rejected; no scored model quality | — / — / — |
| 9 | last_block / class_balanced_contextual_mean_category_v1 | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 10 | last_block / class_balanced_contextual_mean_category_v1 | 0.01 / 1337 | rejected; no scored model quality | — / — / — |
| 11 | last_block / class_balanced_contextual_mean_category_v1 | 0.01 / 2026 | rejected; no scored model quality | — / — / — |

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
| attempt 1 / pooled | semantic | 475 / 493 | 246 / 157 / 336 / 229 | 51.79% | 31.85% | 42.27% | 46.55% | 41.82% |
| attempt 1 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 1 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 1 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 1 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 1 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 1 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 1 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 1 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
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
| attempt 4 / pooled | semantic | 475 / 493 | 243 / 158 / 335 / 232 | 51.16% | 32.05% | 42.04% | 46.15% | 41.60% |
| attempt 4 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% | 40.51% |
| attempt 4 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% | 47.75% |
| attempt 4 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 4 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 4 / pooled | pipeline | 475 / 493 | 426 / 146 / 347 / 49 | 89.68% | 29.61% | 55.11% | 68.27% | 59.65% |
| attempt 4 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% | 62.91% |
| attempt 4 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 4 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 4 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 5 / pooled | semantic | 475 / 493 | 243 / 159 / 334 / 232 | 51.16% | 32.25% | 42.11% | 46.20% | 41.70% |
| attempt 5 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 15 / 24 / 73 | 45.11% | 38.46% | 71.43% | 55.30% | 41.79% |
| attempt 5 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% | 47.75% |
| attempt 5 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 5 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 5 / pooled | pipeline | 475 / 493 | 426 / 147 / 346 / 49 | 89.68% | 29.82% | 55.18% | 68.32% | 59.75% |
| attempt 5 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 14 / 25 / 10 | 92.48% | 35.90% | 83.11% | 87.54% | 64.19% |
| attempt 5 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 5 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 5 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |

| Model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |
| --- | --- | ---: | --- | --- |
| live balanced baseline | v0.3.0+train.2 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 0 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 1 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 2 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 4 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 5 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |

| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.39492777777777827 | 1.7849373482587683 |
| 1 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.3897513440860216 | 1.7888107909533653 |
| 2 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.4585751237067034 | 1.8292780618530662 |
| 3 | — → — | — → — | — → — | — | — | — |
| 4 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.3897513440860216 | 1.7888107909533653 |
| 5 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.4585751237067034 | 1.8292780618530662 |
| 6 | — → — | — → — | — → — | — | — | — |
| 7 | — → — | — → — | — → — | — | — | — |
| 8 | — → — | — → — | — → — | — | — | — |
| 9 | — → — | — → — | — → — | — | — | — |
| 10 | — → — | — → — | — → — | — | — | — |
| 11 | — → — | — → — | — → — | — | — | — |

Legacy average_loss measures weighted classification distance. The new objective uses sensitivity CE + visibility CE + category BCE averaged over labels for both training strategies. Historical summed-category controls and new mean-category treatments optimize differently scaled losses; losses are not interchangeable quality scores.

| Accepted attempt | Actual training class rows | Raw class weights | Effective class weights | Clean / sensitive objective mass |
| ---: | --- | --- | --- | --- |
| 0 | 250 / 6 | 250.0 / 6.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 1 | 248 / 8 | 248.0 / 8.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 2 | 247 / 9 | 247.0 / 9.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 4 | 248 / 8 | 248.0 / 8.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 5 | 247 / 9 | 247.0 / 9.0 | 128.0 / 128.0 | 0.5 / 0.5 |

No eligible frozen winner; no candidate development/fixture score claimed. Retained: False.

Model and training identities, parameter dimensions/counts, trainable/frozen tensors, publication changes, held-out guards, loss definitions, paired predictions, sampling inventories and immutable source/report commitments are retained in the JSON evidence. Service timings exclude browser overhead and do not establish production latency.

- Historical controls were archived, not refitted or randomized contemporaneously; comparisons are exploratory.
- Category-gradient dominance is an unmeasured hypothesis; task loss magnitudes are not gradient norm measurements.
- Model names and parameter counts are not quality rankings; the seeded encoder and live base include authored supervision and prior training.
- Training samples contain only 6, 8 or 9 sensitivity-positive rows; class balancing amplifies sparse provisional targets.
- Presence annotations do not establish contextual severity, visibility, complete span recovery or action correctness.
- Validation and development are reused; untouched generalization and statistical superiority remain unestablished.
- Diagnostic distance, summed-category objective and mean-category objective have different scales and meanings.
- Confidence calibration and representative production latency remain unestablished.
- Prior failed studies remain separate evidence; no protected final examples or labels are opened.

| Attempt | Sensitivity CE | Visibility CE | Mean category BCE | True objective |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 1.4107177411864749 | 0.1643719675710923 | 0.20984763950120103 | 1.7849373482587683 |
| 1 | 1.329871451442185 | 0.19941289805300944 | 0.2595264414581709 | 1.7888107909533653 |
| 2 | 1.1532169342161578 | 0.5313415962828564 | 0.144719531354052 | 1.8292780618530662 |
| 4 | 1.329871451442185 | 0.19941289805300944 | 0.2595264414581709 | 1.7888107909533653 |
| 5 | 1.1532169342161578 | 0.5313415962828564 | 0.144719531354052 | 1.8292780618530662 |

| New attempt | Historical summed-category control | Control outcome | Pipeline recall / specificity |
| ---: | ---: | --- | ---: |
| 0 | 1 | accepted/scored | 89.89% / 29.21% |
| 1 | 3 | accepted/scored | 89.89% / 29.41% |
| 2 | 5 | accepted/scored | 89.89% / 29.41% |
| 3 | 7 | rejected/unscored | — / — |
| 4 | 9 | accepted/scored | 89.68% / 29.61% |
| 5 | 11 | accepted/scored | 89.68% / 29.82% |
| 6 | 13 | rejected/unscored | — / — |
| 7 | 15 | rejected/unscored | — / — |
| 8 | 17 | rejected/unscored | — / — |
| 9 | 19 | rejected/unscored | — / — |
| 10 | 21 | rejected/unscored | — / — |
| 11 | 23 | rejected/unscored | — / — |

Historical controls use identical ordered original training and held-out inputs, but were run earlier. They do not select the new winner. Paired prediction changes and source-specific metrics remain in JSON.

