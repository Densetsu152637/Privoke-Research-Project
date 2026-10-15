# Contextual fuzzer model quality

complete reconciled study

Evidence: [ctxfuzz20261006v2](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2>) · state SHA-256 `c6cf46d7a5f3e84cc0d38a6b57e4da3511e9d1bd876950a0cca958e2aeb7d0d6`.

Quality is assessed from matched semantic and full-pipeline predictions. Capacity names do not establish accuracy. Validation contains 475 positive and 493 negative rows, reused for exploratory selection; final remains uninspected and unscored. A dash means an absent measurement or undefined rate, never zero.

| Original profile | Layer | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| efficient | semantic | 282 / 156 / 337 / 193 | 59.37% | 31.64% | 45.56% | 51.55% |
| efficient | pipeline | 442 / 146 / 347 / 33 | 93.05% | 29.61% | 56.02% | 69.94% |
| balanced | semantic | 283 / 133 / 360 / 192 | 59.58% | 26.98% | 44.01% | 50.63% |
| balanced | pipeline | 435 / 122 / 371 / 40 | 91.58% | 24.75% | 53.97% | 67.92% |
| quality | semantic | 334 / 112 / 381 / 141 | 70.32% | 22.72% | 46.71% | 56.13% |
| quality | pipeline | 445 / 108 / 385 / 30 | 93.68% | 21.91% | 53.61% | 68.20% |

| Attempt | Profile / strategy | Rate / seed | Status / reason | Semantic recall / specificity | Pipeline recall / specificity | Train / held-out sensitivity-positive rows |
| ---: | --- | --- | --- | ---: | ---: | ---: |
| 0 | efficient / heads | 0.003 / 42 | accepted/scored validation-eligible | 58.95% / 32.05% | 93.05% / 30.02% | 6/256; 8/16 |
| 1 | efficient / heads | 0.003 / 1337 | accepted/scored validation-eligible | 58.95% / 32.05% | 93.05% / 30.02% | 8/256; 8/16 |
| 2 | efficient / heads | 0.003 / 2026 | accepted/scored validation-eligible | 58.95% / 32.05% | 93.05% / 30.02% | 9/256; 8/16 |
| 3 | efficient / heads | 0.01 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 4 | efficient / heads | 0.01 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 5 | efficient / heads | 0.01 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 6 | efficient / heads | 0.03 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 7 | efficient / heads | 0.03 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 8 | efficient / heads | 0.03 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 9 | efficient / last_block | 0.003 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 10 | efficient / last_block | 0.003 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 11 | efficient / last_block | 0.003 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 12 | efficient / last_block | 0.01 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 13 | efficient / last_block | 0.01 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 14 | efficient / last_block | 0.01 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 15 | efficient / last_block | 0.03 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 16 | efficient / last_block | 0.03 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 17 | efficient / last_block | 0.03 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 18 | balanced / heads | 0.003 / 42 | accepted/scored validation-eligible | 58.53% / 27.79% | 91.58% / 25.35% | 6/256; 8/16 |
| 19 | balanced / heads | 0.003 / 1337 | accepted/scored validation-eligible | 58.53% / 27.79% | 91.58% / 25.35% | 8/256; 8/16 |
| 20 | balanced / heads | 0.003 / 2026 | accepted/scored validation-eligible | 58.53% / 27.79% | 91.58% / 25.35% | 9/256; 8/16 |
| 21 | balanced / heads | 0.01 / 42 | accepted/scored validation-eligible | 56.63% / 29.21% | 90.74% / 26.77% | 6/256; 8/16 |
| 22 | balanced / heads | 0.01 / 1337 | accepted/scored validation-eligible | 56.63% / 29.21% | 90.74% / 26.77% | 8/256; 8/16 |
| 23 | balanced / heads | 0.01 / 2026 | accepted/scored validation-eligible | 56.84% / 29.21% | 90.74% / 26.77% | 9/256; 8/16 |
| 24 | balanced / heads | 0.03 / 42 | accepted/scored validation-ineligible | 51.16% / 32.25% | 89.68% / 29.82% | 6/256; 8/16 |
| 25 | balanced / heads | 0.03 / 1337 | accepted/scored validation-ineligible | 51.16% / 32.45% | 89.68% / 30.02% | 8/256; 8/16 |
| 26 | balanced / heads | 0.03 / 2026 | accepted/scored validation-ineligible | 51.16% / 32.05% | 89.68% / 29.61% | 9/256; 8/16 |
| 27 | balanced / last_block | 0.003 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 28 | balanced / last_block | 0.003 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 29 | balanced / last_block | 0.003 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 30 | balanced / last_block | 0.01 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 31 | balanced / last_block | 0.01 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 32 | balanced / last_block | 0.01 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 33 | balanced / last_block | 0.03 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 34 | balanced / last_block | 0.03 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 35 | balanced / last_block | 0.03 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 36 | quality / heads | 0.003 / 42 | accepted/scored validation-ineligible | 69.47% / 22.72% | 93.47% / 21.91% | 6/256; 8/16 |
| 37 | quality / heads | 0.003 / 1337 | accepted/scored validation-ineligible | 69.47% / 22.72% | 93.47% / 21.91% | 8/256; 8/16 |
| 38 | quality / heads | 0.003 / 2026 | accepted/scored validation-ineligible | 69.47% / 22.72% | 93.47% / 21.91% | 9/256; 8/16 |
| 39 | quality / heads | 0.01 / 42 | accepted/scored validation-eligible | 68.84% / 23.53% | 93.05% / 22.72% | 6/256; 8/16 |
| 40 | quality / heads | 0.01 / 1337 | accepted/scored validation-eligible | 68.84% / 23.53% | 93.05% / 22.72% | 8/256; 8/16 |
| 41 | quality / heads | 0.01 / 2026 | accepted/scored validation-eligible | 68.84% / 23.53% | 93.05% / 22.72% | 9/256; 8/16 |
| 42 | quality / heads | 0.03 / 42 | accepted/scored validation-eligible | 65.89% / 25.56% | 92.63% / 24.75% | 6/256; 8/16 |
| 43 | quality / heads | 0.03 / 1337 | accepted/scored validation-eligible | 65.89% / 25.76% | 92.63% / 24.95% | 8/256; 8/16 |
| 44 | quality / heads | 0.03 / 2026 | accepted/scored validation-eligible | 65.89% / 25.76% | 92.63% / 24.95% | 9/256; 8/16 |
| 45 | quality / last_block | 0.003 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 46 | quality / last_block | 0.003 / 1337 | accepted/scored validation-ineligible | 46.11% / 41.78% | 88.21% / 39.35% | 8/256; 8/16 |
| 47 | quality / last_block | 0.003 / 2026 | accepted/scored validation-ineligible | 45.68% / 41.78% | 87.79% / 39.35% | 9/256; 8/16 |
| 48 | quality / last_block | 0.01 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 49 | quality / last_block | 0.01 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 50 | quality / last_block | 0.01 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |
| 51 | quality / last_block | 0.03 / 42 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 6/256; 8/16 |
| 52 | quality / last_block | 0.03 / 1337 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 8/256; 8/16 |
| 53 | quality / last_block | 0.03 / 2026 | rejected; no quality score claimed: Candidate model is worse on the held-out evaluation set. | — / — | — / — | 9/256; 8/16 |

Sampling coverage counts authored sensitivity labels S1/S2/S3. It does not supply external presence, severity or action truth. Full role counts and opaque whole-family IDs/labels are retained in JSON.

| Accepted attempt | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |
| ---: | --- | ---: | --- | ---: | ---: | ---: | ---: |
| 0 | semantic | 475 / 493 | 280 / 158 / 335 / 195 | 58.95% | 32.05% | 45.53% | 51.38% |
| 0 | pipeline | 475 / 493 | 442 / 148 / 345 / 33 | 93.05% | 30.02% | 56.16% | 70.05% |
| 1 | semantic | 475 / 493 | 280 / 158 / 335 / 195 | 58.95% | 32.05% | 45.53% | 51.38% |
| 1 | pipeline | 475 / 493 | 442 / 148 / 345 / 33 | 93.05% | 30.02% | 56.16% | 70.05% |
| 2 | semantic | 475 / 493 | 280 / 158 / 335 / 195 | 58.95% | 32.05% | 45.53% | 51.38% |
| 2 | pipeline | 475 / 493 | 442 / 148 / 345 / 33 | 93.05% | 30.02% | 56.16% | 70.05% |
| 18 | semantic | 475 / 493 | 278 / 137 / 356 / 197 | 58.53% | 27.79% | 43.85% | 50.14% |
| 18 | pipeline | 475 / 493 | 435 / 125 / 368 / 40 | 91.58% | 25.35% | 54.17% | 68.08% |
| 19 | semantic | 475 / 493 | 278 / 137 / 356 / 197 | 58.53% | 27.79% | 43.85% | 50.14% |
| 19 | pipeline | 475 / 493 | 435 / 125 / 368 / 40 | 91.58% | 25.35% | 54.17% | 68.08% |
| 20 | semantic | 475 / 493 | 278 / 137 / 356 / 197 | 58.53% | 27.79% | 43.85% | 50.14% |
| 20 | pipeline | 475 / 493 | 435 / 125 / 368 / 40 | 91.58% | 25.35% | 54.17% | 68.08% |
| 21 | semantic | 475 / 493 | 269 / 144 / 349 / 206 | 56.63% | 29.21% | 43.53% | 49.22% |
| 21 | pipeline | 475 / 493 | 431 / 132 / 361 / 44 | 90.74% | 26.77% | 54.42% | 68.03% |
| 22 | semantic | 475 / 493 | 269 / 144 / 349 / 206 | 56.63% | 29.21% | 43.53% | 49.22% |
| 22 | pipeline | 475 / 493 | 431 / 132 / 361 / 44 | 90.74% | 26.77% | 54.42% | 68.03% |
| 23 | semantic | 475 / 493 | 270 / 144 / 349 / 205 | 56.84% | 29.21% | 43.62% | 49.36% |
| 23 | pipeline | 475 / 493 | 431 / 132 / 361 / 44 | 90.74% | 26.77% | 54.42% | 68.03% |
| 24 | semantic | 475 / 493 | 243 / 159 / 334 / 232 | 51.16% | 32.25% | 42.11% | 46.20% |
| 24 | pipeline | 475 / 493 | 426 / 147 / 346 / 49 | 89.68% | 29.82% | 55.18% | 68.32% |
| 25 | semantic | 475 / 493 | 243 / 160 / 333 / 232 | 51.16% | 32.45% | 42.19% | 46.24% |
| 25 | pipeline | 475 / 493 | 426 / 148 / 345 / 49 | 89.68% | 30.02% | 55.25% | 68.38% |
| 26 | semantic | 475 / 493 | 243 / 158 / 335 / 232 | 51.16% | 32.05% | 42.04% | 46.15% |
| 26 | pipeline | 475 / 493 | 426 / 146 / 347 / 49 | 89.68% | 29.61% | 55.11% | 68.27% |
| 36 | semantic | 475 / 493 | 330 / 112 / 381 / 145 | 69.47% | 22.72% | 46.41% | 55.65% |
| 36 | pipeline | 475 / 493 | 444 / 108 / 385 / 31 | 93.47% | 21.91% | 53.56% | 68.10% |
| 37 | semantic | 475 / 493 | 330 / 112 / 381 / 145 | 69.47% | 22.72% | 46.41% | 55.65% |
| 37 | pipeline | 475 / 493 | 444 / 108 / 385 / 31 | 93.47% | 21.91% | 53.56% | 68.10% |
| 38 | semantic | 475 / 493 | 330 / 112 / 381 / 145 | 69.47% | 22.72% | 46.41% | 55.65% |
| 38 | pipeline | 475 / 493 | 444 / 108 / 385 / 31 | 93.47% | 21.91% | 53.56% | 68.10% |
| 39 | semantic | 475 / 493 | 327 / 116 / 377 / 148 | 68.84% | 23.53% | 46.45% | 55.47% |
| 39 | pipeline | 475 / 493 | 442 / 112 / 381 / 33 | 93.05% | 22.72% | 53.71% | 68.10% |
| 40 | semantic | 475 / 493 | 327 / 116 / 377 / 148 | 68.84% | 23.53% | 46.45% | 55.47% |
| 40 | pipeline | 475 / 493 | 442 / 112 / 381 / 33 | 93.05% | 22.72% | 53.71% | 68.10% |
| 41 | semantic | 475 / 493 | 327 / 116 / 377 / 148 | 68.84% | 23.53% | 46.45% | 55.47% |
| 41 | pipeline | 475 / 493 | 442 / 112 / 381 / 33 | 93.05% | 22.72% | 53.71% | 68.10% |
| 42 | semantic | 475 / 493 | 313 / 126 / 367 / 162 | 65.89% | 25.56% | 46.03% | 54.20% |
| 42 | pipeline | 475 / 493 | 440 / 122 / 371 / 35 | 92.63% | 24.75% | 54.25% | 68.43% |
| 43 | semantic | 475 / 493 | 313 / 127 / 366 / 162 | 65.89% | 25.76% | 46.10% | 54.25% |
| 43 | pipeline | 475 / 493 | 440 / 123 / 370 / 35 | 92.63% | 24.95% | 54.32% | 68.48% |
| 44 | semantic | 475 / 493 | 313 / 127 / 366 / 162 | 65.89% | 25.76% | 46.10% | 54.25% |
| 44 | pipeline | 475 / 493 | 440 / 123 / 370 / 35 | 92.63% | 24.95% | 54.32% | 68.48% |
| 46 | semantic | 475 / 493 | 219 / 206 / 287 / 256 | 46.11% | 41.78% | 43.28% | 44.65% |
| 46 | pipeline | 475 / 493 | 419 / 194 / 299 / 56 | 88.21% | 39.35% | 58.36% | 70.24% |
| 47 | semantic | 475 / 493 | 217 / 206 / 287 / 258 | 45.68% | 41.78% | 43.06% | 44.33% |
| 47 | pipeline | 475 / 493 | 417 / 194 / 299 / 58 | 87.79% | 39.35% | 58.24% | 70.03% |

| Measured model | Layer | Balanced accuracy |
| --- | --- | ---: |
| original efficient | semantic | 45.51% |
| original efficient | pipeline | 61.33% |
| original balanced | semantic | 43.28% |
| original balanced | pipeline | 58.16% |
| original quality | semantic | 46.52% |
| original quality | pipeline | 57.80% |
| attempt 0 | semantic | 45.50% |
| attempt 0 | pipeline | 61.54% |
| attempt 1 | semantic | 45.50% |
| attempt 1 | pipeline | 61.54% |
| attempt 2 | semantic | 45.50% |
| attempt 2 | pipeline | 61.54% |
| attempt 18 | semantic | 43.16% |
| attempt 18 | pipeline | 58.47% |
| attempt 19 | semantic | 43.16% |
| attempt 19 | pipeline | 58.47% |
| attempt 20 | semantic | 43.16% |
| attempt 20 | pipeline | 58.47% |
| attempt 21 | semantic | 42.92% |
| attempt 21 | pipeline | 58.76% |
| attempt 22 | semantic | 42.92% |
| attempt 22 | pipeline | 58.76% |
| attempt 23 | semantic | 43.03% |
| attempt 23 | pipeline | 58.76% |
| attempt 24 | semantic | 41.70% |
| attempt 24 | pipeline | 59.75% |
| attempt 25 | semantic | 41.81% |
| attempt 25 | pipeline | 59.85% |
| attempt 26 | semantic | 41.60% |
| attempt 26 | pipeline | 59.65% |
| attempt 36 | semantic | 46.10% |
| attempt 36 | pipeline | 57.69% |
| attempt 37 | semantic | 46.10% |
| attempt 37 | pipeline | 57.69% |
| attempt 38 | semantic | 46.10% |
| attempt 38 | pipeline | 57.69% |
| attempt 39 | semantic | 46.19% |
| attempt 39 | pipeline | 57.89% |
| attempt 40 | semantic | 46.19% |
| attempt 40 | pipeline | 57.89% |
| attempt 41 | semantic | 46.19% |
| attempt 41 | pipeline | 57.89% |
| attempt 42 | semantic | 45.73% |
| attempt 42 | pipeline | 58.69% |
| attempt 43 | semantic | 45.83% |
| attempt 43 | pipeline | 58.79% |
| attempt 44 | semantic | 45.83% |
| attempt 44 | pipeline | 58.79% |
| attempt 46 | semantic | 43.95% |
| attempt 46 | pipeline | 63.78% |
| attempt 47 | semantic | 43.73% |
| attempt 47 | pipeline | 63.57% |

Balanced accuracy averages recall and specificity. It is undefined when either class is absent; these descriptive scores do not establish statistical superiority.

| Measured model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |
| --- | --- | ---: | --- | --- |
| original efficient | v0.3.0 | 19028 / 500 | 24 / 48 / 1 / 2 / 64 / 512 | six contextual heads; encoder frozen |
| original balanced | v0.3.0 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| original quality | v0.3.0 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 0 | v0.3.0+train.1 | 19028 / 500 | 24 / 48 / 1 / 2 / 64 / 512 | six contextual heads; encoder frozen |
| attempt 1 | v0.3.0+train.1 | 19028 / 500 | 24 / 48 / 1 / 2 / 64 / 512 | six contextual heads; encoder frozen |
| attempt 2 | v0.3.0+train.1 | 19028 / 500 | 24 / 48 / 1 / 2 / 64 / 512 | six contextual heads; encoder frozen |
| attempt 18 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 19 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 20 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 21 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 22 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 23 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 24 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 25 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 26 | v0.3.0+train.1 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 36 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 37 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 38 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 39 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 40 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 41 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 42 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 43 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 44 | v0.3.0+train.1 | 54292 / 660 | 32 / 64 / 3 / 4 / 128 / 768 | six contextual heads; encoder frozen |
| attempt 46 | v0.3.0+train.1 | 54292 / 8980 | 32 / 64 / 3 / 4 / 128 / 768 | last encoder block plus six contextual heads |
| attempt 47 | v0.3.0+train.1 | 54292 / 8980 | 32 / 64 / 3 / 4 / 128 / 768 | last encoder block plus six contextual heads |

| Model | Semantic misses rescued by pipeline | Semantic detections lost | Clean pipeline-only flags | With regex / NER signal | Clean semantic flags removed |
| --- | ---: | ---: | ---: | ---: | ---: |
| original efficient | 160 | 0 | 10 | 5 / 5 | 0 |
| original balanced | 152 | 0 | 11 | 5 / 8 | 0 |
| original quality | 111 | 0 | 4 | 1 / 3 | 0 |
| attempt 0 | 162 | 0 | 10 | 5 / 5 | 0 |
| attempt 1 | 162 | 0 | 10 | 5 / 5 | 0 |
| attempt 2 | 162 | 0 | 10 | 5 / 5 | 0 |
| attempt 18 | 157 | 0 | 12 | 5 / 9 | 0 |
| attempt 19 | 157 | 0 | 12 | 5 / 9 | 0 |
| attempt 20 | 157 | 0 | 12 | 5 / 9 | 0 |
| attempt 21 | 162 | 0 | 12 | 5 / 9 | 0 |
| attempt 22 | 162 | 0 | 12 | 5 / 9 | 0 |
| attempt 23 | 161 | 0 | 12 | 5 / 9 | 0 |
| attempt 24 | 183 | 0 | 12 | 5 / 9 | 0 |
| attempt 25 | 183 | 0 | 12 | 5 / 9 | 0 |
| attempt 26 | 183 | 0 | 12 | 5 / 9 | 0 |
| attempt 36 | 114 | 0 | 4 | 1 / 3 | 0 |
| attempt 37 | 114 | 0 | 4 | 1 / 3 | 0 |
| attempt 38 | 114 | 0 | 4 | 1 / 3 | 0 |
| attempt 39 | 115 | 0 | 4 | 1 / 3 | 0 |
| attempt 40 | 115 | 0 | 4 | 1 / 3 | 0 |
| attempt 41 | 115 | 0 | 4 | 1 / 3 | 0 |
| attempt 42 | 127 | 0 | 4 | 1 / 3 | 0 |
| attempt 43 | 127 | 0 | 4 | 1 / 3 | 0 |
| attempt 44 | 127 | 0 | 4 | 1 / 3 | 0 |
| attempt 46 | 200 | 0 | 12 | 5 / 8 | 0 |
| attempt 47 | 200 | 0 | 12 | 5 / 8 | 0 |

Regex/NER signals may overlap. These matched output transitions describe co-occurrences, not causal attribution or contextual privacy correctness.

| Model / source | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| original efficient / AI4Privacy/OpenPII | semantic | 133 / 39 | 82 / 17 / 22 / 51 | 61.65% | 43.59% | 78.85% | 69.20% |
| original efficient / gretel | semantic | 98 / 54 | 49 / 17 / 37 / 49 | 50.00% | 31.48% | 56.98% | 53.26% |
| original efficient / nemotron-pii | semantic | 206 / 384 | 120 / 119 / 265 / 86 | 58.25% | 30.99% | 31.17% | 40.61% |
| original efficient / privy | semantic | 38 / 16 | 31 / 3 / 13 / 7 | 81.58% | 18.75% | 70.45% | 75.61% |
| original efficient / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 15 / 24 / 10 | 92.48% | 38.46% | 83.67% | 87.86% |
| original efficient / gretel | pipeline | 98 / 54 | 96 / 16 / 38 / 2 | 97.96% | 29.63% | 71.64% | 82.76% |
| original efficient / nemotron-pii | pipeline | 206 / 384 | 185 / 115 / 269 / 21 | 89.81% | 29.95% | 40.75% | 56.06% |
| original efficient / privy | pipeline | 38 / 16 | 38 / 0 / 16 / 0 | 100.00% | 0.00% | 70.37% | 82.61% |
| original balanced / AI4Privacy/OpenPII | semantic | 133 / 39 | 74 / 13 / 26 / 59 | 55.64% | 33.33% | 74.00% | 63.52% |
| original balanced / gretel | semantic | 98 / 54 | 79 / 10 / 44 / 19 | 80.61% | 18.52% | 64.23% | 71.49% |
| original balanced / nemotron-pii | semantic | 206 / 384 | 116 / 99 / 285 / 90 | 56.31% | 25.78% | 28.93% | 38.22% |
| original balanced / privy | semantic | 38 / 16 | 14 / 11 / 5 / 24 | 36.84% | 68.75% | 73.68% | 49.12% |
| original balanced / AI4Privacy/OpenPII | pipeline | 133 / 39 | 125 / 12 / 27 / 8 | 93.98% | 30.77% | 82.24% | 87.72% |
| original balanced / gretel | pipeline | 98 / 54 | 96 / 9 / 45 / 2 | 97.96% | 16.67% | 68.09% | 80.33% |
| original balanced / nemotron-pii | pipeline | 206 / 384 | 181 / 94 / 290 / 25 | 87.86% | 24.48% | 38.43% | 53.47% |
| original balanced / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| original quality / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| original quality / gretel | semantic | 98 / 54 | 67 / 5 / 49 / 31 | 68.37% | 9.26% | 57.76% | 62.62% |
| original quality / nemotron-pii | semantic | 206 / 384 | 144 / 88 / 296 / 62 | 69.90% | 22.92% | 32.73% | 44.58% |
| original quality / privy | semantic | 38 / 16 | 31 / 2 / 14 / 7 | 81.58% | 12.50% | 68.89% | 74.70% |
| original quality / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| original quality / gretel | pipeline | 98 / 54 | 96 / 4 / 50 / 2 | 97.96% | 7.41% | 65.75% | 78.69% |
| original quality / nemotron-pii | pipeline | 206 / 384 | 189 / 87 / 297 / 17 | 91.75% | 22.66% | 38.89% | 54.62% |
| original quality / privy | pipeline | 38 / 16 | 37 / 1 / 15 / 1 | 97.37% | 6.25% | 71.15% | 82.22% |
| attempt 0 / AI4Privacy/OpenPII | semantic | 133 / 39 | 82 / 17 / 22 / 51 | 61.65% | 43.59% | 78.85% | 69.20% |
| attempt 0 / gretel | semantic | 98 / 54 | 48 / 17 / 37 / 50 | 48.98% | 31.48% | 56.47% | 52.46% |
| attempt 0 / nemotron-pii | semantic | 206 / 384 | 119 / 121 / 263 / 87 | 57.77% | 31.51% | 31.15% | 40.48% |
| attempt 0 / privy | semantic | 38 / 16 | 31 / 3 / 13 / 7 | 81.58% | 18.75% | 70.45% | 75.61% |
| attempt 0 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 15 / 24 / 10 | 92.48% | 38.46% | 83.67% | 87.86% |
| attempt 0 / gretel | pipeline | 98 / 54 | 96 / 16 / 38 / 2 | 97.96% | 29.63% | 71.64% | 82.76% |
| attempt 0 / nemotron-pii | pipeline | 206 / 384 | 185 / 117 / 267 / 21 | 89.81% | 30.47% | 40.93% | 56.23% |
| attempt 0 / privy | pipeline | 38 / 16 | 38 / 0 / 16 / 0 | 100.00% | 0.00% | 70.37% | 82.61% |
| attempt 1 / AI4Privacy/OpenPII | semantic | 133 / 39 | 82 / 17 / 22 / 51 | 61.65% | 43.59% | 78.85% | 69.20% |
| attempt 1 / gretel | semantic | 98 / 54 | 48 / 17 / 37 / 50 | 48.98% | 31.48% | 56.47% | 52.46% |
| attempt 1 / nemotron-pii | semantic | 206 / 384 | 119 / 121 / 263 / 87 | 57.77% | 31.51% | 31.15% | 40.48% |
| attempt 1 / privy | semantic | 38 / 16 | 31 / 3 / 13 / 7 | 81.58% | 18.75% | 70.45% | 75.61% |
| attempt 1 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 15 / 24 / 10 | 92.48% | 38.46% | 83.67% | 87.86% |
| attempt 1 / gretel | pipeline | 98 / 54 | 96 / 16 / 38 / 2 | 97.96% | 29.63% | 71.64% | 82.76% |
| attempt 1 / nemotron-pii | pipeline | 206 / 384 | 185 / 117 / 267 / 21 | 89.81% | 30.47% | 40.93% | 56.23% |
| attempt 1 / privy | pipeline | 38 / 16 | 38 / 0 / 16 / 0 | 100.00% | 0.00% | 70.37% | 82.61% |
| attempt 2 / AI4Privacy/OpenPII | semantic | 133 / 39 | 82 / 17 / 22 / 51 | 61.65% | 43.59% | 78.85% | 69.20% |
| attempt 2 / gretel | semantic | 98 / 54 | 48 / 17 / 37 / 50 | 48.98% | 31.48% | 56.47% | 52.46% |
| attempt 2 / nemotron-pii | semantic | 206 / 384 | 119 / 121 / 263 / 87 | 57.77% | 31.51% | 31.15% | 40.48% |
| attempt 2 / privy | semantic | 38 / 16 | 31 / 3 / 13 / 7 | 81.58% | 18.75% | 70.45% | 75.61% |
| attempt 2 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 15 / 24 / 10 | 92.48% | 38.46% | 83.67% | 87.86% |
| attempt 2 / gretel | pipeline | 98 / 54 | 96 / 16 / 38 / 2 | 97.96% | 29.63% | 71.64% | 82.76% |
| attempt 2 / nemotron-pii | pipeline | 206 / 384 | 185 / 117 / 267 / 21 | 89.81% | 30.47% | 40.93% | 56.23% |
| attempt 2 / privy | pipeline | 38 / 16 | 38 / 0 / 16 / 0 | 100.00% | 0.00% | 70.37% | 82.61% |
| attempt 18 / AI4Privacy/OpenPII | semantic | 133 / 39 | 72 / 13 / 26 / 61 | 54.14% | 33.33% | 73.47% | 62.34% |
| attempt 18 / gretel | semantic | 98 / 54 | 79 / 10 / 44 / 19 | 80.61% | 18.52% | 64.23% | 71.49% |
| attempt 18 / nemotron-pii | semantic | 206 / 384 | 113 / 103 / 281 / 93 | 54.85% | 26.82% | 28.68% | 37.67% |
| attempt 18 / privy | semantic | 38 / 16 | 14 / 11 / 5 / 24 | 36.84% | 68.75% | 73.68% | 49.12% |
| attempt 18 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 125 / 12 / 27 / 8 | 93.98% | 30.77% | 82.24% | 87.72% |
| attempt 18 / gretel | pipeline | 98 / 54 | 96 / 9 / 45 / 2 | 97.96% | 16.67% | 68.09% | 80.33% |
| attempt 18 / nemotron-pii | pipeline | 206 / 384 | 181 / 97 / 287 / 25 | 87.86% | 25.26% | 38.68% | 53.71% |
| attempt 18 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 19 / AI4Privacy/OpenPII | semantic | 133 / 39 | 72 / 13 / 26 / 61 | 54.14% | 33.33% | 73.47% | 62.34% |
| attempt 19 / gretel | semantic | 98 / 54 | 79 / 10 / 44 / 19 | 80.61% | 18.52% | 64.23% | 71.49% |
| attempt 19 / nemotron-pii | semantic | 206 / 384 | 113 / 103 / 281 / 93 | 54.85% | 26.82% | 28.68% | 37.67% |
| attempt 19 / privy | semantic | 38 / 16 | 14 / 11 / 5 / 24 | 36.84% | 68.75% | 73.68% | 49.12% |
| attempt 19 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 125 / 12 / 27 / 8 | 93.98% | 30.77% | 82.24% | 87.72% |
| attempt 19 / gretel | pipeline | 98 / 54 | 96 / 9 / 45 / 2 | 97.96% | 16.67% | 68.09% | 80.33% |
| attempt 19 / nemotron-pii | pipeline | 206 / 384 | 181 / 97 / 287 / 25 | 87.86% | 25.26% | 38.68% | 53.71% |
| attempt 19 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 20 / AI4Privacy/OpenPII | semantic | 133 / 39 | 72 / 13 / 26 / 61 | 54.14% | 33.33% | 73.47% | 62.34% |
| attempt 20 / gretel | semantic | 98 / 54 | 79 / 10 / 44 / 19 | 80.61% | 18.52% | 64.23% | 71.49% |
| attempt 20 / nemotron-pii | semantic | 206 / 384 | 113 / 103 / 281 / 93 | 54.85% | 26.82% | 28.68% | 37.67% |
| attempt 20 / privy | semantic | 38 / 16 | 14 / 11 / 5 / 24 | 36.84% | 68.75% | 73.68% | 49.12% |
| attempt 20 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 125 / 12 / 27 / 8 | 93.98% | 30.77% | 82.24% | 87.72% |
| attempt 20 / gretel | pipeline | 98 / 54 | 96 / 9 / 45 / 2 | 97.96% | 16.67% | 68.09% | 80.33% |
| attempt 20 / nemotron-pii | pipeline | 206 / 384 | 181 / 97 / 287 / 25 | 87.86% | 25.26% | 38.68% | 53.71% |
| attempt 20 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 21 / AI4Privacy/OpenPII | semantic | 133 / 39 | 69 / 14 / 25 / 64 | 51.88% | 35.90% | 73.40% | 60.79% |
| attempt 21 / gretel | semantic | 98 / 54 | 77 / 12 / 42 / 21 | 78.57% | 22.22% | 64.71% | 70.97% |
| attempt 21 / nemotron-pii | semantic | 206 / 384 | 110 / 107 / 277 / 96 | 53.40% | 27.86% | 28.42% | 37.10% |
| attempt 21 / privy | semantic | 38 / 16 | 13 / 11 / 5 / 25 | 34.21% | 68.75% | 72.22% | 46.43% |
| attempt 21 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% |
| attempt 21 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% |
| attempt 21 / nemotron-pii | pipeline | 206 / 384 | 179 / 101 / 283 / 27 | 86.89% | 26.30% | 38.74% | 53.59% |
| attempt 21 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 22 / AI4Privacy/OpenPII | semantic | 133 / 39 | 69 / 14 / 25 / 64 | 51.88% | 35.90% | 73.40% | 60.79% |
| attempt 22 / gretel | semantic | 98 / 54 | 77 / 12 / 42 / 21 | 78.57% | 22.22% | 64.71% | 70.97% |
| attempt 22 / nemotron-pii | semantic | 206 / 384 | 110 / 107 / 277 / 96 | 53.40% | 27.86% | 28.42% | 37.10% |
| attempt 22 / privy | semantic | 38 / 16 | 13 / 11 / 5 / 25 | 34.21% | 68.75% | 72.22% | 46.43% |
| attempt 22 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% |
| attempt 22 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% |
| attempt 22 / nemotron-pii | pipeline | 206 / 384 | 179 / 101 / 283 / 27 | 86.89% | 26.30% | 38.74% | 53.59% |
| attempt 22 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 23 / AI4Privacy/OpenPII | semantic | 133 / 39 | 69 / 14 / 25 / 64 | 51.88% | 35.90% | 73.40% | 60.79% |
| attempt 23 / gretel | semantic | 98 / 54 | 78 / 12 / 42 / 20 | 79.59% | 22.22% | 65.00% | 71.56% |
| attempt 23 / nemotron-pii | semantic | 206 / 384 | 110 / 107 / 277 / 96 | 53.40% | 27.86% | 28.42% | 37.10% |
| attempt 23 / privy | semantic | 38 / 16 | 13 / 11 / 5 / 25 | 34.21% | 68.75% | 72.22% | 46.43% |
| attempt 23 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% |
| attempt 23 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% |
| attempt 23 / nemotron-pii | pipeline | 206 / 384 | 179 / 101 / 283 / 27 | 86.89% | 26.30% | 38.74% | 53.59% |
| attempt 23 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 24 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 15 / 24 / 73 | 45.11% | 38.46% | 71.43% | 55.30% |
| attempt 24 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% |
| attempt 24 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% |
| attempt 24 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% |
| attempt 24 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 14 / 25 / 10 | 92.48% | 35.90% | 83.11% | 87.54% |
| attempt 24 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% |
| attempt 24 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% |
| attempt 24 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 25 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 15 / 24 / 73 | 45.11% | 38.46% | 71.43% | 55.30% |
| attempt 25 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% |
| attempt 25 / nemotron-pii | semantic | 206 / 384 | 102 / 121 / 263 / 104 | 49.51% | 31.51% | 27.95% | 35.73% |
| attempt 25 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% |
| attempt 25 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 14 / 25 / 10 | 92.48% | 35.90% | 83.11% | 87.54% |
| attempt 25 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% |
| attempt 25 / nemotron-pii | pipeline | 206 / 384 | 175 / 115 / 269 / 31 | 84.95% | 29.95% | 39.41% | 53.85% |
| attempt 25 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 26 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% |
| attempt 26 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% |
| attempt 26 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% |
| attempt 26 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% |
| attempt 26 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% |
| attempt 26 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% |
| attempt 26 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% |
| attempt 26 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% |
| attempt 36 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 36 / gretel | semantic | 98 / 54 | 64 / 5 / 49 / 34 | 65.31% | 9.26% | 56.64% | 60.66% |
| attempt 36 / nemotron-pii | semantic | 206 / 384 | 143 / 88 / 296 / 63 | 69.42% | 22.92% | 32.57% | 44.34% |
| attempt 36 / privy | semantic | 38 / 16 | 31 / 2 / 14 / 7 | 81.58% | 12.50% | 68.89% | 74.70% |
| attempt 36 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 36 / gretel | pipeline | 98 / 54 | 95 / 4 / 50 / 3 | 96.94% | 7.41% | 65.52% | 78.19% |
| attempt 36 / nemotron-pii | pipeline | 206 / 384 | 189 / 87 / 297 / 17 | 91.75% | 22.66% | 38.89% | 54.62% |
| attempt 36 / privy | pipeline | 38 / 16 | 37 / 1 / 15 / 1 | 97.37% | 6.25% | 71.15% | 82.22% |
| attempt 37 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 37 / gretel | semantic | 98 / 54 | 64 / 5 / 49 / 34 | 65.31% | 9.26% | 56.64% | 60.66% |
| attempt 37 / nemotron-pii | semantic | 206 / 384 | 143 / 88 / 296 / 63 | 69.42% | 22.92% | 32.57% | 44.34% |
| attempt 37 / privy | semantic | 38 / 16 | 31 / 2 / 14 / 7 | 81.58% | 12.50% | 68.89% | 74.70% |
| attempt 37 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 37 / gretel | pipeline | 98 / 54 | 95 / 4 / 50 / 3 | 96.94% | 7.41% | 65.52% | 78.19% |
| attempt 37 / nemotron-pii | pipeline | 206 / 384 | 189 / 87 / 297 / 17 | 91.75% | 22.66% | 38.89% | 54.62% |
| attempt 37 / privy | pipeline | 38 / 16 | 37 / 1 / 15 / 1 | 97.37% | 6.25% | 71.15% | 82.22% |
| attempt 38 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 38 / gretel | semantic | 98 / 54 | 64 / 5 / 49 / 34 | 65.31% | 9.26% | 56.64% | 60.66% |
| attempt 38 / nemotron-pii | semantic | 206 / 384 | 143 / 88 / 296 / 63 | 69.42% | 22.92% | 32.57% | 44.34% |
| attempt 38 / privy | semantic | 38 / 16 | 31 / 2 / 14 / 7 | 81.58% | 12.50% | 68.89% | 74.70% |
| attempt 38 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 38 / gretel | pipeline | 98 / 54 | 95 / 4 / 50 / 3 | 96.94% | 7.41% | 65.52% | 78.19% |
| attempt 38 / nemotron-pii | pipeline | 206 / 384 | 189 / 87 / 297 / 17 | 91.75% | 22.66% | 38.89% | 54.62% |
| attempt 38 / privy | pipeline | 38 / 16 | 37 / 1 / 15 / 1 | 97.37% | 6.25% | 71.15% | 82.22% |
| attempt 39 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 39 / gretel | semantic | 98 / 54 | 64 / 6 / 48 / 34 | 65.31% | 11.11% | 57.14% | 60.95% |
| attempt 39 / nemotron-pii | semantic | 206 / 384 | 141 / 91 / 293 / 65 | 68.45% | 23.70% | 32.49% | 44.06% |
| attempt 39 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 39 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 39 / gretel | pipeline | 98 / 54 | 95 / 5 / 49 / 3 | 96.94% | 9.26% | 65.97% | 78.51% |
| attempt 39 / nemotron-pii | pipeline | 206 / 384 | 188 / 90 / 294 / 18 | 91.26% | 23.44% | 39.00% | 54.65% |
| attempt 39 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 40 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 40 / gretel | semantic | 98 / 54 | 64 / 6 / 48 / 34 | 65.31% | 11.11% | 57.14% | 60.95% |
| attempt 40 / nemotron-pii | semantic | 206 / 384 | 141 / 91 / 293 / 65 | 68.45% | 23.70% | 32.49% | 44.06% |
| attempt 40 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 40 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 40 / gretel | pipeline | 98 / 54 | 95 / 5 / 49 / 3 | 96.94% | 9.26% | 65.97% | 78.51% |
| attempt 40 / nemotron-pii | pipeline | 206 / 384 | 188 / 90 / 294 / 18 | 91.26% | 23.44% | 39.00% | 54.65% |
| attempt 40 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 41 / AI4Privacy/OpenPII | semantic | 133 / 39 | 92 / 17 / 22 / 41 | 69.17% | 43.59% | 80.70% | 74.49% |
| attempt 41 / gretel | semantic | 98 / 54 | 64 / 6 / 48 / 34 | 65.31% | 11.11% | 57.14% | 60.95% |
| attempt 41 / nemotron-pii | semantic | 206 / 384 | 141 / 91 / 293 / 65 | 68.45% | 23.70% | 32.49% | 44.06% |
| attempt 41 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 41 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 16 / 23 / 10 | 92.48% | 41.03% | 84.25% | 88.17% |
| attempt 41 / gretel | pipeline | 98 / 54 | 95 / 5 / 49 / 3 | 96.94% | 9.26% | 65.97% | 78.51% |
| attempt 41 / nemotron-pii | pipeline | 206 / 384 | 188 / 90 / 294 / 18 | 91.26% | 23.44% | 39.00% | 54.65% |
| attempt 41 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 42 / AI4Privacy/OpenPII | semantic | 133 / 39 | 88 / 18 / 21 / 45 | 66.17% | 46.15% | 80.73% | 72.73% |
| attempt 42 / gretel | semantic | 98 / 54 | 61 / 7 / 47 / 37 | 62.24% | 12.96% | 56.48% | 59.22% |
| attempt 42 / nemotron-pii | semantic | 206 / 384 | 134 / 99 / 285 / 72 | 65.05% | 25.78% | 31.98% | 42.88% |
| attempt 42 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 42 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 121 / 17 / 22 / 12 | 90.98% | 43.59% | 84.62% | 87.68% |
| attempt 42 / gretel | pipeline | 98 / 54 | 95 / 6 / 48 / 3 | 96.94% | 11.11% | 66.43% | 78.84% |
| attempt 42 / nemotron-pii | pipeline | 206 / 384 | 188 / 98 / 286 / 18 | 91.26% | 25.52% | 39.66% | 55.29% |
| attempt 42 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 43 / AI4Privacy/OpenPII | semantic | 133 / 39 | 88 / 18 / 21 / 45 | 66.17% | 46.15% | 80.73% | 72.73% |
| attempt 43 / gretel | semantic | 98 / 54 | 61 / 8 / 46 / 37 | 62.24% | 14.81% | 57.01% | 59.51% |
| attempt 43 / nemotron-pii | semantic | 206 / 384 | 134 / 99 / 285 / 72 | 65.05% | 25.78% | 31.98% | 42.88% |
| attempt 43 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 43 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 121 / 17 / 22 / 12 | 90.98% | 43.59% | 84.62% | 87.68% |
| attempt 43 / gretel | pipeline | 98 / 54 | 95 / 7 / 47 / 3 | 96.94% | 12.96% | 66.90% | 79.17% |
| attempt 43 / nemotron-pii | pipeline | 206 / 384 | 188 / 98 / 286 / 18 | 91.26% | 25.52% | 39.66% | 55.29% |
| attempt 43 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 44 / AI4Privacy/OpenPII | semantic | 133 / 39 | 88 / 18 / 21 / 45 | 66.17% | 46.15% | 80.73% | 72.73% |
| attempt 44 / gretel | semantic | 98 / 54 | 61 / 8 / 46 / 37 | 62.24% | 14.81% | 57.01% | 59.51% |
| attempt 44 / nemotron-pii | semantic | 206 / 384 | 134 / 99 / 285 / 72 | 65.05% | 25.78% | 31.98% | 42.88% |
| attempt 44 / privy | semantic | 38 / 16 | 30 / 2 / 14 / 8 | 78.95% | 12.50% | 68.18% | 73.17% |
| attempt 44 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 121 / 17 / 22 / 12 | 90.98% | 43.59% | 84.62% | 87.68% |
| attempt 44 / gretel | pipeline | 98 / 54 | 95 / 7 / 47 / 3 | 96.94% | 12.96% | 66.90% | 79.17% |
| attempt 44 / nemotron-pii | pipeline | 206 / 384 | 188 / 98 / 286 / 18 | 91.26% | 25.52% | 39.66% | 55.29% |
| attempt 44 / privy | pipeline | 38 / 16 | 36 / 1 / 15 / 2 | 94.74% | 6.25% | 70.59% | 80.90% |
| attempt 46 / AI4Privacy/OpenPII | semantic | 133 / 39 | 55 / 24 / 15 / 78 | 41.35% | 61.54% | 78.57% | 54.19% |
| attempt 46 / gretel | semantic | 98 / 54 | 46 / 17 / 37 / 52 | 46.94% | 31.48% | 55.42% | 50.83% |
| attempt 46 / nemotron-pii | semantic | 206 / 384 | 94 / 158 / 226 / 112 | 45.63% | 41.15% | 29.38% | 35.74% |
| attempt 46 / privy | semantic | 38 / 16 | 24 / 7 / 9 / 14 | 63.16% | 43.75% | 72.73% | 67.61% |
| attempt 46 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 116 / 22 / 17 / 17 | 87.22% | 56.41% | 87.22% | 87.22% |
| attempt 46 / gretel | pipeline | 98 / 54 | 92 / 15 / 39 / 6 | 93.88% | 27.78% | 70.23% | 80.35% |
| attempt 46 / nemotron-pii | pipeline | 206 / 384 | 178 / 154 / 230 / 28 | 86.41% | 40.10% | 43.63% | 57.98% |
| attempt 46 / privy | pipeline | 38 / 16 | 33 / 3 / 13 / 5 | 86.84% | 18.75% | 71.74% | 78.57% |
| attempt 47 / AI4Privacy/OpenPII | semantic | 133 / 39 | 54 / 24 / 15 / 79 | 40.60% | 61.54% | 78.26% | 53.47% |
| attempt 47 / gretel | semantic | 98 / 54 | 46 / 17 / 37 / 52 | 46.94% | 31.48% | 55.42% | 50.83% |
| attempt 47 / nemotron-pii | semantic | 206 / 384 | 93 / 158 / 226 / 113 | 45.15% | 41.15% | 29.15% | 35.43% |
| attempt 47 / privy | semantic | 38 / 16 | 24 / 7 / 9 / 14 | 63.16% | 43.75% | 72.73% | 67.61% |
| attempt 47 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 115 / 22 / 17 / 18 | 86.47% | 56.41% | 87.12% | 86.79% |
| attempt 47 / gretel | pipeline | 98 / 54 | 92 / 15 / 39 / 6 | 93.88% | 27.78% | 70.23% | 80.35% |
| attempt 47 / nemotron-pii | pipeline | 206 / 384 | 177 / 154 / 230 / 29 | 85.92% | 40.10% | 43.49% | 57.75% |
| attempt 47 / privy | pipeline | 38 / 16 | 33 / 3 / 13 / 5 | 86.84% | 18.75% | 71.74% | 78.57% |

| Accepted attempt | Layer | Δ TP / TN / FP / FN | New / corrected positive misses | New / corrected clean flags | Precision / F1 |
| ---: | --- | --- | ---: | ---: | ---: |
| 0 | semantic | -2 / +2 / -2 / +2 | 2 / 0 | 0 / 2 | 45.53% / 51.38% |
| 0 | pipeline | +0 / +2 / -2 / +0 | 0 / 0 | 0 / 2 | 56.16% / 70.05% |
| 1 | semantic | -2 / +2 / -2 / +2 | 2 / 0 | 0 / 2 | 45.53% / 51.38% |
| 1 | pipeline | +0 / +2 / -2 / +0 | 0 / 0 | 0 / 2 | 56.16% / 70.05% |
| 2 | semantic | -2 / +2 / -2 / +2 | 2 / 0 | 0 / 2 | 45.53% / 51.38% |
| 2 | pipeline | +0 / +2 / -2 / +0 | 0 / 0 | 0 / 2 | 56.16% / 70.05% |
| 18 | semantic | -5 / +4 / -4 / +5 | 5 / 0 | 0 / 4 | 43.85% / 50.14% |
| 18 | pipeline | +0 / +3 / -3 / +0 | 0 / 0 | 0 / 3 | 54.17% / 68.08% |
| 19 | semantic | -5 / +4 / -4 / +5 | 5 / 0 | 0 / 4 | 43.85% / 50.14% |
| 19 | pipeline | +0 / +3 / -3 / +0 | 0 / 0 | 0 / 3 | 54.17% / 68.08% |
| 20 | semantic | -5 / +4 / -4 / +5 | 5 / 0 | 0 / 4 | 43.85% / 50.14% |
| 20 | pipeline | +0 / +3 / -3 / +0 | 0 / 0 | 0 / 3 | 54.17% / 68.08% |
| 21 | semantic | -14 / +11 / -11 / +14 | 14 / 0 | 0 / 11 | 43.53% / 49.22% |
| 21 | pipeline | -4 / +10 / -10 / +4 | 4 / 0 | 0 / 10 | 54.42% / 68.03% |
| 22 | semantic | -14 / +11 / -11 / +14 | 14 / 0 | 0 / 11 | 43.53% / 49.22% |
| 22 | pipeline | -4 / +10 / -10 / +4 | 4 / 0 | 0 / 10 | 54.42% / 68.03% |
| 23 | semantic | -13 / +11 / -11 / +13 | 13 / 0 | 0 / 11 | 43.62% / 49.36% |
| 23 | pipeline | -4 / +10 / -10 / +4 | 4 / 0 | 0 / 10 | 54.42% / 68.03% |
| 24 | semantic | -40 / +26 / -26 / +40 | 40 / 0 | 0 / 26 | 42.11% / 46.20% |
| 24 | pipeline | -9 / +25 / -25 / +9 | 9 / 0 | 0 / 25 | 55.18% / 68.32% |
| 25 | semantic | -40 / +27 / -27 / +40 | 40 / 0 | 0 / 27 | 42.19% / 46.24% |
| 25 | pipeline | -9 / +26 / -26 / +9 | 9 / 0 | 0 / 26 | 55.25% / 68.38% |
| 26 | semantic | -40 / +25 / -25 / +40 | 40 / 0 | 0 / 25 | 42.04% / 46.15% |
| 26 | pipeline | -9 / +24 / -24 / +9 | 9 / 0 | 0 / 24 | 55.11% / 68.27% |
| 36 | semantic | -4 / +0 / +0 / +4 | 4 / 0 | 0 / 0 | 46.41% / 55.65% |
| 36 | pipeline | -1 / +0 / +0 / +1 | 1 / 0 | 0 / 0 | 53.56% / 68.10% |
| 37 | semantic | -4 / +0 / +0 / +4 | 4 / 0 | 0 / 0 | 46.41% / 55.65% |
| 37 | pipeline | -1 / +0 / +0 / +1 | 1 / 0 | 0 / 0 | 53.56% / 68.10% |
| 38 | semantic | -4 / +0 / +0 / +4 | 4 / 0 | 0 / 0 | 46.41% / 55.65% |
| 38 | pipeline | -1 / +0 / +0 / +1 | 1 / 0 | 0 / 0 | 53.56% / 68.10% |
| 39 | semantic | -7 / +4 / -4 / +7 | 7 / 0 | 0 / 4 | 46.45% / 55.47% |
| 39 | pipeline | -3 / +4 / -4 / +3 | 3 / 0 | 0 / 4 | 53.71% / 68.10% |
| 40 | semantic | -7 / +4 / -4 / +7 | 7 / 0 | 0 / 4 | 46.45% / 55.47% |
| 40 | pipeline | -3 / +4 / -4 / +3 | 3 / 0 | 0 / 4 | 53.71% / 68.10% |
| 41 | semantic | -7 / +4 / -4 / +7 | 7 / 0 | 0 / 4 | 46.45% / 55.47% |
| 41 | pipeline | -3 / +4 / -4 / +3 | 3 / 0 | 0 / 4 | 53.71% / 68.10% |
| 42 | semantic | -21 / +14 / -14 / +21 | 21 / 0 | 0 / 14 | 46.03% / 54.20% |
| 42 | pipeline | -5 / +14 / -14 / +5 | 5 / 0 | 0 / 14 | 54.25% / 68.43% |
| 43 | semantic | -21 / +15 / -15 / +21 | 21 / 0 | 0 / 15 | 46.10% / 54.25% |
| 43 | pipeline | -5 / +15 / -15 / +5 | 5 / 0 | 0 / 15 | 54.32% / 68.48% |
| 44 | semantic | -21 / +15 / -15 / +21 | 21 / 0 | 0 / 15 | 46.10% / 54.25% |
| 44 | pipeline | -5 / +15 / -15 / +5 | 5 / 0 | 0 / 15 | 54.32% / 68.48% |
| 46 | semantic | -115 / +94 / -94 / +115 | 119 / 4 | 2 / 96 | 43.28% / 44.65% |
| 46 | pipeline | -26 / +86 / -86 / +26 | 27 / 1 | 2 / 88 | 58.36% / 70.24% |
| 47 | semantic | -117 / +94 / -94 / +117 | 121 / 4 | 2 / 96 | 43.06% / 44.33% |
| 47 | pipeline | -28 / +86 / -86 / +28 | 29 / 1 | 2 / 88 | 58.24% / 70.03% |

| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 31.25% → 31.25% | 87.50% → 87.50% | 37.50% → 37.50% | 0.00% | 0.6979817708333339 | — |
| 1 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.6968750000000005 | — |
| 2 | 25.00% → 25.00% | 87.50% → 87.50% | 50.00% → 50.00% | 0.00% | 0.7223307291666671 | — |
| 3 | — → — | — → — | — → — | — | — | — |
| 4 | — → — | — → — | — → — | — | — | — |
| 5 | — → — | — → — | — → — | — | — | — |
| 6 | — → — | — → — | — → — | — | — | — |
| 7 | — → — | — → — | — → — | — | — | — |
| 8 | — → — | — → — | — → — | — | — | — |
| 9 | — → — | — → — | — → — | — | — | — |
| 10 | — → — | — → — | — → — | — | — | — |
| 11 | — → — | — → — | — → — | — | — | — |
| 12 | — → — | — → — | — → — | — | — | — |
| 13 | — → — | — → — | — → — | — | — | — |
| 14 | — → — | — → — | — → — | — | — | — |
| 15 | — → — | — → — | — → — | — | — | — |
| 16 | — → — | — → — | — → — | — | — | — |
| 17 | — → — | — → — | — → — | — | — | — |
| 18 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5742513020833337 | — |
| 19 | 18.75% → 18.75% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.6177734374999999 | — |
| 20 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.6056966145833333 | — |
| 21 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5742513020833337 | — |
| 22 | 18.75% → 18.75% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.6177734374999999 | — |
| 23 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.6056966145833333 | — |
| 24 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5742513020833337 | — |
| 25 | 18.75% → 25.00% | 100.00% → 100.00% | 25.00% → 37.50% | 0.00% | 0.6177734374999999 | — |
| 26 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.6056966145833333 | — |
| 27 | — → — | — → — | — → — | — | — | — |
| 28 | — → — | — → — | — → — | — | — | — |
| 29 | — → — | — → — | — → — | — | — | — |
| 30 | — → — | — → — | — → — | — | — | — |
| 31 | — → — | — → — | — → — | — | — | — |
| 32 | — → — | — → — | — → — | — | — | — |
| 33 | — → — | — → — | — → — | — | — | — |
| 34 | — → — | — → — | — → — | — | — | — |
| 35 | — → — | — → — | — → — | — | — | — |
| 36 | 31.25% → 31.25% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.43642578124999987 | — |
| 37 | 18.75% → 18.75% | 100.00% → 100.00% | 12.50% → 12.50% | 0.00% | 0.4956380208333338 | — |
| 38 | 18.75% → 18.75% | 87.50% → 87.50% | 12.50% → 12.50% | 0.00% | 0.4750651041666669 | — |
| 39 | 31.25% → 31.25% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.43642578124999987 | — |
| 40 | 18.75% → 18.75% | 100.00% → 100.00% | 12.50% → 12.50% | 0.00% | 0.4956380208333338 | — |
| 41 | 18.75% → 18.75% | 87.50% → 87.50% | 12.50% → 12.50% | 0.00% | 0.4750651041666669 | — |
| 42 | 31.25% → 31.25% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.43642578124999987 | — |
| 43 | 18.75% → 25.00% | 100.00% → 100.00% | 12.50% → 12.50% | 0.00% | 0.4956380208333338 | — |
| 44 | 18.75% → 18.75% | 87.50% → 87.50% | 12.50% → 12.50% | 0.00% | 0.4750651041666669 | — |
| 45 | — → — | — → — | — → — | — | — | — |
| 46 | 18.75% → 37.50% | 100.00% → 100.00% | 12.50% → 50.00% | 0.00% | 0.4956380208333338 | 4.242159068584442 |
| 47 | 18.75% → 25.00% | 87.50% → 87.50% | 12.50% → 25.00% | 0.00% | 0.4750651041666669 | 4.164007097482681 |
| 48 | — → — | — → — | — → — | — | — | — |
| 49 | — → — | — → — | — → — | — | — | — |
| 50 | — → — | — → — | — → — | — | — | — |
| 51 | — → — | — → — | — → — | — | — | — |
| 52 | — → — | — → — | — → — | — | — | — |
| 53 | — → — | — → — | — → — | — | — | — |

Legacy average_loss is a weighted classification-distance diagnostic. The last-block supervised_objective_loss is weighted sensitivity CE + visibility CE + summed category BCE. Their scales and meanings differ. Held-out exact/recall/specificity and severity/action guards use row counts, not example weights. The existing severity/action floor is a publication guard, not independent privacy truth.

| Model | Layer | First / median / p95 service ms |
| --- | --- | ---: |
| original efficient | semantic | 28.95 / 6.19 / 6.84 |
| original efficient | pipeline | 48.08 / 28.79 / 35.85 |
| original balanced | semantic | 56.01 / 11.97 / 12.96 |
| original balanced | pipeline | 85.50 / 34.94 / 41.08 |
| original quality | semantic | 77.39 / 17.73 / 18.99 |
| original quality | pipeline | 112.53 / 40.94 / 48.69 |
| attempt 0 | semantic | 22.98 / 6.26 / 6.98 |
| attempt 0 | pipeline | 49.53 / 29.11 / 35.42 |
| attempt 1 | semantic | 23.81 / 6.39 / 7.19 |
| attempt 1 | pipeline | 49.14 / 28.76 / 35.29 |
| attempt 2 | semantic | 25.14 / 6.42 / 7.12 |
| attempt 2 | pipeline | 48.53 / 28.93 / 34.78 |
| attempt 18 | semantic | 56.11 / 11.81 / 12.94 |
| attempt 18 | pipeline | 84.10 / 35.11 / 41.83 |
| attempt 19 | semantic | 55.17 / 11.95 / 13.22 |
| attempt 19 | pipeline | 84.17 / 35.05 / 41.96 |
| attempt 20 | semantic | 54.24 / 11.72 / 12.81 |
| attempt 20 | pipeline | 85.88 / 34.29 / 39.93 |
| attempt 21 | semantic | 54.03 / 12.01 / 13.18 |
| attempt 21 | pipeline | 84.58 / 34.50 / 40.09 |
| attempt 22 | semantic | 53.83 / 11.77 / 12.82 |
| attempt 22 | pipeline | 84.46 / 34.61 / 40.82 |
| attempt 23 | semantic | 53.91 / 12.03 / 12.97 |
| attempt 23 | pipeline | 88.07 / 34.68 / 41.97 |
| attempt 24 | semantic | 54.80 / 11.98 / 13.16 |
| attempt 24 | pipeline | 88.05 / 34.24 / 40.50 |
| attempt 25 | semantic | 55.92 / 11.98 / 12.94 |
| attempt 25 | pipeline | 85.76 / 33.95 / 39.75 |
| attempt 26 | semantic | 52.27 / 11.80 / 12.75 |
| attempt 26 | pipeline | 85.04 / 34.18 / 40.64 |
| attempt 36 | semantic | 78.51 / 17.78 / 19.39 |
| attempt 36 | pipeline | 113.08 / 40.99 / 48.67 |
| attempt 37 | semantic | 80.29 / 17.67 / 19.08 |
| attempt 37 | pipeline | 115.07 / 41.12 / 50.11 |
| attempt 38 | semantic | 80.46 / 17.58 / 18.94 |
| attempt 38 | pipeline | 114.76 / 41.05 / 49.49 |
| attempt 39 | semantic | 78.49 / 17.59 / 19.11 |
| attempt 39 | pipeline | 116.13 / 40.79 / 47.99 |
| attempt 40 | semantic | 78.28 / 17.64 / 19.34 |
| attempt 40 | pipeline | 115.46 / 40.98 / 49.17 |
| attempt 41 | semantic | 78.32 / 17.61 / 19.17 |
| attempt 41 | pipeline | 112.83 / 40.88 / 51.32 |
| attempt 42 | semantic | 79.59 / 17.72 / 19.26 |
| attempt 42 | pipeline | 118.12 / 41.02 / 49.91 |
| attempt 43 | semantic | 80.01 / 17.58 / 19.06 |
| attempt 43 | pipeline | 114.02 / 40.73 / 50.30 |
| attempt 44 | semantic | 78.28 / 17.65 / 19.36 |
| attempt 44 | pipeline | 113.26 / 40.60 / 49.22 |
| attempt 46 | semantic | 78.17 / 17.15 / 18.85 |
| attempt 46 | pipeline | 115.42 / 39.92 / 48.69 |
| attempt 47 | semantic | 82.14 / 17.41 / 19.09 |
| attempt 47 | pipeline | 116.21 / 39.88 / 49.01 |

Service elapsed_ms includes the first request and excludes browser/bridge overhead; these measurements do not establish representative production latency.

| Frozen endpoint | Layer | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| live balanced | semantic | 146 / 76 / 162 / 118 | 55.30% | 31.93% | 47.40% | 51.05% |
| live balanced | pipeline | 242 / 69 / 169 / 22 | 91.67% | 28.99% | 58.88% | 71.70% |
| frozen winner | semantic | 157 / 62 / 176 / 107 | 59.47% | 26.05% | 47.15% | 52.60% |
| frozen winner | pipeline | 236 / 60 / 178 / 28 | 89.39% | 25.21% | 57.00% | 69.62% |

Development pipeline balanced accuracy: live balanced 60.33%; frozen winner 57.30%.

Development contains 264 positive and 238 negative rows, reused exploratory evidence assessed only after frozen selection.

| Development model / source | Layer | Positive / negative support | Recall | Specificity | Precision | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| live balanced / AI4Privacy/OpenPII | semantic | 81 / 22 | 38.27% | 54.55% | 75.61% | 50.82% |
| live balanced / gretel | semantic | 55 / 28 | 72.73% | 32.14% | 67.80% | 70.18% |
| live balanced / mapa-eur-lex | semantic | 0 / 2 | — | 50.00% | 0.00% | 0.00% |
| live balanced / nemotron-pii | semantic | 110 / 184 | 60.00% | 29.35% | 33.67% | 43.14% |
| live balanced / privy | semantic | 18 / 2 | 50.00% | 0.00% | 81.82% | 62.07% |
| live balanced / AI4Privacy/OpenPII | pipeline | 81 / 22 | 88.89% | 50.00% | 86.75% | 87.80% |
| live balanced / gretel | pipeline | 55 / 28 | 94.55% | 25.00% | 71.23% | 81.25% |
| live balanced / mapa-eur-lex | pipeline | 0 / 2 | — | 50.00% | 0.00% | 0.00% |
| live balanced / nemotron-pii | pipeline | 110 / 184 | 90.91% | 27.17% | 42.74% | 58.14% |
| live balanced / privy | pipeline | 18 / 2 | 100.00% | 0.00% | 90.00% | 94.74% |
| frozen winner / AI4Privacy/OpenPII | semantic | 81 / 22 | 49.38% | 18.18% | 68.97% | 57.55% |
| frozen winner / gretel | semantic | 55 / 28 | 52.73% | 17.86% | 55.77% | 54.21% |
| frozen winner / mapa-eur-lex | semantic | 0 / 2 | — | 0.00% | 0.00% | 0.00% |
| frozen winner / nemotron-pii | semantic | 110 / 184 | 63.64% | 28.80% | 34.83% | 45.02% |
| frozen winner / privy | semantic | 18 / 2 | 100.00% | 0.00% | 90.00% | 94.74% |
| frozen winner / AI4Privacy/OpenPII | pipeline | 81 / 22 | 87.65% | 18.18% | 79.78% | 83.53% |
| frozen winner / gretel | pipeline | 55 / 28 | 92.73% | 17.86% | 68.92% | 79.07% |
| frozen winner / mapa-eur-lex | pipeline | 0 / 2 | — | 0.00% | 0.00% | 0.00% |
| frozen winner / nemotron-pii | pipeline | 110 / 184 | 87.27% | 27.72% | 41.92% | 56.64% |
| frozen winner / privy | pipeline | 18 / 2 | 100.00% | 0.00% | 90.00% | 94.74% |

Retained research artifact: False. Contextual gate: False; newly introduced private action failures: []; newly introduced clean interventions: ['cc-fictional_character-02', 'cc-personal_finance-02', 'cc-implicit_disclosure-01', 'cc-implicit_disclosure-02']. The 41 quantitative cases carry provisional contextual labels; seven ambiguous cases are excluded from the gate. Per-case comparisons remain in JSON.

Private disclosures meeting the minimum action: live 15/17; winner 16/17. Clean controls receiving ALLOW: live 15/24; winner 15/24. Existing failures remain quality limitations even when no new failure is introduced.

Empty successful semantic responses have no per-case identity item; provenance combines explicit model selection, frozen sources/catalog/images and matching returned identities elsewhere in each collection.

Model identities and immutable file commitments:

- original efficient: `privoke-efficient`, `v0.3.0`; internal checksum `a78e4fc8837a50e3fc1e70044f71a1490f7524454f84e86e6a82531f4c8059fe`; inference fingerprint `f12b8fcdaa3d123fd4bc6dd56dbb87d985aae4009bdefac92d04efb596fc551a`; [original-efficient.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\original-efficient.json>) file SHA-256 `c8992bda8a75f5ee7165a3debabaef1a229c4f661be2f5792de65c0aefcf9a5b`.
- original balanced: `privoke-balanced`, `v0.3.0`; internal checksum `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`; inference fingerprint `fec1a27b2252e01f659b5b856e5bdb124ef79b72f28995c7b3599f5ce0bd44c6`; [original-balanced.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\original-balanced.json>) file SHA-256 `dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51`.
- original quality: `privoke-quality`, `v0.3.0`; internal checksum `76bc059fee0d7d6dd2df02b05d8fee9f05ef0ddb949f74e69a0a38064bc644ab`; inference fingerprint `dae7f43f48c8197543b89d66349aca5f4fec2981d7a4145e9f6500b5aa287dea`; [original-quality.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\original-quality.json>) file SHA-256 `c3126ae0ae238d3967226b6c616491fb90e9b766a3fbb6e066203cb92f2ed8c8`.
- attempt 0: `privoke-efficient`, `v0.3.0+train.1`; internal checksum `401c6f2a0bed3f42a034f8a42d27e24c8219a69da2c9e7f76c6ef18a60f30b2b`; inference fingerprint `1ebaecd9f8970cbd85febe0f054bb77b099a8c32169c52202cc39cfdc7d33bcf`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-00\candidate.json>) file SHA-256 `1daf2c095d1760c181dccc17969f02d98dee1a2b764010d9c62a855f3aa90b39`.
- attempt 1: `privoke-efficient`, `v0.3.0+train.1`; internal checksum `ed497f52a9acd82458c8da56240e91743e549e5f2edfd08be11e4059752252c7`; inference fingerprint `327f10c18ccc79c41bfbf45322ff7458b8fb4c9418ac2fe387782dde4148bce0`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-01\candidate.json>) file SHA-256 `d5242f977f7dfcab2f6de3c519b1d259718763f7e59b361065ecbdaec0644069`.
- attempt 2: `privoke-efficient`, `v0.3.0+train.1`; internal checksum `c85f0bd7a67f47efeb2dd84c45f4663b1d5dc7412ad731c1d203214d5b6a10fa`; inference fingerprint `1d32f959e084639908d660ebf2bb500e8a7f56480699b218bc551b1c4bf47792`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-02\candidate.json>) file SHA-256 `2027525813797ae5137094fba5364a948314967866ec5d0b489e27147395828e`.
- attempt 18: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `6ca69e8961307b530dc9611cc7d4d8022448304357400f75f0ba9aa7fa0f0d93`; inference fingerprint `4296b4bf52459dd03a5495a40e1d9b1e3e212e92bfc16d1dbeca0e8d9332543f`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-18\candidate.json>) file SHA-256 `7c8f28bf322beda964da4366ae11f75f14fa140600a2bdb806d63f84459a2ae0`.
- attempt 19: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `23d0b4913c13302fe23d621e926ac644cfa3fc9abc8cc2295f1b2c015e0d72c9`; inference fingerprint `9f53cd33895f845a7748c06d38fa20bb2dd54bbab24a70ed99fb3116bfd5eb02`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-19\candidate.json>) file SHA-256 `4bab23b40e284811e75bf8a31bad351581c03235bae96714c895a6105739bd68`.
- attempt 20: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `e11e0b0d8931343caf8ffbf77d3f7da7ae79c8abf281f5d77a7e9b9c319d5673`; inference fingerprint `adaad218dcc7805a02a748ba7352b649e4980b2e4fa8c4530770c0854fafb3f7`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-20\candidate.json>) file SHA-256 `7411e3fa8b9eaab016d82d3c285c2c00cd923e9e1d3a71110548a028efd0e6b0`.
- attempt 21: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `a6c0941f89240ec251c40868b0b5bc7ec7a8d46f436bb9817e0b87a7e1c89f68`; inference fingerprint `892cfba905e58e1bae4b7c9e0edd3e5f7fcc7c7d78f344956b9c1e1c9ae78741`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-21\candidate.json>) file SHA-256 `924ee919ebf059a54bab1674f46164325eb92e56b764fbb59a854527695cdaf8`.
- attempt 22: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `4fa9ef464398e7cc4bf3bc213f18f8876978dd27f9ea9b56f578c353b7fba293`; inference fingerprint `4c42a197b263d158e5b3b053d9458a66f2fbf4d07d80825d2c735dc3ad03405d`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-22\candidate.json>) file SHA-256 `53d5682bee9d4f01e6ceda45f9c7137c541c830ed1d8983c45393c3677012b37`.
- attempt 23: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `f2e2ae60b4891a2a2fca833520b0f3b0c64534d5315fa53c632a26e44206674e`; inference fingerprint `8c098f2c7f3414519224338f9403949242ae98df7a9fbcfe821736b50d93ad88`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-23\candidate.json>) file SHA-256 `0e13c3a4fc0513920cff326c088417fdf6bc7857b2c8dca0519fde3cfadfcff9`.
- attempt 24: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `09c20e57bffe8480a23fb67e3f7e8bb98e02f2ea1411850691aa98133622b4a6`; inference fingerprint `9c8d3aefffdcf0efc7af650e51af38a62e62e333c1b4632811735e61969de081`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-24\candidate.json>) file SHA-256 `2aa8d8ba72946f0dbcd087279391cf1dd522ce7e4e106134baee4838446785f9`.
- attempt 25: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `51de9ac6ecb2675b4feac4883be2dff28b7284317ad260412ecb08521f4f102e`; inference fingerprint `cc53042bd0b50f48ec5548cc775ec2f0dfaabc304b3a2a0c2abd0b1ac89d716e`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-25\candidate.json>) file SHA-256 `6bc644c342e7031a883e6181e2a25178d8054d11e832194858f0e883490076cf`.
- attempt 26: `privoke-balanced`, `v0.3.0+train.1`; internal checksum `8e8a60467d747f8243fb6b004fc658f14aac573b15c7536305e5759eacde4eea`; inference fingerprint `0c73f3fb491daf4a0e83268e6cb07bf7de93274fcf0a008a56cdb31b4cd121e5`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-26\candidate.json>) file SHA-256 `29cc977e1c1ea01890fedf5eefb1887119b36128ec9744fcb9a63c44a27b3015`.
- attempt 36: `privoke-quality`, `v0.3.0+train.1`; internal checksum `c5a3156123b355ea3337b8f66edeaedadd2cef860bedaf5d4a0e48ce3b86c49d`; inference fingerprint `c707c1a18f9d3e1bbcee3b20583c4231f92d7f1095f949a6ce3271646faa6115`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-36\candidate.json>) file SHA-256 `3e03d146e96f46ddee4000853c2dad75b65fb9c80d7155b8d139e1be3d8c439a`.
- attempt 37: `privoke-quality`, `v0.3.0+train.1`; internal checksum `8bdceb8c904a1acab9d60da991b61b3fb0e5f7cc85a3100b5a06cb1e85b99ecb`; inference fingerprint `45bdaf6fbb603ff7998d9161cc0955f9a0aa1cbbb425cff033e0f3ced9de0369`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-37\candidate.json>) file SHA-256 `15c573c5b3a264cb657048896ffc41632a6b8b6c17447dbed196c80dd7f76261`.
- attempt 38: `privoke-quality`, `v0.3.0+train.1`; internal checksum `aa6aa800301aca4a5bcfae6b7059514ac33eb8d0644ab4e1d8036c0f94ce70bb`; inference fingerprint `94de7490b8284c6870b38541902041d5c8c8edb15c18fa89a2ff750a95d0f72d`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-38\candidate.json>) file SHA-256 `4579fe16a0bc24668804835488c98327409d1adf2be3392f9016027f11a8a0d9`.
- attempt 39: `privoke-quality`, `v0.3.0+train.1`; internal checksum `48d92a50827384f8d3e13250cab9ae8409a5bd077ef46f2e98c23a833f275f06`; inference fingerprint `86db44e670d7278c9b20c9d0849a2910d2ae93f8a932073da4afda9e19a614ca`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-39\candidate.json>) file SHA-256 `754a26371deba30a20b02c6044f9d996cb5738f3dadfa04b1d41e9d9f385408b`.
- attempt 40: `privoke-quality`, `v0.3.0+train.1`; internal checksum `76242c067e131b558ea045d017f720852e58e6411d9b255b5dcec7df1b27156c`; inference fingerprint `7cabcd9b493718cc348455cf7ae482598816bd685d99ac85b9df5b1507fddb3f`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-40\candidate.json>) file SHA-256 `c05258e0654c3c7bad7faa662e4088a92ba12a3ba9ccecbcbf107550ff63f6cf`.
- attempt 41: `privoke-quality`, `v0.3.0+train.1`; internal checksum `a22b997deb5a4d80b8810e19ebaa7f060c602f42e89d28a73b7bdd2d96aa44b6`; inference fingerprint `5ad37ae7f06c2e4195812a7a959b4e159fe7a7dc83d20e5367cc9e6818017835`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-41\candidate.json>) file SHA-256 `134b382a58ba48cd57e0afd2121d1d1121309a231ac6377560f019cf45e7b0d8`.
- attempt 42: `privoke-quality`, `v0.3.0+train.1`; internal checksum `91cda4ef2d14168a05b34451e1ea0e817db2e1369d02938ca71b83f897b58989`; inference fingerprint `94e1bcb15452cb8f99340b6ce2350b90366de5ffa1c2e486b1b394e1fcb457b0`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-42\candidate.json>) file SHA-256 `2e61a6d4679b30760ad0e0a10f4131aff4940300d136f93800ae31e7ae49e059`.
- attempt 43: `privoke-quality`, `v0.3.0+train.1`; internal checksum `73fcf370153afe03171d4615fbfbd3c9d8d38007c64fc2f07330f60a8f6f7c80`; inference fingerprint `3317a23533187fe3ddff6d5b148ba85e5b903e34278810e641bc17016e807d87`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-43\candidate.json>) file SHA-256 `3b0f28bed0f843b74bc8364b8dc03b1d516d47db70ea2dc67edde24de144e697`.
- attempt 44: `privoke-quality`, `v0.3.0+train.1`; internal checksum `39cef4253da17668e083660f3636cbe0864d098f61387546b53cfe6ab8027d5f`; inference fingerprint `47c6b096435dc3df915083490a95a926f6c6a86d1d2acbb86d0b0dbdb43bd27b`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-44\candidate.json>) file SHA-256 `b9460d5f231b8c6d340254185d38ef8f9c050436cfefd40993b5753d46255d54`.
- attempt 46: `privoke-quality`, `v0.3.0+train.1`; internal checksum `44edf3f3f19c8783d893ac931122d8c626aaae9cd740604a27108ffc5fb552bc`; inference fingerprint `f48cc8fecceb97f5d9f284f4f9d93d97beff5ef0551a83bd9af1c50d394547cb`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-46\candidate.json>) file SHA-256 `fdcdead22475983b5e6335c1761a44a314e93c64be78227aa98166285a8a80f2`.
- attempt 47: `privoke-quality`, `v0.3.0+train.1`; internal checksum `2383877960d52a4dd03ee218a78a4103b499441e81a5452efa5355257a5f8515`; inference fingerprint `217e44db504dd577209474a2e60acd6867c2dd80136672a9e99551da58ee5ddf`; [candidate.json](<D:\Git Repositories\Privoke-Research-Project\evaluation\results\contextual_fuzzer_20261006_v2\attempt-47\candidate.json>) file SHA-256 `8b8f1ec0b1b352ad49466f82bf2281fc63c9cc491ca529d92a0478c4a7521b05`.

Reporter SHA-256: `960aa454bbaa773c20bb20081dac9482505767aaedb6498cd074436d0e2c2846`. The complete JSON retains report/source commitments, config fields, exact trainable/frozen tensor names, paired development/source-stratum rates, actual sampling inventories, publication metadata and provisional contextual per-case actions.

- Model quality means measured behavior, not profile names, tensor count or context size.
- Encoders originate in seeded repository-owned random initialization; original heads use authored bootstrap supervision.
- Public annotation negatives and authored contextual targets are provisional; no independent human contextual/action truth is established.
- Validation and development are reused exploratory samples. This report provides no final generalization, causal capacity, statistical superiority or deployment-safety claim.
- Annotation-presence truth cannot establish severity, visibility, complete span recovery or action correctness.
- Only the explicitly supplied study is consumed; failed v1 evidence is separate and is not pooled with v2.
- Final examples and labels are never opened or scored.
- Confidence calibration and representative production latency have not been established.
- The grid uses seeds 42, 1337 and 2026 only; no broad seed-stability or capacity advantage is established.

Reporting correction: held-out guards are row-based, not weighted. Numerical scores and accept/reject/retention decisions are unchanged. The original export and reporter source remain preserved beside model-quality-corrected.*.
