# Class-balanced fuzzer model quality

complete reconciled study

All 24 attempts start independently from the same exact live balanced train.2 model. Original weighting retains the original example weights; it does not mean every row has weight one.

| Attempt | Strategy / objective | Rate / seed | Outcome | Pipeline recall / specificity / balanced accuracy |
| ---: | --- | --- | --- | ---: |
| 0 | heads / uniform | 0.003 / 42 | accepted/scored | 89.68% / 29.41% / 59.55% |
| 1 | heads / class_balanced_contextual_v1 | 0.003 / 42 | accepted/scored | 89.89% / 29.21% / 59.55% |
| 2 | heads / uniform | 0.003 / 1337 | accepted/scored | 89.68% / 29.41% / 59.55% |
| 3 | heads / class_balanced_contextual_v1 | 0.003 / 1337 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 4 | heads / uniform | 0.003 / 2026 | accepted/scored | 89.68% / 29.41% / 59.55% |
| 5 | heads / class_balanced_contextual_v1 | 0.003 / 2026 | accepted/scored | 89.89% / 29.41% / 59.65% |
| 6 | heads / uniform | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 7 | heads / class_balanced_contextual_v1 | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 8 | heads / uniform | 0.01 / 1337 | accepted/scored | 89.47% / 30.83% / 60.15% |
| 9 | heads / class_balanced_contextual_v1 | 0.01 / 1337 | accepted/scored | 89.68% / 29.61% / 59.65% |
| 10 | heads / uniform | 0.01 / 2026 | accepted/scored | 89.47% / 30.83% / 60.15% |
| 11 | heads / class_balanced_contextual_v1 | 0.01 / 2026 | accepted/scored | 89.68% / 29.82% / 59.75% |
| 12 | last_block / uniform | 0.003 / 42 | rejected; no scored model quality | — / — / — |
| 13 | last_block / class_balanced_contextual_v1 | 0.003 / 42 | rejected; no scored model quality | — / — / — |
| 14 | last_block / uniform | 0.003 / 1337 | rejected; no scored model quality | — / — / — |
| 15 | last_block / class_balanced_contextual_v1 | 0.003 / 1337 | rejected; no scored model quality | — / — / — |
| 16 | last_block / uniform | 0.003 / 2026 | rejected; no scored model quality | — / — / — |
| 17 | last_block / class_balanced_contextual_v1 | 0.003 / 2026 | rejected; no scored model quality | — / — / — |
| 18 | last_block / uniform | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 19 | last_block / class_balanced_contextual_v1 | 0.01 / 42 | rejected; no scored model quality | — / — / — |
| 20 | last_block / uniform | 0.01 / 1337 | rejected; no scored model quality | — / — / — |
| 21 | last_block / class_balanced_contextual_v1 | 0.01 / 1337 | rejected; no scored model quality | — / — / — |
| 22 | last_block / uniform | 0.01 / 2026 | rejected; no scored model quality | — / — / — |
| 23 | last_block / class_balanced_contextual_v1 | 0.01 / 2026 | rejected; no scored model quality | — / — / — |

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
| attempt 0 / pooled | semantic | 475 / 493 | 243 / 157 / 336 / 232 | 51.16% | 31.85% | 41.97% | 46.11% | 41.50% |
| attempt 0 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% | 40.51% |
| attempt 0 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 0 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 0 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 0 / pooled | pipeline | 475 / 493 | 426 / 145 / 348 / 49 | 89.68% | 29.41% | 55.04% | 68.21% | 59.55% |
| attempt 0 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% | 62.91% |
| attempt 0 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 0 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 0 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 1 / pooled | semantic | 475 / 493 | 245 / 156 / 337 / 230 | 51.58% | 31.64% | 42.10% | 46.36% | 41.61% |
| attempt 1 / AI4Privacy/OpenPII | semantic | 133 / 39 | 61 / 14 / 25 / 72 | 45.86% | 35.90% | 70.93% | 55.71% | 40.88% |
| attempt 1 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 1 / nemotron-pii | semantic | 206 / 384 | 102 / 119 / 265 / 104 | 49.51% | 30.99% | 27.79% | 35.60% | 40.25% |
| attempt 1 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 1 / pooled | pipeline | 475 / 493 | 427 / 144 / 349 / 48 | 89.89% | 29.21% | 55.03% | 68.27% | 59.55% |
| attempt 1 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 1 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 1 / nemotron-pii | pipeline | 206 / 384 | 175 / 113 / 271 / 31 | 84.95% | 29.43% | 39.24% | 53.68% | 57.19% |
| attempt 1 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 2 / pooled | semantic | 475 / 493 | 243 / 157 / 336 / 232 | 51.16% | 31.85% | 41.97% | 46.11% | 41.50% |
| attempt 2 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% | 40.51% |
| attempt 2 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 2 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 2 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 2 / pooled | pipeline | 475 / 493 | 426 / 145 / 348 / 49 | 89.68% | 29.41% | 55.04% | 68.21% | 59.55% |
| attempt 2 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% | 62.91% |
| attempt 2 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 2 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
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
| attempt 4 / pooled | semantic | 475 / 493 | 243 / 157 / 336 / 232 | 51.16% | 31.85% | 41.97% | 46.11% | 41.50% |
| attempt 4 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% | 40.51% |
| attempt 4 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 4 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 4 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 4 / pooled | pipeline | 475 / 493 | 426 / 145 / 348 / 49 | 89.68% | 29.41% | 55.04% | 68.21% | 59.55% |
| attempt 4 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% | 62.91% |
| attempt 4 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 4 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 4 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 5 / pooled | semantic | 475 / 493 | 246 / 157 / 336 / 229 | 51.79% | 31.85% | 42.27% | 46.55% | 41.82% |
| attempt 5 / AI4Privacy/OpenPII | semantic | 133 / 39 | 62 / 14 / 25 / 71 | 46.62% | 35.90% | 71.26% | 56.36% | 41.26% |
| attempt 5 / gretel | semantic | 98 / 54 | 70 / 12 / 42 / 28 | 71.43% | 22.22% | 62.50% | 66.67% | 46.83% |
| attempt 5 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 5 / privy | semantic | 38 / 16 | 12 / 11 / 5 / 26 | 31.58% | 68.75% | 70.59% | 43.64% | 50.16% |
| attempt 5 / pooled | pipeline | 475 / 493 | 427 / 145 / 348 / 48 | 89.89% | 29.41% | 55.10% | 68.32% | 59.65% |
| attempt 5 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 124 / 13 / 26 / 9 | 93.23% | 33.33% | 82.67% | 87.63% | 63.28% |
| attempt 5 / gretel | pipeline | 98 / 54 | 95 / 11 / 43 / 3 | 96.94% | 20.37% | 68.84% | 80.51% | 58.65% |
| attempt 5 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 5 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 8 / pooled | semantic | 475 / 493 | 238 / 165 / 328 / 237 | 50.11% | 33.47% | 42.05% | 45.73% | 41.79% |
| attempt 8 / AI4Privacy/OpenPII | semantic | 133 / 39 | 59 / 16 / 23 / 74 | 44.36% | 41.03% | 71.95% | 54.88% | 42.69% |
| attempt 8 / gretel | semantic | 98 / 54 | 69 / 13 / 41 / 29 | 70.41% | 24.07% | 62.73% | 66.35% | 47.24% |
| attempt 8 / nemotron-pii | semantic | 206 / 384 | 99 / 125 / 259 / 107 | 48.06% | 32.55% | 27.65% | 35.11% | 40.31% |
| attempt 8 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 8 / pooled | pipeline | 475 / 493 | 425 / 152 / 341 / 50 | 89.47% | 30.83% | 55.48% | 68.49% | 60.15% |
| attempt 8 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 122 / 15 / 24 / 11 | 91.73% | 38.46% | 83.56% | 87.46% | 65.10% |
| attempt 8 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 8 / nemotron-pii | pipeline | 206 / 384 | 175 / 118 / 266 / 31 | 84.95% | 30.73% | 39.68% | 54.10% | 57.84% |
| attempt 8 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 9 / pooled | semantic | 475 / 493 | 243 / 158 / 335 / 232 | 51.16% | 32.05% | 42.04% | 46.15% | 41.60% |
| attempt 9 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 14 / 25 / 73 | 45.11% | 35.90% | 70.59% | 55.05% | 40.51% |
| attempt 9 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% | 47.75% |
| attempt 9 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 9 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 9 / pooled | pipeline | 475 / 493 | 426 / 146 / 347 / 49 | 89.68% | 29.61% | 55.11% | 68.27% | 59.65% |
| attempt 9 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 13 / 26 / 10 | 92.48% | 33.33% | 82.55% | 87.23% | 62.91% |
| attempt 9 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 9 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 9 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 10 / pooled | semantic | 475 / 493 | 238 / 165 / 328 / 237 | 50.11% | 33.47% | 42.05% | 45.73% | 41.79% |
| attempt 10 / AI4Privacy/OpenPII | semantic | 133 / 39 | 59 / 16 / 23 / 74 | 44.36% | 41.03% | 71.95% | 54.88% | 42.69% |
| attempt 10 / gretel | semantic | 98 / 54 | 69 / 13 / 41 / 29 | 70.41% | 24.07% | 62.73% | 66.35% | 47.24% |
| attempt 10 / nemotron-pii | semantic | 206 / 384 | 99 / 125 / 259 / 107 | 48.06% | 32.55% | 27.65% | 35.11% | 40.31% |
| attempt 10 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 10 / pooled | pipeline | 475 / 493 | 425 / 152 / 341 / 50 | 89.47% | 30.83% | 55.48% | 68.49% | 60.15% |
| attempt 10 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 122 / 15 / 24 / 11 | 91.73% | 38.46% | 83.56% | 87.46% | 65.10% |
| attempt 10 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 10 / nemotron-pii | pipeline | 206 / 384 | 175 / 118 / 266 / 31 | 84.95% | 30.73% | 39.68% | 54.10% | 57.84% |
| attempt 10 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |
| attempt 11 / pooled | semantic | 475 / 493 | 243 / 159 / 334 / 232 | 51.16% | 32.25% | 42.11% | 46.20% | 41.70% |
| attempt 11 / AI4Privacy/OpenPII | semantic | 133 / 39 | 60 / 15 / 24 / 73 | 45.11% | 38.46% | 71.43% | 55.30% | 41.79% |
| attempt 11 / gretel | semantic | 98 / 54 | 70 / 13 / 41 / 28 | 71.43% | 24.07% | 63.06% | 66.99% | 47.75% |
| attempt 11 / nemotron-pii | semantic | 206 / 384 | 102 / 120 / 264 / 104 | 49.51% | 31.25% | 27.87% | 35.66% | 40.38% |
| attempt 11 / privy | semantic | 38 / 16 | 11 / 11 / 5 / 27 | 28.95% | 68.75% | 68.75% | 40.74% | 48.85% |
| attempt 11 / pooled | pipeline | 475 / 493 | 426 / 147 / 346 / 49 | 89.68% | 29.82% | 55.18% | 68.32% | 59.75% |
| attempt 11 / AI4Privacy/OpenPII | pipeline | 133 / 39 | 123 / 14 / 25 / 10 | 92.48% | 35.90% | 83.11% | 87.54% | 64.19% |
| attempt 11 / gretel | pipeline | 98 / 54 | 95 / 12 / 42 / 3 | 96.94% | 22.22% | 69.34% | 80.85% | 59.58% |
| attempt 11 / nemotron-pii | pipeline | 206 / 384 | 175 / 114 / 270 / 31 | 84.95% | 29.69% | 39.33% | 53.76% | 57.32% |
| attempt 11 / privy | pipeline | 38 / 16 | 33 / 7 / 9 / 5 | 86.84% | 43.75% | 78.57% | 82.50% | 65.30% |

| Model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |
| --- | --- | ---: | --- | --- |
| live balanced baseline | v0.3.0+train.2 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 0 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 1 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 2 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 3 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 4 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 5 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 8 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 9 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 10 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |
| attempt 11 | v0.3.0+train.3 | 36756 / 660 | 32 / 64 / 2 / 4 / 96 / 512 | six contextual heads; encoder frozen |

| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.5436523437500005 | — |
| 1 | 12.50% → 12.50% | 100.00% → 100.00% | 25.00% → 25.00% | 0.00% | 0.39492777777777827 | — |
| 2 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.5754557291666667 | — |
| 3 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.3897513440860216 | — |
| 4 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.5646809895833337 | — |
| 5 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.4585751237067034 | — |
| 6 | — → — | — → — | — → — | — | — | — |
| 7 | — → — | — → — | — → — | — | — | — |
| 8 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.5754557291666667 | — |
| 9 | 25.00% → 25.00% | 100.00% → 100.00% | 37.50% → 37.50% | 0.00% | 0.3897513440860216 | — |
| 10 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.5646809895833337 | — |
| 11 | 25.00% → 25.00% | 87.50% → 87.50% | 25.00% → 25.00% | 0.00% | 0.4585751237067034 | — |
| 12 | — → — | — → — | — → — | — | — | — |
| 13 | — → — | — → — | — → — | — | — | — |
| 14 | — → — | — → — | — → — | — | — | — |
| 15 | — → — | — → — | — → — | — | — | — |
| 16 | — → — | — → — | — → — | — | — | — |
| 17 | — → — | — → — | — → — | — | — | — |
| 18 | — → — | — → — | — → — | — | — | — |
| 19 | — → — | — → — | — → — | — | — | — |
| 20 | — → — | — → — | — → — | — | — | — |
| 21 | — → — | — → — | — → — | — | — | — |
| 22 | — → — | — → — | — → — | — | — | — |
| 23 | — → — | — → — | — → — | — | — | — |

Legacy average_loss measures weighted classification distance. Last-block supervised_objective_loss uses sensitivity CE + visibility CE + summed category BCE. Original and balanced objectives assign different class weight, so their losses are not interchangeable quality scores.

| Accepted attempt | Actual training class rows | Raw class weights | Effective class weights | Clean / sensitive objective mass |
| ---: | --- | --- | --- | --- |
| 0 | see paired inventory in JSON | original weights | unchanged | no additional balancing |
| 1 | 250 / 6 | 250.0 / 6.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 2 | see paired inventory in JSON | original weights | unchanged | no additional balancing |
| 3 | 248 / 8 | 248.0 / 8.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 4 | see paired inventory in JSON | original weights | unchanged | no additional balancing |
| 5 | 247 / 9 | 247.0 / 9.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 8 | see paired inventory in JSON | original weights | unchanged | no additional balancing |
| 9 | 248 / 8 | 248.0 / 8.0 | 128.0 / 128.0 | 0.5 / 0.5 |
| 10 | see paired inventory in JSON | original weights | unchanged | no additional balancing |
| 11 | 247 / 9 | 247.0 / 9.0 | 128.0 / 128.0 | 0.5 / 0.5 |

No eligible frozen winner; no candidate development/fixture score claimed. Retained: False.

Model and training identities, parameter dimensions/counts, trainable/frozen tensors, publication changes, held-out guards, loss definitions, paired predictions, sampling inventories and immutable source/report commitments are retained in the JSON evidence. Service timings exclude browser overhead and do not establish production latency.

- Profile names and tensor counts do not establish model quality.
- The exact live balanced model includes prior training; encoders originate in repository-owned seeded initialization.
- Authored contextual targets and public negatives are provisional, without independent human action truth.
- Reused validation/development are exploratory; no final generalization, statistical superiority or deployment-safety claim follows.
- Annotation presence does not establish sensitivity, visibility, complete span recovery or contextual action correctness.
- Original weighting and class-balanced objective losses use different class mass; loss values are not interchangeable quality scores.
- Confidence calibration and representative production latency remain unestablished.
- The initial 54-attempt study remains separate failed evidence. No protected final examples or labels are opened.

