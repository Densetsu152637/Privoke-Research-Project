# Complete stratified recalculation tables

Generated from the preserved predictions by the script in [evidence and reproduction](evidence-and-reproduction.md), 6 October 2026. Percentages round only for display. Counts are TP / TN / FP / FN. Missing class rates are shown as —. All runs have zero errors. These are exploratory annotated-PII-presence strata, not contextual action scores.

## Development: same 502 sentences

| Configuration | Dataset source | Positive | Clean | Groups | TP / TN / FP / FN | Recall | Specificity | Balanced accuracy |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| Original NER | AI4Privacy / OpenPII | 81 | 22 | 101 | 20 / 22 / 0 / 61 | 24.69% | 100.00% | 62.35% |
| Original NER | Gretel (PIIMB origin) | 55 | 28 | 79 | 13 / 27 / 1 / 42 | 23.64% | 96.43% | 60.03% |
| Original NER | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 2 / 0 / 0 | — | 100.00% | — |
| Original NER | Nemotron (PIIMB origin) | 110 | 184 | 264 | 19 / 179 / 5 / 91 | 17.27% | 97.28% | 57.28% |
| Original NER | Privy | 18 | 2 | 20 | 3 / 2 / 0 / 15 | 16.67% | 100.00% | 58.33% |
| Original full pipeline | AI4Privacy / OpenPII | 81 | 22 | 101 | 75 / 6 / 16 / 6 | 92.59% | 27.27% | 59.93% |
| Original full pipeline | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 4 / 24 / 2 | 96.36% | 14.29% | 55.32% |
| Original full pipeline | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Original full pipeline | Nemotron (PIIMB origin) | 110 | 184 | 264 | 101 / 36 / 148 / 9 | 91.82% | 19.57% | 55.69% |
| Original full pipeline | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Original regex + NER | AI4Privacy / OpenPII | 81 | 22 | 101 | 61 / 19 / 3 / 20 | 75.31% | 86.36% | 80.84% |
| Original regex + NER | Gretel (PIIMB origin) | 55 | 28 | 79 | 48 / 19 / 9 / 7 | 87.27% | 67.86% | 77.56% |
| Original regex + NER | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 2 / 0 / 0 | — | 100.00% | — |
| Original regex + NER | Nemotron (PIIMB origin) | 110 | 184 | 264 | 71 / 162 / 22 / 39 | 64.55% | 88.04% | 76.29% |
| Original regex + NER | Privy | 18 | 2 | 20 | 18 / 1 / 1 / 0 | 100.00% | 50.00% | 75.00% |
| Original regex | AI4Privacy / OpenPII | 81 | 22 | 101 | 54 / 19 / 3 / 27 | 66.67% | 86.36% | 76.52% |
| Original regex | Gretel (PIIMB origin) | 55 | 28 | 79 | 44 / 19 / 9 / 11 | 80.00% | 67.86% | 73.93% |
| Original regex | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 2 / 0 / 0 | — | 100.00% | — |
| Original regex | Nemotron (PIIMB origin) | 110 | 184 | 264 | 64 / 167 / 17 / 46 | 58.18% | 90.76% | 74.47% |
| Original regex | Privy | 18 | 2 | 20 | 17 / 1 / 1 / 1 | 94.44% | 50.00% | 72.22% |
| Original semantic | AI4Privacy / OpenPII | 81 | 22 | 101 | 39 / 7 / 15 / 42 | 48.15% | 31.82% | 39.98% |
| Original semantic | Gretel (PIIMB origin) | 55 | 28 | 79 | 45 / 8 / 20 / 10 | 81.82% | 28.57% | 55.19% |
| Original semantic | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Original semantic | Nemotron (PIIMB origin) | 110 | 184 | 264 | 75 / 44 / 140 / 35 | 68.18% | 23.91% | 46.05% |
| Original semantic | Privy | 18 | 2 | 20 | 10 / 0 / 2 / 8 | 55.56% | 0.00% | 27.78% |
| Earlier selected full pipeline | AI4Privacy / OpenPII | 81 | 22 | 101 | 75 / 7 / 15 / 6 | 92.59% | 31.82% | 62.21% |
| Earlier selected full pipeline | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 6 / 22 / 2 | 96.36% | 21.43% | 58.90% |
| Earlier selected full pipeline | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Earlier selected full pipeline | Nemotron (PIIMB origin) | 110 | 184 | 264 | 101 / 40 / 144 / 9 | 91.82% | 21.74% | 56.78% |
| Earlier selected full pipeline | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Earlier selected regex | AI4Privacy / OpenPII | 81 | 22 | 101 | 49 / 20 / 2 / 32 | 60.49% | 90.91% | 75.70% |
| Earlier selected regex | Gretel (PIIMB origin) | 55 | 28 | 79 | 44 / 26 / 2 / 11 | 80.00% | 92.86% | 86.43% |
| Earlier selected regex | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 2 / 0 / 0 | — | 100.00% | — |
| Earlier selected regex | Nemotron (PIIMB origin) | 110 | 184 | 264 | 62 / 182 / 2 / 48 | 56.36% | 98.91% | 77.64% |
| Earlier selected regex | Privy | 18 | 2 | 20 | 17 / 1 / 1 / 1 | 94.44% | 50.00% | 72.22% |
| Current selected full pipeline | AI4Privacy / OpenPII | 81 | 22 | 101 | 71 / 11 / 11 / 10 | 87.65% | 50.00% | 68.83% |
| Current selected full pipeline | Gretel (PIIMB origin) | 55 | 28 | 79 | 52 / 7 / 21 / 3 | 94.55% | 25.00% | 59.77% |
| Current selected full pipeline | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Current selected full pipeline | Nemotron (PIIMB origin) | 110 | 184 | 264 | 98 / 51 / 133 / 12 | 89.09% | 27.72% | 58.40% |
| Current selected full pipeline | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Current selected semantic | AI4Privacy / OpenPII | 81 | 22 | 101 | 29 / 12 / 10 / 52 | 35.80% | 54.55% | 45.17% |
| Current selected semantic | Gretel (PIIMB origin) | 55 | 28 | 79 | 39 / 9 / 19 / 16 | 70.91% | 32.14% | 51.53% |
| Current selected semantic | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Current selected semantic | Nemotron (PIIMB origin) | 110 | 184 | 264 | 63 / 55 / 129 / 47 | 57.27% | 29.89% | 43.58% |
| Current selected semantic | Privy | 18 | 2 | 20 | 9 / 0 / 2 / 9 | 50.00% | 0.00% | 25.00% |
| Configured independent Presidio | AI4Privacy / OpenPII | 81 | 22 | 101 | 69 / 15 / 7 / 12 | 85.19% | 68.18% | 76.68% |
| Configured independent Presidio | Gretel (PIIMB origin) | 55 | 28 | 79 | 43 / 21 / 7 / 12 | 78.18% | 75.00% | 76.59% |
| Configured independent Presidio | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Configured independent Presidio | Nemotron (PIIMB origin) | 110 | 184 | 264 | 79 / 152 / 32 / 31 | 71.82% | 82.61% | 77.21% |
| Configured independent Presidio | Privy | 18 | 2 | 20 | 17 / 0 / 2 / 1 | 94.44% | 0.00% | 47.22% |
| Sparse presence: efficient | AI4Privacy / OpenPII | 81 | 22 | 101 | 76 / 12 / 10 / 5 | 93.83% | 54.55% | 74.19% |
| Sparse presence: efficient | Gretel (PIIMB origin) | 55 | 28 | 79 | 55 / 18 / 10 / 0 | 100.00% | 64.29% | 82.14% |
| Sparse presence: efficient | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 0 / 2 / 0 | — | 0.00% | — |
| Sparse presence: efficient | Nemotron (PIIMB origin) | 110 | 184 | 264 | 100 / 139 / 45 / 10 | 90.91% | 75.54% | 83.23% |
| Sparse presence: efficient | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Sparse presence: balanced | AI4Privacy / OpenPII | 81 | 22 | 101 | 74 / 11 / 11 / 7 | 91.36% | 50.00% | 70.68% |
| Sparse presence: balanced | Gretel (PIIMB origin) | 55 | 28 | 79 | 55 / 19 / 9 / 0 | 100.00% | 67.86% | 83.93% |
| Sparse presence: balanced | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 0 / 2 / 0 | — | 0.00% | — |
| Sparse presence: balanced | Nemotron (PIIMB origin) | 110 | 184 | 264 | 100 / 150 / 34 / 10 | 90.91% | 81.52% | 86.22% |
| Sparse presence: balanced | Privy | 18 | 2 | 20 | 18 / 1 / 1 / 0 | 100.00% | 50.00% | 75.00% |
| Sparse presence: quality | AI4Privacy / OpenPII | 81 | 22 | 101 | 73 / 13 / 9 / 8 | 90.12% | 59.09% | 74.61% |
| Sparse presence: quality | Gretel (PIIMB origin) | 55 | 28 | 79 | 55 / 19 / 9 / 0 | 100.00% | 67.86% | 83.93% |
| Sparse presence: quality | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 0 / 2 / 0 | — | 0.00% | — |
| Sparse presence: quality | Nemotron (PIIMB origin) | 110 | 184 | 264 | 101 / 156 / 28 / 9 | 91.82% | 84.78% | 88.30% |
| Sparse presence: quality | Privy | 18 | 2 | 20 | 18 / 1 / 1 / 0 | 100.00% | 50.00% | 75.00% |
| Contextual gate: efficient | AI4Privacy / OpenPII | 81 | 22 | 101 | 74 / 13 / 9 / 7 | 91.36% | 59.09% | 75.22% |
| Contextual gate: efficient | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 18 / 10 / 2 | 96.36% | 64.29% | 80.32% |
| Contextual gate: efficient | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Contextual gate: efficient | Nemotron (PIIMB origin) | 110 | 184 | 264 | 97 / 143 / 41 / 13 | 88.18% | 77.72% | 82.95% |
| Contextual gate: efficient | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Gate study: matched ordinary control | AI4Privacy / OpenPII | 81 | 22 | 101 | 75 / 6 / 16 / 6 | 92.59% | 27.27% | 59.93% |
| Gate study: matched ordinary control | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 6 / 22 / 2 | 96.36% | 21.43% | 58.90% |
| Gate study: matched ordinary control | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Gate study: matched ordinary control | Nemotron (PIIMB origin) | 110 | 184 | 264 | 101 / 40 / 144 / 9 | 91.82% | 21.74% | 56.78% |
| Gate study: matched ordinary control | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Contextual gate: balanced | AI4Privacy / OpenPII | 81 | 22 | 101 | 74 / 11 / 11 / 7 | 91.36% | 50.00% | 70.68% |
| Contextual gate: balanced | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 18 / 10 / 2 | 96.36% | 64.29% | 80.32% |
| Contextual gate: balanced | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Contextual gate: balanced | Nemotron (PIIMB origin) | 110 | 184 | 264 | 97 / 139 / 45 / 13 | 88.18% | 75.54% | 81.86% |
| Contextual gate: balanced | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |
| Contextual gate: quality | AI4Privacy / OpenPII | 81 | 22 | 101 | 74 / 10 / 12 / 7 | 91.36% | 45.45% | 68.41% |
| Contextual gate: quality | Gretel (PIIMB origin) | 55 | 28 | 79 | 53 / 16 / 12 / 2 | 96.36% | 57.14% | 76.75% |
| Contextual gate: quality | MAPA EUR-LEX | 0 | 2 | 1 | 0 / 1 / 1 / 0 | — | 50.00% | — |
| Contextual gate: quality | Nemotron (PIIMB origin) | 110 | 184 | 264 | 97 / 132 / 52 / 13 | 88.18% | 71.74% | 79.96% |
| Contextual gate: quality | Privy | 18 | 2 | 20 | 18 / 0 / 2 / 0 | 100.00% | 0.00% | 50.00% |

## External expanded-data study: validation

Validation was used for selection; these are not independent test scores. Baseline and expanded sparse profiles use their own frozen thresholds. Dataset task strata are merged for AI4Privacy consistently with the main report.

| Profile / control | Dataset source | Positive | Clean | Groups | TP / TN / FP / FN | Recall | Specificity | Balanced accuracy |
| --- | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| efficient / baseline | AI4Privacy / OpenPII | 133 | 39 | 143 | 123 / 25 / 14 / 10 | 92.48% | 64.10% | 78.29% |
| efficient / baseline | Gretel (PIIMB origin) | 98 | 54 | 139 | 91 / 42 / 12 / 7 | 92.86% | 77.78% | 85.32% |
| efficient / baseline | Nemotron (PIIMB origin) | 206 | 384 | 378 | 178 / 308 / 76 / 28 | 86.41% | 80.21% | 83.31% |
| efficient / baseline | Privy | 38 | 16 | 54 | 37 / 3 / 13 / 1 | 97.37% | 18.75% | 58.06% |
| efficient / expanded | AI4Privacy / OpenPII | 133 | 39 | 143 | 121 / 21 / 18 / 12 | 90.98% | 53.85% | 72.41% |
| efficient / expanded | Gretel (PIIMB origin) | 98 | 54 | 139 | 92 / 33 / 21 / 6 | 93.88% | 61.11% | 77.49% |
| efficient / expanded | Nemotron (PIIMB origin) | 206 | 384 | 378 | 179 / 273 / 111 / 27 | 86.89% | 71.09% | 78.99% |
| efficient / expanded | Privy | 38 | 16 | 54 | 36 / 3 / 13 / 2 | 94.74% | 18.75% | 56.74% |
| balanced / baseline | AI4Privacy / OpenPII | 133 | 39 | 143 | 122 / 25 / 14 / 11 | 91.73% | 64.10% | 77.92% |
| balanced / baseline | Gretel (PIIMB origin) | 98 | 54 | 139 | 92 / 45 / 9 / 6 | 93.88% | 83.33% | 88.61% |
| balanced / baseline | Nemotron (PIIMB origin) | 206 | 384 | 378 | 177 / 319 / 65 / 29 | 85.92% | 83.07% | 84.50% |
| balanced / baseline | Privy | 38 | 16 | 54 | 37 / 3 / 13 / 1 | 97.37% | 18.75% | 58.06% |
| balanced / expanded | AI4Privacy / OpenPII | 133 | 39 | 143 | 121 / 23 / 16 / 12 | 90.98% | 58.97% | 74.98% |
| balanced / expanded | Gretel (PIIMB origin) | 98 | 54 | 139 | 91 / 48 / 6 / 7 | 92.86% | 88.89% | 90.87% |
| balanced / expanded | Nemotron (PIIMB origin) | 206 | 384 | 378 | 179 / 321 / 63 / 27 | 86.89% | 83.59% | 85.24% |
| balanced / expanded | Privy | 38 | 16 | 54 | 37 / 4 / 12 / 1 | 97.37% | 25.00% | 61.18% |
| quality / baseline | AI4Privacy / OpenPII | 133 | 39 | 143 | 124 / 23 / 16 / 9 | 93.23% | 58.97% | 76.10% |
| quality / baseline | Gretel (PIIMB origin) | 98 | 54 | 139 | 93 / 45 / 9 / 5 | 94.90% | 83.33% | 89.12% |
| quality / baseline | Nemotron (PIIMB origin) | 206 | 384 | 378 | 174 / 323 / 61 / 32 | 84.47% | 84.11% | 84.29% |
| quality / baseline | Privy | 38 | 16 | 54 | 37 / 3 / 13 / 1 | 97.37% | 18.75% | 58.06% |
| quality / expanded | AI4Privacy / OpenPII | 133 | 39 | 143 | 118 / 25 / 14 / 15 | 88.72% | 64.10% | 76.41% |
| quality / expanded | Gretel (PIIMB origin) | 98 | 54 | 139 | 92 / 45 / 9 / 6 | 93.88% | 83.33% | 88.61% |
| quality / expanded | Nemotron (PIIMB origin) | 206 | 384 | 378 | 183 / 310 / 74 / 23 | 88.83% | 80.73% | 84.78% |
| quality / expanded | Privy | 38 | 16 | 54 | 37 / 4 / 12 / 1 | 97.37% | 25.00% | 61.18% |

## External expanded-data study: positive-only source-heldout

Nemotron here is the official train-origin heldout partition, distinct from PIIMB-origin development. Meddies group counts are coarse metadata families. No clean class exists.

| Profile / control / partition | Positive | Clean | Groups | TP / TN / FP / FN | Recall | Specificity | Balanced accuracy |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| efficient baseline nemotron heldout | 1000 | 0 | 500 | 956 / 0 / 0 / 44 | 95.60% | — | — |
| efficient baseline meddies heldout | 999 | 0 | 36 | 998 / 0 / 0 / 1 | 99.90% | — | — |
| efficient expanded nemotron heldout | 1000 | 0 | 500 | 1000 / 0 / 0 / 0 | 100.00% | — | — |
| efficient expanded meddies heldout | 999 | 0 | 36 | 999 / 0 / 0 / 0 | 100.00% | — | — |
| balanced baseline nemotron heldout | 1000 | 0 | 500 | 919 / 0 / 0 / 81 | 91.90% | — | — |
| balanced baseline meddies heldout | 999 | 0 | 36 | 997 / 0 / 0 / 2 | 99.80% | — | — |
| balanced expanded nemotron heldout | 1000 | 0 | 500 | 1000 / 0 / 0 / 0 | 100.00% | — | — |
| balanced expanded meddies heldout | 999 | 0 | 36 | 999 / 0 / 0 / 0 | 100.00% | — | — |
| quality baseline nemotron heldout | 1000 | 0 | 500 | 892 / 0 / 0 / 108 | 89.20% | — | — |
| quality baseline meddies heldout | 999 | 0 | 36 | 995 / 0 / 0 / 4 | 99.60% | — | — |
| quality expanded nemotron heldout | 1000 | 0 | 500 | 1000 / 0 / 0 / 0 | 100.00% | — | — |
| quality expanded meddies heldout | 999 | 0 | 36 | 999 / 0 / 0 / 0 | 100.00% | — | — |

For scope, denominator definitions, clustering/selection limits and interpretation, read [the main results](results-by-dataset.md). These alternative systems, sources and tasks should not be averaged into a universal score.

