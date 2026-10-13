# Existing v1/v2/v3 model comparison (V123-R1)

The completed comparison found mixed accuracy and cost tradeoffs across all 14 snapshots in the predeclared comparison inventory. The guard-rejected raw v3 quality FULL42 export had the highest context320 joint score (66/320), while v1 balanced and unchanged v2 balanced controls scored 63/320. On context64 those balanced controls scored 10/64, versus 7-8/64 for the v3 candidates. V3 candidates had faster measured CPU RPC latency in this workload, but larger process memory footprints. These findings describe the admitted serving packages on reused DEVELOPMENT fixtures; they establish neither a universal winner nor a causal architecture/pretraining effect.

The user requested: “Now test it and compare the performance of all v1/2/3 models”. In response to “Only the balanced v2 checkpoint exists; v2 efficient and quality are absent. Which comparison should I deliver?”, the user selected “Test all existing checkpoints and mark missing v2 tiers unavailable (Recommended)” and subsequently said “Continue”. This post-study comparison creates no weights, fits no model, promotes nothing and reads no protected-final payload. Earlier training studies remain closed.

Completed on 13 October 2026 (Sydney), the accepted run covered 14 snapshots, 42 fresh runtime processes and 27,902 RPCs: 13,076 accuracy requests (12,978 eligible), 1,344 warmup calls, 13,440 measured calls and 42 first RPCs. All 77 accuracy errors were native v2 over-cap runtime failures and count incorrect. Timing calls had zero failures. The same accuracy cases repeat across snapshots; totals are coverage counts, not independent observations.

## Inventory and native boundaries

The inventory was frozen before outcomes. V2 terminals are effective artifacts, including no-update outcomes; v3 exports are fixed FULL seed-42 artifacts. The guard-rejected quality raw export is tested separately from its effective ORIGINAL control. No checkpoint was selected by comparison outcome. Parameter counts, serialized asset bytes, identities, source paths and provenance come from the [frozen registry](../evaluation/results/v123_comparison_20261013/protocol/protocol-02.json).

| Snapshot | Status | Parameters | Float32 bytes | Deployment bytes | Native cap | Truncated cases | Rejected cases |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1-efficient | original | 19028 | 76112 | 409820 | 64 | 73 | 0 |
| v1-balanced | original | 36756 | 147024 | 789149 | 96 | 11 | 0 |
| v1-quality | original | 54292 | 217168 | 1164872 | 128 | 8 | 0 |
| v2-original | original | 36852 | 147408 | 420391 | 96 | 0 | 11 |
| v2-legacy-42 | updated | 36852 | 147408 | 757800 | 96 | 0 | 11 |
| v2-legacy-43 | updated | 36852 | 147408 | 757629 | 96 | 0 | 11 |
| v2-legacy-44 | updated | 36852 | 147408 | 757861 | 96 | 0 | 11 |
| v2-window-42 | no_update | 36852 | 147408 | 421581 | 96 | 0 | 11 |
| v2-window-43 | no_update | 36852 | 147408 | 421581 | 96 | 0 | 11 |
| v2-window-44 | updated | 36852 | 147408 | 758399 | 96 | 0 | 11 |
| v3-efficient | applied_guard_passed | 4785044 | 19140176 | 19394447 | 512 | 0 | 0 |
| v3-balanced | applied_guard_passed | 9596180 | 38384720 | 38630108 | 512 | 0 | 0 |
| v3-quality | raw_guard_rejected | 17493780 | 69975120 | 70265115 | 512 | 0 | 0 |
| v3-quality-original | original_control | 17493780 | 69975120 | 70264919 | 512 | 0 | 0 |
| v2-efficient | Unavailable | NA | NA | NA | NA | NA | NA |
| v2-quality | Unavailable | NA | NA | NA | NA | NA | NA |

Caps include native special tokens: one start token for Tiny and two BERT special tokens for v3. V1 truncates overlength inputs; v2 and v3 reject them. Wire text/source/hint/purpose fields are identical, without a second normalization or trim. The frozen protocol's `workload.windows` retains every over-cap, truncated and rejected case ID, and `all_case_lengths` retains all native lengths. Each of the seven v2 snapshots rejects the same eleven binary502 cases above its 96-token cap (77 errors total); no other endpoint or snapshot errors occurred. They remain in the 502-case denominator and cannot earn correctness from a failed BLOCK response. All requested error counts, including ambiguous hazard requests, are reported below; every failure stage here is runtime, with zero transport/pre-execution failures.

## Complete endpoint results

S, C, V, A, P, J and B are sensitivity, exact category-set, visibility, allowed-action agreement, packed classification exactness, joint packed-plus-action correctness and annotation-presence correctness. Each cell reports correct/eligible. R and Sp report annotated-sensitive recall and clean specificity. Errors are incorrect for all applicable metrics. Allowed actions are sets. Primary contextual fixtures and secondary binary/hazard fixtures remain separate.

### context320

| Snapshot | S | C | V | A | P | J | B | R | Sp | Errors/requested |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1-efficient | 113/320 | 160/320 | 121/320 | 147/320 | 39/320 | 39/320 | 185/320 | 90/160 | 95/160 | 0/320 |
| v1-balanced | 146/320 | 160/320 | 120/320 | 162/320 | 63/320 | 63/320 | 171/320 | 45/160 | 126/160 | 0/320 |
| v1-quality | 157/320 | 159/320 | 120/320 | 195/320 | 43/320 | 43/320 | 205/320 | 133/160 | 72/160 | 0/320 |
| v2-original | 146/320 | 160/320 | 120/320 | 162/320 | 63/320 | 63/320 | 171/320 | 45/160 | 126/160 | 0/320 |
| v2-legacy-42 | 157/320 | 157/320 | 98/320 | 177/320 | 40/320 | 40/320 | 157/320 | 2/160 | 155/160 | 0/320 |
| v2-legacy-43 | 155/320 | 157/320 | 102/320 | 175/320 | 58/320 | 58/320 | 157/320 | 4/160 | 153/160 | 0/320 |
| v2-legacy-44 | 158/320 | 160/320 | 73/320 | 179/320 | 26/320 | 26/320 | 164/320 | 6/160 | 158/160 | 0/320 |
| v2-window-42 | 146/320 | 160/320 | 120/320 | 162/320 | 63/320 | 63/320 | 171/320 | 45/160 | 126/160 | 0/320 |
| v2-window-43 | 146/320 | 160/320 | 120/320 | 162/320 | 63/320 | 63/320 | 171/320 | 45/160 | 126/160 | 0/320 |
| v2-window-44 | 158/320 | 157/320 | 106/320 | 177/320 | 42/320 | 42/320 | 160/320 | 5/160 | 155/160 | 0/320 |
| v3-efficient | 161/320 | 161/320 | 135/320 | 180/320 | 42/320 | 42/320 | 219/320 | 75/160 | 144/160 | 0/320 |
| v3-balanced | 161/320 | 160/320 | 142/320 | 177/320 | 51/320 | 51/320 | 169/320 | 10/160 | 159/160 | 0/320 |
| v3-quality | 162/320 | 160/320 | 154/320 | 178/320 | 66/320 | 66/320 | 170/320 | 10/160 | 160/160 | 0/320 |
| v3-quality-original | 160/320 | 0/320 | 41/320 | 119/320 | 0/320 | 0/320 | 160/320 | 160/160 | 0/160 | 0/320 |

### context64

| Snapshot | S | C | V | A | P | J | B | R | Sp | Errors/requested |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1-efficient | 30/64 | 32/64 | 24/64 | 31/64 | 9/64 | 9/64 | 42/64 | 29/32 | 13/32 | 0/64 |
| v1-balanced | 35/64 | 30/64 | 25/64 | 34/64 | 10/64 | 10/64 | 46/64 | 27/32 | 19/32 | 0/64 |
| v1-quality | 21/64 | 30/64 | 27/64 | 24/64 | 8/64 | 8/64 | 40/64 | 30/32 | 10/32 | 0/64 |
| v2-original | 35/64 | 30/64 | 25/64 | 34/64 | 10/64 | 10/64 | 46/64 | 27/32 | 19/32 | 0/64 |
| v2-legacy-42 | 44/64 | 30/64 | 16/64 | 44/64 | 2/64 | 2/64 | 53/64 | 23/32 | 30/32 | 0/64 |
| v2-legacy-43 | 48/64 | 31/64 | 8/64 | 47/64 | 0/64 | 0/64 | 48/64 | 18/32 | 30/32 | 0/64 |
| v2-legacy-44 | 47/64 | 32/64 | 14/64 | 47/64 | 5/64 | 5/64 | 55/64 | 23/32 | 32/32 | 0/64 |
| v2-window-42 | 35/64 | 30/64 | 25/64 | 34/64 | 10/64 | 10/64 | 46/64 | 27/32 | 19/32 | 0/64 |
| v2-window-43 | 35/64 | 30/64 | 25/64 | 34/64 | 10/64 | 10/64 | 46/64 | 27/32 | 19/32 | 0/64 |
| v2-window-44 | 46/64 | 33/64 | 20/64 | 47/64 | 5/64 | 5/64 | 55/64 | 25/32 | 30/32 | 0/64 |
| v3-efficient | 54/64 | 34/64 | 16/64 | 52/64 | 8/64 | 8/64 | 57/64 | 31/32 | 26/32 | 0/64 |
| v3-balanced | 57/64 | 33/64 | 21/64 | 55/64 | 8/64 | 8/64 | 61/64 | 31/32 | 30/32 | 0/64 |
| v3-quality | 56/64 | 34/64 | 23/64 | 56/64 | 7/64 | 7/64 | 56/64 | 26/32 | 30/32 | 0/64 |
| v3-quality-original | 32/64 | 0/64 | 13/64 | 7/64 | 0/64 | 0/64 | 32/64 | 32/32 | 0/32 | 0/64 |

### Secondary binary502 and hazard48

| Snapshot | Binary correct | Binary R | Binary Sp | Binary errors/requested | Hazard S | Hazard A | Hazard eligible/requested | Hazard errors/requested |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1-efficient | 219/502 | 158/264 | 61/238 | 0/502 | 14/41 | 28/41 | 41/48 | 0/48 |
| v1-balanced | 229/502 | 169/264 | 60/238 | 0/502 | 16/41 | 27/41 | 41/48 | 0/48 |
| v1-quality | 238/502 | 190/264 | 48/238 | 0/502 | 17/41 | 27/41 | 41/48 | 0/48 |
| v2-original | 226/502 | 166/264 | 60/238 | 11/502 | 16/41 | 27/41 | 41/48 | 0/48 |
| v2-legacy-42 | 200/502 | 70/264 | 130/238 | 11/502 | 16/41 | 30/41 | 41/48 | 0/48 |
| v2-legacy-43 | 203/502 | 60/264 | 143/238 | 11/502 | 14/41 | 33/41 | 41/48 | 0/48 |
| v2-legacy-44 | 213/502 | 69/264 | 144/238 | 11/502 | 17/41 | 32/41 | 41/48 | 0/48 |
| v2-window-42 | 226/502 | 166/264 | 60/238 | 11/502 | 16/41 | 27/41 | 41/48 | 0/48 |
| v2-window-43 | 226/502 | 166/264 | 60/238 | 11/502 | 16/41 | 27/41 | 41/48 | 0/48 |
| v2-window-44 | 209/502 | 64/264 | 145/238 | 11/502 | 18/41 | 33/41 | 41/48 | 0/48 |
| v3-efficient | 248/502 | 113/264 | 135/238 | 0/502 | 16/41 | 35/41 | 41/48 | 0/48 |
| v3-balanced | 272/502 | 91/264 | 181/238 | 0/502 | 16/41 | 33/41 | 41/48 | 0/48 |
| v3-quality | 272/502 | 113/264 | 159/238 | 0/502 | 20/41 | 37/41 | 41/48 | 0/48 |
| v3-quality-original | 264/502 | 264/264 | 0/238 | 0/502 | 16/41 | 15/41 | 41/48 | 0/48 |

Seven ambiguous hazard cases were requested but excluded from correctness denominators for every snapshot. Secondary binary annotations do not establish contextual privacy truth. Quality v3 ORIGINAL has zero joint correctness on both contextual fixtures, with binary recall 264/264 and specificity 0/238; its zero task heads make it a weak task baseline despite intact pretrained encoders. The rejected raw quality export improves joint counts against that control but remains guard-rejected and unpromoted.

## Paired casewise contrasts

The following table includes all 40 same-tier contrasts. Direction is **right minus left**, exactly matching `left__right` keys in the [accepted analysis](../evaluation/results/v123_comparison_20261013/analysis.json). J/B/A cells give net correct change followed by improved/regressed counts. U/O are increases in under/over-restriction distance to allowed actions among pairs with two successful responses. Joint denominators are 320 and 64, binary 502 and hazard action 41. Full per-component improved/regressed/net/rate values and harm comparable/error-pair denominators are retained in `paired` in that analysis; no contrasts or unfavorable seeds are omitted.

| Left -> right | 320 J net (I/R) | 320 U/O | 64 J net (I/R) | 64 U/O | Binary net (I/R) | Hazard A net (I/R) | Hazard U/O |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1-balanced -> v2-legacy-42 | -23 (33/56) | 16/2 | -8 (2/10) | 10/2 | -29 (81/110) | +3 (6/3) | 2/5 |
| v1-balanced -> v2-legacy-43 | -5 (34/39) | 14/5 | -10 (0/10) | 10/2 | -26 (95/121) | +6 (8/2) | 1/3 |
| v1-balanced -> v2-legacy-44 | -37 (26/63) | 14/4 | -5 (5/10) | 10/1 | -16 (97/113) | +5 (8/3) | 2/3 |
| v1-balanced -> v2-original | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | -3 (0/3) | +0 (0/0) | 0/0 |
| v1-balanced -> v2-window-42 | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | -3 (0/3) | +0 (0/0) | 0/0 |
| v1-balanced -> v2-window-43 | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | -3 (0/3) | +0 (0/0) | 0/0 |
| v1-balanced -> v2-window-44 | -21 (36/57) | 14/5 | -5 (5/10) | 8/4 | -20 (100/120) | +6 (8/2) | 2/3 |
| v1-balanced -> v3-balanced | -12 (51/63) | 16/6 | -2 (8/10) | 5/2 | +43 (163/120) | +6 (12/6) | 4/3 |
| v1-efficient -> v3-efficient | +3 (42/39) | 26/34 | -1 (8/9) | 5/4 | +29 (135/106) | +7 (12/5) | 2/4 |
| v1-quality -> v3-quality | +23 (64/41) | 106/5 | -1 (6/7) | 5/1 | +34 (149/115) | +10 (10/0) | 1/1 |
| v1-quality -> v3-quality-original | -43 (0/43) | 0/99 | -8 (0/8) | 4/14 | +26 (74/48) | -12 (1/13) | 0/13 |
| v2-legacy-42 -> v2-legacy-43 | +18 (28/10) | 0/5 | -2 (0/2) | 6/2 | +3 (51/48) | +3 (5/2) | 1/1 |
| v2-legacy-42 -> v2-legacy-44 | -14 (2/16) | 0/2 | +3 (4/1) | 3/0 | +13 (47/34) | +2 (3/1) | 0/1 |
| v2-legacy-42 -> v2-window-42 | +23 (56/33) | 0/29 | +8 (10/2) | 6/12 | +26 (107/81) | -3 (3/6) | 2/4 |
| v2-legacy-42 -> v2-window-43 | +23 (56/33) | 0/29 | +8 (10/2) | 6/12 | +26 (107/81) | -3 (3/6) | 2/4 |
| v2-legacy-42 -> v2-window-44 | +2 (11/9) | 0/4 | +3 (4/1) | 1/3 | +9 (50/41) | +3 (3/0) | 0/0 |
| v2-legacy-42 -> v3-balanced | +11 (31/20) | 0/5 | +6 (8/2) | 2/2 | +72 (128/56) | +3 (8/5) | 2/3 |
| v2-legacy-43 -> v2-legacy-44 | -32 (5/37) | 0/2 | +5 (5/0) | 5/3 | +10 (55/45) | -1 (4/5) | 3/2 |
| v2-legacy-43 -> v2-window-42 | +5 (39/34) | 0/28 | +10 (10/0) | 5/14 | +23 (118/95) | -6 (2/8) | 3/5 |
| v2-legacy-43 -> v2-window-43 | +5 (39/34) | 0/28 | +10 (10/0) | 5/14 | +23 (118/95) | -6 (2/8) | 3/5 |
| v2-legacy-43 -> v2-window-44 | -16 (8/24) | 0/2 | +5 (5/0) | 4/4 | +6 (54/48) | +0 (3/3) | 3/1 |
| v2-legacy-43 -> v3-balanced | -7 (37/44) | 2/6 | +8 (8/0) | 2/2 | +69 (129/60) | +0 (7/7) | 4/3 |
| v2-legacy-44 -> v2-window-42 | +37 (63/26) | 1/30 | +5 (10/5) | 8/12 | +13 (110/97) | -5 (3/8) | 2/6 |
| v2-legacy-44 -> v2-window-43 | +37 (63/26) | 1/30 | +5 (10/5) | 8/12 | +13 (110/97) | -5 (3/8) | 2/6 |
| v2-legacy-44 -> v2-window-44 | +16 (17/1) | 1/3 | +0 (1/1) | 1/3 | -4 (51/55) | +1 (2/1) | 0/2 |
| v2-legacy-44 -> v3-balanced | +25 (32/7) | 3/5 | +3 (5/2) | 2/2 | +59 (128/69) | +1 (6/5) | 2/3 |
| v2-original -> v2-legacy-42 | -23 (33/56) | 16/2 | -8 (2/10) | 10/2 | -26 (81/107) | +3 (6/3) | 2/5 |
| v2-original -> v2-legacy-43 | -5 (34/39) | 14/5 | -10 (0/10) | 10/2 | -23 (95/118) | +6 (8/2) | 1/3 |
| v2-original -> v2-legacy-44 | -37 (26/63) | 14/4 | -5 (5/10) | 10/1 | -13 (97/110) | +5 (8/3) | 2/3 |
| v2-original -> v2-window-42 | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | +0 (0/0) | +0 (0/0) | 0/0 |
| v2-original -> v2-window-43 | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | +0 (0/0) | +0 (0/0) | 0/0 |
| v2-original -> v2-window-44 | -21 (36/57) | 14/5 | -5 (5/10) | 8/4 | -17 (100/117) | +6 (8/2) | 2/3 |
| v2-original -> v3-balanced | -12 (51/63) | 16/6 | -2 (8/10) | 5/2 | +46 (163/117) | +6 (12/6) | 4/3 |
| v2-window-42 -> v2-window-43 | +0 (0/0) | 0/0 | +0 (0/0) | 0/0 | +0 (0/0) | +0 (0/0) | 0/0 |
| v2-window-42 -> v2-window-44 | -21 (36/57) | 14/5 | -5 (5/10) | 8/4 | -17 (100/117) | +6 (8/2) | 2/3 |
| v2-window-42 -> v3-balanced | -12 (51/63) | 16/6 | -2 (8/10) | 5/2 | +46 (163/117) | +6 (12/6) | 4/3 |
| v2-window-43 -> v2-window-44 | -21 (36/57) | 14/5 | -5 (5/10) | 8/4 | -17 (100/117) | +6 (8/2) | 2/3 |
| v2-window-43 -> v3-balanced | -12 (51/63) | 16/6 | -2 (8/10) | 5/2 | +46 (163/117) | +6 (12/6) | 4/3 |
| v2-window-44 -> v3-balanced | +9 (30/21) | 2/5 | +3 (5/2) | 3/1 | +63 (124/61) | +0 (5/5) | 2/3 |
| v3-quality -> v3-quality-original | -66 (0/66) | 1/177 | -7 (0/7) | 20/30 | -8 (151/159) | -22 (1/23) | 1/22 |

Against v1 efficient, v3 efficient changes context320 joint correctness by +3 but context64 by -1; against v1 balanced, v3 balanced changes them by -12 and -2. Against v1 quality, the raw v3 quality candidate changes them by +23 and -1. The higher-capacity family therefore does not improve every fixture or tier. V2 window seeds 42/43 retain ORIGINAL parameters and predictions; other v2 terminals change predictions, with contextual losses and some secondary gains. Paired improvements coexist with regressions and action harms. Repeated cases, unequal training histories and native serving differences prevent independent or causal generation rankings.

The quality joint gain coexists with 17 fewer correct context320 actions (81 improvements and 98 regressions), 106 under-restriction distance worsenings and five over-restriction worsenings against v1 quality. V3-minus-v1 binary correct totals rise by 29/43/34 for efficient/balanced/quality, but sensitive recall falls from 158/169/190 to 113/91/113 correct out of the same 264 positives. Greater specificity compensates for lower recall in those total-correct counts. These secondary gains cannot establish safer contextual decisions.

## CPU cost and process memory

All artifacts ran sequentially in fixed registry order, with three fresh isolated processes each, batch one, concurrency one and one thread for admitted native backend pools. The attested CPU is Intel Core i7-13700KF under Linux/WSL2. The admitted image contains Torch 2.11.0+cu128 executing on CPU for v3 and NumPy 1.26.4 for Tiny; these are CPU results, separate from earlier CUDA fit costs. Tiny/v3 use their native public inference servicers, tokenization, hint postprocessing, windows and NumPy/Torch backends. No training servicer is registered. The exact image and two read-only generated telemetry-module mounts are protocol-pinned; source catalogs remain immutable.

Before outcomes, eight native-length midpoint strata per endpoint selected 32 common-fit inputs within all fourteen windows. Each process made one 32-call warmup pass and ten measured passes (320 calls), using frozen rotations and one persistent host channel. Host full-response `perf_counter_ns` latency is primary; runtime-reported elapsed time remains secondary in the retained records. Errors cannot improve successful latency distributions. Ranges below are across the three process replicates, not confidence intervals or population bounds.

| Snapshot | p50 ms range | p95 ms range | RPC-active successful req/s range | Measured successes | Measured failures |
| --- | --- | --- | --- | --- | --- |
| v1-efficient | 16.810-17.067 | 19.225-20.839 | 61.849-63.280 | 960 | 0 |
| v1-balanced | 26.300-31.188 | 29.904-39.219 | 35.717-43.952 | 960 | 0 |
| v1-quality | 37.754-40.345 | 44.381-48.804 | 27.190-29.101 | 960 | 0 |
| v2-original | 28.153-28.712 | 33.792-38.411 | 37.923-40.384 | 960 | 0 |
| v2-legacy-42 | 29.424-29.959 | 35.657-35.823 | 33.646-34.469 | 960 | 0 |
| v2-legacy-43 | 27.945-29.555 | 33.784-35.310 | 33.662-36.039 | 960 | 0 |
| v2-legacy-44 | 27.890-28.072 | 31.972-37.095 | 34.782-35.177 | 960 | 0 |
| v2-window-42 | 27.048-27.064 | 32.131-35.417 | 41.053-41.658 | 960 | 0 |
| v2-window-43 | 26.919-27.042 | 31.023-40.518 | 40.131-42.244 | 960 | 0 |
| v2-window-44 | 27.659-28.107 | 35.018-36.170 | 35.141-35.452 | 960 | 0 |
| v3-efficient | 4.336-4.468 | 7.804-8.045 | 175.985-186.460 | 960 | 0 |
| v3-balanced | 4.674-4.941 | 10.505-11.277 | 161.666-175.270 | 960 | 0 |
| v3-quality | 10.768-11.213 | 18.463-19.603 | 78.312-83.267 | 960 | 0 |
| v3-quality-original | 10.768-10.887 | 17.512-22.070 | 80.196-80.737 | 960 | 0 |

The throughput proxy divides successful measured requests by total measured RPC time, excluding ledger I/O and loop overhead. It is not sustained end-to-end service throughput or a universal SLA. Startup/readiness includes immutable snapshot preload; the separately measured first RPC is already loaded. Every replicate is shown next. Readiness is seconds; first RPC and latency are milliseconds; memory values are bytes. Loaded RSS is observed after readiness. Peak is PID1 lifetime VmHWM through the measured phase, before the full accuracy loop. Delta is lifetime peak minus loaded RSS and includes startup high water, **not isolated inference allocation**. RSS/HWM include imported runtime and backend overheads and cannot be attributed only to architecture parameters. Float32 parameter bytes and serialized deployment bytes above are different quantities.

| Snapshot | Rep | Ready s | First RPC ms | p50 ms | p95 ms | Loaded RSS B | Lifetime HWM B | HWM minus loaded RSS B | Measured OK/errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v1-efficient | 1 | 5.940 | 22.772 | 16.861 | 19.225 | 70369280 | 73396224 | 3026944 | 320/0 |
| v1-efficient | 2 | 9.780 | 23.881 | 16.810 | 19.754 | 70205440 | 72970240 | 2764800 | 320/0 |
| v1-efficient | 3 | 10.020 | 24.047 | 17.067 | 20.839 | 70213632 | 73052160 | 2838528 | 320/0 |
| v1-balanced | 1 | 5.587 | 34.861 | 31.188 | 39.219 | 73043968 | 77365248 | 4321280 | 320/0 |
| v1-balanced | 2 | 10.795 | 35.138 | 30.552 | 35.362 | 72847360 | 77324288 | 4476928 | 320/0 |
| v1-balanced | 3 | 11.207 | 37.873 | 26.300 | 29.904 | 72953856 | 77398016 | 4444160 | 320/0 |
| v1-quality | 1 | 9.607 | 43.576 | 37.754 | 44.381 | 74477568 | 83243008 | 8765440 | 320/0 |
| v1-quality | 2 | 5.000 | 48.446 | 40.345 | 47.555 | 74608640 | 83099648 | 8491008 | 320/0 |
| v1-quality | 3 | 5.220 | 41.859 | 39.532 | 48.804 | 74268672 | 82354176 | 8085504 | 320/0 |
| v2-original | 1 | 5.118 | 32.880 | 28.712 | 38.411 | 70815744 | 75829248 | 5013504 | 320/0 |
| v2-original | 2 | 5.127 | 33.705 | 28.153 | 33.792 | 70844416 | 75415552 | 4571136 | 320/0 |
| v2-original | 3 | 6.198 | 34.207 | 28.667 | 35.735 | 71307264 | 75665408 | 4358144 | 320/0 |
| v2-legacy-42 | 1 | 6.868 | 35.024 | 29.959 | 35.657 | 72114176 | 76808192 | 4694016 | 320/0 |
| v2-legacy-42 | 2 | 4.956 | 33.697 | 29.424 | 35.659 | 72515584 | 77328384 | 4812800 | 320/0 |
| v2-legacy-42 | 3 | 4.938 | 31.660 | 29.820 | 35.823 | 72613888 | 77402112 | 4788224 | 320/0 |
| v2-legacy-43 | 1 | 5.076 | 32.912 | 29.555 | 35.310 | 72699904 | 77123584 | 4423680 | 320/0 |
| v2-legacy-43 | 2 | 5.296 | 30.946 | 27.978 | 33.784 | 72634368 | 77492224 | 4857856 | 320/0 |
| v2-legacy-43 | 3 | 4.919 | 32.088 | 27.945 | 34.101 | 72691712 | 77352960 | 4661248 | 320/0 |
| v2-legacy-44 | 1 | 4.869 | 29.531 | 27.890 | 33.658 | 72417280 | 77283328 | 4866048 | 320/0 |
| v2-legacy-44 | 2 | 4.598 | 30.861 | 28.004 | 31.972 | 72249344 | 76746752 | 4497408 | 320/0 |
| v2-legacy-44 | 3 | 4.887 | 32.821 | 28.072 | 37.095 | 72462336 | 76935168 | 4472832 | 320/0 |
| v2-window-42 | 1 | 4.594 | 30.742 | 27.064 | 35.417 | 71200768 | 75575296 | 4374528 | 320/0 |
| v2-window-42 | 2 | 5.940 | 40.668 | 27.048 | 32.539 | 70746112 | 75194368 | 4448256 | 320/0 |
| v2-window-42 | 3 | 4.496 | 38.049 | 27.059 | 32.131 | 71581696 | 75935744 | 4354048 | 320/0 |
| v2-window-43 | 1 | 5.440 | 30.494 | 27.042 | 40.518 | 71471104 | 76308480 | 4837376 | 320/0 |
| v2-window-43 | 2 | 4.682 | 30.350 | 26.919 | 31.023 | 71487488 | 76173312 | 4685824 | 320/0 |
| v2-window-43 | 3 | 4.701 | 32.707 | 26.972 | 31.732 | 71073792 | 75620352 | 4546560 | 320/0 |
| v2-window-44 | 1 | 5.039 | 30.435 | 27.659 | 36.047 | 72192000 | 76685312 | 4493312 | 320/0 |
| v2-window-44 | 2 | 4.878 | 29.383 | 27.953 | 36.170 | 72728576 | 77361152 | 4632576 | 320/0 |
| v2-window-44 | 3 | 4.570 | 39.347 | 28.107 | 35.018 | 72876032 | 77484032 | 4608000 | 320/0 |
| v3-efficient | 1 | 43.979 | 427.253 | 4.423 | 7.887 | 791764992 | 803102720 | 11337728 | 320/0 |
| v3-efficient | 2 | 9.387 | 6.419 | 4.468 | 7.804 | 788643840 | 800436224 | 11792384 | 320/0 |
| v3-efficient | 3 | 7.878 | 6.441 | 4.336 | 8.045 | 791961600 | 803602432 | 11640832 | 320/0 |
| v3-balanced | 1 | 9.475 | 7.221 | 4.941 | 11.277 | 812871680 | 825450496 | 12578816 | 320/0 |
| v3-balanced | 2 | 39.508 | 6.607 | 4.674 | 10.505 | 824688640 | 836907008 | 12218368 | 320/0 |
| v3-balanced | 3 | 37.740 | 8.111 | 4.757 | 10.614 | 825253888 | 837869568 | 12615680 | 320/0 |
| v3-quality | 1 | 40.923 | 10.458 | 11.213 | 19.603 | 859684864 | 891940864 | 32256000 | 320/0 |
| v3-quality | 2 | 11.847 | 10.857 | 10.904 | 18.669 | 856813568 | 889004032 | 32190464 | 320/0 |
| v3-quality | 3 | 42.405 | 1963.928 | 10.768 | 18.463 | 862998528 | 894951424 | 31952896 | 320/0 |
| v3-quality-original | 1 | 39.658 | 11.649 | 10.887 | 18.952 | 858570752 | 889913344 | 31342592 | 320/0 |
| v3-quality-original | 2 | 39.010 | 10.075 | 10.839 | 22.070 | 857968640 | 889917440 | 31948800 | 320/0 |
| v3-quality-original | 3 | 40.855 | 10.199 | 10.768 | 17.512 | 860143616 | 890753024 | 30609408 | 320/0 |

Fixed sequential artifact order and three process replicates do not randomize backend effects, host load or time. The shorter v3 successful latencies on this fixed workload coexist with higher runtime memory and mixed accuracy; this comparison does not isolate pretraining, capacity, architecture or backend causation.

Across all three replicates, Tiny lifetime HWM spans 69.590-79.387 MiB and v3 spans 763.355-853.492 MiB (1 MiB = 1,048,576 bytes). These are whole-process observations including imported runtime/native backends, not parameter-storage ratios.

## Method, reproduction and retained evidence

Discovery and the accepted method review are retained under `evaluation/results/v123_comparison_20261013/`. The host runner freezes `protocol/protocol-02.json` there, including byte-pinned artifact/config/vocabulary identities, metadata and initialization/window provenance, all effective source hashes, the exact existing server image, fixture hashes, native input lengths, and deterministic performance prompt selection. Private copied artifacts and independently copied v3 catalogs live under `models/experiments/v123_comparison_20261013/`; source catalogs are never opened writable.

The first protocol (`protocol/protocol.json`, SHA256 `a2c859489cfa5e7f7e26cb4922b1e5597d8254374e24fdd407483c7ae4e458fc`) and `preflight/` failed attempt remain immutable. That attempt stopped before any RPC because the v3 image lacks generated telemetry modules imported by the native Tiny handler. Configuration revision 02 adds read-only mounts of the two unchanged maintained generated modules, with exact byte pins and actual server attestation, without regeneration, image rebuild or old-source changes. Model/fixture/metric/performance policy is unchanged; the new three-generation preflight uses `preflight-02/`.

Every artifact receives the same original text/source/hint/purpose fields on four fixed DEVELOPMENT/support fixtures: context320, context64, binary502 and hazard48. Each has 934 requested and 927 eligible cases, giving 13,076 requested and 12,978 eligible across 14 snapshots. Seven ambiguous hazard cases remain requested. Primary context and secondary binary/hazard metrics stay separate. Allowed actions are sets. Errors count incorrect for applicable metrics even when a failed response says BLOCK; all requested errors are reported. Packed and named classifications must agree.

Every RPC sends explicit semantic layers `[4]` with no presence gate. Every successful response must attest sole actual layer 4 and the full native identity (four Tiny fields, eight v3 fields). Extra/nonsemantic execution or wrong identity invalidates acceptance. A known pre-execution failure may omit execution/identity, remains an explicit failed case, and receives no fabricated attestation. Unfinished request reservations stop resumption rather than trigger a blind duplicate RPC.

This is a native serving-package comparison. Tiny and v3 have different hint postprocessing, native tokenization/windows and NumPy/Torch backends. The runner preserves these differences, records native cap rejection/truncation case IDs, and never trims or normalizes wire input a second time. Results do not establish a causal architecture/pretraining ranking or fresh final generalization.

The common Linux/container CPU lane uses the exact admitted image with offline asset loading, one thread for OMP/MKL/OpenBLAS/NumExpr/BLIS and v3 Torch, batch one and concurrency one. The comparison-only helper loads a pinned Tiny ParameterSnapshot into its existing native cache (TTL 604800 seconds) or initializes the maintained v3 RuntimeServer and preloads its pinned private catalog snapshot. Both use native public inference servicers. No training servicer is registered by the comparison helper. Startup/readiness includes preload; the first RPC is separately recorded and already loaded. Actual CPU/backend/thread/image/source attestations are required.

Before outcomes, 32 common-fit inputs are selected deterministically: eight midpoint rank strata by native input length from each fixed endpoint, within the intersection of all 14 native windows. Each artifact uses three fresh isolated runtime process replicates, one full 32-input warmup pass, then ten measured passes (320 calls), with frozen pass rotation and one persistent host gRPC channel. Host `perf_counter_ns` around receipt of the full response is primary; runtime elapsed time is secondary. Per-replicate p50/p95, their ranges, failed counts and successful requests per total request time are retained. Errors cannot improve the successful latency distribution.

External `/proc/1/status` observations give the same process VmRSS and lifetime VmHWM metric for both families (Linux kB multiplied by 1024 bytes), with PID1 command verification. Loaded baseline is captured after readiness, and performance peak collection ends before the full accuracy loop. Replicate one then performs accuracy once; replicates two/three are cost-only. Lifetime peak minus loaded baseline RSS includes startup high water and is not isolated inference allocation. The throughput measure is explicitly an RPC-active proxy excluding ledger I/O and loop overhead. Absolute peak/delta, raw float32 parameter bytes and serialized deployment asset bytes are separate. These repeated measurements describe this fixed workload, with no universal SLA or population inference.

All tests and dataset/client loops run on host Python (`evaluation/.venv-v3-study/Scripts/python.exe`). Docker hosts only servers in the isolated `privoke-v123-comparison` project on loopback ports 50271/50273. Failed attempts, requests, responses, errors, timing samples and server/resource evidence are immutable. Owned services are stopped after each replicate; no images/volumes or originals are removed.

Implementation/preflight sequence: host contract tests and CLI/compile/source-closure checks; freeze prospective protocol; one fixed non-quality startup probe each for v1 balanced, v2 ORIGINAL, and v3 efficient FULL42; stop services; scoped local commit; root and independent preflight review. The complete 14-artifact benchmark and analysis subsequently passed root and independent raw/numeric acceptance; the tables above report those accepted results. This paragraph preserves the original preflight sequence.

The frozen command sequence is `evaluation/.venv-v3-study/Scripts/python.exe evaluation/run-v123-comparison.py prepare`, then `smoke`, followed after acceptance by `run --model <frozen-name>` for each registry name and `analyze`. These describe the completed immutable run; do not blindly rerun into retained protocol/evidence paths. A reproduction requires separately assigned fresh paths and acceptance without overwriting this study.

### Acceptance, cleanup and limits

The authoritative [analysis](../evaluation/results/v123_comparison_20261013/analysis.json) SHA256 is `6bb52dadc49d87117eea80efee8bff9f0fa704af1ee5004a3fd4d3d5626e9c54`; protocol revision 02 SHA256 is `bb10e93b155ae1bf22cc03a16bd318a7da612b691b0fb4fb2b8042d423e3f0d2`, on implementation commit `343dae1a956bfe5e880e557c3b39db2be60d3890`. The [independent audit](../evaluation/results/v123_comparison_20261013/final-audit/report-01.json), SHA256 `62f5fcee815b309425f7b1f7e0689887e31589a1b175c0fddcadf3a77e2cd1e4`, reconciles all 112,448 inventoried benchmark files, 56 endpoint summaries, 42 cost replicates and 40 paired contrasts without findings. Successful responses attest sole actual semantic layer 4 and pinned native identity; failed responses retain actual failure evidence.

The [corrected execution summary](../evaluation/results/v123_comparison_20261013/execution-evidence/execution-summary-02.json), SHA256 `fd1f0083c57bb36ba06fde042e0f8e285ab84bda293f35cfd9585ce26b54bd45`, records all fourteen model-command exits, accuracy coverage and cleanup. Its predecessor is preserved: a PowerShell dictionary-count reporting error affected three displayed counts, corrected in a new file without changing analysis or raw evidence. The first v1-efficient tee-log parent was absent at launch; it was created during that same live run, whose completion and exit zero were captured without restarting or replaying it.

The [final acceptance supplement](../evaluation/results/v123_comparison_20261013/final-audit/final-acceptance.json), SHA256 `84fe1ad7fd01bbf211b870102b3fd579d82c43dbac3344894e27eef3975937ee`, independently confirms the eleven binary input lengths of 99-295 native tokens including the start token, zero measured failures, cleanup and empty v3 fitting databases. The frozen `workload.windows` enumerates every rejected ID; the supplement ties the same eleven retained runtime failures to each of the seven v2 snapshots.

Accepted cleanup removed the isolated `privoke-v123-comparison` containers and network, leaving zero project containers/networks and ports 50271/50273 released. No volumes, originals or images were deleted. The admitted image `sha256:4a5624eda0c0cd7dfb3da2366e3d18e720eda4a82797bf4e92320fa0987e9bd1`, private model copies, provenance, failed attempts and all immutable evidence remain retained. No task worktree was created; the shared primary checkout and unrelated dirty work were preserved.

This comparison provides complete coverage of the predeclared 14-snapshot inventory, not all possible generation/tier combinations. Other historical training/research checkpoints outside that inventory were not rescored here; prior study history remains unchanged. Missing v2 tiers are unavailable, not zero-performing. Different training histories, guard/effective status, capacities, tokenization, native caps, hint policies and backends confound generation effects. Reused DEVELOPMENT/support cases and dependent comparisons do not establish protected-final generalization, production safety or a promotion decision. No new training, best-seed selection or further experimental study is proposed by this record.

## Follow-up: why v1 balanced appears stronger (V123-D1)

On 13 October 2026, the user asked: “Yeah you can push the commits, but why is V1 balanced so much better than all of the others?” This exploratory decomposition uses the existing frozen predictions; it adds no inference, fitting, checkpoint selection or protected-final evaluation. The [reproducible diagnostic](../evaluation/results/v123_comparison_20261013/diagnostic-v1-balanced/diagnose.py) and [complete subgroup/paired results](../evaluation/results/v123_comparison_20261013/diagnostic-v1-balanced/diagnostic.json) retain the prompt, source/input hashes, category distributions, intersections and case IDs.

V1 balanced does not lead every task. It ties the unchanged balanced v2 controls, while the rejected raw v3 quality export exceeds it on context320 joint correctness (66 versus 63). V3 balanced performs better on several individual components and secondary tasks. Its joint deficit against v1 balanced is 12/320 cases (3.75 percentage points) and 2/64 cases (3.125 points), rather than evidence of a broad superiority of v1.

The main qualification is that these joint scores almost entirely reward clean controls. Joint correctness requires exact sensitivity, the complete category set and visibility, plus an allowed action, all on the same case. For the four snapshots below, **every joint success is a clean control; none is a sensitive disclosure**.

| Snapshot | context320 clean joint /160 | context320 sensitive joint /160 | context64 clean joint /32 | context64 sensitive joint /32 |
| --- | --- | --- | --- | --- |
| v1-balanced | 63 | 0 | 10 | 0 |
| v3-balanced | 51 | 0 | 8 | 0 |
| v1-quality | 43 | 0 | 8 | 0 |
| v3-quality, rejected raw | 66 | 0 | 7 | 0 |

Category prediction blocks sensitive-case joint correctness. On context320, both balanced models get 0/160 sensitive category sets exactly right: v1 balanced predicts an empty category set on 158/160 sensitive cases, and v3 balanced on 160/160. On context64 the corresponding exact counts are 0/32 and 1/32; the one v3 category success has incorrect visibility. This does not mean neither detects sensitivity: for example, v1 quality recognizes sensitive presence on 133/160 context320 disclosures, versus 45/160 for v1 balanced, despite its lower joint total. Detection and complete structured classification measure different capabilities.

The precise balanced-model joint gap comes from **different visibility successes on clean cases**, with no shared joint successes:

| Endpoint | V1-only joint successes | V3-only joint successes | Shared successes | V3 minus v1 |
| --- | --- | --- | --- | --- |
| context320 | 63 | 51 | 0 | -12 |
| context64 | 10 | 8 | 0 | -2 |

All 63 and 10 v1-only successes have `PU` (unspecified) visibility truth. V3 gets sensitivity, categories and action right on those cases but predicts explicit visibility, so visibility alone loses the joint credit. Conversely, all 51 and 8 v3-only successes have explicit visibility truth; v1 predicts `PU`. Among these v3-only successes, v1 also misses sensitivity on four context320 cases and three context64 cases, and action on three cases in each endpoint. V1 balanced returns `PU` on 319/320 and 63/64 cases overall, whereas v3 balanced returns it on 23/320 and 3/64. Clean truth contains `PU` on 93/160 and 20/32 cases, making v1's unspecified-visibility behavior useful for this particular joint metric.

This is an intersection effect, not uniformly better components. On context320, v3 balanced has more correct sensitivity (161 versus 146), visibility (142 versus 120) and actions (177 versus 162), but fewer cases where everything is right together. On context64, it improves sensitivity (57 versus 35), categories (33 versus 30), actions (55 versus 34) and annotation-presence correctness (61 versus 46), while visibility falls from 25 to 21 and joint from 10 to 8. Packed and joint totals are identical here: action is not an additional bottleneck once the classification is exact.

Both primary fixtures omit `visibility_hint` on every row, so all 384 unique input rows produce an empty wire hint. The separate `audience_hint` field in context320 is not forwarded as a protobuf visibility hint. Consequently the known Tiny/v3 difference in explicit hint handling is not an active explanation for these primary results. The diagnostic confirms the returned `PU` versus explicit-visibility pattern; assigning its cause to training, model capacity, pretraining or package postprocessing requires separate source evidence or an intervention.

The method checks all 5,376 contextual prediction records (14 snapshots times 384 rows) against their accepted analysis inventory hashes and independently recomputes clean/sensitive metrics and selected paired contrasts. Every overall component total agrees with the accepted comparison. These remain reused, synthetic/provisional DEVELOPMENT cases with different native serving packages and dependent observations. The findings explain the measured score composition; they establish neither generalization nor a universal winner, and do not change the raw quality export's rejected status or imply promotion.

The [source and training-provenance review](../evaluation/results/v123_comparison_20261013/diagnostic-v1-balanced/source-review.md) confirms that Tiny aggregation preserves explicit visibility and does not generally rewrite it to PU. V1 balanced already had task-trained heads; v3 retained a pretrained language encoder and fitted newly zero-initialized task heads on a different training stream. Head initialization, supervision, category thresholds and readouts differ, so language pretraining alone does not establish stronger privacy classification. Their individual causal contributions remain unmeasured.
