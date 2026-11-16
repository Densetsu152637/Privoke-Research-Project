# Detector uncertainty: paired statistics for old vs new defaults (2026-10-24)

**Scope: detector layers only (regex, NER, and their union = regex OR NER with `regex_first=False`). Not LLM-only or semantic evidence and not a full-product measurement.**

## Goal and instruction

The held-out claims of `detector-precision-installed-20261024.md` rest on net differences of a few rows with no uncertainty. User instruction (24 Oct 2026): "Test all of these in parallel and integrate promising ones", including a one-time authorized re-derivation of per-row results for the two frozen configurations on the held-out final file. This record builds paired-statistics tooling and applies it to old (clean export of `e6c177ff`: original regex rules, lowercased input, no post-filter) versus new (`55cbd1e5` defaults: regex precision repairs, case-preserving detectors, NER post-filter) on dev, dev-TUNE, dev-CHECK, personalized, openai and the held-out final.

## Tooling (reusable)

- `evaluation/evaluate_installed_detectors.py --per-row-dir <dir>`: additionally writes `<label>-<split>.rows.jsonl` (example_id, group_id, stratum, expected_has_pii, and for regex / ner / union: positive flag, maximum sensitivity, category names, runtime action). Layer actions are `pipeline.strongest_result(layer.results)[1]` (the runtime's own aggregation over `ClassificationResult.action()`); the union action is `PipelineAnalysis.action`. No policy is reimplemented. Aggregate output is unchanged. For `final` the per-row file holds only unsalted sha256 prefixes of ids, no text.
- `evaluation/detector_stats.py`: seeded grouped paired percentile bootstrap (10 000 replicates, seed 20261024, whole clusters resampled, baseline and candidate share each replicate), exact McNemar on correctness (separately for positives and negatives, plus mid-p), per-row flip counts, a cluster-level exact sign test, cost-weighted error. Unit tests: `evaluation/tests/test_detector_stats.py`, `evaluation/tests/test_installed_detector_rows.py`.
- `evaluation/detector_uncertainty_report.py`: applies the above to the per-row files, checks them against the recorded aggregates, and writes `detector-uncertainty-20261024.json` (beside this file; every metric, CI, flip count and test for every split x layer x rule).

Definitions. Deltas are new minus old. Recall, specificity, precision, F2 (beta 2). Cost = (k x FN + FP) / n per row for FN:FP ratios k = 2, 4, 9. Rules: **positive** = benchmark definition (any hit with sensitivity != S0 or categories); **WARN-or-BLOCK** and **BLOCK only** = runtime action as the positive prediction (WARN-or-BLOCK flags a row; BLOCK-only flags it only when the policy blocks). Actions are defined for each layer set (regex, NER and the union cascade); a layer-level action is the policy applied to that layer's results alone. The action rules are not the same construct as the `positive` rule: S1-only findings and low-confidence findings are `positive` but `ALLOW` (for example 34 of 264 dev positives under the new union), so action-level recall is structurally lower and BLOCK-only treats every WARN as a miss.

Clustering. Dev and the held-out final cluster by `group_id` (source document; 465 clusters over 502 dev rows, 464 over 498 final rows, so close to row-level). The synthetic sets carry no template or document id: the primary analysis is a plain row bootstrap, which is likely anti-conservative for template-generated text. A sensitivity analysis clusters by the dataset's `scenario` label (20 clusters personalized, 10 openai), which is conservative. Exact McNemar assumes independent rows; the cluster sign test (per-cluster net flips) is reported as a check.

## Method and provenance

- Same host Python environment, same explicit layer list `["regex", "ner"]`, `regex_first=False` as the earlier record; no semantic layer, no Docker, no downloads.
- old tree: clean export of `e6c177ff` (not a git checkout; flags absent). new tree: worktree at `55cbd1e57f0bbc111060c64a7a368069f49e1061`, observed flags both `true`. The earlier record used `89c358fd` for new; the aggregates re-derived here from per-row data equal the recorded ones exactly (below).
- Dataset sha256: development `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`; personalized `fd045ac1bd77fa278ad207a1bc1208f71fced017b9ab4fc174a2074f7d8f1281`; openai `8e8e611b9d40f7d554726d577449585faefb9aec97f5dd4ffb051af1a6da2c3b`; final `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515` (all equal to the recorded values).
- Per-row JSONL (not committed, gitignored): `evaluation/results/detector_uncertainty_20261024/{old,new}-<split>.rows.jsonl`; the console aggregates are in `agg/` and `final-agg/` there.
- Reproduce: `python evaluation/evaluate_installed_detectors.py --tree <root> --label <old|new> --data-root <checkout with datasets> --generated <protobuf dir> --out <dir> --per-row-dir <dir> dev personalized openai` (add `--allow-final-once final` with a fresh `--out` for the final), then `python evaluation/detector_uncertainty_report.py --rows <dir> --recorded docs/experiments/detector-precision-installed-20261024.json --out <json> --splits dev personalized openai final`.

## Held-out final: second authorized use

The user authorized exactly one re-derivation of per-row results for the same two frozen configurations on `final.jsonl`. It was run once per configuration into a new output directory (`final-agg/`), statistics only; no row text was printed or inspected, no code or rule was changed afterwards. Difference to the earlier one-shot note: this run stored per-row outcomes (hashed id and group_id, no text) in the gitignored results directory so that pairing is possible. The final file is therefore now used twice for the same frozen pair; treat it as consumed.

**Reproduction check: all re-derived counts equal the recorded aggregates.** For old and new, on dev (all, TUNE, CHECK), personalized, openai and final, n, positives and TP/TN/FP/FN for regex, NER and union derived from the per-row files equal `detector-precision-installed-20261024.json`; the dataset hashes also match. No mismatch.

## Results

`*` = the bootstrap 95% CI of the difference excludes zero. "p" columns are two-sided exact McNemar p-values on the discordant rows (positives and negatives separately); "group sign p" is the cluster-level exact sign test. "FN>TP / TP>FN" counts rows whose correctness changed in the new run's favor / against it (similarly FP>TN / TN>FP). No multiplicity correction is applied: with this many cells, an isolated p near 0.05 should not be taken as evidence. Rule of thumb: with only one-sided flips, 6 or more are needed for exact p < 0.05 (5 give 0.0625).

### A. Detector definition (rule: positive)

#### Regex only: estimates with 95% CI (rule: positive (any finding))

| Split | n (pos) | Config | Recall | Specificity | Precision | F2 |
|---|---|---|---|---|---|---|
| dev | 502 (264) | old | 0.652 [0.594, 0.708] | 0.971 [0.947, 0.991] | 0.961 [0.929, 0.988] | 0.696 [0.643, 0.747] |
| dev | 502 (264) | new | 0.640 [0.582, 0.696] | 0.983 [0.965, 0.996] | 0.977 [0.952, 0.995] | 0.688 [0.633, 0.738] |
| dev-TUNE | 267 (148) | old | 0.649 [0.571, 0.724] | 0.966 [0.931, 0.992] | 0.960 [0.918, 0.991] | 0.694 [0.620, 0.762] |
| dev-TUNE | 267 (148) | new | 0.642 [0.564, 0.718] | 0.983 [0.957, 1.000] | 0.979 [0.947, 1.000] | 0.689 [0.616, 0.758] |
| dev-CHECK | 235 (116) | old | 0.655 [0.569, 0.739] | 0.975 [0.944, 1.000] | 0.962 [0.914, 1.000] | 0.700 [0.619, 0.775] |
| dev-CHECK | 235 (116) | new | 0.638 [0.550, 0.723] | 0.983 [0.958, 1.000] | 0.974 [0.932, 1.000] | 0.685 [0.602, 0.763] |
| personalized | 2000 (1000) | old | 1.000 [1.000, 1.000] | 0.977 [0.967, 0.986] | 0.978 [0.968, 0.986] | 0.995 [0.993, 0.997] |
| personalized | 2000 (1000) | new | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| openai | 1000 (500) | old | 0.920 [0.896, 0.943] | 0.692 [0.651, 0.732] | 0.749 [0.714, 0.783] | 0.880 [0.858, 0.900] |
| openai | 1000 (500) | new | 0.896 [0.868, 0.922] | 0.932 [0.909, 0.953] | 0.929 [0.906, 0.951] | 0.902 [0.879, 0.924] |
| **held-out final** | 498 (236) | old | 0.653 [0.590, 0.712] | 0.985 [0.968, 0.996] | 0.975 [0.947, 0.994] | 0.699 [0.640, 0.753] |
| **held-out final** | 498 (236) | new | 0.640 [0.576, 0.701] | 0.996 [0.988, 1.000] | 0.993 [0.978, 1.000] | 0.689 [0.629, 0.745] |

#### Regex only: paired differences, new minus old (rule: positive (any finding))

| Split | dRecall [CI] | dSpecificity [CI] | dPrecision [CI] | dF2 [CI] | FN>TP / TP>FN | exact McNemar p (pos) | FP>TN / TN>FP | exact McNemar p (neg) | group sign p (pos / neg) |
|---|---|---|---|---|---|---|---|---|---|
| dev | -0.011 [-0.026, 0.000] | 0.013 [0.000, 0.029] | 0.016 [-0.000, 0.037] | -0.009 [-0.022, 0.002] | 0 / 3 | 0.250 | 3 / 0 | 0.250 | 0.250 / 0.250 |
| dev-TUNE | -0.007 [-0.021, 0.000] | 0.017 [0.000, 0.043] | 0.019 [-0.000, 0.051] | -0.004 [-0.018, 0.004] | 0 / 1 | 1.000 | 2 / 0 | 0.500 | 1.000 / 0.500 |
| dev-CHECK | -0.017 [-0.044, 0.000] | 0.008 [0.000, 0.028] | 0.012 [-0.002, 0.041] | -0.015 [-0.040, 0.003] | 0 / 2 | 0.500 | 1 / 0 | 1.000 | 0.500 / 1.000 |
| personalized | 0.000 [0.000, 0.000] | 0.023 [0.014, 0.033] \* | 0.022 [0.014, 0.032] \* | 0.005 [0.003, 0.007] \* | 0 / 0 | 1.000 | 23 / 0 | <0.001 | 1.000 / <0.001 |
| openai | -0.024 [-0.038, -0.012] \* | 0.240 [0.202, 0.279] \* | 0.180 [0.151, 0.211] \* | 0.023 [0.009, 0.036] \* | 0 / 12 | <0.001 | 121 / 1 | <0.001 | <0.001 / <0.001 |
| **held-out final** | -0.013 [-0.029, 0.000] | 0.011 [0.000, 0.026] | 0.019 [-0.000, 0.043] | -0.010 [-0.025, 0.002] | 0 / 3 | 0.250 | 3 / 0 | 0.250 | 0.250 / 0.250 |

#### NER only: estimates with 95% CI (rule: positive (any finding))

| Split | n (pos) | Config | Recall | Specificity | Precision | F2 |
|---|---|---|---|---|---|---|
| dev | 502 (264) | old | 0.208 [0.160, 0.258] | 0.975 [0.953, 0.992] | 0.902 [0.821, 0.970] | 0.246 [0.192, 0.302] |
| dev | 502 (264) | new | 0.246 [0.195, 0.301] | 0.966 [0.942, 0.987] | 0.890 [0.812, 0.957] | 0.288 [0.231, 0.347] |
| dev-TUNE | 267 (148) | old | 0.236 [0.169, 0.307] | 0.983 [0.957, 1.000] | 0.946 [0.861, 1.000] | 0.278 [0.202, 0.355] |
| dev-TUNE | 267 (148) | new | 0.277 [0.205, 0.350] | 0.966 [0.931, 0.992] | 0.911 [0.818, 0.980] | 0.322 [0.242, 0.399] |
| dev-CHECK | 235 (116) | old | 0.172 [0.106, 0.244] | 0.966 [0.931, 0.992] | 0.833 [0.667, 0.964] | 0.205 [0.128, 0.285] |
| dev-CHECK | 235 (116) | new | 0.207 [0.135, 0.284] | 0.966 [0.932, 0.992] | 0.857 [0.714, 0.969] | 0.244 [0.162, 0.329] |
| personalized | 2000 (1000) | old | 0.800 [0.775, 0.824] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.833 [0.811, 0.854] |
| personalized | 2000 (1000) | new | 0.695 [0.666, 0.724] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.740 [0.714, 0.766] |
| openai | 1000 (500) | old | 0.290 [0.250, 0.330] | 0.984 [0.972, 0.994] | 0.948 [0.910, 0.981] | 0.337 [0.293, 0.380] |
| openai | 1000 (500) | new | 0.170 [0.138, 0.204] | 0.994 [0.986, 1.000] | 0.966 [0.922, 1.000] | 0.204 [0.167, 0.242] |
| **held-out final** | 498 (236) | old | 0.237 [0.183, 0.292] | 0.973 [0.952, 0.992] | 0.889 [0.804, 0.961] | 0.278 [0.217, 0.338] |
| **held-out final** | 498 (236) | new | 0.212 [0.161, 0.267] | 0.966 [0.942, 0.985] | 0.847 [0.750, 0.934] | 0.249 [0.191, 0.310] |

#### NER only: paired differences, new minus old (rule: positive (any finding))

| Split | dRecall [CI] | dSpecificity [CI] | dPrecision [CI] | dF2 [CI] | FN>TP / TP>FN | exact McNemar p (pos) | FP>TN / TN>FP | exact McNemar p (neg) | group sign p (pos / neg) |
|---|---|---|---|---|---|---|---|---|---|
| dev | 0.038 [-0.011, 0.087] | -0.008 [-0.037, 0.020] | -0.011 [-0.104, 0.083] | 0.042 [-0.012, 0.097] | 26 / 16 | 0.164 | 5 / 7 | 0.774 | 0.164 / 0.774 |
| dev-TUNE | 0.041 [-0.027, 0.108] | -0.017 [-0.058, 0.024] | -0.035 [-0.146, 0.075] | 0.044 [-0.031, 0.118] | 16 / 10 | 0.327 | 2 / 4 | 0.688 | 0.327 / 0.688 |
| dev-CHECK | 0.034 [-0.033, 0.103] | 0.000 [-0.041, 0.041] | 0.024 [-0.144, 0.196] | 0.039 [-0.037, 0.117] | 10 / 6 | 0.454 | 3 / 3 | 1.000 | 0.454 / 1.000 |
| personalized | -0.105 [-0.132, -0.078] \* | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | -0.093 [-0.118, -0.069] \* | 52 / 157 | <0.001 | 0 / 0 | 1.000 | <0.001 / 1.000 |
| openai | -0.120 [-0.154, -0.086] \* | 0.010 [0.000, 0.021] | 0.018 [-0.022, 0.058] | -0.133 [-0.170, -0.096] \* | 11 / 71 | <0.001 | 6 / 1 | 0.125 | <0.001 / 0.125 |
| **held-out final** | -0.025 [-0.084, 0.036] | -0.008 [-0.031, 0.015] | -0.041 [-0.137, 0.052] | -0.029 [-0.094, 0.039] | 23 / 29 | 0.488 | 4 / 6 | 0.754 | 0.488 / 0.754 |

#### Union (regex OR NER): estimates with 95% CI (rule: positive (any finding))

| Split | n (pos) | Config | Recall | Specificity | Precision | F2 |
|---|---|---|---|---|---|---|
| dev | 502 (264) | old | 0.731 [0.678, 0.783] | 0.945 [0.915, 0.972] | 0.937 [0.902, 0.968] | 0.765 [0.717, 0.810] |
| dev | 502 (264) | new | 0.761 [0.709, 0.812] | 0.950 [0.918, 0.977] | 0.944 [0.908, 0.974] | 0.792 [0.746, 0.836] |
| dev-TUNE | 267 (148) | old | 0.764 [0.694, 0.831] | 0.950 [0.907, 0.984] | 0.950 [0.907, 0.984] | 0.795 [0.732, 0.853] |
| dev-TUNE | 267 (148) | new | 0.797 [0.731, 0.860] | 0.950 [0.908, 0.984] | 0.952 [0.911, 0.985] | 0.824 [0.766, 0.878] |
| dev-CHECK | 235 (116) | old | 0.690 [0.605, 0.770] | 0.941 [0.898, 0.981] | 0.920 [0.857, 0.973] | 0.726 [0.648, 0.798] |
| dev-CHECK | 235 (116) | new | 0.716 [0.632, 0.795] | 0.950 [0.902, 0.991] | 0.933 [0.866, 0.988] | 0.750 [0.675, 0.820] |
| personalized | 2000 (1000) | old | 1.000 [1.000, 1.000] | 0.977 [0.967, 0.986] | 0.978 [0.968, 0.986] | 0.995 [0.993, 0.997] |
| personalized | 2000 (1000) | new | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |
| openai | 1000 (500) | old | 0.942 [0.921, 0.962] | 0.686 [0.645, 0.726] | 0.750 [0.716, 0.783] | 0.896 [0.877, 0.914] |
| openai | 1000 (500) | new | 0.918 [0.894, 0.941] | 0.926 [0.902, 0.948] | 0.925 [0.902, 0.947] | 0.919 [0.899, 0.939] |
| **held-out final** | 498 (236) | old | 0.767 [0.712, 0.819] | 0.958 [0.932, 0.981] | 0.943 [0.908, 0.973] | 0.797 [0.748, 0.841] |
| **held-out final** | 498 (236) | new | 0.763 [0.707, 0.816] | 0.962 [0.937, 0.984] | 0.947 [0.913, 0.977] | 0.794 [0.744, 0.840] |

#### Union (regex OR NER): paired differences, new minus old (rule: positive (any finding))

| Split | dRecall [CI] | dSpecificity [CI] | dPrecision [CI] | dF2 [CI] | FN>TP / TP>FN | exact McNemar p (pos) | FP>TN / TN>FP | exact McNemar p (neg) | group sign p (pos / neg) |
|---|---|---|---|---|---|---|---|---|---|
| dev | 0.030 [0.004, 0.061] \* | 0.004 [-0.025, 0.034] | 0.007 [-0.025, 0.039] | 0.027 [0.002, 0.054] \* | 12 / 4 | 0.077 | 8 / 7 | 1.000 | 0.077 / 1.000 |
| dev-TUNE | 0.034 [-0.007, 0.079] | 0.000 [-0.041, 0.042] | 0.002 [-0.036, 0.041] | 0.029 [-0.008, 0.069] | 8 / 3 | 0.227 | 4 / 4 | 1.000 | 0.227 / 1.000 |
| dev-CHECK | 0.026 [-0.009, 0.067] | 0.008 [-0.034, 0.052] | 0.013 [-0.041, 0.069] | 0.024 [-0.008, 0.061] | 4 / 1 | 0.375 | 4 / 3 | 1.000 | 0.375 / 1.000 |
| personalized | 0.000 [0.000, 0.000] | 0.023 [0.014, 0.033] \* | 0.022 [0.014, 0.032] \* | 0.005 [0.003, 0.007] \* | 0 / 0 | 1.000 | 23 / 0 | <0.001 | 1.000 / <0.001 |
| openai | -0.024 [-0.039, -0.010] \* | 0.240 [0.202, 0.278] \* | 0.175 [0.146, 0.205] \* | 0.023 [0.009, 0.037] \* | 1 / 13 | 0.002 | 121 / 1 | <0.001 | 0.002 / <0.001 |
| **held-out final** | -0.004 [-0.047, 0.039] | 0.004 [-0.023, 0.031] | 0.005 [-0.030, 0.039] | -0.003 [-0.040, 0.035] | 13 / 14 | 1.000 | 7 / 6 | 1.000 | 1.000 / 1.000 |

Interpretation notes for table A. When every discordant row moves in one direction (for example regex dev, 0 / 3), the percentile CI has an endpoint at exactly 0.000 and is reported as not excluding zero; the exact test (p = 0.25 for 3 vs 0) is the better guide at such counts. The bootstrap percentile interval is also optimistic when only a handful of rows change (dev union recall: CI excludes zero, yet exact McNemar p = 0.077 and the cluster sign test p = 0.077). Both are shown so a reader can see the gap.

### B. Action level (rules: WARN-or-BLOCK and BLOCK only)

Union (the regex + NER cascade; action = `PipelineAnalysis.action`):

#### Union (regex OR NER), rule WARN-or-BLOCK

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.625 [0.567, 0.683] | 0.975 [0.953, 0.992] | 0.672 [0.617, 0.726] |  | | | |  |
| dev | new | 0.636 [0.578, 0.693] | 0.954 [0.923, 0.980] | 0.680 [0.626, 0.733] | 0.011 [-0.018, 0.040] | -0.021 [-0.043, 0.000] | 0.008 [-0.019, 0.035] | 9 / 6 (0.607) | 2 / 7 (0.180) |
| dev-TUNE | old | 0.655 [0.578, 0.732] | 0.983 [0.957, 1.000] | 0.702 [0.629, 0.771] |  | | | |  |
| dev-TUNE | new | 0.662 [0.587, 0.739] | 0.958 [0.918, 0.991] | 0.705 [0.635, 0.774] | 0.007 [-0.038, 0.051] | -0.025 [-0.057, 0.000] | 0.003 [-0.038, 0.044] | 6 / 5 (1.000) | 1 / 4 (0.375) |
| dev-CHECK | old | 0.586 [0.496, 0.673] | 0.966 [0.931, 0.992] | 0.634 [0.547, 0.714] |  | | | |  |
| dev-CHECK | new | 0.603 [0.514, 0.690] | 0.950 [0.902, 0.991] | 0.648 [0.562, 0.728] | 0.017 [-0.016, 0.053] | -0.017 [-0.050, 0.016] | 0.014 [-0.017, 0.048] | 3 / 1 (0.625) | 1 / 3 (0.625) |
| personalized | old | 1.000 [1.000, 1.000] | 0.977 [0.967, 0.986] | 0.995 [0.993, 0.997] |  | | | |  |
| personalized | new | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.023 [0.014, 0.033] \* | 0.005 [0.003, 0.007] \* | 0 / 0 (1.000) | 23 / 0 (<0.001) |
| openai | old | 0.912 [0.887, 0.936] | 0.800 [0.764, 0.835] | 0.892 [0.871, 0.913] |  | | | |  |
| openai | new | 0.900 [0.874, 0.925] | 0.932 [0.909, 0.953] | 0.906 [0.884, 0.927] | -0.012 [-0.024, -0.002] \* | 0.132 [0.102, 0.163] \* | 0.014 [0.003, 0.024] \* | 1 / 7 (0.070) | 67 / 1 (<0.001) |
| **held-out final** | old | 0.606 [0.544, 0.668] | 0.977 [0.957, 0.993] | 0.654 [0.595, 0.712] |  | | | |  |
| **held-out final** | new | 0.602 [0.541, 0.663] | 0.973 [0.952, 0.992] | 0.650 [0.592, 0.706] | -0.004 [-0.049, 0.040] | -0.004 [-0.029, 0.021] | -0.005 [-0.046, 0.037] | 14 / 15 (1.000) | 5 / 6 (1.000) |

#### Union (regex OR NER), rule BLOCK only

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.398 [0.341, 0.456] | 0.996 [0.986, 1.000] | 0.452 [0.392, 0.511] |  | | | |  |
| dev | new | 0.383 [0.326, 0.440] | 0.996 [0.986, 1.000] | 0.436 [0.376, 0.494] | -0.015 [-0.031, -0.004] \* | 0.000 [0.000, 0.000] | -0.016 [-0.032, -0.004] \* | 0 / 4 (0.125) | 0 / 0 (1.000) |
| dev-TUNE | old | 0.351 [0.275, 0.430] | 0.992 [0.972, 1.000] | 0.403 [0.321, 0.485] |  | | | |  |
| dev-TUNE | new | 0.345 [0.269, 0.422] | 0.992 [0.972, 1.000] | 0.396 [0.315, 0.477] | -0.007 [-0.021, 0.000] | 0.000 [0.000, 0.000] | -0.007 [-0.023, 0.000] | 0 / 1 (1.000) | 0 / 0 (1.000) |
| dev-CHECK | old | 0.457 [0.364, 0.545] | 1.000 [1.000, 1.000] | 0.513 [0.418, 0.599] |  | | | |  |
| dev-CHECK | new | 0.431 [0.341, 0.518] | 1.000 [1.000, 1.000] | 0.486 [0.393, 0.573] | -0.026 [-0.059, 0.000] | 0.000 [0.000, 0.000] | -0.026 [-0.060, 0.000] | 0 / 3 (0.250) | 0 / 0 (1.000) |
| personalized | old | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |  | | | |  |
| personalized | new | 0.928 [0.912, 0.943] | 1.000 [1.000, 1.000] | 0.942 [0.928, 0.954] | -0.072 [-0.088, -0.057] \* | 0.000 [0.000, 0.000] | -0.058 [-0.072, -0.046] \* | 0 / 72 (<0.001) | 0 / 0 (1.000) |
| openai | old | 0.754 [0.715, 0.792] | 0.930 [0.907, 0.952] | 0.782 [0.747, 0.815] |  | | | |  |
| openai | new | 0.746 [0.706, 0.784] | 0.940 [0.918, 0.960] | 0.776 [0.741, 0.810] | -0.008 [-0.017, -0.002] \* | 0.010 [0.002, 0.019] \* | -0.005 [-0.013, 0.001] | 0 / 4 (0.125) | 5 / 0 (0.062) |
| **held-out final** | old | 0.398 [0.336, 0.462] | 0.992 [0.981, 1.000] | 0.452 [0.387, 0.517] |  | | | |  |
| **held-out final** | new | 0.386 [0.324, 0.450] | 1.000 [1.000, 1.000] | 0.440 [0.375, 0.505] | -0.013 [-0.029, 0.000] | 0.008 [0.000, 0.019] | -0.012 [-0.029, 0.001] | 0 / 3 (0.250) | 2 / 0 (0.500) |

Regex layer alone (action of the regex results):

#### Regex only, rule WARN-or-BLOCK

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.538 [0.479, 0.597] | 0.979 [0.959, 0.996] | 0.590 [0.533, 0.647] |  | | | |  |
| dev | new | 0.523 [0.464, 0.583] | 0.987 [0.971, 1.000] | 0.576 [0.519, 0.634] | -0.015 [-0.031, -0.004] \* | 0.008 [0.000, 0.022] | -0.014 [-0.030, -0.002] \* | 0 / 4 (0.125) | 2 / 0 (0.500) |
| dev-TUNE | old | 0.534 [0.455, 0.613] | 0.983 [0.957, 1.000] | 0.587 [0.509, 0.662] |  | | | |  |
| dev-TUNE | new | 0.527 [0.448, 0.607] | 0.992 [0.972, 1.000] | 0.581 [0.502, 0.657] | -0.007 [-0.021, 0.000] | 0.008 [0.000, 0.027] | -0.006 [-0.020, 0.002] | 0 / 1 (1.000) | 1 / 0 (1.000) |
| dev-CHECK | old | 0.543 [0.450, 0.631] | 0.975 [0.944, 1.000] | 0.594 [0.503, 0.677] |  | | | |  |
| dev-CHECK | new | 0.517 [0.426, 0.604] | 0.983 [0.958, 1.000] | 0.570 [0.480, 0.653] | -0.026 [-0.058, 0.000] | 0.008 [0.000, 0.028] | -0.024 [-0.055, 0.001] | 0 / 3 (0.250) | 1 / 0 (1.000) |
| personalized | old | 1.000 [1.000, 1.000] | 0.977 [0.967, 0.986] | 0.995 [0.993, 0.997] |  | | | |  |
| personalized | new | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.023 [0.014, 0.033] \* | 0.005 [0.003, 0.007] \* | 0 / 0 (1.000) | 23 / 0 (<0.001) |
| openai | old | 0.896 [0.869, 0.922] | 0.810 [0.775, 0.844] | 0.881 [0.858, 0.903] |  | | | |  |
| openai | new | 0.878 [0.849, 0.906] | 0.932 [0.909, 0.953] | 0.888 [0.863, 0.911] | -0.018 [-0.030, -0.008] \* | 0.122 [0.093, 0.152] \* | 0.007 [-0.005, 0.018] | 0 / 9 (0.004) | 62 / 1 (<0.001) |
| **held-out final** | old | 0.508 [0.446, 0.571] | 0.989 [0.974, 1.000] | 0.562 [0.500, 0.623] |  | | | |  |
| **held-out final** | new | 0.496 [0.433, 0.559] | 1.000 [1.000, 1.000] | 0.551 [0.488, 0.614] | -0.013 [-0.029, 0.000] | 0.011 [0.000, 0.026] | -0.011 [-0.027, 0.002] | 0 / 3 (0.250) | 3 / 0 (0.250) |

#### Regex only, rule BLOCK only

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.398 [0.341, 0.456] | 0.996 [0.986, 1.000] | 0.452 [0.392, 0.511] |  | | | |  |
| dev | new | 0.383 [0.326, 0.440] | 0.996 [0.986, 1.000] | 0.436 [0.376, 0.494] | -0.015 [-0.031, -0.004] \* | 0.000 [0.000, 0.000] | -0.016 [-0.032, -0.004] \* | 0 / 4 (0.125) | 0 / 0 (1.000) |
| dev-TUNE | old | 0.351 [0.275, 0.430] | 0.992 [0.972, 1.000] | 0.403 [0.321, 0.485] |  | | | |  |
| dev-TUNE | new | 0.345 [0.269, 0.422] | 0.992 [0.972, 1.000] | 0.396 [0.315, 0.477] | -0.007 [-0.021, 0.000] | 0.000 [0.000, 0.000] | -0.007 [-0.023, 0.000] | 0 / 1 (1.000) | 0 / 0 (1.000) |
| dev-CHECK | old | 0.457 [0.364, 0.545] | 1.000 [1.000, 1.000] | 0.513 [0.418, 0.599] |  | | | |  |
| dev-CHECK | new | 0.431 [0.341, 0.518] | 1.000 [1.000, 1.000] | 0.486 [0.393, 0.573] | -0.026 [-0.059, 0.000] | 0.000 [0.000, 0.000] | -0.026 [-0.060, 0.000] | 0 / 3 (0.250) | 0 / 0 (1.000) |
| personalized | old | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] |  | | | |  |
| personalized | new | 0.928 [0.912, 0.943] | 1.000 [1.000, 1.000] | 0.942 [0.928, 0.954] | -0.072 [-0.088, -0.057] \* | 0.000 [0.000, 0.000] | -0.058 [-0.072, -0.046] \* | 0 / 72 (<0.001) | 0 / 0 (1.000) |
| openai | old | 0.754 [0.715, 0.792] | 0.930 [0.907, 0.952] | 0.782 [0.747, 0.815] |  | | | |  |
| openai | new | 0.746 [0.706, 0.784] | 0.940 [0.918, 0.960] | 0.776 [0.741, 0.810] | -0.008 [-0.017, -0.002] \* | 0.010 [0.002, 0.019] \* | -0.005 [-0.013, 0.001] | 0 / 4 (0.125) | 5 / 0 (0.062) |
| **held-out final** | old | 0.398 [0.336, 0.462] | 0.992 [0.981, 1.000] | 0.452 [0.387, 0.517] |  | | | |  |
| **held-out final** | new | 0.386 [0.324, 0.450] | 1.000 [1.000, 1.000] | 0.440 [0.375, 0.505] | -0.013 [-0.029, 0.000] | 0.008 [0.000, 0.019] | -0.012 [-0.029, 0.001] | 0 / 3 (0.250) | 2 / 0 (0.500) |

NER layer alone (action of the NER results):

#### NER only, rule WARN-or-BLOCK

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.170 [0.126, 0.217] | 0.996 [0.986, 1.000] | 0.204 [0.152, 0.257] |  | | | |  |
| dev | new | 0.205 [0.157, 0.255] | 0.966 [0.942, 0.987] | 0.242 [0.188, 0.298] | 0.034 [-0.008, 0.077] | -0.029 [-0.052, -0.009] \* | 0.037 [-0.010, 0.085] | 20 / 11 (0.150) | 0 / 7 (0.016) |
| dev-TUNE | old | 0.196 [0.134, 0.262] | 1.000 [1.000, 1.000] | 0.233 [0.162, 0.308] |  | | | |  |
| dev-TUNE | new | 0.216 [0.150, 0.287] | 0.966 [0.931, 0.992] | 0.255 [0.179, 0.332] | 0.020 [-0.041, 0.082] | -0.034 [-0.069, -0.008] \* | 0.021 [-0.048, 0.090] | 12 / 9 (0.664) | 0 / 4 (0.125) |
| dev-CHECK | old | 0.138 [0.079, 0.203] | 0.992 [0.972, 1.000] | 0.166 [0.096, 0.241] |  | | | |  |
| dev-CHECK | new | 0.190 [0.120, 0.264] | 0.966 [0.932, 0.992] | 0.224 [0.145, 0.307] | 0.052 [0.000, 0.106] | -0.025 [-0.056, 0.000] | 0.058 [-0.001, 0.119] | 8 / 2 (0.109) | 0 / 3 (0.250) |
| personalized | old | 0.704 [0.675, 0.732] | 1.000 [1.000, 1.000] | 0.748 [0.722, 0.774] |  | | | |  |
| personalized | new | 0.695 [0.666, 0.724] | 1.000 [1.000, 1.000] | 0.740 [0.714, 0.766] | -0.009 [-0.033, 0.015] | 0.000 [0.000, 0.000] | -0.008 [-0.030, 0.014] | 73 / 82 (0.521) | 0 / 0 (1.000) |
| openai | old | 0.250 [0.213, 0.288] | 0.984 [0.972, 0.994] | 0.293 [0.251, 0.335] |  | | | |  |
| openai | new | 0.156 [0.125, 0.189] | 1.000 [1.000, 1.000] | 0.188 [0.151, 0.225] | -0.094 [-0.124, -0.065] \* | 0.016 [0.006, 0.028] \* | -0.105 [-0.139, -0.073] \* | 7 / 54 (<0.001) | 8 / 0 (0.008) |
| **held-out final** | old | 0.169 [0.121, 0.220] | 0.989 [0.974, 1.000] | 0.203 [0.147, 0.260] |  | | | |  |
| **held-out final** | new | 0.169 [0.123, 0.220] | 0.973 [0.952, 0.992] | 0.202 [0.148, 0.259] | 0.000 [-0.055, 0.055] | -0.015 [-0.037, 0.004] | -0.001 [-0.063, 0.062] | 21 / 21 (1.000) | 2 / 6 (0.289) |

#### NER only, rule BLOCK only

| Split | Config | Recall | Specificity | F2 | dRecall [CI] | dSpecificity [CI] | dF2 [CI] | FN>TP / TP>FN (p) | FP>TN / TN>FP (p) |
|---|---|---|---|---|---|---|---|---|---|
| dev | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| dev | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |
| dev-TUNE | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| dev-TUNE | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |
| dev-CHECK | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| dev-CHECK | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |
| personalized | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| personalized | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |
| openai | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| openai | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |
| **held-out final** | old | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] |  | | | |  |
| **held-out final** | new | 0.000 [0.000, 0.000] | 1.000 [1.000, 1.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0 / 0 (1.000) | 0 / 0 (1.000) |

Where actions change (union):

#### Union action transitions old to new (rows whose action changed; label = has PII)

| Split | label | BLOCK>WARN | BLOCK>ALLOW | WARN>BLOCK | WARN>ALLOW | ALLOW>WARN | ALLOW>BLOCK |
|---|---|---|---|---|---|---|---|
| dev | positive | 3 | 1 | 0 | 5 | 9 | 0 |
| dev | negative | 0 | 0 | 0 | 2 | 7 | 0 |
| personalized | positive | 72 | 0 | 0 | 0 | 0 | 0 |
| personalized | negative | 0 | 0 | 0 | 23 | 0 | 0 |
| openai | positive | 3 | 1 | 0 | 6 | 1 | 0 |
| openai | negative | 0 | 5 | 0 | 62 | 1 | 0 |
| **held-out final** | positive | 1 | 2 | 0 | 13 | 14 | 0 |
| **held-out final** | negative | 0 | 2 | 0 | 3 | 6 | 0 |

Not an error-rate effect but an action effect: all 72 personalized positives that move BLOCK to WARN lose a regex `CHILD` category (the regex layer returns S3 CHILD+IDENTITY in old, S2 IDENTITY in new), so the union action drops from BLOCK to WARN while the row stays flagged. Under the `positive` rule this is invisible (recall 1.000 both). It is the largest single action-level change in the data and appears in the personalized set as a BLOCK-only recall drop of 7.2 points (72 vs 0, p < 0.001). The same change appears on dev (3 BLOCK>WARN, 1 BLOCK>ALLOW), openai (3, 1) and the held-out final (1, 2), at counts too small to test.

### C. Cost-weighted error (cells: old / new / new minus old [95% CI])

Lower is better. Union (cascade) is the headline; regex-only and NER-only are included for completeness.

#### Union (regex OR NER): mean cost per row, cost = k x FN + 1 x FP (cells: old / new / new minus old [CI])

| Split | Rule | k = 2 | k = 4 | k = 9 |
|---|---|---|---|---|
| dev | positive (any finding) | 0.309 / 0.275 / -0.034 [-0.069, -0.002] \* | 0.592 / 0.526 / -0.066 [-0.131, -0.006] \* | 1.299 / 1.153 / -0.145 [-0.290, -0.012] \* |
| dev | WARN-or-BLOCK | 0.406 / 0.404 / -0.002 [-0.034, 0.030] | 0.801 / 0.787 / -0.014 [-0.076, 0.048] | 1.787 / 1.743 / -0.044 [-0.182, 0.092] |
| dev | BLOCK only | 0.635 / 0.651 / 0.016 [0.004, 0.032] \* | 1.269 / 1.301 / 0.032 [0.008, 0.065] \* | 2.853 / 2.924 / 0.072 [0.018, 0.145] \* |
| dev-TUNE | positive (any finding) | 0.285 / 0.247 / -0.037 [-0.091, 0.015] | 0.547 / 0.472 / -0.075 [-0.176, 0.022] | 1.202 / 1.034 / -0.169 [-0.393, 0.044] |
| dev-TUNE | WARN-or-BLOCK | 0.390 / 0.393 / 0.004 [-0.045, 0.055] | 0.772 / 0.768 / -0.004 [-0.100, 0.097] | 1.727 / 1.704 / -0.022 [-0.241, 0.206] |
| dev-TUNE | BLOCK only | 0.723 / 0.730 / 0.007 [0.000, 0.023] | 1.442 / 1.457 / 0.015 [0.000, 0.046] | 3.240 / 3.273 / 0.034 [0.000, 0.103] |
| dev-CHECK | positive (any finding) | 0.336 / 0.306 / -0.030 [-0.075, 0.013] | 0.643 / 0.587 / -0.055 [-0.139, 0.017] | 1.409 / 1.289 / -0.119 [-0.303, 0.039] |
| dev-CHECK | WARN-or-BLOCK | 0.426 / 0.417 / -0.009 [-0.047, 0.026] | 0.834 / 0.809 / -0.026 [-0.099, 0.039] | 1.855 / 1.787 / -0.068 [-0.228, 0.077] |
| dev-CHECK | BLOCK only | 0.536 / 0.562 / 0.026 [0.000, 0.059] | 1.072 / 1.123 / 0.051 [0.000, 0.119] | 2.413 / 2.528 / 0.115 [0.000, 0.267] |
| personalized | positive (any finding) | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* |
| personalized | WARN-or-BLOCK | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* |
| personalized | BLOCK only | 0.000 / 0.072 / 0.072 [0.056, 0.089] \* | 0.000 / 0.144 / 0.144 [0.112, 0.178] \* | 0.000 / 0.324 / 0.324 [0.252, 0.401] \* |
| openai | positive (any finding) | 0.215 / 0.119 / -0.096 [-0.121, -0.070] \* | 0.273 / 0.201 / -0.072 [-0.107, -0.035] \* | 0.418 / 0.406 / -0.012 [-0.078, 0.061] |
| openai | WARN-or-BLOCK | 0.188 / 0.134 / -0.054 [-0.073, -0.035] \* | 0.276 / 0.234 / -0.042 [-0.068, -0.014] \* | 0.496 / 0.484 / -0.012 [-0.061, 0.043] |
| openai | BLOCK only | 0.281 / 0.284 / 0.003 [-0.005, 0.012] | 0.527 / 0.538 / 0.011 [-0.004, 0.029] | 1.142 / 1.173 / 0.031 [0.001, 0.069] \* |
| **held-out final** | positive (any finding) | 0.243 / 0.245 / 0.002 [-0.040, 0.044] | 0.464 / 0.470 / 0.006 [-0.076, 0.086] | 1.016 / 1.032 / 0.016 [-0.167, 0.196] |
| **held-out final** | WARN-or-BLOCK | 0.386 / 0.392 / 0.006 [-0.038, 0.050] | 0.759 / 0.769 / 0.010 [-0.074, 0.095] | 1.693 / 1.713 / 0.020 [-0.169, 0.211] |
| **held-out final** | BLOCK only | 0.574 / 0.582 / 0.008 [-0.006, 0.024] | 1.145 / 1.165 / 0.020 [-0.004, 0.052] | 2.570 / 2.620 / 0.050 [-0.004, 0.122] |

#### Regex only: mean cost per row, cost = k x FN + 1 x FP (cells: old / new / new minus old [CI])

| Split | Rule | k = 2 | k = 4 | k = 9 |
|---|---|---|---|---|
| dev | positive (any finding) | 0.380 / 0.386 / 0.006 [-0.008, 0.022] | 0.747 / 0.765 / 0.018 [-0.006, 0.050] | 1.663 / 1.711 / 0.048 [-0.006, 0.119] |
| dev | WARN-or-BLOCK | 0.496 / 0.508 / 0.012 [-0.004, 0.030] | 0.982 / 1.010 / 0.028 [0.000, 0.063] | 2.197 / 2.265 / 0.068 [0.010, 0.143] \* |
| dev | BLOCK only | 0.635 / 0.651 / 0.016 [0.004, 0.032] \* | 1.269 / 1.301 / 0.032 [0.008, 0.065] \* | 2.853 / 2.924 / 0.072 [0.018, 0.145] \* |
| dev-TUNE | positive (any finding) | 0.404 / 0.404 / 0.000 [-0.015, 0.019] | 0.794 / 0.801 / 0.007 [-0.015, 0.042] | 1.768 / 1.794 / 0.026 [-0.015, 0.099] |
| dev-TUNE | WARN-or-BLOCK | 0.524 / 0.528 / 0.004 [-0.011, 0.023] | 1.041 / 1.052 / 0.011 [-0.011, 0.045] | 2.333 / 2.363 / 0.030 [-0.011, 0.102] |
| dev-TUNE | BLOCK only | 0.723 / 0.730 / 0.007 [0.000, 0.023] | 1.442 / 1.457 / 0.015 [0.000, 0.046] | 3.240 / 3.273 / 0.034 [0.000, 0.103] |
| dev-CHECK | positive (any finding) | 0.353 / 0.366 / 0.013 [-0.009, 0.042] | 0.694 / 0.723 / 0.030 [-0.008, 0.085] | 1.545 / 1.617 / 0.072 [-0.008, 0.192] |
| dev-CHECK | WARN-or-BLOCK | 0.464 / 0.485 / 0.021 [-0.004, 0.054] | 0.915 / 0.962 / 0.047 [-0.004, 0.113] | 2.043 / 2.153 / 0.111 [-0.004, 0.262] |
| dev-CHECK | BLOCK only | 0.536 / 0.562 / 0.026 [0.000, 0.059] | 1.072 / 1.123 / 0.051 [0.000, 0.119] | 2.413 / 2.528 / 0.115 [0.000, 0.267] |
| personalized | positive (any finding) | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* |
| personalized | WARN-or-BLOCK | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* | 0.011 / 0.000 / -0.011 [-0.017, -0.007] \* |
| personalized | BLOCK only | 0.000 / 0.072 / 0.072 [0.056, 0.089] \* | 0.000 / 0.144 / 0.144 [0.112, 0.178] \* | 0.000 / 0.324 / 0.324 [0.252, 0.401] \* |
| openai | positive (any finding) | 0.234 / 0.138 / -0.096 [-0.121, -0.071] \* | 0.314 / 0.242 / -0.072 [-0.105, -0.037] \* | 0.514 / 0.502 / -0.012 [-0.074, 0.055] |
| openai | WARN-or-BLOCK | 0.199 / 0.156 / -0.043 [-0.062, -0.024] \* | 0.303 / 0.278 / -0.025 [-0.052, 0.004] | 0.563 / 0.583 / 0.020 [-0.031, 0.078] |
| openai | BLOCK only | 0.281 / 0.284 / 0.003 [-0.005, 0.012] | 0.527 / 0.538 / 0.011 [-0.004, 0.029] | 1.142 / 1.173 / 0.031 [0.001, 0.069] \* |
| **held-out final** | positive (any finding) | 0.337 / 0.343 / 0.006 [-0.008, 0.022] | 0.667 / 0.685 / 0.018 [-0.006, 0.050] | 1.490 / 1.538 / 0.048 [-0.006, 0.120] |
| **held-out final** | WARN-or-BLOCK | 0.472 / 0.478 / 0.006 [-0.008, 0.022] | 0.938 / 0.956 / 0.018 [-0.006, 0.050] | 2.102 / 2.151 / 0.048 [-0.006, 0.120] |
| **held-out final** | BLOCK only | 0.574 / 0.582 / 0.008 [-0.006, 0.024] | 1.145 / 1.165 / 0.020 [-0.004, 0.052] | 2.570 / 2.620 / 0.050 [-0.004, 0.122] |

#### NER only: mean cost per row, cost = k x FN + 1 x FP (cells: old / new / new minus old [CI])

| Split | Rule | k = 2 | k = 4 | k = 9 |
|---|---|---|---|---|
| dev | positive (any finding) | 0.845 / 0.809 / -0.036 [-0.090, 0.016] | 1.677 / 1.602 / -0.076 [-0.181, 0.027] | 3.759 / 3.584 / -0.175 [-0.411, 0.054] |
| dev | WARN-or-BLOCK | 0.875 / 0.853 / -0.022 [-0.067, 0.022] | 1.747 / 1.689 / -0.058 [-0.147, 0.030] | 3.928 / 3.781 / -0.147 [-0.348, 0.049] |
| dev | BLOCK only | 1.052 / 1.052 / 0.000 [0.000, 0.000] | 2.104 / 2.104 / 0.000 [0.000, 0.000] | 4.733 / 4.733 / 0.000 [0.000, 0.000] |
| dev-TUNE | positive (any finding) | 0.854 / 0.816 / -0.037 [-0.115, 0.040] | 1.700 / 1.618 / -0.082 [-0.236, 0.067] | 3.816 / 3.622 / -0.195 [-0.538, 0.141] |
| dev-TUNE | WARN-or-BLOCK | 0.891 / 0.884 / -0.007 [-0.078, 0.061] | 1.783 / 1.753 / -0.030 [-0.168, 0.105] | 4.011 / 3.925 / -0.086 [-0.395, 0.217] |
| dev-TUNE | BLOCK only | 1.109 / 1.109 / 0.000 [0.000, 0.000] | 2.217 / 2.217 / 0.000 [0.000, 0.000] | 4.989 / 4.989 / 0.000 [0.000, 0.000] |
| dev-CHECK | positive (any finding) | 0.834 / 0.800 / -0.034 [-0.105, 0.034] | 1.651 / 1.583 / -0.068 [-0.206, 0.064] | 3.694 / 3.540 / -0.153 [-0.462, 0.144] |
| dev-CHECK | WARN-or-BLOCK | 0.855 / 0.817 / -0.038 [-0.095, 0.013] | 1.706 / 1.617 / -0.089 [-0.200, 0.009] | 3.834 / 3.617 / -0.217 [-0.463, 0.009] |
| dev-CHECK | BLOCK only | 0.987 / 0.987 / 0.000 [0.000, 0.000] | 1.974 / 1.974 / 0.000 [0.000, 0.000] | 4.443 / 4.443 / 0.000 [0.000, 0.000] |
| personalized | positive (any finding) | 0.200 / 0.305 / 0.105 [0.078, 0.133] \* | 0.400 / 0.610 / 0.210 [0.156, 0.266] \* | 0.900 / 1.373 / 0.473 [0.351, 0.598] \* |
| personalized | WARN-or-BLOCK | 0.296 / 0.305 / 0.009 [-0.016, 0.033] | 0.592 / 0.610 / 0.018 [-0.032, 0.066] | 1.332 / 1.373 / 0.040 [-0.072, 0.149] |
| personalized | BLOCK only | 1.000 / 1.000 / 0.000 [0.000, 0.000] | 2.000 / 2.000 / 0.000 [0.000, 0.000] | 4.500 / 4.500 / 0.000 [0.000, 0.000] |
| openai | positive (any finding) | 0.718 / 0.833 / 0.115 [0.081, 0.150] \* | 1.428 / 1.663 / 0.235 [0.166, 0.305] \* | 3.203 / 3.738 / 0.535 [0.381, 0.690] \* |
| openai | WARN-or-BLOCK | 0.758 / 0.844 / 0.086 [0.056, 0.118] \* | 1.508 / 1.688 / 0.180 [0.121, 0.242] \* | 3.383 / 3.798 / 0.415 [0.282, 0.553] \* |
| openai | BLOCK only | 1.000 / 1.000 / 0.000 [0.000, 0.000] | 2.000 / 2.000 / 0.000 [0.000, 0.000] | 4.500 / 4.500 / 0.000 [0.000, 0.000] |
| **held-out final** | positive (any finding) | 0.737 / 0.765 / 0.028 [-0.030, 0.085] | 1.460 / 1.512 / 0.052 [-0.063, 0.165] | 3.267 / 3.380 / 0.112 [-0.145, 0.363] |
| **held-out final** | WARN-or-BLOCK | 0.793 / 0.801 / 0.008 [-0.045, 0.061] | 1.580 / 1.588 / 0.008 [-0.096, 0.112] | 3.548 / 3.556 / 0.008 [-0.226, 0.240] |
| **held-out final** | BLOCK only | 0.948 / 0.948 / 0.000 [0.000, 0.000] | 1.896 / 1.896 / 0.000 [0.000, 0.000] | 4.265 / 4.265 / 0.000 [0.000, 0.000] |

Cost deltas have bootstrap intervals only (no exact test). On dev union they are driven by the recall gain that the exact tests do not support (below), and on the held-out final no cost delta is distinguishable from zero for any rule or ratio.

### D. Synthetic sets, scenario-cluster sensitivity

#### Synthetic sets: cluster-by-scenario sensitivity (new minus old, rule positive, 95% CI)

| Set | clusters | Layer | dRecall | dSpecificity | dF2 |
|---|---|---|---|---|---|
| personalized | 20 | regex | 0.000 [0.000, 0.000] | 0.023 [0.000, 0.073] | 0.005 [0.000, 0.015] |
| personalized | 20 | ner | -0.105 [-0.225, -0.005] \* | 0.000 [0.000, 0.000] | -0.093 [-0.212, -0.004] \* |
| personalized | 20 | union | 0.000 [0.000, 0.000] | 0.023 [0.000, 0.073] | 0.005 [0.000, 0.015] |
| openai | 10 | regex | -0.024 [-0.039, -0.011] \* | 0.240 [0.174, 0.329] \* | 0.023 [0.013, 0.032] \* |
| openai | 10 | ner | -0.120 [-0.150, -0.089] \* | 0.010 [0.000, 0.019] | -0.133 [-0.167, -0.098] \* |
| openai | 10 | union | -0.024 [-0.032, -0.015] \* | 0.240 [0.181, 0.321] \* | 0.023 [0.012, 0.036] \* |

Row-level bootstrap and exact McNemar treat each template-generated row as independent. With only 20 / 10 scenario clusters, intervals widen sharply; the personalized specificity interval then touches zero (the 23 false positives are probably concentrated in a few scenarios, not verified), while the openai effects on regex and union (specificity gain, recall loss) and the NER recall losses stay clear of zero.

## Verdict: which claimed differences are statistically supported

The held-out final (clean, one-shot) is the only unbiased evidence; dev-TUNE and personalized are design sets, dev-CHECK and openai are post-review.

1. **Regex-only specificity gain: supported on the synthetic sets, not individually supported on the real-text sets.** Personalized 23 FP to 0 (p < 0.001 exact; the scenario-cluster CI touches 0) and openai 154 to 34 (121 gained vs 1 lost, p < 0.001, also robust to scenario clustering) are unambiguous. On dev (3 FP gained, 0 lost; p = 0.25) and the held-out final (3 vs 0; p = 0.25; specificity 0.985 to 0.996, CI of the difference [0.000, 0.026]) the direction is consistent but three rows cannot be distinguished from chance. The held-out final alone does not establish a precision gain; it is compatible with anything from no change to about 2.6 points.
2. **Regex recall cost: about 1 point on dev and final is not statistically distinguishable from zero (3 rows lost, 0 gained, p = 0.25 on each); the 2.4-point loss on openai is real** (12 lost vs 0 gained, p < 0.001). It is a genuine cost on synthetic text and a plausible but unproven cost on real text.
3. **Union on the held-out final is unchanged: supported as "no detectable change", not as "equivalent".** Recall 0.767 to 0.763 (13 gained, 14 lost, p = 1.0), specificity 0.958 to 0.962 (7 vs 6, p = 1.0). The 95% intervals of the differences are [-0.047, 0.039] for recall, [-0.023, 0.031] for specificity and [-0.040, 0.035] for F2; the final set cannot rule out changes of 3 to 5 points in either direction.
4. **Union gain on dev (recall 0.731 to 0.761, F2 +2.7 points): not supported at the 5% level by the exact tests** (12 gained vs 4 lost, p = 0.077; cluster sign test p = 0.077; the percentile CI [0.004, 0.061] only just excludes zero and is optimistic at these counts). dev-TUNE (8 vs 3, p = 0.23) and dev-CHECK (4 vs 1, p = 0.38) are each too small to decide. The gain did not reproduce on the held-out final (13 vs 14).
5. **NER layer: no significant net effect on real text; a significant recall loss on synthetic text.** Dev recall 0.208 to 0.246 (26 gained vs 16 lost, p = 0.16) and final 0.237 to 0.212 (23 vs 29, p = 0.49) are both inside the noise, and have opposite signs. NER false-positive changes (dev 5 vs 7, final 4 vs 6) are noise. Personalized NER recall 0.800 to 0.695 (52 vs 157, p < 0.001) and openai 0.290 to 0.170 (11 vs 71, p < 0.001) are real losses. The earlier statement that a net NER-layer benefit is not established on held-out data stands, and is now quantified.
6. **Action level.** WARN-or-BLOCK union: dev and final changes are inside noise (final recall -0.004, specificity -0.004); personalized specificity +2.3 points (p < 0.001) and openai specificity +13.2 points (67 vs 1, p < 0.001) are real. BLOCK-only recall falls on personalized by 7.2 points (72 vs 0, p < 0.001), a consequence of the `CHILD` rule change described above; on dev (0 gained, 4 lost) and the final (0 vs 3) the same direction is not significant (p = 0.125 and 0.25). Cost: on the held-out final no cost difference for any rule or FN:FP ratio (2, 4, 9) is distinguishable from zero. On dev the BLOCK-only cost is slightly higher for the new run (+0.016 at k = 2, CI [0.004, 0.032]) and the positive-rule cost is slightly lower (-0.034 at k = 2, CI [-0.069, -0.002]); neither is reproduced on the final nor significant in either dev half.

In short: the large synthetic-set changes (regex specificity up, NER and regex recall down, BLOCK actions downgraded to WARN on personalized) are statistically solid. The small real-text changes (dev union gain, regex specificity on dev and final, NER effect) are not: at 3 to 30 discordant rows they are compatible with zero. No claim of a precision improvement on real text should rest on the held-out final alone.

## Limitations

- The final is now used twice (original scoring plus this authorized re-derivation, both on the same frozen configurations) and must not be used for further decisions; per-row outcomes with hashed ids exist locally.
- Bootstrap CIs use percentiles (no BCa) and are optimistic for few discordant rows; exact tests are the primary evidence for small counts. No multiplicity correction; p-values across the hundreds of cells of the JSON are exploratory.
- The synthetic sets lack template ids; row-level inference there is likely anti-conservative, the scenario-cluster check is conservative.
- Labels `expected_has_pii` are noisy and S1 counts as positive; action-level metrics measure agreement of the runtime action with that binary label, which is a different construct.
- Detector layers only: the semantic layer, regex-first short-circuiting (`regex_first=False` here) and the product's enforcement are not exercised. Single spaCy model `en_core_web_sm`. Latency not re-measured.
