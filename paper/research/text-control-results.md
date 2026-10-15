# Sparse text-control results

Measured 4 October 2026 under the [prospective protocol](text-control-protocol.md). This is a custom within-corpus binary annotation-presence control on the prepared PIIMB development split. It does not evaluate contextual privacy decisions, severity, action, independent source generalization, or a deployed model. The locked final partition remains unscored.

## Selection and scores

The fixed train-only word/character TF-IDF representation and balanced logistic regression converged for all three predefined values of C. Validation selected **C=1** at threshold **0.3967909037308085**, with balanced accuracy as the primary candidate ranking criterion after satisfying recall of at least 90%. This choice was persisted before development scoring. No candidate failures or convergence warnings were recorded.

| C | Threshold from validation | Validation TP/TN/FP/FN | Validation recall | Validation specificity | Development TP/TN/FP/FN | Development recall | Development specificity | Development balanced accuracy |
| ---: | ---: | --- | ---: | ---: | --- | ---: | ---: | ---: |
| 0.1 | 0.4499355058 | 428/379/114/47 | 90.11% | 76.88% | 247/177/61/17 | 93.56% | 74.37% | 83.97% |
| **1 (selected)** | **0.3967909037** | **428/394/99/47** | **90.11%** | **79.92%** | **248/186/52/16** | **93.94%** | **78.15%** | **86.05%** |
| 10 | 0.3327467552 | 428/387/106/47 | 90.11% | 78.50% | 247/189/49/17 | 93.56% | 79.41% | 86.49% |

Metrics above are recomputed from the recorded row predictions: development has 264 positives and 238 clean rows; validation has 475 positives and 493 clean rows. C=10 has higher development balanced accuracy and specificity, but C=1 remains the validation-selected candidate and is the reported selected result. The development specificity is below the protocol's 90% target.

The selected result changes 146 development predictions relative to the previous frozen 32D representation probe (C=0.1): 105 prior positives become negative and 41 prior negatives become positive; 259 remain positive and 97 remain negative. The two controls use different feature representations and preprocessing, and these rows have informed earlier development work. This descriptive contrast does not identify a causal representation effect or establish performance on new sources.

## Source composition

Source families use the prefix of `group_id` before the first colon. These are counts, not independent-source validation; label balance differs by source family, especially the positive-heavy AI4Privacy groups and clean-heavy Nemotron group.

| Source family | Train positive/clean | Validation positive/clean | Development positive/clean |
| --- | ---: | ---: | ---: |
| ai4privacy-en | 455/171 | 126/37 | 80/22 |
| ai4privacy-multi | 12/11 | 7/2 | 1/0 |
| gretel | 423/248 | 98/54 | 55/28 |
| mapa-eur-lex | 0/0 | 0/0 | 0/2 |
| nemotron-pii | 888/1,432 | 206/384 | 110/184 |
| privy | 147/45 | 38/16 | 18/2 |
| **Total** | **1,925/1,907** | **475/493** | **264/238** |

On selected C=1 development predictions, Nemotron contributes 100/153/31/10 (TP/TN/FP/FN; 83.15% specificity), while ai4privacy-en contributes 74/13/9/6. These source-level differences underscore that within-corpus style and label composition can support binary separation; they do not show contextual PII recognition or privacy-policy correctness. Tiny groups with a missing class have undefined class-specific rates, retained as null in the report.

## Provenance and reproducibility

The [recomputation script](../../evaluation/results/text_control_20261004_v1/audit/recompute_text_control.py) checks hashes and source revision, recomputes all validation and development confusion counts and rates from saved predictions, joins each candidate's development IDs/truth/groups to locked development, checks source-family summaries, and records transition counts. Its output is [audit.json](../../evaluation/results/text_control_20261004_v1/audit/audit.json). Reproduce with `python evaluation/results/text_control_20261004_v1/audit/recompute_text_control.py` from the repository root. The script never opens `locked-public/final.jsonl`; the final digest below comes from the run's manifest only.

| Evidence | SHA-256 / identity |
| --- | --- |
| Completed run manifest | [run-manifest.json](../../evaluation/results/text_control_20261004_v1/run-manifest.json), `5b3a1168af4fb5307b605073a2202e96cd5dbe7336863cfeed3e6e104a26be22` |
| Selected report | [report.json](../../evaluation/results/text_control_20261004_v1/report.json), `785b0aa7c03bf2a6f63d5300e69c637e28391a69c55f99e6a609f2b0918dad4e` |
| Frozen validation selection | [selection.json](../../evaluation/results/text_control_20261004_v1/selection.json), `c53036db56520f2c2f1d721c68b43cae6ec82f2907d800c70cddd31e66a68bf2` |
| Source and prospective protocol | Revision `6f77710494691f7d8720ae5b6210e94487edc565`; protocol SHA-256 `57d1805f5ae8bd87926f356ca861a35eee18d7bdac63bcf618982ee8973a1670`; fitter SHA-256 `469bf36c2c0e0ec1ef9e147f2772ee7d72f37c058b60ff6251572c4af115c6f1` |
| Prepared partitions | Train `da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d`; validation `d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1`; development `45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706` |
| Protected data and bootstrap | Locked manifest `57461a8cbbb667e6471b32f6ea80896a0249e54e2a7bde1feff1bd9f982a3a88`; locked development `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`; final digest-only `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515`; bootstrap source `75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd` |

The evaluator used Python 3.11.17, NumPy 1.26.4, SciPy 1.17.1, scikit-learn 1.9.1 and threadpoolctl 3.7.0, with OpenBLAS, OpenMP and MKL each limited to one thread. The three candidates converged; no warnings or fit failures were present. Root's recorded Docker evaluator suite passed at checkpoint 74 ([integrated test log](../../evaluation/text-control-integrated-tests.log)). This remains an offline diagnostic: it neither changes the preserved serving checkpoint nor establishes an integrated runtime improvement. Do not substitute this binary score for the existing graded semantic head without a separate prospective interface and contextual/policy validation.
