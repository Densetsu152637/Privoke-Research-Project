# Sparse annotation-presence profiles: fit and runtime measurements

This checkpoint records three fitted sparse word/character profiles for the
binary task `annotation_presence`: whether a PIIMB example is annotated as
containing sensitive content. It does not classify contextual severity,
visibility, or policy action. The profiles are separate evaluation artifacts;
the selected live contextual pipeline remains the existing balanced checkpoint.

## Selection and data

The prospective [model-refactor protocol](../paper/research/model-refactor-protocol.md)
fixed the training, validation, and locked-development partitions at 3,832,
968, and 502 rows. Vocabulary and IDF are fit on training only. For each profile,
the C value and threshold were selected on validation and persisted before any
development scoring. All nine predefined fits converged without warnings or
failures. The independent [fit audit](../evaluation/results/presence_profiles_20261004_v1/audit/audit-v3.json)
recomputed all nine training and validation confusion sets and 8,712 validation
probabilities; maximum absolute probability difference was 1.11e-16. It also
checked 21 artifact checksums, float32 fingerprints and capacity bounds, plus
partition ID, group, and normalized-text-key separation. The audit JSON SHA-256
is `d3d2ff8eea76e6491a36e65693e781dd59a9eaf09d44fd81487e89c4a53e4fcd`.

| Profile | Selected C | Validation threshold | Validation TP/TN/FP/FN | Recall | Specificity | Stored parameters | Artifact bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Efficient | 1 | 0.3611212568 | 429/378/115/46 | 90.32% | 76.67% | 8,001 | 306,114 |
| Balanced | 1 | 0.4024789524 | 428/392/101/47 | 90.11% | 79.51% | 29,851 | 1,148,949 |
| Quality | 10 | 0.3428658704 | 428/394/99/47 | 90.11% | 79.92% | 45,851 | 1,738,280 |

The selected artifacts returned these runtime identities (artifact checksum /
parameter fingerprint): efficient
`10092bb5ac97320a1fb741d636c7b3ccf922035061e143435864109300570e94` /
`910f96b13e93e1780924510c70c4227bf2614008801ea02a2ac8a0f566b67e15`; balanced
`e9d66b20a0dcc40548fe15a40177a2581cb0d38f9e34d7e57bd82a69df957a1d` /
`5830b5ba2927e8c41f097717781d16b8717871c66bfe23e4fdef50d6e0229490`; quality
`e8f718a436dbbe90850d4824cfff63113226f145ee633fd230a7b386347bc553` /
`3700310da4a5d7168e4b1beb5a854fdadfebad47a23883991f1607995e7b518d`. These
identities are recorded in the per-profile runtime reports and manifests.

## Matched runtime-base results

Each frozen profile was evaluated through its typed runtime endpoint on the same
502 locked development rows. All IDs, labels, and groups matched the locked
reference; each run had zero errors, and returned model identity and local/RPC
probabilities matched the archived artifact. The counts below are raw
TP/TN/FP/FN; recall uses 264 positive rows and specificity uses 238 clean rows.

| Profile | Runtime TP/TN/FP/FN | Recall | Specificity | Balanced accuracy | Internal median / p95 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Efficient | 249/169/69/15 | 94.32% | 71.01% | 82.66% | 2.524 / 3.932 |
| Balanced | 247/181/57/17 | 93.56% | 76.05% | 84.81% | 9.921 / 13.803 |
| Quality | 247/189/49/17 | 93.56% | 79.41% | 86.49% | 15.396 / 19.086 |

The timing is the service's internal per-request measurement, including the
first request. It does not measure browser, bridge, or network latency. The
profiles differ in feature capacity and validation-selected C; these
within-corpus results do not isolate a causal effect of model size or establish
profile superiority. Development informed the broader research process, so this
is not an untouched external generalization test.

## Provenance and limits

The [run manifest](../evaluation/results/presence_profiles_20261004_v1/run-manifest.json)
records source revision `d52bf84d83addb827cc21b96f0be8ecc995bfaaa`, protocol SHA-256
`d4c1035c42ef49b0af7992f76bc5332645f2047b3dc313b2679c58a3f14a5f75`, partition
hashes, selected-artifact hashes, and the final-set digest. Its SHA-256 is
`5406a1b58d9bc49e8f36ad5da94d6f9f2f36a093ec640b67bd14922c899609b1`. Per-profile
selection files, artifacts, runtime manifests, reports, and raw predictions are
retained under
[`evaluation/results/presence_profiles_20261004_v1/`](../evaluation/results/presence_profiles_20261004_v1/).
The runtime study used source revision `4615019e5d00d28a48cb05c1ea8324e87b684829`;
the three reports are in `runtime-base/{efficient,balanced,quality}/report.json`.
The evaluator suite passed 84 tests, and the matched runtime manifests record
502 rows and zero errors for each profile.

These are binary annotation-presence measurements, not contextual privacy
judgments or an update of the fuzzer's live model. The original live contextual
pipeline remains at 90.53% recall and 29.41% specificity, below the 90%
specificity development target. No fuzzer update results are included in this
checkpoint. Final data remain unscored; no final examples were read for this
report.
