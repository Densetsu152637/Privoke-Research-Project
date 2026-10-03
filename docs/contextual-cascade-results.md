# Contextual cascade results

## Primary study outcome

The fixed primary cascade completed and passed independent aggregate evidence review. It is an exploratory comparison on the development partition, not a deployment change, independent final test, or validation of contextual privacy/action truth. The gate suppresses only semantic-layer findings when its binary annotation-presence decision is ABSENT; regex/NER contributions remain. Presence does not assign sensitivity, visibility, category, severity, or action.

The primary source revision was `d1e7e3ca77eaef9101907e9082fee3bc0dcbf766`, protocol SHA-256 `2030fd53264bd5000775c1ddfbfd1e7dccc7267f395f89e66410b76e057ce720`, and run-manifest SHA-256 `45fd843f4590e43ee7ab740c1c5b8aa5e34b785a56140c3ea98ab4ed5773c792`. The independent terminal audit is [`cascade-live-terminal-checkpoint-3.json`](../evaluation/results/goal_audit_20261004/cascade-live-terminal-checkpoint-3.json), SHA-256 `90fd30685de2d074f6aa678cbae60074cfd900ea46f315bcf145a9d60a79d11e`. The separate root proof is [`cascade-terminal-root-v3.json`](../evaluation/results/goal_audit_20261004/cascade-terminal-root-v3.json), SHA-256 `f939dab78fc2a3d481aaf780605ca904563bedea189af56786264f0fe2b1d1fe`; the passing root-proof join supplement is [`cascade-live-terminal-root-supplement-3.json`](../evaluation/results/goal_audit_20261004/cascade-live-terminal-root-supplement-3.json), SHA-256 `3169f9340f745890caf7881fe6b99143482ea8c929f228aca152b8c538c88f57`. The [independent audit record](../evaluation/results/goal_audit_20261004/cascade-live-evidence-audit.md) describes scope and checks.

## Fixed design and validation calibration

The original-control comparisons pair original balanced v0.3.0 (model artifact checksum `8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`) with the efficient, balanced, and quality fitted presence profiles. Those values are artifact checksums, not JSON file-byte SHA-256 hashes. The trained-control comparisons use v0.3.0+train.1 (model artifact checksum `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`); this curriculum overlaps validation by 40 exact IDs, 40 normalized text keys, and 190 declared source groups, so those comparisons are diagnostic only.

Validation has 968 rows (475 annotated-positive, 493 clean; SHA-256 `d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1`). Development has 502 rows (264 positive, 238 clean; SHA-256 `45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706`). All six collections, 9,392 candidate thresholds, and frozen selection bindings passed the ordered validation barrier before any development request. Across repeated paired collections the audit verified 5,808 rows and 26,244 RPC records; repeated pair rows/calls are not independent examples.

Ordinary full-pipeline validation controls were TP/TN/FP/FN `435/122/371/40` for original balanced and `426/152/341/49` for selected trained. The current trained control had 426/475 = 89.6842% recall, below the prespecified 90% floor; its three candidates were frozen ineligible and skipped in both validation and development. Original-control gate thresholds were chosen using validation only:

| Original-control profile | Frozen gate threshold | Validation TP/TN/FP/FN | Validation recall | Validation specificity |
| --- | ---: | --- | ---: | ---: |
| Efficient | 0.2903131625644469 | 428/364/129/47 | 90.1053% | 73.8337% |
| Balanced | 0.2985775301044649 | 428/366/127/47 | 90.1053% | 74.2394% |
| Quality | 0.12813894230659534 | 428/337/156/47 | 90.1053% | 68.3570% |

Each selected validation report completed with 968 rows and zero reported errors. Relative to ordinary original validation, every selected gate missed seven additional positive-labelled rows; clean detections rose by 242, 244, and 215 for efficient, balanced, and quality. These are binary annotation-proxy counts, not evidence that the suppressed semantic findings were contextually safe.

## Development results

The fixed original-control development results were:

| Profile | TP/TN/FP/FN | Recall | Specificity | Positive detections lost vs ordinary control | False positives removed vs ordinary control |
| --- | --- | ---: | ---: | ---: | ---: |
| Efficient | 242/175/63/22 | 91.6667% | 73.5294% | 5 | 122 |
| Balanced | 242/169/69/22 | 91.6667% | 71.0084% | 5 | 116 |
| Quality | 242/159/79/22 | 91.6667% | 66.8067% | 5 | 106 |

The ordinary original-control development pipeline was TP/TN/FP/FN `247/53/185/17` (93.5606% recall, 22.2689% specificity). The cascade trades five additional missed positive-labelled rows for fewer clean-row detections. It clears the 90% recall floor but not the 90% specificity target. The profiles are descriptive alternatives; differences do not establish a causal capacity effect. Paired confidence intervals were explicitly uncomputed, so no significance claim is made.

Action changes are separate from the binary score. On the same 502 development rows, observed original-action transitions to ALLOW were:

| Profile | BLOCK → ALLOW | WARN → ALLOW | BLOCK → BLOCK | WARN → WARN | ALLOW → ALLOW |
| --- | ---: | ---: | ---: | ---: | ---: |
| Efficient | 48 | 72 | 139 | 129 | 114 |
| Balanced | 44 | 68 | 143 | 133 | 114 |
| Quality | 42 | 61 | 145 | 140 | 114 |

These aggregate transitions do not establish whether any changed action was safe: the dataset labels annotated PII presence, and the 48-case contextual fixture is provisional and has not received independent human annotation/adjudication. No action-policy or contextual privacy correctness conclusion follows.

## Integrity, restoration, and limits

The run completed 19 named evaluator jobs, 261 successful commands and 21 typed probes; all three development reports contain 502 rows and zero reported errors. The independent audit checked IDs/truth/groups, layer/gate evidence and report commitments. Root's terminal proof confirmed all 15 frozen input commitments, all four model catalog payloads restored byte-for-byte, unchanged runtime images, and quiescent one-off containers. It compared the previously pinned final digest only; no final example was parsed or scored. Study and proof did not change the selected contextual model. The separate current selected model remains at its prior 90.53% recall and 29.41% specificity.

The protocol's paired intervals remain uncomputed. RPC timing is not browser/bridge latency. These results are development evidence with a threshold selected on validation; prior development analysis informed the research. They do not establish untouched generalization, exact entity-span quality, contextual privacy, safe actions, causal improvement, or IEEE readiness. Final 498 remains locked and unscored.

## Preserved execution and audit history

- Attempt v1 failed before scored comparisons; its original manifest says `restoration_verified: false`. Separate recovery/fingerprint-boundary records are preserved at `evaluation/results/goal_audit_20261004/live-cascade-readiness-v1/summary.json` and `evaluation/results/goal_audit_20261004/contextual-fingerprint-boundary-audit.json`. They supplement but do not rewrite that attempt.
- Attempt v2 stopped after 11 rows / 36 RPC responses and before any complete pair report when the controller encountered a missing `evidence` field. Its manifest records restoration verified and no unknown administrative outcome. It is an execution failure, not performance evidence.
- Earlier v1/v2 terminal-proof supplement scripts remain preserved as failed verification attempts (encoded-file versus decoded-payload hash handling, then an authorized post-terminal source advance). Passing supplement v3 joins the primary terminal proof without changing the primary run. After primary source `d1e7e3c` completed, a later source revision `4fa43bf1dfdbcec494153359b19094071ea5d76` was integrated for the separate fixture study; that source advance is not primary input drift.

## Separate contextual fixture study

The 48-case fixture evaluation is a separate study at `evaluation/results/contextual_fixtures_20261004_v1/`, source `4fa43bf1dfdbcec494153359b19094071ea5d76`. Its results and independent review are pending in this update. The case labels remain provisional, professor confirmation remains pending, and the primary cascade result must not be represented as a validation of those labels or of contextual/action policy.
