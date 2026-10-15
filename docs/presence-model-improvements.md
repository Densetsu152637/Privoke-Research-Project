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
ID, group, and normalized-text-key separation among training, validation, and
development. The audit JSON SHA-256 is
`d3d2ff8eea76e6491a36e65693e781dd59a9eaf09d44fd81487e89c4a53e4fcd`.

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
profile superiority. Source families and label composition are imbalanced, and
some source-by-class strata have no examples, so their rates are undefined
(reported as null) rather than evidence of generalization. Development informed
the broader research process, so this is not an untouched external
generalization test.

## Provenance and limits

The [run manifest](../evaluation/results/presence_profiles_20261004_v1/run-manifest.json)
records source revision `d52bf84d83addb827cc21b96f0be8ecc995bfaaa`, protocol SHA-256
`d4c1035c42ef49b0af7992f76bc5332645f2047b3dc313b2679c58a3f14a5f75`, partition
hashes, selected-artifact hashes, and the pinned final-set digest. Its SHA-256 is
`5406a1b58d9bc49e8f36ad5da94d6f9f2f36a093ec640b67bd14922c899609b1`. Per-profile
selection files, artifacts, runtime manifests, reports, and raw predictions are
retained under
[`evaluation/results/presence_profiles_20261004_v1/`](../evaluation/results/presence_profiles_20261004_v1/).
The runtime reports were produced at scoring source revision
`4615019e5d00d28a48cb05c1ea8324e87b684829` and independently audited from
checkout `e519a77ff0d542d39d6a031bf862bbcd92ca758b`. The [served-base audit](../evaluation/results/presence_profiles_20261004_v1/runtime-base/audit/served-base-report-v3.json)
passed 42 checks; its SHA-256 is
`516704d6d7ffb03271ccf1b1f8f503e2aa8088a6c67a87d6b2aa30d335ee82a0`. The
auditor script SHA-256 is
`7496ca3faec340786d0f7c08b0c95c86e64c41daaf4592b66cf9e9dd167aa7f0`. It
verified 502-row identity/label/group joins, raw counts, source-family counts,
returned model identities, and local/RPC score parity to 1.11e-16; each profile
had zero runtime errors. The evaluator suite passed 96 tests at source
`e519a77ff0d542d39d6a031bf862bbcd92ca758b`; see the
[test log](../evaluation/presence-study-evaluator-tests-v2.log).

## Fixed update attempt results

The completed [nine-attempt study](../evaluation/results/presence_updates_20261004_v1/)
used the three frozen profile bases and seeds 42, 43, and 44. All nine update
requests were accepted and produced archived candidate heads; each changed
3,116–14,402 head parameters while the IDF, configuration, and fit provenance
stayed fixed. None met the
predeclared retention rule: validation recall had to be at least 90% and
specificity had to strictly exceed the corresponding base. Counts below are
validation TP/TN/FP/FN (475 positive and 493 clean rows); each row lists the
base followed by its seed 42, 43, and 44 attempts.

| Profile | Fitted base | Seed 42 | Seed 43 | Seed 44 | Retained result |
| --- | ---: | ---: | ---: | ---: | --- |
| Efficient | 429/378/115/46 | 429/378/115/46 | 428/378/115/47 | 428/378/115/47 | Base (no specificity gain) |
| Balanced | 428/392/101/47 | 428/392/101/47 | 427/392/101/48 | 427/392/101/48 | Base (no specificity gain) |
| Quality | 428/394/99/47 | 428/394/99/47 | 427/394/99/48 | 427/394/99/48 | Base (no specificity gain) |

Efficient seeds 43 and 44 stayed above the recall floor but had unchanged
specificity. Balanced and quality seeds 43 and 44 fell below the recall floor
(427/475 = 89.89%); their specificity also stayed unchanged. The seed-42 runs
matched each base's validation counts, so they also failed the strict
specificity-increase condition. Every profile therefore retained its fitted
base, and no updated candidate was selected for development scoring. Verified
502-row base development reports were reused without rescoring. This result
does not show that the fuzzer updates improved detection; it shows these fixed
updates failed the frozen selection gate. No additional C or update cycles were
run in response to the unchanged validation specificity.

The independent [study audit](../evaluation/results/presence_updates_20261004_v1/audit/audit-v2.json)
passed 59,214 checks over 136 files and 11,616 validation probabilities, with
maximum absolute local/RPC difference 1.11e-16. It verified request
fingerprints, receipts, changed candidate heads, unchanged frozen configuration
and IDF, exact data/report joins, stable service/evaluator image identities,
and restoration of all three fitted bases and the previously selected
contextual checkpoint. The study ran at source revision
`e519a77ff0d542d39d6a031bf862bbcd92ca758b`; validation/development/final input
hashes were unchanged before and after the run, with final used only as a
digest. The [study manifest](../evaluation/results/presence_updates_20261004_v1/run-manifest.json)
SHA-256 is
`ae8c3c9dd4a9ccbadb111fdbcbcd0ed9fa0effddf01ba664dc161300fa591695`; audit JSON
SHA-256 is `6829775f7f7620aa0c28caf0b59d6f7d948aa306a8a80f45e34ff4a947a0d35d`;
the [audit script](../evaluation/results/presence_updates_20261004_v1/audit/audit-v2.py)
SHA-256 is
`abe87f3fbcf2a96232301a86acc6cbcf762240acd392d630017d843aa9f43b00`. A
preliminary audit attempt applied the base-scorer source/path assumptions to
update-scoring reports and was superseded by this passing audit. Its script was
edited before v2, so the preliminary attempt is not independently reproducible.

These are binary annotation-presence measurements, not contextual privacy
judgments or evidence that updates improve the fuzzer's live model. The original live contextual
pipeline remains at 90.53% recall and 29.41% specificity, below the 90%
specificity development target. The fit and study audits recorded only the pinned final digest: their
train/validation/development separation checks did not freshly compare final
IDs, groups, or text keys. Final exclusion relies on the earlier pinned
preparation. Final data remain unscored; no final examples were read for this
report.

The next substantive investigation should target representation or
hard-negative/contextual training-data coverage under a new prospective
protocol, then validate severity and action with separately labelled contextual
cases. The logistic presence head and deterministic curriculum fuzzer have no
generative sampling-temperature setting; changing temperature would not address
the measured unchanged false-positive counts. The fixed learning rate and nine
attempts are already covered here, and no result guarantees meeting the 90%/90%
development targets.

The local [evidence archive](../evaluation/artifacts/research-20261004-presence-refactor.zip)
preserves source `bba23579b4d4fe8f474f76b74ebed23c369ffd96` and 1,132 hashed records.
Its [manifest](../paper/research/presence-refactor-artifact-manifest.json) records
ZIP SHA-256 `9e9d354c2eec0f79751d18539e3520cb1cba8a4ce2d8f0ce93706fd7969e47a7`.
Integrity and every recorded file hash passed. Results and archives are local
evidence; raw dataset redistribution and clean-room reproduction remain unverified.
