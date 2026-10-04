# External PII source expansion: evidence ledger

**Status:** preparation, offline fitting, and the fixed v2 runtime comparison are complete. This is a provisional internal development record, not a final-benchmark result or deployment claim.

## Frozen inputs and provenance

The prospective protocol is [dataset-expansion-protocol.md](dataset-expansion-protocol.md), canonical SHA-256 `962198b384aaed7fd5fb98e10c778b295ac6403c0dd1ba5ea376c28ec786eafe`. The source revision was `85c7f475fb8ebd1529254e4135b774d98505ddb1`. The valid preparation manifest is `evaluation/results/external_pii_20261004_prepared_v3/manifest.json`, SHA-256 `2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c`; its train and validation partitions are bound by their hashes in that manifest. The frozen sparse-profile fit is `evaluation/results/external_pii_profiles_20261004_v1/run-manifest.json`, with aggregate profile results in the sibling `diagnostics.json`. Validation selection was frozen before development scoring. The final partition was not opened or scored.

Earlier v1 preparation had a blanket UID ambiguity rule and selected no Nemotron training rows; v2 was interrupted before fitting due to a SQLite staging performance issue. Neither is a model result. The amended v3 protocol recognizes only verified two-locale positive variants, preserves the parent UID as protected group, and uses the shared normalized text key for duplicate protection.

## Data counts and integrity

| Partition/source | Rows | Grouping/label scope |
| --- | ---: | --- |
| Training, original reference | 3,832 | Existing project training reference |
| Training, Nemotron | 13,168 | Positive annotations; whole parent UID groups |
| Training, Meddies | 2,993 | Positive annotations; coarse metadata-family grouping |
| **Total training** | **19,993** | Original rows retained as an exact prefix |
| Validation | 968 | Existing unchanged selection set |
| Nemotron source-heldout | 1,000 | Positive-only; 500 parent UID groups |
| Meddies source-heldout | 999 | Positive-only; 36 metadata families |

Preparation reported zero candidate duplicate IDs/texts, protected group/ID/text overlaps, and cross-partition group overlaps. The source-level exclusion details and pinned source metadata are in the immutable manifest and [dataset analysis](../../docs/PII-dataset-analysis.md). Meddies metadata families are not verified independent documents. Both added-source diagnostics contain positives only; specificity cannot be estimated from them.

## Offline profile measurements

All six profile/C fits converged without warnings. Each profile selected C=10 using the predeclared validation-only criterion. The confusion counts below use validation denominator 475 positives and 493 clean rows; percentages are computed from raw counts. Matched frozen-profile controls are shown for context.

| Profile | Expanded TP/TN/FP/FN | Recall | Specificity | Frozen control TP/TN/FP/FN |
| --- | --- | ---: | ---: | --- |
| Efficient | 428 / 330 / 163 / 47 | 90.11% | 66.94% | 429 / 378 / 115 / 46 |
| Balanced | 428 / 396 / 97 / 47 | 90.11% | 80.32% | 428 / 392 / 101 / 47 |
| Quality | 430 / 384 / 109 / 45 | 90.53% | 77.89% | 428 / 394 / 99 / 47 |

The measurements vary by profile; quality has two additional validation true positives and ten additional false positives versus its matched control. These comparisons are conditional on the fixed validation set used for C/threshold selection and are descriptive, not an independent confirmation of gains.

At the frozen thresholds, positive-only source-heldout recall counts were Nemotron 1,000/1,000 and Meddies 999/999 for all three expanded profiles. Matched frozen controls detected Nemotron 956/1,000 (efficient), 919/1,000 (balanced), 892/1,000 (quality), and Meddies 998/999, 997/999, 995/999 respectively. These results do not provide clean-negative specificity, exact entity-span accuracy, contextual sensitivity, action correctness, or evidence of population-level perfection. The source corpora differ in style, grouping and annotation construction from the project validation prompts.

## Boundary and next evidence

These are binary annotation-presence measurements. Runtime attempt v1 failed before scoring because of a missing protobuf import and remains preserved as a zero-score failure. The fixed v2 runtime comparison completed all 18 matched runs and 17,802 RPC requests with zero errors. The scorer/RPC Docker suite passed 11 tests with no skips; the separate runner suite passed 9 tests. The current selected contextual model remains unchanged; its previously measured 90.53% recall and 29.41% specificity are a distinct operating point. The development recall/specificity targets are not jointly met by the live model, and the final partition remains unscored.

The Meddies source is CC-BY-NC-4.0 and Nemotron is CC-BY-4.0 at the pinned revisions. Keep source attribution and the non-commercial condition attached to research use. Prompt text, clinical text, entity lists and learned vocabularies remain restricted to ignored local experiment artifacts; public documentation should include only reviewed aggregate counts and metrics.

## AdvPIIBench structural and protection preflight

This later preflight is separate from the completed Nemotron/Meddies profile study above. At pinned AdvPIIBench revision `02741d9f99a91b8fdcf48f4316a2c73be7a7449a`, the complete 4,258,476-byte Parquet object matched SHA-256 `e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69`. The count-only scan covered 104,728 rows, found 104,728 unique UIDs, excluded 14,496 few-shot rows, and formed 24,958 components. The scan completed without execution errors, and zero source components overlapped the protected union. The run manifest is `evaluation/results/advpii_structure_20261004_v1/run-manifest.json` (SHA-256 `ba3830cc0416093346d44f72e53f9798d5df7992506f884fc5ef1f4f1443acb7`); its aggregate report is `aggregate-report.json` (SHA-256 `80f718f9b330e550bee5b39451478e85247ad0a6e08f8543a83b259e52cc7c97`).

The protected union covered the opaque 1,000-row selection/929 groups, original train/validation/43 bootstrap anchors, and prior external training and heldout partitions. The native-label row ceilings after structural and protection filters were 66,440 positive, 22,560 negative, and 1,232 hard-negative; the positive rows formed 1,166 components. These native labels and counts are not reviewed whole-prompt truth. The 1,232 hard-negative rows exceed the proposed total quota of 900 numerically, but source-group and partition component floors remain unassessed. The scan did not assign broad labels, partition rows, fit a model, or score results. See the [dataset analysis](../../docs/PII-dataset-analysis.md) for the protocol gates and current limits.

## Verified live RPC results

The completed study is `evaluation/results/external_pii_rpc_20261004_v2/run-manifest.json` (SHA-256 `62b28e0f6c2e8006915e9bdc8498462d636e44d5bb397f8704a95d96d2ab8671`). The aggregate is `evaluation/results/external_pii_summary_20261004_v1.json` (SHA-256 `e5e138d42f0930390702fb56a745ae0b8e7f7772791d8ed473ab56d51b250c2d`). Execution used revision `083ee0c5fb38efdfb63ade634b185eba0c67432d`; fit revision was `85c7f475fb8ebd1529254e4135b774d98505ddb1`; prepared manifest SHA is `2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c`; protocol SHA is `962198b384aaed7fd5fb98e10c778b295ac6403c0dd1ba5ea376c28ec786eafe`. It completed all 18 matched runs / 17,802 RPC requests with zero errors. Restoration was verified, no admin mutation outcome was unknown, the contextual payload SHA-256 matched before/after (`e4363fc47b0b4663f92d923842e2bfe635b0d7b2b165c9cd4a8fb2f4a7e66d93`), and all runtime image IDs were identical before/after. The independent audit record is `evaluation/results/contextual_cascade_20261004_discovery/external-data-code-critic.md`: it joined all responses to row IDs/groups/labels, verified artifact identities and strict RPC fields, independently reproduced all 9 paired intervals with exact endpoints, and found maximum local/RPC probability difference 0. It checked input hashes, unchanged service images, and byte-exact restoration of the three experimental presence artifacts; the contextual artifact remained unchanged, with no contextual install/restore.

The live validation counts matched the offline model scores exactly:

| Profile | Expanded TP/TN/FP/FN | Frozen control TP/TN/FP/FN | Recall delta (95% interval) | Specificity delta (95% interval) |
| --- | --- | --- | --- | --- |
| Efficient | 428 / 330 / 163 / 47 | 429 / 378 / 115 / 46 | −0.21 pp [−2.16, +1.91] pp | −9.74 pp [−13.43, −6.30] pp |
| Balanced | 428 / 396 / 97 / 47 | 428 / 392 / 101 / 47 | 0.00 pp [−1.76, +1.72] pp | +0.81 pp [−1.46, +3.08] pp |
| Quality | 430 / 384 / 109 / 45 | 428 / 394 / 99 / 47 | +0.42 pp [−1.68, +2.60] pp | −2.03 pp [−4.71, +0.43] pp |

Intervals are paired source-group bootstrap intervals (2,000 replicates, 714 groups, seed `10102026`). The balanced interval includes zero; it does not support a convincing specificity improvement. Efficient decreases, and quality’s interval includes zero. Recall deltas were −0.21 pp (efficient), 0.00 pp (balanced), and +0.42 pp (quality); all corresponding 95% intervals include zero. Since C and thresholds were selected on the same validation set, these paired intervals are conditional, descriptive development evidence, not confirmatory unseen-performance estimates or causal effects.

Each expanded profile detected all 1,000 Nemotron and 999 Meddies positive-heldout examples. The matched controls detected 956/1,000, 919/1,000, 892/1,000 Nemotron positives and 998/999, 997/999, 995/999 Meddies positives for efficient/balanced/quality. These source partitions are positive-only, so specificity is not estimable. No result establishes span accuracy, contextual privacy or action correctness, real clinical-record performance, or population-level perfect recall.

The runtime measurements do not promote or replace the current contextual model, and the joint development targets are not met by the current model. The final partition remains locked and unscored.
