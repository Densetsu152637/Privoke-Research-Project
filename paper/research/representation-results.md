# Frozen-representation diagnostic results

Measured 4 October 2026 under the [prospective protocol](representation-protocol.md).
This is an offline binary annotation-presence diagnostic on locked development
data. It is a custom within-corpus experiment, not an independent PIIMB test or a
contextual privacy validation. The locked final 498 rows remain unscored.

## Preparation and selection

After protected-group/ID/text-key exclusions and normalized-text deduplication,
the preparation excluded 618 ambiguous source IDs covering 1,236 rows because
each ID mapped to multiple normalized texts. The fixed selection retained 2,400
annotation-positive and 2,400 clean rows with selection seed 5102026. A
source-group split with seed 6102026 produced 3,832 training rows (1,925
positive, 1,907 clean), 968 validation rows (475 positive, 493 clean), and 502
development rows (264 positive, 238 clean). IDs and normalized text keys were
unique within partitions; source groups were disjoint across training,
validation, development and the locked final set (sibling rows may share a
source group within a partition). Training/validation had no
bootstrap-key overlap. The prepared development keys, labels and groups match
the locked development partition exactly.

All predefined logistic fits converged. Each used a training-fitted StandardScaler,
balanced class weights, lbfgs, max_iter 1000 and seed 7102026. Reported package
versions were NumPy 1.26.4 and scikit-learn 1.9.1. Thresholds were selected
independently on validation to maximize specificity with recall at least 90%;
selection among C values used validation balanced accuracy, then
specificity, recall and lower C. C=0.1 was persisted as the choice before any
development scoring. C=1 and C=10 have slightly higher development balanced
accuracy, but they were not selected or substituted after seeing those results.

| C | Validation threshold | Validation TP/TN/FP/FN | Validation recall | Validation specificity | Validation balanced accuracy | Development TP/TN/FP/FN | Development recall | Development specificity | Development balanced accuracy |
| ---: | ---: | --- | ---: | ---: | ---: | --- | ---: | ---: | ---: |
| 0.1 (selected) | 0.3507067984215434 | 428/213/280/47 | 90.11% | 43.20% | 66.66% | 238/112/126/26 | 90.15% | 47.06% | 68.61% |
| 1 | 0.3281135381 | 428/203/290/47 | 90.11% | 41.18% | 65.64% | 243/110/128/21 | 92.05% | 46.22% | 69.13% |
| 10 | 0.3270974340 | 429/203/290/46 | 90.32% | 41.18% | 65.75% | 243/110/128/21 | 92.05% | 46.22% | 69.13% |

Percentages are recomputed from TP/TN/FP/FN using the class counts shown above.
The selected probe reaches the protocol's 90% recall floor, but its 47.06%
development specificity is below the 90% development target. Combining that
selected probe with the reused regex+NER outputs gives TP/TN/FP/FN
250/108/130/14 (94.70% recall, 45.38% specificity). This is an offline reused-
output diagnostic, not a measured live pipeline.

## Comparisons and interpretation

The selected probe's semantic-only counts are 238/112/126/26. The original
balanced v0.3.0 semantic layer had 169/60/178/95 (64.02% recall, 25.21%
specificity). For context, the original balanced full pipeline scored
247/53/185/17 (93.56%, 22.27%); the currently selected trained balanced live
pipeline scored 239/70/168/25 (90.53%, 29.41%). The new offline probe-plus-rule
union is not either live pipeline configuration, so these counts are scope-
different development observations and do not establish an integrated system
result. The live serving payload remained the previously selected balanced
checkpoint, checksum `8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`.
The saved preservation check confirms its canonical payload matched the prior
selection, SHA-256 `bfa4b6f350d78479e45d94df8e9d0bbae08274c1784f37a416d7a040549f6dc6`.

Three paired source-cluster percentile bootstrap reports use the same 502 IDs,
truth labels and groups (465 groups), 2,000 resamples and seed 3102026:

| Contrast | Recall change, pp (95% interval) | Specificity change, pp (95% interval) | Balanced-accuracy change, pp (95% interval) |
| --- | ---: | ---: | ---: |
| Probe vs original balanced semantic | +26.14 (+19.33,+33.71) | +21.85 (+12.89,+30.84) | +23.99 (+18.25,+29.76) |
| Reused probe+regex/NER union vs original balanced pipeline | +1.14 (-2.65,+4.92) | +23.11 (+14.94,+31.96) | +12.12 (+7.71,+16.91) |
| Reused probe+regex/NER union vs selected trained balanced pipeline | +4.17 (0.00,+8.24) | +15.97 (+6.91,+24.90) | +10.07 (+5.14,+15.10) |

The comparator inputs' SHA-256 values and joins were independently checked; each
paired report has 502 rows and 465 groups. These intervals are descriptive
development comparisons after earlier tuning and a validation-selected probe.
They do not establish causal effects, statistical superiority or final
generalization. Annotation absence is only the chosen binary training target;
this result does not validate contextual sensitivity, privacy policy or action
quality. This source-selected curriculum and validation-fitted scaler, logistic
head and threshold differ from fuzzer training. The probes reuse the original
randomly initialized frozen encoder; they do not demonstrate fuzzer learning or
that this classifier can replace its semantic head.

Because the offline probe-plus-reused-rule diagnostic retains 94.70% recall while
improving specificity, the protocol's next bounded branch is an interface and
evaluation design for a binary head/update path. Define it prospectively and
include separate contextual and policy validation before considering integration.
Do not infer deployment readiness: the 90% specificity target remains unmet and
final data remain unscored.

## Provenance and retained failures

The completed [run manifest](../../evaluation/results/representation_20261004_v3/run-manifest.json)
(SHA-256 `fd02d698a6ee1b11deb5badd1ab17e5a7fb2f6db35668446da2875eb9f3713ab`)
records source revision `656a45297241e5287c832fc43541d8d8ba0a59f4`, unchanged
client-runtime/evaluation image IDs, and phase hashes. Client-runtime image
`sha256:892e83441e726124287e04aa4d7db146165a640184824230703eb35d43c845d4` and
evaluation image `sha256:aa733b1a7947480d9677bb66b99f432a27576730c7ee98e05d2602a6113c7597`
were unchanged before and after. Evaluator 68 passed before this run
([test log](../../evaluation/representation-v3-tests.log)). Model identity was checked-in original balanced
v0.3.0 ([artifact](../../evaluation/results/original-v0.3.0-model.json)): model checksum
`8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`, archived
artifact SHA-256 `dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51`,
and shape-inclusive float32 parameter fingerprint
`fec1a27b2252e01f659b5b856e5bdb124ef79b72f28995c7b3599f5ce0bd44c6`. The
independently computed fingerprint matched the runtime feature export.

| Evidence | Locator and SHA-256 |
| --- | --- |
| Locked development/final data | [manifest](../../evaluation/results/locked-public/manifest.json); `65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095` / `613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515` |
| Prepared inputs/features | [prepared manifest](../../evaluation/results/representation_20261004_v3/prepared/manifest.json) `1ddd514c1660a9ebd1288f93937f17b5aa6c91517573c2d25b37f74846486767`; [feature bundle](../../evaluation/results/representation_20261004_v3/features.json) `4a07e8dcda4a2821333d6cbfe2db48ac659799f1ecdf2cf6f1b392cd731e6f07` |
| Frozen selection and fit | [selection](../../evaluation/results/representation_20261004_v3/fit-report-selection.json) `5a680f8aaedda7172ec2d8f3af450a7498072c6292899f555b3068533ad6ded8`; [fit report](../../evaluation/results/representation_20261004_v3/fit-report.json) `d9ba9d2d1c11fdbe27681966cde1d7aac331d2d2f1288013b1f352557e1e592b` |
| Frozen references | Original semantic `6108300098c2fd993393fbe1f6d29ef8ae30ac9ebe9a44e86743db636d6f0daa`; reused regex+NER `c1f503bd3d97a39a2a76adc9152ef2a110ac5c72d2c1796f22b9e0c1514b191a`; rule source hashes are recorded in the run manifest |
| Diagnostic wrappers | [semantic](../../evaluation/results/representation_20261004_v3/diagnostic-semantic.json) `727efdaf2c26be25f7a316eee3d2607637114920c8b48105acb398c963ab6f85`; [reused union](../../evaluation/results/representation_20261004_v3/diagnostic-reused-union.json) `e0fb9fba4f77392af60215a488144a1eda0b26f750d1905e466b38e3d780463d` |
| Paired comparisons | [original semantic](../../evaluation/results/representation_20261004_v3/paired_original_semantic.json) `d32067cdff83455540518fe5b48d305515da75c74c5dc2ba981026e0be7502b2`; [original pipeline](../../evaluation/results/representation_20261004_v3/paired_original_pipeline.json) `6d7cd797c89b6a77da9b4ce1b57e188a3001e730dda651ac0eb4f0a010d17a98`; [selected pipeline](../../evaluation/results/representation_20261004_v3/paired_selected_pipeline.json) `a58053b548ad138a913b5186a5d72b880e575d7955252b6a0a42729c9f8dcdfc` |
| Preserved serving model | [check](../../evaluation/results/representation_20261004_v3/serving-model-check.json) `c5750a555901f9118515b4c399763b68380c4639d0b91eeea38c412007daea31` |

The locked and partition hashes, exclusion/anchor-source digests, source rules,
and report identities are recorded in the linked manifests. The original
semantic report used errors=`0`; all 502 reference rows joined exactly on ID,
label and group with the feature-export binary. The reused union joined the same
502 IDs/labels/groups and its source-rule hashes matched the tracked files. The
bootstrap source SHA-256 is
`75422c421d1a80d0cc3321979fb049f1045f02f334586d6fe62d8832f8a5a7dd`.

The attempts remain part of the record. [V1](../../evaluation/results/representation_20261004_v1/run-manifest.json)
(`14ab578`) failed Windows cp1252 transport on U+202F before feature export or
fitting. [V2](../../evaluation/results/representation_20261004_v2/run-manifest.json)
(`2608b89`) completed UTF-8 preparation/export but stopped before fitting because
one source ID mapped to two normalized texts; it had no fit entries or probe
scores. V3 is a fresh output after the prospectively recorded ambiguous-ID
exclusion. Neither failed attempt is accuracy evidence.
