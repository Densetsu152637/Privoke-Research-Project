# Prospective lexical text-feature control

Recorded 4 October 2026 before fitting the control. The selected frozen 32D
pooled-vector probe reached 90.15% development recall and 47.06% specificity;
its reused regex+NER union reached 94.70% recall and 45.38% specificity. Both
remain below the 90% development specificity target. The selected live model is
unchanged, and the locked final 498 rows remain unscored.

## Question and boundary

Does a fixed sparse lexical representation support better annotation-presence
discrimination than the original balanced encoder's frozen 32D pooled features
on the same prepared source-disjoint partitions? This is a text-representation
control, not a causal architecture comparison: the feature families, capacity,
and preprocessing differ. It does not test contextual sensitivity, privacy
actions, a fuzzer update, serving integration, deployment cost, or an independent
PIIMB test population. Rows come from the same custom, source-selected PIIMB
corpus and have the same limitations recorded in the
[representation protocol](representation-protocol.md).

No serving artifact, serving source, fuzzer, or runtime service is changed. The
offline evaluator creates fresh, isolated diagnostic fit artifacts and fits
annotation-presence binary labels only. Do not infer
sensitivity severity, visibility, categories, contextual policy, or action from
the binary label. Do not score, inspect, tune on, or report outcomes for final.

## Pinned data and integrity

Use only the exact v3 prepared inputs from the earlier frozen-representation
study. Require prepared manifest SHA-256
`1ddd514c1660a9ebd1288f93937f17b5aa6c91517573c2d25b37f74846486767`, locked
development SHA-256
`65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095`, and
locked final file SHA-256
`613a78b9e5fa677904125b4c056fb8d57d15fb6ebd9c443a75f406ae3ac05515`. Verify
the final file by digest only; never parse or score its prompts. Verify the
current bootstrap source digest equals the v3 manifest's recorded digest and
check that its 43 normalized training keys do not overlap train or validation.

Require these exact prepared JSONL digests and row counts:

| Partition | Rows | SHA-256 |
| --- | ---: | --- |
| Train | 3,832 | `da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d` |
| Validation | 968 | `d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1` |
| Development | 502 | `45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706` |

Validate unique IDs and `training_text_key` values within every partition;
strict boolean targets; exact `text_key` recomputation; at least 50 examples of
each label in train and validation; and disjoint IDs, source groups, and
normalized text keys across train, validation, and development. Join prepared
development to locked development by ID and require exact text, normalized key,
boolean label, and group equality for every row. Fail closed before fitting on
any mismatch. `group_id`'s prefix before the first colon is the recorded source
family; retain family-level counts and metrics for all three splits.

Feature text is `training_text_key(text)` applied independently to each full
source text: NFKC, lowercase, `[at]`/`(at)` replacement, digits-space removal,
and whitespace normalization. Unlike the tiny transformer input, it is not
truncated to a model token limit. This is part of the representation/control
difference and must be stated with results.

## Fixed vectorizer, fitting, and selection

Fit a single, unweighted `FeatureUnion` on train documents only, concatenating:

- word TF-IDF with word n-grams `(1, 2)`, `min_df=2`, `max_features=40000`;
- character TF-IDF with character n-grams `(3, 5)`, `min_df=2`,
  `max_features=40000`.

Both branches use `lowercase=False`, `sublinear_tf=True`, `use_idf=True`,
`smooth_idf=True`, L2 normalization, and float64 values. Retain the exact
configuration, ordered vocabulary, IDF values, and branch feature dimensions.
This definition follows the [`TfidfVectorizer`](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html)
and [`FeatureUnion`](https://scikit-learn.org/stable/modules/generated/sklearn.pipeline.FeatureUnion.html)
APIs; record the actual scikit-learn version used by the evaluator image. No
pretrained model, external vocabulary, or download is permitted.

For the fixed transformed vectors, fit binary `LogisticRegression` with
`C=(0.1, 1, 10)`, `class_weight="balanced"`, `solver="lbfgs"`, `max_iter=1000`,
`tol=1e-4`, and `random_state=7102026`. Record every warning and failure. A
non-converged fit is ineligible but remains in the report. Do not add another
feature configuration or hyperparameter search.

For every converged C, choose a validation threshold maximizing specificity
subject to recall at least 90%; candidates are the distinct validation
probabilities plus exact boundaries 0 and 1. Ties prefer higher recall, then
higher threshold. Select C by validation balanced accuracy, specificity, recall,
then lower C. Persist an exclusive `selection.json` containing all train and
validation outcomes, candidate failures/warnings, selection rule and chosen C,
threshold, and the recoverable vocabulary/IDF/coefficients/intercept before
transforming or scoring any development document. The fitted vectorizer's
vocabulary and IDF must come from train only.

Only after that artifact exists, transform development text once and score every
eligible predefined C at its already fixed validation threshold. Do not rerank,
change thresholds, or suppress unfavorable development results. Preserve
probability, prediction, ID, truth, group, and source family for train,
validation, and development rows. Report confusion counts and rates overall and
by source family; train metrics are in-sample and should be labeled accordingly.
Use `group_id` prefix before the first colon as the source-family definition.

## Execution and evidence

Use the existing evaluator image and documented ordered Compose files. The
evaluator must refuse a reused output directory, write a stage/failure manifest
and traceback log, and preserve output hashes, source revision supplied by the
caller, this protocol's SHA-256 supplied by the caller, pinned input digests,
software versions, and full configuration. Root owns Docker validation and the
real experiment execution. Unit tests must cover pinned-input validation,
leakage rejection, strict labels, train-only vocabulary/IDF, frozen selection
ordering, finite serializable model parameters, family metrics, and output
refusal. No real-data fit is run during implementation.

Bound CPU fitting to one BLAS/OpenMP thread with `OPENBLAS_NUM_THREADS=1`,
`OMP_NUM_THREADS=1`, and `MKL_NUM_THREADS=1`; record these values. Do not
interpret fit duration as deployment or serving latency.

The development rows have already been used by earlier protocol branches; this
control is descriptive and is not an untouched generalization estimate. The
final partition remains protected. Neither result can establish that lexical
text features resolve false positives in contextual use or improve the deployed
system.
