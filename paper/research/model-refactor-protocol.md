# Prospective sparse annotation-presence model refactor

Recorded 4 October 2026 before fitting or scoring the new bounded profiles.
This protocol adds a real streamed, locally executed learned presence model and
a genuine fuzzer update path. It does not replace the contextual detector,
weaken its policy, or establish completion of the original research goal.

## Decision and hypotheses

The preceding lexical control's validation-selected C=1 model had development
TP/TN/FP/FN 248/186/52/16: recall 93.94% and specificity 78.15%. The frozen
32-dimensional random-encoder probe had 238/112/126/26. Within the Nemotron
source family the lexical control had specificity 83.15%, so its improvement
was not entirely explained by family identification, although source/style and
label confounding remain. Neither result met the 90% specificity target.

These observations motivate testing learned lexical features within the existing
bounded transport and publication architecture. Hypotheses: (1) bounded sparse
profiles retain useful annotation-presence discrimination, (2) shared runtime
arithmetic reproduces exported inference, and (3) head-only fuzzer updates can be
published without held-out binary regressions. These are hypotheses, not promised
improvements. A larger sparse profile also changes vocabulary; this study compares
released configurations rather than isolating a causal parameter-count effect.

The original contextual pipeline remains selected and unchanged. Its latest
development result remains 90.53% recall and 29.41% specificity. The original
development targets of at least 90% recall and 90% specificity, plus completion
evidence, remain unmet. Binary presence cannot substitute for contextual severity,
visibility, category, masking or ALLOW/WARN/BLOCK ground truth.

## Protected data and fitting boundaries

Use the audited v3 prepared train/validation/development partitions from
[the lexical-control protocol](text-control-protocol.md): 3,832/968/502 rows.
Require its pinned manifests, file digests, unique IDs/normalized text keys,
strict boolean labels, source-group exclusions and bootstrap-key exclusions.
Protect source groups as well as normalized text/IDs; retain source-family counts
and missing class denominators. The final 498 rows remain unscored and unparsed;
only verify the locked final file digest. No new corpus download or vocabulary
source is authorized by this protocol.

Fit vocabulary, document frequencies, IDF and logistic coefficients on train only.
Validation selects regularization and threshold. Development is a fixed endpoint
for descriptive comparison; it must not choose regularization, threshold, profiles
for further tuning, fuzzer hyperparameters or stopping criteria. Previous use of
development means its measurements are not untouched generalization estimates.

## Model artifact and execution contract

Architecture is `privoke_sparse_presence_v1`; task is `annotation_presence`.
Three separate IDs are `privoke-presence-efficient`, `privoke-presence-balanced`
and `privoke-presence-quality`. Vocabulary maxima per branch are respectively
2,000, 8,000 and 16,000 word and character features. Fixed branches use word
ngrams (1,2) with `(?u)\b\w\w+\b`, and character ngrams (3,5); `min_df=2`,
unweighted concatenation, `lowercase=False`, sublinear term frequency, smooth IDF
and independent L2 branch normalization. Apply `training_text_key_v1` to full
text; do not truncate text to the old transformer token limit.

Train-only ordered vocabularies and complete vectorizer settings live in config.
Config fixes word-before-char column order, profile, normalization, threshold and
coefficient block size 4,096. IDF tensors `features.word.idf` and
`features.char.idf` are frozen. Only `head.presence.weight.000`, `.001`, ...
and `head.presence.bias` are trainable. Blocks cover the full feature columns
contiguously; every block has at most 4,096 values. IDF plus head parameters are
bounded by 8,001/32,001/64,001 values, within the unchanged 65,536 total numeric
cap. Config is bounded to 2 MiB UTF-8 JSON; artifact remains bounded to 8 MiB.
Oversize/invalid exports fail rather than silently removing learned features.

Shared inference in `shared/python/privoke_model/presence.py` defines arithmetic:
parameters round to transported float32; normalized word/character counts produce
`(1+log(count))*IDF`, then independent L2 normalization in float64. Ascending-column
coefficient products use `math.fsum`, with float32 bias and stable sigmoid.
Prediction is probability >= stored threshold. Reconstruct from serialized
config/weights, never from an in-memory sklearn estimator, for calibration and
runtime parity. Frozen vocabulary/IDF/normalizer/threshold changes require a new
release artifact. Updates retain bounded float32 deltas, exact candidate
publication arithmetic, checksums and immutable snapshot/cache identity.

The additive runtime RPCs `DetectAnnotationPresence` and
`ComputePresenceGradients` return typed presence output/training metrics. Targets
are ABSENT/PRESENT; UNSPECIFIED and unknown enum values are errors. No contextual
classification or action is inferred from these labels. Keep `AnalyzePrompt`,
`ComputeSemanticGradients`, original fuzzer training, fusion and policy unchanged;
presence negatives never suppress another detector's findings. Clients must check
error before reading default numeric fields or UNSPECIFIED predictions.

## Frozen fitting and selection procedure

For each profile fit the fixed train-only TF-IDF branches and three balanced
logistic regressions C=(0.1,1,10), solver lbfgs, max_iter=1000, tol=1e-4,
random_state=7102026. Bound BLAS/OpenMP to one thread and retain all warnings,
nonconvergence and failures. A nonconverged or invalid artifact is ineligible.

Convert every candidate's learned parameters to the runtime float32 representation
and reload through the shared inference implementation. Choose a threshold from
distinct validation probabilities plus 0 and 1 to maximize validation specificity
subject to recall >=90%; ties prefer higher recall, then higher threshold.
Choose C by validation balanced accuracy, specificity, recall, then lower C.
Store all validation candidates and a recoverable selection artifact exclusively
before scoring any development rows. There is no additional C or feature search.

For each fixed selected profile publish/export its calibrated release base and
measure streamed runtime presence on exactly the locked 502 development rows,
once per fixed endpoint. Preserve binary probabilities, threshold, ID/label/group,
source-family metrics, errors, elapsed_ms and exact returned identity. Compare
the three predefined profiles descriptively without development reselection.
Report numeric parameter count, head/IDF counts, vocabulary features, JSON bytes,
actual transport bytes if measured and runtime-duration distributions separately.
Fit durations do not measure deployment latency; runtime elapsed_ms excludes
browser/bridge overhead. Do not relabel binary output as S3 to reuse policy scores.

## Genuine fuzzer update study

For each fixed fitted profile run exactly three independent seed42/43/44 cycles
from that profile's unchanged fitted release base. Use learning rate0.03,
maximum absolute delta0.05, training count256 and held-out count32, with no
label-changing transforms. Restore the same release base between independent
seeds. Use fresh request IDs and preserve rejected/failed/unscored attempts.

Cycle training and binary guards are sampled exclusively from train, never from
validation, development or final. Reserve distinct held-out source groups and
exclude all siblings and normalized keys from that cycle's training. Both labels
must be present in the guard; fail on insufficient distinct groups. The release
fit already saw the training curriculum, including guard examples: these are
internal update guards, not unseen generalization evidence.

The existing fuzzer service implements `RunPresenceTrainingCycle`; only runtime
loads weights, performs descent and evaluates candidates. Update receipts and
request fingerprints are salted with `RunPresenceTrainingCycle:annotation_presence:v1`
to prevent cross-objective replay reuse. Preserve durable lookup, stale-base
rejection, clipping, shape/frozen tensor validation and lost-ack recovery.

Runtime metrics are `examples`, `average_loss`, `exact_match_rate`,
`heldout_examples`, `heldout_present_examples`, `heldout_absent_examples`,
`heldout_exact_match_rate`, `heldout_present_recall`,
`heldout_absent_specificity`, and corresponding `candidate_heldout_*` fields.
Both held-out strata and finite valid denominators/rates are mandatory.
Publication requires the configured training exact-match floor and no decrease
in held-out exact-match, present recall or absent specificity. Do not fabricate
contextual safety/severity/action metrics for binary training.

After genuine publication and cache refresh, score each accepted candidate on
validation for retention: recall >=90% and strict specificity improvement over
its fitted base; rank eligible updates by validation specificity, recall, then
seed ascending. Persist each profile's selection decision before scoring its
fixed selected endpoint on development. If none improves validation, retain its
base; do not run extra cycles, retune thresholds or learn from development errors.
Threshold remains fixed through updates. No regression guard by itself establishes
that unseen privacy cases are safe. Restore the original selected contextual
artifact and record restoration even after partial runs/errors.

## Validation and evidence requirements

Before fits, test Python/Go config and tensor acceptance equivalence, bounded
profile manifests, Unicode/token/TF-IDF parity, sigmoid/float32 handling, immutable
candidate reconstruction, enum/error validation, streamed identities/cache refresh,
frozen/stale/malformed update rejection, grouped/text leakage guards, replay
conflicts and receipt recovery. Run legacy contextual suites unchanged. Integrated
Docker checks must verify exact post-update candidate fingerprints and inference.

Every phase refuses output reuse and records source commit, protocol/input hashes,
container identities, software/thread versions and warnings/errors. Archive exact
fit selections, release/update artifacts, request/response receipts, raw reports,
recomputed confusion counts, family metrics and restoration records. Failed cycles
remain in denominators. Source-family imbalance/style effects remain limitations;
missing class metrics are null, not fabricated perfect rates.

Any contextual integration would require a separate prospective policy protocol,
independently labelled public/fictional/private contrast pairs and action/severity
checks. This presence study cannot rename the original pipeline goal, meet its
completion evidence by changing task semantics, or claim final results.
