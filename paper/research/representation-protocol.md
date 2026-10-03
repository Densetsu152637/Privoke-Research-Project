# Prospective frozen-representation diagnostic

Recorded 3 October 2026 before preparing or fitting these probes. The preceding
goal turn made progress: nine independent negative-coverage attempts, one stopped
additional cycle, audited restoration, methodology draft and a verified package.
The current selected pipeline reaches90.53% recall and29.41% specificity; the
required90% specificity remains unmet. Final498 remains unscored.

## Question and boundary

Can fuller binary fitting discriminate annotation-positive and clean public text
using the original frozen32-dimensional encoder representation? The latest
negative-heavy head updates mainly trade recall for specificity. Compare a fitted
binary probe with the original heads to distinguish an underfit-head explanation
from a representation limitation. This bounded diagnostic cannot prove that all
possible training methods fail, establish contextual sensitivity/action quality,
or validate a production replacement.

No serving artifact, encoder, gate or fuzzer loop changes. Use the current local
CPU runtime implementation to export normalized original-model pooled features
and binary predictions, without accessing its serving cache or publishing weights.
The ordinary evaluator retains its existing scoring role; separate diagnostic
tools live in evaluation and explicitly label these reference fits as offline.

## Protected data and grouping

Use the same pinned PIIMB revision and full-population English loader as the
negative-coverage study. Exclude all locked development/final groups, IDs and
shared normalized training-text keys, plus43 bootstrap text keys. Discard normalized
conflicting labels and duplicates before selecting2,400 positives and2,400 clean
sentences using seed5102026. Refuse an undersized class. Record source counts,
exclusions, IDs/groups/text digests and every partition hash.

Reserve20% of the selected source groups for probe validation, using seed6102026
to shuffle sorted group IDs; round the group count upward. Keep all siblings
together. Require at least50 members of each truth class in both partitions;
fail closed rather than silently inventing rows or changing the split. No bootstrap
sample is a fitted/validation example. Earlier unused-source training rows may
recur; this is another custom within-corpus diagnostic, not an independent corpus
or official untouched PIIMB test. Group/text exclusions do not prove semantic
independence or establish contextual nonsensitivity from annotation absence.

## Predefined fitting and selection

Fit only annotation-presence binary targets, without inventing sensitivity,
visibility or category ground truth. Use a StandardScaler fitted on probe training
features and logistic regression with C in0.1,1,10, balanced class weights, lbfgs,
max_iter1000 and seed7102026. Record actual package versions, convergence and
configuration. A non-converged fit is ineligible and retained as a failure.

For each converged fit, choose the threshold maximizing validation specificity
subject to validation recall>=90%, using the exact distinct validation scores
(include0 and1 boundaries). Ties prefer higher recall and then higher threshold.
Choose among fits by validation balanced accuracy, then specificity, recall and
lower C. Freeze that choice before any development scoring. Report all validation
configurations and development outcomes; do not choose a different configuration
because its development score is more favorable.

First require the original offline development binary predictions to match every
archived live original semantic prediction on the same502 locked IDs/truth/groups.
Fail closed on mismatched keys, labels, groups, hashes, missing/error rows or binary
disagreement. Validate feature dimensions, finiteness and partition/text/group
integrity before fitting. Then score the frozen probe on development, alone and
with the archived revised rules+NER union. Verify that union's locked keys and
rule-source hashes; identify it as a reused-output diagnostic, not a live pipeline.

## Execution amendment — 4 October 2026

This amendment was recorded before any valid probe fit. Attempt v1, source
`14ab578`, stopped during Windows text transport: the default cp1252 encoding
could not encode U+202F. It stopped before feature export or fitting. Attempt v2,
source `2608b89`, used UTF-8 transport and completed preparation and feature
export, but the fitter rejected the training partition at its unique-ID gate.
The prepared train split had 3,837 rows and 3,836 distinct source IDs; all 3,837
normalized text keys were distinct. One upstream source ID therefore referred to
two distinct normalized texts. The v2 fit record has no fit entries and no
validation selection or development probe scores. Its failure is a provenance
gate outcome, not accuracy evidence.

For a fresh v3 preparation, after protected-source exclusion and normalized-text
deduplication/conflict removal, count distinct normalized text keys per eligible
source ID. Exclude every eligible row for any ID associated with more than one
distinct normalized text key, and record ambiguous-ID and excluded-row counts in
the preparation manifest. Then retain the original requirement to select 2,400
positive and 2,400 clean rows with seed 5102026, split groups with seed 6102026,
and preserve all locked ID/group/text-key and bootstrap exclusions. Require and
record unique ID and normalized text keys in each resulting partition. This is a
deterministic eligibility correction motivated by input-integrity validation,
not by model performance. V3 must use fresh prepared, feature and fit output
paths; do not reuse v2 features or fit inputs.

The archived semantic reports use the integer `0`. The fitter accepts exact
integer `0` or an empty list for compatibility; reject booleans (including
`false`) and all nonempty error collections. No valid fit or
development probe outcome is available yet; execute the amended protocol only
after the corrected preparation/fitter is integrated and revalidated.

## Evidence and next decision

Preserve raw probabilities/predictions, exact counts and class denominators,
validation selection, fitted scaler/coefficients, feature/model/source identities,
and all errors in fresh output paths. Record thresholds as annotation-presence
diagnostics, not deployment privacy policies. Use development source-group paired
comparisons where applicable; uncertainty after this search is descriptive.

If the selected probe's diagnostic pipeline attains both90% development targets,
investigate integration and policy validation under a new recorded protocol before
publishing anything. If it improves specificity while retaining90% pipeline recall,
investigate an appropriate bounded binary head/update interface; do not silently
substitute the probe for the fuzzer-trained semantic classifier. Otherwise do not
repeat identical cycles: inspect representation/data/task limits and a separately
evaluated representation control. These outcomes determine the next experiment,
not whether the paper can be called complete.

Final scoring, contextual confirmation, installed-extension enforcement, client
costs, artifact reproduction and measured paper/figure integration remain required.
