# Prospective exploratory semantic presence cascade

Recorded before live cascade validation or threshold calibration. This is a
separate opt-in policy experiment, not a deployment change or completion claim.
The default contextual pipeline, regex/NER rules, selected serving artifact and
existing failure policy remain unchanged. No new training is performed.

## Question, controls and fixed artifacts

Test whether suppressing only the original semantic contribution when a learned
annotation-presence gate predicts ABSENT improves the full pipeline's binary
annotation proxy, and expose contextual/action regressions independently.
PRESENT does not assign sensitivity, visibility, category or an action.

Two contextual controls are mandatory: original balanced v0.3.0 checksum
`8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c`, and the
currently selected v0.3.0+train.1 checksum
`8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015`.
Each pairs with the efficient, balanced and quality fitted presence release
bases from the completed model-refactor manifest. All six comparisons are fixed;
head updates are excluded because the preceding nine-attempt study retained no
updated candidate. Archive artifact bytes/checksums/float32 fingerprints, original
fit provenance, source revisions and actual container Image IDs separately.

The original-control three cascades are the primary exploratory comparisons.
The current-control three are diagnostic references: its public-negative
curriculum overlaps validation. A read-only pre-study audit compared 2,443
templates against validation968 and found 40 exact example-ID matches and 40
normalized-text matches, all absent-labelled validation rows; 190 distinct
declared source groups also overlap. Curriculum SHA-256 is
`61b0d5c5f06fe0d948092f86044eb21c64a08c5f6d4f60ec6ecfb1466d42ecda`.
Current-control calibration is therefore not held-out evaluation. Retain all
rows and disclose the overlap; no post-hoc exclusions change the primary sample.

## Runtime and failure contract

Use explicit per-request SemanticPresenceGate, never a global default. Both
semantic and presence inference execute whenever semantic succeeds and is not
skipped by the existing regex BLOCK shortcut. A failed semantic execution records
presence NOT_RUN and preserves the visible semantic error. Gate PRESENT retains original
semantic results; ABSENT removes only those results before fusion. Regex/NER
findings and their independent enforcement cannot be weakened. Presence errors
retain original semantic findings and expose a layer error; semantic errors are
never hidden by a presence negative. Record raw semantic findings and typed gate
status, probability, stored model threshold, explicit decision threshold and both
model identities even when the retained semantic result list is empty.

## Data and prospective calibration

Use the audited prepared-v3 validation968 (475 present/493 absent), SHA-256
`d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1`, and
development502 (264 present/238 absent), SHA-256
`45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706`.
Join every unique ID, boolean truth and source group. No fitting, vocabulary
changes, new cycles or development-driven threshold/profile selection is allowed.
Development has already informed the research process; this is exploratory,
not an untouched generalization estimate. Final498 is never opened or scored.
Its previously pinned digest is provenance only; root verifies it separately.

Collect all six validation comparisons before calibration. For each row call
ordinary full pipeline, explicit gate threshold zero, and regex+NER control.
Threshold-zero output must equal ordinary classification/action/layer results
apart from timing and the added gate trace. Regex+NER results must equal the
corresponding findings within the full pipeline. Those actual API outcomes give
the PRESENT and ABSENT projection branches without reproducing runtime policy.
Extra control-call costs are separate from cascade request latency.

Consider decision thresholds 0, 1, every distinct observed probability, and its
next representable larger float within [0,1], because prediction uses >=.
Maximize projected FULL-PIPELINE validation specificity subject to recall >=90%;
ties prefer higher recall then higher threshold. These are request gate decision
thresholds; presence-model stored thresholds and head parameters stay unchanged.
Persist all six selected thresholds and input/report hashes exclusively before
any development request. If a pair cannot satisfy the recall floor, freeze its
ineligible status with the full candidate grid, then record selected validation
and development as skipped. Continue other eligible comparisons; diagnostic
ineligibility cannot block an eligible primary comparison. Never invent a threshold.

Rerun each selected threshold live on validation and require exact per-row
classification/action agreement with its projection, identical detector findings,
expected identities and zero errors. All six choices must have completed parity
reports or frozen ineligible skip records before development. Then measure every
eligible fixed live development endpoint with matched
ordinary controls. Record the fitted-artifact-threshold projection separately as
retrospective projection, never as an actual live measurement. No further tuning
or default promotion follows from development results under this protocol.

## Metrics, safety evidence and stopping

Primary binary proxy is aggregate sensitivity != S0 OR nonempty categories,
matching the existing evaluator; WARN/BLOCK intervention is a separate outcome.
Retain raw protobuf payloads, per-layer results/errors, truth/groups/IDs, paired
lost/gained detections, action transitions, source-family counts/rates, confusion
counts, recall/specificity/balanced accuracy and runtime median/p95. Missing class
denominators are null. Record model parameter/feature/byte costs independently;
internal request timings are not browser/bridge latency. Group-bootstrap 95%
intervals are desirable descriptive evidence; the bounded caller reports them
as uncomputed and makes no significance claim. No-error execution is
required but does not certify correct contextual labels or safe policy.

Before deployment, a separate frozen contextual contrast set needs two independent
human annotators, a sensitivity/visibility/category/action rubric, explicit supplied
visibility, unknown/ambiguous labels and adjudication. Include public biographies,
fiction/quotes, general medical advice, private personal/third-party disclosures,
credentials, implicit disclosures and long/mixed text. Group by template and
transformation lineage. Existing authored examples are regression checks, not
independent contextual truth. Require no loss on adjudicated private WARN/BLOCK
cases; report disagreements and any suppressed private semantic-only findings.
Root owns annotation/review gates and exact contextual artifact restoration after
every checkpoint group or failure. This study does not promote any default.
The original research targets and completion evidence remain unchanged and unmet
unless measured full-pipeline results and the separate evidence gates establish
them. Stop after these fixed comparisons; preserve null and failure results.
