# Research methodology draft

Prepared 3 October 2026 for the internal review manuscript. This text records the
implemented evaluation design. Final-test results, deployment measurements and
human confirmation remain pending. Update those statuses before incorporating
the text into the paper; do not present development results as final findings.
Use the [writing guide](research-paper-writing-guide.md) and the versioned
[protocol](../paper/research/protocol.md) together with this draft.

## Research questions and evaluated system

We investigate the contribution of individual detection layers and bounded
classification-head updates to prompt-level detection. We evaluate rules, named
entity recognition (NER), a local semantic classifier, rules combined with NER,
and the complete pipeline on matched inputs. The measured semantic backend
streams model parameters to a local CPU runtime. Hosted semantic inference is
outside this experiment.

The original balanced artifact is version v0.3.0, with two encoder blocks,
hidden size32 and context length96. Its encoder is randomly initialized and
frozen; the original heads are fitted using43 authored bootstrap examples.
It is not a pretrained language encoder. Artifact checksums and parameter
fingerprints identify the evaluated weights, because separately trained models
can share a version string. Source revisions and Docker image identities are
recorded separately from model identity.

## Data, labels and protected partition

The public binary study uses English sentences from PIIMB at revision
`4a13e9ffe6fd0d275efbde8afd4d8d8f1ffc2133`. The initial selection uses seed3102026,
exact-text deduplication, conflict exclusion and source-document grouping. The
1,000 selected rows are partitioned into502 development rows, comprising264
annotated-positive and238 clean rows, and498 final rows, comprising236 positive
and262 clean rows. Source groups are disjoint across the two partitions. Locked
input hashes and row/group provenance are retained with the experiment records.

The binary reference label denotes the presence of an annotated entity. A system
prediction is positive when it returns sensitivity S1–S3 or any category,
regardless of its ALLOW/WARN/BLOCK action. This definition does not measure exact
spans, private contextual disclosure, visibility, category accuracy or action
correctness. In particular, public names and dates may be annotated entities, and
absence of an annotation is not independently verified contextual nonsensitivity.

The final partition has not been scored. Development comparisons determine rule
and model choices. Final scoring will occur after those choices and the planned
analyses are frozen; final failures will not be used to revise this study's model.
Synthetic measurements support debugging and controlled checks, with their
template-overlap limitations reported separately.

## Comparisons and development selection

Each comparison uses identical row IDs, labels and source groups. The independent
baseline is Presidio's English analyzer with spaCy `en_core_web_sm` and score
threshold0.5, without PriVoke rules. This NLP model is smaller than the upstream
default large model, so this configuration is not presented as the strongest
available Presidio baseline. Results from unlike datasets or label definitions
are not ranked as directly comparable measurements.

The user-defined development targets are at least90% sensitive recall and90%
clean specificity, together with the completion plan's other evidence
requirements. These practical targets are not IEEE acceptance requirements.
All attempted configurations, update rejections and protocol amendments remain
in the evidence ledger. The original template-update extension and the subsequent
public-negative study use different prospectively documented selection criteria;
their results are not retroactively reselected under one criterion.

The [public-negative protocol](../paper/research/public-negative-protocol.md)
tests2,400 annotation-negative sentences plus all43 bootstrap examples. It
excludes protected development/final groups, IDs and normalized text keys, as
well as conflicting normalized labels. Three independent seeds,42,1337 and2026,
start from the original artifact at learning rates0.03,0.1 and0.3. Each first
cycle uses256 prompts, no transformations and max-gradient0.05. The fuzzer samples
templates deterministically and has no generation-temperature setting. Training
and internal guard inputs use the same canonical normalization as serving.

Every update retains the existing publication and safety checks, including the
16-example internal guard. Declared source groups keep held-out siblings out of
training. That guard is distinct from the public development and final sets.
Selection maximizes pipeline specificity subject to at least90% recall and
specificity no lower than54/238; ties prefer recall, fewer cycles, lower learning
rate and lower seed. Only a gain of at least five percentage points can trigger
up to two further cycles, under the protocol's stopping rules. Semantic recall
losses are reported even when the pipeline satisfies its aggregate recall floor.

PIIMB exposes an upstream split named `test`. Training on unused source documents
from that corpus makes the new experiment a custom within-corpus study, not an
untouched official benchmark-test score. Source and normalized-text exclusions
reduce specific leakage risks but do not prove semantic independence. Public
negative S0/PU training targets are provisional policy labels. Training-path fixes
also distinguish this study from earlier source revisions.

## Outcomes, uncertainty and reproducibility

Report TP, TN, FP and FN with class denominators, recall, specificity, balanced
accuracy, F1/F2, evaluated coverage and runtime errors. Eligibility requires all
502 matched development rows to complete without errors. Confusion counts are
recomputed from archived raw predictions before selection is accepted.
Use paired source-group bootstrap comparisons with2,000 resamples and95%
intervals, retaining the seed and grouping definition. Training seeds are
independent update restarts, not additional independent test samples.
Development-selected comparisons are descriptive and disclose the search;
their intervals do not establish confirmatory significance. Precision from the
selected class mix is not deployment precision.

Archive dataset, configuration, source, service-image, artifact and report
identities, including failed attempts and restoration outcomes. Test callers
and experimental orchestration are in `evaluation`; component tests and the
fuzzer's training implementation remain with their components. Local evidence
packages are verified by per-file hashes and archive integrity checks. Raw-data
redistribution requires a separate source-license review.

## Evidence still required for broader claims

The current Chromium fixture measures the shipped page hook using a controlled
decision broker and a real loopback receiver. It does not establish installed
extension/native messaging behavior, real-provider coverage or deployment
latency. ALLOW and WARN forward the original request; BLOCK cancels it on the
tested supported path. Installed-extension captures and warm/cold end-to-end
latency and resource measurements remain required for broader systems claims.

Contextual/action labels and this agent's methodological assessment are
provisional pending professor [git4san](https://github.com/git4san) confirmation.
No two-human-annotator agreement is claimed. Telemetry claims are limited to the
documented event-level local differential privacy mechanism and its assumptions;
event presence, exact report counts, transport metadata and model training lie
outside that guarantee. No measured usability or telemetry-utility benefit is
claimed without corresponding evidence.
