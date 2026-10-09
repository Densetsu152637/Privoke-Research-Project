# Fuzzer curriculum improvement process and results

The amended semantic-only comparison is complete and audited: 63 cells, 900 live attempts (615 accepted publications, 285 held-out rejections) and 360 separate offline steps. Specificity and clean-control gains coexist with recall loss and casewise harms; no candidate qualified or was promoted. The [completed results](#completed-semantic-only-results) and [safe aggregate evidence](evidence/curriculum-improvement-20261009/README.md) follow the preserved implementation and amendment history.

The revised curriculum and seeded sampler address two separate limitations of the earlier combined training run: narrow template variation and deterministic allocation that ignored the request seed. This record preserves the implementation, controlled comparison and limitations. Implementation alone does not establish improved model quality. The earlier six-hour run increased balanced pipeline specificity from 22.27% to 36.55% while recall fell from 93.56% to 87.50%; those results motivated further experiments and did not qualify a model for promotion.

The user's implementation objective was: “Implement your suggestions. Make sure you document this process as we can use this data to discuss how we improved”. The record separates implemented changes from measured outcomes so later discussion can include improvements, deterioration and unresolved effects. The conversation interface did not expose the original message timestamp.

## Source and resource commitments

Implementation started from `85bf44726f78227c7f8ef22ec3d7098135b406b7` on `feat/dev-testing`. The original resource and v1 rendering remain unchanged. All three reviewed JSON resources use explicit byte-preserving Git attributes so their exact reviewed CRLF byte commitments survive staging and checkout. A pre-freeze Git-blob audit found that text normalization had stored LF blobs despite the reviewed CRLF working bytes; the attribute repair preserves the reviewed bytes without changing any JSON content or experiment targets. The audit is retained in `evaluation/results/curriculum_improvement_20261009_core/git-resource-byte-audit.json`.

| Resource | SHA256 |
| --- | --- |
| `evaluation/datasets/synthetic-teacher-templates.json` | `b6257d9166e6e435105e1fc914c169e0f31990f4a4671adc93ead0addf1d80e6` |
| `evaluation/datasets/synthetic-teacher-templates-v2.json` | `044b94cc9a0723b3ad196c9060db690560f37d3a15dba67db6bc9d48fdeb1583` |
| `evaluation/datasets/contextual-assessment-20261009.json` | `4b90449d9ca625b2eaa498ae1af2542dc1632a79ea2733356c86a19035e5a435` |

V2 has 28 authored situations, four sibling values, two contextual classes and three roles: 672 training rows. Each role has 112 controls and 112 disclosures. Evolved rows have complete authored renderings, rather than only a cosmetic prefix and suffix. Contrasts include disclosure versus discussion, actual versus fictional quotation, asserted versus hypothetical facts, and restricted records versus public generic guidance. Four sibling values remain correlated examples, not four independent situations. All labels remain `assistant_provisional`; separate assistant critique is not human adjudication.

The 16 guard rows and 64 replay rows retain the original texts, targets, IDs and provenance for a common generation seed. Initial independent assistant critique identified mistaken visibility interpretations: P4 denotes unshared personal material, P3 closed group sharing, and P2 explicitly authenticated material. The revised journal, meeting, credential and protected-record cases were corrected before freezing. Comparable politics/religion and financial cases retain the original severity convention. These corrections apply to the revised resource; the historical resource and its reported experiment are preserved.

## Exposure distributions

Both training resources contain S0/S2/S3 counts of 336/84/252. Category counts are multilabel occurrences, so their sum exceeds the disclosure count. The package changes visibility and category exposure as well as wording; its effect cannot be attributed solely to semantic diversity.

| Target | Original train | Revised train |
| --- | ---: | ---: |
| P0 | 72 | 156 |
| P2 | 60 | 120 |
| P3 | 60 | 132 |
| P4 | 60 | 24 |
| PU | 420 | 240 |
| HEALTH | 72 | 72 |
| POLITICS | 24 | 24 |
| RELIGION | 36 | 36 |
| CRIMINAL | 36 | 36 |
| FINANCIAL | 48 | 60 |
| SEXUAL | 24 | 24 |
| CHILD | 36 | 36 |
| LOCATION | 36 | 36 |
| IDENTITY | 60 | 84 |
| THIRD_PARTY | 84 | 168 |

The separate assessment contains 64 rows in 32 paired scenario groups: 32 S0, seven S2 and 25 S3; visibility counts are P0=13, P2=14, P3=9, P4=2, PU=26. Category occurrences are HEALTH=10, POLITICS=4, RELIGION=4, CRIMINAL=4, FINANCIAL=5, SEXUAL=3, CHILD=2, LOCATION=2, IDENTITY=3, THIRD_PARTY=12. Full split inventories are retained in `evaluation/results/curriculum_improvement_20261009_core/inventory.json`.

## Sampler and replay controls

The default `deterministic_v1` retains the original family order, cursor namespace and receipt fingerprint behavior. `seeded_family_v1` uses an explicit stable `curriculum_sampler_seed`, independent of the trainer seed that changes each cycle. For each stratum and epoch, SHA-derived randomness permutes family order and descendants. Each round visits families before revisiting their next descendants. Role/class quotas remain fixed. The row stream is permuted without replacement within an epoch; at epoch boundaries, IDs already in the current batch are consumed and skipped to preserve batch uniqueness. This can make cursor advances larger than the number selected.

SQLite binds seeded cursors to manifest, model, policy, seed and stratum. Allocation and cursor advances commit together; repeated requests reuse reserved IDs after restart. Conflicting retries fail without another allocation. Gate rejection still consumes its reserved batch. Audits include policy, seed, per-stratum start/stop positions and epochs, training/replay ID digests and the replay weight. Seeded reservation fingerprints additionally bind effective count, replay fraction and caller fingerprint. Deterministic legacy reservations remain readable.

`FUZZ_TRAINING_REPLAY_WEIGHT` defaults to 0.35 and accepts finite values in (0,1]. It is a relative example weight, distinct from `FUZZ_CURRICULUM_REPLAY_FRACTION` (default 0.25). With 192 new and 64 replay rows, weight 0.35 gives replay 22.4/214.4 = 10.45% of nominal total example weight; weight 1.0 gives 25%. This is a nominal weighting calculation, not a measured gradient contribution. Effective trainer configuration is bound by the service receipt fingerprint.

## Controlled experiment specification

The primary planned matrix uses three profiles, original/revised training data, deterministic/seeded allocation, and seeds 42,43,44: 36 arms. Each restores the same profile base, uses 20 attempted cycles, no mining, learning rate 0.003, zero transformations, identical gate/replay, row budget and replay weight 0.35. Record attempts, rejections and runtime errors; accepted updates are an outcome, not a fixed budget. Use endpoints 0 and 20 and preserve exact source, model, image, configuration, request and response commitments. Deterministic arms may produce identical allocations or weights across seeds; they are reproducibility replicas, not necessarily independent training realizations.

Nine additional revised/seeded arms vary replay weight to 1.0, outside the primary data/sampler comparison. Representation experiments are a separate comparison with matched data and optimization; they must not be pooled with the online matrix. No model promotion follows automatically from any of these experiments.

The contextual endpoint is frozen before scoring and stored separately from `train`, `heldout` and `replay`; it never enters the publication gate or mining. Preparation checks its IDs, declared groups and normalized texts against the curriculum, opaque protected union and pinned development input. The experiment supervisor must additionally validate it against both curriculum versions using `build_assessment(resource, [original_pools, revised_pools])`. The existing annotation-presence development endpoint remains a separate outcome and is not relabeled as contextual privacy truth. Protected final input is neither needed nor opened.

This is an independently authored scenario regression assessment with overlapping semantic archetypes, not a test of entirely unseen semantic families or broad generalization. Declared assessment groups, parent IDs and exact normalized texts are withheld; within-assessment family bootstrap units do not prove independence from training. Four positive cases test actual disclosure under public wording, quotation of an actual third-party fact, hypothetical framing containing an asserted actual itinerary, and mixed generic discussion plus actual disclosure. V2 has clean quotation/hypothetical/discussion contrasts but does not explicitly train those four positive mechanisms; report their outcomes separately. Both resources operationalize a clean contextual control as S0 with empty categories, so topic category presence is not itself contextual disclosure truth.

## Historical core validation milestone

Focused validation uses the existing host study environment with `PYTHONPATH=evaluation`. Windows sandbox temporary-directory atomic replacement failed in the default OS temporary path; setting `TMP` and `TEMP` to the task's ignored results `test-temp` directory allowed the existing controller fixtures to run. Initial new tests also compared classification objects by identity and left a SQLite connection open; their assertions now compare packed targets/text/metadata and explicitly close the connection.

The focused suites passed: 14 curriculum/config tests, 14 synthetic-resource tests and 16 continual-controller tests. They cover seed-dependent allocation, reproducibility, epochs/restart, within-batch uniqueness, balanced quotas and fair family visits, conflicting retries, independent cursor namespaces, invalid configuration, contextual facts/token capacity, exclusions and separation. Logs are under `evaluation/results/curriculum_improvement_20261009_core/` as `curriculum-tests.log`, `synthetic-tests.log` and `controller-tests.log`. Live training and quality conclusions were pending at this core milestone; the completed amended results are recorded below.

Paper alignment initially belonged to the root integration writer; the semantic-only amendment updates the affected prospective methods under the serialized EX-4 assignment. Affected text is `paper/main.tex` around line 191 (curriculum allocation/replay), line 245 (study commitments), line 324 onward (new results only after measured runs), and line 524 (limitations and unresolved component effects). Existing historical result numbers must remain unchanged.

## Historical v1 execution and evidence contract (superseded by semantic-only v2)

This section records the original combined-detector v1 protocol. It is historical;
the semantic-only v2 amendment below defines the current primary endpoint and
eligibility. The current runner refuses v1 execution.

`evaluation/run-curriculum-improvement-study.py` separates protocol preparation,
execution and read-only raw-evidence auditing. Preparation refuses dirty computation
sources, binds the source commit and all computation/input file hashes, validates
both curriculum exclusions, and attests copied source bytes inside the immutable
serving images. The reviewed resources above remain byte frozen. Each of 63 cells
uses a fresh Compose project with five named volumes; the runtime's otherwise
anonymous data mount is mapped to its owned client-state volume. Execution is
sequential, with automatic updater requests disabled and actual server settings
checked against the prospective protocol before the first endpoint RPC. Existing
projects and normal service images are preserved.

Every cell starts at the exact checked-in artifact bytes and float32 parameter
identity for its profile. Development, contextual and fixture baseline predictions
must match other fresh cells of that profile before training. The controller then
records 20 attempts regardless of rejection, with trainer seeds 1337–1356 and a
separate stable sampler seed. The auditor reconstructs every SQLite allocation,
quota and cursor consumption, including rejected reservations, and checks all
accepted publication payloads and durable receipt rows. Every live round must
retain all encoder tensors exactly. An unknown RPC outcome reuses its exact
pending request ID; replay-only acknowledgments are reconciled to durable update
metadata while preserving the original response and recording recovery counts.

The contextual primary endpoint is **pipeline joint exact agreement on sensitivity,
visibility and category set** across the independent 64-row/32-family assessment.
Eligibility requires no decline in that metric, pipeline annotation-presence recall
at least 90%, strict pipeline specificity improvement, and no newly incorrect or
worsened restriction on any eligible fixture case. The 41 quantitative fixture
cases use their explicit allowed actions and visibility hints; seven ambiguous
cases remain descriptive. Existing baseline failures remain visible, including
the efficient profile's failed recall gate. Sensitivity, visibility, category exact
agreement, action accuracy, under-restriction and over-restriction are reported
separately for semantic and pipeline outputs. Four hard-positive contextual
mechanisms are also reported separately. Semantic degradation is retained even
when a pipeline detector masks it.

Per-profile contrasts are B−A and D−C (curriculum package), C−A and D−B (sampler),
(D−C)−(B−A) (interaction), D−A (combined package), and E−D (separate replay-weight
sensitivity). Individual seeds, means, ranges and sample standard deviations are
reported; deterministic replicas may be identical and are not independent trials.
Paired source-group development and declared-family contextual percentile
bootstraps use 2,000 replicates and seed 10102026. These intervals describe endpoint
sampling uncertainty, not uncertainty estimated from three seeds. Profiles are
never pooled into one quality estimate.

## Separate offline representation comparison

`evaluation/fit-contextual-representation-arm.py` uses the existing
`InHouseTransformerTrainer` mechanics with fresh parameter copies and a fresh Adam
optimizer for every profile/seed/mode cell. Each `head_only`/`end_to_end` pair shares
the same shuffled revised TRAIN schedule, seed 42, 43 or 44, and 20 batches of 32:
640 presentations, a partial epoch of the 672-row pool. Exact unique-row and family
exposure counts are retained. Both modes use learning rate 0.001, weight decay
0.0001 and gradient norm clipping at 1.0; they use no replay, publication gate or
transforms. This optimizer/budget differs from the online fuzzer comparison and
its effects are reported separately.

Exports preserve the existing model tensor contract and pass artifact validation
and independent NumPy inference parity before loading into isolated study storage.
The auditor recomputes tensor changes from the baseline and exported artifact,
requires frozen encoder tensors in `head_only`, requires encoder change in
`end_to_end`, checks optimizer-state hashes and paired schedules, and measures the
same endpoints at 0 and 20. Provisional labels do not become independently verified
because the trainer accepts them. This implements a bounded offline representation
experiment, not an online full-encoder update or a promoted replacement.

## Integration validation status

The new matrix/scorer suite passed 17 tests, the integrated continual controller
passed 16 tests, and periodic requester tests passed 11 tests. Tests cover exact
baseline rejection, source/configuration drift, paired truth/group mismatches,
casewise harms, fixture ALLOW-only actions, visibility-hint forwarding, poisoned
rejected allocations, independent multi-round cursor reconstruction, exact pending
request continuation, replay-only metadata reconciliation and archive tampering.
Actual CPU-image export/parity validation passed one integration test covering
both training modes using wholly synthetic dummy rows; it does not access the
frozen study training data or endpoints. Runtime dependency
probing found no Torch in the existing serving image, so a dedicated CPU training
image was built from the pinned CPU requirements. Source overlays preserve normal
service images. Build and test evidence is retained under the ignored core-results
directory. Source/protocol acceptance and execution authorization were still
pending at this integration milestone; the amended matrix has since completed.


## Semantic-only v2 amendment (10 October local time)

The user instructed: “when running the pipelines for testing the LLM layer,
ensure you are running them only with the LLM layer (and in the future as well)”.
The conversation interface did not expose the original message timestamp; v2
records it as unavailable, separately from amendment preparation time and the
verified cessation at 2026-10-09 13:16:03.311119 UTC. The v1 supervisor and
controller were stopped with no pending training request. Fifteen efficient
cells completed 300 resolved attempts; no balanced or offline cell started.
The final efficient E44 endpoint/archive completion raced with stopping and is
retained honestly in `semantic-only-pause-checkpoint.json`. That explicit record
annotates the interrupted study outside immutable cell archives. V1 protocol
`0892e64651a59d279aafa8975cca90cc337e769509853bd84cd5c0d1e83ad713`, source
`4b71dc504d71d71f7159279911f9cd839ab72e7d`, archived combined-detector outputs
and historical eligibility are preserved; the new runner refuses v1 execution.

V2 uses a separate output directory, protocol and source commitment. Its import
manifest pins the original protocol and pause-record hashes, fifteen cell IDs,
archive hashes and original project/image provenance. Only the isolated semantic
views enter amended analysis: 18,420 successful observations, each with exactly
one successful semantic layer execution. Import validation rejects missing,
changed, unsuccessful, empty or mixed-layer evidence. Original v1 execution
provenance remains authoritative for operation settings, allocation cursors,
publication receipts, model chains and exact baseline bytes. Metrics are computed
after selecting semantic views; historical pipeline scores are not reinterpreted
as LLM results. The remaining 48 cells execute prospectively with fresh v2
projects/volumes and explicit nonempty semantic-only RPC selection. Returned
execution must contain exactly one successful semantic layer. Controller
checkpoints and mining default to semantic only, and their resume configuration
binds that choice. Unknown v2 request outcomes retain exact-ID recovery.

All 63 profile/seed/arm budgets remain: 900 live attempts and 360 separate offline
steps. V2 reuses the original prepared manifests and train/replay/guard/assessment
byte commitments. Training targets and schedules are unchanged. The primary is
now **semantic joint exact sensitivity/visibility/category-set agreement**;
qualification requires semantic recall at least 90%, strict semantic specificity
gain, no primary decline, and no newly incorrect or worsened semantic action harm
on any eligible fixture. Sensitivity, visibility, category exact agreement, actions
and hard-positive mechanisms remain separate. Profiles/seeds and paired group
bootstraps use the same prescribed contrasts. This criterion changed after fifteen
observed cells, so neither the imported views nor the complete amended study are
untouched confirmation. No candidate is automatically promoted. Same-profile
semantic baselines must match across imported and prospective origins. Runtime
and latency comparisons are not pooled across those origins.

The prerequisite CI-4 changes make semantic-only test defaults explicit and reject
unexpected executed layers. CI-5 revises the conversational chat prompt and its
output compatibility following the user's request, “can you also revise the prompt then”.
The exact canonical object `{"results":[]}` is a valid clean response; complete
S0 findings remain compatible. Other malformed empty forms still fail validation.
Eleven chat prompt/compatibility contract checks passed. A later matched host
baseline check reproduced the same three regex-masking subcase failures on
`4b71dc5` and `7c0322d`, with the same interpreter, tests and dependencies:
all six observations lacked `presidio_analyzer`, returned BLOCK and had null
masked text. These observed dependency-setup failures precede the prompt revision;
they are separate from semantic accuracy evidence. Correct masking with the
required dependencies remains unverified. The local comparison handoff hash is
`ceec6095fe50441aa8c7349d39986309d5af19dc8e4ca40ffb92934071d97673`.
Actual chat-model accuracy is unverified. The Tiny classifier and its trainer do not
consume the conversational prompt. Scoped source comparison verifies the semantic
gradient function's AST, training caller, guard, training modules and Tiny inference
remain unchanged from v1. Six changed chat/testing files are recorded explicitly.
New fuzzer/runtime source overlays are therefore versioned environments, rather
than a claim of byte-identical images. Copied serving source files are attested
inside immutable images; updater/model/telemetry/offline images are retained only
where unchanged. New TRAIN authoring ideas belong to a later separately frozen
experiment, not this amendment.

EX-4 validation logs and source/image provenance are retained under
`evaluation/results/curriculum_improvement_20261009_amendment/`. At this implementation
milestone the focused matrix/amendment suite passes 26 tests and the controller
suite passes 17 tests, including tampered imports, empty/mixed layer execution,
semantic casewise qualification, cross-origin baseline poisoning, and exact pending
request recovery. Image attestation validates 45 fuzzer, 26 updater and 80 runtime
computation files. Actual archived import admission validates all 18,420 semantic
observations without issuing new quality RPCs. Source/protocol acceptance and the
48 prospective cells were pending at that implementation milestone; those checks
established contracts, and the completed quality measurements follow below.

## Completed semantic-only results

The amended study completed on 9 October UTC (10 October Sydney time) and passed
the full raw audit. All 63 cells completed: 15 imported efficient live semantic
views and 48 prospective cells. Execution used source
`7c0322d6872e7b99ed88d1bc5bd67f2d0b9623a4` and immutable execution protocol
`f631c6078c439f9f7ff616e29f9c3d09ad36e22f079d2cdeed16a7fb459fc602`.
The documentation publication revision is later and does not replace these
execution commitments. The semantic import manifest is
`8d43fd5d0fda1a6e73b7796cfc0b2585c09ef2d8080c5973b0e23a70f06c5bfa`.

The 45 live cells resolved 900 attempts: 615 accepted publications and durable
receipts, and 285 held-out rejections. Efficient and balanced each accepted
300/300 attempts. Every quality arm/seed accepted its first attempt and rejected
the remaining 19, for 15/300 accepted. All 285 rejected responses have code
FAILED_PRECONDITION and message “Candidate model is worse on the held-out
evaluation set.” Their wrappers contain zero generated prompts and empty
metadata, but all reservations consumed their allocated rows: 5,120
presentations per live cell, 230,400 in total. Exposure is an allocation count,
not an accepted-update count. The attested service path reserves, computes a
candidate and checks its guard before submission; rejected candidates do not
publish or advance the deployed artifact. Their tensors, numerical gate values
and specific failed gate component were not independently retained. Unchanged
deployed endpoints therefore do not establish zero candidate effect.

The separate 18 offline cells completed 360 Adam steps and 11,520 presentations;
each used 640 unique TRAIN rows in a partial epoch, with identical schedules
within head/full pairs. Actual export/NumPy inference parity, serving identities,
fresh-baseline predictions, source/configuration commitments, live encoder
immutability, offline encoder-mode behavior, SQLite cursors, publication payloads
and durable receipts passed the raw audit. Execution and audit processes both
terminated with exit status 0. No protected final examples were read.

No cell qualified, and no model was promoted. Every final development recall
remained below the 90% semantic floor. Several cells also introduced fixture
harms or lost contextual exactness. Qualification failure does not erase the
measured improvements in specificity or clean-control classification.

### Endpoints by profile and arm

A=current curriculum/deterministic/weight 0.35; B=revised/deterministic/0.35;
C=current/seeded/0.35; D=revised/seeded/0.35; E=revised/seeded/1.0.
Offline modes use revised TRAIN and the separate matched Adam protocol above.
The following are final semantic-only means across seeds 42, 43, 44; brackets show
the observed minimum and maximum when they differ. Identical values across
three replicas are shown once. Exact seed outcomes, sample standard deviations,
all component metrics, casewise harm counts and bootstrap intervals are in the
[aggregate summary](evidence/curriculum-improvement-20261009/summary.json).

| Profile | Arm/mode | Recall % | Specificity % | Context joint % | Qualified |
| --- | --- | ---: | ---: | ---: | ---: |
| efficient | A | 59.85 | 25.63 | 14.06 | 0/3 |
| efficient | B | 57.95 | 26.47 | 15.62 | 0/3 |
| efficient | C | 59.85 | 25.63 | 14.06 | 0/3 |
| efficient | D | 57.95 | 26.47 | 15.62 | 0/3 |
| efficient | E | 58.33 | 26.47 | 15.62 | 0/3 |
| efficient | head_only | 54.17 | 31.09 | 15.62 | 0/3 |
| efficient | end_to_end | 46.72 [37.12, 62.12] | 38.52 [23.95, 46.64] | 9.90 [6.25, 12.50] | 0/3 |
| balanced | A | 57.95 | 28.57 | 18.75 | 0/3 |
| balanced | B | 59.85 | 27.73 | 15.62 | 0/3 |
| balanced | C | 57.58 | 28.57 | 18.75 | 0/3 |
| balanced | D | 59.85 | 27.73 | 15.62 | 0/3 |
| balanced | E | 59.85 | 27.31 | 15.62 | 0/3 |
| balanced | head_only | 52.53 [52.27, 52.65] | 29.97 [29.83, 30.25] | 20.31 | 0/3 |
| balanced | end_to_end | 27.15 [21.59, 33.71] | 61.34 [57.56, 67.23] | 39.58 [37.50, 42.19] | 0/3 |
| quality | A | 71.97 | 20.17 | 12.50 | 0/3 |
| quality | B | 71.97 | 20.17 | 12.50 | 0/3 |
| quality | C | 71.97 | 20.17 | 12.50 | 0/3 |
| quality | D | 71.97 | 20.17 | 12.50 | 0/3 |
| quality | E | 71.97 | 20.17 | 12.50 | 0/3 |
| quality | head_only | 67.68 [67.42, 67.80] | 21.85 | 15.62 | 0/3 |
| quality | end_to_end | 55.93 [50.76, 58.71] | 33.47 [31.09, 36.55] | 31.77 [28.12, 34.38] | 0/3 |

Fresh semantic baselines were identical within each profile across all cells:
efficient recall/specificity/context joint = 59.85/25.63/14.06%;
balanced = 64.02/25.21/15.62%; quality = 71.97/20.17/12.50%.
Development metrics use 502 annotation-presence rows (264 positive, 238 negative;
465 source groups). Contextual exactness uses 64 provisional rows in 32 declared
families; it requires simultaneous sensitivity, visibility and category-set
agreement. These are different targets and denominators.

### What the comparisons establish

For efficient, revised B versus A gains 0.84 percentage points in specificity
and 1.56 in contextual joint agreement while losing 1.89 in development recall.
Seeded C versus A and D versus B have identical final aggregate endpoints;
raising replay weight E versus D restores one development positive (0.38 recall
points) with unchanged specificity/contextual joint. This establishes a small
measured tradeoff, not a qualifying improvement.

For balanced, A improves specificity from 25.21% to 28.57% and contextual joint
from 15.62% to 18.75%, while recall falls from 64.02% to 57.95%.
Revised B versus A recovers 1.89 recall points but loses 0.84 specificity and 3.125
contextual points. C versus A misses one additional development positive;
D versus B is unchanged. E versus D loses one correct development negative
(0.42 specificity points). All live balanced cells worsen an already incorrect
fixture restriction from WARN to BLOCK; aggregate action accuracy alone hides
that harm. The fixture gate compares each case against its fresh baseline,
including worsening on already incorrect baseline cases.

Quality live endpoints remain 190/264 positive detections, 48/238 correct
negatives and 8/64 contextual joint-correct rows in every arm and seed. Only one
candidate is published per cell; the 19 subsequent rejections consume allocations
and preserve deployed identities. This is evidence about the guarded deployment
sequence, with the rejected-candidate measurement gaps stated above.

The offline full-encoder comparison changes the tradeoff more strongly.
Balanced full training raises mean specificity to 61.34% and contextual joint
to 39.58%, compared with 29.97% and 20.31% for head-only, while development recall
falls to 27.15% from 52.53%. Quality full training raises specificity to 33.47%
and contextual joint to 31.77%, compared with 21.85% and 15.62%, while recall
falls to 55.93% from 67.68%. Efficient full training has lower mean recall and
contextual joint than head-only, with substantial seed variation. All 18 offline
cells introduce new or worsened eligible fixture harms. Representation updates
are mechanically possible and have measurable effects; these results do not
support an online encoder switch or promotion.

A uniformly applied **post-observation descriptive** breakdown separates 32 S0
controls from 32 authored nonS0 disclosures in every offline cell. All balanced
and quality full-minus-head contextual joint gains come from controls: respectively
12/11/14 and 12/11/8 additional correct controls for seeds 42/43/44.
Efficient loses 6/2/3 correct controls. NonS0 joint correctness stays 0/32 at
baseline and at every offline endpoint. Binary nonS0 sensitivity on the authored
disclosures does not uniformly worsen against head-only: it increases for all
balanced and efficient pairs and two quality pairs, and decreases by one case
for quality seed 42. This cannot be conflated with development annotation-presence
recall. The breakdown explains the observed aggregate conflict; it changes no
primary, qualification threshold, training allocation or RPC. See the
[subgroup aggregates](evidence/curriculum-improvement-20261009/contextual-subgroups.json).
All 63 cells also have 0/4 hard-positive contextual joint-correct cases; sensitivity,
action and component results remain separately visible in the aggregate summary.

All 24 prescribed per-profile comparisons are retained, including B−A, D−C, C−A,
D−B, D−A, E−D, the interaction and offline full−head. Seeded streams are reproducible,
durable and auditable, but endpoint similarity at this budget does not establish
that sampling has no effect. Deterministic replicas are not independent trials.
The 2,000 paired development source-group/contextual family bootstrap replicates
describe scenario sampling variation; they are not confidence intervals inferred
from three training seeds. There is no pooled profile quality estimate.

The concrete implementation improvements are a byte-frozen contextual curriculum,
persistent configurable seeded allocation, configurable replay weighting, strict
semantic isolation, exact-request recovery and a validated offline representation
export path. The measured gains and losses above bound their current quality
evidence. This matrix does not test teacher-model paraphrases, external generation
or hard-case mining; those require later separately frozen experiments and reviewed
targets. Assistant-provisional labels, shared semantic archetypes and the revised
package's changed wording/visibility/category exposure limit causal and
generalization claims. Offline Adam and exposure/gate settings differ from live
training, so their optimizer effects cannot be assigned to the online factors.

### Operational recovery, timing and evidence

After the first six efficient offline cells, Docker exhausted its predefined
address pools while starting reserved balanced A42. No controller, endpoint RPC
or training attempt had begun in that cell. The failed startup log and four
already-created volumes were retained. EX-6 retired 21 exact completed-cell
networks only after verifying raw archives/audits, project labels and empty
endpoints immediately before each removal. The same reserved cell resumed under
the unchanged source/protocol/artifacts. A further 27 completed empty networks
were retired with individual proofs. No global prune, daemon configuration,
unrelated network change or model reset occurred.

The first resumed cell has four different observed spans: 518.51 s across failed
startup/recovery, 75.99 s for its controller including measurements, 61.12 s summed
round durations including RPC, and 87.84 s from successful operations capture to
archive completion. None is isolated model compute time. Failed startup is
excluded from successful-phase estimates, and imported v1 and prospective v2
latency/runtime are not pooled.

At experimental handoff, 63 owned projects retained 378 stopped containers,
315 named volumes (five per project), 15 empty networks and all images. The 48
removed networks have individual archive/identity/removal/absence evidence.
An initial final inventory incorrectly filtered names using a project underscore
prefix; actual volumes have explicit project-hyphen names. That zero-volume
inventory is preserved as superseded evidence. The correction reconciles all 315
exact archived operation mounts, retained container mounts, actual volume names,
owner labels and consumers. Earlier network-retirement volume checks used
nonempty correct inventories (109 initially, including the four reserved-start
volumes; five per subsequent cell) and did not use the defective filter.
Resource cleanup remains a separate acceptance step; no containers, named volumes
or images have been removed at this publication milestone.

The [tracked evidence index](evidence/curriculum-improvement-20261009/README.md)
contains safe aggregates, execution controls, source/image commitments, full audit
archive hashes, exact raw-to-published hash mappings and a deterministic
publication script. The local full summary hash is
`b191e660f3e792a53047282c352e57089ff1f1bf05698a1c3c0d40b0c72867c2`;
the raw audit hash is
`e7b54de530239e39d0b7974c9ccd675152ca76bc2e13af507c16f3564ad43bd4`.
The audit binds that original summary; the sanitized published summary has its
own distinct hash. All cell/group/contrast metrics remain unchanged. Complete
prompts, predictions, SQLite state, model chains, optimizer states and detailed
operations remain in ignored local results and are excluded from tracked artifacts.
Independent full-result critique reconciled all 63 primary endpoints/harms/
qualifications, 18 subgroup breakdowns and 24 contrasts without a quantitative
blocker; this is independent assistant review, not human label adjudication.

### Completed resource cleanup after raw-audit acceptance

EX-8 retired the accepted study resources after revalidating all 63 raw archives
and exact ownership/consumer identities: 378 stopped containers, 315 named
volumes, the 15 remaining empty networks and five unused exclusively task-tagged
images. Every removal has an exact command result and absence proof. All scoped
resources are absent; 27 unrelated containers, 135 unrelated volumes, 11 unrelated
networks and all non-scoped image rows (including parent/shared images) remain
unchanged. The running buildx container was preserved. The earlier 48 verified
empty-network retirements remain separately recorded. No global prune, forced
removal or daemon change was used.

All accepted raw hashes and all 63 archived file inventories were checked again
after cleanup and remain unchanged; complete local raw evidence and superseded
proofs are retained. Cleanup exited successfully. The separate safe
[cleanup receipt](evidence/curriculum-improvement-20261009/cleanup.json) has SHA256
`86e9afa0616e110a99cbe0d91d2cdbdbe3a4cbb7b573d94c74defa2ece3781f7`; detailed before/removal/after identities and
commands remain in the ignored cleanup receipt. This later operational result
does not change execution source/protocol, metrics, qualification or the original
six generated publication artifacts.
