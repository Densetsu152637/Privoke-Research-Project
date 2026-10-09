# Fuzzer curriculum improvement protocol and implementation

The revised curriculum and seeded sampler address two separate limitations of the earlier combined training run: narrow template variation and deterministic allocation that ignored the request seed. This record preserves the implementation, controlled comparison and limitations. Implementation alone does not establish improved model quality. The earlier six-hour run increased balanced pipeline specificity from 22.27% to 36.55% while recall fell from 93.56% to 87.50%; those results motivated further experiments and did not qualify a model for promotion.

## Source and resource commitments

Implementation started from `85bf44726f78227c7f8ef22ec3d7098135b406b7` on `feat/dev-testing`. The original resource and v1 rendering remain unchanged. New JSON resources use explicit LF checkout attributes so their byte commitments survive Git checkout.

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

## Validation and pending evidence

Focused validation uses the existing Python 3.11 study environment with `PYTHONPATH=evaluation`. Windows sandbox temporary-directory atomic replacement failed in the default OS temporary path; setting `TMP` and `TEMP` to the task's ignored results `test-temp` directory allowed the existing controller fixtures to run. Initial new tests also compared classification objects by identity and left a SQLite connection open; their assertions now compare packed targets/text/metadata and explicitly close the connection.

The focused suites passed: 14 curriculum/config tests, 14 synthetic-resource tests and 16 continual-controller tests. They cover seed-dependent allocation, reproducibility, epochs/restart, within-batch uniqueness, balanced quotas and fair family visits, conflicting retries, independent cursor namespaces, invalid configuration, contextual facts/token capacity, exclusions and separation. Logs are under `evaluation/results/curriculum_improvement_20261009_core/` as `curriculum-tests.log`, `synthetic-tests.log` and `controller-tests.log`. Live training and model-quality conclusions remain pending the separately implemented supervisor and its audited results.

Paper alignment is assigned to the root integration writer. Affected text is `paper/main.tex` around line 191 (curriculum allocation/replay), line 245 (study commitments), line 324 onward (new results only after measured runs), and line 524 (limitations and unresolved component effects). Existing historical result numbers must remain unchanged.

## Implemented execution and evidence contract

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
directory; final experiment results remain pending source/protocol acceptance and
explicit execution authorization.
