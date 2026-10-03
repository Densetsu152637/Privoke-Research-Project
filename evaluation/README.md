# Evaluation and test suites

Test invocation and orchestration live here. Test cases remain with their original
components; evaluator tests remain in `tests/`. The fuzzer training loop remains
in `services/privoke-fuzzer`; evaluation calls its existing CLI or endpoint.
Each Python suite runs in a separate process to isolate component imports.

Use the same Compose files throughout:

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml build
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps browser-tests
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps model-tests
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps supervisor-tests
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps evaluation-tests
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps --entrypoint python client-runtime /workspace/evaluation/run-component-tests.py client-runtime
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps --entrypoint python privoke-fuzzer /workspace/evaluation/run-component-tests.py fuzzer
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps --entrypoint python param-update-service /workspace/evaluation/run-component-tests.py param-update
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps --entrypoint python telemetry-service /workspace/evaluation/run-component-tests.py telemetry
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps --entrypoint python client-runtime /workspace/evaluation/run-component-tests.py shared
```

The Go runner invokes the original service tests with the race detector.
Browser tests run without network access. The deployment smoke runner invokes
`deploy/gce/tests/smoke.py` and requires its documented Docker/TLS prerequisites.

For live measurements, start only the five server services and their storage
initializer, rather than starting test containers as persistent services:

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml up -d --wait --wait-timeout 240 model-streaming-service telemetry-service client-runtime privoke-fuzzer param-update-service
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml exec -T client-runtime python /workspace/evaluation/run-component-tests.py stack-smoke --skip-training
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps evaluation-tests python evaluate.py --dataset piimb --samples 500 --sampling balanced --english-only --seed 42 --backend streamed --run-name pilot
```

The evaluator container sends gRPC directly to the existing runtime and persists
reports through `evaluation/results`. Host execution keeps the existing Docker-exec
bridge. `--layer` supports pipeline, regex, NER, semantic and regex+NER ablations.

The user selected development targets on 3 October 2026: sensitive recall >= 90%
and clean specificity >= 90%, together with the research completion plan's evidence
requirements. These are development decision targets, not IEEE acceptance criteria.
Lock source/family-disjoint final data before tuning; never train on final holdout
failures to reach the targets. Synthetic training guard metrics do not establish
public-benchmark generalization. Missing evidence, errors and null results must
remain visible in the paper.

## External annotated-PII training sources

The current prospective expansion uses only pinned official training views: Nemotron-PII `default/train` and Meddies PII `english/train`. The metadata audit verified the pinned files' schemas and footer counts (100,000 and 47,744 rows respectively); the Nemotron README's stated 50k train size conflicts with its pinned train footer, so use the recorded manifest and preserve this discrepancy. Counts are raw source rows, not usable examples after protected-key, deduplication, grouping, and annotation checks.

The target is annotated-PII presence. Added Meddies rows are positive-only, and an empty/missing annotation is not presumed clean. Neither source supplies contextual privacy-action labels. The planned cap and group/split/selection rules are documented in [the dataset expansion protocol](../paper/research/dataset-expansion-protocol.md); source scope and paper wording are in [the PII dataset analysis](../docs/PII-dataset-analysis.md) and [source audit](../paper/research/external-pii-source-audit.md). Meddies is CC-BY-NC-4.0; keep source attribution and non-commercial conditions attached to derived research artifacts.

The amended v3 preparation completed at `evaluation/results/external_pii_20261004_prepared_v3/` (manifest SHA-256 `2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c`): 19,993 training rows (3,832 original, 13,168 Nemotron, 2,993 Meddies), unchanged 968-row validation, and source-heldout diagnostics of 1,000 Nemotron and 999 Meddies positive rows. Protected IDs/groups/text and source partitions passed manifest integrity checks. The offline fit completed all three profiles with no convergence warnings, selected C=10 per profile, and froze profile selections before development scoring. See [the dataset analysis](../docs/PII-dataset-analysis.md) and [the evidence ledger](../paper/research/data-expansion-ledger.md) for the aggregate validation/source diagnostics and limitations. Runtime attempt v1 failed before producing scores because of a missing protobuf import; its zero-score run is retained. Runtime attempt v2 completed all 18 matched runs (17,802 RPC requests) with zero errors. Its run manifest records exact restoration, no unknown admin outcome, and unchanged runtime image identities. The scorer/RPC suite for the fix passed 11 tests with no skips; the runner suite passed 9 tests. See the [verified evidence ledger](../paper/research/data-expansion-ledger.md) for the summary hashes, measured counts, paired intervals, and limits. These results do not promote or replace the current model. The earlier v1 shortfall and interrupted v2 preparation remain preserved as historical preparation attempts, not model evidence.
To reproduce a new runtime batch, check out the committed runtime-caller revision shown in its manifest, keep the prepared data, frozen fit, matched baseline fit, and frozen protocol unchanged, and use a fresh output directory. For example, from the repository root at the v2 caller revision:

```powershell
python evaluation/run-external-pii-study.py `
  --fit-root evaluation/results/external_pii_profiles_20261004_v1 `
  --prepared evaluation/results/external_pii_20261004_prepared_v3 `
  --baseline-fit-root evaluation/results/presence_profiles_20261004_v1 `
  --protocol-file evaluation/results/external_pii_20261004_support_v3/protocol.md `
  --protocol-sha256 962198b384aaed7fd5fb98e10c778b295ac6403c0dd1ba5ea376c28ec786eafe `
  --source-revision 083ee0c5fb38efdfb63ade634b185eba0c67432d `
  --fit-source-revision 85c7f475fb8ebd1529254e4135b774d98505ddb1 `
  --output evaluation/results/external_pii_rpc_FRESH_RUN
```

The runner writes a `run-manifest.json`; after it completes, summarize an existing study into a new JSON file with:

```powershell
python evaluation/summarize-external-pii-study.py `
  --study evaluation/results/external_pii_rpc_20261004_v2 `
  --output evaluation/results/external_pii_summary_FRESH_RUN.json
```

Both output locations must be fresh. Do not overwrite failed attempts or reuse the same output name for a rerun.
The completed v2 summary is `evaluation/results/external_pii_summary_20261004_v1.json` (SHA-256 `e5e138d42f0930390702fb56a745ae0b8e7f7772791d8ed473ab56d51b250c2d`); its study manifest is at `evaluation/results/external_pii_rpc_20261004_v2/run-manifest.json` (SHA-256 `62b28e0f6c2e8006915e9bdc8498462d636e44d5bb397f8704a95d96d2ab8671`). The summary records the paired source-group bootstrap method (2,000 replicates, seed 10102026) and validation-specificity changes of −9.74 pp (efficient), +0.81 pp (balanced), and −2.03 pp (quality). The balanced 95% interval is [−1.46, +3.08] pp and includes zero; see the ledger for all intervals and raw counts. These are conditional development comparisons after validation selection.

## Controlled research runs

The override forces CPU execution and `FUZZER_PROMPT_COUNT=0`, disabling the
updater's inherited startup-training setting. Keep the same override for every
startup, restart, measurement and explicit update. Services use isolated research
containers and named volumes. Do not change a model during a matched batch.

```powershell
# After restoring v0.3.0 and clearing runtime/model caches:
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps evaluation-tests python run-ablations.py --dataset-file results/locked-public/development.jsonl --run-name UNIQUE_RUN_NAME --model-artifact results/original-v0.3.0-model.json
# Invoke actual fuzzer cycles through their existing service, then paired measurements:
python evaluation/run-independent-updates.py --experiment-id UNIQUE_EXPERIMENT_ID
# Native Chromium page hook and local receiver, with controlled broker decisions:
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml build browser-capture
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml run --rm --no-deps browser-capture
```

`run-ablations.py` refuses to overwrite a run directory and fails when returned
semantic model versions differ from the archived artifact. It checks all raw
reports for runtime errors. A manifest records dataset/model/report hashes.
The update driver restores the same checked-in original artifact between seeds
42, 1337 and 2026, uses unique request IDs and archives exact update responses and
model snapshots. The actual training loop remains in the fuzzer service.

The native capture fixture exercises the shipped page-hook source in headless
Chromium with a real HTTPS loopback receiver and fake markers. It supplies
ALLOW/WARN/BLOCK or no decision through a fixture broker. It does not test installed
extension registration, provider pages, native messaging, the supervisor bridge,
or detector quality. Its reported decision durations are fixture durations and
must not be labeled full runtime or end-to-end deployment latency.

See `paper/research/protocol.md` for metric and split definitions and
`paper/research/review-requests.md` for professor confirmation requirements.
Raw generated data are ignored under `results/`; preserve them in a deliberate
local artifact package with a hash manifest before publication figures are made.

## Learning-rate and false-positive development

The deterministic template fuzzer has no generation-temperature parameter. Its
existing learning-rate setting is `FUZZ_TRAINING_LEARNING_RATE` (default0.03).
The checked-in overlays test0.01 and0.003. Do not rebuild the serving image during
a matched run: source-image changes can confound a training comparison even when
the returned model version and artifact checksum are correct.

`compose.original-runtime.yml` uses an immutable source extraction from the tested
commit712ed7212c261e01e12db8c8f3fe7aede8831534, at
`results/original-runtime-source`. Prepare this directory from `git archive` of that
exact revision with Python's safe tar data filter, then build the selected runtime
with that overlay. This source copy is ignored generated data. The original model
for each seed remains the checked-in `models/privoke-balanced.json`; source/model
version and Docker image identity are distinct.

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.original-runtime.yml -f evaluation/compose.learning-rate-001.yml build client-runtime
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.original-runtime.yml -f evaluation/compose.learning-rate-001.yml up -d --no-deps --force-recreate --wait privoke-fuzzer
python evaluation/run-independent-updates.py --experiment-id UNIQUE_LR_RUN --compose-override evaluation/compose.original-runtime.yml --compose-override evaluation/compose.learning-rate-001.yml
```

Multiple `--compose-override` arguments preserve their order. The driver records
allowlisted fuzzer settings and override hashes, restores the original before
every seed, retains rejected RPC details, and measures only accepted candidates.
Failed seeds must remain in the reported experiment denominator; a zero process
exit after independent rejections does not mean every update succeeded.

The fictional clean-topic curriculum and optional existing bootstrap anchors are
generated by `prepare-fuzzer-calibration.py`. Their labels are provisional training
inputs, not independently annotated contextual ground truth. Disable transformations
for these controls because redacting the sole identifier can change a training label.
Compare against the disclosed ordinary-example control and retain all safety gates.

`diagnose-semantic-calibration.py` checks normalized offline original-model binary
outputs against every archived live semantic prediction before reporting a gate
grid. `diagnose-rule-false-positives.py` runs revised rules in a one-off container
and combines them with archived original NER/semantic binary outputs. These are
development diagnostics, not live enforcement, latency or final-test measurements.

`run-training-curve.py` calls at most two more cycles from the selected anchored
0.003 seed42 checkpoint. It stops at a class-rate regression in either semantic
or pipeline and restores the best eligible artifact in a `finally` block.
This driver encodes this particular development protocol; it is not a general
production training loop. `diagnose-ner-casing.py` checks raw-case versus canonical
NER predictions without deploying a normalizer change.

Completed attempts and current selected artifact are recorded in
[false-positive experiments](../paper/research/false-positive-experiments.md).
The preceding extension's integrated live result is 93.56% recall and 22.69%
specificity. The subsequent public-negative coverage study is described below;
final remains unscored and the specificity development target remains unmet.

## Local evidence preservation

After experiments stop and reviewed source/tooling is committed, use a fresh name
and external manifest path:

```powershell
python evaluation/archive-research-artifacts.py --name research-20261003-development --manifest paper/research/artifact-manifest.json
```

The helper includes the exact committed source tar, generated results, local
validation logs and research records. It verifies every archived file against its
SHA-256 and checks ZIP integrity. Both output paths refuse overwrites. The external
manifest records archive hash and source commit; generated ZIP files are ignored
under `evaluation/artifacts/`. This is local preservation. Raw benchmark source
licenses must be audited before redistribution, and no upload is performed.

## Prospective public-negative coverage study

Read [the prospective protocol](../paper/research/public-negative-protocol.md)
before execution. It defines a custom within-corpus training study, source/text
exclusions, provisional negative-policy labels and a full-pipeline recall floor.
It must not be presented as untouched official PIIMB benchmark-test evaluation.

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.public-negatives.yml run --rm --no-deps evaluation-tests python prepare-public-negatives.py
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.public-negatives.yml build client-runtime privoke-fuzzer
python evaluation/run-public-negative-study.py
```

Preparation refuses existing output, checks locked dataset hashes, scans the
pinned revision, excludes all protected groups/IDs/shared training keys and
normalized conflicts, then records the selected curriculum hash and provenance.
It preserves literal braces through the template renderer and adds the existing
bootstrap samples without regenerating model weights. The grouped fuzzer excludes
all held-out source siblings; runtime gradient/held-out execution uses canonical
serving normalization.

The study driver measures the original with revised rules, then calls the existing
independent-update driver for three seeds at each predefined learning rate. It
records rejected attempts, reports semantic and pipeline results, and restores the
selected eligible artifact in `finally`. A partial study or failed restoration is
marked explicitly. Additional cycles require the recorded prospective trigger.
Do not reuse these fixed request/run IDs to restart an interrupted study.
For a corrected launch, pass a fresh `--experiment-prefix` (up to40 characters);
the original launch and its model-restoration record remain preserved. Container
artifact paths use forward slashes regardless of the host operating system.

When the completed study meets its extension trigger, call the selected profile
for at most two additional cycles without rebuilding serving images:

```powershell
python evaluation/run-public-negative-curve.py --study-manifest evaluation/results/STUDY_PREFIX/selection.json --experiment-id UNIQUE_CURVE_ID
```

This caller independently validates the scored reports against locked ID/label/
group keys and recomputed confusion counts before replaying the prospective
ranking. It rejects a changed selected artifact or an unmet trigger, preserves
accepted-but-unscored failures, and restores the best eligible checkpoint after
errors. It stops at rejection, pipeline recall below90%, or no strict specificity
improvement. These criteria belong to this study; the older `run-training-curve.py`
retains its earlier, stricter no-regression criteria.

Completed [public-negative results](../paper/research/public-negative-results.md)
record all nine independent attempts and the stopped second cycle. The restored
first-cycle model has90.53% development recall and29.41% specificity; the final
partition remains unscored. Test invocation remains centralized here, while the
training loop remains in the fuzzer service.

## Released model profiles

Read [the model-profile protocol](../paper/research/model-profile-protocol.md)
before comparing original efficient, balanced and quality artifacts:

```powershell
python evaluation/run-model-profile-study.py --run-prefix UNIQUE_PROFILE_RUN
```

The caller measures semantic and pipeline outputs on the locked development set,
requests each artifact's explicit model ID, verifies matched rows/raw counts,
records runtime-duration distributions and restores the prior trained balanced
payload in `finally`. It refuses reused outputs and does not rebuild serving
images. `run-ablations.py` sets the evaluator's MODEL_ID from the supplied artifact
and checks returned IDs as well as versions/checksums. A shared version string
does not establish that the requested profile was evaluated.

Runtime elapsed_ms excludes browser/bridge overhead. These profiles also differ
in vocabulary, random initialization and bootstrap epochs; a score difference
does not isolate the causal effect of parameter count. Model-size inference
comparisons do not establish that larger-model training/update gates were tested.

The measured original-profile comparison is documented in
[model-profile results](../paper/research/model-profile-results.md): quality has
higher semantic recall, while the original balanced profile has better measured
pipeline recall and specificity than quality. These results do not justify
prioritizing quality-profile training. Fuzzer update experiments so far use the
balanced profile; they do not test larger-profile training.

## Frozen-representation diagnostic

Read the [prospective protocol](../paper/research/representation-protocol.md)
before running the offline frozen-encoder probe. The completed custom
development diagnostic is documented in
[representation results](../paper/research/representation-results.md); its
specificity remains below the selected90% development target, and final remains
unscored.

Use the existing `client-runtime` stack and the same Compose overrides as the
research runner. The public-negative override supplies a read-only bind mount of
`models/generate_baseline.py` to the evaluation container for bootstrap exclusion
checks. The caller loads the checked-in original balanced artifact in memory to
export features; it does not train through the fuzzer, change the serving model,
or publish weights. It expects the runtime and evaluation images to be available
and verifies their IDs before and after execution.

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml -f evaluation/compose.public-negatives.yml up -d --wait --wait-timeout 240 client-runtime
python evaluation/run-representation-diagnostic.py --output FRESH_RESULTS_CHILD
```

`FRESH_RESULTS_CHILD` is a unique child name under `evaluation/results`; do not
reuse failed or completed attempt paths. The caller owns preparation, UTF-8
feature transport, fitting, output hashes and phase logs. It protects development
and final IDs/groups/text keys and does not score final examples. The probe is an
annotation-presence diagnostic, not a contextual privacy policy or a fuzzer-
trained replacement. Results are development-only and do not establish deployment
readiness.

## Sparse annotation-presence profiles

Read the [prospective model-refactor protocol](../paper/research/model-refactor-protocol.md)
before fitting or scoring. The fitter validates the pinned prepared partitions,
exports the three fixed sparse profiles and validation-selected C/threshold
artifacts, and freezes all profile selections before any development inference.
It exports only the train partition as the separate fuzzer curriculum. It does
not score development or read final examples; the locked final file is checked by
SHA-256 only. The scorer makes typed `DetectAnnotationPresence` RPCs directly
from the evaluation container and requires the returned model ID, version,
checksum, parameter fingerprint, threshold, enum, and probability to match the
frozen artifact and shared arithmetic.

Use fresh result-directory names. Fit and standalone scoring commands run in
the evaluation container, which can resolve the runtime service by Compose DNS;
do not invoke these RPC commands from the host. The fourth Compose override
mounts the exact prospective protocol read-only. Use these four files in order
from the repository root:

```powershell
$ComposeFiles = @('-f','docker-compose.yml','-f','evaluation/compose.tests.yml','-f','evaluation/compose.public-negatives.yml','-f','evaluation/compose.presence.yml')
$FitSourceSha = (git rev-parse HEAD).Trim()
$ProtocolSha = (Get-FileHash paper/research/model-refactor-protocol.md -Algorithm SHA256).Hash.ToLowerInvariant()
docker compose @ComposeFiles run --rm --no-deps -T evaluation-tests python /workspace/evaluation/fit-presence-profiles.py --prepared /workspace/evaluation/results/representation_20261004_v3/prepared --locked-root /workspace/evaluation/results/locked-public --bootstrap-source /workspace/models/generate_baseline.py --output /workspace/evaluation/results/FRESHFIT --source-revision $FitSourceSha --protocol-sha256 $ProtocolSha
$ExecutionSha = (git rev-parse HEAD).Trim()
$FitSourceSha = (Get-Content evaluation/results/FRESHFIT/run-manifest.json -Raw | ConvertFrom-Json).source_revision
docker compose @ComposeFiles run --rm --no-deps -T evaluation-tests python /workspace/evaluation/evaluate-presence.py --artifact /workspace/evaluation/results/FRESHFIT/profiles/balanced/artifact.json --selection /workspace/evaluation/results/FRESHFIT/profiles/balanced/selection.json --fit-manifest /workspace/evaluation/results/FRESHFIT/run-manifest.json --dataset-file /workspace/evaluation/results/locked-public/development.jsonl --output /workspace/evaluation/results/FRESH_BASE_SCORE --target client-runtime:50054 --source-revision $ExecutionSha --fit-source-revision $FitSourceSha --protocol-sha256 $ProtocolSha
```

The study owner must first have the four-file Compose stack and images ready,
with all three presence artifacts in the model catalog and the update-volume
permissions initialized. Keep automatic startup training disabled (`FUZZER_PROMPT_COUNT=0`);
the study runner checks this. Do not build or rebuild serving images as part of
the matched study. The standalone scorer requires `client-runtime` already
running with the exact selected profile artifact installed; it never installs
or restores models itself. Use new names instead of reusing `FRESHFIT` or
`FRESH_BASE_SCORE`, including after a failed attempt.

The profile fitter writes each C candidate artifact and validation predictions,
plus a train-only `curriculum/prompts.jsonl`. The scorer emits row IDs, labels,
groups, binary probabilities/predictions, returned identities, elapsed times and
errors without emitting prompt text. Runtime errors or any identity/parity mismatch
make a profile score ineligible; failed evidence is retained in that fresh
output directory. This is a binary annotation-presence signal and does not replace
or suppress contextual classification, severity, categories, or policy actions.

The fit manifest guard checks all three frozen profile selections and their
selected artifacts before scoring. The additive `evaluate-presence-update.py`
measures one fixed validation or development endpoint without recalibrating a
threshold. Changed candidates require the committed update response and durable
receipt evidence; development additionally requires a persisted validation
retention decision. These scoring callers do not run fuzzer updates or modify
model volumes.

The host-side study runner invokes the real fuzzer and updater through the
four-file Compose stack. After the prerequisites above are satisfied, run it
from the committed repository checkout with a new output path and both source
revisions bound to the fit manifest and executing checkout:

```powershell
$ExecutionSha = (git rev-parse HEAD).Trim()
$FitSourceSha = (Get-Content evaluation/results/FRESHFIT/run-manifest.json -Raw | ConvertFrom-Json).source_revision
$ProtocolSha = (Get-FileHash paper/research/model-refactor-protocol.md -Algorithm SHA256).Hash.ToLowerInvariant()
python evaluation/run-presence-update-study.py --fit-root evaluation/results/FRESHFIT --output evaluation/results/FRESHSTUDY --source-revision $ExecutionSha --fit-source-revision $FitSourceSha --protocol-sha256 $ProtocolSha
```

This caller uses fixed seeds 42, 43, and 44 for each of the three fitted
profiles. Validation retention requires recall at least 90% and strictly higher
specificity than that profile's fitted base; eligible candidates rank by
specificity, recall, then lower seed. If none qualifies, the fitted base is
retained. It does not add C values or update cycles in response to these
measurements. Preserve every complete or failed run under its original fresh
path; the runner records restoration and protected-input checks. It does not
read final examples or change the contextual policy task.

In the completed v1 run, all nine update requests were accepted, but none met
the frozen validation retention gate because no candidate improved specificity;
all three fitted bases were retained. The independent 59,214-check evidence
audit and per-seed counts are recorded in the
[results report](../docs/presence-model-improvements.md). This observed result
is not a reason to add C values, change thresholds, or repeat update cycles on
the same development evidence; any next experiment needs a new prospective
question and frozen protocol.
