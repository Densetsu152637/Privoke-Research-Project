# Evaluation and test suites

Test invocation and orchestration live here. Test cases remain with their original
components; evaluator tests remain in `tests/`. The fuzzer training loop remains
in `services/privoke-fuzzer`; evaluation calls its existing CLI or endpoint.
Each Python suite runs in a separate process to isolate component imports.

Run evaluation and integration checks as host Python scripts. Use Python 3.11 or
3.12; the current NumPy constraint excludes Python 3.13 wheels. From the repository
root, create a virtual environment once, install the host dependencies and generate
the protobuf clients. The synthetic evaluator mechanics tests need Torch, but do
not fit a study dataset, publish weights or download pretrained models.

```powershell
py -3.12 -m venv evaluation/.venv
evaluation/.venv/Scripts/Activate.ps1
python -m pip install -r evaluation/requirements-host.txt
python evaluation/setup-host.py
python evaluation/run-component-tests.py evaluator
python evaluation/run-component-tests.py supervisor
python evaluation/run-component-tests.py shared
```

On Linux/macOS use `python3.11 -m venv evaluation/.venv` and
`source evaluation/.venv/bin/activate`. Regenerate clients after protobuf changes.
Use the same interpreter for setup and all checks. Component Python suites can
also run through `run-component-tests.py` on the host after installing that
component's requirements. Existing Python, JavaScript and Go unit tests retain
their original frameworks; the optional image-validation commands below still
test service-image packaging.

The protected research-file suites require a Linux host with their documented
POSIX ownership/descriptor prerequisites; Windows supports the localhost RPC
scripts, but does not supply those protections. Linux-only protected-file
checks are skipped on Windows. These are separate from transport tests, which can
be selected with `python evaluation/run-component-tests.py evaluator -p test_host_scripts.py`
and `python evaluation/run-component-tests.py evaluator -p test_runners.py`.

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

For live measurements, start the five server services and their storage
initializer. The research override publishes all five gRPC ports on `127.0.0.1`;
the development override also publishes the fuzzer on `50053`. No test
container is needed for these checks:

```powershell
docker compose -f docker-compose.yml -f evaluation/compose.tests.yml up -d --wait --wait-timeout 240 model-streaming-service telemetry-service client-runtime privoke-fuzzer param-update-service
python evaluation/run-fuzzer-tests.py health
python evaluation/run-component-tests.py stack-smoke --skip-training
python evaluation/evaluate.py --dataset piimb --samples 500 --sampling balanced --english-only --seed 42 --backend streamed --run-name pilot
python evaluation/run-fuzzer-tests.py test-prompts --layer semantic --prompt "My email is alex@example.com"
```

The evaluator sends gRPC directly to `127.0.0.1:50054` and writes reports under
`evaluation/results`. `PRIVOKE_RUNTIME_TARGET` overrides the runtime address;
`FUZZER_TARGET` or `run-fuzzer-tests.py --target` overrides `127.0.0.1:50053`.
The fuzzer serves health and training RPCs; prompt analysis uses the runtime RPC.
Prompt-probe dumps go to `dumps/privoke-fuzzer` on the host.
Evaluation and prompt tests default to the semantic layer only, and verify the
returned execution so regex/NER cannot affect an LLM-only result. Requests always
declare a nonempty layer selection. `--layer pipeline` (evaluator) or `--layer runtime`
(prompt tests) explicitly selects a product end-to-end test; regex, NER and
regex+NER ablations also require explicit selection for that purpose. Historical
combined-detector reports retain their original meaning and are not LLM-only scores.
See the persistent [repository testing policy](../AGENTS.md).

Legacy combined studies require `--allow-product-pipeline` for separately
authorized product/detector analysis: `run-contextual-fuzzer-study.py` and its
class-balanced, mean-category, role-quota, local-SGD and decision-margin variants;
`run-independent-updates.py`, `run-model-profile-study.py`, `run-training-curve.py`,
`run-public-negative-study.py` and `run-public-negative-curve.py`. They refuse by
default before study data access or work and preserve their original pipeline
eligibility rules. For LLM-only comparisons, use the current semantic-only
curriculum-improvement study rather than this opt-in. `run-ablations.py` and the
named full-pipeline cascade tools serve explicit product/detector tasks.

Normal deployment enables automatic training (32 prompts, hourly interval).
Keep `evaluation/compose.tests.yml` or the study's explicit count-0 override
for every updater in the Compose file sequence for controlled measurements.
Some study overlays disable only their additional updater: the original
`param-update-service` must also have count `0`. This prevents background
requesters from changing the model between observations. The normal
development stack can publish updates into its bind-mounted `./models`.

To test a real training publication and durable replay, run
`python evaluation/run-component-tests.py stack-smoke` without `--skip-training`.
This changes the running model. A single training request is also available as
`python evaluation/run-fuzzer-tests.py train --model-id privoke-balanced --prompt-count 32`.
Rejected cycles exit with status 1. For production-image integration on the host,
use `docker compose -f docker-compose.yml -f evaluation/compose.localhost.yml up -d --wait`;
base production Compose continues to publish no ports. CI uses this loopback
override for its host Python smoke checks. Clients running in containers must
use explicit service DNS targets.

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
python evaluation/run-ablations.py --dataset-file evaluation/results/locked-public/development.jsonl --run-name UNIQUE_RUN_NAME --model-artifact evaluation/results/original-v0.3.0-model.json
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
from a host Python process and requires the returned model ID, version,
checksum, parameter fingerprint, threshold, enum, and probability to match the
frozen artifact and shared arithmetic.

Use fresh result-directory names. Fit and standalone scoring commands run on the
host after the setup above; standalone scoring defaults to `127.0.0.1:50054`.
The matched study controllers still manage Docker images, model volumes and
isolated evidence jobs to preserve their recorded execution identities. Use the
four Compose files in order when starting their server stack:

```powershell
$ComposeFiles = @('-f','docker-compose.yml','-f','evaluation/compose.tests.yml','-f','evaluation/compose.public-negatives.yml','-f','evaluation/compose.presence.yml')
$FitSourceSha = (git rev-parse HEAD).Trim()
$ProtocolSha = (Get-FileHash paper/research/model-refactor-protocol.md -Algorithm SHA256).Hash.ToLowerInvariant()
python evaluation/fit-presence-profiles.py --prepared evaluation/results/representation_20261004_v3/prepared --locked-root evaluation/results/locked-public --bootstrap-source models/generate_baseline.py --output evaluation/results/FRESHFIT --source-revision $FitSourceSha --protocol-sha256 $ProtocolSha
$ExecutionSha = (git rev-parse HEAD).Trim()
$FitSourceSha = (Get-Content evaluation/results/FRESHFIT/run-manifest.json -Raw | ConvertFrom-Json).source_revision
python evaluation/evaluate-presence.py --artifact evaluation/results/FRESHFIT/profiles/balanced/artifact.json --selection evaluation/results/FRESHFIT/profiles/balanced/selection.json --fit-manifest evaluation/results/FRESHFIT/run-manifest.json --dataset-file evaluation/results/locked-public/development.jsonl --output evaluation/results/FRESH_BASE_SCORE --target 127.0.0.1:50054 --source-revision $ExecutionSha --fit-source-revision $FitSourceSha --protocol-sha256 $ProtocolSha
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

## Continual synthetic fuzzer study

The prospective curriculum comparison is controlled by
`run-curriculum-improvement-study.py` with explicit `prepare`, `execute`, and
`audit` phases. Its specification and provisional-label limitations are in
[`docs/fuzzer-curriculum-improvement-process-20261009.md`](../docs/fuzzer-curriculum-improvement-process-20261009.md).
The amended semantic-only v2 matrix contains 45 live cells (900 attempted cycles)
and a separate 18-cell offline matched-Adam mechanics comparison. Fifteen completed
v1 efficient live cells contribute read-only isolated semantic views; 48 cells
are prospective. The original combined-detector measurements remain historical. It never promotes a model.
Preparation requires committed computation sources, reviewed resource hashes,
and an images JSON mapping the five serving service names plus
`offline-training` to full immutable `sha256:` image IDs. Source-only service
overlays and the CPU training target are in `Dockerfile.curriculum-improvement`.
The existing service parent tags must be inspected and their resolved IDs
retained in the build logs; ordinary service images are not overwritten.

```powershell
python evaluation/run-curriculum-improvement-study.py prepare --study-id privoke-improve-UNIQUE-v2 --output evaluation/results/curriculum_improvement_20261009_v2 --images evaluation/results/curriculum_improvement_20261009_amendment/images.json --import-semantic-from evaluation/results/curriculum_improvement_20261009_v1
python evaluation/run-curriculum-improvement-study.py execute --output evaluation/results/curriculum_improvement_20261009_v2 --cell efficient-head-only-42
python evaluation/run-curriculum-improvement-study.py execute --output evaluation/results/curriculum_improvement_20261009_v2
python evaluation/run-curriculum-improvement-study.py audit --output evaluation/results/curriculum_improvement_20261009_v2
```

Replace `UNIQUE` with a unique lowercase identifier. The first full cell provides
an elapsed-cost benchmark. Every prospective cell owns a unique Compose project and five
named volumes; cells run sequentially on ports 50051–50055. An interrupted
`execute` resumes saved state, retained storage and the controller's exact pending
request ID. It never resets a model or retries a known rejection as a new attempt.
Interrupted offline fits require an audited repair; partial output is preserved.
The v1 supervisor is never resumed: its explicit interruption checkpoint remains
outside immutable archives. V2 binds imported archive hashes and each original
execution protocol, unchanged prepared inputs, new source/images, and the user
instruction. Its semantic primary/qualification criterion changed after fifteen
observed cells; the study is exploratory rather than untouched confirmation.
All fresh requests explicitly select semantic only and validate actual execution.
Reports contain semantic metrics only, with casewise fixture harms and no pooled
runtime or latency comparison between imported and prospective observations.
Services stop after each cell. Preserve task volumes until all raw archives and
durable receipts pass audit; subsequent cleanup must use only the recorded task
project names. The unrelated builder and existing projects remain outside scope.
`summary.json` and `audit.json` contain aggregate evidence; raw checkpoints,
predictions, parameters, IDs and databases remain in ignored results storage.

For ordinary periodic training, the updater accepts
`FUZZER_CURRICULUM_SAMPLER_POLICY=seeded_family_v1` and a stable unsigned
`FUZZER_CURRICULUM_SAMPLER_SEED` (for example 42). Base Compose forwards both
variables and `FUZZ_TRAINING_REPLAY_WEIGHT` to their consuming services. Defaults
retain `deterministic_v1`, seed 0, and replay weight 0.35. The stable sampler seed
does not increment with the periodic trainer seed. Seeded sampling also requires
the existing prepared curriculum manifest/state configuration and a sufficient
prompt budget; this configuration does not change the ordinary model or gate.

`prepare-synthetic-curriculum.py` creates fresh, deterministic grammar, offline
teacher, and evolved pools. Its required opaque exclusion index is checked before
output; optional development examples require their exact SHA-256. All contextual
targets are assistant provisional, and lexical siblings share permanent families.

Use `--teacher-templates evaluation/datasets/synthetic-teacher-templates-v2.json`
for the versioned revised situation resource at the original 672-row budget.
Optional `--assessment-resource evaluation/datasets/contextual-assessment-20261009.json`
freezes a separate 64-row contextual endpoint in `manifest.assessment`, outside
the training, replay and gate splits. It must also be checked against both
curriculum versions before matrix execution. The controller accepts
`--curriculum-sampler-policy seeded_family_v1 --curriculum-sampler-seed 42`;
the stable allocation seed is distinct from its changing trainer cycle seed.
The original deterministic sampler remains the default. See the
[improvement protocol](../docs/fuzzer-curriculum-improvement-process-20261009.md)
for the controlled matrix and limits on causal and generalization claims.

`compose.continual-fuzzer-study.yml` adds isolated storage and manual training to
the base plus `compose.tests.yml`. Set a unique `CONTINUAL_STUDY_ID`, the absolute
prepared directory in `CONTINUAL_STUDY_CURRICULUM`, and
`CONTINUAL_STUDY_MODEL_ID` to the model being trained. Start the stack with those
three Compose files and a unique `--project-name`; it exposes ports 50051–50055.
Automatic startup requests are disabled for this experiment. RPC timeouts remain
positive; zero would cancel a call rather than accelerate training.

Run the host Python controller against the already running stack:

```powershell
python evaluation/run-continual-fuzzer-study.py --model-id privoke-balanced --cycles 20 --prompt-count 256 --checkpoints 0,5,10,20 --dataset-file evaluation/results/locked-public/development.jsonl --curriculum-manifest evaluation/results/FRESH/curriculum/manifest.json --output evaluation/results/FRESH/balanced
```

Switch the fuzzer and updater's configured model together before each profile,
keeping the isolated model catalog and per-model cursor. Use a fresh output
directory for each run. `--resume` verifies inputs, archived evidence and live
identity, and retries only an ambiguous pending request under its exact ID.
Known gate rejections count as attempts, not accepted updates. Mining examines
only TRAIN rows, never endpoint examples. Checkpoints archive parameter values,
row predictions, RPC errors, confusion counts, paired changes and group bootstrap
intervals for semantic and pipeline detection. Development labels measure binary
annotation presence, which is not identical to contextual privacy. The controller
does not promote a model or access final examples. Fixed synthetic guard results
alone do not establish generalization.

For reproducible live runs, pass `--operational-manifest` pointing to a frozen JSON
record with `containers` mapping each serving container name to its `image_id`
and selected `environment` key/value map. The controller uses read-only Docker
inspection before starting and before every training request; changed images,
settings, stopped services or changed manifest bytes abort the run. Preserve the
prospective protocol and source hashes alongside this record. An RPC-only run
without this argument does not establish that server configuration stayed fixed.

The completed 9 October study made 60 attempts across the three profiles, with
41 accepted updates. Balanced gained pipeline specificity while losing recall;
efficient had one semantic correction with no pipeline change; quality retained
one update with no endpoint prediction changes. See the
[results and limitations](../docs/continual-fuzzer-results-20261009.md).
`summarize-continual-fuzzer-study.py --study-root PATH` independently reconciles
archived predictions, float32 exports, hashes and durable batch allocations;
it does not read datasets or issue service RPCs.

The completed six-hour study is reported in
[`docs/long-fuzzer-results-20261009.md`](../docs/long-fuzzer-results-20261009.md).
Its tracked safe evidence copies are
[`summary.json`](../docs/evidence/long-fuzzer-20261009/summary.json),
[`independent-audit.json`](../docs/evidence/long-fuzzer-20261009/independent-audit.json),
[`protocol.json`](../docs/evidence/long-fuzzer-20261009/protocol.json) and
[`provenance.json`](../docs/evidence/long-fuzzer-20261009/provenance.json).
The independent six-hour audit passed for all three profiles: 1,220 attempts
and 72 paired metric checks per profile. The summary and audit copies preserve
their original SHA-256 commitments. The provenance sidecar adds only safe
aggregate timestamps, source hashes, role-exposure totals and serving image
IDs; it contains no prompts, row IDs, predictions or model weights.

For a new sustained run, use fresh isolated volumes and a new output path and
study ID.

New sustained runs use protocol schema 3, `evaluation_layers=["semantic"]`
and the `sustained-semantic-v1` results contract. The wrapper accepts only
semantic checkpoint results. Archived combined-detector runs keep their
original protocol and scores; this change does not reinterpret those archives.

From PowerShell, create a unique lowercase ID and run:

```powershell
$studyId = "privoke-long-" + [guid]::NewGuid().ToString("N")
$studyOutput = "evaluation/results/long_fuzzer_$studyId"
python evaluation/run-long-fuzzer-study.py --output $studyOutput --study-id $studyId
```

The supervisor runs each profile for two hours, pauses 15 seconds between
requests, measures approximately every 20 minutes, and exports the final
results. `supervisor.json` records the process and profile status; `results.md`
and `summary.json` are produced only after all profiles finish. Preserve
interrupted directories and volumes. The controller's duration mode uses
`--cycles` as a safety cap, which fails if reached early. An expired deadline
still resolves an ambiguous pending request under the same ID on `--resume`;
deadlines are preserved rather than reset. Full parameter snapshots may be
restricted to checkpoints with `--checkpoint-only-snapshots`, while every
round still verifies published values.

Elapsed windows include inter-request pauses, mining and checkpoint work;
reported duration is not GPU compute time. An interrupted window is not
evidence of uninterrupted training. After a future run completes, execute
`python evaluation/audit-long-fuzzer-study.py --study-root $studyOutput`.
The audit requires six hours across profiles by default and independently
recomputes paired bootstrap intervals with grouped count vectors and inclusive
quantiles. It also checks archived round/response files, publication identity
chains, settings and elapsed windows. It reads only study outputs.
`--minimum-hours 0` is reserved for testing the auditor on the brief integration
run; it cannot establish the six-hour goal.

## AdvPIIBench clean-data preflight

The pinned AdvPIIBench Parquet was downloaded and its complete 4,258,476 bytes verified against the recorded LFS SHA-256. A count-only structural scan covered 104,728 rows, found unique UIDs throughout, and recorded 24,958 components and 14,496 few-shot exclusions. The local protected-key union was also built from the opaque prior selection, reference/bootstrap rows, and existing Nemotron/Meddies partitions. These checks establish source integrity and structural exclusion coverage only: native labels have not received the required blinded whole-prompt review, and no new train/validation/test partitions, model fit, or score have been produced. See the [dataset analysis](../docs/PII-dataset-analysis.md) and [evidence ledger](../paper/research/data-expansion-ledger.md); the frozen protocol and rubric remain the authority for any later access or fitting.

## Frozen pretrained contextual head study

`run-pretrained-context-study.py` provides separate prepare/freeze/fit/evaluate/operational/secondary/report phases for the fixed 60-family, 640/160/160-row frozen-encoder comparison. Preparation stops before fitting. An accepted concrete resource/protocol review and committed-source freeze with exact byte inventory are mandatory before fit; all six validation selections precede assessment scoring. See the [prospective study procedure](../docs/semantic-pretrained-context-study-20261010.md) for exact settings, exclusions, target conventions, gates and limitations.

Use the dedicated interpreter at `evaluation/results/semantic_improvement_20261010_assets/.venv/Scripts/python.exe`, set `PRIVOKE_MODEL_DEVICE=cpu`, and keep TEMP/TMP under that asset directory's `tmp/`. The admitted NumPy 2.2.6 / ONNXRuntime 1.23.2 / tokenizers 0.22.1 environment is separate from ordinary host evaluation dependencies. The tool never starts services, publishes artifacts or promotes a model. Actual runtime phases require an isolated server attestation and explicit semantic-only responses, including used-model identity for pretrained clean empty results.

The corrected preparation is `evaluation/results/semantic_pretrained_20261010/prepared-v3/`; preceding preparations are preserved in the parent and `prepared-v2/` directories. Preparation and synthetic mechanics tests do not establish learned quality or operational readiness. Historical fixture topic-category labels differ from the new asserted-personal-disclosure target convention; reused development and fixture guards remain separate secondary evidence.
