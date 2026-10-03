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
The integrated live result is 93.56% recall and 22.69% specificity; final remains
unscored and the 90% specificity development target is not met.

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
