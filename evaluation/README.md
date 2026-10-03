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
