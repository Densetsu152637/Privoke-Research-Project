# privoke-fuzzer

> Source area: `services/privoke-fuzzer`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, asks `client-runtime` to execute a bounded semantic training batch, submits the returned classification-head gradients to `param-update-service`, and runs ad hoc prompt tests through the same runtime service.

It is not in the hosted prompt decision path. Training cycles deliberately target the streamed semantic model path rather than the full regex + NER + semantic pipeline.

## gRPC Worker

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `RunPresenceTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `Health(HealthRequest) -> HealthResponse`

Default port: `50053`

Startup:

```bash
python src/main.py
```

On `RunTrainingCycle`, the service:

1. validates `prompt_count > 0`,
2. caps prompt counts above `FUZZ_MAX_PROMPT_COUNT`,
3. checks durable update status for the same source/request identity and returns an existing committed outcome on replay,
4. reserves distinct labeled clean and sensitive held-out examples, then samples training prompts excluding their normalized texts and any declared held-out source groups,
5. sends bounded training and held-out batches through `ComputeSemanticGradients`,
6. receives deltas and before/candidate metrics tied to the exact model version; rejects missing, non-finite, invalid or regressing quality evidence,
7. submits accepted deltas through `SubmitParameterUpdate` with replay identity and request fingerprint,
8. returns the committed acknowledgment and training metadata to the requester.

The fuzzer does not connect to `model-streaming-service`. Fetching, validation, caching, model execution, and gradient descent all occur inside `client-runtime`.

`RunPresenceTrainingCycle` is a separate binary annotation-presence objective. It requires an explicit `model_id` matching `PRESENCE_MODEL_ID`, and loads a prepared JSONL curriculum from `FUZZ_PRESENCE_DATASET_PATH`. Each row has a unique string `id`, nonempty `text`, strict boolean `sensitive`, and nonempty `group_id`. Sampling is deterministic, holds out both labels, and excludes normalized text and source groups across the two partitions. It sends explicit absent/present enum labels to `ComputePresenceGradients`; no contextual classifications are synthesized and no text transforms are applied. Runtime returns gradients and before/candidate metrics for the frozen representation, and only presence-head gradients are submitted. The presence quality gate requires finite metrics, positive consistent held-out counts for both labels, and no decrease in held-out exact match, present recall, or absent specificity. Presence requests use a task-specific durable fingerprint namespace so request IDs cannot replay a contextual update.

## Training Semantics

The training cycle fine-tunes the sensitivity, visibility, and multi-label category heads of the streamed transformer. The encoder remains frozen in this first architecture revision, which keeps updates small and makes online experiments repeatable.
Training and held-out execution use the same canonical text normalization as
serving, so Unicode compatibility forms, obfuscated email separators and spaced
digits have a consistent semantic representation in candidate quality checks.

`train_parameter_batch`:

- generates optional transformed variants per new example and rejects overlap with held-out normalized texts,
- delegates the complete model-dependent batch to `client-runtime`,
- receives bounded tensor deltas, metrics, fingerprints, and the exact base version,
- packages those values for `param-update-service` without receiving model weights.

Only trainable-head deltas are sent to `param-update-service`; raw prompt text is not included. Runtime quality evaluation compares the base model and exact clipped/float32 candidate on distinct held-out labels without mutating its serving cache. Publication requires training exact-match rate strictly above `FUZZ_MIN_EXACT_MATCH_RATE`, both held-out strata present, and no decrease in held-out exact-match rate, sensitive recall, or clean specificity. `candidate_heldout_safety_regression_rate` must also be zero: each example preserves at least the lesser of its target and baseline severity and policy action, including confidence-based action thresholds. Missing/invalid metrics fail the cycle. This synthetic held-out guard does not establish generalization to public benchmarks.

The update service checks the base version, atomically applies accepted deltas, increments `+train.N`, and streaming makes that artifact available on the next request. Runtime caches refresh after their configured interval. A retry after a lost acknowledgment queries durable status before generating or training new data; conflicting request reuse is rejected, and unavailable status storage prevents a new cycle.

## Prompt Generation

Default prompt seeds cover financial, health, third-party, identity/location, public, beliefs, criminal, and location cases.

Custom prompt datasets can be JSON arrays, JSON objects with `prompts`, `examples`, or `data`, or JSONL. Entries must include `template`, `text`, or `prompt`, plus either `packed_classification` or a classification object/components.

Example:

```json
{
  "template": "My {account} is behind login.",
  "packed_classification": 526,
  "metadata": {
    "dataset": "custom_financial"
  }
}
```

Templates use vocabulary slots from `src/prompt_generation/vocabulary.py`.
For document-derived curricula, supply `metadata.group_id`. The held-out sampler
reserves distinct declared groups and keeps their metadata; all siblings from
those groups are excluded from training. Insufficient groups fail the cycle.
Datasets without group metadata retain normalized-text disjointness.

## Environment Variables

- `PARAM_UPDATE_TARGET`, default `param-update-service:50052`
- `PRIVOKE_RUNTIME_TARGET`, default `client-runtime:50054`
- `MODEL_ID`, default `privoke-baseline`
- `FUZZER_ID`, default `privoke-fuzzer`
- `FUZZER_PORT`, default `50053`
- `FUZZ_TIMEOUT_SECONDS`, default `10.0`
- `FUZZ_SEED`, default `1337`
- `FUZZ_MAX_PROMPT_COUNT`, default `256`
- `FUZZ_MAX_CONCURRENT_CYCLES`, default `1`; additional simultaneous requests receive `RESOURCE_EXHAUSTED`
- `FUZZ_PROMPT_DATASET_PATH`
- `PRESENCE_MODEL_ID`, default `privoke-presence-balanced`; presence-cycle requests must name this model explicitly
- `FUZZ_PRESENCE_DATASET_PATH`; required dedicated presence JSONL curriculum
- `FUZZ_TRAINING_LEARNING_RATE`, default `0.03`
- `FUZZ_TRAINING_MAX_GRADIENT`, default `0.05`
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`, default `1`
- `FUZZ_MIN_EXACT_MATCH_RATE`, default `0.0`, finite in `[0,1]`; training rate must be strictly greater
- `FUZZ_HELDOUT_PROMPT_COUNT`, default `16`, allowed range `2` to `256`; requires distinct clean and sensitive examples
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`

## Runtime Boundary

The fuzzer has no source dependency on `extension/client-runtime`. Production and development Compose both deploy that code as the `client-runtime:50054` service, and the fuzzer waits for it to become healthy. It never calls `model-streaming-service`, the extension bridge on `8080`, its control plane on `50056`, or its workstation detector on `50057`. Prompt tests use `AnalyzePrompt`; contextual training uses `ComputeSemanticGradients`; annotation-presence training uses `ComputePresenceGradients`. Model selection, fetching, validation, caching, execution, descent, and model-version selection remain inside the runtime.

## CLI

Train and persist a new model version from inside the Compose fuzzer container:

```bash
python src/cli.py train \
  --target privoke-fuzzer:50053 \
  --model-id privoke-baseline \
  --prompt-count 32
```

Run a prompt through the runtime gRPC service:

```bash
python src/cli.py test-prompts \
  --layer runtime \
  --prompt "My email is alex@example.com"
```

Run generated prompts against multiple layers:

```bash
python src/cli.py test-prompts \
  --layer regex \
  --layer ner \
  --layer semantic \
  --model-id privoke-baseline \
  --regex-parallel \
  --generated-count 8
```

Available test layers:

- `runtime`: asks the runtime to run its complete configured detector set.
- `regex`: asks the runtime to isolate regex detection.
- `ner`: asks the runtime to isolate NER detection.
- `semantic`: asks the runtime to isolate its configured semantic backend.

Repeat `--layer` to send a selected set in one RPC. `--regex-first` and `--regex-parallel` override the runtime's default ordering for that request. `--model-id` selects the streamed semantic model and defaults to `MODEL_ID` when set. Detector failures are written to the report from the runtime's per-layer response and cause the CLI to exit with status `1`; layers intentionally skipped after a regex `BLOCK` are counted separately and are not failures.

Prompt files can be JSON, JSONL, or text. JSON entries may be strings or objects with `text`/`prompt` fields.

The CLI writes a JSON dump for each prompt-test run and prints the full per-prompt JSON report. Each prompt entry includes the request text, optional expected classification, and each selected layer's elapsed runtime time plus observed classification/action/results. If any layer run fails, it exits with status `1`.

In Docker dev mode, dumps are bind-mounted to `./dumps/privoke-fuzzer` on the host. In the production stack, `/workspace/dumps/privoke-fuzzer` is backed by the `fuzzer-dumps` named volume.

## Subagent Tasks

Subagents working here should:

- add deterministic experiment fixtures,
- improve generated prompt coverage,
- add training-cycle integration tests with streaming and update services,
- keep gradient bounds explicit,
- preserve metadata needed to trace updates back to request IDs and training config,
- preserve the runtime RPC boundary for all detector execution.

The default dataset mixes challenging compound templates with independently labeled calibration phrases also used by model bootstrap training. The held-out split is disjoint within each adaptive cycle; this calibration overlap cannot establish generalization to unseen data.
