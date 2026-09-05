# privoke-fuzzer

> Source area: `services/privoke-fuzzer`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, asks `client-runtime` to execute a bounded semantic training batch, submits the returned classification-head gradients to `param-update-service`, and runs ad hoc prompt tests through the same runtime service.

It is not in the hosted prompt decision path. Training cycles deliberately target the streamed semantic model path rather than the full regex + NER + semantic pipeline.

## gRPC Worker

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `RunTrainingCycle(FuzzerTrainingRequest) -> FuzzerTrainingResponse`
- `Health(HealthRequest) -> HealthResponse`

Default port: `50053`

Startup:

```bash
python src/main.py
```

On `RunTrainingCycle`, the service:

1. validates `prompt_count > 0`,
2. caps prompt counts above `FUZZ_MAX_PROMPT_COUNT`,
3. generates labeled prompts through `src/prompt_generation`,
4. sends one bounded `ComputeSemanticGradients` request to `PrivokeRuntimeService`,
5. receives gradients tied to the exact model version used by the runtime,
6. submits those deltas to `ParamUpdateService.SubmitParameterUpdate`,
7. returns the update acknowledgment and training metadata to the requester.

The fuzzer does not connect to `model-streaming-service`. Fetching, validation, caching, model execution, and gradient descent all occur inside `client-runtime`.

## Training Semantics

The training cycle fine-tunes the sensitivity, visibility, and multi-label category heads of the streamed transformer. The encoder remains frozen in this first architecture revision, which keeps updates small and makes online experiments repeatable.

`train_parameter_batch`:

- generates optional transformed variants per new example,
- delegates the complete model-dependent batch to `client-runtime`,
- receives bounded tensor deltas, metrics, fingerprints, and the exact base version,
- packages those values for `param-update-service` without receiving model weights.

Only trainable-head deltas are sent to `param-update-service`; raw prompt text is not included. The update service checks the base version, atomically applies the deltas, increments `+train.N`, and the next runtime request receives that version.

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
- `FUZZ_TRAINING_LEARNING_RATE`, default `0.03`
- `FUZZ_TRAINING_MAX_GRADIENT`, default `0.05`
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`, default `1`
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`

## Runtime Boundary

The fuzzer has no source dependency on `extension/client-runtime`. Production and development Compose both deploy that code as the `client-runtime:50054` service, and the fuzzer waits for it to become healthy. It never calls `model-streaming-service`, the extension bridge on `8080`, its control plane on `50056`, or its workstation detector on `50057`. Prompt tests use `AnalyzePrompt`; training uses `ComputeSemanticGradients`. Model selection, fetching, validation, caching, execution, descent, and model-version selection remain inside the runtime.

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
