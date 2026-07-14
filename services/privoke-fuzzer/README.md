# privoke-fuzzer

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, asks the local PriVoke runtime to evaluate them, computes bounded parameter-gradient deltas, submits updates to `param-update-service`, and runs ad hoc prompt tests through the same runtime RPC.

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
3. fetches the current parameter snapshot from `model-streaming-service`,
4. generates labeled prompts through `src/prompt_generation`,
5. requests isolated semantic evaluation from `PrivokeRuntimeService`,
6. computes gradient deltas with `src/training`,
7. submits those deltas to `ParamUpdateService.SubmitParameterUpdate`,
8. returns the update acknowledgment and training metadata to the requester.

If the model-streaming service is unavailable after retries, the RPC aborts with `UNAVAILABLE`.

## Training Semantics

This service does not run a full ML training job. It treats streamed parameter vectors as trainable calibration values for the local semantic feature model.

`train_parameter_batch`:

- converts streamed parameters into its local experiment snapshot value,
- uses default trainable parameters when the snapshot is empty,
- generates optional transformed variants per new example,
- obtains predicted classifications from the runtime gRPC service,
- computes classification loss over sensitivity, visibility, and categories,
- accumulates bounded per-parameter gradient deltas,
- returns both gradients and locally updated parameter values for metadata/fingerprints.

Only gradients are sent to `param-update-service`.

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

- `MODEL_STREAMING_TARGET`, default `model-streaming-service:50051`
- `PARAM_UPDATE_TARGET`, default `param-update-service:50052`
- `PRIVOKE_RUNTIME_TARGET`, default `privoke-runtime:50054`
- `MODEL_ID`, default `privoke-baseline`
- `FUZZER_ID`, default `privoke-fuzzer`
- `FUZZER_PORT`, default `50053`
- `FUZZ_TIMEOUT_SECONDS`, default `10.0`
- `FUZZ_SEED`, default `1337`
- `FUZZ_MAX_PROMPT_COUNT`, default `256`
- `FUZZ_PROMPT_DATASET_PATH`
- `FUZZ_TRAINING_LEARNING_RATE`, default `0.03`
- `FUZZ_TRAINING_MAX_GRADIENT`, default `0.05`
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`, default `1`
- `MODEL_STREAMING_FETCH_MAX_ATTEMPTS`, default `5`
- `MODEL_STREAMING_CONNECT_TIMEOUT_SECONDS`, default `2.0`
- `MODEL_STREAMING_RETRY_INITIAL_SECONDS`, default `1.0`
- `MODEL_STREAMING_RETRY_MAX_SECONDS`, default `4.0`
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`

## Runtime Boundary

The fuzzer has no dependency on `services/client-runtime`. Prompt tests send one `AnalyzePrompt` request containing the requested layer set and regex ordering. Training requests the semantic layer through the same client. Detector selection, initialization, scheduling, short-circuiting, and error capture all remain inside the runtime.

## CLI

Fetch parameters:

```bash
python src/cli.py fetch-params \
  --target model-streaming-service:50051 \
  --consumer-id privoke-fuzzer \
  --model-id privoke-baseline
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
  --regex-parallel \
  --generated-count 8
```

Available test layers:

- `runtime`: asks the runtime to run its complete configured detector set.
- `regex`: asks the runtime to isolate regex detection.
- `ner`: asks the runtime to isolate NER detection.
- `semantic`: asks the runtime to isolate its configured semantic backend.

Repeat `--layer` to send a selected set in one RPC. `--regex-first` and `--regex-parallel` override the runtime's default ordering for that request. Detector failures are written to the report from the runtime's per-layer response and cause the CLI to exit with status `1`.

Prompt files can be JSON, JSONL, or text. JSON entries may be strings or objects with `text`/`prompt` fields.

The CLI writes a JSON dump for each prompt-test run and prints the full per-prompt JSON report. Each prompt entry includes the request text, optional expected classification, and each selected layer's observed classification/action/results. If any layer run fails, it exits with status `1`.

In Docker dev mode, dumps are bind-mounted to `./dumps/privoke-fuzzer` on the host. In the baseline stack, dumps stay inside the container at `/workspace/dumps/privoke-fuzzer`.

## Subagent Tasks

Subagents working here should:

- add deterministic experiment fixtures,
- improve generated prompt coverage,
- add training-cycle integration tests with streaming and update services,
- keep gradient bounds explicit,
- preserve metadata needed to trace updates back to request IDs and training config,
- preserve the runtime RPC boundary for all detector execution.
