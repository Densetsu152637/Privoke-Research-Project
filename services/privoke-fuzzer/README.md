# privoke-fuzzer

`privoke-fuzzer` is a Python gRPC worker and CLI for PriVoke research experiments. It generates labeled prompts, evaluates the streamed semantic model, computes bounded parameter-gradient deltas, submits updates to `param-update-service`, and can run ad hoc prompt tests against individual runtime layers.

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
2. rejects counts above `FUZZ_MAX_PROMPT_COUNT`,
3. fetches the current parameter snapshot from `model-streaming-service`,
4. generates labeled prompts through `src/prompt_generation`,
5. evaluates them with client-runtime's `ParameterBackedPrivacyModel`,
6. computes gradient deltas with `src/training`,
7. submits those deltas to `ParamUpdateService.SubmitParameterUpdate`,
8. returns the update acknowledgment and training metadata to the requester.

If the model-streaming service is unavailable after retries, the RPC aborts with `UNAVAILABLE`.

## Training Semantics

This service does not run a full ML training job. It treats streamed parameter vectors as trainable calibration values for the local semantic feature model.

`train_parameter_batch`:

- converts streamed parameters into a client `ParameterSnapshot`,
- uses default trainable parameters when the snapshot is empty,
- generates optional transformed variants per new example,
- predicts classifications with `ParameterBackedPrivacyModel`,
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
- `PRIVOKE_RUNTIME_URL`, default `http://client-runtime:8765` for CLI runtime tests
- `PRIVOKE_FUZZER_DUMP_DIR`, default `/workspace/dumps/privoke-fuzzer`
- `PRIVOKE_TEST_SEMANTIC_BACKEND`, default `streamed` for CLI `--layer semantic`

## Client Runtime Imports

The fuzzer installs `services/client-runtime` as the `privoke_client_runtime` package via `services/privoke-fuzzer/requirements.txt`. Its requirements also declare the Hugging Face, PEFT, TRL, datasets, and torch packages used by the research training notes.

Example:

```python
from privoke_client_runtime.LLM.privoke.semantic_features import (
    extract_semantic_signals,
)

signals = extract_semantic_signals("my bank account is overdrawn")
```

## CLI

Fetch parameters:

```bash
python src/cli.py fetch-params \
  --target model-streaming-service:50051 \
  --consumer-id client-runtime \
  --model-id privoke-baseline
```

Run a prompt through the hosted runtime:

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
  --layer semantic-streamed \
  --generated-count 8
```

Available test layers:

- `runtime`: POSTs to client-runtime `/analyze`.
- `pipeline`: runs the full client-runtime pipeline in-process.
- `regex`: runs only `RuleDetector`.
- `ner`: runs only `EntityNERDetector`.
- `semantic`: alias resolved by `--semantic-backend`.
- `semantic-streamed`: runs `PriVokeClassifier`.
- `semantic-local`: runs `LocalClassifier`.
- `semantic-openai`: runs `OpenClassifier`.

Prompt files can be JSON, JSONL, or text. JSON entries may be strings or objects with `text`/`prompt` fields.

The CLI writes a JSON dump for each prompt-test run and prints a summary. If any layer run fails, it exits with status `1`.

In Docker dev mode, dumps are bind-mounted to `./dumps/privoke-fuzzer` on the host. In the baseline stack, dumps stay inside the container at `/workspace/dumps/privoke-fuzzer`.

## Subagent Tasks

Subagents working here should:

- add deterministic experiment fixtures,
- improve generated prompt coverage,
- add training-cycle integration tests with streaming and update services,
- keep gradient bounds explicit,
- preserve metadata needed to trace updates back to request IDs and training config,
- avoid mixing full hosted pipeline results into streamed-only training unless that is an intentional experiment change.
