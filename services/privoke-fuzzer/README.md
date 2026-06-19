# privoke-fuzzer

The fuzzer is a request-driven research worker for generating labeled privacy
prompts, evaluating the streamed PriVoke semantic model, and submitting update
payloads back to `param-update-service`.

## Responsibilities

The fuzzer should:

- wait for `param-update-service` to call `FuzzerService.RunTrainingCycle`,
- generate the requested number of labeled prompts,
- fetch the current parameter snapshot from `model-streaming-service`,
- run prompts through the streamed semantic model only,
- compare expected classifications with model outputs,
- submit update payloads to `param-update-service`,
- record experiment metadata,
- avoid producing updates that cannot be traced to an experiment configuration.

## Relationship to Detection Pipeline

The three-layer detection pipeline is:

1. regex/rule detection,
2. NER/entity extraction,
3. semantic context detection.

The fuzzer deliberately does not use the full client pipeline for training
cycles. It imports client-runtime code, but isolates the streamed semantic model
path so regex and NER detections do not affect the achieved result.

## Client Runtime Imports

The client runtime is exposed as the `privoke_client_runtime` package. Fuzzer
code should import client-runtime structures directly:

```python
from privoke_client_runtime.LLM.privoke.semantic_features import (
    extract_semantic_signals,
)

signals = extract_semantic_signals("my bank account is overdrawn")
```

The package is defined by `services/client-runtime/pyproject.toml`, mapping the
existing `services/client-runtime/src` tree to the import name
`privoke_client_runtime`. The fuzzer installs it via
`services/privoke-fuzzer/requirements.txt`.

## Request Flow

`param-update-service` sends:

```protobuf
FuzzerTrainingRequest {
  prompt_count: 8
  model_id: "privoke-baseline"
}
```

The fuzzer then:

1. generates `prompt_count` labeled prompts via `src/prompt_generation`,
2. evaluates them with `ParameterBackedPrivacyModel` from client-runtime,
3. trains parameter deltas from expected versus achieved classifications,
4. submits those deltas with `ParamUpdateService.SubmitParameterUpdate`,
5. returns a `FuzzerTrainingResponse` to the requester.

Relevant environment variables:

- `FUZZER_PORT`: fuzzer gRPC port, default `50053`.
- `FUZZ_MAX_PROMPT_COUNT`: upper bound for one request, default `256`.
- `FUZZ_PROMPT_DATASET_PATH`: optional JSON/JSONL prompt seed dataset.
- `FUZZ_TRAINING_LEARNING_RATE`: delta scale, default `0.03`.
- `FUZZ_TRAINING_MAX_GRADIENT`: per-weight clamp, default `0.05`.
- `FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE`: dynamic variants per generated prompt.
- `PRIVOKE_RUNTIME_URL`: client-runtime HTTP URL for runtime-layer tests.
- `PRIVOKE_FUZZER_DUMP_DIR`: prompt-test dump directory, default
  `/workspace/dumps/privoke-fuzzer`.

Prompt seed datasets should prefer packed 16-bit classifications for scale:

```json
{"template": "My {account} is behind login.", "packed_classification": 526}
```

The fuzzer decodes those values with client-runtime's `Classification` helpers.

## Prompt Testing

Local prompt testing is owned by the fuzzer so tests can target individual
detection layers instead of always hitting the full hosted runtime.

Run prompts against the hosted client-runtime server:

```bash
python src/cli.py test-prompts \
  --layer runtime \
  --prompt "My email is alex@example.com"
```

Run generated prompts against selected layers:

```bash
python src/cli.py test-prompts \
  --layer regex \
  --layer ner \
  --layer semantic-streamed \
  --generated-count 8
```

Available layers:

- `runtime`: POSTs to client-runtime `/analyze`.
- `pipeline`: runs the full client-runtime pipeline in-process.
- `regex`: runs only the deterministic rule detector.
- `ner`: runs only the NER detector.
- `semantic-streamed`: runs only the streamed PriVoke semantic model.
- `semantic-local`: runs only the LM Studio/OpenAI-compatible classifier.
- `semantic-openai`: runs only the OpenAI classifier.

In Docker dev mode, dumps are bound to `./dumps/privoke-fuzzer` on the host.
In the baseline stack, dumps stay inside the container at
`/workspace/dumps/privoke-fuzzer`.

## Subagent Tasks

Subagents working here should:

- add deterministic seeds,
- add experiment configuration files,
- add bounds for prompt counts and update magnitudes,
- add provenance metadata to updates,
- add integration tests against the streaming and update services,
- optionally generate privacy prompt hard cases for offline evaluation.
