# Semantic Classifiers

This directory contains layer 3 of the PriVoke client-runtime detector pipeline. All semantic backends implement `AbstractClassifier.classify(text) -> list[ClassificationResult]`.

## Backend Selection

`src/pipeline.py` chooses a backend from `GLOBAL_CONFIG.get_llm_config()`:

- `streamed` -> `PriVokeClassifier`
- `local` -> `LocalClassifier`
- `openai` -> `OpenClassifier`

The active backend can be selected with `--llm-choice` or `PRIVOKE_LLM_CHOICE`, and changed through `POST /config/llm`.

## Streamed PriVoke Transformer

`PriVokeClassifier` consumes `StreamModelParameters` from `model-streaming-service`. On each classification it:

1. receives ordered tensor chunks for one immutable version,
2. validates chunk order, offsets, shapes, model ID, and completeness,
3. reconstructs the NumPy transformer defined by `shared/python/privoke_model`,
4. runs local self-attention, feed-forward, and sensitivity/visibility/category heads,
5. caches that executable version until the artifact fingerprint changes.

Only the newest version of each model ID is retained in memory. Prompts never go to `model-streaming-service`; only model weights travel over that connection.

This is now a real trainable neural artifact rather than the previous regex-feature calibration placeholder. It is intentionally a compact research transformer, not a general-purpose conversational LLM. Its small size lets the repository demonstrate persistence, transport, local execution, and fuzzer fine-tuning without an external model download.

Environment:

- `MODEL_STREAMING_TARGET`, default `127.0.0.1:50051`
- `MODEL_ID`, default `privoke-baseline`
- `MODEL_STREAMING_CONSUMER_ID`, default `client-runtime`
- `MODEL_STREAMING_TIMEOUT_SECONDS`, default `10.0`

## Other Backends

`LocalClassifier` calls an OpenAI-compatible `/v1/chat/completions` endpoint such as LM Studio. `OpenClassifier` calls an OpenAI-compatible hosted endpoint through the OpenAI SDK. Both parse the JSON contract defined in `prompt.py`.
