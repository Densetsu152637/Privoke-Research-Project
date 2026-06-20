# Semantic Classifiers

This directory contains layer 3 of the PriVoke client-runtime detector pipeline: semantic and contextual privacy detection.

All semantic backends implement `AbstractClassifier.classify(text) -> list[ClassificationResult]`.

## Backend Selection

`src/pipeline.py` chooses a backend from `GLOBAL_CONFIG.get_llm_config()`:

- `streamed` -> `PriVokeClassifier`
- `local` -> `LocalClassifier`
- `openai` -> `OpenClassifier`

The active backend can be selected at startup with `--llm-choice` or `PRIVOKE_LLM_CHOICE`, and changed at runtime through `POST /config/llm`.

## Streamed PriVoke Backend

Files:

- `privoke_classifier.py`
- `privoke/parameter_stream.py`
- `privoke/streamed_model.py`
- `privoke/semantic_features.py`

`PriVokeClassifier` is the default backend. It fetches `ModelParametersResponse` snapshots from `model-streaming-service` through generated gRPC stubs, then classifies locally.

Current behavior:

- parameters are fetched lazily on each `classify()` call,
- `StreamedModelCache` reuses a `ParameterBackedPrivacyModel` when model ID, version, and parameter fingerprint match,
- streamed vectors calibrate thresholds, bias, and category weights,
- semantic signals are regex-like local feature patterns in `semantic_features.py`,
- one combined `ClassificationResult` is returned when signals create a non-empty classification.

The streamed backend is not a full external transformer model in this codebase. It is a local semantic feature model calibrated by streamed float vectors.

Environment:

- `MODEL_STREAMING_TARGET`, default `model-streaming-service:50051`
- `MODEL_ID`, default `privoke-baseline`
- `MODEL_STREAMING_CONSUMER_ID`, default `client-runtime`
- `MODEL_STREAMING_TIMEOUT_SECONDS`, default `10.0`

`grpcio` and the generated Python stubs must be present before this backend is imported. Docker and the dev Compose override generate stubs under `services/client-runtime/generated`; local runs must do the same from `shared/proto/privoke/v1/parameters.proto`.

## Local OpenAI-Compatible Backend

`LocalClassifier` calls an OpenAI-compatible `/v1/chat/completions` API such as LM Studio.

Behavior:

- discovers the first model from `/v1/models` if no model is configured,
- requests JSON output using either `json_schema`, `json_object`, or no response format,
- parses JSON response content into `ClassificationResult` values through `build_results`,
- returns an empty list when model content cannot be parsed as JSON.

Environment:

- `LM_STUDIO_BASE_URL`, default `http://localhost:1234/v1`
- `LM_STUDIO_MODEL`
- `LM_STUDIO_API_KEY`, default is no api key is provided (as use case is most likely a localhost)
- `LM_STUDIO_TIMEOUT_SECONDS`, default `60.0`
- `LM_STUDIO_TEMPERATURE`, default `0.25`
- `LM_STUDIO_MAX_TOKENS`, default `512`
- `LM_STUDIO_RESPONSE_FORMAT`, default `json_schema`

## OpenAI Backend

`OpenClassifier` uses the OpenAI SDK and requests `response_format={"type": "json_object"}`.

Behavior:

- requires an API key from `OPENAI_API_KEY` or runtime config,
- supports optional `OPENAI_BASE_URL` or `OPENAI_API_BASE`,
- parses response JSON through `build_results`,
- lets SDK or JSON parsing errors propagate to the caller.

Environment:

- `OPENAI_API_KEY`
- `OPENAI_MODEL`, default `gpt-4o-mini`
- `OPENAI_BASE_URL` or `OPENAI_API_BASE`
- `OPENAI_TIMEOUT_SECONDS`, default `60.0`
- `OPENAI_TEMPERATURE`, default `0.25`
- `OPENAI_MAX_TOKENS`, default `512`

## Prompt Contract for LLM Backends

`prompt.py` asks JSON-producing LLMs to return:

- `sensitivity`: `S0` through `S3`
- `visibility`: `P0`, `P1`, `P2`, `P3`, `P4`, or `PU`
- `categories`: names from the shared `Category` enum
- `section_of_text`
- `reasoning`
- `confidence`
- optional `metadata`

`build_results` defaults unknown sensitivity/visibility enum values to `S0`/`PU` and ignores unknown categories.

## Subagent Tasks

Semantic-detector subagents should:

- keep every backend returning `ClassificationResult` values,
- add tests for malformed JSON and enum defaulting behavior,
- improve `semantic_features.py` coverage for implicit disclosures,
- document any change that makes the streamed backend depend on a real model artifact rather than calibration vectors,
- avoid passing model-specific labels beyond this package boundary.
