# Semantic Classifiers

For current cloud credentials and the hidden local-stack switch, see [Client configuration](README.Client-configuration.md). Cloud is now the workstation default.

> Source area: `extension/client-runtime/src/LLM`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

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
3. reconstructs the transformer defined by `src/model.py`,
4. runs local self-attention, feed-forward, and sensitivity/visibility/category heads
   on CUDA/MPS when available, with a NumPy CPU fallback,
5. caches that executable version and coalesces concurrent classifications for a short
   refresh interval before checking the streaming service for a new artifact.

Only the newest version of each model ID is retained in memory. Prompts never go to `model-streaming-service`; only model weights travel over that connection.

`PrivokeRuntimeService.ComputeSemanticGradients` also executes inside this boundary. It accepts a bounded labeled batch, reuses the cached streamed model, computes and bounds classification-head deltas, and returns the exact base version plus fingerprints and metrics. Model tensors are never sent to the fuzzer.

This is now a real trainable neural artifact rather than the previous regex-feature calibration placeholder. It is intentionally a compact research transformer, not a general-purpose conversational LLM. Its small size lets the repository demonstrate persistence, transport, local execution, and fuzzer fine-tuning without an external model download.

## Separate Annotation-Presence Model

The runtime also exposes an explicitly separate `annotation_presence` task through
`DetectAnnotationPresence` and `ComputePresenceGradients`. It loads only model IDs in
the `privoke-presence-*` family and validates the `privoke_sparse_presence_v1`
architecture before inference. This bounded word/character TF-IDF model predicts only
whether an annotation is present. It does not predict sensitivity, visibility,
categories, or policy actions, and it is not inserted into the semantic classifier or
the prompt-decision pipeline. Presence results never suppress regex or NER findings.

`ComputePresenceGradients` updates only the sparse logistic head; its vocabulary and
IDF tensors remain frozen. Optional held-out examples must contain both binary labels
and must not share normalized text or declared groups with training. The response
reports the exact candidate evaluated with the same float32 publication arithmetic.
This RPC returns deltas and does not itself publish or mutate a serving artifact.

Environment:

- `PRIVOKE_CLOUD_TARGET` for cloud; `PRIVOKE_USE_LOCAL_STACK=true` selects `127.0.0.1:50051`
- `MODEL_ID`, default `latest`
- `MODEL_STREAMING_CONSUMER_ID`, default `client-runtime`
- `MODEL_STREAMING_TIMEOUT_SECONDS`, default `10.0`
- `MODEL_STREAMING_CACHE_TTL_SECONDS`, default `1.0`
- `PRIVOKE_MODEL_DEVICE`, default `auto` (`auto`, `cpu`, `cuda`, or `mps`)

## Other Backends

`LocalClassifier` calls an OpenAI-compatible `/v1/chat/completions` endpoint such as LM Studio. `OpenClassifier` calls an OpenAI-compatible hosted endpoint through the OpenAI SDK. Both parse the JSON contract defined in `prompt.py`.


Both external backends validate complete classification results before accepting them. Missing/unknown sensitivity, visibility or category values, malformed fields, non-finite/out-of-range confidence, invalid spans, and mixed valid/invalid result lists cause a layer error instead of a clean default. No-risk responses must contain an explicit valid `S0` result; empty arrays are errors. Local responses may use a complete Markdown JSON fence, but partial JSON surrounded by arbitrary text is rejected. Error messages exclude raw model content. The internal legacy `build_results` parser remains available for trusted callers.
