# Semantic Classifiers

For current cloud credentials and the hidden local-stack switch, see [Client configuration](../runtime/client-configuration.md). Cloud is now the workstation default.

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

The generated transformer is a compact research classifier, not a general-purpose
conversational LLM. Its encoder starts from seeded NumPy random initialization;
the baseline generator bootstraps only the six sensitivity, visibility, and
category head tensors on a small synthetic phrase curriculum. The current
default Tiny semantic update path is head-only and does not use external pretrained weights.
See [in-house model training status](../in-house-model-training.md) for this
implemented path and the separately accepted, not-yet-validated end-to-end
training direction.

## Experimental Frozen Pretrained Contextual Model

The explicit streamed model ID `privoke-pretrained-context-minilm` selects
`privoke_pretrained_context_v1`. It uses a local frozen
`sentence-transformers/all-MiniLM-L6-v2` ONNX encoder and six offline-fitted
sensitivity/visibility/category head tensors (7,700 float32 values). It is an
experimental English contextual classifier. The [completed study](../semantic-pretrained-context-study-20261010.md) measured synthetic contextual gains but failed its casewise harm veto; it was not promoted. It
cannot be selected by the `latest` alias or `MODEL_LATEST_ID`. Default Tiny
models and conversational backends retain their existing behavior. Online
semantic gradient requests and parameter updates for this architecture fail
explicitly; no backbone tensors are streamed or trained.

Its immutable config binds
`category_semantics="asserted_personal_disclosure_v1"`: categories describe
asserted personal disclosures, rather than standalone topic tags. Invented or
generic discussion controls therefore have empty target categories. A disclosure
about another person's child requires both `CHILD` and `THIRD_PARTY`. This
experimental target convention does not relabel historical fixtures that permit
topic categories on S0/S1 controls, or change default Tiny targets.

Install `extension/client-runtime/requirements-pretrained-context.txt` in a
dedicated semantic-only environment; it includes pinned gRPC/protobuf,
configuration and HTTP dependencies. This path was checked with Python 3.13
on Windows. Do not combine it with `evaluation/requirements-host.txt`, whose
NumPy constraint differs. Compatibility with the default spaCy/NER environment
has not been verified. The loader requires exactly NumPy 2.2.6, ONNX Runtime
1.23.2 and Tokenizers 0.22.1. Configure
`PRIVOKE_PRETRAINED_CONTEXT_DIR` to a local directory containing only the fixed
runtime asset names `model.onnx` and `tokenizer.json` (additional provenance files
may coexist). No hub download, remote code or artifact-selected path is used.
Obtain the official files from revision
`1110a243fdf4706b3f48f1d95db1a4f5529b4d41`:

- [ONNX model](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/onnx/model.onnx), SHA-256 `6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452`.
- [Tokenizer](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/tokenizer.json), SHA-256 `be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037`.
- [Model card](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/blob/1110a243fdf4706b3f48f1d95db1a4f5529b4d41/README.md), which declares Apache-2.0 licensing; the pinned repository has no separate `LICENSE` file.

The loader verifies file bytes before constructing a CPU-only session and
tokenizer. The admitted graph takes `input_ids`, `attention_mask` and
`token_type_ids`, all int64 `[batch_size, sequence_length]`, and returns float32
`last_hidden_state` `[batch_size, sequence_length, 384]`. Features use masked
mean pooling including special tokens followed by L2 normalization. Artifacts explicitly
select a 256- or 512-token limit including special tokens. Builders and offline
encoding default to 256 for historical reproduction. A 512-token artifact has a
distinct version/checksum even with identical heads; encoder caches include the
limit, and mismatched configurations fail. Overlength input raises a semantic
layer error without silent truncation. The original study used 256. A later
nine-request semantic-only check verified 512-token execution, short-input parity
and boundary rejection, including recovery of the two formerly overlength inputs.
This checks execution capacity, not accuracy or latency at the expanded limit.
Missing assets/dependencies, hash/signature drift and non-finite output also
remain visible errors, with the ordinary failure policy and no fallback.

The pipeline applies detector normalization once. Runtime heads consume
`FrozenPretrainedEncoder.encode_normalized`; offline callers use `encode` or
`features` on raw text. `privoke_model.pretrained_context.build_head_artifact`
serializes the exact six flat head arrays with frozen serving flags. Head refreshes
reuse the frozen encoder, while artifact checksum changes replace the wrapper.
Successful clean results remain empty findings. For every admitted pretrained
snapshot, even a clean result or subsequent inference error, the gRPC response
metadata supplies `privoke.pretrained_context.` keys `model_id`, `model_version`,
`artifact_checksum`, `parameter_fingerprint`, `backbone_sha256` and
`tokenizer_sha256`. Failed asset admission supplies none of these keys; request
metadata cannot impersonate them. Evaluations must explicitly select only the
semantic layer and verify returned execution and model identity.

## Separate Annotation-Presence Model

The runtime also exposes an explicitly separate `annotation_presence` task through
`DetectAnnotationPresence` and `ComputePresenceGradients`. It loads only model IDs in
the `privoke-presence-*` family and validates the `privoke_sparse_presence_v1`
architecture before inference. This bounded word/character TF-IDF model predicts only
whether an annotation is present. It does not predict sensitivity, visibility,
categories, or policy actions, and it is not inserted into the semantic classifier.
The ordinary prompt-decision pipeline does not use its output. The additive
`AnalyzePromptRequest.semantic_presence_gate` field enables an explicit research-only
cascade: for a request that also names streamed `semantic_model_id="privoke-balanced"`
and includes the semantic layer, the runtime runs both models and suppresses only the
original semantic results when the presence decision is ABSENT. PRESENT retains the
original semantic results. Regex and NER findings are never gated or suppressed.
The model weights are streamed to the client and both inferences run locally; prompt
text is not sent to the model-streaming service. ABSENT can remove a valid private
semantic-only finding, so this experiment is not safety-validated and is not a
deployment recommendation.

The caller must explicitly name one of `privoke-presence-efficient`,
`privoke-presence-balanced`, or `privoke-presence-quality`. An optional finite
decision-threshold override in `[0, 1]` is request-scoped; it does not mutate the
artifact's stored threshold or weights. Presence output still does not assign
sensitivity, visibility, categories, or policy actions, and an ABSENT result does not
make a prompt clean or safe. Check the typed per-layer gate trace for APPLIED status,
both model identities, probabilities, thresholds, labels, and preserved raw semantic
results. Errors remain visible, and the ordinary failure policy applies. Older servers
may ignore the additive request field; a caller must verify the returned trace.

This option is exploratory. It has no default enablement or validated safety claim;
the [prospective cascade protocol](../../paper/research/contextual-cascade-protocol.md)
records the planned controls and limitations.

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

The conversational policy now requires supported textual evidence and distinguishes
general discussion or explicitly invented examples from asserted personal facts.
It forbids inventing identifying facts or external linkage, retains actual disclosures
inside quotations, hypothetical frames or mixed passages, and treats public availability
separately from sensitivity. Sensitivity, visibility and categories retain their existing
definitions; unstated visibility is `PU`. The analyzed text is encoded as one JSON string
and instructions within it are designated as data. These are prompt instructions, not a
verified injection-resistance guarantee or a measured improvement in accuracy.

Both backends receive the same system policy and request exactly one JSON object
containing a `results` array. The exact envelope `{"results": []}` is now a valid
explicit no-risk response and yields a successful empty finding list; the runtime's
existing empty-result aggregation remains clean. Complete explicit `S0` findings remain
compatible. Bare `[]`, `{}`, an empty envelope with additional error keys, malformed
JSON and partial/mixed-invalid findings remain errors. This is a deliberate external
output contract change from the earlier requirement for a nonempty clean finding.

The streamed `PriVokeClassifier` reconstructs and executes tensor parameters and does
not consume `prompt.py`; this conversational revision does not change the current
streamed curriculum experiment, its training data, gradients or publication guard.
Compatibility checks use mocked chat responses. Actual hosted/local model accuracy
and prompt-injection behavior require separately authorized semantic-only evaluation.

Both external backends validate complete classification results before accepting them. Missing/unknown sensitivity, visibility or category values, malformed fields, non-finite/out-of-range confidence, invalid spans, and mixed valid/invalid result lists cause a layer error instead of a clean default. Local responses may use a complete Markdown JSON fence, but partial JSON surrounded by arbitrary text is rejected. Error messages exclude raw model content. The internal legacy `build_results` parser remains available for trusted callers.
