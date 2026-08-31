# PriVoke Client Runtime

The client runtime is PriVoke's reusable prompt inspection service. It runs detector layers, returns an action (`ALLOW`, `WARN`, or `BLOCK`), and includes aggregate and per-layer evidence/errors in its gRPC response.

This package is the only component currently in the prompt classification path. The parameter-streaming service is used only when the semantic backend is set to `streamed`.

## Deployment modes

This package is instantiated in two independent contexts:

| Context | Owner | Binding | Consumer |
| --- | --- | --- | --- |
| Server simulation | Docker Compose | `[::]:50054` inside Compose; the development override also publishes `127.0.0.1:50054` | Fuzzer, evaluator, and server services |
| Browser extension | `../runtime-supervisor` | `127.0.0.1:50057` | Supervisor-owned bridge for the WebExtension |

The contexts share source code only. The extension never calls the Compose instance, and the fuzzer never calls the extension instance. The supervisor also exposes its separate control service on `127.0.0.1:50056` and its gRPC-Web bridge on `127.0.0.1:8080`.

## Local HTTP Harness

The optional local server is implemented with Python's standard `http.server` stack. It is a client-side development and integration harness, not part of the Docker Compose server deployment.

Default binding:

- host: `127.0.0.1`
- port: `8765`
- non-loopback binds require `PRIVOKE_ALLOW_NON_LOOPBACK_BIND=true`

Endpoints:

- `GET /` returns a small service index.
- `GET /health` return health metadata.
- `POST /analyze` inspect prompt text.
- `GET /config/llm` returns the current semantic backend config with API keys redacted.
- `POST /config/llm` update the live semantic backend config.
- `OPTIONS` returns CORS headers.

Analyze requests must be JSON objects. The prompt can be supplied as `text` or `prompt`.

```json
{
  "text": "My email is alex@example.com",
  "source": "browser_extension",
  "visibility_hint": "P3",
  "request_id": "req-123",
  "metadata": {
    "client": "example"
  }
}
```

Validation behavior:

- `Content-Length` is required.
- `Content-Type`, when present, must include `application/json`.
- `text`/`prompt` must be a non-empty string after trimming.
- `metadata`, when present, must be an object.
- `visibility_hint`, when present, must be one of `P0`, `P1`, `P2`, `P3`, `P4`, or `PU`.
- `PRIVOKE_MAX_PROMPT_CHARS` controls the text length limit and defaults to `20000`.

Example response:

```json
{
  "request_id": "req-123",
  "action": "BLOCK",
  "classification": {
    "sensitivity": "S3",
    "visibility": "PU",
    "categories": ["IDENTITY"]
  },
  "evidence": {
    "section_of_text": "alex@example.com",
    "span": [12, 28],
    "reasoning": "Matched rule 'email'",
    "confidence": 0.95,    
    "metadata": {
      "rule_name": "email"
    }
  },  
  "metadata": {
    "source": "browser_extension",
    "elapsed_ms": 8.2,
    "detector": "client-runtime.runtime"
  }
}
```

`masked_text` is only populated for `WARN` responses when the selected result has a valid span. It replaces that one span with `[PRIVOKE_MASKED]`.

## Pipeline

The current pipeline is in `src/pipeline.py`:

```text
raw prompt
  -> detection.normalize_text
  -> RuleDetector
  -> EntityNERDetector
  -> configured semantic classifier
  -> strongest_result
```

Important behavior:

- Normalization lowercases text, applies Unicode NFKC, replaces `[at]` and `(at)` with `@`, removes spaces between adjacent digits, collapses horizontal whitespace, and preserves newlines.
- `PRIVOKE_WAIT_FOR_REGEX` defaults to true. In that mode regex runs first and a regex `BLOCK` short-circuits NER and semantic detection.
- gRPC callers can request any subset of `regex`, `ner`, and `semantic`, and can override regex-first versus parallel scheduling per request.
- gRPC callers can set `semantic_model_id` per request to select a streamed PriVoke model without mutating global runtime configuration.
- The streamed client rejects a snapshot whose returned model ID differs from an explicitly requested model. The special `latest` alias accepts the server's resolved release-channel model ID.
- Every requested layer returns `ok`, `error`, or `skipped`; one layer failure does not erase successful results from other layers.
- When regex does not block, NER and semantic classification run through `GLOBAL_CONFIG.threadpool`.
- `strongest_result` compares `ClassificationResult.action().value` and returns the first result that raises the action above `ALLOW`.
- The local response does not currently merge all detector categories, visibility signals, or evidence into one final classification.
- If all detector results are `ALLOW`, the response uses the default `S0`/`PU` classification unless a visibility hint was provided.

## Classification Contract

Shared classification primitives live in `src/classification`.

- `Classification` is a 16-bit packed value with sensitivity, visibility, and category bits.
- `ClassificationResult` adds `section_of_text`, `reasoning`, optional `span`, optional `confidence`, and metadata.
- `classification_policy.py` derives `PriVokeAction` from each result.

Action policy:

- `S3` -> `BLOCK`.
- Low-confidence `S3` -> `WARN`.
- `S2` -> `WARN`.
- Low-confidence non-identifying `S2` -> `ALLOW`.
- `IDENTITY`/`LOCATION` combinations can warn when visibility is restricted/private or both categories are present.
- `S0`/`S1` without an action rule -> `ALLOW`.

`ClassificationResult.__post_init__` drops reserved metadata keys named `signal`, `signals`, and `source`.

## Detector Layers

Regex rules are in `src/regex`. `RuleDetector.analyze(text)` returns one `ClassificationResult` per regex or heuristic hit. Rules are grouped by visibility, identity, location, health, financial, sensitive category, and context modules.

NER is in `src/NER`. `EntityNERDetector` uses spaCy `en_core_web_sm` and maps `PERSON`, `GPE`, `LOC`, `FAC`, and `ORG` labels into PriVoke classifications. spaCy and the model are install-time dependencies from `requirements.txt`; missing packages or model data fail during import or detector initialization.

Semantic classifiers are in `src/LLM`:

- `PriVokeClassifier` validates streamed tensor chunks, reconstructs the shared NumPy transformer, caches the newest model version/fingerprint, and runs neural inference locally.
- `LocalClassifier` calls an OpenAI-compatible local API such as LM Studio.
- `OpenClassifier` calls the OpenAI SDK.

## Live Semantic Backend Config

The startup backend is controlled by `--llm-choice` or `PRIVOKE_LLM_CHOICE`.

Supported aliases:

- streamed: `streamed`, `privoke`, `model-streaming`, `model_streaming`
- local: `local`, `lm-studio`, `lm_studio`, `lmstudio`
- openai: `open`, `openai`

Examples:

```bash
curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"streamed","streamed":{"target":"127.0.0.1:50051","model_id":"latest"}}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"local","local":{"base_url":"http://localhost:1234/v1","model":"your-lm-studio-model"}}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"openai","openai":{"api_key":"sk-...","model":"gpt-4o-mini"}}'
```

Environment variables:

- `PRIVOKE_HOST`, `PRIVOKE_PORT` for the optional HTTP harness
- `PRIVOKE_GRPC_HOST`, Python default `127.0.0.1`; the server image sets `0.0.0.0`, Compose sets `[::]`, and the workstation supervisor forces `127.0.0.1`
- `PRIVOKE_GRPC_PORT`, direct/server default `50054`; the workstation supervisor sets it to `50057` for its child
- `PRIVOKE_LLM_CHOICE`
- `PRIVOKE_WAIT_FOR_REGEX`
- `PRIVOKE_MAX_PROMPT_CHARS`
- `PRIVOKE_MAX_GRPC_MESSAGE_BYTES`, default `262144`
- `PRIVOKE_MAX_GRPC_RESPONSE_BYTES`, default `1048576`
- `PRIVOKE_CORS_ORIGIN`, disabled by default; when enabled it must be one exact `http`, `https`, or supported WebExtension origin and cannot be `*`
- `PRIVOKE_ALLOW_NON_LOOPBACK_BIND`
- `MODEL_STREAMING_TARGET`, default `127.0.0.1:50051`; Compose sets `model-streaming-service:50051`
- `MODEL_ID`, default `latest`; `MODEL_STREAMING_CONSUMER_ID`; `MODEL_STREAMING_TIMEOUT_SECONDS`
- `MODEL_STREAMING_CACHE_TTL_SECONDS`, default `1.0`; coalesces concurrent
  classifications onto one immutable streamed snapshot before checking for a new version
- `PRIVOKE_MODEL_DEVICE`, default `auto`; uses CUDA or Apple MPS through PyTorch when
  available and otherwise keeps inference on the NumPy CPU backend
- `LM_STUDIO_BASE_URL`, `LM_STUDIO_MODEL`, `LM_STUDIO_API_KEY`, `LM_STUDIO_TIMEOUT_SECONDS`, `LM_STUDIO_TEMPERATURE`, `LM_STUDIO_MAX_TOKENS`, `LM_STUDIO_RESPONSE_FORMAT`
- `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `OPENAI_TIMEOUT_SECONDS`, `OPENAI_TEMPERATURE`, `OPENAI_MAX_TOKENS`
- `TELEMETRY_ENABLED`, default `false` outside Compose
- `TELEMETRY_TARGET`, default `127.0.0.1:50055`; Compose sets `telemetry-service:50055`
- `TELEMETRY_SOURCE_ID`, default `client-runtime`
- `TELEMETRY_TIMEOUT_SECONDS`, default `1.0`
- `TELEMETRY_QUEUE_SIZE`, default `1024`
- `PRIVOKE_DETECTOR_VERSION`, default `v2`

`PRIVOKE_DEV_LOG_PROMPTS=true` logs raw prompt text only for requests whose `source` contains `fuzzer`. Keep it off outside local debugging.

To expose an NVIDIA GPU to the container, use the opt-in override on a host with
the NVIDIA Container Toolkit installed:

```bash
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build
```

The normal Compose files do not request a GPU and remain portable to CPU-only hosts.
The override also installs `requirements-gpu.txt`; the base image omits PyTorch and
therefore avoids carrying CUDA libraries when only CPU inference is needed.

## Telemetry

The gRPC runtime uses `StructuredEventEmitter` and a bounded background `TelemetryReporter` when `TELEMETRY_ENABLED=true`. Prompt decisions never wait for telemetry delivery. Queue overflow or collector failure drops the packet and logs event metadata only.

Packets deliberately exclude raw prompt text, matched spans, reasoning, arbitrary request metadata, and exception messages. They contain coarse classification/action data, text length, timing, risk bucket, and requested layer statuses. Compose enables reporting to `telemetry-service`, which stores events in SQLite.

## Local Setup

```bash
cd extension/client-runtime
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install ../../shared/python
mkdir generated  # omit this line when the directory already exists
python -m grpc_tools.protoc \
  -I ../../shared/proto \
  --python_out=generated \
  --grpc_python_out=generated \
  ../../shared/proto/privoke/v1/parameters.proto \
  ../../shared/proto/privoke/v1/runtime.proto \
  ../../shared/proto/privoke/v1/telemetry.proto
```

For GPU-backed streamed-transformer inference in the workstation process used by the
browser extension, install PyTorch into this same environment:

```bash
pip install -r requirements-gpu.txt
```

With `PRIVOKE_MODEL_DEVICE=auto` (the default), CUDA is preferred, then Apple MPS, with
an automatic NumPy CPU fallback. This affects only the streamed transformer; regex and
spaCy NER continue to execute on CPU. The `docker-compose.gpu.yml` override configures a
different, server-side runtime and does not accelerate requests made by the extension.
Each streamed-transformer result includes `compute_device` metadata (`cuda`, `mps`, or
`cpu`) for verification.

The checked-in workstation defaults expect a parameter-streaming service or secure local forward on `127.0.0.1:50051`. Docker Compose supplies its own internal DNS target.

Run a standalone gRPC runtime (direct default port `50054`):

```bash
python src/grpc_main.py
```

For extension-controlled startup and shutdown, run the sibling [`runtime-supervisor`](../runtime-supervisor/README.md) package instead of starting this server directly. The supervisor forces its child to `127.0.0.1:50057`; it does not connect to an already-running service on `50054`.

Run the optional local server:

```bash
python src/main.py --port 8765 --llm-choice streamed
```

## Verification

Compile check:

```bash
python -m compileall extension\client-runtime
```

Useful smoke checks:

- email or credit card input should return `BLOCK`.
- `username: alex` or other structured identity fields should usually return `WARN`.
- pure safe text should return `ALLOW`.
- visibility-only text may not appear in hosted classification unless passed as `visibility_hint`, because the current strongest-result selector drops all-`ALLOW` evidence.
