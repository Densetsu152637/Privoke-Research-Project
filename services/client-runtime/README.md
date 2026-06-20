# PriVoke Client Runtime

The client runtime is PriVoke's local prompt inspection package. It is intended to run on a user's local computer, not as a server-side microservice. It runs the detector pipeline, returns an action (`ALLOW`, `WARN`, or `BLOCK`), and includes the strongest available classification evidence in the response.

This package is the only component currently in the prompt classification path. The parameter-streaming service is used only when the semantic backend is set to `streamed`.

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
    "detector": "client-runtime.pipeline"
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

- `PriVokeClassifier` fetches snapshots from `model-streaming-service`, caches a `ParameterBackedPrivacyModel` by model/version/fingerprint, and classifies with local semantic feature patterns calibrated by streamed float vectors.
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
  -d '{"choice":"streamed","streamed":{"target":"model-streaming-service:50051","model_id":"privoke-baseline"}}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"local","local":{"base_url":"http://localhost:1234/v1","model":"your-lm-studio-model"}}'

curl -X POST http://127.0.0.1:8765/config/llm \
  -H "Content-Type: application/json" \
  -d '{"choice":"openai","openai":{"api_key":"sk-...","model":"gpt-4o-mini"}}'
```

Environment variables:

- `PRIVOKE_HOST`, `PRIVOKE_PORT`
- `PRIVOKE_LLM_CHOICE`
- `PRIVOKE_WAIT_FOR_REGEX`
- `PRIVOKE_MAX_PROMPT_CHARS`
- `PRIVOKE_CORS_ORIGIN`
- `PRIVOKE_ALLOW_NON_LOOPBACK_BIND`
- `MODEL_STREAMING_TARGET`, `MODEL_ID`, `MODEL_STREAMING_CONSUMER_ID`, `MODEL_STREAMING_TIMEOUT_SECONDS`
- `LM_STUDIO_BASE_URL`, `LM_STUDIO_MODEL`, `LM_STUDIO_API_KEY`, `LM_STUDIO_TIMEOUT_SECONDS`, `LM_STUDIO_TEMPERATURE`, `LM_STUDIO_MAX_TOKENS`, `LM_STUDIO_RESPONSE_FORMAT`
- `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `OPENAI_TIMEOUT_SECONDS`, `OPENAI_TEMPERATURE`, `OPENAI_MAX_TOKENS`

`PRIVOKE_DEV_LOG_PROMPTS=true` logs raw prompt text only for requests whose `source` contains `fuzzer`. Keep it off outside local debugging.

## Local Setup

```bash
cd services/client-runtime
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

For streamed classification outside Docker, generate the gRPC stubs into `services/client-runtime/generated` from `shared/proto/privoke/v1/parameters.proto` before importing the streamed backend or starting the local server. The fuzzer image also generates these stubs because it imports this package directly.

Run the optional local server:

```bash
python src/main.py --port 8765 --llm-choice streamed
```

## Telemetry

`src/telemetry/event_emitter.py` is a metadata event helper for older fused-output-shaped dictionaries. It is not called by the hosted `/analyze` path. Treat it as a prototype component until it is adapted to the current `pipeline_analyse_text` response model.

## Verification

Compile check:

```bash
python -m compileall services\client-runtime
```

Useful smoke checks:

- email or credit card input should return `BLOCK`.
- `username: alex` or other structured identity fields should usually return `WARN`.
- pure safe text should return `ALLOW`.
- visibility-only text may not appear in hosted classification unless passed as `visibility_hint`, because the current strongest-result selector drops all-`ALLOW` evidence.
