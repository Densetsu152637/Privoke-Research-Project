# Hosting and HTTP Integration

This package exposes the client runtime as a local HTTP service. It owns request validation, endpoint routing, runtime LLM configuration updates, visibility-hint application, response serialization, CORS headers, and warning-span masking.

## Files

- `server.py`: `ThreadingHTTPServer` setup and HTTP request handler.
- `models.py`: `PromptInspectionRequest` and validation error type.
- `serialization.py`: request parsing, response serialization, error payloads, and `WARN` masking.
- `analyzer.py`: calls `pipeline_analyse_text` and applies `visibility_hint`.
- `runtime_config.py`: serializes and updates the live semantic classifier configuration.

## Endpoints

Default server:

```bash
python src/main.py --host 127.0.0.1 --port 8765 --llm-choice streamed
```

Endpoint aliases:

- `GET /`
- `GET /health`
- `POST /analyze`
- `GET /config/llm`
- `POST /config/llm`
- `OPTIONS *`

The server binds to loopback by default. Binding to `0.0.0.0` or another non-loopback address requires `PRIVOKE_ALLOW_NON_LOOPBACK_BIND=true`, which Docker Compose sets for the containerized runtime.

## Analyze Request Shape

```json
{
  "text": "prompt text",
  "source": "browser_extension",
  "visibility_hint": "P3",
  "target_app": "web_llm",
  "request_id": "req-123",
  "metadata": {}
}
```

`prompt` is accepted as an alias for `text`.

Validation behavior:

- request body must be a JSON object,
- `text`/`prompt` must be a non-empty string after trimming,
- prompt length is capped by `max_text_chars` or `PRIVOKE_MAX_PROMPT_CHARS`,
- `metadata` must be an object when provided,
- optional string fields must be strings,
- `visibility_hint` must match a `Visibility` enum name.

## Analyze Response Shape

```json
{
  "request_id": "req-123",
  "action": "WARN",
  "allowed": true,
  "classification": {
    "sensitivity": "S2",
    "visibility": "P2",
    "categories": ["IDENTITY"]
  },
  "reason": "Matched rule 'structured_identity'",
  "evidence": {
    "section_of_text": "phone: 0400 000 000",
    "span": [3, 22],
    "reasoning": "Matched rule 'structured_identity'",
    "confidence": 0.95,
    "action": "WARN",
    "metadata": {
      "rule_name": "structured_identity"
    }
  },
  "metadata": {
    "source": "browser_extension",
    "target_app": "web_llm",
    "visibility_hint": "P3",
    "text_length": 22,
    "elapsed_ms": 8.2,
    "detector": "client-runtime.pipeline"
  }
}
```

## Live LLM Config

`GET /config/llm` returns the active backend config and redacts API keys.

`POST /config/llm` accepts nested sections:

```json
{
  "choice": "local",
  "local": {
    "base_url": "http://localhost:1234/v1",
    "model": "local-model-id",
    "api_key": null,
    "timeout_seconds": 60,
    "temperature": 0.25,
    "max_tokens": 512,
    "response_format": "json_schema"
  }
}
```

Supported `choice` aliases are parsed by `LLMChoice.parse`.

## Logging and CORS

The server logs request metadata only. It does not log request bodies except when `PRIVOKE_DEV_LOG_PROMPTS=true` and the request `source` contains `fuzzer`; that dev path prints raw fuzzer prompt text for debugging.

CORS defaults to `*` and can be changed with `--cors-origin` or `PRIVOKE_CORS_ORIGIN`.

## Subagent Tasks

Hosting subagents should:

- add endpoint tests for validation failures,
- keep raw prompt text out of logs by default,
- review whether `BLOCK` responses should ever include masked text,
- document browser-extension calling conventions when a client is added,
