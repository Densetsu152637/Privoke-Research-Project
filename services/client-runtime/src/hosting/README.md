# Hosting and Client Integration

This directory is reserved for code that connects the Python client runtime to a front-end or browser-side client.

The intended role is to receive prompt text from a TypeScript or browser extension runtime, pass it through the PriVoke detection pipeline, and return an enforcement decision.

## Responsibilities

Hosting code should:

- expose a local API for prompt inspection,
- receive raw prompt text and optional context metadata,
- call the client-runtime pipeline,
- return action, masked text if applicable, and classification metadata,
- avoid sending raw prompts to telemetry,
- avoid bypassing enforcement.

## Expected Request Shape

The local server listens on loopback only by default:

```bash
python src/main.py --port 8765 --llm-choice local
```

The main prompt inspection endpoint is:

```text
POST http://127.0.0.1:8765/analyze
```

```json
{
  "text": "prompt text",
  "source": "browser_extension",
  "visibility_hint": "P3",
  "target_app": "web_llm"
}
```

`visibility_hint` is optional. If provided, hosting code should map it into `Visibility` and pass it into the detection pipeline or context adapter rather than leaving every detector at `PU`.

Health checks are available at:

```text
GET http://127.0.0.1:8765/health
```

The live LLM backend configuration is available at:

```text
GET  http://127.0.0.1:8765/config/llm
POST http://127.0.0.1:8765/config/llm
```

Example LM Studio update:

```json
{
  "choice": "local",
  "local": {
    "base_url": "http://localhost:1234/v1",
    "model": "local-model-id"
  }
}
```

Example OpenAI update:

```json
{
  "choice": "openai",
  "openai": {
    "api_key": "sk-...",
    "model": "gpt-4o-mini"
  }
}
```

`GET /config/llm` redacts configured API keys.

## Expected Response Shape

```json
{
  "action": "ALLOW",
  "allowed": true,
  "masked_text": null,
  "classification": {
    "sensitivity": "S0",
    "visibility": "PU",
    "categories": [],
    "packed": 28
  },
  "reason": "No privacy risk detected.",
  "evidence": null,
  "metadata": {
    "source": "browser_extension",
    "target_app": "web_llm",
    "visibility_hint": null,
    "text_length": 11,
    "elapsed_ms": 8.2,
    "detector": "client-runtime.pipeline"
  }
}
```

## Subagent Tasks

Hosting subagents should:

- define the local API boundary,
- add request validation,
- map client metadata into `Visibility`,
- preserve raw prompt only for the active request lifecycle,
- add integration tests with browser-client fixtures,
- document how the TypeScript client should call the runtime.
