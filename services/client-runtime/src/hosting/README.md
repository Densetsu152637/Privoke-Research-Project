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

```json
{
  "text": "prompt text",
  "source": "browser_extension",
  "visibility_hint": "P3",
  "target_app": "web_llm"
}
```

`visibility_hint` is optional. If provided, hosting code should map it into `Visibility` and pass it into the detection pipeline or context adapter rather than leaving every detector at `PU`.

## Expected Response Shape

```json
{
  "action": "ALLOW",
  "masked_text": null,
  "classification": {
    "sensitivity": "S0",
    "visibility": "PU",
    "categories": [],
    "packed": 28
  },
  "reason": "S0/S1 risk content allowed"
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
