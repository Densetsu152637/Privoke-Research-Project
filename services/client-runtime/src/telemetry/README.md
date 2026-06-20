# Telemetry

This directory contains `StructuredEventEmitter`, a prototype metadata-event helper for the client runtime.

It is not currently wired into the hosted `/analyze` request path. The active HTTP response path is `hosting/analyzer.py` and `hosting/serialization.py`.

## Current Event Emitter Contract

`StructuredEventEmitter.emit(original_text, enforcement_output, fused_output, timestamp=None)` expects older fused-output-shaped dictionaries.

Required or expected fields:

- `fused_output["classification"]`: a `Classification`
- `fused_output["raw_score"]`: optional numeric score, defaults to `0.0`
- `fused_output["rule"]["classification"]`: optional rule classification
- `fused_output["llm"]["classification"]`: optional LLM classification
- `fused_output["llm"]["entities"]`: optional entity flags
- `enforcement_output["action"]`: optional `PriVokeAction` or action string

The current pipeline does not naturally produce this full fused shape, so callers need an adapter before using this emitter with hosted analysis results.

## Event Shape

The emitter returns:

```json
{
  "event_id": "evt_20260617100000_abcdef123456",
  "timestamp": "2026-06-17T10:00:00Z",
  "time_bucket": "2026-06-17 10:00",
  "date_bucket": "2026-06-17",
  "risk_category": "PII",
  "risk_score": 0.92,
  "risk_score_bucket": "0.8-1.0",
  "action_taken": "BLOCK",
  "classification": {
    "sensitivity": "S3",
    "visibility": "PU",
    "categories": ["IDENTITY"]
  },
  "detector_version": "v1",
  "metadata": {
    "text_length": 48,
    "entities_detected": ["email"],
    "rule_classification": {
      "sensitivity": "S3",
      "visibility": "PU",
      "categories": ["IDENTITY"]
    },
    "llm_classification": {
      "sensitivity": "S0",
      "visibility": "PU",
      "categories": []
    },
    "disagreement": true
  }
}
```

## Privacy Notes

The event does not include raw prompt text or exact entity values. It does use the original prompt to compute text length and a short SHA-256-derived event ID. That hash should be treated as linkable metadata, not as differential privacy or anonymization.

Do not add free-form model reasoning to telemetry unless it is scrubbed first; reasoning can contain prompt fragments.

## Serialization

- `serialize(event)` returns formatted JSON for one event.
- `batch_serialize(events)` wraps events with `event_batch`, `batch_count`, and `batch_timestamp`.

## Subagent Tasks

Telemetry subagents should:

- adapt the emitter to the current `ClassificationResult`-based pipeline,
- keep raw prompt text and exact entity values out of emitted events,
- decide whether prompt-derived event IDs are acceptable,
- add schema tests for serialized events,
- document retention and aggregation expectations before sending telemetry off-device.
