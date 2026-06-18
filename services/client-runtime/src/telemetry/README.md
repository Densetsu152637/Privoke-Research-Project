# Telemetry

This directory contains metadata-only event generation for the client runtime.

Telemetry is downstream of detection and enforcement. It should record enough information for aggregate evaluation and detector improvement without storing raw prompts.

## Responsibilities

The telemetry emitter should capture:

- event ID,
- timestamp,
- time and date buckets,
- risk category bucket,
- risk score and score bucket,
- enforcement action,
- final `Classification`,
- derived `PriVokeAction`,
- detector version,
- entity type names,
- detector disagreement metadata.

It must not emit raw prompt text.

## Event Shape

Events should look like:

```json
{
  "event_id": "evt_...",
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
    "categories": ["IDENTITY"],
    "packed": 8223
  },
  "detector_version": "v1",
  "metadata": {
    "text_length": 48,
    "entities_detected": ["email"],
    "disagreement": false
  }
}
```

## Privacy Requirements

Telemetry must avoid:

- raw prompt text,
- exact sensitive entity values,
- exact unbucketed timestamps when aggregated telemetry is sufficient,
- free-form model reasoning if it may contain prompt fragments.

## Subagent Tasks

Telemetry subagents should:

- add aggregation-ready fields,
- add event schema tests,
- scrub free-form fields,
- improve detector version tracking,
- prepare differential privacy or k-anonymity aggregation hooks,
- keep event serialization stable for downstream services.
