# param-update-service

> Source area: `services/param-update-service`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`param-update-service` accepts bounded tensor updates, atomically applies them to the persistent PriVoke model artifact, and appends an audit record to JSONL. It can also request training cycles from `privoke-fuzzer` after startup.

It is experiment infrastructure, not part of the hosted prompt classification path.

## API

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `SubmitParameterUpdate(ParameterUpdateRequest) -> ParameterUpdateAck`
- `Health(HealthRequest) -> HealthResponse`

`SubmitParameterUpdate`:

- validates required identifiers, the configured model ID, metadata sizes, unique gradient names, value counts, finite values, and the maximum absolute gradient,
- loads and validates `MODEL_ARTIFACT_PATH`,
- rejects stale `base_version` values and updates to frozen, unknown, or misshaped tensors,
- applies deltas and atomically replaces the Git-storable JSON artifact,
- increments the artifact version as `<release>+train.<revision>`,
- appends one mode-`0600` audit line to `PARAM_UPDATE_STORAGE_PATH`,
- logs source, model, and gradient count,
- returns `accepted=true`,
- returns the actually committed artifact version.

Stored JSONL shape:

```json
{
  "source_id": "server-fuzzer",
  "model_id": "privoke-baseline",
  "base_version": "v0.2.0",
  "applied_version": "v0.2.0+train.1",
  "gradients": [
    {
      "name": "head.sensitivity.bias",
      "shape": [4],
      "values": [0.0, 0.0, 0.0, 0.01]
    }
  ],
  "metadata": {
    "request_id": "param-update-service-..."
  }
}
```

The current implementation does not perform idempotency checks, retention enforcement, or privacy filtering beyond rejecting oversized metadata. It never accepts raw prompt text as a dedicated field.

## Runtime

Default port: `50052`

Environment variables:

- `PARAM_UPDATE_PORT`, default `50052`
- `PARAM_UPDATE_STORAGE_PATH`, default `/data/updates.jsonl`
- `MODEL_ARTIFACT_PATH`, default `/models/privoke-baseline.json`
- `PARAM_UPDATE_MAX_ABS_GRADIENT`, default `1.0`
- `PARAM_UPDATE_MAX_MESSAGE_BYTES`, default `1048576`
- `MODEL_ID`, default `privoke-baseline`; updates for other model IDs are rejected

Docker Compose persists audit data in `param-update-data` and bind-mounts `./models` read-write. The streaming service mounts the same repository directory read-only. After a successful training cycle, `git diff -- models/privoke-baseline.json` shows the new version and weights, and the artifact can be committed normally.

The `Health` RPC returns `SERVING` only when the audit path is writable and the model artifact is valid and replaceable.

## Fuzzer Requests

If `FUZZER_PROMPT_COUNT` is greater than zero, the service starts a daemon requester thread after gRPC startup.

Environment variables:

- `FUZZER_TARGET`, default `privoke-fuzzer:50053`
- `FUZZER_PROMPT_COUNT`, default `0`
- `MODEL_ID`, default `privoke-baseline`
- `PARAM_UPDATE_SOURCE_ID`, default `param-update-service`
- `FUZZER_REQUEST_TIMEOUT_SECONDS`, default `30.0`
- `FUZZER_REQUEST_INTERVAL_SECONDS`, default `0.0`
- `FUZZER_REQUEST_INITIAL_DELAY_SECONDS`, default `2.0`
- `FUZZER_REQUEST_RETRY_SECONDS`, default `2.0`
- `FUZZER_REQUEST_MAX_ATTEMPTS`, default `3`
- `FUZZER_REQUEST_SEED`, default `1337`

When enabled, it sends:

```protobuf
FuzzerTrainingRequest {
  request_id: "<source>-<unix>-<suffix>"
  source_id: "param-update-service"
  model_id: "privoke-baseline"
  prompt_count: 8
  seed: 1337
  metadata: {
    "initiator": "param-update-service"
  }
}
```

If `FUZZER_REQUEST_INTERVAL_SECONDS` is `0`, the requester stops after one successful request or after `FUZZER_REQUEST_MAX_ATTEMPTS` consecutive failures. If the interval is positive, it keeps requesting on that interval and retries failures after `FUZZER_REQUEST_RETRY_SECONDS`.
Retries of one cycle retain the same `request_id`; a new ID is allocated only after a
successful cycle and interval.

## Relationship to Other Services

- Receives updates from `privoke-fuzzer` through `SubmitParameterUpdate`.
- May initiate `FuzzerService.RunTrainingCycle`.
- Does not call `client-runtime`.
- Publishes into the shared artifact path; `model-streaming-service` reloads it on the next request.

## Subagent Tasks

Subagents working here should:

- preserve and extend validation for required identifiers, metadata, and gradient bounds,
- add idempotency keys before repeated training requests become common,
- add a storage abstraction if JSONL is no longer enough,
- document retention and privacy constraints,
- keep raw prompt text out of update metadata unless an experiment explicitly approves it.
