# model-streaming-service

`model-streaming-service` is a Go gRPC service that serves the current parameter snapshot for PriVoke experiments.

It is not a prompt classifier. The client runtime uses it only when the semantic backend is set to `streamed`; the service returns named float vectors, and the Python runtime uses those vectors to calibrate its local `ParameterBackedPrivacyModel`.

## API

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse`
- `Health(HealthRequest) -> HealthResponse`

Request:

```protobuf
ModelParametersRequest {
  consumer_id: "client-runtime"
  model_id: "privoke-baseline"
}
```

Current response behavior:

- logs the requested `consumer_id` and `model_id`,
- returns gRPC `NOT_FOUND` when a non-empty requested model ID does not match the configured `MODEL_ID`,
- returns the service-configured `MODEL_ID` and `MODEL_VERSION`,
- sets `generated_at_unix` to the current Unix timestamp,
- returns three hard-coded parameter vectors:
  - `encoder.layer.0.attention`
  - `encoder.layer.1.ffn`
  - `classifier.bias`
- returns metadata with `served_by=model-streaming-service` and the requester `consumer_id`.

The service currently hosts only one configured model snapshot. An empty model ID selects that configured model; a different non-empty ID is rejected rather than silently returning the wrong snapshot.

## Runtime

Default port: `50051`

Environment variables:

- `MODEL_STREAMING_PORT`, default `50051`
- `MODEL_ID`, default `privoke-baseline`
- `MODEL_VERSION`, default `v0.1.0`

Run directly from the service directory after protobuf generation:

```bash
go run ./cmd/server
```

Dockerfile behavior:

- installs `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc`,
- generates Go bindings under `services/model-streaming-service/gen`,
- starts `go run ./cmd/server`.

The Compose healthcheck probes the configured TCP port with `nc`.

## Consumers

- `client-runtime` streamed semantic backend fetches snapshots lazily from `PriVokeClassifier.classify`.
- `privoke-fuzzer` fetches a snapshot before each requested training cycle and through the `fetch-params` CLI command.

## Subagent Tasks

Subagents working here should:

- replace hard-coded vectors with real versioned snapshot loading when an artifact format exists,
- add a versioned model registry if multiple model IDs are supported,
- preserve protobuf compatibility when adding fields,
- add integration tests for `client-runtime` and `privoke-fuzzer` consumers,
- document parameter provenance and versioning semantics.
