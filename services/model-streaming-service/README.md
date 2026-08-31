# model-streaming-service

`model-streaming-service` serves the persistent PriVoke transformer family. It reloads the selected artifact for every request, so an atomically published fuzzer update becomes visible without restarting this service or the client runtime.

## Artifact

The service catalogs every valid JSON model artifact in `models`. Requests may select `privoke-efficient`, `privoke-balanced`, or `privoke-quality`; an empty ID or `latest` resolves to the configured release channel. Each artifact contains:

- schema, model, architecture, and version identifiers,
- transformer/tokenizer dimensions and output labels,
- named row-major tensors with explicit shapes and float values,
- a per-tensor `trainable` flag,
- training revision metadata and a checksum.

The baseline is roughly 400 KB and is deliberately plain JSON, so it can be reviewed, diffed, committed, and pushed with normal Git. `models/generate_baseline.py` deterministically recreates the release baseline.

## API

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `StreamModelParameters(ModelParametersRequest) -> stream ModelParameterChunk` is the primary client/fuzzer API. Tensor values are sent in ordered chunks with offsets and shapes.
- `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse` remains as a unary compatibility and inspection API.
- `Health(HealthRequest) -> HealthResponse` returns `SERVING` only while the configured artifact can be loaded and validated.

Each stream is pinned to one artifact version. The service verifies the canonical
artifact checksum before serving it, and consumers reject reordered, incomplete,
discontinuous, non-finite, or mixed-version streams before constructing a model.

## Runtime

Environment variables:

- `MODEL_STREAMING_PORT`, default `50051`
- `MODEL_LATEST_ID`, default `privoke-balanced`
- `MODEL_ARTIFACT_DIR`, default `/models`

Compose bind-mounts the repository `models` directory read-only into this service. The update service mounts the same directory read-write and publishes balanced-model replacements atomically.
