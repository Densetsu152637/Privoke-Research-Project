# model-streaming-service

> Source area: `services/model-streaming-service`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`model-streaming-service` serves persistent PriVoke contextual transformer and
sparse annotation-presence artifacts. It reloads the selected artifact for every
request, so an atomically published fuzzer update becomes visible without
restarting this service or the client runtime.

## Artifact

The service catalogs every valid JSON model artifact in `models`. Requests may select `privoke-efficient`, `privoke-balanced`, or `privoke-quality`; an empty ID or `latest` resolves to the configured release channel. Each artifact contains:

- schema, model, architecture, and version identifiers,
- transformer/tokenizer dimensions and output labels,
- named row-major tensors with explicit shapes and float values,
- a per-tensor `trainable` flag,
- training revision metadata and a checksum.

The baseline is roughly 400 KB and is deliberately plain JSON, so it can be reviewed, diffed, committed, and pushed with normal Git. `models/generate_baseline.py` deterministically recreates the release baseline.

When fitted presence artifacts are installed in the catalog, callers select
`privoke-presence-efficient`, `privoke-presence-balanced` or
`privoke-presence-quality` explicitly. Their architecture is
`privoke_sparse_presence_v1`, task `annotation_presence`; their config includes
learned word/character vocabularies, TF-IDF settings, normalization and threshold.
Their frozen IDF tensors and trainable coefficient/bias blocks are validated
against the exact profile manifest. The profiles allow at most 2,000/8,000/16,000
features per branch and 8,001/32,001/64,001 IDF-plus-head values respectively.
Coefficient blocks contain at most 4,096 values. Config is bounded to 2 MiB and
the existing 65,536 numeric-value and 8 MiB artifact limits remain in force.

The default `latest` alias still resolves to `privoke-balanced`; installing a
presence artifact does not change that release channel. Presence is a separate
binary task, with no inferred contextual severity or privacy action. See
[model artifacts](README.Model-artifacts.md) and the
[prospective protocol](../paper/research/model-refactor-protocol.md).

## API

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `StreamModelParameters(ModelParametersRequest) -> stream ModelParameterChunk` is the primary runtime-consumer API. Tensor values are sent in ordered chunks with offsets and shapes; the fuzzer calls the runtime rather than this service.
- `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse` remains as a unary compatibility and inspection API.
- `Health(HealthRequest) -> HealthResponse` returns `SERVING` only while the configured artifact can be loaded and validated.

Each stream is pinned to one artifact version. The service verifies the canonical
artifact checksum before serving it, and consumers reject reordered, incomplete,
discontinuous, non-finite, or mixed-version streams before constructing a model.

Only the first chunk contains model metadata/configuration. Presence metadata
includes task, profile, normalization and arithmetic identifiers alongside the
existing architecture, checksum and trainable manifest. The shared snapshot cache
identity includes architecture/config and tensor fingerprints, preventing reuse
across incompatible tasks or changed release data. Presence detection/training
use additive runtime RPCs rather than changing this tensor transport. Rebuild
affected images and regenerate consumer bindings when adopting those RPCs; older
consumers retain the contextual path.

## Runtime

Environment variables:

- `MODEL_STREAMING_PORT`, default `50051`
- `MODEL_LATEST_ID`, default `privoke-balanced`
- `MODEL_ARTIFACT_DIR`, default `/models`

Production Compose and Compute Engine use the persistent `model-data` volume: this service mounts it read-only, and the update service mounts it read-write. The initializer seeds artifacts while preserving existing trained contents. The development override replaces these model mounts with repository `./models` binds, read-only here and read-write in the updater. An atomically published revision is loaded on the next streaming request; the client cache refreshes after its configured interval rather than on every prompt.

Runtime model configuration rejects tensor layouts above 65,536 values before
allocation. Contextual transformer context remains capped at 512 tokens; presence
uses normalized full text under the runtime request text bound, with its separate
bounded vocabulary/config manifest.
