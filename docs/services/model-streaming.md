# model-streaming-service

> Source area: `services/model-streaming-service`. Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`model-streaming-service` serves persistent PriVoke contextual transformer and
sparse annotation-presence artifacts. It reloads the selected artifact for every
request, so a replaced legacy artifact becomes visible without restarting this
service or the client runtime. V1 artifacts are no longer updated by a fuzzer
(stage V3-R8b); V3 versions come from the signed publication tree.

The opt-in `privoke_tiny_transformer_v2` architecture streams the same schema-1
tensor protocol with explicit `residual_task_query_v1` readout configuration and
three task query vectors. The service validates the architecture/config pair,
exact tensor shapes and scope-dependent trainable flags before streaming.
Clients reconstruct task-specific features and logits; head updates include the
queries and full updates publish the complete candidate atomically. Existing v1
artifacts remain supported. See [the artifact contract](model-artifacts.md#opt-in-tiny-task-query-readouts)
for migration and parameter counts; support does not change the release channel.

## Standard V3 binary packages

`latest` resolves to `privoke-v3-balanced`. The maintained Go service serves the
three exact selected AU3 inference packages through `GetModelPackage` and
`StreamModelAsset`. Run `python models/prepare_standard_releases.py` from the
repository root before starting Compose. This verifies and copies the immutable
local AU3 exports into ignored `models/standard-releases`; it performs no fitting.
Compose mounts this store read-only and refuses an absent store. Deployments must
stage that prepared directory separately and set `MODEL_RELEASE_DIR`; weights are
excluded from Git and image build contexts. This task does not deploy them.

Canonical model IDs, manifest SHA-256 pins and four asset names are allowlisted.
Ordered binary chunks are bounded to 1 MiB, assets to 80 MiB, and manifests to
256 KiB. Startup verifies all asset hashes; streams recheck hashes and manifest
identity and fail on mutation. Health and client refresh check small manifests
and file identities, rather than repeatedly loading model weights. The native
product cache verifies size/hash/order and exact manifest identity before loading
the complete BERT encoder, pooler and fitted heads. No Tiny fallback is used.

Explicit `privoke-efficient`, `privoke-balanced`, `privoke-quality` and
`privoke-baseline` retain the older V1 float RPCs and their original bounds. A
server configured with an explicit legacy `MODEL_LATEST_ID` remains a legacy-only
server; it does not admit V3 packages. The separate MiniLM family remains explicit
only. Mutable legacy JSON updates cannot change the configured V3 alias or the
read-only pinned release store.

## Separate experimental v3 checkpoint service

The [pretrained v3 stack](../pretrained-v3-study.md#isolated-services-and-binary-publication)
uses an isolated Python checkpoint server and dedicated bounded binary protocol.
It validates pinned manifests and complete safetensors before atomic publication;
staged/rejected candidates do not change the serving pointer. Its 80 MiB blob,
1 MiB chunk and 256 KiB manifest bounds are independent of this Go service.
The JSON/tensor transport and 65,536-value limits below describe legacy families.
That research server remains separate from the maintained product package route above.

## Artifact

At startup, the service catalogs valid JSON artifacts in `models`. Requests may select `privoke-efficient`, `privoke-balanced`, or `privoke-quality`; an empty ID or `latest` resolves to the configured release channel. Each artifact contains:

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

The six allowlisted `privoke-scratch-presence-{efficient,balanced,quality}-{head-only,full-encoder}` IDs use their exact `<model-id>.json` filenames. The service checks those files on each explicit request, so an atomically installed artifact is available without restarting the service. It reads through the directory handle captured at startup, binds the inspected regular file to the opened descriptor, and validates the bounded bytes read from that descriptor. Removing a file returns `NOT_FOUND`; a present but invalid file returns `UNAVAILABLE`. Missing optional scratch files leave baseline health unchanged, while an invalid present file makes health `NOT_SERVING`. Unknown scratch IDs are never turned into filenames or discovered by a rescan, and scratch IDs cannot become `latest`.

The default `latest` alias resolves to `privoke-v3-balanced`; installing a
presence artifact does not change that release channel. Presence is a separate
binary task, with no inferred contextual severity or privacy action. See
[model artifacts](model-artifacts.md) and the
[prospective protocol](../../paper/research/model-refactor-protocol.md).

## API

Defined in `shared/proto/privoke/v1/parameters.proto`:

- `StreamModelParameters(ModelParametersRequest) -> stream ModelParameterChunk` is the legacy runtime-consumer API. Tensor values are sent in ordered chunks with offsets and shapes; the fuzzer calls the runtime rather than this service.
- `GetModelParameters(ModelParametersRequest) -> ModelParametersResponse` remains as a unary compatibility and inspection API.
- `GetModelPackage` returns the pinned manifest and asset size/hash declarations.
- `StreamModelAsset` streams one explicitly pinned, allowlisted binary asset.
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

## Transport and access control

The deployed service is the Rust `model-streaming-service` (`rust/services/model-streaming`, built from
`rust/services/model-streaming/Dockerfile`). It has no plaintext mode: every listener is mutual TLS, built from a
client CA, a CRL and a registry, and the binary exits before binding if any of `--cert`, `--key`, `--client-ca`,
`--crl` or `--registry` is missing or invalid. There is no reverse proxy; the service terminates TLS itself. The Go
service (`services/model-streaming-service`) is retired from deployment and kept as the parity oracle. It opened a
plaintext listener with no authentication and relied on a reverse proxy for client certificates.

| Listener | Port | RPCs | Callers |
| --- | --- | --- | --- |
| Public | `50443` in the container, published as `443` | `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset` | registered installations (role `consumer`); rate-limited per installation identity |
| Internal | `50051`, never published | `GetModelParameters`, `Health` | registered services (`publisher`, `trainer`, `runtime`) |

An RPC that a listener does not list is `UNIMPLEMENTED` there, so the private RPCs (`GetModelParameters` and every
`ParamUpdateService`, runtime and fuzzer method) are not reachable from the network. `GetModelPackage` and
`StreamModelAsset` are public, so a cloud client can fetch the default `privoke-v3-balanced` package and verify its
pin. On the public listener a request that names a `consumer_id` is refused unless it is the caller's own
installation UUID (an empty one is accepted), so the label is no longer self-asserted. The reporter credential and
unregistered certificates are refused. Revocation is a CRL applied at the handshake plus a registry deny list checked on
every request. The default `latest` model is V3, and the legacy tensor RPCs reject V3 (including an empty or `latest`
ID that resolves to it) with `FAILED_PRECONDITION`, so V3 is served only by the two package RPCs. Retrieval is
read-only: no RPC on this service writes the model directory or the pinned V3 release store. The full description,
including the environment and the health-check subcommand, is in
[the Rust workspace document](../runtime/rust-workspace.md#privoke-model-streaming) and the deployment topology in
[Google Cloud deployment](../deployment/google-cloud.md#architecture-and-prerequisites).

The measured behaviour of the retired Go service, with the legacy and V3 paths exercised
separately, is recorded in
[UPDSEC-20261116](../../paper/research/update-security-20261116.md)
(rows T1 to T14 and X1 to X16; gaps `GAP-NO-RETRIEVAL-AUTH`,
`GAP-IDENTITY-SELF-ASSERTED`, `GAP-NO-REVOCATION`). The release-store
fingerprint was unchanged across the whole run.

## Runtime

Environment variables:

- `MODEL_STREAMING_PORT`, default `50051`
- `MODEL_LATEST_ID`, default `privoke-v3-balanced`
- `MODEL_ARTIFACT_DIR`, default `/models` (legacy JSON)
- `MODEL_RELEASE_DIR`, default `/model-releases` (prepared pinned V3 packages)

Production Compose and Compute Engine use the persistent `model-data` volume: this service mounts it read-only, and the update service mounts it read-write. The initializer seeds artifacts while preserving existing trained contents. The development override replaces these model mounts with repository `./models` binds, read-only here and read-write in the updater. An atomically published revision is loaded on the next streaming request; the client cache refreshes after its configured interval rather than on every prompt.

Runtime model configuration rejects tensor layouts above 65,536 values before
allocation. Contextual transformer context remains capped at 512 tokens; presence
uses normalized full text under the runtime request text bound, with its separate
bounded vocabulary/config manifest.

The experimental `full_projected_adam64_v1` artifact policy requires the full
encoder strategy, `class_balanced_contextual_sum_category_decision_margin_v1`,
`candidate_train_exact_eligibility_v1`, and the exact canonical supported Adam
configuration shared with the Python runtime. Missing, unsupported or mixed
diagnostics/backtracking policies fail catalog validation. The summed-category
decision-margin objective uses the same S0/non-S0 label and category-threshold
checks as the earlier decision-margin objective. Existing tensor shape,
trainability and size checks still apply. Serving this metadata permits artifact
transport; it does not establish training qualification or measured quality.
## Frozen-window policy identity

Go admission recognizes the separate `full_projected_adam64_window_checkpoint_v1` optimizer, exact canonical frozen-window configuration, `candidate_window_exact_component_retention_v1` eligibility and both window/component manifest pins. It rejects orphan pins, policy mixtures and changed configuration, while preserving earlier Adam/retention contracts. Existing full tensor validation applies to both legacy and v2 task-query shapes. Stream cache identity includes all new policy/config/pin fields, preventing reuse of a snapshot under changed window semantics. No study result or default artifact is replaced by this opt-in capability.

Normal startup seeds existing legacy JSON without training. V1 training was removed in stage V3-R8b: V1 models are served for detection only. Routine training of the V3 tiers runs only under the explicit `v3-training` Compose profile, and
its signed versions reach clients through `GetModelPackage` (see [V3 publication](../runtime/v3-publication.md)). Selecting V3 reflects bounded
AU3 research results, not universal superiority or a retention guarantee.
