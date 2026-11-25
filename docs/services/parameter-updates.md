# param-update-service

> Source area: `rust/services/param-update` (the Python `services/param-update-service` is the retired parity oracle). Commands retain their original working-directory assumptions; follow explicit directory instructions, or use this source area for component-local commands.

`param-update-service` is the Rust service that owns the V3 checkpoint store and the routine-training scheduler. Once per round it asks `v3-fuzzer` for one HEADS fit and one FULL_ENCODER fit of each of the three V3 tiers. Each candidate passes the DriftGate, the GuardGate and the RetentionGate and is then published under an Ed25519-signed statement. The gates, the publication tree, key custody and rollback are specified in [V3 publication](../runtime/v3-publication.md).

It is experiment infrastructure, not part of the hosted prompt classification path. V1 models are served for detection only and are no longer trained: the V1 gradient update RPCs were removed in stage V3-R8b and answer `UNIMPLEMENTED` (`rust/services/param-update/src/lib.rs`, `server.rs`, `service.rs`).

## API

Defined in `shared/proto/privoke/v1/parameters.proto` and `shared/proto/privoke/experimental/v3.proto`:

- `ParamUpdateService.SubmitParameterUpdate`: answers `UNIMPLEMENTED` for every caller. It is not in the transport policy.
- `ParamUpdateService.GetParameterUpdateStatus(ParameterUpdateStatusRequest) -> ParameterUpdateStatus`: looks up a recorded V1 receipt; `publisher` and `trainer` services only. A non-empty `source_id` must equal the caller's service name.
- `ParamUpdateService.Health(HealthRequest) -> HealthResponse`: `publisher`, `trainer` and `runtime` services (the container probe and the operator).
- `CheckpointService` (when `V3_STORE` is set): `CommitCandidate` for `publisher` and `trainer` services only; `StageCheckpoint`, `ResolveCurrent`, `FetchBlob`, `GetCommitStatus` and `Health` also for `runtime` services (`v3-runtime` stages the candidates it fits and never commits them); `RollbackModel` for `publisher` services only.

The remaining V1 pieces are the receipt store, the model bootstrap and the engine shell that serve the status lookup and health.

## Gates and publication

A commit is admitted by the store and then checked in this order (`rust/services/param-update/src/main.rs` installs the chain; the gates are in `v3_guard.rs` and `v3_retention.rs`, publication is `v3_publish.rs`):

1. `DriftGate` (always on when the store is on; `V3_DRIFT_BOUNDS` is required with `V3_STORE`): the candidate may not move farther than the calibrated bounds from its parent or from its routine root.
2. `GuardGate` over the scheduler's journal: the commit must be one the scheduler allocated, with the allocated base, sampler, scope and source commitment, and the guard rows and the recomputed guard result must hold.
3. `RetentionGate` (when `V3_RETENTION_ROOT` and `V3_RETENTION_BANK` are set): the candidate is scored on the approved ORIGINAL TRAIN bank against the tier's reference release.
4. The publisher (when `V3_PUBLISH_ROOT` is set): stage the files, then sign and record the statement inside the compare-and-swap transaction, then publish the directory and move the pointer last.

Each refusal is a durable `rejected` receipt with a reason. `V3_PUBLICATION_KEY_FILE` (a mounted secret holding the Ed25519 seed) and `V3_PUBLICATION_KEY_ID` select the signing key.

## Access control

The service is one mutual-TLS listener (`50052`, never published) built from the fail-closed `privoke-transport` configuration. It refuses to start without a client CA, a CRL and a registry, and no public listener routes any `ParamUpdateService` or `CheckpointService` method. It runs only in the `v3-training` profile. Roles are as listed under [API](#api); the scheduler's own client identity is `param-update`, registered `publisher`.

## Runtime

Default port: `50052`

Environment variables of the listener:

- `PARAM_UPDATE_PORT`, default `50052`; `PARAM_UPDATE_BIND`, default `0.0.0.0`
- `PARAM_UPDATE_STORAGE_PATH`, default `/data/updates.jsonl`; the receipt database is its sibling
- `PARAM_UPDATE_MAX_MESSAGE_BYTES`, default `1048576`
- `PARAM_UPDATE_RATE_PER_SECOND` and `PARAM_UPDATE_RATE_BURST`, per-identity request rate

`PARAM_UPDATE_MAX_ABS_GRADIENT`, `PARAM_UPDATE_DRIFT_POLICY`, `PARAM_UPDATE_MAX_UPDATE_L2` and `PARAM_UPDATE_MAX_CUMULATIVE_L2` are no longer read.

V3 store, publication and gates (`rust/services/param-update/src/config.rs`): `V3_STORE` enables the checkpoint store and requires `V3_SOURCE_ROOT` and `V3_DRIFT_BOUNDS`; `V3_INITIAL` and `V3_PINNED` admit ORIGINAL packages and pinned routine roots at startup; `V3_PUBLISH_ROOT` with `V3_PUBLICATION_KEY_FILE` and `V3_PUBLICATION_KEY_ID` enables signed publication; `V3_RETENTION_ROOT` and `V3_RETENTION_BANK` enable the RetentionGate and are set together or not at all; `V3_AUDIENCE_MANIFEST_PATH` and `V3_AUDIENCE_MANIFEST_SHA256` (both or neither) select a custom AU3 release.

The Compose stacks persist the audit, receipt and scheduler data in `param-update-data` and the store and published tree in `v3-store` and `v3-published`. The deployment values are listed in [V3 publication](../runtime/v3-publication.md#deployment-stage-v3-r7).

## Fuzzer Requests

The scheduler runs when `V3_STORE` is set and `FUZZER_PROMPT_COUNT` is positive (`main.rs`; with a positive count and no store the service logs that routine training is off). It is the single allocator of each request's id, seed and expected base: it journals the allocation durably before it calls `v3-fuzzer` (`scheduler.rs`, `journal.rs`), computes the source commitment itself, and after a restart asks the store (`GetCommitStatus`) what became of an in-flight request before it asks the fuzzer again. A lost fit is replaced by a new allocation with a new request id and seed. HEADS and FULL_ENCODER commits are independent publications, not one atomic transaction.

Environment variables (defaults from `FuzzerRequestConfig::defaults`):

- `FUZZER_TARGET`, default `v3-fuzzer:50053` in the binary; the Compose files set `v3-fuzzer:50172`
- `FUZZER_PROMPT_COUNT`, default `256`, the frozen original-prompt budget of the 64-step policy (the fuzzer refuses any other value); `0` disables the scheduler
- `FUZZER_REQUEST_INTERVAL_SECONDS`, default `10800`; `0` requests one round and stops
- `FUZZER_REQUEST_TIMEOUT_SECONDS`, default `3600`
- `FUZZER_REQUEST_INITIAL_DELAY_SECONDS`, default `2`; `FUZZER_REQUEST_RETRY_SECONDS`, default `30`; `FUZZER_REQUEST_MAX_ATTEMPTS`, default `3`
- `FUZZER_REQUEST_SEED`, default `1337`, unsigned 32-bit initial seed
- `FUZZER_CYCLE_STATE_PATH`, default `/data/training-cycles.sqlite3`, the durable allocation journal
- `V3_POLICY_FILE`, default `/config/v3-policy.json`, the canonical 64-step policy
- `V3_TIERS`, default `efficient,balanced,quality`
- `FUZZER_TLS_SERVER_NAME`, default the host of `FUZZER_TARGET`

Back up the journal with the store and the published tree. The V1 receipt store is reachable only through `GetParameterUpdateStatus`.

## Relationship to Other Services

- Calls `v3-fuzzer` (`V3FuzzerService.RunTrainingCycle`) as a `publisher` client.
- Receives `CommitCandidate` from `v3-fuzzer` (role `trainer`) and `StageCheckpoint` from `v3-runtime` (role `runtime`).
- Publishes a signed tree under `V3_PUBLISH_ROOT`; `model-streaming-service` reads the store and the tree and serves the current version through `GetModelPackage`.
- Does not call `client-runtime` and no longer writes the V1 model artifacts.

## Subagent Tasks

Subagents working here should:

- keep the gate order and the durable rejection receipts intact,
- keep the scheduler the only allocator of request ids, seeds and expected bases,
- keep the key out of images, logs and repositories (see [V3 publication](../runtime/v3-publication.md#key-custody)),
- keep raw prompt text out of receipts and metadata.
