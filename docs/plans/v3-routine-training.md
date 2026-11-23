# Plan: routine training on the V3 models

Revision: 2026-11-23, revised after the plan gate (feat/rust-rewrite 505aa85; design report RUST-V3R-DESIGN; plan-gate findings D1-D12, N1-N8 and M1-M4)

User decision, 23 November 2026, verbatim: "the routine training should train all of the V3 models, not the V1 models. The V1 models should be available for the detection pipeline, but should be removed from training."

User decisions on the open questions, 23 November 2026:

- **U1, client trust:** a new V3 version is accepted on lineage plus a publication signature. The version must descend from the pinned ORIGINAL, its evidence must pass the guard, and it must be signed by a param-update publication key compiled into the client.
- **U2, routine data:** the frozen BC01 (taxonomy plus benign) and AU3 (audience) releases, with a fresh seed per cycle. No new curriculum pipeline.
- **U3, retention:** a V3 retention check gates publication (stage V3-R9).
- **U4, presence:** presence training is retired. The V1 presence gate keeps working for detection with its current model.

Root defaults, which the user may override:

- **U5, compute:** CPU-only Rust fits. Stage V3-R5 measures the per-tier cycle time. Threshold: a full routine round (3 tiers x HEADS and FULL_ENCODER) must finish within the scheduler interval on the deployment VM's CPUs; if the quality FULL fit alone exceeds 60 minutes on 8 CPUs, root stops before V3-R7 and asks the user (CUDA, fewer steps, or a longer interval). CUDA is otherwise out of scope.
- **U6, V1 training code:** the Rust V1 training path is removed (stage V3-R8). The Python V1 training code is frozen, not deleted, because it is the oracle for the committed Rust goldens and for reproducing the historical training studies.
- **Python clients:** the Rust controller (W4) is the client. Python `v3_package.py` is frozen at the compiled pins and gains no lineage admission. To keep historical evaluations working after the first publication, model-streaming keeps a pin-addressed way to fetch each ORIGINAL (V3-R3), and V3-R3 lists the Python consumers that fetch by model id.

## Goals

- **G1. The routine cycle trains all three V3 tiers.** A deployment-like mTLS test runs the scheduler through `privoke-v3-{efficient,balanced,quality}`, with HEADS then FULL_ENCODER per tier, and journals each outcome. Verified by the stage V3-R6 test.
- **G2. A trained V3 version reaches clients only through lineage plus a signed publication statement.**
  - The supervisor fetch refuses: a wrong ORIGINAL, a bad or missing signature, an unknown key id, a statement for another model, and a sequence lower than the client's persisted high-water mark (replay and downgrade, including the unsigned ORIGINAL once a signed version was seen).
  - An intentional rollback is a new signed statement with a higher sequence pointing at an earlier manifest, and it is accepted.
  - During a key-rotation overlap both key ids are accepted.
  - After the refresh interval (`V3_PACKAGE_REFRESH_SECONDS`, defined in V3-R4b) a valid newer statement replaces the cached snapshot.
  - The signature attests param-update's admission only; the trainer's self-reported guard evidence is not a security control on the client.
  - Verified by the V3-R4a and V3-R4b tests and new rows in `evaluation/update_security.py`.
- **G3. Publication is atomic, single-authority and bounded.**
  - One authoritative record holds each tier's current version; the published directory and pointer are derived from it and repaired from it at startup.
  - Crash injection at every step boundary (staged, signed, renamed, authority swapped, pointer updated) leaves the old or the new version fully served, never a missing or unsigned one.
  - A stale base, an over-budget drift, a guard failure (recomputed by param-update, not read from trainer evidence) or a retention failure is refused, and nothing changes.
  - A restart between fit and commit neither stalls the tier nor commits different bytes under a reused request id.
  - Verified by the V3-R2, V3-R5 and V3-R9 tests.
- **G4. Pinned behaviour is unchanged until something is published.** With nothing published, model-streaming is byte-identical to its Go-parity corpus (`tests/go_standard_v3.rs`), and the pinned ORIGINAL fetch golden (`fetch_golden.rs`) is unchanged.
- **G5. No V1 model is trained.**
  - The scheduler makes no V1 `FuzzerService` call.
  - At the supervisor's public gRPC surface, `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` and `ComputePresenceGradients` answer `UNIMPLEMENTED`, and a test proves the Python worker is never invoked for them (no refusal fallback).
  - The Rust V1 training code is gone.
  - Verified by the V3-R8a and V3-R8b tests and greps.
- **G6. V1 detection is unchanged.** The V1 analysis goldens of stages 14 and 17, the presence-gate golden, and the V1 catalog serving corpus pass unchanged.
- **G7. LLM isolation.** Every V3 fit and analysis test sends `[SEMANTIC]` and asserts the executed layer. None sends an empty layer list.
- **G8. CI.** Rust workspace CI and service stack CI are green on the integrated head. Each *ported* contract (the checkpoint store and its evidence validator) has a Python oracle golden; the new contracts (signed statements, lineage admission, drift bounds, V3 retention) are specified here and tested by Rust tests only, since Python is frozen.

## Scope and non-goals

- **Scope:** Rust only. param-update hosts the V3 checkpoint store and publication. v3-fuzzer gains a routine mode. model-streaming serves published V3 versions. The supervisor fetch gains lineage admission. The scheduler and deployment are cut over. V1 is removed from the Rust training path.
- **Non-goals:**
  - CUDA.
  - Binary package deltas. Revisit if full-package refreshes prove too costly; every tier is under the 80 MB asset cap.
  - New curricula.
  - Presence training.
  - Changing V1 inference.
  - Deleting the Python oracles.
  - Re-running historical studies.

## Assumptions

- The deployment is not live, so cutover can happen at any time.
- The v3-runtime `FitCandidate` (stage 22) is the fit, and its parity is established.
- The Python `services/pretrained-v3/src/checkpoint_store.py` is the oracle for the store port.
- Plan stage 10 of `rust-server-rewrite.md` (the checkpoint server) is folded into V3-R1.

## Relevant paths

- `rust/services/param-update/src/{scheduler,journal,apply,policy,receipts,audit,bootstrap}.rs`
- `rust/services/v3-fuzzer/src/{cycle,source,config}.rs`
- `rust/services/v3-runtime`
- `rust/services/model-streaming/src/{releases,service,catalog}.rs`
- `rust/services/runtime-supervisor/src/fetch.rs`
- `rust/crates/privoke-contracts/src/v3.rs`
- `rust/crates/privoke-training/src/{v3_fit,reference,window,...}.rs`
- `rust/services/fuzzer`
- `rust/services/runtime/src/training.rs`
- `services/pretrained-v3/src/{checkpoint_store,fuzzer_training}.py` (oracle)
- `deploy/gce/compose.yml`, `docker-compose.prod.yml`
- `evaluation/update_security.py`

## Related docs

- [Rust rewrite plan](rust-server-rewrite.md). This plan wins for the training target. Stage 10 there is superseded by V3-R1.
- [Rust workspace](../runtime/rust-workspace.md).
- [Client runtime](../runtime/client-runtime.md).

## Stage V3-R1: Port the V3 checkpoint store into param-update

- Objective:
  - A Rust `CheckpointService` in param-update, on the internal listener for the publisher and trainer roles, ported from `checkpoint_store.py`. Its proto is `shared/proto/privoke/experimental/v3.proto`, which v3-fuzzer already calls.
  - It is content-addressed and holds the `current(model, manifest)` authority table.
  - It runs `admit_candidate` (lineage, provenance, config and inventory unchanged, changed tensors verified, HEADS changes only `heads.*`), `stage`, and the compare-and-swap `commit` with request-id idempotence.
  - Port `validate_source_evidence` with it.
  - Move `validate_execution` and `publication_passes` into `privoke-contracts::v3`, out of `privoke-training::v3_fit` and v3-fuzzer's duplicate `contract.rs`. Param-update, v3-fuzzer and the supervisor then share one copy.
- Depends on: none.
- Owned paths: `rust/services/param-update/src/v3_store/`, `rust/crates/privoke-contracts/src/v3.rs` (the moved functions), `rust/services/v3-fuzzer/src/contract.rs` (de-duplicated), `evaluation/generate_checkpoint_store_golden.py`.
- Acceptance checks:
  - The golden replay of admit, stage and commit outcomes and reasons (including `stale_base`, `guard_rejected` and request-id reuse) equals the Python oracle.
  - The v3-fuzzer recorded replay (23 fits) passes against the Rust store.
  - Rust CI is green.
- Status: in progress (RUST-V3R1, 23 Nov 2026; plan gate converged in 4 rounds).
- Outcome:
- Handoff notes: the sqlite `current` table is the single authority for every later stage.

## Stage V3-R2: Signed publication, derived directory and drift bounds

- Objective:
  - **Signed statement.** A domain-separated statement `{tag, key_id, model_id, manifest_sha, parent, original, sequence}` with a per-model monotonic `sequence`. It is signed by a dedicated Ed25519 publication key. The key is not a TLS key: it is mounted as a secret and never baked into an image. The ModelPackage response proto gains a field for the statement.
  - **Commit order.** Stage the files with fsync into a private staging area. Then, inside the one `BEGIN IMMEDIATE` transaction that performs the compare-and-swap, run the stale-base and gate checks, allocate the sequence and sign. After the transaction commits, rename the staged directory into `<root>/<model-id>/<manifest-sha>/` and update the derived `current` pointer. Staging is durable, on the same filesystem as the published root. Startup reconciliation promotes a staged directory that the authority references (an interrupted rename), repairs the pointer from the authority, and deletes or quarantines any published or staged directory the authority does not reference; staging is cleaned only after promotion. A candidate that loses the race is never signed and never published. Directory fsync is a no-op on Windows.
  - **Rollback.** An operator RPC, restricted to the publisher role, issues a new statement with a higher sequence pointing at a manifest from that model's authority history, the ORIGINAL included.
  - **Drift bounds.** Per-update L2 and cumulative L2 from the pinned ORIGINAL, separately for HEADS and FULL_ENCODER. R2 ships *provisional* bounds, configurable per tier and scope, and enforces them. V3-R5 recalibrates them from real-weight fits of every tier and scope (twice the largest observed L2) and records the numbers and their source here. The existing recorded fits cannot be used: the v3-fuzzer golden is synthetic and the stage 22 fixtures use a toy checkpoint.
  - **Routine guard-row selection.** One shared function in `privoke-curriculum` (`v3::routine_guard_rows(release, seed, source_commitment)`), owned by this stage, defines how a routine seed selects the 16 guard rows from the frozen BC01/AU3 releases. V3-R5 calls it; nothing else re-implements it.
  - **Guard recomputation.** Param-update rebuilds the 16 guard rows itself from the frozen BC01/AU3 releases, the scheduler-allocated seed and the `source_commitment`, never from rows the trainer supplies. It recomputes the guard on both the base and the candidate with the Rust V3 encoder, loading the candidate through `V3Model::with_tensors`, not through `admitted_manifest`. This runs before the transaction and is bound to the candidate SHA.
  - **Key custody and rotation.** Clients compile a key set indexed by `key_id`. Test keys exist only behind a `test-keys` cargo feature.
- Depends on: V3-R1.
- Owned paths: `rust/services/param-update/src/{v3_publish,v3_policy,v3_guard}.rs`, `rust/crates/privoke-curriculum/src/v3.rs` (`routine_guard_rows`), `rust/services/param-update/config/v3-drift-bounds.toml` (format and provisional values), the ModelPackage proto field, `docs/runtime/v3-publication.md` (custody and rotation).
- Note: the drift bounds are final only after V3-R5's recalibration.
- Acceptance checks:
  - Crash injection at each boundary (staged, transaction committed, renamed, pointer updated), plus a "candidate lost the race" case, leaves the old or the new version fully served after restart and reconciliation. No signed statement exists for a candidate that lost the race.
  - Negative tests: a stale base, an over-budget update, a guard failure on recomputation, forged trainer evidence claiming a pass, and forged guard rows are each refused, and nothing changes.
  - Rollback is refused for a caller without the publisher role and for a manifest outside the model's history.
  - For the same seed and commitment, the rows param-update recomputes equal the rows `routine_guard_rows` gives the fuzzer.
  - A rollback statement is issued with a higher sequence.
  - The rotation document exists.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: the rotation overlap is tested in V3-R4a. Record in `docs/runtime/v3-publication.md` the accepted limitation that the high-water mark lives in the client cache, so a wiped cache re-admits the unsigned ORIGINAL once (trust on first use).

## Stage V3-R3: model-streaming serves published V3 versions

- Objective:
  - `GetModelPackage(privoke-v3-<tier>)` returns the current published manifest with its signed statement, or the pinned ORIGINAL when nothing is published.
  - `StreamModelAsset` serves only manifest SHAs that the authority references (current or in the rollback history), never anything merely present on disk.
  - A pin-addressed request still returns each ORIGINAL after publication, so historical results stay reproducible.
  - `latest` stays `privoke-v3-balanced`.
  - List the Python consumers that fetch V3 by model id, and confirm each one uses the pin-addressed path or is unaffected.
- Depends on: V3-R2.
- Owned paths: `rust/services/model-streaming/src/{releases,published}.rs`.
- Acceptance checks:
  - G4: the Go corpus is byte-identical with nothing published.
  - A published candidate is served with its statement.
  - An unpublished SHA, or a directory on disk that the authority does not reference, gets `INVALID_ARGUMENT`.
  - The ORIGINAL stays fetchable by pin after publication.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: the Go-parity claim ends at the pinned set.

## Stage V3-R4a: Client lineage and signature admission

- Objective: add a new lineage-admission function in `privoke-contracts::v3`, and use it through `LineageAdmission` in `runtime-supervisor/src/fetch.rs`. `admitted_manifest` stays pin-only, because `privoke-semantic/src/v3.rs` and `runtime/src/semantic.rs` share it. A manifest is accepted when all of these hold:
  - the signed statement verifies under a compiled `key_id`;
  - the statement names this model and this manifest;
  - its sequence is above the persisted high-water mark, or equal to it with the same `manifest_sha`;
  - the statement's `parent` and `original` equal the manifest's own fields;
  - either `validate_manifest` passes and `original` equals the compiled tier pin, or the manifest *is* the compiled tier pin (a signed rollback to the ORIGINAL).

  An unsigned manifest is admitted only when it is the compiled tier pin and no high-water mark exists yet for that model (first start, unchanged behaviour).

  The statement and the high-water mark are persisted in the cache and re-verified on restart.
- Depends on: V3-R2 (statement format and keys), V3-R3.
- Owned paths: `rust/services/runtime-supervisor/src/fetch.rs`, `rust/crates/privoke-contracts/src/v3.rs` (the new lineage-admission function only), the cache layout, `evaluation/update_security.py`.
- Acceptance checks:
  - G2 attack rows, each refused: wrong ORIGINAL, bad signature, unknown key, a statement for another model, replay of a lower sequence, the same sequence with a different manifest, a statement whose parent or original differs from the manifest, and downgrade to the unsigned ORIGINAL after a signed version.
  - A signed rollback to the ORIGINAL is accepted.
  - A key-rotation overlap accepts both keys.
  - G4: `fetch_golden.rs` is unchanged.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: the highest-security change. A critic reviews the diff.

## Stage V3-R4b: Refresh, snapshot reload and cache housekeeping

- Objective:
  - Define `V3_PACKAGE_REFRESH_SECONDS`. On refresh, admit a newer statement through V3-R4a and reload the worker snapshot.
  - At an offline start-up, select the cached version at the high-water mark.
  - Garbage-collect superseded versions, always keeping the ORIGINAL.
- Depends on: V3-R4a.
- Owned paths: the supervisor refresh loop, the worker snapshot reload, and the two loader call sites `rust/crates/privoke-semantic/src/v3.rs` (model load) and `rust/services/runtime/src/semantic.rs`, which accept a non-pinned manifest only when the supervisor has verified it.
- Acceptance checks:
  - A published candidate replaces the cached snapshot after the interval.
  - An offline restart serves the high-water version.
  - Garbage collection never removes the ORIGINAL or the current version.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R5: v3-fuzzer routine mode

- Objective:
  - A routine mode beside the frozen study mode, using BC01 and AU3 with a fresh seed per cycle (U2).
  - The fuzzer computes and records the `source_commitment` itself, and selects guard rows only through `privoke-curriculum::v3::routine_guard_rows` (V3-R2).
  - The scheduler (V3-R6) is the only allocator of `(request_id, seed, expected_base)`; it journals them before the call and passes them to the fuzzer, which only records them. On restart the scheduler queries `GetCommitStatus` for the journalled request id before re-requesting; if the earlier fit was lost, the scheduler allocates a new request id. Until V3-R6 lands, the R5 tests act as the scheduler.
  - It commits the candidate through the param-update store.
  - It measures the per-tier cycle time and applies the U5 threshold.
  - It recalibrates the V3-R2 drift bounds from real-weight fits of every tier and scope, writes the values into `rust/services/param-update/config/v3-drift-bounds.toml` (this stage owns the values; V3-R2 owns the format), and records them in this plan.
- Depends on: V3-R1, and V3-R2's `routine_guard_rows` (which V3-R2 lands first).
- Owned paths: `rust/services/v3-fuzzer/src/{cycle,source,config}.rs`.
- Acceptance checks:
  - The frozen-mode recorded replay (23 fits) is identical.
  - An mTLS test completes a routine HEADS-then-FULL cycle for each tier, sending `[SEMANTIC]` only.
  - A crash after the fit and before the commit neither stalls the tier nor causes a request-id content conflict.
  - The timings are recorded against the U5 threshold.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R6: Scheduler targets V3

- Objective: param-update's scheduler loops over the three V3 tiers and two stages through the `V3FuzzerService` client, taking `expected_base` from the store authority. It is the single allocator and journal of `(request_id, seed, expected_base)`, including the restart rule stated in V3-R5.
- Depends on: V3-R5 and V3-R2, so that the G1 test runs through the signed, bounded commit path.
- Owned paths: `rust/services/param-update/src/{scheduler,journal}.rs`.
- Acceptance checks:
  - G1: 3 tiers × 2 stages are journalled and restart-safe.
  - No V1 `FuzzerService` call remains in `scheduler.rs`.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: re-run the G1 test after V3-R9 lands.

## Stage V3-R9: V3 retention gate (U3)

- Objective:
  - First move the retention constants and helpers that `reference.rs` uses into a V3-neutral module, so that V3-R8b can delete the V1 modules: `BANK_SHA256`, `BOUNDARY`, `EPSILON`, `safety_margin`, `is_sensitive`, `teacher_tensors`.
  - Generalise `privoke_training::reference` to a V3 teacher. The approved bank is the one pinned by `BANK_SHA256` (`train-sensitive-retention/approved-train-bank.json`). First check that every bank row's labels map onto the V3 heads' outputs; if they do not, stop and report to root, who names a V3 bank. Build per-tier V3 reference releases from the pinned ORIGINALs, with new pins, loading candidates through `V3Model::with_tensors`.
  - Param-update computes retention on the candidate before the commit transaction, bound to the candidate SHA; the commit only checks that result.
- Depends on: V3-R2.
- Owned paths: `rust/crates/privoke-training/src/{reference,retention_v3}.rs`, `rust/crates/privoke-training/src/{retention,window}.rs` (extraction only), `rust/services/param-update/src/v3_retention.rs`, the reference-release generator.
- Acceptance checks:
  - Every bank row maps onto the V3 head outputs (or a V3 bank is named).
  - A regressing candidate is refused, and a non-regressing one passes.
  - The reference releases are reproducible from the pins.
  - Commit and status calls for other tiers meet their deadlines while a quality-tier retention check runs.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: runs in parallel with V3-R3 to V3-R6. It must land before V3-R7.

## Stage V3-R7: Deployment cutover

- Objective:
  - Add v3-runtime and v3-fuzzer, with their certificates, to `deploy/gce/compose.yml` and `docker-compose.prod.yml`. Give param-update the publication key secret, a read-only mount of the frozen BC01/AU3 releases (for guard rows), the V3 reference releases (for retention) and the drift-bounds config.
  - Remove `privoke-fuzzer` and the V1 `MODEL_ID` and `FUZZER_TARGET`.
- Depends on: V3-R4b, V3-R6, V3-R9, and the U5 threshold being met.
- Owned paths: those compose files and the stage 23 smoke CI.
- Acceptance checks:
  - The container smoke CI is green.
  - One end-to-end efficient cycle publishes, and a client refreshes to the new version.
  - The deployed `v3-drift-bounds.toml` holds V3-R5's recalibrated values, not the provisional ones.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R8a: Remove V1 gradient serving and extract shared code

- Objective:
  - The supervisor answers all three gradient RPCs `UNIMPLEMENTED`, with no Python fallback.
  - Before any deletion, extract the helpers that inference and V3 still need:
    - `window::action_value`, used by `v3_fit`;
    - `objective::fsum` and `rpc::training_text_key`, used by presence inference.
  - Split presence inference (`PresenceModel`) from `compute_presence_gradients`, and delete `compute_presence_gradients`.
- Depends on: V3-R7.
- Owned paths: `rust/services/runtime-supervisor/src/routing.rs`, `rust/services/runtime/src/training.rs`, `rust/crates/privoke-training/src/{presence,objective,rpc,window}.rs` (extraction only).
- Acceptance checks:
  - G5 at the supervisor surface, including the test that the Python worker is never invoked.
  - G6, including the presence-gate golden.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R8b: Delete the Rust V1 training code

- Objective:
  - Delete:
    - `rust/services/fuzzer`;
    - the V1 application in param-update: `apply`, `validate`, `window`, and the float-delta part of `policy`;
    - the V1-only `privoke-training` modules (`net`, `objective`, `adam`, `trace`, `window`, `retention`, and the gradient RPC modules), after the V3-R8a and V3-R9 extractions.
  - Keep V1 inference, V1 catalog serving and the presence gate.
  - Update `docs/runtime/rust-workspace.md`, and record in `docs/plans/rust-server-rewrite.md` that this decision retired the stage 19 and 21 V1 training ports.
- Depends on: V3-R8a. Python stays frozen (U6).
- Owned paths: as listed.
- Acceptance checks:
  - G5 greps: no V1 training module or service remains.
  - G6: the goldens are unchanged.
  - `cargo test --workspace --locked` and clippy `-D warnings` pass in CI.
- Status: pending.
- Outcome:
- Handoff notes: the Python oracles and goldens for the deleted code stay.

Order: R1 → R2 (lands `routine_guard_rows` first) → (R5, R3, R9) → R6 → R4a → R4b → R7 → R8a → R8b.
