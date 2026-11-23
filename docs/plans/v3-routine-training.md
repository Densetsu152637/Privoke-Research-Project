# Plan: routine training on the V3 models

Revision: 2026-11-23 (feat/rust-rewrite 4893ec5; design report RUST-V3R-DESIGN)

User decision, 23 November 2026, verbatim: "the routine training should train all of the V3 models, not the V1 models. The V1 models should be available for the detection pipeline, but should be removed from training."

User decisions on the open questions, 23 November 2026:

- **U1, client trust:** a new V3 version is accepted on lineage plus a publication signature. The version must descend from the pinned ORIGINAL, its evidence must pass the guard, and it must be signed by a param-update publication key compiled into the client.
- **U2, routine data:** the frozen BC01 (taxonomy plus benign) and AU3 (audience) releases, with a fresh seed per cycle. No new curriculum pipeline.
- **U3, retention:** a V3 retention check gates publication (stage V3-R9).
- **U4, presence:** presence training is retired. The V1 presence gate keeps working for detection with its current model.

Root defaults, which the user may override:

- **U5, compute:** CPU-only Rust fits. Stage V3-R5 measures the per-tier cycle time, quality tier included, before cutover. CUDA is not in scope.
- **U6, V1 training code:** the Rust V1 training path is removed (stage V3-R8). The Python V1 training code is frozen, not deleted, because it is the oracle for the committed Rust goldens and for reproducing the historical training studies.
- **Python clients:** the Rust controller (W4) is the client. Python `v3_package.py` is frozen at the compiled pins and gains no lineage admission.

## Goals

- **G1. The routine cycle trains all three V3 tiers.** A deployment-like mTLS test runs the scheduler through `privoke-v3-{efficient,balanced,quality}`, with HEADS then FULL_ENCODER per tier, and journals each outcome. Verified by the stage V3-R6 test.
- **G2. A trained V3 version reaches clients only through lineage plus signature.**
  - The supervisor fetch refuses a forged manifest: wrong ORIGINAL, failing evidence, or a bad or missing signature.
  - It replaces the cached snapshot with a valid published candidate after the TTL.
  - Verified by the stage V3-R4 tests.
- **G3. Publication is atomic and bounded.**
  - A crash during a commit leaves no partial package.
  - A stale base, an over-budget drift, a guard failure or a retention failure is refused, and nothing changes.
  - Verified by the stage V3-R2 and V3-R9 tests.
- **G4. Pinned behaviour is unchanged until something is published.** With nothing published, model-streaming is byte-identical to its Go-parity corpus (`tests/go_standard_v3.rs`), and the pinned ORIGINAL fetch golden (`fetch_golden.rs`) is unchanged.
- **G5. No V1 model is trained.**
  - The scheduler makes no V1 `FuzzerService` call.
  - The runtime worker's V1 gradient RPCs answer `UNIMPLEMENTED`.
  - The Rust V1 training code is gone.
  - Verified by the stage V3-R8 greps and tests.
- **G6. V1 detection is unchanged.** The V1 analysis goldens of stages 14 and 17, and the V1 catalog serving corpus, pass unchanged.
- **G7. LLM isolation.** Every V3 fit and analysis test sends `[SEMANTIC]` and asserts the executed layer. None sends an empty layer list.
- **G8. CI.** Rust workspace CI and service stack CI are green on the integrated head. Each new parity contract has a Python oracle golden.

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

- Objective: a Rust `CheckpointService` in param-update, on the internal listener for the publisher and trainer roles, ported from `checkpoint_store.py`. It is content-addressed, has a `current(model, manifest)` table, and runs `admit_candidate` (lineage, provenance, config and inventory unchanged, evidence verified, HEADS changes only `heads.*`), `stage` and a compare-and-swap `commit` gated by `publication_passes`. Port `validate_source_evidence` with it.
- Depends on: none.
- Owned paths: `rust/services/param-update/src/v3_store/`, `evaluation/generate_checkpoint_store_golden.py`.
- Acceptance checks:
  - The golden replay of admit, stage and commit outcomes and reasons (including `stale_base` and `guard_rejected`) equals the Python oracle.
  - The v3-fuzzer recorded replay (23 fits) passes against the Rust store.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: one publication authority. The store is not a separate service.

## Stage V3-R2: V3 publication, drift bounds and signature

- Objective:
  - An atomic published-releases directory `<root>/<model-id>/<manifest-sha>/` (fsync, then rename) with a `current` pointer.
  - Receipts and audit.
  - Per-update L2 and cumulative L2 bounds from the pinned ORIGINAL.
  - A publication signature over the manifest (U1): a key held by param-update, with the public key compiled into clients.
- Depends on: V3-R1.
- Owned paths: `rust/services/param-update/src/{v3_publish,policy}.rs`.
- Acceptance checks:
  - A crash-injection test leaves no partial package.
  - Negative tests: a stale base, an over-budget update and a bad signature are each refused, with nothing changed.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: key generation and storage follow the existing PKI (`privoke-pki`). Document rotation.

## Stage V3-R3: model-streaming serves published V3 versions

- Objective:
  - `GetModelPackage(privoke-v3-<tier>)` returns the current published manifest, or the pinned ORIGINAL when nothing is published.
  - `StreamModelAsset` accepts any manifest SHA held in the published store.
  - `latest` stays `privoke-v3-balanced`.
- Depends on: V3-R2.
- Owned paths: `rust/services/model-streaming/src/{releases,published}.rs`.
- Acceptance checks:
  - G4: the Go corpus is byte-identical with nothing published.
  - A published candidate is served.
  - An unpublished SHA gets `INVALID_ARGUMENT`.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: the Go-parity claim ends at the pinned set.

## Stage V3-R4: Client lineage admission and refresh

- Objective: add `LineageAdmission` to `runtime-supervisor/src/fetch.rs`. It accepts a manifest when all of these hold:
  - `validate_manifest` passes;
  - `original` equals the compiled tier pin;
  - the evidence passes `validate_execution` and `publication_passes`;
  - the signature verifies against the compiled publication key.

  After the TTL the worker reloads the snapshot.
- Depends on: V3-R3.
- Owned paths: `rust/services/runtime-supervisor/src/fetch.rs` and the worker snapshot reload; `evaluation/update_security.py`.
- Acceptance checks:
  - G2.
  - G4: the fetch golden is unchanged.
  - The update-security harness covers the new attack rows.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: this is the highest-security change. It needs a critic on the diff.

## Stage V3-R5: v3-fuzzer routine mode

- Objective:
  - A routine mode beside the frozen study mode, using BC01 and AU3 with a fresh seed per cycle (U2).
  - The fuzzer computes and records the `source_commitment` itself.
  - Seeds come from the journal.
  - The candidate is committed through the param-update store.
  - Measure the per-tier cycle time, quality included (U5).
- Depends on: V3-R1.
- Owned paths: `rust/services/v3-fuzzer/src/{cycle,source,config}.rs`.
- Acceptance checks:
  - The frozen-mode recorded replay (23 fits) is identical.
  - An mTLS test completes a routine HEADS-then-FULL cycle per tier, sending `[SEMANTIC]` only.
  - The timings are recorded.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R6: Scheduler targets V3

- Objective: param-update's scheduler loops over the three V3 tiers and two stages through the `V3FuzzerService` client, with `expected_base` taken from the store.
- Depends on: V3-R5.
- Owned paths: `rust/services/param-update/src/{scheduler,journal}.rs`.
- Acceptance checks:
  - G1: 3 tiers × 2 stages are journalled and restart-safe.
  - No V1 `FuzzerService` call remains in `scheduler.rs`.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R9: V3 retention gate (U3)

- Objective:
  - Generalise `privoke_training::reference` to a V3 teacher.
  - Build per-tier V3 reference releases on the approved bank, with new pins.
  - Refuse any candidate that regresses against them, inside the V3-R2 commit.
- Depends on: V3-R2.
- Owned paths: `rust/crates/privoke-training/src/reference.rs`, param-update commit gate, the reference-release generator.
- Acceptance checks:
  - A regressing candidate is refused, and a non-regressing one passes.
  - The reference releases are reproducible from the pins.
  - Rust CI is green.
- Status: pending.
- Outcome:
- Handoff notes: runs in parallel with V3-R3 to V3-R6. It must land before V3-R7.

## Stage V3-R7: Deployment cutover

- Objective:
  - Add v3-runtime and v3-fuzzer, with certificates, to `deploy/gce/compose.yml` and `docker-compose.prod.yml`.
  - Remove `privoke-fuzzer` and the V1 `MODEL_ID` and `FUZZER_TARGET`.
- Depends on: V3-R4, V3-R6, V3-R9.
- Owned paths: those compose files and the stage 23 smoke CI.
- Acceptance checks:
  - The container smoke CI is green.
  - One end-to-end efficient cycle publishes, and a client refreshes to the new version.
- Status: pending.
- Outcome:
- Handoff notes:

## Stage V3-R8: Remove V1 from the Rust training path

- Objective:
  - Delete or unwire the V1 training path:
    - `rust/services/fuzzer`;
    - the V1 application in param-update (`apply`, `validate`, `window`, and the float-delta part of `policy`);
    - the runtime worker's `training.rs` gradient routes and supervisor `route_gradients`;
    - the V1-only `privoke-training` modules (`net`, `objective`, `adam`, `trace`, `window`, `retention`).
  - Extract the shared helpers first, for example `window::action_value`, which `v3_fit` uses.
  - Keep V1 inference, V1 catalog serving and the presence gate.
- Depends on: V3-R7. Python is frozen (U6).
- Owned paths: as listed. Also `docs/plans/rust-server-rewrite.md` stage 19/21 notes and `docs/runtime/rust-workspace.md`.
- Acceptance checks:
  - G5.
  - G6: the V1 analysis goldens are unchanged.
  - `cargo test --workspace --locked` and clippy `-D warnings` pass in CI.
- Status: pending.
- Outcome:
- Handoff notes: the deleted code's Python oracles and goldens stay. Record in the rewrite plan that the stage 19 and 21 V1 training ports were retired by this decision.

Order: R1 → (R2, R5) → (R3, R9, R6) → R4 → R7 → R8.
