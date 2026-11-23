# Plan: routine training on the V3 models

Revision: 2026-11-23, revised after the plan gate (feat/rust-rewrite 505aa85; design report RUST-V3R-DESIGN; plan-gate findings D1-D12, N1-N8 and M1-M4)

User decision, 23 November 2026, verbatim: "the routine training should train all of the V3 models, not the V1 models. The V1 models should be available for the detection pipeline, but should be removed from training."

User decisions on the open questions, 23 November 2026:

- **U1, client trust:** a new V3 version is accepted on lineage plus a publication signature. The version must descend from the pinned ORIGINAL, its evidence must pass the guard, and it must be signed by a param-update publication key compiled into the client.
- **U2, routine data:** the frozen BC01 (taxonomy plus benign) and AU3 (audience) releases, with a fresh seed per cycle. No new curriculum pipeline.
- **U3, retention:** a V3 retention check gates publication (stage V3-R9).
- **U4, presence:** presence training is retired. The V1 presence gate keeps working for detection with its current model.

- **U7, cumulative drift cap (23 November 2026):** routine cycles add about 1 to 2 L2 per cycle with no saturation in three cycles. The user chose "Raise the cap": the cumulative bound is sized for about 50 cycles at the largest observed growth (100 for every tier and scope); per-update bounds stay as calibrated in V3-R5.
- **Routine root (root decision, 23 November 2026):** routine training starts from the pinned standard release of each tier (scope full_encoder, `original` = the initials ORIGINAL manifest), never from `initials/`. Candidates carry parent = the pin or a later published version and original = the pin's `original`; cumulative drift is measured from the pinned release.

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
- Status: done (RUST-V3R1, 23 Nov 2026; plan gate converged in 4 rounds).
- Outcome: `74dfdae` (merged). Rust CI run 45129063820 green. Golden replay equals the Python oracle (3 stories, 98 steps, 6 applied, 3 stale_base, 2 guard_rejected, 2107 blob listings and 339 receipt rows identical). The 23 recorded v3-fuzzer fits replay identically against the Rust store (10 applied, 13 rejected; re-run by root in Docker). R2 seam: `CommitObserver::before_swap` inside the commit transaction. Admission still runs under the commit lock; V3-R9 must hoist it.
- Handoff notes: the sqlite `current` table is the single authority for every later stage. R2 signs inside the commit transaction through `CommitObserver::before_swap` (`rust/services/param-update/src/v3_store/store.rs`). Roles on `CheckpointService`: `CommitCandidate` publisher and trainer only; stage, read and health also `runtime`. The golden needs the public official `config.json` and `vocab.txt` as fixtures (`tests/fixtures/v3_store/`).

## Stage V3-P: Pre-flight checks for the two user stop points

- Objective: before V3-R2 starts, answer the two late stop conditions with existing code. (1) Time one real-weight quality-tier FULL_ENCODER fit (and HEADS) through the stage-22 `FitCandidate` with 8 CPUs, sending `[SEMANTIC]`, against the U5 threshold. (2) Check read-only that every row of the approved bank (`BANK_SHA256`) maps onto the V3 heads' outputs.
- Depends on: none (runs beside V3-R1).
- Owned paths: a timing script or env-gated test and a bank-mapping check; results recorded in the V3-R5 and V3-R9 handoff notes. Calibration weights, if any are kept, go under `models/experiments/<run>/` with provenance.
- Acceptance checks: the timings and the mapping result are recorded; if either stop condition triggers, root asks the user before V3-R2.
- Status: done (23 Nov 2026).
- Outcome: `2453616` (merged). Neither stop condition triggers. Quality FULL_ENCODER fit 13.5 min on 8 CPUs (22% of the U5 threshold); a full 3-tier round takes about 25 min, so the scheduler interval must exceed that plus retention and publication. Bank: 200 of 200 rows map onto the V3 heads. Single-update L2 from the standard releases: HEADS up to 2.17, FULL up to 1.88; calibration weights in `models/experiments/v3p_timing_20261123/` (ignored). Details in the V3-R5 and V3-R9 handoff notes.
- Handoff notes: V3-R5 and V3-R9 keep their checks as confirmations.

## Stage V3-R2: Signed publication, derived directory and drift bounds

- Objective:
  - **Signed statement.** A domain-separated statement `{tag, key_id, model_id, manifest_sha, parent, original, sequence}` with a per-model monotonic `sequence`. It is signed by a dedicated Ed25519 publication key. The key is not a TLS key: it is mounted as a secret and never baked into an image. The ModelPackage response proto gains a field for the statement.
  - **Commit order.** Stage the files with fsync into a private staging area. Then, inside the one `BEGIN IMMEDIATE` transaction that performs the compare-and-swap, run the stale-base and gate checks, allocate the sequence and sign. After the transaction commits, rename the staged directory into `<root>/<model-id>/<manifest-sha>/` and update the derived `current` pointer. Staging is durable, on the same filesystem as the published root. Startup reconciliation promotes a staged directory that the authority references (an interrupted rename), repairs the pointer from the authority, and deletes or quarantines any published or staged directory the authority does not reference; staging is cleaned only after promotion. A candidate that loses the race is never signed and never published. Directory fsync is a no-op on Windows.
  - **Rollback.** An operator RPC, restricted to the publisher role, issues a new statement with a higher sequence pointing at a manifest from that model's authority history, the ORIGINAL included.
  - **Drift bounds.** Per-update L2 and cumulative L2 from the pinned ORIGINAL, separately for HEADS and FULL_ENCODER. R2 ships *provisional* bounds, configurable per tier and scope, and enforces them. V3-R5 recalibrates them from real-weight fits of every tier and scope (twice the largest observed L2) and records the numbers and their source here. The existing recorded fits cannot be used: the v3-fuzzer golden is synthetic and the stage 22 fixtures use a toy checkpoint.
  - **Routine guard-row selection.** One shared function in `privoke-curriculum` (`v3::routine_guard_rows(release, seed, source_commitment)`), owned by this stage, defines how a routine seed selects the 16 guard rows from the frozen BC01/AU3 releases. V3-R5 calls it; nothing else re-implements it.
  - **Guard recomputation.** Param-update rebuilds the 16 guard rows itself from the frozen BC01/AU3 releases, the scheduler-allocated seed and the `source_commitment`, never from rows the trainer supplies. It recomputes the guard on both the base and the candidate with the Rust V3 encoder, loading the candidate through `V3Model::with_tensors`, not through `admitted_manifest`. This runs before the transaction and is bound to the candidate SHA.
  - **Key custody and rotation.** Clients compile a key set indexed by `key_id`. Test keys exist only behind a `test-keys` cargo feature.
  - **Shared signed-chain fixtures.** Generate one deterministic fixture set with the test keys on the toy checkpoint: ORIGINAL → HEADS → FULL → rollback to the ORIGINAL, a second key for the rotation overlap, and the forged variants. V3-R3, V3-R4a, V3-R4b and the `update_security.py` rows consume these fixtures.
  - **Bounds evidence field.** `v3-drift-bounds.toml` carries the SHA-256 of the calibration record its values came from.
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
- Status: done (RUST-V3R2, 23 Nov 2026).
- Outcome: `86c77f4` (merged). Rust CI run 45145107514 green. Independent code review: 2 rounds, 7 findings accepted and fixed (trainer-chosen guard release, untested recompute path, doc overclaim, cumulative-base test, unbounded commits and rollback to unvetted versions, key-id validation, unverified base read), plus a malleable-signature fixture and a CI check that `test-keys` is absent from the service build. Root re-ran the 23-fit store replay on 8e71d0a: identical. Guard gate is wired into `main.rs` only in V3-R6 (deferral recorded in v3-publication.md).
- Handoff notes: R2 (23 Nov 2026, wt/rust-v3r2): `routine_guard_rows(RoutineRelease::{Bc01,Au3}, seed, source_commitment)` derives the BC01 guard seed from `sha256(domain, seed, commitment)`; the commitment must not cover the guard rows (it would be circular), so V3-R5 must pass the commitment of the TRAIN part of the source, and the source record's frozen-guard check in `validate_source_evidence_bc01` has to accept the routine guard (the AU3 guard is the release's pinned 16 rows and never varies). The guard gate needs an `Allocations` implementation from the V3-R6 journal. The shared fixtures are `rust/crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json` (the toy ORIGINAL is not the compiled pin; lineage admission takes the pin as a parameter). Publication details: `docs/runtime/v3-publication.md`. Review fixes (23 Nov 2026): the guard gate is deferred to V3-R6 (`main.rs` does not install it; a V3-R2 signature attests the drift gate and the oracle's trainer-evidence guard, not a recomputed guard); `Allocation` carries `sampler` and `scope`; the drift gate is always attached when the store is on; rollback targets are the ORIGINAL or signed versions; for V3-R5, the cumulative bound uses the scope of the latest update (a HEADS update after a FULL one is judged by the HEADS cumulative bound). The rotation overlap is tested in V3-R4a. Record in `docs/runtime/v3-publication.md` the accepted limitation that the high-water mark lives in the client cache, so a wiped cache re-admits the unsigned ORIGINAL once (trust on first use).

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
- Status: done (RUST-V3R3, 23 Nov 2026).
- Outcome: `aade7fe` (merged). Rust CI run 45149588550 green. Serves only the pin or manifests with a `publications` row, read from param-update's catalog read-only; pin-addressed fetch is `privoke-v3-<tier>@<manifest-sha>`. Root ran `go_standard_v3` with the real pinned releases in Docker: 3 passed (G4 holds with nothing published). Open: the frozen Python `v3_package.py` sends the plain id and fails closed after the first publication; historical Python runs that fetch over the wire need `@pin` (decide if needed). V3-R7 must mount the store so SQLite can keep its WAL `-shm`.
- Handoff notes: the Go-parity claim ends at the pinned set.
  R3 (23 Nov 2026, wt/rust-v3r3; details in `docs/runtime/v3-publication.md#serving`):
  - Authority read: model-streaming opens `<V3_STORE>/catalog.sqlite` read-only on every request (`current`, `publications`); `V3_PUBLISH_ROOT` and `V3_STORE` are set together or not at all. Servable = the compiled pin, or any manifest with a publication row. The published tree only supplies bytes. The store directory needs a mount where SQLite can keep its WAL `-shm` file for a reader (V3-R7 compose: same user as param-update, or read-write on that directory only).
  - Pin-addressed form: the request has no pin field, so the pin rides in the model id, `privoke-v3-<tier>@<manifest-sha>` (no proto change). The pin returns the ORIGINAL with an empty statement; a published sha returns that version with its statement; anything else is `INVALID_ARGUMENT`. The plain id after a signed rollback to the ORIGINAL returns the pinned bytes with the rollback statement, which V3-R4a needs.
  - Python consumers: only `extension/client-runtime/src/LLM/privoke/v3_package.py` is affected (it fetches by plain id and refuses any non-pin manifest, so it fails closed once a tier is published); it is frozen, so a historical run needs its owner to send the `@pin` id. The evaluation consumers and the Go service are unaffected while nothing is published. Table in the publication doc.
  - V3-R4a: the server does not verify signatures (no keys); the client verifies. An authority that serves a manifest other than its newest publication's answers `UNAVAILABLE` to the plain request; the supervisor treats that as a transient failure and keeps its cache.
  - Test seam: `StandardReleases::open_with_pins` (production uses the compiled pins) lets CI serve toy ORIGINALs; the shared `chain.json` is used for authority and statement reading, while byte-level tests sign their own toy packages with the same test keys (the fixture manifests name stand-in digests with no files behind them).

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
- Status: done (RUST-V3R4A, 23 Nov 2026).
- Outcome: `bb12d18` (merged). Rust CI run 45166749316 green; 42 lineage attack rows, none unmet. Lineage rule as decided: `original` equals the pinned release's `original`; no parent-is-admitted check (the signature attests param-update's lineage admission). Independent review: no admission bypass; 5 findings fixed (a mark signed by a dropped key now becomes a floor instead of bricking the model, and a missing mark is rebuilt from the highest verified cached statement; LF10 reason; scope branch exercised; pins and originals checked against the conformance corpus; stale comment). The delta review of those fixes was a root self-check (usage gate closed): an unverifiable mark under an unknown key can only raise the floor (denial of service), never admit anything. Deferred to V3-R4b: advisory lock on the mark; loaders must honour the mark. `PRODUCTION_KEYS` is empty until V3-R7.
- Handoff notes: the highest-security change. A critic reviews the diff.
  R4a (23 Nov 2026, wt/rust-v3r4a; details in `docs/runtime/v3-publication.md#client-admission`):
  - Rule: `privoke_contracts::v3::admit_lineage(manifest, statement, requested, keys, state)` with `LineageState { tier_pin, high_water }`; `admitted_manifest` is untouched. The supervisor's `fetch::LineageAdmission` implements `Admission` over it; `Admission` gained the defaulted `admit_published` and `accepted`, so `StandardAdmission` and `fetch_golden.rs` did not change. `privoke-supervisor fetch-model` now uses `LineageAdmission::production`.
  - For R4b: the mark is rebuilt from cached `statement.json` files when missing and kept as a floor when its key was dropped (see the publication doc). Loaders must go through `verify_package` or the mark at load time, so a client with a signed mark never loads the unsigned pin. Once a refresh loop runs beside other processes, the cross-process mark write needs an advisory lock (today it re-reads and never lowers, but two writers can race).
  - Lineage rule as corrected by root: the compiled pin is the standard release manifest (scope `full_encoder`), so a trained version needs `statement.original == pinned release's original` (compiled as `Tier::release_original`, with `LineageState::tier_pin` returning `TierPin { manifest_sha, original }`), not `original == pin`; the pin itself stays the signed-rollback and unsigned-first-start branch. Deviation: `parent` is not checked against the pin or an admitted set, since a client that skipped a publication would refuse the next one; the signature attests param-update's lineage admission. The toy fixtures use pin = original = the toy ORIGINAL.
  - Persistence, in the model cache: `<cache>/<model>/<manifest-sha>/statement.json` (the admitting statement) and `<cache>/<model>/high-water.statement` (the highest accepted statement, written only after the package is complete and verified). Both are the signed wire form and are re-verified under the compiled keys on every read. A mark that does not verify (tampered, or signed by a dropped key) refuses the whole model (fail closed; the operator removes the file). R4b must keep this when it adds the refresh loop and the offline choice: the cached version at the mark is the one whose `statement.json` has `sequence == mark.sequence`; `verify_package` on an older cached version is refused as a replay, which is correct.
  - The production key set is `privoke_contracts::publication::PRODUCTION_KEYS`, EMPTY until the operator generates the first publication key (V3-R7 deployment step: generate, record the public key and key id there, release the client). With it empty a client admits no signed version, so the whole of V3-R4a is inert in production until then. Test keys reach the supervisor only through dev-dependencies (CI `cargo tree` check); `LineageAdmission::with_pins` is `test-helpers` only.
  - End-to-end Fetcher tests use a synthetic efficient-tier chain (official `config.json` and `vocab.txt` from param-update's fixtures, stand-in weights), because a manifest on a real tier needs the official config and vocabulary bytes and the real releases' weights are not in the repository (the pinned manifests themselves are, in `tests/conformance/model_streaming.json`; a contracts test hashes them against `Tier.manifest_pin` and compares their `original` with `Tier.release_original`). The toy chain's ORIGINAL has scope `original` and no evidence, so it can only be used at the `admit_lineage` level; the real pinned releases carry evidence (they are scope `heads` or `full_encoder`), which the Fetcher tests copy.
  - Loaders: `privoke-semantic/src/v3.rs` and `runtime/src/semantic.rs` still call `admitted_manifest` and refuse a non-pinned directory. After R4a a signed version can be fetched into the cache but is not loaded until R4b. Python `v3_package.py` is unchanged (frozen).
  - Rows: `evaluation/update_security.py --target rust --rust-service client-lineage` (L01-L25, LF1-LF14), run in Rust CI after the two test binaries write `PRIVOKE_LINEAGE_ROWS_OUT`.

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
- Status: done (RUST-V3R4B, 24 Nov 2026).
- Outcome: `5c20a97` (merged). Rust CI run 45189684410 green. The worker selects the version at the high-water mark from the cache on every load (no fallback); refresh via `V3_PACKAGE_REFRESH_SECONDS` / `V3_PACKAGE_REFRESH_MODELS` (opt-in until V3-R7); advisory lock on `<model>/.lock`; GC never removes the pin or the marked version. Independent review: 2 rounds, 8 findings fixed (a deleted mark plus dropped pin files reopened the unsigned pin; statement replaced before the mark moved; cross-process GC race; vocab re-read after verification; dropped-key cached statements; rotation doc; pin-dir link check; snapshot bypass), plus deterministic lock and interval tests.
- Handoff notes: R4b (24 Nov 2026, wt/rust-v3r4b; design in `docs/runtime/v3-publication.md#loading-from-the-cache`):
  - The worker is not told its version: `privoke_contracts::model_cache::ModelCache::select` (mark, else the compiled pin) runs on every load in `runtime/src/semantic.rs`, and `V3Model::load_published` admits the manifest bytes by `admit_lineage` before reading an asset. A moved mark reloads the snapshot on the next request; no message, no restart. `admitted_manifest` stays pin-only (release directories, non-standard ids). A model directory with a mark ignores a dropped-in `manifest.json`.
  - Refresh: `refresh::Refresher`; `V3_PACKAGE_REFRESH_SECONDS` (default 3600) and `V3_PACKAGE_REFRESH_MODELS` (comma list; empty = no loop). The loop is wired into `native-host` but is OFF until V3-R7 sets the models (and `PRODUCTION_KEYS` is filled). Advisory lock `<model>/.lock` (`File::lock`) guards mark writes and GC; GC deletes versions whose verified statement is below the mark, never the pin or the mark's version.
  - `select` returns `Ok(None)` for a pinned version directory that is a link (no pinned release is then cached); an error is returned only for a mark whose version is missing or does not match.
  - Limits for R7: the positive load of a real signed version (real weights) is not in CI (same `load_verified` path as the pinned releases); versions without a statement left by an interrupted download are not collected; wiping the mark and every cached statement is the documented trust-on-first-use state. The Python worker never loads a published version. Rows RB1-RB5 in `update_security.py`; CI also checks `test-keys` is absent from `privoke-runtime` and `privoke-semantic`.

## Stage V3-R5: v3-fuzzer routine mode

- Objective:
  - A routine mode beside the frozen study mode, using BC01 and AU3 with a fresh seed per cycle (U2).
  - The fuzzer computes and records the `source_commitment` itself, and selects guard rows only through `privoke-curriculum::v3::routine_guard_rows` (V3-R2).
  - The scheduler (V3-R6) is the only allocator of `(request_id, seed, expected_base)`; it journals them before the call and passes them to the fuzzer, which only records them. On restart the scheduler queries `GetCommitStatus` for the journalled request id before re-requesting; if the earlier fit was lost, the scheduler allocates a new request id. Until V3-R6 lands, the R5 tests act as the scheduler.
  - It commits the candidate through the param-update store.
  - It measures the per-tier cycle time and applies the U5 threshold.
  - It recalibrates the V3-R2 drift bounds from real-weight fits of every tier and scope, keeps the calibration fits, their provenance and the observed L2 values under `models/experiments/<run>/`, writes the values and that record's SHA-256 into `rust/services/param-update/config/v3-drift-bounds.toml` (this stage owns the values; V3-R2 owns the format), and records them in this plan.
- Depends on: V3-R1, and V3-R2's `routine_guard_rows` (which V3-R2 lands first).
- Owned paths: `rust/services/v3-fuzzer/src/{cycle,source,config}.rs`.
- Acceptance checks:
  - The frozen-mode recorded replay (23 fits) is identical.
  - An mTLS test completes a routine HEADS-then-FULL cycle for each tier, sending `[SEMANTIC]` only.
  - A crash after the fit and before the commit neither stalls the tier nor causes a request-id content conflict.
  - The timings are recorded against the U5 threshold.
  - Rust CI is green.
- Status: done (RUST-V3R5, 23 Nov 2026; merged at `fe43652`, Rust CI run 45168916116 green). GuardGate adapted to the routine commitment, pinned-release bootstrap (`bootstrap_pinned`) and routine-root drift added, with CI tests in `param-update/tests/v3_pinned.rs`; cumulative cap 100 per U7.
- Outcome: routine mode (`V3_MODE=routine`) in `rust/services/v3-fuzzer`; frozen replay identical (23 fits, 92 of 92 wire messages, 161 files, 23 rows; also against the Rust store: 10 applied, 13 rejected); per-tier mTLS HEADS-then-FULL test, crash and restart tests, and a real-weight test; U5 not triggered; drift bounds recalibrated (`v3-drift-bounds.toml`, status calibrated, per-update bounds from the calibration, cumulative cap 100 by user decision, evidence SHA-256 `c35c73508940d39672e5acfa2b6f408cc0e0b775378aefbb8be3f0a95d45fef7`). Rust CI green on 964a603 (runs 45142151172 and 45142151179).
- Handoff notes: V3-P pre-flight (23 Nov 2026, wt/rust-v3p; `rust/services/v3-runtime/tests/fit_timing.rs`, env-gated, no golden). `FitCandidate` through the Rust runtime, release build, Docker `--cpus=8`, 8 threads, frozen BC01 schedule (seed 20261123), 64-step policy, 16 guard rows, `[SEMANTIC]` asserted on the request and as the executed layer in the evidence. Wall seconds per fit; both the untrained-heads `initials/<tier>` and the `standard-releases/privoke-v3-<tier>` bases were admitted with the real pins and give the same timing.
  - Timing (initials | standard releases): efficient HEADS 33.4 | 35.5 s, FULL 68.3 | 68.3 s; balanced HEADS 63.8 | 64.7 s, FULL 131.9 | 131.9 s; quality HEADS 377.5 | 377.8 s (6.3 min), FULL 755.2 | 808.1 s (12.6 | 13.5 min). A full round (3 tiers x HEADS and FULL, run back to back) is 1,430 | 1,486 s, about 24-25 min. The U5 stop condition (quality FULL > 60 min on 8 CPUs) does not trigger; quality FULL is 22% of the threshold. The scheduler interval must exceed about 25 min plus the V3-R9 retention checks and the publish path.
  - Drift L2 of the candidate from its base (all candidate tensors; "heads" is the `heads.*` tensors, "encoder" every other tensor). Standard-release bases: efficient HEADS 2.003, FULL 1.734 (heads 1.681, encoder 0.426); balanced HEADS 2.170, FULL 1.875 (1.815, 0.471); quality HEADS 2.092, FULL 1.645 (1.531, 0.601). Untrained-heads bases: efficient HEADS 1.908, FULL 2.123 (2.009, 0.686); balanced HEADS 2.500, FULL 2.813 (2.641, 0.968); quality HEADS 2.595, FULL 2.997 (2.729, 1.239). HEADS changes 6 tensors; FULL changes 67, 37 and 187 more (efficient, balanced, quality). These are single first-cycle updates from the pinned ORIGINAL with the 64-step policy; cumulative drift over repeated cycles still needs its own observations. The twice-the-largest rule gives, over the standard-release bases, about 4.3 (HEADS) and 3.8 (FULL) as per-update floors, but R5 decides the bounds from the cycle it runs. The calibration candidates and per-fit JSON (seconds, L2, candidate, base and evidence SHA-256) are kept under `models/experiments/v3p_timing_20261123/{init,std}/` with `PROVENANCE.md`; they are local and Git-ignored.
  - Re-run: `MSYS_NO_PATHCONV=1 docker run --rm --name v3p-<t> --cpus=8 -e CARGO_TARGET_DIR=target-docker -e PRIVOKE_V3_TIMING_PACKAGE=/pkg -e PRIVOKE_V3_TIMING_OUT=/out/<tag> -v <worktree>:/work -v <package>:/pkg:ro -v <out>:/out -w /work/rust rust:1.99.1-bookworm cargo test -p privoke-v3-runtime --release --locked --test fit_timing -- --nocapture`.
  V3-R5 (23 Nov 2026, wt/rust-v3r5):
  - Commitment design. `source_commitment` for the guard selection is the *routine commitment* C (`privoke_curriculum::v3::routine_commitment`): the digest of `{sampler, inputs, source_hashes, policy_sha256, seed S}`, covering no row. The schedule is built at `routine_guard_seed(S, C)`, so the runtime's and the store's frozen validators accept a routine source unchanged (no `validate_source_evidence_bc01` variant is needed: its guard check holds at `source.seed`, which is the derived seed). The runtime still requires `digest(source_json) == FitRequest.source_commitment`, so evidence `source_commitment` stays the digest of the full record, which covers the guard and cannot be the guard's input.
  - GuardGate adaptation, done in a follow-up under root's authorisation (`v3_guard.rs`, `tests/v3_guard.rs`): the gate recomputes C = `routine_commitment_of_source(evidence.source, digest_of(evidence.policy), allocation.seed)`, requires it equal to `allocation.source_commitment` (the scheduler journals the `routine_commitment` that the fuzzer returns, with the seed), rebuilds the rows from C, and after the row checks requires `evidence.source.seed == routine_guard_seed(allocation.seed, C)` (the AU3 guard ignores the seed, so this also binds the training rows). V3-R6 must journal that `routine_commitment` as the allocation's `source_commitment`. `tests/v3_guard.rs` gains the derived-seed positive case and a refusal for a trainer-chosen seed.
  - Restart rule as implemented: the same identity with the same content resumes from `commit-request.pb` (recorded commit looked up with `GetCommitStatus`, re-sent with the same bytes if unknown, never refitted); otherwise `FAILED_PRECONDITION`, and the scheduler allocates a new request id and seed. Reusing an id with other content is `ALREADY_EXISTS`.
  - Routine request metadata: `expected_base`, `policy_sha256`, `sampler`; `request.seed` is S. Response metadata adds `mode`, `sampler`, `seed`, `routine_commitment`, `schedule_seed`, `source_commitment`. The work directory adds `routine.json`.
  - Timings (Docker `--cpus=8`, 8 threads, release, 64 steps; efficient and balanced ran beside a second container, quality beside one or two, so these include memory-bandwidth contention; V3-P's isolated figures are in the paragraph above). Seconds per fit, HEADS | FULL: efficient BC01 41.5-42.7 | 84.6-100.5, AU3 64.2-65.4 | 132.7-134.8; balanced BC01 74.3-80.2 | 151.1-164.2, AU3 111.4-115.3 | 230.5-237.2; quality BC01 413.4-462.0 | 887.6-910.9, AU3 649.8-694.1 | 1305.6-1349.7. One routine cycle (HEADS then FULL): efficient 127 s (BC01), 197 s (AU3); balanced 238-245 s, 342-353 s; quality 1313-1374 s (22-23 min), 1956-2045 s (33-34 min). A full 3-tier round is therefore about 28 min on BC01 and about 42 min on AU3, before retention and publication. U5: the largest quality FULL fit is 1350 s (22.5 min, AU3), 37% of the 60 min threshold, so it does not trigger. AU3 rows are longer, hence slower.
  - Drift (L2 of candidate minus base, all tensors). Per-update, largest observed over both bases: efficient HEADS 2.09, FULL 2.56; balanced HEADS 2.83, FULL 3.45; quality HEADS 2.60, FULL 3.00. Standard-release bases, 3 cycles, cumulative from the base after cycles 1/2/3 (the second FULL of each cycle): efficient 3.11, 3.12, 4.84; balanced 3.34, 3.52, 5.65; quality 3.19, 3.71, 6.02. Untrained-heads bases (real store, rejected candidates leave the base): efficient 3.99, 4.71, 7.67 (largest cumulative of any run); balanced up to 4.59; quality up to 5.19. Later updates are smaller than the first (1.0-1.7 against 1.7-2.2 on standard bases). Bounds written: per-update efficient heads 4.2 / full 5.2; balanced 5.7 / 7.0; quality 5.2 / 6.0; cumulative 100 for all. Cumulative cap: the user decided on 23 Nov 2026 to raise it ("Raise the cap"): every tier and scope now has `max_cumulative_l2 = 100`, about 50 cycles at the largest observed growth (about 1.9 per cycle), measured from the pinned standard release (the routine root), not from the initials ORIGINAL. The per-update bounds above are unchanged. The values in the cumulative column of the calibration record are the observed distances, not the bounds.
  - Calibration record: `models/experiments/v3r5_routine_20261123/CALIBRATION.json` (local, ignored), SHA-256 `c35c73508940d39672e5acfa2b6f408cc0e0b775378aefbb8be3f0a95d45fef7`; per-fit records and every candidate under `std/` and `init/` of that directory.
  - Routine root (root's decision, done in the follow-up): routine training starts from the pinned standard release, never from `initials/`. `CheckpointStore::bootstrap_pinned(original_dir, release_dir)` admits the ORIGINAL and the pinned `full_encoder` release (bytes must hash to the model's pin, `original` must be that ORIGINAL), makes the release current and records both in `versions`; a rollback to the pin is served as the pin. Candidates have parent = the pin and original = the ORIGINAL; admission accepts that unchanged. `bootstrap` for ORIGINAL scope is unchanged (the golden passes). The drift gate measures cumulative drift from the pin its parent chain reaches (`DriftGate::root`). Open for V3-R4a: its lineage rule must be "the parent chain reaches the compiled pin", not "`original` equals the compiled pin". V3-R7: the deployed store must be seeded with `bootstrap_pinned`.
  - End-to-end through `store.commit` on real weights (pinned bootstrap, GuardGate recomputing the guard with the Rust encoder, DriftGate with the calibrated bounds, allocation made before each call, efficient and balanced tiers, three routine cycles each): cycle 0 HEADS and FULL applied; later candidates were `guard_rejected` by the trainer-evidence rule, none by a gate mismatch; balanced, same setup: 5 of 6 applied. CI cannot carry this (real tier manifests need real weights), so the CI coverage is `tests/v3_guard.rs` with a fixed scorer plus `routine.rs`.
  - Re-run: `MSYS_NO_PATHCONV=1 docker run --rm --name v3r5-<t> --cpus=8 -e CARGO_TARGET_DIR=target-docker-rel -e PRIVOKE_V3_ROUTINE_STORE=memory|store -e PRIVOKE_V3_ROUTINE_PACKAGES=/pkg -e PRIVOKE_V3_ROUTINE_OUT=/out -e PRIVOKE_V3_ROUTINE_TIERS=<tier> -v <worktree>:/work -v <packages>:/pkg:ro -v <out>:/out -w /work/rust rust:1.99.1-bookworm cargo test -p privoke-v3-fuzzer --release --locked --test routine_real -- --nocapture`.

## Stage V3-R6: Scheduler targets V3

- Objective: param-update's scheduler loops over the three V3 tiers and two stages through the `V3FuzzerService` client, taking `expected_base` from the store authority. It is the single allocator and journal of `(request_id, seed, expected_base)`, including the restart rule stated in V3-R5.
- Depends on: V3-R5 and V3-R2, so that the G1 test runs through the signed, bounded commit path.
- Owned paths: `rust/services/param-update/src/{scheduler,journal}.rs`.
- Acceptance checks:
  - G1: 3 tiers × 2 stages are journalled and restart-safe.
  - No V1 `FuzzerService` call remains in `scheduler.rs`.
  - Rust CI is green.
- Status: done (RUST-V3R6, 24 Nov 2026; merged at `590e9d1`, Rust CI run 45205976805 green). Deviation accepted by root: the scheduler computes the routine commitment itself (the commit happens inside the fuzzer call); the old V1 scheduler and its tests were removed here rather than in V3-R8.
- Outcome: branch `wt/rust-v3r6`; Rust CI run 45192895162 and service stack CI run 45192895171 green. `scheduler.rs` and `journal.rs` rewritten for V3 (no V1 `FuzzerService` call); `main.rs` installs admission, drift, guard (over the journal), retention, publisher. G1 is covered by `tests/scheduler.rs` over mutual TLS with a fake fuzzer and store table (kills at every boundary), with the real `GuardGate` over the journal in `tests/v3_guard.rs`; `tests/scheduler_chain.rs` adds G1 through the real commit path in CI (toy candidates for all three tiers into a real store seeded by `bootstrap_pinned`, chain drift, guard over the journal, retention (fixed scorer, no references), signing publisher; one `commitment_mismatch` refusal settled `rejected`). Real weights (24 Nov 2026, Docker `--cpus=8`, release, `v3-fuzzer/tests/scheduler_real.rs`, the real scheduler with the in-process routine engine and runtime, efficient tier, pinned bootstrap from the standard release and `initials/efficient`, chain with the real reference release): one round took 104.6 s; HEADS request `v3r-c0-efficient-heads-a0-df10cd89` was refused by the store with `guard_rejected` (the candidate did not beat its base on the trainer-evidence guard) and settled `rejected`; FULL_ENCODER request `v3r-c0-efficient-full_encoder-a0-588b009b` was applied after retention (4 violations of 155 eligible, 7 allowed) and published as sequence 1 (candidate `5a7d07c2...`). The mTLS leg to a separate v3-fuzzer process was not run on real weights.
- Handoff notes: V3-R6 (24 Nov 2026, wt/rust-v3r6; details in `docs/runtime/rust-workspace.md`, routine scheduler bullet):
  - Deviation: the allocation's `source_commitment` is computed by the scheduler (`PinnedCommitments`), not journalled from the fuzzer's response, because the fuzzer commits inside the call and the guard gate reads the allocation then. The fuzzer's `routine_commitment` is compared afterwards and a difference is logged. The scheduler needs the same `V3_SOURCE_ROOT` checkout and `V3_POLICY_FILE` as the fuzzer; a mismatch makes the guard refuse (`commitment_mismatch`), never publish.
  - The V1 scheduler and its tests, and `fuzzer/tests/scheduler_mtls.rs`, are gone; the V1 `train_underlying`/Tiny-artifact startup check too. Environment: `FUZZER_TARGET` is now the V3 fuzzer, `FUZZER_REQUEST_TIMEOUT_SECONDS` defaults to 3600 (a quality FULL fit is 25 min), the interval to 10800 s; `FUZZER_CURRICULUM_*`, `MODEL_ID` and `FUZZER_TRAIN_UNDERLYING` no longer apply. V3-R7 must set `V3_STORE` (with the guard and retention mounts), `V3_POLICY_FILE` and the scheduler's TLS files for param-update, and drop the V1 variables.
  - A rejection (for example `retention_regressed`) settles that stage `rejected` and the round continues to the next stage; a stage left in flight (fuzzer unreachable) resumes next pass. Re-run the G1 test after any scheduler change.

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
- Status: done (RUST-V3R9, 24 Nov 2026; merged at `8896b60`). Root accepted a 5% per-tier violation allowance (7/9/10 rows): at zero tolerance every efficient routine candidate failed on 1 to 4 fragile rows; tighten by rebuilding the reference releases.
- Outcome: branch `wt/rust-v3r9`; Rust CI run 45182360838 and service stack CI run 45182360854 green on the pushed head. Retention items moved to `retention_common.rs` (V1 goldens unchanged); V3 teacher in `reference.rs` and `retention_v3.rs`; reference releases for the three tiers pinned (`RELEASE_PINS`) and reproducible with `privoke-v3-retention-reference verify`; `v3_retention::RetentionGate` scores before the transaction and `before_swap` only checks the verdict bound to the candidate; reason `retention_regressed`. Real weights: every tier's teacher retains 100% of its eligible rows (155, 197, 200), the three-cycle routine calibration candidates pass at the 5% tolerance (worst: efficient 4 of 155, balanced 3 of 197, quality 1 of 200), a forgetful candidate regresses on 149, 197 and 200 rows and is refused.
- Handoff notes: V3-R9 (24 Nov 2026, wt/rust-v3r9; details in `docs/runtime/v3-publication.md#retention-stage-v3-r9-decision-u3`):
  - Pins (sha256 of `manifest.json`; reference releases under `models/experiments/v3r9_retention_20261124/<tier>/`, local, with `PROVENANCE.md`): efficient `72ca6cc073bdf5f75e07c5dd7070c0a6fe42f273f9374e6ea9fe75c63a3caf5a`, balanced `c43862591e8caa505312ebbe5a307f4d673e08be20c331ec1855777f97bf0b3c`, quality `d2472f6ea6281542063cce8fac37b01497ceec1e0d81a398d3cc2b3927cf47ec`. References digests 224f1340..., 61336102..., 56a959b8.... Scoring the 200 bank rows takes 1.0 s (efficient), 1.2 s (balanced), 7 s (quality) on 8 CPUs, so the retention check is not the cost of a cycle.
  - Deviation from a strict rule: zero tolerance refuses every efficient calibration candidate (1 to 4 of 155 eligible rows regress, mostly `third_party_coworksalary/13`), so the production releases allow 5% of the eligible rows, rounded down (7, 9, 10). The user may tighten it by rebuilding the releases; the tolerance is inside the pinned manifest.
  - The hoist: admission and `prepare` were already outside the `BEGIN IMMEDIATE` since V3-R2 (the R1 note was stale); R9 adds the gate, a test with a parked scorer (resolve, status, a transaction on the other tier and a whole same-tier commit complete while a check is parked) and the check that `before_swap` finds a verdict for exactly that candidate and request.
  - V3-R6: wire the guard gate before the retention gate (cheap first). V3-R7: set `V3_RETENTION_ROOT` and `V3_RETENTION_BANK` (read-only mounts of the three reference releases and the approved bank; the bank is prompt text and must not be baked into an image); `main.rs` installs the gate only when they are set, so a deployment that omits them publishes without retention. The reference releases are Git-ignored: V3-R7 must decide how they reach the deployment (they hold ids and numbers, no prompt text, and could be committed under `rust/services/param-update/config/` if the user prefers; they are about 40 KB each).
  - Rerun: `MSYS_NO_PATHCONV=1 docker run --rm --cpus=8 -e CARGO_TARGET_DIR=target-docker-rel -e PRIVOKE_V3_RETENTION_RELEASES=/data/models/standard-releases -e PRIVOKE_V3_RETENTION_BANK=<bank> -e PRIVOKE_V3_RETENTION_CANDIDATES=<dir> -v <worktree>:/work -v <data>:/data:ro -w /work/rust rust:1.99.1-bookworm cargo test -p privoke-training --release --locked --test retention_v3_release -- --nocapture`.
  - Runs in parallel with V3-R3 to V3-R6. It must land before V3-R7.
  V3-P bank check (23 Nov 2026, read-only): the file at `train-sensitive-retention/approved-train-bank.json` hashes to `BANK_SHA256` (`c9b0b641...a41a`) and holds 200 rows (20 groups, all `train`). Every row has exactly `classification{sensitivity, visibility, categories}`, `packed_classification` and `allowed_actions`. All 200 rows map onto the V3 heads' outputs: 0 unmapped. Sensitivity is S1 (40), S2 (48) or S3 (112), all inside the head's S0-S3; visibility is P0 (20), P1 (40), P2 (20), P3 (20), P4 (40) or PU (60), all inside P0-P4 and PU; categories use 10 of the head's 10 (THIRD_PARTY 40, FINANCIAL 32, the other eight 16 each). Every `packed_classification` decodes with `Classification` and re-packs to itself with named labels equal to the decoded ones, and `allowed_actions` is the one action of the row's sensitivity (S1 ALLOW, S2 WARN, S3 BLOCK). The stop condition (a bank row whose labels do not map) does not trigger. The check covers label compatibility only; the teacher margin and gap over V3 head outputs still need the V3 port, and the 20 required groups of `BOUNDARY` are met by the bank as it stands.

## Stage V3-R7: Deployment cutover

- Objective:
  - Add v3-runtime and v3-fuzzer, with their certificates, to `deploy/gce/compose.yml` and `docker-compose.prod.yml`. Give param-update the publication key secret, a read-only mount of the frozen BC01/AU3 releases (for guard rows), the V3 reference releases (for retention) and the drift-bounds config.
  - Remove `privoke-fuzzer` and the V1 `MODEL_ID` and `FUZZER_TARGET`.
- Depends on: V3-R4b, V3-R6, V3-R9, and the U5 threshold being met.
- Owned paths: those compose files and the stage 23 smoke CI.
- Acceptance checks:
  - The container smoke CI is green.
  - One end-to-end efficient cycle publishes, and a client refreshes to the new version.
  - The deployed `v3-drift-bounds.toml` holds V3-R5's recalibrated values, and its evidence SHA-256 matches V3-R5's calibration record.
- Status: done (RUST-V3R7, 24 Nov 2026).
- Outcome: `8f01107` (merged). Rust CI run 45263929474 and service stack CI with container smoke run 45267737727 green. `v3-training` profile (param-update, v3-runtime, v3-fuzzer routine) replaces V1 training; reference releases committed and verified against `RELEASE_PINS`; drift bounds calibrated (evidence `c35c7350...`). Production key `privoke-v3-pub-2026-11` (user-approved): public half in `PRODUCTION_KEYS`, private seed at `C:/Users/Nicholas/.privoke/v3-publication.key`, never committed. Local Compose e2e with a test key: an efficient HEADS candidate published as sequence 1 (retention 4 of 155) and a client moved to it. Operator steps before first deploy: reissue the server certificate and identities, stage the ORIGINAL and bank directories, copy the key to Secret Manager, release a client build carrying the key.
- Handoff notes: V3-R7 (24 Nov 2026, wt/rust-v3r7; details in `docs/runtime/v3-publication.md#deployment-stage-v3-r7` and `docs/deployment/google-cloud.md`):
  - Compose (`deploy/gce/compose.yml`, `docker-compose.prod.yml`, `docker-compose.yml`): profile `v3-training` = `param-update-service`, `v3-runtime`, `v3-fuzzer` (`V3_MODE=routine`); `privoke-fuzzer`, `param-update-bootstrap`, `MODEL_ID`, `MODEL_ARTIFACT_PATH` and the V1 `FUZZER_TARGET` are gone, `analysis-service` and `analysis-model-streaming` are not deployed (they stay in `docker-compose.prod.yml` under profile `legacy-analysis` for the oracle checks; delete them with V3-R8b). The fuzzer and runtime sit on the `internal: true` network `training`. Param-update gets `V3_STORE`, `V3_PINNED` (new, three `<original>=<pinned release>` pairs: `bootstrap_pinned` at startup), `V3_SOURCE_ROOT`, `V3_DRIFT_BOUNDS`, `V3_POLICY_FILE`, `V3_RETENTION_ROOT` (reference releases in the image), `V3_RETENTION_BANK` (read-only mount, never in an image), `V3_PUBLISH_ROOT`, `V3_PUBLICATION_KEY_FILE` (mounted secret) and `V3_PUBLICATION_KEY_ID`, `V3_TIERS` and the scheduler's TLS; model-streaming gets `V3_STORE` (a writable volume so SQLite can keep its WAL `-shm`) and `V3_PUBLISH_ROOT` (read-only). Both Rust images create `/v3-store` and `/v3-published` for user 65532.
  - Found and fixed while running it for real: the scheduler's default `FUZZER_PROMPT_COUNT` was 32 but the fuzzer requires the frozen budget, 256 for the 64-step policy (every request was `InvalidArgument`); the V3 fuzzer had no Dockerfile or health check (added, with a `healthcheck` subcommand in both V3 services); the v3-runtime Dockerfile lacked the rule file `privoke-rules` embeds. `V3_SOURCE_ROOT` is assembled by `deploy.sh` from the deployed commit (the Python closure, and the frozen BC01 inputs and AU3 release, which are tracked as `rust/crates/privoke-curriculum/tests/fixtures/{bc01,au3}`); a checkout with autocrlf would change the pinned bytes, so the local source directory must come from `git archive`.
  - Identities: `param-update` (publisher, also the scheduler), `v3-fuzzer` (trainer), `v3-runtime` (runtime), `probe` (runtime); the server certificate must name `v3-fuzzer` and `v3-runtime` (reissue for the first deployment). Operator staging: `MODEL_RELEASE_DIR`, `V3_ORIGINAL_DIR` (initials ORIGINALs), `V3_RETENTION_BANK_DIR`, secret `V3_PUBLICATION_KEY_SECRET`.
  - Production key: id `privoke-v3-pub-2026-11`, public `867b106cf01cdd94e745efc536c57bdc8d7f36c7f11ffef1e3065c564969160c` in `PRODUCTION_KEYS`. The private seed is `C:\Users\Nicholas\.privoke\v3-publication.key` (outside every repository; never printed or committed). Open for the operator, not done by the build: copy it to Secret Manager and name the secret in `/opt/privoke/.env`; release a client build (the key is compiled into it) before the first publication, or older clients stay on the pinned ORIGINAL. Clients: the native-host installers store `V3_PACKAGE_REFRESH_MODELS` (default `privoke-v3-balanced`; the Windows launcher reads it as a fifth config line).
  - Reference releases: committed under `rust/services/param-update/config/v3-retention/<tier>/` (about 43 KB per tier, ids and numbers); `privoke-v3-retention-reference verify` against the pinned standard releases and the bank reproduced all three byte for byte (references 224f1340..., 61336102..., 56a959b8...), and `tests/v3_deployment.rs` hashes the committed manifests against `RELEASE_PINS` in CI. The deployed drift bounds are `calibrated`, evidence `c35c7350...45fef7` (same test).
  - End to end (local Docker Compose on loopback, real efficient/balanced/quality standard releases and the efficient ORIGINAL mounted read-only, a TEST publication key, never the production key; the client was built from a scratch copy with that key as its only `PRODUCTION_KEYS` entry): one efficient round, request `v3r-c0-efficient-heads-a0-ce01c404`, retention 4 violations of 155 eligible (7 allowed), published as sequence 1 (candidate `2569c9b8b8e6f88bf6aa03db6f9ab6550bf83bc8729397bee0251618e74ad5f6`, parent the pin `1f45a21b...`), signed by the test key; the FULL_ENCODER stage after it was `guard_rejected` (trainer-evidence rule) and settled `rejected`. A supervisor client (`privoke-supervisor fetch-model`, the same `Fetcher` and `LineageAdmission` as the refresh loop) went from the pinned `1f45a21b...` to `2569c9b8...` with the high-water mark at sequence 1. Not covered: the supervisor's own refresh loop timer and the worker load of the new version with real weights (R4b limit), a second round, quality and balanced rounds in the container stack, and the production key (it signs nothing until the operator copies it).
  - For V3-R8: `rust/services/v3-fuzzer` still depends on the V1 `privoke-fuzzer` crate (`pywire`, `client_tls_from_lookup`); extract those before deleting `rust/services/fuzzer`. `rust/services/analysis/tests/test_container.py` and `docker-compose.analysis-test.yml` lose their fuzzer and training checks with V1 training (the overlay no longer carries them). `evaluation/compose.presence.yml` now extends `docker-compose.legacy.yml`.

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

Order: (R1, P) → R2 (lands `routine_guard_rows` first) → (R5, R3, R9) → R6 → R4a → R4b → R7 → R8a → R8b.
