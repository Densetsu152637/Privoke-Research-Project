# V3 update attacks (V3UPDATK-20261126)

Rendered from the JSON record of the same name by `evaluation/v3_update_attacks_report.py --assemble`.

## Header

| field | value |
| --- | --- |
| schema | v3-update-attacks/1 |
| study_id | V3UPDATK-20261126 |
| scope_label | update path (Rust V3) |
| build.branch | feat/asiaccs-s13c2 |
| build.sha | 90fcd35b67551eb555b369b398a555c7fc82a1f1 |
| build.clean | True |
| build.update_path | The V3 guarded update path exists only in the Rust build (feat/rust-rewrite line); the Python submission build has no V3 update path. |
| host | os: Windows 11 Home, Docker Desktop 29.8.2 (WSL2); logical_cpus: 24; cpu_caps: real leg run 1 --cpus=8 (8 fit threads); real leg run 2 --cpus=12 (12 fit threads, 3 scorings at once); image builds on a buildx docker-container builder with cpuset and quota of 8 then 12 CPUs; stack param-update cpus 10, model-streaming 1, test client 1; toolchain: rust:1.99.1-bookworm; network: test client on the Compose project network (param-update-service:50052, model-streaming-service:50443); published ports stay on 127.0.0.1 |
| run_dates | 2026-11-25 (UTC), 2026-11-26 (AEST) |

### Build of each leg

| leg | build |
| --- | --- |
| ci | cargo test in rust:1.99.1-bookworm on 90fcd35b67551eb555b369b398a555c7fc82a1f1, clean tree. |
| container | Test client on 90fcd35b67551eb555b369b398a555c7fc82a1f1, clean tree; param-update image built from git archive of b3ed95b5ffc498f35a2e8bb9e7725bcbdb758a36 (the defect fix; param-update src identical to the build sha); model-streaming image built from git archive of 4d1b8ba780f3953941f5a56884c2832ea110c6af (model-streaming src identical to the build sha). |
| real | NOT the build sha and NOT clean: the real-weight leg ran on 4d1b8ba780f3953941f5a56884c2832ea110c6af plus the then uncommitted search fix that was committed unchanged as f693e5250dcc69bde71b3c9dd34d8db2df285aa5 (build.clean false for these rows). The later commits change only the rollback-control check, the C6 shape mutation and the param-update bootstrap of the pin's evidence, none of which the real rows exercise. |

Real-weight rows: build `4d1b8ba780f3953941f5a56884c2832ea110c6af+f693e52 (uncommitted at run time)`, clean `False`.

## Findings

- **F1 rollback-to-pin**: 13c-2 found that RollbackModel to the pinned standard release failed in every publishing deployment: bootstrap_pinned never stored the release's evidence.json, which the Publisher writes when it publishes the pin again, so the rollback answered NOT_FOUND 'Checkpoint object is not in this private catalog.' (container run 1, plan step 4). Fixed by `b3ed95b5ffc498f35a2e8bb9e7725bcbdb758a36`. bootstrap_pinned stores <release>/evidence.json after checking its SHA-256 against the manifest; a mismatch is refused and nothing unverified is stored; regression tests in rust/services/param-update/tests/v3_pinned.rs. The container rows of this record ran on the fixed build.
- **F2 v3-training healthcheck**: Under the docker-compose v3-training profile, the param-update healthcheck reports NOT_SERVING: the V1 engine's Health requires /models/privoke-baseline.json, which that profile does not mount. The V3 CheckpointService answers normally; the leg ran without waiting for Compose health. Not fixed (recorded only).

## Chain

| link | statement |
| --- | --- |
| threat | A compromised or faulty trainer (trainer or publisher role), or a corrupted transfer or store, supplies a bad V3 candidate. |
| defense | Admission (admit_candidate); DriftGate, GuardGate, RetentionGate and the Publisher's staging in prepare before the compare-and-swap; the compare-and-swap with request-id idempotence, stale_base and the trainer-evidence guard, signing; model-streaming serves only signed versions; clients apply admit_lineage and verify_package. |
| experiment | Every variant of rust/services/param-update/tests/s13c_rows.json: in CI (stand-in weights, test scorers), with the real Rust V3 encoder and the efficient release (C11b, C11f, C11g), and against the Compose v3-training param-update and model-streaming containers (every wire_path variant that is not CI-only). |
| metric | Per variant: the active model is unchanged (current, versions, publications, served version, client mark), or applied and recovered, or applied by design; and the check that refused it. |
| evidence | This record (rows, aggregates) and the row manifest; --check re-derives every aggregate. |

## Aggregates

| measure | value |
| --- | --- |
| rows | 87 |
| rows run | 85 |
| rows not run | 2 |
| property met | 85 |
| property not met | 0 |
| orphan blobs (reported, not a change) | 1329 |

| leg | rows | met | not met | not run |
| --- | --- | --- | --- | --- |
| ci | 50 | 50 | 0 | 0 |
| container | 33 | 32 | 0 | 1 |
| real | 4 | 3 | 0 | 1 |

### Rows by expected outcome

| outcome | ci | container | real |
| --- | --- | --- | --- |
| accepted_by_design | 1 | 1 | 1 |
| applied_recovered | 3 | 0 | 0 |
| noop_unchanged | 2 | 2 | 0 |
| rejected_unchanged | 44 | 30 | 3 |

### Rows by observed outcome

| outcome | ci | container | real |
| --- | --- | --- | --- |
| applied | 2 | 2 | 1 |
| client_refused | 7 | 0 | 0 |
| not_run | 0 | 1 | 1 |
| ok | 1 | 1 | 0 |
| refused:DATA_LOSS | 1 | 0 | 0 |
| refused:INTERNAL | 5 | 0 | 0 |
| refused:INVALID_ARGUMENT | 24 | 23 | 0 |
| rejected:commitment_mismatch | 1 | 0 | 0 |
| rejected:drift_exceeded | 2 | 1 | 0 |
| rejected:guard_recomputed | 1 | 1 | 1 |
| rejected:guard_rejected | 1 | 1 | 0 |
| rejected:guard_rows_differ | 1 | 0 | 0 |
| rejected:request_not_allocated | 1 | 1 | 0 |
| rejected:retention_regressed | 1 | 1 | 1 |
| rejected:stale_base | 2 | 1 | 0 |

## Positive controls (container leg)

| control | request | observed | met |
| --- | --- | --- | --- |
| publisher commit applied | v3r-c0-efficient-heads-a0-ff9e1fcd | applied | True |
| rollback to the pin applied | s13c2-rollback-r2 | applied:rollback | True |

## Real-weight leg

| measure | value |
| --- | --- |
| genuine request | v3r-c0-efficient-heads-a0-ff9e1fcd |
| genuine scope | heads |
| retention allowance | 7 |
| update bound (max_update_l2) | 4.2 |
| scorer evaluations (run 2; run 1) | 50; 36 |
| search seconds (run 2) | 165.3 |

| row | guard passes | joint (base, candidate) | retention violations | L2 from the pin |
| --- | --- | --- | --- | --- |
| C11b | False | 6, 5 | 0 | 0.9989 |
| C11f | True | 6, 11 | 11 | 4.0624 |
| C11g | True | 6, 11 | 7 | 3.4886 |

## Fit timings (planning only, not a result)

| request | tier | scope | wall seconds | cpus | outcome |
| --- | --- | --- | --- | --- | --- |
| v3r-c0-efficient-heads-a0-acd05a0b | efficient | heads | 45.7 | 8 | applied |
| v3r-c0-efficient-full_encoder-a0-093bfb25 | efficient | full_encoder | 93.1 | 8 | rejected:guard_rejected |
| v3r-c0-efficient-heads-a0-ff9e1fcd | efficient | heads | 52.0 | 12 | applied |
| v3r-c0-efficient-full_encoder-a0-1dde317c | efficient | full_encoder | 86.6 | 12 | rejected:guard_rejected |

## Rows

| id | leg | surface | expected | observed | rejecting check | property | not run reason |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C1a | ci | commit | rejected_unchanged | rejected:stale_base | commit compare-and-swap: stale_base | True |  |
| C1a | container | commit | rejected_unchanged | rejected:stale_base | commit compare-and-swap: stale_base | True |  |
| C1b | ci | commit | rejected_unchanged | rejected:stale_base | commit compare-and-swap: stale_base | True |  |
| C1c | ci | rollback | rejected_unchanged | refused:INVALID_ARGUMENT | rollback: Rollback target is not in the history of this model. | True |  |
| C1c | container | rollback | rejected_unchanged | refused:INVALID_ARGUMENT | rollback: Rollback target is not in the history of this model. | True |  |
| C1d | ci | rollback | rejected_unchanged | refused:INVALID_ARGUMENT | rollback: Rollback target was never published. | True |  |
| C2a | ci | commit | noop_unchanged | applied | replay / replayed: returns the stored receipt (receipt_status applied) | True |  |
| C2a | container | commit | noop_unchanged | applied | replay / replayed: returns the stored receipt (receipt_status applied) | True |  |
| C2b | ci | commit | rejected_unchanged | refused:INVALID_ARGUMENT | replayed: Request ID reused with different commit content. | True |  |
| C2b | container | commit | rejected_unchanged | refused:INVALID_ARGUMENT | replayed: Request ID reused with different commit content. | True |  |
| C2c | ci | client | rejected_unchanged | client_refused | admit_lineage: LineageError::Replay | True |  |
| C2d | ci | client | rejected_unchanged | client_refused | admit_lineage: LineageError::Downgrade | True |  |
| C3a | ci | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C3a | container | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C3b | ci | stage | noop_unchanged | ok | put (content addressed): the second stage is idempotent | True |  |
| C3b | container | stage | noop_unchanged | ok | put (content addressed): the second stage is idempotent | True |  |
| C4a | ci | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C4a | container | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C4b | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed immutable model provenance/config. | True |  |
| C4b | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed immutable model provenance/config. | True |  |
| C4c | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate ORIGINAL binding mismatch. | True |  |
| C4c | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate ORIGINAL binding mismatch. | True |  |
| C4d | ci | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C4d | container | commit | rejected_unchanged | refused:INVALID_ARGUMENT | commit identity check: Commit identity differs from candidate/fit evidence. | True |  |
| C4e | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidates cannot claim ORIGINAL scope. | True |  |
| C4e | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidates cannot claim ORIGINAL scope. | True |  |
| C4f | ci | client | rejected_unchanged | client_refused | LineageError::StatementModel / StatementManifest / WrongOriginal: StatementManifest; StatementModel and WrongOriginal were refused too | True |  |
| C5a | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed admitted tensor inventory. | True |  |
| C5a | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed admitted tensor inventory. | True |  |
| C5b | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | verify_checkpoint: Safetensors inventory differs from manifest. | True |  |
| C5b | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | verify_checkpoint: Safetensors inventory differs from manifest. | True |  |
| C6a | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed admitted tensor inventory. | True |  |
| C6a | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Candidate changed admitted tensor inventory. | True |  |
| C6b | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | verify_checkpoint: Safetensors inventory differs from manifest. | True |  |
| C6b | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | verify_checkpoint: Safetensors inventory differs from manifest. | True |  |
| C7a | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C7a | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C7b | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C7b | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C7c | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C7c | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | finite check, called from verify_checkpoint: Snapshot tensors must be finite float32. | True |  |
| C8a | ci | commit | rejected_unchanged | rejected:drift_exceeded | DriftGate::prepare: drift_exceeded | True |  |
| C8a | container | commit | rejected_unchanged | rejected:drift_exceeded | DriftGate::prepare: drift_exceeded | True |  |
| C8b | ci | commit | rejected_unchanged | rejected:drift_exceeded | DriftGate::prepare (cumulative from DriftGate::root): drift_exceeded | True |  |
| C8b | real | commit | rejected_unchanged | not_run |  | not run | C8b needs about 25 consecutive in-bound updates to reach the cumulative cap of 100; it runs synthetically in CI only (stand-in weights and test scorers), and the real-weight and container legs build one genuine candidate |
| C8b | container | commit | rejected_unchanged | not_run |  | not run | C8b needs about 25 consecutive in-bound updates to reach the cumulative cap of 100; it runs synthetically in CI only (stand-in weights and test scorers), and the real-weight and container legs build one genuine candidate |
| C8c | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | validate_execution: HEADS changed pretrained encoder. | True |  |
| C8c | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | validate_execution: HEADS changed pretrained encoder. | True |  |
| C8d | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Reported changes differ from actual checkpoint tensors. | True |  |
| C8d | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | admit_candidate: Reported changes differ from actual checkpoint tensors. | True |  |
| C9a | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Incomplete/corrupt checkpoint upload. | True |  |
| C9a | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Incomplete/corrupt checkpoint upload. | True |  |
| C9b | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Invalid bounded ordered checkpoint upload. | True |  |
| C9b | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Invalid bounded ordered checkpoint upload. | True |  |
| C9c | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Incomplete/corrupt checkpoint upload. | True |  |
| C9c | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage_checkpoint: Incomplete/corrupt checkpoint upload. | True |  |
| C9d | ci | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage: Candidate snapshot identity mismatch. | True |  |
| C9d | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | stage: Candidate snapshot identity mismatch. | True |  |
| C9e | ci | commit | rejected_unchanged | refused:INVALID_ARGUMENT | read: Immutable blob hash mismatch. | True |  |
| C9f-serve | ci | serve | rejected_unchanged | refused:DATA_LOSS | package / stream_asset re-hash: model asset hash mismatch | True |  |
| C9f-client | ci | client | rejected_unchanged | client_refused | download / verify_package: Model asset stream is incomplete or corrupted | True |  |
| C10a | ci | commit | rejected_unchanged | refused:INTERNAL | Publisher::prepare (CrashHook staged): the commit errors and rolls back | True |  |
| C10b | ci | commit | rejected_unchanged | refused:INTERNAL | Publisher::before_swap (CrashHook signed): the commit errors and rolls back | True |  |
| C10c | ci | commit | applied_recovered | refused:INTERNAL | Publisher::after_commit (CrashHook committed); reconcile promotes the staged directory: applied before the crash; recovered by reconcile | True |  |
| C10d | ci | commit | applied_recovered | refused:INTERNAL | Publisher::publish (CrashHook renamed); reconcile repairs the pointer: applied before the crash; recovered by reconcile | True |  |
| C10e | ci | commit | applied_recovered | refused:INTERNAL | Publisher::publish (CrashHook pointer); reconcile cleans up: applied before the crash; recovered by reconcile | True |  |
| C11a | ci | commit | rejected_unchanged | rejected:guard_rejected | commit via v3::publication_passes: guard_rejected | True |  |
| C11a | container | commit | rejected_unchanged | rejected:guard_rejected | commit via v3::publication_passes: guard_rejected | True |  |
| C11b | ci | commit | rejected_unchanged | rejected:guard_recomputed | GuardGate::prepare: guard_recomputed | True |  |
| C11b | real | commit | rejected_unchanged | rejected:guard_recomputed | GuardGate::prepare (V3Scorer, Rust V3 encoder): guard_recomputed | True |  |
| C11b | container | commit | rejected_unchanged | rejected:guard_recomputed | GuardGate::prepare (V3Scorer, Rust V3 encoder): guard_recomputed | True |  |
| C11c | ci | commit | rejected_unchanged | rejected:guard_rows_differ | GuardGate::prepare: guard_rows_differ | True |  |
| C11c | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | guard_targets (admission source validation): Execution guard targets differ from dispatched pinned source. | True |  |
| C11d | ci | commit | rejected_unchanged | rejected:commitment_mismatch | GuardGate::prepare: commitment_mismatch | True |  |
| C11d | container | stage | rejected_unchanged | refused:INVALID_ARGUMENT | validate_source_evidence (admission source validation): Execution source bytes differ from fit commitment. | True |  |
| C11e | ci | commit | rejected_unchanged | rejected:request_not_allocated | GuardGate::prepare: request_not_allocated | True |  |
| C11e | container | commit | rejected_unchanged | rejected:request_not_allocated | GuardGate::prepare: request_not_allocated | True |  |
| C11f | ci | commit | rejected_unchanged | rejected:retention_regressed | RetentionGate::prepare: retention_regressed | True |  |
| C11f | real | commit | rejected_unchanged | rejected:retention_regressed | RetentionGate::prepare (V3RetentionScorer, Rust V3 encoder): retention_regressed | True |  |
| C11f | container | commit | rejected_unchanged | rejected:retention_regressed | RetentionGate::prepare (V3RetentionScorer, Rust V3 encoder): retention_regressed | True |  |
| C11g | ci | commit | accepted_by_design | applied | RetentionGate::prepare (violations <= max_violations): accepted by design: a documented limit | True |  |
| C11g | real | commit | accepted_by_design | applied | RetentionGate::prepare (violations <= max_violations): accepted by design: a documented limit | True |  |
| C11g | container | commit | accepted_by_design | applied | RetentionGate::prepare (violations <= max_violations): accepted by design: a documented limit | True |  |
| CS1 | ci | serve | rejected_unchanged | refused:INVALID_ARGUMENT | is_published (authority only): explicit standard model and manifest pin required | True |  |
| CS2 | ci | client | rejected_unchanged | client_refused | verify: LineageError::Publication (unknown key) | True |  |
| CS3 | ci | client | rejected_unchanged | client_refused | verify: LineageError::Publication (bad signature) | True |  |
| CS4 | ci | client | rejected_unchanged | client_refused | admit_lineage: LineageError::Unsigned | True |  |

## Run times (UTC)

| run | step | time |
| --- | --- | --- |
| heavy_run_1 | lock_taken | 2026-11-25T14:13:02Z |
| heavy_run_1 | image_builds | 14:19:30-14:45:20 |
| heavy_run_1 | real_leg_run_1 | 14:46:00-14:55:53 |
| heavy_run_1 | real_leg_run_2 | 15:04:28-15:14:10 |
| heavy_run_1 | stack_up | 15:15:32 |
| heavy_run_1 | container_run_1_stopped_on_defect | about 15:27-15:28 |
| heavy_run_1 | lock_released | 2026-11-25T15:37:03Z |
| heavy_run_2 | lock_taken | 2026-11-25T15:58:55Z |
| heavy_run_2 | param_update_image_build | 15:59:44-16:10:23 |
| heavy_run_2 | container_run_2 | 16:18:23-16:20:41 |
| heavy_run_2 | container_run_3 | 16:23:16-16:24:48 |
| heavy_run_2 | container_run_4 | 16:28:00-16:29:12 |
| heavy_run_2 | teardown | 16:29:29 |
| heavy_run_2 | ci_rows | 16:29:29-16:32:33 |

## Harness corrections during the run

- Real leg run 1 (fit and search only, no rows kept): the first scorer search found no C11b, C11f or C11g candidate; the search was changed (f693e52) and the real leg rerun (run 2), whose rows and export this record uses.
- Container run 2 (fixed build): the rollback to the pin was applied, signed as sequence 2 and served, but the harness demanded an empty receipt reason (the reason is 'rollback'); corrected in 8fa6b15.
- Container run 3: C6a and C6b staged as valid because the exported mutation flattened a 1-D head bias (no shape change); corrected in 90fcd35, the two candidates re-derived from the exported genuine one, and the leg rerun on a fresh stack (run 4, whose rows this record uses). Every other container row of run 3 matched run 4's expected checks.

## Deviations from the plan

- The container-leg test client runs in a container on the Compose project network instead of the host loopback; the services stay published on 127.0.0.1 only.
- GetModelPackage is on model-streaming's public listener (consumer role), so the leg reads the served version as a registered test installation.
- A scratch Compose override rebinds /model-releases to the main checkout's standard releases, renames the two containers (s13c2-...) because a stale container from another project holds the name model-streaming-service, and caps their CPUs.
- The source root (the Python closure and the BC01/AU3 fixtures, as scheduler_real lays them out) is evaluation/results/s13c/source in the main checkout, mounted as V3_SOURCE_DIR.
- The evidence of the exported candidates (prompt-bearing) is exported separately (S13C_EXPORT_EVIDENCE) under evaluation/results/s13c; weights and manifests under models/experiments/s13c2-20261126.
- Rejection-only container candidates use the genuine candidate's evidence, not synthetic evidence: production admission validates the evidence source, so synthetic evidence would be refused before the targeted check.
- C11c and C11d are refused at stage in production by the admission source validation (recorded at that check); their CI rows reach GuardGate because CI stubs that validation (the 13c-1 deviation).
- C8b is not run in the real and container legs (CI only, per the plan).
- C11f and C11g real candidates come from a search with the real scorers (one head bias entry of the genuine candidate, swept at the full update budget, then bisected for exactly the allowance); the search trace is summarized below.
- The S13C_ALLOCATIONS parser moved to tests/s13c_allocations (shared); the report script gained --assemble.

## Not established

- C8b (the cumulative drift cap) on real weights or in the containers: CI only.
- C1b (a real race of two genuine candidates) and C1d (a deployment without the Publisher) in the containers: CI-only rows.
- Balanced and quality tiers: every real and container row is on the efficient tier.
- The client side on real weights: the client rows are the CI rows of s13c_client_admission.
- That an exactly-at-allowance candidate arises from a routine fit: C11g's candidate was found by a scorer search.
- The production publication key: every signature here uses a disposable test key.

## User actions

- none

## Commands

- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks (S13C_OUT=ci)`
- `RUSTDOCK cargo test -p privoke-runtime-supervisor --release --locked --test s13c_client_admission (S13C_OUT=ci)`
- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_real_leg (PRIVOKE_V3_S13C_*, S13C_EXPORT_*, S13C_SCORE_BATCH=3)`
- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_rederive_shape_candidates`
- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_compose_pki (S13C_PKI_DIR)`
- `docker compose -p s13c2 -f docker-compose.yml -f <scratch override> --profile v3-training up -d --no-build param-update-service model-streaming-service (FUZZER_PROMPT_COUNT=0, test PKI and publication key)`
- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_journal_seed (S13C_JOURNAL, S13C_ALLOCATIONS; param-update stopped)`
- `RUSTDOCK cargo test -p privoke-param-update --release --locked --test s13c_update_attacks_real s13c_container_leg (S13C_ENDPOINT, S13C_MODEL_ENDPOINT, --network s13c2_default)`
- `$PY evaluation/v3_update_attacks_report.py --assemble <header> --rows <ci, client, real, container rows> --out paper/research/v3-update-attacks-20261126.json --markdown paper/research/v3-update-attacks-20261126.md`
- `$PY evaluation/v3_update_attacks_report.py --check paper/research/v3-update-attacks-20261126.json`
