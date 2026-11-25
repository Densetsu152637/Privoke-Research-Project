# V3 update attacks (V3UPDATK-20261126)

Summary of stage 13c (ASIACCS stage 13 plan, 13c-1 and 13c-2). The full record is
`paper/research/v3-update-attacks-20261126.json`, with its rendering in `paper/research/v3-update-attacks-20261126.md`. Every
number below is taken from that record's `aggregates`, and `evaluation/v3_update_attacks_report.py --check` recomputes them from
the rows.

- **Question.** Can an invalid, stale, replayed or behaviourally unsafe update replace the active V3 model? This is RQ2,
  `sec:eval_update`.
- **Build.** `feat/asiaccs-s13c2` at `90fcd35b67551eb555b369b398a555c7fc82a1f1`, clean, for the CI and container legs. The V3
  guarded update path exists only in the Rust build. The real-weight rows ran on `4d1b8ba` plus the search fix that was later
  committed as `f693e52`, which was not clean at run time. The record states this for each leg.
- **Scope label.** `update path (Rust V3)`.

## Outcome

- **Rows.** There are 87 rows: 50 CI, 4 real-weight and 33 container. 85 ran, 2 did not (C8b in the real-weight and container
  legs, which is CI-only by plan).
- **Property.** 85 of the 85 rows that ran met their property: the active model was unchanged, recovered, or applied by design.
  None failed.
- **Real-weight leg.** A genuine efficient-tier HEADS candidate came from a real routine fit. The real Rust V3 scorers then
  repeated the three scorer-dependent rows:
  - C11b was refused with `guard_recomputed`.
  - C11f was refused with `retention_regressed`: 11 violations against an allowance of 7.
  - C11g was applied by design at exactly 7 violations, a documented limit.
- **Container leg.** Every `wire_path` variant that is not CI-only ran against the Compose `v3-training` param-update and
  model-streaming containers. They used mutual TLS, a test PKI and a disposable test publication key. The served version was read
  through `GetModelPackage`.
  - The positive control was applied, signed and served.
  - The rollback to the pin was applied as sequence 2.
  - Every attack row was refused at its named check, except C11g, which was applied by design.
  - C11c and C11d were refused at stage by the production admission source validation.

## Findings

1. **Rollback to the pinned release failed in every publishing deployment.** `bootstrap_pinned` never stored the release's
   `evidence.json`, so `RollbackModel` to the pin answered NOT_FOUND. The container leg found this; it is fixed in `b3ed95b`, with
   regression tests in `rust/services/param-update/tests/v3_pinned.rs`. The container rows of the record ran on the fixed build.
2. **The `v3-training` profile reports param-update as NOT_SERVING.** The V1 engine's health check needs
   `/models/privoke-baseline.json`, which that profile does not mount. The V3 checkpoint service is unaffected. This is recorded
   only and not fixed.

## Not established

- C8b (the cumulative drift cap) was not run on real weights or in the containers.
- C1b and C1d did not run in the containers; they are CI-only.
- The balanced and quality tiers were not tested.
- The client side was not tested on real weights.
- An exactly-at-allowance candidate was not shown to arise from a routine fit: C11g's candidate was found by a scorer search.
- The production publication key was not used.

The record reaches `feat/nick-branch` only through the record import.
