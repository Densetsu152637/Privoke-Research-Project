# Authentication and authorisation against the Rust stack (AUTHZ-20261126)

Summary of stage 13d (ASIACCS stage 13 plan, 13d-1a, 13d-1b and the 13d-2 run). The full record is
`paper/research/authn-authz-20261126.json`, with its rendering in `paper/research/authn-authz-20261126.md`. Every number below
comes from that record's rows. `evaluation/update_security_report.py --check` re-derives the totals and verifies the citations of
UPDSEC-20261116 and UPDSEC-20261117 in the gap table. `--check-s13d-coverage` verifies the attack map.

- **Question.** Can an unauthorised identity retrieve protected resources, submit updates or publish a candidate model? This is RQ2,
  `sec:eval_auth`.
- **Build.** `feat/asiaccs-s13d2` at `4e3f0ed`, clean.
  - The model-streaming and param-update images are the 13d-1b images, built from `7982a0c`; the service source is identical at
    `4e3f0ed`.
  - The telemetry image and the `privoke-pki` tool were built from `4e3f0ed` for this run and removed afterwards.
- **Date.** The record uses the local run date: 26 Nov 2026, Australia/Sydney, AEDT (UTC+11). The run was on 25 Nov in UTC,
  18:34–18:38. The harness output's UTC-dated header fields were renamed when the record was promoted, and the record lists those
  changes.
- **Scope labels.** `transport (Rust)` and `update path (Rust V3)`.

## Outcome

- **Rows.** 96 rows ran, with the standard V3 packages present; none was `not_run`. Every row met its property.
- **Coverage.** Each of the 10 attacks in the 13d map has at least one denied row with its denying layer. The layers are the TLS
  handshake, revocation, the registry, the role policy, the RPC surface and the application checks. No request that should have been
  denied was admitted: no `not_denied` attack row.
- **UPDSEC-20261117.** Its nine V3 rows that were `not_run` all ran here.
- **CheckpointService.** CK1–CK9 were denied at their claimed layers. CK8, a valid trainer committing a genuine 13c candidate under an
  unallocated request id, was rejected with `request_not_allocated` and the authority unchanged.
- **Positive controls.** The publisher commit was applied and served, the rollback to the pin was applied, and the runtime stage was
  accepted.
- **TLS level.** The captured bytes of an authenticated commit, replayed (TL1 and TL1-candidate), got no receipt. Every
  request-bearing record with one bit flipped aborted the connection under the 13d-1a rule (TL2). A man-in-the-middle server
  certificate was refused (TL3).

## Not established

- The client high-water mark is not observed, because no client runs in this stack. The version model-streaming serves stands in for
  it.
- Application-level replay and tamper are the 13c rows C2a, C2b and C9, cross-referenced here.
- The store-unchanged half of TL1, TL2 and CK1–CK7 is vacuous, because their store is empty. CK8 and TL1-candidate carry it on a
  populated store.
- There was one run on one host, over loopback.

The record reaches `feat/nick-branch` only through the record import.
