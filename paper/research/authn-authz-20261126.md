# Authentication and authorisation against the Rust stack (AUTHZ-20261126)

Stage 13d-2 of the ASIACCS stage 13 plan. The JSON record of the same name holds every row. The generated tables below are rendered from it by
`evaluation/update_security_report.py --record paper/research/authn-authz-20261126.json --document paper/research/authn-authz-20261126.md`.
`--check` verifies the header, the vocabulary of every row, the coverage of the 13d attack map, the gap-table citations of
UPDSEC-20261116 and UPDSEC-20261117 and the totals; `--check-s13d-coverage` verifies the attack map alone.

## Header

| field | value |
| --- | --- |
| schema | privoke.authn-authz.v1 |
| study_id | AUTHZ-20261126 |
| scope_label | transport (Rust); update path (Rust V3) |
| build.branch | feat/asiaccs-s13d2 |
| build.sha | 4e3f0ed0720250bbaeffd1eec4602b2b25734f0d |
| build.clean | True |
| host | Windows 11 Home, Docker Desktop (WSL2), 24 logical CPUs; Python 3.13 host client (grpcio, OpenSSL helper); services in Docker on 127.0.0.1 |
| run_dates | 2026-11-25 (UTC), 2026-11-26 (AEDT, UTC+11) |
| run window | builds 18:27:41–18:33:49 UTC, harness 18:34:19–18:38:00 UTC (05:27–05:38 AEDT, 26 Nov), under `s13-host.lock`, 8-core cap |
| commands | `json.commands` (the harness command line, every `privoke-pki` call, the RUSTDOCK helpers and the Compose stack) |
| user_actions | none |

**Record date and timezone.** The record is named by the local run date, Australia/Sydney (AEDT, UTC+11), as V3UPDATK-20261126 is. The
harness names its output by the UTC date (AUTHZ-20261125). When the harness output (`evaluation/results/s13d/13d-2/authz-13d2-run1.json`
in the main checkout, Git-ignored) was promoted to this record, four header fields were changed: `study_id`, `id` and `chain.evidence`
(AUTHZ-20261125 to AUTHZ-20261126) and `run_dates`. Four fields were added: `header_promotion` (which lists these changes),
`run_window_utc`, `image_provenance` and `client_high_water_mark`. Two notes were appended to `not_established`. No row, summary,
coverage or gap entry was edited, and `--check` passes on the promoted record.

## Chain

| link | statement |
| --- | --- |
| threat | An attacker with no credentials, wrong credentials or stolen low-privilege credentials. |
| defense | Mutual TLS with the rustls verifier and CRL hot reload; the registry; the role policy; the RPC surface; the V3 store's application checks. |
| experiment | Negative rows, with positive controls, from a host Python client against the Rust containers on loopback, with the standard V3 packages present. |
| metric | For each attack, denial (required) and the denying layer (`denied_by`). |
| evidence | This record. |

## Build and images

The host client and harness ran at `4e3f0ed` (clean), the merge of 13d-1a, 13c-2 and 13d-1b into `feat/rust-rewrite`.

| image or tool | provenance |
| --- | --- |
| `privoke-model-streaming-rust:s13d1b` (7aff0f8c7f5f) | Built by 13d-1b from `7982a0c`. `rust/` and `docker-compose.prod.yml` are identical between `7982a0c` and `4e3f0ed`, so it is the service at the build sha. |
| `privoke-param-update-rust:s13d1b` (eb41b5bf6f67) | Built by 13d-1b from `7982a0c`; identical service source at `4e3f0ed`, as above. |
| `privoke-telemetry-rust:s13d2` (cd0264c29d84) | Built for this run with the unchanged `rust/services/telemetry/Dockerfile` from a `git archive` of `4e3f0ed`, on a buildx builder capped at 8 CPUs. Removed after the run. |
| `privoke-pki` | Linux release build of the crate at `4e3f0ed` (`cargo build --release --locked -p privoke-pki` in `rust:1.99.1-bookworm`), run in a container by the harness. Deleted after the run. |
| RUSTDOCK helpers | `rust:1.99.1-bookworm`, the 13c-2 seam helpers (`s13c_compose_pki`, `s13c_source_root`, `s13c_journal_seed`) at `4e3f0ed`, `--cpus=8`. |

The 13c-2 export used by CK8, the positive controls and TL1-candidate is the same one 13d-1b used:
`models/experiments/s13c2-20261126/candidates`, `evaluation/results/s13c/evidence`, the ORIGINAL packages in
`models/experiments/pretrained_v3_20261012/initials` and the approved retention bank. All of these are local and not in Git.
The PKI and keys were disposable, made in the harness's scratch directory and deleted with it; the production publication key was not used.

## Families

- **T (model-streaming retrieval)** and **R3, R4, R7, R8, R9 (credentials and retrieval)**, **X8, I1–I4 (installations)**, **R6
  (plaintext ports)**, **X13 (live revocation and deny-list)** and **R10 (telemetry)**: the 13d-1a re-run families. They ran with
  the standard V3 packages present, without `--no-v3`. The nine rows that UPDSEC-20261117 left `not_run` (T7, T9, T10, R8-wrong-pin,
  R8-not-allowlisted, I3, X1, X1b and X1c) all ran here. T7, T9, T10, R8-wrong-pin, R8-not-allowlisted and I3 were denied at the
  application layer. X1, X1b and X1c are positive controls and were served.
- **CK1–CK7, CK9 (CheckpointService)**: denied at their claimed layers (role policy, TLS handshake, revocation after a CRL swap with no
  restart, the registry deny-list on an open connection, and the RPC surface).
- **TL1–TL3 (TLS level)**: TL2 follows the 13d-1a rule. Each request-bearing type-23 record was flipped; the client saw UNKNOWN; the
  server alerted and closed before any answer-sized record; and a clean control then returned NOT_FOUND. `TL2-handshake` is reported
  separately.
- **13d-1b rows** on their own Compose v3-training stack (`s13d2-*` containers): CK8 was rejected with `request_not_allocated` at the
  application layer, with the authority unchanged. TL1-candidate's replay got no receipt, with the authority unchanged. The publisher's
  commit of the same candidate was then applied and served, and the rollback to the pin was applied. The runtime stage was accepted
  with the store unchanged.

## Not established and limits

- **Client high-water mark.** The shared convention's "unchanged" authority includes the client high-water mark. It is not observed
  here, because no client (runtime supervisor) runs in this stack; the version model-streaming serves stands in for it in every
  authority observation. Client admission is 13c's subject.
- Application-level replay and tamper are the 13c rows C2a, C2b and C9, cross-referenced and not repeated.
- The store-unchanged half of TL1, TL2 and CK1–CK7 is vacuous, because their store is empty. CK8 and TL1-candidate carry the check
  on a store that holds the pin and an admissible candidate.
- The candidate rows use the test PKI of the 13c-2 helper (the `privoke_pki` crate), not the `privoke-pki` CLI PKI of the other rows.
- The 13d-1a family containers are named `updsec-rust-*` by the harness; only the candidate stack and its helpers carry the `s13d2-`
  prefix. Every container was removed after the run.
- One run on one host, over loopback. The rows are deterministic denials, not samples, and no repeat run was made.

Full list: `json.not_established`.

<!-- BEGIN GENERATED TABLES -->
Rows: 96; not run: 0; rows whose security property was not met: 0 (none). Coverage of the attack map: complete.

### Attack coverage

| Attack | Rows that ran with a denied_by | Layers | Cross-reference | Covered |
| --- | --- | --- | --- | --- |
| Invalid credentials | R3-expired, R3-not-yet-valid, R3-no-client-auth-eku, R3-server-auth-only, R4, R4-self-signed | tls_handshake | none | yes |
| Expired certificate | R3-expired, R3-not-yet-valid | tls_handshake | none | yes |
| Missing credentials | R7-no-cert, R8-no-cert, R10-no-cert, CK5 | tls_handshake | none | yes |
| Wrong client identity | R7-unregistered, X8, CK3 | registry, role_policy | none | yes |
| Unauthorised model retrieval | T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, R7-no-cert, R7-unregistered, R7-reporter, R7-traversal, R7-unknown, R8-no-cert, R8-unregistered, R8-reporter, R8-wrong-pin, R8-not-allowlisted | application, registry, role_policy, tls_handshake | none | yes |
| Unauthorised update submission | R9-submit-update, CK1, CK3, CK4 | role_policy, rpc_surface | none | yes |
| Unauthorised publication | CK2, CK6, CK7 | registry, revocation, role_policy | none | yes |
| Replayed authenticated request | TL1 | tls_handshake | 13c C2a, 13c C2b | yes |
| Tampered request | TL2, TL3 | tls_handshake | 13c C9 | yes |
| Cross-identity misuse | R7-reporter, R10-installation, CK2, CK4, CK8 | application, role_policy | none | yes |

### Rows by denying layer

| denied_by | Rows |
| --- | ---: |
| tls_handshake | 27 |
| revocation | 3 |
| registry | 8 |
| role_policy | 10 |
| rpc_surface | 7 |
| application | 14 |
| client_admission | 0 |
| not_denied | 24 |
| (no layer: did not run, or a property row) | 3 |

### Rows

| ID | Service | Scope | Path | Row | Identity | Issuer | Observed | Code | denied_by | Store unchanged | Property met |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| X1 | model-streaming | transport (Rust) | rust-public | Registered installation certificate from the client CA (positive control): fetch the default V3 manifest. | registered | privoke-pki | accepted | OK | not_denied | yes | yes |
| X1d | model-streaming | transport (Rust) | rust-public | Registered installation streams the legacy catalogue model over mutual TLS (positive control that needs no V3 package). | registered | privoke-pki | accepted | OK | not_denied | yes | yes |
| X1b | model-streaming | transport (Rust) | rust-public | Registered installation streams config.json of the default V3 package and verifies its pin (G8 positive control). | registered | privoke-pki | accepted | OK | not_denied | yes | yes |
| X1c | model-streaming | transport (Rust) | rust-public | Registered installation streams the whole model.safetensors of the default V3 package over mutual TLS and verifies its pin. | registered | privoke-pki | accepted | OK | not_denied | yes | yes |
| T1 | model-streaming | transport (Rust) | rust-public | Model download by an unauthenticated consumer with an arbitrary consumer_id. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| T2 | model-streaming | transport (Rust) | rust-public | Model download by a registered installation claiming the installed runtime's consumer_id. | registered | privoke-pki | rejected | PERMISSION_DENIED | application | yes | yes |
| T3 | model-streaming | transport (Rust) | rust-public | Model download with no consumer_id and no client certificate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| T4 | model-streaming | transport (Rust) | rust-public | Model download with a control character in consumer_id (registered installation). | registered | privoke-pki | rejected | PERMISSION_DENIED | application | yes | yes |
| T5 | model-streaming | transport (Rust) | rust-public | Download of a model id that is not in the catalogue (registered installation). | registered | privoke-pki | rejected | NOT_FOUND | application | yes | yes |
| T6 | model-streaming | transport (Rust) | rust-public | Download with a path-traversal model id (registered installation). | registered | privoke-pki | rejected | NOT_FOUND | application | yes | yes |
| T7 | model-streaming | transport (Rust) | standard-v3 | Legacy float-tensor download of the standard V3 model (registered installation). | registered | privoke-pki | rejected | FAILED_PRECONDITION | application | yes | yes |
| T8 | model-streaming | transport (Rust) | standard-v3 | Standard V3 package manifest requested by an unauthenticated consumer. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| T9 | model-streaming | transport (Rust) | standard-v3 | Asset stream with a wrong manifest pin (registered installation). | registered | privoke-pki | rejected | INVALID_ARGUMENT | application | yes | yes |
| T10 | model-streaming | transport (Rust) | standard-v3 | Asset stream for a non-allowlisted asset name (path traversal). | registered | privoke-pki | rejected | INVALID_ARGUMENT | application | yes | yes |
| T11 | model-streaming | transport (Rust) | standard-v3 | Asset stream for a legacy model id (registered installation). | registered | privoke-pki | rejected | INVALID_ARGUMENT | application | yes | yes |
| T12 | model-streaming | transport (Rust) | standard-v3 | Asset stream with correct pin and name by an unauthenticated consumer. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R3-expired | model-streaming | transport (Rust) | rust-public | An expired client certificate, for a registered identity, is refused at the TLS handshake. | expired | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R3-not-yet-valid | model-streaming | transport (Rust) | rust-public | A not-yet-valid client certificate, for a registered identity, is refused at the TLS handshake. | future | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R3-no-client-auth-eku | model-streaming | transport (Rust) | rust-public | A client certificate with no extended key usage, for a registered identity, is refused at the TLS handshake. | no-eku | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R3-server-auth-only | model-streaming | transport (Rust) | rust-public | A client certificate whose only usage is serverAuth, for a registered identity, is refused at the TLS handshake. | server-only | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R4 | model-streaming | transport (Rust) | rust-public | A certificate from a foreign CA carrying a registered installation's subject is refused at the handshake. | foreign | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R4-self-signed | model-streaming | transport (Rust) | rust-public | A self-signed certificate carrying a registered installation's subject is refused at the handshake. | self-signed | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R7-no-cert | model-streaming | transport (Rust) | rust-public | GetModelPackage without a client certificate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R7-unregistered | model-streaming | transport (Rust) | rust-public | GetModelPackage by a valid, unregistered installation certificate. | second | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| R7-reporter | model-streaming | transport (Rust) | rust-public | GetModelPackage with the telemetry reporter credential. | reporter | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| R7-traversal | model-streaming | transport (Rust) | rust-public | GetModelPackage with a path-traversal model id (registered installation). | registered | privoke-pki | rejected | NOT_FOUND | application | yes | yes |
| R7-unknown | model-streaming | transport (Rust) | rust-public | GetModelPackage for a model that is not in the catalogue (registered installation). | registered | privoke-pki | rejected | NOT_FOUND | application | yes | yes |
| R8-no-cert | model-streaming | transport (Rust) | standard-v3 | StreamModelAsset without a client certificate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R8-unregistered | model-streaming | transport (Rust) | standard-v3 | StreamModelAsset by a valid, unregistered installation certificate. | second | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| R8-reporter | model-streaming | transport (Rust) | standard-v3 | StreamModelAsset with the telemetry reporter credential. | reporter | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| R8-wrong-pin | model-streaming | transport (Rust) | standard-v3 | StreamModelAsset with a wrong pin (registered installation). | registered | privoke-pki | rejected | INVALID_ARGUMENT | application | yes | yes |
| R8-not-allowlisted | model-streaming | transport (Rust) | standard-v3 | StreamModelAsset for a non-allowlisted asset name (registered installation). | registered | privoke-pki | rejected | INVALID_ARGUMENT | application | yes | yes |
| R9-get-model-parameters | model-streaming | transport (Rust) | rust-public | GetModelParameters on the public listener (registered installation). | registered | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| R9-submit-update | model-streaming | transport (Rust) | rust-public | ParamUpdateService.SubmitParameterUpdate on the public listener (registered installation). | registered | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| R9-update-status | model-streaming | transport (Rust) | rust-public | ParamUpdateService.GetParameterUpdateStatus on the public listener (registered installation). | registered | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| X8 | model-streaming | transport (Rust) | rust-public | A second, distinct installation certificate from the same client CA whose id is not registered. | second | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| X8b | model-streaming | transport (Rust) | rust-public | A second installation certificate from the same client CA whose id is registered (positive control). | second-registered | privoke-pki | accepted | OK | not_denied | yes | yes |
| I1 | model-streaming | transport (Rust) | rust-internal | A registered service identity downloads a legacy model on the internal listener (positive control). | runtime | privoke-pki | accepted | OK | not_denied | yes | yes |
| I2 | model-streaming | transport (Rust) | rust-internal | A registered installation (consumer role) on the internal listener. | registered | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| I3 | model-streaming | transport (Rust) | rust-internal | A registered service identity asks the internal listener for the V3 model through the legacy float RPC. | runtime | privoke-pki | rejected | FAILED_PRECONDITION | application | yes | yes |
| I4 | model-streaming | transport (Rust) | rust-internal | A registered service identity calls a consumer RPC on the internal listener. | runtime | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| R6-model-main-public | model-streaming | transport (Rust) | rust-public | A plaintext call to the public model-streaming port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R6-model-main-internal | model-streaming | transport (Rust) | rust-public | A plaintext call to the internal model-streaming port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R10-no-cert | telemetry | transport (Rust) | rust-telemetry | RecordTelemetry on the public listener without a client certificate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R10-installation | telemetry | transport (Rust) | rust-telemetry | RecordTelemetry on the public listener with a registered installation certificate (not the reporter credential). | registered | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| R10-unregistered | telemetry | transport (Rust) | rust-telemetry | RecordTelemetry on the public listener with a valid but unregistered installation certificate. | second | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| R10-summary-no-cert | telemetry | transport (Rust) | rust-telemetry | GetTelemetrySummary on the internal listener without a client certificate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R10-summary-installation | telemetry | transport (Rust) | rust-telemetry | GetTelemetrySummary on the internal listener with a registered installation certificate. | registered | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| R10-summary-unregistered | telemetry | transport (Rust) | rust-telemetry | GetTelemetrySummary on the internal listener with an unregistered installation certificate. | second | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| R10-summary-reporter | telemetry | transport (Rust) | rust-telemetry | GetTelemetrySummary on the internal listener with the shared reporter credential. | reporter | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| R10-summary-public | telemetry | transport (Rust) | rust-telemetry | GetTelemetrySummary on the public listener with the reporter credential. | reporter | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| R10-reporter | telemetry | transport (Rust) | rust-telemetry | The shared reporter credential records a randomised report (positive control). | reporter | privoke-pki | accepted | OK | not_denied | no | yes |
| R10-summary-service | telemetry | transport (Rust) | rust-telemetry | A registered service identity reads the aggregate summary on the internal listener (positive control). | runtime | privoke-pki | accepted | OK | not_denied | yes | yes |
| R6-telemetry-public | telemetry | transport (Rust) | rust-telemetry | A plaintext call to the public telemetry port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R6-telemetry-internal | telemetry | transport (Rust) | rust-telemetry | A plaintext call to the internal telemetry port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R10-no-identity-in-log | telemetry | transport (Rust) | rust-telemetry | After refused and accepted requests from named identities, the container log holds none of their installation ids. | registered, unregistered, reporter | none | rejected | OK |  | n/a | yes |
| X13-baseline-x13-revoked | model-streaming | transport (Rust) | rust-public | A registered installation (x13-revoked) is served before any revocation (positive control). | x13-revoked | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-baseline-x13-denied | model-streaming | transport (Rust) | rust-public | A registered installation (x13-denied) is served before any revocation (positive control). | x13-denied | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-baseline-x13-bystander | model-streaming | transport (Rust) | rust-public | A registered installation (x13-bystander) is served before any revocation (positive control). | x13-bystander | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-open-connection-baseline | model-streaming | transport (Rust) | rust-public | The installation that will be deny-listed has an open, working connection (positive control). | x13-denied | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-revoked | model-streaming | transport (Rust) | rust-public | A revoked installation's new handshake fails after the CRL is swapped, without a restart. | x13-revoked | privoke-pki | rejected | UNAVAILABLE | revocation | yes | yes |
| X13-bystander | model-streaming | transport (Rust) | rust-public | An installation that was not revoked is still served after the CRL swap (positive control). | x13-bystander | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-corrupt-crl-keeps-revocation | model-streaming | transport (Rust) | rust-public | After the CRL file is replaced by garbage, the revoked installation is still refused (the old configuration is kept). | x13-revoked | privoke-pki | rejected | UNAVAILABLE | revocation | yes | yes |
| X13-corrupt-crl-keeps-serving | model-streaming | transport (Rust) | rust-public | After the CRL file is replaced by garbage, the service keeps serving a valid installation (positive control). | x13-bystander | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-denylist-open-connection | model-streaming | transport (Rust) | rust-public | A deny-listed identity gets PERMISSION_DENIED on a connection that was already open. | x13-denied | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| X13-denylist-new-connection | model-streaming | transport (Rust) | rust-public | The same deny-listed identity is also refused on a new connection. | x13-denied | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| X13-bystander-after-denylist | model-streaming | transport (Rust) | rust-public | A registered installation that is not deny-listed is still served (positive control). | x13-bystander | privoke-pki | accepted | OK | not_denied | yes | yes |
| X13-no-restart | model-streaming | transport (Rust) | rust-public | None of the changes above needed a restart: the service process is the one that started the run. | operator | none | rejected | OK |  | n/a | yes |
| R6-model-public | model-streaming | transport (Rust) | rust-public | A plaintext call to the public model-streaming port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| R6-model-internal | model-streaming | transport (Rust) | rust-public | A plaintext call to the internal model-streaming port. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| CK0-publisher-health | param-update | update path (Rust V3) | rust-checkpoint | The publisher service identity reaches CheckpointService.Health (positive control: the denials below are not a configuration failure). | publisher | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK0-trainer-health | param-update | update path (Rust V3) | rust-checkpoint | The trainer service identity reaches CheckpointService.Health (positive control: the denials below are not a configuration failure). | trainer | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK0-runtime-health | param-update | update path (Rust V3) | rust-checkpoint | The runtime service identity reaches CheckpointService.Health (positive control: the denials below are not a configuration failure). | runtime | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK1 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate as a runtime service. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | runtime | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| CK2 | param-update | update path (Rust V3) | rust-checkpoint | RollbackModel as a trainer service. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | trainer | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| CK3 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate with a registered installation certificate. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | registered | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| CK4 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate with the shared reporter credential. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | reporter | privoke-pki | rejected | PERMISSION_DENIED | role_policy | yes | yes |
| CK5 | param-update | update path (Rust V3) | rust-checkpoint | StageCheckpoint with no client certificate. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | no client certificate | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| CK9 | param-update | update path (Rust V3) | rust-checkpoint | An RPC the policy does not list (TrainingService.FitCandidate), called by a publisher. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | publisher | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| CK9-submit-update | param-update | update path (Rust V3) | rust-checkpoint | The removed V1 SubmitParameterUpdate on the update listener, called by a publisher. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | publisher | privoke-pki | rejected | UNIMPLEMENTED | rpc_surface | yes | yes |
| R6-checkpoint | param-update | update path (Rust V3) | rust-checkpoint | A plaintext call to the update service port that serves CheckpointService. | no TLS at all | none | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| CK6-baseline | param-update | update path (Rust V3) | rust-checkpoint | The trainer that will be revoked reaches CheckpointService.Health before the CRL changes (positive control). | ck-revoked-trainer | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK6 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate from a revoked trainer after an atomic CRL swap, with no restart. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | ck-revoked-trainer | privoke-pki | rejected | UNAVAILABLE | revocation | yes | yes |
| CK7-baseline | param-update | update path (Rust V3) | rust-checkpoint | The trainer that will be deny-listed has an open, working connection (positive control). | ck-denied-trainer | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK7 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate from a deny-listed trainer on a connection that was already open. The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | ck-denied-trainer | privoke-pki | rejected | PERMISSION_DENIED | registry | yes | yes |
| CK-no-restart | param-update | update path (Rust V3) | rust-checkpoint | Neither the CRL swap nor the deny-list entry needed a restart. | operator | none | rejected | OK |  | n/a | yes |
| TL1 | param-update | transport (Rust) | rust-tls | The recorded TLS 1.3 bytes of an authenticated CommitCandidate, replayed on a new connection (no receipt). The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | trainer | privoke-pki | rejected | CONNECTION_ABORTED | tls_handshake | yes | yes |
| TL2 | param-update | transport (Rust) | rust-tls | One bit flipped in each client record that carries the request, through a loopback proxy (the connection aborts, no receipt). The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | trainer | privoke-pki | rejected | CONNECTION_ABORTED | tls_handshake | yes | yes |
| TL2-handshake | param-update | transport (Rust) | rust-tls | Extra to TL2: one bit flipped in the client's handshake flight (Certificate, CertificateVerify, Finished). The store-unchanged check of this row is vacuous: the store is empty, so an admitted request and a refused one leave the same state. CK8 and TL1-candidate (13d-1b) carry the check on a store that holds the pin and an admissible candidate. | trainer | privoke-pki | rejected | CONNECTION_ABORTED | tls_handshake | yes | yes |
| TL3 | param-update | transport (Rust) | rust-tls | A man in the middle presents a server certificate that is not from the server CA: the client refuses before it sends a request. | trainer (client) against a foreign-CA server certificate | openssl-helper | rejected | UNAVAILABLE | tls_handshake | yes | yes |
| TL3-control | param-update | transport (Rust) | rust-tls | The same server certificate completes a handshake with a client that trusts its CA (positive control: the refusal above is about the CA). | trainer (client) trusting the foreign CA | openssl-helper | accepted | OK | not_denied | yes | yes |
| CK-positive-runtime-stage | param-update | update path (Rust V3) | rust-checkpoint | A runtime service stages the genuine 13c candidate: its evidence, then its checkpoint with the manifest (accepted). | v3-runtime (runtime) | privoke-pki | accepted | OK | not_denied | yes | yes |
| CK8 | param-update | update path (Rust V3) | rust-checkpoint | CommitCandidate from a valid trainer carrying a valid 13c candidate (the genuine checkpoint, evidence naming an unallocated request id): rejected/request_not_allocated, the authority unchanged. | s13c2-trainer (trainer) | privoke-pki | rejected | RECEIPT_REJECTED | application | yes | yes |
| TL1-candidate | param-update | transport (Rust) | rust-tls | The TLS 1.3 bytes of a publisher's authenticated CommitCandidate of the genuine 13c candidate, recorded while the proxy held the request back from the server, replayed on a new connection: no receipt, the authority unchanged, and the same commit is applied when sent cleanly afterwards (the unchanged store is not vacuous). | s13c2-publisher (publisher) | privoke-pki | rejected | CONNECTION_ABORTED | tls_handshake | yes | yes |
| CK-positive-publisher-commit | param-update | update path (Rust V3) | rust-checkpoint | A publisher commits the allocated genuine 13c candidate on the pin (applied, signed and served). | s13c2-publisher (publisher) | privoke-pki | accepted | OK | not_denied | no | yes |
| CK-positive-publisher-rollback | param-update | update path (Rust V3) | rust-checkpoint | A publisher rolls back to the pin (applied: a new signed publication with a higher sequence, served). | s13c2-publisher (publisher) | privoke-pki | accepted | OK | not_denied | no | yes |

### Unmet properties

No request that should have been denied was admitted.

### Pending rows (13d-1b)

None.

### Gap table

| Gap | Status | Reason | Rows that ran | Static rows |
| --- | --- | --- | --- | --- |
| GAP-IDENTITY-SELF-ASSERTED | kept (telemetry) | source_id and consumer_id come from the certificate for update and model retrieval (met). Telemetry reports carry no identity field and the shared reporter credential is deliberately not individual, so nothing is bound there (kept). | T2, R10-no-identity-in-log | none |
| GAP-NO-CREDENTIAL-MECHANISM | met | Client certificates are checked by the service itself: a bearer token is ignored, and expired, not-yet-valid, wrong-usage and foreign-CA certificates are refused at the handshake. | R3-expired, R3-not-yet-valid, R3-no-client-auth-eku, R3-server-auth-only | none |
| GAP-NO-RETRIEVAL-AUTH | met | Every model RPC except Health needs the consumer role; the private RPCs answer UNIMPLEMENTED on the public listener. GetModelPackage and StreamModelAsset are public by design (G8). | T1, T3, T8, T12, R4, R4-self-signed, R7-no-cert, R7-unregistered, R7-reporter, R7-traversal, R7-unknown, R8-no-cert, R8-unregistered, R8-reporter, R8-wrong-pin, R8-not-allowlisted, R9-get-model-parameters, R9-submit-update, R9-update-status | ST2, ST7 |
| GAP-NO-PER-INSTALLATION-AUTHZ | kept (telemetry) | Model retrieval admits only registered installations (met). Telemetry accepts the one shared reporter credential, which avoids linkable reports and is revocable only as a whole (kept). | R7-no-cert, R7-unregistered, R7-reporter, R7-traversal, R7-unknown, X8, X8b, R10-no-cert, R10-installation, R10-unregistered, R10-summary-no-cert, R10-summary-installation, R10-summary-unregistered, R10-summary-reporter, R10-summary-public, R10-reporter, R10-summary-service, R10-no-identity-in-log | none |
| GAP-NO-REVOCATION | met | A revoked installation's new handshake fails after an atomic CRL swap, a corrupt CRL keeps the old configuration, and a deny-list entry takes effect on an open connection, all without a restart. | X13-baseline-x13-revoked, X13-baseline-x13-denied, X13-baseline-x13-bystander, X13-open-connection-baseline, X13-revoked, X13-bystander, X13-corrupt-crl-keeps-revocation, X13-corrupt-crl-keeps-serving, X13-denylist-open-connection, X13-denylist-new-connection, X13-bystander-after-denylist, X13-no-restart | none |
| GAP-LOOPBACK-PLAINTEXT-POLICY | kept | Plaintext is refused on every Compose-network listener (closed). Workstation loopback traffic between the supervisor, the worker and the bridge stays plaintext because it never leaves the host (kept; row X16). | R6-model-main-public, R6-model-main-internal, R6-telemetry-public, R6-telemetry-internal, R6-model-public, R6-model-internal, R6-checkpoint | ST1 |
| UPDSEC-20261116 | cited | The Go-era record: guarded-update and authentication rows against the Python services. This record repeats its authentication classes against the Rust stack. | none | none |
| UPDSEC-20261117 | cited | The Rust-stack record. Its nine V3 rows that were not_run without the standard packages (T7, T9, T10, R8-wrong-pin, R8-not-allowlisted, I3, X1, X1b, X1c) are run here. | none | none |
<!-- END GENERATED TABLES -->
