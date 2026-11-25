# Rust server stack: authentication, revocation and guarded-update security rows (UPDSEC-20261117)

Evidence unit for goals G2 and G3 of the [Rust server plan](../../docs/plans/rust-server-rewrite.md) (stage 9). It is the successor of [UPDSEC-20261116](update-security-20261116.md) for the Rust build and does not replace or edit it: that record keeps describing the Python and Go build behind the reverse proxy. Data: [update-security-20261117.json](update-security-20261117.json), produced by the CI job `container-smoke` of [Service stack CI](../../.github/workflows/service-stack-ci.yml), run 44022854928, commit `f1172143310cea34f968357149da0858425cba6b`, and copied here unchanged from the run's `update-security-rust-44022854928-1` artifact.

This is a **negative-test and mechanism-observation** record on synthetic inputs, a disposable OpenSSL PKI and the tracked legacy model. It is not a penetration test, a proof of security, or a measurement of model quality. The paper text is not changed by it; the sentences it would affect are listed under [Paper follow-ups](#paper-follow-ups).

## Goal

Run the negative rows of UPDSEC-20261116 again, and the new rows of the plan, against the Rust services as built by their Dockerfiles, and decide for each of the eight gaps of UPDSEC-20261116 whether it is met, kept, or kept for telemetry only, with at least one row that ran as evidence.

## Mechanism map (the Rust build)

| Gap closed by | Mechanism | Where |
| --- | --- | --- |
| In-service authentication | Each Rust server terminates mutual TLS itself (`rustls`), verifies the client against a client CA and a CRL, and maps the certificate URN to a role through a registry. A server exits before binding without `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`. | `rust/crates/privoke-transport`; the five flags are in every service command of `docker-compose.prod.yml` |
| Identity binding | `source_id` and `consumer_id` come from the certificate; a mismatching field is `PERMISSION_DENIED`. | `rust/services/param-update`, `rust/services/model-streaming` |
| Revocation | CRL and registry files are polled and swapped atomically; a corrupt file keeps the previous configuration; the registry deny list wins on an open connection. | `privoke-transport` hot reload |
| Cumulative bound | A per-update L2 bound and a rolling cumulative L2 budget on top of the per-coordinate bound. | `rust/services/param-update` |
| Public surface | `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset` on the model listener and `RecordTelemetry` on the telemetry listener; every private RPC answers `UNIMPLEMENTED` there. | model and telemetry servers |

The reverse proxy no longer exists, so the old static rows ST1 to ST10 (which read the Python and Go sources and the proxy configuration) are replaced by rows ST1 to ST7 over the Rust Compose files and Dockerfiles. UPDSEC-20261116 stays reproducible at the tag `rust-reference-20261117`; its static checks read their files from that tag.

## Method

1. CI builds `privoke-pki` and generates a disposable PKI for the Compose stack (`deploy/gce/tests/make_test_pki.py`). The images are built from the Dockerfiles, and `docker-compose.prod.yml --profile legacy-training` is brought up on loopback with `--wait`. `deploy/gce/tests/smoke.py --images` runs against it (35 checks, all passed in this run).
2. `evaluation/update_security.py --target rust --rust-service all --no-v3` then hosts, with `docker run`, a fresh container of each Rust server (model streaming, parameter update, telemetry) with its own disposable OpenSSL PKI, and drives every row from the host runner with Python gRPC clients. No test case runs inside a container.
3. For the model and update rows the active store is compared before and after each row; for telemetry the exact stored sample count is. `model_unchanged` means identical.
4. The X13 rows run on a model-streaming container with a one-second reload poll: the CA revokes an installation and a new CRL is swapped in atomically, then the CRL file is replaced by garbage, then an installation is added to the registry deny list while its connection is open. The container is never restarted.
5. The start-up rows run each cloud image without `--client-ca` and then without `--crl` and require a non-zero exit.
6. The static rows render the Compose files with `docker compose config --no-interpolate --format json` and read the Dockerfiles and sources.
7. Property rule per row: a rejected attack meets its property only with an allowed status code and an unchanged store; a positive control must be accepted; a gap keeps its claimed status only if a row linked to it ran and no linked row is unmet.

## Results

89 of 98 rows ran; none had its property unmet, none of the required row families is missing, and all eight gaps are verified. Rows by service: model streaming 56 (including the live revocation rows), parameter update 20, telemetry 13, start-up 8.

<!-- BEGIN GENERATED TABLES -->
Rows: 98; not run: 9; rows whose security property was not met: 0 (none). Missing row families: none.

### Goal checks

| Goal | Check | Result |
| --- | --- | --- |
| G2 | Rows A1, A3, T1, T3, T8, T12, T14 and R7 are rejected with the model unchanged | yes |
| G2 | Static rows ST1, ST2, ST3, ST5 and ST6 hold | yes |
| G2 | Every cloud image started without `--client-ca` or without `--crl` exits non-zero (8 rows) | yes |
| G3 | All 8 gaps are verified by at least one row that ran | yes |

### Gap closure (G3)

| Gap | Status | Reason | Rows that ran | Static rows |
| --- | --- | --- | --- | --- |
| GAP-NO-PUBLISHER-AUTH | met | The update service serves only on the internal listener, requires mutual TLS and the publisher role for SubmitParameterUpdate, and exits without a client CA or CRL. | A1, T14, R1, R1-trainer, R1-unregistered, S-startup-model-streaming-service-no-client-ca, S-startup-model-streaming-service-no-crl, S-startup-param-update-service-no-client-ca, S-startup-param-update-service-no-crl, S-startup-telemetry-service-no-client-ca, S-startup-telemetry-service-no-crl, S-startup-analysis-service-no-client-ca, S-startup-analysis-service-no-crl | ST1, ST3 |
| GAP-IDENTITY-SELF-ASSERTED | kept (telemetry) | source_id and consumer_id come from the certificate for update and model retrieval (met). Telemetry reports carry no identity field and the shared reporter credential is deliberately not individual, so nothing is bound there (kept). | T2, A2, R2, R10-no-identity-in-log | none |
| GAP-NO-CREDENTIAL-MECHANISM | met | Client certificates are checked by the service itself: a bearer token is ignored, and expired, not-yet-valid, wrong-usage and foreign-CA certificates are refused at the handshake. | R3-expired, R3-not-yet-valid, R3-no-client-auth-eku, R3-server-auth-only, A3 | none |
| GAP-NO-RETRIEVAL-AUTH | met | Every model RPC except Health needs the consumer role; the private RPCs answer UNIMPLEMENTED on the public listener. GetModelPackage and StreamModelAsset are public by design (G8). | T1, T3, T8, T12, R4, R7-no-cert, R7-unregistered, R7-reporter, R7-traversal, R7-unknown, R8-no-cert, R8-unregistered, R8-reporter, R9-get-model-parameters, R9-submit-update, R9-update-status | ST2, ST7 |
| GAP-NO-PER-INSTALLATION-AUTHZ | kept (telemetry) | Model retrieval admits only registered installations (met). Telemetry accepts the one shared reporter credential, which avoids linkable reports and is revocable only as a whole (kept). | R7-no-cert, R7-unregistered, R7-reporter, R7-traversal, R7-unknown, X8, X8b, R10-no-cert, R10-installation, R10-unregistered, R10-summary-no-cert, R10-summary-installation, R10-summary-unregistered, R10-summary-reporter, R10-summary-public, R10-reporter, R10-summary-service, R10-no-identity-in-log | none |
| GAP-NO-REVOCATION | met | A revoked installation's new handshake fails after an atomic CRL swap, a corrupt CRL keeps the old configuration, and a deny-list entry takes effect on an open connection, all without a restart. | X13-baseline-x13-revoked, X13-baseline-x13-denied, X13-baseline-x13-bystander, X13-open-connection-baseline, X13-revoked, X13-bystander, X13-corrupt-crl-keeps-revocation, X13-corrupt-crl-keeps-serving, X13-denylist-open-connection, X13-denylist-new-connection, X13-bystander-after-denylist, X13-no-restart | none |
| GAP-NO-CUMULATIVE-BOUND | met | A per-update L2 bound and a rolling cumulative L2 budget refuse drift that the per-coordinate bound allowed. | E7, E6, R5-replay, R5-conflict, R5 | none |
| GAP-LOOPBACK-PLAINTEXT-POLICY | kept | Plaintext is refused on every Compose-network listener (closed). Workstation loopback traffic between the supervisor, the worker and the bridge stays plaintext because it never leaves the host (kept; row X16). | R6-model-main-public, R6-model-main-internal, R6-update, R6-telemetry-public, R6-telemetry-internal, R6-model-public, R6-model-internal | ST1 |

### Rows

| ID | Service | Path | Row | Observed | Code | Store unchanged | Property met | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| X1 | model-streaming | rust-public | Registered installation certificate from the client CA (positive control): fetch the default V3 manifest. | not_run | NOT_RUN | n/a | n/a | GAP-NO-RETRIEVAL-AUTH |
| X1d | model-streaming | rust-public | Registered installation streams the legacy catalogue model over mutual TLS (positive control that needs no V3 package). | accepted | OK | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| X1b | model-streaming | rust-public | Registered installation streams config.json of the default V3 package and verifies its pin (G8 positive control). | not_run | NOT_RUN | n/a | n/a | GAP-NO-RETRIEVAL-AUTH |
| X1c | model-streaming | rust-public | Registered installation streams the whole model.safetensors of the default V3 package over mutual TLS and verifies its pin. | not_run | NOT_RUN | n/a | n/a | GAP-NO-RETRIEVAL-AUTH |
| T1 | model-streaming | rust-public | Model download by an unauthenticated consumer with an arbitrary consumer_id. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| T2 | model-streaming | rust-public | Model download by a registered installation claiming the installed runtime's consumer_id. | rejected | PERMISSION_DENIED | yes | yes | GAP-IDENTITY-SELF-ASSERTED |
| T3 | model-streaming | rust-public | Model download with no consumer_id and no client certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| T4 | model-streaming | rust-public | Model download with a control character in consumer_id (registered installation). | rejected | PERMISSION_DENIED | yes | yes |  |
| T5 | model-streaming | rust-public | Download of a model id that is not in the catalogue (registered installation). | rejected | NOT_FOUND | yes | yes |  |
| T6 | model-streaming | rust-public | Download with a path-traversal model id (registered installation). | rejected | NOT_FOUND | yes | yes |  |
| T7 | model-streaming | standard-v3 | Legacy float-tensor download of the standard V3 model (registered installation). | not_run | NOT_RUN | n/a | n/a |  |
| T8 | model-streaming | standard-v3 | Standard V3 package manifest requested by an unauthenticated consumer. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| T9 | model-streaming | standard-v3 | Asset stream with a wrong manifest pin (registered installation). | not_run | NOT_RUN | n/a | n/a |  |
| T10 | model-streaming | standard-v3 | Asset stream for a non-allowlisted asset name (path traversal). | not_run | NOT_RUN | n/a | n/a |  |
| T11 | model-streaming | standard-v3 | Asset stream for a legacy model id (registered installation). | rejected | INVALID_ARGUMENT | yes | yes |  |
| T12 | model-streaming | standard-v3 | Asset stream with correct pin and name by an unauthenticated consumer. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| R3-expired | model-streaming | rust-public | An expired client certificate, for a registered identity, is refused at the TLS handshake. | rejected | UNAVAILABLE | yes | yes | GAP-NO-CREDENTIAL-MECHANISM |
| R3-not-yet-valid | model-streaming | rust-public | A not-yet-valid client certificate, for a registered identity, is refused at the TLS handshake. | rejected | UNAVAILABLE | yes | yes | GAP-NO-CREDENTIAL-MECHANISM |
| R3-no-client-auth-eku | model-streaming | rust-public | A client certificate with no extended key usage, for a registered identity, is refused at the TLS handshake. | rejected | UNAVAILABLE | yes | yes | GAP-NO-CREDENTIAL-MECHANISM |
| R3-server-auth-only | model-streaming | rust-public | A client certificate whose only usage is serverAuth, for a registered identity, is refused at the TLS handshake. | rejected | UNAVAILABLE | yes | yes | GAP-NO-CREDENTIAL-MECHANISM |
| R4 | model-streaming | rust-public | A certificate from a foreign CA carrying a registered installation's subject is refused at the handshake. | rejected | UNAVAILABLE | yes | yes | GAP-IDENTITY-SELF-ASSERTED |
| R7-no-cert | model-streaming | rust-public | GetModelPackage without a client certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| R7-unregistered | model-streaming | rust-public | GetModelPackage by a valid, unregistered installation certificate. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R7-reporter | model-streaming | rust-public | GetModelPackage with the telemetry reporter credential. | rejected | PERMISSION_DENIED | yes | yes |  |
| R7-traversal | model-streaming | rust-public | GetModelPackage with a path-traversal model id (registered installation). | rejected | NOT_FOUND | yes | yes |  |
| R7-unknown | model-streaming | rust-public | GetModelPackage for a model that is not in the catalogue (registered installation). | rejected | NOT_FOUND | yes | yes |  |
| R8-no-cert | model-streaming | standard-v3 | StreamModelAsset without a client certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-RETRIEVAL-AUTH |
| R8-unregistered | model-streaming | standard-v3 | StreamModelAsset by a valid, unregistered installation certificate. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R8-reporter | model-streaming | standard-v3 | StreamModelAsset with the telemetry reporter credential. | rejected | PERMISSION_DENIED | yes | yes |  |
| R8-wrong-pin | model-streaming | standard-v3 | StreamModelAsset with a wrong pin (registered installation). | not_run | NOT_RUN | n/a | n/a |  |
| R8-not-allowlisted | model-streaming | standard-v3 | StreamModelAsset for a non-allowlisted asset name (registered installation). | not_run | NOT_RUN | n/a | n/a |  |
| R9-get-model-parameters | model-streaming | rust-public | GetModelParameters on the public listener (registered installation). | rejected | UNIMPLEMENTED | yes | yes |  |
| R9-submit-update | model-streaming | rust-public | ParamUpdateService.SubmitParameterUpdate on the public listener (registered installation). | rejected | UNIMPLEMENTED | yes | yes |  |
| R9-update-status | model-streaming | rust-public | ParamUpdateService.GetParameterUpdateStatus on the public listener (registered installation). | rejected | UNIMPLEMENTED | yes | yes |  |
| X8 | model-streaming | rust-public | A second, distinct installation certificate from the same client CA whose id is not registered. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| X8b | model-streaming | rust-public | A second installation certificate from the same client CA whose id is registered (positive control). | accepted | OK | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| I1 | model-streaming | rust-internal | A registered service identity downloads a legacy model on the internal listener (positive control). | accepted | OK | yes | yes |  |
| I2 | model-streaming | rust-internal | A registered installation (consumer role) on the internal listener. | rejected | PERMISSION_DENIED | yes | yes |  |
| I3 | model-streaming | rust-internal | A registered service identity asks the internal listener for the V3 model through the legacy float RPC. | not_run | NOT_RUN | n/a | n/a |  |
| I4 | model-streaming | rust-internal | A registered service identity calls a consumer RPC on the internal listener. | rejected | UNIMPLEMENTED | yes | yes |  |
| R6-model-main-public | model-streaming | rust-public | A plaintext call to the public model-streaming port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| R6-model-main-internal | model-streaming | rust-public | A plaintext call to the internal model-streaming port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| C1 | param-update | rust-update | A registered publisher submits a small update naming itself (positive control). | accepted | OK | no | yes |  |
| A1 | param-update | rust-update | Valid update from a peer with no client certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-PUBLISHER-AUTH |
| A2 | param-update | rust-update | Update from a peer with no certificate that claims the trainer's source_id. | rejected | UNAVAILABLE | yes | yes | GAP-IDENTITY-SELF-ASSERTED |
| A3 | param-update | rust-update | Update presenting an invalid bearer token and API key in gRPC metadata and no certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-CREDENTIAL-MECHANISM |
| T14 | param-update | rust-update | Unauthenticated update-receipt status lookup. | rejected | UNAVAILABLE | yes | yes | GAP-NO-PUBLISHER-AUTH |
| R1 | param-update | rust-update | A valid consumer installation certificate submits an update. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PUBLISHER-AUTH |
| R1-trainer | param-update | rust-update | A registered trainer service submits an update. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PUBLISHER-AUTH |
| R1-unregistered | param-update | rust-update | A service certificate signed by the client CA but not registered submits an update. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R2 | param-update | rust-update | A registered publisher (test-trainer) claims source_id=server-fuzzer. | rejected | PERMISSION_DENIED | yes | yes | GAP-IDENTITY-SELF-ASSERTED |
| R6-update | param-update | rust-update | A plaintext (non-TLS) call to the update service port, as a peer on the Compose network could make. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| E1 | param-update | rust-update | One coordinate at 1.0000001 (just above the 1.0 per-coordinate bound). | rejected | INVALID_ARGUMENT | yes | yes |  |
| E2 | param-update | rust-update | Coordinate magnitude 100. | rejected | INVALID_ARGUMENT | yes | yes |  |
| E3 | param-update | rust-update | Coordinate magnitude 3.4e38 (largest finite float32). | rejected | INVALID_ARGUMENT | yes | yes |  |
| E4 | param-update | rust-update | Negative coordinate -2.0. | rejected | INVALID_ARGUMENT | yes | yes |  |
| E5 | param-update | rust-update | Update with every coordinate exactly at the 1.0 bound (boundary value, norm 2.0; positive control). | accepted | OK | no | yes |  |
| E7 | param-update | rust-update | Single update moving every trainable coordinate (41876 values, L2 norm 204.6) by the 1.0 bound. | rejected | INVALID_ARGUMENT | yes | yes | GAP-NO-CUMULATIVE-BOUND |
| E6 | param-update | rust-update | Twenty-five successive valid updates (norm 2.0 each) against a cumulative budget of 40. | rejected | FAILED_PRECONDITION | yes | yes | GAP-NO-CUMULATIVE-BOUND |
| R5-replay | param-update | rust-update | After the budget is exhausted, an exact replay of an accepted request is answered from its receipt and changes nothing. | idempotent_noop | OK | yes | yes | GAP-NO-CUMULATIVE-BOUND |
| R5-conflict | param-update | rust-update | After the budget is exhausted, a request id reused with a different payload is refused and changes nothing. | rejected | INVALID_ARGUMENT | yes | yes | GAP-NO-CUMULATIVE-BOUND |
| R5 | param-update | rust-update | Updates of norm 1.0 (each far under the per-update bound) are refused once their sum passes the budget of 8. | rejected | FAILED_PRECONDITION | yes | yes | GAP-NO-CUMULATIVE-BOUND |
| R10-no-cert | telemetry | rust-telemetry | RecordTelemetry on the public listener without a client certificate. | rejected | UNAVAILABLE | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R10-installation | telemetry | rust-telemetry | RecordTelemetry on the public listener with a registered installation certificate (not the reporter credential). | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R10-unregistered | telemetry | rust-telemetry | RecordTelemetry on the public listener with a valid but unregistered installation certificate. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R10-summary-no-cert | telemetry | rust-telemetry | GetTelemetrySummary on the internal listener without a client certificate. | rejected | UNAVAILABLE | yes | yes |  |
| R10-summary-installation | telemetry | rust-telemetry | GetTelemetrySummary on the internal listener with a registered installation certificate. | rejected | PERMISSION_DENIED | yes | yes |  |
| R10-summary-unregistered | telemetry | rust-telemetry | GetTelemetrySummary on the internal listener with an unregistered installation certificate. | rejected | PERMISSION_DENIED | yes | yes |  |
| R10-summary-reporter | telemetry | rust-telemetry | GetTelemetrySummary on the internal listener with the shared reporter credential. | rejected | PERMISSION_DENIED | yes | yes |  |
| R10-summary-public | telemetry | rust-telemetry | GetTelemetrySummary on the public listener with the reporter credential. | rejected | UNIMPLEMENTED | yes | yes |  |
| R10-reporter | telemetry | rust-telemetry | The shared reporter credential records a randomised report (positive control). | accepted | OK | no | yes | GAP-NO-PER-INSTALLATION-AUTHZ |
| R10-summary-service | telemetry | rust-telemetry | A registered service identity reads the aggregate summary on the internal listener (positive control). | accepted | OK | yes | yes |  |
| R6-telemetry-public | telemetry | rust-telemetry | A plaintext call to the public telemetry port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| R6-telemetry-internal | telemetry | rust-telemetry | A plaintext call to the internal telemetry port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| R10-no-identity-in-log | telemetry | rust-telemetry | After refused and accepted requests from named identities, the container log holds none of their installation ids. | rejected | OK | n/a | yes | GAP-IDENTITY-SELF-ASSERTED |
| X13-baseline-x13-revoked | model-streaming | rust-public | A registered installation (x13-revoked) is served before any revocation (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-baseline-x13-denied | model-streaming | rust-public | A registered installation (x13-denied) is served before any revocation (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-baseline-x13-bystander | model-streaming | rust-public | A registered installation (x13-bystander) is served before any revocation (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-open-connection-baseline | model-streaming | rust-public | The installation that will be deny-listed has an open, working connection (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-revoked | model-streaming | rust-public | A revoked installation's new handshake fails after the CRL is swapped, without a restart. | rejected | UNAVAILABLE | yes | yes | GAP-NO-REVOCATION |
| X13-bystander | model-streaming | rust-public | An installation that was not revoked is still served after the CRL swap (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-corrupt-crl-keeps-revocation | model-streaming | rust-public | After the CRL file is replaced by garbage, the revoked installation is still refused (the old configuration is kept). | rejected | UNAVAILABLE | yes | yes | GAP-NO-REVOCATION |
| X13-corrupt-crl-keeps-serving | model-streaming | rust-public | After the CRL file is replaced by garbage, the service keeps serving a valid installation (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-denylist-open-connection | model-streaming | rust-public | A deny-listed identity gets PERMISSION_DENIED on a connection that was already open. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-REVOCATION |
| X13-denylist-new-connection | model-streaming | rust-public | The same deny-listed identity is also refused on a new connection. | rejected | PERMISSION_DENIED | yes | yes | GAP-NO-REVOCATION |
| X13-bystander-after-denylist | model-streaming | rust-public | A registered installation that is not deny-listed is still served (positive control). | accepted | OK | yes | yes | GAP-NO-REVOCATION |
| X13-no-restart | model-streaming | rust-public | None of the changes above needed a restart: the service process is the one that started the run. | rejected | OK | n/a | yes | GAP-NO-REVOCATION |
| R6-model-public | model-streaming | rust-public | A plaintext call to the public model-streaming port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| R6-model-internal | model-streaming | rust-public | A plaintext call to the internal model-streaming port. | rejected | UNAVAILABLE | yes | yes | GAP-LOOPBACK-PLAINTEXT-POLICY |
| S-startup-model-streaming-service-no-client-ca | startup | container-startup | model-streaming-service started without --client-ca must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-model-streaming-service-no-crl | startup | container-startup | model-streaming-service started without --crl must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-param-update-service-no-client-ca | startup | container-startup | param-update-service started without --client-ca must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-param-update-service-no-crl | startup | container-startup | param-update-service started without --crl must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-telemetry-service-no-client-ca | startup | container-startup | telemetry-service started without --client-ca must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-telemetry-service-no-crl | startup | container-startup | telemetry-service started without --crl must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-analysis-service-no-client-ca | startup | container-startup | analysis-service started without --client-ca must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| S-startup-analysis-service-no-crl | startup | container-startup | analysis-service started without --crl must exit non-zero before serving. | rejected | exit 1 | n/a | yes | GAP-NO-PUBLISHER-AUTH |
| X16 | client | workstation-loopback | Workstation loopback (supervisor to worker, bridge to supervisor) stays plaintext by design; internal Compose mode refuses it. | not_applicable | n/a | n/a | n/a | GAP-LOOPBACK-PLAINTEXT-POLICY |

### Static rows

| ID | Claim | Holds | Detail |
| --- | --- | --- | --- |
| ST1 | Every Rust server in the production and deployment Compose files starts with the five TLS flags (--cert, --key, --client-ca, --crl, --registry), passes no plaintext or insecure flag and sets no plaintext opt-out variable. | yes | every rendered service satisfies it |
| ST2 | The only published ports are the two public listeners, 50443 and 58443, on loopback unless the operator overrides them. | yes | every rendered service satisfies it |
| ST3 | No internal listener (50051, 50052, 50053, 50054, 50055) is published, and the quarantined analysis services publish nothing. | yes | every rendered service satisfies it |
| ST4 | No reverse proxy is referenced in any deployment path (G1). | yes | every rendered service satisfies it |
| ST5 | Every deployed container has a read-only root, drops all capabilities, sets no-new-privileges and keeps Docker's default seccomp profile. | yes | every rendered service satisfies it |
| ST6 | The cloud images are built with no cargo feature, so the workstation-loopback listener is never compiled in. | yes | every rendered service satisfies it |
| ST7 | The model and telemetry servers still name their private RPCs, so the public/internal split that R9 and R10 exercise live is present in the source. | yes | every rendered service satisfies it |

### Rows not run

X1, X1b, X1c, T7, T9, T10, R8-wrong-pin, R8-not-allowlisted, I3. The standard V3 packages are ignored by Git and absent from CI. Rows that need them are recorded as not_run with the reason and are not evidence; G8 (package fetch and pin verification over mutual TLS) is not covered by this record.
<!-- END GENERATED TABLES -->

## Findings and defects

- No row showed an unexpected accept, and no rejected attack changed a store. The harness reported no unmet property on its first complete run.
- The reverse-proxy-era claim that cloud ingress routes three RPCs no longer holds by design: the public surface is the five RPCs above, and R7 to R9 show that every other RPC is refused or unimplemented there. This is the behaviour change G8 names.
- Two gaps remain partly open on purpose and are reported as such: identity is not individual for telemetry (the shared reporter credential), and workstation loopback traffic stays plaintext (row X16).

## Limitations

- **The standard V3 packages were not present.** They are ignored by Git and CI cannot fetch them, so the stack served the tracked legacy catalogue model and the nine rows that need a V3 package (X1, X1b, X1c, T7, T9, T10, R8-wrong-pin, R8-not-allowlisted, I3) were recorded as `not_run` with that reason. They are not evidence. In particular G8, fetching `privoke-v3-balanced` over mutual TLS and verifying its pin, is **not covered by this record**; the smoke test replaces it with a legacy stream, and a local run with `models/standard-releases` present (or the first real deployment) is needed for it. The unauthenticated V3 rows T8, T12 and R7 to R9 still ran, because they are refused before any package lookup.
- Each server is hosted by this harness in its own container with an OpenSSL PKI, not inside the Compose network. The Compose stack itself is exercised by the smoke test (mutual TLS, role gating, R9, telemetry, start-up refusal), not by these rows.
- The Python fuzzer and the quarantined analysis service are not driven by these rows. Their plaintext refusal (R6, X16) is covered for the Python side by the stage 6 component tests (`run-component-tests.py shared`), which run in the CI job `supervisor-tests`.
- One run on one runner image and one commit, synthetic inputs, a model state that is the tracked legacy artifact. Certificates last one hour, the CAs two days.
- The telemetry rows check the sample count and the container log, not the stored database contents.

## Paper follow-ups

Not applied here (paper text needs its own `REWRITE_SCOPE` authorisation). The paper would need to change where it says that update-path authentication is pending, that the cumulative change is unbounded, that identities are self-asserted, that there is no revocation, and that cloud ingress routes three RPCs; the threats table row "Client certificates on streaming and telemetry routes"; and the guarded-update text. The claims it could make instead are the met rows above, with the telemetry and loopback exceptions and the missing G8 evidence stated.

## Reproduce

```bash
export PRIVOKE_PKI_DIR=$RUNNER_TEMP/pki     # see .github/workflows/service-stack-ci.yml, job container-smoke
python deploy/gce/tests/make_test_pki.py --tool rust/target/release/privoke-pki --out "$PRIVOKE_PKI_DIR" --creds "$RUNNER_TEMP/creds" --work "$RUNNER_TEMP/pki-work"
docker compose -f docker-compose.prod.yml --profile legacy-training build && docker compose -f docker-compose.prod.yml --profile legacy-training up -d --wait
python evaluation/update_security.py --target rust --rust-service all --no-v3 --rust-image <model image> --rust-update-image <update image> \
    --rust-telemetry-image <telemetry image> --rust-analysis-image <analysis image> --output record.json
python evaluation/update_security_report.py --record record.json --document update-security-20261117.md
```

CI is the only environment this record was produced in.
