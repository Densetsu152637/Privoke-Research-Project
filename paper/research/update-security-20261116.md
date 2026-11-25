# Guarded-update and authentication security tests (UPDSEC-20261116)

Evidence unit for goals G7 (guarded-update attacks) and G8 (authentication negative tests) of the [ASIACCS revision plan](../../docs/plans/asiaccs-2027-revision.md), authorised by the 16 November 2026 entry of [REWRITE_SCOPE](../REWRITE_SCOPE.md). Data: [update-security-20261116.json](update-security-20261116.json). Harness: `evaluation/update_security.py` (helpers `update_security_pki.py`, `update_security_report.py`); tests: `evaluation/tests/test_update_security.py`. Experiment note: [docs/experiments/update-security-20261116.md](../../docs/experiments/update-security-20261116.md).

This is a **negative-test and mechanism-observation** record on synthetic inputs and a synthetic model state. It is not a penetration test, a proof of security, or a measurement of model quality.

## Goal

Observe, for each attack class the supervisor named, what the actual PriVoke services do, and whether the active model stayed byte-for-byte unchanged afterwards. Record every missing mechanism as an unmet property with code evidence, and still run the attack to show the actual outcome.

## Mechanism map (from code at the tested revision)

| Path | What it is | Update RPC? | Where |
| --- | --- | --- | --- |
| `legacy-update` | Mutable JSON Tiny artifact (`privoke-balanced`). Gradient updates are applied by `ParamUpdateService.SubmitParameterUpdate` as compare-and-swap on `base_version`, with an atomic temp-file rename and a durable receipt per `request_id`. | Yes, the only one | `services/param-update-service/app/{server,validation,receipts}.py`, `shared/python/privoke_model/artifact.py` |
| `standard-v3` | Immutable, hash-pinned binary packages (`privoke-v3-balanced` and siblings), served read-only by `GetModelPackage` and `StreamModelAsset`. | No. Legacy gradient requests reject V3. | `services/model-streaming-service/cmd/server/standard_v3.go`; `docs/services/model-streaming.md` |
| `transport-standin` | A grpcio mutual-TLS terminator, standing in for the nginx ingress for certificate-class tests (see limitations). | n/a | `evaluation/update_security_pki.py` |
| `static` | Source or configuration check; no behaviour was run. | n/a | rows ST1 to ST10 below |

The guarded-update mechanism in the paper is therefore the `legacy-update` path. For the standard V3 path the security property is "no update path exists and the release store cannot be written by any RPC"; rows A4, A5 and T7 to T12 exercise it, and the release store fingerprint was unchanged over the whole run.

Transport and identity as built: both services open plaintext gRPC ports and contain no credential, token, expiry or peer-identity check (ST1 to ST3). In the cloud shape, nginx terminates TLS, requires a client certificate and routes only three RPC methods (ST4 to ST6). The production compose file exposes the update service only on the internal network (ST8).

## Method

1. Host `param-update-service/app/server.py` as a host process on 127.0.0.1 over a private copy of the tracked `models/privoke-balanced.json`, first prepared by the deployment's own `app/bootstrap.py`. The only deviation from `serve()` is that the listener binds `127.0.0.1` instead of `[::]`; the rest is `create_server`.
2. Host the Go `model-streaming-service` (image built from this checkout) on a loopback port with `docker run`, mounting the same artifact directory and the prepared standard releases read-only. No test case runs inside a container.
3. Before and after every attack, snapshot the artifact (file SHA-256, version, training revision) and what the streaming service serves (version, tensor hash). `model_unchanged` means both were identical.
4. Attacks that need a specific model state reset it first (pristine prepared artifact, receipts cleared). The attacker learns `base_version` from the unauthenticated download, as a real peer could.
5. Property rule per row: a rejected attack meets its property only if the model was unchanged; replay and duplicate rows must apply at most once; rows for a missing mechanism are marked unmet and linked to a gap.

Every number in the tables below is rendered from the JSON by `evaluation/update_security_report.py`, and a test compares the rendered text with this file.

## Results

### Guarded update (G7)

- **Stale** (S1 to S3): three of three rejected with `FAILED_PRECONDITION`, model unchanged.
- **Replayed** (R1 to R4): a byte-identical replay of a committed request returns the original version with no second application; the same payload without `request_id` is rejected as stale; reuse of a `request_id` with a different payload is rejected; the same payload under another `source_id` is rejected as stale.
- **Duplicate** (D1, D2): eight concurrent identical submissions applied once, with and without `request_id`.
- **Malformed tensors** (M1 to M23): all 23 rejected, including empty values, mismatched or zero shape, duplicate and unknown and frozen names, control characters, count and size limits, 1.2 MB message, bad metadata, and three raw-wire malformations. Raw-wire decode failures return `INTERNAL` from the gRPC layer ("Exception deserializing request"), not `INVALID_ARGUMENT`; the model was unchanged in each case.
- **NaN and Inf** (N1 to N7): all seven rejected (NaN, both Infs, all-NaN, signalling NaN, NaN inside a large tensor, 1e39 overflow).
- **Wrong shape** (W1 to W5): all five rejected, including a same-size transposed shape and a two-tensor update where only the second tensor is wrong (nothing applied).
- **Excessive change** (E1 to E7): values above the 1.0 per-coordinate bound are rejected (E1 to E4). A value exactly at the bound is accepted (E5). The bound is per coordinate only: 25 successive maximum-magnitude updates were all accepted (cumulative per-coordinate drift 26, including E5), and one update moving 41,876 coordinates by 1.0 (L2 norm 204.6) was accepted (E6, E7). This is **GAP-NO-CUMULATIVE-BOUND**.
- **Interrupted** (I1 to I4): a 1 ms client deadline followed by a retry applied once; ten hard kills of the updater at ten delays left a valid artifact every time and a retry with the same `request_id` applied exactly once in 10 of 10 (one kill landed after commit, nine before); a stray half-written temp file did not block the next update; a truncated active artifact made the updater report `NOT_SERVING`, reject updates and made the streaming service answer `UNAVAILABLE` (fail closed). The recorded trials left no temp file; in two earlier, unrecorded development runs a kill during the write left `.privoke-balanced.json.*.tmp` files beside the artifact, and no startup code removes them.
- **Unauthorized publication** (A1, A2, A4, A5): A1 and A2 are **accepted**: any peer that can reach the port, with no credential and any `source_id`, publishes an update, and `last_update_source` in the artifact then records the forged source. A4 (update for the V3 model id) and A5 (update RPC sent to the streaming port) are rejected.

### Authentication and communication security (G8)

- **Invalid credentials** (A3, X13, X14): the services have no application credentials; a bogus bearer token and API key were ignored and the update accepted (**GAP-NO-CREDENTIAL-MECHANISM**). Certificate revocation is not configured (**GAP-NO-REVOCATION**, not exercised). The client factory refuses a non-loopback target without certificate and key.
- **Invalid certificates** (X2, X3, X7, X9, X11, X12): missing, self-signed and wrong-usage client certificates, an untrusted server, a server certificate whose name does not match, and a plaintext client were all refused, and the stand-in handler was never invoked.
- **Expired credentials** (X5, X6, X10): an expired client certificate, a not-yet-valid client certificate and an expired server certificate were refused. No application-level credential expiry exists.
- **Impersonation** (A2, T2, X4, X8): a foreign-CA certificate with the legitimate subject is refused, but identities inside the system are self-asserted: `source_id` and `consumer_id` are accepted as claimed, and a second valid installation certificate gets identical access (**GAP-IDENTITY-SELF-ASSERTED**, **GAP-NO-PER-INSTALLATION-AUTHZ**).
- **Replayed requests** (R1, R2, R4, T13): update replays are idempotent or stale-rejected as above; retrieval replays are read-only and returned identical tensors.
- **Unauthorized retrieval** (T1 to T12): unknown models, a path-traversal model id, the legacy RPC for a V3 model, a wrong manifest pin, a non-allowlisted asset name and a legacy asset request are rejected. Retrieval itself needs no credential at the service: an arbitrary or empty `consumer_id` is served the legacy model, the V3 manifest and an asset (**GAP-NO-RETRIEVAL-AUTH** at the service; the cloud ingress is the compensating control).
- **Unauthorized update** (A1, A3, A4, A5, T14): see above; the receipt-status lookup also answers unauthenticated peers.
- **Client policy** (X15, X16): with certificate files set and a non-loopback mutual-TLS endpoint, `grpc_channel` authenticates. For loopback targets it uses plaintext even when TLS files are configured (**GAP-LOOPBACK-PLAINTEXT-POLICY**, by design).

<!-- BEGIN GENERATED TABLES -->
Rows: 91. Rows whose security property was not met: 12 (E6, E7, A1, A2, A3, T1, T2, T3, T8, T12, T14, X8).

### G7 guarded-update attack classes

| Class | Rows | Rejected | Accepted | Idempotent / applied once | Not applicable | Property met | Property unmet |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| stale | 3 | 3 | 0 | 0 | 0 | 3 | 0 |
| replayed | 4 | 3 | 0 | 1 | 0 | 4 | 0 |
| duplicate | 2 | 0 | 0 | 2 | 0 | 2 | 0 |
| malformed_tensor | 23 | 23 | 0 | 0 | 0 | 23 | 0 |
| nan_inf | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| wrong_shape | 5 | 5 | 0 | 0 | 0 | 5 | 0 |
| excessive_change | 7 | 4 | 3 | 0 | 0 | 5 | 2 |
| interrupted | 4 | 1 | 1 | 2 | 0 | 4 | 0 |
| unauthorized_publication | 4 | 2 | 2 | 0 | 0 | 2 | 2 |

### G8 authentication test classes

| Class | Rows | Rejected | Accepted | Idempotent / applied once | Not applicable | Property met | Property unmet |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| invalid_credentials | 3 | 1 | 1 | 0 | 1 | 1 | 1 |
| invalid_certificate | 7 | 7 | 0 | 0 | 0 | 7 | 0 |
| expired_credentials | 3 | 3 | 0 | 0 | 0 | 3 | 0 |
| impersonation | 4 | 1 | 3 | 0 | 0 | 1 | 3 |
| replayed_request | 4 | 2 | 0 | 2 | 0 | 4 | 0 |
| unauthorized_retrieval | 10 | 6 | 4 | 0 | 0 | 6 | 4 |
| unauthorized_update | 5 | 2 | 3 | 0 | 0 | 2 | 3 |

### Attack by outcome

| ID | Class | Path | Attack | Observed | Code | Model unchanged | Property met | Gap |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C1 | control | legacy-update | Legitimate small update with a request_id (positive control). | accepted | OK | no | yes |  |
| S1 | stale | legacy-update | Fresh update (no request_id) built on the superseded base version after another update committed. | rejected | FAILED_PRECONDITION | yes | yes |  |
| S2 | stale | legacy-update | Update citing a fabricated future base version. | rejected | FAILED_PRECONDITION | yes | yes |  |
| S3 | stale | legacy-update | Update citing the pristine release version after training advanced (rollback-style base). | rejected | FAILED_PRECONDITION | yes | yes |  |
| R1 | replayed | legacy-update | Byte-identical replay of the committed request (same request_id) after later state changes. | idempotent_noop | OK | yes | yes |  |
| R2 | replayed | legacy-update | Replay of the same payload without a request_id after it was applied once. | rejected | FAILED_PRECONDITION | yes | yes |  |
| R3 | replayed | legacy-update | Reuse of a committed request_id with a different payload. | rejected | INVALID_ARGUMENT | yes | yes |  |
| R4 | replayed | legacy-update | Replay of the committed payload under a different source_id (new receipt key, stale base). | rejected | FAILED_PRECONDITION | yes | yes |  |
| D1 | duplicate | legacy-update | Eight concurrent identical submissions with one request_id. | applied_once | OK | no | yes |  |
| D2 | duplicate | legacy-update | Eight concurrent identical submissions without request_id (base-version compare-and-swap only). | applied_once | FAILED_PRECONDITION | no | yes |  |
| M1 | malformed_tensor | legacy-update | Gradient with an empty values array. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M2 | malformed_tensor | legacy-update | Value count does not match the declared shape (3 values for shape [4]). | rejected | INVALID_ARGUMENT | yes | yes |  |
| M3 | malformed_tensor | legacy-update | Shape with a zero dimension. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M4 | malformed_tensor | legacy-update | Gradient with no shape. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M5 | malformed_tensor | legacy-update | Duplicate gradient names in one update. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M6 | malformed_tensor | legacy-update | Unknown parameter name. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M8 | malformed_tensor | legacy-update | Empty gradient name. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M9 | malformed_tensor | legacy-update | Control character in the gradient name. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M10 | malformed_tensor | legacy-update | Gradient name longer than 256 characters. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M11 | malformed_tensor | legacy-update | Packed float field whose byte length is not a multiple of four (raw wire). | rejected | INTERNAL | yes | yes |  |
| M12 | malformed_tensor | legacy-update | Truncated protobuf message (raw wire). | rejected | INTERNAL | yes | yes |  |
| M13 | malformed_tensor | legacy-update | Random bytes as the request body (raw wire). | rejected | INTERNAL | yes | yes |  |
| M14 | malformed_tensor | legacy-update | 257 gradients (one more than the 256-gradient limit). | rejected | INVALID_ARGUMENT | yes | yes |  |
| M15 | malformed_tensor | legacy-update | One tensor with 24,577 values (above the largest per-tensor limit of 24,576). | rejected | INVALID_ARGUMENT | yes | yes |  |
| M16 | malformed_tensor | legacy-update | Three 24,576-value tensors (73,728 values, above the 65,536 total limit). | rejected | INVALID_ARGUMENT | yes | yes |  |
| M17 | malformed_tensor | legacy-update | Request body of about 1.2 MB (above the 1 MiB receive limit). | rejected | RESOURCE_EXHAUSTED | yes | yes |  |
| M18 | malformed_tensor | legacy-update | 65 metadata entries (above the 64-entry limit). | rejected | INVALID_ARGUMENT | yes | yes |  |
| M19 | malformed_tensor | legacy-update | Metadata value of 3,000 characters. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M20 | malformed_tensor | legacy-update | Non-integer generated_prompt_count metadata. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M21 | malformed_tensor | legacy-update | Missing base_version. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M22 | malformed_tensor | legacy-update | No gradients. | rejected | INVALID_ARGUMENT | yes | yes |  |
| M23 | malformed_tensor | legacy-update | Control character in source_id. | rejected | INVALID_ARGUMENT | yes | yes |  |
| N1 | nan_inf | legacy-update | NaN in one coordinate. | rejected | INVALID_ARGUMENT | yes | yes |  |
| N2 | nan_inf | legacy-update | +Inf in one coordinate. | rejected | INVALID_ARGUMENT | yes | yes |  |
| N3 | nan_inf | legacy-update | -Inf in one coordinate. | rejected | INVALID_ARGUMENT | yes | yes |  |
| N4 | nan_inf | legacy-update | All-NaN tensor. | rejected | INVALID_ARGUMENT | yes | yes |  |
| N5 | nan_inf | legacy-update | Signalling-NaN bit pattern (raw wire). | rejected | INVALID_ARGUMENT | yes | yes |  |
| N6 | nan_inf | legacy-update | NaN in a large tensor (head.category.weight). | rejected | INVALID_ARGUMENT | yes | yes |  |
| N7 | nan_inf | legacy-update | Value beyond float32 range sent as +1e39 (becomes Inf on the wire). | rejected | INVALID_ARGUMENT | yes | yes |  |
| W1 | wrong_shape | legacy-update | Shape [5] with 5 values for a [4] tensor (consistent but wrong). | rejected | INVALID_ARGUMENT | yes | yes |  |
| W2 | wrong_shape | legacy-update | Transposed shape [4,32] for the [32,4] weight (same value count). | rejected | INVALID_ARGUMENT | yes | yes |  |
| W3 | wrong_shape | legacy-update | Flattened shape [128] for the [32,4] weight. | rejected | INVALID_ARGUMENT | yes | yes |  |
| W4 | wrong_shape | legacy-update | Shape [2,2] for the [4] bias (same value count, wrong rank). | rejected | INVALID_ARGUMENT | yes | yes |  |
| W5 | wrong_shape | legacy-update | Right shape for one tensor, wrong shape for a second tensor in the same update (atomicity). | rejected | INVALID_ARGUMENT | yes | yes |  |
| E1 | excessive_change | legacy-update | One coordinate at 1.0000001 (just above the 1.0 per-coordinate bound). | rejected | INVALID_ARGUMENT | yes | yes |  |
| E2 | excessive_change | legacy-update | Coordinate magnitude 100. | rejected | INVALID_ARGUMENT | yes | yes |  |
| E3 | excessive_change | legacy-update | Coordinate magnitude 3.4e38 (largest finite float32). | rejected | INVALID_ARGUMENT | yes | yes |  |
| E4 | excessive_change | legacy-update | Negative coordinate -2.0. | rejected | INVALID_ARGUMENT | yes | yes |  |
| E5 | excessive_change | legacy-update | Update with every coordinate exactly at the 1.0 bound (boundary value). | accepted | OK | no | yes |  |
| E6 | excessive_change | legacy-update | Twenty-five successive valid updates each at the 1.0 per-coordinate bound (cumulative change, no rate limit). | accepted | OK | no | NO | GAP-NO-CUMULATIVE-BOUND |
| E7 | excessive_change | legacy-update | Single update moving every trainable coordinate (up to 65,536 values) by the 1.0 bound. | accepted | OK | no | NO | GAP-NO-CUMULATIVE-BOUND |
| M7 | malformed_tensor | legacy-update | Update to the frozen (non-trainable) tensor layers.0.attention.key.weight of the unprepared head-only artifact. | rejected | INVALID_ARGUMENT | yes | yes |  |
| I1 | interrupted | legacy-update | Client deadline of 1 ms then retry with the same request_id. | applied_once | DEADLINE_EXCEEDED | no | yes |  |
| I2 | interrupted | legacy-update | Hard-kill the updater process at ten delays during an in-flight update, restart, retry the same request_id. | applied_once | KILLED | no | yes |  |
| I3 | interrupted | legacy-update | A half-written temp file left beside the artifact by an earlier crash; next legitimate update. | accepted | OK | no | yes |  |
| I4 | interrupted | legacy-update | Truncate the active artifact to half its bytes (torn write by an external actor); updater and streaming must fail closed. | rejected | INVALID_ARGUMENT | yes | yes |  |
| A1 | unauthorized_publication | legacy-update | Valid update from a peer with no credential and an arbitrary source_id. | accepted | OK | no | NO | GAP-NO-PUBLISHER-AUTH |
| A2 | impersonation | legacy-update | Update that claims the legitimate trainer's source_id ('server-fuzzer'). | accepted | OK | no | NO | GAP-IDENTITY-SELF-ASSERTED |
| A3 | invalid_credentials | legacy-update | Update presenting an invalid bearer token and API key in gRPC metadata. | accepted | OK | no | NO | GAP-NO-CREDENTIAL-MECHANISM |
| A4 | unauthorized_publication | standard-v3 | Update addressed to the standard V3 model id on the update service. | rejected | INVALID_ARGUMENT | yes | yes |  |
| A5 | unauthorized_publication | standard-v3 | Update RPC sent to the model-streaming service port. | rejected | UNIMPLEMENTED | yes | yes |  |
| T1 | unauthorized_retrieval | legacy-update | Model download by an unauthenticated consumer with an arbitrary consumer_id. | accepted | OK | yes | NO | GAP-NO-RETRIEVAL-AUTH |
| T2 | impersonation | legacy-update | Model download claiming the installed runtime's consumer_id. | accepted | OK | yes | NO | GAP-IDENTITY-SELF-ASSERTED |
| T3 | unauthorized_retrieval | legacy-update | Model download with no consumer_id. | accepted | OK | yes | NO | GAP-NO-RETRIEVAL-AUTH |
| T4 | unauthorized_retrieval | legacy-update | Model download with a control character in consumer_id. | rejected | INVALID_ARGUMENT | yes | yes |  |
| T5 | unauthorized_retrieval | legacy-update | Download of a model id that is not in the catalogue. | rejected | NOT_FOUND | yes | yes |  |
| T6 | unauthorized_retrieval | legacy-update | Download with a path-traversal model id. | rejected | NOT_FOUND | yes | yes |  |
| T7 | unauthorized_retrieval | standard-v3 | Legacy float-tensor download of the standard V3 model. | rejected | FAILED_PRECONDITION | yes | yes |  |
| T8 | unauthorized_retrieval | standard-v3 | Standard V3 package manifest requested by an unauthenticated consumer. | accepted | OK | yes | NO | GAP-NO-RETRIEVAL-AUTH |
| T9 | unauthorized_retrieval | standard-v3 | Asset stream with a wrong manifest pin. | rejected | INVALID_ARGUMENT | yes | yes |  |
| T10 | unauthorized_retrieval | standard-v3 | Asset stream for a non-allowlisted asset name (path traversal). | rejected | INVALID_ARGUMENT | yes | yes |  |
| T11 | unauthorized_retrieval | standard-v3 | Asset stream for a legacy model id. | rejected | INVALID_ARGUMENT | yes | yes |  |
| T12 | unauthorized_retrieval | standard-v3 | Asset stream with correct pin and name by an unauthenticated consumer. | accepted | OK | yes | NO | GAP-NO-RETRIEVAL-AUTH |
| T13 | replayed_request | legacy-update | Replay of an identical retrieval request. | idempotent_noop | OK | yes | yes |  |
| T14 | unauthorized_update | legacy-update | Unauthenticated update-receipt status lookup. | accepted | OK | yes | NO | GAP-NO-PUBLISHER-AUTH |
| X1 | invalid_certificate | transport-standin | Valid CA-signed client certificate (positive control). | accepted | OK | yes | yes |  |
| X2 | invalid_certificate | transport-standin | TLS client presenting no certificate. | rejected | UNAVAILABLE | yes | yes |  |
| X3 | invalid_certificate | transport-standin | Self-signed client certificate. | rejected | UNAVAILABLE | yes | yes |  |
| X4 | impersonation | transport-standin | Client certificate with the legitimate subject name but signed by a foreign CA. | rejected | UNAVAILABLE | yes | yes |  |
| X5 | expired_credentials | transport-standin | Expired client certificate (validity ended five hours ago) signed by the trusted CA. | rejected | UNAVAILABLE | yes | yes |  |
| X6 | expired_credentials | transport-standin | Not-yet-valid client certificate signed by the trusted CA. | rejected | UNAVAILABLE | yes | yes |  |
| X7 | invalid_certificate | transport-standin | Client certificate carrying only the serverAuth key usage. | rejected | UNAVAILABLE | yes | yes |  |
| X8 | impersonation | transport-standin | A second, distinct installation certificate from the same client CA. | accepted | OK | yes | NO | GAP-NO-PER-INSTALLATION-AUTHZ |
| X9 | invalid_certificate | transport-standin | Client rejects a server certificate issued by an untrusted CA (server impersonation). | rejected | UNAVAILABLE | yes | yes |  |
| X10 | expired_credentials | transport-standin | Client rejects an expired server certificate. | rejected | UNAVAILABLE | yes | yes |  |
| X11 | invalid_certificate | transport-standin | Client rejects a server certificate whose SAN does not match the dialled address. | rejected | UNAVAILABLE | yes | yes |  |
| X12 | invalid_certificate | transport-standin | Plaintext (no TLS) client against the mutual-TLS endpoint. | rejected | UNAVAILABLE | yes | yes |  |
| X13 | invalid_credentials | static | Certificate revocation: revoke the client certificate of one installation. | not_applicable |  | n/a | n/a | GAP-NO-REVOCATION |
| X14 | invalid_credentials | transport-standin | grpc_channel to a non-loopback target with no certificate or key configured. | rejected | ValueError | yes | yes |  |
| X15 | invalid_credentials | transport-standin | grpc_channel with the installation certificate to a non-loopback mutual-TLS endpoint. | accepted | OK | yes | yes |  |
| X16 | invalid_credentials | transport-standin | grpc_channel to a loopback target with TLS files configured (client policy: loopback and internal mode are plaintext). | rejected | UNAVAILABLE | yes | n/a | GAP-LOOPBACK-PLAINTEXT-POLICY |

### Unmet properties (gaps)

| Gap | Property | Status | Compensating control |
| --- | --- | --- | --- |
| GAP-NO-PUBLISHER-AUTH | Only an authenticated, authorised publisher can change the active model | unmet at the service; met only by network placement | The update service is not routed by the cloud ingress and has no host port in the production compose file. |
| GAP-IDENTITY-SELF-ASSERTED | Update and consumer identities are authenticated, not caller-asserted | unmet | None in-service; mutual TLS at the ingress authenticates a certificate, not the source_id. |
| GAP-NO-CREDENTIAL-MECHANISM | Application credentials (tokens/keys) exist, are validated and expire | unmet (mechanism absent) | Certificate validity periods at the ingress only. |
| GAP-NO-RETRIEVAL-AUTH | Model retrieval is restricted to authorised consumers | unmet at the service; met at the cloud ingress by client certificates | Mutual TLS at nginx; models are non-secret released artifacts. |
| GAP-NO-PER-INSTALLATION-AUTHZ | Each installation is individually identified and can be individually revoked | unmet | Documented: all certificates from the client CA share the same access; rotate the CA to revoke. |
| GAP-NO-REVOCATION | A compromised client certificate can be revoked before expiry | unmet (no CRL configured) | Short certificate validity; client CA rotation. |
| GAP-NO-CUMULATIVE-BOUND | Aggregate model change is bounded per update and over time | unmet | Per-coordinate magnitude bound (default 1.0), message and value-count limits, and base-version compare-and-swap. |
| GAP-LOOPBACK-PLAINTEXT-POLICY | Configured TLS is applied to every client channel | by design for loopback and internal mode | Loopback/internal traffic does not leave the host or compose network. |

### Static evidence

| ID | Claim | Holds | Detail |
| --- | --- | --- | --- |
| ST1 | param-update-service listens on an insecure (plaintext, unauthenticated) gRPC port | yes | line 230: server.add_insecure_port(f"[::]:{config.port}") |
| ST2 | model-streaming-service builds its gRPC server without TLS credentials or interceptors | yes | grpc.NewServer options: MaxRecvMsgSize, MaxSendMsgSize, MaxConcurrentStreams only |
| ST3 | no credential, token, expiry or peer-identity check exists in either service's source | yes | 18 source files scanned; 0 matches |
| ST4 | cloud ingress requires and verifies a client certificate | yes | ssl_verify_client on; ssl_client_certificate /run/secrets/client-ca.crt |
| ST5 | cloud ingress routes only three RPC methods and denies the rest | yes | routed: ['/privoke.v1.ModelStreamingService/Health', '/privoke.v1.ModelStreamingService/StreamModelParameters', '/privoke.v1.TelemetryService/RecordTelemetry']; default: return 404 |
| ST6 | ParamUpdateService and the V3 package RPCs are not among the routed ingress methods | yes | routed: ['/privoke.v1.ModelStreamingService/Health', '/privoke.v1.ModelStreamingService/StreamModelParameters', '/privoke.v1.TelemetryService/RecordTelemetry'] |
| ST7 | no certificate revocation list is configured at the ingress | yes | no ssl_crl directive |
| ST8 | update service is published only on the internal compose network in the production stack (expose, no ports) | yes | param-update-service: expose 50052, no host port mapping |
| ST9 | client channel factory uses plaintext for loopback targets and internal mode regardless of configured TLS | yes | if loopback or env.get("PRIVOKE_STACK_MODE") == "internal":; return grpc.insecure_channel(target, options=options) |
| ST10 | the deployment smoke test asserts private RPCs are unreachable through the ingress and untrusted/missing client identity is refused | yes | asserted in CI against nginx; not executed in this run |
<!-- END GENERATED TABLES -->

## Existing tests reused as evidence

Run at the tested revision: `python evaluation/run-component-tests.py param-update` (from `services/param-update-service`) ran 37 tests, all OK; `go test ./...` for `services/model-streaming-service` passed. They cover the same properties at unit level: finite, shape, model and control-character rejection (`test_security_validation.py`), idempotent restart, conflicting reuse, concurrent commit, receipt-recovery crash windows (`test_update_receipts.py`), and V3 package admission (`standard_v3_test.go`). The crash windows between artifact rename and receipt write are exercised only by those injected-fault tests; the live hard-kill trials cannot target that window deterministically.

## Findings and defects

- No attack was wrongly accepted where a small, safe fix exists, and **no service code was changed**. The accepted attacks (A1, A2, A3, E6, E7, T1 to T3, T8, T12, T14, X8) are absent mechanisms, not implementation slips; each is recorded as an unmet property in the gap table.
- Observation for the maintainers, not a security defect and not tested live: `deploy/gce/nginx.conf` routes `StreamModelParameters`, `Health` and `RecordTelemetry` only, while the default latest model is V3 whose package RPCs (`GetModelPackage`, `StreamModelAsset`) are not routed (ST6). Whether cloud clients can obtain V3 through that ingress was not run here.
- Observation (from unrecorded development runs only): a kill during the atomic write can leave a temp file beside the artifact, which nothing sweeps at startup. Its effect on serving was not tested.

## Limitations

- Mutual-TLS rows run against a grpcio stand-in terminator, not the production nginx ingress, because its image is not part of this run. They show the certificate semantics (validity window, chain, key usage, name) of the TLS stack, not nginx's configuration. The nginx behaviour is covered only by static checks ST4 to ST7 and the CI smoke test `deploy/gce/tests/smoke.py`, which was not executed.
- The update service ran as a host process bound to loopback, and the Go service as a Docker container on loopback. No remote network path, container hardening or cloud firewall was exercised. No load or denial-of-service testing was done beyond message-size and value-count limits.
- The model is the legacy `privoke-balanced` Tiny artifact; the effect of a bounded-but-hostile update on detection quality was not measured.
- Telemetry upload authentication and replay, the fuzzer service and the browser extension are outside this record.
- Hard-kill trials sample ten delays on one machine; they show no violation, not absence of one. Windows `TerminateProcess` stands in for SIGKILL.
- Test identities are synthetic and generated per run; no real credentials were used and none are stored in the record.

## Reproduce

```
python evaluation/setup-host.py
docker build -f services/model-streaming-service/Dockerfile --target development -t privoke-updsec-model-dev:20261116 .
python evaluation/update_security.py --release-dir models/standard-releases
python evaluation/update_security_report.py
python -m unittest discover -s evaluation/tests -p test_update_security.py
```

Use the host Python with `grpcio`, `grpcio-tools`, `protobuf` and the repository's `privoke_model` imports; OpenSSL is required for the certificate rows. `models/standard-releases` is the ignored store prepared by `models/prepare_standard_releases.py`.
