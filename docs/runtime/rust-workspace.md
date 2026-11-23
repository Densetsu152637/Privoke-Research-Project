# Rust workspace

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0 to 5, 7, 11 to 16, 17 (partial), 18, 19 (partial), 20, 21 (partial), W2 and W3. Run every command from the repository root unless stated.

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0 to 5, 7, 11 to 14, 18, W2 and W3. Run every command from the repository root unless stated.

The workspace holds the Rust side of the server rewrite. Stages 1 and 2 added three libraries and the PKI tool; stage 3 adds the first service, `privoke-model-streaming`; stage 11 adds the spaCy client crate and the spaCy worker. The Python and Go services are unchanged and remain the measured system until a later stage replaces them.

| Crate | Purpose |
| --- | --- |
| `privoke-proto` | Protobuf messages and tonic clients and servers for `shared/proto`. The `build.rs` compiles the protos with `protox`, a pure-Rust protoc, so no `protoc` is needed on any host. Map fields are `BTreeMap`, so encoding is key-ordered like Python's `SerializeToString(deterministic=True)`. |
| `privoke-contracts` | Byte-exact ports of the Python contracts: canonical JSON in four layouts including Python's float `repr`, artifact checksums, receipt keys, window-training seeds, tensor fingerprints, the pinned V3 manifest rules and the V3 execution-evidence contract (`validate_execution`, `publication_passes`, `tensor_changes`, strict `parse`; one copy, shared by `v3_fit`, the V3 fuzzer and the checkpoint store). Re-exports `privoke-proto` as `proto`. |
| `privoke-transport` | In-service mutual TLS, authorisation, limits, the identity registry and hot reload. It replaces nginx. |
| `privoke-pki` (`rust/tools/privoke-pki`) | Operator CA tool and installation enrolment: `init-ca`, `issue-server`, `issue-reporter`, `sign`, `sign-service`, `revoke`, `crl`, and the installation commands `enrol`, `renew`, `install-cert` and `status`. The library is what `privoke-supervisor` will call. |
| `privoke-model-streaming` (`rust/services/model-streaming`) | The model-streaming service that replaces the Go service: legacy float catalog, standard V3 packages, two mutual-TLS listeners and a `healthcheck` subcommand. See [below](#privoke-model-streaming). |
| `privoke-telemetry` (`rust/services/telemetry`) | The telemetry service that replaces `services/telemetry-service` (Python): ingestion, validation, SQLite aggregate storage that opens the Python service's databases, and the summary estimator, behind mutual TLS with the shared reporter credential. See [below](#privoke-telemetry-stage-4). |
| `privoke-spacy` | Client of the spaCy worker: the framed protocol, UTF-8 and UTF-16 offset conversion, and the supervised worker pool. No Python dependency. |
| `privoke-spacy-worker` (`services/spacy-worker`) | The worker process. It embeds CPython 3.11 through PyO3 and serves the unchanged spaCy `en_core_web_sm`. The `embed` feature is off by default, so the workspace builds and tests without Python. |
| `privoke-runtime-supervisor` (`rust/services/runtime-supervisor`) | The workstation supervisor `privoke-supervisor` (stage 7): native-messaging host, runtime child supervision, loopback control service, model fetch and the enrolment commands. See [below](#privoke-runtime-supervisor-stage-7). |
| `privoke-rules` | The regex rule layer (300 rules including the ported Presidio recognisers and the Gitleaks catalogue) and the canonical-text preprocessing with offset maps, identical to the Python client runtime (stage 12). |
| `privoke-analysis` (`rust/services/analysis`) | The quarantined analysis microservice for the fuzzer (stage W3): mutual TLS, a fuzzer-only policy, and a pool of W1 Python workers. See [below](#privoke-analysis-stage-w3). |
| `privoke-param-update` (`rust/services/param-update`) | The parameter-update service and training-cycle scheduler (stage 5): guarded compare-and-swap publication, durable receipts, publisher identities over mutual TLS, drift bounds. See [below](#privoke-param-update-stage-5). |
| `privoke-semantic` | Semantic inference (stage 14): the V3 pretrained BERT encoder with its heads, the legacy Tiny transformer and the semantic layer, on a dependency-free float64 reference backend and the `tokenizers` crate. See [below](#privoke-semantic-stage-14). It also holds the external classifier client (stage 16), see [below](#external-classifier-client-stage-16). |
| `privoke-curriculum` | Curricula, schedules and update aggregation (stage 20): exact CPython `random`, the fuzzer prompt curricula and the frozen V3 AU3 and BC01 schedules. See [below](#privoke-curriculum-stage-20). |
| `privoke-training` | Gradients and local training of the Tiny transformer (stage 19, partial): reverse-mode kernels, the supervised objectives, the FULL projected Adam, the gradient RPC computation with its local-SGD, backtracking and diagnostics routes, and the policy and admission checks, on the stage 14 float64 reference backend. See [below](#privoke-training-stage-19). |
| `privoke-telemetry-client` | The client telemetry reporter (stage 18): CPython-identical random draws on an injectable byte source, binary64 GRR thresholds, the persistent daily epsilon ledger, the report builder and the delivery worker over mutual TLS. See [below](#privoke-telemetry-client-stage-18). |
| `privoke-fuzzer` (`rust/services/fuzzer`) | The fuzzer service that replaces `services/privoke-fuzzer` (stage 21, partial): one bounded training cycle per request with the stage 20 samplers in process, a mutual-TLS client of the runtime and of the parameter-update service, durable evidence and reservations, and the SQLite curriculum cursor state. See [below](#privoke-fuzzer-stage-21). |
| `privoke-v3-fuzzer` (`rust/services/v3-fuzzer`) | The experimental V3 fuzzer service that replaces `services/pretrained-v3/src/fuzzer_server.py` (stage 21, second half): one frozen-schedule fit per request, mutual-TLS clients of the V3 runtime and the checkpoint service, the SQLite `cycles` table and the work directory of every wire message. See [below](#privoke-v3-fuzzer-stage-21). |
| `privoke-v3-runtime` (`rust/services/v3-runtime`) | The experimental V3 runtime that replaces `services/pretrained-v3/src/runtime_server.py` (stage 22): semantic-only `AnalyzePrompt`, `FitCandidate`, `GetFitStatus` and `Health` over mutual TLS, the SQLite `fits` table and a checkpoint-service client. See [below](#privoke-v3-runtime-stage-22). |
| `privoke-runtime` (`rust/services/runtime`) | The Rust analysis runtime (stage 17, partial): `AnalyzePrompt` for the regex and NER layers and `Health` as a W1 worker for the W2 pool, with spaCy in process, the pipeline and policy aggregation, and a response encoder that writes Python's deterministic bytes. See [below](#privoke-runtime-stage-17). |

## Build and test

Rust 1.90 or newer is required (the host has 1.99.1). `Cargo.lock` is committed, so use `--locked`.

```
cargo test --workspace --locked --manifest-path rust/Cargo.toml
cargo clippy --workspace --all-targets --locked --manifest-path rust/Cargo.toml
cargo fmt --all --check --manifest-path rust/Cargo.toml
```

Targeted checks used by the plan:

```
cargo test -p privoke-transport fail_closed --locked --manifest-path rust/Cargo.toml
cargo test -p privoke-contracts --locked --manifest-path rust/Cargo.toml
```

All tests run on the host, as `AGENTS.md` requires. Test certificates, keys and CRLs are generated per test with `rcgen` into a temporary directory. No private key is committed.

## Conformance corpus

`privoke-contracts` replays the stage 0 corpus in `tests/conformance/`. The corpus was captured from the reference revision (tag `rust-reference-20261117`) by `evaluation/capture_conformance.py`; rerun it with the host Python environment:

```
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/capture_conformance.py --release-dir models/standard-releases
git diff --exit-code tests/conformance
```

`--release-dir` points at the prepared standard V3 releases (they are ignored by Git). The Go service runs in Docker from the `privoke-updsec-model-dev:20261116` image, as in UPDSEC. The corpus has an index, `manifest.json`, with file hashes and the recorded gaps. Comparison rules for the later replay (goal G5) are in `tests/conformance/normalization.toml`.

## `privoke-contracts`

- **Canonical JSON.** `json::parse` is a strict parser that keeps integers as exact digits and floats as IEEE-754 values, rejects `NaN`, overflowing floats, lone surrogate escapes and, on request, duplicate keys. `canonical::to_string` writes one of four `Variant` layouts. All sort keys and use compact separators:
  - `Ascii`: `ensure_ascii=True` (`full_adam.canonical`, receipts, admission headers).
  - `Utf8`: `ensure_ascii=False` (fingerprints).
  - `Utf8Go`: `Utf8` with U+2028 and U+2029 escaped (`artifact_checksum`).
  - `Utf8Lf`: `Utf8` plus one LF (V3 and retention contracts).
- **Float repr.** `pyfloat::repr` reproduces `repr(float)`, for example `1e-08` and `1e+16`. This is the lexical gotcha that Go's encoder and `serde_json` get wrong.
- **Checksums and fingerprints.** `digest::artifact_checksum`, `receipt_key`, `derived_seed` and `fingerprint::parameter_fingerprint`.
- **V3 manifests.** `v3::parse_canonical`, `validate_manifest` and `admitted_manifest` apply the tier tables, source pins and manifest pins of `v3_contract.py` and `standard_v3.py`.

Known limits, each covered by a corpus case: lone surrogates are errors (Python's ASCII variant would emit them, but every UTF-8 variant fails), and integers longer than 4300 digits are errors, as in Python.

## `privoke-transport`

A server is built in four steps; see the crate documentation for the recipe.

1. `ReloadableTls::load(ServerTlsConfig::new(cert, key, client_ca, crl))` builds the `rustls` configuration. `ServerTlsConfig` has no constructor that omits the client CA or the CRL, and loading fails if any file is missing, empty or invalid, if the CRL is not signed by the client CA, has no `nextUpdate` or is stale.
2. `SecureListener::bind` accepts TCP, completes the TLS handshake per connection against the live configuration, enforces the connection caps and the handshake timeout, and gives tonic the verified identity as connect info.
3. `AuthLayer` (a tower layer, added with `secure_server`) applies the `Policy`, the per-peer rate limit and the `Registry` to every request.
4. Each generated service sets `max_decoding_message_size(limits.max_message_bytes)`.

What is enforced, and where:

| Control | Mechanism |
| --- | --- |
| Client certificate required, one CA | `WebPkiClientVerifier` with anonymous clients refused. |
| Validity window | Checked by `rustls` at every handshake. |
| Missing or wrong EKU | `PrivokeClientVerifier` requires an explicit `clientAuth` extended key usage. A certificate with no EKU extension is refused, which `rustls` alone would accept. |
| Identity | Exactly one well-formed `urn:privoke:` URI SAN (`installation:<uuid>`, `service:<name>` or `reporter`). |
| Revocation | CRL in the verifier, end-entity check, expiry enforced. A stale CRL fails handshakes. |
| Hot reload | `ArcSwap<ServerConfig>`, rebuilt from the files by a `notify` watcher plus a poll. A failed reload keeps the old configuration and records the reason in `ReloadStatus`. |
| No session resumption | Session storage and TLS 1.3 tickets are off, so a resumed session cannot skip the CRL. |
| Per-RPC authorisation | Unlisted RPC: `UNIMPLEMENTED`. No verified peer: `UNAUTHENTICATED`. Unknown, denied or wrong-role identity: `PERMISSION_DENIED`. The registry is read on every request, so a deny-list change reaches open connections. |
| Rate limit | `governor`, keyed by identity or by source IP per rule; over the limit: `RESOURCE_EXHAUSTED`. Defaults are 20 requests per second with a burst of 40. |
| Limits | 1 MiB messages, 60 s timeout, 20 connections per IP, 10 s handshake timeout, 10 min maximum connection age with a 30 s grace. Values live in `Limits`. |
| Claimed identity | `Principal::check_claim` rejects a `consumer_id` or `source_id` that disagrees with the certificate. |

### Registry

`registry::RegistryFile` is the TOML file (version 1): `reporter = true|false`, `[[installation]]` (`id`, `label`, `expires`), `[[service]]` (`name`, `role` of `publisher`, `trainer` or `runtime`, `expires`) and `[[deny]]` (`urn`, `reason`). The format is documented in the module and in section 4 of the [deployment guide](../deployment/google-cloud.md#4-provision-tls-and-installation-credentials). A file is refused whole if any entry is invalid (bad UUID, duplicate, unknown role, non-UTC expiry, non-PriVoke deny URN). `RegistryFileReloader` loads it at startup (a failure stops the server) and polls it afterwards; a refused edit keeps the previous registry and is reported in `RegistryStatus`. Entries can expire, and the deny list wins over registration. The registry is read on every RPC, so a change reaches open connections.

### Operator and enrolment tool

`privoke-pki` implements the operator-mediated enrolment of the plan. The installation runs `enrol` (key and CSR; only the public CSR leaves the machine). The operator runs `sign`: it checks the CSR's single SAN against the UUID they confirmed out of band, records the certificate in `ledger.toml`, registers the installation and writes the delivery bundle, including the shared reporter credential. The installation then runs `install-cert`. `renew` keeps the UUID and the active certificate until the new one is installed, so both are valid until the old one expires. `revoke` marks every certificate of an identity and adds a deny entry; `crl` publishes the revocation list (7 days by default, and servers refuse all handshakes once it lapses). `status` reads only local files and warns 30 days before expiry. The deployment guide has the full procedure and the list of secret files.

```
cargo test -p privoke-pki --locked --manifest-path rust/Cargo.toml
```

### Fail-closed startup

`startup::CloudTlsArgs` is the flag set every cloud binary flattens into its arguments: `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`. `into_config` returns an error naming the first missing or unusable input, and the binary must exit non-zero before binding. There is no insecure flag. `privoke-listener-probe` (built with the `probe` feature) is the reference binary, and `cargo test -p privoke-transport fail_closed` runs it.

### Plaintext loopback

`listener::loopback` exists only with the `workstation-loopback` feature, which is off by default and must be enabled only by the workstation supervisor and tests. It refuses to bind a non-loopback address and never carries an identity, so `AuthLayer` answers `UNAUTHENTICATED` to it. The check that a cloud build does not enable the feature is:

```
cargo tree --locked -p privoke-transport -e features -e no-dev --manifest-path rust/Cargo.toml
```

The output must not contain `workstation-loopback`; `fail_closed_release_dependency_tree_has_no_plaintext_feature` asserts it.

## `privoke-model-streaming`

The Rust replacement for `services/model-streaming-service` (Go, left in place). It serves the same artifact catalog, legacy float streams and standard V3 packages with byte-identical output, behind in-service mutual TLS instead of the nginx ingress. Binary: `model-streaming-service`. Dockerfile: `rust/services/model-streaming/Dockerfile`.

### Listeners and authorisation

Both listeners are `privoke-transport` mutual-TLS listeners over the same server certificate, client CA, CRL and registry. An RPC that a listener's policy does not list is `UNIMPLEMENTED` there.

| Listener | Default port | RPCs | Roles |
| --- | --- | --- | --- |
| Public | 50443 (`MODEL_STREAMING_PUBLIC_PORT`) | `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset` | `consumer` (registered installations), rate key: identity |
| Internal | 50051 (`MODEL_STREAMING_PORT`) | `GetModelParameters`, `Health` | `publisher`, `trainer`, `runtime` (registered services), rate key: identity |

`GetModelPackage` and `StreamModelAsset` are public for the first time (plan goal G8); the nginx ingress routed only three RPCs and not these two. The reporter credential is refused on both listeners.

Caller binding: on the public listener a request that names a `consumer_id` is refused with `PERMISSION_DENIED` unless it is the caller's own installation UUID (or its URN); an empty `consumer_id` is accepted. On the internal listener `consumer_id` stays a log label, because service principals are not installations. A request that reaches a handler with no authenticated principal is refused `UNAUTHENTICATED`, so the service cannot be wired to a listener without the authorisation layer by mistake.

### Startup and configuration

The binary needs `--cert`, `--key`, `--client-ca`, `--crl` and `--registry` (`privoke_transport::startup::CloudTlsArgs`). It builds the TLS verifier and parses the registry before it reads any model file or binds a socket, so a missing, empty or invalid input exits 1 with the flag named. There is no flag, feature or environment variable that disables authentication; `--insecure` and similar are unknown arguments (exit 2). `cargo test -p privoke-model-streaming --test features` asserts that the dependency tree has no `workstation-loopback`.

Environment, as in the Go service where a name existed there:

| Variable | Default | Meaning |
| --- | --- | --- |
| `MODEL_STREAMING_PORT` | `50051` | internal listener port |
| `MODEL_STREAMING_PUBLIC_PORT` | `50443` | public listener port (new) |
| `MODEL_STREAMING_BIND` | `0.0.0.0` | interface for both listeners (new) |
| `MODEL_LATEST_ID` | `privoke-v3-balanced` | what `latest` resolves to; never a scratch or pretrained-contextual model |
| `MODEL_ARTIFACT_DIR` | `/models` | legacy JSON artifacts (every `*.json` is validated at startup) |
| `MODEL_RELEASE_DIR` | `/model-releases` | prepared standard V3 releases, verified against the pinned manifests when `MODEL_LATEST_ID` is a standard model |
| `V3_PUBLISH_ROOT` and `V3_STORE` | unset | the published V3 root and the V3 checkpoint store of param-update (stage V3-R3); both or neither. See [Published V3 versions](#published-v3-versions-stage-v3-r3) |

### Published V3 versions (stage V3-R3)

`src/published.rs` serves the trained V3 versions that param-update publishes ([V3 publication](v3-publication.md#serving)), next to the pinned releases. With `V3_PUBLISH_ROOT` and `V3_STORE` set, `GetModelPackage(privoke-v3-<tier>)` returns the model's newest publication with its signed statement (`ModelPackageResponse.publication_statement`), and the pinned ORIGINAL (empty statement) when nothing is published. `StreamModelAsset` serves a manifest only when it is the compiled pin or the authority holds a publication of it. A model id `privoke-v3-<tier>@<manifest-sha>` is the pin-addressed form: the pinned ORIGINAL without a statement, or a published version with its statement; any other manifest is `INVALID_ARGUMENT`. `latest` is unchanged (`privoke-v3-balanced`), and with the two variables unset the service is byte-identical to the Go-parity corpus. The authority is read from `catalog.sqlite` read-only on every request (`rusqlite`, bundled); published files are re-hashed against their manifest like pinned ones. Tests: `tests/published.rs` (toy packages signed with the shared test keys, plus the shared `chain.json` fixtures) and the unchanged `tests/go_standard_v3.rs`.

`model-streaming-service healthcheck --client-cert C --client-key K --server-ca CA [--address host:port] [--server-name N]` makes one mutual-TLS `Health` call to the internal listener and exits 0 only for `model-streaming-service` reporting `SERVING`. The probe needs a registered service identity (any of the three roles), so a container health check mounts one; the Go probe was plaintext. Each flag has an environment fallback (`MODEL_HEALTHCHECK_CERT`, `_KEY`, `_SERVER_CA`, `_SERVER_NAME`).

### Behaviour kept from the Go service

Every contract below is a line-for-line port and is covered by the ported tests: artifact size and checksum rules (`calculateArtifactChecksum` is the contracts crate's `Utf8Go` canonical form), the exact raw-flag, duplicate-key and Unicode guards for scratch and pretrained artifacts, all five architectures (Tiny, Tiny with task-query readout, sparse presence, scratch presence, pretrained context), the contextual training strategy, objective and optimizer policies (FULL Adam, ORIGINAL retention, window checkpoint), the pinned standard V3 store with symlink refusal and re-hashing before streaming, the live scratch catalog with its inspect-open-inspect race checks, `Health` as `NOT_SERVING` when any catalog entry fails to validate, 1024-value parameter chunks with the metadata on the first chunk only, and 1 MiB asset chunks.

Training-contract metadata (`full_projected_adam_config_v1`, `train_window_config_v1`) is compared lexically against the Python `canonical()` text, so `epsilon` is `1e-08` and `margin_cap` is `1.0` in `contextual.rs`. Floats are never written by this service except in the checksum canonical form, which goes through `privoke_contracts::pyfloat::repr` and not `serde_json`.

### Deliberate differences

- **Caller binding and two listeners** (above). Go had one plaintext listener and no caller identity.
- **Stricter JSON.** Case variants of a field name (`Model_ID`) are ignored where Go's decoder folded case; lone surrogates and invalid UTF-8 are refused for every architecture (Go replaced them in the two Tiny architectures and guarded only presence, scratch and pretrained); a `null` inside a tensor's `shape` or `values` array is refused (Go decoded it as 0). Each only rejects inputs Python's reader also refuses or that no tool writes.
- **Checksums use the Python float text.** A number is written back with Python's `repr` (as the Python writer did) and not with its original lexical form (as Go's `UseNumber` did). They agree for every artifact the Python writer produced; a hand-edited artifact with `1e-8` or `1E5` is accepted by Rust and Python alike but was refused by Go.
- **No path in `NOT_FOUND`.** Go's message for an absent scratch file embedded the `lstat` error text, which contained a server path. Rust says `scratch artifact is absent`.
- **Limits are the nginx defaults of `privoke-transport`** (1 MiB request, 60 s, 64 concurrent streams per connection) in place of Go's 64 KiB, 8 MiB and 32.

### Build and run

```
docker build -f rust/services/model-streaming/Dockerfile -t privoke-model-streaming-rust:<tag> .
```

The Dockerfile builds `--locked` in `rust:1.99.1-slim-bookworm` and runs on `gcr.io/distroless/cc-debian12:nonroot` with the repository's `models/privoke-*.json` under `/models`. A `Dockerfile.dockerignore` next to it allow-lists `rust/`, `shared/proto/` and those artifacts (the repository `.dockerignore` drops every `bin` directory, which would remove `privoke-transport/src/bin`). A run needs the five TLS files and the release store, for example:

```
docker run --rm -p 127.0.0.1:50443:50443 -p 127.0.0.1:50051:50051 \
  -v <models>:/models:ro -v <releases>:/model-releases:ro -v <pki>:/pki:ro \
  privoke-model-streaming-rust:<tag> --cert /pki/server.crt --key /pki/server.key \
  --client-ca /pki/client-ca.pem --crl /pki/crl.pem --registry /pki/registry.toml
```

### Tests

All of these run on the host (`cargo test -p privoke-model-streaming --locked`).

- **Ported Go tests** (`tests/go_*.rs`): every one of the 57 `Test*` functions in `services/model-streaming-service/cmd/server/*_test.go` has a Rust test with the name in a comment above it, and the three Go tests with several subtests are split where the subtests need different set-up. The table is below. Fixtures are the same files (`shared/python/tests/fixtures`, `models/privoke-*.json`).
- **Corpus replay** (`tests/corpus.rs`): the four legacy catalog models (`GetModelParameters` message digest, every streamed chunk and the stream digest), the 20 recorded negative requests (status and details), and, for each of the three standard V3 models, the package message, manifest bytes and every asset chunk, all compared byte for byte with `tests/conformance/model_streaming.json`. The V3 half reads the prepared release store from `V3_TEST_RELEASE_DIR`, `models/standard-releases`, or the main checkout of a linked worktree, and reports itself skipped when none exists.
- **Mutual TLS end to end** (`tests/mtls.rs`): real certificates issued with `privoke-pki`, both listeners, role gating, caller binding, unregistered, foreign-CA and no-certificate peers, deny-list and late-registration reload, the V3 fetch with pin verification, the binary's fail-closed startup for each missing flag, the absence of insecure flags, the live binary and its `healthcheck` subcommand.
- **Container rows**: `python evaluation/update_security.py --target rust --rust-image <image>` hosts the built image on loopback with a disposable PKI (client CA, server CA, a foreign CA, registered and unregistered installations, a registered service, the reporter credential, and expired, not-yet-valid, serverAuth-only and no-EKU certificates for registered identities) and runs rows T1 to T12, R3, R4, R7, R8, R9 and X8 (plus positive controls X1, X1b, X8b and the internal-listener rows I1 to I4). It writes `.tmp/update-security-rust-s03.json` by default and never touches the recorded UPDSEC files; `--rust-binary` runs a host binary instead, for development. The default `--target go` is unchanged.

The Go-test mapping:

| Go test (`cmd/server`) | Rust test (`rust/services/model-streaming/tests`) |
| --- | --- |
| `TestAllSixScratchIDsAreServedAfterCatalogConstruction` (scratch_catalog_live_test.go) | `go_scratch_live::all_six_scratch_ids_are_served_after_catalog_construction` |
| `TestArtifactChecksumMatchesSharedPythonCanonicalJSON` (main_test.go) | `go_main::artifact_checksum_matches_shared_python_canonical_json` |
| `TestContextualDecisionMarginConfigurationFailsClosed` (contextual_training_test.go) | `go_contextual::contextual_decision_margin_configuration_fails_closed` |
| `TestContextualDecisionMarginObjectivePreservesManifestAndStreams` (contextual_training_test.go) | `go_contextual::contextual_decision_margin_objective_preserves_manifest_and_streams` |
| `TestContextualMeanCategoryObjectivePreservesManifestAndStreams` (contextual_training_test.go) | `go_contextual::contextual_mean_category_objective_preserves_manifest_and_streams` |
| `TestContextualObjectiveIndependentOfTrainingStrategy` (contextual_training_test.go) | `go_contextual::contextual_objective_independent_of_training_strategy` |
| `TestContextualOptimizerIndependentAndStreamed` (contextual_training_test.go) | `go_contextual::contextual_optimizer_independent_and_streamed` |
| `TestContextualRawFlagsRequireBoolean` (contextual_training_test.go) | `go_contextual::contextual_raw_flags_require_boolean` |
| `TestContextualRawObjectiveTypesRejected` (contextual_training_test.go) | `go_contextual::contextual_raw_objective_types_rejected` |
| `TestContextualRawOptimizerTypesRejected` (contextual_training_test.go) | `go_contextual::contextual_raw_optimizer_types_rejected` |
| `TestContextualSharedFixtureTrainabilityAndMetadata` (contextual_training_test.go) | `go_contextual::contextual_shared_fixture_trainability_and_metadata` |
| `TestContextualStrategyAndManifestRejectInvalid` (contextual_training_test.go) | `go_contextual::contextual_strategy_and_manifest_reject_invalid` |
| `TestFullAdamPolicyRejectsMissingMalformedMixedAndUnsupported` (full_adam_policy_test.go) | `go_contextual::full_adam_policy_rejects_missing_malformed_mixed_and_unsupported` |
| `TestFullAdamThreeProfilesAndExactMetadata` (full_adam_policy_test.go) | `go_contextual::full_adam_three_profiles_and_exact_metadata` |
| `TestFullEncoderProfilesAdmitEmbeddingsAndRejectFrozenOrWrongScope` (contextual_training_test.go) | `go_contextual::full_encoder_profiles_admit_embeddings_and_reject_frozen_or_wrong_scope` |
| `TestGetModelParametersLoadsPersistentArtifact` (main_test.go) | `go_main::get_model_parameters_loads_persistent_artifact` |
| `TestGetModelParametersRejectsControlCharacters` (main_test.go) | `go_main::get_model_parameters_rejects_control_characters` |
| `TestGetModelParametersRejectsInvalidArtifactChecksum` (main_test.go) | `go_main::get_model_parameters_rejects_invalid_artifact_checksum` |
| `TestGetModelParametersRejectsUnknownModel` (main_test.go) | `go_main::get_model_parameters_rejects_unknown_model` |
| `TestGetModelParametersResolvesLatestAlias` (main_test.go) | `go_main::get_model_parameters_resolves_latest_alias` |
| `TestLoadModelCatalogDiscoversArtifacts` (main_test.go) | `go_main::load_model_catalog_discovers_artifacts` |
| `TestLoadPresenceArtifactRejectsMissingAndNullTrainableFlags` (artifact_test.go) | `go_artifact::load_presence_artifact_rejects_missing_and_null_trainable_flags` |
| `TestLoadRepositoryArtifact` (main_test.go) | `go_main::load_repository_artifact` |
| `TestPresenceConfigRejectsInvalidContracts` (artifact_test.go) | `go_artifact::presence_config_rejects_invalid_contracts` |
| `TestPresenceParametersRejectInvalidManifest` (artifact_test.go) | `go_artifact::presence_parameters_reject_invalid_manifest` |
| `TestPresenceRawTrainableFlagsAndUnicode` (artifact_test.go) | `go_artifact::presence_raw_trainable_flags_and_unicode` |
| `TestPresenceSharedPythonFixtureLoadsAndStreamsMetadata` (artifact_test.go) | `go_artifact::presence_shared_python_fixture_loads_and_streams_metadata` |
| `TestPretrainedArtifactRejectsConfigHeadAndIdentityDrift` (pretrained_context_test.go) | `go_pretrained::pretrained_artifact_rejects_config_head_and_identity_drift` |
| `TestPretrainedCannotBeLatestAndExplicitCatalogLoadPreservesIdentity` (pretrained_context_test.go) | `go_pretrained::pretrained_cannot_be_latest_and_explicit_catalog_load_preserves_identity` |
| `TestPretrainedClosedASCIIReleaseVersionsMatchPython` (pretrained_context_test.go) | `go_pretrained::pretrained_closed_ascii_release_versions_match_python` |
| `TestPretrainedOnlyAdmittedContextProfilesPreserveStreamConfig` (pretrained_context_test.go) | `go_pretrained::pretrained_only_admitted_context_profiles_preserve_stream_config` |
| `TestPretrainedRawDuplicateFlagsAndUnknownFieldsRejected` (pretrained_context_test.go) | `go_pretrained::pretrained_raw_duplicate_flags_and_unknown_fields_rejected` |
| `TestPretrainedSharedPythonFixtureLoadsAndStreamsSixFrozenHeads` (pretrained_context_test.go) | `go_pretrained::pretrained_shared_python_fixture_loads_and_streams_six_frozen_heads` |
| `TestScratchAllProfilesAndOfflineModes` (scratch_presence_test.go) | `go_scratch::scratch_all_profiles_and_offline_modes` |
| `TestScratchCatalogCannotBecomeLatestOnConstructionOrReload` (scratch_presence_test.go) | `go_scratch::scratch_catalog_cannot_become_latest_on_construction_or_reload` |
| `TestScratchCatalogConcurrentReadsInstallAndRemove` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_concurrent_reads_install_and_remove` |
| `TestScratchCatalogPropagatesStatErrors` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_propagates_stat_errors` |
| `TestScratchCatalogRejectsDirectoryPathSubstitution` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_rejects_directory_path_substitution` |
| `TestScratchCatalogRejectsInspectedFileABAReplacement` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_rejects_inspected_file_aba_replacement` |
| `TestScratchCatalogRejectsOutsideSymlinkSubstitutionDuringOpen` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_rejects_outside_symlink_substitution_during_open` |
| `TestScratchCatalogRejectsSymlinkDirectoryAndWrongIdentity` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_rejects_symlink_outside_catalog`<br>`go_scratch_live::scratch_catalog_rejects_directory_at_canonical_filename`<br>`go_scratch_live::scratch_catalog_rejects_wrong_model_identity` |
| `TestScratchCatalogRejectsUnknownAndTraversalIDs` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_rejects_unknown_and_traversal_ids` |
| `TestScratchCatalogSeesAtomicReplacementAndRemoval` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_sees_atomic_replacement_and_removal` |
| `TestScratchCatalogServesFileInstalledAfterConstruction` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_catalog_serves_file_installed_after_construction` |
| `TestScratchOptionalFilesDoNotBreakBaselineHealthButInvalidFilesDo` (scratch_catalog_live_test.go) | `go_scratch_live::scratch_optional_files_do_not_break_baseline_health_but_invalid_files_do` |
| `TestScratchRawGuardsRunBeforeTypedDecode` (scratch_presence_test.go) | `go_scratch::scratch_raw_guards_run_before_typed_decode` |
| `TestScratchRejectsWrongShapesModesAndProvenance` (scratch_presence_test.go) | `go_scratch::scratch_rejects_wrong_shapes_modes_and_provenance` |
| `TestScratchRequestConsumerContract` (scratch_presence_test.go) | `go_scratch::scratch_request_consumer_contract` |
| `TestScratchSharedFixtureChecksumAndFirstChunkMetadata` (scratch_presence_test.go) | `go_scratch::scratch_shared_fixture_checksum_and_first_chunk_metadata` |
| `TestSensitiveRetentionPoliciesCoexistAndFailClosed` (sensitive_retention_test.go) | `go_contextual::sensitive_retention_policies_coexist_and_fail_closed` |
| `TestStandardV3ActualPinnedAssetsAndLegacyIsolation` (standard_v3_test.go) | `go_standard_v3::standard_v3_actual_pinned_assets_and_legacy_isolation` |
| `TestStandardV3DefaultAndMissingStoreFailClosed` (standard_v3_test.go) | `go_standard_v3::standard_v3_default_and_missing_store_fail_closed` |
| `TestStandardV3RejectsLinksTraversalAndUnpinnedManifests` (standard_v3_test.go) | `go_standard_v3::standard_v3_rejects_links_traversal_and_unpinned_manifests` |
| `TestSumDecisionMarginConfigAndOptimizerParity` (full_adam_policy_test.go) | `go_contextual::sum_decision_margin_config_and_optimizer_parity` |
| `TestTaskQueryFailClosed` (task_query_test.go) | `go_contextual::task_query_fail_closed` |
| `TestTaskQuerySharedFixtureTransportAndScopes` (task_query_test.go) | `go_contextual::task_query_shared_fixture_transport_and_scopes` |
| `TestWindowPolicyRequiresExactConfigurationAndIndependentPins` (train_window_test.go) | `go_contextual::window_policy_requires_exact_configuration_and_independent_pins` |

Tests that need a symlink (`scratch_catalog_rejects_symlink_outside_catalog`, `scratch_catalog_rejects_outside_symlink_substitution_during_open`, and the asset-symlink assertion in `standard_v3_rejects_links_traversal_and_unpinned_manifests`) report themselves skipped on a Windows host without the symlink privilege, as the Go tests do. The directory cases use a junction there instead, which `symlink_metadata` also reports as a link, so the path-substitution and root-link refusals do run.

## `privoke-telemetry` (stage 4)

The Rust replacement for `services/telemetry-service` (Python, left in place as the parity oracle). Binary: `telemetry-service`. Dockerfile: `rust/services/telemetry/Dockerfile`. Modules mirror the Python files: `validation` (`validation.py`), `storage` (`storage.py`, including the estimator), `config` (`config.py`) and `service` (the collector of `server.py`); `daily`, `server` and `healthcheck` are new.

### Listeners and authorisation

| Listener | Default port | RPCs | Roles | Rate key |
| --- | --- | --- | --- | --- |
| public | `58443` (published as `8443`) | `RecordTelemetry`, `Health` | `reporter` (the shared credential `urn:privoke:reporter`) | source IP |
| internal | `50055` | `GetTelemetrySummary`, `Health` | `publisher`, `trainer`, `runtime` | service identity |

Both are `privoke-transport` mutual-TLS listeners over one server certificate, client CA, CRL and registry. The binary needs `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`, and exits 1 naming the first missing or invalid one before it opens the database or binds a port. An RPC that a listener does not list is `UNIMPLEMENTED` there: the summary cannot be read with the credential that every installation holds, and a service identity cannot report. An installation certificate (registered or not) is `PERMISSION_DENIED` on both listeners; no certificate, or one from another CA, fails the handshake. The registry must carry `reporter = true`; turning it off reaches open connections.

### What is and is not kept about a peer

The certificate identity is the shared reporter credential and says nothing about who reported, so the service reads it for admission only. The one per-peer value it uses is the **source IP**, held in memory for two controls. Neither reaches the database or a log line.

- **Rate limit.** The transport token bucket (20 requests per second, burst 40) is keyed by source IP on the public listener. Two clients holding the same certificate at different addresses are limited independently, and two connections from one address share a bucket. `TELEMETRY_RATE_PER_SECOND` and `TELEMETRY_RATE_BURST` change it.
- **Daily cap.** At most `TELEMETRY_DAILY_CAP_PER_IP` (default 10000) accepted reports per source per UTC day, then `RESOURCE_EXHAUSTED`. Reports that fail validation or storage do not use the allowance. IPv6 sources count by /64, and at most one million sources are tracked per day (beyond that the service refuses instead of growing). The counters are dropped at the day boundary. At rollover the service logs three aggregate numbers (accepted, distinct sources, refused) with no address: this is the per-IP daily acceptance counter that records counts by day and no identities. Nothing about a day is persisted.

The database has the Python schema and nothing else: `telemetry_strata(epsilon_micros, sample_count)` and `telemetry_counts(epsilon_micros, dimension, value, observed_count)`. No column can hold an identity, an address or a time. The log lines are the startup line (ports and the cap, no address), persistence or aggregation failures (no request data) and the day summary. The Python per-report "recorded" line is dropped. `no_identity_column_and_no_identity_log_line` runs the binary, sends reports from three source addresses with the reporter and an installation certificate, and asserts that neither its stderr nor any file of the data directory contains the URNs, the installation UUID, the certificate fingerprints or any source address.

### Behaviour kept from the Python service

- Validation order and messages: mechanism, epsilon range, the six-decimal rule with Python's `isclose`, then each dimension in `time_bucket, action, primary_category, risk_bucket, model_version` order.
- The legacy-database and incompatible-schema refusals. The file is inspected before WAL mode is set, so a legacy database is left byte for byte unchanged (Python switched it to WAL first).
- One `BEGIN IMMEDIATE` transaction per report, a fresh connection per operation, and `Health` as a writable-transaction probe.
- The estimator, with the same IEEE operations in the same order: `exp_epsilon + domain_size - 1`, `count - n * other`, and Python's `min` and `max` tie rules. Results agree bit for bit on the host; G5 allows 4 ULP for another libm.
- A request above `TELEMETRY_MAX_MESSAGE_BYTES` (131072) is refused before the handler.

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `TELEMETRY_PORT` | `50055` | internal listener port |
| `TELEMETRY_PUBLIC_PORT` | `58443` | public listener port (new) |
| `TELEMETRY_BIND` | `0.0.0.0` | interface for both listeners (new) |
| `TELEMETRY_DB_PATH` | `/data/telemetry-ldp-v1.sqlite3` | the SQLite file; a Python-written file opens unchanged |
| `TELEMETRY_MAX_MESSAGE_BYTES` | `131072` | largest request message |
| `TELEMETRY_DAILY_CAP_PER_IP` | `10000` | accepted reports per source per UTC day (new) |
| `TELEMETRY_RATE_PER_SECOND`, `TELEMETRY_RATE_BURST` | `20`, `40` | per-source rate limit (new) |

`telemetry-service healthcheck --client-cert C --client-key K --server-ca CA [--address host:port] [--server-name N]` makes one mutual-TLS `Health` call to the internal listener. It needs a registered service identity; the reporter credential is not admitted there.

### Build and run

```
docker build -f rust/services/telemetry/Dockerfile -t privoke-telemetry-rust:<tag> .
docker run --rm -p 127.0.0.1:58443:58443 -p 127.0.0.1:50055:50055 \
  -v <pki>:/pki:ro -v <data-volume>:/data \
  privoke-telemetry-rust:<tag> --cert /pki/server.crt --key /pki/server.key \
  --client-ca /pki/client-ca.pem --crl /pki/crl.pem --registry /pki/registry.toml
```

The image builds `--locked` in `rust:1.99.1-slim-bookworm` (SQLite is compiled in through the `bundled` feature of `rusqlite`) and runs on `gcr.io/distroless/cc-debian12:nonroot`. `/data` is created owned by `nonroot`, so a fresh volume is writable; an existing volume must be writable by uid 65532. `Dockerfile.dockerignore` allow-lists `rust/` and `shared/proto/` and excludes keys, certificates and databases.

### Tests

Run on the host: `cargo test -p privoke-telemetry --locked --manifest-path rust/Cargo.toml`.

| File | Covers |
| --- | --- |
| `tests/parity.rs` | The stage 0 corpus: 195 packets through the handlers, 6 strata and 155 marginal rows exact, 26 summary estimates within 4 ULP, the serialised summary hash, the empty summary and health. The telemetry-audit fixtures in `tests/fixtures/estimator_oracle.json`: the packets of `store_parity` in `evaluation/analysis/audit-telemetry-mechanism.py` (26 estimates) and 1200 further packets over 400 strata that stress `exp`. A database written by the Python store (`tests/fixtures/python_written.sqlite3`), opened and extended. |
| `tests/ported.rs` | Every test of `services/telemetry-service/tests/test_security_validation.py`, and the malformed-packet cases: truncated and non-UTF-8 protobuf, wrong wire types, reserved legacy tags, duplicate fields, the legacy and incompatible databases, and rejected packets that are neither stored nor counted. |
| `tests/mtls.rs` | The policy on both listeners and R10 in process. Per-source-IP independence of the limiter with one certificate (client sockets bound to `127.0.0.2`, `.3` and `.4`). The daily cap. An oversize message. No identity column and no identity log line. Fail-closed startup with the built binary (each flag, and a legacy database). The `healthcheck` subcommand. |
| `tests/emitter.rs`, `tests/emitter_check.py` | The stage 6 check: the real Python emitter (`event_emitter.py`, unmodified) delivers four reports over mutual TLS with the reporter credential, and is refused with an installation certificate in the telemetry slot. |
| `tests/container.rs` | R10 against the built container, the container's own `healthcheck`, the emitter against the container, and a container log that holds no peer data. |

`emitter.rs` and `container.rs` report themselves skipped, and pass, when their inputs are absent:

- `PRIVOKE_HOST_PYTHON` is a host interpreter with `grpcio` and `protobuf` (for example the one in `evaluation/.venv-v1-v3-pipeline`). `PRIVOKE_PY_GENERATED` is a directory holding the generated `privoke/v1/telemetry_pb2*.py`: `evaluation/setup-host.py` makes them, or `python -m grpc_tools.protoc -I shared/proto --python_out=<dir> --grpc_python_out=<dir> shared/proto/privoke/v1/telemetry.proto`. The script patches `is_loopback_target`, as the stage 6 test does, so that a loopback target takes the production TLS path.
- `TELEMETRY_CONTAINER_IMAGE` is an image built from the Dockerfile. The test starts it as `privoke-s04-telemetry-r10` on two ephemeral loopback ports with a fresh volume, and removes both when it ends. Only the server key pair, the CA certificates, the CRL and the registry are mounted.

The two fixtures were generated by running the Python oracle (`services/telemetry-service/app/storage.py`) and record its bit patterns. Regenerate them with the same Python, from the packets inside the fixture, only if the estimator is changed deliberately.

## `privoke-param-update` (stage 5)

The Rust replacement for `services/param-update-service` (Python, left in place as the parity oracle). Binary: `param-update-service`. Dockerfile: `rust/services/param-update/Dockerfile`. Modules mirror the Python files: `validate` (`validation.py`), `window` (`window_training.validate_publication`), `apply` and `artifact_io` (`privoke_model.artifact`), `receipts`, `audit`, `bootstrap`, `engine` (the service class of `server.py` without the transport), `journal` and `scheduler` (`training_cycles.py`, `fuzzer_requests.py`). New: `policy` (drift bounds), `service`/`server` (mutual TLS), `healthcheck`, `pyfmt` (Python text and number behaviour).

### Listener and authorisation

One mutual-TLS listener (`PARAM_UPDATE_PORT`, default `50052`, internal network only), built from the same fail-closed `privoke-transport` configuration as the other services. `SubmitParameterUpdate`: registered `publisher` services. `GetParameterUpdateStatus`: `publisher` and `trainer`. `Health`: `publisher`, `trainer`, `runtime`. Everything else is `UNIMPLEMENTED`; a peer with no certificate fails at the handshake. **Identity binding:** a non-empty `source_id` must equal the caller's service name, so the fuzzer's certificate must be issued under the name it publishes as (`FUZZER_ID`). `docker-compose.analysis.yml` sets `FUZZER_ID: fuzzer` for the `fuzzer` certificate; the production file's `server-fuzzer` needs a certificate of that name at stage 8a.

### Behaviour kept from the Python service

Validation order and messages, compare-and-swap on `base_version`, `round(float32(v)+float32(d), 8)`, the artifact layout (`indent=2`, sorted keys, fsynced temp file, rename, directory fsync), the receipt in artifact metadata and in SQLite (`<audit>.receipts.sqlite3`, `BEGIN IMMEDIATE`, checkpoint and reload), conflicting-payload refusal, the audit JSONL, window-policy publication evidence, `bootstrap` (preparation of the full-encoder release) and the scheduler journal (`cycles` table). Artifact validity is the stage 3 loader's.

### Drift bounds (GAP-NO-CUMULATIVE-BOUND, new)

`PARAM_UPDATE_DRIFT_POLICY=enforce|off` (default `enforce`), `PARAM_UPDATE_MAX_UPDATE_L2` (default 16.0), `PARAM_UPDATE_MAX_CUMULATIVE_L2` (default 512.0, per anchored `release_version`, measured as the sum of accepted update norms). With `off`, artifacts and receipts are byte-identical to Python. With `enforce` the artifact gains one metadata key, `update_drift_v1` (committed by the same rename, so recovery restores the total); the receipt format is unchanged. A replayed request id is answered from its receipt before any bound. Defaults are structural bounds (0.05 per coordinate over 65,536 values is 12.8; 340 recorded head updates of at most 1.3 sum to under 436); the per-update norms of the C4, C10 and C16 runs are not in the repository, so they were not replayed.

### Configuration

`MODEL_ID`, `MODEL_ARTIFACT_PATH`, `PARAM_UPDATE_STORAGE_PATH`, `PARAM_UPDATE_MAX_ABS_GRADIENT`, `PARAM_UPDATE_MAX_MESSAGE_BYTES` as Python; new `PARAM_UPDATE_BIND`, `PARAM_UPDATE_RATE_PER_SECOND`/`_BURST`, `MODEL_TRAINING_MAX_TOKENS` (bootstrap). Scheduler: the `FUZZER_*` and `PARAM_UPDATE_SOURCE_ID` variables of Python, plus `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE` (required when `FUZZER_PROMPT_COUNT > 0`) and `FUZZER_TLS_SERVER_NAME`. Not ported: the bounded study controls of `request_fuzzer_loop`.

Subcommands: `healthcheck` (mutual-TLS `Health`) and `bootstrap`. Build: `docker build -f rust/services/param-update/Dockerfile -t privoke-param-update-rust:<tag> .`

### Tests

`cargo test -p privoke-param-update --locked --manifest-path rust/Cargo.toml` (CI: 26 unit tests plus `corpus.rs` 3, `guarded.rs` 21, `mtls.rs` 7, `scheduler.rs` 18). `corpus.rs` replays the stage 0 sequence (bootstrap, 19 updates, 6 lookups) byte for byte; `guarded.rs` ports `test_security_validation.py`, `test_update_receipts.py`, the injected crash windows and `test_model_bootstrap.py`; `mtls.rs` covers A1 to A3, T14, R1, R2, R5, R9 and fail-closed startup in process; `scheduler.rs` covers the dual-cycle tests and one cycle against an in-process mutual-TLS fuzzer. Container rows: `python evaluation/update_security.py --target rust --rust-service param-update --rust-update-image <image>`.

### V3 checkpoint store (stage V3-R1)

> Plan: [V3 routine training](../plans/v3-routine-training.md#stage-v3-r1-port-the-v3-checkpoint-store-into-param-update). Oracle: `services/pretrained-v3/src/{checkpoint_store,checkpoint_server}.py` (frozen), `fuzzer_training.validate_source_evidence`.

`src/v3_store/` ports the V3 checkpoint store and serves `privoke.experimental.v3.CheckpointService` on the internal mutual-TLS listener when `V3_STORE` is set (off otherwise, so nothing changes for existing deployments).

- **Layout and authority.** `<V3_STORE>/blobs/<sha256>` (immutable, fsynced temp file plus rename) and `catalog.sqlite` with the Python tables `current(model, manifest)` and `receipts(id, fingerprint, payload)`, WAL, `synchronous=FULL`; a directory written by either implementation opens under the other. The `current` table is the single authority for each model's version; later stages derive everything else from it.
- **Operations.** `bootstrap` (ORIGINAL assets, `INSERT OR IGNORE`), `resolve`, `put`/`read`, `verify_checkpoint`, `admit_candidate` (ORIGINAL binding, immutable provenance, unchanged inventory, finite float32 tensors equal to the manifest, execution evidence, `validate_source_evidence`, identity and reported changes, HEADS may change only `heads.*`), `stage`, `status` and `commit` (one `BEGIN IMMEDIATE`: receipt replay or content conflict, admission, identity, then `stale_base`, `guard_rejected` or the compare-and-swap). An admission failure records nothing; a rejection records a durable receipt.
- **Signing seam (V3-R2).** `CommitObserver::before_swap` runs inside the commit transaction after every gate and before the `current` row changes; an error rolls the commit back. The default does nothing.
- **Source evidence.** `PinnedSources` loads the BC01 inputs and the AU3 release once (`V3_SOURCE_ROOT`, `V3_AUDIENCE_MANIFEST_PATH` plus `V3_AUDIENCE_MANIFEST_SHA256`) and dispatches on the record's sampler; `privoke_curriculum::v3::validate_source_evidence_bc01` is new beside the AU3 one, and the guard targets are checked against the dispatched sidecar.
- **Roles.** `CommitCandidate`: `publisher` and `trainer`. `StageCheckpoint`, `ResolveCurrent`, `FetchBlob`, `GetCommitStatus`, `Health`: also `runtime` (the V3 runtime stages what it fits and never commits). The service accepts 2 MiB messages (1 MiB chunks); the update service keeps 1 MiB. Refusals are `INVALID_ARGUMENT` (contract), `NOT_FOUND` (missing blob) and a fixed `INTERNAL` message.
- **Configuration.** `V3_STORE`, `V3_INITIAL` (ORIGINAL directories, separated like `PATH`), `V3_SOURCE_ROOT` (required with `V3_STORE`), the two audience variables.
- **Oracle golden.** `evaluation/generate_checkpoint_store_golden.py` drives the unchanged Python store over 98 steps in three stories (BC01 lifecycle, AU3, two tiers) and records every answer, refusal text and the catalog (blobs, `current`, `receipts`) after each step. The manifest contract pins the real parameter counts, so each weights file is 4.8 or 9.6 million float32 values from a closed-form function of (salt, index) that `tests/checkpoint_store_golden.rs` reproduces and checks by SHA-256; evidence is recorded without its `source` member, regenerated from the committed pinned inputs and checked by SHA-256. The official `config.json` and `vocab.txt` (public, admitted by SHA-256) are the fixtures in `tests/fixtures/v3_store/`. No prompt text is committed.
- **Tests.** `checkpoint_store_golden.rs` (the golden), `checkpoint_mtls.rs` (roles, bounded ordered chunks both ways, refusals as statuses), unit tests in `store.rs` and `config.rs`. `privoke-v3-fuzzer/tests/store_replay.rs` replays the 23 recorded real fits with the store as checkpoint service (local, needs `PRIVOKE_V3_FUZZER_RECORDED_GOLDEN` and `PRIVOKE_V3_RECORDED_MODELS`; run in Docker `rust:1.99.1-bookworm` on 23 Nov 2026: 23 fits, 10 applied and 13 rejected as recorded, 92 of 92 wire messages, 161 work-directory files and 23 `cycles` rows identical, and the store's receipt equals the recorded one for every fit, in 281 s).

### V3 publication (stage V3-R2)

> Plan: [V3 routine training](../plans/v3-routine-training.md#stage-v3-r2-signed-publication-derived-directory-and-drift-bounds). Operator document: [V3 publication](v3-publication.md) (statement format, commit order, custody, rotation, the trust-on-first-use limitation).

- **`privoke-contracts::publication`**: the signed statement `{tag, key_id, model_id, manifest_sha, parent, original, sequence}` (canonical JSON, Ed25519 over those bytes), `sign`, `verify`, `KeySet` indexed by `key_id`, and the deterministic test keys behind the `test-keys` cargo feature (never enabled by a service or client build). Ed25519 is `ring`, already in the workspace through rustls. `ModelPackageResponse.publication_statement` (field 6) carries the wire form.
- **Shared signed-chain fixtures**: `rust/crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`, written by `evaluation/generate_v3_signed_chain_fixtures.py` with a pure-Python RFC 8032 signer (checked against the RFC vector): ORIGINAL, HEADS (1), FULL (2), rollback to the ORIGINAL (3), a second-key version (4) and ten forged variants. `param-update/tests/v3_signed_chain.rs` verifies the chain, re-signs every statement in Rust and compares bytes, and checks each forged variant; R3, R4a, R4b and `update_security.py` read the same file.
- **`v3_publish`**: `Publisher`, a `CommitObserver`. Stage (fsynced, before the transaction), allocate the sequence and sign inside the compare-and-swap transaction, rename the staged directory and move the pointer after it; startup `reconcile` promotes an intact staged directory, rebuilds from the store, repairs the pointer and quarantines what the authority does not reference. A `CrashHook` injects a failure at `staged`, `signed`, `committed`, `renamed` and `pointer`.
- **`CheckpointStore`** gained the `Candidate`/`Swap` observer hooks (`prepare`, `before_swap`, `after_commit`, `abandon`), `ChainObserver`, the `versions` and `publications` tables (additive; the oracle's tables are unchanged and the R1 golden still passes), `history`, and `rollback` (`CheckpointService.RollbackModel`, publisher role only). Admission, drift and the recomputed guard now run before the `BEGIN IMMEDIATE`, and a repeated applied request finishes its interrupted publication.
- **`v3_policy`** (`config/v3-drift-bounds.toml`): per tier and scope, the largest L2 of a candidate from its parent and from the ORIGINAL; provisional values from V3-P (HEADS 4.3, FULL 3.8 per update; cumulative four times that), `status` and the SHA-256 of the calibration record. A breach is a `rejected` receipt `drift_exceeded`; V3-R5 recalibrates.
- **`v3_guard`**: rebuilds the 16 guard rows with `privoke_curriculum::v3::routine_guard_rows` from the scheduler's allocation (`Allocations`; V3-R6 implements it over the journal), checks the evidence guard targets against them, scores base and candidate (`V3Model::with_tensors`) and applies the `publication_passes` rule. The scoring is checked against the Python product's recorded predictions on the stage 22 toy package.
- **Configuration**: `V3_DRIFT_BOUNDS` (required with `V3_STORE`: every commit is bounded), `V3_PUBLISH_ROOT`, `V3_PUBLICATION_KEY_FILE` (a mounted 64-hex seed), `V3_PUBLICATION_KEY_ID` (validated at startup); subcommand `publication-key --key-file F` prints the public key for the clients' key sets. The guard gate is not installed by `main` until V3-R6 provides the allocations.
- **Tests**: `tests/v3_publication.rs` (publication, a loser, five crash points with restart and retry, a loser that dies staged, rollback, reconciliation repairs, the drift gate), `tests/v3_guard.rs`, `tests/checkpoint_mtls.rs` (rollback roles), `v3_signed_chain.rs`, `routine_guard.rs` in `privoke-curriculum`.

## `privoke-telemetry-client` (stage 18)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-18-telemetry-reporter-in-rust-d8). Audit record: [rust-telemetry-epsilon-audit-20261117](../../paper/research/rust-telemetry-epsilon-audit-20261117.md).

The Rust port of the client telemetry reporter, `extension/client-runtime/src/telemetry/{privacy,event_emitter}.py`, which stay in place as the parity oracle. It is a library; the controller wires it in (`privoke-runtime-supervisor`, [Telemetry](#telemetry-stage-18-wired-in-rust-s17b)). Dependencies: `privoke-contracts` (the packet), `privoke-transport` (client mutual TLS), `rusqlite` (bundled), `getrandom`, `tonic` and `tokio` (a current-thread runtime on the worker thread only).

| Module | Python source |
| --- | --- |
| `random` | The draws of `random.SystemRandom`: `random_unit` (7 bytes, `>> 3`, times 2^-53), `random_bits` (`getrandbits`) and `random_below` (`_randbelow` rejection sampling), over a `RandomSource` trait. `OsRandom` reads the operating system; `ReplayRandom` replays fixed bytes and counts them (tests). |
| `privacy` | `generalized_randomized_response`, `grr_kernel` / `grr_probabilities` (binary64: `exp(x) / ((exp(x) + K) - 1)`), `randomize_report`, `validate_privacy_config`, the five domains in the oracle order. Messages are the Python texts. |
| `ledger` | `DailyPrivacyBudget`: one SQLite file with the Python table text, `BEGIN IMMEDIATE`, UTC day, `+1e-12` cap tolerance, never refunded, fail closed (`LedgerUnavailable`) on corruption, a bad row, a backwards clock or any I/O fault. `default_ledger_path` follows the Python rules. |
| `event` | `StructuredEventEmitter::true_values`, `assemble_packet`, `build_packet` over `AnalysisInput` (action name, optional classification with sensitivity and category names, optional model version string). |
| `reporter` | `TelemetryReporter`: reserve, build, bounded queue (`try_send`), one worker thread (`privoke-telemetry-reporter`), the Python log texts, `close(timeout)`. `ReportOutcome` and `DeliveryOutcome` expose what happened; `ReporterParts` injects the transport, random source, clock and an observer. |
| `grpc` | `GrpcTransport` (a `PacketTransport`) and `ReporterEndpoint::from_environment`: a loopback target is plaintext; any other target needs `PRIVOKE_TELEMETRY_TLS_CERT_FILE`, `PRIVOKE_TELEMETRY_TLS_KEY_FILE` and `PRIVOKE_TLS_CA_FILE`, with the host part of the target as the certificate name. The channel is made on first use and again after a connection failure. |

### What is identical, and the decisions that matter

- **Same bytes, same draws.** One `random()` (7 bytes) per dimension, then, if the answer is not truthful, one `_randbelow(K - 1)` (rejection sampling on `bit_length(K - 1)` bits, at least one byte per attempt). Dimensions are drawn in the order `action, risk_bucket, primary_category, model_version, time_bucket`, alternatives in domain order. The tests assert the output and the exact byte count of 485 single draws, 160 full reports and 40 packets.
- **Same thresholds.** The binary64 threshold of every (event epsilon, domain size) cell equals Python's bit for bit on the Linux CI host (65 grid cells and 35 real cells in `tests/golden.rs`, 25 audited cells in `tests/audit_thresholds.rs`). `f64::exp` calls the platform libm, as CPython's `math.exp` does, so another libm can differ in the last bit: the tests would fail there and the audit record would not apply.
- **Budget before packet, never refunded.** `report` reserves first, builds second, queues last; a failed build, a full queue, a closed worker and a failed delivery keep the spend, as in Python.
- **Ledger.** The Python file opens and continues in Rust (fixture `python_written_ledger.sqlite3`), the table text is the same, and 15 scenarios (cap, reopen, UTC conversion, rollover, rollback, bad rows, corruption, a blocked parent directory and its recovery) give the same result and the same rows operation by operation.

### Known differences

None changes a decision, a draw or a packet:

- `report` takes both the reservation day and the time bucket from one injectable clock (Python reads `datetime.now` twice); a report that straddles a four-hour boundary between the two reads could differ by that.
- A ledger value that is not text or a number (a hand-edited file) is a ledger fault in Rust; Python lets a `TypeError` escape `reserve` (the reporter catches it all the same).
- A directory created for the ledger gets mode `0700` for every component created (Python: the last one). The file mode is `0600`, set after the file is created, as in Python. Neither is applied on Windows.
- The `PRIVOKE_ALLOW_INSECURE_INTERNAL_PLAINTEXT` research opt-out of the oracle is not offered, and a CA bundle file is required for a non-loopback target (no system roots).
- `Closed` is a new `ReportOutcome` (Python has no closed state; its worker is a daemon thread). `close` waits for the worker up to the timeout and, like Python, does nothing when the queue is full.

### Integration notes for stage 17

1. Build one reporter at runtime start: `TelemetryReporter::start(settings, Box::new(GrpcTransport::new(ReporterEndpoint::from_environment(target, &|name| std::env::var(name).ok())?)?))`, with `ReporterSettings { event_epsilon, daily_epsilon, ledger_path, ..Default::default() }`. The defaults are the Python ones (epsilon 1, daily 8, timeout 1 s, queue 1024).
2. After each analysis, map the result to `AnalysisInput { action: "ALLOW" | "WARN" | "BLOCK", result: Some(AnalysisResult { classification: Some(Classification { sensitivity: "S0" to "S3", categories: [names] }), model_version: the metadata value }) }` and call `report(&input)`. Only these fields can reach a packet. Ignore the returned `ReportOutcome` unless a test wants it.
3. `report` does a short blocking SQLite transaction. Call it from a worker thread or `spawn_blocking`, not directly from a tokio task.
4. Call `close(Duration)` on shutdown. A telemetry failure must never fail an analysis: nothing `report` does returns an error or panics.
5. The stage 7 supervisor owns the reporter credential files (`PRIVOKE_TELEMETRY_TLS_*`); the reporter only reads their paths.

**Wired in** (RUST-S17B): the controller does this; see [Telemetry](#telemetry-stage-18-wired-in-rust-s17b). The worker has no reporter.

### Tests

Run on the host or in CI: `cargo test -p privoke-telemetry-client --locked --manifest-path rust/Cargo.toml`.

| File | Covers |
| --- | --- |
| `tests/golden.rs` | Everything above against `tests/fixtures/golden.json`, written by `evaluation/generate_telemetry_client_golden.py` from the unmodified Python (standard library only; its random source is a recorded byte stream). Python test: `evaluation/tests/test_generate_telemetry_client_golden.py` (the committed fixture equals a fresh run). |
| `tests/audit_thresholds.rs` | The finite-epsilon audit record against the crate thresholds and sampler (see below). |
| `tests/service.rs` | The Rust reporter against the stage 4 Rust service in process over mutual TLS: delivery and the daily cap, refusal of a non-reporter credential, outage and recovery. |

Regenerate the fixture only if the oracle or the scenario list changes deliberately:

```
python evaluation/generate_telemetry_client_golden.py \
    --out rust/crates/privoke-telemetry-client/tests/fixtures/golden.json \
    --ledger-out rust/crates/privoke-telemetry-client/tests/fixtures/python_written_ledger.sqlite3
```

### Finite-epsilon audit of the Rust kernel

`evaluation/audit_rust_telemetry_epsilon.py` (new code, standard library only) computes the exact likelihood ratios of the Rust thresholds and writes `paper/research/rust-telemetry-epsilon-audit-20261117.json`; the record explains the method. The result at event epsilon 0.5, 0.75, 1, 1.5 and 2: the actual maximum log ratio exceeds the nominal epsilon by 1.294e-15, 4.882e-16, 1.503e-15, 4.427e-16 and 1.226e-15 (all strictly positive), the thresholds equal the Python kernel's, and at 0.5, 1 and 2 the numbers equal C34's. C34 keeps describing the CPython kernel; this record describes the Rust one wherever `tests/audit_thresholds.rs` passes (Linux CI run 44013270917).

## Not in this stage

No other service than `privoke-model-streaming` (stage 4 adds `privoke-telemetry`, above), no PyO3, and no CI job (no `.github/` change before the submission deadline). The `privoke-supervisor` wrapper commands (`enrol`, `install-cert`, `renew`, `status`) belong to stage 7; they call the `privoke_pki::client` library. The Rust CI job waits for the deadline.
No other service than `privoke-model-streaming`, no PyO3, and no CI job (no `.github/` change before the submission deadline). The `privoke-supervisor` wrapper commands (`enrol`, `install-cert`, `renew`, `status`) are stage 7, now in `privoke-runtime-supervisor`. The Rust CI job waits for the deadline.

## Not in stage 1

No service and no CI job (no `.github/` change before the submission deadline). The registry file format and the `privoke-pki` tool are stage 2.

## spaCy through PyO3 (stage 11)

Plan: [stage 11](../plans/rust-server-rewrite.md#stage-11-spacy-through-pyo3-in-a-supervised-worker-pool-d1-engine). spaCy 3.7.5 and `en_core_web_sm` 3.7.1 run unchanged inside `privoke-spacy-worker`. The runtime (stages 13 and 17) uses the `privoke-spacy` pool and never imports Python itself.

```
cargo test -p privoke-spacy --locked --manifest-path rust/Cargo.toml          # pool, protocol, offsets (Python-free fake worker)
cargo test -p privoke-spacy-worker --locked --manifest-path rust/Cargo.toml   # the worker's request loop (no Python)
```

Both run in `cargo test --workspace --locked`. The real worker needs a CPython 3.11 development install to link (`PYO3_PYTHON`) and the bundle, so it sits behind the `embed` feature, which is off by default:

```
python rust/services/spacy-worker/tools/build_bundle.py --out rust/target/bundle/windows --test-hooks --build-python <Python311/python.exe> --model-installed <reference site-packages>
PYO3_PYTHON=<Python311/python.exe> PRIVOKE_SPACY_BUNDLE=rust/target/bundle/windows cargo test -p privoke-spacy-worker --features embed,test-hooks --locked --manifest-path rust/Cargo.toml
```

`--test-hooks` adds the crash, print and sleep requests and a `--lock` override that the tests need. Never ship a bundle built with it.

### Bundle

`build_bundle.py` produces a directory that runs with no system Python on `PATH`:

| Item | Source |
| --- | --- |
| CPython 3.11.9 | The python.org Windows embeddable package, checked against the SHA-256 in the lock. Its `python311.dll` is byte-identical to the reference interpreter's and carries the Python Software Foundation signature. `python311._pth` makes CPython ignore the user's environment, the user site and `PYTHON*` variables. |
| `Lib/site-packages` | `pip install --require-hashes --no-deps --only-binary=:all:` of `rust/services/spacy-worker/bundle.lock.txt`. |
| Model | The lock names the release wheel and its hash. That wheel is only on GitHub, and this build fetches from python.org and PyPI only, so the build copies the files of an installed model after checking each one against the model's own `RECORD` (`--model-installed`), or unpacks the wheel (`--model-wheel`, checked against the lock hash). |
| Licenses | `licenses/` holds spaCy's, thinc's and the model's `LICENSE`, the model's `LICENSES_SOURCES` and `meta.json` (MIT). The build fails if one is missing. |
| Worker | `cargo build --release -p privoke-spacy-worker --features embed`, linked against `python311.lib` from `--build-python` and loading `python311.dll` from the bundle. |

The lock is the complete freeze: 44 distributions, the model among them (the closure of spaCy and the model, plus `click`, which spaCy imports although typer 0.27 no longer requires it). Each has the hashes of every CPython 3.11 `win_amd64` and `manylinux` x86-64 wheel that PyPI publishes. The header records the CPython distribution and hash, the CPython build identity and the BLIS CPU-dispatch target (`haswell` on the Windows host). Regenerate the package section with `tools/closure.py` (run in the read-only reference environment) and `tools/generate_lock.py`.

At every start the worker compares the interpreter version and build, every installed distribution (name and version, in both directions) and the BLIS dispatch target with the whole lock. It also checks that `sys.path` and `sys.prefix` lie inside the bundle. It refuses to run on any difference: it sends a `fatal` frame with the reasons, exits 78, and the pool does not restart it. A different BLIS target (another CPU family) is refused too, because different kernels can round differently; regenerate the lock for such a host.

### Protocol and supervision

Frames are a 4-byte little-endian length and a JSON payload (`privoke_spacy::protocol`). Requests go to the worker's stdin. Responses go to a duplicate of the original stdout that the worker takes before Python starts; Python then points fd 1 and `sys.stdout` at stderr. The result of `analyze` is built by one function, `analyze_body`, which the worker and the reference environment both run.

| Behaviour | Test |
| --- | --- |
| Bounded queue, `RESOURCE_EXHAUSTED` when full | `full_queue_is_resource_exhausted` |
| One deadline for queue plus serving, below the bridge's 30 s; a worker that misses it is killed and replaced | `deadline_kills_the_worker_and_the_pool_recovers`, `deadline_kills_a_stuck_real_worker` |
| Maximum text length (20 000 characters, the runtime default) | `invalid_text_is_rejected_before_queueing` |
| P3 poisoned input: never retried on another worker | `p3_poisoned_input_is_not_retried`, `p3_crash_input_is_unavailable_and_not_retried` |
| P3 crash-loop backoff, 100 ms doubling to 30 s, reset by a completed request | `p3_crash_loop_backs_off`, `backoff_doubles_from_100ms_to_a_30s_cap` |
| P3 readiness: nothing is accepted until `spacy.load` has finished | `p3_request_during_load_is_unavailable`, `p3_request_during_spacy_load_is_unavailable` |
| P4 framing: a print inside the worker leaves the frames intact | `p4_print_inside_the_worker_leaves_the_framing_intact` |
| P4 offsets: code points to UTF-8 and UTF-16 | `p4_offsets_are_correct_for_emoji_combining_marks_and_cjk`, `offsets` unit tests |
| Killing a worker mid-request: `UNAVAILABLE`, then recovery | `killing_a_worker_mid_request_is_unavailable_and_the_pool_recovers` |
| A lock that differs from the environment: refusal, no restart | `a_lock_that_differs_from_the_environment_is_refused`, `refused_bundle_stops_the_slot_and_reports_why` |
| Start with no system Python on `PATH` | `starts_with_no_python_on_path_and_reports_its_identity`, the `build_bundle.py` self-check |

Every failure except invalid input and a full queue is `Unavailable` (`SpacyError::status`). That fails the NER layer, which blocks an otherwise ALLOW decision.

### Parity gate

```
python rust/services/spacy-worker/tools/parity_gate.py --bundle rust/target/bundle/windows --work rust/target/parity [--smoke]
```

The gate extracts the recorded NER sets (read-only, hash-checked) into an ignored work directory and runs plain spaCy over them in the read-only reference environment `evaluation/.venv-v1-v3-pipeline`, in parallel shards (`tools/reference_dump.py`). It sends the same documents through the bundle's pool (`examples/parity_dump.rs`) and compares the SHA-256 of every result, per set and per selection. The pool path also decodes each result, which checks every token and entity offset against the text. `--smoke` runs the 200-document check: 160 documents sampled with a fixed seed from the recorded sets, and 40 synthetic stress documents (URLs, emoji, CJK, zero-width characters, casing extremes, odd whitespace). Golden data stays in `rust/target/parity`, which Git ignores.

The sets are `development` (502 rows), `personalized` (2000), `openai` (1000), `piimb` (150,022 sentences, the pool that F1, F3 and F4 were drawn from), `dolly15k` and `oasst2` (the sources of F2), and the synthetic `stress` set. WildChat, the third F2 source, is a parquet shard that neither environment can read, and its sampled rows are not stored, so it is not covered. `final.jsonl` is a locked partition and is not opened.

No service, no PyO3, and no CI job (no `.github/` change before the submission deadline). The registry file format and the `privoke-pki` tool are stage 2.

## In-process spaCy (stage 11b)

Plan: [stage 11b](../plans/rust-server-rewrite.md#stage-11b-in-process-spacy-backend-user-decision-17-november-2026). The user's instruction is that no external spaCy process exists: spaCy is integrated into the client-runtime process. `privoke-spacy` therefore has two backends behind one API, and the in-process one is the default.

| Backend | What it is | Use |
| --- | --- | --- |
| `InProcess` (default) | CPython 3.11 embedded through PyO3 on **one dedicated interpreter thread** (`privoke-spacy-interpreter`) that owns the GIL and the loaded `en_core_web_sm`. Callers reach it through a bounded channel. No child process. | The runtime worker (stage 17). |
| `SpacyPool` | The stage 11 pool of `privoke-spacy-worker` child processes. | Tests, and the parity oracle for `InProcess`. |

`Spacy` is the enum the runtime holds (`Spacy::start(&SpacyConfig)`); `SpacyConfig::default()` is `InProcess`, with the bundle directory taken from the running executable. Both variants have the same methods (`analyze_raw`, `analyze`, `lemma_index`, `wait_ready`, `worker_info`), return the same `SpacyError`, and use the same offset conversion, so the NER layer (`privoke-ner-layer`) implements its `SpacyBackend` trait for `InProcess` and `Spacy` as it does for `SpacyPool`.

### Same bundle, same lock check, same bytes

The interpreter thread runs the Python file the stage 11 worker embeds (`rust/services/spacy-worker/python/privoke_spacy_impl.py`, included from there, so there is one copy). `startup` compares the interpreter and every installed package with the whole `bundle.lock.txt`, checks that `sys.path` and `sys.prefix` lie inside the bundle, and loads the model. A difference is a refusal: the backend never becomes ready and `wait_ready` returns the reason. `redirect_stdout` runs before anything else, so Python's fd 1 and `sys.stdout` point at stderr and a stray `print` or C-library message cannot reach a stream that the host owns. `analyze_body` produces the result bytes in every place, which is what the parity gate compares.

The host executable must sit in the bundle directory: CPython finds `python311._pth` next to its library, and the isolation check refuses a process that sees anything outside the bundle. The PyO3 engine is behind the `in-process` feature of `privoke-spacy` (off by default, like `embed` on the worker), so `cargo test --workspace` needs no Python. Without the feature, `InProcess::start` fails with a configuration error and never falls back to a worker process.

### Failure model

Isolation comes from the runtime worker boundary, not from the interpreter. The W2 pool and sandbox wrap the whole runtime worker, so a crash of the interpreter (a segfault in spaCy, thinc or NumPy, an OOM) takes down that worker only, and the pool restarts it and never retries the request that was in flight. A stuck interpreter cannot be killed from inside; the pool's deadline replaces the worker. Throughput scales by adding runtime workers, not interpreters.

| Behaviour | Test (`rust/crates/privoke-spacy/tests`) |
| --- | --- |
| Bounded queue, `RESOURCE_EXHAUSTED` when full | `inprocess::full_queue_is_resource_exhausted` |
| One deadline for queue and interpreter, caller not held; an abandoned queued request is skipped | `inprocess::deadline_is_unavailable_and_the_caller_is_not_held`, `inprocess::an_abandoned_queued_request_is_not_run` |
| P3 readiness: a request during the model load is `UNAVAILABLE` | `inprocess::p3_request_during_load_is_unavailable` |
| A refused bundle is final and reports why; a failed or panicking start is `UNAVAILABLE` | `inprocess::a_refused_bundle_is_final_and_reports_why`, `inprocess::a_failed_start_and_a_panicking_factory_are_unavailable` |
| An engine error is reported and the interpreter keeps serving; a panic on the thread makes the backend `UNAVAILABLE` | `inprocess::an_engine_error_is_reported_and_the_interpreter_keeps_serving`, `inprocess::a_panic_on_the_interpreter_thread_makes_the_backend_unavailable` |
| `InProcess` is the default; the real backend needs the feature | `inprocess::the_default_backend_is_in_process`, `inprocess::the_real_backend_needs_the_in_process_feature` |
| Bytes equal to the pool backend (Python-free harness) | `inprocess::results_are_byte_identical_to_the_worker_pool_backend` |
| No child process when NER runs | `runtime_worker::no_child_process_is_created_when_ner_runs` (Python-free host, Linux), `real_interpreter::no_child_process_is_created_when_real_ner_runs` (real interpreter) |
| Interpreter crash kills only that worker; the pool restarts it; no retry | `runtime_worker::an_interpreter_crash_kills_only_that_worker_and_the_request_is_not_retried`, `runtime_worker::a_poisoned_document_crashes_one_worker_and_is_not_retried`, `real_interpreter::a_real_interpreter_crash_kills_only_that_worker_and_is_not_retried` (CPython `abort()`) |
| A stuck interpreter is replaced with its worker at the pool deadline | `runtime_worker::a_stuck_interpreter_is_replaced_with_its_worker_at_the_pool_deadline` |
| P4 framing: a print inside the in-process interpreter | `real_interpreter::a_print_inside_the_interpreter_leaves_the_framing_intact` |
| NER parity on every recorded set, both selections | `real_interpreter::in_process_output_is_byte_identical_to_the_worker_pool_on_every_recorded_set` |

`runtime_worker.rs` drives `privoke-spacy-host`, a stand-in for the stage 17 runtime worker: one process that hosts `InProcess` and speaks the worker frame protocol, so the W2 pool supervises it as it will supervise the runtime worker. Its Python-free engine runs in CI. `real_interpreter.rs` needs the bundle and the recorded sets, and each of its tests skips itself with a printed `SKIPPED` reason when one is missing:

```
PYO3_PYTHON=<python 3.11> cargo build --release -p privoke-spacy --bin privoke-spacy-host --features fake-worker,in-process,test-hooks --manifest-path rust/Cargo.toml
PRIVOKE_SPACY_HOST=rust/target/release/privoke-spacy-host PRIVOKE_SPACY_BUNDLE=rust/target/bundle/windows \
  cargo test -p privoke-spacy --test real_interpreter --locked --manifest-path rust/Cargo.toml -- --nocapture
```

`PRIVOKE_SPACY_PARITY_SETS` names the sets directory that `parity_sets.py` writes (default `rust/target/parity/sets`; never committed), and `PRIVOKE_SPACY_PARITY_LIMIT` caps the documents per set for a quick run. The host is copied into the bundle as `privoke-spacy-host-s11b` (a test artefact, built with the test hooks and never shipped). CI compiles and lints the in-process feature (job `spaCy worker embed build (Linux)`, step "Clippy with in-process"); the real-interpreter tests need the Linux bundle, which is stage 23.

## `privoke-rules` (stage 12)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-12-regex-rules-and-preprocessing-in-rust-d2).

`privoke-rules` ports the regex layer (`extension/client-runtime/src/regex/*`) and the canonical-text preprocessing (`detection/preprocessing.py`). Offsets are code point indexes, as in Python, so spans and offset maps compare equal to Python's without conversion.

| Module | Python source |
| --- | --- |
| `detector` | `rule_detector.py`, `rule_heuristics.py`, `detection/context.py`: collection, validators and downgrades, clean-context suppression, the two synthetic hits, de-duplication. |
| `rules` | `rules_*.py` in execution order, the labelled-identifier family, and the Presidio adapter of `rules_presidio.py`. |
| `presidio` | The 43 pattern recognisers of `presidio-analyzer` 2.2.363 that `rules_presidio.py` imports, transcribed with their recogniser and pattern names. |
| `gitleaks` | `rules_gitleaks.py`: the tracked `gitleaks.toml` is embedded at build time and converted exactly as Python does (208 of 222 source rules survive). |
| `validators` | `rule_validators.py`: Luhn, IBAN mod 97, NHS mod 11, SSN ranges, whole-word context. |
| `preprocessing` | `normalize_with_offsets` with offset maps and the `strip_format_chars`, `canonicalise_digits` and `canonicalise_email_words` flags. |
| `layer` | The regex path of `pipeline.analyse_text(text, layers=["regex"])`: normalise, detect, remap spans to the original prompt. |
| `pyre`, `pyunicode`, `unicode_tables` | Python `re` semantics and Python's Unicode data (below). |

### Pinned Unicode version

**Unicode 14.0.0**, the version of the reference interpreter (CPython 3.11.9, `unicodedata.unidata_version`). Python's text semantics follow its own database, so the crate carries it: `unicode_tables.rs` is generated by `evaluation/generate_rules_golden.py tables` and holds `\w`, `\d`, `\s`, `isdigit`, `Cf`, combining classes, `lower` and `upper` (including the final-sigma context), the `re.IGNORECASE` equivalents of ASCII letters (dotted and dotless `i`, long `s`, Kelvin sign), and the NFKD and composition data for NFKC. No Rust Unicode crate is used, and the Unicode version of `regex` and `fancy-regex` never matters (next section). Moving to a newer Python means regenerating the file; `test_tables_are_deterministic_and_current` fails when it is stale.

### How Python `re` is reproduced

`pyre::PyRegex` compiles a Python pattern for `regex` or `fancy-regex` and searches a shadow text. Every character outside printable ASCII is replaced by a stand-in of the same Python class (word, decimal digit, space or other; `İ`, `ı`, `ſ`, the Kelvin sign and `’` are kept), one for one, so offsets convert back by index. `\w`, `\d` and `\s` are translated into small explicit classes over the stand-ins. Escapes, `{,n}`, literal braces and class syntax follow Python's grammar and errors (`\z`, `\p`, mid-pattern flags and reversed ranges are rejected, which is what excludes three Gitleaks rules). `$` means the end of text or just before a final newline: rules with `$` run on `regex` with `\z`, and on text that ends in a newline switch to an exact `fancy-regex` variant. No packaged rule can match the empty string (`no_rule_matches_the_empty_string`).

### Patterns that need `fancy-regex`

Seventeen of the 300 rules, and four preprocessing patterns, use look-around or a back-reference, which the `regex` crate does not support. The other 283 rules run on `regex`. `cargo run -p privoke-rules --example fancy_report --manifest-path rust/Cargo.toml` prints the same list. No pattern needs `pcre2`, and the crate has no C dependency.

| Pattern | Why `fancy-regex` |
| --- | --- |
| `phone_us` | `(?<![\w])` before the number. |
| `social_handle` | `(?<![a-zA-Z0-9.])` before `@` and `(?!...)` after it. |
| `student_id` | `(?=[a-z0-9-]*\d)` requires a digit in the identifier. |
| `password_assignment` | `(?!(?:required\|optional\|...)\b)` rejects placeholder values. |
| `structured_identity` | `(?=[+(\d])` after the `phone` label. |
| `labelled_identifier_sensitive` | `(?<!loyalty\s)` and six more lookbehinds on `card`, `(?=[:=#])` after a document noun, `(?=[A-Z0-9_\-]*\d)` in the value. |
| `labelled_identifier_generic` | `(?=[A-Z0-9_\-]*\d)` in the value. |
| `license_plate` | `(?!(?:rfc\|cve\|iso\|iec\|bcp\|std)-)`. |
| `location_keyword` | `(?!(?:<closed-class words>)\b)` after the connector. |
| `bank_account` | Two lookaheads that bound and require a digit in the number. |
| `presidio_creditcardrecognizer_all credit cards (weak)` | `(?!1\d{12}(?!\d))`, nested negative lookaheads. |
| `presidio_ibanrecognizer_iban generic` | `(?<![A-Z0-9])` and `(?![A-Z0-9])`. |
| `presidio_iprecognizer_ipv4_mapped`, `_ipv4_embedded` | `(?<![\w:])`. |
| `presidio_iprecognizer_ipv6`, `_ipv6_unspecified` | `(?<![\w:])` and `(?![\w:])`. |
| `presidio_macaddressrecognizer_mac_colon_or_hyphen` | Back-reference `\1` to the separator. |
| preprocessing `email_with_at_sign`, `email_with_at_word` | `(?<![\w.%+\-])` and `(?![\w@\-])` around the address. |
| preprocessing `spelled_run` | `(?<![\w])` and `(?![\w])` around spelled digits. |
| preprocessing `single_digit_chain` | `(?<!\d)`, `\1` and `(?!\w)`. |

The default-path preprocessing (`[at]` markers, digit gaps, space and newline runs) is hand-coded rather than regex.

### FULL Adam policy cycle (RUST-S21F)

A request that carries the exact FULL Adam expectations (`expected_contextual_training_objective`, `_optimizer`, `_candidate_eligibility`, `expected_full_projected_adam_config_v1`, `_scope`) runs the policy cycle:

1. The expectations resolve as in Python (`policy`); the header scope, the fixed rate and cap, the durable dump directory and the `ORIGINAL retention requires the unchanged BC01 main composition.` check come before any reservation. The effective settings fingerprint includes the expectations and the header, and the header is sent as the gRPC metadata `x-privoke-training-admission-v1` on the `[SEMANTIC]` gradient request, with the 180 second deadline of a FULL fit (`CallOptions`).
2. `attempts::reserve_physical_attempt` creates `full-adam-runtime/<identity>/started.json` exclusively (a second physical request with the same bytes and header is refused, with `reservation-rejections/attempts/<ns>.json` recorded); the raw request and response are retained in `backtracking-attempts/<digest>/attempts/<ns>.json` before admission and the verdict in `.../admission/attempts/<ns>.json`.
3. The response is admitted (`runtime::validate_response`: the response contract, then `policy_response`: executed objective, optimizer identity, the plain FULL Adam or retention trace).
4. `full_adam_evidence::validate_candidate_route` re-reads the retained attempt and checks the raw request and response, the header, the executed phases and the trace against the update; the candidate TRAIN exact metric is selected only through it. `gate_summary` is stored under `full_adam_gate_v1`.
5. The publication projects the metadata (the weight audit and the taxonomy audit packed, the trace left in the retained cycle) and binds the retained cycle by `training_evidence_sha256`. A failure outside Python's handlers is `UNKNOWN` with `Exception calling application:` as in the Python server.

**Replay** (`evaluation/generate_full_adam_cycle_golden.py`, golden `tests/fixtures/full_adam_cycles_golden.json`, test `tests/full_adam_cycles.rs`): the maintained Python service replays recorded FULL Adam cycles of the iterative fuzzer study (`iterative_fuzzer_20261011`: a published and a refused cell; the study's dataset is not in the repository, so the sampler runs over the committed taxonomy fixture and the recorded response is replayed for the request the oracle builds). Seven policy cycles plus the study gate diagnostics: the published cycle, a guard refusal, a repeat refused by the physical reservation, a response with another objective, a response with a corrupted trace summary, a header whose scope differs, and a retention request without the benign strategy; two cycles with `study_gate_diagnostics=v1`. Wire messages, admission headers and deadlines, responses and aborts, every file of the dump (timestamp names become ordinals and the dump path `<DUMP>`; both are the only normalisation) and the reservation rows are identical. `training_evidence_sha256` hashes the attempt path, so the golden keeps the oracle's raw path and the Rust test recomputes the hash over its own record with it. **ORIGINAL retention** (`evaluation/generate_retention_trace_golden.py`, `tests/fixtures/retention_trace_golden.json`, `tests/retention_trace.rs`): the Python oracle's verdicts and error messages for the raw trace, the execution phases and the source bindings of two retained retention cycles (gate and hinge, efficient profile) and 30 mutations each; the retained release was authenticated by the oracle against the ORIGINAL teacher artifact pinned by its hash (found in the `block01` catalogs of the study, not in `models/`). Counts printed by CI: FULL Adam cycle replay 9 cycles (2 accepted, 7 refused), 15 wire messages, 6 runtime calls (header and deadline), 23 dump files, 2 publication evidence hashes, 2 gate diagnostics records; FULL Adam trace admission 2 admitted and 24 refused; ORIGINAL retention evidence 6 admitted and 54 refused, all identical to the Python oracle

Run: `https://github.com/Densetsu152637/Privoke-Research-Project/actions/runs/45036104880` on `d80f750`.

### Parity with Python

`evaluation/generate_rules_golden.py` writes the golden from the unchanged Python runtime with an explicit regex-only layer selection: every row goes through `pipeline.analyse_text(text, layers=["regex"])`, and the returned layer execution is asserted to be one `regex` layer (an empty layer list means the whole detector pipeline and is never sent). It covers the case-preserved and lowercased views, the three robustness flags singly and together, and `PRIVOKE_REGEX_PRESIDIO` and `PRIVOKE_REGEX_GITLEAKS` off singly and together. Normalisation is checked in seven configurations, the regex layer in nine.

```
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/setup-host.py
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_rules_golden.py sets development personalized openai f1 f2 f3 f4 probe-development probe-openai fuzz --data-root <checkout with the datasets>
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_rules_golden.py sweep
cargo run --release -p privoke-rules --example parity --manifest-path rust/Cargo.toml -- evaluation/results/rules-golden-20261117
```

`sets` writes into `evaluation/results/`, which Git ignores; recorded-set golden is never committed. It refuses any path named like `final`: the locked-public final endpoint is consumed and is not used. Committed fixtures hold only synthetic text: `synthetic_inputs.b64` with its golden `synthetic_golden.b64` (base64 of the JSON, so that no token-shaped sample such as a fake Slack, GitHub or AWS key is committed as a literal), the full rule inventory of the Python registry (`rule_inventory.json`, compared name by name, with pattern text or hash, classification, validator and downgrades), and a sample of the Unicode sweep.

```
cargo test -p privoke-rules --locked --manifest-path rust/Cargo.toml
PRIVOKE_RULES_GOLDEN_DIR=evaluation/results/rules-golden-20261117 cargo test --release -p privoke-rules --test golden --test unicode_parity --manifest-path rust/Cargo.toml
```

The Stage 0 corpus (`tests/conformance/`) has no regex or preprocessing surface, so it contributes no case here; the synthetic fixture stands in for it.

Known limits: lone surrogates cannot be a Rust `&str`, so rows that contain one would be skipped (none in the recorded sets). Python raises `KeyError` for a spelled digit with a dotless `ı` or long `ſ` when `canonicalise_digits` is on; the port reports the same layer error text. Constructs that no shipped pattern uses (atomic groups, possessive quantifiers, conditionals, `DOTALL`) are rejected.

## `privoke-worker-pool` (stage W2)

Plan: [stage W2](../plans/rust-server-rewrite.md#stage-w2-generic-worker-pool-and-os-sandbox-privoke-worker-pool). One protocol-agnostic crate runs every worker process: `privoke-spacy` today, the quarantined analysis service (W3) and the client controller (W4) next. It knows frames (a 4-byte little-endian length and the payload), not what they mean; a `Protocol` implementation reads the first frame (`Hello::Ready` or `Hello::Fatal`) and each answer (`Reply::Answer`, `Reported` or `Violation`). `privoke-spacy` supplies its JSON protocol and keeps its public API.

```
cargo test -p privoke-worker-pool --locked --manifest-path rust/Cargo.toml    # pool rules and sandbox, host
```

Supervision, per slot: spawn under the sandbox, wait for the first frame, serve from the shared bounded queue, replace the process on exit, crash, protocol violation or missed deadline. The frame pipe is the worker's stdin and stdout; a worker calls `worker_side::claim_frame_output()` (or the Python `os.dup`/`os.dup2` equivalent in W1) first, which takes the original standard output for frames and points standard output at standard error. The pool logs standard error.

| Rule | Test (`tests/pool_rules.rs`) |
| --- | --- |
| Readiness gate: a request while no worker is ready fails at once | `request_during_load_is_not_ready` |
| Poisoned input is never retried on another worker | `poisoned_input_is_not_retried` |
| Crash-loop backoff, never faster than the configured delay | `crash_loop_backs_off`, `backoff_doubles_from_100ms_to_a_30s_cap` |
| A completed request resets the failure count | `a_completed_request_resets_the_backoff` |
| A refused worker is final | `refused_worker_stops_the_slot_and_reports_why` |
| Bounded queue | `full_queue_is_resource_exhausted` |
| One deadline for queue plus service; a missed deadline kills the worker | `deadline_kills_the_worker_and_the_pool_recovers`, `queued_request_survives_a_hung_worker_ahead_of_it` |
| Worker errors keep the worker; out-of-protocol answers restart it | `worker_reported_error_keeps_the_worker`, `out_of_protocol_answer_restarts_the_worker` |
| A stray print leaves the frames intact | `stray_output_does_not_corrupt_the_frames` |

### Sandbox

`PoolConfig::sandbox` is a `SandboxPolicy`. The default only ties the worker's life to the parent's; `SandboxPolicy::strict(python_home)` adds a clean environment, an explicit `PYTHONHOME` and network denial, and `memory_limit_bytes` and `max_processes` add limits. A control that is asked for and cannot be installed fails the spawn, so a worker never runs less confined than its policy says.

| Control | Windows | Linux | Test (`tests/sandbox.rs`) |
| --- | --- | --- | --- |
| Dies with the parent | Job Object, kill-on-close; the worker is created suspended, put in the job, then resumed, so it cannot start a child that escapes | `PR_SET_PDEATHSIG` (SIGKILL), with a `getppid` check against the fork race | `children_die_with_the_parent`, `dropping_the_pool_kills_the_workers` |
| Memory limit | job memory limit (committed memory of the worker and its descendants) | `RLIMIT_AS` | `a_memory_limit_kills_a_runaway_worker` |
| Process limit | job active-process limit; counts the worker, and a process created over it is terminated | `RLIMIT_NPROC`, a ceiling for the whole real user | `a_process_limit_stops_a_runaway_worker` |
| Other | UI restrictions on the job; die on unhandled exception | `RLIMIT_CORE` 0 | |
| Network denied | **not provided** | seccomp filter: `socket`, `connect`, `bind`, `listen`, `accept`, `accept4`, `sendto`, `sendmsg`, `sendmmsg` and `io_uring_*` return `EPERM`; other architectures and x32 entry points are refused or killed | `network_denial_blocks_connect_on_linux` |
| Clean environment, explicit `PYTHONHOME` | yes (`SystemRoot` is kept) | yes | `clean_environment_and_explicit_pythonhome` |

Limits and caveats:

- **Windows has no network denial.** A Job Object limits lifetime and resources; it cannot cut off sockets. The worker's own self-check (it refuses to start when it can open a socket in sandboxed mode, W1) and the absence of network code are the controls there. `network_denial_enforced()` is false on Windows, a policy that asks for denial logs a warning, and no document or test claims it.
- **Linux descendants.** `PR_SET_PDEATHSIG` is cleared across `fork`, so it covers the workers the pool starts, not a worker's own children; a worker that spawns children must set it on them. On Windows the job covers the whole tree. The signal fires when the *thread* that forked the worker exits, so the pool must be started from a thread that lives as long as it (a Tokio runtime thread does).
- **`RLIMIT_NPROC` does not bind uid 0** (without a user namespace). The Linux process-limit test skips as root and runs as uid 1000 in the container run.
- **Linux filter choice.** The filter is seccomp, not Landlock: it needs no kernel feature beyond seccomp and no path configuration. `socketpair` stays allowed, as it has no peer outside the process tree.

### Linux container run

Docker hosts a Linux build and test container; the test binaries run inside it with `docker run`, never `docker compose run`. The container builds as root, then runs the sandbox test binary as uid 1000 so `RLIMIT_NPROC` binds:

```
docker run --rm --init -v <worktree>:/work -v privoke-w2-target:/target -v privoke-w2-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target rust:1.99.1-slim-bookworm bash -c \
  "cd /work/rust && cargo test -p privoke-worker-pool -p privoke-spacy --locked \
   && chmod -R a+rX /target && setpriv --reuid 1000 --regid 1000 --clear-groups /target/debug/deps/sandbox-<hash>"
```

`--init` reaps the workers the tests kill. A Linux-built `privoke-spacy-worker` bundle is still pending (stage 11's CI/Linux stage).

## `privoke-runtime-supervisor` controller (stages 7 and W4)

Plans: [stage 7](../plans/rust-server-rewrite.md#stage-7-rust-runtime-supervisor) and [stage W4](../plans/rust-server-rewrite.md#stage-w4-client-controller-without-listening-ports). Binary `privoke-supervisor` (`rust/services/runtime-supervisor`). Under W4 it is the client controller: the browser starts it as a native-messaging host, it owns one sandboxed `privoke-worker-pool` of the W1 Python worker, and it opens no listening socket. `confine.rs`, `process.rs`, the loopback control service and the Python-compatible `ensure_supervisor` host were removed; the Python supervisor, bridge and host stay in `extension/runtime-supervisor` as the oracle only.

| Command | Does |
| --- | --- |
| (none) or `native-host` | The controller on stdio. A browser passes only the calling origin, which is ignored. |
| `enrol`, `renew`, `install-cert`, `status` | Unchanged from stage 7 (`privoke_pki::client`). |
| `fetch-model [--model-id latest]` | Downloads the standard V3 package over mutual TLS into the user cache (below). |

### Controller protocol

One native-messaging port, frames as in `native_host.rs` (native-endian `u32` length, JSON, 1 MiB cap both ways). Messages are the `runtime.proto` messages, base64 in a JSON envelope; replies carry the request `id` and may arrive in any order.

```text
request  {"v":1,"id":7,"method":"AnalyzePrompt","payload":"<base64>"}
success  {"v":1,"id":7,"ok":true,"payload":"<base64>"}
failure  {"v":1,"id":7,"ok":false,"code":"UNAVAILABLE","message":"..."}
```

| Method | Request | Response |
| --- | --- | --- |
| `AnalyzePrompt` | `AnalyzePromptRequest` | `AnalyzePromptResponse` |
| `Status` | `RuntimeHealthRequest` | `RuntimeControlStatus` |
| `SetRuntimeEnabled` | `SetRuntimeEnabledRequest` | `RuntimeControlStatus` |
| `ModelStreamingHealth` | `RuntimeHealthRequest` | `RuntimeHealthResponse` |

Failure policy: every failure is an error reply with a gRPC-style code (`INVALID_ARGUMENT`, `FAILED_PRECONDITION`, `UNAVAILABLE`, `DEADLINE_EXCEEDED`, `RESOURCE_EXHAUSTED`, `UNIMPLEMENTED`, `INTERNAL`); nothing becomes a decision. A frame that is not JSON, or has no integer `id`, ends the session without a reply. A reply over 1 MiB becomes `RESOURCE_EXHAUSTED`. End of input (port closed, browser gone) stops the runtime before the process exits. The worker rejects an empty layer list (`INVALID_LAYERS` becomes `INVALID_ARGUMENT`), so a request can never run the full pipeline by omission.

### Worker and sandbox

`worker.rs` holds the W1 frame codec and the pool `Protocol`; `runtime.rs` the lifecycle (enable, disable, status, cancel on stop); `python/worker_shim.py` adapts the pool's `u32` framing to the W1 worker's pipe descriptors and lets the worker read the controller's cache layout (`<cache>/<model_id>/<pin>/`) read-only. W3 has a similar shim; reconcile the two when both merge. The pool runs one worker under `SandboxPolicy`: dies with the controller, 6 GiB memory limit (`PRIVOKE_WORKER_MEMORY_MB`, 0 for none), at most 8 processes, a clean environment limited to named variables (no credentials). Network denial is enforced on Linux only; on Windows none is claimed. Analysis deadline 27 s (`PRIVOKE_RUNTIME_REQUEST_TIMEOUT_SECONDS`), worker start 30 s (`PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS`). The Linux code path was not compiled or run here.

**Routing (stage 17).** `routing.rs` sends each call to the worker that serves it. With `PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust` the controller starts a second pool, `privoke-runtime-worker` (beside the supervisor, or `PRIVOKE_RUNTIME_RUST_WORKER`), under the same sandbox policy, environment allow-list and deadlines; `AnalyzePrompt` for the regex and NER layers goes to it and everything else to the Python worker. The default (`python`) starts no second pool. Details and the table are in [`privoke-runtime`](#privoke-runtime-stage-17).

### Tests

`tests/controller_session.rs` (16) runs the real host process against a stand-in worker (`privoke-supervisor-test-worker`, `test-helpers` feature): round trip, fail-closed errors, layer pass-through, malformed frames, concurrency, closing the port and killing the controller both kill the worker, crash, hang deadline, start failure, oversize, no listening socket. `tests/real_worker.rs` runs the real Python worker (skips without the runtime virtual environment). `tests/health.rs` ports the model-health tests. 18 unit tests; fetch and enrolment tests are unchanged.

### Model fetch

`fetch.rs` ports `v3_package.fetch_package` and `receive_asset`, with the same cache layout and rules, so the Python runtime and the supervisor share one cache (`MODEL_PACKAGE_CACHE_DIR`, else `%LOCALAPPDATA%\PriVoke\model-packages` or `$XDG_CACHE_HOME/privoke/model-packages`). The channel (`channel.rs`) is plaintext only to a loopback target (the local development stack, as in Python); every other target needs mutual TLS with the installation certificate (`PRIVOKE_TLS_CERT_FILE` and key, else `client.crt` and `client.key` in the credential directory) and a pinned server CA (`PRIVOKE_TLS_CA_FILE`, else `server-ca.pem`); there is no system-roots fallback. `PRIVOKE_MODEL_STREAMING_TLS=true` keeps mutual TLS on loopback, which a locally run Rust model-streaming needs.

Checks, in order: the manifest bytes hash to the pin compiled into the client and satisfy the manifest contract (`privoke_contracts::v3`); the response names that model and pin; exactly the four assets are declared, with the manifest's hashes and `0 < size <= 80 MiB`; each asset stream keeps its model, pin, name, hash, total, offset and chunk bounds, ends at the declared size and hash, and is written to a temporary file that is renamed only when complete; the manifest is read again after the downloads and must be identical; the directory is re-read and re-hashed. An existing cached file is re-hashed and never overwritten; the cache path must not traverse a link. `manifest.json` is written last, so an interrupted fetch never looks complete.

One deliberate difference from Python: the request's `consumer_id` is the installation UUID (or empty), not `MODEL_STREAMING_CONSUMER_ID` (default `client-runtime`), because the Rust public listener refuses a `consumer_id` that is not the caller's own identity. The test `the_server_binds_the_caller_and_the_registry_decides_who_may_fetch` shows `client-runtime` being refused.

Tests run an in-process `privoke-model-streaming` on certificates generated at test time, and fetch the real pinned releases (read from the main checkout's ignored `models/standard-releases`; skipped when absent). A scripted server with a synthetic pin set breaks each rule on its own: a flipped byte, 12 stream manipulations, a forged manifest, response identity, 7 asset-declaration manipulations, a manifest that changes during the download, a corrupted or foreign cached file, a link in the cache path, server errors and family confusion.

### Lineage and signature admission (stage V3-R4a)

> Plan: [V3 routine training](../plans/v3-routine-training.md#stage-v3-r4a-client-lineage-and-signature-admission). Rule and persistence: [V3 publication](v3-publication.md#client-admission).

- **`privoke_contracts::v3::admit_lineage`** (with `LineageError`, `LineageState`, `LineageAdmitted`) is the client rule for a trained version; `admitted_manifest` stays pin-only (release directories); the model loaders use it for those and the lineage rule for a cache directory since V3-R4b (below). The tier pin and the high-water statement come from a `LineageState`, so tests can name the toy ORIGINAL of the shared fixtures as the pin.
- **`fetch::LineageAdmission`** implements `Admission` over it. `Admission` gained two defaulted methods (`admit_published`, `accepted`), so `StandardAdmission` and the golden's `SyntheticAdmission` are unchanged. The `Fetcher` hands the response's `publication_statement` to the admission, keeps the statement beside the version as `statement.json`, and records the mark only after the package is complete and verified. `FetchError::is_transient` is true for `UNAVAILABLE` and `DEADLINE_EXCEEDED`. `privoke-supervisor fetch-model` uses `LineageAdmission::production`: the compiled key set (`privoke_contracts::publication::PRODUCTION_KEYS`, empty until the first publication key exists, so a build admits nothing signed) and the compiled tier pins. `test-keys` reaches the supervisor only through its dev-dependencies (a CI step checks `cargo tree`); `LineageAdmission::with_pins` exists only with `test-helpers`.
- **Tests.** `tests/lineage_chain.rs` runs 25 rows of the shared signed-chain fixtures through `admit_lineage` (the eleven forged variants, downgrades, an unsigned trained version, no compiled key, the toy chain against the compiled pin, the rollback, both rotation keys). `tests/lineage_fetch.rs` runs the real `Fetcher` against a scripted server with a synthetic chain on the efficient tier (official `config.json` and `vocab.txt`, stand-in weights): the chain with its persisted statements and mark, replay, conflict, downgrade, bad signature, unknown key, foreign ORIGINAL, restart re-verification (cached versions and mark, a dropped key, a tampered mark), `UNAVAILABLE`, and a statement that changes during the download. `fetch_golden.rs` is unchanged. Every row is appended to `PRIVOKE_LINEAGE_ROWS_OUT` and judged by `python evaluation/update_security.py --target rust --rust-service client-lineage --lineage-rows <file>` (CI runs both; without `--lineage-rows` the target runs `cargo test` itself).

### Refresh, snapshot reload and cache housekeeping (stage V3-R4b)

> Plan: [V3 routine training](../plans/v3-routine-training.md#stage-v3-r4b-refresh-snapshot-reload-and-cache-housekeeping). Design and rules: [V3 publication](v3-publication.md#loading-from-the-cache).

- **`privoke_contracts::model_cache`** (new) is the cache as every reader sees it: `CacheRules` (compiled keys and tier pins; `with_pins` only with `test-keys`), `ModelCache::{read_high_water, versions, select, lock}`, `Selected`, `ModelLock`. `read_high_water` is the V3-R4a mark logic (a mark under a dropped key is a floor, a missing mark is rebuilt from the cached statements, a tampered one fails closed), moved here from `LineageAdmission` so that the worker applies the same rule. `ModelCache` implements `LineageState`.
- **How the worker learns its version.** It is not told. `SemanticLayer::locate` calls `ModelCache::select` on every load of a standard V3 id in the controller's cache layout: the version the mark names (statement re-verified, sequence and manifest equal to the mark's), or the pinned release while there is no mark. `V3Model::load_published` (`privoke-semantic`) then admits the manifest bytes by `admit_lineage` under the compiled keys and the mark before it reads an asset. The worker's per-id model cache is keyed by the manifest hash, so the snapshot is reloaded on the first request after the supervisor moves the mark, with no message and no restart. `SemanticLayer::with_cache_rules` replaces the keys and pins (tests). A release directory (`<root>/<id>/manifest.json`) and non-standard ids keep the pin-only path.
- **`refresh::Refresher`** (supervisor): `refresh` fetches one model through the `Fetcher` and `LineageAdmission` and then collects garbage; `run` does it for a list of models at start and every interval. `V3_PACKAGE_REFRESH_SECONDS` (default 3600) sets the interval and `V3_PACKAGE_REFRESH_MODELS` lists the models; with no models there is no loop, and `native-host` starts the loop on its runtime when models are listed. Outcomes: `Unchanged`, `Updated`, `Offline` (transient failure or no connection), `Refused`. Nothing but a complete, admitted version ever changes the cache's current version.
- **Mark writes and garbage collection** take the advisory lock `<cache>/<model>/.lock` (`std::fs::File::lock`) and re-read the mark under it. `LineageAdmission::collect_garbage` deletes the versions whose verified statement is below the mark's (renamed to `.gc-*` first), never the compiled pin or the version at the mark. `Fetcher` forgets an in-process verification whose directory is gone.
- **Tests.** `tests/lineage_fetch.rs` (rows RB1-RB5, judged by `evaluation/update_security.py --rust-service client-lineage`): refresh after the interval, offline restart, garbage collection, the signed mark against the cache, a deterministic lock test and two concurrent writers. `runtime/tests/published_cache.rs` runs the worker's `SemanticLayer` over a cache of the shared signed-chain fixtures (which version is selected, no fallback to the pin, a newer version without a restart); `privoke-semantic/tests/v3_published.rs` runs the loader's own admission. The positive load of real signed weights is not in CI: it is the `load_release` path (`release_parity`, `v3_release`, which need the real releases). `fetch_golden.rs` and the V1 and V3 analysis goldens are unchanged. CI also checks that `test-keys` is absent from the `privoke-runtime` and `privoke-semantic` builds.

### Telemetry (stage 18 wired in, RUST-S17B)

`telemetry.rs` makes the controller the owner of the stage 18 `TelemetryReporter`; the inference worker has none (it has no network and `WORKER_ENVIRONMENT` passes no telemetry or TLS variable). After an `AnalyzePrompt` result has passed through the controller (`Controller::dispatch`), `Telemetry::observe` decodes the response, maps it with `analysis_input` to an `AnalysisInput` and calls `report` on a blocking thread (`spawn_blocking`, at most 2 s of waiting for the ledger transaction; the delivery itself never delays the reply). `Telemetry::close` runs when the session ends.

- **What reaches a report.** The action name, the sensitivity and category names of the evidence's classification, and the evidence's `model_version` metadata. The text, spans, request id, reasoning and every other metadata value never enter an `AnalysisInput`, and the packet has seven fields, all drawn from fixed domains.
- **What is not reported.** An error reply (the worker refused, the runtime was stopped, a deadline passed), and a response with neither evidence nor a layer execution (what the Python servicer returns from its exception path, which does not report either). A response whose layers all failed is reported like any other result, as in Python.
- **Configuration**, names and defaults of `grpc_main.py`: `TELEMETRY_ENABLED` (only `1`, `true`, `yes`, `on` enable it), the target of the stack (`PRIVOKE_CLOUD_TELEMETRY_TARGET`; `PRIVOKE_LOCAL_TELEMETRY_TARGET`, default `127.0.0.1:50055`, with the local stack; `TELEMETRY_TARGET` in internal mode; no fallback to the model target), `TELEMETRY_LDP_EPSILON` (1), `TELEMETRY_LDP_DAILY_EPSILON` (8), `TELEMETRY_PRIVACY_LEDGER_PATH`, `TELEMETRY_TIMEOUT_SECONDS` (1), `TELEMETRY_QUEUE_SIZE` (1024). Off when unconfigured or without a target. A configuration that cannot start a reporter (a bad number, a non-loopback target without the reporter credential files, an unwritable ledger) leaves telemetry off, prints the reason on stderr and keeps the controller running; Python's runtime would crash on a bad number, which is the one deliberate difference.
- **Tests.** `tests/controller_telemetry.rs` drives a `Controller` over the real pool and the stand-in worker with a scripted `PacketTransport`: three analyses give three reports whose fields all lie in the fixed domains (the test destructures `TelemetryPacket` without `..`) and never contain the request text or id; a controller without a reporter, and every environment that leaves it off, send nothing; a refused analysis and one after the runtime stopped are not reported. Unit tests cover the target rules, the settings and the response mapping.

### Parity with the Python fetch (D11, RUST-S17B)

The Python fetch (`v3_package.fetch_package` and `receive_asset`; the legacy `parameter_stream.ModelParameterStreamer`) is the oracle. `evaluation/generate_model_fetch_golden.py` runs both unchanged against an in-process fake client (no socket) and writes `tests/fixtures/model_fetch_golden.json`; `evaluation/tests/test_generate_model_fetch_golden.py` checks and regenerates it.

- **V3 package** (a synthetic pin set, so each rule can be broken alone; the real pinned manifests are covered by the end-to-end tests on the prepared releases). 29 cases: an honest fetch (by `latest` and by name), a complete cache, a corrupted cached asset, a differing cached manifest, a manifest that is not the pinned one, a wrong pin and a wrong model id in the response, a missing, an extra and a duplicate asset, a wrong hash, a zero and an oversize declared size, eleven manipulations of the asset stream, a manifest that changes during the download, and three family confusions. `tests/fetch_golden.rs` fetches each case with the Rust `Fetcher` and compares what Python left: the cache directory (names, SHA-256 and size of every file), the temporary files left, the order of the asset requests, the number of `GetModelPackage` calls, the consumer id sent, and the refusal text byte for byte.
- **One difference found and fixed.** Python downloads the assets in the order the server declares them; the Rust fetch iterated a sorted map, so after a refused asset a different set of (verified) files remained. It now iterates `package.assets` in declared order.
- **The legacy stream writes no cache in Python**: the client keeps the snapshot in memory, so there are no legacy cache bytes to compare. The content is compared: for each tracked legacy model the golden records what the Python client holds (version, timestamp, checksum, every tensor's name, shape, count and float32 digest), and `rust/services/analysis/tests/fetch_golden.rs` has the real Rust model-streaming serve the same four models to the analysis `ModelCache` and compares the tensors of its cached `<id>.snapshot.pb` (4 of 4). Ten synthetic snapshots that break one rule each (shape mismatch, NaN, plus and minus infinity, unnamed tensor, zero dimension, empty shape, no version, no timestamp) are refused by `validate` exactly as by Python; five refusals that exist only in a chunk stream have no unary form and are recorded as Python behaviour only.
- **Known differences (no decision changes).** The analysis service uses the unary `GetModelParameters`; `validate` also requires strictly increasing tensor names, a 64-hex `artifact_checksum`, a version of at most 128 characters, at most 65,536 values and (when configured) a pin. Python's scratch-presence stream guard is not ported. Python creates only the last directory of the cache path with mode 0700, the Rust fetch every directory it creates (stricter; contents unaffected).

### Not in this stage

The installed-client claims (C5, C6, C42) are not claimed for this build. The telemetry reporter is wired in above.

## `privoke-analysis` (stage W3)

Plan: [stage W3](../plans/rust-server-rewrite.md#stage-w3-quarantined-analysis-microservice-for-the-fuzzer). `rust/services/analysis` is the quarantined analysis microservice for the fuzzer: a thin tonic service with in-service mutual TLS (`privoke-transport`, the stage 2 registry) that owns a `privoke-worker-pool` of W1 Python workers. It runs no analysis of its own and holds no publisher credential.

```
cargo test -p privoke-analysis --locked --manifest-path rust/Cargo.toml                       # unit tests, model cache, start-up refusal
PRIVOKE_ANALYSIS_TEST_PYTHON=<python with the client-runtime requirements> \
  cargo test -p privoke-analysis --locked --manifest-path rust/Cargo.toml                     # adds the real-worker scenarios
```

Without `PRIVOKE_ANALYSIS_TEST_PYTHON` the two real-worker tests print that they are skipped and pass. `evaluation/.venv-v1-v3-pipeline` is a suitable interpreter on the development host.

### What it serves, and to whom

| Layer | Rule | Result |
| --- | --- | --- |
| Transport policy | The six `PrivokeRuntimeService` RPCs (`AnalyzePrompt`, `DetectAnnotationPresence`, `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients`, `ComputePresenceGradients`, `Health`) for the `publisher`, `trainer` and `runtime` registry roles | Any other path, including every publisher RPC and the model RPCs, is `UNIMPLEMENTED`. An installation or the reporter is `PERMISSION_DENIED`. A missing or untrusted client certificate fails the handshake. |
| Service allow list | Only the service names in `ANALYSIS_ALLOWED_SERVICES` (default `fuzzer`) | Another registered service, and the service's own model credential, get `PERMISSION_DENIED`. `ANALYSIS_HEALTH_SERVICES` names identities that may call `Health` only (the container's own probe). |
| Layer selection | Every layer-bearing request must name exactly `[DETECTION_LAYER_SEMANTIC]` | An empty list, regex, NER, the whole pipeline, or a mixed list is `INVALID_ARGUMENT` before any worker sees it. The fuzzer's own `_validate_requested_execution` therefore holds through the service. |

There is no `fuzzer` value in the `Role` enum. The fuzzer is a registered service (`urn:privoke:service:fuzzer`, role `publisher`, because it also publishes updates), and "fuzzer only" is the service-name allow list on top of the role policy. The transport crate is unchanged.

### Responses are the worker's bytes

The worker serialises each response with deterministic map order, as the gRPC server does. Decoding that into a Rust message and encoding it again is not byte-faithful: `prost` leaves out a map entry's value when it is the default (a `0.0` metric), where Python writes it, and that cost 54 bytes in the first gradient response. So `src/raw.rs` serves the service over a pass-through codec: the request bytes reach the worker as the client sent them, and the worker's response bytes reach the client as the worker wrote them. Only `Health` is built here.

### Models

The worker has no network, so the service fetches models and the worker reads them.

- **Fetch.** `GetModelParameters` on the model-streaming internal listener, over mutual TLS, with the service's own `runtime` certificate (`urn:privoke:service:analysis`). The empty id and `latest` mean `ANALYSIS_DEFAULT_MODEL_ID` (default `privoke-balanced`), because `latest` on model-streaming resolves to a V3 package.
- **Checks.** The identity returned is the one requested; version and timestamp are present; names are strictly ordered, shapes positive, value counts equal the shape, all values finite, at most 65,536 values; `artifact_checksum` is present; and, for an id in `ANALYSIS_MODEL_PINS` (`id=sha256,...`), it equals the pin. A refused model is `FAILED_PRECONDITION` and is never written.
- **Cache.** The checked response is stored as `<model_id>.snapshot.pb` in a named volume (`ANALYSIS_CACHE_DIR`), replaced atomically, and fetched again when it is older than `ANALYSIS_MODEL_TTL_MS` (default 1000), so a published update reaches the worker within about two seconds, as with the old runtime's one-second cache. If model-streaming is unreachable the cached snapshot keeps serving and the failure is logged; with nothing cached the call is `UNAVAILABLE`.
- **Worker side.** `python/worker_shim.py` runs the unchanged W1 worker in-process and swaps its model provider for one that reads those snapshots and builds exactly the `ParameterSnapshot` the streaming client builds. The worker's own artifact and V3-package readers stay as the fallback. The worker never writes a model root; nothing but its code stops it writing the cache volume inside the container, so the guarantee is the worker's code and the read-only root, not a separate read-only mount.
- **Not served.** V3 packages (`privoke-v3-*`) are not fetched: they need the public listener and a `consumer` credential. A request that names one gets the worker's own error text inside the response. The W1 gradient RPCs do not serve V3 packages either.

### Worker and pool

`python/worker_shim.py` also adapts the pool's framing (a 4-byte little-endian length, then the frame) to the W1 worker's 20-byte-header frames on two dedicated pipes, in one process, so the pool and the W1 protocol are both used as specified. The pool returns an answer as text, so a response travels base64-encoded between the two. The sandbox policy is `deny_network`, a clean environment and the worker's `PRIVOKE_WORKER_SANDBOX=1` socket self-check; the interpreter is the virtual environment's own (`PYTHONHOME` would override its `pyvenv.cfg` and hide `site-packages`). No address-space or `RLIMIT_NPROC` ceiling is set: torch maps large ranges and the container's cgroup memory and pids limits are the controls. The pool has one deadline, the longest gradient deadline plus a grace (330 s), so a hung analysis request holds its worker that long; the worker's own cooperative deadline (25 s for analysis) normally ends it first.

On a Windows host the worker's socket self-check cannot pass (W2 provides no network denial there), so the Rust tests run with `require_sandbox` off on Windows and on in the container. The container is the quarantine.

### The Rust analysis worker (stage 17 follow-up, RUST-S17D)

`ANALYSIS_RUST_WORKER` (the `privoke-runtime-worker` executable) adds a second pool beside the Python one. `ANALYSIS_RUST_MODEL_ROOT` is optional and defaults to the service's own `ANALYSIS_CACHE_DIR`; `ANALYSIS_RUST_BUNDLE` and `ANALYSIS_RUST_PRETRAINED_CONTEXT_DIR` are optional too (`config::RustWorkerSettings`), and any of those three without the worker is a configuration error. Unset, the service is what it was: one Python pool. The Rust pool has the same sandbox, memory and process limits, queue and deadlines as the Python pool, warms no layer, warms the start-up models only when its root is the cache, and the service reports `SERVING` only while both pools are ready.

Each call is routed per request by `privoke_supervisor::routing` (`route_analysis`, `route_presence`, `route_gradients`, with the Rust claim `Capabilities::RUST.with_semantic()`) and made through `routing::call_routed`: a call the Rust worker declines before executing anything (`UNSUPPORTED_ROUTE` or `UNSUPPORTED_LAYERS`) is sent once to the Python pool, and every other failure is the call's result (never retried on the other engine). A repeated or non-text admission header, a scratch presence model and a gate on one are the Python worker's. The semantic-only rule is checked before routing, so the Rust worker only ever sees `layers=[SEMANTIC]`.

**The model root (RUST-S17E).** The service stores each fetched model as `<id>.snapshot.pb` (the `ModelParametersResponse` it checked), replaced atomically, and the Rust worker now reads that file (`privoke_runtime::snapshot`, used by `ArtifactStore`, `PresenceModels` and `SemanticLayer`): a model a training cycle publishes reaches the Rust pool through the file the service already writes, and the worker, like the Python shim, prefers a snapshot to an artifact file or package of the same id in any root. Reading the snapshot was chosen over writing a `<id>.json` for the worker because the artifact file cannot be rebuilt from a snapshot: its float64 values, its bytes (`artifact_file_checksum`) and the checksum over its contents are gone, so a rebuilt file would have an identity different from the Python worker's. The snapshot's metadata is used verbatim, as the Python provider does (`artifact_checksum`, `artifact_file_checksum`, `model_config`, `trainable_parameters`, and the presence keys), the identity and the tensors are the response's float32 values, and what the model code reads as JSON (`config` from `model_config`, the tensors with `trainable` from the manifest, `checksum`) is rebuilt from them. The checksum over the file contents is not recomputed (the service has checked the snapshot, as the worker does not recompute it for Tiny artifacts). Snapshots of the pretrained contextual model are not served through `Artifact` (as for files); `SemanticLayer` would read one.

Tests (CI): `snapshot` unit tests and `runtime/tests/snapshot_models.rs` (every readable worker fixture as a file and as a snapshot built the way model-streaming builds its response: identity, metadata, tensors, the JSON for training, semantic results and the presence model equal, the snapshot read first, a damaged one an error), `analysis/tests/rust_snapshot.rs` (the four tracked models fetched from the real model-streaming over mutual TLS into the cache, then read by the Rust worker's readers and compared with the artifact files they were served from: all identity fields, every file metadata entry unchanged and only `consumer_id` and `served_by` added, tensors and shapes equal, the training JSON equal after float32 narrowing, semantic results equal on three texts for each model and `latest`), `config` (the three variables, the worker with the default root, a root without the worker) and `service` unit tests (the engine chosen for each RPC with and without a Rust pool, header cases, scratch presence, only a refusal moves to Python, and `call_routed` tries Python once after a refusal and never after a failure). No worker process is started by these tests (not even a gradient request through the snapshot path: the training code is covered through the equality of the JSON it reads); the real-worker scenarios of `tests/service.rs` still run the Python pool only.

### Compose

Since stage 8a the analysis services (`analysis-service`, `analysis-model-streaming`) and the fuzzer override belong to `docker-compose.prod.yml` under the `legacy-training` profile; the former `docker-compose.analysis.yml` overlay is gone. The test-only gateway overlay layers over the production file:

```
docker build -f extension/client-runtime/Dockerfile --target runtime -t privoke-client-runtime-base:local .
PRIVOKE_PKI_DIR=<dir> docker compose -f docker-compose.prod.yml -f docker-compose.analysis-test.yml \
    --profile legacy-training up -d --build
```

`PRIVOKE_PKI_DIR` names a directory laid out as `docker-compose.prod.yml` describes, made by `privoke-pki` (`server-ca.pem`, `client-ca.pem`, `live/{crl.pem,registry.toml}`, `server/server.{crt,key}`, `svc/{probe,param-update,fuzzer,analysis}.{crt,key}`); the test builds one per run and deletes it. The server certificate must carry the names `analysis-service`, `analysis-model-streaming` and `privoke-fuzzer`. The analysis image is built on the client-runtime image (`PRIVOKE_PYTHON_RUNTIME_IMAGE`), so the worker runs on the dependency set of the runtime it replaces.

| Service | What it is |
| --- | --- |
| `analysis-service` (profile `legacy-training`) | Networks: only `analysis-fuzzer` and `analysis-models`, both `internal: true`, so there is no route out and no published port. `read_only: true`, a `/tmp` tmpfs (`noexec,nosuid,nodev`), user 10001, `cap_drop: [ALL]`, `no-new-privileges`, Docker's default seccomp profile (never `unconfined`), `mem_limit` and `memswap_limit` 3 GiB, 2 CPUs, `pids_limit` 256. The model cache is the named volume `analysis-model-cache`. |
| `analysis-model-streaming` | The stage 3 Rust service on `analysis-models`, reading the same `model-data` volume the param-update service writes, read-only. |
| `privoke-fuzzer` (override) | `PRIVOKE_RUNTIME_TARGET=analysis-service:50054` with the fuzzer's service certificate, so the unchanged stage 6 `service_channel` speaks mutual TLS to it; the dependency on the plaintext `client-runtime` is removed. Its own listener gets server credentials (stage 6) and admits the fuzzer and the test driver. |

`docker-compose.analysis-test.yml` adds two test-only pieces, never part of a deployment (see the file's header): a TCP gateway that publishes three loopback ports, because a host cannot reach a container whose only networks are `internal: true` (TLS stays end to end and the gateway holds no credential), and, until stage 5, `param-update-front`, a TLS front for the Python param-update server. Stage 5 removed it: the overlay now runs the Rust parameter-update service, which terminates mutual TLS itself, and the fuzzer's `training/parameter_updates.py` uses `service_channel`.

### Checks

Driven from the host; nothing runs through `docker compose run`.

```
python -m unittest rust/services/analysis/tests/test_container.py -v     # hosts the stack, then probes it from the host
```

Results of the run recorded in the plan (17 November 2026, Docker Desktop on Windows 11, torch 2.11.0+cpu in both the host virtual environment and the container image):

| Plan check | Where it is checked | Result |
| --- | --- | --- |
| Responses match the W1 pipe responses | `tests/service.rs` (host, Windows) and `test_container.py::ParityTests` (container) replay the 22 recorded semantic-only `AnalyzePrompt` cases of `tests/conformance/worker-frames/analysis.json` | all 22 digests equal, in both places |
| Gradient parity | `tests/replay.rs` replays the 9 recorded gradient and presence cases of `training.json` with the capture's own models (the prepared full-encoder release and a presence release), over the pass-through codec; `ParityTests` repeats a head-gradient call in the container | 9 of 9 byte-identical (semantic, underlying full-encoder, presence detect, presence gradients, the admission-header cases). The tenth case (wrong layers) is `INVALID_ARGUMENT` by design. No float tolerance is needed |
| Access | `AccessTests`, `tests/service.rs` | the fuzzer is served; another registered publisher, the service's own `runtime` credential, the test driver and an installation get `PERMISSION_DENIED` on analysis, gradient and presence RPCs; `ParamUpdateService` and `ModelStreamingService.GetModelParameters` and `FuzzerService` are `UNIMPLEMENTED`; no certificate or a certificate from another CA cannot connect |
| Quarantine | `QuarantineTests` | outbound connections to three addresses and a name fail from inside the container; the root and the code directories are not writable, `/tmp` and the cache volume are; the worker's READY frame says `sandbox_self_check: passed` and `telemetry: disabled`; `docker inspect` shows the hardening above; both networks are `internal: true` and the container has no published port |
| Semantic-only | `SemanticOnlyTests` | empty, regex, NER, runtime and mixed selections are `INVALID_ARGUMENT` for every layer-bearing RPC; the fuzzer's own `PrivokeRuntimeClient` (unchanged, over `service_channel`) completes a semantic call and raises for the others |
| Models with a read-only root | `QuarantineTests` | the service was healthy and answering with `read_only: true`; the cache is on the volume |
| Training cycle | `TrainingCycleTests` | `RunTrainingCycle` (32 prompts, seed 1) through the fuzzer, with the analysis service as its only runtime: accepted, `v0.3.0` to `v0.3.0+train.1`, weights changed, and the analysis service's cache followed to the new version without a restart |
| Drivers on the host | all of the above | `docker compose up` hosts the stack; no `docker compose run`; `docker exec` is used only for the in-container probes |

Unit and component checks: `cargo test -p privoke-analysis` is 17 unit tests, 4 model-cache tests (mutual-TLS fetch, checks, pins, update, outage, unregistered caller), 2 service tests and 1 replay test with a real worker (skipped without `PRIVOKE_ANALYSIS_TEST_PYTHON`), and the container module is 15 tests.

Findings and limits:

- **Stage 3 refuses what `bootstrap.py` writes.** `services/param-update-service/app/bootstrap.py` always rewrites the tracked `privoke-balanced.json` as a prepared full-encoder release (`v0.4.0-full-ctx256-...`, 908,225 bytes). The Rust model service rejects it (`artifact checksum does not match its contents`), although Python's own `artifact_checksum` of the file equals the stored value and every float token in it round-trips through `privoke_contracts::pyfloat::repr`. The cause is not found. The test stack therefore starts param-update without the bootstrap, with `FUZZER_TRAIN_UNDERLYING=false`, and serves the tracked artifact, so the cycle it runs is the head-only one. The full-encoder (`RunUnderlyingTrainingCycle`) path through the service is covered by the byte-identical gradient replay, not by a cycle. Stage 3 should reproduce this with the file in the `model-data` volume before the cutover (the file is regenerated by `docker compose up` of the production file).
- **The fuzzer cannot use its default sampler here.** `audience_coverage_v1` needs the pinned AU3 manifest, which neither the production file nor the repository supplies, so the test overlay sets `FUZZ_CONTEXTUAL_SAMPLING_STRATEGY=legacy_random_v1`, as `evaluation/compose.legacy-ci.yml` does for the historical V1 topology coverage.
- **A process-wide channel policy and two plaintext channels.** `service_channel` uses mutual TLS for every target once the fuzzer holds a certificate, while `training/parameter_updates.py` and `training/window_evidence.py` keep `grpc.insecure_channel` (G6 paths). The window-evidence path to the runtime is therefore plaintext and would not reach this service; the cycle paths that go through `runtime_client` do. The param-update front in the test file is the stand-in until stage 5.
- **V3 packages are not served** (see above). The fuzzer's default `MODEL_ID` in the production file is `privoke-balanced`, so nothing it sends names one.
- **One deadline.** 330 s for every method, as above.
- **The worker can write the cache volume** if its code were compromised; the root, the code and the interpreter are read-only and the worker has no socket. A second, read-only mount of the volume for the worker would need a separate container, which the pool does not support.
- **Windows.** The Rust tests pass on Windows with `require_sandbox` off; the container is where the sandbox self-check and the network denial are exercised.
- **Gaps in the checks.** The in-container run does not replay the gradient digests (the training models are not in the stack's volume), and the quarantine probes use `docker exec`, whose process is not under the worker's seccomp filter; the worker-side denial is shown by the worker's own `sandbox_self_check: passed` (it tried TCP and UDP sockets and was refused) and by W2's Linux test.

## `privoke-ner-layer` (stage 13)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-13-ner-layer-and-post-filter-in-rust-d1).

`privoke-ner-layer` ports the NER layer of the client runtime (`extension/client-runtime/src/NER`) onto the stage 11 spaCy worker. It reuses `privoke-rules` for the preprocessing (`normalize_with_offsets`, the offset maps and the three robustness flags) and for Python's text semantics (`pyre`, `pyunicode`). Offsets are code point indexes, as in Python; spaCy's own offsets are code points too.

| Module | Python source |
| --- | --- |
| `detector` | `ner_detector.py`: `EntityNERDetector`, the caseless gate (`PRIVOKE_NER_CASELESS_GATE`, default off) and the post-filter switch (`PRIVOKE_NER_POSTFILTER`, default on). |
| `postfilter` | `ner_postfilter.py`: both stages, the five span rules, the eight combination rules, the context cues, `has_case_signal`, `fold_case`, `CASELESS_DISABLED_RULES`, and the lexicon from the model's `lemma_index`. The decision log (rule, stage, candidate, outcome) is returned with the results. |
| `usecases` | `use_cases.py`: PERSON, GPE, LOC, FAC and ORG with their packed classification and confidence. |
| `pattern` | `pattern_entity_detector.py`: cues, shapes, optional gazetteer, recurrence, and the hybrid `augment_entities`. It needs no spaCy and is not wired into the pipeline in Python either. |
| `layer` | The NER path of `pipeline.analyse_text(text, layers=["ner"])`: case-preserved normalisation (or the lowercased view when case preservation is off), detection, and remapping of spans to the original prompt, with the same `error` outcome for a normalisation failure. |
| `analyzer`, `replay` | The `SpacyBackend` trait (implemented for `privoke_spacy::SpacyPool`), a replay of recorded spaCy results for the tests, and a per-document cache for the parity runs. |
| `pytext`, `unicode_tables` | `isalpha`, `isupper`, `islower`, spaCy's `is_punct` and `str` helpers, from tables generated from the reference interpreter (Unicode 14.0.0, the same version as `privoke-rules`). |
| `pat` | Python patterns on top of `privoke_rules::pyre` (below). |

The post-filter reads spaCy only through `SpacyBackend`: `analyze(text, Selection::Full)` for the entities, the tokens and the dependency parse (`Span.root` is recomputed from the token heads exactly as spaCy does, including its special case for punctuation and space tokens), `analyze(phrase, Selection::TaggerOnly)` for the common-word rule, and `lemma_index()` for the lexicon.

### Patterns that name a non-ASCII character

`PyRegex` accepts only ASCII (plus a few preserved characters) in a pattern, and the NER patterns name the en dash, the em dash, the bullet and `é` (`[:\-–]`, `[–—\-]`, `[-*•]`, `fianc[ée]e?`). `privoke-rules` is not changed for this; `pat` handles them in this crate:

- **Dashes and bullet.** For each of them that the text holds, the pattern and the text are relabelled with one ASCII punctuation character that occurs neither in the text nor as a literal in the pattern (the sentinel stays "other", like the dash). A kind that the text does not hold needs no sentinel and its class member is dropped. When the text holds a dash and every one of the 24 candidates the search returns an error instead of guessing; no recorded set reaches that.
- **`é`.** Only the two relation cues name it. The main pattern holds the unaccented branch (`fiancee?`) and a second pattern holds the accented branch alone with `\w` in the `[ée]` slot; a match of the second counts only if the text has `é` or `É` in that slot. Python's alternatives are different words, so at one start at most one of the two applies, and the leftmost match of the two is the one Python finds.

### Parity with Python

The golden output comes from the unchanged Python runtime and `evaluation/generate_ner_golden.py`. Every run selects the layer explicitly (`pipeline.analyse_text(text, layers=["ner"])`) and asserts that exactly one `ner` layer ran; the regex and semantic layers are never requested and an empty layer list is never sent. The generator wraps `ner_detector.postfilter` to record every decision, and the spaCy pipeline to cache and (for the committed fixture) record every analysis.

Settings per row (`LAYER_CONFIGS`): `default`, `caseless` (gate on), `format`, `digits`, `email` (each robustness flag alone), `all-flags`, `caseless-all-flags`, `lowercase` (case preservation off) and `no-postfilter`. The pattern detector runs in six configurations (`PATTERN_CONFIGS`: default, gazetteer, cues only, shape only, no recurrence, hybrid with the spaCy results as seeds). A run is identical when the results (span in the original prompt, text, packed classification, confidence, reasoning, metadata including `postfilter_rule`) and the decision log (rule, stage, keep, sensitivity, label, span, text and the four cue features of each candidate) agree.

```
# golden, into the ignored evaluation/results/ (read-only access to the datasets of the main checkout)
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_ner_golden.py sets development personalized openai stress fuzz \
    lower-development upper-development ... --data-root "D:/Git Repositories/Privoke-Research-Project" --out evaluation/results/ner-golden-<date>
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_ner_golden.py sets piimb --shard 0 --shards 6 ...   # likewise dolly15k, oasst2
# Rust, through the real worker pool
cargo run --release -p privoke-ner-layer --example parity --manifest-path rust/Cargo.toml -- \
    --worker rust/target/bundle/windows/privoke-spacy-worker.exe --golden evaluation/results/ner-golden-<date> --workers 8
```

The sets are those of the stage 11 gate (`parity_sets.py`, hash-checked, read-only): `development`, `personalized`, `openai`, `piimb`, `dolly15k`, `oasst2` and the synthetic `stress` set, plus a seeded `fuzz` corpus of name, place and organisation sentences built to reach every rule and the `lower-` and `upper-` variants of the three small sets (so that the caseless gate sees prompts with no case signal). `final.jsonl` is never opened. WildChat (the third F2 source) is not covered, as in stage 11.

| Set | Rows | NER layer (9 settings) | Pattern detector (6 settings) |
| --- | --- | --- | --- |
| development | 502 | 4,518 / 4,518 | 3,012 / 3,012 |
| personalized | 2,000 | 18,000 / 18,000 | 12,000 / 12,000 |
| openai | 1,000 | 9,000 / 9,000 | 6,000 / 6,000 |
| piimb | 150,022 | 1,350,198 / 1,350,198 | 900,132 / 900,132 |
| dolly15k | 19,478 | 175,302 / 175,302 | 116,868 / 116,868 |
| oasst2 | 64,592 | 581,328 / 581,328 | 387,552 / 387,552 |
| stress | 40 | 360 / 360 | 240 / 240 |
| fuzz | 4,000 | 36,000 / 36,000 | 24,000 / 24,000 |
| lower-development | 502 | 4,518 / 4,518 | 3,012 / 3,012 |
| upper-development | 502 | 4,518 / 4,518 | 3,012 / 3,012 |
| lower-personalized | 2,000 | 18,000 / 18,000 | 12,000 / 12,000 |
| upper-personalized | 2,000 | 18,000 / 18,000 | 12,000 / 12,000 |
| lower-openai | 1,000 | 9,000 / 9,000 | 6,000 / 6,000 |
| upper-openai | 1,000 | 9,000 / 9,000 | 6,000 / 6,000 |
| **all** | 248,638 | 2,237,742 / 2,237,742 | 1,491,828 / 1,491,828 |

Every cell is identical: results, remapped spans and the post-filter decision log. Zero differences, zero errors. (Windows, Python 3.11.9, spaCy 3.7.5, model 3.7.1, BLIS `haswell`; the Linux bundle is pending.)

Two further checks run in `cargo test --workspace --locked`: the committed synthetic fixture (`tests/fixtures/synthetic_golden.b64`, generated by `generate_ner_golden.py synthetic`: 123 generic prompts, all 9 NER-layer and 6 pattern settings, with the spaCy analyses that Python saw replayed, so no worker is needed; a second test asserts that every post-filter rule decides at least once), and the unit tests of `pytext`, `pat`, `usecases` and `pattern`. With `PRIVOKE_SPACY_BUNDLE=<bundle dir>` the same fixture runs through the real worker (`tests/real_worker.rs`; it skips, and passes, when the variable is unset).

## `privoke-semantic` (stage 14)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-14-semantic-inference-in-rust-d3).

`privoke-semantic` ports semantic inference of the client runtime. Everything in it is LLM-only: it never calls the regex or NER layers, and its results are reported apart from any product-pipeline result.

| Module | Python source |
| --- | --- |
| `v3` | `v3/model.py::PretrainedV3`: the native pretrained BERT of the standard releases with its three affine heads, `load_release` (the pinned manifest, asset hashes and the tensor inventory, as `PretrainedV3.load` checks them), `tokenize`, `forward`, `predictions` and `findings`. |
| `bert`, `safetensors` | `BertModel(..., add_pooling_layer=True)` in inference mode (exact GELU, absolute positions, all-zero token types) and a reader for complete finite float32 safetensors. |
| `tiny` | `model.py::TinyTransformerModel`, `transformer_encoder.py`, `task_readout.py` and `StreamedTransformerPrivacyModel.classify`: hashed word tokens, learned positions, post-norm blocks, both readouts (`legacy_pool_v1`, `residual_task_query_v1`), the artifact JSON loader and its shape and inventory checks. |
| `layer` | The semantic path of `pipeline.analyse_text(text, layers=["semantic"])`: lowercased canonical text (`privoke_rules::normalize_with_offsets`), classification, and remapping of spans to the original prompt, with the layer `error` outcome. |
| `math`, `labels` | The numeric kernels and the label tables and prediction rules shared by both models. |
| `onnx`, `context` | The pretrained contextual encoder (stage 17, RUST-S17B): see [below](#pretrained-contextual-encoder-stage-17). |

### Backend decision

The plan asks for a measured spike over `tch-rs`, `candle` and `ort`, with `tch-rs` the default if it reaches decision parity. **The spike was not run.** Under the CI-first rule no `cargo build` runs on the host, the CI image has no libtorch or ONNX Runtime, and fetching either is a network and supply-chain decision outside this stage. The crate therefore uses a **dependency-free reference backend** (`math`): float32 weights read straight from the checkpoint, float64 activations, one rounding to float32 at the head output. Reasons, in the order they decided it:

1. It builds and runs in the existing CI with no new native dependency (the only added crate is `tokenizers`, below).
2. Parity with torch is bounded by torch's own rounding error. torch float32 differs from the exact (float64) value of the same model by 4e-6 to 6e-6 on the pinned releases (measured below), and by 1.7e-6 to 2.4e-6 between 4 and 1 threads. A float32 backend such as `candle` adds its own error of the same size on top, so two float32 implementations can differ by roughly the sum; a float64 one differs by about torch's error alone. The 1e-5 tolerance is therefore met with a margin of about two on the pinned releases, and it is not met by any float32 backend with a margin that can be promised in advance.
3. It is easy to replace: `Dense::apply` and `attention` are the only kernels. A `tch-rs` backend would need a libtorch download in CI (about 200 MB) and links the process to it; `candle` would add a pure-Rust float32 path; `ort` needs a model export. None of them has been measured here, and the speed of the reference kernels has not been measured either (no Rust benchmark was run). If the paper must quote Torch numerics from Rust, rerun the spike in a CI job that provides libtorch before choosing.

Thread settings: the kernels take a thread count (`V3Model::with_threads`, default 4, the paper's Torch setting). Every row is computed independently, so the count does not change a single bit (tested). The Python golden was made with Torch 2.11.0 CPU, 4 threads.

### Tokenisation

`tokenizers` 0.22.2 is the same crate version as the Python wheel the reference runtime pins (`tokenizers-0.22.2`). `build_tokenizer` rebuilds what `BertTokenizerFast(vocab_file=..., do_lower_case=True)` constructs: `BertNormalizer(clean_text, handle_chinese_chars, strip_accents=None, lowercase)`, `BertPreTokenizer`, `WordPiece` with `[UNK]` and `##`, and `[CLS] ... [SEP]`. The text first goes through `normalize_with_offsets` (NFKC and Python's `lower()`, from `privoke-rules`), so the special tokens cannot occur in the text. The 512-token limit and its message are Python's. Features: `default-features = false, features = ["onig"]` (no progress bar, no C++ unigram trainer); `onig` compiles a small C library, so the CI image's C compiler is used.

The Tiny model's tokens are not WordPiece: `[A-Za-z]+('[A-Za-z]+)?|\d+|[^\w\s]` over `str.lower()`, hashed with SHA-256 (`word_tokens`, using `privoke_rules::pyunicode` for `\w`, `\s`, `\d` and `lower`).

### Parity with Python

`evaluation/generate_semantic_golden.py` makes the golden from the unchanged client runtime and host Python (`evaluation/.venv-v1-v3-pipeline`, read only). Every run selects the layer explicitly (`pipeline.analyse_text(text, layers=["semantic"])`) and asserts that exactly one `semantic` layer ran with status `ok` or `error`; the regex and NER layers are never requested and an empty layer list is never sent. The product's own classes build the models (`PretrainedV3`, `StreamedTransformerPrivacyModel`); only the service fetch is replaced, by hooking `pipeline._detector_for`. Each row holds the token ids, the pooled output, the logits of all three heads, the decision (labels, packed classification, unrounded and reported confidence) and the layer result (span in the original prompt, text, classification, confidence, reasoning, or the error). A row is identical when ids, labels, categories, packed classifications and spans are equal, every logit is within an absolute 1e-5, and the reported confidence is equal (a one-step rounding difference is accepted, and counted, only where the unrounded values agree within 1e-5 and lie within 2e-5 of a rounding boundary).

| Check | Where it runs | Status |
| --- | --- | --- |
| Synthetic V3 release (seeded 3-layer BERT, hidden 32, random heads; 195 prompts including CJK, emoji, accents, specials, a 2,000-character word and two inputs over 512 tokens) through the whole loader | `cargo test` (CI) | 195 of 195 rows identical (ids, decisions, spans; 2 layer errors with Python's message); max logit difference 5.39e-6, pooled 1.44e-6 (CI run 43890561608) |
| Tiny, both readouts, two seeded synthetic artifacts, 195 prompts each | `cargo test` (CI) | 390 of 390 rows identical; max logit difference 1.31e-6 (legacy) and 1.67e-6 (task query) |
| The four tracked legacy models (`models/privoke-*.json`) on the same 195 prompts | `cargo test` (CI) | 780 of 780 rows identical (4 models x 195); max logit difference 3.8e-6 (`privoke-balanced`, `privoke-quality`) |
| The three pinned V3 releases (`models/standard-releases`) on the 195 synthetic prompts, tolerance 1.5e-5 | local only | **pending** (golden made; Rust not run) |
| Recorded sets (development, personalized, openai, stress, piimb, dolly15k, oasst2: 300 evenly spaced rows each, 40 for stress) for three V3 tiers and four Tiny models | local only | **pending** (golden made; Rust not run) |

The synthetic release is generated by `generate_semantic_golden.py synthetic`, byte-reproducibly (a Python test regenerates the safetensors and compares it). It is built with the pinned tiers' file layout and tensor names, so the loader, the safetensors reader, the tokenizer, the encoder and the heads all run in CI without the ignored release store. Its weights are scaled so that the network is as well conditioned as the pinned releases (torch float32 against float64: 4.1e-6; the pinned releases: 4.3e-6 to 6.2e-6). A first version with larger weights had a torch rounding error of 5.8e-5, which no other implementation can match to 1e-5; that is a property of the fixture, not of the port.

Torch's own noise floor on the pinned releases, measured with the same Python environment on 40 of the synthetic prompts (maximum absolute logit difference):

| Release | torch f32 against torch f64 | torch 4 threads against 1 thread |
| --- | --- | --- |
| `privoke-v3-efficient` | 5.97e-6 | 2.38e-6 |
| `privoke-v3-balanced` | 6.23e-6 | 1.67e-6 |
| `privoke-v3-quality` | 4.31e-6 | 2.38e-6 |

The 1e-5 tolerance is thus not a bound that torch itself keeps against the exact value. Running the golden's own model in float64 over the 4,050 recorded rows (2,025 each, efficient and balanced; 7.46e-6 at most for quality) shows 2 of 81,000 logit values above 1e-5 (1.03e-5 and 1.10e-5, on prompts of 86 and 25 tokens). A float64 backend can match torch no better than that, so **the declared logit tolerance for the pinned releases is an absolute 1.5e-5** (`RELEASE_LOGIT_TOLERANCE` in `tests/release_parity.rs`), with the number of values above 1e-5 printed; decisions must still be identical. The synthetic fixtures keep 1e-5 (they are conditioned for it and pass at 5.4e-6).

To run the local checks (the golden is already generated into the ignored `evaluation/results/semantic-golden-20261117/` of the worktree that made this stage; regenerate with the first two commands):

```
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_semantic_golden.py releases --releases-root models/standard-releases
evaluation/.venv-v1-v3-pipeline/Scripts/python.exe evaluation/generate_semantic_golden.py sets development personalized openai stress piimb dolly15k oasst2 \
    --releases-root models/standard-releases --data-root "D:/Git Repositories/Privoke-Research-Project" --limit 300
PRIVOKE_V3_RELEASES=models/standard-releases PRIVOKE_SEMANTIC_GOLDEN=evaluation/results/semantic-golden-20261117 \
    cargo test -p privoke-semantic --release --test release_parity --manifest-path rust/Cargo.toml -- --nocapture
```

Without the two variables the tests write why they skipped to stderr and pass.

### Pretrained contextual encoder (stage 17)

`context.rs` and `onnx.rs` port `src/pretrained_context.py` (`FrozenPretrainedEncoder`, `PretrainedContextModel`): a frozen MiniLM backbone (`all-MiniLM-L6-v2`: 6 layers, hidden 384, 12 heads) and three offline heads (`features @ W + b`, `W` stored `[384][labels]`).

- **Backbone.** Python runs the pinned `model.onnx` in onnxruntime. That file is the plain PyTorch export of a Hugging Face `BertModel`, admitted by its SHA-256 (`BACKBONE_SHA256`), so its graph is the audited one. The port does not interpret the graph: `onnx.rs` decodes the few protobuf messages it needs, takes the constants out by name, and names each anonymous `onnx::MatMul_N` weight after the `MatMul` node that consumes it (`/encoder/layer.3/attention/self/query/MatMul` is `encoder.layer.3.attention.self.query.weight`, transposed from `[input][output]`). Reading the file in the main checkout (its SHA-256 equals the pin) shows 101 initializers: 65 named tensors and 36 matrix weights, epsilon 1e-12, exact GELU, no pooler. Every initializer must be explained; anything else, external data, a non-float32 or non-finite tensor and a duplicate are refused. `bert.rs` gained `Encoder::from_tensors_without_pooler` and `hidden_states`, and runs the V3 computation (float32 weights, float64 activations).
- **Encoder.** The tokenizer is the pinned `tokenizer.json` with truncation and padding switched off, as Python does. Fewer than 2 or more than `max_tokens` (256 or 512 from the artifact) tokens is the layer's error with Python's message; the features are the mean of the last hidden states over all tokens, L2-normalised, rounded to float32 once.
- **Heads and decisions.** Softmax argmax for sensitivity and visibility, sigmoid and `>= category_threshold` (compared in float32, as the pinned numpy 2.2.6 does with a Python float) for the categories; the confidence is the largest sensitivity or category probability. The runtime builds the finding as `StreamedTransformerPrivacyModel.classify` does, with `classifier` `privoke_pretrained_context` and the backbone and tokenizer digests.
- **Admission.** `ContextEncoder::load_directory` reads `model.onnx` and `tokenizer.json` from a read-only directory (regular non-link files of bounded size) and verifies both SHA-256 values before parsing. `load_directory_admitted_by` takes the digests and the backbone configuration as arguments (the product passes the pinned ones; the tests a small synthetic backbone).
- **Golden** (`evaluation/generate_pretrained_context_golden.py`, `tests/fixtures/context_golden.json`, 4 MB). **The reference is not onnxruntime**: the host has none. The backbone is a synthetic export (hidden 384, one layer, 12 heads, intermediate 48, vocabulary 63) written as a real ONNX file with the names of the pinned export; its reference is a numpy float32 implementation of the exported graph. The heads, decision rules and findings are the unchanged Python `PretrainedContextModel.predict` and `StreamedPretrainedContextModel.classify`. The tokenizer is built with the pinned `tokenizers` wheel and carries truncation and padding settings that must be ignored. 14 prompts (a prompt over the encoder's context length, empty text) plus four on heads that decide the empty classification; every decision is at least 1e-3 from a boundary.
- **Real backbone (RUST-S17G, local, Docker).** `tests/context_onnx_real.rs` (env-gated on `PRIVOKE_PRETRAINED_CONTEXT_DIR` and `PRIVOKE_CONTEXT_ONNX_GOLDEN`; skipped in CI) compares the encoder on the pinned `model.onnx` with onnxruntime 1.23.2 (`evaluation/generate_context_encoder_onnx_golden.py`, 31 committed-fixture texts of 2 to 376 tokens): 11,904 features, max difference 1.993e-7, 449 bit-identical, none above 1e-6. The golden is git-ignored under `tests/local/`. Command: `docker run --rm --name s17g-encoder --cpus=8 -e CARGO_TARGET_DIR=target-docker -v <worktree>:/work -v <asset dir>:/model:ro -w /work/rust -e PRIVOKE_PRETRAINED_CONTEXT_DIR=/model -e PRIVOKE_CONTEXT_ONNX_GOLDEN=/work/rust/crates/privoke-semantic/tests/local/context_onnx_golden.json rust:1.99.1-bookworm cargo test -p privoke-semantic --release --locked --test context_onnx_real -- --nocapture`.
- **Results** (CI run 44999560727): features within 1e-6 of the float32 reference (a float64 reference differed from it by 4.5e-8), probabilities within 1e-5, every label, category and the existence of a finding identical; the three context-length errors identical; the digests refuse a tampered, a missing and a non-pinned file. **Not measured:** agreement with onnxruntime on the real `model.onnx` or the real `tokenizer.json`; onnxruntime is installed in no environment on the host. A local comparison on that file is the missing evidence for a real-weights parity claim.

### Not in this stage

- The sparse presence models (`privoke_model/presence.py`, `presence_model.py`) and the scratch-presence model are not ported by this crate (the pretrained-context model is, above). They share the Tiny encoder or a different backbone, but each has its own artifact validation and training contract; they stay in Python until the stage that needs them (stage 17 routes by RPC).
- `reject_overlength` (the strict mode of full-encoder contextual artifacts) and the batch `predict_many` are not ported; one text is classified at a time, as the pipeline does.
- Loading from the model-streaming protobuf (`GetModelParameters`, `GetModelPackage`) is stage 17 (D11). The crate reads a prepared release directory or an artifact JSON.
- The tolerance claim covers CPU float32 torch and NumPy; GPU results differ by more.

## External classifier client (stage 16)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-16-external-classifier-client-d10).

`privoke_semantic::open_*` ports the external (OpenAI-compatible) semantic classifier of the client runtime (`LLM/open_classifier.py`, `LLM/prompt.py`, `classification/external_output.py` and the result building of `classification_results.py`). It is LLM-only and implements the `SemanticClassifier` trait of stage 14, so `analyse_semantic_layer` runs it unchanged.

| Module | Python source |
| --- | --- |
| `open_prompt` | `prompt.py`: `system_prompt` and `user_prompt(text)`. The two long texts are `open_system_prompt.txt` and `open_user_prompt_tail.txt`, generated from the Python constants (trailing spaces included). |
| `open_classifier` | `OpenClassifier.__init__` (`OpenConfig::resolve`: explicit options, then `OPENAI_API_KEY`, `OPENAI_BASE_URL` then `OPENAI_API_BASE`, `OPENAI_MODEL`, `OPENAI_TIMEOUT_SECONDS`, `OPENAI_TEMPERATURE`, `OPENAI_MAX_TOKENS`, same defaults and error texts), the request (`build_request`) and the blocking `reqwest` client (`OpenClassifier`). |
| `open_response` | `classify` after the call and `build_external_results`: strict validation (the exact `{"results": []}` envelope is "no risk"; bare empty arrays, missing fields, unknown enum names, out-of-range confidence and bad spans are errors) and `parse_result` (packed classification, metadata without `signal`, `signals`, `source`). |

- **Cargo feature `external-classifier`** (RUST-S17B, on by default). `open_classifier` and its re-exports exist only with the feature, because it is the only module that uses an HTTP client; `open_prompt` and `open_response` are pure and stay. `privoke-runtime` (the inference worker) and `privoke-training` depend on this crate with `default-features = false`, so the worker links no HTTP stack. CI asserts it (job `Rust workspace tests`, step "Worker links no HTTP stack"): the crate checks without the feature, and `cargo tree -p privoke-runtime -e normal` contains none of `reqwest`, `rustls`, `native-tls`, `openssl`. The tests of the client carry `required-features`. `tonic` stays in the worker's tree through `privoke-contracts` (the protobuf types), which opens no connection.
- **HTTP.** `reqwest` 0.12 with `default-features = false, features = ["blocking", "rustls-tls"]`: rustls with the bundled webpki roots, no OpenSSL or native-tls (a test asserts both are absent from `Cargo.lock`). The client is blocking, like `classify`; call it from a thread that is not an async runtime worker (stage 17: `spawn_blocking` or the worker's own thread).
- **Request.** `POST <base_url>/chat/completions` (the base URL gets a trailing slash, as in the SDK; default `https://api.openai.com/v1`). Headers `accept` and `content-type` (both `application/json`) and `authorization: Bearer <key>`. The body is compact JSON with the SDK's key order `messages`, `model`, `max_tokens`, `response_format`, `temperature`, and text unescaped (`ensure_ascii=False`). The SDK retries a failed request twice (408, 409, 429, 5xx, timeouts, connection errors) with a doubling delay from 0.5 s to 8 s and honours a `retry-after` of 0 to 60 s; so does the Rust client (no jitter).
- **API key.** Only from the options or `OPENAI_API_KEY` at run time. The `Debug` output of the options, the configuration and the request redacts it, the header value is marked sensitive, and no fixture or test records a key (tests use the literal `PLACEHOLDER`).
- **Errors.** The layer error text is `str(exception)`: the classifier's own `RuntimeError` texts are identical to Python's. A non-2xx status is `Error code: <status>` (the SDK appends the response body, which could echo the prompt; this client never does). A timeout is `Request timed out.` and a transport failure `Connection error.`, as in the SDK.
- **Findings.** `classify_detailed` returns `ExternalResult` with `confidence: Option<f64>` (Python keeps `None`) and the metadata. The `SemanticClassifier` impl maps a missing confidence to `1.0`, which the Python policy treats the same (never low); stage 17 can read the detailed results when it needs the distinction.

### Parity with Python

`evaluation/generate_open_classifier_golden.py` runs the unchanged `OpenClassifier` against an in-process `httpx.MockTransport` (no network, key `PLACEHOLDER`) and writes `tests/fixtures/open_classifier_golden.json`: the request the SDK builds for the 19 stage 0 prompts of `tests/conformance/worker-frames/prompts.json` (the `secret-key` prompt is left out because it holds a credential-shaped example; `overlong` is recorded by hash only) and for four configurations, 83 recorded HTTP answers with the outcome Python produced (valid, empty envelope, every malformed case of `build_external_results`, bad JSON, no choices, refusals, HTTP errors), and 15 environment resolutions. The reference was `openai` 3.3.1 and `httpx` 0.28.1 on the host interpreter (Python 3.13.2); `evaluation/.venv-v1-v3-pipeline` lists `openai` but cannot import it (`httpx` is missing there), and the other evaluation environments do not have it.

| Check | Test |
| --- | --- |
| Method, URL, body bytes, SHA-256 and length equal for every request case; `accept` and `content-type` equal, `authorization` is `Bearer` plus the key | `tests/open_request.rs` |
| Configuration resolution (defaults, precedence, error texts) | `tests/open_request.rs` |
| 83 recorded answers parse to the same packed classification, section, reasoning, span, confidence and metadata, or the same error text | `tests/open_response.rs` |
| The same request on a real `reqwest` exchange (loopback server in the test binary), retries, status errors, timeout, closed port, layer integration | `tests/open_http.rs` |

Known differences, none of which changes a request or a parsed result:

- Host-dependent SDK headers (`user-agent`, `x-stainless-*`) are not reproduced; the client sends `privoke-semantic/<version>` as its user agent. `host`, `content-length`, `connection` and `accept-encoding` are the transport's.
- The timeout is one total budget per attempt (plus the connect budget), where `httpx` applies it to each phase.
- A `NaN` or `Infinity` token in the model's JSON, which Python's `json.loads` accepts, is read as a string of the same name. It can only matter as a confidence or span (both rejected either way) or an ignored extra.
- A lone-surrogate escape in the model's JSON is accepted by Python and rejected by `serde_json` (reported as invalid JSON). The SDK's retry jitter is not reproduced, and a `temperature` below 1e-4 is written as `1e-5` where Python writes `1e-05`.
- Non-finite `OPENAI_*` numbers (`nan`, `inf`) are refused; Python accepts them by accident.

No test makes a live API call.

## GLiNER backend (stage 15)

`privoke_ner_layer::gliner` ports `NER/gliner_detector.py`, the optional GLiNER NER backend (`PRIVOKE_NER_BACKEND=gliner`). It is not shipped by default, as in Python: the model backend is behind the cargo feature `gliner-ort` of `privoke-ner-layer` (off by default), and nothing in the product wires the backend in.

| Part | What it ports |
| --- | --- |
| `LabelPreset`, `CORE_LABELS`, `pii_extra_use_case` | The pre-registered `core` and `pii` label presets, the mapping of `core` labels onto `PERSON`, `GPE`, `FAC`, `ORG`, and the fixed identifier use cases. |
| `word_windows`, `split_words` | Windows of at most 300 whitespace separated words, and GLiNER's `\w+(?:[-_]\w+)*|\S` word splitter, with Python's `isspace` and `\w`. |
| `prompt_words`, `words_mask`, `span_inputs`, `decode_spans` | The model-side input layout and the flat-NER decoder (sigmoid above the threshold, greedy by descending score, overlap removal), so a backend only runs the network. |
| `GlinerDetector` | `predict_raw` (threshold and label filters, order), `extract_entities`: core spans go through the NER post-filter on the spaCy `Doc` (`char_span(..., "expand")`), identifier spans are emitted directly, results sorted by span. |
| `gliner_ort::GlinerOrt` (feature `gliner-ort`) | ONNX Runtime (`ort` 2.0.0-rc.10, `load-dynamic`: set `ORT_DYLIB_PATH`) plus `tokenizers` 0.22.2 over `tokenizer.json`, `gliner_config.json` and the ONNX export of the span model. |

- **spaCy.** The tokens and parse come through the `SpacyBackend` trait (the in-process backend by default). The detector asks for `Selection::Full` and ignores the entities: `en_core_web_sm`'s tagger and parser do not read `ner`, so the tokens equal Python's ner-disabled parse. A ner-disabled selection in `privoke-spacy` would only save the NER compute.
- **Settings.** `GlinerOptions` reads `PRIVOKE_NER_GLINER_THRESHOLD` (default 0.3, as Python) and `PRIVOKE_NER_GLINER_LABELS` (default `core`); `GlinerOptions::frozen()` is the study's frozen `core`, 0.5 (`gliner-core-t0.5-pf1`). The post-filter follows `NerOptions::postfilter`.
- **Not ported.** The layer entry point (`analyse_ner_layer`) still builds the spaCy detector; selecting the GLiNER detector there is the analysis runtime's job (stage 17).
- **Parity.** `evaluation/generate_gliner_golden.py` records, from Python, each model call, the spaCy analyses the post-filter read and the results with the post-filter on and off, for the C53 sets (development, `personalized`, `openai`). `tests/gliner_replay.rs` replays them without the weights when `PRIVOKE_GLINER_GOLDEN` points at the (ignored) output, and reports `PENDING` otherwise. The pure parts have unit tests with synthetic logits.

```
evaluation/.venv-ner-models/Scripts/python.exe evaluation/generate_gliner_golden.py --gliner-dir <checkpoint> --out <ignored dir> development openai
PRIVOKE_GLINER_GOLDEN=<ignored dir> cargo test -p privoke-ner-layer --test gliner_replay --manifest-path rust/Cargo.toml -- --nocapture
```

The checkpoint is `knowledgator/gliner-pii-small-v1.0` at revision `d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e` (Apache-2.0); its weights were deleted after the study (`docs/experiments/ner-models-20261024.md`). A run of the model with ONNX Runtime is a separate check from Python parity: the ONNX export and the torch checkpoint agree only to float tolerance, and the model's own span scores can differ near the threshold.

## `privoke-curriculum` (stage 20)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-20-curricula-schedules-and-update-aggregation-in-rust-d5).

`privoke-curriculum` ports the fuzzer's curricula and the frozen V3 schedules, on top of an exact reimplementation of CPython `random`. A seed reproduces the Python selection, order, metadata and every digest.

| Module | Python source |
| --- | --- |
| `pyrandom` | CPython `random.Random`: MT19937 seeded from int, str and bytes (version 2), `random`, `getrandbits`, `_randbelow`, `choice`, `shuffle`, `sample`, `randrange`, `randint`, `uniform`, `choices` (weights and cumulative weights). |
| `generator`, `defaults`, `templates`, `prompt_seed` | `prompt_generation/{generator,defaults,templates,vocabulary,loader,types}.py` with `json_records` and `training/classifications.py`: the legacy prompt generator, the held-out partition and the contextual role-quota sampler. |
| `taxonomy`, `anchor`, `benign` | `taxonomy_coverage.py`, `anchor_rehearsal.py`, `benign_coverage.py`: releases, partitions, audits and retained-audit evidence. |
| `audience`, `privacy_heads` | `audience_coverage.py` (AU3) and `privacy_heads_curriculum.py` (PH3 rows, `build`, `audit`). |
| `presence`, `curriculum`, `train_window` | `presence.py`, `curriculum.py` (the SQLite state is the `CursorState` trait; `MemoryState` for tests), `train_window.py` with the window contract of `window_training.py`. |
| `trainer` | The pure half of `training/trainer.py` and `parameter_updates.py`: seeded augmentation, request validation, publication metadata and the compact audit. |
| `v3` | `pretrained-v3/src/{fuzzer_training,audience_schedule}.py`: the AU3 and BC01 frozen streams, sidecars and wire digests. |

### Parity with Python

`evaluation/generate_curriculum_golden.py` (`random`, `recorded`, `live`; host Python `evaluation/.venv-v1-v3-pipeline`, read only) writes `tests/golden/*.json`. All of it runs in `cargo test` (CI).

| Check | Result |
| --- | --- |
| CPython `random`: 4 seeds (0, 42, 2^32, 2^64-59) x 36 method variants x 10^6 draws, digest of each draw stream; plus str and bytes seeds | identical |
| Recorded AU3 source records (seeds 42, 43, 44; pilot and 8-batch): train and guard wire digests, sidecar digest, whole-record digest, exposure counts | identical (6 of 6) |
| Retained BC01 and rehearsal sampling audits, including expanded wire commitments | 52 of 52 reproducible audits identical (49 rehearsal, 3 benign) |
| Live Python on further seeds: legacy generator, taxonomy, anchor, benign, AU3 partitions and audits, AU3 and BC01 V3 schedules, PH3 pools, augmentation, role quota, presence, curriculum reservations and fingerprints | identical |

Three retained benign audits (manifest `7d9b12f0...`, seed 42) come from a superseded manifest that the maintained Python itself refuses; they are recorded as `oracle_refuses` and cannot be reproduced by any port.

Two inputs need care. The AU3 manifest pins its two catalogs as CRLF bytes but the manifest and guard as LF bytes, so no single checkout line-ending setting passes the Python pin check; `tests/fixtures/au3` holds the pinned bytes under `-text`. The recorded `source_hashes` pin the Python bytes of the time, so tests take them as inputs.

### Not in this stage

- The gRPC submission, SQLite cursor storage, retained-evidence files of the service and the model-bound `privoke_model` contracts (stage 21 and later). The email and phone redaction transforms, which no curriculum uses.
- `str.format` is supported for plain `{name}` fields and `{{ }}` escapes only.

## `privoke-training` (stage 19)

`privoke-training` ports the Tiny transformer's gradients and the FULL projected Adam fit. It is LLM-only (it never runs a detector layer) and it does not use libtorch: the backward pass is written by hand over the stage 14 style reference arithmetic (float32 weights, float64 activations and gradients). CUDA is out of scope.

**Status: partial.** Done: checkpoint 1, the gradient RPC computation (`rpc`) with the local-SGD, backtracking and TRAIN-diagnostics routes (`routes`, `trace`) and the policy and admission checks (`admission`), presence gradients. Not done: the window, supervised-wrapper and sensitive-retention training loops, `reference_preparation.py` and `v3/training.py`. See the stage 19 handoff in `docs/plans/rust-server-rewrite.md`.

### What is ported

- `net`: `TinyNet` (artifact loader with the inventory and shape checks; both readouts; multi-head attention, post-norm blocks without affine layer norm, tanh GELU) with `forward` and a reverse-mode `backward` over every tensor, including the embeddings. Rows are independent, so the Python microbatch padding (masked keys, masked readout) has no effect on a real row and is not reproduced.
- `objective`: `supervised_deltas`, the port of `supervised_training.supervised_last_block_deltas` for the legacy summed-category objective (also `class_balanced_contextual_v1`), `..._mean_category_v1`, `..._decision_margin_v1` and `..._sum_category_decision_margin_v1`; the global weight denominator and the float32 weight rounding; `class_balanced` (`_class_balanced_examples`, with `math.fsum`).
- `adam`: `adam_step` and `fit` for `full_projected_adam64_v1` (64 steps, eta 0.003, betas 0.9 and 0.999, epsilon 1e-8, float64 moments, cumulative float32 delta capped at the float32 value just inside 0.05, candidate `float32(round(float32(base) + float32(delta), 8))`), the per-step fingerprints (`privoke-contracts`) and the counters. `fit_with` takes any gradient source, so a recorded Python gradient replays the recurrence.

### Golden and parity

`evaluation/generate_training_golden.py synthetic` runs the product's own `supervised_last_block_deltas` and `full_adam_training.fit` (Torch 2.11.0 CPU, Python 3.11.9, `OMP_NUM_THREADS=MKL_NUM_THREADS=1`, one Torch thread) on two seeded synthetic Tiny models (legacy and task-query readout; hidden 8, two layers, vocabulary 24) and 12 rows, and writes `rust/crates/privoke-training/tests/fixtures/tiny_training_golden.json` (tensors as float32 bit patterns). The generated protobuf clients are needed to import `training.py` (`PRIVOKE_GENERATED`). Its test is `python -m unittest discover -s evaluation/tests -p test_generate_training_golden.py`.

`cargo test -p privoke-training` (in `rust-ci.yml`) checks:

| Check | Runs | Result |
| --- | --- | --- |
| Gradients, 5 objectives on 2 models | 10 cases, 12,960 coordinates | all within 1e-6 (max 3.07e-7); 2,595 bitwise equal to torch |
| Gradients along Python's 64-step trajectory | 64 steps, 83,712 coordinates | all within 1e-6 (max 8.40e-7); 12,967 bitwise equal |
| Adam recurrence fed Python's recorded gradients | 64 steps | before, after, delta fingerprints and clipped counts identical at 64 of 64; final candidate byte-equal |
| Chained Rust fit (Rust gradients, 64 steps) | 1 run, 1,308 candidate coordinates | all within 1e-6 (max 1.34e-7); 1,139 bitwise equal; final fingerprint not identical |

By the stage's artifact rule, the replay run (gradients bitwise Python's) is in the byte-equal category and the chained run is in the tolerance category (same inventory and shapes, every coordinate within 1e-6). The torch gradients are float32, so about 80 percent of gradient coordinates differ from the float64 value by float32 rounding; the Adam update bounds the effect at the scale seen above.

### Gradient RPC computation (`rpc`)

`rpc::compute_gradients(&Snapshot, &Request)` is `training._compute_training_gradients` on the single-update route, for `ComputeSemanticGradients` (head scope: heads and, with the task-query readout, the queries) and `ComputeUnderlyingModelGradients` (full-encoder scope: every tensor, on a full-capable artifact only). It ports the request validation, canonical text normalisation (`privoke_rules::normalize_text`), class balancing, the transported update `float32(clamp(delta * lr, +-cap))` with the inward float32 cap on full-capable artifacts, the candidate (`updated_parameter_values`), the no-encoder-change check, the held-out guard (`training_text_key` with NFKC, exact match, sensitive recall, clean specificity, and the safety-regression rate from the policy action mapping) and the response metrics, executions and scope.

Golden: the product's `_compute_training_gradients` runs on a fake streamed snapshot (the streamer and cache are replaced; nothing else is). `tests/rpc_parity.rs` checks 12 cases (2 models x legacy, mean-category and sum-margin objectives x head and full-encoder scopes), 8 held-out rows each: the transported update (all coordinates within 1e-6; the 12 cases hold 8928 coordinates), the metric names and values (302 metrics: decision counts and rates exact, losses and weights within 1e-5 relative), the executions, and the guard outcome: the candidate safety-regression rate is equal in all 12 cases, and the accept (rate 0) or reject decision is identical in all 12 (2 rejected, 10 accepted).

Checkpoint 3a serves this computation from the Rust worker (`privoke-runtime`, `training.rs`), which builds the response metadata strings and the objective-only admission and FULL Adam refusal around it. Not ported on this route: other admission headers, local-SGD, backtracking and diagnostics routes, window and retention routes and the FULL Adam fit in an RPC (the fit is `adam`); `reject_overlength` is reproduced by the worker. The streamed protobuf envelope is stage 17 and 22's.

### Routes and admission (checkpoint 4, item 2c)

`routes.rs` ports the three routes of `_compute_training_gradients` beyond the single update. `local_sgd` is `_local_sgd_updates` (`local_sgd_1_v1` and `local_sgd_4_v1`): one immutable base, the direction recomputed at each transported state `float32(round(float32(base) + float32(delta), 8))`, a float32 accumulator capped inward of the request bound, and the bounded `contextual_optimizer_trace` (losses per state, fingerprints, update norms, clipped counts; at most 2,048 bytes). `backtracking` is `_backtracking_trials`: the scales 1, 1/4, 1/16, 1/64 and 1/256 of the requested rate on one original direction, a trial is accepted when it lowers the TRAIN objective by more than `2e-5` and changes an encoder tensor, a trial that fails numerically is an `invalid_numeric` row, and no accepted trial is the response `error` `TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1` with no transported tensor. `diagnostics` is `_training_diagnostics` (losses and the six accuracies of the base and candidate states, the update summary). `local_training_losses` is `_local_training_losses` (true cross-entropy and binary cross-entropy per task, the decision-margin loss). `trace.rs` writes the records as `json.dumps(..., separators=(",", ":"))` does (insertion-ordered keys, `float.__repr__` through `privoke_contracts::pyfloat`).

`admission.rs` ports `full_adam.validate_policy` and `validate_admission` with the window and ORIGINAL-retention dispatch (the orphan-pin checks, the window and retention header comparisons and their texts; the window and retention training loops are not ported, so `admit` reports an artifact that passes them as `Admitted::Elsewhere`), `validate_backtracking_policy` (the preparation record and its SHA-256) and `admit`, which returns the route (`Route { objective, optimizer, diagnostics, backtracking }`) after the checks of `_compute_training_gradients` that read the artifact metadata and the request's admission header, in Python's order. `rpc::Snapshot` carries the route and `rpc::Batch` returns the route metadata, the response `error` and the trained tensor inventory.

Golden: `evaluation/generate_training_golden.py routes` writes `tests/fixtures/tiny_training_routes_golden.json` (44 served cases and 26 refusals from the product's `_compute_training_gradients` on a fake streamed snapshot). `tests/routes_parity.rs` (CI step `Training parity report`) checks: 38,208 transported coordinates all within 1e-6 (max 7.82e-8, 18,755 bitwise equal); 1,138 of 1,138 metrics; the guard outcome identical in 38 of 38 (31 accepted, 7 rejected); the backtracking outcome identical in 24 of 24 (12 first scale, 6 second scale, 6 rejected); 26 of 26 refusal texts; and the route metadata strings (JSON traces structurally equal, floats within 1e-5, 102 of 188 strings byte-equal). The worker level is `privoke-runtime` `worker_golden.rs` (below).

### Window loop (checkpoint 5, RUST-S19D)

`window.rs` ports `window_training.compute` (policy `full_projected_adam64_window_checkpoint_v1`): the pinned window and the component release loaders, the block schedule, the component-hinge direction, the checkpoint scoring, selection and guard, and the retained trace and summary. CI covers it with synthetic inputs (`tests/window_synthetic.rs`); the comparison with the unchanged Python loop on a real release is the env-gated `tests/window_release_parity.rs`, run locally (the golden holds study-derived data and is ignored by Git): see the stage 19 plan entry for the Docker command and the results. The worker and routing do not serve this loop yet.

The worker serves the window route since RUST-S19E: `training.rs` parses the schema 5 header, reads the `PRIVOKE_WINDOW_*` and `PRIVOKE_COMPONENT_*` configuration (`WindowConfig`), runs `window::run` and writes Python's response metadata; `routing::admission_is_served` accepts the nine-key schema 5 record and the supervisor passes the eight variables to its workers. See the checkpoint 6 entry of the stage 19 plan for the tests and the gated worker command.

The retention loops are ported in `retention.rs` (checkpoint 7, RUST-S19F): the release loader, the hinge direction, the fit with the safety audit and the trace; the worker serves the schema 4 header from the `PRIVOKE_RETENTION_*` configuration and `routing::admission_is_served` accepts the eight-key record. See the checkpoint 7 entry of the stage 19 plan for the tests and the gated commands.

Reference preparation (`reference.rs`, checkpoint 8, RUST-S19G) is an offline tool without a route: `prepare_references` authenticates the approved bank and the ORIGINAL teacher and returns the canonical reference payload and the teacher identity; see the checkpoint 8 entry of the stage 19 plan for the gated command.

### Presence gradients and admission

`presence` ports `privoke_model/presence.py` (the sparse TF-IDF presence model, which stage 14 did not port; additive, `privoke-semantic` is unchanged) and `compute_presence_gradients`. On the synthetic golden every one of 606 transported coordinates is bitwise equal to Python, as are the probabilities, 18 of 18 metrics and the 4 fingerprints (the arithmetic is float64 with `fsum`, no torch). `admission` ports the FULL Adam artifact policy and pre-gradient admission: 9 of 9 scenarios give the same outcome and error text (the window and retention policies are ported at checkpoint 4, above). `training_text_key` follows Python's `\d` (`Nd`) and `str.split()` whitespace through `privoke_rules::pyunicode`. CI prints the per-case numbers in the `Training parity report` step of `rust-ci.yml`.

### Known differences

- The FULL trace's `gradient` and `moments` identities hash the float64 bytes of the gradients, so they are bit-sensitive and Rust does not reproduce them unless the gradients are bitwise equal; the Rust fit reports the before, after and delta fingerprints, the loss and the clipped count of each step, and the counters derived from the fixed schedule.
- `round(x, 8)` is `format!("{x:.8}")`; the two differ only on an exact decimal tie.
- `reject_overlength`, cancellation hooks, the retention auxiliary and the observed NumPy work counters are not ported (the worker reproduces `reject_overlength`).
- Checkpoint 4: the window and retention training loops are Python's; `validate_backtracking_trace` and `validate_training_diagnostics` are reproduced for their byte budget and finiteness only; head-scope local-SGD directions are the head slice of the full-network gradient; a numerically failing backtracking trial is an `invalid_numeric` row without Python's four exception texts; trace losses are float64 over the reference forward pass (about 1e-7 relative to Python's).
- Gradient and loss reductions are float64; torch accumulates in float32, so losses agree to about 1e-6 relative.

## `privoke-fuzzer` (stage 21)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-21-fuzzer-orchestration-in-rust-d6). Binary: `fuzzer-service`. Dockerfile: `rust/services/fuzzer/Dockerfile`.

**Status: partial.** `rust/services/fuzzer` replaces `services/privoke-fuzzer/src/{fuzzer_service,runtime_client,main,cli,config,json_records}.py` for the cycles that need only what stages 19 and 20 provide. The Python service stays in place as the oracle and for the historical study runners. `rust/services/v3-fuzzer` (the port of `services/pretrained-v3/src/fuzzer_server.py`) is the second half of the stage and is described [below](#privoke-v3-fuzzer-stage-21).

| Module | Python source |
| --- | --- |
| `config` | `config.py` (`FuzzerConfig`, `validated()`, the same messages) and the credentials of the outbound channels. |
| `validate` | `privoke_service.validate_text`, `validate_training_request`, `validate_presence_training_request`. |
| `runtime` | `runtime_client.py`: `compute_semantic_gradients` (request construction, the explicit `[SEMANTIC]` layer list, `validate_training_response` with the tensor inventory derived from the model configuration) and a mutual-TLS client. |
| `updates` | `training/parameter_updates.py` (publication metadata and tensors) and the receipt lookup of `fuzzer_service.py`, with a mutual-TLS client of the parameter-update service. |
| `evidence` | `training/evidence.py`: the reservation table, the complete cycle record, recovery of a lost acknowledgement. |
| `state` | The SQLite `CursorState` of the fixed curriculum (`batches` and `cursors` tables), one `BEGIN IMMEDIATE` transaction per reservation. |
| `pywire` | Protobuf bytes as Python writes them for the two messages whose bytes are hashed or retained (see below). |
| `cycle` | `fuzzer_service.py`: validation, the concurrency bound, the FULL scope namespace, fingerprints, sampling, the publication guard, submission and the response. |
| `policy`, `policy_response` | `contextual_training.training_policy_expectations`, `training_admission_metadata` (the header) and its parse; `runtime_client.validate_training_policy_response` (the executed objective, the optimizer identity, the 64-step trace). |
| `full_adam`, `retention` | `privoke_model/full_adam.validate_trace`; `sensitive_retention` (raw trace, bounded summary, execution phases) and `sensitive_retention_evidence` (`validate_source_bindings`, `persist_release`, `retained_release`, over `privoke_training::retention::Release::load`). |
| `attempts`, `full_adam_evidence` | `training/evidence.py` and `full_adam_evidence.py`: the exclusive physical attempt reservation, the immutable attempt record and its admission verdict, a reservation rejection; `validate_candidate_route`, `eligibility_metric`, `gate_summary` and `publication_metadata` (weight and taxonomy audit projections, `training_evidence_sha256`, the 64-entry and 2048-byte budget). |
| `gate_diagnostics` | `fuzzer_service.gate_diagnostics` and `write_gate_diagnostics` (`study_gate_diagnostics=v1`). |
| `service`, `server` | The gRPC shell and its policy: the training RPCs for `publisher` and `trainer` services, `Health` also for `runtime`; everything else `UNIMPLEMENTED`. No plaintext listener. |
| `cli` | `cli.py` `train` (over mutual TLS) and a `healthcheck` subcommand. |

`json_records.py` is the stage 20 `privoke-curriculum` loader (`prompt_seed::load_prompt_dataset`); it needed no port here.

### Behaviour kept from the Python service

Request validation order and messages; `max_concurrent_cycles` as a try-acquire (`RESOURCE_EXHAUSTED`); the prompt cap and the `request.seed or config.seed` rule; the FULL scope derived `source_id` and `original_request_source_id`; the request fingerprints (`sha256` of the request, of `[hex(request), settings]`, and the curriculum fingerprint); the receipt lookup before any work, with `ALREADY_EXISTS` and `UNAVAILABLE` mapped as Python maps them and a found receipt answered as `{"replayed": "true"}`; the held-out guard (`validate_training_update`) and its messages; the gRPC status of each failure (`FAILED_PRECONDITION` for a `ValueError`, `UNAVAILABLE` for the runtime and the updater); the retained record written whole (temporary file, flush, rename, directory flush) and rewritten with the acknowledgement; the response `metadata` (update metadata, then `str(metric)`).

Every gradient request names exactly `[DETECTION_LAYER_SEMANTIC]` and no constructor can produce an empty list, which the runtime would read as the complete detector pipeline. A response that does not report exactly the three semantic executions (`training`, `base_heldout`, `candidate_heldout`) is refused.

### Deliberate differences

- **Mutual TLS everywhere.** The listener, the runtime client, the updater client and the CLI present a registered certificate; the fuzzer certificate name must equal `FUZZER_ID`, the `source_id` it publishes as (stage 5 binds them). The Python service used `service_channel`, which can fall back to plaintext on the Compose network.
- **The listener deadline.** One RPC is one whole cycle, so `FUZZER_REQUEST_TIMEOUT_SECONDS` (default 1800) replaces the transport 60 s default, and connections drain only after it.
- **Curriculum allocation text.** The `allocation` column holds `json.dumps(sort_keys=True)` of the allocation; Python wrote the keys in insertion order. Both read back as the same value (the replay compares parsed rows).
- **Python map encoding (`pywire`).** Python writes every protobuf map entry with its key and value fields, even a default value (an empty string or `0.0`); `prost` leaves a default value out. The messages decode identically, but a fingerprint over the request and the retained `response_protobuf_base64` must be the bytes Python wrote, so those two are encoded by `pywire`. The first CI run found this: a recorded response carries `candidate_heldout_safety_regression_rate = 0.0`. **Finding for stage 20:** `privoke_curriculum::curriculum::request_fingerprint` hashes `request.encode_to_vec()`, which differs from Python for a request whose metadata has an empty value; the fuzzer never reaches that call with such a request in any recorded cycle, and the stage 20 crate was left unchanged.
- **Named gaps instead of different cycles** (below).

### Not ported

Nothing in the cycle dispatch answers `UNIMPLEMENTED` any more (RUST-S21H). What stays out of the service is `cli.py test-prompts` (`prompt_testing.py`), a study helper outside it, and the bounded study controls of `request_fuzzer_loop`.

### Window, audience and presence cycles (RUST-S21H)

- **Window cycle** (`window.rs`, `window_cycle.rs`; Python `training/window_cycle.py`, `window_evidence.py`, `privoke_model/window_training.py`). A request with the window policy header and the window sampler reconstructs everything before the reservation and the receipt lookup: the pinned window (`FUZZ_WINDOW_PATH`, `FUZZ_WINDOW_MANIFEST_SHA256`), the authenticated component release (`FUZZ_COMPONENT_*`, four sidecars and two pins), the taxonomy and benign snapshots and the frozen source selection. The window and component bytes are retained (`window-inputs/`), the physical attempt is reserved and retained like a FULL Adam attempt (header, deadline `max(FUZZ_TIMEOUT_SECONDS, 180)`, the explicit `[SEMANTIC]` list), the response is re-derived (`validate_response`, `validate_trace`: schedule, recurrence identities, checkpoint counts and ORIGINAL component predicates, selection, guard, work accounting, compact summary), and either the selected checkpoint is published (compact metadata bound to the retained cycle by `training_evidence_sha256`) or a terminal receipt `window-outcomes/<identity>.json` answers repeats (`Known no_update; immutable BASE retained.`). `train` of the CLI builds the window request (`--training-policy`, both pins).
- **Audience sampler** (`cycle.rs`). The default strategy when no dataset is configured. The pinned AU3 release (`FUZZ_AUDIENCE_MANIFEST_PATH`/`_SHA256` or the bundled one) is loaded before the reservation; Python binds the sha256 of its own sampler sources (`implementation_closure`) into the fingerprint, the audit and the retained evidence, so Rust reads the same files from the new `AUDIENCE_SOURCE_ROOT` (the checkout; a cycle without it is `FAILED_PRECONDITION` naming the variable).
- **Presence cycle** (`presence_cycle.rs`; Python `_run_presence_training_cycle`, `training/presence.py`, `compute_presence_gradients`). The presence partition, the explicit `[SEMANTIC]` `ComputePresenceGradients` request, the retained attempts (`presence-runtime/<request sha256>/attempts/`), the response admission, `validate_presence_training_update`, the retained cycle record (also kept under `training-cycles/<id>/attempts/`) and the publication. No reservation: the receipt answers a repeat.
- **Admission.** `validate_training_request` checks a window request (256 originals, the exact policy, no backtracking or diagnostics policy). Python wrote the window messages and Rust reproduces them.

- **Parity counts (CI run 45049024695 on f4f4cab, green).** Audience replay: 7 cycles (3 accepted, 4 refused), 13 wire messages, 5 runtime calls, 3 dump files. Presence replay: 6 cycles (2 accepted, 4 refused), 10 wire messages, 4 runtime calls, 11 dump files. Window admission refusals: 8 cycles refused, identical messages. All identical to the Python oracle under the G5 normalisation.
- **Window recorded fits (local, env-gated).** `evaluation/generate_window_cycle_golden.py` replays the three host fits of `task_query_window_20261012` through the Python oracle (the oracle reproduced each recorded runtime request byte for byte) into the git-ignored `rust/services/fuzzer/tests/local/window_cycles_golden.json` (seed 42: 7 cycles, 10 dump files; seed 43: 1 cycle, 5 dump files; seed 44: 7 cycles, 10 dump files). The Rust replay is `tests/window_cycles.rs` (`PRIVOKE_FUZZER_WINDOW_GOLDEN`, `PRIVOKE_FUZZER_WINDOW_ROOT`), run by root in Docker; it prints the same counts line as the other replays.
- **Not verified in CI:** the window trace admission against the recorded fits (needs the local data above). The audience closure hashes the Python files byte for byte, so a checkout with CRLF files hashes differently from the Linux one (the oracle hashes with LF endings).

### Rehearsal and benign coverage, ORIGINAL retention, TRAIN diagnostics and backtracking (RUST-S21G)

**Item 5, rehearsal and benign coverage.** `FuzzerConfig` reads `FUZZ_REHEARSAL_MANIFEST_PATH`, `FUZZ_BENIGN_POOL_PATH`, `FUZZ_BENIGN_MANIFEST_PATH` and `FUZZ_BENIGN_EXCLUSION_PROOF_PATH`. Before any reservation the cycle checks the exact authenticated FULL Adam policy and unit weights (`policy::exact_full_adam`), loads the snapshot, runs `validate_pins` and `generate_partition`, and folds the manifest, pool, proof and policy contract into the settings fingerprint. The audit of the originals (`audit_originals`) is merged into the metadata; the audit of the expanded rows (`audit_expanded`) is retained by `persist_audit` before the runtime call (`rehearsal-audits/<sha>.json`, `benign-audits/<sha>.json`, referenced from `execution_evidence`). The publication projects `full_adam_rehearsal_audit_v1` and `full_adam_benign_audit_v1` after `validate_retained_audit` and the ordered TRAIN and guard wire commitments over the actual protobuf rows. A complete ORIGINAL retention cycle (benign strategy and a retention policy) loads the four sidecars (`retention::load_requested`: request pin and model, then the configured trust pin, in the Python order), retains the release (`persist_release`) before compute and binds the response to it (`validate_source_bindings`, a `ValueError`, so `FAILED_PRECONDITION`).

**Item 3, TRAIN diagnostics and FULL backtracking** (`src/diagnostics.rs`): `validate_training_diagnostics`, `validate_backtracking_trace`, `validate_backtracking_response` (every failure is the single `RuntimeAnalysisError` of the caller), the known-rejection route (`TRAIN_BACKTRACKING_NO_IMPROVEMENT_V1`: validated with `rejected=True`, admission `known_train_rejection`, answered `FAILED_PRECONDITION` "FULL TRAIN backtracking found no meaningful improving candidate.", no reservation of a physical attempt, as in Python) and the compact publication of an opted-in update with more than 64 metadata entries (`training_audit_v1`, `training_evidence_sha256` over metadata, metrics and execution evidence). Deviation: a JSON document that holds `NaN` or an infinity is refused by the parser (Python accepts the literal and then fails its first finite check); the verdict is the same.

**Replay.** `evaluation/generate_coverage_cycle_golden.py` (golden `tests/fixtures/coverage_cycles_golden.json`, the rehearsal manifest `tests/fixtures/rehearsal-manifest.json` prepared by the oracle from the committed taxonomy fixture): 21 cycles over the committed rehearsal and benign fixtures, with the retained runtime responses of the iterative study replayed (both strategies expand to 64 TRAIN and 16 guard rows): accepted, guard refused, repeat refused by the physical reservation, weak policy, wrong pins, bad responses, retention refusals before the release is read, orphan pins and unconfigured paths. `evaluation/generate_backtracking_cycle_golden.py` (golden `tests/fixtures/backtracking_cycles_golden.json`): no study retained a physical backtracking or diagnostics response, so the response is the retained FULL Adam response with its Adam evidence removed and the diagnostics record, trace and trials written for the request the oracle built (a response is a function of the oracle's request and is recorded as bytes). All replays share `tests/common/cycle_replay.rs`; every wire message, header and deadline, response or abort, dump file and reservation row is identical, and `training_evidence_sha256` is recomputed over the Rust record with the oracle's absolute evidence paths (`evidence_paths_raw`).

**Complete retention replay (env-gated, local golden).** `evaluation/generate_retention_cycle_golden.py` replays every retained cycle of `sensitive-retention-pilot03` (gate) and `-pilot04` (gate, hinge) with the pilot's own sidecars (read by bare file name from the working directory so that the recorded teacher path is the same string on Windows and Linux); the oracle reproduces each recorded runtime request byte for byte. The golden holds prompt text and is written to the ignored `rust/services/fuzzer/tests/local/`. Run (root, local Docker, from the worktree root): `docker run --rm -v <worktree>:/work -v <checkout with results>/evaluation/results:/results:ro -w /work/rust -e PRIVOKE_FUZZER_RETENTION_GOLDEN=/work/rust/services/fuzzer/tests/local/retention_cycles_golden.json -e PRIVOKE_FUZZER_RETENTION_RESULTS=/results rust:1.99.1-slim-bookworm cargo test -p privoke-fuzzer --test retention_cycles --locked -- --nocapture` (the golden is generated on the host with `generate_retention_cycle_golden.py --results <checkout>/evaluation/results --generated <PRIVOKE_GENERATED>`).

### Parity with Python

`evaluation/generate_fuzzer_golden.py` runs the maintained `FuzzerTrainingService` in process on the host (`evaluation/.venv-v1-v3-pipeline`, generated protobuf clients) with the runtime replaced by the response bytes of a real recorded cycle (`execution_evidence.response_protobuf_base64` of the retained `accelerated_all_surfaces_20261010` cells) and the updater replaced by a fake. It writes `rust/services/fuzzer/tests/fixtures/fuzzer_cycles_golden.json`; no detector layer runs and no stack is needed. The recorded legacy cell runtime request is not reproduced by any seed, because the study used a prompt dataset that is not in the repository; its request is generated by the Python oracle for the same configuration instead, and the golden marks that (`runtime_request_matches_recorded`). `cargo test -p privoke-fuzzer` replays the same requests through the Rust engine against scripted backends:

| Check | Result |
| --- | --- |
| Cycles replayed (2 legacy-sampler cycles, 3 fixed-curriculum cycles over the SQLite state, one of them the retry of the first) | 5 cycles: 4 accepted and 1 refused by the guard |
| Wire messages (gradient request, receipt lookup, publication), after the same decode | 14 of 14 identical, in the same order |
| Response of accepted cycles, abort code and message of the refused one | 5 of 5 identical |
| Retained cycle records, byte for byte | 4 of 4 identical |
| Reservation rows; curriculum `batches` and `cursors` rows (parsed) | 4 of 4 and 10 of 10 identical |

The G5 normalisation (`tests/conformance/normalization.toml`) replaces timestamps and server-generated identifiers; these records contain none, so the comparison is exact. `tests/scheduler_mtls.rs` runs the stage 5 scheduler (its `GrpcFuzzer` and journal) against the real Rust fuzzer service over mutual TLS through one dual cycle (heads, then the full encoder on the published version; the runtime behind it is scripted, the full-encoder tensors synthesised from the model configuration), and checks that an unregistered certificate, a certificate registered only for health probes and a server certificate from an untrusted CA are refused before any cycle is served.

### Build and run

```
docker build -f rust/services/fuzzer/Dockerfile -t privoke-fuzzer-rust:<tag> .
```

The service reads the `FUZZ_*`, `MODEL_ID`, `FUZZER_ID`, `PARAM_UPDATE_TARGET` and `PRIVOKE_RUNTIME_TARGET` variables of the Python service, plus `FUZZER_BIND`, `FUZZER_REQUEST_TIMEOUT_SECONDS`, `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE` and the optional `PRIVOKE_RUNTIME_TLS_SERVER_NAME` and `PARAM_UPDATE_TLS_SERVER_NAME` (default: the target host). Cloud flags as for the other services: `--cert`, `--key`, `--client-ca`, `--crl`, `--registry`.

## `privoke-v3-fuzzer` (stage 21)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-21-fuzzer-orchestration-in-rust-d6). Binary: `v3-fuzzer-service`. RUST-S21B.

`rust/services/v3-fuzzer` replaces `services/pretrained-v3/src/fuzzer_server.py`, the experimental fuzzer of the V3 pretrained models. One request runs one fit of a frozen schedule: the sampler's rows are fitted by the V3 runtime (`TrainingService.FitCandidate`), the candidate manifest is checked against the checkpoint service (`CheckpointService.FetchBlob`), and the checkpoint service judges and publishes it (`CommitCandidate`). Only checkpoint references and their evidence leave the runtime. The Python file stays in place as the oracle and for the historical study runners.

| Module | Python source |
| --- | --- |
| `contract` | `shared/python/privoke_model/v3_contract.py` as the fuzzer uses it. Nothing is reimplemented: `parse` (duplicate rejection, finite numbers, canonical bytes) is `privoke_contracts::v3::parse_canonical`, `validate_policy` is `privoke_curriculum::v3::Policy::from_value`, `validate_manifest` is `privoke_contracts::v3::validate_manifest`, and `validate_execution` (with `validate_guard`) and `publication_passes` are the stage 19 ports in `privoke_training::v3_fit`. The module converts a strictly parsed document to `serde_json` for those and carries the Python error texts. |
| `backend` | The two dependencies as traits, their mutual-TLS clients (`GrpcFit`, `GrpcCheckpoint`) with the Python deadlines (15 s for health, resolution and status, 120 s for a fetch or a commit, `V3_FIT_TIMEOUT` for a fit) and the 2 MiB message limits, and `fetch` of `common.py` (`assemble_blob`: ordered, bounded, hash-checked chunks). |
| `state` | The SQLite `cycles(id, fingerprint, response)` table of `cycles.sqlite`, `synchronous=FULL`, identities reserved before the fit and answered from the row afterwards. |
| `source` | The two frozen samplers over `privoke_curriculum::v3` (`schedule_bc01`; `build_au3` followed by `validate_au3`) and the `source_inventory()` identity reported by `Health`. |
| `cycle` | `FuzzerServer.run`: the frozen budget, the fingerprint (scope, request bytes and, for AU3, sampler and release), the lock, the work directory, the expected base, the schedule and the host's policy and source commitments, the fit, the evidence and manifest checks, the commit and the response. |
| `config`, `pywire`, `service`, `server`, `main` | The environment of `__main__`, Python-identical request and response bytes (reusing `privoke_fuzzer::pywire` for the request), the gRPC shell and the mutual-TLS listener, and the binary. |

### The cycle and its work directory

The files written under `<V3_FUZZER_STATE>/<sha256(request_id)>/`, in this order, are the contract that a retried identity depends on: `cycle-request.pb`, `source.json`, `fit-request.pb`, then either `fit-status-after-error.pb` (a failed fit call is never retried) or, after the evidence and the manifest are validated, `fit-response.pb`, `evidence.json`, `commit-request.pb`, `unknown-commit.pb` (a commit whose outcome cannot be established) and `receipt.pb`. A known identity answers from its row (`ALREADY_EXISTS` for different content or scope, `FAILED_PRECONDITION` while the outcome is unknown, never a second fit). Every fit request lists exactly `[SEMANTIC]` (4); no constructor can produce an empty layer list, which the runtime would read as the complete detector pipeline. A cycle that stops after the row was reserved leaves its row without a response, as in Python.

An exception that the Python servicer does not catch (a `ValueError`, a `RuntimeError`, an `OSError`) is `UNKNOWN` with the message as its text; `context.abort` is the named status.

### Configuration

`V3_POLICY_FILE`, `V3_RUNTIME_TARGET`, `V3_CHECKPOINT_TARGET`, `V3_FUZZER_STATE`, `V3_PORT` (50172), `V3_BIND` (127.0.0.1), `V3_SAMPLING_STRATEGY` (`existing_taxonomy_benign_common_frozen_stream_v1` or `audience_common_frozen_stream_v1`), `V3_FIT_TIMEOUT` (7200), `V3_AUDIENCE_MANIFEST_PATH` and `V3_AUDIENCE_MANIFEST_SHA256` (both or neither) are the variables of the Python server. New: `V3_SOURCE_ROOT` (the checkout whose Python sources and pinned BC01 inputs the host committed to; the Python service derived it from its own location), `V3_REQUEST_TIMEOUT_SECONDS` (the listener deadline, default the fit timeout plus 600 s), `V3_MODE` (`frozen` or `routine`, see [below](#routine-mode-stage-v3-r5)) and, for the outbound credentials, `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE`, `V3_RUNTIME_TLS_SERVER_NAME` and `V3_CHECKPOINT_TLS_SERVER_NAME`.

### Deliberate differences

- **Mutual TLS everywhere.** The listener refuses a peer without a registered certificate (`publisher` and `trainer` may run a cycle, `runtime` may probe `Health`) and the clients present the fuzzer's own registered certificate. The Python server allowed plaintext on loopback and `service_channel` could fall back to plaintext. Stage 8a supplies the certificate (`privoke-pki sign-service`); the `deploy/` files are untouched.
- **Source root.** The `source_hashes` of the source record, the pinned BC01 inputs and the `source_closure` of `Health` come from `V3_SOURCE_ROOT` instead of the module location. A host whose checkout differs from the root's bytes fails the source commitment, as it does against the Python server.
- **Shared contract.** Since V3-R1 `validate_execution`, `publication_passes`, `parse` and `to_serde` live once in `privoke_contracts::v3` (a `serde_json` dependency of the contracts crate); `privoke_training::v3_fit` keeps thin wrappers and `contract.rs` only maps errors.
- **Message text of propagated RPC errors.** A dependency failure that Python lets escape as `grpc.RpcError` is `UNKNOWN` here with the code and message of the status; the text is not compared with Python's.
- **Not ported:** a container image (`deploy/` is out of scope) and a CLI; the Python server had neither.

### Parity with Python

`evaluation/generate_v3_fuzzer_golden.py` runs the maintained `FuzzerServer` in process on the host (`evaluation/.venv-v1-v3-pipeline`; `PRIVOKE_GENERATED` names the generated protobuf clients) with the runtime and the checkpoint service replaced by scripted answers, and records the response or abort of every cycle, every wire message, every work-directory file (name, length, SHA-256) and the `cycles` rows. The fit request that crosses the fake channel is the oracle's own frozen schedule over the committed pinned inputs of `privoke-curriculum`.

- `synthetic` (committed, `tests/fixtures/v3_fuzzer_cycles_golden.json`, no study data beyond the committed fixtures): the runtime evidence and the manifest are synthesised to satisfy `validate_execution` and `validate_manifest`. 3 sequences and 19 cycles cover both samplers, both scopes, a replay, scope reuse, a bad budget, a stale base, an unknown-outcome retry, policy and source commitment mismatches, a lost fit, tampered evidence, a manifest mismatch, a lost commit acknowledgement, an unknown commit and a mismatched receipt. `tests/replay.rs` runs in the Rust workspace CI and prints the counts (the "V3 fuzzer replay report" step).
- `recorded` (LOCAL and git-ignored, `tests/local/recorded_cycles_golden.json`, 22 MB; the files hold prompt text): the 23 retained real fits, that is the work directories of the 2 audience pilots (`audience_v3_20261013`, AU3) and of the 18 pretrained cells and 3 pilots (`pretrained_v3_20261012`, BC01), answered from their recorded fit responses, manifests and receipts. The Python oracle reproduced all 23 cycles with every file (`cycle-request.pb`, `source.json`, `fit-request.pb`, `fit-response.pb`, `evidence.json`, `commit-request.pb`, `receipt.pb`) and the recorded host response byte-identical to what the retained run wrote (the `source_hashes` of the retained records are inputs, because they pin the Python bytes of the time). `tests/replay.rs` replays it when `PRIVOKE_V3_FUZZER_RECORDED_GOLDEN` names the file; otherwise it is skipped. Regenerate it with `python evaluation/generate_v3_fuzzer_golden.py recorded --models <checkout>/models/experiments --results <checkout>/evaluation/results`.

The G5 normalisation (`tests/conformance/normalization.toml`) replaces timestamps and server-generated identifiers; none occurs in these records, so every comparison is exact. `tests/mtls.rs` runs the real listener: a registered publisher or trainer runs a complete cycle (the fit request has 64 training rows, 16 guard rows and exactly `[SEMANTIC]`); an unregistered certificate and a `runtime`-role certificate are `PERMISSION_DENIED` before any cycle (no call reaches a dependency, no `cycles` row, no work directory); a peer with no certificate and a server certificate from an untrusted CA are refused.

### Routine mode (stage V3-R5)

`V3_MODE=routine` (default `frozen`) loads both samplers and serves routine requests beside nothing else: the frozen request contract is unchanged in frozen mode (the recorded replay of 23 fits is identical). A routine request carries what the scheduler allocated: `request_id`, `seed` (the scheduler seed `S`), `expected_base` and `policy_sha256` in the metadata, and `sampler` (BC01 or AU3). The fuzzer computes and records the rest:

- **Routine commitment** `C` (`source::routine_commitment`): SHA-256 of the canonical record `{schema, domain, sampler, inputs, source_hashes, policy_sha256, seed}`. It covers no row of the schedule, so the guard can be selected from it without circularity. `source::routine_commitment_of_source` recomputes it from the `source` of fit evidence plus `S` and the policy digest, which is all a verifier (param-update, V3-R2) needs.
- **Schedule seed** `routine_guard_seed(S, C)`. The schedule is the frozen sampler at that seed, so the runtime's `validate_bc01`/`validate_au3` and the store's `validate_source_evidence` accept a routine source unchanged. The guard rows come from `privoke_curriculum::v3::routine_guard_rows(release, S, C)` and must equal the schedule's guard (BC01 reselects its 16 rows per seed; AU3's are the release's fixed 16).
- **Source commitment** is still the digest of the canonical source record (the runtime requires it). `routine.json` in the work directory and the response metadata (`mode`, `sampler`, `seed`, `routine_commitment`, `schedule_seed`, `source_commitment`) record all of it.
- **Restart rule.** The scheduler journals `(request_id, S, expected_base)` before calling and, after a restart, asks the store `GetCommitStatus` for that identity. If the fuzzer's work directory holds `commit-request.pb`, re-asking with the same identity and content resumes: the recorded commit is looked up and, if the store never saw it, re-sent with the same bytes (idempotent by request id); nothing is refitted. If the fit was lost, the scheduler allocates a new request id (and seed); re-using an identity with other content is `ALREADY_EXISTS` at the fuzzer and at the store.
- **Tests.** `tests/routine.rs` (CI): a fake runtime and store (`tests/common/fakes.rs`) that apply the real request checks and the param-update store's own source-evidence validator; HEADS then FULL per tier through the mutual-TLS listener, asserting `[SEMANTIC]` on every request and layer 4 in every evidence; crash and restart cases. `tests/routine_real.rs` (local, `PRIVOKE_V3_ROUTINE_PACKAGES`, `PRIVOKE_V3_ROUTINE_OUT`): the same cycle on real weights through the real runtime and store, with timings and L2 records.

## `privoke-v3-runtime` (stage 22)

> Plan: [Rust server rewrite](../plans/rust-server-rewrite.md#stage-22-pretrained-v3-runtime-and-training-server-in-rust-d7). Binary: `v3-runtime-service`. RUST-S22.

`rust/services/v3-runtime` replaces `services/pretrained-v3/src/runtime_server.py`. One mutual-TLS port serves `PrivokeRuntimeService.AnalyzePrompt` (V3 semantic inference, over `privoke-semantic`) and `TrainingService` (`FitCandidate` over `privoke_training::v3_fit`, `GetFitStatus`, `Health`). The Python file stays as the parity oracle. Out of scope: the fuzzer (`v3-fuzzer`). `checkpoint_server.py` is the param-update `CheckpointService` ([V3 checkpoint store](#v3-checkpoint-store-stage-v3-r1)).

**LLM-layer isolation.** `AnalyzePrompt` and `FitCandidate` require `layers == [SEMANTIC]`, a model (inference) and no presence gate; an empty list is `INVALID_ARGUMENT`, never the whole pipeline. All results here are semantic-only.

### Configuration

`V3_CHECKPOINT_TARGET` and `V3_RUNTIME_STATE` and `V3_SOURCE_ROOT` (required), `V3_PORT` (50171), `V3_BIND` (127.0.0.1), `V3_TORCH_THREADS` (4), `V3_DEVICE` (`cpu` only; anything else is refused at startup), `V3_AUDIENCE_MANIFEST_PATH`/`_SHA256` (both or neither), `V3_REQUEST_TIMEOUT_SECONDS` (7800). Outbound: `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE`, `V3_CHECKPOINT_TLS_SERVER_NAME`. Flags: `--cert --key --client-ca --crl --registry`. Image: `rust/services/v3-runtime/Dockerfile`; study-stack override: `compose.study.yml`.

### Deliberate differences from Python

- No plaintext listener; roles: `AnalyzePrompt`/`Health` for publisher, trainer and runtime services, `FitCandidate`/`GetFitStatus` for publisher and trainer.
- CPU only (CUDA is not ported). `capabilities` describe this build (no torch or transformers versions); the evidence records `device=cpu`, `torch=privoke-training-rust`.
- `GetFitStatus` answers while a fit runs (Python waited on the lock). `PrivokeRuntimeService.Health` and the four RPCs Python never served (`ComputeSemanticGradients`, `ComputeUnderlyingModelGradients`, `DetectAnnotationPresence`, `ComputePresenceGradients`) answer `UNIMPLEMENTED` naming the gap (Python's `Health` there could never serialise).
- gRPC errors from the checkpoint service print in the `_InactiveRpcError` shape without `debug_error_string`.
- The fit runs in its own task: a caller that gives up stops it at the next step and the row becomes `failed`, as Python's `is_active()`.
- Cached assets are written to a temporary name and renamed.
- `Admission::Structural` (tests only, not selectable from the binary) skips the admitted-tier pins so synthetic packages can run.

### Parity with Python

Oracle: `evaluation/generate_v3_runtime_golden.py` runs the real `RuntimeServer` with an in-memory checkpoint stub (environment `preflight` replaced). Committed synthetic goldens (`tests/fixtures/v3_runtime_*_golden.json`, synthetic V3 package plus the committed BC01 fixtures) are replayed in CI by `tests/analyze_replay.rs` and `tests/fit_replay.rs`; results of the pushed head are recorded in the plan. Gated real-data replays (`tests/analyze_release.rs`, `tests/fit_release.rs`) read git-ignored goldens under `tests/local/`; see the plan for their commands.

## `privoke-runtime` (stage 17)

> Checkpoint 3a (RUST-S17A, [below](#presence-the-presence-gate-and-the-gradient-rpcs-checkpoint-3a)) adds the presence gate, `DetectAnnotationPresence` and the gradient RPCs for the shapes stage 19 ported; where this paragraph says they are not done, read that section.
>
> Status: checkpoint 3b of stage 17 (checkpoint 3b, RUST-S17B: telemetry in the controller, fetch parity with Python, no HTTP stack in the worker, the pretrained contextual encoder; the presence and gradient routes of 17a are described below). Earlier text of this paragraph, from checkpoint 2: The regex, NER and semantic layers (legacy Tiny artifacts and pinned V3 packages from read-only model roots), `Health`, the pipeline and policy aggregation and the supervisor routing are done and green in CI. The presence gate, the pretrained contextual encoder, `DetectAnnotationPresence`, the gradient RPCs, GLiNER selection, the Rust-side model fetch (D11) and the telemetry wiring are **not** done; the Python worker serves them, and the routing keeps every call that the Rust worker does not claim on it. What remains is listed at the end of this section.

`rust/services/runtime` (`privoke-runtime`, binary `privoke-runtime-worker`) is the `PrivokeRuntimeService` analysis path of `extension/client-runtime/src` as a worker behind the W1 frame protocol ([worker protocol](worker-protocol.md#the-rust-worker-stage-17)). The pool (W2) starts it where it starts `worker_shim.py`; spaCy runs in the same process through the stage 11b `InProcess` backend (no spaCy process), so the W2 sandbox and restart cover the whole thing, and an interpreter crash kills this worker only.

| Module | Ports |
| --- | --- |
| `model` | `privoke_contracts/classification.py`, `classification_policy.py`, `ClassificationResult` and `pipeline.strongest_result`: the packed classification, the action policy with its below-0.5 confidence rule, the combined evidence, and the first-of-equals tie rule of Python's `max`. |
| `request` | `hosting/serialization.parse_prompt_request` and the layer, regex-order and presence-gate checks of `hosting/grpc_server.py`, with Python's messages (`str.strip`, code point lengths, the `json.dumps` length of metadata values). |
| `pipeline` | `pipeline.analyse_text` for the regex and NER layers: regex first by default (`PRIVOKE_WAIT_FOR_REGEX`) and the other layers skipped after a `BLOCK`, a failing layer reported as that layer's `error` and blocking an otherwise ALLOW. Composes `privoke-rules` and `privoke-ner-layer`; the NER layer reads spaCy through `SpacyBackend`. |
| `response` | The visibility hint, the masked prompt, the `reason`, the metadata map and the `AnalyzePromptResponse` bytes. |
| `wire` | A small protobuf encoder that writes what `upb` writes with `SerializeToString(deterministic=True)`: field order, proto3 defaults left out, and **every map entry written with its key and its value**. `prost` leaves the value out of an entry whose value is the default (the W3 finding), so responses are not built with it; `prost` only decodes requests. |
| `semantic` | The semantic layer over read-only model roots: `<id>.json` legacy Tiny artifacts, `<id>/manifest.json` pinned V3 packages, and the controller's cache layout `<id>/<pin>/manifest.json`. A model is rebuilt only when its bytes change. It attaches the result metadata Python attaches (`classifier`, `architecture`, `model_id`, `model_version`, `parameter_count`, `parameter_fingerprint`, `artifact_checksum`, `compute_device`, `category_probabilities`; for V3 also `backbone_sha256`, `tokenizer_sha256`, `torch_threads`) and the response identity `privoke.semantic.*`. |
| `store`, `presence`, `gate`, `training` | Checkpoint 3a: the read-only artifact reader (`LocalModelProvider` and `load_artifact`), `DetectAnnotationPresence` and the presence models, the gate trace, and the three gradient RPCs over `privoke-training` with Python's response metadata. See the section below. |
| `frames`, `service`, `worker` | The W1 codec and limits, the request handling (one frame in, one frame out), the READY announcement, the sandbox self-check and the serve loop. |

### Behaviour kept, and where it differs

- A validation failure, an unsupported layer value and a bad regex order are ordinary responses with `error` set under the request's own `request_id`, as in Python; `ERROR` frames are for protocol faults. An empty layer list and `DETECTION_LAYER_RUNTIME` are `INVALID_LAYERS` before anything runs.
- A selection the worker does not serve gets `UNSUPPORTED_LAYERS`, and a presence or gradient request it does not serve gets `UNSUPPORTED_ROUTE` (checkpoint 3a), before anything runs, so a mis-routed call fails visibly and is never answered wrongly.
- The NER layer's own errors differ in wording only where Python's come from the spaCy library (a worker `Unavailable` replaces a Python exception); both are layer errors that block an ALLOW.
- No parallelism between regex and NER (Python runs them on a thread pool when regex-first is off); the results do not depend on it.
- The worker has no telemetry code and no network code. Its sandbox self-check opens and closes loopback sockets to test that it cannot, and `privoke-contracts` brings the `tonic` types in as a dependency, but no code path here opens a connection.

### Supervisor routing

`rust/services/runtime-supervisor/src/routing.rs` decides which worker serves a call, by RPC path (`Rpc::from_path("/privoke.v1.PrivokeRuntimeService/...")`) and, for `AnalyzePrompt`, by layer selection. `PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust` adds a second pool (`privoke-runtime-worker`, found beside the supervisor or at `PRIVOKE_RUNTIME_RUST_WORKER`); the default `python` starts none, so nothing changes by default. The Python worker is always started, because it serves what the Rust worker does not.

| Call | Engine |
| --- | --- |
| `AnalyzePrompt`, every layer regex or NER | Rust |
| `AnalyzePrompt` naming the semantic layer | Rust when the Rust worker was given model roots (the controller's model cache exists) and the request has no unserved presence gate (the pretrained contextual encoder is a semantic model of the Rust worker since RUST-S17B); otherwise Python |
| `AnalyzePrompt`, any other selection (empty, runtime, unknown value) | Python |
| `Health` | Rust |
| `DetectAnnotationPresence`, semantic-only selection, sparse presence model | Rust with model roots; a scratch model, any other selection, or no model roots: Python |
| `AnalyzePrompt` with a sparse presence gate | Rust when the worker serves the semantic layer and presence; a scratch gate: Python |
| `ComputeSemanticGradients`, `ComputeUnderlyingModelGradients` | Rust with model roots and no admission header or the objective-only header (schema 2); any other header: Python |
| `ComputePresenceGradients` | Rust with model roots |

The claim is one constant (`Capabilities::RUST` claims presence and gradients; `with_semantic()` when the worker has model roots, `without_models()` when it has none); a later stage that ports another part changes it and the router follows. A call is never retried on the other engine, and a Rust worker that is down is a failed call (`UNAVAILABLE`), not a silent fallback. The controller reports the runtime as running only when every configured pool is ready. The W3 analysis service (`rust/services/analysis`) is not changed: it still starts the Python shim, and can start this worker with the same routing table when its owner wires a second pool.

### Parity with Python

`evaluation/generate_runtime_golden.py write` runs the unchanged `PrivokeRuntimeService.AnalyzePrompt` (host Python, `evaluation/.venv-v1-v3-pipeline`, read only) on 238 requests with explicit layer selections and records the response, serialised deterministically with `elapsed_ms` and `metadata["elapsed_ms"]` cleared (the normal form of the W1 capture), plus every spaCy result the NER layer saw and the lexicon words the post-filter asked about. No request has an empty layer list or names the semantic layer. The fixture is synthetic (the W1 capture's 20 prompts, nine more generic sentences and 17 validation cases); nothing from a recorded dataset is read.

| Scope | Requests | Byte-identical in Rust |
| --- | ---: | ---: |
| detector ablation (one layer) | 99 | 99 |
| product pipeline (regex and NER) | 122 | 122 |
| validation and policy | 17 | 17 |
| of which: requests taken from the W1 capture, whose recorded Python digests are matched | 60 | 60 |

The 238 are 5 selections for each of 29 prompts (regex, NER, both, both with the parallel order, both with the first order), the six visibility hints on a NER finding and on a regex finding, context-field stripping, duplicate layers, an ignored semantic model id, and the validation cases (empty, blank, over and at the length limit, a bad hint, control characters, over-long fields, metadata limits, unsupported layer and order values, and the presence-gate checks). The 60 W1 capture requests are among the 238. Regeneration is byte-identical (`evaluation/tests/test_generate_runtime_golden.py`). The Rust test is `rust/services/runtime/tests/golden.rs`; CI prints the counts (`Runtime golden report`).

The spaCy results are replayed, so this is parity of the Rust logic with Python given the same spaCy output, and spaCy itself is identical by construction (stage 11b). The real-interpreter run needs the bundle and is pending for stage 23.

**Floats.** The regex and NER findings carry confidences from tables, so no float rounding is involved here and the responses are byte-equal, including the product pipeline of both layers (the plan requires byte equality only for regex-only and NER-only; it holds for the pair as well, where no model float exists). The rule for selections that do involve model floats is declared in `tests/conformance/normalization.toml`, section `analysis_runtime`: decisions exact, floats equal after rounding to 6 decimal places or within an absolute 1e-5, only the wall-clock fields cleared.

### Semantic parity (LLM-only, reported apart)

`evaluation/generate_runtime_golden.py semantic` serves the four tracked legacy models (`models/privoke-{baseline,efficient,balanced,quality}.json`) to the unchanged Python servicer the way the Python worker serves them (`worker_main.LocalModelProvider`, read-only files) and records 135 requests. Each `llm_only` request has `layers = [DETECTION_LAYER_SEMANTIC]` and nothing else; the generator asserts that the returned layer execution is exactly the semantic layer with status `ok`, and so does the Rust test for every Rust response. The `product_pipeline` rows (regex, NER and semantic, in both execution orders) are separate.

| Scope | Requests | Within the declared rule | Byte-identical |
| --- | ---: | ---: | ---: |
| LLM-only (semantic only): 4 models on 29 prompts, a visibility hint, unknown, invalid and unresolvable model ids, a long prompt | 121 | 121 | 120 |
| product pipeline (regex, NER and semantic) | 14 | 14 | 14 |

The rule is the one of `tests/conformance/normalization.toml`: every decision field and text exactly, confidence after rounding to 6 decimal places or within 1e-5, and the 4-decimal `category_probabilities` within one unit of their last digit. The one response that is not byte-identical differs only inside that tolerance. These are tracked synthetic-prompt rows on legacy Tiny models; **the pinned V3 releases and the recorded sets are not covered** (the pinned-release parity run of stage 14 is still local-only and pending), and V3 loading in the worker is exercised only through its refusal paths here.

### Presence, the presence gate and the gradient RPCs (checkpoint 3a)

RUST-S17A. The worker serves `DetectAnnotationPresence`, the sparse presence gate of `AnalyzePrompt` and the three gradient RPCs, reading models from `--model-root` directories the way `LocalModelProvider` does (`store.rs`: size budget, schema, tensor checks, the checksum over the canonical content, the raw `config` text; a pinned V3 package or non-string metadata is declined, not served).

- **Presence.** `presence.rs` builds `privoke_training::presence::PresenceModel` from the artifact with the `StreamedPresenceModel` checks and the provider's identity (version, artifact checksum, parameter fingerprint). `DetectAnnotationPresence` follows `grpc_server.py` check for check. A scratch model id is the Python worker's error ("not available").
- **Gate.** `Pipeline::analyse_gated` and `SemanticLayer::run_gated` follow `_execute_semantic_with_presence_gate`: the semantic model classifies the normalised prompt, the gate probability against the request's threshold or the model's own keeps or drops the findings, and the layer carries the `SemanticPresenceGateTrace` in every case Python reports one (applied, error after the layer ran, not run, skipped after a regex BLOCK). A gated execution carries no `privoke.semantic.*` identity, as in Python. The request checks (gate model, semantic layer, `semantic_model_id='privoke-balanced'`, threshold in [0, 1]) have Python's messages. A scratch gate is refused with `UNSUPPORTED_LAYERS`.
- **Gradients (`training.rs`).** Served: the single-update route on full-capable Tiny artifacts, head and full-encoder scopes, legacy, class-balanced, mean-category, decision-margin and summed-margin objectives, with no admission header or the objective-only header (schema 2); the FULL Adam admission refusal (an artifact that declares FULL Adam and a request without the matching header gets Python's error, via `privoke_training::admission`); sparse presence gradients. The response metadata is Python's (`strategy`, scope, inventory and base/updated fingerprints, `model_config`, `model_cache_key`, the weight audit, the mean-category block) and the `reject_overlength` token check of full-capable artifacts is reproduced.
- **Declined before anything runs (`UNSUPPORTED_ROUTE`).** A header of another schema (backtracking, FULL Adam, retention, window) or a malformed or repeated header; an artifact that is not full-capable, that declares an optimizer (local SGD, FULL Adam with its own admission, window, retention), diagnostics, backtracking, eligibility or window policy, or an objective outside the verified set; a row without an explicit target; a pinned V3 package; a worker without model roots. The FULL Adam fit itself stays on Python: its audit trace hashes the float64 gradient bytes, which match only for bitwise-equal gradients.
- **Routing.** `routing.rs`: `Capabilities::RUST` now claims `presence` and `gradients` (with `without_models()` for a worker without roots); `route_analysis`, `route_presence` and `route_gradients` decide per request (gate model, presence model, admission header); `call_routed` sends a call the Rust worker refused (`Attempt::Refused`) once to the Python worker, and never retries a failure, so no call runs twice. The controller itself still dispatches only `AnalyzePrompt`; the gradient and presence dispatcher is the analysis service's (W3), which was not changed.

**Golden.** `evaluation/generate_runtime_worker_golden.py write` hands the unchanged Python `worker_main.Dispatcher` W1 frames (with the admission header in a metadata block) over synthetic artifacts committed in `rust/services/runtime/tests/fixtures/worker_models/` and the tracked legacy models (the gate's semantic model), and records 190 answers. Every request names its layers explicitly and non-empty (semantic only; the 11 `product_pipeline` gate rows add regex and are reported apart); no empty list is ever sent to Python. Regeneration is byte-identical (`evaluation/tests/test_generate_runtime_worker_golden.py`, 7 tests).

| Scope (method) | Rows | Within the rule | Byte-identical |
| --- | ---: | ---: | ---: |
| LLM-only gated `AnalyzePrompt` | 61 | 61 | 61 |
| Gate, regex plus semantic (product pipeline) | 11 | 11 | 11 |
| `DetectAnnotationPresence` | 27 | 27 | 27 |
| Gradients, single update (heads 7, full encoder 6) | 13 | 13 | 0 |
| Presence gradients | 6 | 6 | 6 |
| Validation and refusals | 72 | 72 | 72 |

Gradients: 13,518 transported coordinates, all within 1e-6 (max 1.12e-7), 8,518 bitwise equal; 440 of 440 metrics within the rule; the fingerprints of the updated floats equal in 18 of 31 (they may differ only when a coordinate is not bitwise equal, which the test enforces). The rule is `[worker_gradients]` of `tests/conformance/normalization.toml`. These are LLM-only rows except where labelled; the declined shapes are tested for `UNSUPPORTED_ROUTE` (`shapes_the_worker_does_not_serve_are_refused_before_anything_runs`).

**Checkpoint 4 (RUST-S19C, item 2c).** The worker serves the local-SGD, TRAIN-diagnostics and FULL backtracking routes of `ComputeSemanticGradients` and `ComputeUnderlyingModelGradients` on full-capable Tiny artifacts, with the schema 1 (backtracking) and schema 2 (with or without the diagnostics policy) admission headers; `served_artifact` is now `privoke_training::admission::admit` over the artifact metadata, the response carries the route metadata, the backtracking rejection `error` and the opt-in fields of the cache key, and `ComputeSemanticGradients` with a backtracking header answers `Backtracking admission is FULL-only.`. A FULL Adam, window or retention artifact gets Python's policy and admission refusal as a response, or is declined to Python when its checks pass. `routing::route_gradients` sends the served headers to Rust and every other header to Python (`routing::admission_is_served`, replacing `admission_is_objective_only`). The worker golden `worker_routes_golden.json` (`generate_runtime_worker_golden.py routes`, 12 route cases and 6 refusals over W1 frames, 7 new synthetic artifacts) is checked by `the_route_answers_match_the_python_worker`: 9,828 coordinates within 1e-6 (4,608 bitwise), 302 of 302 metrics, 19 JSON traces under the `[worker_gradients]` rule of `tests/conformance/normalization.toml` (`json_metadata_keys`, `json_metadata_float_relative_tolerance`), refusals byte-identical.

**API changes.** Checkpoint 4: `privoke_training::{routes, trace}` (new), `admission::{Header, Policy, Route, Admitted, policy_admission, validate_backtracking_policy, admit}` and the window and retention policies in `validate_policy` (a window or retention artifact is no longer reported as unsupported), `rpc::Snapshot` gains `optimizer`, `diagnostics` and `backtracking` (and derives `Default`), `rpc::Batch` gains `error`, `inventory` and `metadata`; `privoke-supervisor`: `routing::admission_is_served` replaces `admission_is_objective_only`. Earlier: `privoke_training::presence::PresenceModel::threshold()` (additive). `privoke-runtime`: `frames::Request.metadata`, `frames::{encode_metadata, split_metadata}`, codes `INVALID_METADATA` and `UNSUPPORTED_ROUTE`, `pipeline::LayerExecution.gate`, `Pipeline::{with_presence, analyse_gated, serves_gate, presence}`, `Service::with_training`, `wire::{double_always, packed_f32, packed_u32, double_map}`, modules `store`, `presence`, `gate`, `training`. `privoke-supervisor`: `routing::{route_presence, route_gradients, call_routed, Attempt, is_refusal, Capabilities::without_models}` and `Capabilities::RUST` (presence and gradients now true).

### Tests

- `tests/worker_golden.rs` (checkpoint 3a): 190 presence, gate and gradient comparisons with the Python worker, the refusals and the declared rule.
- `tests/semantic_golden.rs`: the 135 semantic comparisons above.
- `tests/golden.rs`: the 238 byte comparisons through the frame codec, the W1 capture digests, and the declared float rule.
- `tests/context_semantic.rs`: the semantic layer on the pretrained contextual model against the Python findings, metadata and identity (LLM-only: the semantic layer alone), the empty classification, the context-length error naming the model, missing and non-pinned assets, and seven artifacts that break the contract.
- `tests/worker_process.rs`: the real worker binary as a child process on the pool framing, with the Python-free stand-in spaCy engine (`--spacy fake`, feature `fake-spacy`): READY, `Health`, regex and NER analysis, `INVALID_LAYERS`, `UNSUPPORTED_LAYERS`, `UNKNOWN_METHOD`, `INVALID_PAYLOAD`, malformed frames, the text limit, a clean exit when the pipe closes, the sandbox self-check, and a usage error. Every child is killed in a drop guard.
- Unit tests in `model`, `request`, `response`, `wire` and `frames`.
- Supervisor: `routing.rs` unit tests (paths, layers, capabilities, the engine setting), `worker.rs` (the Rust worker settings), and `tests/routing.rs`, which runs the real controller process with two stand-in workers and checks that each call reaches the engine that serves it.
- CI (`rust-ci.yml`): the `embed-check` job lints the worker with `--features in-process` (CPython 3.11 development install), and the test job prints the golden counts.

### Not in this checkpoint

- **The external classifier** (`PRIVOKE_LLM_CHOICE=open`): it needs the network, which the worker never has, and the Python worker forces the streamed choice for the same reason. The stage 16 client stays in `privoke-semantic` behind the cargo feature `external-classifier`; the worker depends on the crate without it, so no HTTP client is linked (asserted in CI).
- **The pretrained contextual encoder** is served (RUST-S17B): `privoke-pretrained-context-minilm.json` in a model root and the backbone and tokenizer in the directory of `--pretrained-context-dir` (the controller passes `PRIVOKE_PRETRAINED_CONTEXT_DIR` when set); the identity is `privoke.pretrained_context.*`, which the response carries even when the layer failed. It is golden-tested against the Python heads over a synthetic backbone with a numpy float32 reference (`tests/context_semantic.rs`, `privoke-semantic/tests/context_golden.rs`); agreement with onnxruntime on the real file is not measured. The artifact checksum is not recomputed (as for Tiny artifacts). Without the asset directory the model is the layer's error. `routing.rs` no longer sends this model id to Python.
- Scratch-presence artifacts stay on the Python worker. The analysis service's `<id>.snapshot.pb` cache layout is read since RUST-S17E (see the analysis section).
- **Pinned V3 releases** (RUST-S17H, local): compared with the Python W1 worker, LLM-only, on the stage 14 selection: 6,105 of 6,105 rows within the declared rule, 6,104 byte-identical, identity fields identical (one rounding-boundary confidence row, accepted by the stated rule). `tests/v3_release.rs`, env-gated on `PRIVOKE_RUNTIME_V3_GOLDEN` (written by `evaluation/generate_runtime_v3_golden.py real`, git-ignored, holds prompt text) and `PRIVOKE_V3_RELEASES`; skipped in CI. Command: `docker run --rm --name s17h-v3 --cpus=8 -e CARGO_TARGET_DIR=target-docker -v <worktree>:/work -v <models/standard-releases>:/releases:ro -w /work/rust -e PRIVOKE_V3_RELEASES=/releases -e PRIVOKE_RUNTIME_V3_GOLDEN=/work/rust/services/runtime/tests/local/v3 rust:1.99.1-bookworm cargo test -p privoke-runtime --release --locked --test v3_release -- --nocapture`. The golden is generated with `OMP_NUM_THREADS=4`: the worker reports the constant 4 as `torch_threads`, the Python worker the thread count of its torch.
- **D11** fetch code in the worker: none, by design (no network). The front ends fetch in Rust and are now compared with the Python fetch ([above](#parity-with-the-python-fetch-d11-rust-s17b)).
- GLiNER selection (`PRIVOKE_NER_BACKEND=gliner`): the worker builds the spaCy detector only.
- Telemetry: the worker has none by design; the controller owns the reporter.
- The real-interpreter run (the stage 23 bundle) and the extension tests, which are pending for stage 23.
