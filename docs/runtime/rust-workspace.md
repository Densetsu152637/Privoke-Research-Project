# Rust workspace

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0 to 3 and 11. Run every command from the repository root unless stated.

The workspace holds the Rust side of the server rewrite. Stages 1 and 2 added three libraries and the PKI tool; stage 3 adds the first service, `privoke-model-streaming`; stage 11 adds the spaCy client crate and the spaCy worker. The Python and Go services are unchanged and remain the measured system until a later stage replaces them.

| Crate | Purpose |
| --- | --- |
| `privoke-proto` | Protobuf messages and tonic clients and servers for `shared/proto`. The `build.rs` compiles the protos with `protox`, a pure-Rust protoc, so no `protoc` is needed on any host. Map fields are `BTreeMap`, so encoding is key-ordered like Python's `SerializeToString(deterministic=True)`. |
| `privoke-contracts` | Byte-exact ports of the Python contracts: canonical JSON in four layouts including Python's float `repr`, artifact checksums, receipt keys, window-training seeds, tensor fingerprints and the pinned V3 manifest rules. Re-exports `privoke-proto` as `proto`. |
| `privoke-transport` | In-service mutual TLS, authorisation, limits, the identity registry and hot reload. It replaces nginx. |
| `privoke-pki` (`rust/tools/privoke-pki`) | Operator CA tool and installation enrolment: `init-ca`, `issue-server`, `issue-reporter`, `sign`, `sign-service`, `revoke`, `crl`, and the installation commands `enrol`, `renew`, `install-cert` and `status`. The library is what `privoke-supervisor` will call. |
| `privoke-model-streaming` (`rust/services/model-streaming`) | The model-streaming service that replaces the Go service: legacy float catalog, standard V3 packages, two mutual-TLS listeners and a `healthcheck` subcommand. See [below](#privoke-model-streaming). |
| `privoke-spacy` | Client of the spaCy worker: the framed protocol, UTF-8 and UTF-16 offset conversion, and the supervised worker pool. No Python dependency. |
| `privoke-spacy-worker` (`services/spacy-worker`) | The worker process. It embeds CPython 3.11 through PyO3 and serves the unchanged spaCy `en_core_web_sm`. The `embed` feature is off by default, so the workspace builds and tests without Python. |
| `privoke-runtime-supervisor` (`rust/services/runtime-supervisor`) | The workstation supervisor `privoke-supervisor` (stage 7): native-messaging host, runtime child supervision, loopback control service, model fetch and the enrolment commands. See [below](#privoke-runtime-supervisor-stage-7). |
| `privoke-rules` | The regex rule layer (300 rules including the ported Presidio recognisers and the Gitleaks catalogue) and the canonical-text preprocessing with offset maps, identical to the Python client runtime (stage 12). |

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

## Not in this stage

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

## `privoke-runtime-supervisor` (stage 7)

Plan: [stage 7](../plans/rust-server-rewrite.md#stage-7-rust-runtime-supervisor), as revised by the [worker isolation architecture](../plans/rust-server-rewrite.md#worker-isolation-architecture-user-decision-17-november-2026). Binary: `privoke-supervisor` (`rust/services/runtime-supervisor`). It replaces three Python files: the native-messaging host (`native_messaging_host.py`), the process supervisor (`runtime_supervisor.py`) and `PrivokeRuntimeControlService` (`main.py`). The gRPC-Web bridge (`grpc_web_bridge.py`) is not rebuilt, and the extension transport is unchanged until W4. The Python supervisor, host and bridge stay in place as the oracle.

```
cargo test -p privoke-runtime-supervisor --locked --manifest-path rust/Cargo.toml
```

| Command | Does |
| --- | --- |
| (none) or `native-host` | The native-messaging host on stdio. A browser starts it with only the calling origin, which is ignored. |
| `serve` | The supervisor: the runtime child plus the loopback control service on `127.0.0.1:50056`. Environment names are the Python ones (`PRIVOKE_LOCAL_RUNTIME_PORT`, `PRIVOKE_CONTROL_GRPC_PORT`, `PRIVOKE_RUNTIME_START_ENABLED`, the timeouts). |
| `enrol`, `renew`, `install-cert`, `status` | The installation side of enrolment, calling `privoke_pki::client`. `--dir` defaults to `PRIVOKE_CREDENTIAL_DIR`, else `%LOCALAPPDATA%\PriVoke\credentials` or `$XDG_DATA_HOME/privoke/credentials`. The key never leaves that directory; `status` reads local files only, warns 30 days before expiry and says what still works after it. |
| `fetch-model [--model-id latest]` | Downloads the standard V3 package over mutual TLS and verifies it into the user cache (below). |

### Native host

The wire format is the Python host's: a native-endian `u32` length and a JSON body of at most 1 MiB, one supported action (`ensure_supervisor`). The replay tests feed every stage 0 transcript (`tests/conformance/native_messaging.json`, 17) to the library and to the real process (34 replays) and compare the bytes written. Replies are `json.dumps` compact with `ensure_ascii`. A truncated header or body, an oversized length, invalid UTF-8 or invalid JSON ends the process with exit code 1 and no reply, as the Python exception did, and a top-level `null` ends the session as end of input did. The JSON reader accepts what Python's does (`NaN`, `Infinity`, lone surrogate escapes, duplicate keys, huge integers), because `serde_json` would turn a message Python answered into a crash.

Two normalisations in the replay: `<ROOT>` and path separators (the recorded `supervisor-entry-missing` message), and the two port numbers of the `control-port-conflict` message. The recording used the real ports 8080 and 50056; the replay binds ephemeral ports instead (a real runtime may hold the real ones) and maps the numbers back before rebuilding the frame, so the framing is still compared byte for byte. Ports, the entry program and the timeout can be changed only in a build with the `test-helpers` feature.

`ensure_supervisor` keeps the Python order: bridge port open means already running, control port open means conflict, otherwise start the entry detached and wait for the bridge port. The entry is `privoke-supervisor serve` instead of `main.py`. Because the bridge is not rebuilt, nothing in the Rust build opens port 8080; until W4 a Rust-only install answers `ensure_supervisor` with a timeout. The Rust control service can sit behind the Python bridge (it serves the same `PrivokeRuntimeControlService`), which is how the oracle is exercised.

The native-host manifest templates are written by `extension/runtime-supervisor/scripts/install-native-host.{sh,ps1}`. Set `PRIVOKE_SUPERVISOR_BINARY` (sh) or pass `-SupervisorBinary` (ps1) to register the Rust executable (`<binary> native-host`) instead of the Python host; unset, nothing changes. These two scripts were checked for syntax only; running them writes the user's real registration, so they were not run.

### The runtime child and "children die with the supervisor"

`process.rs` is the port of `RuntimeProcessSupervisor` (same messages, same start, stop and stack-switch rules). All state lives on one long-lived thread, which both serialises requests like the Python lock and satisfies the Linux rule that the parent-death signal follows the thread that started the child. The child is always the fixed argv `python src/grpc_main.py` (after `dependency_check.py`), loopback only; no caller of the control service can change argv, directory or environment. A test build can replace the argv through `PRIVOKE_TEST_RUNTIME_COMMAND`; a normal build has no such switch.

`confine.rs` is the confinement. Windows: a Job Object with kill-on-close, the child created suspended, put in the job and resumed, so even the venv `python.exe` redirector's child is in the job. Stopping terminates the job and waits until it is empty. Linux: `PR_SET_PDEATHSIG` with a `getppid` check, `setsid`, and a signal to the process group on stop. It repeats the two operating-system calls of `privoke-worker-pool` and does not depend on that crate, whose pool needs framed workers; W4 moves the controller onto the pool and removes `confine.rs`. The Linux half follows the same pattern but was not compiled or run here (the host is Windows).

| Rule | Test |
| --- | --- |
| The runtime child dies when the supervisor is killed with no cleanup | `real_processes::the_runtime_child_dies_with_the_supervisor` |
| The whole tree (launcher and the process holding the port) dies with it | `real_processes::the_whole_runtime_tree_dies_with_the_supervisor` |
| Stop releases the port and restart works, three times, also through a launcher that starts the real runtime | `real_processes::stopping_*` |
| A failed tree termination is not reported as stopped, even when the launcher exited | `supervisor_cases::failed_tree_termination_*`, `partial_tree_failure_*` |

`stop` also waits for the runtime port to close before returning, since the operating system closes a dead process's listening socket a moment later and an immediate restart would otherwise mistake it for a foreign process.

### Control service

`PrivokeRuntimeControlService` (`SetRuntimeEnabled`, `Status`, `ModelStreamingHealth`) is served by `control.rs` on plaintext loopback through `privoke_transport`'s `workstation-loopback` listener, which refuses any other address. This crate is the only one that enables that feature, and the existing transport tests still assert that the cloud crates do not. The listener carries no identity and the cloud `AuthLayer` is not applied: any local process can call it, as it could the Python control port (GAP-LOOPBACK-PLAINTEXT-POLICY keeps this). W4 removes it from workstation installs. `ModelStreamingHealth` is lazy and reports `NOT_SERVING` for every failure (no credential, refused handshake, unregistered identity, timeout).

### Model fetch

`fetch.rs` ports `v3_package.fetch_package` and `receive_asset`, with the same cache layout and rules, so the Python runtime and the supervisor share one cache (`MODEL_PACKAGE_CACHE_DIR`, else `%LOCALAPPDATA%\PriVoke\model-packages` or `$XDG_CACHE_HOME/privoke/model-packages`). The channel (`channel.rs`) is plaintext only to a loopback target (the local development stack, as in Python); every other target needs mutual TLS with the installation certificate (`PRIVOKE_TLS_CERT_FILE` and key, else `client.crt` and `client.key` in the credential directory) and a pinned server CA (`PRIVOKE_TLS_CA_FILE`, else `server-ca.pem`); there is no system-roots fallback. `PRIVOKE_MODEL_STREAMING_TLS=true` keeps mutual TLS on loopback, which a locally run Rust model-streaming needs.

Checks, in order: the manifest bytes hash to the pin compiled into the client and satisfy the manifest contract (`privoke_contracts::v3`); the response names that model and pin; exactly the four assets are declared, with the manifest's hashes and `0 < size <= 80 MiB`; each asset stream keeps its model, pin, name, hash, total, offset and chunk bounds, ends at the declared size and hash, and is written to a temporary file that is renamed only when complete; the manifest is read again after the downloads and must be identical; the directory is re-read and re-hashed. An existing cached file is re-hashed and never overwritten; the cache path must not traverse a link. `manifest.json` is written last, so an interrupted fetch never looks complete.

One deliberate difference from Python: the request's `consumer_id` is the installation UUID (or empty), not `MODEL_STREAMING_CONSUMER_ID` (default `client-runtime`), because the Rust public listener refuses a `consumer_id` that is not the caller's own identity. The test `the_server_binds_the_caller_and_the_registry_decides_who_may_fetch` shows `client-runtime` being refused.

Tests run an in-process `privoke-model-streaming` on certificates generated at test time, and fetch the real pinned releases (read from the main checkout's ignored `models/standard-releases`; skipped when absent). A scripted server with a synthetic pin set breaks each rule on its own: a flipped byte, 12 stream manipulations, a forged manifest, response identity, 7 asset-declaration manipulations, a manifest that changes during the download, a corrupted or foreign cached file, a link in the cache path, server errors and family confusion.

### Not in this stage

The gRPC-Web bridge, the extension transport (W4), the Python worker protocol and pool (W1, W2, W4), the telemetry reporter, and any CI job. The installed-client claims (C5, C6, C42) are not claimed for this build.
