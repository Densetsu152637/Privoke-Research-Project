# Rust workspace

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0 and 1. Run every command from the repository root unless stated.

The workspace holds the Rust side of the server rewrite. At stage 1 it contains three libraries and no service. The Python and Go services are unchanged and remain the measured system until a later stage replaces them.

| Crate | Purpose |
| --- | --- |
| `privoke-proto` | Protobuf messages and tonic clients and servers for `shared/proto`. The `build.rs` compiles the protos with `protox`, a pure-Rust protoc, so no `protoc` is needed on any host. Map fields are `BTreeMap`, so encoding is key-ordered like Python's `SerializeToString(deterministic=True)`. |
| `privoke-contracts` | Byte-exact ports of the Python contracts: canonical JSON in four layouts including Python's float `repr`, artifact checksums, receipt keys, window-training seeds, tensor fingerprints and the pinned V3 manifest rules. Re-exports `privoke-proto` as `proto`. |
| `privoke-transport` | In-service mutual TLS, authorisation, limits and hot reload. It replaces nginx. |

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

The registry here is the in-memory model. Stage 2 adds the file format, its hot reload and the issuing tool.

### Fail-closed startup

`startup::CloudTlsArgs` is the flag set every cloud binary flattens into its arguments: `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`. `into_config` returns an error naming the first missing or unusable input, and the binary must exit non-zero before binding. There is no insecure flag. `privoke-listener-probe` (built with the `probe` feature) is the reference binary, and `cargo test -p privoke-transport fail_closed` runs it.

### Plaintext loopback

`listener::loopback` exists only with the `workstation-loopback` feature, which is off by default and must be enabled only by the workstation supervisor and tests. It refuses to bind a non-loopback address and never carries an identity, so `AuthLayer` answers `UNAUTHENTICATED` to it. The check that a cloud build does not enable the feature is:

```
cargo tree --locked -p privoke-transport -e features -e no-dev --manifest-path rust/Cargo.toml
```

The output must not contain `workstation-loopback`; `fail_closed_release_dependency_tree_has_no_plaintext_feature` asserts it.

## Not in this stage

No service, no PyO3, and no CI job (no `.github/` change before the submission deadline). The registry file format and the `privoke-pki` tool are stage 2.
