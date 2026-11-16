# Rust workspace

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0, 1 and 11. Run every command from the repository root unless stated.

The workspace holds the Rust side of the server rewrite. At stage 1 it contained three libraries and no service; stage 11 adds the spaCy client crate and the spaCy worker. The Python and Go services are unchanged and remain the measured system until a later stage replaces them.

| Crate | Purpose |
| --- | --- |
| `privoke-proto` | Protobuf messages and tonic clients and servers for `shared/proto`. The `build.rs` compiles the protos with `protox`, a pure-Rust protoc, so no `protoc` is needed on any host. Map fields are `BTreeMap`, so encoding is key-ordered like Python's `SerializeToString(deterministic=True)`. |
| `privoke-contracts` | Byte-exact ports of the Python contracts: canonical JSON in four layouts including Python's float `repr`, artifact checksums, receipt keys, window-training seeds, tensor fingerprints and the pinned V3 manifest rules. Re-exports `privoke-proto` as `proto`. |
| `privoke-transport` | In-service mutual TLS, authorisation, limits and hot reload. It replaces nginx. |
| `privoke-spacy` | Client of the spaCy worker: the framed protocol, UTF-8 and UTF-16 offset conversion, and the supervised worker pool. No Python dependency. |
| `privoke-spacy-worker` (`services/spacy-worker`) | The worker process. It embeds CPython 3.11 through PyO3 and serves the unchanged spaCy `en_core_web_sm`. The `embed` feature is off by default, so the workspace builds and tests without Python. |

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
