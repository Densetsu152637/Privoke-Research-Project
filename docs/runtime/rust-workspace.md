# Rust workspace

> Source area: `rust`. Plan: [Rust server rewrite](../plans/rust-server-rewrite.md), stages 0 and 1. Run every command from the repository root unless stated.

The workspace holds the Rust side of the server rewrite. At stage 1 it contains three libraries and no service. The Python and Go services are unchanged and remain the measured system until a later stage replaces them.

| Crate | Purpose |
| --- | --- |
| `privoke-proto` | Protobuf messages and tonic clients and servers for `shared/proto`. The `build.rs` compiles the protos with `protox`, a pure-Rust protoc, so no `protoc` is needed on any host. Map fields are `BTreeMap`, so encoding is key-ordered like Python's `SerializeToString(deterministic=True)`. |
| `privoke-contracts` | Byte-exact ports of the Python contracts: canonical JSON in four layouts including Python's float `repr`, artifact checksums, receipt keys, window-training seeds, tensor fingerprints and the pinned V3 manifest rules. Re-exports `privoke-proto` as `proto`. |
| `privoke-transport` | In-service mutual TLS, authorisation, limits and hot reload. It replaces nginx. |
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
