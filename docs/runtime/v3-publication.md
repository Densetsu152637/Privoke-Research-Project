# V3 publication: signed versions, custody and rotation

> Plan: [V3 routine training](../plans/v3-routine-training.md), stage V3-R2 (publication), serving in V3-R3 (`rust/services/model-streaming/src/published.rs`), the client side in V3-R4a and V3-R4b. Implementation: `rust/services/param-update/src/{v3_publish,v3_policy,v3_guard}.rs`, `rust/crates/privoke-contracts/src/publication.rs`. Fixtures: `rust/crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`, written by `evaluation/generate_v3_signed_chain_fixtures.py`.

A trained V3 version reaches a client only with a **publication statement**: a signature by param-update's publication key over the version's identity and lineage. The signature attests param-update's own admission of the version: lineage, bytes, the execution evidence and its source record, the drift bounds and, once the scheduler's allocation journal exists (stage V3-R6 attaches the guard gate), the guard it recomputed itself. Until V3-R6 a signature does **not** attest a recomputed guard: the guard gate is implemented and tested but not installed by the service, so a published version has passed the trainer-evidence guard of the oracle and the drift gate only. It never attests anything the trainer reported about itself beyond that.

## The statement

The canonical JSON object `{tag, key_id, model_id, manifest_sha, parent, original, sequence}` (sorted keys, compact, UTF-8, one trailing newline), signed with Ed25519 over exactly those bytes. The tag `privoke-v3-publication-v1` is the domain separation: nothing else the key signs can be replayed as a statement. The wire form adds `signature` (128 lowercase hexadecimal characters) and is what `ModelPackageResponse.publication_statement` carries (empty for a pinned ORIGINAL).

- `parent` and `original` repeat the manifest's own fields (empty for an ORIGINAL).
- `sequence` is per model, starts at 1 and increases by one for every publication, rollbacks included. A client keeps the highest sequence it has accepted and refuses anything below it, and the same sequence for another manifest (V3-R4a).
- A client compiles a **key set indexed by `key_id`** (`privoke_contracts::publication::KeySet`). A statement with an unknown `key_id` is refused.

## How a version is published

The SQLite `current(model, manifest)` table of the checkpoint store is the single authority for the version each model serves. The published tree is derived from it and repaired from it:

```
<V3_PUBLISH_ROOT>/<model-id>/<manifest-sha>/   manifest.json model.safetensors config.json vocab.txt [evidence.json] statement.json
<V3_PUBLISH_ROOT>/<model-id>/current           the manifest sha the model serves (derived from the newest publication)
<V3_PUBLISH_ROOT>/.staging/<model-id>/<manifest-sha>.<request>/   the private staging area (same filesystem)
<V3_PUBLISH_ROOT>/.quarantine/                 what the authority does not reference
```

1. **Stage.** After admission and the gates, and before the transaction, the files are written into a staging directory and fsynced. Nothing is signed.
2. **Transaction.** In the one `BEGIN IMMEDIATE` transaction that compares and swaps (after the stale-base and guard gates) the sequence is allocated (`MAX(sequence)+1`), the statement is signed and recorded in `publications`, and `current` changes. A candidate that loses the race, or fails a gate, never reaches the signature: no statement exists for it, and its staging is released.
3. **Publish.** After the commit, the statement is written into the staging directory, the directory is renamed to `<manifest-sha>/` and the pointer is rewritten, last. Until the pointer moves the previous version is fully served.

Directory fsync is a no-op on Windows.

A crash at any step leaves the previous version complete and served, with the authority already naming the new one. At startup `Publisher::reconcile` completes the publication from the authority (promoting an intact staged directory, else rebuilding the version from the store), repairs the pointers, and quarantines every published or staged directory the authority does not reference. A repeated request whose receipt is `applied` finishes the publication again (it is idempotent). If the authority serves a version that has no publication while the model has publications (a version swapped in without a signature), startup refuses and the operator rolls back to a published version.

## Gates before the transaction

Each refusal is a durable `rejected` receipt with a reason, and changes nothing else.

| Reason | Meaning |
| --- | --- |
| `stale_base` | the model no longer serves the candidate's base (first, as in the oracle) |
| `guard_rejected` | the trainer's own evidence does not show an improvement (the oracle rule) |
| `drift_exceeded` | the candidate moved farther than `config/v3-drift-bounds.toml` allows from its parent or from the pinned ORIGINAL |
| `request_not_allocated`, `allocation_mismatch`, `commitment_mismatch` | the scheduler's journal does not allocate this request, this base or this source commitment |
| `guard_rows_differ` | the evidence guard targets are not the rows param-update rebuilt with `privoke_curriculum::v3::routine_guard_rows` from the allocated seed and commitment |
| `guard_recomputed` | scored by the Rust V3 encoder on those rows (base, and the candidate loaded through `V3Model::with_tensors`), the candidate does not improve the joint count without harming an action |

The guard gate is not installed by `main.rs` until the scheduler's allocation journal exists (stage V3-R6); until then a deployment publishes with the drift gate and the trainer-evidence gate only (see the first section). The drift gate is always on when the store is: `V3_DRIFT_BOUNDS` is required with `V3_STORE`, published or not. The allocation names the release (`sampler`) and the scope too: evidence that names another one is `allocation_mismatch`, so a trainer cannot pick the guard release (the AU3 guard ignores the seed). `drift_exceeded` uses provisional bounds until stage V3-R5 calibrates them (`status` and `evidence_sha256` of the file say which).

## Serving

Stage V3-R3. `privoke-model-streaming` (`src/published.rs`) serves published versions; the client side is V3-R4a and V3-R4b.

**How model-streaming reads the authority.** It opens `<V3_STORE>/catalog.sqlite` read-only (`SQLITE_OPEN_READ_ONLY`, one snapshot per request, nothing cached) and reads the `current` and `publications` rows of the model. It needs `V3_STORE` and `V3_PUBLISH_ROOT`, both or neither, checked at startup (a symlink on either path is refused). The catalog is in WAL mode, so the store directory must be mounted where SQLite can maintain its `-shm` file for a reader (the same user as param-update, or a read-write mount of that directory); the service never writes a table. A missing catalog file means nothing is published. The published tree is a byte source only: a directory is read only after the authority names its manifest, so a directory the authority does not reference (a straggler before reconciliation, a quarantine leftover, a hand-made copy) is never served.

**What is servable.** The pinned ORIGINAL of each tier, always, from the standard release store; and every manifest that has a publication row (the current version and the rollback history, a rolled-back-to ORIGINAL included). A version that went live without a signature (a `versions` row with no publication) is not servable.

| Request | Nothing published | Published |
| --- | --- | --- |
| `GetModelPackage(privoke-v3-<tier>)` and `latest` (balanced) | the pinned ORIGINAL, empty statement | the newest publication's manifest with its wire statement; after a signed rollback to the ORIGINAL, the pinned bytes with the rollback's statement |
| `GetModelPackage(privoke-v3-<tier>@<sha>)` | the pinned ORIGINAL if `<sha>` is the pin, else `INVALID_ARGUMENT` | the pin: the ORIGINAL with an empty statement; a published `<sha>`: that version with its newest statement; else `INVALID_ARGUMENT` |
| `StreamModelAsset(model, sha, asset)` | only the pin | the pin or any published `<sha>`; else `INVALID_ARGUMENT` |

If the authority serves a manifest other than its newest publication's, the plain request is `UNAVAILABLE` (the state param-update refuses to start in) rather than serving a possibly unsigned version; the pin-addressed forms keep working. A statement that does not decode, or names another model or manifest, is `UNAVAILABLE`. Published files are verified against the digests their manifest names (hashed once, again whenever the file changes, and again before every stream), so a modified file is `DATA_LOSS`. The service does not check signatures: it has no keys, and clients verify the statement under their compiled key set.

**Pin-addressed fetches.** The request message has no pin field, so the pin rides in the model id: `privoke-v3-<tier>@<64 lowercase hex manifest sha>`. With the ORIGINAL's pin it returns the ORIGINAL with an empty statement, which is what a historical evaluation or the frozen Python client needs once something is published. A client that wants the signed rollback to the ORIGINAL (the current version after a rollback) asks by the plain id.

**Python consumers that fetch V3 by model id** (bounded grep of `extension`, `evaluation`, `services`, `shared`; the Rust clients are not listed):

| Consumer | Path | After the first publication |
| --- | --- | --- |
| `extension/client-runtime/src/LLM/privoke/v3_package.py` (`fetch_package`, called from `parameter_stream.py`; `worker_main.py` and `streamed_model.py` only load the cached directory) | `GetModelPackage` with the plain id, then `StreamModelAsset` by the compiled pin | **Affected.** It refuses a manifest that is not the compiled pin (`admitted_manifest`, `STANDARD_PINS`), so with the plain id it fails closed once a tier is published. It is frozen by plan decision. To keep running it, its owner must send `privoke-v3-<tier>@<pin>` on the wire and keep the bare id for `admitted_manifest` (which compares the id string); this stage does not touch it. Until then plain-id runs are valid only while nothing is published. |
| `evaluation/update_security.py` (V3 fetch rows) | plain id, then assets by the manifest it received | Unaffected while nothing is published; against a store with publications, the ORIGINAL rows use `<id>@<pin>`. The signed-chain rows are the separate `--rust-service client-lineage` target (V3-R4a, Client admission). |
| `evaluation/capture_conformance.py` (Go-parity capture) | plain ids against the Go service or a fresh Rust service | Unaffected: it records a service with nothing published (the Go-parity claim ends at the pinned set). |
| `evaluation/generate_model_fetch_golden.py` | a scripted stub, not a service | Unaffected. |
| `evaluation/run-rq3-semantic-cost.py`, `evaluation/adversarial_evasion.py`, `extension/src/settings.js`, `extension/test/rq3-v3-browser-cost.*` | name V3 model ids, but load from a local release directory or through the client-runtime row above | Unaffected by the server; the client-runtime row applies wherever they fetch. |
| `services/model-streaming-service` (Go) | serves only the pinned set | Unaffected (never reads the published root). |

## Client admission

Stage V3-R4a. `privoke_contracts::v3::admit_lineage` (`rust/crates/privoke-contracts/src/v3.rs`) is the rule, `LineageAdmission` (`rust/services/runtime-supervisor/src/fetch.rs`) applies it in the supervisor fetch. `admitted_manifest` stays the pin-only rule of the model loaders until stage V3-R4b.

A fetched manifest is accepted only when all of these hold (checked in this order):

1. the manifest is canonical, satisfies the manifest contract and names the requested model;
2. a statement is present, is a canonical statement of exactly the admitted fields, names a `key_id` of the compiled key set and verifies under it (a changed or malleable signature fails);
3. the statement names this model and this manifest;
4. the statement's `parent` and `original` equal the manifest's own fields;
5. its `sequence` is above the persisted high-water mark of the model, or equal to it with the same manifest (a mark that names another model, or that does not verify, refuses everything);
6. the manifest is the compiled tier pin (the pinned release: a signed rollback), or its `original` equals the `original` field of the pinned release (`Tier::release_original`, compiled beside the pin: the ORIGINAL-scope manifest the release descends from). Trained versions descend from the pinned release, so their `parent` is the pin or a later published version; the client does not check `parent` against what it has admitted, because it may have skipped versions (the signature attests param-update's own lineage admission).

Without a statement only the compiled pin is accepted, and only while the model has no high-water mark (the first start, as today). The unsigned ORIGINAL after a signed version is refused as a downgrade, and any other unsigned manifest as unsigned. The server's claim of which manifest it serves is never trusted, and the client asks by the plain model id (`privoke-v3-<tier>`, or `latest`): a signed rollback to the ORIGINAL is the pinned bytes with a rollback statement, which only the plain id returns. The server answers `UNAVAILABLE` (an authority that serves a manifest other than its newest publication's, see Serving) or `DEADLINE_EXCEEDED` transiently: the fetch fails, nothing in the cache or the mark changes, and the client retries later.

**Key set.** `privoke_contracts::publication::PRODUCTION_KEYS` lists the `(key_id, public key)` pairs compiled into a client build. It is empty until the first publication key is generated, so a client admits no signed version and keeps the pinned ORIGINAL until a release adds the key (the operator step in Key custody). The deterministic test keys exist only behind the `test-keys` cargo feature, which no client or service build enables (CI checks `cargo tree`). A rotation overlap lists both keys.

**What is persisted** (in the model cache, `<cache>/<model-id>/`):

| File | Meaning |
| --- | --- |
| `<manifest-sha>/statement.json` | the statement that admitted that version, written before the version is used and replaced when a rollback returns to a version the cache already holds |
| `high-water.statement` | the highest statement accepted for the model: the statement itself, replaced atomically, only after the package is complete and verified, never lowered |

Both are the signed wire form, so they are re-verified under the compiled keys on every read, not trusted as files. A fresh process (a restart) therefore re-admits a cached version from its `statement.json` and the mark. A mark that does not verify (tampered, unreadable, or signed by a key the client no longer compiles) refuses every version of that model and names the file: the client fails closed and the operator removes the record to trust the pinned ORIGINAL once again (the trust-on-first-use state below). A rotation therefore keeps the order in Rotation, so that clients take a new-key statement before the old key is dropped. One fetch runs at a time in a process; two supervisors fetching into one cache at the same moment can each pass the check, and the mark is then written by the later one, but never to a lower sequence than it read just before.

**Tests and rows.** `tests/lineage_chain.rs` and `tests/lineage_fetch.rs` of `rust/services/runtime-supervisor`, judged by `evaluation/update_security.py --target rust --rust-service client-lineage` (rows L01-L25 over the shared fixtures, LF1-LF14 through the real fetch).

## Rollback

`CheckpointService.RollbackModel` (publisher role only) serves an earlier version again: the target must be in the model's history (every version the model served) and be either the ORIGINAL or a version that has a signed publication: a version that went live without one was never vetted and is refused (`Rollback target was never published.`). It is a new compare-and-swap with a new, higher sequence and a new signature, so a client that already accepted a later sequence accepts it. A rollback to the version already served is a `rejected` receipt (`already_current`).

## Key custody

- The publication key is an **Ed25519 key dedicated to publication**. It is not a TLS key and is never reused as one.
- It is a 32-byte seed in a **mounted secret file** (64 hexadecimal characters, `V3_PUBLICATION_KEY_FILE`), readable only by the param-update service user. It is never baked into an image, never in the repository, never in an environment variable, and `test-keys` (the deterministic keys of the fixtures) exist only behind the `test-keys` cargo feature, which no service or client build enables.
- Generate it on a trusted host: `head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n' > publication.key` (mode 0400). Read the public key for the client key set with `param-update-service publication-key --key-file publication.key`; record the key id (`V3_PUBLICATION_KEY_ID`, for example `publication-2026-1`) with it.
- Clients compile the public keys into the supervisor (`PRODUCTION_KEYS`, V3-R4a). A key change is a client release.

## Rotation

A rotation is an overlap, so that no client ever holds a statement it cannot verify:

1. Generate the new key and a new key id.
2. Release clients that compile **both** public keys (old and new). Wait until clients have updated (the cache refresh interval defines how fast).
3. Switch param-update to the new key (`V3_PUBLICATION_KEY_FILE` and `V3_PUBLICATION_KEY_ID`) and restart. New publications are signed by the new key; statements already issued stay valid while the old key is in the clients' set.
4. Publish once under the new key (the next routine cycle, or a rollback to an earlier version and forward again) so that the served version carries a new-key statement.
5. Release clients that drop the old key.

Clients accept either key during step 2 to 4 (tested in V3-R4a with the shared fixtures: `rotation-second-key`, rows L22, L23, L24 and LF4). A client keeps the statement that set its high-water mark, so step 5 must wait until clients have fetched a version under the new key; a client still holding an old-key mark when it drops that key refuses the model until its record is removed. If a key is compromised, skip the overlap: release clients that drop it, accept that clients on the old release refuse new publications until they update, and publish under the new key.

## Accepted limitation: trust on first use

A client keeps its highest accepted sequence in its cache. A client whose cache is wiped re-admits the unsigned pinned ORIGINAL once (trust on first use) before it fetches any signed version, and an attacker who can wipe a cache and serve an old signed statement can serve a version older than the one the client had. The pinned ORIGINAL is the compiled-in fallback, and every later version needs a statement, so the exposure is bounded to the versions this service has signed; a stronger guarantee needs a client-side monotonic store outside the cache and is out of scope.

## Shared fixtures

`chain.json` holds, on a toy checkpoint (manifests that satisfy the manifest contract with a stand-in tensor inventory, no weights): ORIGINAL, HEADS (sequence 1), FULL (2), a rollback to the ORIGINAL (3), a HEADS version signed by the second key (4), and the forged variants (bad signature, unknown key, non-canonical encoding, another model, a lower sequence, the same sequence for another manifest, a parent or original that differs from the manifest's, a statement attached to another manifest, a wrong ORIGINAL). The ORIGINAL of the toy chain is not the compiled tier pin (the real pinned manifests are not in the repository), so lineage admission takes the tier pin as a parameter in tests and the fixture names it (`original_pin`). R3, R4a, R4b and `evaluation/update_security.py` consume this file; param-update replays it in `tests/v3_signed_chain.rs`, including re-signing every statement with the Rust signer and comparing bytes (the file is signed by an independent pure-Python RFC 8032 implementation).
