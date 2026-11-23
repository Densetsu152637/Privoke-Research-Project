# V3 publication: signed versions, custody and rotation

> Plan: [V3 routine training](../plans/v3-routine-training.md), stage V3-R2 (publication), with the client side in V3-R4a and V3-R4b. Implementation: `rust/services/param-update/src/{v3_publish,v3_policy,v3_guard}.rs`, `rust/crates/privoke-contracts/src/publication.rs`. Fixtures: `rust/crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`, written by `evaluation/generate_v3_signed_chain_fixtures.py`.

A trained V3 version reaches a client only with a **publication statement**: a signature by param-update's publication key over the version's identity and lineage. The signature attests param-update's own admission of the version (lineage, bytes, evidence, drift bounds and the recomputed guard), not anything the trainer reported about itself.

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

The guard gate is attached when the scheduler's allocation journal exists (stage V3-R6); until then a deployment publishes with the drift gate and the trainer-evidence gate only. `drift_exceeded` uses provisional bounds until stage V3-R5 calibrates them (`status` and `evidence_sha256` of the file say which).

## Rollback

`CheckpointService.RollbackModel` (publisher role only) serves an earlier version again: the target must be in the model's history (every version the model served, the ORIGINAL included). It is a new compare-and-swap with a new, higher sequence and a new signature, so a client that already accepted a later sequence accepts it. A rollback to the version already served is a `rejected` receipt (`already_current`).

## Key custody

- The publication key is an **Ed25519 key dedicated to publication**. It is not a TLS key and is never reused as one.
- It is a 32-byte seed in a **mounted secret file** (64 hexadecimal characters, `V3_PUBLICATION_KEY_FILE`), readable only by the param-update service user. It is never baked into an image, never in the repository, never in an environment variable, and `test-keys` (the deterministic keys of the fixtures) exist only behind the `test-keys` cargo feature, which no service or client build enables.
- Generate it on a trusted host: `head -c 32 /dev/urandom | od -An -vtx1 | tr -d ' \n' > publication.key` (mode 0400). Read the public key for the client key set with `param-update-service publication-key --key-file publication.key`; record the key id (`V3_PUBLICATION_KEY_ID`, for example `publication-2026-1`) with it.
- Clients compile the public keys into the controller (V3-R4a). A key change is a client release.

## Rotation

A rotation is an overlap, so that no client ever holds a statement it cannot verify:

1. Generate the new key and a new key id.
2. Release clients that compile **both** public keys (old and new). Wait until clients have updated (the cache refresh interval defines how fast).
3. Switch param-update to the new key (`V3_PUBLICATION_KEY_FILE` and `V3_PUBLICATION_KEY_ID`) and restart. New publications are signed by the new key; statements already issued stay valid while the old key is in the clients' set.
4. Publish once under the new key (the next routine cycle, or a rollback to an earlier version and forward again) so that the served version carries a new-key statement.
5. Release clients that drop the old key.

Clients accept either key during step 2 to 4 (tested in V3-R4a with the shared fixtures: `rotation-second-key`). If a key is compromised, skip the overlap: release clients that drop it, accept that clients on the old release refuse new publications until they update, and publish under the new key.

## Accepted limitation: trust on first use

A client keeps its highest accepted sequence in its cache. A client whose cache is wiped re-admits the unsigned pinned ORIGINAL once (trust on first use) before it fetches any signed version, and an attacker who can wipe a cache and serve an old signed statement can serve a version older than the one the client had. The pinned ORIGINAL is the compiled-in fallback, and every later version needs a statement, so the exposure is bounded to the versions this service has signed; a stronger guarantee needs a client-side monotonic store outside the cache and is out of scope.

## Shared fixtures

`chain.json` holds, on a toy checkpoint (manifests that satisfy the manifest contract with a stand-in tensor inventory, no weights): ORIGINAL, HEADS (sequence 1), FULL (2), a rollback to the ORIGINAL (3), a HEADS version signed by the second key (4), and the forged variants (bad signature, unknown key, non-canonical encoding, another model, a lower sequence, the same sequence for another manifest, a parent or original that differs from the manifest's, a statement attached to another manifest, a wrong ORIGINAL). The ORIGINAL of the toy chain is not the compiled tier pin (the real pinned manifests are not in the repository), so lineage admission takes the tier pin as a parameter in tests and the fixture names it (`original_pin`). R3, R4a, R4b and `evaluation/update_security.py` consume this file; param-update replays it in `tests/v3_signed_chain.rs`, including re-signing every statement with the Rust signer and comparing bytes (the file is signed by an independent pure-Python RFC 8032 implementation).
