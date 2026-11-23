//! The content-addressed V3 checkpoint store (`services/pretrained-v3/src/checkpoint_store.py`).
//!
//! * `blobs/<sha256>` holds every immutable object (weights, config, vocabulary, manifests and execution evidence), written
//!   through a fsynced temporary file and one rename.
//! * `catalog.sqlite` holds the authority: `current(model, manifest)` names the one manifest each model serves, and
//!   `receipts(id, fingerprint, payload)` holds one durable outcome per request id. Both tables, the WAL mode and the file
//!   names are the Python store's, so a directory written by one implementation opens under the other.
//!
//! The `current` table is the single authority for the version of a model. Everything derived from it later (published
//! directories, pointers, signed statements) is repaired from it, never the other way round.
//!
//! # Commit
//!
//! [`CheckpointStore::commit`] is one `BEGIN IMMEDIATE` transaction: answer a repeated request id from its receipt (a different
//! payload under the same id is refused), admit the candidate again ([`CheckpointStore::admit_candidate`]: lineage,
//! provenance, config, inventory, the checkpoint bytes and the execution evidence), check the commit identity, then compare and
//! swap. A stale base or a guard failure records a `rejected` receipt and changes nothing; an admission failure records
//! nothing, so the request can be retried.
//!
//! The seam for signing and publication is [`CommitObserver::before_swap`]: it runs inside the transaction after every gate
//! passed and before the `current` row changes, and an error there rolls the whole commit back.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::{Commit, Receipt};
use privoke_contracts::v3::{self, ContractError, MAX_BLOB_BYTES, MAX_MANIFEST_BYTES, TIERS};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value as Serde;

use super::evidence::SourceEvidence;

/// The bound on an evidence document (`MAX_BLOB_BYTES`).
pub const MAX_EVIDENCE_BYTES: usize = 80 * 1024 * 1024;

/// Why a store operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A `ValueError` of the oracle: the text is its message.
    Invalid(String),
    /// A blob or file the store does not hold (the oracle's `FileNotFoundError`).
    Missing(String),
    /// Storage failed; the text is for the log.
    Storage(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Missing(message) | Self::Storage(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ContractError> for StoreError {
    fn from(error: ContractError) -> Self {
        Self::Invalid(error.0)
    }
}

impl From<privoke_curriculum::Error> for StoreError {
    fn from(error: privoke_curriculum::Error) -> Self {
        Self::Invalid(error.to_string())
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound { Self::Missing(error.to_string()) } else { Self::Storage(error.to_string()) }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

fn bad<T>(message: &str) -> Result<T, StoreError> {
    Err(StoreError::Invalid(message.to_string()))
}

/// `digest(payload)`.
pub fn digest(payload: &[u8]) -> String {
    sha256_hex(payload)
}

fn get<'a>(document: &'a Value, key: &str) -> Option<&'a Value> {
    match document {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

fn text<'a>(document: &'a Value, key: &str) -> &'a str {
    match get(document, key) {
        Some(Value::String(text)) => text,
        _ => "",
    }
}

/// `canonical(value)` of an object of strings.
fn canonical_strings(pairs: &[(&str, &str)]) -> Result<Vec<u8>, StoreError> {
    let map: BTreeMap<String, Value> = pairs.iter().map(|(key, text)| ((*key).to_string(), Value::String((*text).to_string()))).collect();
    canonical::to_bytes(&Value::Object(map), Variant::Utf8Lf).map_err(|error| StoreError::Invalid(error.to_string()))
}

/// The tensor inventory of a manifest: name to shape and dtype.
fn inventory(manifest: &Value) -> BTreeMap<String, (Option<Value>, Option<Value>)> {
    match get(manifest, "tensors") {
        Some(Value::Object(tensors)) => {
            tensors.iter().map(|(name, tensor)| (name.clone(), (get(tensor, "shape").cloned(), get(tensor, "dtype").cloned()))).collect()
        }
        _ => BTreeMap::new(),
    }
}

/// The tensor digests of a manifest: name to SHA-256.
fn tensor_digests(manifest: &Value) -> BTreeMap<String, String> {
    match get(manifest, "tensors") {
        Some(Value::Object(tensors)) => tensors.iter().map(|(name, tensor)| (name.clone(), text(tensor, "sha256").to_string())).collect(),
        _ => BTreeMap::new(),
    }
}

/// A compare-and-swap that every gate has passed, as [`CommitObserver::before_swap`] sees it.
#[derive(Debug)]
pub struct Swap<'a> {
    /// The model whose `current` row is about to change.
    pub model_id: &'a str,
    /// The manifest the model serves now (the request's `expected_base`, already compared).
    pub base: &'a str,
    /// The manifest it will serve.
    pub candidate: &'a str,
    /// The request identity.
    pub request_id: &'a str,
    /// The admitted execution evidence of the candidate.
    pub evidence: &'a Serde,
}

/// Work that belongs to the commit transaction without being part of the oracle's contract: allocating a sequence and signing a
/// publication statement, for example. It runs after the stale-base and guard gates and before the `current` row changes.
pub trait CommitObserver: Send + Sync + fmt::Debug {
    /// Called inside the `BEGIN IMMEDIATE` transaction. An error refuses the commit and rolls the transaction back.
    fn before_swap(&self, swap: &Swap<'_>, transaction: &Connection) -> Result<(), StoreError>;
}

/// The oracle's behaviour: nothing happens between the gates and the swap.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoObserver;

impl CommitObserver for NoObserver {
    fn before_swap(&self, _swap: &Swap<'_>, _transaction: &Connection) -> Result<(), StoreError> {
        Ok(())
    }
}

/// The store: blobs on disk, the authority in SQLite.
pub struct CheckpointStore {
    directory: PathBuf,
    blobs: PathBuf,
    db: Mutex<Connection>,
    put_lock: Mutex<()>,
    sources: Arc<dyn SourceEvidence>,
    observer: Arc<dyn CommitObserver>,
}

impl fmt::Debug for CheckpointStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("CheckpointStore").field("directory", &self.directory).finish_non_exhaustive()
    }
}

impl CheckpointStore {
    /// Open (and create) the store in `directory`. `sources` validates the source record of every candidate's evidence.
    pub fn open(directory: impl Into<PathBuf>, sources: Arc<dyn SourceEvidence>) -> Result<Self, StoreError> {
        let directory = directory.into();
        let blobs = directory.join("blobs");
        std::fs::create_dir_all(&blobs)?;
        let db = Connection::open(directory.join("catalog.sqlite"))?;
        // `journal_mode` answers with a row.
        db.query_row("PRAGMA journal_mode=WAL", [], |_row| Ok(()))?;
        db.execute_batch("PRAGMA synchronous=FULL")?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS current(model TEXT PRIMARY KEY, manifest TEXT NOT NULL);\
             CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, payload BLOB NOT NULL);",
        )?;
        Ok(Self { directory, blobs, db: Mutex::new(db), put_lock: Mutex::new(()), sources, observer: Arc::new(NoObserver) })
    }

    /// The same store with `observer` between the commit gates and the swap.
    #[must_use]
    pub fn with_observer(mut self, observer: Arc<dyn CommitObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// The store directory.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `put(payload)`: store an immutable blob and return its SHA-256.
    pub fn put(&self, payload: &[u8]) -> Result<String, StoreError> {
        if payload.is_empty() || payload.len() as u64 > MAX_BLOB_BYTES {
            return bad("Blob exceeds v3 bound.");
        }
        let sha = digest(payload);
        let path = self.blobs.join(&sha);
        let _guard = self.put_lock.lock().unwrap_or_else(PoisonError::into_inner);
        if path.exists() {
            if digest(&std::fs::read(&path)?) != sha {
                return bad("Existing immutable blob corrupted.");
            }
            return Ok(sha);
        }
        let temp = self.blobs.join(format!("stage-{}", uuid::Uuid::new_v4().simple()));
        let written = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut file = std::fs::File::create(&temp)?;
            file.write_all(payload)?;
            file.flush()?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &path)?;
            // Directory fsync is a no-op on Windows.
            #[cfg(unix)]
            std::fs::File::open(&self.blobs)?.sync_all()?;
            Ok(())
        })();
        if temp.exists() {
            let _ = std::fs::remove_file(&temp);
        }
        written?;
        Ok(sha)
    }

    /// `read(sha)`: an immutable blob, re-hashed.
    pub fn read(&self, sha: &str) -> Result<Vec<u8>, StoreError> {
        v3::check_sha(sha)?;
        let payload = std::fs::read(self.blobs.join(sha))?;
        if digest(&payload) != sha {
            return bad("Immutable blob hash mismatch.");
        }
        Ok(payload)
    }

    /// `manifest(sha)`: a stored manifest, parsed strictly and validated.
    pub fn manifest(&self, sha: &str) -> Result<Value, StoreError> {
        let document = v3::parse(&self.read(sha)?, MAX_MANIFEST_BYTES)?;
        v3::validate_manifest(&document).map_err(|error| StoreError::Invalid(error.to_string()))?;
        Ok(document)
    }

    /// `resolve(model)`: the manifest the model serves.
    pub fn resolve(&self, model: &str) -> Result<String, StoreError> {
        let conn = self.connection();
        current_of(&conn, model)
    }

    /// `verify_checkpoint(manifest)`: the snapshot's tensors are finite float32 and are exactly the declared inventory.
    pub fn verify_checkpoint(&self, manifest: &Value) -> Result<(), StoreError> {
        let payload = self.read(text(manifest, "blob"))?;
        let tensors = privoke_semantic::safetensors::parse(&payload)
            .map_err(|_| StoreError::Invalid("Snapshot tensors must be finite float32.".to_string()))?;
        let actual: BTreeMap<String, Value> = tensors
            .iter()
            .map(|(name, tensor)| {
                let shape: Vec<Value> = tensor.shape.iter().map(|size| Value::Int(size.to_string())).collect();
                let entry: BTreeMap<String, Value> = [
                    ("dtype".to_string(), Value::String("F32".to_string())),
                    ("sha256".to_string(), Value::String(tensor.sha256.clone())),
                    ("shape".to_string(), Value::Array(shape)),
                ]
                .into_iter()
                .collect();
                (name.clone(), Value::Object(entry))
            })
            .collect();
        if get(manifest, "tensors") != Some(&Value::Object(actual)) {
            return bad("Safetensors inventory differs from manifest.");
        }
        Ok(())
    }

    /// `bootstrap(directory)`: admit an independently prepared ORIGINAL (`manifest.json`, `model.safetensors`, `config.json`,
    /// `vocab.txt`) and make it current for its model unless the model already has a version.
    pub fn bootstrap(&self, directory: &Path) -> Result<(), StoreError> {
        let payload = std::fs::read(directory.join("manifest.json"))?;
        let document = v3::parse(&payload, MAX_MANIFEST_BYTES)?;
        let manifest = v3::validate_manifest(&document).map_err(|error| StoreError::Invalid(error.to_string()))?;
        if manifest.scope != "original" {
            return bad("Bootstrap requires independently prepared ORIGINAL.");
        }
        for (name, key) in [("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")] {
            if self.put(&std::fs::read(directory.join(name))?)? != text(&document, key) {
                return bad("ORIGINAL asset identity mismatch.");
            }
        }
        self.verify_checkpoint(&document)?;
        let sha = self.put(&payload)?;
        let conn = self.connection();
        conn.execute("INSERT OR IGNORE INTO current VALUES (?1,?2)", params![manifest.model_id, sha])?;
        Ok(())
    }

    /// `admit_candidate(manifest)`: the one admission path shared by staging and the transactional commit. Returns the
    /// candidate's admitted execution evidence.
    pub fn admit_candidate(&self, document: &Value) -> Result<Serde, StoreError> {
        let manifest = v3::validate_manifest(document).map_err(|error| StoreError::Invalid(error.to_string()))?;
        if manifest.scope == "original" {
            return bad("Candidates cannot claim ORIGINAL scope.");
        }
        let parent_sha = text(document, "parent");
        let parent = self.manifest(parent_sha)?;
        let original_sha = match text(&parent, "original") {
            "" => parent_sha,
            recorded => recorded,
        };
        let original = self.manifest(original_sha)?;
        if text(&original, "scope") != "original" || text(document, "original") != original_sha {
            return bad("Candidate ORIGINAL binding mismatch.");
        }
        for ancestor in [&parent, &original] {
            for key in ["model_id", "tier", "source", "config", "vocab", "parameter_count"] {
                if get(document, key) != get(ancestor, key) {
                    return bad("Candidate changed immutable model provenance/config.");
                }
            }
        }
        if inventory(document) != inventory(&original) {
            return bad("Candidate changed admitted tensor inventory.");
        }
        for key in ["config", "vocab"] {
            self.read(text(document, key))?;
        }
        self.verify_checkpoint(document)?;
        let evidence_document = v3::parse(&self.read(text(document, "evidence"))?, MAX_EVIDENCE_BYTES)?;
        let evidence = v3::to_serde(&evidence_document)?;
        v3::validate_execution(&evidence, true)?;
        self.sources.validate(&evidence_document)?;
        if evidence["base"].as_str() != Some(parent_sha)
            || evidence["candidate_blob"].as_str() != Some(text(document, "blob"))
            || evidence["scope"].as_str() != Some(manifest.scope.as_str())
            || evidence["model_id"].as_str() != Some(manifest.model_id.as_str())
        {
            return bad("Candidate evidence differs from snapshot identity/scope.");
        }
        let layers = TIERS.iter().find(|tier| tier.name == manifest.tier).map_or(0, |tier| tier.num_hidden_layers as usize);
        let (changed, changes) = v3::tensor_changes(&tensor_digests(&parent), &tensor_digests(document), layers);
        let mut reported: Vec<String> = evidence["changed_tensors"]
            .as_array()
            .map_or_else(Vec::new, |items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect());
        reported.sort();
        if changed != reported || changes != evidence["changes"] {
            return bad("Reported changes differ from actual checkpoint tensors.");
        }
        if manifest.scope == "heads" && changed.iter().any(|name| !name.starts_with("heads.")) {
            return bad("HEADS candidate changed pretrained encoder/pooler bytes.");
        }
        Ok(evidence)
    }

    /// `stage(payload, manifest_payload)`: store finalized execution evidence (no manifest), or a candidate snapshot that has
    /// passed admission together with its manifest.
    pub fn stage(&self, payload: &[u8], manifest_payload: &[u8]) -> Result<String, StoreError> {
        if manifest_payload.is_empty() {
            // Finalized execution evidence is the only manifest-free transport object.
            let evidence = v3::to_serde(&v3::parse(payload, MAX_EVIDENCE_BYTES)?)?;
            v3::validate_execution(&evidence, true)?;
            return self.put(payload);
        }
        let document = v3::parse(manifest_payload, MAX_MANIFEST_BYTES)?;
        v3::validate_manifest(&document).map_err(|error| StoreError::Invalid(error.to_string()))?;
        if text(&document, "blob") != digest(payload) {
            return bad("Candidate snapshot identity mismatch.");
        }
        self.put(payload)?;
        self.admit_candidate(&document)?;
        self.put(manifest_payload)
    }

    /// `status(request_id)`: the recorded outcome of a commit, or `unknown`.
    pub fn status(&self, request_id: &str) -> Result<Receipt, StoreError> {
        let conn = self.connection();
        let payload: Option<Vec<u8>> =
            conn.query_row("SELECT payload FROM receipts WHERE id=?1", params![request_id], |row| row.get(0)).optional()?;
        match payload {
            Some(payload) => receipt_of(&payload),
            None => Ok(Receipt { status: "unknown".to_string(), request_id: request_id.to_string(), ..Receipt::default() }),
        }
    }

    /// `commit(request)`: the compare-and-swap, with request-id idempotence.
    pub fn commit(&self, request: &Commit) -> Result<Receipt, StoreError> {
        if request.request_id.is_empty() || request.request_id.chars().count() > 200 {
            return bad("Explicit bounded request identity required.");
        }
        for sha in [&request.expected_base, &request.candidate, &request.evidence] {
            v3::check_sha(sha)?;
        }
        let fingerprint = digest(&canonical_strings(&[
            ("request_id", request.request_id.as_str()),
            ("model_id", request.model_id.as_str()),
            ("expected_base", request.expected_base.as_str()),
            ("candidate", request.candidate.as_str()),
            ("evidence", request.evidence.as_str()),
        ])?);
        let conn = self.connection();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match self.commit_locked(&conn, request, &fingerprint) {
            Ok(receipt) => {
                if let Err(error) = conn.execute_batch("COMMIT") {
                    if !conn.is_autocommit() {
                        let _ = conn.execute_batch("ROLLBACK");
                    }
                    return Err(error.into());
                }
                Ok(receipt)
            }
            Err(error) => {
                if !conn.is_autocommit() {
                    let _ = conn.execute_batch("ROLLBACK");
                }
                Err(error)
            }
        }
    }

    fn commit_locked(&self, conn: &Connection, request: &Commit, fingerprint: &str) -> Result<Receipt, StoreError> {
        let prior: Option<(String, Vec<u8>)> = conn
            .query_row("SELECT fingerprint,payload FROM receipts WHERE id=?1", params![request.request_id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?;
        if let Some((stored, payload)) = prior {
            if stored != fingerprint {
                return bad("Request ID reused with different commit content.");
            }
            return receipt_of(&payload);
        }
        let manifest = self.manifest(&request.candidate)?;
        let evidence = self.admit_candidate(&manifest)?;
        if text(&manifest, "parent") != request.expected_base
            || text(&manifest, "evidence") != request.evidence
            || text(&manifest, "model_id") != request.model_id
            || evidence["request_id"].as_str() != Some(request.request_id.as_str())
        {
            return bad("Commit identity differs from candidate/fit evidence.");
        }
        let current = current_of(conn, &request.model_id)?;
        let reason = if current != request.expected_base {
            "stale_base"
        } else if !v3::publication_passes(&evidence)? {
            "guard_rejected"
        } else {
            ""
        };
        let receipt = Receipt {
            status: if reason.is_empty() { "applied" } else { "rejected" }.to_string(),
            request_id: request.request_id.clone(),
            model_id: request.model_id.clone(),
            base: request.expected_base.clone(),
            candidate: request.candidate.clone(),
            reason: reason.to_string(),
        };
        if reason.is_empty() {
            self.observer.before_swap(
                &Swap {
                    model_id: &request.model_id,
                    base: &request.expected_base,
                    candidate: &request.candidate,
                    request_id: &request.request_id,
                    evidence: &evidence,
                },
                conn,
            )?;
            conn.execute(
                "UPDATE current SET manifest=?1 WHERE model=?2 AND manifest=?3",
                params![request.candidate, request.model_id, request.expected_base],
            )?;
        }
        conn.execute("INSERT INTO receipts VALUES (?1,?2,?3)", params![request.request_id, fingerprint, receipt_bytes(&receipt)?])?;
        Ok(receipt)
    }
}

fn current_of(conn: &Connection, model: &str) -> Result<String, StoreError> {
    let row: Option<String> = conn.query_row("SELECT manifest FROM current WHERE model=?1", params![model], |row| row.get(0)).optional()?;
    row.ok_or_else(|| StoreError::Invalid("Model is not in this private catalog.".to_string()))
}

/// `canonical(receipt)`: the six fields of a receipt as the oracle stores them.
fn receipt_bytes(receipt: &Receipt) -> Result<Vec<u8>, StoreError> {
    canonical_strings(&[
        ("status", receipt.status.as_str()),
        ("request_id", receipt.request_id.as_str()),
        ("model_id", receipt.model_id.as_str()),
        ("base", receipt.base.as_str()),
        ("candidate", receipt.candidate.as_str()),
        ("reason", receipt.reason.as_str()),
    ])
}

fn receipt_of(payload: &[u8]) -> Result<Receipt, StoreError> {
    let document = v3::parse(payload, MAX_MANIFEST_BYTES)?;
    Ok(Receipt {
        status: text(&document, "status").to_string(),
        request_id: text(&document, "request_id").to_string(),
        model_id: text(&document, "model_id").to_string(),
        base: text(&document, "base").to_string(),
        candidate: text(&document, "candidate").to_string(),
        reason: text(&document, "reason").to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NoSources;

    impl SourceEvidence for NoSources {
        fn validate(&self, _evidence: &Value) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn store() -> (tempfile::TempDir, CheckpointStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = CheckpointStore::open(directory.path().join("store"), Arc::new(NoSources)).unwrap();
        (directory, store)
    }

    #[test]
    fn blobs_are_content_addressed_immutable_and_bounded() {
        let (_directory, store) = store();
        let sha = store.put(b"payload").unwrap();
        assert_eq!(sha, digest(b"payload"));
        assert_eq!(store.put(b"payload").unwrap(), sha, "a second put is the same object");
        assert_eq!(store.read(&sha).unwrap(), b"payload");
        assert_eq!(store.put(b"").unwrap_err(), StoreError::Invalid("Blob exceeds v3 bound.".to_string()));
        std::fs::write(store.directory().join("blobs").join(&sha), b"tampered").unwrap();
        assert_eq!(store.read(&sha).unwrap_err(), StoreError::Invalid("Immutable blob hash mismatch.".to_string()));
        assert_eq!(store.put(b"payload").unwrap_err(), StoreError::Invalid("Existing immutable blob corrupted.".to_string()));
        assert!(matches!(store.read(&digest(b"absent")), Err(StoreError::Missing(_))));
        assert_eq!(store.read("not-a-sha").unwrap_err(), StoreError::Invalid("Expected a lowercase SHA-256 identity.".to_string()));
    }

    #[test]
    fn an_unknown_request_and_an_unknown_model_are_reported() {
        let (_directory, store) = store();
        let status = store.status("never-issued").unwrap();
        assert_eq!((status.status.as_str(), status.request_id.as_str(), status.reason.as_str()), ("unknown", "never-issued", ""));
        assert_eq!(
            store.resolve("privoke-v3-efficient").unwrap_err(),
            StoreError::Invalid("Model is not in this private catalog.".to_string())
        );
    }

    #[test]
    fn a_commit_needs_a_bounded_request_identity_and_lowercase_digests() {
        let (_directory, store) = store();
        let sha = digest(b"x");
        let commit = |request_id: &str, base: &str| Commit {
            request_id: request_id.to_string(),
            model_id: "privoke-v3-efficient".to_string(),
            expected_base: base.to_string(),
            candidate: sha.clone(),
            evidence: sha.clone(),
        };
        let identity = StoreError::Invalid("Explicit bounded request identity required.".to_string());
        assert_eq!(store.commit(&commit("", &sha)).unwrap_err(), identity);
        assert_eq!(store.commit(&commit(&"x".repeat(201), &sha)).unwrap_err(), identity);
        assert_eq!(
            store.commit(&commit("r", "BASE")).unwrap_err(),
            StoreError::Invalid("Expected a lowercase SHA-256 identity.".to_string())
        );
        // The candidate is absent, so nothing is recorded and the identity stays free.
        assert!(matches!(store.commit(&commit("r", &sha)), Err(StoreError::Missing(_))));
        assert_eq!(store.status("r").unwrap().status, "unknown");
    }
}
