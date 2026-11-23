//! Signed, atomic publication of V3 versions (stage V3-R2 of the routine-training plan).
//!
//! The SQLite `current` table of the checkpoint store is the one authority for the version each model serves. Everything here is
//! derived from it and repaired from it:
//!
//! * `<root>/<model-id>/<manifest-sha>/` is a published version: `manifest.json`, `model.safetensors`, `config.json`,
//!   `vocab.txt`, `evidence.json` (absent for an ORIGINAL) and `statement.json`, the signed publication statement of the newest
//!   publication of that manifest. A published directory appears by one rename of a complete, fsynced staging directory.
//! * `<root>/<model-id>/current` names the manifest the model serves (derived from the newest publication).
//! * `<root>/.staging/<model-id>/<manifest-sha>.<request>/` is the private staging area, on the same filesystem so that the rename
//!   is atomic. `<root>/.quarantine/` receives anything the authority does not reference.
//!
//! # Commit order
//!
//! 1. [`prepare`](CommitObserver::prepare), before the transaction: the files are written into a staging directory and fsynced.
//!    Nothing is signed yet.
//! 2. [`before_swap`](CommitObserver::before_swap), inside the `BEGIN IMMEDIATE` transaction that compares and swaps, after the
//!    stale-base and gate checks: the sequence is allocated (`MAX(sequence)+1` of the model) and the statement signed and
//!    recorded in `publications`. A candidate that loses the race never reaches this point, so no statement exists for it.
//! 3. [`after_commit`](CommitObserver::after_commit), after the transaction committed: the statement is written into the staging
//!    directory, the directory is renamed to `<root>/<model-id>/<manifest-sha>/`, and the pointer is rewritten.
//!
//! A crash at any point leaves the previous version fully served (the pointer moves last) and the authority already naming the
//! new one; [`Publisher::reconcile`] at startup completes the publication (promoting the staged directory when it is intact, else
//! rebuilding it from the store), repairs the pointer from the authority and quarantines every directory the authority does not
//! reference. Directory fsync is a no-op on Windows.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::publication::{self, Statement};
use privoke_contracts::v3;
use rusqlite::{Connection, params};

use crate::v3_store::{Candidate, CheckpointStore, CommitObserver, StoreError, Swap};

/// A fault-injection point: called with the phase name (`staged`, `signed`, `committed`, `renamed`, `pointer`). An error
/// simulates the process dying there: the publisher stops cleaning up after itself, so the files stay as a crash leaves them.
pub type CrashHook = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// A hook that never fails.
pub fn no_crash() -> CrashHook {
    Arc::new(|_phase: &str| -> Result<(), String> { Ok(()) })
}

/// What the publication of a version left on disk, as [`Publisher::served`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Served {
    /// The manifest the pointer names.
    pub manifest_sha: String,
    /// The signed statement of the published directory.
    pub statement: Vec<u8>,
    /// The published directory.
    pub directory: PathBuf,
}

/// What a startup reconciliation did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reconciled {
    /// Published directories created from an intact staged directory.
    pub promoted: usize,
    /// Published directories rebuilt from the store.
    pub rebuilt: usize,
    /// Directories moved to the quarantine.
    pub quarantined: usize,
    /// Staged directories deleted after their version was published.
    pub cleaned: usize,
    /// Pointers written or removed.
    pub pointers: usize,
}

/// One publication recorded in the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRow {
    /// The per-model sequence.
    pub sequence: u64,
    /// The published manifest.
    pub manifest: String,
    /// The signing key.
    pub key_id: String,
    /// The signed statement (wire form).
    pub statement: Vec<u8>,
    /// The request that published it.
    pub request_id: String,
}

impl CheckpointStore {
    /// The models the catalog serves.
    pub fn models(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.connection();
        let mut statement = conn.prepare("SELECT model FROM current ORDER BY model")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Every publication of the model, oldest first.
    pub fn publications(&self, model: &str) -> Result<Vec<PublicationRow>, StoreError> {
        let conn = self.connection();
        let mut statement =
            conn.prepare("SELECT sequence,manifest,key_id,statement,request_id FROM publications WHERE model=?1 ORDER BY sequence")?;
        let rows = statement.query_map(params![model], |row| {
            Ok(PublicationRow {
                sequence: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                manifest: row.get(1)?,
                key_id: row.get(2)?,
                statement: row.get(3)?,
                request_id: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

fn text(document: &Value, key: &str) -> String {
    match document {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// Directory fsync (a no-op on Windows, where a directory cannot be opened as a file).
fn sync_dir(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Replace `path` with `bytes` through a synced temporary file and one rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let name = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
    let temp = path.with_file_name(format!(".{name}.tmp-{}", uuid::Uuid::new_v4().simple()));
    write_synced(&temp, bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// The signing side of publication: an Ed25519 publication key (never a TLS key), the published root and the fault hook.
pub struct Publisher {
    root: PathBuf,
    key_id: String,
    seed: [u8; 32],
    hook: CrashHook,
    crashed: AtomicBool,
    lock: Mutex<()>,
}

impl fmt::Debug for Publisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Publisher").field("root", &self.root).field("key_id", &self.key_id).finish_non_exhaustive()
    }
}

impl Publisher {
    /// A publisher over `root` that signs with the key of `seed` as `key_id`.
    pub fn new(root: impl Into<PathBuf>, key_id: &str, seed: [u8; 32], hook: CrashHook) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(root.join(".staging"))?;
        fs::create_dir_all(root.join(".quarantine"))?;
        // The key and its id must produce a statement that a client decodes, before anything is staged or signed.
        let probe = Statement {
            key_id: key_id.to_string(),
            model_id: "privoke-v3-efficient".to_string(),
            manifest_sha: "0".repeat(64),
            parent: String::new(),
            original: String::new(),
            sequence: 1,
        };
        let wire = publication::sign(&seed, &probe).map_err(|error| StoreError::Storage(error.to_string()))?;
        publication::decode(&wire).map_err(|error| StoreError::Invalid(format!("The publication key id is not usable: {error}")))?;
        Ok(Self { root, key_id: key_id.to_string(), seed, hook, crashed: AtomicBool::new(false), lock: Mutex::new(()) })
    }

    /// The published root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn crash(&self, phase: &str) -> Result<(), StoreError> {
        (self.hook)(phase).map_err(|message| {
            self.crashed.store(true, Ordering::SeqCst);
            StoreError::Storage(format!("injected failure at {phase}: {message}"))
        })
    }

    fn model_dir(&self, model: &str) -> PathBuf {
        self.root.join(model)
    }

    fn published_dir(&self, model: &str, sha: &str) -> PathBuf {
        self.root.join(model).join(sha)
    }

    fn staging_root(&self, model: &str) -> PathBuf {
        self.root.join(".staging").join(model)
    }

    fn staging_dir(&self, model: &str, sha: &str, request_id: &str) -> PathBuf {
        self.staging_root(model).join(format!("{sha}.{}", &sha256_hex(request_id.as_bytes())[..16]))
    }

    /// The staged directories of a version, any request.
    fn staged_of(&self, model: &str, sha: &str) -> Vec<PathBuf> {
        let prefix = format!("{sha}.");
        let Ok(entries) = fs::read_dir(self.staging_root(model)) else { return Vec::new() };
        let mut found: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(&prefix)))
            .collect();
        found.sort();
        found
    }

    fn quarantine(&self, path: &Path) -> Result<(), StoreError> {
        let name = path.file_name().map(|name| name.to_string_lossy().to_string()).unwrap_or_default();
        let target = self.root.join(".quarantine").join(format!("{name}-{}", uuid::Uuid::new_v4().simple()));
        fs::rename(path, target)?;
        Ok(())
    }

    /// Write the files of a version into `directory` (created fresh), fsynced.
    fn write_files(&self, store: &CheckpointStore, sha: &str, manifest: &Value, directory: &Path) -> Result<(), StoreError> {
        fs::create_dir_all(directory)?;
        write_synced(&directory.join("manifest.json"), &store.read(sha)?)?;
        for (name, key) in [("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")] {
            write_synced(&directory.join(name), &store.read(&text(manifest, key))?)?;
        }
        let evidence = text(manifest, "evidence");
        if !evidence.is_empty() {
            write_synced(&directory.join("evidence.json"), &store.read(&evidence)?)?;
        }
        sync_dir(directory)
    }

    /// Whether `directory` holds exactly the bytes the manifest names.
    fn intact(&self, sha: &str, manifest: &Value, directory: &Path) -> bool {
        let matches = |name: &str, expected: &str| fs::read(directory.join(name)).is_ok_and(|bytes| sha256_hex(&bytes) == expected);
        let evidence = text(manifest, "evidence");
        matches("manifest.json", sha)
            && matches("model.safetensors", &text(manifest, "blob"))
            && matches("config.json", &text(manifest, "config"))
            && matches("vocab.txt", &text(manifest, "vocab"))
            && (evidence.is_empty() || matches("evidence.json", &evidence))
    }

    /// Stage a version privately under `request_id`.
    fn stage(&self, store: &CheckpointStore, model: &str, sha: &str, request_id: &str, manifest: &Value) -> Result<PathBuf, StoreError> {
        let directory = self.staging_dir(model, sha, request_id);
        if directory.exists() {
            fs::remove_dir_all(&directory)?;
        }
        fs::create_dir_all(self.staging_root(model))?;
        self.write_files(store, sha, manifest, &directory)?;
        sync_dir(&self.staging_root(model))?;
        Ok(directory)
    }

    fn published_complete(&self, model: &str, sha: &str) -> bool {
        let directory = self.published_dir(model, sha);
        fs::read(directory.join("manifest.json")).is_ok_and(|bytes| sha256_hex(&bytes) == sha) && directory.join("statement.json").is_file()
    }

    /// Make sure the published directory of `sha` exists, is the version's, and carries `statement`.
    fn ensure_published(
        &self,
        store: &CheckpointStore,
        model: &str,
        sha: &str,
        statement: &[u8],
        report: &mut Reconciled,
    ) -> Result<(), StoreError> {
        let target = self.published_dir(model, sha);
        if self.published_complete(model, sha) {
            if fs::read(target.join("statement.json")).ok().as_deref() != Some(statement) {
                write_atomic(&target.join("statement.json"), statement)?;
            }
            return Ok(());
        }
        if target.exists() {
            self.quarantine(&target)?;
            report.quarantined += 1;
        }
        let manifest = store.manifest(sha)?;
        let mut source = None;
        for staged in self.staged_of(model, sha) {
            if source.is_none() && self.intact(sha, &manifest, &staged) {
                source = Some(staged);
                report.promoted += 1;
            }
        }
        let source = match source {
            Some(source) => source,
            None => {
                report.rebuilt += 1;
                self.stage(store, model, sha, "rebuild", &manifest)?
            }
        };
        write_synced(&source.join("statement.json"), statement)?;
        sync_dir(&source)?;
        fs::create_dir_all(self.model_dir(model))?;
        fs::rename(&source, &target)?;
        sync_dir(&self.model_dir(model))?;
        sync_dir(&self.staging_root(model))?;
        Ok(())
    }

    /// Point `<root>/<model>/current` at the newest publication, or remove it when the model has none.
    fn write_pointer(&self, model: &str, newest: Option<&str>, report: &mut Reconciled) -> Result<(), StoreError> {
        let pointer = self.model_dir(model).join("current");
        let wanted = newest.map(|sha| format!("{sha}\n"));
        let existing = fs::read_to_string(&pointer).ok();
        if existing == wanted {
            return Ok(());
        }
        match wanted {
            Some(content) => {
                fs::create_dir_all(self.model_dir(model))?;
                write_atomic(&pointer, content.as_bytes())?;
            }
            None => fs::remove_file(&pointer)?,
        }
        report.pointers += 1;
        Ok(())
    }

    fn remove_staged(&self, model: &str, sha: &str, report: &mut Reconciled) {
        for staged in self.staged_of(model, sha) {
            if fs::remove_dir_all(&staged).is_ok() {
                report.cleaned += 1;
            }
        }
    }

    /// Finish the publication of an applied version (idempotent): the published directory, then the pointer, then the cleanup.
    fn publish(&self, store: &CheckpointStore, model: &str, sha: &str) -> Result<(), StoreError> {
        let rows = store.publications(model)?;
        let Some(row) = rows.iter().rev().find(|row| row.manifest == sha) else {
            return Err(StoreError::Storage("The applied version has no publication statement.".to_string()));
        };
        let mut report = Reconciled::default();
        self.ensure_published(store, model, sha, &row.statement, &mut report)?;
        self.crash("renamed")?;
        let newest = rows.last().map(|row| row.manifest.as_str());
        self.write_pointer(model, newest, &mut report)?;
        self.crash("pointer")?;
        self.remove_staged(model, sha, &mut report);
        Ok(())
    }

    /// Startup reconciliation: complete interrupted publications from the authority, repair the pointers, and quarantine what the
    /// authority does not reference.
    pub fn reconcile(&self, store: &CheckpointStore) -> Result<Reconciled, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let mut report = Reconciled::default();
        let models = store.models()?;
        for model in &models {
            let rows = store.publications(model)?;
            if let Some(last) = rows.last() {
                // The authority must agree with its newest publication: a version swapped in without a signature is not served.
                let current = store.resolve(model)?;
                if current != last.manifest {
                    return Err(StoreError::Storage(format!(
                        "The authority serves {current} for {model} but its newest publication is {}; roll back to a published version.",
                        last.manifest
                    )));
                }
            }
            let expected: BTreeSet<String> = rows.iter().map(|row| row.manifest.clone()).collect();
            for sha in &expected {
                if let Some(row) = rows.iter().rev().find(|row| &row.manifest == sha) {
                    self.ensure_published(store, model, sha, &row.statement, &mut report)?;
                }
            }
            if let Ok(entries) = fs::read_dir(self.model_dir(model)) {
                for entry in entries.filter_map(Result::ok) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if entry.path().is_dir() && !expected.contains(&name) {
                        self.quarantine(&entry.path())?;
                        report.quarantined += 1;
                    }
                }
            }
            self.write_pointer(model, rows.last().map(|row| row.manifest.as_str()), &mut report)?;
            for sha in &expected {
                self.remove_staged(model, sha, &mut report);
            }
            // What is still staged for this model belongs to a request that never reached the authority.
            if let Ok(entries) = fs::read_dir(self.staging_root(model)) {
                for entry in entries.filter_map(Result::ok) {
                    self.quarantine(&entry.path())?;
                    report.quarantined += 1;
                }
            }
        }
        if let Ok(entries) = fs::read_dir(self.root.join(".staging")) {
            for entry in entries.filter_map(Result::ok) {
                let name = entry.file_name().to_string_lossy().to_string();
                if !models.contains(&name) && entry.path().is_dir() {
                    self.quarantine(&entry.path())?;
                    report.quarantined += 1;
                }
            }
        }
        Ok(report)
    }

    /// What clients of the published root are served for `model`: the version the pointer names, checked to be complete and to
    /// carry its own statement. `Ok(None)` when nothing is published.
    pub fn served(&self, model: &str) -> Result<Option<Served>, StoreError> {
        let Ok(pointer) = fs::read_to_string(self.model_dir(model).join("current")) else { return Ok(None) };
        let sha = pointer.trim().to_string();
        v3::check_sha(&sha)?;
        let directory = self.published_dir(model, &sha);
        let manifest = fs::read(directory.join("manifest.json"))?;
        if sha256_hex(&manifest) != sha {
            return Err(StoreError::Storage("The served directory is not the version the pointer names.".to_string()));
        }
        let statement = fs::read(directory.join("statement.json"))?;
        let (decoded, _) = publication::decode(&statement).map_err(|error| StoreError::Storage(error.to_string()))?;
        if decoded.manifest_sha != sha || decoded.model_id != model {
            return Err(StoreError::Storage("The served statement is not for the served version.".to_string()));
        }
        Ok(Some(Served { manifest_sha: sha, statement, directory }))
    }
}

impl CommitObserver for Publisher {
    fn prepare(&self, candidate: &Candidate<'_>) -> Result<Option<String>, StoreError> {
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if !self.published_complete(candidate.model_id, candidate.manifest_sha) {
            self.stage(candidate.store, candidate.model_id, candidate.manifest_sha, candidate.request_id, candidate.manifest)?;
        }
        self.crash("staged")?;
        Ok(None)
    }

    fn before_swap(&self, swap: &Swap<'_>, transaction: &Connection) -> Result<(), StoreError> {
        let manifest = swap.store.manifest(swap.candidate)?;
        let sequence: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(sequence),0)+1 FROM publications WHERE model=?1",
            params![swap.model_id],
            |row| row.get(0),
        )?;
        let statement = Statement {
            key_id: self.key_id.clone(),
            model_id: swap.model_id.to_string(),
            manifest_sha: swap.candidate.to_string(),
            parent: text(&manifest, "parent"),
            original: text(&manifest, "original"),
            sequence: u64::try_from(sequence).map_err(|_| StoreError::Storage("The publication sequence is negative.".to_string()))?,
        };
        let wire = publication::sign(&self.seed, &statement).map_err(|error| StoreError::Storage(error.to_string()))?;
        self.crash("signed")?;
        transaction.execute(
            "INSERT INTO publications(model,sequence,manifest,key_id,statement,request_id) VALUES (?1,?2,?3,?4,?5,?6)",
            params![swap.model_id, sequence, swap.candidate, self.key_id, wire, swap.request_id],
        )?;
        Ok(())
    }

    fn after_commit(&self, swap: &Swap<'_>) -> Result<(), StoreError> {
        self.crash("committed")?;
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.publish(swap.store, swap.model_id, swap.candidate)
    }

    fn abandon(&self, model_id: &str, manifest_sha: &str, request_id: &str) {
        if self.crashed.load(Ordering::SeqCst) {
            return;
        }
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        let directory = self.staging_dir(model_id, manifest_sha, request_id);
        if directory.exists() {
            let _ = fs::remove_dir_all(directory);
        }
    }
}
