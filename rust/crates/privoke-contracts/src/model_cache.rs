//! The client's model cache as every reader of it sees it (stage V3-R4b of the V3 routine-training plan).
//!
//! The supervisor fetch writes the cache and the sandboxed worker reads it, so the rule that says which version of a model may be
//! loaded lives here, in one place, and both sides apply it:
//!
//! ```text
//! <cache>/<model id>/<manifest sha>/{manifest.json, model.safetensors, config.json, vocab.txt, evidence.json, statement.json}
//! <cache>/<model id>/high-water.statement     the highest statement accepted for the model (V3-R4a)
//! <cache>/<model id>/.lock                    advisory lock of the writers of the mark and of the garbage collection
//! ```
//!
//! [`ModelCache::select`] is the offline start-up rule and the reload rule in one: the version a loader may use is the one the
//! high-water mark names (its statement, re-verified under the compiled keys, must carry the mark's sequence and manifest), or,
//! while the model has no mark at all (the first start), the compiled pinned release. A client whose mark is a signed version
//! therefore never selects the unsigned pin, nor any version below the mark, and a loader that calls the selection on every load
//! sees a newer version as soon as the supervisor has admitted it and moved the mark. Reading takes no lock: the mark and every
//! statement are replaced by atomic renames, and a version directory is complete before the mark names it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::publication::{self, KeySet, PublicationError, Statement};
use crate::v3::{self, LineageState, TierPin};

/// The publication statement of a version, kept beside its manifest in the cache directory (absent for an unsigned ORIGINAL).
pub const STATEMENT_FILE: &str = "statement.json";
/// The highest statement accepted for a model, kept in `<cache>/<model id>/` and re-verified on every read.
pub const HIGH_WATER_FILE: &str = "high-water.statement";
/// The advisory lock file of a model directory.
pub const LOCK_FILE: &str = ".lock";

/// Why the cache could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacheError {
    /// A rule of the cache failed (a tampered mark, a missing version, a link where a file belongs).
    #[error("{0}")]
    Invalid(String),
    /// A file could not be read or written.
    #[error("{path}: {message}")]
    Io {
        /// The path involved.
        path: String,
        /// The cause.
        message: String,
    },
}

fn invalid(message: &str) -> CacheError {
    CacheError::Invalid(message.to_string())
}

fn io_at(path: &Path) -> impl FnOnce(std::io::Error) -> CacheError + '_ {
    move |source| CacheError::Io { path: path.display().to_string(), message: source.to_string() }
}

/// What a client trusts: the compiled publication keys and the compiled tier pins.
#[derive(Debug, Clone)]
pub struct CacheRules {
    keys: KeySet,
    pins: Option<BTreeMap<String, TierPin>>,
}

impl CacheRules {
    /// The product rules: the keys and the tier pins compiled into this build.
    pub fn production() -> Self {
        Self::new(publication::production_key_set())
    }

    /// An explicit key set with the compiled tier pins.
    pub fn new(keys: KeySet) -> Self {
        Self { keys, pins: None }
    }

    /// Replace the compiled tier pins (a synthetic ORIGINAL in tests). Compiled only with the `test-keys` feature.
    #[cfg(feature = "test-keys")]
    #[must_use]
    pub fn with_pins(mut self, pins: BTreeMap<String, TierPin>) -> Self {
        self.pins = Some(pins);
        self
    }

    /// The compiled publication keys.
    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// The compiled pin of a standard model id.
    pub fn tier_pin(&self, model_id: &str) -> Option<TierPin> {
        match &self.pins {
            Some(pins) => pins.get(model_id).cloned(),
            None => v3::standard_tier_pin(model_id),
        }
    }
}

/// A cached version directory and the statement kept beside it, when that verifies under the compiled keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedVersion {
    /// The manifest SHA-256 (the directory name).
    pub manifest_sha: String,
    /// The directory.
    pub directory: PathBuf,
    /// The verified statement of `statement.json`; `None` when there is none or it does not verify.
    pub statement: Option<Statement>,
    /// The statement of `statement.json` when it names a key this build no longer compiles: it cannot be verified, so it only
    /// counts as a floor (like a mark under a dropped key), never as admission.
    pub unverified: Option<Statement>,
}

/// The version a loader may load now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    /// The version directory.
    pub directory: PathBuf,
    /// The manifest SHA-256.
    pub manifest_sha: String,
    /// The wire statement kept beside the manifest, empty for the unsigned pinned release. The loader admits the manifest with
    /// it through [`v3::admit_lineage`] before it uses a byte of the version.
    pub statement: Vec<u8>,
}

/// An exclusive advisory lock on a model directory, released when dropped.
#[derive(Debug)]
pub struct ModelLock {
    file: fs::File,
}

impl Drop for ModelLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// The model cache under `root` and the rules that admit what is in it.
#[derive(Debug, Clone)]
pub struct ModelCache {
    root: PathBuf,
    rules: CacheRules,
}

impl ModelCache {
    /// The cache at `root`.
    pub fn new(root: &Path, rules: CacheRules) -> Self {
        Self { root: root.to_path_buf(), rules }
    }

    /// The cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The rules.
    pub fn rules(&self) -> &CacheRules {
        &self.rules
    }

    /// The directory of a standard model, beneath no link. It is not created.
    pub fn model_directory(&self, model_id: &str) -> Result<PathBuf, CacheError> {
        if v3::standard_pin(model_id).is_none() {
            return Err(invalid("Model is not a pinned standard AU3 release"));
        }
        let path = self.root.join(model_id);
        let path = std::path::absolute(&path).map_err(io_at(&path))?;
        for parent in path.ancestors() {
            if is_link(parent)? {
                return Err(invalid("Model cache must not traverse symlinks"));
            }
        }
        Ok(path)
    }

    /// The floor a new statement must clear: the mark when it verifies; when it is signed by a key this build no longer compiles
    /// (a rotation or a compromise), its sequence and manifest still count as the floor, and the next version must carry a
    /// statement under a current key above it; a mark that is malformed or whose signature is wrong fails closed. Without a
    /// mark, the floor is rebuilt from the highest cached `statement.json` that still verifies (a deleted mark reopens nothing
    /// while the cache holds a signed version; only an empty model cache is trust on first use).
    pub fn read_high_water(&self, model_id: &str) -> Result<Option<Statement>, CacheError> {
        let directory = self.model_directory(model_id)?;
        if !directory.is_dir() {
            return Ok(None);
        }
        let path = directory.join(HIGH_WATER_FILE);
        if !exists_or_link(&path)? {
            return self.cached_floor(model_id);
        }
        let bytes = read_statement_file(&path)?;
        let statement = match publication::verify(&self.rules.keys, &bytes) {
            Ok(statement) => statement,
            Err(PublicationError::UnknownKey) => publication::decode(&bytes).map(|(statement, _)| statement).map_err(|error| {
                CacheError::Invalid(format!("High-water record of {model_id} is malformed ({error}); clear the model cache of {model_id}"))
            })?,
            Err(error) => {
                return Err(CacheError::Invalid(format!(
                    "High-water record of {model_id} does not verify ({error}); clear the model cache of {model_id} to trust the pinned ORIGINAL again"
                )));
            }
        };
        if statement.model_id != model_id {
            return Err(invalid("High-water record names another model"));
        }
        Ok(Some(statement))
    }

    /// The highest sequence among the cached versions whose `statement.json` verifies under the current keys.
    fn cached_floor(&self, model_id: &str) -> Result<Option<Statement>, CacheError> {
        let mut floor: Option<Statement> = None;
        for version in self.versions(model_id)? {
            if let Some(statement) = version.statement.or(version.unverified)
                && floor.as_ref().is_none_or(|best| statement.sequence > best.sequence)
            {
                floor = Some(statement);
            }
        }
        Ok(floor)
    }

    /// Every cached version directory of the model (a directory named by a SHA-256, not a link), with its verified statement.
    pub fn versions(&self, model_id: &str) -> Result<Vec<CachedVersion>, CacheError> {
        let directory = self.model_directory(model_id)?;
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut found = Vec::new();
        for entry in fs::read_dir(&directory).map_err(io_at(&directory))? {
            let entry = entry.map_err(io_at(&directory))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let version = directory.join(&name);
            if !v3::is_sha_text(&name) || is_link(&version)? || !version.is_dir() {
                continue;
            }
            let bytes = read_statement(&version).ok().filter(|bytes| !bytes.is_empty());
            let named = |statement: &Statement| statement.model_id == model_id && statement.manifest_sha == name;
            let (mut statement, mut unverified) = (None, None);
            if let Some(bytes) = bytes {
                match publication::verify(&self.rules.keys, &bytes) {
                    Ok(verified) if named(&verified) => statement = Some(verified),
                    Err(PublicationError::UnknownKey) => {
                        unverified = publication::decode(&bytes).ok().map(|(decoded, _)| decoded).filter(named)
                    }
                    _ => {}
                }
            }
            found.push(CachedVersion { manifest_sha: name, directory: version, statement, unverified });
        }
        found.sort_by(|left, right| left.manifest_sha.cmp(&right.manifest_sha));
        Ok(found)
    }

    /// The version a loader may load, or `None` when the model has nothing cached yet.
    ///
    /// With a high-water mark it is the version the mark names, and only that one: the statement kept beside it must verify under
    /// the compiled keys and carry the mark's sequence and manifest, so the unsigned pin, an older version and a directory
    /// whose statement was swapped are all refused. Without a mark (the first start) it is the compiled pinned release. A mark
    /// whose version is missing or does not match is an error, never a fallback to another version: the supervisor's next
    /// refresh restores it. The returned statement still has to be admitted by the loader ([`v3::admit_lineage`]).
    pub fn select(&self, model_id: &str) -> Result<Option<Selected>, CacheError> {
        let directory = self.model_directory(model_id)?;
        if !directory.is_dir() {
            return Ok(None);
        }
        let mark = self.read_high_water(model_id)?;
        let Some(mark) = mark else {
            let pin = self.rules.tier_pin(model_id).ok_or_else(|| invalid("Model is not a pinned standard AU3 release"))?;
            let version = directory.join(&pin.manifest_sha);
            if is_link(&version)? || !version.join("manifest.json").is_file() {
                return Ok(None);
            }
            let statement = read_statement(&version)?;
            return Ok(Some(Selected { directory: version, manifest_sha: pin.manifest_sha, statement }));
        };
        if !v3::is_sha_text(&mark.manifest_sha) {
            return Err(invalid("High-water record names no manifest"));
        }
        let version = directory.join(&mark.manifest_sha);
        if is_link(&version)? || !version.join("manifest.json").is_file() {
            return Err(CacheError::Invalid(format!(
                "The version at the high-water mark of {model_id} ({}) is not in the cache; the next refresh restores it",
                mark.manifest_sha
            )));
        }
        let bytes = read_statement(&version)?;
        let kept = publication::verify(&self.rules.keys, &bytes).map_err(|error| {
            CacheError::Invalid(format!("The statement of the version at the high-water mark of {model_id} does not verify ({error})"))
        })?;
        // The statement kept beside the version may be newer than the mark for the same manifest: a version that is served again
        // under a higher sequence gets its statement before the mark moves. Anything below the mark, or for another manifest, is not.
        if kept.model_id != model_id || kept.manifest_sha != mark.manifest_sha || kept.sequence < mark.sequence {
            return Err(invalid("The cached version does not carry the statement of the high-water mark"));
        }
        Ok(Some(Selected { directory: version, manifest_sha: mark.manifest_sha, statement: bytes }))
    }

    /// Take the exclusive advisory lock of a model directory, waiting for another holder (another process, or another thread
    /// that opened its own handle). A writer of the high-water mark and the garbage collector hold it while they read the mark
    /// and act on it, so two of them cannot interleave. The model directory must exist.
    pub fn lock(&self, model_id: &str) -> Result<ModelLock, CacheError> {
        let directory = self.model_directory(model_id)?;
        let path = directory.join(LOCK_FILE);
        if is_link(&path)? {
            return Err(invalid("Model cache lock must not be a symlink"));
        }
        let file = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&path).map_err(io_at(&path))?;
        file.lock().map_err(io_at(&path))?;
        Ok(ModelLock { file })
    }
}

impl LineageState for ModelCache {
    fn tier_pin(&self, model_id: &str) -> Option<TierPin> {
        self.rules.tier_pin(model_id)
    }

    fn high_water(&self, model_id: &str) -> Result<Option<Statement>, String> {
        self.read_high_water(model_id).map_err(|error| error.to_string())
    }
}

/// The statement kept beside a cached manifest; empty when there is none (an unsigned ORIGINAL).
pub fn read_statement(directory: &Path) -> Result<Vec<u8>, CacheError> {
    let path = directory.join(STATEMENT_FILE);
    if !exists_or_link(&path)? {
        return Ok(Vec::new());
    }
    read_statement_file(&path)
}

/// A regular, non-link, size-bounded statement file.
pub fn read_statement_file(path: &Path) -> Result<Vec<u8>, CacheError> {
    if is_link(path)? || !path.is_file() {
        return Err(invalid("Publication statement must be a regular non-symlink file"));
    }
    if fs::metadata(path).map_err(io_at(path))?.len() > publication::MAX_STATEMENT_BYTES as u64 {
        return Err(invalid("Publication statement is too large"));
    }
    fs::read(path).map_err(io_at(path))
}

/// Symlinks and Windows junctions and reparse points, including broken ones.
pub fn is_link(path: &Path) -> Result<bool, CacheError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let reparse = false;
            Ok(metadata.file_type().is_symlink() || reparse)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_at(path)(source)),
    }
}

fn exists_or_link(path: &Path) -> Result<bool, CacheError> {
    Ok(path.exists() || is_link(path)?)
}
