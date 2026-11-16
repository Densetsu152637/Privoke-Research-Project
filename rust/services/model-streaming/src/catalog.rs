//! The model catalog: an allow-list of validated artifact IDs and their paths. Requests never become file paths
//! directly, which prevents path traversal. Port of `catalog.go`.
//!
//! Scratch presence models may be installed after startup, so they are read live. Each live read inspects the entry
//! without following links, opens it, and requires that the opened file, the entry before the read and the entry after
//! the read are the same file, and that the pinned catalog directory is still the same directory.

use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use same_file::Handle;

use crate::artifact::{self, LoadedArtifact, MAX_ARTIFACT_BYTES};
use crate::error::{Error, Result};
use crate::fail;
use crate::pretrained;
use crate::releases::{StandardReleases, is_standard_v3};
use crate::scratch::{self, is_scratch_model_id, scratch_model_ids};

/// The alias for the configured latest model.
pub const LATEST_MODEL_ALIAS: &str = "latest";

/// Test seam: replaces the entry inspection of a scratch file (`root`, file name).
pub type LstatHook = Arc<dyn Fn(&Path, &str) -> std::io::Result<Metadata> + Send + Sync>;
/// Test seam: replaces the open of a scratch file (`root`, file name).
pub type OpenHook = Arc<dyn Fn(&Path, &str) -> std::io::Result<File> + Send + Sync>;

#[derive(Debug)]
enum EntryError {
    Absent,
    Failed(String),
}

impl From<EntryError> for Error {
    fn from(error: EntryError) -> Self {
        match error {
            EntryError::Absent => Self("scratch artifact is absent".into()),
            EntryError::Failed(message) => Self(message),
        }
    }
}

struct Entry {
    metadata: Metadata,
    identity: Option<Handle>,
}

#[derive(Debug)]
struct DirectoryPin {
    path: PathBuf,
    identity: Handle,
}

/// The catalog.
pub struct Catalog {
    latest_model_id: String,
    /// The standard V3 release store, present only when `latest` is a standard model.
    pub releases: Option<StandardReleases>,
    directory: Option<DirectoryPin>,
    paths: BTreeMap<String, PathBuf>,
    scratch_lstat: RwLock<Option<LstatHook>>,
    scratch_open: RwLock<Option<OpenHook>>,
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Catalog")
            .field("latest_model_id", &self.latest_model_id)
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

fn file_name_has_json_extension(name: &str) -> bool {
    name.rfind('.').is_some_and(|dot| &name[dot..] == ".json")
}

impl Catalog {
    /// A catalog built by hand over explicit paths, with no pinned directory (the Go tests' `modelCatalog{...}`).
    pub fn from_paths(latest_model_id: &str, paths: BTreeMap<String, PathBuf>) -> Self {
        Self {
            latest_model_id: latest_model_id.to_string(),
            releases: None,
            directory: None,
            paths,
            scratch_lstat: RwLock::new(None),
            scratch_open: RwLock::new(None),
        }
    }

    /// `loadModelCatalog`: validate every artifact in the directory and pin the directory.
    pub fn load(directory: &Path, latest_model_id: &str) -> Result<Self> {
        if scratch::is_scratch_model_id(latest_model_id) {
            fail!("scratch presence cannot be the latest model");
        }
        if latest_model_id == pretrained::MODEL_ID {
            fail!("experimental pretrained contextual model cannot be latest");
        }
        let resolved = std::fs::canonicalize(directory).map_err(|error| Error(format!("resolve model artifact directory: {error}")))?;
        let identity = Handle::from_path(&resolved).map_err(|error| Error(format!("open model artifact directory: {error}")))?;
        if !std::fs::metadata(&resolved).is_ok_and(|info| info.is_dir()) {
            fail!("model artifact path is not a directory");
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&resolved).map_err(|error| Error(format!("read model artifact directory: {error}")))? {
            let entry = entry.map_err(|error| Error(format!("read model artifact directory: {error}")))?;
            let is_directory = entry.file_type().is_ok_and(|kind| kind.is_dir());
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_directory || !file_name_has_json_extension(&name) {
                continue;
            }
            names.push(name);
        }
        names.sort();
        let mut paths: BTreeMap<String, PathBuf> = BTreeMap::new();
        for name in names {
            let path = resolved.join(&name);
            let loaded =
                artifact::load_model_artifact(&path, "").map_err(|error| Error(format!("load catalog artifact {name:?}: {error}")))?;
            let model_id = loaded.artifact.model_id;
            if model_id == LATEST_MODEL_ALIAS {
                fail!("model ID {LATEST_MODEL_ALIAS:?} is reserved");
            }
            if is_scratch_model_id(&model_id) && name != format!("{model_id}.json") {
                fail!("scratch model {model_id:?} must use its canonical filename");
            }
            if model_id == pretrained::MODEL_ID && name != format!("{}.json", pretrained::MODEL_ID) {
                fail!("pretrained contextual model must use its canonical filename");
            }
            if paths.contains_key(&model_id) {
                fail!("duplicate model ID {model_id:?}");
            }
            paths.insert(model_id, path);
        }
        if paths.is_empty() {
            fail!("model artifact directory contains no models");
        }
        if !paths.contains_key(latest_model_id) && !is_standard_v3(latest_model_id) {
            fail!("latest model {latest_model_id:?} is not in the catalog");
        }
        Ok(Self {
            latest_model_id: latest_model_id.to_string(),
            releases: None,
            directory: Some(DirectoryPin { path: resolved, identity }),
            paths,
            scratch_lstat: RwLock::new(None),
            scratch_open: RwLock::new(None),
        })
    }

    /// The configured latest model.
    pub fn latest_model_id(&self) -> &str {
        &self.latest_model_id
    }

    /// Test support: change the latest model of a hand-built catalog.
    pub fn set_latest_model_id(&mut self, id: &str) {
        self.latest_model_id = id.to_string();
    }

    /// Install or clear the scratch inspection seam.
    pub fn set_scratch_lstat(&self, hook: Option<LstatHook>) {
        *self.scratch_lstat.write().unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    /// Install or clear the scratch open seam.
    pub fn set_scratch_open(&self, hook: Option<OpenHook>) {
        *self.scratch_open.write().unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    /// `catalog.load`: resolve `latest`, then load and revalidate the artifact from disk.
    pub fn load_model(&self, requested: &str) -> Result<LoadedArtifact> {
        if self.latest_model_id == pretrained::MODEL_ID {
            fail!("experimental pretrained contextual model cannot be latest");
        }
        let model_id = if requested.is_empty() || requested == LATEST_MODEL_ALIAS { self.latest_model_id.as_str() } else { requested };
        if is_scratch_model_id(model_id) {
            if model_id == self.latest_model_id {
                fail!("scratch presence cannot be the latest model");
            }
            if self.directory.is_none() {
                // Preserve hand-built catalogs used by embedded callers and tests.
                if let Some(path) = self.paths.get(model_id) {
                    return artifact::load_model_artifact(path, model_id);
                }
                fail!("model {requested:?} is unavailable");
            }
            return self.load_scratch(model_id);
        }
        let Some(path) = self.paths.get(model_id) else { fail!("model {requested:?} is unavailable") };
        let loaded = artifact::load_model_artifact(path, model_id)?;
        if model_id == self.latest_model_id && loaded.artifact.architecture == pretrained::ARCHITECTURE {
            fail!("experimental pretrained contextual model cannot be latest");
        }
        if model_id == self.latest_model_id && loaded.artifact.architecture == scratch::SCRATCH_PRESENCE_ARCHITECTURE {
            fail!("scratch presence cannot be the latest model");
        }
        Ok(loaded)
    }

    fn load_scratch(&self, model_id: &str) -> Result<LoadedArtifact> {
        if !is_scratch_model_id(model_id) || model_id == self.latest_model_id {
            fail!("scratch model {model_id:?} is unavailable");
        }
        let entry = self.scratch_entry(model_id)?;
        if !entry.metadata.is_file() {
            fail!("scratch artifact must be a regular file");
        }
        let name = format!("{model_id}.json");
        let file = self.open_scratch(&name).map_err(|error| Error(format!("open scratch artifact: {error}")))?;
        let opened = Handle::from_file(file.try_clone()?).map_err(|error| Error(format!("stat opened scratch artifact: {error}")))?;
        let opened_regular = file.metadata().is_ok_and(|info| info.is_file());
        if !opened_regular || entry.identity.as_ref() != Some(&opened) {
            fail!("opened scratch artifact does not match the inspected regular file");
        }
        let mut raw = Vec::new();
        file.take(MAX_ARTIFACT_BYTES as u64 + 1).read_to_end(&mut raw).map_err(|error| Error(format!("read scratch artifact: {error}")))?;
        if raw.is_empty() || raw.len() > MAX_ARTIFACT_BYTES {
            fail!("scratch artifact bytes exceed supported range");
        }
        let after = self.scratch_entry(model_id)?;
        if !after.metadata.is_file() || after.identity != entry.identity {
            fail!("scratch artifact path changed while reading");
        }
        self.verify_directory_identity()?;
        artifact::load_model_artifact_bytes(&raw, model_id)
    }

    fn scratch_entry(&self, model_id: &str) -> std::result::Result<Entry, EntryError> {
        if !is_scratch_model_id(model_id) {
            return Err(EntryError::Failed(format!("scratch model {model_id:?} is unavailable")));
        }
        self.verify_directory_identity().map_err(|error| EntryError::Failed(error.0))?;
        let name = format!("{model_id}.json");
        let metadata = self.lstat_scratch(&name).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                EntryError::Absent
            } else {
                EntryError::Failed(format!("inspect scratch artifact: {error}"))
            }
        })?;
        let identity = if metadata.is_file() {
            let path = self.directory_path().join(&name);
            Some(Handle::from_path(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    EntryError::Absent
                } else {
                    EntryError::Failed(format!("inspect scratch artifact: {error}"))
                }
            })?)
        } else {
            None
        };
        Ok(Entry { metadata, identity })
    }

    fn directory_path(&self) -> &Path {
        self.directory.as_ref().map_or_else(|| Path::new("."), |pin| pin.path.as_path())
    }

    fn verify_directory_identity(&self) -> Result<()> {
        let Some(pin) = &self.directory else { fail!("scratch catalog directory identity is unavailable") };
        match Handle::from_path(&pin.path) {
            Ok(current) if current == pin.identity => {}
            Ok(_) => fail!("scratch catalog directory path changed"),
            Err(error) => fail!("stat scratch catalog directory path: {error}"),
        }
        if !std::fs::metadata(&pin.path).is_ok_and(|info| info.is_dir()) {
            fail!("scratch catalog directory path changed");
        }
        Ok(())
    }

    fn lstat_scratch(&self, name: &str) -> std::io::Result<Metadata> {
        let hook = self.scratch_lstat.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        match hook {
            Some(hook) => hook(self.directory_path(), name),
            None => std::fs::symlink_metadata(self.directory_path().join(name)),
        }
    }

    fn open_scratch(&self, name: &str) -> std::io::Result<File> {
        let hook = self.scratch_open.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        match hook {
            Some(hook) => hook(self.directory_path(), name),
            None => File::open(self.directory_path().join(name)),
        }
    }

    /// `contains`: whether a request names something the catalog may serve (a failed scratch inspection counts, so
    /// the caller reports `UNAVAILABLE` rather than `NOT_FOUND`).
    pub fn contains(&self, requested: &str) -> bool {
        if is_standard_v3(requested) {
            return self.releases.is_some();
        }
        if requested.is_empty() || requested == LATEST_MODEL_ALIAS {
            return true;
        }
        if is_scratch_model_id(requested) {
            if self.directory.is_none() {
                return self.paths.contains_key(requested);
            }
            return !matches!(self.scratch_entry(requested), Err(EntryError::Absent));
        }
        self.paths.contains_key(requested)
    }

    /// `modelIDs`, sorted.
    pub fn model_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.paths.keys().filter(|id| !is_scratch_model_id(id) || self.directory.is_none()).cloned().collect();
        if self.directory.is_some() {
            ids.extend(scratch_model_ids().into_iter().filter(|id| self.contains(id)));
        }
        if self.releases.is_some() {
            ids.extend(crate::releases::STANDARD_IDS.iter().map(|id| (*id).to_string()));
        }
        ids.sort();
        ids
    }

    /// `validate`: the readiness check behind `Health`.
    pub fn validate(&self) -> Result<()> {
        if is_standard_v3(&self.latest_model_id) {
            let Some(releases) = &self.releases else { fail!("standard V3 releases unavailable") };
            releases.validate()?;
        }
        if is_scratch_model_id(&self.latest_model_id) {
            fail!("scratch presence cannot be the latest model");
        }
        for (model_id, path) in &self.paths {
            if is_scratch_model_id(model_id) {
                if self.directory.is_none() {
                    artifact::load_model_artifact(path, model_id)?;
                }
                continue;
            }
            self.load_model(model_id)?;
        }
        if self.directory.is_none() {
            return Ok(());
        }
        for model_id in scratch_model_ids() {
            match self.scratch_entry(&model_id) {
                Err(EntryError::Absent) => continue,
                Err(EntryError::Failed(message)) => fail!("inspect optional scratch model {model_id:?}: {message}"),
                Ok(_) => {}
            }
            self.load_scratch(&model_id).map_err(|error| Error(format!("validate optional scratch model {model_id:?}: {error}")))?;
        }
        Ok(())
    }
}

/// Lowercase hexadecimal, re-exported for the modules that hash.
pub use crate::util::hex;
