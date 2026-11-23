//! Trained V3 versions published by param-update (stage V3-R3 of `docs/plans/v3-routine-training.md`).
//!
//! model-streaming serves a trained version only when param-update's **authority** names it. The authority is the SQLite catalog
//! of the V3 checkpoint store (`<V3_STORE>/catalog.sqlite`, tables `current` and `publications`; see
//! `docs/runtime/v3-publication.md`), opened read-only and read again for every request, so a publication, a rollback or a
//! restart of param-update is visible at once and nothing is cached across requests except the proof that an asset file is
//! unchanged. The published tree (`<V3_PUBLISH_ROOT>/<model-id>/<manifest-sha>/`) only supplies bytes: a directory that the
//! authority does not reference is never served, whatever it holds.
//!
//! What is servable for a model:
//!
//! * the pinned ORIGINAL, always, from the standard release store (the compiled pin), whether or not anything was published;
//! * every manifest with a signed publication (the current one and the rollback history). A version that went live without a
//!   signature was never vetted and is never served.
//!
//! `GetModelPackage` with a plain model id returns the model's newest publication when the authority serves it (the signed
//! statement rides along), the pinned ORIGINAL when the model has no publication, and `UNAVAILABLE` when the authority and its
//! publications disagree (the same state param-update refuses to start in). A model id of the form `<model-id>@<manifest-sha>`
//! addresses a version by manifest: the pinned ORIGINAL (without a statement, so historical evaluations reproduce) or a
//! published version (with its newest statement); any other manifest is `INVALID_ARGUMENT`. The signature is not checked here:
//! clients hold the public keys, and this service only serves what the authority records.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use privoke_contracts::proto::v1::{ModelAssetChunk, ModelPackageResponse};
use privoke_contracts::publication;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use tonic::Status;

use crate::error::{Error, Result};
use crate::fail;
use crate::releases::{
    FileInfo, StandardReleases, bounded_file_hash, is_standard_v3, open_file_in, package_in, real_directory, stream_in, unsafe_directory,
};
use crate::util::log;

/// The catalog file inside the V3 store directory.
pub const CATALOG_FILE: &str = "catalog.sqlite";

/// Whether `text` has the shape of a manifest digest: 64 lowercase hexadecimal characters.
pub fn is_manifest_sha(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One signed publication recorded by param-update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// The per-model sequence.
    pub sequence: u64,
    /// The published manifest.
    pub manifest: String,
    /// The signed statement, wire form.
    pub statement: Vec<u8>,
}

/// What param-update's authority says about one model, read in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authority {
    /// The manifest the model serves (`current`), if the store knows the model.
    pub current: Option<String>,
    /// Every publication of the model.
    pub publications: Vec<Publication>,
}

impl Authority {
    /// The newest publication of the model.
    pub fn latest(&self) -> Option<&Publication> {
        self.publications.iter().max_by_key(|publication| publication.sequence)
    }

    /// The newest publication of `manifest`.
    pub fn publication_of(&self, manifest: &str) -> Option<&Publication> {
        self.publications.iter().filter(|publication| publication.manifest == manifest).max_by_key(|publication| publication.sequence)
    }
}

fn sqlite(error: rusqlite::Error) -> Error {
    Error(error.to_string())
}

fn unavailable(error: impl std::fmt::Display) -> Status {
    log(format_args!("published V3 versions: {error}"));
    Status::unavailable("published V3 versions are unavailable")
}

fn not_published() -> Status {
    Status::invalid_argument("explicit standard model and manifest pin required")
}

/// Check that a statement from the authority is about this model and manifest.
fn check_statement(id: &str, manifest: &str, wire: &[u8]) -> std::result::Result<(), Status> {
    match publication::decode(wire) {
        Ok((statement, _)) if statement.model_id == id && statement.manifest_sha == manifest => Ok(()),
        Ok(_) => Err(unavailable("a publication statement names another model or manifest")),
        Err(error) => Err(unavailable(format!("a publication statement is malformed: {error}"))),
    }
}

type Verified = Vec<(String, FileInfo)>;

/// A read-only view of param-update's published versions.
#[derive(Debug)]
pub struct Published {
    root: PathBuf,
    catalog: PathBuf,
    /// Per `<model>/<manifest>`: the asset files whose bytes were hashed against the manifest, as they were then.
    verified: Mutex<BTreeMap<String, Verified>>,
}

impl Published {
    /// A view of the published root `root` whose authority is the catalog in `store_dir`. Both directories must exist and be
    /// real (no symlink on the path). The catalog file itself may not exist yet (nothing published).
    pub fn open(root: &Path, store_dir: &Path) -> Result<Self> {
        let root = real_directory(root, "published V3 directory is missing or unsafe")?;
        let store = real_directory(store_dir, "V3 store directory is missing or unsafe")?;
        Ok(Self { root, catalog: store.join(CATALOG_FILE), verified: Mutex::new(BTreeMap::new()) })
    }

    /// What the authority says about `model`: a read-only snapshot. A missing catalog is an empty authority (nothing has been
    /// published); an unreadable one is an error.
    pub fn authority(&self, model: &str) -> Result<Authority> {
        if !is_standard_v3(model) {
            fail!("unknown standard model");
        }
        match std::fs::symlink_metadata(&self.catalog) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Authority::default()),
            Err(error) => return Err(error.into()),
            Ok(info) if !info.is_file() => fail!("the V3 catalog is not a regular file"),
            Ok(_) => {}
        }
        let database = Connection::open_with_flags(&self.catalog, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(sqlite)?;
        database.busy_timeout(Duration::from_secs(5)).map_err(sqlite)?;
        let snapshot = database.unchecked_transaction().map_err(sqlite)?;
        let current = snapshot
            .query_row("SELECT manifest FROM current WHERE model=?1", params![model], |row| row.get::<_, String>(0))
            .optional()
            .map_err(sqlite)?;
        let mut publications = Vec::new();
        {
            let mut query = snapshot
                .prepare("SELECT sequence,manifest,statement FROM publications WHERE model=?1 ORDER BY sequence")
                .map_err(sqlite)?;
            let rows = query
                .query_map(params![model], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))
                .map_err(sqlite)?;
            for row in rows {
                let (sequence, manifest, statement) = row.map_err(sqlite)?;
                let Ok(sequence) = u64::try_from(sequence) else { fail!("a publication has a negative sequence") };
                publications.push(Publication { sequence, manifest, statement });
            }
        }
        Ok(Authority { current, publications })
    }

    /// The published directory of a version, after the shape checks and the symlink checks of its two path components.
    fn version_directory(&self, id: &str, sha: &str) -> std::result::Result<PathBuf, Status> {
        if !is_standard_v3(id) || !is_manifest_sha(sha) {
            return Err(not_published());
        }
        let model = self.root.join(id);
        let directory = model.join(sha);
        if unsafe_directory(&model) || unsafe_directory(&directory) {
            return Err(unavailable(format!("the published directory of {id}@{sha} is missing or unsafe")));
        }
        Ok(directory)
    }

    /// The package of a published version, read from its directory: the manifest hashes to `sha`, and every asset has the
    /// digest the manifest names (hashed once, and again whenever the file changes on disk). No statement is attached.
    fn package(&self, id: &str, sha: &str) -> std::result::Result<ModelPackageResponse, Status> {
        let directory = self.version_directory(id, sha)?;
        let package = package_in(&directory, id, sha).map_err(|error| unavailable(format!("{id}@{sha}: {error}")))?;
        let mut opened = Vec::new();
        for asset in &package.assets {
            let (file, info) = open_file_in(&directory, &asset.name).map_err(|error| unavailable(format!("{id}@{sha}: {error}")))?;
            opened.push((asset.name.clone(), file, info));
        }
        let key = format!("{id}/{sha}");
        let unchanged = self.verified.lock().unwrap_or_else(PoisonError::into_inner).get(&key).is_some_and(|previous| {
            previous.len() == opened.len()
                && previous.iter().zip(&opened).all(|((name, before), (other, _, after))| name == other && before.same_as(after))
        });
        if !unchanged {
            for (asset, (_, file, _)) in package.assets.iter().zip(opened.iter_mut()) {
                match bounded_file_hash(file) {
                    Ok(digest) if digest == asset.sha256 => {}
                    _ => return Err(Status::data_loss("model asset hash mismatch")),
                }
            }
            let proven = opened.into_iter().map(|(name, _, info)| (name, info)).collect();
            self.verified.lock().unwrap_or_else(PoisonError::into_inner).insert(key, proven);
        }
        Ok(package)
    }

    /// What `GetModelPackage` returns for `id` when the request names no manifest.
    pub fn current_package(&self, releases: &StandardReleases, id: &str) -> std::result::Result<ModelPackageResponse, Status> {
        let pinned = || releases.manifest(id).map_err(|_| Status::unavailable("standard V3 manifest is unavailable"));
        let authority = self.authority(id).map_err(unavailable)?;
        let Some(latest) = authority.latest() else { return pinned() };
        if authority.current.as_deref() != Some(latest.manifest.as_str()) {
            return Err(unavailable(format!("{id}: the authority serves a version without its newest publication")));
        }
        check_statement(id, &latest.manifest, &latest.statement)?;
        // A signed rollback to the ORIGINAL serves the pinned bytes.
        let mut package = if releases.pin(id) == Some(latest.manifest.as_str()) { pinned()? } else { self.package(id, &latest.manifest)? };
        package.publication_statement.clone_from(&latest.statement);
        Ok(package)
    }

    /// What `GetModelPackage` returns for `<id>@<sha>`: the pinned ORIGINAL (no statement) or a published version.
    pub fn package_at(&self, releases: &StandardReleases, id: &str, sha: &str) -> std::result::Result<ModelPackageResponse, Status> {
        if releases.pin(id) == Some(sha) {
            return releases.manifest(id).map_err(|_| Status::unavailable("standard V3 manifest is unavailable"));
        }
        let authority = self.authority(id).map_err(unavailable)?;
        let Some(publication) = authority.publication_of(sha) else { return Err(not_published()) };
        check_statement(id, sha, &publication.statement)?;
        let mut package = self.package(id, sha)?;
        package.publication_statement.clone_from(&publication.statement);
        Ok(package)
    }

    /// Whether the authority holds a publication of `sha` for `id` (the pinned ORIGINAL is the caller's to serve).
    pub fn is_published(&self, id: &str, sha: &str) -> std::result::Result<bool, Status> {
        if !is_standard_v3(id) || !is_manifest_sha(sha) {
            return Ok(false);
        }
        Ok(self.authority(id).map_err(unavailable)?.publication_of(sha).is_some())
    }

    /// `StreamModelAsset` for a published version: the authority is read again, then the asset is re-hashed and streamed
    /// exactly as a pinned one is. A manifest that has no publication is `INVALID_ARGUMENT`.
    pub fn stream_asset(
        &self,
        id: &str,
        sha: &str,
        asset_name: &str,
        send: impl FnMut(ModelAssetChunk) -> bool,
    ) -> std::result::Result<(), Status> {
        if !self.is_published(id, sha)? {
            return Err(not_published());
        }
        let directory = self.version_directory(id, sha)?;
        stream_in(&directory, id, sha, asset_name, send)
    }
}
