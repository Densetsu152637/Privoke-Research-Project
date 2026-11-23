//! Model fetch: the supervisor, not the runtime, downloads the standard V3 package.
//!
//! This is the port of `v3_package.fetch_package` and `receive_asset`, with the same cache layout
//! (`<cache>/<model id>/<manifest pin>/{manifest.json, model.safetensors, config.json, vocab.txt, evidence.json}`),
//! so the Python runtime and the Rust supervisor share one cache. The trust chain is:
//!
//! 1. the call is made over mutual TLS with the installation certificate (see [`crate::channel`]);
//! 2. the manifest bytes must hash to the pin compiled into the client for that model, and satisfy the manifest
//!    contract ([`privoke_contracts::v3`]); the server's claim of which pin it serves is not trusted;
//! 3. every asset stream must keep its declared identity, order, bounds, size and SHA-256, and is written to a
//!    temporary file first; nothing partial is ever visible under its final name;
//! 4. the manifest is fetched again after the assets and must not have changed;
//! 5. the finished directory is re-read from disk and every file is re-hashed against the manifest.
//!
//! Step 2 is the [`Admission`] rule. [`StandardAdmission`] is pin-only. [`LineageAdmission`] (stage V3-R4a of the V3 routine-training
//! plan) also admits a trained version, on a publication statement that verifies under a compiled key, lineage from the compiled
//! ORIGINAL and a per-model sequence above the high-water mark persisted next to the cache (see its documentation).
//!
//! Directories are private to the user and must not traverse links; an existing cached asset is re-hashed, never
//! trusted, and a corrupted one is an error, not something to overwrite.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_contracts::proto::v1::{ModelAssetRequest, ModelPackageResponse, ModelParametersRequest};
use privoke_contracts::publication::{self, KeySet, PublicationError, Statement};
use privoke_contracts::v3::{self, LineageError, LineageState, TierPin};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tonic::transport::Channel;

/// The publication statement of a version, kept beside its manifest in the cache directory (absent for an unsigned ORIGINAL).
pub const STATEMENT_FILE: &str = "statement.json";
/// The highest statement accepted for a model, kept in `<cache>/<model id>/` and re-verified on every read.
pub const HIGH_WATER_FILE: &str = "high-water.statement";

/// The four assets of a package and the manifest key that holds each one's hash.
pub const ASSETS: [(&str, &str); 4] =
    [("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab"), ("evidence.json", "evidence")];

/// Why a fetch failed. Every variant leaves no partial package under a final name.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// A rule of the package contract failed (the Python `ValueError`s).
    #[error("{0}")]
    Invalid(String),
    /// The server answered with an error status.
    #[error("model-streaming error: {0}")]
    Rpc(#[from] tonic::Status),
    /// The lineage and signature rule refused the version (stage V3-R4a).
    #[error("{0}")]
    Lineage(#[from] LineageError),
    /// The cache could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The cause.
        source: std::io::Error,
    },
}

impl FetchError {
    /// Whether the failure is transient: the server is unavailable or did not answer in time. Nothing in the cache or the
    /// persisted high-water mark changed, so the caller keeps what it has and retries later.
    pub fn is_transient(&self) -> bool {
        matches!(self, FetchError::Rpc(status) if matches!(status.code(), tonic::Code::Unavailable | tonic::Code::DeadlineExceeded))
    }
}

fn invalid(message: &str) -> FetchError {
    FetchError::Invalid(message.to_string())
}

fn io_at(path: &Path) -> impl FnOnce(std::io::Error) -> FetchError + '_ {
    move |source| FetchError::Io { path: path.to_path_buf(), source }
}

/// What the client accepts as a manifest, the hash it must have and which hash each asset must have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedManifest {
    /// `privoke-v3-<tier>`.
    pub model_id: String,
    /// The SHA-256 of the manifest bytes: the compiled pin for [`StandardAdmission`], the version's own hash for a trained
    /// version admitted by [`LineageAdmission`].
    pub pin: String,
    /// Asset name to its SHA-256, from the manifest.
    pub assets: BTreeMap<&'static str, String>,
}

/// The admission rule. The product uses [`LineageAdmission::production`]; [`StandardAdmission`] is the pin-only rule, and tests
/// supply their own pins for a synthetic package.
pub trait Admission: Send + Sync {
    /// Admit `manifest_json` for a request naming `requested` (`latest`, a model id or empty).
    fn admit(&self, manifest_json: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError>;

    /// Admit `manifest_json` together with the publication statement the server sent with it (empty when none). Nothing is
    /// persisted. The default ignores the statement and applies [`Admission::admit`], which is the pin-only rule.
    fn admit_published(&self, manifest_json: &[u8], statement: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError> {
        let _ = statement;
        self.admit(manifest_json, requested)
    }

    /// Called when the package is complete and verified in the cache, before the fetch returns: records what the admission
    /// needs to remember (the high-water mark). The default records nothing.
    fn accepted(&self, admitted: &AdmittedManifest, statement: &[u8]) -> Result<(), FetchError> {
        let _ = (admitted, statement);
        Ok(())
    }
}

/// The pinned standard releases compiled into this build (`privoke_contracts::v3`).
#[derive(Debug, Clone, Copy, Default)]
pub struct StandardAdmission;

impl Admission for StandardAdmission {
    fn admit(&self, manifest_json: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError> {
        let manifest = v3::admitted_manifest(manifest_json, Some(requested)).map_err(|error| FetchError::Invalid(error.to_string()))?;
        let pin = v3::standard_pin(&manifest.model_id).ok_or_else(|| invalid("Model is not a pinned standard AU3 release"))?;
        let assets = assets_of(&manifest)?;
        Ok(AdmittedManifest { model_id: manifest.model_id, pin: pin.to_string(), assets })
    }
}

fn assets_of(manifest: &v3::Manifest) -> Result<BTreeMap<&'static str, String>, FetchError> {
    let evidence = manifest.evidence.clone().ok_or_else(|| invalid("Model package must contain exactly the declared assets"))?;
    Ok(BTreeMap::from([
        ("model.safetensors", manifest.blob.clone()),
        ("config.json", manifest.config.clone()),
        ("vocab.txt", manifest.vocab.clone()),
        ("evidence.json", evidence),
    ]))
}

/// Lineage and signature admission of a trained V3 version (stage V3-R4a), the client rule of
/// [`privoke_contracts::v3::admit_lineage`].
///
/// A manifest is accepted only when its publication statement verifies under a key of the compiled [`KeySet`], names this model
/// and this manifest, repeats the manifest's own `parent` and `original`, and carries a sequence above the persisted high-water
/// mark (or equal to it for the same manifest); and either the manifest satisfies the manifest contract with `original` equal to
/// the compiled tier pin, or it is the compiled pin itself (a signed rollback to the ORIGINAL). An unsigned manifest is accepted
/// only as the compiled pin and only while the model has no high-water mark.
///
/// The high-water mark is the highest accepted statement itself, kept at `<cache>/<model id>/high-water.statement` and verified
/// again under the compiled keys whenever it is read: a record that no longer verifies refuses every version of the model (fail
/// closed; remove the file to trust the pinned ORIGINAL again). It is written only after the package is complete in the cache,
/// and the version's statement is kept as `statement.json` beside its manifest so a restart re-verifies it.
#[derive(Debug, Clone)]
pub struct LineageAdmission {
    keys: KeySet,
    cache_root: PathBuf,
    pins: Option<BTreeMap<String, TierPin>>,
}

impl LineageAdmission {
    /// The product rule: the publication keys and tier pins compiled into this build.
    pub fn production(cache_root: &Path) -> Self {
        Self::new(publication::production_key_set(), cache_root)
    }

    /// The rule with an explicit key set and the compiled tier pins.
    pub fn new(keys: KeySet, cache_root: &Path) -> Self {
        Self { keys, cache_root: cache_root.to_path_buf(), pins: None }
    }

    /// Replace the compiled tier pins (a synthetic ORIGINAL in tests). Compiled only with the `test-helpers` feature.
    #[cfg(feature = "test-helpers")]
    #[must_use]
    pub fn with_pins(mut self, pins: BTreeMap<String, TierPin>) -> Self {
        self.pins = Some(pins);
        self
    }

    fn model_directory(&self, model_id: &str) -> Result<PathBuf, FetchError> {
        if !v3::TIERS.iter().any(|tier| model_id == format!("privoke-v3-{}", tier.name)) {
            return Err(invalid("Model is not a pinned standard AU3 release"));
        }
        private_directory(&self.cache_root.join(model_id))
    }

    /// The floor a new statement must clear. The mark when it verifies; when it is signed by a key this build no longer compiles
    /// (a rotation or a compromise), its sequence and manifest still count as the floor, and the next version must carry a
    /// statement under a current key above it; a mark that is malformed or whose signature is wrong fails closed. Without a
    /// mark, the floor is rebuilt from the highest cached `statement.json` that still verifies (a deleted mark reopens nothing
    /// while the cache holds a signed version; only an empty model cache is trust on first use).
    fn read_high_water(&self, model_id: &str) -> Result<Option<Statement>, FetchError> {
        let directory = self.model_directory(model_id)?;
        let path = directory.join(HIGH_WATER_FILE);
        if !exists_or_link(&path)? {
            return self.cached_floor(&directory, model_id);
        }
        let bytes = read_statement_file(&path)?;
        let statement = match publication::verify(&self.keys, &bytes) {
            Ok(statement) => statement,
            Err(PublicationError::UnknownKey) => publication::decode(&bytes).map(|(statement, _)| statement).map_err(|error| {
                FetchError::Invalid(format!("High-water record of {model_id} is malformed ({error}); clear the model cache of {model_id}"))
            })?,
            Err(error) => {
                return Err(FetchError::Invalid(format!(
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
    fn cached_floor(&self, directory: &Path, model_id: &str) -> Result<Option<Statement>, FetchError> {
        let mut floor: Option<Statement> = None;
        for entry in fs::read_dir(directory).map_err(io_at(directory))? {
            let entry = entry.map_err(io_at(directory))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let version = directory.join(&name);
            if !v3::is_sha_text(&name) || is_link(&version)? || !version.is_dir() {
                continue;
            }
            let Ok(bytes) = read_statement(&version) else { continue };
            let Ok(statement) = publication::verify(&self.keys, &bytes) else { continue };
            if statement.model_id == model_id
                && statement.manifest_sha == name
                && floor.as_ref().is_none_or(|best| statement.sequence > best.sequence)
            {
                floor = Some(statement);
            }
        }
        Ok(floor)
    }
}

impl LineageState for LineageAdmission {
    fn tier_pin(&self, model_id: &str) -> Option<TierPin> {
        match &self.pins {
            Some(pins) => pins.get(model_id).cloned(),
            None => v3::standard_tier_pin(model_id),
        }
    }

    fn high_water(&self, model_id: &str) -> Result<Option<Statement>, String> {
        self.read_high_water(model_id).map_err(|error| error.to_string())
    }
}

impl Admission for LineageAdmission {
    fn admit(&self, manifest_json: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError> {
        self.admit_published(manifest_json, &[], requested)
    }

    fn admit_published(&self, manifest_json: &[u8], statement: &[u8], requested: &str) -> Result<AdmittedManifest, FetchError> {
        let admitted = v3::admit_lineage(manifest_json, statement, Some(requested), &self.keys, self)?;
        let assets = assets_of(&admitted.manifest)?;
        Ok(AdmittedManifest { model_id: admitted.manifest.model_id, pin: admitted.manifest_sha, assets })
    }

    fn accepted(&self, admitted: &AdmittedManifest, statement: &[u8]) -> Result<(), FetchError> {
        if statement.is_empty() {
            return Ok(());
        }
        let verified = publication::verify(&self.keys, statement).map_err(|error| FetchError::Lineage(error.into()))?;
        if verified.model_id != admitted.model_id || verified.manifest_sha != admitted.pin {
            return Err(invalid("Accepted statement differs from the admitted manifest"));
        }
        // The mark may have moved since the admission: it is never lowered.
        if let Some(current) = self.read_high_water(&admitted.model_id)? {
            if verified.sequence < current.sequence {
                return Err(LineageError::Replay { seen: current.sequence, got: verified.sequence }.into());
            }
            if verified.sequence == current.sequence && verified.manifest_sha != current.manifest_sha {
                return Err(LineageError::SequenceConflict(verified.sequence).into());
            }
        }
        let directory = self.model_directory(&admitted.model_id)?;
        let path = directory.join(HIGH_WATER_FILE);
        if is_link(&path)? {
            return Err(invalid("High-water record must be a regular non-symlink file"));
        }
        let temporary = directory.join(format!(".high-water-{}", uuid::Uuid::new_v4().simple()));
        let outcome = (|| -> Result<(), FetchError> {
            write_new(&temporary, statement)?;
            fs::rename(&temporary, &path).map_err(io_at(&path))
        })();
        let _ = fs::remove_file(&temporary);
        outcome
    }
}

/// A package that is complete and verified in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedPackage {
    /// The model id.
    pub model_id: String,
    /// The manifest pin.
    pub pin: String,
    /// The cache directory holding the five files; read-only input for the worker.
    pub directory: PathBuf,
}

/// Settings of a fetch.
#[derive(Debug, Clone)]
pub struct FetchConfig {
    /// The `consumer_id` to send: the installation UUID or empty. The public listener refuses any other value.
    pub consumer_id: String,
    /// Deadline of each `GetModelPackage` call.
    pub rpc_timeout: Duration,
    /// Deadline of each asset download (`MODEL_PACKAGE_TIMEOUT_SECONDS`, default 120 s).
    pub download_timeout: Duration,
    /// The cache root.
    pub cache_root: PathBuf,
}

/// Fetches packages and remembers which ones it has already admitted in this process. One fetch runs at a time.
#[derive(Debug, Default)]
pub struct Fetcher {
    verified: Mutex<BTreeSet<(String, PathBuf, String)>>,
}

impl Fetcher {
    /// An empty fetcher.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make sure the package for `model_id` (`latest` or a model id) is in the cache and verified.
    ///
    /// `Ok(None)` means the server answered with a legacy, non-V3 model (an explicit legacy-only server override);
    /// those use the float parameter RPCs, which are not this supervisor's job.
    pub async fn fetch(
        &self,
        channel: Channel,
        target: &str,
        model_id: &str,
        admission: &dyn Admission,
        config: &FetchConfig,
    ) -> Result<Option<FetchedPackage>, FetchError> {
        let mut client = ModelStreamingServiceClient::new(channel);
        let request = ModelParametersRequest { consumer_id: config.consumer_id.clone(), model_id: model_id.to_string() };
        let package = rpc(&mut client, &request, config.rpc_timeout).await?;
        if package.architecture != v3::ARCHITECTURE {
            if model_id.starts_with("privoke-v3-") || !package.manifest_json.is_empty() || !package.assets.is_empty() {
                return Err(invalid("V3 request returned a different model family"));
            }
            return Ok(None);
        }
        let manifest = admission.admit_published(&package.manifest_json, &package.publication_statement, model_id)?;
        if package.model_id != manifest.model_id || package.manifest_sha256 != manifest.pin {
            return Err(invalid("Model package response identity differs from admitted manifest"));
        }
        let descriptors: BTreeMap<&str, _> = package.assets.iter().map(|asset| (asset.name.as_str(), asset)).collect();
        let declared: BTreeSet<&str> = ASSETS.iter().map(|(name, _)| *name).collect();
        if package.assets.len() != ASSETS.len() || descriptors.keys().copied().collect::<BTreeSet<_>>() != declared {
            return Err(invalid("Model package must contain exactly the declared assets"));
        }
        for (name, asset) in &descriptors {
            if manifest.assets.get(name) != Some(&asset.sha256) || asset.size_bytes == 0 || asset.size_bytes > v3::MAX_BLOB_BYTES {
                return Err(invalid("Model package asset declarations differ"));
            }
        }

        let mut verified = self.verified.lock().await;
        let directory = private_directory(&config.cache_root.join(&manifest.model_id).join(&manifest.pin))?;
        let identity = (target.to_string(), directory.clone(), manifest.pin.clone());
        let done = FetchedPackage { model_id: manifest.model_id.clone(), pin: manifest.pin.clone(), directory: directory.clone() };
        if verified.contains(&identity) {
            // Refresh only the small manifest; a reload revalidates the assets.
            if digest_file(&safe_file(&directory, "manifest.json")?)? != manifest.pin {
                return Err(invalid("Cached manifest was corrupted"));
            }
            store_statement(&directory, &package.publication_statement)?;
            admission.accepted(&manifest, &package.publication_statement)?;
            return Ok(Some(done));
        }
        // In the order the server declared the assets, as the Python fetch does: when one asset is refused, the same
        // assets are already in the cache.
        for asset in &package.assets {
            let name = asset.name.as_str();
            let destination = directory.join(name);
            if exists_or_link(&destination)? {
                if digest_file(&safe_file(&directory, name)?)? != asset.sha256 {
                    return Err(invalid("Existing model cache asset is corrupted"));
                }
                continue;
            }
            let temporary = directory.join(format!(".download-{}", uuid::Uuid::new_v4().simple()));
            let outcome =
                download(&mut client, config, &manifest, name, asset.sha256.as_str(), asset.size_bytes, &temporary, &destination).await;
            let _ = fs::remove_file(&temporary);
            outcome?;
        }
        let after = rpc(&mut client, &request, config.rpc_timeout).await?;
        if after != package {
            return Err(invalid("Model manifest changed while assets were downloaded"));
        }
        let manifest_path = directory.join("manifest.json");
        if exists_or_link(&manifest_path)? {
            if digest_file(&safe_file(&directory, "manifest.json")?)? != manifest.pin {
                return Err(invalid("Cached model manifest differs"));
            }
        } else {
            let temporary = directory.join(format!(".manifest-{}", uuid::Uuid::new_v4().simple()));
            let outcome = (|| -> Result<(), FetchError> {
                write_new(&temporary, &package.manifest_json)?;
                if exists_or_link(&manifest_path)? {
                    return Err(invalid("Model manifest appeared during cache admission"));
                }
                fs::rename(&temporary, &manifest_path).map_err(io_at(&manifest_path))
            })();
            let _ = fs::remove_file(&temporary);
            outcome?;
        }
        store_statement(&directory, &package.publication_statement)?;
        verify_package(&directory, model_id, admission)?;
        admission.accepted(&manifest, &package.publication_statement)?;
        verified.insert(identity);
        Ok(Some(done))
    }
}

async fn rpc(
    client: &mut ModelStreamingServiceClient<Channel>,
    request: &ModelParametersRequest,
    timeout: Duration,
) -> Result<ModelPackageResponse, FetchError> {
    let mut call = tonic::Request::new(request.clone());
    call.set_timeout(timeout);
    let answer = tokio::time::timeout(timeout, client.get_model_package(call))
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("GetModelPackage timed out"))??;
    Ok(answer.into_inner())
}

#[allow(clippy::too_many_arguments)]
async fn download(
    client: &mut ModelStreamingServiceClient<Channel>,
    config: &FetchConfig,
    manifest: &AdmittedManifest,
    name: &str,
    expected_sha: &str,
    expected_size: u64,
    temporary: &Path,
    destination: &Path,
) -> Result<(), FetchError> {
    let mut call = tonic::Request::new(ModelAssetRequest {
        consumer_id: config.consumer_id.clone(),
        model_id: manifest.model_id.clone(),
        manifest_sha256: manifest.pin.clone(),
        asset_name: name.to_string(),
    });
    call.set_timeout(config.download_timeout);
    let work = async {
        let mut stream = client.stream_model_asset(call).await?.into_inner();
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(temporary).map_err(io_at(temporary))?;
        let mut offset: u64 = 0;
        let mut digest = Sha256::new();
        while let Some(chunk) = stream.message().await? {
            let length = chunk.data.len() as u64;
            if chunk.model_id != manifest.model_id
                || chunk.manifest_sha256 != manifest.pin
                || chunk.asset_name != name
                || chunk.sha256 != expected_sha
                || chunk.offset != offset
                || chunk.total_bytes != expected_size
                || length == 0
                || length > v3::CHUNK_BYTES as u64
                || offset + length > expected_size
            {
                return Err(invalid("Model asset stream changed identity, order or bounds"));
            }
            file.write_all(&chunk.data).map_err(io_at(temporary))?;
            digest.update(&chunk.data);
            offset += length;
        }
        if offset != expected_size || hex(&digest.finalize()) != expected_sha {
            return Err(invalid("Model asset stream is incomplete or corrupted"));
        }
        file.flush().map_err(io_at(temporary))?;
        file.sync_all().map_err(io_at(temporary))?;
        Ok::<(), FetchError>(())
    };
    tokio::time::timeout(config.download_timeout, work)
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("StreamModelAsset timed out"))??;
    if exists_or_link(destination)? {
        return Err(invalid("Model cache destination appeared during download"));
    }
    fs::rename(temporary, destination).map_err(io_at(destination))
}

/// `verify_package`: the manifest on disk is admitted and every asset's size and hash match it.
pub fn verify_package(directory: &Path, model_id: &str, admission: &dyn Admission) -> Result<AdmittedManifest, FetchError> {
    let bytes = fs::read(safe_file(directory, "manifest.json")?).map_err(io_at(directory))?;
    let statement = read_statement(directory)?;
    let manifest = admission.admit_published(&bytes, &statement, model_id)?;
    for (name, _) in ASSETS {
        let path = safe_file(directory, name)?;
        let size = fs::metadata(&path).map_err(io_at(&path))?.len();
        if size == 0 || size > v3::MAX_BLOB_BYTES || manifest.assets.get(name) != Some(&digest_file(&path)?) {
            return Err(invalid("Model package asset size/hash differs from pinned manifest"));
        }
    }
    Ok(manifest)
}

/// The statement kept beside a cached manifest; empty when there is none (an unsigned ORIGINAL).
fn read_statement(directory: &Path) -> Result<Vec<u8>, FetchError> {
    if !exists_or_link(&directory.join(STATEMENT_FILE))? {
        return Ok(Vec::new());
    }
    read_statement_file(&safe_file(directory, STATEMENT_FILE)?)
}

/// A regular, non-link, size-bounded statement file.
fn read_statement_file(path: &Path) -> Result<Vec<u8>, FetchError> {
    if is_link(path)? || !path.is_file() {
        return Err(invalid("Publication statement must be a regular non-symlink file"));
    }
    if fs::metadata(path).map_err(io_at(path))?.len() > publication::MAX_STATEMENT_BYTES as u64 {
        return Err(invalid("Publication statement is too large"));
    }
    fs::read(path).map_err(io_at(path))
}

/// Keep the verified statement of the fetched version beside its manifest, replacing an older one (a rollback to a version the
/// cache already holds carries a newer statement). Nothing is written for an unsigned ORIGINAL.
fn store_statement(directory: &Path, statement: &[u8]) -> Result<(), FetchError> {
    if statement.is_empty() || read_statement(directory)? == statement {
        return Ok(());
    }
    let path = directory.join(STATEMENT_FILE);
    let temporary = directory.join(format!(".statement-{}", uuid::Uuid::new_v4().simple()));
    let outcome = (|| -> Result<(), FetchError> {
        write_new(&temporary, statement)?;
        fs::rename(&temporary, &path).map_err(io_at(&path))
    })();
    let _ = fs::remove_file(&temporary);
    outcome
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SHA-256 of a file, streamed.
pub fn digest_file(path: &Path) -> Result<String, FetchError> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(io_at(path))?;
    let mut digest = Sha256::new();
    let mut block = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut block).map_err(io_at(path))?;
        if read == 0 {
            return Ok(hex(&digest.finalize()));
        }
        digest.update(&block[..read]);
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), FetchError> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(io_at(path))?;
    file.write_all(bytes).map_err(io_at(path))?;
    file.flush().map_err(io_at(path))?;
    file.sync_all().map_err(io_at(path))
}

/// Symlinks and Windows junctions and reparse points, including broken ones.
pub fn is_link(path: &Path) -> Result<bool, FetchError> {
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
        Err(source) => Err(FetchError::Io { path: path.to_path_buf(), source }),
    }
}

fn exists_or_link(path: &Path) -> Result<bool, FetchError> {
    Ok(path.exists() || is_link(path)?)
}

/// A user-private directory beneath no link.
pub fn private_directory(path: &Path) -> Result<PathBuf, FetchError> {
    let path = std::path::absolute(path).map_err(io_at(path))?;
    for parent in path.ancestors() {
        if is_link(parent)? {
            return Err(invalid("Model cache must not traverse symlinks"));
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path).map_err(io_at(&path))?;
    Ok(path)
}

/// Only the fixed package names, as regular non-link files beneath a directory that has no link in its path.
pub fn safe_file(root: &Path, name: &str) -> Result<PathBuf, FetchError> {
    if name != "manifest.json" && name != STATEMENT_FILE && !ASSETS.iter().any(|(asset, _)| *asset == name) {
        return Err(invalid("Unrecognized model package asset"));
    }
    let root = std::path::absolute(root).map_err(io_at(root))?;
    for parent in root.ancestors() {
        if is_link(parent)? {
            return Err(invalid("Model package directories must not be symlinks"));
        }
    }
    let path = root.join(name);
    if is_link(&path)? || !path.is_file() {
        return Err(invalid("Model asset must be a regular non-symlink file"));
    }
    Ok(path)
}
