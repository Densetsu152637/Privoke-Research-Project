//! The standard V3 (pinned binary package) release store. Port of `standard_v3.go`.
//!
//! The store is a read-only directory `<root>/<model-id>/{manifest.json,model.safetensors,config.json,vocab.txt,
//! evidence.json}`. Every manifest is pinned by SHA-256, every asset by the digest the manifest names, and every path
//! is refused if it crosses a symlink. Assets are hashed once at admission and again before they are streamed.
//!
//! The per-directory readers ([`open_file_in`], [`package_in`], [`stream_in`]) are shared with
//! [`crate::published`], which serves trained versions from the published tree with the same checks.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use privoke_contracts::json::Value;
use privoke_contracts::proto::v1::{ModelAssetChunk, ModelPackageAsset, ModelPackageResponse};
use privoke_contracts::v3;
use same_file::Handle;
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::error::{Error, Result};
use crate::fail;
use crate::jsonx;

/// The only admitted V3 architecture.
pub const V3_ARCHITECTURE: &str = v3::ARCHITECTURE;
/// Largest asset.
pub const MAX_MODEL_ASSET_BYTES: u64 = 80 * 1024 * 1024;
/// Bytes per streamed asset chunk.
pub const MODEL_ASSET_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

/// The three standard model IDs.
pub const STANDARD_IDS: [&str; 3] = ["privoke-v3-efficient", "privoke-v3-balanced", "privoke-v3-quality"];

/// The asset names and the manifest key that holds each one's digest.
pub const ASSET_KEYS: [(&str, &str); 4] =
    [("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab"), ("evidence.json", "evidence")];

/// `isStandardV3`.
pub fn is_standard_v3(id: &str) -> bool {
    STANDARD_IDS.contains(&id)
}

/// The pinned manifest digest of a standard model.
pub fn standard_pin(id: &str) -> Option<&'static str> {
    v3::standard_pin(id)
}

/// Whether `name` is one of the four streamable asset names.
pub fn is_allowlisted_asset(name: &str) -> bool {
    ASSET_KEYS.iter().any(|(asset, _)| *asset == name)
}

/// What identifies an opened file: its identity on disk, size and modification time.
#[derive(Debug)]
pub struct FileInfo {
    handle: Handle,
    size: u64,
    modified: SystemTime,
}

impl FileInfo {
    fn of(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self { handle: Handle::from_file(file.try_clone()?)?, size: metadata.len(), modified: metadata.modified()? })
    }

    /// Whether `other` is the same file, unchanged: same identity on disk, size and modification time.
    pub fn same_as(&self, other: &Self) -> bool {
        self.handle == other.handle && self.size == other.size && self.modified == other.modified
    }
}

/// An admitted release store.
#[derive(Debug)]
pub struct StandardReleases {
    root: PathBuf,
    pins: BTreeMap<String, String>,
    identities: BTreeMap<String, FileInfo>,
}

pub(crate) fn unsafe_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).map_or(true, |info| !info.is_dir() || info.file_type().is_symlink())
}

/// The compiled manifest pins of the three standard models.
fn compiled_pins() -> BTreeMap<String, String> {
    STANDARD_IDS.iter().filter_map(|id| standard_pin(id).map(|pin| ((*id).to_string(), pin.to_string()))).collect()
}

/// `directory` as an absolute path, refusing a symlink on it or on any ancestor and a missing or non-directory root.
pub(crate) fn real_directory(directory: &Path, missing: &str) -> Result<PathBuf> {
    let absolute = std::path::absolute(directory).map_err(|error| Error(error.to_string()))?;
    for current in absolute.ancestors() {
        if unsafe_directory(current) {
            fail!("standard release path must not traverse symlinks");
        }
    }
    if unsafe_directory(directory) {
        fail!("{missing}");
    }
    Ok(absolute)
}

/// `openAsset` for one directory: a regular, non-symlink file of 1 to 80 MiB, named `manifest.json` or an allowlisted asset.
pub(crate) fn open_file_in(directory: &Path, name: &str) -> Result<(File, FileInfo)> {
    if name != "manifest.json" && !is_allowlisted_asset(name) {
        fail!("unknown model asset");
    }
    if unsafe_directory(directory) {
        fail!("unsafe model directory");
    }
    let path = directory.join(name);
    let info = std::fs::symlink_metadata(&path).map_err(|_| Error("unsafe or oversized model asset".into()))?;
    if !info.is_file() || info.len() == 0 || info.len() > MAX_MODEL_ASSET_BYTES {
        fail!("unsafe or oversized model asset");
    }
    let file = File::open(&path)?;
    let actual = FileInfo::of(&file)?;
    let on_disk = Handle::from_path(&path).map_err(|_| Error("model asset changed while opening".into()))?;
    if actual.handle != on_disk {
        fail!("model asset changed while opening");
    }
    Ok((file, actual))
}

/// `manifest` for one directory: the manifest must hash to `expected_sha` and describe model `id`; the asset table comes from
/// the digests it names and the sizes on disk.
pub(crate) fn package_in(directory: &Path, id: &str, expected_sha: &str) -> Result<ModelPackageResponse> {
    let (file, _) = open_file_in(directory, "manifest.json")?;
    let mut raw = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        fail!("invalid model manifest size");
    }
    let pin = privoke_contracts::digest::sha256_hex(&raw);
    if pin != expected_sha {
        fail!("standard V3 manifest pin mismatch");
    }
    let text = std::str::from_utf8(&raw).map_err(|_| Error("standard V3 manifest is not UTF-8".into()))?;
    let manifest = jsonx::object_of(text)?;
    let field = |key: &str| -> String {
        match manifest.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => String::new(),
        }
    };
    if field("model_id") != id || field("architecture") != V3_ARCHITECTURE {
        fail!("standard V3 manifest identity mismatch");
    }
    let mut package = ModelPackageResponse {
        model_id: id.to_string(),
        architecture: V3_ARCHITECTURE.to_string(),
        manifest_sha256: pin,
        manifest_json: raw,
        assets: Vec::new(),
        publication_statement: Vec::new(),
    };
    let mut names: Vec<(&str, &str)> = ASSET_KEYS.to_vec();
    names.sort_unstable();
    for (name, key) in names {
        let (_, info) = open_file_in(directory, name)?;
        let expected = field(key);
        if expected.len() != 64 {
            fail!("invalid asset digest");
        }
        package.assets.push(ModelPackageAsset { name: name.to_string(), sha256: expected, size_bytes: info.size });
    }
    Ok(package)
}

/// `StreamModelAsset` for one directory after request validation: re-hash the asset, then send it in 1 MiB chunks, then
/// verify that neither the asset nor the manifest changed. `send` returns `false` when the client has gone away.
pub(crate) fn stream_in(
    directory: &Path,
    id: &str,
    manifest_sha256: &str,
    asset_name: &str,
    mut send: impl FnMut(ModelAssetChunk) -> bool,
) -> std::result::Result<(), Status> {
    let package = package_in(directory, id, manifest_sha256).map_err(|_| Status::unavailable("model manifest changed"))?;
    let Some(selected) = package.assets.iter().find(|asset| asset.name == asset_name) else {
        return Err(Status::invalid_argument("asset is not allowlisted"));
    };
    let (mut file, info) = open_file_in(directory, asset_name).map_err(|_| Status::unavailable("model asset unavailable"))?;
    match bounded_file_hash(&mut file) {
        Ok(digest) if digest == selected.sha256 => {}
        _ => return Err(Status::data_loss("model asset hash mismatch")),
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| Status::internal(error.to_string()))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; MODEL_ASSET_CHUNK_BYTES];
    let mut offset = 0u64;
    loop {
        let filled = read_full(&mut file, &mut buffer).map_err(|error| Status::internal(error.to_string()))?;
        if filled == 0 {
            break;
        }
        hash.update(&buffer[..filled]);
        if offset + filled as u64 > selected.size_bytes {
            return Err(Status::data_loss("model asset grew while streaming"));
        }
        let chunk = ModelAssetChunk {
            model_id: id.to_string(),
            manifest_sha256: manifest_sha256.to_string(),
            asset_name: asset_name.to_string(),
            sha256: selected.sha256.clone(),
            offset,
            total_bytes: selected.size_bytes,
            data: buffer[..filled].to_vec(),
        };
        if !send(chunk) {
            return Err(Status::cancelled("client went away"));
        }
        offset += filled as u64;
        if filled < buffer.len() {
            break;
        }
    }
    let changed = FileInfo::of(&file).map_or(true, |after| !after.same_as(&info));
    if changed || offset != selected.size_bytes || crate::util::hex(&hash.finalize()) != selected.sha256 {
        return Err(Status::data_loss("model asset changed while streaming"));
    }
    if package_in(directory, id, manifest_sha256).is_err() {
        return Err(Status::data_loss("model manifest changed while streaming"));
    }
    Ok(())
}

impl StandardReleases {
    /// `openStandardReleases`: refuse any symlink on the path, then verify every manifest pin and every asset digest.
    pub fn open(directory: &Path) -> Result<Self> {
        Self::open_with_pins(directory, compiled_pins())
    }

    /// [`open`](Self::open) against explicit manifest pins (one per standard model) instead of the compiled ones. The service
    /// uses the compiled pins; this exists so that tests can serve small packages whose pins they know.
    pub fn open_with_pins(directory: &Path, pins: BTreeMap<String, String>) -> Result<Self> {
        let absolute =
            real_directory(directory, "standard V3 release directory is missing or unsafe; run models/prepare_standard_releases.py")?;
        if STANDARD_IDS.iter().any(|id| pins.get(*id).is_none_or(|pin| pin.len() != 64)) {
            fail!("standard V3 manifest pins must name every standard model");
        }
        let mut releases = Self { root: absolute, pins, identities: BTreeMap::new() };
        for id in STANDARD_IDS {
            let package = releases.manifest(id)?;
            for asset in &package.assets {
                let (mut file, before) = releases.open_asset(id, &asset.name)?;
                match bounded_file_hash(&mut file) {
                    Ok(hash) if hash == asset.sha256 => {}
                    _ => fail!("standard V3 asset hash mismatch: {id}/{}", asset.name),
                }
                releases.identities.insert(format!("{id}/{}", asset.name), before);
            }
        }
        Ok(releases)
    }

    /// The manifest pin of a standard model in this store.
    pub fn pin(&self, id: &str) -> Option<&str> {
        self.pins.get(id).map(String::as_str)
    }

    /// A store over `root` that has not been admitted (test support for the unit tests that call `manifest` and
    /// `open_asset` directly, as the Go tests build `standardReleases{root: root}`).
    pub fn unadmitted(root: &Path) -> Self {
        Self { root: root.to_path_buf(), pins: compiled_pins(), identities: BTreeMap::new() }
    }

    /// `openAsset`: a regular, non-symlink file of 1 to 80 MiB inside a real model directory.
    pub fn open_asset(&self, id: &str, name: &str) -> Result<(File, FileInfo)> {
        if !is_standard_v3(id) {
            fail!("unknown standard model");
        }
        open_file_in(&self.root.join(id), name)
    }

    /// `manifest`: the pinned manifest and the asset table it describes.
    pub fn manifest(&self, id: &str) -> Result<ModelPackageResponse> {
        let Some(pin) = self.pins.get(id).filter(|_| is_standard_v3(id)) else { fail!("unknown standard model") };
        package_in(&self.root.join(id), id, pin)
    }

    /// `validate`: every manifest still pins, and no admitted asset has been replaced or modified.
    pub fn validate(&self) -> Result<()> {
        for id in STANDARD_IDS {
            let package = self.manifest(id)?;
            for asset in &package.assets {
                let (_, info) = self.open_asset(id, &asset.name)?;
                let Some(before) = self.identities.get(&format!("{id}/{}", asset.name)) else {
                    fail!("standard asset changed after admission")
                };
                if !before.same_as(&info) {
                    fail!("standard asset changed after admission");
                }
            }
        }
        Ok(())
    }

    /// `StreamModelAsset` after request validation: re-hash the asset, then send it in 1 MiB chunks, then verify that
    /// neither the asset nor the manifest changed. `send` returns `false` when the client has gone away.
    pub fn stream_asset(
        &self,
        id: &str,
        manifest_sha256: &str,
        asset_name: &str,
        send: impl FnMut(ModelAssetChunk) -> bool,
    ) -> std::result::Result<(), Status> {
        if self.pin(id) != Some(manifest_sha256) {
            return Err(Status::invalid_argument("explicit standard model and manifest pin required"));
        }
        stream_in(&self.root.join(id), id, manifest_sha256, asset_name, send)
    }
}

/// Fill `buffer` from `file`, returning fewer bytes only at end of file.
fn read_full(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

/// `boundedFileHash`: SHA-256 of 1 byte to 80 MiB.
pub fn bounded_file_hash(file: &mut File) -> std::result::Result<String, Error> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > MAX_MODEL_ASSET_BYTES {
            fail!("invalid model asset bytes");
        }
        hash.update(&buffer[..read]);
    }
    if total == 0 {
        fail!("invalid model asset bytes");
    }
    Ok(crate::util::hex(&hash.finalize()))
}
