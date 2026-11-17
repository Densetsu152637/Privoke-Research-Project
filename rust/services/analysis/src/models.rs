//! The model cache: models arrive over mutual TLS from model-streaming, are checked, and are written to a cache
//! directory that the worker reads and never writes.
//!
//! The worker has no network, so this service is the only party that talks to model-streaming. It presents its own
//! `runtime` service certificate to the internal listener (`GetModelParameters`). It holds no publisher credential.
//!
//! A cached model is the serialized `ModelParametersResponse` that model-streaming sent, stored as
//! `<model_id>.snapshot.pb` and replaced atomically. The worker shim builds exactly the snapshot the streaming client
//! would have built from it, so analysis and gradient responses do not depend on how the model reached the worker.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use privoke_contracts::proto::v1::ModelParametersRequest;
use privoke_contracts::proto::v1::ModelParametersResponse;
use privoke_contracts::proto::v1::model_streaming_service_client::ModelStreamingServiceClient;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use prost::Message as _;
use sha2::{Digest, Sha256};
use tonic::transport::Channel;

use crate::config::{ModelSource, is_model_id};
use crate::util::{hex, log};

/// Largest number of float values a legacy artifact may carry (`MAX_PARAMETER_VALUES` of the Python loader).
pub const MAX_PARAMETER_VALUES: usize = 65_536;
/// The consumer label sent to model-streaming. On the internal listener it is a log label only.
pub const CONSUMER_ID: &str = "analysis-service";
/// File suffix of a cached snapshot.
pub const SNAPSHOT_SUFFIX: &str = ".snapshot.pb";

/// Why a model could not be made available.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// model-streaming does not know the model.
    #[error("model {0:?} is not known to model-streaming")]
    NotFound(String),
    /// model-streaming serves the model another way (a V3 package), which this service does not fetch.
    #[error("model {0:?} is not a legacy float artifact; V3 packages are not served by the quarantined service")]
    Unsupported(String),
    /// model-streaming answered with something that fails a check (shape, finite values, identity, pin).
    #[error("model {id:?} was refused: {reason}")]
    Refused {
        /// The model.
        id: String,
        /// The failed check.
        reason: String,
    },
    /// model-streaming could not be reached and the cache holds nothing.
    #[error("model {id:?} is unavailable: {reason}")]
    Unavailable {
        /// The model.
        id: String,
        /// The cause.
        reason: String,
    },
}

#[derive(Debug, Default)]
struct Entry {
    checked: Option<Instant>,
    digest: Option<[u8; 32]>,
}

/// The cache and its connection to model-streaming.
#[derive(Debug)]
pub struct ModelCache {
    dir: PathBuf,
    source: ModelSource,
    ttl: Duration,
    pins: std::collections::BTreeMap<String, String>,
    default_id: String,
    channel: tokio::sync::Mutex<Option<Channel>>,
    entries: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Entry>>>>,
}

/// The path of a model's cached snapshot.
pub fn snapshot_path(dir: &Path, model_id: &str) -> PathBuf {
    dir.join(format!("{model_id}{SNAPSHOT_SUFFIX}"))
}

/// The checks the streaming client applies to a snapshot, plus the identity and pin checks of this service.
pub fn validate(response: &ModelParametersResponse, requested: &str, pin: Option<&str>) -> Result<(), String> {
    if response.model_id != requested {
        return Err(format!("model-streaming returned {:?} for {requested:?}", response.model_id));
    }
    if response.version.is_empty() || response.version.len() > 128 {
        return Err("the snapshot has no valid version".into());
    }
    if response.generated_at_unix <= 0 {
        return Err("the snapshot has no valid timestamp".into());
    }
    if response.parameters.is_empty() {
        return Err("the snapshot has no tensors".into());
    }
    let mut total = 0usize;
    let mut previous: Option<&str> = None;
    for parameter in &response.parameters {
        if parameter.name.is_empty() || parameter.name.len() > 256 {
            return Err("a tensor name is empty or too long".into());
        }
        if previous.is_some_and(|name| name >= parameter.name.as_str()) {
            return Err("tensors are not in strictly increasing name order".into());
        }
        previous = Some(&parameter.name);
        if parameter.shape.is_empty() || parameter.shape.contains(&0) {
            return Err(format!("tensor {:?} has an invalid shape", parameter.name));
        }
        let expected = parameter.shape.iter().try_fold(1usize, |product, size| product.checked_mul(*size as usize));
        if expected != Some(parameter.values.len()) {
            return Err(format!("tensor {:?} shape does not match its values", parameter.name));
        }
        if !parameter.values.iter().all(|value| value.is_finite()) {
            return Err(format!("tensor {:?} has non-finite values", parameter.name));
        }
        total += parameter.values.len();
    }
    if total > MAX_PARAMETER_VALUES {
        return Err(format!("the snapshot has {total} values, above the {MAX_PARAMETER_VALUES} limit"));
    }
    let checksum = response.metadata.get("artifact_checksum").map(String::as_str).unwrap_or_default();
    if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("the snapshot carries no artifact_checksum".into());
    }
    if let Some(pin) = pin
        && !checksum.eq_ignore_ascii_case(pin)
    {
        return Err("the artifact_checksum differs from the configured pin".into());
    }
    Ok(())
}

impl ModelCache {
    /// A cache in `dir` that fetches from `source` and trusts a fetch for `ttl`.
    pub fn new(
        dir: impl Into<PathBuf>,
        source: ModelSource,
        ttl: Duration,
        pins: std::collections::BTreeMap<String, String>,
        default_id: impl Into<String>,
    ) -> Self {
        Self {
            dir: dir.into(),
            source,
            ttl,
            pins,
            default_id: default_id.into(),
            channel: tokio::sync::Mutex::new(None),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The cache directory the worker is given as its model root.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The id a request means: the empty id and the alias `latest` are the configured default.
    pub fn resolve<'a>(&'a self, requested: &'a str) -> &'a str {
        if requested.is_empty() || requested == "latest" { &self.default_id } else { requested }
    }

    async fn client(&self) -> Result<ModelStreamingServiceClient<Channel>, String> {
        let mut slot = self.channel.lock().await;
        if let Some(channel) = slot.as_ref() {
            return Ok(ModelStreamingServiceClient::new(channel.clone()));
        }
        let spec = ClientTlsConfig {
            server_ca: self.source.server_ca.clone(),
            identity: Some((self.source.client_cert.clone(), self.source.client_key.clone())),
            server_name: self.source.server_name.clone(),
        };
        let channel = tokio::time::timeout(Duration::from_secs(10), connect(&self.source.target, &spec))
            .await
            .map_err(|_| "connecting to model-streaming timed out".to_string())?
            .map_err(|error| error.to_string())?;
        *slot = Some(channel.clone());
        Ok(ModelStreamingServiceClient::new(channel))
    }

    async fn drop_channel(&self) {
        *self.channel.lock().await = None;
    }

    /// Makes sure a current, checked snapshot of the model a request names is in the cache, and returns its id.
    ///
    /// A fetch is skipped while the last one is younger than the ttl. If model-streaming cannot be reached but an
    /// earlier snapshot is cached, the cached one stays in use and the failure is logged.
    pub async fn ensure(&self, requested: &str) -> Result<String, SyncError> {
        let id = self.resolve(requested).to_string();
        if !is_model_id(&id) {
            return Err(SyncError::Refused { id, reason: "not a valid model id".into() });
        }
        let entry = {
            let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            entries.entry(id.clone()).or_default().clone()
        };
        // One fetch per model at a time; the others wait and then find it fresh.
        let mut entry = entry.lock().await;
        if entry.checked.is_some_and(|at| at.elapsed() < self.ttl) {
            return Ok(id);
        }
        let outcome = self.fetch(&id).await;
        match outcome {
            Ok(response) => {
                if let Err(reason) = validate(&response, &id, self.pins.get(&id).map(String::as_str)) {
                    log(format_args!("model {id:?} refused: {reason}"));
                    return Err(SyncError::Refused { id, reason });
                }
                let bytes = response.encode_to_vec();
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                if entry.digest != Some(digest) {
                    let path = snapshot_path(&self.dir, &id);
                    let identity = (id.clone(), response.version.clone());
                    tokio::task::spawn_blocking(move || write_atomic(&path, &bytes))
                        .await
                        .map_err(|error| SyncError::Unavailable { id: id.clone(), reason: error.to_string() })?
                        .map_err(|error| SyncError::Unavailable { id: id.clone(), reason: format!("cannot write the cache: {error}") })?;
                    entry.digest = Some(digest);
                    log(format_args!("model cache updated model={:?} version={:?} sha256={}", identity.0, identity.1, hex(&digest)));
                }
                entry.checked = Some(Instant::now());
                Ok(id)
            }
            Err(error) => {
                if matches!(error, SyncError::NotFound(_) | SyncError::Unsupported(_)) {
                    return Err(error);
                }
                if snapshot_path(&self.dir, &id).is_file() {
                    log(format_args!("model-streaming unavailable for {id:?}, serving the cached snapshot: {error}"));
                    entry.checked = Some(Instant::now());
                    return Ok(id);
                }
                Err(error)
            }
        }
    }

    async fn fetch(&self, id: &str) -> Result<ModelParametersResponse, SyncError> {
        let unavailable = |reason: String| SyncError::Unavailable { id: id.to_string(), reason };
        let mut client = self.client().await.map_err(unavailable)?;
        let request = ModelParametersRequest { consumer_id: CONSUMER_ID.to_string(), model_id: id.to_string() };
        match tokio::time::timeout(Duration::from_secs(30), client.get_model_parameters(request)).await {
            Err(_) => {
                self.drop_channel().await;
                Err(unavailable("model-streaming did not answer in time".into()))
            }
            Ok(Ok(response)) => Ok(response.into_inner()),
            Ok(Err(status)) => match status.code() {
                tonic::Code::NotFound => Err(SyncError::NotFound(id.to_string())),
                tonic::Code::FailedPrecondition => Err(SyncError::Unsupported(id.to_string())),
                tonic::Code::InvalidArgument => Err(SyncError::Refused { id: id.to_string(), reason: status.message().to_string() }),
                code => {
                    self.drop_channel().await;
                    Err(unavailable(format!("{code:?}: {}", status.message())))
                }
            },
        }
    }

    /// Fetches the start-up models, retrying until `within` runs out, because model-streaming may still be starting.
    pub async fn warm(&self, ids: &[String], within: Duration) -> Result<(), SyncError> {
        let deadline = Instant::now() + within;
        for requested in ids {
            let mut delay = Duration::from_millis(250);
            loop {
                match self.ensure(requested).await {
                    Ok(_) => break,
                    Err(error @ SyncError::Unavailable { .. }) if Instant::now() < deadline => {
                        log(format_args!("waiting for model-streaming: {error}"));
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }
}

/// Writes `bytes` to a temporary file in the same directory and renames it over `path`, so a reader sees the old file
/// or the new one and never a partial write. The rename is retried briefly: Windows refuses it while a reader holds the
/// old file open.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().ok_or_else(|| std::io::Error::other("cache path has no directory"))?;
    std::fs::create_dir_all(directory)?;
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let temporary = directory.join(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&temporary, bytes)?;
    let mut last = None;
    for _ in 0..50 {
        match std::fs::rename(&temporary, path) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last = Some(error);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    let _ = std::fs::remove_file(&temporary);
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use privoke_contracts::proto::v1::Parameter;

    use super::*;

    fn response() -> ModelParametersResponse {
        ModelParametersResponse {
            model_id: "privoke-test".into(),
            version: "v1".into(),
            generated_at_unix: 5,
            parameters: vec![
                Parameter { name: "a".into(), values: vec![1.0, 2.0, 3.0, 4.0], shape: vec![2, 2] },
                Parameter { name: "b".into(), values: vec![0.5], shape: vec![1] },
            ],
            metadata: BTreeMap::from([("artifact_checksum".to_string(), "ab".repeat(32))]),
        }
    }

    #[test]
    fn a_well_formed_snapshot_passes() {
        assert_eq!(validate(&response(), "privoke-test", None), Ok(()));
    }

    #[test]
    fn identity_shape_finiteness_order_and_pin_are_checked() {
        let mut other = response();
        other.model_id = "other".into();
        assert!(validate(&other, "privoke-test", None).is_err());
        let mut bad = response();
        bad.parameters[0].shape = vec![3, 2];
        assert!(validate(&bad, "privoke-test", None).is_err());
        let mut bad = response();
        bad.parameters[1].values = vec![f32::NAN];
        assert!(validate(&bad, "privoke-test", None).is_err());
        let mut bad = response();
        bad.parameters.reverse();
        assert!(validate(&bad, "privoke-test", None).is_err());
        let mut bad = response();
        bad.metadata.clear();
        assert!(validate(&bad, "privoke-test", None).is_err());
        assert!(validate(&response(), "privoke-test", Some(&"cd".repeat(32))).is_err());
        assert_eq!(validate(&response(), "privoke-test", Some(&"AB".repeat(32))), Ok(()));
    }

    #[test]
    fn the_default_model_answers_the_empty_id_and_latest() {
        let source = ModelSource {
            target: "x:1".into(),
            server_ca: "ca".into(),
            client_cert: "c".into(),
            client_key: "k".into(),
            server_name: "x".into(),
        };
        let cache = ModelCache::new("dir", source, Duration::from_secs(1), BTreeMap::new(), "privoke-balanced");
        assert_eq!(cache.resolve(""), "privoke-balanced");
        assert_eq!(cache.resolve("latest"), "privoke-balanced");
        assert_eq!(cache.resolve("privoke-quality"), "privoke-quality");
    }

    #[test]
    fn writes_replace_the_file_in_one_step() {
        let directory = tempfile::tempdir().unwrap();
        let path = snapshot_path(directory.path(), "m");
        write_atomic(&path, b"one").unwrap();
        write_atomic(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
