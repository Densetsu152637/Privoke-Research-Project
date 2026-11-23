//! Process configuration from the environment, with the Go service's names and defaults.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::artifact::validate_configured_identifier;
use crate::error::{Error, Result};
use crate::fail;
use crate::pretrained;

/// Default internal listener port (Go's `MODEL_STREAMING_PORT`).
pub const DEFAULT_INTERNAL_PORT: u16 = 50051;
/// Default public listener port.
pub const DEFAULT_PUBLIC_PORT: u16 = 50443;
/// Default latest model.
pub const DEFAULT_LATEST_MODEL_ID: &str = "privoke-v3-balanced";
/// Default legacy artifact directory.
pub const DEFAULT_ARTIFACT_DIR: &str = "/models";
/// Default standard release store.
pub const DEFAULT_RELEASE_DIR: &str = "/model-releases";

/// What the environment configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Internal listener port: `GetModelParameters` and `Health` for service principals (`MODEL_STREAMING_PORT`).
    pub internal_port: u16,
    /// Public listener port: the consumer RPCs (`MODEL_STREAMING_PUBLIC_PORT`).
    pub public_port: u16,
    /// Interface both listeners bind (`MODEL_STREAMING_BIND`).
    pub bind: IpAddr,
    /// The model that `latest` resolves to (`MODEL_LATEST_ID`).
    pub latest_model_id: String,
    /// Directory of legacy JSON artifacts (`MODEL_ARTIFACT_DIR`).
    pub artifact_dir: PathBuf,
    /// Directory of standard V3 releases (`MODEL_RELEASE_DIR`).
    pub release_dir: PathBuf,
    /// The published V3 root of param-update (`V3_PUBLISH_ROOT`); set together with `v3_store`, or not at all.
    pub publish_root: Option<PathBuf>,
    /// The V3 checkpoint store directory whose `catalog.sqlite` is the authority for published versions (`V3_STORE`).
    pub v3_store: Option<PathBuf>,
}

fn env_string(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: &str) -> String {
    get(key).filter(|value| !value.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn env_port(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: u16) -> Result<u16> {
    let Some(value) = get(key).filter(|value| !value.is_empty()) else { return Ok(fallback) };
    let parsed: i64 = value.parse().map_err(|error| Error(format!("{key} must be an integer: {error}")))?;
    if !(1..=65535).contains(&parsed) {
        fail!("{key} must be between 1 and 65535");
    }
    Ok(parsed as u16)
}

impl ServiceConfig {
    /// `loadServerConfig`, reading variables through `get` so tests do not touch the process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let internal_port = env_port(&get, "MODEL_STREAMING_PORT", DEFAULT_INTERNAL_PORT)?;
        let public_port = env_port(&get, "MODEL_STREAMING_PUBLIC_PORT", DEFAULT_PUBLIC_PORT)?;
        let bind: IpAddr = env_string(&get, "MODEL_STREAMING_BIND", "0.0.0.0")
            .parse()
            .map_err(|error| Error(format!("MODEL_STREAMING_BIND must be an IP address: {error}")))?;
        let config = Self {
            internal_port,
            public_port,
            bind,
            latest_model_id: env_string(&get, "MODEL_LATEST_ID", DEFAULT_LATEST_MODEL_ID),
            artifact_dir: env_string(&get, "MODEL_ARTIFACT_DIR", DEFAULT_ARTIFACT_DIR).into(),
            release_dir: env_string(&get, "MODEL_RELEASE_DIR", DEFAULT_RELEASE_DIR).into(),
            publish_root: get("V3_PUBLISH_ROOT").filter(|value| !value.is_empty()).map(PathBuf::from),
            v3_store: get("V3_STORE").filter(|value| !value.is_empty()).map(PathBuf::from),
        };
        if config.publish_root.is_some() != config.v3_store.is_some() {
            fail!("V3_PUBLISH_ROOT and V3_STORE must be set together");
        }
        if config.internal_port == config.public_port {
            fail!("MODEL_STREAMING_PORT and MODEL_STREAMING_PUBLIC_PORT must differ");
        }
        validate_configured_identifier("MODEL_LATEST_ID", &config.latest_model_id)?;
        if config.latest_model_id == pretrained::MODEL_ID {
            fail!("experimental pretrained contextual model cannot be MODEL_LATEST_ID");
        }
        Ok(config)
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }
}
