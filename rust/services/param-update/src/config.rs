//! Process configuration from the environment, with the Python service's names and defaults (`config.py`) plus the
//! listener, rate and drift-policy settings. An empty variable counts as unset.

use std::net::IpAddr;
use std::path::PathBuf;

use privoke_transport::RateLimit;

use crate::engine::EngineConfig;
use crate::error::{Error, Result};
use crate::policy::{DEFAULT_MAX_CUMULATIVE_L2, DEFAULT_MAX_UPDATE_L2, DriftPolicy};
use crate::validate::validate_text;

/// Default listener port (`PARAM_UPDATE_PORT`).
pub const DEFAULT_PORT: u16 = 50052;
/// Default audit file (`PARAM_UPDATE_STORAGE_PATH`).
pub const DEFAULT_STORAGE_PATH: &str = "/data/updates.jsonl";
/// Default model artifact (`MODEL_ARTIFACT_PATH`).
pub const DEFAULT_MODEL_ARTIFACT_PATH: &str = "/models/privoke-baseline.json";
/// Default model (`MODEL_ID`).
pub const DEFAULT_MODEL_ID: &str = "privoke-baseline";
/// Default largest request message (`PARAM_UPDATE_MAX_MESSAGE_BYTES`).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;
/// Default per-identity rate: the nginx values of the cloud deployment.
pub const DEFAULT_RATE: RateLimit = RateLimit { per_second: 20, burst: 40 };

/// The V3 checkpoint store (stage V3-R1): enabled by `V3_STORE`, which is the oracle's variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3Config {
    /// The store directory (`V3_STORE`): `blobs/` and `catalog.sqlite`.
    pub store: PathBuf,
    /// ORIGINAL packages to admit at startup (`V3_INITIAL`, separated like `PATH`): each a directory with `manifest.json`,
    /// `model.safetensors`, `config.json` and `vocab.txt`. A model that already has a version is left as it is.
    pub initial: Vec<PathBuf>,
    /// The checkout that holds the pinned BC01 inputs and the bundled AU3 release (`V3_SOURCE_ROOT`).
    pub source_root: PathBuf,
    /// A custom AU3 release and its pin (`V3_AUDIENCE_MANIFEST_PATH` and `V3_AUDIENCE_MANIFEST_SHA256`, both or neither).
    pub audience: Option<(PathBuf, String)>,
}

impl V3Config {
    fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let Some(store) = get("V3_STORE").filter(|value| !value.is_empty()) else { return Ok(None) };
        let source_root = get("V3_SOURCE_ROOT")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error("V3_SOURCE_ROOT is required when V3_STORE is set.".to_string()))?;
        let path = get("V3_AUDIENCE_MANIFEST_PATH").filter(|value| !value.is_empty());
        let sha256 = get("V3_AUDIENCE_MANIFEST_SHA256").filter(|value| !value.is_empty());
        let audience = match (path, sha256) {
            (Some(path), Some(sha256)) => Some((PathBuf::from(path), sha256)),
            (None, None) => None,
            _ => return Err(Error("Custom v3 audience release requires both trusted path and pin.".to_string())),
        };
        let initial: Vec<PathBuf> = get("V3_INITIAL")
            .filter(|value| !value.is_empty())
            .map(|value| std::env::split_paths(&value).filter(|path| !path.as_os_str().is_empty()).collect())
            .unwrap_or_default();
        Ok(Some(Self { store: PathBuf::from(store), initial, source_root: PathBuf::from(source_root), audience }))
    }
}

/// What the environment configures for the server.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceConfig {
    /// Listener port (`PARAM_UPDATE_PORT`).
    pub port: u16,
    /// Interface to bind (`PARAM_UPDATE_BIND`).
    pub bind: IpAddr,
    /// The audit file (`PARAM_UPDATE_STORAGE_PATH`); the receipt database is its sibling.
    pub storage_path: PathBuf,
    /// The mutable model (`MODEL_ARTIFACT_PATH`).
    pub model_artifact_path: PathBuf,
    /// The model this service updates (`MODEL_ID`).
    pub model_id: String,
    /// The per-coordinate bound (`PARAM_UPDATE_MAX_ABS_GRADIENT`).
    pub max_abs_gradient: f64,
    /// Largest request message (`PARAM_UPDATE_MAX_MESSAGE_BYTES`).
    pub max_message_bytes: usize,
    /// Per-identity request rate (`PARAM_UPDATE_RATE_PER_SECOND`, `PARAM_UPDATE_RATE_BURST`).
    pub rate: RateLimit,
    /// The change bounds (`PARAM_UPDATE_DRIFT_POLICY`, `PARAM_UPDATE_MAX_UPDATE_L2`, `PARAM_UPDATE_MAX_CUMULATIVE_L2`).
    pub drift: DriftPolicy,
    /// Context the `bootstrap` subcommand prepares (`MODEL_TRAINING_MAX_TOKENS`).
    pub bootstrap_max_tokens: i64,
    /// The V3 checkpoint store, when `V3_STORE` is set.
    pub v3: Option<V3Config>,
}

fn text(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: &str) -> String {
    get(key).filter(|value| !value.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn integer(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: i64) -> Result<i64> {
    let Some(value) = get(key).filter(|value| !value.is_empty()) else { return Ok(fallback) };
    value.trim().parse().map_err(|_| Error(format!("{key} must be an integer.")))
}

fn number(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: f64) -> Result<f64> {
    let Some(value) = get(key).filter(|value| !value.is_empty()) else { return Ok(fallback) };
    value.trim().parse().map_err(|_| Error(format!("{key} must be a number.")))
}

fn positive_number(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: f64) -> Result<f64> {
    let parsed = number(get, key, fallback)?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(Error(format!("{key} must be finite and positive.")));
    }
    Ok(parsed)
}

fn unsigned(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: u32) -> Result<u32> {
    let parsed = integer(get, key, i64::from(fallback))?;
    u32::try_from(parsed).map_err(|_| Error(format!("{key} must be between 0 and {}.", u32::MAX)))
}

impl ServiceConfig {
    /// Read variables through `get`, so tests do not touch the process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let port = integer(&get, "PARAM_UPDATE_PORT", i64::from(DEFAULT_PORT))?;
        if !(1..=65_535).contains(&port) {
            return Err(Error("PARAM_UPDATE_PORT must be between 1 and 65535.".to_string()));
        }
        let model_id = text(&get, "MODEL_ID", DEFAULT_MODEL_ID).trim().to_string();
        validate_text(&model_id, "MODEL_ID", true, 128).map_err(|failure| Error(failure.to_string()))?;
        let max_message_bytes = integer(&get, "PARAM_UPDATE_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES as i64)?;
        if max_message_bytes <= 0 {
            return Err(Error("PARAM_UPDATE_MAX_MESSAGE_BYTES must be positive.".to_string()));
        }
        let rate = RateLimit {
            per_second: unsigned(&get, "PARAM_UPDATE_RATE_PER_SECOND", DEFAULT_RATE.per_second)?,
            burst: unsigned(&get, "PARAM_UPDATE_RATE_BURST", DEFAULT_RATE.burst)?,
        };
        if rate.per_second == 0 || rate.burst == 0 {
            return Err(Error("PARAM_UPDATE_RATE_PER_SECOND and PARAM_UPDATE_RATE_BURST must be positive.".to_string()));
        }
        let drift = match text(&get, "PARAM_UPDATE_DRIFT_POLICY", "enforce").trim().to_ascii_lowercase().as_str() {
            "off" => DriftPolicy::Off,
            "enforce" => DriftPolicy::Enforce {
                max_update_l2: positive_number(&get, "PARAM_UPDATE_MAX_UPDATE_L2", DEFAULT_MAX_UPDATE_L2)?,
                max_cumulative_l2: positive_number(&get, "PARAM_UPDATE_MAX_CUMULATIVE_L2", DEFAULT_MAX_CUMULATIVE_L2)?,
            },
            _ => return Err(Error("PARAM_UPDATE_DRIFT_POLICY must be enforce or off.".to_string())),
        };
        let bootstrap_max_tokens = integer(&get, "MODEL_TRAINING_MAX_TOKENS", 256)?;
        let bind: IpAddr = text(&get, "PARAM_UPDATE_BIND", "0.0.0.0")
            .parse()
            .map_err(|error| Error(format!("PARAM_UPDATE_BIND must be an IP address: {error}")))?;
        Ok(Self {
            port: u16::try_from(port).map_err(|_| Error("PARAM_UPDATE_PORT must be between 1 and 65535.".to_string()))?,
            bind,
            storage_path: text(&get, "PARAM_UPDATE_STORAGE_PATH", DEFAULT_STORAGE_PATH).into(),
            model_artifact_path: text(&get, "MODEL_ARTIFACT_PATH", DEFAULT_MODEL_ARTIFACT_PATH).into(),
            model_id,
            max_abs_gradient: positive_number(&get, "PARAM_UPDATE_MAX_ABS_GRADIENT", 1.0)?,
            max_message_bytes: usize::try_from(max_message_bytes)
                .map_err(|_| Error("PARAM_UPDATE_MAX_MESSAGE_BYTES is too large.".to_string()))?,
            rate,
            drift,
            bootstrap_max_tokens,
            v3: V3Config::from_lookup(&get)?,
        })
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The engine's configuration.
    pub fn engine_config(&self) -> EngineConfig {
        EngineConfig {
            storage_path: self.storage_path.clone(),
            model_artifact_path: self.model_artifact_path.clone(),
            expected_model_id: self.model_id.clone(),
            max_abs_gradient: self.max_abs_gradient,
            drift: self.drift,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::collections::HashMap;

    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Result<ServiceConfig> {
        let map: HashMap<String, String> = pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect();
        ServiceConfig::from_lookup(|key| map.get(key).cloned())
    }

    #[test]
    fn defaults_match_the_python_service_and_enforce_the_bounds() {
        let configured = config(&[]).unwrap();
        assert_eq!(configured.port, 50052);
        assert_eq!(configured.model_id, "privoke-baseline");
        assert_eq!(configured.max_abs_gradient, 1.0);
        assert_eq!(configured.max_message_bytes, 1_048_576);
        assert_eq!(configured.drift, DriftPolicy::default());
        assert_eq!(configured.bootstrap_max_tokens, 256);
        assert_eq!(configured.v3, None, "the V3 store is off unless V3_STORE is set");
    }

    #[test]
    fn the_v3_store_is_configured_by_the_oracles_variables() {
        let configured = config(&[("V3_STORE", "/store"), ("V3_SOURCE_ROOT", "/repo")]).unwrap().v3.unwrap();
        assert_eq!(configured.store, PathBuf::from("/store"));
        assert_eq!(configured.source_root, PathBuf::from("/repo"));
        assert!(configured.initial.is_empty() && configured.audience.is_none());
        assert!(config(&[("V3_STORE", "/store")]).is_err(), "the pinned sources are required");
        assert!(config(&[("V3_STORE", "/store"), ("V3_SOURCE_ROOT", "/repo"), ("V3_AUDIENCE_MANIFEST_PATH", "/release.json")]).is_err());
        let pinned = config(&[
            ("V3_STORE", "/store"),
            ("V3_SOURCE_ROOT", "/repo"),
            ("V3_AUDIENCE_MANIFEST_PATH", "/release.json"),
            ("V3_AUDIENCE_MANIFEST_SHA256", "abc"),
        ])
        .unwrap()
        .v3
        .unwrap();
        assert_eq!(pinned.audience, Some((PathBuf::from("/release.json"), "abc".to_string())));
    }

    #[test]
    fn invalid_settings_are_refused() {
        for pairs in [
            vec![("PARAM_UPDATE_PORT", "0")],
            vec![("PARAM_UPDATE_PORT", "http")],
            vec![("PARAM_UPDATE_MAX_ABS_GRADIENT", "0")],
            vec![("PARAM_UPDATE_MAX_ABS_GRADIENT", "inf")],
            vec![("PARAM_UPDATE_MAX_MESSAGE_BYTES", "-1")],
            vec![("PARAM_UPDATE_DRIFT_POLICY", "maybe")],
            vec![("PARAM_UPDATE_MAX_CUMULATIVE_L2", "0")],
            vec![("MODEL_ID", "bad\nid")],
        ] {
            assert!(config(&pairs).is_err(), "{pairs:?}");
        }
    }

    #[test]
    fn the_drift_policy_can_be_switched_off_or_tuned() {
        assert_eq!(config(&[("PARAM_UPDATE_DRIFT_POLICY", "off")]).unwrap().drift, DriftPolicy::Off);
        let tuned = config(&[("PARAM_UPDATE_MAX_UPDATE_L2", "3.5"), ("PARAM_UPDATE_MAX_CUMULATIVE_L2", "40")]).unwrap();
        assert_eq!(tuned.drift, DriftPolicy::Enforce { max_update_l2: 3.5, max_cumulative_l2: 40.0 });
    }
}
