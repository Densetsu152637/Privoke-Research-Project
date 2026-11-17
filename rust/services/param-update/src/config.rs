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
