//! The environment of `fuzzer_server.py` (`__main__`), validated before anything is opened or bound.
//!
//! | variable | meaning | default |
//! | --- | --- | --- |
//! | `V3_POLICY_FILE` | canonical frozen policy (`parse` and `validate_policy`) | required |
//! | `V3_RUNTIME_TARGET` | the V3 runtime's `TrainingService` (`host:port`) | required |
//! | `V3_CHECKPOINT_TARGET` | the `CheckpointService` (`host:port`) | required |
//! | `V3_FUZZER_STATE` | the state directory: `cycles.sqlite` and one work directory per request | required |
//! | `V3_PORT`, `V3_BIND` | the listener | `50172`, `127.0.0.1` |
//! | `V3_SAMPLING_STRATEGY` | `existing_taxonomy_benign_common_frozen_stream_v1` or `audience_common_frozen_stream_v1` | BC01 |
//! | `V3_FIT_TIMEOUT` | seconds the runtime may take for one fit | `7200` |
//! | `V3_AUDIENCE_MANIFEST_PATH`, `V3_AUDIENCE_MANIFEST_SHA256` | a custom audience release and its pin (both or neither) | bundled |
//! | `V3_SOURCE_ROOT` | the checkout whose Python sources and pinned inputs the host committed to | required |
//! | `V3_REQUEST_TIMEOUT_SECONDS` | the per-RPC deadline of the listener | fit timeout plus 600 |
//!
//! `V3_SOURCE_ROOT` is new: the Python service derived the repository root from its own location. The outbound credentials are
//! `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE` and `PRIVOKE_TLS_KEY_FILE`, with `V3_RUNTIME_TLS_SERVER_NAME` and
//! `V3_CHECKPOINT_TLS_SERVER_NAME` when a certificate does not carry the target host name.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privoke_curriculum::audience;
use privoke_curriculum::v3::{self, Policy};
use privoke_curriculum::value::Value;

use crate::contract::{self, MAX_MANIFEST_BYTES};
use crate::error::{Error, Result, invalid};
use crate::source::{Sampler, Schedules, bc01_input_paths, python_source_hashes};

/// The default port (`V3_PORT`).
pub const DEFAULT_PORT: u16 = 50172;
/// The default fit deadline in seconds (`V3_FIT_TIMEOUT`).
pub const DEFAULT_FIT_TIMEOUT: f64 = 7200.0;

/// The validated settings.
#[derive(Debug, Clone, PartialEq)]
pub struct V3Settings {
    /// `V3_RUNTIME_TARGET`.
    pub runtime_target: String,
    /// `V3_CHECKPOINT_TARGET`.
    pub checkpoint_target: String,
    /// `V3_FUZZER_STATE`.
    pub directory: PathBuf,
    /// `V3_POLICY_FILE`.
    pub policy_file: PathBuf,
    /// `V3_PORT`.
    pub port: u16,
    /// `V3_BIND`.
    pub bind: IpAddr,
    /// `V3_SAMPLING_STRATEGY`.
    pub sampler: Sampler,
    /// `V3_FIT_TIMEOUT`.
    pub fit_timeout: Duration,
    /// `V3_AUDIENCE_MANIFEST_PATH`.
    pub audience_manifest_path: Option<PathBuf>,
    /// `V3_AUDIENCE_MANIFEST_SHA256`.
    pub audience_manifest_sha256: Option<String>,
    /// `V3_SOURCE_ROOT`.
    pub source_root: PathBuf,
    /// `V3_REQUEST_TIMEOUT_SECONDS`.
    pub request_timeout: Duration,
}

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String> {
    get(name).map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).ok_or_else(|| Error(format!("{name} is required.")))
}

fn present(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).filter(|value| !value.is_empty())
}

fn seconds(get: &impl Fn(&str) -> Option<String>, name: &str, default: f64) -> Result<Duration> {
    let number = match get(name) {
        None => default,
        Some(raw) => raw.trim().parse::<f64>().map_err(|_| Error(format!("{name} must be a number.")))?,
    };
    match Duration::try_from_secs_f64(number) {
        Ok(duration) if !duration.is_zero() => Ok(duration),
        _ => invalid(format!("{name} must be finite and positive.")),
    }
}

impl V3Settings {
    /// The settings from any lookup, validated.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let port = match get("V3_PORT") {
            None => i64::from(DEFAULT_PORT),
            Some(raw) => raw.trim().parse::<i64>().map_err(|_| Error("V3_PORT must be an integer.".to_string()))?,
        };
        let port =
            u16::try_from(port).ok().filter(|port| *port != 0).ok_or_else(|| Error("V3_PORT must be between 1 and 65535.".to_string()))?;
        let bind = get("V3_BIND").unwrap_or_else(|| "127.0.0.1".to_string());
        let sampler = Sampler::parse(get("V3_SAMPLING_STRATEGY").as_deref().unwrap_or(v3::BC01_SAMPLER))?;
        let fit_timeout = seconds(&get, "V3_FIT_TIMEOUT", DEFAULT_FIT_TIMEOUT)?;
        let request_timeout = seconds(&get, "V3_REQUEST_TIMEOUT_SECONDS", fit_timeout.as_secs_f64() + 600.0)?;
        let audience_manifest_path = present(&get, "V3_AUDIENCE_MANIFEST_PATH").map(PathBuf::from);
        let audience_manifest_sha256 = present(&get, "V3_AUDIENCE_MANIFEST_SHA256");
        if audience_manifest_path.is_some() != audience_manifest_sha256.is_some() {
            return invalid("Custom v3 audience release requires both trusted path and pin.");
        }
        Ok(Self {
            runtime_target: required(&get, "V3_RUNTIME_TARGET")?,
            checkpoint_target: required(&get, "V3_CHECKPOINT_TARGET")?,
            directory: PathBuf::from(required(&get, "V3_FUZZER_STATE")?),
            policy_file: PathBuf::from(required(&get, "V3_POLICY_FILE")?),
            port,
            bind: bind.trim().parse::<IpAddr>().map_err(|_| Error("V3_BIND must be an IP address.".to_string()))?,
            sampler,
            fit_timeout,
            audience_manifest_path,
            audience_manifest_sha256,
            source_root: PathBuf::from(required(&get, "V3_SOURCE_ROOT")?),
            request_timeout,
        })
    }

    /// The settings from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
}

/// `parse(Path(V3_POLICY_FILE).read_bytes())` and `validate_policy(policy, pilot=policy["steps"] == 2)`.
pub fn load_policy(path: &Path) -> Result<(Value, Policy)> {
    let document = contract::parse(&std::fs::read(path)?, MAX_MANIFEST_BYTES)?;
    let policy = contract::validate_policy(&document)?;
    Ok((document, policy))
}

/// The sampler's inputs under `settings.source_root`, loaded and pinned.
pub fn load_schedules(settings: &V3Settings) -> Result<Schedules> {
    let hashes = python_source_hashes(&settings.source_root, settings.sampler)?;
    Ok(match settings.sampler {
        Sampler::Bc01 => Schedules::bc01(v3::load_sources_from(&bc01_input_paths(&settings.source_root))?, hashes),
        Sampler::Au3 => {
            let release = match (&settings.audience_manifest_path, &settings.audience_manifest_sha256) {
                (Some(path), Some(pin)) => v3::trusted_release(Some(path.as_path()), Some(pin.as_str()))?,
                _ => {
                    let bundled = settings.source_root.join("services/privoke-fuzzer/data/audience-v3-manifest-v1.json");
                    audience::load_release_from(&bundled, true, None)?
                }
            };
            Schedules::au3(release, hashes)
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn lookup(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut map: BTreeMap<String, String> = [
            ("V3_RUNTIME_TARGET", "runtime:50171"),
            ("V3_CHECKPOINT_TARGET", "checkpoint:50170"),
            ("V3_FUZZER_STATE", "/state"),
            ("V3_POLICY_FILE", "/policy.json"),
            ("V3_SOURCE_ROOT", "/repo"),
        ]
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
        for (key, value) in extra {
            map.insert((*key).to_string(), (*value).to_string());
        }
        move |name| map.get(name).cloned()
    }

    #[test]
    fn the_defaults_are_the_python_defaults() {
        let settings = V3Settings::from_lookup(lookup(&[])).unwrap();
        assert_eq!(settings.port, 50172);
        assert_eq!(settings.bind.to_string(), "127.0.0.1");
        assert_eq!(settings.sampler, Sampler::Bc01);
        assert_eq!(settings.fit_timeout, Duration::from_secs(7200));
        assert_eq!(settings.request_timeout, Duration::from_secs(7800));
    }

    #[test]
    fn invalid_settings_are_refused() {
        let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (vec![("V3_SAMPLING_STRATEGY", "other")], "Unknown configured v3 sampler."),
            (vec![("V3_PORT", "x")], "V3_PORT must be an integer."),
            (vec![("V3_PORT", "0")], "V3_PORT must be between 1 and 65535."),
            (vec![("V3_FIT_TIMEOUT", "0")], "V3_FIT_TIMEOUT must be finite and positive."),
            (vec![("V3_FIT_TIMEOUT", "soon")], "V3_FIT_TIMEOUT must be a number."),
            (vec![("V3_BIND", "host")], "V3_BIND must be an IP address."),
            (vec![("V3_AUDIENCE_MANIFEST_PATH", "m.json")], "Custom v3 audience release requires both trusted path and pin."),
            (vec![("V3_POLICY_FILE", "")], "V3_POLICY_FILE is required."),
        ];
        for (pairs, message) in cases {
            assert_eq!(V3Settings::from_lookup(lookup(&pairs)).unwrap_err().0, message, "{pairs:?}");
        }
        let missing = |name: &str| if name == "V3_RUNTIME_TARGET" { None } else { lookup(&[])(name) };
        assert_eq!(V3Settings::from_lookup(missing).unwrap_err().0, "V3_RUNTIME_TARGET is required.");
    }

    #[test]
    fn the_policy_file_must_be_canonical_and_frozen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let frozen = contract::canonical(&Policy { steps: 64 }.to_value()).unwrap();
        std::fs::write(&path, &frozen).unwrap();
        let (document, policy) = load_policy(&path).unwrap();
        assert_eq!(policy, Policy { steps: 64 });
        assert_eq!(contract::canonical(&document).unwrap(), frozen);
        std::fs::write(&path, String::from_utf8(frozen).unwrap().replace("\"steps\":64", "\"steps\": 64")).unwrap();
        assert_eq!(load_policy(&path).unwrap_err().0, "Canonical JSON bytes required.");
    }
}
