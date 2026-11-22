//! The environment of `runtime_server.py` (`__main__`), validated before anything is opened or bound.
//!
//! | variable | meaning | default |
//! | --- | --- | --- |
//! | `V3_CHECKPOINT_TARGET` | the `CheckpointService` (`host:port`) | required |
//! | `V3_RUNTIME_STATE` | the state directory: `fits.sqlite`, `assets/` and one work directory per fit | required |
//! | `V3_DEVICE` | the execution device | `cpu` (the only device this build runs) |
//! | `V3_PORT`, `V3_BIND` | the listener | `50171`, `127.0.0.1` |
//! | `V3_TORCH_THREADS` | threads of the matrix kernels (the name is the Python variable's) | `4` |
//! | `V3_SOURCE_ROOT` | the checkout whose Python sources the evidence's `source_hashes` and the `source_closure` commit to | required |
//! | `V3_REQUEST_TIMEOUT_SECONDS` | the per-RPC deadline of the listener (one RPC is one whole fit) | `7800` |
//!
//! `V3_SOURCE_ROOT` and `V3_REQUEST_TIMEOUT_SECONDS` are new: the Python service derived the repository root from its own
//! location and set no deadline. A `V3_DEVICE` other than `cpu` is refused at startup: CUDA is not ported. The outbound
//! credentials are `PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE` and `PRIVOKE_TLS_KEY_FILE`, with
//! `V3_CHECKPOINT_TLS_SERVER_NAME` when the certificate does not carry the target host name.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result, invalid};

/// The default port (`V3_PORT`).
pub const DEFAULT_PORT: u16 = 50171;
/// The default number of kernel threads (`V3_TORCH_THREADS`).
pub const DEFAULT_THREADS: usize = 4;
/// The default per-RPC deadline in seconds.
pub const DEFAULT_REQUEST_TIMEOUT: f64 = 7800.0;

/// The validated settings.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeSettings {
    /// `V3_CHECKPOINT_TARGET`.
    pub checkpoint_target: String,
    /// `V3_RUNTIME_STATE`.
    pub directory: PathBuf,
    /// `V3_PORT`.
    pub port: u16,
    /// `V3_BIND`.
    pub bind: IpAddr,
    /// `V3_TORCH_THREADS`.
    pub threads: usize,
    /// `V3_SOURCE_ROOT`.
    pub source_root: PathBuf,
    /// `V3_REQUEST_TIMEOUT_SECONDS`.
    pub request_timeout: Duration,
}

fn required(get: &impl Fn(&str) -> Option<String>, name: &str) -> Result<String> {
    get(name).map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).ok_or_else(|| Error(format!("{name} is required.")))
}

impl RuntimeSettings {
    /// The settings from any lookup, validated.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let device = get("V3_DEVICE").unwrap_or_else(|| "cpu".to_string());
        if device.trim() != "cpu" {
            return invalid(format!("V3_DEVICE={}: this runtime executes on the CPU only (CUDA is not ported).", device.trim()));
        }
        let port = match get("V3_PORT") {
            None => i64::from(DEFAULT_PORT),
            Some(raw) => raw.trim().parse::<i64>().map_err(|_| Error("V3_PORT must be an integer.".to_string()))?,
        };
        let port =
            u16::try_from(port).ok().filter(|port| *port != 0).ok_or_else(|| Error("V3_PORT must be between 1 and 65535.".to_string()))?;
        let bind = get("V3_BIND").unwrap_or_else(|| "127.0.0.1".to_string());
        let threads = match get("V3_TORCH_THREADS") {
            None => DEFAULT_THREADS,
            Some(raw) => raw
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|threads| *threads > 0)
                .ok_or_else(|| Error("V3_TORCH_THREADS must be a positive integer.".to_string()))?,
        };
        let number = match get("V3_REQUEST_TIMEOUT_SECONDS") {
            None => DEFAULT_REQUEST_TIMEOUT,
            Some(raw) => raw.trim().parse::<f64>().map_err(|_| Error("V3_REQUEST_TIMEOUT_SECONDS must be a number.".to_string()))?,
        };
        let request_timeout = match Duration::try_from_secs_f64(number) {
            Ok(duration) if !duration.is_zero() => duration,
            _ => return invalid("V3_REQUEST_TIMEOUT_SECONDS must be finite and positive."),
        };
        Ok(Self {
            checkpoint_target: required(&get, "V3_CHECKPOINT_TARGET")?,
            directory: PathBuf::from(required(&get, "V3_RUNTIME_STATE")?),
            port,
            bind: bind.trim().parse::<IpAddr>().map_err(|_| Error("V3_BIND must be an IP address.".to_string()))?,
            threads,
            source_root: PathBuf::from(required(&get, "V3_SOURCE_ROOT")?),
            request_timeout,
        })
    }

    /// The settings from the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn lookup(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut map: BTreeMap<String, String> =
            [("V3_CHECKPOINT_TARGET", "checkpoint:50170"), ("V3_RUNTIME_STATE", "/state"), ("V3_SOURCE_ROOT", "/repo")]
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
        let settings = RuntimeSettings::from_lookup(lookup(&[])).unwrap();
        assert_eq!(settings.port, 50171);
        assert_eq!(settings.bind.to_string(), "127.0.0.1");
        assert_eq!(settings.threads, 4);
        assert_eq!(settings.request_timeout, Duration::from_secs(7800));
    }

    #[test]
    fn invalid_settings_are_refused() {
        let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (vec![("V3_DEVICE", "cuda:0")], "V3_DEVICE=cuda:0: this runtime executes on the CPU only (CUDA is not ported)."),
            (vec![("V3_PORT", "x")], "V3_PORT must be an integer."),
            (vec![("V3_PORT", "0")], "V3_PORT must be between 1 and 65535."),
            (vec![("V3_BIND", "host")], "V3_BIND must be an IP address."),
            (vec![("V3_TORCH_THREADS", "0")], "V3_TORCH_THREADS must be a positive integer."),
            (vec![("V3_REQUEST_TIMEOUT_SECONDS", "0")], "V3_REQUEST_TIMEOUT_SECONDS must be finite and positive."),
            (vec![("V3_REQUEST_TIMEOUT_SECONDS", "soon")], "V3_REQUEST_TIMEOUT_SECONDS must be a number."),
            (vec![("V3_RUNTIME_STATE", "")], "V3_RUNTIME_STATE is required."),
        ];
        for (pairs, message) in cases {
            assert_eq!(RuntimeSettings::from_lookup(lookup(&pairs)).unwrap_err().0, message, "{pairs:?}");
        }
        let missing = |name: &str| if name == "V3_CHECKPOINT_TARGET" { None } else { lookup(&[])(name) };
        assert_eq!(RuntimeSettings::from_lookup(missing).unwrap_err().0, "V3_CHECKPOINT_TARGET is required.");
    }
}
