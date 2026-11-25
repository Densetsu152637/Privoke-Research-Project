//! Process configuration from the environment, with the Python service's names and defaults plus the new listener,
//! bind, rate and daily-cap settings.

use std::net::IpAddr;
use std::path::PathBuf;

use privoke_transport::RateLimit;

use crate::error::{Error, Result};
use crate::fail;

/// Default internal listener port (Python's `TELEMETRY_PORT`).
pub const DEFAULT_INTERNAL_PORT: u16 = 50055;
/// Default public listener port. The plan stages the cloud telemetry listener on 58443 (published as 8443).
pub const DEFAULT_PUBLIC_PORT: u16 = 58443;
/// Default database path.
pub const DEFAULT_DATABASE_PATH: &str = "/data/telemetry-ldp-v1.sqlite3";
/// Default largest request message (Python's `TELEMETRY_MAX_MESSAGE_BYTES`).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 131_072;
/// Default per-source daily cap. The emitter's daily epsilon budget allows a few reports per installation, so this
/// leaves room for a large network behind one address.
pub const DEFAULT_DAILY_CAP_PER_SOURCE: u32 = 10_000;
/// Default per-source rate: the nginx values of the cloud deployment.
pub const DEFAULT_RATE: RateLimit = RateLimit { per_second: 20, burst: 40 };

/// What the environment configures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// Internal listener port: `GetTelemetrySummary` and `Health` for service principals (`TELEMETRY_PORT`).
    pub internal_port: u16,
    /// Public listener port: `RecordTelemetry` for the reporter (`TELEMETRY_PUBLIC_PORT`).
    pub public_port: u16,
    /// Interface both listeners bind (`TELEMETRY_BIND`).
    pub bind: IpAddr,
    /// The SQLite file (`TELEMETRY_DB_PATH`).
    pub database_path: PathBuf,
    /// Largest accepted request message (`TELEMETRY_MAX_MESSAGE_BYTES`).
    pub max_message_bytes: usize,
    /// Accepted reports per source IP per UTC day (`TELEMETRY_DAILY_CAP_PER_IP`).
    pub daily_cap: u32,
    /// Requests per second per source IP (`TELEMETRY_RATE_PER_SECOND`) and burst (`TELEMETRY_RATE_BURST`).
    pub rate: RateLimit,
}

fn text(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: &str) -> String {
    get(key).filter(|value| !value.is_empty()).unwrap_or_else(|| fallback.to_string())
}

fn integer(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: i64) -> Result<i64> {
    let Some(value) = get(key).filter(|value| !value.is_empty()) else { return Ok(fallback) };
    value.parse().map_err(|error| Error(format!("{key} must be an integer: {error}")))
}

fn port(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: u16) -> Result<u16> {
    let parsed = integer(get, key, i64::from(fallback))?;
    if !(1..=65_535).contains(&parsed) {
        fail!("{key} must be between 1 and 65535");
    }
    Ok(parsed as u16)
}

fn unsigned(get: &impl Fn(&str) -> Option<String>, key: &str, fallback: u32) -> Result<u32> {
    let parsed = integer(get, key, i64::from(fallback))?;
    u32::try_from(parsed).map_err(|_| Error(format!("{key} must be between 0 and {}", u32::MAX)))
}

impl ServiceConfig {
    /// Read variables through `get`, so tests do not touch the process environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let max_message_bytes = integer(&get, "TELEMETRY_MAX_MESSAGE_BYTES", DEFAULT_MAX_MESSAGE_BYTES as i64)?;
        if max_message_bytes <= 0 {
            fail!("TELEMETRY_MAX_MESSAGE_BYTES must be positive.");
        }
        let bind: IpAddr = text(&get, "TELEMETRY_BIND", "0.0.0.0")
            .parse()
            .map_err(|error| Error(format!("TELEMETRY_BIND must be an IP address: {error}")))?;
        let rate = RateLimit {
            per_second: unsigned(&get, "TELEMETRY_RATE_PER_SECOND", DEFAULT_RATE.per_second)?,
            burst: unsigned(&get, "TELEMETRY_RATE_BURST", DEFAULT_RATE.burst)?,
        };
        if rate.per_second == 0 || rate.burst == 0 {
            fail!("TELEMETRY_RATE_PER_SECOND and TELEMETRY_RATE_BURST must be positive.");
        }
        let config = Self {
            internal_port: port(&get, "TELEMETRY_PORT", DEFAULT_INTERNAL_PORT)?,
            public_port: port(&get, "TELEMETRY_PUBLIC_PORT", DEFAULT_PUBLIC_PORT)?,
            bind,
            database_path: text(&get, "TELEMETRY_DB_PATH", DEFAULT_DATABASE_PATH).into(),
            max_message_bytes: usize::try_from(max_message_bytes).map_err(|_| Error("TELEMETRY_MAX_MESSAGE_BYTES is too large".into()))?,
            daily_cap: unsigned(&get, "TELEMETRY_DAILY_CAP_PER_IP", DEFAULT_DAILY_CAP_PER_SOURCE)?,
            rate,
        };
        if config.internal_port == config.public_port {
            fail!("TELEMETRY_PORT and TELEMETRY_PUBLIC_PORT must differ");
        }
        Ok(config)
    }

    /// Read the process environment.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }
}
