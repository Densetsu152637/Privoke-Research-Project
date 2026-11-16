//! The PriVoke telemetry service in Rust (stage 4 of the server rewrite). It replaces
//! `services/telemetry-service` (Python), which stays in place as the parity oracle.
//!
//! The service receives locally randomised reports (generalised randomised response over five fixed public domains),
//! stores only epsilon-stratified aggregate counts in SQLite and answers a debiased summary. Modules mirror the Python
//! files: [`validation`] (`validation.py`), [`storage`] (`storage.py`), [`config`] (`config.py`) and [`service`] plus
//! [`server`] (`server.py`). New here: [`daily`] (a per-source-IP daily cap) and [`healthcheck`].
//!
//! Identity handling. Every reporter holds the same certificate (`urn:privoke:reporter`), so the peer identity says
//! nothing and is never read for storage or logging. The only per-peer value the service uses is the source IP, in
//! memory, for the rate limit and the daily cap; neither is written to the database or to a log line.

pub mod config;
pub mod daily;
pub mod error;
pub mod healthcheck;
pub mod server;
pub mod service;
pub mod storage;
pub mod util;
pub mod validation;

pub use error::{Error, Result};

/// The service name reported by `Health` and by the `healthcheck` subcommand.
pub const SERVICE_NAME: &str = "telemetry-service";
