//! The PriVoke fuzzer service in Rust (stage 21 of the server rewrite). It replaces
//! `services/privoke-fuzzer/src/{fuzzer_service,runtime_client,main,cli,config,json_records}.py`; the Python files stay in
//! place as the parity oracle and for the historical study runners.
//!
//! One request runs one bounded training cycle: the curriculum (stage 20, in process) selects the examples, the client
//! runtime computes the gradients and the held-out guard metrics, the cycle's guard decides whether the update is
//! publishable, and the parameter-update service applies it. Modules mirror the Python files:
//!
//! * [`config`] (`config.py`), [`cli`] (`cli.py`) and [`validate`] (`privoke_service.validate_text` and the request
//!   validators of `fuzzer_service.py`);
//! * [`runtime`] (`runtime_client.py`): the gradient request, the response admission and the mutual-TLS client;
//! * [`updates`] (`training/parameter_updates.py` and the status lookup): the publication metadata and the client of the
//!   parameter-update service;
//! * [`evidence`] (`training/evidence.py`): reservations, the durable cycle record and recovery of a lost acknowledgement;
//! * [`state`]: the SQLite [`privoke_curriculum::curriculum::CursorState`] of the fixed curriculum;
//! * [`cycle`] (`fuzzer_service.py`): the orchestration, [`service`] and [`server`] (the gRPC shell and its policy).
//!
//! Paths that need parts of the stage 19 training crate that are not ported yet, and the policy-admitted FULL Adam,
//! retention and window cycles, answer `UNIMPLEMENTED` with the name of the gap instead of running a different cycle.

pub mod attempts;
pub mod cli;
pub mod config;
pub mod cycle;
pub mod error;
pub mod evidence;
pub mod full_adam;
pub mod full_adam_evidence;
pub mod policy;
pub mod policy_response;
pub mod pywire;
pub mod runtime;
pub mod server;
pub mod service;
pub mod state;
pub mod updates;
pub mod validate;

pub use error::{Error, Result};

/// The service name reported by `Health`.
pub const SERVICE_NAME: &str = "privoke-fuzzer";
