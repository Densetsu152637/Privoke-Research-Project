//! The experimental V3 fuzzer service in Rust (the remaining half of stage 21 of the server rewrite). It replaces
//! `services/pretrained-v3/src/fuzzer_server.py`; the Python file stays in place as the parity oracle and for the historical
//! study runners.
//!
//! One request runs one frozen-schedule fit: the schedule (stage 20, [`privoke_curriculum::v3`]) names the TRAIN rows and the
//! guard, the V3 runtime fits a candidate from them (`TrainingService`), and the checkpoint service snapshots, judges and
//! publishes the candidate (`CheckpointService`). Only checkpoint references and their evidence leave the runtime. Every fit
//! request is semantic-only: the layer list is always exactly `[SEMANTIC]` and never empty.
//!
//! * [`contract`]: `v3_contract.py` as the fuzzer uses it. Strict parsing (duplicate fields, canonical bytes) and the policy
//!   come from [`privoke_contracts::v3`] and [`privoke_curriculum::v3`]; `validate_execution` and `publication_passes` are the
//!   stage 19 ports of [`privoke_training::v3_fit`].
//! * [`backend`]: the two dependencies as traits, their mutual-TLS gRPC clients and the bounded blob transport of `common.py`.
//! * [`state`]: the SQLite `cycles` table (`id`, `fingerprint`, `response`).
//! * [`source`]: the frozen schedules and the identity of the Python source closure.
//! * [`cycle`]: the orchestration, with the work directory of request, source, fit, evidence, commit and receipt files.
//! * [`config`], [`service`], [`server`]: the environment, the gRPC shell and the mutual-TLS listener.

pub mod backend;
pub mod config;
pub mod contract;
pub mod cycle;
pub mod error;
pub mod pywire;
pub mod server;
pub mod service;
pub mod source;
pub mod state;

pub use error::{Error, Failure, Result};

/// The role reported by `Health`.
pub const ROLE: &str = "fuzzer";
