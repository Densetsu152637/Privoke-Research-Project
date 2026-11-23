//! The experimental V3 runtime in Rust (stage 22 of the server rewrite). It replaces
//! `services/pretrained-v3/src/runtime_server.py`; the Python file stays in place as the parity oracle and for the historical
//! study runners.
//!
//! One process serves two gRPC services on one mutual-TLS port, as the Python server did:
//!
//! * `privoke.v1.PrivokeRuntimeService.AnalyzePrompt`: V3 semantic inference. The request must select exactly the semantic layer
//!   (`layers == [SEMANTIC]`, never an empty list, which would mean the whole detector pipeline), name the model and carry no
//!   presence gate. Every other RPC of that service answers `UNIMPLEMENTED` with the precise gap.
//! * `privoke.experimental.v3.TrainingService`: `FitCandidate` (one physical fit per request identity, over the stage 19
//!   `privoke_training::v3_fit` port), `GetFitStatus` and `Health`.
//!
//! * [`assets`]: the snapshot fetch, the digest-keyed asset cache and the model load (`fetch`, `materialize`, `load`).
//! * [`analyze`]: `AnalyzePrompt`; [`pyerr`]: the Python exception texts it reports.
//! * [`fit`]: `FitCandidate`; [`evidence`]: the evidence value, the candidate's safetensors bytes and the source digests.
//! * [`config`]: the environment of `runtime_server.py` (`__main__`), validated before anything is opened or bound.
//! * [`state`]: the SQLite `fits` table (`id`, `fingerprint`, `status`, `candidate`, `reason`).
//! * [`checkpoint`]: the checkpoint service as the runtime uses it, with its mutual-TLS client.
//! * [`server`]: the mutual-TLS listener and its role policy.
//! * [`service`]: the engine and the two gRPC shells.

pub mod analyze;
pub mod assets;
pub mod checkpoint;
pub mod config;
pub mod evidence;
pub mod fit;
pub mod healthcheck;
pub mod pyerr;
pub mod server;
pub mod service;
pub mod state;

pub use privoke_v3_fuzzer::error;
pub use privoke_v3_fuzzer::error::{Error, Result, invalid};

/// The role reported by `Health`.
pub const ROLE: &str = "runtime";
