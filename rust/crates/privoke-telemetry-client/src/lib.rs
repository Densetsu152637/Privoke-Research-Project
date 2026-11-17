//! The PriVoke client telemetry reporter in Rust (stage 18 of the server rewrite, decision D8).
//!
//! It ports `extension/client-runtime/src/telemetry/{privacy,event_emitter}.py`, which stay in place as the parity
//! oracle:
//!
//! * [`random`]: the 53-bit uniform draw and the rejection-sampled choice of CPython's `random.SystemRandom`, on an
//!   injectable byte source, so the same bytes give the same draws;
//! * [`privacy`]: generalised randomised response with the oracle's binary64 thresholds, and `randomize_report`;
//! * [`ledger`]: the persistent UTC-day epsilon ledger (SQLite, the Python file layout, no refunds, fail closed);
//! * [`event`]: the bounded categorical report built from an [`AnalysisInput`] and its packet;
//! * [`reporter`]: reserve, randomise, queue and deliver on a worker thread;
//! * [`grpc`]: delivery to the stage 4 telemetry service over mutual TLS with the shared reporter credential.
//!
//! The randomiser reads only the bytes of its [`random::RandomSource`] and the arguments it is given. Its privacy
//! statement is the audited one only for the finite thresholds this crate computes: see the audit record of stage 18
//! (`paper/research/rust-telemetry-epsilon-audit-20261117.md`), which supersedes C34 for this kernel and for nothing else.

pub mod error;
pub mod event;
pub mod grpc;
pub mod ledger;
pub mod privacy;
pub mod random;
pub mod reporter;

pub use error::{LedgerFault, PrivacyError, RandomError, ReporterError};
pub use event::{AnalysisInput, AnalysisResult, Classification, StructuredEventEmitter};
pub use grpc::{GrpcTransport, ReporterChannel, ReporterEndpoint};
pub use ledger::{DailyPrivacyBudget, default_ledger_path, default_ledger_path_with};
pub use privacy::{
    DAILY_EPSILON_DEFAULT, DAILY_EPSILON_MAX, DIMENSIONS, EVENT_EPSILON_DEFAULT, EVENT_EPSILON_MAX, EVENT_EPSILON_MIN, GrrKernel,
    MECHANISM, domain, generalized_randomized_response, grr_kernel, grr_probabilities, randomize_report, validate_privacy_config,
};
pub use random::{OsRandom, RandomSource, ReplayRandom};
pub use reporter::{
    DeliveryFailure, DeliveryObserver, DeliveryOutcome, PacketTransport, ReportOutcome, ReporterParts, ReporterSettings, TelemetryReporter,
};
