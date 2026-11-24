//! The PriVoke parameter-update service and training-cycle scheduler in Rust (stage 5 of the server rewrite). It
//! replaces `services/param-update-service` (Python), which stays in place as the parity oracle.
//!
//! The V1 gradient update path (`SubmitParameterUpdate`: validation, application, drift bounds, per-request receipts) was
//! removed in stage V3-R8b: V1 models are served for detection and no longer trained, so the RPC is `UNIMPLEMENTED`. The
//! status lookup, `Health` and the V1 model bootstrap stay. Modules mirror the Python files:
//!
//! * [`artifact_io`] (`privoke_model.artifact`): the atomic, fsynced write of the model artifact;
//! * [`receipts`] (`receipts.py`), [`audit`] (`audit.py`) and [`bootstrap`] (`bootstrap.py`);
//! * [`engine`] (`server.py`'s service class without the transport) and [`service`] plus [`server`] (the transport);
//! * [`journal`] (`training_cycles.py`) and [`scheduler`] (`fuzzer_requests.py`): the training-cycle scheduler.
//!
//! The V3 checkpoint store ([`v3_store`], `checkpoint_store.py` and `checkpoint_server.py`) is served on the same listener to the
//! publisher and trainer roles.
//!
//! New here: publisher authorisation and identity binding
//! (`privoke-transport`), fail-closed startup, and the [`healthcheck`] subcommand. [`pyfmt`] holds the Python text and
//! number behaviour the artifact, receipt and journal formats depend on.

pub mod artifact_io;
pub mod audit;
pub mod bootstrap;
pub mod config;
pub mod engine;
pub mod error;
pub mod healthcheck;
pub mod journal;
pub mod pyfmt;
pub mod receipts;
pub mod scheduler;
pub mod server;
pub mod service;
pub mod util;
pub mod v3_guard;
pub mod v3_policy;
pub mod v3_publish;
pub mod v3_retention;
pub mod v3_store;

pub use error::{Error, Failure, Result};

/// The service name reported by `Health` and by the `healthcheck` subcommand.
pub const SERVICE_NAME: &str = "param-update-service";

/// The publication seed: 64 hexadecimal characters in a mounted secret file.
pub fn read_seed(path: &std::path::Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).map_err(|error| Error(format!("V3 publication key file: {error}")))?;
    let text = text.trim();
    let bytes: Option<Vec<u8>> = (text.len() == 64 && text.is_ascii())
        .then(|| (0..64).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok()).collect::<Option<Vec<u8>>>())
        .flatten();
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error("V3 publication key file must hold 64 hexadecimal characters.".to_string()))
}

/// The observers of a deployment, in the order they run, and its publisher when publication is configured.
pub type BuiltObservers = (Vec<std::sync::Arc<dyn v3_store::CommitObserver>>, Option<std::sync::Arc<v3_publish::Publisher>>);

/// Build the commit observers of a V3 deployment, in the order the gates run before the transaction, cheapest first: the drift
/// bounds, the recomputed guard over the scheduler's allocations, the retention check, and last the publisher that stages the
/// files. Every commit is bounded, published or not. `guard_scorer` and `retention_scorer` replace the real scorers when given
/// (`None` is the production behaviour); `crash` is the publisher's fault-injection hook. The publisher is returned as well, for
/// the startup reconciliation.
pub fn build_observers(
    config: &config::V3Config,
    sources: std::sync::Arc<v3_store::PinnedSources>,
    allocations: std::sync::Arc<dyn v3_guard::Allocations>,
    crash: v3_publish::CrashHook,
    guard_scorer: Option<std::sync::Arc<dyn v3_guard::GuardScorer>>,
    retention_scorer: Option<std::sync::Arc<dyn v3_retention::RetentionScorer>>,
) -> Result<BuiltObservers> {
    use std::sync::Arc;

    use util::log;
    use v3_guard::GuardGate;
    use v3_policy::{DriftBounds, DriftGate};
    use v3_publish::Publisher;
    use v3_retention::{RetentionGate, RetentionReleases};

    let mut publisher = None;
    let bounds = DriftBounds::load(&config.drift_bounds).map_err(|error| Error(format!("V3 drift bounds: {error}")))?;
    log(format_args!("V3 drift bounds status={} evidence={}", bounds.status, bounds.evidence_sha256));
    let mut observers: Vec<Arc<dyn v3_store::CommitObserver>> = vec![Arc::new(DriftGate::new(bounds))];
    // The guard is recomputed from the rows param-update rebuilds, for requests the scheduler allocated (its journal is the table).
    let mut guard = GuardGate::new(sources, allocations);
    if let Some(scorer) = guard_scorer {
        guard = guard.with_scorer(scorer);
    }
    observers.push(Arc::new(guard));
    // The retention check is the costliest gate, so it follows the cheap ones; like them it runs before the transaction.
    if let Some(retention) = &config.retention {
        let releases =
            RetentionReleases::load(&retention.root, &retention.bank).map_err(|error| Error(format!("V3 retention: {error}")))?;
        log(format_args!("V3 retention gate on root={}", retention.root.display()));
        let mut gate = RetentionGate::new(releases);
        if let Some(scorer) = retention_scorer {
            gate = gate.with_scorer(scorer);
        }
        observers.push(Arc::new(gate));
    }
    if let Some(publication) = &config.publication {
        let seed = read_seed(&publication.key_file)?;
        let signer = Arc::new(
            Publisher::new(&publication.root, &publication.key_id, seed, crash).map_err(|error| Error(format!("V3 publisher: {error}")))?,
        );
        observers.push(signer.clone());
        publisher = Some(signer);
    }
    Ok((observers, publisher))
}
