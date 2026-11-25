//! The delivery side of the reporter (`TelemetryReporter` of `event_emitter.py`): reserve budget, randomise, queue, and
//! send on a worker thread, so that prompt analysis never waits for the network.
//!
//! The order of operations is the oracle's and is part of the privacy argument: the budget is reserved before the packet
//! is built, a reservation is never refunded, and a packet that cannot be queued or delivered is dropped, not retried.
//! Every drop is logged with a fixed text that carries no report data.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use privoke_contracts::proto::v1::TelemetryPacket;
use time::OffsetDateTime;

use crate::error::ReporterError;
use crate::event::{AnalysisInput, StructuredEventEmitter};
use crate::ledger::{DailyPrivacyBudget, default_ledger_path};
use crate::privacy::{DAILY_EPSILON_DEFAULT, EVENT_EPSILON_DEFAULT, validate_privacy_config};
use crate::random::{OsRandom, RandomSource};

const WORKER_NAME: &str = "privoke-telemetry-reporter";
const EVENT_LABEL: &str = "protected-report";

/// What `report` did with one analysis. Everything except `Queued` is a suppression: nothing was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOutcome {
    /// The packet is in the delivery queue.
    Queued,
    /// The daily budget is spent.
    BudgetExhausted,
    /// The ledger or the report builder failed; `class` is the Python exception class the oracle would log.
    PrivacyFailure {
        /// The oracle's exception class name.
        class: &'static str,
    },
    /// The delivery queue is full; the reserved budget stays spent.
    QueueFull,
    /// The worker has stopped; the reserved budget stays spent.
    Closed,
}

impl ReportOutcome {
    /// The log line of this outcome (the oracle's text), or `None` for `Queued`.
    pub fn log_message(&self) -> Option<String> {
        match self {
            Self::Queued => None,
            Self::BudgetExhausted => Some("telemetry daily privacy budget exhausted; report suppressed".to_string()),
            Self::PrivacyFailure { class } => Some(format!("telemetry privacy processing failed; report suppressed ({class})")),
            Self::QueueFull => Some("telemetry queue full; report suppressed".to_string()),
            Self::Closed => Some("telemetry reporter closed; report suppressed".to_string()),
        }
    }
}

/// How one queued packet ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The collector accepted it.
    Accepted,
    /// The collector answered but did not accept it.
    Rejected,
    /// The call failed with a gRPC status (`StatusCode.UNAVAILABLE` style name).
    RpcFailed {
        /// The status code name.
        code: String,
    },
    /// Any other failure (the transport could not even try).
    Failed {
        /// The failure class.
        class: String,
    },
}

impl DeliveryOutcome {
    /// The log line of this outcome (the oracle's text), or `None` for `Accepted`.
    pub fn log_message(&self) -> Option<String> {
        match self {
            Self::Accepted => None,
            Self::Rejected => Some("telemetry report rejected".to_string()),
            Self::RpcFailed { code } => Some(format!("telemetry submission failed event={EVENT_LABEL} code={code}")),
            Self::Failed { class } => Some(format!("telemetry reporter failed event={EVENT_LABEL} error={class}")),
        }
    }
}

/// Why a send did not complete with a collector answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryFailure {
    /// A gRPC status, or a failure to reach the server (reported as `StatusCode.UNAVAILABLE`).
    Rpc {
        /// The status code name, for example `StatusCode.UNAVAILABLE`.
        code: String,
    },
    /// Anything else.
    Other {
        /// The failure class.
        class: String,
    },
}

/// Sends packets to the collector. Called on the worker thread only, one packet at a time, in queue order.
pub trait PacketTransport: Send {
    /// Send `packet` within `timeout`. `Ok(true)` is an accepted report.
    fn send(&mut self, packet: &TelemetryPacket, timeout: Duration) -> Result<bool, DeliveryFailure>;
}

/// Called on the worker thread with every delivery outcome, after it is logged.
pub type DeliveryObserver = Arc<dyn Fn(&DeliveryOutcome) + Send + Sync>;

/// The numbers and paths of a reporter.
#[derive(Debug, Clone)]
pub struct ReporterSettings {
    /// Epsilon of every report, in `[0.5, 2]` with at most six decimals.
    pub event_epsilon: f64,
    /// Daily epsilon cap, at least the event epsilon and at most 8.
    pub daily_epsilon: f64,
    /// The ledger file; the platform default when `None`.
    pub ledger_path: Option<PathBuf>,
    /// Deadline of each delivery attempt.
    pub timeout: Duration,
    /// Packets that may wait for the worker (at least one).
    pub queue_size: usize,
}

impl Default for ReporterSettings {
    fn default() -> Self {
        Self {
            event_epsilon: EVENT_EPSILON_DEFAULT,
            daily_epsilon: DAILY_EPSILON_DEFAULT,
            ledger_path: None,
            timeout: Duration::from_secs(1),
            queue_size: 1024,
        }
    }
}

/// The injectable parts of a reporter. [`TelemetryReporter::start`] fills in the production ones.
#[allow(missing_debug_implementations)]
pub struct ReporterParts {
    /// Sends the queued packets.
    pub transport: Box<dyn PacketTransport>,
    /// The source of random bytes for the report draw.
    pub random: Box<dyn RandomSource + Send>,
    /// The clock, read for the UTC day of the reservation and for the time bucket.
    pub clock: Box<dyn Fn() -> OffsetDateTime + Send + Sync>,
    /// Optional observer of delivery outcomes.
    pub observer: Option<DeliveryObserver>,
}

enum Job {
    Packet(TelemetryPacket),
    Stop,
}

/// Reserves budget, randomises and delivers reports without delaying the caller.
///
/// `report` does a short blocking SQLite transaction; call it from a blocking-friendly context (for example
/// `spawn_blocking` inside an async runtime). Dropping the reporter lets the worker finish what is queued and stop;
/// `close` waits for it.
pub struct TelemetryReporter {
    budget: DailyPrivacyBudget,
    event_epsilon: f64,
    random: Mutex<Box<dyn RandomSource + Send>>,
    clock: Box<dyn Fn() -> OffsetDateTime + Send + Sync>,
    sender: SyncSender<Job>,
    finished: Mutex<Receiver<()>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl fmt::Debug for TelemetryReporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryReporter")
            .field("budget", &self.budget)
            .field("event_epsilon", &self.event_epsilon)
            .finish_non_exhaustive()
    }
}

impl TelemetryReporter {
    /// A reporter with the operating-system random source and the wall clock, delivering through `transport`.
    pub fn start(settings: ReporterSettings, transport: Box<dyn PacketTransport>) -> Result<Self, ReporterError> {
        Self::with_parts(
            settings,
            ReporterParts { transport, random: Box::new(OsRandom), clock: Box::new(OffsetDateTime::now_utc), observer: None },
        )
    }

    /// A reporter over explicit parts (deterministic tests, an observer).
    pub fn with_parts(settings: ReporterSettings, parts: ReporterParts) -> Result<Self, ReporterError> {
        validate_privacy_config(settings.event_epsilon, settings.daily_epsilon)?;
        let path = match settings.ledger_path {
            Some(path) => path,
            None => default_ledger_path()?,
        };
        let budget = DailyPrivacyBudget::new(path, settings.daily_epsilon)?;
        let (sender, receiver) = sync_channel::<Job>(settings.queue_size.max(1));
        let (finished_sender, finished) = std::sync::mpsc::channel::<()>();
        let ReporterParts { transport, random, clock, observer } = parts;
        let timeout = settings.timeout;
        let worker = std::thread::Builder::new().name(WORKER_NAME.to_string()).spawn(move || {
            run_worker(&receiver, transport, timeout, observer.as_deref());
            let _ = finished_sender.send(());
        })?;
        Ok(Self {
            budget,
            event_epsilon: settings.event_epsilon,
            random: Mutex::new(random),
            clock,
            sender,
            finished: Mutex::new(finished),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// The ledger this reporter spends from.
    pub fn budget(&self) -> &DailyPrivacyBudget {
        &self.budget
    }

    /// Reserve budget, randomise and queue one report. Never fails and never waits for the network.
    pub fn report(&self, analysis: &AnalysisInput) -> ReportOutcome {
        let outcome = self.prepare_and_queue(analysis);
        match &outcome {
            ReportOutcome::Queued => {}
            ReportOutcome::BudgetExhausted => tracing::info!("telemetry daily privacy budget exhausted; report suppressed"),
            other => {
                if let Some(message) = other.log_message() {
                    tracing::warn!("{message}");
                }
            }
        }
        outcome
    }

    fn prepare_and_queue(&self, analysis: &AnalysisInput) -> ReportOutcome {
        match self.budget.reserve(self.event_epsilon, Some((self.clock)())) {
            Ok(true) => {}
            Ok(false) => return ReportOutcome::BudgetExhausted,
            Err(error) => return ReportOutcome::PrivacyFailure { class: error.python_class() },
        }
        let packet = {
            let mut random = self.random.lock().unwrap_or_else(PoisonError::into_inner);
            match StructuredEventEmitter::build_packet(analysis, self.event_epsilon, (self.clock)(), &mut **random) {
                Ok(packet) => packet,
                Err(error) => return ReportOutcome::PrivacyFailure { class: error.python_class() },
            }
        };
        // A reserved budget is never refunded, even when no packet is sent.
        match self.sender.try_send(Job::Packet(packet)) {
            Ok(()) => ReportOutcome::Queued,
            Err(TrySendError::Full(_)) => ReportOutcome::QueueFull,
            Err(TrySendError::Disconnected(_)) => ReportOutcome::Closed,
        }
    }

    /// Ask the worker to stop after the packets already queued and wait up to `timeout` for it. Like the oracle, this
    /// does nothing when the queue is full (the worker then stops when the reporter is dropped).
    pub fn close(&self, timeout: Duration) {
        if self.sender.try_send(Job::Stop).is_err() {
            return;
        }
        let finished = self.finished.lock().unwrap_or_else(PoisonError::into_inner);
        if finished.recv_timeout(timeout).is_ok() {
            let handle = self.worker.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(handle) = handle {
                let _ = handle.join();
            }
        }
    }
}

fn run_worker(
    receiver: &Receiver<Job>,
    mut transport: Box<dyn PacketTransport>,
    timeout: Duration,
    observer: Option<&(dyn Fn(&DeliveryOutcome) + Send + Sync)>,
) {
    while let Ok(job) = receiver.recv() {
        let packet = match job {
            Job::Stop => return,
            Job::Packet(packet) => packet,
        };
        let sent = catch_unwind(AssertUnwindSafe(|| transport.send(&packet, timeout)));
        let outcome = match sent {
            Ok(Ok(true)) => DeliveryOutcome::Accepted,
            Ok(Ok(false)) => DeliveryOutcome::Rejected,
            Ok(Err(DeliveryFailure::Rpc { code })) => DeliveryOutcome::RpcFailed { code },
            Ok(Err(DeliveryFailure::Other { class })) => DeliveryOutcome::Failed { class },
            Err(_) => DeliveryOutcome::Failed { class: "Panic".to_string() },
        };
        if let Some(message) = outcome.log_message() {
            tracing::warn!("{message}");
        }
        if let Some(observer) = observer {
            observer(&outcome);
        }
    }
}
