//! Aggregate storage and the summary estimator (`storage.py`).
//!
//! The database holds exactly two tables, `telemetry_strata` and `telemetry_counts`, with the schema the Python
//! service created, so an existing `telemetry-ldp-v1.sqlite3` opens unchanged. There is no column that could hold a
//! peer identity, a source address or a timestamp. Each operation opens its own connection, as the Python store does,
//! so a failure leaves nothing half-open.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use privoke_contracts::proto::v1::TelemetryPacket;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::validation::{DIMENSIONS, MAX_EPSILON, MIN_EPSILON, allowed_values, dimension_value};

/// Epsilon is split evenly over the five dimensions.
const DIMENSION_EPSILON: f64 = DIMENSIONS.len() as f64;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS telemetry_strata (
    epsilon_micros INTEGER PRIMARY KEY,
    sample_count INTEGER NOT NULL CHECK(sample_count >= 0)
);
CREATE TABLE IF NOT EXISTS telemetry_counts (
    epsilon_micros INTEGER NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    observed_count INTEGER NOT NULL CHECK(observed_count >= 0),
    PRIMARY KEY (epsilon_micros, dimension, value),
    FOREIGN KEY (epsilon_micros) REFERENCES telemetry_strata(epsilon_micros)
);
";
const STRATUM_COLUMNS: [&str; 2] = ["epsilon_micros", "sample_count"];
const COUNT_COLUMNS: [&str; 4] = ["epsilon_micros", "dimension", "value", "observed_count"];

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A database from the pre-LDP service. It is neither read nor modified.
    #[error(
        "legacy unprotected telemetry database schema detected; use the new telemetry-ldp-v1.sqlite3 database path. Historical data was not imported or deleted."
    )]
    Legacy,
    /// The aggregate tables exist with other columns.
    #[error("incompatible telemetry aggregate schema; use a fresh telemetry-ldp-v1.sqlite3 database.")]
    Incompatible,
    /// A stored stratum epsilon outside the accepted range.
    #[error("stored privacy epsilon is invalid")]
    InvalidEpsilon,
    /// A stored count that cannot be a count.
    #[error("stored telemetry count is invalid")]
    InvalidCount,
    /// The directory of the database could not be created.
    #[error("create the database directory: {0}")]
    Directory(#[from] std::io::Error),
    /// SQLite refused.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// One category of a dimension.
#[derive(Debug, Clone, PartialEq)]
pub struct CategoryEstimate {
    /// The category value.
    pub value: &'static str,
    /// The debiased estimate, clipped to `[0, sample_count]`.
    pub estimated_count: f64,
    /// The noisy count actually observed, summed over strata.
    pub observed_noisy_count: u64,
}

/// One dimension and its categories in value order.
#[derive(Debug, Clone, PartialEq)]
pub struct DimensionEstimate {
    /// The dimension name.
    pub dimension: &'static str,
    /// The categories, sorted by value.
    pub values: Vec<CategoryEstimate>,
}

/// The whole summary.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    /// The exact number of stored reports.
    pub sample_count: u64,
    /// The five dimensions in storage order.
    pub dimensions: Vec<DimensionEstimate>,
}

/// The aggregate store.
#[derive(Debug, Clone)]
pub struct TelemetryStore {
    path: PathBuf,
}

/// `int(round(float(epsilon) * 1_000_000))`: Python's `round` ties to even.
pub fn epsilon_micros(epsilon: f64) -> i64 {
    (epsilon * 1_000_000.0).round_ties_even() as i64
}

impl TelemetryStore {
    /// Open or create the database and check its schema. The legacy and incompatible schemas are refused without
    /// modification.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self { path: path.as_ref().to_path_buf() };
        if let Some(parent) = store.path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        // Inspect with a plain connection first: `connect` switches the file to WAL mode, which rewrites its header,
        // and a legacy or foreign database must be left byte for byte as it was found.
        let connection = Connection::open(&store.path)?;
        connection.busy_timeout(Duration::from_millis(5000))?;
        let legacy: Option<i64> = connection
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'telemetry_events'", [], |row| row.get(0))
            .optional()?;
        if legacy.is_some() {
            return Err(StoreError::Legacy);
        }
        for (table, expected) in [("telemetry_strata", &STRATUM_COLUMNS[..]), ("telemetry_counts", &COUNT_COLUMNS[..])] {
            let existing: Option<i64> = connection
                .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |row| row.get(0))
                .optional()?;
            if existing.is_some() {
                let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
                let columns: BTreeSet<String> = statement.query_map([], |row| row.get(1))?.collect::<Result<_, _>>()?;
                if columns != expected.iter().map(|name| (*name).to_string()).collect() {
                    return Err(StoreError::Incompatible);
                }
            }
        }
        drop(connection);
        store.connect()?.execute_batch(SCHEMA)?;
        Ok(store)
    }

    /// Add one validated report to its epsilon stratum and to the five marginals, in one immediate transaction.
    pub fn record(&self, packet: &TelemetryPacket) -> Result<(), StoreError> {
        let micros = epsilon_micros(packet.privacy_epsilon);
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO telemetry_strata(epsilon_micros, sample_count) VALUES (?1, 0) ON CONFLICT(epsilon_micros) DO NOTHING",
            [micros],
        )?;
        transaction.execute("UPDATE telemetry_strata SET sample_count = sample_count + 1 WHERE epsilon_micros = ?1", [micros])?;
        for dimension in DIMENSIONS {
            transaction.execute(
                "INSERT INTO telemetry_counts(epsilon_micros, dimension, value, observed_count) VALUES (?1, ?2, ?3, 1) \
                 ON CONFLICT(epsilon_micros, dimension, value) DO UPDATE SET observed_count = observed_count + 1",
                (micros, dimension, dimension_value(packet, dimension)),
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// The debiased summary. Each epsilon stratum is inverted with its own randomised-response kernel and the
    /// per-stratum estimates are summed, then clipped to `[0, sample_count]` (post-processing that adds bias).
    pub fn summary(&self) -> Result<Summary, StoreError> {
        let connection = self.connect()?;
        let strata: Vec<(i64, i64)> = connection
            .prepare("SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let counts: Vec<(i64, String, String, i64)> = connection
            .prepare("SELECT epsilon_micros, dimension, value, observed_count FROM telemetry_counts")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?
            .collect::<Result<_, _>>()?;
        drop(connection);
        estimate(&strata, &counts)
    }

    /// Whether a write transaction can start (the `Health` probe). Rolls back immediately.
    pub fn check_writable(&self) -> Result<(), StoreError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_millis(500))?;
        connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK;")?;
        Ok(())
    }

    /// The database path, for tests and the startup log.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open(&self.path)?;
        connection.busy_timeout(Duration::from_millis(5000))?;
        connection.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        connection.execute_batch("PRAGMA foreign_keys=ON")?;
        Ok(connection)
    }
}

/// The estimator over stored strata and counts. It performs the IEEE operations of `TelemetryStore.summary` in the
/// same order, so results agree with the Python service bit for bit apart from `exp` in libm.
pub fn estimate(strata: &[(i64, i64)], counts: &[(i64, String, String, i64)]) -> Result<Summary, StoreError> {
    let mut sample_count: i64 = 0;
    for (_, samples) in strata {
        sample_count += samples;
    }
    let observed: HashMap<(i64, &str, &str), i64> =
        counts.iter().map(|(micros, dimension, value, count)| ((*micros, dimension.as_str(), value.as_str()), *count)).collect();
    let mut dimensions = Vec::with_capacity(DIMENSIONS.len());
    for dimension in DIMENSIONS {
        let domain = allowed_values(dimension);
        let mut values = Vec::with_capacity(domain.len());
        for &value in domain {
            let mut estimate = 0.0_f64;
            let mut observed_count: i64 = 0;
            let domain_size = domain.len() as f64;
            for &(micros, n) in strata {
                let epsilon = micros as f64 / 1_000_000.0;
                if !epsilon.is_finite() || !(MIN_EPSILON..=MAX_EPSILON).contains(&epsilon) {
                    return Err(StoreError::InvalidEpsilon);
                }
                let epsilon_per_dimension = epsilon / DIMENSION_EPSILON;
                let exp_epsilon = epsilon_per_dimension.exp();
                let denominator = exp_epsilon + domain_size - 1.0;
                let truthful_probability = exp_epsilon / denominator;
                let other_probability = 1.0 / denominator;
                let gap = truthful_probability - other_probability;
                let count = observed.get(&(micros, dimension, value)).copied().unwrap_or(0);
                observed_count += count;
                estimate += (count as f64 - n as f64 * other_probability) / gap;
            }
            // Python: min(float(sample_count), max(0.0, estimate)).
            let lower = if estimate > 0.0 { estimate } else { 0.0 };
            let upper = sample_count as f64;
            let clipped = if lower < upper { lower } else { upper };
            values.push(CategoryEstimate {
                value,
                estimated_count: clipped,
                observed_noisy_count: u64::try_from(observed_count).map_err(|_| StoreError::InvalidCount)?,
            });
        }
        dimensions.push(DimensionEstimate { dimension, values });
    }
    Ok(Summary { sample_count: u64::try_from(sample_count).map_err(|_| StoreError::InvalidCount)?, dimensions })
}
