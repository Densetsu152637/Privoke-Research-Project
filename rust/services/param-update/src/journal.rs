//! The routine-training journal (stage V3-R6 of the routine-training plan).
//!
//! The scheduler is the only allocator of `(request_id, seed, expected_base, sampler, scope, source_commitment)`. Every
//! allocation is written here, durably, **before** the fuzzer is called, so that
//!
//! * a restart finds the request it had in flight and asks the store (`GetCommitStatus`) what became of it before re-requesting;
//! * the guard gate ([`crate::v3_guard::Allocations`]) can later tell, from the same file, that a commit belongs to a request
//!   the scheduler made, on which base, in which release, at which scope and under which commitment.
//!
//! Two tables: `v3_cycles` (one routine round: a seed, the sampler of the round, its state) and `v3_allocations` (one row per
//! tier x stage request: `allocated`, then `accepted`, `rejected` or `lost`). A fit that was lost is replaced by a new row with a
//! new request id and seed (`attempt + 1`); the old row stays as the record of the loss.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};

use crate::error::{Error, Result};
use crate::v3_guard::{Allocation, Allocations};

/// The two kinds of request a round makes per tier, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `RunTrainingCycle`: the heads.
    Heads,
    /// `RunUnderlyingTrainingCycle`: the full encoder.
    FullEncoder,
}

impl Stage {
    /// The name in the journal, which is the scope name of the evidence.
    pub fn name(self) -> &'static str {
        match self {
            Self::Heads => "heads",
            Self::FullEncoder => "full_encoder",
        }
    }

    /// The stage of a journal name.
    pub fn of(name: &str) -> Option<Self> {
        [Self::Heads, Self::FullEncoder].into_iter().find(|stage| stage.name() == name)
    }
}

/// The tiers a round trains, in order.
pub const TIERS: [&str; 3] = ["efficient", "balanced", "quality"];

/// The model of a tier.
pub fn model_of(tier: &str) -> String {
    format!("privoke-v3-{tier}")
}

/// One round.
#[derive(Debug, Clone, PartialEq)]
pub struct Cycle {
    /// Position in the journal.
    pub sequence: i64,
    /// The seed of the round (each allocation derives its own from it).
    pub seed: u32,
    /// `existing_taxonomy_benign_common_frozen_stream_v1` (BC01) or `audience_common_frozen_stream_v1` (AU3).
    pub sampler: String,
    /// `pending` or `complete`.
    pub state: String,
    /// When it was reserved.
    pub created_at: f64,
    /// When it ended.
    pub finished_at: Option<f64>,
}

/// One allocation: a request the scheduler made (or is about to make) of the fuzzer.
#[derive(Debug, Clone, PartialEq)]
pub struct AllocationRow {
    /// The request id, unique for ever.
    pub request_id: String,
    /// The round.
    pub cycle: i64,
    /// `privoke-v3-<tier>`.
    pub model_id: String,
    /// The stage (scope).
    pub stage: Stage,
    /// 0 for the first request of the stage, 1 after one lost fit, and so on.
    pub attempt: i64,
    /// The frozen release the guard and the schedule come from.
    pub sampler: String,
    /// The routine seed.
    pub seed: u32,
    /// The version the store served when the request was allocated.
    pub expected_base: String,
    /// The routine commitment the scheduler computed.
    pub source_commitment: String,
    /// `allocated`, `accepted`, `rejected` or `lost`.
    pub state: String,
    /// The candidate the store applied (`accepted`) or refused (`rejected`).
    pub candidate: Option<String>,
    /// The store's reason for a refusal, or why a fit was lost.
    pub reason: Option<String>,
}

const COLUMNS: &str =
    "request_id, cycle, model_id, stage, attempt, sampler, seed, expected_base, source_commitment, state, candidate, reason";

fn db(error: rusqlite::Error) -> Error {
    Error(format!("training journal: {error}"))
}

fn allocation_of(row: &Row<'_>) -> rusqlite::Result<AllocationRow> {
    let stage: String = row.get(3)?;
    Ok(AllocationRow {
        request_id: row.get(0)?,
        cycle: row.get(1)?,
        model_id: row.get(2)?,
        stage: Stage::of(&stage).ok_or_else(|| rusqlite::Error::InvalidColumnType(3, "stage".to_string(), rusqlite::types::Type::Text))?,
        attempt: row.get(4)?,
        sampler: row.get(5)?,
        seed: u32::try_from(row.get::<_, i64>(6)?).unwrap_or_default(),
        expected_base: row.get(7)?,
        source_commitment: row.get(8)?,
        state: row.get(9)?,
        candidate: row.get(10)?,
        reason: row.get(11)?,
    })
}

fn connect(path: &Path) -> Result<Connection> {
    let connection = Connection::open(path).map_err(db)?;
    connection.busy_timeout(Duration::from_secs(120)).map_err(db)?;
    Ok(connection)
}

/// The journal database.
#[derive(Debug)]
pub struct Journal {
    connection: Connection,
}

impl Journal {
    /// Open or create the journal, creating its directory.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| Error(format!("training journal directory: {error}")))?;
        }
        let connection = connect(path)?;
        connection.execute_batch("PRAGMA synchronous=FULL").map_err(db)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS v3_cycles (
                     sequence INTEGER PRIMARY KEY, seed INTEGER NOT NULL, sampler TEXT NOT NULL, state TEXT NOT NULL,
                     created_at REAL NOT NULL, finished_at REAL);
                 CREATE TABLE IF NOT EXISTS v3_allocations (
                     request_id TEXT PRIMARY KEY, cycle INTEGER NOT NULL, model_id TEXT NOT NULL, stage TEXT NOT NULL,
                     attempt INTEGER NOT NULL, sampler TEXT NOT NULL, seed INTEGER NOT NULL, expected_base TEXT NOT NULL,
                     source_commitment TEXT NOT NULL, state TEXT NOT NULL, candidate TEXT, reason TEXT);",
            )
            .map_err(db)?;
        Ok(Self { connection })
    }

    /// The round to work on at time `now`: the pending one (resumed with its identities), else, when the last one finished and
    /// `interval` seconds have passed (or none ever existed), a new one at the next seed with the next sampler of `samplers`
    /// (alternating by sequence). `None` for a one-shot (`interval <= 0`) whose round is complete.
    pub fn reserve(&mut self, base_seed: u32, samplers: &[&str], interval: f64, now: f64) -> Result<Option<Cycle>> {
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db)?;
        let latest = transaction
            .query_row(
                "SELECT sequence, seed, sampler, state, created_at, finished_at FROM v3_cycles ORDER BY sequence DESC LIMIT 1",
                [],
                |row| {
                    Ok(Cycle {
                        sequence: row.get(0)?,
                        seed: u32::try_from(row.get::<_, i64>(1)?).unwrap_or_default(),
                        sampler: row.get(2)?,
                        state: row.get(3)?,
                        created_at: row.get(4)?,
                        finished_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(db)?;
        let outcome = match latest {
            Some(cycle) if cycle.state == "pending" => Some(cycle),
            Some(_) if interval <= 0.0 => None,
            Some(cycle) if now < cycle.finished_at.unwrap_or(0.0) + interval => Some(cycle),
            other => {
                let sequence = other.map_or(0, |cycle| cycle.sequence + 1);
                let seed = u32::try_from((i128::from(base_seed) + i128::from(sequence) * 7919).rem_euclid(0xFFFF_FFFF) + 1).unwrap_or(1);
                let sampler = samplers[usize::try_from(sequence).unwrap_or(0) % samplers.len()].to_string();
                transaction
                    .execute(
                        "INSERT INTO v3_cycles (sequence, seed, sampler, state, created_at) VALUES (?1, ?2, ?3, 'pending', ?4)",
                        params![sequence, i64::from(seed), sampler, now],
                    )
                    .map_err(db)?;
                Some(Cycle { sequence, seed, sampler, state: "pending".to_string(), created_at: now, finished_at: None })
            }
        };
        transaction.commit().map_err(db)?;
        Ok(outcome)
    }

    /// Mark a round complete.
    pub fn finish(&mut self, cycle: &Cycle, now: f64) -> Result<()> {
        self.connection
            .execute("UPDATE v3_cycles SET state='complete', finished_at=?1 WHERE sequence=?2", params![now, cycle.sequence])
            .map_err(db)?;
        Ok(())
    }

    /// The allocations of a round, oldest first.
    pub fn allocations(&self, cycle: i64) -> Result<Vec<AllocationRow>> {
        let mut statement =
            self.connection.prepare(&format!("SELECT {COLUMNS} FROM v3_allocations WHERE cycle=?1 ORDER BY rowid")).map_err(db)?;
        let rows = statement.query_map(params![cycle], allocation_of).map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    /// Record an allocation (durably, before the request is made).
    pub fn allocate(&mut self, row: &AllocationRow) -> Result<()> {
        self.connection
            .execute(
                &format!("INSERT INTO v3_allocations ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"),
                params![
                    row.request_id,
                    row.cycle,
                    row.model_id,
                    row.stage.name(),
                    row.attempt,
                    row.sampler,
                    i64::from(row.seed),
                    row.expected_base,
                    row.source_commitment,
                    row.state,
                    row.candidate,
                    row.reason
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Record how a request ended.
    pub fn settle(&mut self, request_id: &str, state: &str, candidate: Option<&str>, reason: Option<&str>) -> Result<()> {
        self.connection
            .execute(
                "UPDATE v3_allocations SET state=?1, candidate=?2, reason=?3 WHERE request_id=?4",
                params![state, candidate, reason, request_id],
            )
            .map_err(db)?;
        Ok(())
    }
}

/// The allocations as the guard gate reads them: the journal file, opened per lookup (the scheduler writes it from another
/// connection; SQLite serialises the two).
#[derive(Debug, Clone)]
pub struct JournalAllocations {
    path: PathBuf,
}

impl JournalAllocations {
    /// The allocations recorded in the journal at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Allocations for JournalAllocations {
    fn allocation(&self, request_id: &str, model_id: &str) -> Option<Allocation> {
        let connection = connect(&self.path).ok()?;
        let row = connection
            .query_row(
                &format!("SELECT {COLUMNS} FROM v3_allocations WHERE request_id=?1 AND model_id=?2"),
                params![request_id, model_id],
                allocation_of,
            )
            .optional()
            .ok()??;
        Some(Allocation {
            sampler: row.sampler,
            scope: row.stage.name().to_string(),
            seed: u64::from(row.seed),
            source_commitment: row.source_commitment,
            expected_base: row.expected_base,
        })
    }
}
