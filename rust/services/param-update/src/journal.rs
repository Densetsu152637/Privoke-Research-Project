//! The persistent training-cycle journal (`training_cycles.py`): sequential head and encoder requests, each
//! publication independent. The SQLite file and its record text are the Python ones (`cycles(sequence, fingerprint,
//! state, record)`, the record written with `json.dumps(sort_keys=True)`), so a journal the Python scheduler started
//! resumes here with the same identities and seed.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::{self, Value};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::error::{Error, Result};
use crate::pyfmt::{Layout, dumps};
use crate::scheduler::FuzzerRequestConfig;

/// The two kinds of request a cycle makes, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `RunTrainingCycle`: the heads.
    Heads,
    /// `RunUnderlyingTrainingCycle`: the full encoder.
    FullEncoder,
}

impl Stage {
    /// The name in the journal.
    pub fn name(self) -> &'static str {
        match self {
            Self::Heads => "heads",
            Self::FullEncoder => "full_encoder",
        }
    }

    /// The stages a configuration trains, in order.
    pub fn sequence(train_underlying: bool) -> Vec<Self> {
        if train_underlying { vec![Self::Heads, Self::FullEncoder] } else { vec![Self::Heads] }
    }
}

/// One stage of a cycle.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StageRecord {
    /// The request id sent to the fuzzer, stable across retries and restarts.
    pub request_id: String,
    /// `pending`, `accepted` or `rejected`.
    pub state: String,
    /// The exact request bytes, fixed before the first attempt.
    pub request_protobuf_hex: Option<String>,
    /// How many physical requests were started.
    pub physical_attempts: i64,
    /// The base version the fuzzer reported.
    pub base_version: Option<String>,
    /// The version the stage published.
    pub applied_version: Option<String>,
    /// The response bytes.
    pub response_protobuf_hex: Option<String>,
    /// The last error text.
    pub last_error: Option<String>,
    /// Every attempt's error text.
    pub attempt_errors: Vec<String>,
}

/// One scheduled cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct Cycle {
    /// Position in the journal.
    pub sequence: i64,
    /// `dual-` and a random hex id.
    pub cycle_id: String,
    /// The training-settings fingerprint.
    pub fingerprint: String,
    /// The seed of this cycle's requests.
    pub seed: i64,
    /// The model.
    pub model_id: String,
    /// The requester's source id.
    pub source_id: String,
    /// `pending`, `complete`, `partial` or `rejected`.
    pub state: String,
    /// When it was reserved (seconds since the epoch).
    pub created_at: f64,
    /// When it ended.
    pub finished_at: Option<f64>,
    /// The stages in request order.
    pub stages: Vec<(String, StageRecord)>,
}

impl Cycle {
    /// The record of a stage.
    pub fn stage(&self, stage: Stage) -> Option<&StageRecord> {
        self.stages.iter().find(|(name, _)| name == stage.name()).map(|(_, record)| record)
    }

    /// Replace the record of a stage.
    pub fn set_stage(&mut self, stage: Stage, record: StageRecord) {
        if let Some(slot) = self.stages.iter_mut().find(|(name, _)| name == stage.name()) {
            slot.1 = record;
        }
    }

    /// Whether every stage was accepted.
    pub fn all_accepted(&self) -> bool {
        self.stages.iter().all(|(_, record)| record.state == "accepted")
    }

    fn to_value(&self) -> Value {
        let text = |value: &str| Value::String(value.to_string());
        let mut map = BTreeMap::new();
        map.insert("schema_version".to_string(), Value::Int("1".to_string()));
        map.insert("sequence".to_string(), Value::Int(self.sequence.to_string()));
        map.insert("cycle_id".to_string(), text(&self.cycle_id));
        map.insert("fingerprint".to_string(), text(&self.fingerprint));
        map.insert("seed".to_string(), Value::Int(self.seed.to_string()));
        map.insert("model_id".to_string(), text(&self.model_id));
        map.insert("source_id".to_string(), text(&self.source_id));
        map.insert("state".to_string(), text(&self.state));
        map.insert("created_at".to_string(), Value::Float(self.created_at));
        if let Some(finished) = self.finished_at {
            map.insert("finished_at".to_string(), Value::Float(finished));
        }
        let stages = self.stages.iter().map(|(name, record)| (name.clone(), record.to_value())).collect();
        map.insert("stages".to_string(), Value::Object(stages));
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<Self> {
        let Value::Object(map) = value else { return None };
        let string = |name: &str| match map.get(name) {
            Some(Value::String(text)) => Some(text.clone()),
            _ => None,
        };
        let integer = |name: &str| match map.get(name) {
            Some(Value::Int(digits)) => digits.parse::<i64>().ok(),
            _ => None,
        };
        let float = |name: &str| match map.get(name) {
            Some(Value::Float(number)) => Some(*number),
            Some(Value::Int(digits)) => digits.parse::<f64>().ok(),
            _ => None,
        };
        let Some(Value::Object(stage_map)) = map.get("stages") else { return None };
        let mut stages = Vec::new();
        for stage in [Stage::Heads, Stage::FullEncoder] {
            if let Some(record) = stage_map.get(stage.name()) {
                stages.push((stage.name().to_string(), StageRecord::from_value(record)?));
            }
        }
        Some(Self {
            sequence: integer("sequence")?,
            cycle_id: string("cycle_id")?,
            fingerprint: string("fingerprint")?,
            seed: integer("seed")?,
            model_id: string("model_id")?,
            source_id: string("source_id")?,
            state: string("state")?,
            created_at: float("created_at")?,
            finished_at: float("finished_at"),
            stages,
        })
    }
}

impl StageRecord {
    fn to_value(&self) -> Value {
        let text = |value: &str| Value::String(value.to_string());
        let mut map = BTreeMap::new();
        map.insert("request_id".to_string(), text(&self.request_id));
        map.insert("state".to_string(), text(&self.state));
        map.insert("physical_attempts".to_string(), Value::Int(self.physical_attempts.to_string()));
        for (key, value) in [
            ("request_protobuf_hex", &self.request_protobuf_hex),
            ("base_version", &self.base_version),
            ("applied_version", &self.applied_version),
            ("response_protobuf_hex", &self.response_protobuf_hex),
            ("last_error", &self.last_error),
        ] {
            if let Some(value) = value {
                map.insert(key.to_string(), text(value));
            }
        }
        if !self.attempt_errors.is_empty() {
            map.insert("attempt_errors".to_string(), Value::Array(self.attempt_errors.iter().map(|error| text(error)).collect()));
        }
        Value::Object(map)
    }

    fn from_value(value: &Value) -> Option<Self> {
        let Value::Object(map) = value else { return None };
        let optional = |name: &str| match map.get(name) {
            Some(Value::String(text)) => Some(text.clone()),
            _ => None,
        };
        let attempt_errors = match map.get("attempt_errors") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::String(text) => Some(text.clone()),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?,
            _ => Vec::new(),
        };
        let physical_attempts = match map.get("physical_attempts") {
            Some(Value::Int(digits)) => digits.parse::<i64>().ok()?,
            _ => 0,
        };
        Some(Self {
            request_id: optional("request_id")?,
            state: optional("state")?,
            request_protobuf_hex: optional("request_protobuf_hex"),
            physical_attempts,
            base_version: optional("base_version"),
            applied_version: optional("applied_version"),
            response_protobuf_hex: optional("response_protobuf_hex"),
            last_error: optional("last_error"),
            attempt_errors,
        })
    }
}

/// `config_fingerprint`: transport and cadence changes do not alter the training payload; training settings do, so an
/// in-flight payload that changed across a restart fails closed.
pub fn config_fingerprint(config: &FuzzerRequestConfig) -> String {
    let mut map = BTreeMap::new();
    map.insert("model_id".to_string(), Value::String(config.model_id.clone()));
    map.insert("source_id".to_string(), Value::String(config.source_id.clone()));
    map.insert("prompt_count".to_string(), Value::Int(config.prompt_count.to_string()));
    map.insert("seed".to_string(), Value::Int(config.seed.to_string()));
    map.insert("curriculum_sampler_policy".to_string(), Value::String(config.curriculum_sampler_policy.clone()));
    map.insert("curriculum_sampler_seed".to_string(), Value::Int(config.curriculum_sampler_seed.to_string()));
    map.insert("train_underlying".to_string(), Value::Bool(config.train_underlying));
    let text = dumps(&Value::Object(map), Layout::Compact).unwrap_or_default();
    sha256_hex(text.as_bytes())
}

/// The journal database.
#[derive(Debug)]
pub struct Journal {
    connection: Connection,
}

fn db(error: rusqlite::Error) -> Error {
    Error(format!("training journal: {error}"))
}

fn new_cycle(config: &FuzzerRequestConfig, fingerprint: &str, sequence: i64, now: f64) -> Cycle {
    let seed = (i128::from(config.seed) + i128::from(sequence) - 1).rem_euclid(0xFFFF_FFFF) + 1;
    let identity = format!("dual-{}", uuid::Uuid::new_v4().simple());
    let stages = Stage::sequence(config.train_underlying)
        .into_iter()
        .map(|stage| {
            (
                stage.name().to_string(),
                StageRecord { request_id: format!("{identity}-{}", stage.name()), state: "pending".to_string(), ..StageRecord::default() },
            )
        })
        .collect();
    Cycle {
        sequence,
        cycle_id: identity,
        fingerprint: fingerprint.to_string(),
        seed: i64::try_from(seed).unwrap_or(1),
        model_id: config.model_id.clone(),
        source_id: config.source_id.clone(),
        state: "pending".to_string(),
        created_at: now,
        finished_at: None,
        stages,
    }
}

impl Journal {
    /// Open or create the journal, creating its directory.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|error| Error(format!("training journal directory: {error}")))?;
        }
        let connection = Connection::open(path).map_err(db)?;
        connection.busy_timeout(Duration::from_secs(120)).map_err(db)?;
        connection.execute_batch("PRAGMA synchronous=FULL").map_err(db)?;
        connection
            .execute_batch("CREATE TABLE IF NOT EXISTS cycles (sequence INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, state TEXT NOT NULL, record TEXT NOT NULL)")
            .map_err(db)?;
        Ok(Self { connection })
    }

    /// `reserve`: the cycle to work on at time `now`, or `None` when a completed one-shot cycle with the same settings
    /// already exists. A pending cycle resumes with its original identities; one that belongs to different training
    /// settings is an error (resume its original settings first). A finished cycle with the same settings is returned
    /// until its interval has passed; after that, or when the settings changed, a new cycle with fresh identities and
    /// the next seed is created.
    pub fn reserve(&mut self, config: &FuzzerRequestConfig, now: f64) -> Result<Option<Cycle>> {
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db)?;
        let row = transaction
            .query_row("SELECT sequence, fingerprint, state, record FROM cycles ORDER BY sequence DESC LIMIT 1", [], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))
            })
            .optional()
            .map_err(db)?;
        let fingerprint = config_fingerprint(config);
        let parse = |text: &str| -> Result<Cycle> {
            let value = json::parse(text).map_err(|error| Error(format!("training journal record: {error}")))?;
            Cycle::from_value(&value).ok_or_else(|| Error("training journal record is not a cycle".to_string()))
        };
        let next_sequence = row.as_ref().map_or(0, |(sequence, ..)| sequence + 1);
        let mut resumed: Option<Option<Cycle>> = None;
        if let Some((_, row_fingerprint, state, record)) = &row {
            if state == "pending" {
                if *row_fingerprint != fingerprint {
                    return Err(Error(
                        "Pending automatic training cycle belongs to different training settings; resume its original settings first."
                            .to_string(),
                    ));
                }
                resumed = Some(Some(parse(record)?));
            } else if *row_fingerprint == fingerprint && config.interval_seconds <= 0.0 {
                // A completed one-shot stays completed on restart.
                resumed = Some(None);
            } else if *row_fingerprint == fingerprint {
                let cycle = parse(record)?;
                if now < cycle.finished_at.unwrap_or(0.0) + config.interval_seconds {
                    resumed = Some(Some(cycle));
                }
            }
        }
        let outcome = match resumed {
            Some(found) => found,
            None => {
                let cycle = new_cycle(config, &fingerprint, next_sequence, now);
                let text = dumps(&cycle.to_value(), Layout::Spaced).map_err(|error| Error(error.to_string()))?;
                transaction
                    .execute("INSERT INTO cycles VALUES (?1, ?2, ?3, ?4)", params![cycle.sequence, cycle.fingerprint, cycle.state, text])
                    .map_err(db)?;
                Some(cycle)
            }
        };
        transaction.commit().map_err(db)?;
        Ok(outcome)
    }

    /// `save`: persist a cycle's state and record.
    pub fn save(&mut self, cycle: &Cycle) -> Result<()> {
        let text = dumps(&cycle.to_value(), Layout::Spaced).map_err(|error| Error(error.to_string()))?;
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db)?;
        transaction
            .execute(
                "UPDATE cycles SET state = ?1, record = ?2 WHERE sequence = ?3 AND fingerprint = ?4",
                params![cycle.state, text, cycle.sequence, cycle.fingerprint],
            )
            .map_err(db)?;
        transaction.commit().map_err(db)
    }

    /// The newest cycle, for tests and operators.
    pub fn latest(&self) -> Result<Option<Cycle>> {
        let record = self
            .connection
            .query_row("SELECT record FROM cycles ORDER BY sequence DESC LIMIT 1", [], |row| row.get::<_, String>(0))
            .optional()
            .map_err(db)?;
        match record {
            None => Ok(None),
            Some(text) => {
                let value = json::parse(&text).map_err(|error| Error(error.to_string()))?;
                Ok(Cycle::from_value(&value))
            }
        }
    }
}
