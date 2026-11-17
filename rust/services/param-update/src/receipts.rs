//! Durable update receipts (`receipts.py`), recovered from the atomically committed model.
//!
//! The model stores its latest receipt in the same rename as the weights. Before any later update, that receipt is
//! reconciled into SQLite. This closes the crash window between publishing weights and recording the RPC outcome
//! without keeping a growing receipt history in the streamed artifact. The SQLite file is the Python one: the same
//! name (`<audit path>.receipts.sqlite3`), table, row layout and `BEGIN IMMEDIATE` writer lock, so a database the
//! Python service wrote opens here and the two exclude each other.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privoke_contracts::digest::{receipt_key, sha256_hex};
use privoke_contracts::json::{self, Value};
use privoke_contracts::proto::v1::ParameterUpdateRequest;
use privoke_model_streaming::artifact::ModelArtifact;
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Failure;
use crate::pyfmt::{Layout, dumps, py_int};

/// The artifact metadata key that holds the latest receipt.
pub const RECEIPT_METADATA_KEY: &str = "last_update_receipt";
/// The artifact metadata key that holds the latest drift record when the drift policy is enforced.
pub const DRIFT_METADATA_KEY: &str = "update_drift_v1";

/// One update outcome. The seven fields and their text are the Python receipt's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// `receipt_key(source_id, request_id, request_source_id)`.
    pub key: String,
    /// SHA-256 of the request's deterministic protobuf encoding.
    pub payload_digest: String,
    /// `training_request_fingerprint` metadata, or empty.
    pub request_fingerprint: String,
    /// The model the update applied to.
    pub model_id: String,
    /// The version the request was built on.
    pub base_version: String,
    /// The version it produced.
    pub applied_version: String,
    /// `generated_prompt_count` metadata, or zero.
    pub prompts_generated: i64,
}

impl Receipt {
    /// The receipt of `request` once it produced `applied_version`; `None` for a request without a `request_id`.
    pub fn for_request(request: &ParameterUpdateRequest, applied_version: &str) -> Result<Option<Self>, Failure> {
        let request_id = request.metadata.get("request_id").map(String::as_str).unwrap_or_default();
        if request_id.is_empty() {
            return Ok(None);
        }
        let source = request.metadata.get("request_source_id").map(String::as_str).unwrap_or_default();
        let key = receipt_key(&request.source_id, request_id, source).map_err(|error| Failure::invalid(error.to_string()))?;
        let prompts = request.metadata.get("generated_prompt_count").map_or(Some(0), |text| py_int(text));
        let prompts_generated = prompts
            .and_then(|count| i64::try_from(count).ok())
            .ok_or_else(|| Failure::invalid("generated_prompt_count must be an integer."))?;
        Ok(Some(Self {
            key,
            payload_digest: payload_digest(request),
            request_fingerprint: request.metadata.get("training_request_fingerprint").cloned().unwrap_or_default(),
            model_id: request.model_id.clone(),
            base_version: request.base_version.clone(),
            applied_version: applied_version.to_string(),
            prompts_generated,
        }))
    }

    /// The receipt as a JSON object.
    pub fn to_value(&self) -> Value {
        let text = |value: &str| Value::String(value.to_string());
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), text(&self.key));
        map.insert("payload_digest".to_string(), text(&self.payload_digest));
        map.insert("request_fingerprint".to_string(), text(&self.request_fingerprint));
        map.insert("model_id".to_string(), text(&self.model_id));
        map.insert("base_version".to_string(), text(&self.base_version));
        map.insert("applied_version".to_string(), text(&self.applied_version));
        map.insert("prompts_generated".to_string(), Value::Int(self.prompts_generated.to_string()));
        Value::Object(map)
    }

    /// `json.dumps(receipt, sort_keys=True, separators=(",", ":"))`.
    pub fn to_json(&self) -> Result<String, Failure> {
        dumps(&self.to_value(), Layout::Compact).map_err(Failure::persistence)
    }

    /// Parse the stored or embedded text. `None` for anything that is not exactly the seven-field receipt.
    pub fn parse(text: &str) -> Option<Self> {
        let Value::Object(map) = json::parse(text).ok()? else { return None };
        if map.len() != 7 {
            return None;
        }
        let string = |name: &str| match map.get(name) {
            Some(Value::String(value)) => Some(value.clone()),
            _ => None,
        };
        let prompts_generated = match map.get("prompts_generated") {
            Some(Value::Int(digits)) => digits.parse::<i64>().ok()?,
            _ => return None,
        };
        Some(Self {
            key: string("key")?,
            payload_digest: string("payload_digest")?,
            request_fingerprint: string("request_fingerprint")?,
            model_id: string("model_id")?,
            base_version: string("base_version")?,
            applied_version: string("applied_version")?,
            prompts_generated,
        })
    }
}

/// SHA-256 of the request's deterministic protobuf encoding (map entries in key order).
pub fn payload_digest(request: &ParameterUpdateRequest) -> String {
    sha256_hex(&request.encode_to_vec())
}

/// The latest drift record of an enforced drift policy, kept in the artifact so that it commits with the weights.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftRecord {
    /// The release the budget is measured from (`release_version`).
    pub anchor: String,
    /// The L2 norm of the update that produced this version.
    pub update_l2: f64,
    /// The running total for the anchor after this update.
    pub cumulative_l2: f64,
}

impl DriftRecord {
    /// The record as artifact metadata text.
    pub fn to_json(&self) -> Result<String, Failure> {
        let mut map = BTreeMap::new();
        map.insert("anchor".to_string(), Value::String(self.anchor.clone()));
        map.insert("cumulative_l2".to_string(), Value::Float(self.cumulative_l2));
        map.insert("update_l2".to_string(), Value::Float(self.update_l2));
        dumps(&Value::Object(map), Layout::Compact).map_err(Failure::persistence)
    }

    /// Parse the metadata text; `None` unless it is exactly the three fields with finite, non-negative numbers.
    pub fn parse(text: &str) -> Option<Self> {
        let Value::Object(map) = json::parse(text).ok()? else { return None };
        if map.len() != 3 {
            return None;
        }
        let number = |name: &str| match map.get(name) {
            Some(Value::Float(value)) if value.is_finite() && *value >= 0.0 => Some(*value),
            Some(Value::Int(digits)) => digits.parse::<f64>().ok().filter(|value| value.is_finite() && *value >= 0.0),
            _ => None,
        };
        let anchor = match map.get("anchor") {
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            _ => return None,
        };
        Some(Self { anchor, update_l2: number("update_l2")?, cumulative_l2: number("cumulative_l2")? })
    }
}

/// The path of the receipt database for an audit path.
pub fn receipts_path(audit_path: &Path) -> PathBuf {
    let mut name = audit_path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
    name.push(".receipts.sqlite3");
    audit_path.with_file_name(name)
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(path).map(drop)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path).map(drop)
}

/// The receipt database inside one `BEGIN IMMEDIATE` transaction. That transaction is also the cross-process model
/// writer lock. Dropping the store without [`commit`](Self::commit) rolls back.
#[derive(Debug)]
pub struct ReceiptStore {
    connection: Connection,
    open: bool,
}

impl ReceiptStore {
    /// Open (creating at mode 0600) and begin the writer transaction. A symbolic link is refused.
    pub fn begin(audit_path: &Path) -> Result<Self, Failure> {
        let path = receipts_path(audit_path);
        if std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(Failure::persistence("Update receipt database must not be a symbolic link."));
        }
        create_private(&path)?;
        let connection = Connection::open(&path)?;
        connection.busy_timeout(Duration::from_secs(10))?;
        connection.execute_batch("PRAGMA synchronous=FULL")?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS update_receipts (key TEXT PRIMARY KEY, receipt TEXT NOT NULL)")?;
        connection.execute_batch("BEGIN IMMEDIATE")?;
        Ok(Self { connection, open: true })
    }

    /// `COMMIT`.
    pub fn commit(&mut self) -> Result<(), Failure> {
        if self.open {
            self.open = false;
            self.connection.execute_batch("COMMIT")?;
        }
        Ok(())
    }

    /// `ROLLBACK`, ignoring a failure (the connection is dropped next).
    pub fn rollback(&mut self) {
        if self.open {
            self.open = false;
            let _ = self.connection.execute_batch("ROLLBACK");
        }
    }

    /// The receipt stored under `key`.
    pub fn get(&self, key: &str) -> Result<Option<Receipt>, Failure> {
        let row = self
            .connection
            .query_row("SELECT receipt FROM update_receipts WHERE key = ?1", params![key], |row| row.get::<_, String>(0))
            .optional()?;
        match row {
            None => Ok(None),
            Some(text) => Receipt::parse(&text).map(Some).ok_or_else(|| Failure::persistence("stored update receipt is not valid")),
        }
    }

    /// Reconcile the receipt committed with the model into the database. `true` when it was not there yet.
    pub fn recover(&mut self, artifact: &ModelArtifact) -> Result<bool, Failure> {
        let Some(raw) = artifact.metadata().get(RECEIPT_METADATA_KEY).filter(|raw| !raw.is_empty()) else { return Ok(false) };
        let invalid = || Failure::invalid("Committed model update receipt is invalid.");
        let receipt = Receipt::parse(raw).ok_or_else(invalid)?;
        if receipt.model_id != artifact.model_id || receipt.applied_version != artifact.version {
            return Err(invalid());
        }
        let missing = self.get(&receipt.key)?.is_none();
        self.put(&receipt)?;
        Ok(missing)
    }

    /// Durably record an older outcome before replacing its recovery marker. Callers must reload the artifact
    /// afterwards, since another process may have published across the transaction boundary.
    pub fn checkpoint(&mut self) -> Result<(), Failure> {
        self.connection.execute_batch("COMMIT")?;
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        Ok(())
    }

    /// Record `receipt`; an existing different receipt under the same key is a conflict.
    pub fn put(&mut self, receipt: &Receipt) -> Result<(), Failure> {
        if let Some(existing) = self.get(&receipt.key)?
            && existing != *receipt
        {
            return Err(Failure::invalid("Update receipt conflicts with an existing request."));
        }
        let text = receipt.to_json()?;
        self.connection.execute("INSERT OR IGNORE INTO update_receipts(key, receipt) VALUES (?1, ?2)", params![receipt.key, text])?;
        Ok(())
    }

    /// Every stored receipt ordered by key, for tests and audits.
    pub fn all(&self) -> Result<Vec<(String, String)>, Failure> {
        let mut statement = self.connection.prepare("SELECT key, receipt FROM update_receipts ORDER BY key")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    fn ensure_drift_table(&self) -> Result<(), Failure> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS drift_budget (anchor TEXT PRIMARY KEY, cumulative_l2 REAL NOT NULL)")?;
        Ok(())
    }

    /// The running L2 total of `anchor` (zero before the first accepted update).
    pub fn drift_total(&self, anchor: &str) -> Result<f64, Failure> {
        self.ensure_drift_table()?;
        let total = self
            .connection
            .query_row("SELECT cumulative_l2 FROM drift_budget WHERE anchor = ?1", params![anchor], |row| row.get::<_, f64>(0))
            .optional()?;
        Ok(total.unwrap_or(0.0))
    }

    /// Raise the total of `anchor` to at least `cumulative_l2`. Idempotent, so reconciling the record committed with
    /// the model after an interrupted publication cannot double-count.
    pub fn raise_drift(&mut self, anchor: &str, cumulative_l2: f64) -> Result<(), Failure> {
        self.ensure_drift_table()?;
        self.connection.execute(
            "INSERT INTO drift_budget(anchor, cumulative_l2) VALUES (?1, ?2) \
             ON CONFLICT(anchor) DO UPDATE SET cumulative_l2 = MAX(cumulative_l2, excluded.cumulative_l2)",
            params![anchor, cumulative_l2],
        )?;
        Ok(())
    }
}

impl Drop for ReceiptStore {
    fn drop(&mut self) {
        self.rollback();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn receipts_round_trip_in_the_python_text() {
        let receipt = Receipt {
            key: "a".repeat(64),
            payload_digest: "b".repeat(64),
            request_fingerprint: "fp".into(),
            model_id: "m".into(),
            base_version: "v1".into(),
            applied_version: "v1+train.1".into(),
            prompts_generated: 32,
        };
        let text = receipt.to_json().unwrap();
        assert!(text.starts_with(r#"{"applied_version":"v1+train.1","base_version":"v1","key":"#));
        assert!(text.contains("\"prompts_generated\":32"));
        assert_eq!(Receipt::parse(&text), Some(receipt));
        assert_eq!(Receipt::parse(r#"{"key":"x"}"#), None);
    }

    #[test]
    fn the_receipt_database_name_matches_python() {
        assert_eq!(receipts_path(Path::new("/data/updates.jsonl")), PathBuf::from("/data/updates.jsonl.receipts.sqlite3"));
    }

    #[test]
    fn drift_records_round_trip() {
        let record = DriftRecord { anchor: "v0.4.0".into(), update_l2: 0.25, cumulative_l2: 1.5 };
        let text = record.to_json().unwrap();
        assert_eq!(text, r#"{"anchor":"v0.4.0","cumulative_l2":1.5,"update_l2":0.25}"#);
        assert_eq!(DriftRecord::parse(&text), Some(record));
        assert_eq!(DriftRecord::parse(r#"{"anchor":"","cumulative_l2":1.5,"update_l2":0.25}"#), None);
    }

    #[test]
    fn the_store_conflicts_and_rolls_back() {
        let directory = tempfile::tempdir().unwrap();
        let audit = directory.path().join("updates.jsonl");
        let receipt = |digest: &str| Receipt {
            key: "k".repeat(64),
            payload_digest: digest.repeat(64),
            request_fingerprint: String::new(),
            model_id: "m".into(),
            base_version: "v1".into(),
            applied_version: "v1+train.1".into(),
            prompts_generated: 0,
        };
        let mut store = ReceiptStore::begin(&audit).unwrap();
        store.put(&receipt("a")).unwrap();
        store.put(&receipt("a")).unwrap();
        assert!(store.put(&receipt("b")).is_err());
        drop(store); // not committed
        let mut store = ReceiptStore::begin(&audit).unwrap();
        assert!(store.get(&"k".repeat(64)).unwrap().is_none());
        store.put(&receipt("a")).unwrap();
        store.raise_drift("v1", 2.0).unwrap();
        store.raise_drift("v1", 1.0).unwrap();
        assert!((store.drift_total("v1").unwrap() - 2.0).abs() < 1e-12);
        store.commit().unwrap();
        let store = ReceiptStore::begin(&audit).unwrap();
        assert_eq!(store.all().unwrap().len(), 1);
    }
}
