//! `training/evidence.py`: durable reservations and the complete cycle record of generated training cycles.
//!
//! The directory layout, the SQLite reservation table and the JSON records are the Python service's, so evidence of
//! either implementation can be read by the other. Records are written whole to a temporary file in the same directory,
//! flushed, renamed over the final name and the directory is flushed, so a reader sees a complete record or none.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use privoke_contracts::proto::v1::{FuzzerTrainingRequest, ParameterUpdateAck, ParameterUpdateStatus};
use privoke_curriculum::value::{self, Value};
use rusqlite::{Connection, OptionalExtension};

use crate::error::{Error, Result, invalid};
use crate::runtime::BatchUpdate;

const DURABLE_DUMP_REQUIRED: &str = "Automatic dual training requires durable PRIVOKE_FUZZER_DUMP_DIR.";

fn requires_dump(request: &FuzzerTrainingRequest) -> bool {
    request.metadata.get("require_full_capability").map(String::as_str) == Some("true")
}

/// `cycle_identity(request, stage)`: the SHA-256 of the compact JSON of `[stage, source_id, request_id]`.
pub fn cycle_identity(request: &FuzzerTrainingRequest, stage: &str) -> Result<String> {
    let identity = value::strings(&[stage, request.source_id.as_str(), request.request_id.as_str()]);
    Ok(value::sha256(value::dumps_compact(&identity)?.as_bytes()))
}

/// `reserve_training_request`: bind the cycle identity to the fingerprint of its effective settings and data.
pub fn reserve_training_request(directory: Option<&Path>, request: &FuzzerTrainingRequest, stage: &str, fingerprint: &str) -> Result<()> {
    let Some(directory) = directory else {
        return if requires_dump(request) { invalid(DURABLE_DUMP_REQUIRED) } else { Ok(()) };
    };
    std::fs::create_dir_all(directory)?;
    let connection = Connection::open(directory.join("training-reservations.sqlite3"))?;
    connection.busy_timeout(Duration::from_secs(30))?;
    connection.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS requests (identity TEXT PRIMARY KEY, fingerprint TEXT NOT NULL); BEGIN IMMEDIATE;")?;
    let identity = cycle_identity(request, stage)?;
    let existing: Option<String> =
        connection.query_row("SELECT fingerprint FROM requests WHERE identity=?1", [identity.as_str()], |row| row.get(0)).optional()?;
    if existing.as_deref().is_some_and(|stored| stored != fingerprint) {
        // Dropping the connection rolls the open transaction back.
        return invalid("request_id belongs to different effective training settings or data.");
    }
    connection.execute("INSERT OR IGNORE INTO requests VALUES (?1, ?2)", (identity.as_str(), fingerprint))?;
    connection.execute_batch("COMMIT")?;
    Ok(())
}

fn string_object(map: &BTreeMap<String, String>) -> Value {
    value::from_string_map(map)
}

fn ack_value(ack: &ParameterUpdateAck) -> Value {
    value::object(vec![
        ("accepted", Value::Bool(ack.accepted)),
        ("model_id", value::string(&ack.model_id)),
        ("applied_version", value::string(&ack.applied_version)),
        ("message", value::string(&ack.message)),
    ])
}

fn flush_directory(directory: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

/// `json.dump(record, sort_keys=True, allow_nan=False)` plus a newline, committed atomically.
pub fn write_atomic(path: &Path, record: &Value) -> Result<()> {
    let parent = path.parent().ok_or_else(|| Error(format!("{} has no parent directory.", path.display())))?;
    let mut text = value::dumps(record)?;
    text.push('\n');
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_nanos());
    let temporary: PathBuf = parent.join(format!(".{}-{unique}.tmp", std::process::id()));
    let outcome = commit(&temporary, path, parent, &text);
    if outcome.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    outcome.map_err(Error::from)
}

fn commit(temporary: &Path, path: &Path, parent: &Path, text: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(temporary)?;
    file.write_all(text.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    flush_directory(parent)
}

/// `recover_cycle_evidence_ack`: a lost acknowledgement is restored from the updater's receipt.
pub fn recover_cycle_evidence_ack(
    directory: Option<&Path>,
    request: &FuzzerTrainingRequest,
    stage: &str,
    previous: &ParameterUpdateStatus,
) -> Result<()> {
    let Some(directory) = directory else { return Ok(()) };
    let parent = directory.join("training-cycles").join(cycle_identity(request, stage)?);
    if !parent.exists() {
        return Ok(());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&parent)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
        .collect();
    files.sort();
    let ack = previous.ack.clone().unwrap_or_default();
    for path in files {
        let mut record = value::parse_bytes(&std::fs::read(&path)?)?;
        if value::get(&record, "base_version").and_then(value::as_str) == Some(previous.base_version.as_str())
            && let Value::Object(map) = &mut record
        {
            map.insert("ack".to_string(), ack_value(&ack));
            map.insert("ack_source".to_string(), value::string("updater_receipt"));
            write_atomic(&path, &record)?;
        }
    }
    Ok(())
}

/// `persist_cycle_evidence(request, update, stage, gate_passed=, ack=)`.
pub fn persist_cycle_evidence(
    directory: Option<&Path>,
    request: &FuzzerTrainingRequest,
    update: &BatchUpdate,
    stage: &str,
    gate_passed: bool,
    ack: Option<&ParameterUpdateAck>,
) -> Result<()> {
    let Some(directory) = directory else {
        return if requires_dump(request) { invalid(DURABLE_DUMP_REQUIRED) } else { Ok(()) };
    };
    let parent = directory.join("training-cycles").join(cycle_identity(request, stage)?);
    std::fs::create_dir_all(&parent)?;
    let base_fingerprint =
        update.metadata.get("base_parameter_fingerprint").ok_or_else(|| Error("'base_parameter_fingerprint'".to_string()))?;
    let path = parent.join(format!("{base_fingerprint}.json"));
    let original_source = request.metadata.get("original_request_source_id").unwrap_or(&request.source_id);
    let mut record = value::object(vec![
        ("schema_version", value::int(1)),
        ("training_stage", value::string(stage)),
        ("request_id", value::string(&request.request_id)),
        ("source_id", value::string(&request.source_id)),
        ("original_source_id", value::string(original_source)),
        ("model_id", value::string(&update.model_id)),
        ("base_version", value::string(&update.base_version)),
        ("metadata", string_object(&update.metadata)),
        ("metrics", Value::Object(update.metrics.iter().map(|(key, number)| (key.clone(), Value::Float(*number))).collect())),
        ("execution_evidence", update.execution_evidence.clone()),
        ("gate_passed", Value::Bool(gate_passed)),
    ]);
    if let (Some(ack), Value::Object(map)) = (ack, &mut record) {
        map.insert("ack".to_string(), ack_value(ack));
    }
    write_atomic(&path, &record)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request(id: &str) -> FuzzerTrainingRequest {
        FuzzerTrainingRequest { request_id: id.into(), source_id: "source".into(), ..FuzzerTrainingRequest::default() }
    }

    #[test]
    fn identity_is_the_hash_of_the_compact_json_triple() {
        let identity = cycle_identity(&request("r"), "heads").unwrap();
        assert_eq!(identity, value::sha256(br#"["heads","source","r"]"#));
    }

    #[test]
    fn a_request_id_keeps_the_fingerprint_it_was_reserved_with() {
        let directory = tempfile::tempdir().unwrap();
        reserve_training_request(Some(directory.path()), &request("r"), "heads", "one").unwrap();
        reserve_training_request(Some(directory.path()), &request("r"), "heads", "one").unwrap();
        let error = reserve_training_request(Some(directory.path()), &request("r"), "heads", "two").unwrap_err();
        assert_eq!(error.0, "request_id belongs to different effective training settings or data.");
        reserve_training_request(Some(directory.path()), &request("r"), "full_encoder", "two").unwrap();
    }

    #[test]
    fn without_a_dump_directory_only_the_dual_cycle_is_refused() {
        assert!(reserve_training_request(None, &request("r"), "heads", "one").is_ok());
        let mut dual = request("r");
        dual.metadata.insert("require_full_capability".into(), "true".into());
        assert_eq!(reserve_training_request(None, &dual, "heads", "one").unwrap_err().0, DURABLE_DUMP_REQUIRED);
    }

    fn update() -> BatchUpdate {
        BatchUpdate {
            model_id: "m".into(),
            base_version: "v1".into(),
            gradients: Vec::new(),
            shapes: BTreeMap::new(),
            metrics: BTreeMap::from([("exact_match_rate".to_string(), 0.5), ("examples".to_string(), 64.0)]),
            metadata: BTreeMap::from([("base_parameter_fingerprint".to_string(), "ab".repeat(32))]),
            execution_evidence: value::object(vec![("rpc", value::string("ComputeSemanticGradients"))]),
        }
    }

    #[test]
    fn a_record_is_written_whole_then_gains_its_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let cycle = request("r");
        persist_cycle_evidence(Some(directory.path()), &cycle, &update(), "heads", true, None).unwrap();
        let path = directory
            .path()
            .join("training-cycles")
            .join(cycle_identity(&cycle, "heads").unwrap())
            .join(format!("{}.json", "ab".repeat(32)));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("}\n"));
        assert!(text.contains("\"metrics\": {\"exact_match_rate\": 0.5, \"examples\": 64.0}"));
        assert!(!text.contains("\"ack\""));
        let ack = ParameterUpdateAck { accepted: true, model_id: "m".into(), applied_version: "v2".into(), message: String::new() };
        persist_cycle_evidence(Some(directory.path()), &cycle, &update(), "heads", true, Some(&ack)).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"applied_version\": \"v2\""));
        let leftovers = std::fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "no temporary file remains");
    }

    #[test]
    fn recovery_restores_the_receipt_acknowledgement() {
        let directory = tempfile::tempdir().unwrap();
        let cycle = request("r");
        persist_cycle_evidence(Some(directory.path()), &cycle, &update(), "heads", true, None).unwrap();
        let ack = ParameterUpdateAck { accepted: true, model_id: "m".into(), applied_version: "v9".into(), message: "ok".into() };
        let status = ParameterUpdateStatus { found: true, ack: Some(ack), base_version: "v1".into(), prompts_generated: 64 };
        recover_cycle_evidence_ack(Some(directory.path()), &cycle, "heads", &status).unwrap();
        let path = directory
            .path()
            .join("training-cycles")
            .join(cycle_identity(&cycle, "heads").unwrap())
            .join(format!("{}.json", "ab".repeat(32)));
        let text = std::fs::read_to_string(path).unwrap();
        assert!(text.contains("\"ack_source\": \"updater_receipt\""));
        assert!(text.contains("\"applied_version\": \"v9\""));
    }
}
