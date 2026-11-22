//! The physical-attempt evidence of `training/evidence.py` and `training/full_adam_evidence.py`: the exclusive reservation of a
//! policy-admitted runtime call, the immutable record of the call and its response (written before the response is
//! admitted), the verdict of the admission, and the record of a reservation that was refused.
//!
//! Records are immutable: each is written to a temporary file in `<parent>/attempts/`, flushed, and linked under a nanosecond
//! timestamp name, so an existing record is never replaced. The layout and the JSON are the Python service's.

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use privoke_contracts::proto::v1::{ComputeSemanticGradientsRequest, ComputeSemanticGradientsResponse};
use privoke_curriculum::value::{self, Value};
use prost::Message;

use crate::policy::{ADMISSION_HEADER, Expectations};
use crate::runtime::{full_encoder_tensor_shapes, head_names};

/// Why an evidence operation failed: Python's `ValueError` (a contract failure) or `OSError` (the disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `ValueError`.
    Value(String),
    /// `OSError`: the exception class name and its message.
    Os(&'static str, String),
}

impl Failure {
    /// The exception class name Python records.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Value(_) => "ValueError",
            Self::Os(name, _) => name,
        }
    }

    /// `str(exception)`.
    pub fn message(&self) -> &str {
        match self {
            Self::Value(message) | Self::Os(_, message) => message,
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        let name = if error.kind() == std::io::ErrorKind::AlreadyExists { "FileExistsError" } else { "OSError" };
        Self::Os(name, error.to_string())
    }
}

impl From<crate::error::Error> for Failure {
    fn from(error: crate::error::Error) -> Self {
        Self::Value(error.0)
    }
}

impl From<privoke_curriculum::Error> for Failure {
    fn from(error: privoke_curriculum::Error) -> Self {
        Self::Value(error.to_string())
    }
}

/// The class and message of the exception an admission recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded<'a> {
    /// `type(error).__name__`.
    pub type_name: &'a str,
    /// `str(error)`.
    pub message: &'a str,
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn truncated(message: &str) -> String {
    message.chars().take(512).collect()
}

fn nanoseconds() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_nanos())
}

/// Write the temporary file, flush it, and link it under its final name.
fn commit_link(temporary: &Path, path: &Path, text: &str) -> std::io::Result<()> {
    let mut file = std::fs::File::create(temporary)?;
    file.write_all(text.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    // A hard link fails when the final name exists, so a collision never erases a prior attempt.
    std::fs::hard_link(temporary, path)
}

/// `_write_presence_attempt(parent, record)`: commit complete immutable JSON under `<parent>/attempts/<ns>.json`.
pub fn write_attempt(parent: &Path, record: &Value) -> Result<PathBuf, Failure> {
    let mut text = value::dumps(record)?;
    text.push('\n');
    let attempts = parent.join("attempts");
    std::fs::create_dir_all(&attempts)?;
    let stamp = nanoseconds();
    let path = attempts.join(format!("{stamp}.json"));
    let temporary = attempts.join(format!(".{}-{stamp}.tmp", std::process::id()));
    let outcome = commit_link(&temporary, &path, &text);
    let _ = std::fs::remove_file(&temporary);
    outcome?;
    Ok(path)
}

/// The invocation metadata as Python records it: `[[name, value]]`.
pub fn invocation_value(header: &str) -> Value {
    Value::Array(vec![Value::Array(vec![value::string(ADMISSION_HEADER), value::string(header)])])
}

/// `canonical(header)` of a physical attempt's identity: the compact JSON of the invocation pairs.
fn identity(request: &ComputeSemanticGradientsRequest, header: &str) -> Result<(Vec<u8>, String), Failure> {
    let wire = request.encode_to_vec();
    let mut bytes = wire.clone();
    bytes.extend_from_slice(value::dumps_compact(&invocation_value(header))?.as_bytes());
    Ok((wire, value::sha256(&bytes)))
}

/// `reserve_physical_attempt(request, header, directory)`: fail closed on a repeated physical request, crash and unknown
/// outcomes included. The exclusive creation of `started.json` is the reservation.
pub fn reserve_physical_attempt(
    request: &ComputeSemanticGradientsRequest,
    header: &str,
    directory: Option<&Path>,
) -> Result<PathBuf, Failure> {
    let Some(directory) = directory else {
        return Err(Failure::Value("FULL Adam requires durable physical attempt reservation.".to_string()));
    };
    let (wire, identity) = identity(request, header)?;
    let path = directory.join("full-adam-runtime").join(&identity).join("started.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let record = value::object(vec![
        ("schema", value::int(1)),
        ("request_sha256", value::string(&value::sha256(&wire))),
        ("invocation_metadata", invocation_value(header)),
        ("status", value::string("reserved_outcome_unknown_until_durable_response")),
    ]);
    let text = value::dumps_compact(&record)?;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    file.write_all(text.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    Ok(path)
}

/// `persist_reservation_rejection`: a rejected local reservation is zero RPC work; the original outcome stays unknown.
pub fn persist_reservation_rejection(
    request: &ComputeSemanticGradientsRequest,
    header: &str,
    directory: Option<&Path>,
    error: &Failure,
) -> Result<PathBuf, Failure> {
    let directory = directory.ok_or_else(|| Failure::Value("FULL Adam requires durable physical attempt reservation.".to_string()))?;
    let (wire, identity) = identity(request, header)?;
    let record = value::object(vec![
        ("schema", value::int(1)),
        ("compute_status", value::string("reservation_rejected_no_rpc")),
        ("rpc_calls", value::int(0)),
        ("request_sha256", value::string(&value::sha256(&wire))),
        ("invocation_metadata", invocation_value(header)),
        ("error_type", value::string(error.type_name())),
        ("prior_attempt_outcome", value::string("unchanged_unknown_no_replay")),
    ]);
    write_attempt(&directory.join("full-adam-runtime").join(identity).join("reservation-rejections"), &record)
}

fn directory_required(directory: Option<&Path>, message: &str) -> Result<PathBuf, Failure> {
    directory.map(Path::to_path_buf).ok_or_else(|| Failure::Value(message.to_string()))
}

/// `persist_policy_attempt`: immutable physical RPC evidence of a policy cycle without an admission header, including
/// unadmitted and unknown outcomes.
pub fn persist_policy_attempt(
    directory: Option<&Path>,
    request: &ComputeSemanticGradientsRequest,
    response: Option<&ComputeSemanticGradientsResponse>,
    scope: &str,
    expectations: &Expectations,
    error: Option<&Recorded<'_>>,
) -> Result<PathBuf, Failure> {
    let directory = directory_required(directory, "Training policy attempts require durable PRIVOKE_FUZZER_DUMP_DIR.")?;
    let wire = request.encode_to_vec();
    let digest = value::sha256(&wire);
    let described = error.map(|error| {
        if error.type_name == "ValueError" || error.type_name == "RuntimeAnalysisError" {
            truncated(error.message)
        } else {
            "Runtime transport failed; execution outcome unknown.".to_string()
        }
    });
    let mut pairs = vec![
        ("schema_version", value::int(1)),
        ("training_stage", value::string(scope)),
        ("request_id", value::string(&request.request_id)),
        ("model_id", value::string(&request.model_id)),
        ("expectations", expectations.to_value()),
        ("request_protobuf_base64", value::string(&encode(&wire))),
        ("request_protobuf_sha256", value::string(&digest)),
        ("compute_status", value::string(if response.is_some() { "response_received_unadmitted" } else { "transport_outcome_unknown" })),
        ("admission_status", value::string(if error.is_some() { "rejected" } else { "accepted" })),
        ("error_type", error.map_or(Value::Null, |error| value::string(error.type_name))),
        ("error", described.map_or(Value::Null, |text| value::string(&text))),
    ];
    if let Some(response) = response {
        let executions = response
            .executions
            .iter()
            .map(|execution| {
                value::object(vec![
                    ("phase", value::string(&execution.phase)),
                    ("layer", value::int(i64::from(execution.layer))),
                    ("status", value::string(&execution.status)),
                    ("examples", value::int(i64::from(execution.examples))),
                ])
            })
            .collect();
        pairs.push(("response_protobuf_base64", value::string(&encode(&crate::pywire::compute_response_bytes(response)))));
        pairs.push(("declared_executions", Value::Array(executions)));
        if error.is_none() {
            pairs.retain(|(key, _)| *key != "compute_status");
            pairs.push(("compute_status", value::string("semantic_execution_validated")));
        }
    }
    write_attempt(&directory.join("policy-attempts").join(digest), &value::object(pairs))
}

/// `persist_backtracking_attempt`: one immutable header-admitted attempt, committed before the response is admitted.
pub fn persist_backtracking_attempt(
    directory: Option<&Path>,
    request: &ComputeSemanticGradientsRequest,
    response: Option<&ComputeSemanticGradientsResponse>,
    scope: &str,
    expectations: &Expectations,
    header: &str,
    error: Option<&Recorded<'_>>,
) -> Result<PathBuf, Failure> {
    let directory = directory_required(directory, "Backtracking requires durable PRIVOKE_FUZZER_DUMP_DIR.")?;
    let wire = request.encode_to_vec();
    let digest = value::sha256(&wire);
    let mut pairs = vec![
        ("schema_version", value::int(1)),
        ("record_kind", value::string("physical_compute_attempt")),
        ("training_stage", value::string(scope)),
        ("request_id", value::string(&request.request_id)),
        ("model_id", value::string(&request.model_id)),
        ("expectations", expectations.to_value()),
        ("invocation_metadata", invocation_value(header)),
        ("request_protobuf_sha256", value::string(&digest)),
        ("request_protobuf_base64", value::string(&encode(&wire))),
        ("compute_status", value::string(if response.is_some() { "response_received_unadmitted" } else { "transport_outcome_unknown" })),
        ("gradient_fits", Value::Null),
        ("error_type", error.map_or(Value::Null, |error| value::string(error.type_name))),
    ];
    if let Some(response) = response {
        pairs.push(("response_protobuf_base64", value::string(&encode(&crate::pywire::compute_response_bytes(response)))));
    }
    write_attempt(&directory.join("backtracking-attempts").join(digest), &value::object(pairs))
}

/// `contextual_output_trainable_names(config)`: the head tensors (and the task-query readouts) of the artifact.
fn output_names(config: &Value) -> Result<std::collections::BTreeSet<String>, Failure> {
    Ok(head_names(config)?)
}

/// `persist_backtracking_admission`: the verdict on an attempt (`accepted`, `known_train_rejection` or `unadmitted`).
pub fn persist_backtracking_admission(
    attempt: &Path,
    response: Option<&ComputeSemanticGradientsResponse>,
    status: &str,
    error: Option<&Recorded<'_>>,
) -> Result<PathBuf, Failure> {
    let attempt_bytes = std::fs::read(attempt)?;
    let selected = matches!(status, "accepted" | "known_train_rejection");
    let mut pairs = vec![
        ("schema_version", value::int(1)),
        ("record_kind", value::string("admission_verdict")),
        ("physical_attempt", value::string(&attempt.display().to_string())),
        ("physical_attempt_sha256", value::string(&value::sha256(&attempt_bytes))),
        ("status", value::string(status)),
        ("gradient_fits", if selected { value::int(1) } else { Value::Null }),
        ("error_type", error.map_or(Value::Null, |error| value::string(error.type_name))),
        ("error", error.map_or(Value::Null, |error| value::string(&truncated(error.message)))),
    ];
    if selected {
        let response = response.ok_or_else(|| Failure::Value("An admitted attempt needs its response.".to_string()))?;
        let record = value::parse_bytes(&attempt_bytes)?;
        let scope = value::get(&record, "training_stage").and_then(value::as_str).unwrap_or_default().to_string();
        let model_config = response.metadata.get("model_config").ok_or_else(|| Failure::Value("'model_config'".to_string()))?;
        let config = privoke_contracts::json::parse(model_config).map_err(|error| Failure::Value(error.to_string()))?;
        let mut shapes = full_encoder_tensor_shapes(&config)?;
        if scope == "heads" {
            let heads = output_names(&config)?;
            shapes.retain(|name, _| heads.contains(name));
        } else if scope != "full_encoder" {
            return Err(Failure::Value("Unknown admitted training scope.".to_string()));
        }
        if status == "accepted" {
            let actual: std::collections::BTreeMap<String, Vec<u64>> = response
                .gradients
                .iter()
                .map(|parameter| (parameter.name.clone(), parameter.shape.iter().map(|size| u64::from(*size)).collect()))
                .collect();
            if actual != shapes {
                return Err(Failure::Value("Admitted response tensor inventory differs from its training scope.".to_string()));
            }
        }
        let shape_value = Value::Object(
            shapes
                .iter()
                .map(|(name, shape)| (name.clone(), Value::Array(shape.iter().map(|size| value::uint(*size)).collect())))
                .collect(),
        );
        pairs.push(("raw_gradient_shapes", shape_value));
    }
    let parent = attempt.parent().and_then(Path::parent).ok_or_else(|| Failure::Value("The attempt has no directory.".to_string()))?;
    write_attempt(&parent.join("admission"), &value::object(pairs))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request() -> ComputeSemanticGradientsRequest {
        ComputeSemanticGradientsRequest { request_id: "r".into(), model_id: "m".into(), layers: vec![4], ..Default::default() }
    }

    #[test]
    fn a_physical_attempt_is_reserved_exactly_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = reserve_physical_attempt(&request(), "{}", Some(directory.path())).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"invocation_metadata\":[[\"x-privoke-training-admission-v1\",\"{}\"]]"));
        assert!(text.ends_with("\"status\":\"reserved_outcome_unknown_until_durable_response\"}"));
        let again = reserve_physical_attempt(&request(), "{}", Some(directory.path())).unwrap_err();
        assert_eq!(again.type_name(), "FileExistsError");
        let rejected = persist_reservation_rejection(&request(), "{}", Some(directory.path()), &again).unwrap();
        assert!(std::fs::read_to_string(rejected).unwrap().contains("\"compute_status\": \"reservation_rejected_no_rpc\""));
        assert_eq!(
            reserve_physical_attempt(&request(), "{}", None).unwrap_err().message(),
            "FULL Adam requires durable physical attempt reservation."
        );
    }

    #[test]
    fn attempts_are_immutable_and_the_admission_names_its_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let expectations = Expectations::default();
        let attempt =
            persist_backtracking_attempt(Some(directory.path()), &request(), None, "full_encoder", &expectations, "{}", None).unwrap();
        assert!(attempt.starts_with(directory.path().join("backtracking-attempts")));
        let error = Recorded { type_name: "RuntimeAnalysisError", message: "refused" };
        let verdict = persist_backtracking_admission(&attempt, None, "unadmitted", Some(&error)).unwrap();
        assert!(verdict.to_string_lossy().contains("admission"));
        let text = std::fs::read_to_string(verdict).unwrap();
        assert!(text.contains("\"status\": \"unadmitted\"") && text.contains("\"gradient_fits\": null"));
    }
}
