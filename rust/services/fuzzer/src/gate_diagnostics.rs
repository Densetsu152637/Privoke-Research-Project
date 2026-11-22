//! `fuzzer_service.gate_diagnostics` and `write_gate_diagnostics`: the numeric, prompt-free record of the unchanged publication
//! guard that a study asks for with `study_gate_diagnostics=v1`. It states which predicate of the guard held for the update,
//! next to the metrics it compared, and is retained beside the curriculum state before the guard decides.

use std::collections::BTreeMap;
use std::path::PathBuf;

use privoke_contracts::proto::v1::FuzzerTrainingRequest;
use privoke_curriculum::value::{self, Value};

use crate::config::FuzzerConfig;
use crate::cycle::{plain_fingerprint, validate_training_update};
use crate::error::{Error, Result, invalid};
use crate::evidence::write_atomic;
use crate::full_adam_evidence::{eligibility_metric, gate_summary};
use crate::runtime::BatchUpdate;

const CANDIDATE_METRIC: &str = "candidate_train_exact_match_rate";
const METRIC_KEYS: [&str; 10] = [
    "exact_match_rate",
    "heldout_exact_match_rate",
    "candidate_heldout_exact_match_rate",
    "heldout_sensitive_recall",
    "candidate_heldout_sensitive_recall",
    "heldout_clean_specificity",
    "candidate_heldout_clean_specificity",
    "heldout_sensitive_examples",
    "heldout_clean_examples",
    "candidate_heldout_safety_regression_rate",
];

fn is_fingerprint(text: Option<&String>) -> bool {
    text.is_some_and(|text| text.len() == 64)
}

/// `gate_diagnostics(request, update, minimum)`.
pub fn gate_diagnostics(request: &FuzzerTrainingRequest, update: &BatchUpdate, minimum: f64) -> Result<Value> {
    let selected = eligibility_metric(update)?;
    let candidate_route = selected == CANDIDATE_METRIC;
    // Invalid values stay explicit and serialisable rather than becoming zero.
    let metrics: BTreeMap<String, Option<f64>> = update
        .metrics
        .iter()
        .filter(|(key, _)| METRIC_KEYS.contains(&key.as_str()) || (candidate_route && key.as_str() == CANDIDATE_METRIC))
        .map(|(key, number)| (key.clone(), number.is_finite().then_some(*number)))
        .collect();
    let mut failures: Vec<Value> = Vec::new();
    if let Err(error) = validate_training_update(update, minimum) {
        failures.push(value::object(vec![("predicate", value::string("validation")), ("message", value::string(&error.0))]));
    }
    let comparisons: [(&str, &str, Option<&str>); 5] = [
        ("training_exact_above_minimum", selected, None),
        ("heldout_exact_no_decline", "candidate_heldout_exact_match_rate", Some("heldout_exact_match_rate")),
        ("heldout_recall_no_decline", "candidate_heldout_sensitive_recall", Some("heldout_sensitive_recall")),
        ("heldout_specificity_no_decline", "candidate_heldout_clean_specificity", Some("heldout_clean_specificity")),
        ("no_safety_regression", "candidate_heldout_safety_regression_rate", None),
    ];
    for (predicate, key, reference) in comparisons {
        let number = metrics.get(key).copied().flatten();
        let base = reference.and_then(|name| metrics.get(name).copied().flatten());
        let failed = match number {
            None => true,
            Some(_) if reference.is_some() && base.is_none() => true,
            Some(number) if key == selected => number <= minimum,
            Some(number) => match base {
                None => number > 0.0,
                Some(base) => number < base,
            },
        };
        if failed {
            failures.push(value::object(vec![("predicate", value::string(predicate))]));
        }
    }
    let base_fingerprint = update.metadata.get("base_parameter_fingerprint");
    let updated_fingerprint = update.metadata.get("updated_parameter_fingerprint");
    if !is_fingerprint(base_fingerprint) || !is_fingerprint(updated_fingerprint) {
        return invalid("Study gate diagnostics require exact base and candidate fingerprints.");
    }
    let mut pairs = vec![
        ("schema_version", value::int(1)),
        ("request_id", value::string(&request.request_id)),
        ("source_id", value::string(&request.source_id)),
        ("request_sha256", value::string(&plain_fingerprint(request))),
        ("model_id", value::string(&update.model_id)),
        ("base_version", value::string(&update.base_version)),
        ("base_parameter_fingerprint", value::string(base_fingerprint.map_or("", String::as_str))),
        ("updated_parameter_fingerprint", value::string(updated_fingerprint.map_or("", String::as_str))),
        ("minimum_exact_match_rate", Value::Float(minimum)),
        ("metrics", Value::Object(metrics.iter().map(|(key, number)| (key.clone(), number.map_or(Value::Null, Value::Float))).collect())),
        ("gate_passed", Value::Bool(failures.is_empty())),
        ("failed_predicates", Value::Array(failures)),
    ];
    if candidate_route {
        pairs.push(("metric_role", value::string("candidate_train")));
        pairs.push(("gate_policy", gate_summary(update, minimum)?));
    }
    Ok(value::object(pairs))
}

/// `write_gate_diagnostics(request, update, config)`: the record is written once, named by the request's hash; a second
/// request with the same hash must produce the same record.
pub fn write_gate_diagnostics(request: &FuzzerTrainingRequest, update: &BatchUpdate, config: &FuzzerConfig) -> Result<()> {
    let Some(state) = &config.curriculum_state_path else {
        return invalid("Study diagnostics require durable curriculum storage.");
    };
    let record = gate_diagnostics(request, update, config.minimum_exact_match_rate)?;
    let digest = value::get(&record, "request_sha256").and_then(value::as_str).unwrap_or_default().to_string();
    let directory: PathBuf = state.parent().map_or_else(PathBuf::new, std::path::Path::to_path_buf).join("gate-diagnostics");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{digest}.json"));
    if path.exists() {
        let existing = value::parse_bytes(&std::fs::read(&path)?)?;
        if existing != record {
            return Err(Error("Conflicting durable gate diagnostics for the same request.".to_string()));
        }
        return Ok(());
    }
    write_atomic(&path, &record)
}
