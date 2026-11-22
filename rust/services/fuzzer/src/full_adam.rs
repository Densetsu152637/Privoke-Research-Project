//! The fuzzer's FULL Adam evidence (`privoke_model/full_adam.py` and `training/full_adam_evidence.py`).
//!
//! The runtime reports the detailed 64-step recurrence of a FULL Adam fit as canonical JSON in its response metadata, with an
//! independently bound summary. [`validate_trace`] is `full_adam.validate_trace`: the fuzzer admits a FULL candidate only if the
//! trace names the artifact policy and configuration, starts at the base parameters, chains 64 steps from one state to the next,
//! ends at the candidate, carries the transported delta and accounts for every direction and microbatch.
//!
//! The retention policies have their own trace ([`privoke_training::retention`]); they are not validated here and answer an error
//! that names the gap, so an ORIGINAL-retention update is never admitted by the plain FULL Adam rules.

use std::collections::BTreeSet;

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::json::{self, Value};
use privoke_curriculum::value;
use privoke_training::admission::CONFIG_CANONICAL;

use crate::error::{Error, Result, invalid};
use crate::policy::{FULL_ADAM_POLICY, Metadata};

pub(crate) const ELIGIBILITY: &str = "candidate_train_exact_eligibility_v1";
pub(crate) const ELIGIBILITY_KEY: &str = "contextual_candidate_eligibility";
pub(crate) const EXECUTED_KEY: &str = "executed_contextual_training_optimizer";
pub(crate) const TRACE_KEY: &str = "full_projected_adam_trace_v1";
pub(crate) const SUMMARY_KEY: &str = "full_projected_adam_summary_v1";
pub(crate) const CONFIG_KEY: &str = "full_projected_adam_config_v1";
pub(crate) const OPTIMIZER_KEY: &str = "contextual_training_optimizer";
pub(crate) const RETENTION_POLICIES: [&str; 2] =
    ["full_projected_adam64_original_train_gate_v1", "full_projected_adam64_original_train_hinge_v1"];
const MAX_TRACE_BYTES: usize = 131_072;

fn canonical_text(document: &Value) -> Result<String> {
    let bytes = canonical::to_bytes(document, Variant::Ascii).map_err(|error| Error(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| Error(error.to_string()))
}

fn is_hash(document: Option<&Value>) -> bool {
    matches!(document, Some(Value::String(text)) if text.len() == 64 && text.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
}

fn keys(document: &Value) -> BTreeSet<&str> {
    value::as_object(document).map(|map| map.keys().map(String::as_str).collect()).unwrap_or_default()
}

fn parse(text: &str) -> Result<Value> {
    json::parse(text).map_err(|error| Error(error.to_string()))
}

/// `validate_trace(metadata, scope=, examples=, candidate_fingerprint=, delta_fingerprint=)`. A HEAD update returns `None`.
pub fn validate_trace(
    metadata: &Metadata,
    scope: &str,
    examples: usize,
    candidate_fingerprint: &str,
    delta_fingerprint: &str,
) -> Result<Option<Value>> {
    let get = |key: &str| metadata.get(key).map(String::as_str);
    if get(OPTIMIZER_KEY).is_some_and(|policy| RETENTION_POLICIES.contains(&policy)) {
        return crate::retention::validate_trace(metadata, scope, examples, candidate_fingerprint, delta_fingerprint);
    }
    if get(OPTIMIZER_KEY) != Some(FULL_ADAM_POLICY) || get(CONFIG_KEY) != Some(CONFIG_CANONICAL) {
        return invalid("Missing FULL Adam artifact policy/config identity.");
    }
    let executed = get(EXECUTED_KEY);
    if scope == "heads" {
        if executed != Some("dormant_head_v1") || [TRACE_KEY, SUMMARY_KEY, ELIGIBILITY_KEY].iter().any(|key| metadata.contains_key(*key)) {
            return invalid("HEAD must report dormant Adam without candidate eligibility.");
        }
        return Ok(None);
    }
    if scope != "full_encoder" || executed != Some(FULL_ADAM_POLICY) || get(ELIGIBILITY_KEY) != Some(ELIGIBILITY) {
        return invalid("Candidate eligibility requires actual FULL Adam execution.");
    }
    let Some(raw) = get(TRACE_KEY).filter(|raw| raw.len() <= MAX_TRACE_BYTES) else {
        return invalid("Missing or excessive FULL Adam detailed trace.");
    };
    let raw_summary = get(SUMMARY_KEY).ok_or_else(|| Error(format!("'{SUMMARY_KEY}'")))?;
    let (trace, summary) = (parse(raw)?, parse(raw_summary)?);
    if raw != canonical_text(&trace)? || raw_summary != canonical_text(&summary)? {
        return invalid("FULL Adam evidence must use canonical JSON.");
    }
    let config = parse(CONFIG_CANONICAL)?;
    let wanted_keys: BTreeSet<&str> =
        ["schema", "policy", "config", "base", "final", "delta", "steps", "counts", "train"].into_iter().collect();
    let steps = value::get(&trace, "steps").and_then(value::as_array);
    let field = |name: &str| value::get(&trace, name).cloned().unwrap_or(Value::Null);
    let expected_summary = value::object(vec![
        ("schema", value::int(1)),
        ("policy", value::string(FULL_ADAM_POLICY)),
        ("trace_sha256", value::string(&value::sha256(raw.as_bytes()))),
        ("base", field("base")),
        ("final", field("final")),
        ("delta", field("delta")),
        ("counts", field("counts")),
        ("eligibility", value::string(ELIGIBILITY)),
        ("metric", value::string("candidate_train_exact_match_rate")),
    ]);
    let base = metadata.get("base_parameter_fingerprint").map(|text| Value::String(text.clone()));
    if keys(&trace) != wanted_keys
        || value::get(&trace, "schema") != Some(&value::int(1))
        || value::get(&trace, "policy") != Some(&value::string(FULL_ADAM_POLICY))
        || value::get(&trace, "config") != Some(&config)
        || base.is_none()
        || value::get(&trace, "base") != base.as_ref()
        || value::get(&trace, "final") != Some(&value::string(candidate_fingerprint))
        || value::get(&trace, "delta") != Some(&value::string(delta_fingerprint))
        || value::get(&trace, "train") != Some(&value::int(examples as i64))
        || steps.is_none_or(|rows| rows.len() != 64)
        || summary != expected_summary
    {
        return invalid("FULL Adam trace/summary identity differs.");
    }
    let rows = steps.unwrap_or(&Vec::new()).clone();
    let step_keys: BTreeSet<&str> = ["step", "before", "after", "loss", "gradient", "moments", "delta", "clipped"].into_iter().collect();
    let mut previous = field("base");
    for (index, row) in rows.iter().enumerate() {
        let loss = value::get(row, "loss");
        let loss_ok = match loss {
            Some(Value::Int(_)) => loss.and_then(value::as_number).is_some_and(|number| number >= 0.0),
            Some(Value::Float(number)) => number.is_finite() && *number >= 0.0,
            _ => false,
        };
        let clipped_ok = matches!(value::get(row, "clipped"), Some(Value::Int(digits)) if !digits.starts_with('-'));
        if keys(row) != step_keys
            || value::get(row, "step") != Some(&value::int(index as i64 + 1))
            || value::get(row, "before") != Some(&previous)
            || !loss_ok
            || !clipped_ok
            || !["before", "after", "gradient", "moments", "delta"].iter().all(|name| is_hash(value::get(row, name)))
        {
            return invalid("Malformed FULL Adam step recurrence evidence.");
        }
        previous = value::get(row, "after").cloned().unwrap_or(Value::Null);
    }
    let last_delta = rows.last().and_then(|row| value::get(row, "delta"));
    if previous != field("final") || last_delta != value::get(&trace, "delta") {
        return invalid("FULL Adam final state differs from recurrence.");
    }
    let batches = examples.div_ceil(32) as i64;
    let counts = field("counts");
    let count = |name: &str| value::get(&counts, name).and_then(value::as_i64);
    if count("directions_attempted") != Some(64)
        || count("directions_completed") != Some(64)
        || count("microbatch_forward_attempted") != Some(64 * batches)
        || count("microbatch_forward_completed") != Some(64 * batches)
        || count("microbatch_backward_started") != Some(64 * batches)
        || count("microbatch_backward_completed") != Some(64 * batches)
        || count("train_parameter_states") != Some(65)
    {
        return invalid("FULL Adam actual direction/microbatch/state accounting differs.");
    }
    Ok(Some(trace))
}
