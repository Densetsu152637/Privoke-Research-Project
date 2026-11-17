//! Generalised randomised response over the five fixed telemetry domains (`privacy.py`).
//!
//! The sampler is the audited one: a truthful answer is returned when a uniform multiple of 2^-53 is strictly below the
//! binary64 threshold `p = exp(e) / (exp(e) + K - 1)`, and otherwise one of the other `K - 1` values is drawn by
//! rejection sampling. Threshold arithmetic is the same IEEE operations in the same order as the oracle.

use std::collections::BTreeMap;

use crate::error::PrivacyError;
use crate::random::{RandomSource, random_below, random_unit};

/// The only mechanism label the collector accepts.
pub const MECHANISM: &str = "grr_rr_v1";
/// Default per-event epsilon.
pub const EVENT_EPSILON_DEFAULT: f64 = 1.0;
/// Smallest per-event epsilon.
pub const EVENT_EPSILON_MIN: f64 = 0.5;
/// Largest per-event epsilon.
pub const EVENT_EPSILON_MAX: f64 = 2.0;
/// Default daily epsilon budget.
pub const DAILY_EPSILON_DEFAULT: f64 = 8.0;
/// Largest daily epsilon budget.
pub const DAILY_EPSILON_MAX: f64 = 8.0;
/// The protected dimensions, in the order the oracle randomises them (so the order bytes are consumed).
pub const DIMENSIONS: [&str; 5] = ["action", "risk_bucket", "primary_category", "model_version", "time_bucket"];

const ACTION: &[&str] = &["ALLOW", "WARN", "BLOCK"];
const RISK_BUCKET: &[&str] = &["0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"];
const PRIMARY_CATEGORY: &[&str] =
    &["NONE", "CHILD", "HEALTH", "CRIMINAL", "SEXUAL", "FINANCIAL", "IDENTITY", "LOCATION", "RELIGION", "POLITICS", "THIRD_PARTY"];
const MODEL_VERSION: &[&str] = &["v0.3.0", "OTHER"];
const TIME_BUCKET: &[&str] = &["00-04_UTC", "04-08_UTC", "08-12_UTC", "12-16_UTC", "16-20_UTC", "20-24_UTC"];

/// The finite domain of a dimension, in the oracle's order (the order decides which alternative a draw selects).
pub fn domain(dimension: &str) -> Option<&'static [&'static str]> {
    match dimension {
        "action" => Some(ACTION),
        "risk_bucket" => Some(RISK_BUCKET),
        "primary_category" => Some(PRIMARY_CATEGORY),
        "model_version" => Some(MODEL_VERSION),
        "time_bucket" => Some(TIME_BUCKET),
        _ => None,
    }
}

/// `math.isclose(a, b, abs_tol=1e-7)` with Python's default `rel_tol` of 1e-9.
pub(crate) fn is_close(a: f64, b: f64) -> bool {
    if a == b {
        return true;
    }
    if a.is_infinite() || b.is_infinite() {
        return false;
    }
    (a - b).abs() <= (1e-9 * a.abs().max(b.abs())).max(1e-7)
}

/// Whether `epsilon` has at most six decimal places, as the oracle and the collector test it.
pub(crate) fn has_six_decimals(epsilon: f64) -> bool {
    let micros = epsilon * 1_000_000.0;
    is_close(micros, micros.round_ties_even())
}

/// `validate_privacy_config`: finite epsilons inside their ranges with at most six decimals.
pub fn validate_privacy_config(event_epsilon: f64, daily_epsilon: f64) -> Result<(), PrivacyError> {
    if !event_epsilon.is_finite() || !(EVENT_EPSILON_MIN..=EVENT_EPSILON_MAX).contains(&event_epsilon) {
        return Err(PrivacyError::invalid("TELEMETRY_LDP_EPSILON must be between 0.5 and 2."));
    }
    if !daily_epsilon.is_finite() || !(event_epsilon..=DAILY_EPSILON_MAX).contains(&daily_epsilon) {
        return Err(PrivacyError::invalid("TELEMETRY_LDP_DAILY_EPSILON must be at least the per-event epsilon and at most 8."));
    }
    if !has_six_decimals(event_epsilon) {
        return Err(PrivacyError::invalid("TELEMETRY_LDP_EPSILON must have at most six decimal places."));
    }
    if !has_six_decimals(daily_epsilon) {
        return Err(PrivacyError::invalid("TELEMETRY_LDP_DAILY_EPSILON must have at most six decimal places."));
    }
    Ok(())
}

/// The binary64 output distribution of one input under `K`-ary GRR: the truthful probability and the probability of
/// each other value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GrrKernel {
    /// `exp(e) / (exp(e) + K - 1)`: also the sampler's threshold.
    pub truthful: f64,
    /// `1 / (exp(e) + K - 1)`.
    pub other: f64,
}

/// The kernel for a domain of `size` values at per-dimension `epsilon` (`grr_probabilities`' arithmetic).
pub fn grr_kernel(size: usize, epsilon: f64) -> Result<GrrKernel, PrivacyError> {
    if size < 2 {
        return Err(PrivacyError::invalid("GRR domain must contain at least two unique values."));
    }
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(PrivacyError::invalid("GRR epsilon must be finite and positive."));
    }
    let exp_epsilon = epsilon.exp();
    // `exp_epsilon + K - 1`, left to right, as the oracle evaluates it.
    let denominator = exp_epsilon + size as f64 - 1.0;
    if !denominator.is_finite() {
        return Err(PrivacyError::invalid("GRR epsilon is too large for binary64."));
    }
    Ok(GrrKernel { truthful: exp_epsilon / denominator, other: 1.0 / denominator })
}

fn check_domain(domain: &[&str]) -> Result<(), PrivacyError> {
    let unique = domain.iter().enumerate().all(|(index, value)| !domain[..index].contains(value));
    if domain.len() < 2 || !unique {
        return Err(PrivacyError::invalid("GRR domain must contain at least two unique values."));
    }
    Ok(())
}

/// `grr_probabilities`: the exact output distribution for `value`, in domain order.
pub fn grr_probabilities(value: &str, domain: &[&str], epsilon: f64) -> Result<Vec<(String, f64)>, PrivacyError> {
    check_domain(domain)?;
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(PrivacyError::invalid("GRR epsilon must be finite and positive."));
    }
    if !domain.contains(&value) {
        return Err(PrivacyError::invalid("GRR input must be in the declared finite domain."));
    }
    let kernel = grr_kernel(domain.len(), epsilon)?;
    Ok(domain.iter().map(|output| ((*output).to_string(), if *output == value { kernel.truthful } else { kernel.other })).collect())
}

/// `generalized_randomized_response`: `K`-ary GRR with a pure epsilon-LDP target. Draw order: one `random()`, then, if
/// the answer is not truthful, one rejection-sampled choice among the other values in domain order.
pub fn generalized_randomized_response(
    value: &str,
    domain: &[&str],
    epsilon: f64,
    source: &mut dyn RandomSource,
) -> Result<String, PrivacyError> {
    check_domain(domain)?;
    if !domain.contains(&value) {
        return Err(PrivacyError::invalid("GRR input must be in the declared finite domain."));
    }
    if !epsilon.is_finite() || epsilon <= 0.0 {
        return Err(PrivacyError::invalid("GRR epsilon must be finite and positive."));
    }
    let kernel = grr_kernel(domain.len(), epsilon)?;
    if random_unit(source)? < kernel.truthful {
        return Ok(value.to_string());
    }
    let alternatives: Vec<&str> = domain.iter().copied().filter(|candidate| *candidate != value).collect();
    let index = random_below(source, alternatives.len())?;
    Ok(alternatives[index].to_string())
}

/// `randomize_report`: randomise every protected dimension at `epsilon / 5` each. `values` must hold exactly the five
/// dimensions, each inside its domain.
pub fn randomize_report(
    values: &BTreeMap<String, String>,
    epsilon: f64,
    source: &mut dyn RandomSource,
) -> Result<BTreeMap<String, String>, PrivacyError> {
    let exact = values.len() == DIMENSIONS.len() && DIMENSIONS.iter().all(|name| values.contains_key(*name));
    if !exact {
        return Err(PrivacyError::invalid("Telemetry report must contain exactly the protected dimensions."));
    }
    validate_privacy_config(epsilon, DAILY_EPSILON_MAX)?;
    let per_dimension = epsilon / DIMENSIONS.len() as f64;
    let mut protected = BTreeMap::new();
    for name in DIMENSIONS {
        let choices = domain(name).unwrap_or(&[]);
        let value = values.get(name).map_or("", String::as_str);
        protected.insert(name.to_string(), generalized_randomized_response(value, choices, per_dimension, source)?);
    }
    Ok(protected)
}
