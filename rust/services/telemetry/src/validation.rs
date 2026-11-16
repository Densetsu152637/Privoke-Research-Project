//! Strict ingestion validation for locally privatised telemetry reports (`validation.py`).
//!
//! The checks run in the Python order and return the Python messages, which the stage 0 corpus records.

use privoke_contracts::proto::v1::TelemetryPacket;

/// The only accepted local privacy mechanism.
pub const MECHANISM: &str = "grr_rr_v1";
/// Smallest accepted per-report epsilon.
pub const MIN_EPSILON: f64 = 0.5;
/// Largest accepted per-report epsilon.
pub const MAX_EPSILON: f64 = 2.0;

/// The five dimensions in storage and summary order.
pub const DIMENSIONS: [&str; 5] = ["action", "risk_bucket", "primary_category", "model_version", "time_bucket"];

const TIME_BUCKET: &[&str] = &["00-04_UTC", "04-08_UTC", "08-12_UTC", "12-16_UTC", "16-20_UTC", "20-24_UTC"];
const ACTION: &[&str] = &["ALLOW", "BLOCK", "WARN"];
const PRIMARY_CATEGORY: &[&str] =
    &["CHILD", "CRIMINAL", "FINANCIAL", "HEALTH", "IDENTITY", "LOCATION", "NONE", "POLITICS", "RELIGION", "SEXUAL", "THIRD_PARTY"];
const RISK_BUCKET: &[&str] = &["0.0-0.2", "0.2-0.5", "0.5-0.8", "0.8-1.0"];
const MODEL_VERSION: &[&str] = &["OTHER", "v0.3.0"];

/// The allowed values of a dimension, sorted by byte order as Python's `sorted(frozenset)` is.
pub fn allowed_values(dimension: &str) -> &'static [&'static str] {
    match dimension {
        "time_bucket" => TIME_BUCKET,
        "action" => ACTION,
        "primary_category" => PRIMARY_CATEGORY,
        "risk_bucket" => RISK_BUCKET,
        "model_version" => MODEL_VERSION,
        _ => &[],
    }
}

/// A packet's value for one dimension.
pub fn dimension_value<'a>(packet: &'a TelemetryPacket, dimension: &str) -> &'a str {
    match dimension {
        "time_bucket" => &packet.time_bucket,
        "action" => &packet.action,
        "primary_category" => &packet.primary_category,
        "risk_bucket" => &packet.risk_bucket,
        "model_version" => &packet.model_version,
        _ => "",
    }
}

/// `math.isclose(a, b, abs_tol=1e-7)` with Python's default `rel_tol` of 1e-9.
fn is_close(a: f64, b: f64) -> bool {
    if a == b {
        return true;
    }
    if a.is_infinite() || b.is_infinite() {
        return false;
    }
    let difference = (a - b).abs();
    difference <= (1e-9 * a.abs().max(b.abs())).max(1e-7)
}

/// Check a packet. The error text is the `ValueError` message of the Python service.
pub fn validate_telemetry_packet(packet: &TelemetryPacket) -> Result<(), String> {
    if packet.privacy_mechanism != MECHANISM {
        return Err("Unsupported or missing local privacy mechanism.".to_string());
    }
    let epsilon = packet.privacy_epsilon;
    if !epsilon.is_finite() || !(MIN_EPSILON..=MAX_EPSILON).contains(&epsilon) {
        return Err("privacy_epsilon must be finite and between 0.5 and 2.".to_string());
    }
    let micros = epsilon * 1_000_000.0;
    if !is_close(micros, micros.round_ties_even()) {
        return Err("privacy_epsilon must have at most six decimal places.".to_string());
    }
    for field in ["time_bucket", "action", "primary_category", "risk_bucket", "model_version"] {
        if !allowed_values(field).contains(&dimension_value(packet, field)) {
            return Err(format!("{field} has an unsupported value."));
        }
    }
    Ok(())
}
