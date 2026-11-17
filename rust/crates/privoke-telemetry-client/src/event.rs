//! The bounded categorical report and its local privatisation (`StructuredEventEmitter` of `event_emitter.py`).
//!
//! The runtime hands over an [`AnalysisInput`], the few facts of a prompt analysis that the report may use: the action
//! name, the sensitivity and category names of the classification, and the model version string. Nothing else (no text,
//! no span, no identifier) is representable, so nothing else can reach a packet.

use std::collections::BTreeMap;

use privoke_contracts::proto::v1::TelemetryPacket;
use time::{OffsetDateTime, UtcOffset};

use crate::error::PrivacyError;
use crate::privacy::{EVENT_EPSILON_DEFAULT, MECHANISM, domain, randomize_report};
use crate::random::RandomSource;

/// The categories in the order that picks the primary one (the first present wins).
const CATEGORY_PRECEDENCE: [&str; 10] =
    ["CHILD", "HEALTH", "CRIMINAL", "SEXUAL", "FINANCIAL", "IDENTITY", "LOCATION", "RELIGION", "POLITICS", "THIRD_PARTY"];

/// The classification of an analysis: its sensitivity level and category names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Sensitivity name (`S0` to `S3`); any other name scores zero.
    pub sensitivity: String,
    /// Names of the categories found; names outside the fixed list are ignored.
    pub categories: Vec<String>,
}

/// The analysis result of a prompt.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisResult {
    /// The classification, when the semantic layer produced one.
    pub classification: Option<Classification>,
    /// The `model_version` metadata value, when present.
    pub model_version: Option<String>,
}

/// What a report may use of a prompt analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisInput {
    /// Action name (`ALLOW`, `WARN` or `BLOCK`; any other name is reported as `ALLOW`).
    pub action: String,
    /// The analysis result; `None` when the analysis produced none.
    pub result: Option<AnalysisResult>,
}

/// Builds privatised reports. Stateless: the clock and the random source are arguments.
#[derive(Debug, Default, Clone, Copy)]
pub struct StructuredEventEmitter;

impl StructuredEventEmitter {
    /// The true (unprotected) value of each dimension. It never leaves the process: only the randomised values do.
    pub fn true_values(analysis: &AnalysisInput, now: OffsetDateTime) -> BTreeMap<String, String> {
        let classification = analysis.result.as_ref().and_then(|result| result.classification.as_ref());
        let sensitivity = classification.map_or("S0", |found| found.sensitivity.as_str());
        let risk = risk_score(&analysis.action, sensitivity);
        let action = if domain("action").is_some_and(|names| names.contains(&analysis.action.as_str())) {
            analysis.action.as_str()
        } else {
            "ALLOW"
        };
        BTreeMap::from([
            ("action".to_string(), action.to_string()),
            ("risk_bucket".to_string(), risk_bucket(risk).to_string()),
            ("primary_category".to_string(), primary_category(classification).to_string()),
            ("model_version".to_string(), model_release_version(analysis.result.as_ref()).to_string()),
            ("time_bucket".to_string(), time_bucket(now)),
        ])
    }

    /// Wrap already-protected values in the wire packet.
    pub fn assemble_packet(protected: &BTreeMap<String, String>, epsilon: f64) -> TelemetryPacket {
        let field = |name: &str| protected.get(name).cloned().unwrap_or_default();
        TelemetryPacket {
            time_bucket: field("time_bucket"),
            action: field("action"),
            primary_category: field("primary_category"),
            risk_bucket: field("risk_bucket"),
            model_version: field("model_version"),
            privacy_mechanism: MECHANISM.to_string(),
            privacy_epsilon: epsilon,
        }
    }

    /// Randomise one report locally and build its packet (`build_packet`). `epsilon` is the event epsilon.
    pub fn build_packet(
        analysis: &AnalysisInput,
        epsilon: f64,
        now: OffsetDateTime,
        source: &mut dyn RandomSource,
    ) -> Result<TelemetryPacket, PrivacyError> {
        let protected = randomize_report(&Self::true_values(analysis, now), epsilon, source)?;
        Ok(Self::assemble_packet(&protected, epsilon))
    }

    /// [`Self::build_packet`] at the default event epsilon.
    pub fn build_default_packet(
        analysis: &AnalysisInput,
        now: OffsetDateTime,
        source: &mut dyn RandomSource,
    ) -> Result<TelemetryPacket, PrivacyError> {
        Self::build_packet(analysis, EVENT_EPSILON_DEFAULT, now, source)
    }
}

fn primary_category(classification: Option<&Classification>) -> &'static str {
    let Some(found) = classification else {
        return "NONE";
    };
    CATEGORY_PRECEDENCE.iter().find(|name| found.categories.iter().any(|category| category == *name)).copied().unwrap_or("NONE")
}

fn model_release_version(result: Option<&AnalysisResult>) -> &'static str {
    let Some(result) = result else {
        return "OTHER";
    };
    let version = result.model_version.as_deref().unwrap_or("");
    // Training revisions keep the public release channel and drop the unbounded per-update identifier.
    let release = version.split_once("+train.").map_or(version, |(release, _)| release);
    domain("model_version").and_then(|names| names.iter().find(|name| **name == release)).copied().unwrap_or("OTHER")
}

fn time_bucket(occurred_at: OffsetDateTime) -> String {
    let start_hour = (occurred_at.to_offset(UtcOffset::UTC).hour() / 4) * 4;
    let end_hour = start_hour + 4;
    format!("{start_hour:02}-{end_hour:02}_UTC")
}

fn risk_score(action: &str, sensitivity: &str) -> f64 {
    let action_score = match action {
        "WARN" => 0.65,
        "BLOCK" => 1.0,
        _ => 0.0,
    };
    let sensitivity_score = match sensitivity {
        "S1" => 0.25,
        "S2" => 0.65,
        "S3" => 1.0,
        _ => 0.0,
    };
    f64::max(action_score, sensitivity_score)
}

fn risk_bucket(score: f64) -> &'static str {
    if score < 0.2 {
        "0.0-0.2"
    } else if score < 0.5 {
        "0.2-0.5"
    } else if score < 0.8 {
        "0.5-0.8"
    } else {
        "0.8-1.0"
    }
}
