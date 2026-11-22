//! The semantic presence gate (`pipeline.SemanticPresenceGateRequest` and `SemanticPresenceGateTrace`): a sparse
//! annotation-presence model decides whether the semantic layer's findings are kept.
//!
//! The trace is what the response reports for the gated layer, in every case Python reports one: the gate was not run
//! (the layer failed first, or was skipped after a regex `BLOCK`), applied, or failed after the semantic layer ran.

use crate::model::Finding;

/// A requested gate: the presence model and an optional decision threshold (the model's own when absent).
#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
    /// `model_id`: one of the presence models a gate may name.
    pub model_id: String,
    /// `threshold`, in `[0, 1]`.
    pub threshold: Option<f64>,
}

/// `SemanticPresenceGateStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// `NOT_RUN`.
    NotRun,
    /// `APPLIED`.
    Applied,
    /// `ERROR`.
    Error,
}

impl GateStatus {
    /// The enum value of `SemanticPresenceGateStatus`.
    pub fn proto_value(self) -> i32 {
        match self {
            Self::NotRun => 1,
            Self::Applied => 2,
            Self::Error => 3,
        }
    }
}

/// `AnnotationPresenceLabel` of a decided gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    /// `ANNOTATION_PRESENCE_ABSENT`.
    Absent,
    /// `ANNOTATION_PRESENCE_PRESENT`.
    Present,
}

impl Label {
    /// The enum value of `AnnotationPresenceLabel`.
    pub fn proto_value(self) -> i32 {
        match self {
            Self::Absent => 1,
            Self::Present => 2,
        }
    }
}

/// `SemanticPresenceGateTrace`.
#[derive(Debug, Clone, PartialEq)]
pub struct GateTrace {
    /// The status.
    pub status: GateStatus,
    /// The gate model: the requested id until the model is read, then the identity of the model that ran.
    pub model_id: String,
    /// The presence model's version.
    pub model_version: String,
    /// The presence artifact's checksum.
    pub artifact_checksum: String,
    /// The presence model's parameter fingerprint.
    pub parameter_fingerprint: String,
    /// The presence probability of the normalised prompt.
    pub probability: Option<f64>,
    /// The presence model's own threshold.
    pub model_threshold: Option<f64>,
    /// The threshold that decided (the request's, or the model's).
    pub decision_threshold: Option<f64>,
    /// `PRESENT` or `ABSENT`; `None` when the gate did not decide.
    pub predicted_label: Option<Label>,
    /// What the semantic layer found before the gate decided.
    pub semantic_results: Vec<Finding>,
    /// The error, when the gate or the layer failed or was skipped.
    pub error: Option<String>,
    /// The semantic model that classified: its id.
    pub contextual_model_id: String,
    /// The semantic model's version.
    pub contextual_model_version: String,
    /// The semantic artifact's checksum.
    pub contextual_artifact_checksum: String,
    /// The semantic model's parameter fingerprint.
    pub contextual_parameter_fingerprint: String,
}

impl GateTrace {
    /// The trace before anything ran (`status="NOT_RUN"`), carrying the request's gate and an optional error.
    pub fn not_run(gate: &Gate, error: Option<String>) -> Self {
        Self {
            status: GateStatus::NotRun,
            model_id: gate.model_id.clone(),
            model_version: String::new(),
            artifact_checksum: String::new(),
            parameter_fingerprint: String::new(),
            probability: None,
            model_threshold: None,
            decision_threshold: gate.threshold,
            predicted_label: None,
            semantic_results: Vec::new(),
            error,
            contextual_model_id: String::new(),
            contextual_model_version: String::new(),
            contextual_artifact_checksum: String::new(),
            contextual_parameter_fingerprint: String::new(),
        }
    }
}

/// `SEMANTIC_PRESENCE_MODEL_IDS` minus the scratch models: the presence models a Rust worker can run as a gate.
pub fn is_sparse_gate_model(model_id: &str) -> bool {
    matches!(model_id, "privoke-presence-efficient" | "privoke-presence-balanced" | "privoke-presence-quality")
}

/// The scratch-presence models, which only the Python worker names (and then refuses, because no W1 worker serves them).
pub fn is_scratch_presence_model(model_id: &str) -> bool {
    ["efficient", "balanced", "quality"]
        .iter()
        .any(|profile| ["head-only", "full-encoder"].iter().any(|mode| model_id == format!("privoke-scratch-presence-{profile}-{mode}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_model_families_are_disjoint() {
        assert!(is_sparse_gate_model("privoke-presence-balanced"));
        assert!(!is_sparse_gate_model("privoke-scratch-presence-balanced-head-only"));
        assert!(is_scratch_presence_model("privoke-scratch-presence-quality-full-encoder"));
        assert!(!is_scratch_presence_model("privoke-presence-quality"));
        assert!(!is_scratch_presence_model("privoke-scratch-presence-quality"));
    }

    #[test]
    fn a_trace_that_did_not_run_carries_the_request() {
        let trace = GateTrace::not_run(&Gate { model_id: "privoke-presence-efficient".into(), threshold: Some(0.0) }, Some("why".into()));
        assert_eq!((trace.status, trace.decision_threshold, trace.error.as_deref()), (GateStatus::NotRun, Some(0.0), Some("why")));
        assert_eq!(trace.status.proto_value(), 1);
        assert_eq!(Label::Present.proto_value(), 2);
    }
}
