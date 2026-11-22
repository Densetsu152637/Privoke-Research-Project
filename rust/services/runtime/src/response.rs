//! The `AnalyzePromptResponse`: `hosting/analyzer.py` (visibility hint, masked text, the combined evidence),
//! `hosting/serialization.serialize_analysis_response` and `hosting/grpc_server._analysis_response`, written with the
//! encoder of [`crate::wire`] so that the bytes equal Python's deterministic serialisation.

use std::collections::BTreeMap;

use privoke_contracts::pyfloat;

use crate::gate::GateTrace;
use crate::model::{
    Action, Finding, InvalidVisibility, PU, category_names, from_parts, strongest_result, strongest_visibility, visibility_name,
};
use crate::pipeline::{LayerExecution, Status};
use crate::request::PromptRequest;
use crate::wire;

/// Text the masked prompt carries in place of the finding.
const MASK: &str = "[PRIVOKE_MASKED]";

/// What the response says about the elapsed time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Elapsed {
    /// The measured wall-clock time in milliseconds.
    Measured(f64),
    /// Neither `elapsed_ms` nor `metadata["elapsed_ms"]`: the normal form the conformance comparison uses.
    Cleared,
}

/// `PromptAnalysis`: the request, the layers and the decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Analysis {
    /// The validated request.
    pub request: PromptRequest,
    /// The layer executions, in pipeline order.
    pub executions: Vec<LayerExecution>,
    /// The combined result (after the visibility hint), `None` when there is no finding.
    pub result: Option<Finding>,
    /// The action.
    pub action: Action,
}

fn error_texts(executions: &[LayerExecution]) -> Vec<String> {
    executions
        .iter()
        .filter(|execution| execution.status == Status::Error)
        .map(|execution| format!("{}: {}", execution.layer.name(), execution.error.clone().unwrap_or_default()))
        .collect()
}

/// `PipelineAnalysis` followed by `analyse_prompt`'s visibility hint step.
pub fn decide(request: PromptRequest, executions: Vec<LayerExecution>) -> Result<Analysis, InvalidVisibility> {
    let (result, mut action) = strongest_result(executions.iter().flat_map(|execution| execution.results.iter()))?;
    // An execution that failed (status error with a message) blocks an otherwise ALLOW decision.
    if executions.iter().any(|execution| execution.status == Status::Error && execution.error.as_deref().is_some_and(|e| !e.is_empty()))
        && action == Action::Allow
    {
        action = Action::Block;
    }
    let (result, action) = apply_visibility_hint(result, action, &request)?;
    Ok(Analysis { request, executions, result, action })
}

/// `_apply_visibility_hint`.
fn apply_visibility_hint(
    result: Option<Finding>,
    action: Action,
    request: &PromptRequest,
) -> Result<(Option<Finding>, Action), InvalidVisibility> {
    let (Some(hint), Some(name)) = (request.visibility_hint, request.visibility_hint_name) else {
        return Ok((result, action));
    };
    let Some(current_result) = result.as_ref() else {
        return Ok((None, action));
    };
    let result = current_result;
    let current = result.classification.pack();
    visibility_name(current)?;
    let current_visibility = current & 0b1_1100;
    let visibility = strongest_visibility(&[current_visibility, hint]);
    if visibility == current_visibility {
        return Ok((Some(result.clone()), action));
    }
    let mut metadata = result.metadata.clone();
    metadata.insert("visibility_hint".to_string(), name.to_string());
    let hinted = Finding {
        classification: from_parts(current & 0b11, visibility, current & 0x7FE0),
        section: result.section.clone(),
        reasoning: format!("{} Visibility hint applied: {name}.", result.reasoning),
        span: result.span,
        confidence: result.confidence,
        metadata,
    };
    let hinted_action = hinted.action()?;
    Ok((Some(hinted), action.max(hinted_action)))
}

/// `_masked_text`: the prompt with the finding replaced, only for a WARN with a span that matches its section.
fn masked_text(text: &str, result: Option<&Finding>, action: Action) -> Option<String> {
    let result = result?;
    if action != Action::Warn {
        return None;
    }
    let (start, end) = result.span?;
    let chars: Vec<char> = text.chars().collect();
    if !(start < end && end <= chars.len()) {
        return None;
    }
    let section: String = chars[start..end].iter().collect();
    if section != result.section {
        return None;
    }
    let mut masked: String = chars[..start].iter().collect();
    masked.push_str(MASK);
    masked.extend(chars[end..].iter());
    Some(masked)
}

fn classification_message(packed: u16) -> Result<Vec<u8>, InvalidVisibility> {
    let mut out = Vec::new();
    let sensitivity = ["S0", "S1", "S2", "S3"][usize::from(packed & 0b11)];
    wire::string(&mut out, 1, sensitivity);
    wire::string(&mut out, 2, visibility_name(packed)?);
    for category in category_names(packed) {
        wire::string_always(&mut out, 3, category);
    }
    wire::uint32(&mut out, 4, u32::from(packed));
    Ok(out)
}

fn detection_result(result: &Finding) -> Result<Vec<u8>, InvalidVisibility> {
    let mut out = Vec::new();
    wire::message(&mut out, 1, &classification_message(result.classification.pack())?);
    wire::string(&mut out, 2, result.action()?.name());
    wire::string(&mut out, 3, &result.section);
    let (start, end) = result.span.unwrap_or((0, 0));
    wire::int32(&mut out, 4, i32::try_from(start).unwrap_or(i32::MAX));
    wire::int32(&mut out, 5, i32::try_from(end).unwrap_or(i32::MAX));
    wire::boolean(&mut out, 6, result.span.is_some());
    wire::double(&mut out, 7, result.confidence.unwrap_or(0.0));
    wire::boolean(&mut out, 8, result.confidence.is_some());
    wire::string(&mut out, 9, &result.reasoning);
    wire::string_map(&mut out, 10, &result.metadata);
    Ok(out)
}

fn layer_execution(execution: &LayerExecution) -> Result<Vec<u8>, InvalidVisibility> {
    let mut out = Vec::new();
    wire::enumeration(&mut out, 1, execution.layer.proto_value());
    wire::string(&mut out, 2, execution.status.name());
    for result in &execution.results {
        wire::message(&mut out, 3, &detection_result(result)?);
    }
    wire::string(&mut out, 4, execution.error.as_deref().unwrap_or(""));
    if let Some(trace) = &execution.gate {
        wire::message(&mut out, 5, &gate_trace(trace)?);
    }
    Ok(out)
}

/// `SemanticPresenceGateTrace`: the three optional doubles are written whenever they are set, zero included.
fn gate_trace(trace: &GateTrace) -> Result<Vec<u8>, InvalidVisibility> {
    let mut out = Vec::new();
    wire::enumeration(&mut out, 1, trace.status.proto_value());
    wire::string(&mut out, 2, &trace.model_id);
    wire::string(&mut out, 3, &trace.model_version);
    wire::string(&mut out, 4, &trace.artifact_checksum);
    wire::string(&mut out, 5, &trace.parameter_fingerprint);
    for (field, value) in [(6, trace.probability), (7, trace.model_threshold), (8, trace.decision_threshold)] {
        if let Some(value) = value {
            wire::double_always(&mut out, field, value);
        }
    }
    if let Some(label) = trace.predicted_label {
        wire::enumeration(&mut out, 9, label.proto_value());
    }
    for result in &trace.semantic_results {
        wire::message(&mut out, 10, &detection_result(result)?);
    }
    wire::string(&mut out, 11, trace.error.as_deref().unwrap_or(""));
    wire::string(&mut out, 12, &trace.contextual_model_id);
    wire::string(&mut out, 13, &trace.contextual_model_version);
    wire::string(&mut out, 14, &trace.contextual_artifact_checksum);
    wire::string(&mut out, 15, &trace.contextual_parameter_fingerprint);
    Ok(out)
}

/// `round(value, 3)` and Python's `json.dumps` of the float.
fn elapsed_text(milliseconds: f64) -> String {
    let rounded = format!("{milliseconds:.3}").parse::<f64>().unwrap_or(milliseconds);
    pyfloat::repr(rounded).unwrap_or_else(|_| "0.0".to_string())
}

/// The serialised `AnalyzePromptResponse` for a decided analysis.
pub fn encode_analysis(analysis: &Analysis, elapsed: Elapsed) -> Result<Vec<u8>, InvalidVisibility> {
    let request = &analysis.request;
    let errors = error_texts(&analysis.executions);
    let has_errors = analysis.executions.iter().any(|e| e.status == Status::Error && e.error.as_deref().is_some_and(|m| !m.is_empty()));

    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    if let Some(source) = &request.source {
        metadata.insert("source".to_string(), source.clone());
    }
    if let Some(target) = &request.target_app {
        metadata.insert("target_app".to_string(), target.clone());
    }
    if let Some(name) = request.visibility_hint_name {
        metadata.insert("visibility_hint".to_string(), name.to_string());
    }
    metadata.insert("text_length".to_string(), request.text.chars().count().to_string());
    for execution in &analysis.executions {
        let Some(identity) = &execution.identity else { continue };
        for (name, value) in identity {
            if name.starts_with(crate::semantic::CONTEXT_IDENTITY_PREFIX) {
                // `pretrained_context_identity` is attached whatever the layer's outcome.
                metadata.insert(name.clone(), value.clone());
            } else if execution.status == Status::Ok {
                metadata.insert(format!("privoke.semantic.{name}"), value.clone());
            }
        }
    }
    if let Elapsed::Measured(milliseconds) = elapsed {
        metadata.insert("elapsed_ms".to_string(), elapsed_text(milliseconds));
    }
    metadata.insert("detector".to_string(), "client-runtime.runtime".to_string());

    let classification = match &analysis.result {
        Some(result) => result.classification.pack(),
        None => from_parts(0, request.visibility_hint.unwrap_or(PU), 0).pack(),
    };
    let reason = if has_errors && analysis.action == Action::Block {
        "PriVoke could not complete analysis safely.".to_string()
    } else {
        analysis.result.as_ref().map_or_else(|| "No privacy risk detected.".to_string(), |result| result.reasoning.clone())
    };

    let mut out = Vec::new();
    wire::string(&mut out, 1, request.request_id.as_deref().unwrap_or(""));
    wire::string(&mut out, 2, analysis.action.name());
    wire::boolean(&mut out, 3, analysis.action != Action::Block);
    wire::string(&mut out, 4, masked_text(&request.text, analysis.result.as_ref(), analysis.action).as_deref().unwrap_or(""));
    wire::message(&mut out, 5, &classification_message(classification)?);
    wire::string(&mut out, 6, &reason);
    if let Some(result) = &analysis.result {
        wire::message(&mut out, 7, &detection_result(result)?);
    }
    wire::string_map(&mut out, 8, &metadata);
    for execution in &analysis.executions {
        wire::message(&mut out, 10, &layer_execution(execution)?);
    }
    if let Elapsed::Measured(milliseconds) = elapsed {
        wire::double(&mut out, 11, milliseconds);
    }
    wire::string(&mut out, 12, &errors.join("; "));
    Ok(out)
}

/// A response that carries only the request's own `request_id` and an error, which is what Python returns when a
/// handler raises.
pub fn error_response(request_id: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::string(&mut out, 1, request_id);
    wire::string(&mut out, 12, message);
    out
}

/// The `RuntimeHealthResponse` of a serving runtime.
pub fn health_response() -> Vec<u8> {
    let mut out = Vec::new();
    wire::string(&mut out, 1, "client-runtime");
    wire::string(&mut out, 2, "SERVING");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use privoke_rules::classification::{Classification, Sensitivity, visibility};

    use super::*;
    use crate::request::Layer;

    fn request(text: &str) -> PromptRequest {
        PromptRequest {
            text: text.to_string(),
            source: None,
            target_app: None,
            request_id: Some("r1".into()),
            visibility_hint: None,
            visibility_hint_name: None,
        }
    }

    fn finding(span: Option<(usize, usize)>, section: &str) -> Finding {
        Finding {
            classification: Classification::new(Sensitivity::S2, visibility::PU, 0),
            section: section.to_string(),
            reasoning: "why".into(),
            span,
            confidence: Some(0.9),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn a_warn_with_a_matching_span_masks_the_prompt() {
        let f = finding(Some((6, 11)), "world");
        assert_eq!(masked_text("hello world!", Some(&f), Action::Warn).as_deref(), Some("hello [PRIVOKE_MASKED]!"));
        assert_eq!(masked_text("hello world!", Some(&f), Action::Block), None);
        assert_eq!(masked_text("hello there!", Some(&f), Action::Warn), None);
        assert_eq!(masked_text("hello world!", Some(&finding(None, "world")), Action::Warn), None);
        assert_eq!(masked_text("short", Some(&finding(Some((2, 9)), "x")), Action::Warn), None);
    }

    #[test]
    fn a_hint_raises_the_visibility_and_says_so() {
        let mut req = request("x");
        req.visibility_hint = Some(0b10000);
        req.visibility_hint_name = Some("P3");
        let (hinted, action) = apply_visibility_hint(Some(finding(Some((0, 1)), "x")), Action::Warn, &req).unwrap();
        let hinted = hinted.unwrap();
        assert_eq!(visibility_name(hinted.classification.pack()).unwrap(), "P3");
        assert_eq!(hinted.reasoning, "why Visibility hint applied: P3.");
        assert_eq!(hinted.metadata.get("visibility_hint").map(String::as_str), Some("P3"));
        assert_eq!(action, Action::Warn);
        // A hint that does not raise the visibility changes nothing.
        req.visibility_hint = Some(PU);
        req.visibility_hint_name = Some("PU");
        let (same, _) = apply_visibility_hint(Some(finding(Some((0, 1)), "x")), Action::Warn, &req).unwrap();
        assert_eq!(same.unwrap().reasoning, "why");
    }

    #[test]
    fn an_empty_analysis_is_s0_with_the_hinted_visibility() {
        let mut req = request("hello");
        req.visibility_hint = Some(0b01100);
        req.visibility_hint_name = Some("P2");
        let analysis = decide(
            req,
            vec![LayerExecution { layer: Layer::Regex, status: Status::Ok, results: vec![], error: None, identity: None, gate: None }],
        )
        .unwrap();
        assert_eq!(analysis.action, Action::Allow);
        let bytes = encode_analysis(&analysis, Elapsed::Cleared).unwrap();
        assert!(bytes.windows(14).any(|w| w == b"No privacy ris"), "{bytes:?}");
    }

    #[test]
    fn a_failed_layer_blocks_an_allow_and_names_itself() {
        let failed = LayerExecution {
            layer: Layer::Ner,
            status: Status::Error,
            results: vec![],
            error: Some("boom".into()),
            identity: None,
            gate: None,
        };
        let analysis = decide(request("hello"), vec![failed]).unwrap();
        assert_eq!(analysis.action, Action::Block);
        let bytes = encode_analysis(&analysis, Elapsed::Cleared).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("PriVoke could not complete analysis safely.") && text.contains("ner: boom"), "{text}");
    }

    #[test]
    fn health_and_error_responses_are_minimal() {
        assert_eq!(&health_response()[..2], &[0x0a, 14]);
        assert_eq!(error_response("", "bad"), [0x62, 3, b'b', b'a', b'd']);
        assert_eq!(elapsed_text(12.34567), "12.346");
        assert_eq!(elapsed_text(7.0), "7.0");
    }
}
