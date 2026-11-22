//! `RuntimeServer.AnalyzePrompt` of `runtime_server.py`: V3 semantic inference, semantic-only.
//!
//! The request must select exactly the semantic layer (`layers == [SEMANTIC]`), name the model and carry no presence gate, or it
//! is `INVALID_ARGUMENT`; an empty layer list is refused like any other, never read as the whole detector pipeline. The snapshot
//! is the request's `metadata["v3_checkpoint"]` or else the checkpoint service's current one; the last snapshot used is cached,
//! and any other replaces it.
//!
//! A failure after the request was accepted is not a gRPC error: it is a `BLOCK` response whose `error`, and whose layer's
//! `error`, name the exception, as the Python server answered. The model is the stage 14 reference backend (float32 weights,
//! float64 activations), so confidences and the logits behind them match Torch within the declared tolerance, not bit for bit.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use privoke_contracts::proto::v1::{
    AnalyzePromptRequest, AnalyzePromptResponse, DetectionLayer, RuntimeClassification, RuntimeDetectionResult, RuntimeLayerExecution,
};
use privoke_runtime::model::{Action, Finding, PU, category_names, visibility_by_name, visibility_name};
use privoke_semantic::SemanticClassifier;
use tonic::Status;

use crate::assets::Loaded;
use crate::pyerr::PyError;
use crate::service::Runtime;

/// The layer of every execution this runtime reports.
const SEMANTIC: i32 = DetectionLayer::Semantic as i32;
/// The request metadata key that pins the snapshot.
const CHECKPOINT_KEY: &str = "v3_checkpoint";
/// `reason` of an analysis without a finding.
const CLEAN_REASON: &str = "No privacy risk detected.";

/// `classification(value)`: the named and packed form of a classification.
pub fn classification(packed: u16) -> Result<RuntimeClassification, PyError> {
    let sensitivity = ["S0", "S1", "S2", "S3"][usize::from(packed & 0b11)];
    Ok(RuntimeClassification {
        sensitivity: sensitivity.to_string(),
        visibility: visibility_name(packed)?.to_string(),
        categories: category_names(packed).into_iter().map(str::to_string).collect(),
        packed: u32::from(packed),
    })
}

/// `detection(result)`.
pub fn detection(result: &Finding) -> Result<RuntimeDetectionResult, PyError> {
    let (start, end) = result.span.unwrap_or((0, 0));
    Ok(RuntimeDetectionResult {
        classification: Some(classification(result.classification.pack())?),
        action: result.action()?.name().to_string(),
        section_of_text: result.section.clone(),
        span_start: i32::try_from(start).unwrap_or(i32::MAX),
        span_end: i32::try_from(end).unwrap_or(i32::MAX),
        has_span: result.span.is_some(),
        confidence: result.confidence.unwrap_or(0.0),
        has_confidence: result.confidence.is_some(),
        reasoning: result.reasoning.clone(),
        metadata: result.metadata.clone(),
    })
}

/// `_masked_text`: the prompt with the finding replaced, only for a WARN with a span that matches its section.
pub fn masked_text(text: &str, result: Option<&Finding>, action: Action) -> Option<String> {
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
    masked.push_str("[PRIVOKE_MASKED]");
    masked.extend(chars[end..].iter());
    Some(masked)
}

/// `classification_for_response(Visibility[hint] if hint else None)`: a clean classification of the hinted visibility.
fn clean_classification(hint: &str) -> Result<RuntimeClassification, PyError> {
    let visibility = if hint.is_empty() { PU } else { visibility_by_name(hint).ok_or_else(|| PyError::key(hint))? };
    classification(visibility)
}

/// The result of an accepted request, before it is shaped into a response.
struct Outcome {
    findings: Vec<Finding>,
    clean: RuntimeClassification,
}

fn prefixed(identity: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    identity.iter().map(|(key, value)| (format!("privoke.semantic.{key}"), value.clone())).collect()
}

fn text_of(manifest: &serde_json::Value, key: &str) -> String {
    manifest[key].as_str().unwrap_or_default().to_string()
}

/// The identity block of a snapshot (`identity` of `AnalyzePrompt`).
pub fn identity_of(manifest: &serde_json::Value, sha: &str) -> Result<BTreeMap<String, String>, PyError> {
    let backbone = manifest["source"]["weights_sha256"].as_str().ok_or_else(|| PyError::key("weights_sha256"))?;
    let count = manifest["parameter_count"].to_string();
    Ok([
        ("model_id", text_of(manifest, "model_id")),
        ("model_version", sha.to_string()),
        ("artifact_checksum", sha.to_string()),
        ("parameter_fingerprint", text_of(manifest, "blob")),
        ("parameter_count", count),
        ("backbone_sha256", backbone.to_string()),
        ("tokenizer_sha256", text_of(manifest, "vocab")),
        ("architecture", text_of(manifest, "architecture")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect())
}

impl Runtime {
    /// `AnalyzePrompt`.
    pub async fn analyze_prompt(&self, request: AnalyzePromptRequest) -> Result<AnalyzePromptResponse, Status> {
        if request.layers != [SEMANTIC] || request.semantic_model_id.is_empty() || request.semantic_presence_gate.is_some() {
            return Err(Status::invalid_argument("V3 inference requires explicit sole semantic layer/model and no presence gate."));
        }
        let start = Instant::now();
        let mut identity = BTreeMap::new();
        let outcome = self.analyze_accepted(&request, &mut identity).await;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        Ok(match outcome {
            Ok(outcome) => Self::respond(&request, outcome, &identity, elapsed_ms),
            Err(error) => Self::fail(&request, &error, &identity, elapsed_ms),
        })
    }

    async fn analyze_accepted(&self, request: &AnalyzePromptRequest, identity: &mut BTreeMap<String, String>) -> Result<Outcome, PyError> {
        let mut cache = self.cache.lock().await;
        let pinned = request.metadata.get(CHECKPOINT_KEY).filter(|sha| !sha.is_empty()).cloned();
        let sha = match pinned {
            Some(sha) => sha,
            None => self.checkpoint.resolve_current(&request.semantic_model_id).await.map_err(|status| PyError::rpc(&status))?.sha256,
        };
        if cache.as_ref().is_none_or(|(cached, _)| *cached != sha) {
            *cache = None;
            let loaded = self.load(&sha, false).await?;
            *cache = Some((sha.clone(), Arc::new(loaded)));
        }
        let loaded: Arc<Loaded> = match cache.as_ref() {
            Some((_, loaded)) => Arc::clone(loaded),
            None => return Err(PyError::value("Snapshot cache is empty.")),
        };
        if loaded.manifest["model_id"].as_str() != Some(request.semantic_model_id.as_str()) {
            return Err(PyError::value("Snapshot belongs to another model."));
        }
        *identity = identity_of(&loaded.manifest, &sha)?;
        let text = request.text.clone();
        let metadata = identity.clone();
        let model = Arc::clone(&loaded);
        let findings = tokio::task::spawn_blocking(move || -> Result<Vec<Finding>, PyError> {
            let found = model.model.classify(&text)?;
            Ok(found
                .into_iter()
                .map(|finding| Finding {
                    classification: finding.classification,
                    section: finding.section,
                    reasoning: finding.reasoning,
                    span: finding.span,
                    confidence: Some(finding.confidence),
                    metadata: metadata.clone(),
                })
                .collect())
        })
        .await
        .map_err(|error| PyError::value(error.to_string()))??;
        let clean = clean_classification(&request.visibility_hint)?;
        Ok(Outcome { findings, clean })
    }

    fn respond(
        request: &AnalyzePromptRequest,
        outcome: Outcome,
        identity: &BTreeMap<String, String>,
        elapsed_ms: f64,
    ) -> AnalyzePromptResponse {
        Self::build(request, &outcome, identity, elapsed_ms).unwrap_or_else(|error| Self::fail(request, &error, identity, elapsed_ms))
    }

    fn build(
        request: &AnalyzePromptRequest,
        outcome: &Outcome,
        identity: &BTreeMap<String, String>,
        elapsed_ms: f64,
    ) -> Result<AnalyzePromptResponse, PyError> {
        let result = outcome.findings.first();
        let action = match result {
            Some(result) => result.action()?,
            None => Action::Allow,
        };
        let results = outcome.findings.iter().map(detection).collect::<Result<Vec<_>, _>>()?;
        Ok(AnalyzePromptResponse {
            request_id: request.request_id.clone(),
            action: action.name().to_string(),
            allowed: action != Action::Block,
            masked_text: masked_text(&request.text, result, action).unwrap_or_default(),
            classification: Some(match result {
                Some(result) => classification(result.classification.pack())?,
                None => outcome.clean.clone(),
            }),
            reason: result.map_or_else(|| CLEAN_REASON.to_string(), |result| result.reasoning.clone()),
            evidence: result.map(detection).transpose()?,
            metadata: prefixed(identity),
            layers: vec![RuntimeLayerExecution { layer: SEMANTIC, status: "ok".to_string(), results, ..Default::default() }],
            elapsed_ms,
            error: String::new(),
        })
    }

    fn fail(
        request: &AnalyzePromptRequest,
        error: &PyError,
        identity: &BTreeMap<String, String>,
        elapsed_ms: f64,
    ) -> AnalyzePromptResponse {
        AnalyzePromptResponse {
            request_id: request.request_id.clone(),
            action: Action::Block.name().to_string(),
            allowed: false,
            classification: classification(PU).ok(),
            error: error.to_string(),
            metadata: prefixed(identity),
            layers: vec![RuntimeLayerExecution {
                layer: SEMANTIC,
                status: "error".to_string(),
                error: error.message.clone(),
                ..Default::default()
            }],
            elapsed_ms,
            ..Default::default()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use privoke_rules::classification::{Classification, Sensitivity};

    use super::*;

    fn finding(sensitivity: Sensitivity, text: &str, span: Option<(usize, usize)>) -> Finding {
        Finding {
            classification: Classification::new(sensitivity, PU, 0),
            section: text.to_string(),
            reasoning: "r".to_string(),
            span,
            confidence: Some(0.9),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn a_warn_with_a_matching_span_masks_the_whole_prompt() {
        let text = "héllo wörld";
        let result = finding(Sensitivity::S2, text, Some((0, text.chars().count())));
        assert_eq!(masked_text(text, Some(&result), Action::Warn).as_deref(), Some("[PRIVOKE_MASKED]"));
        assert_eq!(masked_text(text, Some(&result), Action::Block), None);
        assert_eq!(masked_text(text, None, Action::Warn), None);
        let partial = finding(Sensitivity::S2, "wörld", Some((6, 11)));
        assert_eq!(masked_text(text, Some(&partial), Action::Warn).as_deref(), Some("héllo [PRIVOKE_MASKED]"));
        let mismatch = finding(Sensitivity::S2, "other", Some((6, 11)));
        assert_eq!(masked_text(text, Some(&mismatch), Action::Warn), None);
        let empty = finding(Sensitivity::S2, "", None);
        assert_eq!(masked_text("", Some(&empty), Action::Warn), None);
    }

    #[test]
    fn a_clean_classification_takes_the_hinted_visibility_and_a_bad_hint_is_a_key_error() {
        assert_eq!(clean_classification("").unwrap().visibility, "PU");
        assert_eq!(clean_classification("P2").unwrap().visibility, "P2");
        assert_eq!(clean_classification("P2").unwrap().packed, 0b01100);
        assert_eq!(clean_classification("p2").unwrap_err().to_string(), "KeyError: 'p2'");
    }

    #[test]
    fn the_identity_names_the_snapshot_and_the_pinned_backbone() {
        let manifest = serde_json::json!({
            "model_id": "privoke-v3-efficient", "blob": "b", "vocab": "v", "architecture": "arch", "parameter_count": 4785044,
            "source": {"weights_sha256": "w"}
        });
        let identity = identity_of(&manifest, "sha").unwrap();
        assert_eq!(identity["model_version"], "sha");
        assert_eq!(identity["artifact_checksum"], "sha");
        assert_eq!(identity["parameter_fingerprint"], "b");
        assert_eq!(identity["parameter_count"], "4785044");
        assert_eq!(identity["backbone_sha256"], "w");
        assert_eq!(identity["tokenizer_sha256"], "v");
        assert_eq!(prefixed(&identity)["privoke.semantic.model_id"], "privoke-v3-efficient");
    }
}
