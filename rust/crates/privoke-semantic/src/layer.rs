//! The semantic layer as the pipeline runs it: normalise, classify, map spans to the original prompt
//! (`pipeline.analyse_text(text, layers=["semantic"])`).

use privoke_rules::classification::Classification;
use privoke_rules::preprocessing::normalize_with_offsets;

use crate::error::SemanticError;

/// One finding of a classifier, in the coordinates of the text it was given.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The classification.
    pub classification: Classification,
    /// The reported confidence.
    pub confidence: f64,
    /// `reasoning`.
    pub reasoning: String,
    /// `(0, len(text))`, or `None` for an empty text.
    pub span: Option<(usize, usize)>,
    /// `section_of_text`: the whole text.
    pub section: String,
}

/// A model that classifies one text (`model.classify` of the Python wrappers).
pub trait SemanticClassifier {
    /// Findings for `text`, which the pipeline has already normalised. An `Err` is the layer's error.
    fn classify(&self, text: &str) -> Result<Vec<Finding>, SemanticError>;
}

/// One finding of the semantic layer, spans remapped to the original prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerHit {
    /// Span in the original prompt, or `None` when it cannot be mapped.
    pub span: Option<(usize, usize)>,
    /// The original text of the span, or the classified text when unmapped.
    pub text: String,
    /// Classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
    /// `reasoning`.
    pub reasoning: String,
}

/// Outcome of the semantic layer.
#[derive(Debug, Clone, PartialEq)]
pub enum LayerOutcome {
    /// Status `ok`.
    Ok(Vec<LayerHit>),
    /// Status `error`, with `str(exception)` of the failure.
    Error(String),
}

/// Run the semantic layer on one prompt (LLM-only: no regex or NER layer is involved).
pub fn analyse_semantic_layer(model: &impl SemanticClassifier, text: &str) -> LayerOutcome {
    let normalised = match normalize_with_offsets(text, true, None) {
        Ok(normalised) => normalised,
        Err(error) => return LayerOutcome::Error(error.to_string()),
    };
    let findings = match model.classify(normalised.text()) {
        Ok(findings) => findings,
        Err(error) => return LayerOutcome::Error(error.to_string()),
    };
    let hits = findings
        .into_iter()
        .map(|finding| {
            let original_span = finding.span.and_then(|span| normalised.original_span(span));
            let original = original_span.and_then(|(start, end)| normalised.original().get(start..end));
            let text = original.map_or_else(|| finding.section.clone(), |chars| chars.iter().collect::<String>());
            LayerHit {
                span: original.and(original_span),
                text,
                classification: finding.classification,
                confidence: finding.confidence,
                reasoning: finding.reasoning,
            }
        })
        .collect();
    LayerOutcome::Ok(hits)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use privoke_rules::classification::{Sensitivity, visibility};

    use super::*;

    struct Fixed(Result<Vec<Finding>, String>);

    impl SemanticClassifier for Fixed {
        fn classify(&self, text: &str) -> Result<Vec<Finding>, SemanticError> {
            match &self.0 {
                Ok(findings) => Ok(findings
                    .iter()
                    .map(|f| Finding {
                        span: if text.is_empty() { None } else { Some((0, text.chars().count())) },
                        section: text.to_string(),
                        ..f.clone()
                    })
                    .collect()),
                Err(message) => Err(SemanticError::Input(message.clone())),
            }
        }
    }

    fn finding() -> Finding {
        Finding {
            classification: Classification::new(Sensitivity::S1, visibility::P0, 0),
            confidence: 0.5,
            reasoning: "r".into(),
            span: None,
            section: String::new(),
        }
    }

    #[test]
    fn spans_map_back_to_the_original_prompt() {
        let outcome = analyse_semantic_layer(&Fixed(Ok(vec![finding()])), "Hello \u{FF21}BC");
        let LayerOutcome::Ok(hits) = outcome else { panic!("expected findings") };
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].span, Some((0, 9)));
        assert_eq!(hits[0].text, "Hello \u{FF21}BC");
    }

    #[test]
    fn an_empty_prompt_has_no_span() {
        let LayerOutcome::Ok(hits) = analyse_semantic_layer(&Fixed(Ok(vec![finding()])), "") else { panic!("expected findings") };
        assert_eq!(hits[0].span, None);
        assert_eq!(hits[0].text, "");
    }

    #[test]
    fn classifier_errors_become_the_layer_error() {
        assert_eq!(analyse_semantic_layer(&Fixed(Err("too long".into())), "x"), LayerOutcome::Error("too long".into()));
    }
}
