//! The NER layer as the pipeline runs it: normalise, detect, map spans to the original prompt
//! (`pipeline.analyse_text(text, layers=["ner"])`).

use privoke_rules::classification::Classification;
use privoke_rules::preprocessing::{NormalizeError, RobustnessOptions, env_bool, env_bool_with, normalize_with_offsets};

use crate::analyzer::{NerError, SpacyBackend};
use crate::detector::{EntityNerDetector, Extraction, NerOptions, NerResult};
use crate::pytext;

/// Options of one NER-layer run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerOptions {
    /// `PRIVOKE_CASE_PRESERVING_DETECTORS`: the NER layer sees case-preserved text.
    pub case_preserving: bool,
    /// Robustness flags for the case-preserved view; `None` follows the `PRIVOKE_*` variables.
    pub robustness: Option<RobustnessOptions>,
    /// The detector settings.
    pub ner: NerOptions,
}

impl Default for LayerOptions {
    fn default() -> Self {
        Self { case_preserving: true, robustness: Some(RobustnessOptions::default()), ner: NerOptions::default() }
    }
}

impl LayerOptions {
    /// The `PRIVOKE_*` variables (default on for case preservation, default off for every robustness flag).
    pub fn from_env() -> Self {
        Self { case_preserving: env_bool("PRIVOKE_CASE_PRESERVING_DETECTORS", true), robustness: None, ner: NerOptions::from_env() }
    }

    /// The same, reading variables through `lookup`; the robustness flags are resolved now.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        Self {
            case_preserving: env_bool_with(lookup, "PRIVOKE_CASE_PRESERVING_DETECTORS", true),
            robustness: Some(RobustnessOptions::from_lookup(lookup)),
            ner: NerOptions::from_lookup(lookup),
        }
    }
}

/// One finding of the NER layer, spans remapped to the original prompt.
#[derive(Clone, Debug, PartialEq)]
pub struct LayerHit {
    /// `metadata["label"]`.
    pub label: String,
    /// `metadata["entity_type"]`.
    pub entity_type: &'static str,
    /// `metadata["model"]`.
    pub model: String,
    /// Span in the original prompt, or `None` when it cannot be mapped.
    pub span: Option<(usize, usize)>,
    /// The original text of the span, or the matched text when unmapped.
    pub text: String,
    /// Classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
    /// `reasoning`.
    pub reasoning: String,
    /// `metadata["postfilter_rule"]`.
    pub postfilter_rule: Option<String>,
}

/// Outcome of the NER layer.
#[derive(Clone, Debug, PartialEq)]
pub enum LayerOutcome {
    /// Status `ok`: findings and the post-filter's decision log (spans are those of the text spaCy saw).
    Ok(Vec<LayerHit>, Extraction),
    /// Status `error`, with `str(exception)`.
    Error(String),
}

/// Run the NER layer on one prompt.
///
/// An `Err` is a failure Python would also report as an error layer; [`LayerOutcome::Error`] carries the message of
/// failures Python reports through `normalize_with_offsets`.
pub async fn analyse_ner_layer<A: SpacyBackend>(
    detector: &EntityNerDetector<A>,
    text: &str,
    options: &LayerOptions,
) -> Result<LayerOutcome, NerError> {
    let normalised = if options.case_preserving {
        normalize_with_offsets(text, false, options.robustness)
    } else {
        normalize_with_offsets(text, true, None)
    };
    let normalised = match normalised {
        Ok(normalised) => normalised,
        Err(error @ NormalizeError::UnknownDigitWord(_)) => return Ok(LayerOutcome::Error(error.to_string())),
        Err(NormalizeError::Pattern(error)) => return Err(NerError::Pattern(error)),
    };
    let extraction = detector.extract_entities(normalised.text(), &options.ner).await?;
    let mut hits = Vec::with_capacity(extraction.results.len());
    for result in &extraction.results {
        hits.push(remap(&normalised, result));
    }
    Ok(LayerOutcome::Ok(hits, extraction))
}

fn remap(normalised: &privoke_rules::NormalizedText, result: &NerResult) -> LayerHit {
    let (start, end) = result.span;
    let chars = normalised.chars();
    let section_matches = chars.len() >= end && start <= end && pytext::string(&chars[start..end]) == result.text;
    let original_span = normalised.original_span(result.span).filter(|_| section_matches);
    let text = match original_span {
        Some((a, b)) => pytext::string(&normalised.original()[a..b]),
        None => result.text.clone(),
    };
    LayerHit {
        label: result.label.clone(),
        entity_type: result.entity_type,
        model: result.model.clone(),
        span: original_span,
        text,
        classification: result.classification,
        confidence: result.confidence,
        reasoning: result.reasoning.clone(),
        postfilter_rule: result.postfilter_rule.clone(),
    }
}
