//! The regex layer as the pipeline runs it: normalise, detect, map spans to the original prompt
//! (`pipeline.analyse_text(text, layers=["regex"])`).

use crate::classification::Classification;
use crate::detector::{Detector, DetectorError, RuleSetOptions};
use crate::preprocessing::{NormalizeError, RobustnessOptions, env_bool, env_bool_with, normalize_with_offsets};

/// Options of one regex-layer run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerOptions {
    /// `PRIVOKE_CASE_PRESERVING_DETECTORS`: the regex layer sees case-preserved text.
    pub case_preserving: bool,
    /// Robustness flags for the case-preserved view; `None` follows the `PRIVOKE_*` variables.
    pub robustness: Option<RobustnessOptions>,
}

impl Default for LayerOptions {
    fn default() -> Self {
        Self { case_preserving: true, robustness: Some(RobustnessOptions::default()) }
    }
}

impl LayerOptions {
    /// Read `PRIVOKE_CASE_PRESERVING_DETECTORS` (default on) and the robustness variables.
    pub fn from_env() -> Self {
        Self { case_preserving: env_bool("PRIVOKE_CASE_PRESERVING_DETECTORS", true), robustness: None }
    }

    /// The same, reading variables through `lookup`; the robustness flags are resolved now.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        Self {
            case_preserving: env_bool_with(lookup, "PRIVOKE_CASE_PRESERVING_DETECTORS", true),
            robustness: Some(RobustnessOptions::from_lookup(lookup)),
        }
    }
}

/// One finding of the regex layer, spans remapped to the original prompt.
#[derive(Clone, Debug, PartialEq)]
pub struct LayerHit {
    /// Rule name (`metadata["rule_name"]`).
    pub rule_name: String,
    /// Span in the original prompt, or `None` when it cannot be mapped.
    pub span: Option<(usize, usize)>,
    /// The original text of the span, or the matched canonical text when unmapped.
    pub text: String,
    /// Classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
}

/// Outcome of the regex layer: findings, or the error message of the failed layer.
#[derive(Clone, Debug, PartialEq)]
pub enum LayerOutcome {
    /// Status `ok`.
    Ok(Vec<LayerHit>),
    /// Status `error`, with `str(exception)`.
    Error(String),
}

/// Run the regex layer on one prompt.
pub fn analyse_regex_layer(detector: &Detector, text: &str, options: &LayerOptions) -> Result<LayerOutcome, DetectorError> {
    let normalised = if options.case_preserving {
        normalize_with_offsets(text, false, options.robustness)
    } else {
        normalize_with_offsets(text, true, None)
    };
    let normalised = match normalised {
        Ok(normalised) => normalised,
        Err(error @ NormalizeError::UnknownDigitWord(_)) => return Ok(LayerOutcome::Error(error.to_string())),
        Err(NormalizeError::Pattern(error)) => return Err(DetectorError::Pattern(error)),
    };
    let hits = detector.analyze(normalised.text())?;
    let mut remapped = Vec::with_capacity(hits.len());
    for hit in hits {
        let original_span =
            normalised.original_span(hit.span).filter(|_| normalised.chars()[hit.span.0..hit.span.1].iter().copied().eq(hit.text.chars()));
        let (span, text) = match original_span {
            Some((a, b)) => (Some((a, b)), normalised.original()[a..b].iter().collect()),
            None => (None, hit.text.clone()),
        };
        remapped.push(LayerHit {
            rule_name: hit.rule_name.clone(),
            span,
            text,
            classification: hit.classification,
            confidence: hit.confidence,
        });
    }
    Ok(LayerOutcome::Ok(remapped))
}

/// Build the detector for the `PRIVOKE_REGEX_*` variables and run one prompt (convenience).
pub fn analyse_from_env(text: &str) -> Result<LayerOutcome, DetectorError> {
    let detector = Detector::new(RuleSetOptions::from_env())?;
    analyse_regex_layer(&detector, text, &LayerOptions::from_env())
}
