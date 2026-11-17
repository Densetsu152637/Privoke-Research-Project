//! The detection pipeline (`pipeline.analyse_text`): which layers run, in which order, and what a layer's outcome is.
//!
//! The regex and NER layers are the stage 12 and 13 crates, composed here the way `pipeline.py` composes them: with the
//! regex layer first when `PRIVOKE_WAIT_FOR_REGEX` or the request says so, the other layers skipped when it returns
//! `BLOCK`, and an error in a layer reported as that layer's outcome (which blocks an otherwise ALLOW decision).
//!
//! The semantic layer runs only when the pipeline was given model roots ([`Pipeline::with_semantic`]); without them a
//! selection that names it is refused by the service, and the supervisor routes it to the Python worker.

use std::collections::BTreeMap;

use privoke_ner_layer::{EntityNerDetector, LayerOptions as NerLayerOptions, LayerOutcome as NerOutcome, SpacyBackend, analyse_ner_layer};
use privoke_rules::preprocessing::env_bool;
use privoke_rules::{Detector, LayerOptions as RegexLayerOptions, LayerOutcome as RegexOutcome, analyse_regex_layer};

use crate::model::{Action, Finding, InvalidVisibility, strongest_result};
use crate::request::Layer;
use crate::semantic::SemanticLayer;

/// The status of one layer's execution (`LayerExecution.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The layer ran.
    Ok,
    /// The layer failed; its message is the execution's error.
    Error,
    /// The layer was not run because the regex layer returned `BLOCK`.
    Skipped,
}

impl Status {
    /// The status text of `RuntimeLayerExecution.status`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }
}

/// One layer's outcome (`LayerExecution`).
#[derive(Debug, Clone, PartialEq)]
pub struct LayerExecution {
    /// The layer.
    pub layer: Layer,
    /// The status.
    pub status: Status,
    /// The findings, in the layer's own order, in the coordinates of the original prompt.
    pub results: Vec<Finding>,
    /// The error text of an `Error` or `Skipped` layer.
    pub error: Option<String>,
    /// The identity of the model that classified (`LayerExecution.semantic_model_identity`), for a semantic layer that ran.
    pub identity: Option<BTreeMap<String, String>>,
}

impl LayerExecution {
    fn ok(layer: Layer, results: Vec<Finding>) -> Self {
        Self { layer, status: Status::Ok, results, error: None, identity: None }
    }

    fn failed(layer: Layer, message: String) -> Self {
        Self { layer, status: Status::Error, results: Vec::new(), error: Some(message), identity: None }
    }
}

/// Why the pipeline could not produce an analysis at all (the servicer turns these into the response's `error`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipelineError {
    /// A classification outside the visibility enum reached the aggregation.
    #[error(transparent)]
    Visibility(#[from] InvalidVisibility),
    /// A layer this worker does not serve.
    #[error("The {} layer is not served by the Rust worker.", .0.name())]
    Unsupported(Layer),
}

/// The settings Python reads from `GLOBAL_CONFIG` at each call.
#[derive(Debug, Clone, Copy)]
pub struct PipelineOptions {
    /// The regex layer (case preservation and robustness flags).
    pub regex: RegexLayerOptions,
    /// The NER layer (case preservation, robustness flags, caseless gate, post-filter).
    pub ner: NerLayerOptions,
    /// `PRIVOKE_WAIT_FOR_REGEX` (default on): the regex layer runs first and a `BLOCK` skips the rest.
    pub wait_for_regex: bool,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self { regex: RegexLayerOptions::default(), ner: NerLayerOptions::default(), wait_for_regex: true }
    }
}

impl PipelineOptions {
    /// The `PRIVOKE_*` variables, read once at start-up.
    pub fn from_env() -> Self {
        Self {
            regex: RegexLayerOptions::from_env(),
            ner: NerLayerOptions::from_env(),
            wait_for_regex: env_bool("PRIVOKE_WAIT_FOR_REGEX", true),
        }
    }
}

/// The pipeline over its two detectors.
#[derive(Debug)]
pub struct Pipeline<A> {
    regex: Detector,
    ner: EntityNerDetector<A>,
    semantic: Option<SemanticLayer>,
    options: PipelineOptions,
}

fn error_message(message: String, kind: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() { kind.to_string() } else { message }
}

impl<A: SpacyBackend> Pipeline<A> {
    /// A pipeline over a built regex detector and an NER detector.
    pub fn new(regex: Detector, ner: EntityNerDetector<A>, options: PipelineOptions) -> Self {
        Self { regex, ner, semantic: None, options }
    }

    /// Adds the semantic layer over the model roots.
    #[must_use]
    pub fn with_semantic(mut self, semantic: SemanticLayer) -> Self {
        self.semantic = Some(semantic);
        self
    }

    /// True when the semantic layer is configured.
    pub fn serves_semantic(&self) -> bool {
        self.semantic.is_some()
    }

    /// The NER detector (its spaCy source).
    pub fn ner(&self) -> &EntityNerDetector<A> {
        &self.ner
    }

    fn regex_layer(&self, text: &str) -> LayerExecution {
        match analyse_regex_layer(&self.regex, text, &self.options.regex) {
            Ok(RegexOutcome::Ok(hits)) => LayerExecution::ok(
                Layer::Regex,
                hits.into_iter()
                    .map(|hit| Finding {
                        classification: hit.classification,
                        section: hit.text,
                        reasoning: format!("Matched rule '{}'", hit.rule_name),
                        span: hit.span,
                        confidence: Some(hit.confidence),
                        metadata: BTreeMap::from([("rule_name".to_string(), hit.rule_name)]),
                    })
                    .collect(),
            ),
            Ok(RegexOutcome::Error(message)) => LayerExecution::failed(Layer::Regex, error_message(message, "RuntimeError")),
            Err(error) => LayerExecution::failed(Layer::Regex, error_message(error.to_string(), "RuntimeError")),
        }
    }

    async fn ner_layer(&self, text: &str) -> LayerExecution {
        match analyse_ner_layer(&self.ner, text, &self.options.ner).await {
            Ok(NerOutcome::Ok(hits, _decisions)) => LayerExecution::ok(
                Layer::Ner,
                hits.into_iter()
                    .map(|hit| {
                        let mut metadata = BTreeMap::from([
                            ("label".to_string(), hit.label),
                            ("entity_type".to_string(), hit.entity_type.to_string()),
                            ("model".to_string(), hit.model),
                        ]);
                        if let Some(rule) = hit.postfilter_rule {
                            metadata.insert("postfilter_rule".to_string(), rule);
                        }
                        Finding {
                            classification: hit.classification,
                            section: hit.text,
                            reasoning: hit.reasoning,
                            span: hit.span,
                            confidence: Some(hit.confidence),
                            metadata,
                        }
                    })
                    .collect(),
            ),
            Ok(NerOutcome::Error(message)) => LayerExecution::failed(Layer::Ner, error_message(message, "RuntimeError")),
            Err(error) => LayerExecution::failed(Layer::Ner, error_message(error.to_string(), "RuntimeError")),
        }
    }

    /// `analyse_text` for the named layers (in pipeline order, without duplicates). `regex_first` overrides
    /// `PRIVOKE_WAIT_FOR_REGEX`. The executions come back in the order of `layers`.
    pub async fn analyse(
        &self,
        text: &str,
        layers: &[Layer],
        regex_first: Option<bool>,
        semantic_model_id: Option<&str>,
    ) -> Result<Vec<LayerExecution>, PipelineError> {
        if self.semantic.is_none()
            && let Some(layer) = layers.iter().find(|layer| **layer == Layer::Semantic)
        {
            return Err(PipelineError::Unsupported(*layer));
        }
        let run_regex_first = regex_first.unwrap_or(self.options.wait_for_regex);
        let mut completed: BTreeMap<Layer, LayerExecution> = BTreeMap::new();
        if layers.contains(&Layer::Regex) && run_regex_first {
            let execution = self.regex_layer(text);
            let (_, action) = strongest_result(&execution.results)?;
            completed.insert(Layer::Regex, execution);
            if action == Action::Block {
                for layer in layers.iter().filter(|layer| **layer != Layer::Regex) {
                    completed.insert(
                        *layer,
                        LayerExecution {
                            layer: *layer,
                            status: Status::Skipped,
                            results: Vec::new(),
                            error: Some("Skipped after regex returned BLOCK.".to_string()),
                            identity: None,
                        },
                    );
                }
                return Ok(ordered(layers, completed));
            }
        }
        for layer in layers {
            if completed.contains_key(layer) {
                continue;
            }
            let execution = match layer {
                Layer::Regex => self.regex_layer(text),
                Layer::Ner => self.ner_layer(text).await,
                Layer::Semantic => match &self.semantic {
                    Some(semantic) => semantic.run(text, semantic_model_id),
                    None => return Err(PipelineError::Unsupported(*layer)),
                },
            };
            completed.insert(*layer, execution);
        }
        Ok(ordered(layers, completed))
    }
}

fn ordered(layers: &[Layer], mut completed: BTreeMap<Layer, LayerExecution>) -> Vec<LayerExecution> {
    layers.iter().filter_map(|layer| completed.remove(layer)).collect()
}
