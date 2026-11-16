//! The spaCy entity detector (`NER/ner_detector.py::EntityNERDetector`): caseless gate, post-filter, results.

use std::collections::HashSet;
use std::sync::Arc;

use privoke_rules::classification::Classification;
use privoke_rules::preprocessing::env_bool_with;
use privoke_spacy::{Entity, Selection};

use crate::analyzer::{NerError, SpacyBackend};
use crate::postfilter::{CASELESS_DISABLED_RULES, Decision, Doc, fold_case, has_case_signal, postfilter};
use crate::pytext;
use crate::usecases::use_case;

/// The default spaCy model name (`PRIVOKE_NER_MODEL`).
pub const DEFAULT_MODEL: &str = "en_core_web_sm";

/// The detector settings that Python reads from `GLOBAL_CONFIG` at each call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NerOptions {
    /// `PRIVOKE_NER_CASELESS_GATE` (default off): a prompt with no case signal is lower-cased before spaCy.
    pub caseless_gate: bool,
    /// `PRIVOKE_NER_POSTFILTER` (default on).
    pub postfilter: bool,
}

impl Default for NerOptions {
    fn default() -> Self {
        Self { caseless_gate: false, postfilter: true }
    }
}

impl NerOptions {
    /// The `PRIVOKE_NER_*` variables.
    pub fn from_env() -> Self {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// The same, reading variables through `lookup`.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        Self {
            caseless_gate: env_bool_with(lookup, "PRIVOKE_NER_CASELESS_GATE", false),
            postfilter: env_bool_with(lookup, "PRIVOKE_NER_POSTFILTER", true),
        }
    }
}

/// One classification result of the NER layer, spans in the text spaCy saw (code points).
#[derive(Clone, Debug, PartialEq)]
pub struct NerResult {
    /// `metadata["label"]`.
    pub label: String,
    /// `metadata["entity_type"]`.
    pub entity_type: &'static str,
    /// `metadata["model"]`.
    pub model: String,
    /// `ent.start_char`, `ent.end_char`.
    pub span: (usize, usize),
    /// `ent.text`.
    pub text: String,
    /// The packed classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
    /// `reasoning`.
    pub reasoning: String,
    /// `metadata["postfilter_rule"]`, present when the post-filter decided.
    pub postfilter_rule: Option<String>,
}

/// What one detector call returns: the results and the post-filter's decision log.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Extraction {
    /// Results, in decision order.
    pub results: Vec<NerResult>,
    /// Every post-filter decision (empty when the post-filter is off).
    pub decisions: Vec<Decision>,
}

/// Entity extraction backed by spaCy NER labels.
#[derive(Debug)]
pub struct EntityNerDetector<A> {
    analyzer: A,
    model_name: String,
    lexicon: Arc<HashSet<String>>,
}

impl<A: SpacyBackend> EntityNerDetector<A> {
    /// A detector over `analyzer`; loads the model's lemma-index word list once (`_english_lexicon`).
    pub async fn new(analyzer: A, model_name: &str) -> Result<Self, NerError> {
        let lexicon = analyzer.lemma_index().await?.iter().cloned().collect();
        Ok(Self { analyzer, model_name: model_name.to_owned(), lexicon: Arc::new(lexicon) })
    }

    /// A detector that shares an already loaded lexicon (see [`EntityNerDetector::lexicon`]).
    pub fn with_lexicon(analyzer: A, model_name: &str, lexicon: Arc<HashSet<String>>) -> Self {
        Self { analyzer, model_name: model_name.to_owned(), lexicon }
    }

    /// The lexicon (the model's lemma-index word list).
    pub fn lexicon(&self) -> Arc<HashSet<String>> {
        self.lexicon.clone()
    }

    /// The spaCy source.
    pub fn analyzer(&self) -> &A {
        &self.analyzer
    }

    /// The model name recorded in result metadata.
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// `EntityNERDetector.extract_entities` for the given settings.
    pub async fn extract_entities(&self, text: &str, options: &NerOptions) -> Result<Extraction, NerError> {
        let original: Vec<char> = text.chars().collect();
        let caseless = options.caseless_gate && !has_case_signal(&original)?;
        let chars = if caseless { fold_case(&original) } else { original };
        if chars.is_empty() {
            return Ok(Extraction::default());
        }
        let spacy_text = pytext::string(&chars);
        let analysis = self.analyzer.analyze(&spacy_text, Selection::Full).await?;
        let entities: Vec<Entity> = analysis.entities.clone();
        let doc = Doc::new(chars, analysis);
        if options.postfilter {
            let disabled: &[&str] = if caseless { &CASELESS_DISABLED_RULES } else { &[] };
            return self.postfiltered(&doc, &entities, disabled).await;
        }
        Ok(Extraction { results: self.classified(&doc, &entities), decisions: Vec::new() })
    }

    async fn postfiltered(&self, doc: &Doc, ents: &[Entity], disabled: &[&str]) -> Result<Extraction, NerError> {
        let mut candidates: Vec<Entity> = Vec::new();
        let mut seen = HashSet::new();
        for ent in ents {
            if use_case(&ent.label).is_none() {
                continue;
            }
            let key = (ent.span.start_char, ent.span.end_char, ent.label.clone());
            if seen.insert(key) {
                candidates.push(ent.clone());
            }
        }
        let decisions = postfilter(
            doc,
            &candidates,
            Some(&self.analyzer),
            &self.lexicon,
            disabled,
            Some(privoke_rules::classification::Sensitivity::S1),
        )
        .await?;
        let mut results = Vec::new();
        for decision in &decisions {
            if let Some(result) = decision.keep.then(|| self.decided_entity(decision)).flatten() {
                results.push(result);
            }
        }
        Ok(Extraction { results, decisions })
    }

    fn decided_entity(&self, decision: &Decision) -> Option<NerResult> {
        let candidate = &decision.candidate;
        let case = use_case(&candidate.label)?;
        let classification = decision.sensitivity.map_or_else(|| case.classification(), |s| case.with_sensitivity(s));
        Some(NerResult {
            label: candidate.label.clone(),
            entity_type: case.entity_type,
            model: self.model_name.clone(),
            span: (candidate.start, candidate.end),
            text: candidate.text.clone(),
            classification,
            confidence: case.confidence,
            reasoning: format!("spaCy labelled this span as {}", candidate.label),
            postfilter_rule: Some(decision.rule.clone()),
        })
    }

    fn classified(&self, doc: &Doc, ents: &[Entity]) -> Vec<NerResult> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();
        for ent in ents {
            let Some(case) = use_case(&ent.label) else { continue };
            if !seen.insert((ent.span.start_char, ent.span.end_char, ent.label.clone())) {
                continue;
            }
            results.push(NerResult {
                label: ent.label.clone(),
                entity_type: case.entity_type,
                model: self.model_name.clone(),
                span: (ent.span.start_char, ent.span.end_char),
                text: pytext::string(pytext::slice(&doc.chars, ent.span.start_char, ent.span.end_char)),
                classification: case.classification(),
                confidence: case.confidence,
                reasoning: format!("spaCy labelled this span as {}", ent.label),
                postfilter_rule: None,
            });
        }
        results
    }
}
