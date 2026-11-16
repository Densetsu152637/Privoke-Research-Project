//! The NER layer of the PriVoke client runtime, ported from `extension/client-runtime/src/NER` (stage 13).
//!
//! * [`detector`]: `EntityNERDetector`, including the caseless gate (`has_case_signal`, `fold_case`,
//!   `CASELESS_DISABLED_RULES`).
//! * [`postfilter`]: both post-filter stages and all their rules, with the decision log. The common-word rule re-tags
//!   a lower-cased phrase through the tagger-only selection and reads the lexicon from the model's `lemma_index`.
//! * [`usecases`]: the label to classification table.
//! * [`pattern`]: the experimental pattern entity detector (cues, shapes, recurrence, optional gazetteer).
//! * [`layer`]: the layer as the pipeline runs it, with normalisation from `privoke-rules` and span remapping to the
//!   original prompt.
//!
//! spaCy is reached through the [`SpacyBackend`] trait, implemented for the stage 11 [`privoke_spacy::SpacyPool`]; the
//! parity tests replay recorded analyses through [`replay::ReplayAnalyzer`] instead. All offsets are code point
//! indexes, as in Python.
//!
//! Python's text semantics come from tables generated from the reference interpreter ([`unicode_tables`], Unicode
//! 14.0.0) and from `privoke_rules::pyunicode`, never from Rust's `char` predicates.

pub mod analyzer;
pub mod detector;
pub mod layer;
pub(crate) mod pat;
pub mod pattern;
pub mod postfilter;
pub mod pytext;
pub mod replay;
#[rustfmt::skip]
pub mod unicode_tables;
pub mod usecases;

pub use analyzer::{NerError, SpacyBackend};
pub use detector::{EntityNerDetector, Extraction, NerOptions, NerResult};
pub use layer::{LayerHit, LayerOptions, LayerOutcome, analyse_ner_layer};
pub use postfilter::{Decision, Stage};
