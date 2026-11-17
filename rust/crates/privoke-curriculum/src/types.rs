//! `training.types`: the example and configuration records the trainer and the samplers pass around.

use std::collections::BTreeMap;

use crate::classification::Classification;
use crate::error::{Error, Result};

/// `BatchTrainingConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchTrainingConfig {
    /// `learning_rate`.
    pub learning_rate: f64,
    /// `max_gradient`.
    pub max_gradient: f64,
    /// `new_example_weight`.
    pub new_example_weight: f64,
    /// `golden_example_weight`.
    pub golden_example_weight: f64,
    /// `transformations_per_example`.
    pub transformations_per_example: i64,
    /// `seed`.
    pub seed: u64,
}

impl Default for BatchTrainingConfig {
    fn default() -> Self {
        Self {
            learning_rate: 0.03,
            max_gradient: 0.05,
            new_example_weight: 1.0,
            golden_example_weight: 0.35,
            transformations_per_example: 1,
            seed: 42,
        }
    }
}

/// `BatchTrainingExample`.
#[derive(Debug, Clone, PartialEq)]
pub struct Example {
    /// `text`.
    pub text: String,
    /// `expected_classification`.
    pub target: Option<Classification>,
    /// `weight`.
    pub weight: f64,
    /// `metadata`.
    pub metadata: BTreeMap<String, String>,
}

impl Example {
    /// `BatchTrainingExample(text, target, weight, metadata)`.
    pub fn new(text: impl Into<String>, target: Classification, weight: f64, metadata: BTreeMap<String, String>) -> Self {
        Self { text: text.into(), target: Some(target), weight, metadata }
    }

    /// The explicit target, refusing an unlabeled example.
    pub fn classification(&self) -> Result<Classification> {
        self.target.ok_or_else(|| Error::Invalid("Contextual role-quota rows require explicit classification targets.".to_string()))
    }

    /// `expected_packed_classification`.
    pub fn packed(&self) -> Option<u16> {
        self.target.map(Classification::pack)
    }

    /// `with_text_and_weight(text, weight)`.
    pub fn with_text_and_weight(&self, text: String, weight: f64) -> Self {
        Self { text, target: self.target, weight, metadata: self.metadata.clone() }
    }

    /// `metadata[key]`.
    pub fn meta(&self, key: &str) -> Result<&str> {
        self.metadata.get(key).map(String::as_str).ok_or_else(|| Error::Invalid(format!("missing metadata {key}")))
    }

    /// `metadata.get(key)`.
    pub fn meta_opt(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

/// `{**metadata, key: value, ...}`.
pub fn with_entries(metadata: &BTreeMap<String, String>, entries: &[(&str, String)]) -> BTreeMap<String, String> {
    let mut out = metadata.clone();
    for (key, value) in entries {
        out.insert((*key).to_string(), value.clone());
    }
    out
}
