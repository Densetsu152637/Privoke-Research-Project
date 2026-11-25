//! The ONNX Runtime implementation of [`GlinerModel`] (cargo feature `gliner-ort`, off by default).
//!
//! The checkpoint directory holds `tokenizer.json`, `gliner_config.json` and an ONNX export of the span model
//! (`onnx/model*.onnx`). ONNX Runtime is loaded dynamically (`ort` feature `load-dynamic`): set `ORT_DYLIB_PATH` to the
//! runtime library, so building needs no download.
//!
//! The graph inputs are the span-model inputs of the GLiNER export: `input_ids`, `attention_mask`, `words_mask`,
//! `text_lengths`, `span_idx` and `span_mask`, and the output is `logits` of shape `[1, words, max_width, classes]`.
//! Input construction and decoding are the tested functions of [`crate::gliner`].

use std::path::Path;
use std::sync::Mutex;

use ort::session::Session;
use ort::value::Tensor;
use tokenizers::{Tokenizer, TruncationParams};

use crate::analyzer::NerError;
use crate::gliner::{Found, GlinerModel, decode_spans, prompt_words, span_inputs, split_words, words_mask};
use crate::pytext;

fn fail(what: impl std::fmt::Display) -> NerError {
    NerError::SpacyBackend(format!("GLiNER backend: {what}"))
}

/// The fields of `gliner_config.json` the backend reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlinerConfig {
    /// Widest span in words (`max_width`, default 12).
    pub max_width: usize,
    /// Longest input in words and subwords (`max_len`, default 384).
    pub max_len: usize,
    /// The entity marker word (`ent_token`, default `<<ENT>>`).
    pub ent_token: String,
    /// The separator word (`sep_token`, default `<<SEP>>`).
    pub sep_token: String,
}

impl GlinerConfig {
    /// Reads the configuration, taking GLiNER's defaults for absent keys.
    pub fn from_json(text: &str) -> Result<Self, NerError> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(fail)?;
        let number = |key: &str, default: usize| value.get(key).and_then(serde_json::Value::as_u64).map_or(default, |v| v as usize);
        let string = |key: &str, default: &str| value.get(key).and_then(serde_json::Value::as_str).unwrap_or(default).to_owned();
        Ok(Self {
            max_width: number("max_width", 12),
            max_len: number("max_len", 384),
            ent_token: string("ent_token", "<<ENT>>"),
            sep_token: string("sep_token", "<<SEP>>"),
        })
    }
}

/// A GLiNER span model run by ONNX Runtime.
pub struct GlinerOrt {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    config: GlinerConfig,
}

impl std::fmt::Debug for GlinerOrt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlinerOrt").field("config", &self.config).finish_non_exhaustive()
    }
}

impl GlinerOrt {
    /// Loads `tokenizer.json` and `gliner_config.json` from `dir` and the ONNX graph at `onnx`.
    pub fn load(dir: &Path, onnx: &Path) -> Result<Self, NerError> {
        let config = GlinerConfig::from_json(&std::fs::read_to_string(dir.join("gliner_config.json")).map_err(fail)?)?;
        let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json")).map_err(fail)?;
        tokenizer.with_truncation(Some(TruncationParams { max_length: config.max_len, ..TruncationParams::default() })).map_err(fail)?;
        let session = Session::builder().map_err(fail)?.commit_from_file(onnx).map_err(fail)?;
        Ok(Self { session: Mutex::new(session), tokenizer, config })
    }
}

impl GlinerModel for GlinerOrt {
    fn predict_entities(&self, window: &str, labels: &[&str], threshold: f32) -> Result<Vec<Found>, NerError> {
        let chars: Vec<char> = window.chars().collect();
        let mut words = split_words(&chars);
        words.truncate(self.config.max_len);
        if words.is_empty() {
            return Ok(Vec::new());
        }
        let prompt = prompt_words(labels, &self.config.ent_token, &self.config.sep_token);
        let word_text: Vec<String> = words.iter().map(|&(a, b)| pytext::string(&chars[a..b])).collect();
        let pieces: Vec<&str> = prompt.iter().map(String::as_str).chain(word_text.iter().map(String::as_str)).collect();
        let encoding = self.tokenizer.encode(pieces, true).map_err(fail)?;
        let length = encoding.get_ids().len();
        let ids: Vec<i64> = encoding.get_ids().iter().map(|&v| i64::from(v)).collect();
        let attention: Vec<i64> = encoding.get_attention_mask().iter().map(|&v| i64::from(v)).collect();
        let word_ids: Vec<Option<usize>> = encoding.get_word_ids().iter().map(|w| w.map(|v| v as usize)).collect();
        let mask = words_mask(&word_ids, prompt.len());
        let (span_idx, span_mask) = span_inputs(words.len(), self.config.max_width);
        let span_count = (words.len() * self.config.max_width) as i64;

        let mut session = self.session.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let outputs = session
            .run(ort::inputs![
                "input_ids" => Tensor::from_array(([1i64, length as i64], ids)).map_err(fail)?,
                "attention_mask" => Tensor::from_array(([1i64, length as i64], attention)).map_err(fail)?,
                "words_mask" => Tensor::from_array(([1i64, length as i64], mask)).map_err(fail)?,
                "text_lengths" => Tensor::from_array(([1i64, 1], vec![words.len() as i64])).map_err(fail)?,
                "span_idx" => Tensor::from_array(([1i64, span_count, 2], span_idx)).map_err(fail)?,
                "span_mask" => Tensor::from_array(([1i64, span_count], span_mask)).map_err(fail)?,
            ])
            .map_err(fail)?;
        let (_, logits) = outputs["logits"].try_extract_tensor::<f32>().map_err(fail)?;
        let spans = decode_spans(logits, words.len(), self.config.max_width, labels.len(), threshold);
        Ok(spans
            .into_iter()
            .map(|s| Found { start: words[s.start].0, end: words[s.end].1, label: labels[s.class].to_owned(), score: s.score })
            .collect())
    }
}
