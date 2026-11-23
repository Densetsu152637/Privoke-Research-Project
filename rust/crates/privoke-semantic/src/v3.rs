//! The V3 model: native pretrained BERT with affine task heads (`v3/model.py::PretrainedV3`).

use std::collections::BTreeMap;
use std::path::Path;

use ahash::AHashMap;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::publication::KeySet;
use privoke_contracts::v3::{LineageState, Manifest, admit_lineage, admitted_manifest};
use privoke_rules::classification::Classification;
use privoke_rules::preprocessing::normalize_with_offsets;
use serde_json::Value;
use tokenizers::models::wordpiece::WordPiece;
use tokenizers::normalizers::bert::BertNormalizer;
use tokenizers::pre_tokenizers::bert::BertPreTokenizer;
use tokenizers::processors::bert::BertProcessing;
use tokenizers::{Model, Tokenizer};

use crate::bert::{BertConfig, Encoder, take};
use crate::error::SemanticError;
use crate::labels::{CATEGORY, HEAD_WIDTHS, Prediction, SENSITIVITY, VISIBILITY, argmax, is_empty_classification, reported_confidence};
use crate::layer::{Finding, SemanticClassifier};
use crate::math::{Dense, sigmoid_f32, softmax_f32};
use crate::safetensors::{self, Tensor};

/// Native WordPiece tokens a V3 input may hold, including the two special tokens.
pub const MAX_TOKENS: usize = 512;
/// Threads of the matrix kernels unless set (the paper's Torch setting).
pub const DEFAULT_THREADS: usize = 4;
/// `reasoning` of every V3 finding.
pub const REASONING: &str = "Experimental pretrained v3 contextual classification.";

/// The head outputs for one input.
#[derive(Debug, Clone, PartialEq)]
pub struct V3Logits {
    /// `pooler_output`.
    pub pooled: Vec<f32>,
    /// Sensitivity logits.
    pub sensitivity: Vec<f32>,
    /// Visibility logits.
    pub visibility: Vec<f32>,
    /// Category logits.
    pub category: Vec<f32>,
}

/// A loaded V3 model.
#[derive(Debug, Clone)]
pub struct V3Model {
    encoder: Encoder,
    sensitivity: Dense,
    visibility: Dense,
    category: Dense,
    tokenizer: Tokenizer,
    threads: usize,
}

fn read(path: &Path) -> Result<Vec<u8>, SemanticError> {
    std::fs::read(path).map_err(|source| SemanticError::Io { path: path.display().to_string(), source })
}

/// The `BertTokenizerFast(vocab_file=..., do_lower_case=True)` pipeline: clean, lower-case and strip accents,
/// split on whitespace and punctuation, greedy WordPiece with `[UNK]`, then `[CLS]` and `[SEP]`.
///
/// The vocabulary is given as bytes (the ones that were hashed against the manifest), read as `WordPiece::read_file` reads a file:
/// one token per line, its id the line number, trailing whitespace trimmed.
fn build_tokenizer(vocab: &[u8]) -> Result<Tokenizer, SemanticError> {
    let failure = |error: tokenizers::Error| SemanticError::Tokenizer(error.to_string());
    let text = std::str::from_utf8(vocab).map_err(|_| SemanticError::artifact("The vocabulary is not UTF-8."))?;
    let tokens: AHashMap<String, u32> = text.lines().enumerate().map(|(index, line)| (line.trim_end().to_owned(), index as u32)).collect();
    let model = WordPiece::builder().vocab(tokens).unk_token("[UNK]".to_string()).build().map_err(failure)?;
    let cls = model.token_to_id("[CLS]").ok_or_else(|| SemanticError::artifact("The vocabulary has no [CLS] token."))?;
    let sep = model.token_to_id("[SEP]").ok_or_else(|| SemanticError::artifact("The vocabulary has no [SEP] token."))?;
    if model.token_to_id("[UNK]").is_none() {
        return Err(SemanticError::artifact("The vocabulary has no [UNK] token."));
    }
    let mut tokenizer = Tokenizer::new(model);
    tokenizer.with_normalizer(Some(BertNormalizer::new(true, true, None, true)));
    tokenizer.with_pre_tokenizer(Some(BertPreTokenizer));
    tokenizer.with_post_processor(Some(BertProcessing::new(("[SEP]".to_string(), sep), ("[CLS]".to_string(), cls))));
    Ok(tokenizer)
}

fn head(tensors: &mut BTreeMap<String, Tensor>, task: &str, labels: usize, hidden: usize) -> Result<Dense, SemanticError> {
    let weight = take(tensors, &format!("heads.{task}_weight"), &[labels, hidden])?;
    let bias = take(tensors, &format!("heads.{task}_bias"), &[labels])?;
    Dense::new(weight, bias, hidden, labels)
}

impl V3Model {
    /// Build a model from its three files without checking them against a manifest (fixtures and tests; products
    /// use [`V3Model::load_release`]).
    pub fn from_files(config: &Path, checkpoint: &Path, vocab: &Path) -> Result<Self, SemanticError> {
        let config_text = String::from_utf8(read(config)?).map_err(|_| SemanticError::artifact("config.json is not UTF-8."))?;
        Self::from_parts(&config_text, safetensors::parse(&read(checkpoint)?)?, &read(vocab)?)
    }

    fn from_parts(config_text: &str, mut tensors: BTreeMap<String, Tensor>, vocab: &[u8]) -> Result<Self, SemanticError> {
        let config = BertConfig::from_json(config_text)?;
        let hidden = config.hidden_size;
        let encoder = Encoder::from_tensors(config, &mut tensors, "encoder.")?;
        let [sensitivity, visibility, category] = HEAD_WIDTHS;
        let model = Self {
            sensitivity: head(&mut tensors, "sensitivity", sensitivity, hidden)?,
            visibility: head(&mut tensors, "visibility", visibility, hidden)?,
            category: head(&mut tensors, "category", category, hidden)?,
            encoder,
            tokenizer: build_tokenizer(vocab)?,
            threads: DEFAULT_THREADS,
        };
        if !tensors.is_empty() {
            return Err(SemanticError::artifact("Checkpoint includes unsupported or missing model keys."));
        }
        Ok(model)
    }

    /// Load a pinned standard release (`dir` holds `manifest.json`, `config.json`, `vocab.txt` and
    /// `model.safetensors`) the way the product does: the manifest must be the pinned one of `model_id`, every asset must
    /// hash to the manifest, and the checkpoint inventory (names, shapes, dtypes, tensor hashes) must equal the manifest's.
    pub fn load_release(dir: &Path, model_id: &str) -> Result<Self, SemanticError> {
        let manifest_bytes = read(&dir.join("manifest.json"))?;
        let manifest = admitted_manifest(&manifest_bytes, Some(model_id)).map_err(|error| SemanticError::artifact(error.to_string()))?;
        Self::load_verified(dir, &manifest_bytes, &manifest)
    }

    /// Load a version the supervisor admitted by lineage and signature (stage V3-R4b), or the pinned release itself.
    ///
    /// `manifest_bytes` are the bytes of the version's `manifest.json` as the caller read them, and `statement` the statement kept
    /// beside them (empty for the unsigned pinned release). The version is admitted here, by [`admit_lineage`], under `keys` and
    /// the persisted high-water mark and compiled pin of `state`: a statement that does not verify, a version below the mark,
    /// and the unsigned pin once the mark is a signed version are each refused before any asset is read. Then every asset must
    /// hash to the admitted manifest and the checkpoint inventory must equal its tensors, as for [`V3Model::load_release`],
    /// which stays the pin-only rule. The admitted manifest is returned with the model.
    pub fn load_published(
        dir: &Path,
        model_id: &str,
        manifest_bytes: &[u8],
        statement: &[u8],
        keys: &KeySet,
        state: &dyn LineageState,
    ) -> Result<(Self, Manifest), SemanticError> {
        let admitted = admit_lineage(manifest_bytes, statement, Some(model_id), keys, state)
            .map_err(|error| SemanticError::artifact(format!("The cached version is not admitted: {error}")))?;
        let model = Self::load_verified(dir, manifest_bytes, &admitted.manifest)?;
        Ok((model, admitted.manifest))
    }

    /// The assets of `dir` against an admitted manifest, then the model.
    fn load_verified(dir: &Path, manifest_bytes: &[u8], manifest: &Manifest) -> Result<Self, SemanticError> {
        let config_bytes = read(&dir.join("config.json"))?;
        let checkpoint_bytes = read(&dir.join("model.safetensors"))?;
        let vocab_bytes = read(&dir.join("vocab.txt"))?;
        for (bytes, expected) in [(&checkpoint_bytes, &manifest.blob), (&config_bytes, &manifest.config), (&vocab_bytes, &manifest.vocab)] {
            if sha256_hex(bytes) != *expected {
                return Err(SemanticError::artifact("Runtime asset bytes do not match admitted manifest."));
            }
        }
        let tensors = safetensors::parse(&checkpoint_bytes)?;
        let value: Value = serde_json::from_slice(manifest_bytes).map_err(|error| SemanticError::artifact(error.to_string()))?;
        verify_inventory(&tensors, value.get("tensors"))?;
        let config_text = String::from_utf8(config_bytes).map_err(|_| SemanticError::artifact("config.json is not UTF-8."))?;
        // The vocabulary that was hashed against the manifest, not a second read of the file.
        Self::from_parts(&config_text, tensors, &vocab_bytes)
    }

    /// The same model (tokenizer and thread count) over other weights: `tensors` holds every checkpoint tensor (`encoder.*`
    /// and `heads.*`), as `from_parts` reads them. Used to assess a fitted candidate without reloading the vocabulary.
    pub fn with_tensors(&self, mut tensors: BTreeMap<String, Tensor>) -> Result<Self, SemanticError> {
        let config = self.encoder.config().clone();
        let hidden = config.hidden_size;
        let encoder = Encoder::from_tensors(config, &mut tensors, "encoder.")?;
        let [sensitivity, visibility, category] = HEAD_WIDTHS;
        let model = Self {
            sensitivity: head(&mut tensors, "sensitivity", sensitivity, hidden)?,
            visibility: head(&mut tensors, "visibility", visibility, hidden)?,
            category: head(&mut tensors, "category", category, hidden)?,
            encoder,
            tokenizer: self.tokenizer.clone(),
            threads: self.threads,
        };
        if !tensors.is_empty() {
            return Err(SemanticError::artifact("Checkpoint includes unsupported or missing model keys."));
        }
        Ok(model)
    }

    /// Set the number of threads of the matrix kernels.
    #[must_use]
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = threads.max(1);
        self
    }

    /// The encoder.
    pub fn encoder(&self) -> &Encoder {
        &self.encoder
    }

    /// `tokenize`: canonical text (`normalize_with_offsets(text).text`), WordPiece with special tokens, at most 512 tokens.
    pub fn tokenize(&self, text: &str) -> Result<Vec<u32>, SemanticError> {
        let normalised = normalize_with_offsets(text, true, None).map_err(|error| SemanticError::Input(error.to_string()))?;
        let encoding = self.tokenizer.encode(normalised.text(), true).map_err(|error| SemanticError::Tokenizer(error.to_string()))?;
        let ids = encoding.get_ids().to_vec();
        if ids.len() > MAX_TOKENS {
            return Err(SemanticError::Input("V3 input exceeds 512 native WordPiece tokens including special tokens.".into()));
        }
        Ok(ids)
    }

    /// Pooled output and head logits for token ids.
    pub fn logits_for_ids(&self, ids: &[u32]) -> Result<V3Logits, SemanticError> {
        let pooled = self.encoder.pooled(ids, self.threads)?;
        Ok(V3Logits {
            sensitivity: self.sensitivity.apply_to_f32(&pooled),
            visibility: self.visibility.apply_to_f32(&pooled),
            category: self.category.apply_to_f32(&pooled),
            pooled,
        })
    }

    /// `forward([text])`: logits for one text.
    pub fn logits(&self, text: &str) -> Result<V3Logits, SemanticError> {
        self.logits_for_ids(&self.tokenize(text)?)
    }

    /// `predictions([text])[0]`.
    pub fn predict(&self, text: &str) -> Result<Prediction, SemanticError> {
        let logits = self.logits(text)?;
        let sensitivity = softmax_f32(&logits.sensitivity);
        let visibility = softmax_f32(&logits.visibility);
        let categories = sigmoid_f32(&logits.category);
        let (sensitivity_label, sensitivity_value) = SENSITIVITY[argmax(&sensitivity)];
        let (visibility_label, visibility_value) = VISIBILITY[argmax(&visibility)];
        let mut mask = 0u16;
        let mut names = Vec::new();
        for ((name, bit), probability) in CATEGORY.iter().zip(&categories) {
            if *probability >= 0.5 {
                mask |= bit;
                names.push((*name).to_string());
            }
        }
        let raw = sensitivity.iter().chain(&categories).copied().fold(f32::NEG_INFINITY, f32::max);
        Ok(Prediction {
            classification: Classification::new(sensitivity_value, visibility_value, mask),
            sensitivity: sensitivity_label.to_string(),
            visibility: visibility_label.to_string(),
            categories: names,
            confidence_raw: f64::from(raw),
            confidence: reported_confidence(f64::from(raw)),
        })
    }
}

fn verify_inventory(tensors: &BTreeMap<String, Tensor>, inventory: Option<&Value>) -> Result<(), SemanticError> {
    let mismatch = || SemanticError::artifact("Checkpoint inventory/hash mismatch.");
    let Some(Value::Object(expected)) = inventory else {
        return Err(mismatch());
    };
    if expected.len() != tensors.len() {
        return Err(mismatch());
    }
    for (name, tensor) in tensors {
        let entry = expected.get(name).ok_or_else(mismatch)?;
        let shape: Option<Vec<usize>> = entry
            .get("shape")
            .and_then(Value::as_array)
            .and_then(|dims| dims.iter().map(|d| d.as_u64().and_then(|d| usize::try_from(d).ok())).collect());
        let same = entry.get("dtype").and_then(Value::as_str) == Some("F32")
            && shape.as_deref() == Some(tensor.shape.as_slice())
            && entry.get("sha256").and_then(Value::as_str) == Some(tensor.sha256.as_str());
        if !same {
            return Err(mismatch());
        }
    }
    Ok(())
}

impl SemanticClassifier for V3Model {
    /// `PretrainedV3.findings`: one finding unless the prediction is the empty classification.
    fn classify(&self, text: &str) -> Result<Vec<Finding>, SemanticError> {
        let prediction = self.predict(text)?;
        let classification = prediction.classification;
        let visibility = VISIBILITY.iter().find(|(name, _)| *name == prediction.visibility).map_or(0, |(_, value)| *value);
        if is_empty_classification(classification.sensitivity(), classification.categories(), visibility) {
            return Ok(Vec::new());
        }
        Ok(vec![Finding {
            classification,
            confidence: prediction.confidence,
            reasoning: REASONING.to_string(),
            span: if text.is_empty() { None } else { Some((0, text.chars().count())) },
            section: text.to_string(),
        }])
    }
}
