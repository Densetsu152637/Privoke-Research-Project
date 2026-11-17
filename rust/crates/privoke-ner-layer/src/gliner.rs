//! The optional GLiNER NER backend (`NER/gliner_detector.py`, `PRIVOKE_NER_BACKEND=gliner`, stage 15).
//!
//! Not shipped by default, as in the Python build. Everything here except the model itself is plain Rust and always
//! compiled:
//!
//! * the pre-registered label presets (`core`, `pii`) and their mapping onto the spaCy label scheme and the fixed
//!   identifier use cases;
//! * `word_windows` (windows of at most 300 whitespace separated words) and the GLiNER word splitter;
//! * the model-side input construction and the greedy flat-NER span decoder ([`prompt_words`], [`words_mask`],
//!   [`span_inputs`], [`decode_spans`]), so that a model backend only has to run the network;
//! * [`GlinerDetector`], the detector contract: windows, threshold, the spaCy `Doc` (through the [`SpacyBackend`]) that
//!   the post-filter needs, `char_span(..., alignment_mode="expand")` and the result order.
//!
//! The network sits behind [`GlinerModel`]. The ONNX Runtime implementation lives in `gliner_ort` behind the
//! `gliner-ort` cargo feature (off by default, `ort` with `load-dynamic`, so it needs no download at build time).
//!
//! The spaCy parse is taken with `Selection::Full` and the entities are ignored. Python disables `ner` for this parse;
//! the dependency parse and the tags do not read the `ner` component, so the tokens are identical. A dedicated
//! ner-disabled selection in `privoke-spacy` would only save the NER compute.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use privoke_rules::classification::{Classification, Sensitivity, category, visibility};
use privoke_spacy::{Entity, OffsetMap, Selection, Token};

use crate::analyzer::{NerError, SpacyBackend};
use crate::detector::{NerOptions, NerResult};
use crate::postfilter::{Decision, Doc, postfilter};
use crate::pytext;
use crate::usecases::{EntityUseCase, use_case};

/// `CORE_LABELS`: GLiNER label string and the spaCy-scheme label it maps to.
pub const CORE_LABELS: [(&str, &str); 7] = [
    ("name", "PERSON"),
    ("location city", "GPE"),
    ("location state", "GPE"),
    ("location country", "GPE"),
    ("location street", "FAC"),
    ("location address", "FAC"),
    ("organization", "ORG"),
];

/// The extra identifier labels of the `pii` preset, in the Python dictionary order.
pub const PII_EXTRA_LABELS: [&str; 12] = [
    "phone number",
    "email address",
    "ip address",
    "username",
    "dob",
    "ssn",
    "passport number",
    "driver license",
    "password",
    "credit card",
    "account number",
    "medical condition",
];

/// GLiNER scores long inputs in windows of at most this many whitespace separated words.
pub const MAX_WINDOW_WORDS: usize = 300;

/// The Python default of `PRIVOKE_NER_GLINER_THRESHOLD`.
pub const DEFAULT_THRESHOLD: f64 = 0.3;

/// The threshold frozen by the model study (`ner-models-20261024.freeze.json`, `gliner-core-t0.5-pf1`).
pub const FROZEN_THRESHOLD: f64 = 0.5;

/// The `NER_BACKEND` model reference recorded in result metadata when none is given.
pub const DEFAULT_MODEL_REF: &str = "knowledgator/gliner-pii-small-v1.0";

/// GLiNER label string to the spaCy-scheme label (`CORE_LABELS.get`).
pub fn core_target(label: &str) -> Option<&'static str> {
    CORE_LABELS.iter().find(|(source, _)| *source == label).map(|(_, target)| *target)
}

const fn extra(entity_type: &'static str, sensitivity: Sensitivity, categories: u16, confidence: f64) -> EntityUseCase {
    EntityUseCase { entity_type, sensitivity, visibility: visibility::PU, categories, confidence }
}

/// `PII_EXTRA_USE_CASES.get(label)`.
pub fn pii_extra_use_case(label: &str) -> Option<EntityUseCase> {
    use Sensitivity::{S2, S3};
    Some(match label {
        "phone number" => extra("phone", S2, category::IDENTITY, 0.8),
        "email address" => extra("email", S2, category::IDENTITY, 0.8),
        "ip address" => extra("ip_address", S2, category::IDENTITY, 0.8),
        "username" => extra("username", S2, category::IDENTITY, 0.75),
        "dob" => extra("date_of_birth", S2, category::IDENTITY, 0.8),
        "ssn" | "passport number" | "driver license" => extra("government_id", S3, category::IDENTITY, 0.8),
        "password" => extra("secret", S3, category::IDENTITY, 0.8),
        "credit card" => extra("payment_card", S3, category::FINANCIAL, 0.8),
        "account number" => extra("financial_account", S3, category::FINANCIAL, 0.8),
        "medical condition" => extra("health_condition", S3, category::HEALTH, 0.75),
        _ => return None,
    })
}

/// `LABEL_PRESETS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelPreset {
    /// Names, places and organisations.
    Core,
    /// `Core` plus the non-name personal identifiers.
    Pii,
}

impl LabelPreset {
    /// Parses a preset name; the error is Python's `ValueError` message.
    pub fn parse(name: &str) -> Result<Self, NerError> {
        match name {
            "core" => Ok(Self::Core),
            "pii" => Ok(Self::Pii),
            other => Err(NerError::SpacyBackend(format!("Unknown GLiNER label preset '{other}'; expected one of ['core', 'pii']"))),
        }
    }

    /// The preset's name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Pii => "pii",
        }
    }

    /// The label strings asked of the model, in order.
    pub fn labels(self) -> Vec<&'static str> {
        let mut labels: Vec<&'static str> = CORE_LABELS.iter().map(|(source, _)| *source).collect();
        if self == Self::Pii {
            labels.extend(PII_EXTRA_LABELS);
        }
        labels
    }
}

/// The GLiNER settings that Python reads from `GLOBAL_CONFIG`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlinerOptions {
    /// `PRIVOKE_NER_GLINER_THRESHOLD`.
    pub threshold: f64,
    /// `PRIVOKE_NER_GLINER_LABELS`.
    pub preset: LabelPreset,
}

impl Default for GlinerOptions {
    fn default() -> Self {
        Self { threshold: DEFAULT_THRESHOLD, preset: LabelPreset::Core }
    }
}

impl GlinerOptions {
    /// The configuration frozen by the model study: preset `core`, threshold 0.5.
    pub const fn frozen() -> Self {
        Self { threshold: FROZEN_THRESHOLD, preset: LabelPreset::Core }
    }

    /// The `PRIVOKE_NER_GLINER_*` variables, read through `lookup` (an invalid or non-positive threshold keeps the default).
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, NerError> {
        let threshold = lookup("PRIVOKE_NER_GLINER_THRESHOLD")
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .unwrap_or(DEFAULT_THRESHOLD);
        let preset = match lookup("PRIVOKE_NER_GLINER_LABELS").map(|v| v.trim().to_lowercase()).filter(|v| !v.is_empty()) {
            Some(name) => LabelPreset::parse(&name)?,
            None => LabelPreset::Core,
        };
        Ok(Self { threshold, preset })
    }

    /// The same, from the process environment.
    pub fn from_env() -> Result<Self, NerError> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }
}

// ---- words and windows ------------------------------------------------------------------------------------------

/// `word_windows`: character ranges `[start, end)` of the pieces of at most `max_words` whitespace separated words.
pub fn word_windows(chars: &[char], max_words: usize) -> Vec<(usize, usize)> {
    let mut windows = Vec::new();
    let (mut count, mut start, mut in_word) = (0usize, 0usize, false);
    for (index, &c) in chars.iter().enumerate() {
        if pytext::is_space(c) {
            in_word = false;
            continue;
        }
        if !in_word {
            in_word = true;
            count += 1;
            if count > max_words {
                windows.push((start, index));
                start = index;
                count = 1;
            }
        }
    }
    if chars[start..].iter().any(|&c| !pytext::is_space(c)) {
        windows.push((start, chars.len()));
    }
    windows
}

/// GLiNER's word splitter, `re.finditer(r"\w+(?:[-_]\w+)*|\S", text)`: character ranges of the words.
pub fn split_words(chars: &[char]) -> Vec<(usize, usize)> {
    let mut words = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if pytext::is_word(c) {
            let start = i;
            while i < chars.len() && pytext::is_word(chars[i]) {
                i += 1;
            }
            // `(?:[-_]\w+)*`: a hyphen followed by more word characters continues the token.
            while i + 1 < chars.len() && chars[i] == '-' && pytext::is_word(chars[i + 1]) {
                i += 1;
                while i < chars.len() && pytext::is_word(chars[i]) {
                    i += 1;
                }
            }
            words.push((start, i));
        } else if !pytext::is_space(c) {
            words.push((i, i + 1));
            i += 1;
        } else {
            i += 1;
        }
    }
    words
}

// ---- model contract ------------------------------------------------------------------------------------------------

/// One span returned by the model for a window, offsets in code points of the window.
#[derive(Clone, Debug, PartialEq)]
pub struct Found {
    /// `found["start"]`.
    pub start: usize,
    /// `found["end"]`.
    pub end: usize,
    /// `found["label"]`: one of the requested label strings.
    pub label: String,
    /// `found["score"]`.
    pub score: f32,
}

/// `GLiNER.predict_entities(window, labels, threshold=...)`: the network, flat NER, single label per span.
pub trait GlinerModel: Send + Sync {
    /// Spans of `window` whose score exceeds `threshold`, after greedy overlap removal, ordered by start.
    fn predict_entities(&self, window: &str, labels: &[&str], threshold: f32) -> Result<Vec<Found>, NerError>;
}

/// The prompt, as the words the tokenizer sees: `[<ent>, label, ..., <sep>]` in front of the text words.
pub fn prompt_words(labels: &[&str], ent_token: &str, sep_token: &str) -> Vec<String> {
    let mut prompt = Vec::with_capacity(labels.len() * 2 + 1);
    for label in labels {
        prompt.push(ent_token.to_owned());
        prompt.push((*label).to_owned());
    }
    prompt.push(sep_token.to_owned());
    prompt
}

/// `words_mask`: for each subword, the 1-based index of the text word it starts, 0 for everything else (special
/// tokens, prompt words and continuation subwords). `word_ids` is the tokenizer's word index per subword.
pub fn words_mask(word_ids: &[Option<usize>], prompt_len: usize) -> Vec<i64> {
    let mut mask = Vec::with_capacity(word_ids.len());
    let mut previous: Option<usize> = None;
    for &word in word_ids {
        let value = match word {
            Some(id) if Some(id) != previous && id >= prompt_len => (id - prompt_len + 1) as i64,
            _ => 0,
        };
        mask.push(value);
        previous = word;
    }
    mask
}

/// `span_idx` (`[num_words * max_width, 2]`, start and start + width, zeroed when past the end) and `span_mask`.
pub fn span_inputs(num_words: usize, max_width: usize) -> (Vec<i64>, Vec<bool>) {
    let mut idx = Vec::with_capacity(num_words * max_width * 2);
    let mut mask = Vec::with_capacity(num_words * max_width);
    for start in 0..num_words {
        for width in 0..max_width {
            let end = start + width;
            let valid = end < num_words;
            mask.push(valid);
            idx.push(if valid { start as i64 } else { 0 });
            idx.push(if valid { end as i64 } else { 0 });
        }
    }
    (idx, mask)
}

/// One decoded span, word indexes (end inclusive) and class index.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DecodedSpan {
    /// First word.
    pub start: usize,
    /// Last word, inclusive.
    pub end: usize,
    /// Index into the requested labels.
    pub class: usize,
    /// Sigmoid of the logit.
    pub score: f32,
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// The decoder of GLiNER's flat NER: `sigmoid(logits) > threshold` over `[word][width][class]`, spans that run past the
/// last word dropped, then greedy selection by descending score (stable) that drops any span overlapping a kept one,
/// ordered by start (stable).
pub fn decode_spans(logits: &[f32], num_words: usize, max_width: usize, num_classes: usize, threshold: f32) -> Vec<DecodedSpan> {
    let mut spans = Vec::new();
    if num_classes == 0 {
        return spans;
    }
    for (position, &logit) in logits.iter().enumerate().take(num_words * max_width * num_classes) {
        let score = sigmoid(logit);
        if score <= threshold {
            continue;
        }
        let class = position % num_classes;
        let width = (position / num_classes) % max_width;
        let start = position / (num_classes * max_width);
        let end = start + width;
        if end >= num_words {
            continue;
        }
        spans.push(DecodedSpan { start, end, class, score });
    }
    spans.sort_by(|a, b| b.score.total_cmp(&a.score));
    let mut kept: Vec<DecodedSpan> = Vec::new();
    for span in spans {
        if kept.iter().all(|k| span.end < k.start || k.end < span.start) {
            kept.push(span);
        }
    }
    kept.sort_by_key(|s| s.start);
    kept
}

// ---- detector ------------------------------------------------------------------------------------------------------

/// `RawSpan`: a model span with the attribute names the post-filter and the results use, absolute code point offsets.
#[derive(Clone, Debug, PartialEq)]
pub struct RawSpan {
    /// The span text.
    pub text: String,
    /// The mapped label (`PERSON`, ...) for core labels, the GLiNER label otherwise.
    pub label: String,
    /// Start in the text.
    pub start: usize,
    /// End (exclusive) in the text.
    pub end: usize,
    /// The model score.
    pub score: f64,
    /// The label string the model returned.
    pub source_label: String,
}

/// A result of the GLiNER detector: the NER result plus the `metadata["score"]` of identifier spans.
#[derive(Clone, Debug, PartialEq)]
pub struct GlinerHit {
    /// The result, with the fields of the spaCy detector (`label` is `metadata["label"]`).
    pub result: NerResult,
    /// `metadata["score"]` (rounded to 4 places), present for the `pii` identifier spans only.
    pub score: Option<f64>,
}

/// What one GLiNER call returns.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GlinerExtraction {
    /// Results ordered by span.
    pub results: Vec<GlinerHit>,
    /// The post-filter's decision log of the core spans (empty when the post-filter is off).
    pub decisions: Vec<Decision>,
}

/// `GlinerEntityDetector`: GLiNER spans, spaCy tokens for the post-filter, the shared use-case table.
#[derive(Debug)]
pub struct GlinerDetector<A, M> {
    analyzer: A,
    model: M,
    model_name: String,
    options: GlinerOptions,
    lexicon: OnceLock<Arc<HashSet<String>>>,
}

impl<A: SpacyBackend, M: GlinerModel> GlinerDetector<A, M> {
    /// A detector. The spaCy lexicon is loaded on first use, like Python's lazily loaded syntax pipeline.
    pub fn new(analyzer: A, model: M, model_name: &str, options: GlinerOptions) -> Self {
        Self { analyzer, model, model_name: model_name.to_owned(), options, lexicon: OnceLock::new() }
    }

    /// The model name recorded in result metadata.
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// The settings.
    pub fn options(&self) -> &GlinerOptions {
        &self.options
    }

    /// `predict_raw`: spans at the threshold over the preset labels, absolute offsets, ordered by `(start, end)`.
    pub fn predict_raw(&self, text: &str) -> Result<Vec<RawSpan>, NerError> {
        let chars: Vec<char> = text.chars().collect();
        let labels = self.options.preset.labels();
        let threshold = self.options.threshold;
        let mut spans = Vec::new();
        for (offset, end) in word_windows(&chars, MAX_WINDOW_WORDS) {
            let window = &chars[offset..end];
            let window_text = pytext::string(window);
            for found in self.model.predict_entities(&window_text, &labels, threshold as f32)? {
                let score = f64::from(found.score);
                if score < threshold || !labels.contains(&found.label.as_str()) {
                    continue;
                }
                spans.push(RawSpan {
                    text: pytext::string(pytext::slice(window, found.start, found.end)),
                    label: core_target(&found.label).map_or_else(|| found.label.clone(), str::to_owned),
                    start: offset + found.start,
                    end: offset + found.end,
                    score,
                    source_label: found.label,
                });
            }
        }
        spans.sort_by_key(|s| (s.start, s.end));
        Ok(spans)
    }

    /// `extract_entities`.
    pub async fn extract_entities(&self, text: &str, ner: &NerOptions) -> Result<GlinerExtraction, NerError> {
        let spans = self.predict_raw(text)?;
        let core: Vec<&RawSpan> = spans.iter().filter(|s| core_target(&s.source_label).is_some()).collect();
        let extras: Vec<&RawSpan> = spans.iter().filter(|s| pii_extra_use_case(&s.source_label).is_some()).collect();
        let mut out = GlinerExtraction::default();
        if !core.is_empty() {
            if ner.postfilter {
                self.postfiltered_core(text, &core, &mut out).await?;
            } else {
                self.classified_core(&core, &mut out);
            }
        }
        out.results.extend(extras.iter().filter_map(|s| self.extra_entity(s)));
        out.results.sort_by_key(|hit| hit.result.span);
        Ok(out)
    }

    fn core_result(
        &self,
        label: &str,
        span: (usize, usize),
        text: String,
        case: EntityUseCase,
        classification: Classification,
        rule: Option<String>,
    ) -> NerResult {
        NerResult {
            label: label.to_owned(),
            entity_type: case.entity_type,
            model: self.model_name.clone(),
            span,
            text,
            classification,
            confidence: case.confidence,
            reasoning: format!("GLiNER labelled this span as {label}"),
            postfilter_rule: rule,
        }
    }

    fn classified_core(&self, core: &[&RawSpan], out: &mut GlinerExtraction) {
        let mut seen = HashSet::new();
        for raw in core {
            let Some(case) = use_case(&raw.label) else { continue };
            if !seen.insert((raw.start, raw.end, raw.label.clone(), raw.text.clone())) {
                continue;
            }
            let result = self.core_result(&raw.label, (raw.start, raw.end), raw.text.clone(), case, case.classification(), None);
            out.results.push(GlinerHit { result, score: None });
        }
    }

    async fn lexicon(&self) -> Result<Arc<HashSet<String>>, NerError> {
        if let Some(lexicon) = self.lexicon.get() {
            return Ok(lexicon.clone());
        }
        let loaded: HashSet<String> = self.analyzer.lemma_index().await?.iter().cloned().collect();
        Ok(self.lexicon.get_or_init(|| Arc::new(loaded)).clone())
    }

    async fn postfiltered_core(&self, text: &str, core: &[&RawSpan], out: &mut GlinerExtraction) -> Result<(), NerError> {
        let analysis = self.analyzer.analyze(text, Selection::Full).await?;
        let offsets = OffsetMap::new(text);
        let mut attached: Vec<Entity> = Vec::new();
        let mut seen = HashSet::new();
        for raw in core {
            let Some((start, end)) = char_span_expand(&analysis.tokens, raw.start, raw.end) else { continue };
            if !seen.insert((start, end, raw.label.clone())) {
                continue;
            }
            let Some(span) = offsets.span(start, end) else { continue };
            attached.push(Entity { label: raw.label.clone(), span });
        }
        // `_postfiltered_entities`: labels without a use case are skipped, duplicates dropped.
        let mut candidates: Vec<Entity> = Vec::new();
        let mut seen = HashSet::new();
        for ent in attached {
            if use_case(&ent.label).is_some() && seen.insert((ent.span.start_char, ent.span.end_char, ent.label.clone())) {
                candidates.push(ent);
            }
        }
        let doc = Doc::new(text.chars().collect(), analysis);
        let lexicon = self.lexicon().await?;
        let decisions = postfilter(&doc, &candidates, Some(&self.analyzer), &lexicon, &[], Some(Sensitivity::S1)).await?;
        for decision in &decisions {
            if !decision.keep {
                continue;
            }
            let candidate = &decision.candidate;
            let Some(case) = use_case(&candidate.label) else { continue };
            let classification = decision.sensitivity.map_or_else(|| case.classification(), |s| case.with_sensitivity(s));
            let result = self.core_result(
                &candidate.label,
                (candidate.start, candidate.end),
                candidate.text.clone(),
                case,
                classification,
                Some(decision.rule.clone()),
            );
            out.results.push(GlinerHit { result, score: None });
        }
        out.decisions = decisions;
        Ok(())
    }

    fn extra_entity(&self, span: &RawSpan) -> Option<GlinerHit> {
        let case = pii_extra_use_case(&span.source_label)?;
        let result = NerResult {
            label: span.source_label.clone(),
            entity_type: case.entity_type,
            model: self.model_name.clone(),
            span: (span.start, span.end),
            text: span.text.clone(),
            classification: case.classification(),
            confidence: case.confidence,
            reasoning: format!("GLiNER labelled this span as {}", span.source_label),
            postfilter_rule: None,
        };
        Some(GlinerHit { result, score: Some(round4(span.score)) })
    }
}

/// Python's `round(x, 4)` for a score in `[0, 1]`.
fn round4(x: f64) -> f64 {
    (x * 1e4).round_ties_even() / 1e4
}

/// spaCy's `token_by_char`: the token whose extent, trailing space included, holds `char_idx`.
fn token_by_char(tokens: &[Token], char_idx: usize) -> Option<usize> {
    let (mut start, mut end) = (0isize, tokens.len() as isize - 1);
    while start <= end {
        let mid = (start + end) / 2;
        let token = &tokens[mid as usize];
        let length = token.text.chars().count() + usize::from(!token.whitespace.is_empty());
        if char_idx < token.idx {
            end = mid - 1;
        } else if char_idx >= token.idx + length {
            start = mid + 1;
        } else {
            return Some(mid as usize);
        }
    }
    None
}

/// `Doc.char_span(start, end, alignment_mode="expand")` as `(start_char, end_char)` of the resulting span.
pub fn char_span_expand(tokens: &[Token], start_idx: usize, end_idx: usize) -> Option<(usize, usize)> {
    let mut start = token_by_char(tokens, start_idx)?;
    let end = token_by_char(tokens, end_idx.checked_sub(1)?)?;
    // A start inside the trailing whitespace of a token belongs to the next token.
    if start_idx == tokens[start].idx + tokens[start].text.chars().count() {
        start += 1;
    }
    if start > end {
        return None;
    }
    Some((tokens[start].idx, tokens[end].idx + tokens[end].text.chars().count()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    #[test]
    fn windows_cover_the_text_in_word_groups() {
        let text = chars("a b c d e");
        assert_eq!(word_windows(&text, 2), vec![(0, 4), (4, 8), (8, 9)]);
        assert_eq!(word_windows(&chars("  "), 2), vec![]);
        assert_eq!(word_windows(&chars(""), 2), vec![]);
        assert_eq!(word_windows(&chars("one two"), 300), vec![(0, 7)]);
    }

    #[test]
    fn words_split_like_the_gliner_regex() {
        let text = chars("Hi, Mary-Ann O'Neil_x! 3.5");
        let words: Vec<String> = split_words(&text).iter().map(|&(a, b)| pytext::string(&text[a..b])).collect();
        assert_eq!(words, ["Hi", ",", "Mary-Ann", "O", "'", "Neil_x", "!", "3", ".", "5"]);
        // A trailing hyphen is its own word, a leading one too.
        let text = chars("a- -b");
        let words: Vec<String> = split_words(&text).iter().map(|&(a, b)| pytext::string(&text[a..b])).collect();
        assert_eq!(words, ["a", "-", "-", "b"]);
    }

    #[test]
    fn presets_list_labels_in_order() {
        assert_eq!(LabelPreset::Core.labels().len(), 7);
        let pii = LabelPreset::Pii.labels();
        assert_eq!(pii.len(), 19);
        assert_eq!(pii[7], "phone number");
        assert_eq!(pii[18], "medical condition");
        assert!(LabelPreset::parse("full").is_err());
        assert_eq!(pii_extra_use_case("ssn").map(|u| u.entity_type), Some("government_id"));
        assert_eq!(PII_EXTRA_LABELS.iter().filter(|l| pii_extra_use_case(l).is_none()).count(), 0);
    }

    #[test]
    fn options_read_the_python_variables() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| (*v).to_owned())
        };
        assert_eq!(GlinerOptions::from_lookup(&env(&[])).unwrap(), GlinerOptions::default());
        let set =
            GlinerOptions::from_lookup(&env(&[("PRIVOKE_NER_GLINER_THRESHOLD", "0.5"), ("PRIVOKE_NER_GLINER_LABELS", "PII")])).unwrap();
        assert_eq!(set, GlinerOptions { threshold: 0.5, preset: LabelPreset::Pii });
        assert_eq!(GlinerOptions::from_lookup(&env(&[("PRIVOKE_NER_GLINER_THRESHOLD", "-1")])).unwrap().threshold, 0.3);
        assert!(GlinerOptions::from_lookup(&env(&[("PRIVOKE_NER_GLINER_LABELS", "x")])).is_err());
    }

    #[test]
    fn model_inputs_follow_the_prompt_layout() {
        let prompt = prompt_words(&["name", "organization"], "<<ENT>>", "<<SEP>>");
        assert_eq!(prompt, ["<<ENT>>", "name", "<<ENT>>", "organization", "<<SEP>>"]);
        // [CLS] prompt(5 words, one with two subwords) text(2 words) [SEP]
        let ids = [None, Some(0), Some(1), Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(6), None];
        assert_eq!(words_mask(&ids, 5), [0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0]);
        let (idx, mask) = span_inputs(2, 3);
        assert_eq!(idx, [0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0]);
        assert_eq!(mask, [true, true, false, true, false, false]);
    }

    fn logits(num_words: usize, width: usize, classes: usize, set: &[(usize, usize, usize, f32)]) -> Vec<f32> {
        let mut out = vec![-10.0; num_words * width * classes];
        for &(start, w, class, value) in set {
            out[(start * width + w) * classes + class] = value;
        }
        out
    }

    #[test]
    fn decoder_keeps_the_best_non_overlapping_spans() {
        // Words 0..4, two classes. A strong span 1..2, a weaker overlapping 0..1, a disjoint one at 3.
        let l = logits(4, 3, 2, &[(1, 1, 0, 4.0), (0, 1, 1, 2.0), (3, 0, 1, 1.0), (3, 1, 0, 9.0)]);
        let spans = decode_spans(&l, 4, 3, 2, 0.5);
        // (3, width 1) runs past the last word and is dropped.
        assert_eq!(spans.iter().map(|s| (s.start, s.end, s.class)).collect::<Vec<_>>(), [(1, 2, 0), (3, 3, 1)]);
        assert!(spans[0].score > spans[1].score);
        // The threshold is strict.
        assert!(decode_spans(&logits(1, 1, 1, &[(0, 0, 0, 0.0)]), 1, 1, 1, 0.5).is_empty());
    }

    fn token(text: &str, idx: usize, space: bool) -> Token {
        let map = OffsetMap::new(&format!("{}{}", " ".repeat(idx), text));
        Token {
            text: text.to_owned(),
            idx,
            whitespace: if space { " ".to_owned() } else { String::new() },
            is_alpha: true,
            lower: text.to_lowercase(),
            tag: String::new(),
            pos: String::new(),
            lemma: String::new(),
            dep: String::new(),
            head: 0,
            span: map.span(idx, idx + text.chars().count()).unwrap(),
        }
    }

    #[test]
    fn char_span_expands_to_token_boundaries() {
        // "Dr Mary Smith ."
        let tokens = [token("Dr", 0, true), token("Mary", 3, true), token("Smith", 8, true), token(".", 14, false)];
        assert_eq!(char_span_expand(&tokens, 3, 13), Some((3, 13)));
        assert_eq!(char_span_expand(&tokens, 4, 11), Some((3, 13)), "inside tokens expands both sides");
        assert_eq!(char_span_expand(&tokens, 2, 7), Some((3, 7)), "a start in the trailing space moves on");
        assert_eq!(char_span_expand(&tokens, 0, 0), None);
        assert_eq!(char_span_expand(&tokens, 30, 31), None);
    }

    struct Fixed(Vec<Found>);

    impl GlinerModel for Fixed {
        fn predict_entities(&self, _window: &str, _labels: &[&str], _threshold: f32) -> Result<Vec<Found>, NerError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct NoSpacy;

    #[allow(clippy::manual_async_fn)]
    impl SpacyBackend for NoSpacy {
        fn analyze<'a>(
            &'a self,
            _text: &'a str,
            _selection: Selection,
        ) -> impl std::future::Future<Output = Result<privoke_spacy::Analysis, NerError>> + Send + 'a {
            async { Err(NerError::SpacyBackend("spaCy is not used here".into())) }
        }

        fn lemma_index(&self) -> impl std::future::Future<Output = Result<Arc<Vec<String>>, NerError>> + Send {
            async { Ok(Arc::new(Vec::new())) }
        }
    }

    impl std::fmt::Debug for Fixed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Fixed").field("found", &self.0.len()).finish()
        }
    }

    fn found(start: usize, end: usize, label: &str, score: f32) -> Found {
        Found { start, end, label: label.to_owned(), score }
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
    }

    #[test]
    fn raw_spans_follow_python_filters_and_order() {
        let text = "Ask Mary Smith, call 555 0100 at Acme";
        let model = Fixed(vec![
            found(33, 37, "organization", 0.9),
            found(4, 14, "name", 0.8),
            found(21, 29, "phone number", 0.9),
            found(0, 3, "name", 0.2),
            found(0, 3, "mystery", 0.9),
        ]);
        let detector = GlinerDetector::new(NoSpacy, model, "m", GlinerOptions { threshold: 0.5, preset: LabelPreset::Pii });
        let raw = detector.predict_raw(text).unwrap();
        let view: Vec<_> = raw.iter().map(|s| (s.start, s.end, s.label.as_str(), s.text.as_str())).collect();
        assert_eq!(view, [(4, 14, "PERSON", "Mary Smith"), (21, 29, "phone number", "555 0100"), (33, 37, "ORG", "Acme")]);
        // The core preset does not ask for identifiers: the model's phone span is dropped.
        let core = GlinerDetector::new(NoSpacy, Fixed(vec![found(21, 29, "phone number", 0.9)]), "m", GlinerOptions::frozen());
        assert!(core.predict_raw(text).unwrap().is_empty());
    }

    #[test]
    fn without_the_postfilter_results_are_classified_directly() {
        let text = "Ask Mary Smith, call 555 0100 at Acme";
        let model = Fixed(vec![found(33, 37, "organization", 0.9), found(4, 14, "name", 0.8), found(21, 29, "phone number", 0.91237)]);
        let detector = GlinerDetector::new(NoSpacy, model, "gl", GlinerOptions { threshold: 0.5, preset: LabelPreset::Pii });
        let out = block_on(detector.extract_entities(text, &NerOptions { caseless_gate: false, postfilter: false })).unwrap();
        let view: Vec<_> =
            out.results.iter().map(|h| (h.result.span, h.result.label.as_str(), h.result.entity_type, h.score.is_some())).collect();
        assert_eq!(
            view,
            [((4, 14), "PERSON", "name", false), ((21, 29), "phone number", "phone", true), ((33, 37), "ORG", "organization", false)]
        );
        assert_eq!(out.results[0].result.reasoning, "GLiNER labelled this span as PERSON");
        assert_eq!(out.results[0].result.classification.pack(), 8222);
        assert_eq!(out.results[1].score, Some(0.9124));
        assert!(out.decisions.is_empty());
    }
}
