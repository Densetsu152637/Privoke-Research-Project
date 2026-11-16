//! Analysers for the parity tests: recorded spaCy results replayed without a worker, and a per-document cache.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use privoke_spacy::{Analysis, Entity, OffsetMap, Selection, Token};
use serde_json::Value;

use crate::analyzer::{NerError, SpacyBackend};

fn bad(what: &str) -> String {
    format!("malformed recorded analysis: {what}")
}

/// Decodes one recorded `{"tokens": [...], "ents": [...]}` body against the text it was recorded for.
pub fn decode_body(text: &str, body: &Value) -> Result<Analysis, String> {
    let map = OffsetMap::new(text);
    let mut tokens = Vec::new();
    for item in body.get("tokens").and_then(Value::as_array).ok_or_else(|| bad("tokens"))? {
        let f = item.as_array().filter(|f| f.len() == 10).ok_or_else(|| bad("token"))?;
        let string = |i: usize| f[i].as_str().map(str::to_owned).ok_or_else(|| bad("token string"));
        let int = |i: usize| f[i].as_u64().map(|v| v as usize).ok_or_else(|| bad("token integer"));
        let token_text = string(0)?;
        let idx = int(1)?;
        let end = idx + token_text.chars().count();
        let span = map.span(idx, end).ok_or_else(|| bad("token offset"))?;
        tokens.push(Token {
            text: token_text,
            idx,
            whitespace: string(2)?,
            is_alpha: f[3].as_bool().ok_or_else(|| bad("is_alpha"))?,
            lower: string(4)?,
            tag: string(5)?,
            pos: string(6)?,
            lemma: string(7)?,
            dep: string(8)?,
            head: int(9)?,
            span,
        });
    }
    let mut entities = Vec::new();
    for item in body.get("ents").and_then(Value::as_array).ok_or_else(|| bad("ents"))? {
        let f = item.as_array().filter(|f| f.len() == 3).ok_or_else(|| bad("entity"))?;
        let (start, end) =
            (f[0].as_u64().ok_or_else(|| bad("entity start"))? as usize, f[1].as_u64().ok_or_else(|| bad("entity end"))? as usize);
        let label = f[2].as_str().ok_or_else(|| bad("entity label"))?.to_owned();
        entities.push(Entity { label, span: map.span(start, end).ok_or_else(|| bad("entity offset"))? });
    }
    Ok(Analysis { tokens, entities })
}

/// Recorded analyses keyed by selection and text, and a recorded subset of the lemma-index word list.
#[derive(Debug, Default)]
pub struct ReplayAnalyzer {
    analyses: HashMap<(Selection, String), Analysis>,
    lexicon: Arc<Vec<String>>,
}

impl ReplayAnalyzer {
    /// Builds the replay from `{"sel", "text", "body"}` records and the lexicon words the recording queried.
    pub fn new(records: &[Value], lexicon: Vec<String>) -> Result<Self, String> {
        let mut analyses = HashMap::new();
        for record in records {
            let selection = match record.get("sel").and_then(Value::as_str) {
                Some("full") => Selection::Full,
                Some("tagger") => Selection::TaggerOnly,
                _ => return Err(bad("selection")),
            };
            let text = record.get("text").and_then(Value::as_str).ok_or_else(|| bad("text"))?;
            let body = record.get("body").ok_or_else(|| bad("body"))?;
            analyses.insert((selection, text.to_owned()), decode_body(text, body)?);
        }
        Ok(Self { analyses, lexicon: Arc::new(lexicon) })
    }
}

#[allow(clippy::manual_async_fn)] // the explicit `Send` bound is part of the trait
impl SpacyBackend for ReplayAnalyzer {
    fn analyze<'a>(&'a self, text: &'a str, selection: Selection) -> impl Future<Output = Result<Analysis, NerError>> + Send + 'a {
        async move {
            self.analyses
                .get(&(selection, text.to_owned()))
                .cloned()
                .ok_or_else(|| NerError::SpacyBackend(format!("no recorded {} analysis for {text:?}", selection.as_str())))
        }
    }

    fn lemma_index(&self) -> impl Future<Output = Result<Arc<Vec<String>>, NerError>> + Send {
        async move { Ok(self.lexicon.clone()) }
    }
}

/// Remembers every analysis for the lifetime of one document, so that the settings of a parity run (which mostly see
/// the same text) call the worker once per distinct text.
#[derive(Debug)]
pub struct CachedAnalyzer<'a, A> {
    inner: &'a A,
    cache: Mutex<HashMap<(Selection, String), Analysis>>,
}

impl<'a, A: SpacyBackend> CachedAnalyzer<'a, A> {
    /// A cache over `inner`.
    pub fn new(inner: &'a A) -> Self {
        Self { inner, cache: Mutex::new(HashMap::new()) }
    }
}

#[allow(clippy::manual_async_fn)] // the explicit `Send` bound is part of the trait
impl<A: SpacyBackend> SpacyBackend for CachedAnalyzer<'_, A> {
    fn analyze<'a>(&'a self, text: &'a str, selection: Selection) -> impl Future<Output = Result<Analysis, NerError>> + Send + 'a {
        async move {
            let key = (selection, text.to_owned());
            if let Some(found) = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&key) {
                return Ok(found.clone());
            }
            let analysis = self.inner.analyze(text, selection).await?;
            self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(key, analysis.clone());
            Ok(analysis)
        }
    }

    fn lemma_index(&self) -> impl Future<Output = Result<Arc<Vec<String>>, NerError>> + Send {
        self.inner.lemma_index()
    }
}
