//! The source of spaCy results: the stage 11 worker pool, or a recording replayed in tests.

use std::future::Future;
use std::sync::Arc;

use privoke_rules::pyre::PatternError;
use privoke_spacy::{Analysis, Selection, SpacyError, SpacyPool};

/// A failure of the NER layer: the spaCy worker, or a pattern that Python would also reject.
#[derive(Debug, thiserror::Error)]
pub enum NerError {
    /// The spaCy worker failed (`SpacyError::status` gives the gRPC-style status).
    #[error(transparent)]
    Spacy(#[from] SpacyError),
    /// A regular expression failed to compile or run.
    #[error(transparent)]
    Pattern(#[from] PatternError),
    /// Any other analyser failure (for example a missing recorded result).
    #[error("{0}")]
    SpacyBackend(String),
}

/// What the NER layer needs from spaCy: tokens and entities for a text, and the model's lemma-index word list.
pub trait SpacyBackend: Send + Sync {
    /// Runs the full pipeline or the tagger-only sub-pipeline over `text`.
    fn analyze<'a>(&'a self, text: &'a str, selection: Selection) -> impl Future<Output = Result<Analysis, NerError>> + Send + 'a;

    /// The words of the rule lemmatizer's `lemma_index` table (the post-filter's lexicon). Empty when the model has no
    /// lemmatizer table.
    fn lemma_index(&self) -> impl Future<Output = Result<Arc<Vec<String>>, NerError>> + Send;
}

#[allow(clippy::manual_async_fn)] // the explicit `Send` bound is part of the trait
impl SpacyBackend for SpacyPool {
    fn analyze<'a>(&'a self, text: &'a str, selection: Selection) -> impl Future<Output = Result<Analysis, NerError>> + Send + 'a {
        async move { Ok(SpacyPool::analyze(self, text, selection).await?) }
    }

    fn lemma_index(&self) -> impl Future<Output = Result<Arc<Vec<String>>, NerError>> + Send {
        async move { Ok(SpacyPool::lemma_index(self).await?) }
    }
}
