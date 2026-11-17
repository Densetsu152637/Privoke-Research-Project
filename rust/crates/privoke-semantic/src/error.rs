//! Errors of the semantic crate.

/// Why a model could not be loaded or an input could not be classified.
///
/// The `Input` message is the text of the exception the Python runtime raises, because the pipeline reports it as the
/// layer's error.
#[derive(Debug, thiserror::Error)]
pub enum SemanticError {
    /// The input cannot be classified (for example it is longer than the model's context).
    #[error("{0}")]
    Input(String),
    /// A model file, manifest or tensor is invalid.
    #[error("{0}")]
    Artifact(String),
    /// The tokenizer failed.
    #[error("tokenizer: {0}")]
    Tokenizer(String),
    /// A file could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: String,
        /// The cause.
        #[source]
        source: std::io::Error,
    },
}

impl SemanticError {
    pub(crate) fn artifact(message: impl Into<String>) -> Self {
        Self::Artifact(message.into())
    }
}
