//! Errors of the training paths; the messages follow the Python `ValueError` texts where one exists.

use privoke_contracts::canonical::CanonicalError;
use privoke_semantic::SemanticError;

/// A training failure.
#[derive(Debug, thiserror::Error)]
pub enum TrainingError {
    /// A request or contract violation (`ValueError` in Python).
    #[error("{0}")]
    Invalid(String),
    /// The artifact could not be loaded.
    #[error(transparent)]
    Model(#[from] SemanticError),
    /// A fingerprint could not be encoded (a non-finite value).
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

impl TrainingError {
    /// A contract violation with the given message.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}
