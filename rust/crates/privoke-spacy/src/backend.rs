//! The backend choice the runtime makes: [`Spacy::InProcess`] by default, [`Spacy::WorkerPool`] only for tests and as
//! the parity oracle.
//!
//! Both variants have the same methods, the same errors and the same offset conversion, so the NER layer cannot tell
//! them apart.

use std::sync::Arc;
use std::time::Duration;

use crate::error::{ConfigError, SpacyError};
use crate::inprocess::{InProcess, InProcessConfig};
use crate::pool::{PoolConfig, SpacyPool};
use crate::protocol::{Analysis, RawAnalysis, Selection, WorkerInfo};

/// Which backend to start. The default is the in-process one: no separate spaCy process exists.
#[derive(Clone, Debug)]
pub enum SpacyConfig {
    /// spaCy on a dedicated interpreter thread of this process (stage 11b). The default.
    InProcess(InProcessConfig),
    /// A supervised pool of `privoke-spacy-worker` child processes (stage 11). For tests and as the parity oracle.
    WorkerPool(PoolConfig),
}

impl Default for SpacyConfig {
    fn default() -> Self {
        Self::InProcess(InProcessConfig::default())
    }
}

impl SpacyConfig {
    /// The in-process backend over a bundle directory.
    pub fn in_process(bundle: impl Into<std::path::PathBuf>) -> Self {
        Self::InProcess(InProcessConfig::new(bundle))
    }

    /// The worker-pool backend (tests and parity only).
    pub fn worker_pool(cfg: PoolConfig) -> Self {
        Self::WorkerPool(cfg)
    }
}

/// A running spaCy backend.
#[derive(Debug)]
pub enum Spacy {
    /// See [`SpacyConfig::InProcess`].
    InProcess(InProcess),
    /// See [`SpacyConfig::WorkerPool`].
    WorkerPool(SpacyPool),
}

impl Spacy {
    /// Starts the chosen backend. Returns at once; [`Spacy::wait_ready`] waits for the model.
    /// The worker-pool variant must run inside a Tokio runtime.
    pub fn start(cfg: &SpacyConfig) -> Result<Self, ConfigError> {
        Ok(match cfg {
            SpacyConfig::InProcess(cfg) => Self::InProcess(InProcess::start(cfg)?),
            SpacyConfig::WorkerPool(cfg) => Self::WorkerPool(SpacyPool::start(cfg.clone())?),
        })
    }

    /// True once the model is loaded and something can answer.
    pub fn is_ready(&self) -> bool {
        match self {
            Self::InProcess(b) => b.is_ready(),
            Self::WorkerPool(b) => b.is_ready(),
        }
    }

    /// The loaded model's announcement.
    pub fn worker_info(&self) -> Option<WorkerInfo> {
        match self {
            Self::InProcess(b) => b.worker_info(),
            Self::WorkerPool(b) => b.worker_info(),
        }
    }

    /// Waits until the model is loaded; see [`InProcess::wait_ready`].
    pub async fn wait_ready(&self, within: Duration) -> Result<(), SpacyError> {
        match self {
            Self::InProcess(b) => b.wait_ready(within).await,
            Self::WorkerPool(b) => b.wait_ready(within).await,
        }
    }

    /// Runs spaCy on `text` and returns the exact result bytes.
    pub async fn analyze_raw(&self, text: &str, selection: Selection) -> Result<RawAnalysis, SpacyError> {
        match self {
            Self::InProcess(b) => b.analyze_raw(text, selection).await,
            Self::WorkerPool(b) => b.analyze_raw(text, selection).await,
        }
    }

    /// Runs spaCy on `text` and decodes the result (UTF-8 and UTF-16 offsets).
    pub async fn analyze(&self, text: &str, selection: Selection) -> Result<Analysis, SpacyError> {
        match self {
            Self::InProcess(b) => b.analyze(text, selection).await,
            Self::WorkerPool(b) => b.analyze(text, selection).await,
        }
    }

    /// The model's lemma-index word list.
    pub async fn lemma_index(&self) -> Result<Arc<Vec<String>>, SpacyError> {
        match self {
            Self::InProcess(b) => b.lemma_index().await,
            Self::WorkerPool(b) => b.lemma_index().await,
        }
    }
}
