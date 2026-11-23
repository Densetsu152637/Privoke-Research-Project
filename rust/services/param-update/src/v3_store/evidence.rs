//! `validate_source_evidence` of `services/pretrained-v3/src/fuzzer_training.py`: the admission of the fit's source record.
//!
//! The evidence of a fit carries the whole frozen source it trained on (the pinned inputs, the ordered sidecars and the wire
//! commitments). Admission reconstructs the committed wires from the sidecars and checks every row against the pinned inputs
//! (the BC01 taxonomy and benign release, or the trusted AU3 release): the trainer's own claim is never enough. The row-level
//! validation is [`privoke_curriculum::v3`] (stage 20); this module chooses the sampler, loads the pinned inputs once and adds
//! the last check, that the guard targets in the evidence are the ones the pinned source dispatched.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use privoke_contracts::json::Value;
use privoke_curriculum::audience::{self, AudienceRelease};
use privoke_curriculum::v3::{self, AU3_SAMPLER, INPUTS, Sources};
use privoke_curriculum::value;

use super::store::StoreError;

/// What the store asks of the pinned sources: validate the `source` of one parsed evidence document.
pub trait SourceEvidence: Send + Sync + std::fmt::Debug {
    /// `validate_source_evidence(evidence)`.
    fn validate(&self, evidence: &Value) -> Result<(), StoreError>;
}

/// Where the trusted AU3 release comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudienceSource {
    /// A custom manifest and its SHA-256 pin (`V3_AUDIENCE_MANIFEST_PATH` and `V3_AUDIENCE_MANIFEST_SHA256`).
    Trusted {
        /// The manifest.
        path: PathBuf,
        /// Its pin.
        sha256: String,
    },
    /// The release bundled with the checkout, which carries its own pin.
    Bundled(PathBuf),
}

/// The pinned inputs of the two frozen samplers, loaded on first use and kept.
#[derive(Debug)]
pub struct PinnedSources {
    bc01_paths: BTreeMap<&'static str, PathBuf>,
    audience: AudienceSource,
    bc01: Mutex<Option<Arc<Sources>>>,
    release: Mutex<Option<Arc<AudienceRelease>>>,
}

impl PinnedSources {
    /// Sources under a checkout `root`, as the V3 fuzzer and runtime read them: the BC01 inputs at their repository paths, and
    /// either the trusted custom AU3 release or the one bundled at `services/privoke-fuzzer/data/`.
    pub fn from_root(root: &std::path::Path, audience: Option<(PathBuf, String)>) -> Self {
        let bc01_paths = INPUTS.iter().map(|(key, relative, _)| (*key, root.join(relative))).collect();
        let audience = match audience {
            Some((path, sha256)) => AudienceSource::Trusted { path, sha256 },
            None => AudienceSource::Bundled(root.join("services/privoke-fuzzer/data/audience-v3-manifest-v1.json")),
        };
        Self::new(bc01_paths, audience)
    }

    /// Sources at explicit locations (the four BC01 inputs by key, and the AU3 release).
    pub fn new(bc01_paths: BTreeMap<&'static str, PathBuf>, audience: AudienceSource) -> Self {
        Self { bc01_paths, audience, bc01: Mutex::new(None), release: Mutex::new(None) }
    }

    fn sources(&self) -> Result<Arc<Sources>, StoreError> {
        let mut slot = self.bc01.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(loaded) = slot.as_ref() {
            return Ok(loaded.clone());
        }
        let loaded = Arc::new(v3::load_sources_from(&self.bc01_paths)?);
        *slot = Some(loaded.clone());
        Ok(loaded)
    }

    fn release(&self) -> Result<Arc<AudienceRelease>, StoreError> {
        let mut slot = self.release.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(loaded) = slot.as_ref() {
            return Ok(loaded.clone());
        }
        let loaded = Arc::new(match &self.audience {
            AudienceSource::Trusted { path, sha256 } => v3::trusted_release(Some(path.as_path()), Some(sha256.as_str()))?,
            AudienceSource::Bundled(path) => audience::load_release_from(path, true, None)?,
        });
        *slot = Some(loaded.clone());
        Ok(loaded)
    }
}

impl SourceEvidence for PinnedSources {
    fn validate(&self, evidence: &Value) -> Result<(), StoreError> {
        let source = value::require(evidence, "source")?;
        if value::get(source, "sampler").and_then(value::as_str) == Some(AU3_SAMPLER) {
            let release = self.release()?;
            v3::validate_source_evidence_au3(evidence, &release)?;
        } else {
            let sources = self.sources()?;
            v3::validate_source_evidence_bc01(evidence, &sources)?;
        }
        guard_targets(evidence)
    }
}

/// The last check of `validate_source_evidence`: both guard assessments score the targets of the dispatched pinned source.
pub fn guard_targets(evidence: &Value) -> Result<(), StoreError> {
    let source = value::require(evidence, "source")?;
    let expected: Vec<Option<&Value>> =
        value::array_at(source, "guard_sidecar")?.iter().map(|row| value::get(row, "packed_target")).collect();
    for key in ["base_guard", "candidate_guard"] {
        let rows = value::array_at(value::require(evidence, key)?, "rows")?;
        let actual: Vec<Option<&Value>> = rows.iter().map(|row| value::get(row, "target")).collect();
        if actual != expected {
            return Err(StoreError::Invalid("Execution guard targets differ from dispatched pinned source.".to_string()));
        }
    }
    Ok(())
}
