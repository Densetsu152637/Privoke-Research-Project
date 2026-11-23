//! Drift bounds for V3 candidates (stage V3-R2 of the routine-training plan).
//!
//! A routine cycle must not move a model far from the pinned ORIGINAL, however many cycles pass. Two L2 distances over every
//! tensor of the checkpoint are bounded, separately for each tier and for each scope (HEADS and FULL_ENCODER):
//!
//! * the **update**: the distance of the candidate from its parent (the version the fit started from);
//! * the **cumulative drift**: the distance of the candidate from the routine root, the pinned standard release its lineage
//!   descends from (or the ORIGINAL when the lineage never passes through one).
//!
//! The bounds live in `config/v3-drift-bounds.toml`. R2 ships *provisional* values from the V3-P pre-flight (twice the largest
//! single update observed from the standard releases, and four times that for the cumulative distance); stage V3-R5 recalibrates
//! them from real-weight fits of every tier and scope. The file carries the SHA-256 of the calibration record its values came
//! from (`evidence_sha256`) and its `status`.
//!
//! The check runs before the commit transaction ([`CommitObserver::prepare`]) and a breach is a `rejected` receipt with the
//! reason `drift_exceeded`: nothing is signed or published. A rollback is exempt (it returns to a version that passed once).

use std::collections::BTreeMap;
use std::path::Path;

use privoke_contracts::json::Value;
use privoke_semantic::safetensors::{self, Tensor};

use crate::v3_store::{Candidate, CheckpointStore, CommitObserver, StoreError};

/// The reason of a `rejected` receipt for a candidate that moved too far.
pub const DRIFT_EXCEEDED: &str = "drift_exceeded";

/// The bounds of one tier and scope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bound {
    /// The largest L2 distance of a candidate from its parent.
    pub max_update_l2: f64,
    /// The largest L2 distance of a candidate from the routine root (the pinned standard release).
    pub max_cumulative_l2: f64,
}

/// The bounds file: every tier and scope, the calibration status and its evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftBounds {
    /// `provisional` until a calibration run replaces the values, then `calibrated`.
    pub status: String,
    /// The SHA-256 of the calibration record the values came from.
    pub evidence_sha256: String,
    bounds: BTreeMap<(String, String), Bound>,
}

const TIERS: [&str; 3] = ["efficient", "balanced", "quality"];
const SCOPES: [&str; 2] = ["heads", "full_encoder"];

fn invalid(message: impl Into<String>) -> StoreError {
    StoreError::Invalid(message.into())
}

impl DriftBounds {
    /// Parse `config/v3-drift-bounds.toml`. Every tier and scope must be present, positive and finite: a bounds file that
    /// leaves one out is refused rather than read as unbounded.
    pub fn parse(text: &str) -> Result<Self, StoreError> {
        let table: toml::Table = text.parse().map_err(|error| invalid(format!("Drift bounds are not valid TOML: {error}")))?;
        if table.get("schema").and_then(toml::Value::as_integer) != Some(1) {
            return Err(invalid("Drift bounds require schema 1."));
        }
        let status = table.get("status").and_then(toml::Value::as_str).unwrap_or_default().to_string();
        if !["provisional", "calibrated"].contains(&status.as_str()) {
            return Err(invalid("Drift bounds status must be provisional or calibrated."));
        }
        let evidence_sha256 = table.get("evidence_sha256").and_then(toml::Value::as_str).unwrap_or_default().to_string();
        if evidence_sha256.len() != 64 || !evidence_sha256.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(invalid("Drift bounds require the SHA-256 of their calibration record."));
        }
        let number = |table: &toml::Table, key: &str| -> Result<f64, StoreError> {
            let value = table.get(key).and_then(|value| value.as_float().or_else(|| value.as_integer().map(|integer| integer as f64)));
            value
                .filter(|number| number.is_finite() && *number > 0.0)
                .ok_or_else(|| invalid(format!("Drift bound {key} must be a positive number.")))
        };
        let mut bounds = BTreeMap::new();
        for tier in TIERS {
            for scope in SCOPES {
                let entry = table
                    .get(tier)
                    .and_then(toml::Value::as_table)
                    .and_then(|tier_table| tier_table.get(scope))
                    .and_then(toml::Value::as_table)
                    .ok_or_else(|| invalid(format!("Drift bounds lack {tier}.{scope}.")))?;
                bounds.insert(
                    (tier.to_string(), scope.to_string()),
                    Bound { max_update_l2: number(entry, "max_update_l2")?, max_cumulative_l2: number(entry, "max_cumulative_l2")? },
                );
            }
        }
        Ok(Self { status, evidence_sha256, bounds })
    }

    /// Read and parse a bounds file.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// The bound of a tier and scope.
    pub fn bound(&self, tier: &str, scope: &str) -> Option<Bound> {
        self.bounds.get(&(tier.to_string(), scope.to_string())).copied()
    }
}

/// The L2 distance of two checkpoints over every tensor (float64 accumulation of float32 differences).
pub fn l2_distance(left: &BTreeMap<String, Tensor>, right: &BTreeMap<String, Tensor>) -> Result<f64, StoreError> {
    if left.len() != right.len() {
        return Err(invalid("Checkpoints differ in their tensor inventory."));
    }
    let mut total = 0.0f64;
    for (name, tensor) in left {
        let other = right.get(name).ok_or_else(|| invalid("Checkpoints differ in their tensor inventory."))?;
        if other.data.len() != tensor.data.len() {
            return Err(invalid("Checkpoints differ in their tensor inventory."));
        }
        total += tensor.data.iter().zip(&other.data).map(|(a, b)| (f64::from(*a) - f64::from(*b)).powi(2)).sum::<f64>();
    }
    Ok(total.sqrt())
}

fn text(document: &Value, key: &str) -> String {
    match document {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn checkpoint(store: &CheckpointStore, manifest: &Value) -> Result<BTreeMap<String, Tensor>, StoreError> {
    safetensors::parse(&store.read(&text(manifest, "blob"))?).map_err(|_| invalid("Snapshot tensors must be finite float32."))
}

/// The drift gate: a [`CommitObserver`] whose `prepare` refuses a candidate that moved beyond its bounds.
#[derive(Debug)]
pub struct DriftGate {
    bounds: DriftBounds,
}

impl DriftGate {
    /// A gate enforcing `bounds`.
    pub fn new(bounds: DriftBounds) -> Self {
        Self { bounds }
    }

    /// The routine root of a candidate: the pinned standard release its parent chain reaches (cumulative drift is measured from the
    /// version the clients pin), or, for a lineage that never passes through one, its ORIGINAL.
    pub fn root(store: &CheckpointStore, manifest: &Value) -> Result<Value, StoreError> {
        let model = text(manifest, "model_id");
        let pin = store.pin(&model);
        let mut parent = text(manifest, "parent");
        // The chain is bounded by the history of the model; a cycle would need a hash collision.
        for _ in 0..100_000 {
            if parent.is_empty() {
                break;
            }
            let version = store.manifest(&parent)?;
            if pin.as_deref() == Some(parent.as_str()) {
                return Ok(version);
            }
            parent = text(&version, "parent").to_string();
        }
        store.manifest(&text(manifest, "original"))
    }

    /// The two distances of an admitted candidate: from its parent and from the ORIGINAL.
    pub fn distances(store: &CheckpointStore, manifest: &Value) -> Result<(f64, f64), StoreError> {
        let candidate = checkpoint(store, manifest)?;
        let update = l2_distance(&candidate, &checkpoint(store, &store.manifest(&text(manifest, "parent"))?)?)?;
        let root = Self::root(store, manifest)?;
        let cumulative = l2_distance(&candidate, &checkpoint(store, &root)?)?;
        Ok((update, cumulative))
    }
}

impl CommitObserver for DriftGate {
    fn prepare(&self, candidate: &Candidate<'_>) -> Result<Option<String>, StoreError> {
        if candidate.evidence.is_none() {
            return Ok(None);
        }
        let (tier, scope) = (text(candidate.manifest, "tier"), text(candidate.manifest, "scope"));
        let bound = self.bounds.bound(&tier, &scope).ok_or_else(|| invalid(format!("No drift bound for {tier} {scope}.")))?;
        let (update, cumulative) = Self::distances(candidate.store, candidate.manifest)?;
        if update > bound.max_update_l2 || cumulative > bound.max_cumulative_l2 {
            return Ok(Some(DRIFT_EXCEEDED.to_string()));
        }
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn file(extra: &str) -> String {
        let mut text = format!("schema = 1\nstatus = \"provisional\"\nevidence_sha256 = \"{SHA}\"\n");
        for tier in TIERS {
            for scope in SCOPES {
                text.push_str(&format!("[{tier}.{scope}]\nmax_update_l2 = 4.3\nmax_cumulative_l2 = 17\n"));
            }
        }
        text.push_str(extra);
        text
    }

    fn tensor(values: &[f32]) -> Tensor {
        Tensor { shape: vec![values.len()], data: values.to_vec(), sha256: String::new() }
    }

    #[test]
    fn a_complete_bounds_file_is_read_and_a_bound_is_found_by_tier_and_scope() {
        let bounds = DriftBounds::parse(&file("")).unwrap();
        assert_eq!((bounds.status.as_str(), bounds.evidence_sha256.as_str()), ("provisional", SHA));
        assert_eq!(bounds.bound("quality", "full_encoder"), Some(Bound { max_update_l2: 4.3, max_cumulative_l2: 17.0 }));
        assert_eq!(bounds.bound("quality", "original"), None);
    }

    #[test]
    fn an_incomplete_or_unsound_bounds_file_is_refused() {
        assert!(DriftBounds::parse(&file("").replace("[balanced.heads]\nmax_update_l2 = 4.3\nmax_cumulative_l2 = 17\n", "")).is_err());
        assert!(DriftBounds::parse(&file("").replace("max_update_l2 = 4.3", "max_update_l2 = 0")).is_err());
        assert!(DriftBounds::parse(&file("").replace("schema = 1", "schema = 2")).is_err());
        assert!(DriftBounds::parse(&file("").replace("provisional", "guessed")).is_err());
        assert!(DriftBounds::parse(&file("").replace(SHA, "abc")).is_err());
        assert!(DriftBounds::parse("not toml =").is_err());
    }

    #[test]
    fn the_distance_is_the_l2_norm_over_every_tensor() {
        let left: BTreeMap<String, Tensor> =
            [("a".to_string(), tensor(&[3.0, 0.0])), ("b".to_string(), tensor(&[0.0]))].into_iter().collect();
        let right: BTreeMap<String, Tensor> =
            [("a".to_string(), tensor(&[0.0, 0.0])), ("b".to_string(), tensor(&[4.0]))].into_iter().collect();
        assert_eq!(l2_distance(&left, &right).unwrap(), 5.0);
        assert_eq!(l2_distance(&left, &left).unwrap(), 0.0);
        let shorter: BTreeMap<String, Tensor> = [("a".to_string(), tensor(&[0.0]))].into_iter().collect();
        assert!(l2_distance(&left, &shorter).is_err());
    }
}
