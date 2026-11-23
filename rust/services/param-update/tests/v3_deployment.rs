//! What the deployment (stage V3-R7) ships inside the param-update image under `config/`, checked against the compiled pins: the
//! frozen routine policy, the three V3 retention reference releases, the calibrated drift bounds and the production key set. The
//! reference releases hold ids and numbers only (no prompt text); the approved bank is a separate read-only mount that is never
//! committed, so the full rebuild (`privoke-v3-retention-reference verify`) stays a local step recorded in the plan.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use privoke_contracts::digest::sha256_hex;
use privoke_curriculum::v3::Policy;
use privoke_curriculum::value::canonical_bytes;
use privoke_param_update::v3_policy::DriftBounds;
use privoke_training::retention_v3::RELEASE_PINS;

fn config() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config")
}

/// The calibration record of stage V3-R5 that the deployed bounds name (`models/experiments/v3r5_routine_20261123/CALIBRATION.json`).
const V3_R5_EVIDENCE_SHA256: &str = "c35c73508940d39672e5acfa2b6f408cc0e0b775378aefbb8be3f0a95d45fef7";

#[test]
fn the_shipped_routine_policy_is_the_frozen_64_step_policy() {
    let shipped = std::fs::read(config().join("v3-policy.json")).unwrap();
    assert_eq!(shipped, canonical_bytes(&Policy { steps: 64 }.to_value()).unwrap(), "config/v3-policy.json");
}

#[test]
fn the_shipped_reference_releases_are_the_pinned_ones() {
    for (tier, pin) in RELEASE_PINS {
        let directory = config().join("v3-retention").join(tier);
        let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
        assert_eq!(sha256_hex(&manifest), pin, "{tier} manifest.json is not the pinned reference release");
        let references = std::fs::read(directory.join("references.json")).unwrap();
        let text = String::from_utf8(manifest).unwrap();
        assert!(text.contains(&sha256_hex(&references)), "{tier} manifest does not name its references.json digest");
        assert!(references.len() < 128 * 1024, "{tier} references are ids and numbers only");
    }
}

#[test]
fn the_deployed_drift_bounds_are_the_calibrated_ones() {
    let bounds = DriftBounds::load(&config().join("v3-drift-bounds.toml")).unwrap();
    assert_eq!(bounds.status, "calibrated");
    assert_eq!(bounds.evidence_sha256, V3_R5_EVIDENCE_SHA256);
}

#[test]
fn a_production_publication_key_is_compiled_in() {
    use privoke_contracts::publication::{PRODUCTION_KEYS, production_key_set};
    assert!(!PRODUCTION_KEYS.is_empty(), "V3-R7 compiles the first publication key into the clients");
    let keys = production_key_set();
    for (key_id, public) in PRODUCTION_KEYS {
        assert!(keys.contains(key_id), "{key_id} must parse");
        assert_eq!(public.len(), 64);
        assert!(!key_id.starts_with("test-"), "no test key is a production key");
    }
}
