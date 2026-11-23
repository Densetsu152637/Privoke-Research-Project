//! The worker's semantic layer over the controller's model cache (stage V3-R4b of the V3 routine-training plan): which cached
//! version of a standard V3 model it may load.
//!
//! The cache is built from the shared signed-chain fixtures (`privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`, a toy
//! ORIGINAL, HEADS and FULL with test keys) with manifests and statements only. A version that the layer admits then fails at the
//! first asset it reads (`config.json` is absent), which tells the version that was selected and admitted apart from every refusal
//! by the lineage rule, by the high-water mark or by the cache. The positive load of a real signed version needs real weights and is
//! the same `load_verified` path as the pinned releases (`release_parity`, `v3_release`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::model_cache::{CacheRules, HIGH_WATER_FILE, STATEMENT_FILE};
use privoke_contracts::publication::test_keys;
use privoke_contracts::v3::TierPin;
use privoke_runtime::semantic::SemanticLayer;
use serde_json::Value;

const MODEL: &str = "privoke-v3-efficient";

struct Chain(Value);

impl Chain {
    fn load() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json");
        Self(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
    }

    fn manifest(&self, label: &str) -> Vec<u8> {
        let entry = self.0["manifests"].as_array().unwrap().iter().find(|entry| entry["label"] == label).unwrap();
        base64::engine::general_purpose::STANDARD.decode(entry["manifest_b64"].as_str().unwrap()).unwrap()
    }

    /// The manifest and statement of the signed chain's `index`th version (0 HEADS, 1 FULL).
    fn version(&self, index: usize) -> (Vec<u8>, Vec<u8>) {
        let entry = &self.0["chain"][index];
        (self.manifest(entry["manifest"].as_str().unwrap()), entry["statement"].as_str().unwrap().as_bytes().to_vec())
    }

    fn pin(&self) -> Vec<u8> {
        self.manifest("original")
    }
}

/// A layer over `root` whose compiled keys are the test keys and whose tier pin is the toy ORIGINAL.
fn layer(root: &Path, pin: &[u8]) -> SemanticLayer {
    let tier_pin = TierPin { manifest_sha: sha256_hex(pin), original: sha256_hex(pin) };
    let rules = CacheRules::new(test_keys::key_set()).with_pins(BTreeMap::from([(MODEL.to_string(), tier_pin)]));
    SemanticLayer::new(vec![root.to_path_buf()], None).unwrap().with_cache_rules(rules)
}

fn put(root: &Path, manifest: &[u8], statement: Option<&[u8]>) -> PathBuf {
    let directory = root.join(MODEL).join(sha256_hex(manifest));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("manifest.json"), manifest).unwrap();
    if let Some(statement) = statement {
        std::fs::write(directory.join(STATEMENT_FILE), statement).unwrap();
    }
    directory
}

fn mark(root: &Path, statement: &[u8]) {
    std::fs::write(root.join(MODEL).join(HIGH_WATER_FILE), statement).unwrap();
}

/// The text of the refusal of the layer's fetch.
fn refusal(layer: &SemanticLayer) -> String {
    layer.fetch(MODEL).unwrap_err()
}

/// The error of a version that was selected and admitted: its first asset is missing in this cache.
fn admitted_but_incomplete(error: &str, sha: &str) -> bool {
    error.contains("config.json") && error.contains(sha) && !error.contains("not admitted")
}

#[test]
fn the_first_start_loads_the_pinned_release_only() {
    let (chain, root) = (Chain::load(), tempfile::tempdir().unwrap());
    let pin = chain.pin();
    put(root.path(), &pin, None);
    // No mark and nothing signed cached: the pinned release is selected, admitted, and fails only at its first missing asset.
    let error = refusal(&layer(root.path(), &pin));
    assert!(admitted_but_incomplete(&error, &sha256_hex(&pin)), "{error}");
}

#[test]
fn a_deleted_mark_and_a_dropped_pin_do_not_reopen_the_unsigned_pin() {
    let (chain, root) = (Chain::load(), tempfile::tempdir().unwrap());
    let pin = chain.pin();
    put(root.path(), &pin, None);
    let (heads, statement) = chain.version(0);
    put(root.path(), &heads, Some(&statement));
    // No mark file, and the pinned release's manifest dropped beside the versions (the release layout): the floor is rebuilt from
    // the cached statement that verifies, so the selection is HEADS, and the pin is not loaded by either route.
    std::fs::write(root.path().join(MODEL).join("manifest.json"), &pin).unwrap();
    let error = refusal(&layer(root.path(), &pin));
    assert!(admitted_but_incomplete(&error, &sha256_hex(&heads)), "{error}");
    assert!(!error.contains(&sha256_hex(&pin)), "{error}");
}

#[test]
fn a_signed_mark_loads_its_version_and_never_the_pin() {
    let (chain, root) = (Chain::load(), tempfile::tempdir().unwrap());
    let pin = chain.pin();
    put(root.path(), &pin, None);
    let (heads, statement) = chain.version(0);
    put(root.path(), &heads, Some(&statement));
    mark(root.path(), &statement);
    let layer = layer(root.path(), &pin);

    let error = refusal(&layer);
    assert!(admitted_but_incomplete(&error, &sha256_hex(&heads)), "{error}");
    assert!(!error.contains(&sha256_hex(&pin)), "{error}");

    // The version at the mark disappears (a damaged cache): an error, not a fallback to the unsigned pin.
    std::fs::remove_dir_all(root.path().join(MODEL).join(sha256_hex(&heads))).unwrap();
    let error = refusal(&layer);
    assert!(error.contains("is not in the cache"), "{error}");

    // A manifest dropped beside the mark is not the pin-only release layout of a cache directory.
    std::fs::write(root.path().join(MODEL).join("manifest.json"), &pin).unwrap();
    let error = refusal(&layer);
    assert!(error.contains("is not in the cache"), "{error}");
}

#[test]
fn a_statement_that_is_not_the_marks_is_refused() {
    let (chain, root) = (Chain::load(), tempfile::tempdir().unwrap());
    let pin = chain.pin();
    put(root.path(), &pin, None);
    let (_, heads_statement) = chain.version(0);
    let (full, full_statement) = chain.version(1);
    // The mark is FULL's, and the directory it names holds HEADS's statement (a swapped file).
    let directory = put(root.path(), &full, Some(&heads_statement));
    mark(root.path(), &full_statement);
    let error = refusal(&layer(root.path(), &pin));
    assert!(error.contains("does not carry the statement"), "{error}");
    assert!(!admitted_but_incomplete(&error, &sha256_hex(&full)), "{error}");

    // No statement under the version the mark names: it does not verify, and the pin is not a fallback.
    std::fs::remove_file(directory.join(STATEMENT_FILE)).unwrap();
    let error = refusal(&layer(root.path(), &pin));
    assert!(error.contains("does not verify") && !admitted_but_incomplete(&error, &sha256_hex(&pin)), "{error}");

    // A tampered mark refuses the whole model.
    let mut forged = full_statement.clone();
    let start = forged.windows(13).position(|window| window == b"\"signature\":\"").unwrap() + 17;
    forged[start] = if forged[start] == b'0' { b'1' } else { b'0' };
    mark(root.path(), &forged);
    let error = refusal(&layer(root.path(), &pin));
    assert!(error.contains("High-water record") && error.contains("does not verify"), "{error}");
}

#[test]
fn a_newer_version_is_loaded_without_a_restart() {
    let (chain, root) = (Chain::load(), tempfile::tempdir().unwrap());
    let pin = chain.pin();
    put(root.path(), &pin, None);
    let (heads, heads_statement) = chain.version(0);
    let (full, full_statement) = chain.version(1);
    put(root.path(), &heads, Some(&heads_statement));
    mark(root.path(), &heads_statement);
    let layer = layer(root.path(), &pin);
    let error = refusal(&layer);
    assert!(admitted_but_incomplete(&error, &sha256_hex(&heads)), "{error}");

    // The supervisor admits FULL: its directory is complete, then the mark moves. The same layer follows.
    put(root.path(), &full, Some(&full_statement));
    mark(root.path(), &full_statement);
    let error = refusal(&layer);
    assert!(admitted_but_incomplete(&error, &sha256_hex(&full)), "{error}");

    // HEADS has been collected and the mark names FULL: nothing of HEADS is a candidate.
    std::fs::remove_dir_all(root.path().join(MODEL).join(sha256_hex(&heads))).unwrap();
    let error = refusal(&layer);
    assert!(admitted_but_incomplete(&error, &sha256_hex(&full)), "{error}");
}
