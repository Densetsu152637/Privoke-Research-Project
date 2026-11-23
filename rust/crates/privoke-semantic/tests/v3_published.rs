//! `V3Model::load_published` (stage V3-R4b): a cached version is admitted by lineage and signature, under the persisted high-water mark,
//! before any asset is read. The versions are the shared signed-chain fixtures (a toy ORIGINAL, HEADS, FULL; test keys), which have
//! manifests and statements but no weights: a version that is admitted fails at its first missing asset (`config.json`), and every
//! refusal by the rule is a different error, so the two tell the admission outcome apart. The positive load of real weights runs the
//! same `load_verified` path as `load_release` (the release parity tests).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use base64::Engine as _;
use privoke_contracts::publication::{self, Statement, test_keys};
use privoke_contracts::v3::{LineageState, TierPin};
use privoke_semantic::V3Model;
use serde_json::Value;

const MODEL: &str = "privoke-v3-efficient";

fn chain() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../privoke-contracts/tests/fixtures/v3_signed_chain/chain.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn manifest(chain: &Value, label: &str) -> Vec<u8> {
    let entry = chain["manifests"].as_array().unwrap().iter().find(|entry| entry["label"] == label).unwrap();
    base64::engine::general_purpose::STANDARD.decode(entry["manifest_b64"].as_str().unwrap()).unwrap()
}

/// The compiled pin (the toy ORIGINAL) and the persisted high-water statement of a client.
struct Client {
    pin: String,
    seen: Option<Statement>,
}

impl LineageState for Client {
    fn tier_pin(&self, _: &str) -> Option<TierPin> {
        Some(TierPin { manifest_sha: self.pin.clone(), original: self.pin.clone() })
    }

    fn high_water(&self, _: &str) -> Result<Option<Statement>, String> {
        Ok(self.seen.clone())
    }
}

fn load(client: &Client, manifest: &[u8], statement: &[u8]) -> String {
    let empty = tempfile::tempdir().unwrap();
    let error = V3Model::load_published(empty.path(), MODEL, manifest, statement, &test_keys::key_set(), client).unwrap_err();
    error.to_string()
}

#[test]
fn a_signed_mark_refuses_the_unsigned_pin_and_a_lower_version_before_any_asset_is_read() {
    let chain = chain();
    let pin = chain["original_pin"].as_str().unwrap().to_string();
    let original = manifest(&chain, "original");
    let (heads, full) = (manifest(&chain, "heads"), manifest(&chain, "full"));
    let statement = |index: usize| chain["chain"][index]["statement"].as_str().unwrap().as_bytes().to_vec();
    let verified = |index: usize| publication::verify(&test_keys::key_set(), &statement(index)).unwrap();

    // The mark is FULL (sequence 2): the unsigned pin is a downgrade and HEADS (sequence 1) a replay.
    let signed = Client { pin: pin.clone(), seen: Some(verified(1)) };
    let error = load(&signed, &original, &[]);
    assert!(error.contains("not admitted") && error.contains("unsigned ORIGINAL refused"), "{error}");
    let error = load(&signed, &heads, &statement(0));
    assert!(error.contains("not admitted") && error.contains("below the accepted high-water mark"), "{error}");
    // A statement of another manifest, and a tampered one, are refused too.
    let error = load(&signed, &full, &statement(0));
    assert!(error.contains("not admitted"), "{error}");

    // FULL at the mark, and the unsigned pin on a first start, are admitted: they fail only at the first missing asset.
    let error = load(&signed, &full, &statement(1));
    assert!(error.contains("config.json") && !error.contains("not admitted"), "{error}");
    let first = Client { pin, seen: None };
    let error = load(&first, &original, &[]);
    assert!(error.contains("config.json") && !error.contains("not admitted"), "{error}");
    // ... but an unsigned trained version is never admitted, mark or not.
    let error = load(&first, &heads, &[]);
    assert!(error.contains("not admitted"), "{error}");
}
