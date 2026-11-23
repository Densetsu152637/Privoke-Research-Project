//! The shared signed-chain fixtures (`privoke-contracts/tests/fixtures/v3_signed_chain/chain.json`, written by
//! `evaluation/generate_v3_signed_chain_fixtures.py`): the statement format and the Ed25519 verification, replayed against a
//! chain that an independent implementation (a pure-Python RFC 8032) signed. Every consumer of the fixtures (the publisher, the
//! model service, the supervisor's lineage admission, `update_security.py`) reads the same file. The test lives here because the
//! deterministic test keys exist only behind the `test-keys` feature of `privoke-contracts`, which this crate enables for its tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::publication::test_keys::{self, PRIMARY_ID, SECONDARY_ID};
use privoke_contracts::publication::{KeySet, PublicationError, decode, public_key, sign, verify};
use privoke_contracts::v3;
use serde_json::Value;

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_test_keys_are_the_fixtures_keys() {
    let chain = fixture();
    for id in [PRIMARY_ID, SECONDARY_ID] {
        assert_eq!(hex(&public_key(&test_keys::seed(id)).unwrap()), chain["keys"][id].as_str().unwrap(), "{id}");
    }
    let rebuilt = KeySet::new()
        .with_hex(PRIMARY_ID, chain["keys"][PRIMARY_ID].as_str().unwrap())
        .unwrap()
        .with_hex(SECONDARY_ID, chain["keys"][SECONDARY_ID].as_str().unwrap())
        .unwrap();
    assert_eq!(rebuilt, test_keys::key_set());
}

#[test]
fn the_toy_manifests_satisfy_the_manifest_contract_and_the_chain_verifies() {
    let chain = fixture();
    let mut manifests: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    for entry in chain["manifests"].as_array().unwrap() {
        let raw = base64::engine::general_purpose::STANDARD.decode(entry["manifest_b64"].as_str().unwrap()).unwrap();
        assert_eq!(sha256_hex(&raw), entry["manifest_sha"].as_str().unwrap());
        v3::validate_manifest(&v3::parse(&raw, v3::MAX_MANIFEST_BYTES).unwrap()).unwrap();
        manifests.insert(entry["label"].as_str().unwrap().to_string(), (entry["manifest_sha"].as_str().unwrap().to_string(), raw));
    }
    let keys = test_keys::key_set();
    let mut sequence = 0;
    for entry in chain["chain"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let wire = entry["statement"].as_str().unwrap().as_bytes();
        let statement = verify(&keys, wire).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(statement.manifest_sha, manifests[entry["manifest"].as_str().unwrap()].0, "{name}: the statement names its manifest");
        assert_eq!(statement.model_id, chain["model_id"].as_str().unwrap());
        assert!(statement.sequence > sequence, "{name}: sequences increase along the chain");
        sequence = statement.sequence;
        // Ed25519 is deterministic: signing the same statement again gives the fixture's bytes.
        assert_eq!(sign(&test_keys::seed(&statement.key_id), &statement).unwrap(), wire, "{name}: the Rust signature is the fixture's");
    }
    // The ORIGINAL's statement carries empty lineage; a rollback is a higher sequence for an earlier manifest.
    let rollback = &chain["chain"][2];
    let (statement, _) = decode(rollback["statement"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!((statement.parent.as_str(), statement.original.as_str(), statement.sequence), ("", "", 3));
    assert_eq!(statement.manifest_sha, chain["original_pin"].as_str().unwrap());
}

#[test]
fn a_rotation_overlap_accepts_both_keys_and_a_key_set_without_the_new_key_refuses_it() {
    let chain = fixture();
    let second = chain["chain"][3]["statement"].as_str().unwrap().as_bytes();
    assert_eq!(verify(&test_keys::key_set(), second).unwrap().key_id, SECONDARY_ID);
    assert_eq!(verify(&test_keys::primary_only(), second).unwrap_err(), PublicationError::UnknownKey);
    let first = chain["chain"][0]["statement"].as_str().unwrap().as_bytes();
    assert_eq!(verify(&test_keys::primary_only(), first).unwrap().key_id, PRIMARY_ID);
}

#[test]
fn the_forged_variants_are_refused_where_the_format_can_refuse_them() {
    let chain = fixture();
    for entry in chain["forged"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let outcome = verify(&test_keys::key_set(), entry["statement"].as_str().unwrap().as_bytes());
        match entry["verify"].as_str().unwrap() {
            "bad_signature" => assert_eq!(outcome.unwrap_err(), PublicationError::BadSignature, "{name}"),
            "unknown_key" => assert_eq!(outcome.unwrap_err(), PublicationError::UnknownKey, "{name}"),
            "malformed" => assert!(matches!(outcome, Err(PublicationError::Malformed(_))), "{name}"),
            // Validly signed, forged only against the manifest or the lineage: the lineage rules of V3-R4a refuse these.
            "ok" => {
                outcome.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert!(entry["lineage"].as_str().unwrap().starts_with("refused"), "{name}: a lineage rule is named");
            }
            other => panic!("{name}: {other}"),
        }
    }
}
