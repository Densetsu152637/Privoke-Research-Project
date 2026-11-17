//! The three pinned standard V3 manifests captured from the Go service must be admitted unchanged, and every
//! tampered variant must be refused.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{array, get, load, object, text, unsigned};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::v3::{self, ManifestError, TIERS};

fn manifests() -> Vec<(String, String)> {
    let corpus = load("model_streaming.json");
    object(get(&corpus, "v3")).iter().map(|(model, entry)| (model.clone(), text(get(entry, "manifest_json")).to_string())).collect()
}

#[test]
fn pinned_manifests_are_admitted_and_hash_to_their_pins() {
    let all = manifests();
    assert_eq!(all.len(), 3);
    for (model, payload) in &all {
        let manifest = v3::admitted_manifest(payload.as_bytes(), Some(model)).unwrap();
        assert_eq!(&manifest.model_id, model);
        assert_eq!(sha256_hex(payload.as_bytes()), v3::standard_pin(model).unwrap());
        assert_eq!(manifest.scope, "full_encoder");
        assert!(v3::admitted_manifest(payload.as_bytes(), Some("latest")).is_ok());
        assert!(v3::admitted_manifest(payload.as_bytes(), None).is_ok());
        assert_eq!(v3::admitted_manifest(payload.as_bytes(), Some("privoke-v3-other")), Err(ManifestError::IdentityDiffers));
    }
}

#[test]
fn recorded_package_responses_agree_with_the_manifests() {
    let corpus = load("model_streaming.json");
    for (model, entry) in object(get(&corpus, "v3")) {
        let package = get(entry, "get_model_package");
        let manifest = v3::admitted_manifest(text(get(entry, "manifest_json")).as_bytes(), Some(model)).unwrap();
        assert_eq!(text(get(package, "manifest_sha256")), v3::standard_pin(model).unwrap());
        let assets = array(get(package, "assets"));
        assert_eq!(assets.len(), v3::ASSET_NAMES.len());
        for asset in assets {
            let name = text(get(asset, "name"));
            assert!(v3::ASSET_NAMES.contains(&name), "{name}");
            let expected = match name {
                "model.safetensors" => &manifest.blob,
                "config.json" => &manifest.config,
                "vocab.txt" => &manifest.vocab,
                _ => manifest.evidence.as_ref().unwrap(),
            };
            assert_eq!(text(get(asset, "sha256")), expected, "{model} {name}");
            let streamed = get(get(get(entry, "stream_asset"), name), "bytes");
            assert_eq!(unsigned(get(asset, "size_bytes")), unsigned(streamed));
        }
    }
    assert_eq!(TIERS.len(), 3);
}

fn tamper(payload: &str, from: &str, to: &str) -> String {
    assert!(payload.contains(from), "tamper anchor {from} missing");
    payload.replacen(from, to, 1)
}

#[test]
fn tampered_manifests_are_refused() {
    let (model, payload) = manifests().into_iter().find(|(model, _)| model == "privoke-v3-balanced").unwrap();
    let bytes = payload.as_bytes();

    // Any change to the bytes breaks the pin even when it stays valid canonical JSON.
    let renamed = tamper(&payload, "\"scope\":\"full_encoder\"", "\"scope\":\"heads\"");
    assert_eq!(v3::admitted_manifest(renamed.as_bytes(), Some(&model)), Err(ManifestError::NotPinned));

    // Whitespace, a missing final LF and key reordering are not canonical.
    let spaced = tamper(&payload, "\"schema\":1", "\"schema\": 1");
    assert_eq!(v3::admitted_manifest(spaced.as_bytes(), None), Err(ManifestError::NotCanonical));
    let without_lf = &bytes[..bytes.len() - 1];
    assert_eq!(v3::admitted_manifest(without_lf, None), Err(ManifestError::NotCanonical));

    // Duplicate keys are rejected rather than resolved.
    let duplicate = tamper(&payload, "\"schema\":1", "\"schema\":1,\"schema\":1");
    assert!(matches!(v3::admitted_manifest(duplicate.as_bytes(), None), Err(ManifestError::Json(_))));

    // Non-finite JSON, invalid UTF-8 and oversize input.
    assert!(matches!(v3::parse_canonical(b"{\"x\":NaN}\n", 1024), Err(ManifestError::Json(_))));
    assert_eq!(v3::parse_canonical(&[0xff, 0xfe], 1024), Err(ManifestError::NotUtf8));
    assert_eq!(v3::parse_canonical(&vec![b' '; v3::MAX_MANIFEST_BYTES + 1], v3::MAX_MANIFEST_BYTES), Err(ManifestError::TooLarge));
}

fn validate(payload: &str) -> Result<v3::Manifest, ManifestError> {
    // Validation without the pin: tampered contents that would otherwise pass canonical parsing.
    v3::validate_manifest(&v3::parse_canonical(payload.as_bytes(), v3::MAX_MANIFEST_BYTES)?)
}

#[test]
fn manifest_contract_rules_reject_each_violation() {
    let (_, payload) = manifests().into_iter().find(|(model, _)| model == "privoke-v3-balanced").unwrap();
    assert!(validate(&payload).is_ok());

    let canonical_edit = |from: &str, to: &str| validate(&tamper(&payload, from, to));
    assert!(canonical_edit("\"tier\":\"balanced\"", "\"tier\":\"efficient\"").is_err());
    assert!(canonical_edit("\"model_id\":\"privoke-v3-balanced\"", "\"model_id\":\"privoke-v3-quality\"").is_err());
    assert!(canonical_edit("\"architecture\":\"privoke_pretrained_bert_v3\"", "\"architecture\":\"other\"").is_err());
    assert!(canonical_edit("\"schema\":1", "\"schema\":2").is_err());
    assert!(canonical_edit("\"parameter_count\":9596180", "\"parameter_count\":9596181").is_err());
    assert!(canonical_edit("\"repository\":\"google/bert_uncased_L-2_H-256_A-4\"", "\"repository\":\"evil/bert\"").is_err());
    assert!(
        canonical_edit(
            "\"revision\":\"4e937a8675e5afd9a4836735c186ec01695bc3ea\"",
            "\"revision\":\"0000000000000000000000000000000000000000\""
        )
        .is_err()
    );
    assert!(canonical_edit("\"scope\":\"full_encoder\"", "\"scope\":\"everything\"").is_err());
    assert!(canonical_edit("\"dtype\":\"F32\"", "\"dtype\":\"F16\"").is_err());
    // An ORIGINAL manifest may not carry lineage; a candidate must.
    assert!(canonical_edit("\"scope\":\"full_encoder\"", "\"scope\":\"original\"").is_err());
    let upper = payload.replacen(
        "e48e7c1aa46310b3b7b1f6422f7aa8902c70cf6ff861f7540a7c4be151de4df2",
        "E48E7C1AA46310B3B7B1F6422F7AA8902C70CF6FF861F7540A7C4BE151DE4DF2",
        1,
    );
    assert!(validate(&upper).is_err());
    assert!(v3::validate_manifest(&privoke_contracts::json::parse("[]").unwrap()).is_err());
}
