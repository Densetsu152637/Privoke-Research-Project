//! Shared helpers of the parity tests: golden files, fixtures and the digests the Python golden script computes.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use privoke_curriculum::Example;
use privoke_curriculum::value::{self, Value};

/// The crate directory.
pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The repository root.
pub fn repo_root() -> PathBuf {
    crate_dir().join("../../..")
}

/// A committed fixture.
pub fn fixture(relative: &str) -> PathBuf {
    crate_dir().join("tests/fixtures").join(relative)
}

/// A committed golden file as `serde_json`.
pub fn golden(name: &str) -> serde_json::Value {
    let path = crate_dir().join("tests/golden").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))).unwrap()
}

/// `serde_json` to the contracts value type (integers stay integers, floats stay floats).
pub fn to_value(item: &serde_json::Value) -> Value {
    value::parse_bytes(item.to_string().as_bytes()).unwrap()
}

/// `rows_digest` of the golden script: text, packed target, weight and metadata of each ordered example.
pub fn rows_digest(rows: &[Example]) -> String {
    let items: Vec<Value> = rows
        .iter()
        .map(|row| {
            Value::Array(vec![
                value::string(&row.text),
                value::int(i64::from(row.packed().unwrap())),
                Value::Float(row.weight),
                value::from_string_map(&row.metadata),
            ])
        })
        .collect();
    value::digest_of(&Value::Array(items)).unwrap()
}

/// `{training_sha256, heldout_sha256, training, heldout}` of the golden script.
pub fn partition_matches(entry: &serde_json::Value, training: &[Example], heldout: &[Example], label: &str) {
    assert_eq!(rows_digest(training), entry["training_sha256"].as_str().unwrap(), "{label}: training rows");
    assert_eq!(rows_digest(heldout), entry["heldout_sha256"].as_str().unwrap(), "{label}: held-out rows");
    assert_eq!(training.len() as u64, entry["training"].as_u64().unwrap(), "{label}: training count");
    assert_eq!(heldout.len() as u64, entry["heldout"].as_u64().unwrap(), "{label}: held-out count");
}

/// `sha256(canonical(audit))` of an audit map.
pub fn audit_digest(audit: &BTreeMap<String, String>) -> String {
    value::digest_of(&value::from_string_map(audit)).unwrap()
}

/// The bundled-fixture paths of the four BC01 inputs.
pub fn bc01_paths() -> BTreeMap<&'static str, PathBuf> {
    let mut paths = BTreeMap::new();
    paths.insert("taxonomy", fixture("bc01/taxonomy-coverage-v1.json"));
    paths.insert("pool", fixture("bc01/pool-authored.json"));
    paths.insert("manifest", fixture("bc01/benign-manifest.json"));
    paths.insert("proof", fixture("bc01/exclusion-proof.json"));
    paths
}

/// A benign release from a fixture directory.
pub fn benign_release(
    directory: &Path,
    dataset: &privoke_curriculum::taxonomy::TaxonomyDataset,
) -> privoke_curriculum::benign::BenignRelease {
    privoke_curriculum::benign::load_release(
        &directory.join("pool-authored.json"),
        &directory.join("benign-manifest.json"),
        &directory.join("exclusion-proof.json"),
        dataset,
    )
    .unwrap()
}

/// The AU3 release from the fixture copy that holds exactly the bytes its manifest pins (the manifest and guard are
/// pinned as LF bytes, the two catalogs as CRLF bytes, which no single checkout line-ending setting reproduces).
pub fn au3_release() -> privoke_curriculum::audience::AudienceRelease {
    privoke_curriculum::audience::load_release(
        Some(&fixture("au3/audience-v3-manifest-v1.json")),
        Some(privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256),
    )
    .unwrap()
}
