//! Replays the stage 0 conformance corpus: canonical JSON, float repr, contract configs, checksums and fingerprints
//! must reproduce the Python reference byte for byte.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;

use common::{array, corpus_dir, get, load, number, object, opt, repo_root, text, unsigned};
use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::{artifact_checksum, artifact_checksum_of_artifact, derived_seed, receipt_key, sha256_hex};
use privoke_contracts::fingerprint::parameter_fingerprint;
use privoke_contracts::json::{self, Duplicates, ParseOptions, Value};
use privoke_contracts::pyfloat;

fn parse_case(input: &str, case: &Value) -> Result<Value, json::JsonError> {
    let duplicates = match opt(case, "duplicates").map(text) {
        Some("last_wins") | None => Duplicates::LastWins,
        Some(other) => panic!("unknown duplicate policy {other}"),
    };
    json::parse_with(input, ParseOptions { duplicates, ..ParseOptions::default() })
}

#[test]
fn canonical_json_matches_python_byte_for_byte() {
    let corpus = load("canonical_json.json");
    let cases = array(get(&corpus, "cases"));
    assert!(cases.len() > 200, "corpus unexpectedly small: {}", cases.len());
    let (mut compared, mut refused) = (0, 0);
    for case in cases {
        let label = opt(case, "id").map(text).unwrap_or("duplicate-key-case");
        let input = text(get(case, "input_json"));
        let variant = Variant::from_corpus_name(text(get(case, "variant"))).unwrap();
        let parsed = parse_case(input, case);
        if opt(case, "rust_rejects_lone_surrogate").is_some() {
            assert!(parsed.is_err(), "{label}: lone surrogate must be rejected");
            refused += 1;
            continue;
        }
        match opt(case, "expected") {
            Some(expected) => {
                let value = parsed.unwrap_or_else(|error| panic!("{label}: {input}: {error}"));
                let actual = canonical::to_string(&value, variant).unwrap_or_else(|error| panic!("{label}: {error}"));
                assert_eq!(actual, text(expected), "{label}: {input}");
                compared += 1;
            }
            None => {
                let failed = match parsed {
                    Err(_) => true,
                    Ok(value) => canonical::to_string(&value, variant).is_err(),
                };
                assert!(failed, "{label}: Python refused {input} but Rust accepted it");
                refused += 1;
            }
        }
    }
    assert!(compared > 150 && refused > 5, "compared {compared}, refused {refused}");
}

#[test]
fn float_repr_matches_python_for_every_recorded_double() {
    let corpus = load("float_repr.json");
    let rows = array(get(&corpus, "cases"));
    assert!(rows.len() > 800);
    for row in rows {
        let pair = array(row);
        let bits = u64::from_str_radix(text(&pair[0]), 16).unwrap();
        let value = f64::from_bits(bits);
        assert_eq!(pyfloat::repr(value).unwrap(), text(&pair[1]), "bits {bits:016x}");
        // The text must parse back to the same double, as Python guarantees.
        assert_eq!(text(&pair[1]).parse::<f64>().unwrap().to_bits(), bits);
    }
}

#[test]
fn contract_configs_canonicalise_identically() {
    let corpus = load("contract_configs.json");
    let configs = array(get(&corpus, "configs"));
    assert!(configs.len() >= 10);
    for config in configs {
        let name = text(get(config, "name"));
        let variant = Variant::from_corpus_name(text(get(config, "variant"))).unwrap();
        let value = json::parse(text(get(config, "input_json"))).unwrap();
        assert_eq!(canonical::to_string(&value, variant).unwrap(), text(get(config, "expected")), "{name}");
    }
}

#[test]
fn derived_seeds_and_receipt_keys_match() {
    let corpus = load("contract_configs.json");
    for seed in array(get(&corpus, "derived_seeds")) {
        let actual = derived_seed(unsigned(get(seed, "seed")), text(get(seed, "purpose")), unsigned(get(seed, "index"))).unwrap();
        assert_eq!(actual, unsigned(get(seed, "expected")));
    }
    let keys = array(get(&corpus, "receipt_keys"));
    assert!(!keys.is_empty());
    for key in keys {
        let actual = receipt_key(text(get(key, "source_id")), text(get(key, "request_id")), text(get(key, "request_source_id"))).unwrap();
        assert_eq!(actual, text(get(key, "expected")));
    }
}

#[test]
fn v3_constants_equal_the_python_tables() {
    use privoke_contracts::v3::TIERS;
    let corpus = load("contract_configs.json");
    let configs = array(get(&corpus, "configs"));
    let find = |name: &str| configs.iter().find(|config| text(get(config, "name")) == name).unwrap();

    let mut tiers = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for tier in TIERS {
        let mut entry = BTreeMap::new();
        entry.insert("repository".to_string(), Value::String(tier.repository.into()));
        entry.insert("revision".to_string(), Value::String(tier.revision.into()));
        entry.insert("hidden_size".to_string(), Value::Int(tier.hidden_size.to_string()));
        entry.insert("num_hidden_layers".to_string(), Value::Int(tier.num_hidden_layers.to_string()));
        entry.insert("num_attention_heads".to_string(), Value::Int(tier.num_attention_heads.to_string()));
        entry.insert("parameters".to_string(), Value::Int(tier.parameters.to_string()));
        tiers.insert(tier.name.to_string(), Value::Object(entry));
        pins.insert(
            tier.name.to_string(),
            Value::Array(vec![Value::String(tier.weights_sha256.into()), Value::String(tier.config_sha256.into())]),
        );
    }
    assert_eq!(canonical::to_string(&Value::Object(tiers), Variant::Utf8Lf).unwrap(), text(get(find("v3_contract.TIERS"), "expected")));
    assert_eq!(
        canonical::to_string(&Value::Object(pins), Variant::Utf8Lf).unwrap(),
        text(get(find("v3_contract.SOURCE_PINS"), "expected"))
    );

    let standard = object(get(get(&corpus, "constants"), "v3_standard_pins"));
    assert_eq!(standard.len(), TIERS.len());
    for tier in TIERS {
        assert_eq!(text(&standard[&format!("privoke-v3-{}", tier.name)]), tier.manifest_pin);
    }
}

#[test]
fn synthetic_artifact_checksums_match() {
    let corpus = load("checksums.json");
    let cases = array(get(&corpus, "synthetic"));
    assert_eq!(cases.len(), 40);
    for case in cases {
        let payload = json::parse(text(get(case, "input_json"))).unwrap();
        assert_eq!(artifact_checksum(&payload).unwrap(), text(get(case, "expected")));
        // A checksum member is ignored when computing the checksum of a whole artifact.
        let mut with_checksum = object(&payload).clone();
        with_checksum.insert("checksum".into(), Value::String("0".repeat(64)));
        assert_eq!(artifact_checksum_of_artifact(&Value::Object(with_checksum)).unwrap(), text(get(case, "expected")));
    }
}

fn tensors(artifact: &Value) -> (BTreeMap<String, Vec<f64>>, BTreeMap<String, Vec<u64>>) {
    let mut values = BTreeMap::new();
    let mut shapes = BTreeMap::new();
    for (name, tensor) in object(get(artifact, "parameters")) {
        values.insert(name.clone(), array(get(tensor, "values")).iter().map(number).collect());
        shapes.insert(name.clone(), array(get(tensor, "shape")).iter().map(unsigned).collect());
    }
    (values, shapes)
}

#[test]
fn tracked_model_artifacts_keep_their_checksum_and_fingerprint() {
    let corpus = load("checksums.json");
    let artifacts = array(get(&corpus, "artifacts"));
    assert_eq!(artifacts.len(), 4);
    for entry in artifacts {
        let path = repo_root().join(text(get(entry, "path")));
        let raw = std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        // Git may check the file out with CRLF on Windows; the corpus hash folds it to LF.
        let folded: Vec<u8> = String::from_utf8(raw.clone()).unwrap().replace("\r\n", "\n").into_bytes();
        assert_eq!(sha256_hex(&folded), text(get(entry, "file_sha256_lf")), "{}", path.display());

        let artifact = json::parse(std::str::from_utf8(&raw).unwrap()).unwrap();
        let declared = text(get(&artifact, "checksum"));
        assert_eq!(declared, text(get(entry, "declared_checksum")));
        assert_eq!(artifact_checksum_of_artifact(&artifact).unwrap(), declared, "{}", path.display());

        let (values, shapes) = tensors(&artifact);
        assert_eq!(values.len() as u64, unsigned(get(entry, "tensors")));
        assert_eq!(values.values().map(Vec::len).sum::<usize>() as u64, unsigned(get(entry, "values")));
        assert_eq!(parameter_fingerprint(&values, Some(&shapes)).unwrap(), text(get(entry, "fingerprint_with_shapes")));
        assert_eq!(parameter_fingerprint(&values, None).unwrap(), text(get(entry, "fingerprint_without_shapes")));
    }
}

#[test]
fn synthetic_fingerprints_match() {
    let corpus = load("fingerprints.json");
    let cases = array(get(&corpus, "synthetic"));
    assert!(cases.len() >= 7);
    for case in cases {
        let name = text(get(case, "name"));
        let parameters = json::parse(text(get(case, "parameters_json"))).unwrap();
        let values: BTreeMap<String, Vec<f64>> =
            object(&parameters).iter().map(|(key, list)| (key.clone(), array(list).iter().map(number).collect())).collect();
        let shapes: BTreeMap<String, Vec<u64>> = object(&json::parse(text(get(case, "shapes_json"))).unwrap())
            .iter()
            .map(|(key, list)| (key.clone(), array(list).iter().map(unsigned).collect()))
            .collect();
        assert_eq!(parameter_fingerprint(&values, Some(&shapes)).unwrap(), text(get(case, "expected_with_shapes")), "{name}");
        assert_eq!(parameter_fingerprint(&values, None).unwrap(), text(get(case, "expected_without_shapes")), "{name}");
    }
}

#[test]
fn manifest_lists_every_corpus_file_and_hash() {
    let manifest = load("manifest.json");
    for (name, entry) in object(get(&manifest, "files")) {
        let bytes = std::fs::read(corpus_dir().join(name)).unwrap();
        assert_eq!(sha256_hex(&bytes), text(get(entry, "sha256")), "{name}");
    }
}
