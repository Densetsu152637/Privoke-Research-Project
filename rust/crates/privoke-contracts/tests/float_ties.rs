//! Exact decimal ties: float32-derived doubles whose 17- or 16-digit shortest form sits exactly halfway between two
//! round-tripping strings. Python `repr` rounds the last digit to even; Rust's shortest `{:e}` rounds up. The
//! prepared full-encoder release (`v0.4.0-full-ctx256`) contains `0.016115188598632812`, which made the model
//! service refuse it with "artifact checksum does not match its contents" (RUST-CHECKSUM-1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::excessive_precision)]

use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::artifact_checksum_of_artifact;
use privoke_contracts::json::{self, Value};
use privoke_contracts::pyfloat;

/// Minimal synthetic artifact; the document and its checksum were produced by Python
/// `privoke_model.artifact.artifact_checksum` and `json.dumps(sort_keys=True, separators=(",", ":"))`.
const ARTIFACT: &str = r#"{"checksum":"61c0cfc1f9f7f71e5f69b1782be46852892228a68c598e8e24e55db70f6742e8","model_id":"tie-probe","parameters":{"w":[0.016115188598632812,-913.7710571289062,750.6682739257812,1010.4002075195312,0.1]}}"#;

#[test]
fn tie_values_use_python_half_even_digits() {
    for (value, expected) in [
        (0.016115188598632812, "0.016115188598632812"),
        (-913.7710571289062, "-913.7710571289062"),
        (750.6682739257812, "750.6682739257812"),
        (1010.4002075195312, "1010.4002075195312"),
    ] {
        // Rust's own shortest form differs in the last digit, which is the divergence being guarded.
        assert_ne!(format!("{value}"), expected, "{value:e} is no longer a tie case");
        assert_eq!(pyfloat::repr(value).unwrap(), expected);
        assert_eq!(expected.parse::<f64>().unwrap().to_bits(), value.to_bits());
    }
}

#[test]
fn synthetic_tie_artifact_checksum_matches_python() {
    let root = json::parse(ARTIFACT).unwrap();
    let Value::Object(map) = &root else { panic!("artifact is an object") };
    let Some(Value::String(stored)) = map.get("checksum") else { panic!("checksum member") };
    assert_eq!(&artifact_checksum_of_artifact(&root).unwrap(), stored);
    // The canonical text is the input itself (already sorted and compact) without the checksum member.
    let mut body = map.clone();
    body.remove("checksum");
    let expected =
        r#"{"model_id":"tie-probe","parameters":{"w":[0.016115188598632812,-913.7710571289062,750.6682739257812,1010.4002075195312,0.1]}}"#;
    assert_eq!(canonical::to_string(&Value::Object(body), Variant::Utf8Go).unwrap(), expected);
}
