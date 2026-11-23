//! Client lineage and signature admission against the shared signed-chain fixtures (stage V3-R4a of the V3 routine-training plan).
//!
//! `privoke-contracts/tests/fixtures/v3_signed_chain/chain.json` holds an ORIGINAL, a HEADS and a FULL version, a signed rollback to the
//! ORIGINAL, a second-key version and eleven forged variants, all on a toy checkpoint whose ORIGINAL is not the compiled tier pin.
//! The fixture names that ORIGINAL (`original_pin`), so every case here takes it as the tier pin. Each case runs
//! `privoke_contracts::v3::admit_lineage` and must end as the table says; `evaluation/update_security.py` reads the rows
//! (`PRIVOKE_LINEAGE_ROWS_OUT`) and judges them against its own copy of the table.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

use base64::Engine as _;
use common::rows::record;
use privoke_contracts::publication::test_keys::{self, SECONDARY_ID};
use privoke_contracts::publication::{self, KeySet, PublicationError, Statement};
use privoke_contracts::v3::{self, LineageError, LineageState, TierPin};
use serde_json::Value;

const MODEL: &str = "privoke-v3-efficient";

fn fixture() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-contracts/tests/fixtures/v3_signed_chain/chain.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// The compiled pin and the persisted high-water statement of a test client.
struct Client {
    pin: String,
    seen: Option<Statement>,
}

impl LineageState for Client {
    fn tier_pin(&self, model_id: &str) -> Option<TierPin> {
        // The toy ORIGINAL is the pinned release and the `original` of every version descending from it.
        (model_id == MODEL).then(|| TierPin { manifest_sha: self.pin.clone(), original: self.pin.clone() })
    }

    fn high_water(&self, model_id: &str) -> Result<Option<Statement>, String> {
        assert_eq!(model_id, MODEL);
        Ok(self.seen.clone())
    }
}

struct Chain {
    value: Value,
}

impl Chain {
    fn pin(&self) -> String {
        self.value["original_pin"].as_str().unwrap().to_string()
    }

    fn manifest(&self, label: &str) -> Vec<u8> {
        let entry = self.value["manifests"].as_array().unwrap().iter().find(|entry| entry["label"] == label).unwrap();
        base64::engine::general_purpose::STANDARD.decode(entry["manifest_b64"].as_str().unwrap()).unwrap()
    }

    /// The statement of the `index`th version of the signed chain (0 HEADS, 1 FULL, 2 rollback, 3 second key).
    fn statement(&self, index: usize) -> Vec<u8> {
        self.value["chain"][index]["statement"].as_str().unwrap().as_bytes().to_vec()
    }

    fn manifest_of(&self, index: usize) -> Vec<u8> {
        self.manifest(self.value["chain"][index]["manifest"].as_str().unwrap())
    }

    fn forged(&self, name: &str) -> (Vec<u8>, Vec<u8>) {
        let entry = self.value["forged"].as_array().unwrap().iter().find(|entry| entry["name"] == name).unwrap();
        (self.manifest(entry["manifest"].as_str().unwrap()), entry["statement"].as_str().unwrap().as_bytes().to_vec())
    }

    /// The high-water mark after the `index`th version of the chain was accepted.
    fn seen(&self, index: usize) -> Statement {
        publication::verify(&test_keys::key_set(), &self.statement(index)).unwrap()
    }
}

/// One row of the table.
struct Case {
    id: &'static str,
    name: &'static str,
    manifest: Vec<u8>,
    statement: Vec<u8>,
    seen: Option<Statement>,
    keys: KeySet,
    pin: String,
    requested: &'static str,
    /// `None`: accepted. `Some(reason)`: refused, with the variant of the refusal.
    refused: Option<&'static str>,
}

fn reason(error: &LineageError) -> &'static str {
    match error {
        LineageError::Manifest(_) => "Manifest",
        LineageError::Publication(PublicationError::Malformed(_)) => "Malformed",
        LineageError::Publication(PublicationError::UnknownKey) => "UnknownKey",
        LineageError::Publication(PublicationError::BadSignature) => "BadSignature",
        LineageError::Publication(PublicationError::BadKey) => "BadKey",
        LineageError::NoPin => "NoPin",
        LineageError::Unsigned => "Unsigned",
        LineageError::Downgrade => "Downgrade",
        LineageError::StatementModel => "StatementModel",
        LineageError::StatementManifest => "StatementManifest",
        LineageError::StatementLineage => "StatementLineage",
        LineageError::Replay { .. } => "Replay",
        LineageError::SequenceConflict(_) => "SequenceConflict",
        LineageError::WrongOriginal => "WrongOriginal",
        LineageError::HighWater(_) => "HighWater",
    }
}

fn run(case: &Case) {
    let client = Client { pin: case.pin.clone(), seen: case.seen.clone() };
    let outcome = v3::admit_lineage(&case.manifest, &case.statement, Some(case.requested), &case.keys, &client);
    let expected = if case.refused.is_some() { "refused" } else { "accepted" };
    match (&outcome, case.refused) {
        (Ok(admitted), None) => {
            record(case.id, case.name, expected, "accepted", "");
            assert_eq!(admitted.manifest.model_id, MODEL, "{}", case.id);
            assert_eq!(admitted.statement.is_some(), !case.statement.is_empty(), "{}", case.id);
        }
        (Err(error), Some(wanted)) => {
            record(case.id, case.name, expected, "refused", reason(error));
            assert_eq!(reason(error), wanted, "{} {}: {error}", case.id, case.name);
        }
        (Ok(_), Some(wanted)) => {
            record(case.id, case.name, expected, "accepted", "");
            panic!("{} {}: accepted, expected the refusal {wanted}", case.id, case.name);
        }
        (Err(error), None) => {
            record(case.id, case.name, expected, "refused", reason(error));
            panic!("{} {}: refused: {error}", case.id, case.name);
        }
    }
}

fn cases(chain: &Chain) -> Vec<Case> {
    let both = test_keys::key_set();
    let pin = chain.pin();
    let case = |id: &'static str,
                name: &'static str,
                manifest: Vec<u8>,
                statement: Vec<u8>,
                seen: Option<Statement>,
                refused: Option<&'static str>| Case {
        id,
        name,
        manifest,
        statement,
        seen,
        keys: both.clone(),
        pin: pin.clone(),
        requested: MODEL,
        refused,
    };
    let forged = |id: &'static str, name: &'static str, seen: Option<Statement>, refused: &'static str| {
        let (manifest, statement) = chain.forged(name);
        case(id, name, manifest, statement, seen, Some(refused))
    };
    let first_only = test_keys::primary_only();
    let second_only = KeySet::new().with(SECONDARY_ID, publication::public_key(&test_keys::seed(SECONDARY_ID)).unwrap());
    let mut cases = vec![
        // The eleven forged variants.
        forged("L01", "wrong-original", None, "WrongOriginal"),
        forged("L02", "bad-signature", None, "BadSignature"),
        forged("L03", "malleable-signature", None, "BadSignature"),
        forged("L04", "unknown-key", None, "UnknownKey"),
        forged("L05", "not-canonical", None, "Malformed"),
        forged("L06", "another-model", None, "StatementModel"),
        forged("L07", "lower-sequence-replay", Some(chain.seen(2)), "Replay"),
        forged("L08", "same-sequence-other-manifest", Some(chain.seen(0)), "SequenceConflict"),
        forged("L09", "parent-differs-from-manifest", None, "StatementLineage"),
        forged("L10", "original-differs-from-manifest", None, "StatementLineage"),
        forged("L11", "statement-for-another-manifest", None, "StatementManifest"),
        // Downgrade and unsigned versions.
        case(
            "L12",
            "downgrade-to-unsigned-original-after-heads",
            chain.manifest("original"),
            Vec::new(),
            Some(chain.seen(0)),
            Some("Downgrade"),
        ),
        case(
            "L13",
            "downgrade-to-unsigned-original-after-rollback",
            chain.manifest("original"),
            Vec::new(),
            Some(chain.seen(2)),
            Some("Downgrade"),
        ),
        case("L14", "unsigned-trained-version", chain.manifest("heads"), Vec::new(), None, Some("Unsigned")),
        // Keys, pins and the requested model.
        Case { keys: KeySet::new(), ..case("L15", "no-compiled-key", chain.manifest_of(0), chain.statement(0), None, Some("UnknownKey")) },
        Case {
            pin: v3::standard_pin(MODEL).unwrap().to_string(),
            ..case("L16", "toy-chain-under-the-compiled-pin", chain.manifest_of(0), chain.statement(0), None, Some("WrongOriginal"))
        },
        Case {
            requested: "privoke-v3-quality",
            ..case("L17", "other-model-requested", chain.manifest_of(0), chain.statement(0), None, Some("Manifest"))
        },
        Case {
            keys: first_only,
            ..case(
                "L23",
                "second-key-refused-when-only-the-first-is-compiled",
                chain.manifest_of(3),
                chain.statement(3),
                Some(chain.seen(2)),
                Some("UnknownKey"),
            )
        },
        Case {
            keys: second_only,
            ..case(
                "L24",
                "first-key-refused-when-only-the-second-is-compiled",
                chain.manifest_of(0),
                chain.statement(0),
                None,
                Some("UnknownKey"),
            )
        },
        // What is accepted.
        case("L18", "first-start-unsigned-original", chain.manifest("original"), Vec::new(), None, None),
        case("L19", "heads-signed-by-the-first-key", chain.manifest_of(0), chain.statement(0), None, None),
        case("L20", "full-after-heads", chain.manifest_of(1), chain.statement(1), Some(chain.seen(0)), None),
        case("L21", "signed-rollback-to-the-original", chain.manifest_of(2), chain.statement(2), Some(chain.seen(1)), None),
        case("L22", "version-signed-by-the-second-key", chain.manifest_of(3), chain.statement(3), Some(chain.seen(2)), None),
        case("L25", "the-statement-at-the-high-water-mark-again", chain.manifest_of(0), chain.statement(0), Some(chain.seen(0)), None),
    ];
    cases.sort_by_key(|case| case.id);
    cases
}

#[test]
fn every_row_of_the_lineage_table_ends_as_expected() {
    let chain = Chain { value: fixture() };
    let table = cases(&chain);
    let ids: Vec<&str> = table.iter().map(|case| case.id).collect();
    assert_eq!(ids.len(), 25);
    for case in &table {
        run(case);
    }
}

#[test]
fn the_signed_chain_is_admitted_in_order_with_the_mark_following_it() {
    let chain = Chain { value: fixture() };
    let keys = test_keys::key_set();
    let mut seen: Option<Statement> = None;
    for index in 0..4 {
        let client = Client { pin: chain.pin(), seen: seen.clone() };
        let admitted = v3::admit_lineage(&chain.manifest_of(index), &chain.statement(index), Some("latest"), &keys, &client).unwrap();
        let statement = admitted.statement.unwrap();
        assert!(seen.as_ref().is_none_or(|before| statement.sequence > before.sequence), "sequence {index}");
        seen = Some(statement);
    }
    assert_eq!(seen.unwrap().sequence, 4);
}

#[test]
fn a_statement_cannot_be_replayed_after_a_later_one_in_any_order() {
    let chain = Chain { value: fixture() };
    let keys = test_keys::key_set();
    for later in 0..4 {
        for earlier in 0..later {
            let client = Client { pin: chain.pin(), seen: Some(chain.seen(later)) };
            let error = v3::admit_lineage(&chain.manifest_of(earlier), &chain.statement(earlier), Some(MODEL), &keys, &client).unwrap_err();
            assert!(matches!(error, LineageError::Replay { .. }), "{earlier} after {later}: {error}");
        }
    }
}

#[test]
fn a_manifest_whose_scope_is_original_but_is_not_the_pin_is_refused() {
    // The toy ORIGINAL and another ORIGINAL-scope manifest: only the one that hashes to the tier pin is the pinned ORIGINAL.
    let chain = Chain { value: fixture() };
    let other = chain.manifest("other-original");
    let client = Client { pin: chain.pin(), seen: None };
    assert!(matches!(v3::admit_lineage(&other, &[], Some(MODEL), &test_keys::key_set(), &client), Err(LineageError::Unsigned)));
}
