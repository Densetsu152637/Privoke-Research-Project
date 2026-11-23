//! The V3 retention (stage V3-R9) on the stage 22 toy V3 package: the reference release is built from a teacher, reloaded under
//! its pins and refused when anything differs; the rule judges candidates (a regressing one is refused, a non-regressing one
//! passes); the single-forward prediction equals `V3Model::predict`. The real standard releases and the approved bank are
//! `retention_v3_release.rs` (environment gated, run in Docker).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use privoke_contracts::digest::sha256_hex;
use privoke_semantic::V3Model;
use privoke_semantic::safetensors;
use privoke_training::reference::BankSpec;
use privoke_training::retention_common::EPSILON;
use privoke_training::retention_v3::{Prediction, ReleaseSpec, RetentionRelease, RowReport, build_release, predict, prediction_of};
use serde_json::{Value, json};

const MODEL: &str = "privoke-v3-efficient";
const TEACHER_PIN: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

const GROUPS: usize = 6;
const PER_GROUP: usize = 4;

fn package() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../privoke-semantic/tests/fixtures/v3_synthetic")
}

fn teacher() -> V3Model {
    let dir = package();
    V3Model::from_files(&dir.join("config.json"), &dir.join("model.safetensors"), &dir.join("vocab.txt")).unwrap()
}

/// A deterministic pool of short texts over the toy vocabulary.
fn pool() -> Vec<String> {
    let words = ["account", "afraid", "age", "alone", "an", "and", "are", "arrested", "article", "at", "avenue", "bank", "be", "brother"];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..600)
        .map(|_| {
            let mut text = Vec::new();
            for _ in 0..4 {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                text.push(words[((state >> 33) as usize) % words.len()]);
            }
            text.join(" ")
        })
        .collect()
}

/// A bank of `GROUPS * PER_GROUP` rows that the teacher predicts with a severity and a positive margin and gap, so that every group
/// has eligible rows. The gold of every row is S2 with the P0 visibility.
fn bank(teacher: &V3Model) -> Vec<u8> {
    let mut rows: Vec<Value> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for text in pool() {
        if !seen.insert(text.clone()) {
            continue;
        }
        let logits = teacher.logits(&text).unwrap();
        let (prediction, gap) = prediction_of(&logits).unwrap();
        if prediction.packed & 0b11 == 0 || prediction.margin <= EPSILON || gap <= EPSILON {
            continue;
        }
        let index = rows.len();
        rows.push(json!({
            "id": format!("row-{index:02}"), "text": text, "packed_classification": 6,
            "metadata": {"taxonomy_partition": "train", "split": "train", "group_id": format!("g{}", index % GROUPS)}
        }));
        if rows.len() == GROUPS * PER_GROUP {
            break;
        }
    }
    assert_eq!(rows.len(), GROUPS * PER_GROUP, "the toy teacher found too few sensitive rows");
    serde_json::to_vec(&rows).unwrap()
}

fn identity() -> Value {
    json!({
        "model_id": MODEL, "tier": "efficient", "scope": "full_encoder", "manifest_sha256": TEACHER_PIN,
        "original_sha256": "b".repeat(64), "blob_sha256": "c".repeat(64), "config_sha256": "d".repeat(64), "vocab_sha256": "e".repeat(64)
    })
}

struct Built {
    bank: Vec<u8>,
    bank_sha: String,
    references: String,
    manifest: String,
    manifest_sha: String,
}

fn built(max_violations: usize) -> Built {
    let teacher = teacher();
    let bank = bank(&teacher);
    let bank_sha = sha256_hex(&bank);
    let spec = BankSpec { sha256: &bank_sha, rows: GROUPS * PER_GROUP, groups: GROUPS };
    let release = build_release(&bank, &spec, &teacher, &identity(), &|_| max_violations, &mut |_| {}).unwrap();
    let manifest_sha = release.manifest_sha256();
    Built { bank, bank_sha, references: release.references, manifest: release.manifest, manifest_sha }
}

impl Built {
    fn spec(&self) -> ReleaseSpec<'_> {
        ReleaseSpec {
            model_id: MODEL,
            teacher_manifest_sha256: TEACHER_PIN,
            manifest_sha256: &self.manifest_sha,
            bank: BankSpec { sha256: &self.bank_sha, rows: GROUPS * PER_GROUP, groups: GROUPS },
        }
    }

    fn load(&self) -> RetentionRelease {
        RetentionRelease::load(&self.bank, self.references.as_bytes(), self.manifest.as_bytes(), &self.spec()).unwrap()
    }
}

#[test]
fn the_single_forward_prediction_is_the_models_own() {
    let model = teacher();
    for text in pool().iter().take(60) {
        let expected = model.predict(text).unwrap();
        let ours = predict(&model, text).unwrap();
        assert_eq!(ours.packed, expected.classification.pack(), "{text}");
        assert_eq!(ours.confidence, expected.confidence, "{text}");
        assert!(ours.margin.is_finite());
    }
}

#[test]
fn a_release_is_reproducible_and_reloads_under_its_pins() {
    let first = built(0);
    let second = built(0);
    assert_eq!(
        (&first.references, &first.manifest),
        (&second.references, &second.manifest),
        "the same teacher and bank build the same bytes"
    );
    let release = first.load();
    assert_eq!(release.model_id, MODEL);
    assert_eq!(release.sha256, first.manifest_sha);
    assert!(release.references.len() >= GROUPS, "every group has an eligible row");
    assert!(release.references.iter().all(|reference| reference.margin > EPSILON && reference.original & 0b11 != 0));
    assert_eq!(first.manifest.matches('\n').count(), 1, "canonical: one trailing LF");
    assert!(first.references.starts_with("{\"bank_sha256\":\""), "sorted keys");
}

#[test]
fn a_release_that_differs_from_its_pins_is_refused() {
    let good = built(0);
    let load = |bank: &[u8], references: &str, manifest: &str, spec: &ReleaseSpec<'_>| {
        RetentionRelease::load(bank, references.as_bytes(), manifest.as_bytes(), spec).map(|_| ()).unwrap_err().to_string()
    };
    // The manifest must be the pinned one.
    let other_pin = ReleaseSpec { manifest_sha256: &"0".repeat(64), ..good.spec() };
    assert_eq!(load(&good.bank, &good.references, &good.manifest, &other_pin), "Retention release manifest differs from its pin.");
    // The bank must be the approved one.
    let mut bank: Vec<Value> = serde_json::from_slice(&good.bank).unwrap();
    bank[0]["text"] = Value::String("another prompt".to_string());
    let other_bank = serde_json::to_vec(&bank).unwrap();
    assert_eq!(
        load(&other_bank, &good.references, &good.manifest, &good.spec()),
        "Retention bank differs from the independently approved200 TRAIN rows."
    );
    // A teacher that is not the pinned standard release of the model.
    let other_teacher = ReleaseSpec { teacher_manifest_sha256: &"f".repeat(64), ..good.spec() };
    assert_eq!(
        load(&good.bank, &good.references, &good.manifest, &other_teacher),
        "Retention teacher is not the pinned standard release of this model."
    );
    let other_model = ReleaseSpec { model_id: "privoke-v3-quality", ..good.spec() };
    assert_eq!(
        load(&good.bank, &good.references, &good.manifest, &other_model),
        "Retention teacher is not the pinned standard release of this model."
    );
    // A references file that is not the one the manifest names (its digest is part of the manifest).
    let mut references: Value = serde_json::from_str(&good.references).unwrap();
    let first = references["rows"].as_array().unwrap().iter().position(|row| row["eligible"] == true).unwrap();
    references["rows"][first]["margin"] = json!(123.5);
    let tampered = references.to_string();
    let mismatch = load(&good.bank, &tampered, &good.manifest, &good.spec());
    assert_eq!(mismatch, "Retention manifest/reference/bank/teacher snapshot differs.");
    // An eligibility flag that is not what the strict policy gives from the row's own numbers.
    let mut references: Value = serde_json::from_str(&good.references).unwrap();
    references["rows"][first]["eligible"] = json!(false);
    assert_eq!(
        load(&good.bank, &references.to_string(), &good.manifest, &good.spec()),
        "Retention eligibility mask differs from the fixed strict policy."
    );
    // A manifest whose rule was loosened is not the pinned manifest.
    let loosened = good.manifest.replace("\"max_violations\":0", "\"max_violations\":99");
    assert_ne!(loosened, good.manifest);
    assert_eq!(load(&good.bank, &good.references, &loosened, &good.spec()), "Retention release manifest differs from its pin.");
}

/// A predictor that answers what each reference's teacher said.
fn echo(release: &RetentionRelease) -> impl FnMut(&str) -> Result<Prediction, privoke_training::TrainingError> + '_ {
    move |text| {
        let reference = release.references.iter().find(|reference| reference.text == text).unwrap();
        Ok(Prediction { packed: reference.original, confidence: reference.confidence, margin: reference.margin })
    }
}

fn violations(rows: &[RowReport]) -> Vec<&str> {
    rows.iter().filter(|row| row.violation).map(|row| row.id.as_str()).collect()
}

#[test]
fn the_rule_refuses_a_candidate_that_lost_what_the_teacher_kept_and_passes_one_that_did_not() {
    let release = built(0).load();
    let total = release.references.len();
    // The teacher itself retains everything.
    let report = release.assess_with(echo(&release)).unwrap();
    assert_eq!((report.violations, report.rows.len(), report.passes()), (0, total, true));

    // A candidate that predicts nothing sensitive on every eligible row regresses on all of them.
    let silent = release.assess_with(|_| Ok(Prediction { packed: 0, confidence: 0.9, margin: -3.0 })).unwrap();
    assert_eq!((silent.violations, silent.passes()), (total, false));

    // One row that lost its severity is one violation: refused at zero tolerance, passed at one.
    let victim = release.references[0].clone();
    let lose_one = |text: &str| {
        let reference = release.references.iter().find(|reference| reference.text == text).unwrap();
        let packed = if reference.id == victim.id { reference.original & !0b11 | 0b0010_0000 } else { reference.original };
        Ok(Prediction { packed, confidence: reference.confidence, margin: reference.margin })
    };
    let one = release.assess_with(lose_one).unwrap();
    assert_eq!((violations(&one.rows), one.passes()), (vec![victim.id.as_str()], false));
    let lenient = built(1).load();
    let tolerated = lenient.assess_with(|text| {
        let reference = lenient.references.iter().find(|reference| reference.text == text).unwrap();
        let packed = if reference.id == victim.id { reference.original & !0b11 | 0b0010_0000 } else { reference.original };
        Ok(Prediction { packed, confidence: reference.confidence, margin: reference.margin })
    });
    assert!(tolerated.unwrap().passes(), "a release that allows one regressed row passes a candidate with one");

    // A candidate that became more protective than the teacher (and the gold) is not penalised.
    let stricter = release
        .assess_with(|text| {
            let reference = release.references.iter().find(|reference| reference.text == text).unwrap();
            Ok(Prediction { packed: reference.original | 0b11, confidence: 0.999, margin: reference.margin + 5.0 })
        })
        .unwrap();
    assert!(stricter.passes() && stricter.violations == 0, "the target caps the comparison: more protection is retention");
}

/// A candidate checkpoint of the toy package: its tensors with the bias of the S0 logit pushed far up, so that every text reads
/// as clean (what a fit that forgot the sensitive class would do).
fn forgetful(teacher: &V3Model) -> V3Model {
    let dir = package();
    let mut tensors = safetensors::parse(&std::fs::read(dir.join("model.safetensors")).unwrap()).unwrap();
    tensors.get_mut("heads.sensitivity_bias").unwrap().data[0] += 1_000.0;
    teacher.with_tensors(tensors).unwrap()
}

#[test]
fn a_candidate_loaded_through_with_tensors_is_judged_on_its_own_weights() {
    let model = teacher();
    let release = built(0).load();
    // Loaded over itself with its own tensors, the teacher retains.
    let dir = package();
    let same = model.with_tensors(safetensors::parse(&std::fs::read(dir.join("model.safetensors")).unwrap()).unwrap()).unwrap();
    let kept = release.assess(&same).unwrap();
    assert!(kept.passes() && kept.violations == 0, "{:?}", violations(&kept.rows));
    // The toy fit candidates of stage 22 are other weights: whatever they do, the verdict follows the rule applied to them.
    let regressed = release.assess(&forgetful(&model)).unwrap();
    assert!(!regressed.passes(), "a candidate that reads everything as S0 regressed");
    assert_eq!(regressed.violations, release.references.len(), "every eligible row has a severity the candidate lost");
}

#[test]
fn the_production_allowance_is_five_percent_rounded_down() {
    use privoke_training::retention_v3::production_allowance;
    assert_eq!((production_allowance(155), production_allowance(197), production_allowance(19), production_allowance(0)), (7, 9, 0, 0));
}
