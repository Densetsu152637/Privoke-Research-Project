//! The routine root (stage V3-R5): a tier's `current` can be seeded with the pinned standard release instead of the ORIGINAL.
//!
//! The fixtures are synthetic but contract-valid: manifests with the real efficient-tier constants and a two-tensor inventory
//! (`encoder.w` and `heads.w`, 4,785,044 parameters in all), the public official config and vocabulary, and tiny weight changes so
//! that every distance is known. The pin is named with `CheckpointStore::with_pins` because the real pinned manifests are not in the
//! repository.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::Commit;
use privoke_contracts::v3::{self as contract, TIERS, VOCAB_SHA256, action_value, harm_count};
use privoke_curriculum::v3::Policy;
use privoke_curriculum::value;
use privoke_param_update::v3_policy::{DRIFT_EXCEEDED, DriftBounds, DriftGate};
use privoke_param_update::v3_store::{Candidate, CheckpointStore, CommitObserver, SourceEvidence, StoreError};
use serde_json::{Value as Json, json};

const MODEL: &str = "privoke-v3-efficient";
const HEADS: usize = 20 * (128 + 1);

#[derive(Debug)]
struct AcceptSources;

impl SourceEvidence for AcceptSources {
    fn validate(&self, _evidence: &Value) -> Result<(), StoreError> {
        Ok(())
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v3_store")
}

/// Tensors of one version: `encoder.w` stays zero, `heads.w` carries the leading values given.
struct Weights {
    heads: Vec<f32>,
}

impl Weights {
    fn new(leading: &[f32]) -> Self {
        let mut heads = vec![0.0f32; HEADS];
        heads[..leading.len()].copy_from_slice(leading);
        Self { heads }
    }

    fn parts(&self) -> Vec<(&'static str, Vec<u8>, usize)> {
        let encoder = vec![0u8; (TIERS[0].parameters as usize - HEADS) * 4];
        let heads: Vec<u8> = self.heads.iter().flat_map(|value| value.to_le_bytes()).collect();
        vec![("encoder.w", encoder, TIERS[0].parameters as usize - HEADS), ("heads.w", heads, HEADS)]
    }

    fn safetensors(&self) -> Vec<u8> {
        let parts = self.parts();
        let mut header = serde_json::Map::new();
        let mut offset = 0usize;
        for (name, bytes, count) in &parts {
            header.insert((*name).to_string(), json!({"dtype": "F32", "shape": [count], "data_offsets": [offset, offset + bytes.len()]}));
            offset += bytes.len();
        }
        let header = serde_json::to_vec(&Json::Object(header)).unwrap();
        let mut file = (header.len() as u64).to_le_bytes().to_vec();
        file.extend_from_slice(&header);
        for (_, bytes, _) in &parts {
            file.extend_from_slice(bytes);
        }
        file
    }

    fn inventory(&self) -> Value {
        let tensors = self
            .parts()
            .into_iter()
            .map(|(name, bytes, count)| {
                (
                    name,
                    value::object(vec![
                        ("dtype", value::string("F32")),
                        ("shape", Value::Array(vec![value::uint(count as u64)])),
                        ("sha256", value::string(&sha256_hex(&bytes))),
                    ]),
                )
            })
            .collect::<Vec<_>>();
        value::object(tensors)
    }
}

/// A manifest of the efficient tier. `parent`, `original` and `evidence` are empty for an ORIGINAL.
fn manifest(weights: &Weights, scope: &str, parent: &str, original: &str, evidence: &str) -> Vec<u8> {
    let tier = &TIERS[0];
    let document = value::object(vec![
        ("schema", value::int(1)),
        ("architecture", value::string(contract::ARCHITECTURE)),
        ("model_id", value::string(MODEL)),
        ("tier", value::string(tier.name)),
        ("parent", value::string(parent)),
        ("original", value::string(original)),
        ("blob", value::string(&sha256_hex(&weights.safetensors()))),
        ("config", value::string(tier.config_sha256)),
        ("vocab", value::string(VOCAB_SHA256)),
        ("evidence", value::string(evidence)),
        (
            "source",
            value::object(vec![
                ("repository", value::string(tier.repository)),
                ("revision", value::string(tier.revision)),
                ("weights_sha256", value::string(tier.weights_sha256)),
                ("config_sha256", value::string(tier.config_sha256)),
                ("vocab_sha256", value::string(VOCAB_SHA256)),
            ]),
        ),
        ("tensors", weights.inventory()),
        ("parameter_count", value::uint(tier.parameters)),
        ("scope", value::string(scope)),
    ]);
    value::canonical_bytes(&document).unwrap()
}

/// A package directory: `manifest.json`, the weights, the config and the vocabulary.
fn package(directory: &Path, weights: &Weights, manifest: &[u8]) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(directory.join("manifest.json"), manifest).unwrap();
    std::fs::write(directory.join("model.safetensors"), weights.safetensors()).unwrap();
    std::fs::copy(fixtures().join("config-efficient.json"), directory.join("config.json")).unwrap();
    std::fs::copy(fixtures().join("vocab.txt"), directory.join("vocab.txt")).unwrap();
}

struct Fixture {
    scratch: tempfile::TempDir,
    original_sha: String,
    pin_sha: String,
    original: PathBuf,
    release: PathBuf,
}

/// The toy ORIGINAL (zero heads), and a toy pinned release (scope `full_encoder`, `original` the ORIGINAL, a parent) whose heads
/// are `release_heads`.
fn fixture(release_heads: &[f32]) -> Fixture {
    let scratch = tempfile::tempdir().unwrap();
    let original_weights = Weights::new(&[]);
    let original_manifest = manifest(&original_weights, "original", "", "", "");
    let original_sha = sha256_hex(&original_manifest);
    let release_weights = Weights::new(release_heads);
    let release_manifest = manifest(
        &release_weights,
        "full_encoder",
        &sha256_hex(b"the heads release that the pin descends from"),
        &original_sha,
        &sha256_hex(b"the evidence of the release"),
    );
    let pin_sha = sha256_hex(&release_manifest);
    let (original, release) = (scratch.path().join("original"), scratch.path().join("release"));
    package(&original, &original_weights, &original_manifest);
    package(&release, &release_weights, &release_manifest);
    Fixture { scratch, original_sha, pin_sha, original, release }
}

fn store_in(directory: &Path, pin: &str) -> CheckpointStore {
    CheckpointStore::open(directory.join("store"), Arc::new(AcceptSources))
        .unwrap()
        .with_pins([(MODEL.to_string(), pin.to_string())].into_iter().collect())
}

fn refusal(error: StoreError) -> String {
    match error {
        StoreError::Invalid(message) => message,
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_pinned_release_is_bootstrapped_current_and_servable_beside_its_original() {
    let fixture = fixture(&[3.0]);
    let store = store_in(fixture.scratch.path(), &fixture.pin_sha);
    store.bootstrap_pinned(&fixture.original, &fixture.release).unwrap();
    assert_eq!(store.resolve(MODEL).unwrap(), fixture.pin_sha, "routine training starts from the pin");
    let mut history = store.history(MODEL).unwrap();
    history.sort();
    let mut expected = vec![fixture.original_sha.clone(), fixture.pin_sha.clone()];
    expected.sort();
    assert_eq!(history, expected, "both are in the model's history");
    assert_eq!(store.pin(MODEL).as_deref(), Some(fixture.pin_sha.as_str()));
    // A second bootstrap changes nothing.
    store.bootstrap_pinned(&fixture.original, &fixture.release).unwrap();
    assert_eq!(store.resolve(MODEL).unwrap(), fixture.pin_sha);
}

#[test]
fn a_release_that_is_not_the_pin_does_not_descend_from_the_original_or_is_an_original_is_refused() {
    let fixture = fixture(&[3.0]);
    // Its bytes do not hash to the pin.
    let wrong_pin = store_in(fixture.scratch.path(), &sha256_hex(b"another pin"));
    assert_eq!(
        refusal(wrong_pin.bootstrap_pinned(&fixture.original, &fixture.release).unwrap_err()),
        "Release is not the pinned standard release of the model."
    );
    assert!(wrong_pin.resolve(MODEL).is_err(), "nothing became current");

    // Its `original` is not the supplied ORIGINAL.
    let other = tempfile::tempdir().unwrap();
    let weights = Weights::new(&[3.0]);
    let stranger = manifest(&weights, "full_encoder", &sha256_hex(b"parent"), &sha256_hex(b"another original"), &sha256_hex(b"evidence"));
    let release = other.path().join("release");
    package(&release, &weights, &stranger);
    let store = store_in(other.path(), &sha256_hex(&stranger));
    assert_eq!(
        refusal(store.bootstrap_pinned(&fixture.original, &release).unwrap_err()),
        "Pinned release does not descend from the supplied ORIGINAL."
    );

    // An ORIGINAL-scope release.
    let original_manifest = std::fs::read(fixture.original.join("manifest.json")).unwrap();
    let store = store_in(other.path(), &sha256_hex(&original_manifest));
    assert_eq!(
        refusal(store.bootstrap_pinned(&fixture.original, &fixture.original).unwrap_err()),
        "Pinned release must be the full-encoder release of the model."
    );
}

/// The evidence of a HEADS candidate over `base`: the guard is better and no action is harmed.
fn evidence(request_id: &str, base: &str, blob: &str, changes: &(Vec<String>, Json)) -> Json {
    let tier = &TIERS[0];
    let policy: Json = serde_json::from_slice(&value::canonical_bytes(&Policy::PILOT.to_value()).unwrap()).unwrap();
    let row = |prediction: u64, target: u64| {
        let action = |packed: u64, confidence: f64| action_value(u16::try_from(packed).unwrap(), Some(confidence));
        let (a, t) = (action(prediction, 0.999), action(target, 0.999));
        let names = ["ALLOW", "WARN", "BLOCK"];
        json!({
            "target": target, "prediction": prediction, "confidence": 0.999,
            "action": names[usize::try_from(a).unwrap()], "action_value": a,
            "target_action": names[usize::try_from(t).unwrap()], "target_action_value": t,
            "joint_correct": prediction == target && a == t
        })
    };
    let summary = |rows: Vec<Json>| {
        let joint = rows.iter().filter(|row| row["joint_correct"] == true).count();
        let action = rows.iter().filter(|row| row["action"] == row["target_action"]).count();
        json!({"examples": rows.len(), "rows": rows, "joint_correct": joint, "action_correct": action})
    };
    let (before, after): (Vec<Json>, Vec<Json>) = (0..16).map(|index| (row(if index < 8 { 13 } else { 12 }, 13), row(13, 13))).unzip();
    let harms = harm_count(&Json::Array(before.clone()), &Json::Array(after.clone()));
    let (steps, rows, micro) =
        (policy["steps"].as_u64().unwrap(), policy["batch_rows"].as_u64().unwrap(), policy["microbatch"].as_u64().unwrap());
    let microbatches = steps * rows / micro;
    let layers = tier.num_hidden_layers;
    json!({
        "schema": 1, "model_id": MODEL, "tier": tier.name, "request_id": request_id, "base": base, "scope": "heads", "layers": [4],
        "source_commitment": sha256_hex(b"source"), "policy": policy,
        "train_wire_sha256": sha256_hex(b"train"), "guard_wire_sha256": sha256_hex(b"guard"),
        "phases": {
            "training": {"layer": 4, "status": "ok", "examples": steps * rows},
            "base_heldout": {"layer": 4, "status": "ok", "examples": 16},
            "candidate_heldout": {"layer": 4, "status": "ok", "examples": 16}
        },
        "base_guard": summary(before), "candidate_guard": summary(after), "action_harms": harms,
        "changes": changes.1, "changed_tensors": changes.0,
        "counts": {
            "optimizer_steps": steps, "train_rows": steps * rows, "microbatch_forward": microbatches, "microbatch_backward": microbatches,
            "encoder_block_forward": microbatches * layers, "encoder_block_backward": 0
        },
        "block_counts": {"forward": vec![microbatches; layers as usize], "backward": vec![0; layers as usize]},
        "losses": (0..steps).map(|step| 1.0 / (step as f64 + 1.0)).collect::<Vec<_>>(),
        "gradient_trace": (0..steps).map(|step| json!({"step": step + 1, "norm_before_clip": 1.0, "encoder_nonzero_gradients": 0})).collect::<Vec<_>>(),
        "parameter_count": tier.parameters, "trainable_count": 20 * (tier.hidden_size + 1),
        "device": "cpu", "torch": "test", "seconds": 0.0, "cuda_peak_bytes": 0,
        "candidate_blob": blob, "serialized_guard_parity": true, "capabilities": {}, "source": {}
    })
}

fn canonical_json(document: &Json) -> Vec<u8> {
    value::canonical_bytes(&value::parse_bytes(document.to_string().as_bytes()).unwrap()).unwrap()
}

fn digests(manifest: &Value) -> BTreeMap<String, String> {
    let Value::Object(map) = manifest else { panic!("object") };
    let Some(Value::Object(tensors)) = map.get("tensors") else { panic!("tensors") };
    tensors
        .iter()
        .map(|(name, tensor)| match tensor {
            Value::Object(fields) => match fields.get("sha256") {
                Some(Value::String(sha)) => (name.clone(), sha.clone()),
                _ => panic!("sha"),
            },
            _ => panic!("tensor"),
        })
        .collect()
}

#[test]
fn a_candidate_whose_parent_is_the_pin_is_admitted_and_commits() {
    let fixture = fixture(&[3.0]);
    let store = store_in(fixture.scratch.path(), &fixture.pin_sha);
    store.bootstrap_pinned(&fixture.original, &fixture.release).unwrap();

    let weights = Weights::new(&[3.0, 4.0]);
    let pin_manifest = contract::parse(&store.read(&fixture.pin_sha).unwrap(), contract::MAX_MANIFEST_BYTES).unwrap();
    let candidate_blob = sha256_hex(&weights.safetensors());
    let layers = TIERS[0].num_hidden_layers as usize;
    let probe = contract::parse(&manifest(&weights, "heads", "", "", ""), contract::MAX_MANIFEST_BYTES).unwrap();
    let changes = contract::tensor_changes(&digests(&pin_manifest), &digests(&probe), layers);
    assert_eq!(changes.0, vec!["heads.w".to_string()]);
    let evidence_document = canonical_json(&evidence("routine-1", &fixture.pin_sha, &candidate_blob, &changes));
    let evidence_sha = store.stage(&evidence_document, b"").unwrap();
    let candidate = manifest(&weights, "heads", &fixture.pin_sha, &fixture.original_sha, &evidence_sha);
    let staged = store.stage(&weights.safetensors(), &candidate).unwrap();

    let receipt = store
        .commit(&Commit {
            request_id: "routine-1".to_string(),
            model_id: MODEL.to_string(),
            expected_base: fixture.pin_sha.clone(),
            candidate: staged.clone(),
            evidence: evidence_sha,
        })
        .unwrap();
    assert_eq!((receipt.status.as_str(), receipt.reason.as_str()), ("applied", ""), "{receipt:?}");
    assert_eq!(store.resolve(MODEL).unwrap(), staged);
    assert!(store.history(MODEL).unwrap().contains(&staged));

    // A candidate whose `original` is the pin (not the ORIGINAL the pin descends from) is not the lineage.
    let wrong = manifest(&weights, "heads", &fixture.pin_sha, &fixture.pin_sha, &sha256_hex(b"x"));
    assert!(store.stage(&weights.safetensors(), &wrong).is_err());
}

fn bounds(update: f64, cumulative: f64) -> DriftBounds {
    let mut text = format!("schema = 1\nstatus = \"calibrated\"\nevidence_sha256 = \"{}\"\n", sha256_hex(b"record"));
    for tier in ["efficient", "balanced", "quality"] {
        for scope in ["heads", "full_encoder"] {
            text.push_str(&format!("[{tier}.{scope}]\nmax_update_l2 = {update}\nmax_cumulative_l2 = {cumulative}\n"));
        }
    }
    DriftBounds::parse(&text).unwrap()
}

/// The drift gate's verdict on a stored candidate (a HEADS manifest with the given parent).
fn verdict(store: &CheckpointStore, gate: &DriftGate, weights: &Weights, parent: &str, original: &str) -> Option<String> {
    store.put(&weights.safetensors()).unwrap();
    let bytes = manifest(weights, "heads", parent, original, &sha256_hex(b"e"));
    let sha = store.put(&bytes).unwrap();
    let document = contract::parse(&bytes, contract::MAX_MANIFEST_BYTES).unwrap();
    let evidence = json!({});
    gate.prepare(&Candidate {
        store,
        model_id: MODEL,
        manifest_sha: &sha,
        request_id: "r",
        expected_base: parent,
        manifest: &document,
        evidence: Some(&evidence),
    })
    .unwrap()
}

#[test]
fn the_cumulative_drift_is_measured_from_the_pinned_release_when_the_lineage_has_one() {
    // The ORIGINAL is zero, the pin is (3), so the pin is 3 from the ORIGINAL.
    let fixture = fixture(&[3.0]);
    let store = store_in(fixture.scratch.path(), &fixture.pin_sha);
    store.bootstrap_pinned(&fixture.original, &fixture.release).unwrap();

    // (3, 4): 4 from the pin, 5 from the ORIGINAL. A cap of 4.5 passes only if the root is the pin.
    let outward = Weights::new(&[3.0, 4.0]);
    let gate = DriftGate::new(bounds(10.0, 4.5));
    assert_eq!(verdict(&store, &gate, &outward, &fixture.pin_sha, &fixture.original_sha), None);
    assert_eq!(
        verdict(&store, &DriftGate::new(bounds(10.0, 3.9)), &outward, &fixture.pin_sha, &fixture.original_sha).as_deref(),
        Some(DRIFT_EXCEEDED)
    );

    // (-3): 6 from the pin, 3 from the ORIGINAL. A cap of 4.5 refuses only if the root is the pin.
    let back = Weights::new(&[-3.0]);
    assert_eq!(verdict(&store, &gate, &back, &fixture.pin_sha, &fixture.original_sha).as_deref(), Some(DRIFT_EXCEEDED));
}

#[test]
fn a_lineage_without_a_pin_is_measured_from_its_original() {
    let fixture = fixture(&[3.0]);
    // The model's pin is some other manifest, so the chain never reaches one: the ORIGINAL is the root.
    let store = store_in(fixture.scratch.path(), &sha256_hex(b"a pin this lineage never passes through"));
    store.bootstrap(&fixture.original).unwrap();
    let outward = Weights::new(&[3.0, 4.0]);
    // 5 from the ORIGINAL: refused by a cap of 4.5, passed by a cap of 5.5.
    assert_eq!(
        verdict(&store, &DriftGate::new(bounds(10.0, 4.5)), &outward, &fixture.original_sha, &fixture.original_sha).as_deref(),
        Some(DRIFT_EXCEEDED)
    );
    assert_eq!(verdict(&store, &DriftGate::new(bounds(10.0, 5.5)), &outward, &fixture.original_sha, &fixture.original_sha), None);
}
