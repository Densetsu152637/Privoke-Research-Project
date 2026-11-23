//! The V3 checkpoint store against its Python oracle (acceptance check 1 of stage V3-R1).
//!
//! `tests/fixtures/v3_checkpoint_store_golden.json` is written by `evaluation/generate_checkpoint_store_golden.py`: the unchanged
//! `services/pretrained-v3/src/checkpoint_store.py` ran a scripted sequence of bootstraps, stagings, commits and lookups on a
//! synthetic package (three stories: a BC01 lifecycle with one refusal per admission rule, an AU3 pilot and a two-tier catalog),
//! and every outcome, every refusal reason and the whole catalog after each step were recorded. Here the Rust store runs the same
//! operations over the same bytes, and everything observable must be identical:
//!
//! * the answer of each operation, or the refusal and its text;
//! * the blobs on disk, the `current` table and the `receipts` table (fingerprint and payload bytes) after each step.
//!
//! The golden holds no prompt text. The weights are a closed-form function of (salt, index) that this test reproduces, and every
//! reproduced file is checked against its recorded SHA-256; an evidence document is recorded without its `source` member, which
//! the test regenerates from the committed pinned inputs of `privoke-curriculum` and checks against the recorded SHA-256 too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine as _;
use privoke_contracts::canonical::{self, Variant};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::{Commit, Receipt};
use privoke_contracts::v3 as contract;
use privoke_curriculum::audience::{AudienceRelease, BUNDLED_MANIFEST_SHA256};
use privoke_curriculum::v3::{self as curriculum, AU3_SAMPLER, BC01_SAMPLER, Policy, Sources};
use privoke_curriculum::value;
use privoke_param_update::v3_store::{AudienceSource, CheckpointStore, PinnedSources, StoreError};
use serde_json::{Value as Json, json};

fn decode(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text).unwrap()
}

fn encode(raw: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(raw)
}

fn param_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn curriculum_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-curriculum/tests/fixtures")
}

fn bc01_paths() -> BTreeMap<&'static str, PathBuf> {
    let root = curriculum_fixtures();
    [
        ("taxonomy", "bc01/taxonomy-coverage-v1.json"),
        ("pool", "bc01/pool-authored.json"),
        ("manifest", "bc01/benign-manifest.json"),
        ("proof", "bc01/exclusion-proof.json"),
    ]
    .into_iter()
    .map(|(key, relative)| (key, root.join(relative)))
    .collect()
}

fn au3_manifest() -> PathBuf {
    curriculum_fixtures().join("au3/audience-v3-manifest-v1.json")
}

/// The weights of `evaluation/generate_checkpoint_store_golden.py::values(salt, count)` as little-endian float32 bytes.
fn weights(salt: u64, count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(count * 4);
    let offset = salt.wrapping_mul(0xD1B5_4A32_D192_ED03);
    for index in 0..count as u64 {
        let mut x = index.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(offset);
        x ^= x >> 29;
        x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x ^= x >> 32;
        let value = ((x & 0xFFFF) as f32) / 65536.0 - 0.5;
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

/// The safetensors file of a recipe, byte for byte as the generator writes it.
fn safetensors(layouts: &Json, recipe: &Json) -> Vec<u8> {
    let layout = layouts[recipe["layout"].as_str().unwrap()].as_array().unwrap();
    let default = recipe["default"].as_u64().unwrap();
    let nan = recipe["nan"].as_str();
    let (mut header, mut body, mut offset) = (Vec::new(), Vec::new(), 0usize);
    for entry in layout {
        let name = entry[0].as_str().unwrap();
        let shape: Vec<usize> = entry[1].as_array().unwrap().iter().map(|size| size.as_u64().unwrap() as usize).collect();
        let salt = recipe["overrides"][name].as_u64().unwrap_or(default);
        let mut raw = weights(salt, shape.iter().product());
        if nan == Some(name) {
            raw[..4].copy_from_slice(&0x7FC0_0000u32.to_le_bytes());
        }
        let dims: Vec<String> = shape.iter().map(ToString::to_string).collect();
        header.push(format!(
            "\"{name}\":{{\"dtype\":\"F32\",\"shape\":[{}],\"data_offsets\":[{offset},{}]}}",
            dims.join(","),
            offset + raw.len()
        ));
        offset += raw.len();
        body.extend_from_slice(&raw);
    }
    let mut encoded = format!("{{{}}}", header.join(",")).into_bytes();
    while encoded.len() % 8 != 0 {
        encoded.push(b' ');
    }
    let mut file = (encoded.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&encoded);
    file.extend_from_slice(&body);
    file
}

fn to_value(document: &Json) -> Value {
    value::parse_bytes(&serde_json::to_vec(document).unwrap()).unwrap()
}

fn set_path(document: &mut Value, path: &[Json], replacement: Value) {
    let (head, rest) = path.split_first().unwrap();
    let slot = match (document, head) {
        (Value::Object(map), Json::String(key)) => map.get_mut(key).unwrap(),
        (Value::Array(items), Json::Number(index)) => items.get_mut(index.as_u64().unwrap() as usize).unwrap(),
        (other, key) => panic!("no path {key} in {other:?}"),
    };
    if rest.is_empty() {
        *slot = replacement;
    } else {
        set_path(slot, rest, replacement);
    }
}

/// What the replay builds from the golden and keeps: the reproduced weights, the pinned inputs and the evidence documents.
struct World {
    golden: Json,
    blobs: RefCell<HashMap<String, Rc<Vec<u8>>>>,
    evidence: RefCell<HashMap<String, Rc<Vec<u8>>>>,
    sources: Sources,
    release: AudienceRelease,
}

impl World {
    fn load() -> Self {
        let path = param_fixtures().join("v3_checkpoint_store_golden.json");
        let golden: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let sources = curriculum::load_sources_from(&bc01_paths()).unwrap();
        let release = curriculum::trusted_release(Some(au3_manifest().as_path()), Some(BUNDLED_MANIFEST_SHA256)).unwrap();
        Self { golden, blobs: RefCell::default(), evidence: RefCell::default(), sources, release }
    }

    fn blob(&self, sha: &str) -> Rc<Vec<u8>> {
        if let Some(cached) = self.blobs.borrow().get(sha) {
            return cached.clone();
        }
        let bytes = safetensors(&self.golden["layouts"], &self.golden["blobs"][sha]);
        assert_eq!(sha256_hex(&bytes), sha, "the reproduced weights file {} are not the oracle's", self.golden["blobs"][sha]);
        let bytes = Rc::new(bytes);
        self.blobs.borrow_mut().insert(sha.to_string(), bytes.clone());
        bytes
    }

    fn document(&self, sha: &str) -> Vec<u8> {
        decode(self.golden["documents"][sha].as_str().unwrap())
    }

    /// The evidence document: the recorded skeleton and the source record regenerated from the pinned inputs.
    fn evidence(&self, key: &str) -> Rc<Vec<u8>> {
        if let Some(cached) = self.evidence.borrow().get(key) {
            return cached.clone();
        }
        let record = &self.golden["evidence"][key];
        let mut document = contract::parse(&decode(record["skeleton_b64"].as_str().unwrap()), 80 * 1024 * 1024).unwrap();
        let hashes = to_value(&record["source_hashes"]);
        let seed = record["seed"].as_u64().unwrap();
        let schedule = match record["sampler"].as_str().unwrap() {
            BC01_SAMPLER => curriculum::schedule_bc01(seed, Policy::PILOT, &self.sources, hashes).unwrap(),
            AU3_SAMPLER => curriculum::build_au3(seed, Policy::PILOT, &self.release, hashes).unwrap(),
            other => panic!("sampler {other}"),
        };
        let mut source = schedule.source;
        for edit in record["edits"].as_array().unwrap() {
            set_path(&mut source, edit[0].as_array().unwrap(), to_value(&edit[1]));
        }
        let Value::Object(map) = &mut document else { panic!("evidence is an object") };
        map.insert("source".to_string(), source);
        let bytes = canonical::to_bytes(&document, Variant::Utf8Lf).unwrap();
        assert_eq!(sha256_hex(&bytes), key, "the regenerated evidence document is not the oracle's");
        let bytes = Rc::new(bytes);
        self.evidence.borrow_mut().insert(key.to_string(), bytes.clone());
        bytes
    }

    fn asset(&self, description: &Json) -> Vec<u8> {
        match description["fixture"].as_str() {
            Some(name) => std::fs::read(param_fixtures().join("v3_store").join(name)).unwrap(),
            None => decode(description["b64"].as_str().unwrap()),
        }
    }
}

fn receipt_json(receipt: &Receipt) -> Json {
    json!({
        "status": receipt.status, "request_id": receipt.request_id, "model_id": receipt.model_id, "base": receipt.base,
        "candidate": receipt.candidate, "reason": receipt.reason
    })
}

/// The blobs, the `current` table and the `receipts` table of a store directory.
fn snapshot(directory: &Path) -> Json {
    let mut blobs: Vec<String> = std::fs::read_dir(directory.join("blobs"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .filter(|name| !name.starts_with("stage-"))
        .collect();
    blobs.sort();
    let connection = rusqlite::Connection::open(directory.join("catalog.sqlite")).unwrap();
    let mut statement = connection.prepare("SELECT model,manifest FROM current ORDER BY model").unwrap();
    let current: serde_json::Map<String, Json> = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, Json::String(row.get::<_, String>(1)?))))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut statement = connection.prepare("SELECT id,fingerprint,payload FROM receipts ORDER BY id").unwrap();
    let receipts: Vec<Json> = statement
        .query_map([], |row| Ok(json!([row.get::<_, String>(0)?, row.get::<_, String>(1)?, encode(&row.get::<_, Vec<u8>>(2)?)])))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    json!({"blobs": blobs, "current": current, "receipts": receipts})
}

/// Run one operation on the store and report its outcome in the golden's form.
fn perform(world: &World, store: &CheckpointStore, step: &Json, scratch: &Path) -> Result<Json, StoreError> {
    match step["op"].as_str().unwrap() {
        "bootstrap" => {
            let directory = scratch.join(format!("initial-{}", step["label"].as_str().unwrap().replace(' ', "-")));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("manifest.json"), world.document(step["manifest"].as_str().unwrap())).unwrap();
            std::fs::write(directory.join("model.safetensors"), world.blob(step["blob"].as_str().unwrap()).as_slice()).unwrap();
            std::fs::write(directory.join("config.json"), world.asset(&step["config"])).unwrap();
            std::fs::write(directory.join("vocab.txt"), world.asset(&step["vocab"])).unwrap();
            store.bootstrap(&directory).map(|()| Json::Null)
        }
        "resolve" => store.resolve(step["model"].as_str().unwrap()).map(Json::String),
        "status" => store.status(step["request_id"].as_str().unwrap()).map(|receipt| receipt_json(&receipt)),
        "stage" => {
            let payload = &step["payload"];
            let bytes: Vec<u8> = if let Some(sha) = payload["blob"].as_str() {
                world.blob(sha).as_slice().to_vec()
            } else if let Some(key) = payload["evidence"].as_str() {
                world.evidence(key).as_slice().to_vec()
            } else {
                decode(payload["b64"].as_str().unwrap())
            };
            let manifest: Vec<u8> = match &step["manifest"] {
                Json::Null => Vec::new(),
                description => match description["document"].as_str() {
                    Some(sha) => world.document(sha),
                    None => decode(description["b64"].as_str().unwrap()),
                },
            };
            store.stage(&bytes, &manifest).map(Json::String)
        }
        "commit" => {
            let request = &step["request"];
            let field = |name: &str| request[name].as_str().unwrap().to_string();
            let commit = Commit {
                request_id: field("request_id"),
                model_id: field("model_id"),
                expected_base: field("expected_base"),
                candidate: field("candidate"),
                evidence: field("evidence"),
            };
            store.commit(&commit).map(|receipt| receipt_json(&receipt))
        }
        other => panic!("operation {other}"),
    }
}

/// Counts of one replay, reported for the CI log.
#[derive(Debug, Default)]
struct Counts {
    stories: usize,
    steps: usize,
    answers: usize,
    refusals: usize,
    missing: usize,
    applied: usize,
    stale_base: usize,
    guard_rejected: usize,
    blobs: usize,
    receipts: usize,
}

#[test]
fn the_store_replays_the_python_oracle_identically() {
    let world = World::load();
    let mut counts = Counts::default();
    for story in world.golden["stories"].as_array().unwrap() {
        let name = story["name"].as_str().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let directory = scratch.path().join("store");
        let pinned =
            PinnedSources::new(bc01_paths(), AudienceSource::Trusted { path: au3_manifest(), sha256: BUNDLED_MANIFEST_SHA256.to_string() });
        let store = CheckpointStore::open(&directory, Arc::new(pinned)).unwrap();
        counts.stories += 1;
        for (index, step) in story["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}/{index} {} {}", step["op"].as_str().unwrap(), step["label"].as_str().unwrap_or_default());
            let actual = perform(&world, &store, step, scratch.path());
            let expected = &step["outcome"];
            counts.steps += 1;
            match (&actual, expected.get("ok"), expected.get("error")) {
                (Ok(answer), Some(ok), None) => {
                    assert_eq!(answer, ok, "{label}: the answer");
                    counts.answers += 1;
                    if step["op"] == "commit" {
                        match answer["status"].as_str().unwrap() {
                            "applied" => counts.applied += 1,
                            _ if answer["reason"] == "stale_base" => counts.stale_base += 1,
                            _ => counts.guard_rejected += 1,
                        }
                    }
                }
                (Err(error), None, Some(refusal)) => {
                    counts.refusals += 1;
                    match (refusal["class"].as_str().unwrap(), refusal["message"].as_str()) {
                        ("ValueError", Some(message)) => {
                            assert_eq!(error, &StoreError::Invalid(message.to_string()), "{label}: the reason")
                        }
                        ("FileNotFoundError", _) => {
                            assert!(matches!(error, StoreError::Missing(_)), "{label}: a missing blob, got {error:?}");
                            counts.missing += 1;
                        }
                        (class, _) => assert!(matches!(error, StoreError::Invalid(_)), "{label}: a refusal like {class}, got {error:?}"),
                    }
                }
                _ => panic!("{label}: the oracle answered {expected} and the store {actual:?}"),
            }
            let after = snapshot(&directory);
            assert_eq!(after, step["after"], "{label}: the catalog after the step");
            counts.blobs += after["blobs"].as_array().unwrap().len();
            counts.receipts += after["receipts"].as_array().unwrap().len();
        }
    }
    eprintln!(
        "v3 checkpoint store replay ({}): {} stories, {} steps ({} answers, {} refusals of which {} missing blobs), commits {} applied, {} stale_base, {} guard_rejected; {} blob listings and {} receipt rows identical to the Python oracle",
        world.golden["oracle"].as_str().unwrap(),
        counts.stories,
        counts.steps,
        counts.answers,
        counts.refusals,
        counts.missing,
        counts.applied,
        counts.stale_base,
        counts.guard_rejected,
        counts.blobs,
        counts.receipts,
    );
    // The golden covers the whole contract.
    assert_eq!((counts.stories, counts.steps), (3, 98));
    assert_eq!((counts.applied, counts.stale_base, counts.guard_rejected), (6, 3, 2));
}
