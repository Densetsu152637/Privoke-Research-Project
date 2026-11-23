//! The V3 fuzzer's recorded fits against the Rust checkpoint store (acceptance check 2 of stage V3-R1).
//!
//! `tests/replay.rs` replays the retained real fits (the audience pilots, the pretrained pilots and the 18 pretrained cells)
//! against scripted answers. Here the checkpoint service is the real param-update store instead: each fit's retained checkpoint
//! directory seeds a store (the ORIGINAL admitted through `bootstrap`, the staged candidate, its weights and its evidence copied
//! as the runtime staged them), and the fuzzer's `ResolveCurrent`, `FetchBlob` and `CommitCandidate` calls reach `admit_candidate`
//! and the compare-and-swap. Everything the replay compares (the response, every wire message, every work-directory file and the
//! `cycles` rows) must still equal the Python oracle's, and the store must end where the recorded service ended: the candidate
//! current, and the recorded receipt answered byte for byte.
//!
//! Local only: the fits hold prompt text and 17 to 70 MB checkpoints. The test runs when both
//! `PRIVOKE_V3_FUZZER_RECORDED_GOLDEN` (the golden `evaluation/generate_v3_fuzzer_golden.py recorded` writes) and
//! `PRIVOKE_V3_RECORDED_MODELS` (the `models/experiments` directory of the checkout that holds the retained fits) are set, and is
//! skipped otherwise.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{COMMIT, COMMIT_STATUS, Counts, FETCH, Inputs, RESOLVE, Scripted, b64, read_json, replay_sequence_with};
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::v1::FuzzerTrainingRequest;
use privoke_contracts::v3 as contract;
use privoke_curriculum::audience::BUNDLED_MANIFEST_SHA256;
use privoke_param_update::v3_store::service::status_of;
use privoke_param_update::v3_store::{AudienceSource, CheckpointStore, PinnedSources};
use privoke_v3_fuzzer::backend::{CheckpointBackend, blob_chunks};
use prost::Message;
use tonic::Status;

/// The checkpoint service of the fuzzer, answered by the store; the scripted services log every wire message it sends.
struct StoreBackend {
    scripted: Arc<Scripted>,
    store: Arc<CheckpointStore>,
}

#[tonic::async_trait]
impl CheckpointBackend for StoreBackend {
    async fn resolve_current(&self, model_id: &str) -> Result<v3::Ref, Status> {
        self.scripted.log(RESOLVE, &v3::Model { model_id: model_id.to_string() }.encode_to_vec());
        self.store.resolve(model_id).map(|sha256| v3::Ref { sha256 }).map_err(status_of)
    }

    async fn fetch_blob(&self, sha256: &str) -> Result<Vec<v3::Chunk>, Status> {
        self.scripted.log(FETCH, &v3::Ref { sha256: sha256.to_string() }.encode_to_vec());
        self.store.read(sha256).map(|payload| blob_chunks(&payload)).map_err(status_of)
    }

    async fn commit_candidate(&self, commit: v3::Commit) -> Result<v3::Receipt, Status> {
        self.scripted.log(COMMIT, &commit.encode_to_vec());
        self.store.commit(&commit).map_err(status_of)
    }

    async fn commit_status(&self, request_id: &str) -> Result<v3::Receipt, Status> {
        self.scripted.log(COMMIT_STATUS, &v3::StatusRequest { request_id: request_id.to_string() }.encode_to_vec());
        self.store.status(request_id).map_err(status_of)
    }

    async fn health(&self) -> Result<v3::HealthResponse, Status> {
        Ok(v3::HealthResponse { ready: true, role: "checkpoint".to_string(), capabilities: Default::default() })
    }
}

fn pinned_sources() -> PinnedSources {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/privoke-curriculum/tests/fixtures");
    let bc01 = [
        ("taxonomy", "bc01/taxonomy-coverage-v1.json"),
        ("pool", "bc01/pool-authored.json"),
        ("manifest", "bc01/benign-manifest.json"),
        ("proof", "bc01/exclusion-proof.json"),
    ]
    .into_iter()
    .map(|(key, relative)| (key, root.join(relative)))
    .collect();
    PinnedSources::new(
        bc01,
        AudienceSource::Trusted { path: root.join("au3/audience-v3-manifest-v1.json"), sha256: BUNDLED_MANIFEST_SHA256.to_string() },
    )
}

/// The retained checkpoint directory of a recorded sequence (`recorded:<kind>/<name>`).
fn retained_blobs(models: &Path, label: &str) -> PathBuf {
    let (kind, name) = label.strip_prefix("recorded:").and_then(|rest| rest.split_once('/')).unwrap();
    let cell = match kind {
        "pretrained-cell" => models.join("pretrained_v3_20261012/cells").join(name),
        "pretrained-pilot" => models.join("pretrained_v3_20261012/pilots").join(name),
        "audience-pilot" => models.join("audience_v3_20261013/pilots").join(name),
        other => panic!("unknown kind of recorded fit {other}"),
    };
    cell.join("checkpoint/blobs")
}

/// A store holding what the retained run's checkpoint service held before the commit: the ORIGINAL as the model's version,
/// and the candidate with its evidence staged.
fn seeded_store(retained: &Path, base: &str, directory: &Path) -> Arc<CheckpointStore> {
    let store = CheckpointStore::open(directory.join("store"), Arc::new(pinned_sources())).unwrap();
    let manifest_bytes = std::fs::read(retained.join(base)).unwrap();
    let manifest = contract::parse(&manifest_bytes, contract::MAX_MANIFEST_BYTES).unwrap();
    let field = |key: &str| match &manifest {
        Value::Object(map) => match map.get(key) {
            Some(Value::String(text)) => text.clone(),
            _ => panic!("manifest field {key}"),
        },
        _ => panic!("manifest is an object"),
    };
    let original = directory.join("original");
    std::fs::create_dir_all(&original).unwrap();
    std::fs::write(original.join("manifest.json"), &manifest_bytes).unwrap();
    for (name, key) in [("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab")] {
        std::fs::copy(retained.join(field(key)), original.join(name)).unwrap();
    }
    store.bootstrap(&original).unwrap();
    std::fs::remove_dir_all(&original).unwrap();
    // Everything else the retained service held (the candidate's manifest, weights and evidence) is staged as it was.
    for entry in std::fs::read_dir(retained).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        let target = store.directory().join("blobs").join(&name);
        if !name.starts_with("stage-") && !target.exists() {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
    Arc::new(store)
}

#[tokio::test]
async fn the_recorded_fits_replay_identically_against_the_rust_store() {
    let (Some(golden_path), Some(models)) =
        (std::env::var_os("PRIVOKE_V3_FUZZER_RECORDED_GOLDEN"), std::env::var_os("PRIVOKE_V3_RECORDED_MODELS"))
    else {
        eprintln!("v3-fuzzer store replay skipped: PRIVOKE_V3_FUZZER_RECORDED_GOLDEN and PRIVOKE_V3_RECORDED_MODELS are not both set");
        return;
    };
    let models = PathBuf::from(models);
    let golden = read_json(Path::new(&golden_path));
    assert_eq!(golden["kind"], "recorded");
    let inputs = Inputs::load();
    let mut total = Counts::default();
    let (mut applied, mut rejected) = (0usize, 0usize);
    for sequence in golden["sequences"].as_array().unwrap() {
        let label = sequence["label"].as_str().unwrap();
        let cycle = &sequence["cycles"][0];
        let request = FuzzerTrainingRequest::decode(b64(cycle["request"].as_str().unwrap()).as_slice()).unwrap();
        let recorded_receipt = v3::Receipt::decode(b64(cycle["answers"]["commit"]["receipt"].as_str().unwrap()).as_slice()).unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let retained = retained_blobs(&models, label);
        let store = seeded_store(&retained, cycle["answers"]["resolve"].as_str().unwrap(), scratch.path());
        let service = store.clone();
        let counts = replay_sequence_with(sequence, &inputs, move |scripted| {
            Arc::new(StoreBackend { scripted: scripted.clone(), store: service }) as Arc<dyn CheckpointBackend>
        })
        .await;
        total.add(counts);
        // The store ended where the recorded service ended: the same receipt, and the candidate current when it was applied.
        let receipt = store.status(&request.request_id).unwrap();
        assert_eq!(receipt, recorded_receipt, "{label}: the store's receipt is the recorded one");
        let current = store.resolve(&request.model_id).unwrap();
        if receipt.status == "applied" {
            assert_eq!(current, receipt.candidate, "{label}: the candidate is current");
            applied += 1;
        } else {
            assert_eq!(current, receipt.base, "{label}: a rejected candidate changes nothing");
            rejected += 1;
        }
    }
    eprintln!(
        "v3-fuzzer recorded replay against the Rust checkpoint store: {} fits ({} applied, {} rejected), {} cycles, {} of {} wire messages, {} work-directory files and {} cycles rows identical to the Python oracle",
        total.sequences, applied, rejected, total.cycles, total.wire_messages, total.wire_messages, total.files, total.rows,
    );
    assert!(total.sequences > 0, "the local golden holds fits");
}
