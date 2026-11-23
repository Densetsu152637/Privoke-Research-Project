//! The V3 `CheckpointService` on the internal mutual-TLS listener, in process, with certificates issued at test time: which
//! roles reach which method, the bounded ordered blob transport in both directions and the store's refusals as gRPC statuses.
//! The store's own behaviour (admission, staging and commit against the Python oracle) is `checkpoint_store_golden.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::{Creds, Env, engine, generous};
use privoke_contracts::digest::sha256_hex;
use privoke_contracts::json::Value;
use privoke_contracts::proto::experimental_v3::checkpoint_service_client::CheckpointServiceClient;
use privoke_contracts::proto::experimental_v3::{Chunk, Commit, HealthRequest, Model, Ref, Rollback, StatusRequest};
use privoke_contracts::v3::CHUNK_BYTES;
use privoke_param_update::server::ServerHandle;
use privoke_param_update::v3_store::{CheckpointHandler, CheckpointStore, SourceEvidence, StoreError};
use tonic::transport::Channel;
use tonic::{Code, Status};

/// The V3 admission needs the pinned sources only for evidence the fixture never gets as far as.
#[derive(Debug)]
struct NoSources;

impl SourceEvidence for NoSources {
    fn validate(&self, _evidence: &Value) -> Result<(), StoreError> {
        Err(StoreError::Invalid("no pinned sources in this fixture".to_string()))
    }
}

struct Fixture {
    env: Env,
    store: Arc<CheckpointStore>,
    server: ServerHandle,
    _directory: tempfile::TempDir,
}

async fn fixture() -> (Fixture, Creds, Creds, Creds, Creds, Creds) {
    let env = Env::new();
    let directory = tempfile::tempdir().unwrap();
    let model = common::copy_model(directory.path(), "privoke-baseline");
    let publisher = env.service("publisher-1", Some("publisher"));
    let trainer = env.service("trainer-1", Some("trainer"));
    let runtime = env.service("runtime-1", Some("runtime"));
    let unregistered = env.service("unregistered", None);
    let consumer = env.installation("consumer", true);
    let store = Arc::new(CheckpointStore::open(directory.path().join("v3"), Arc::new(NoSources)).unwrap());
    let engine = Arc::new(engine(directory.path(), &model, "privoke-baseline"));
    let server = env.start_with_checkpoint(engine, CheckpointHandler::new(store.clone()), generous()).await;
    (Fixture { env, store, server, _directory: directory }, publisher, trainer, runtime, unregistered, consumer)
}

async fn peer(fixture: &Fixture, creds: &Creds) -> CheckpointServiceClient<Channel> {
    connect(&fixture.env, fixture.server.addr, creds).await
}

async fn connect(env: &Env, address: SocketAddr, creds: &Creds) -> CheckpointServiceClient<Channel> {
    let channel = privoke_transport::client::connect(&address.to_string(), &env.client_config(Some(creds))).await.expect("connect");
    CheckpointServiceClient::new(channel).max_decoding_message_size(2 * 1024 * 1024)
}

fn commit(request_id: &str) -> Commit {
    let sha = sha256_hex(b"x");
    Commit {
        request_id: request_id.to_string(),
        model_id: "privoke-v3-efficient".to_string(),
        expected_base: sha.clone(),
        candidate: sha.clone(),
        evidence: sha,
    }
}

fn upload(parts: &[(&str, u64, u64, &[u8])]) -> Vec<Chunk> {
    parts
        .iter()
        .map(|(sha, offset, total, data)| Chunk {
            sha256: (*sha).to_string(),
            offset: *offset,
            total_bytes: *total,
            data: data.to_vec(),
            manifest_json: Vec::new(),
        })
        .collect()
}

#[tokio::test]
async fn a_blob_streams_in_bounded_ordered_chunks_to_every_internal_role() {
    let (fixture, publisher, trainer, runtime, ..) = fixture().await;
    let payload: Vec<u8> = (0..(CHUNK_BYTES * 2 + 1000)).map(|index| (index % 251) as u8).collect();
    let sha = fixture.store.put(&payload).unwrap();
    for creds in [&publisher, &trainer, &runtime] {
        let mut client = peer(&fixture, creds).await;
        let mut stream = client.fetch_blob(Ref { sha256: sha.clone() }).await.unwrap().into_inner();
        let mut received = Vec::new();
        let mut offsets = Vec::new();
        while let Some(chunk) = stream.message().await.unwrap() {
            assert_eq!((chunk.sha256.as_str(), chunk.total_bytes), (sha.as_str(), payload.len() as u64));
            assert!(!chunk.data.is_empty() && chunk.data.len() <= CHUNK_BYTES && chunk.manifest_json.is_empty());
            offsets.push(chunk.offset);
            received.extend_from_slice(&chunk.data);
        }
        assert_eq!(offsets, vec![0, CHUNK_BYTES as u64, 2 * CHUNK_BYTES as u64], "{}", creds.id);
        assert_eq!(received, payload);
    }
    let mut client = peer(&fixture, &publisher).await;
    assert_eq!(client.fetch_blob(Ref { sha256: sha256_hex(b"absent") }).await.unwrap_err().code(), Code::NotFound);
    assert_eq!(client.fetch_blob(Ref { sha256: "not-a-sha".to_string() }).await.unwrap_err().code(), Code::InvalidArgument);
    fixture.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn lookups_answer_for_unknown_models_and_requests_and_health_names_the_service() {
    let (fixture, publisher, trainer, ..) = fixture().await;
    for creds in [&publisher, &trainer] {
        let mut client = peer(&fixture, creds).await;
        let status = client.resolve_current(Model { model_id: "privoke-v3-efficient".to_string() }).await.unwrap_err();
        assert_eq!((status.code(), status.message()), (Code::InvalidArgument, "Model is not in this private catalog."));
        let unknown = client.get_commit_status(StatusRequest { request_id: "never-issued".to_string() }).await.unwrap().into_inner();
        assert_eq!((unknown.status.as_str(), unknown.request_id.as_str()), ("unknown", "never-issued"));
        let health = client.health(HealthRequest {}).await.unwrap().into_inner();
        assert!(health.ready);
        assert_eq!(health.role, "checkpoint");
        assert_eq!(health.capabilities["publication"], "sqlite_atomic_cas_v1");
    }
    fixture.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn only_publishers_and_trainers_commit_and_unknown_peers_reach_nothing() {
    let (fixture, publisher, trainer, runtime, unregistered, consumer) = fixture().await;
    // The commit is authorised for the publisher and the trainer, which then meet the store's own refusal.
    for creds in [&publisher, &trainer] {
        let mut client = peer(&fixture, creds).await;
        let refused = client.commit_candidate(commit("")).await.unwrap_err();
        assert_eq!((refused.code(), refused.message()), (Code::InvalidArgument, "Explicit bounded request identity required."));
    }
    // A runtime service reads and stages, and never commits.
    let mut runtime_client = peer(&fixture, &runtime).await;
    assert_eq!(runtime_client.commit_candidate(commit("r")).await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(
        runtime_client.resolve_current(Model { model_id: "privoke-v3-efficient".to_string() }).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    // A rollback is an operator action: the publisher reaches the store (which does not hold this manifest), no one else gets in.
    let rollback = Rollback { request_id: "r".to_string(), model_id: "privoke-v3-efficient".to_string(), manifest: sha256_hex(b"x") };
    let mut publisher_client = peer(&fixture, &publisher).await;
    assert_eq!(publisher_client.rollback_model(rollback.clone()).await.unwrap_err().code(), Code::NotFound);
    let mut trainer_client = peer(&fixture, &trainer).await;
    assert_eq!(trainer_client.rollback_model(rollback.clone()).await.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(runtime_client.rollback_model(rollback.clone()).await.unwrap_err().code(), Code::PermissionDenied);
    // A certificate the registry does not know, and a consumer installation, reach no method.
    for creds in [&unregistered, &consumer] {
        let mut client = peer(&fixture, creds).await;
        assert_eq!(client.health(HealthRequest {}).await.unwrap_err().code(), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(client.commit_candidate(commit("r")).await.unwrap_err().code(), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(client.rollback_model(rollback.clone()).await.unwrap_err().code(), Code::PermissionDenied, "{}", creds.id);
        assert_eq!(client.fetch_blob(Ref { sha256: sha256_hex(b"x") }).await.unwrap_err().code(), Code::PermissionDenied, "{}", creds.id);
    }
    fixture.server.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_upload_is_bounded_ordered_and_hash_checked_before_the_store_sees_it() {
    let (fixture, _publisher, trainer, runtime, ..) = fixture().await;
    let sha = sha256_hex(b"abc");
    let refusal = |status: Status| (status.code(), status.message().to_string());
    for creds in [&trainer, &runtime] {
        let mut client = peer(&fixture, creds).await;
        let invalid = |message: &str| (Code::InvalidArgument, message.to_string());
        // The first chunk starts past zero.
        let late = upload(&[(&sha, 1, 3, b"abc")]);
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(late)).await.unwrap_err()),
            invalid("Invalid bounded ordered checkpoint upload.")
        );
        // An empty chunk.
        let empty = upload(&[(&sha, 0, 3, b"")]);
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(empty)).await.unwrap_err()),
            invalid("Invalid bounded ordered checkpoint upload.")
        );
        // More bytes than declared.
        let long = upload(&[(&sha, 0, 2, b"abc")]);
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(long)).await.unwrap_err()),
            invalid("Upload exceeds declared byte count.")
        );
        // Fewer bytes than declared, a hash that is not the payload's, and no chunk at all.
        let short = upload(&[(&sha, 0, 4, b"abc")]);
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(short)).await.unwrap_err()),
            invalid("Incomplete/corrupt checkpoint upload.")
        );
        let wrong = upload(&[(&sha256_hex(b"other"), 0, 3, b"abc")]);
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(wrong)).await.unwrap_err()),
            invalid("Incomplete/corrupt checkpoint upload.")
        );
        assert_eq!(
            refusal(client.stage_checkpoint(tokio_stream::iter(Vec::new())).await.unwrap_err()),
            invalid("Incomplete/corrupt checkpoint upload.")
        );
        // A complete upload reaches the store, which refuses a payload that is not evidence (no manifest was sent).
        let whole = upload(&[(&sha, 0, 3, b"abc")]);
        let refused = client.stage_checkpoint(tokio_stream::iter(whole)).await.unwrap_err();
        assert_eq!(refused.code(), Code::InvalidArgument, "{}", creds.id);
    }
    fixture.server.shutdown().await.unwrap();
}
