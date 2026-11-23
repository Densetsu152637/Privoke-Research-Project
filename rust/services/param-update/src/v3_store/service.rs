//! The `CheckpointService` handlers (`shared/proto/privoke/experimental/v3.proto`, served in Python by `checkpoint_server.py`).
//!
//! Authorisation has already happened in `privoke-transport`'s layer ([`crate::server::policy`]): the registered `publisher`
//! and `trainer` services reach every method, a `runtime` service reaches the read and stage methods but never
//! `CommitCandidate`. What is left here is the transport contract of the oracle: bounded, ordered, hash-checked blob chunks in
//! both directions, and the store's refusals as gRPC statuses (`INVALID_ARGUMENT` for a rule of the contract, `NOT_FOUND` for
//! a blob the store does not hold, a fixed `INTERNAL` message for storage failures).
//!
//! The store does blocking file and SQLite work, so each call runs on the blocking pool.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;

use privoke_contracts::proto::experimental_v3::checkpoint_service_server::CheckpointService;
use privoke_contracts::proto::experimental_v3::{Chunk, Commit, HealthRequest, HealthResponse, Model, Receipt, Ref, StatusRequest};
use privoke_contracts::v3::{CHUNK_BYTES, MAX_BLOB_BYTES};
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

use super::store::{CheckpointStore, StoreError, digest};
use crate::util::log;

/// The role `Health` reports.
pub const ROLE: &str = "checkpoint";
/// The publication contract `Health` reports (the oracle's name for the compare-and-swap in one SQLite transaction).
pub const PUBLICATION: &str = "sqlite_atomic_cas_v1";
/// The largest gRPC message of this service: a 1 MiB chunk and its framing (the oracle's `OPTIONS`).
pub const MESSAGE_LIMIT: usize = 2 * 1024 * 1024;

/// The handlers over a shared store.
#[derive(Debug, Clone)]
pub struct CheckpointHandler {
    store: Arc<CheckpointStore>,
}

impl CheckpointHandler {
    /// Handlers over `store`.
    pub fn new(store: Arc<CheckpointStore>) -> Self {
        Self { store }
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&CheckpointStore) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, Status> {
        let store = self.store.clone();
        match tokio::task::spawn_blocking(move || work(store.as_ref())).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(status_of(error)),
            Err(error) => {
                log(format_args!("checkpoint task failed: {error}"));
                Err(Status::internal("Checkpoint task failed."))
            }
        }
    }
}

/// The gRPC status of a refusal.
pub fn status_of(error: StoreError) -> Status {
    match error {
        StoreError::Invalid(message) => Status::invalid_argument(message),
        StoreError::Missing(message) => {
            log(format_args!("checkpoint object missing: {message}"));
            Status::not_found("Checkpoint object is not in this private catalog.")
        }
        StoreError::Storage(detail) => {
            log(format_args!("checkpoint storage failed: {detail}"));
            Status::internal("Checkpoint storage failed.")
        }
    }
}

type ChunkStream = Pin<Box<dyn Stream<Item = Result<Chunk, Status>> + Send>>;

#[tonic::async_trait]
impl CheckpointService for CheckpointHandler {
    type FetchBlobStream = ChunkStream;

    async fn resolve_current(&self, request: Request<Model>) -> Result<Response<Ref>, Status> {
        let model = request.into_inner().model_id;
        let sha256 = self.blocking(move |store| store.resolve(&model)).await?;
        Ok(Response::new(Ref { sha256 }))
    }

    async fn fetch_blob(&self, request: Request<Ref>) -> Result<Response<Self::FetchBlobStream>, Status> {
        let sha = request.into_inner().sha256;
        let payload = Arc::new(self.blocking(move |store| store.read(&sha)).await?);
        let sha256 = digest(&payload);
        let total = payload.len() as u64;
        let count = payload.len().div_ceil(CHUNK_BYTES);
        let chunks = (0..count).map(move |index| {
            let start = index * CHUNK_BYTES;
            let end = (start + CHUNK_BYTES).min(payload.len());
            Ok::<Chunk, Status>(Chunk {
                sha256: sha256.clone(),
                offset: start as u64,
                total_bytes: total,
                data: payload[start..end].to_vec(),
                manifest_json: Vec::new(),
            })
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks))))
    }

    async fn stage_checkpoint(&self, request: Request<Streaming<Chunk>>) -> Result<Response<Ref>, Status> {
        let mut stream = request.into_inner();
        let invalid = |message: &str| Status::invalid_argument(message.to_string());
        let mut data: Vec<u8> = Vec::new();
        let mut identity: Option<String> = None;
        let mut total: u64 = 0;
        let mut manifest: Vec<u8> = Vec::new();
        let mut offset: u64 = 0;
        while let Some(part) = stream.message().await? {
            let refused = part.data.is_empty()
                || part.data.len() > CHUNK_BYTES
                || part.offset != offset
                || part.total_bytes == 0
                || part.total_bytes > MAX_BLOB_BYTES
                || identity.as_ref().is_some_and(|sha| part.sha256 != *sha || part.total_bytes != total)
                || (offset != 0 && !part.manifest_json.is_empty());
            if refused {
                return Err(invalid("Invalid bounded ordered checkpoint upload."));
            }
            if offset == 0 {
                identity = Some(part.sha256.clone());
                total = part.total_bytes;
                manifest = part.manifest_json.clone();
            }
            offset += part.data.len() as u64;
            if offset > total {
                return Err(invalid("Upload exceeds declared byte count."));
            }
            data.extend_from_slice(&part.data);
        }
        if identity.as_deref() != Some(digest(&data).as_str()) || offset != total {
            return Err(invalid("Incomplete/corrupt checkpoint upload."));
        }
        let sha256 = self.blocking(move |store| store.stage(&data, &manifest)).await?;
        Ok(Response::new(Ref { sha256 }))
    }

    async fn commit_candidate(&self, request: Request<Commit>) -> Result<Response<Receipt>, Status> {
        let commit = request.into_inner();
        Ok(Response::new(self.blocking(move |store| store.commit(&commit)).await?))
    }

    async fn get_commit_status(&self, request: Request<StatusRequest>) -> Result<Response<Receipt>, Status> {
        let request_id = request.into_inner().request_id;
        Ok(Response::new(self.blocking(move |store| store.status(&request_id)).await?))
    }

    async fn health(&self, _request: Request<HealthRequest>) -> Result<Response<HealthResponse>, Status> {
        let capabilities: BTreeMap<String, String> =
            [("schema", "1"), ("publication", PUBLICATION), ("implementation", "privoke-param-update-v3-store")]
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect();
        Ok(Response::new(HealthResponse { ready: true, role: ROLE.to_string(), capabilities }))
    }
}
