//! The two dependencies of the V3 fuzzer, as the cycle uses them: the V3 runtime's `TrainingService` and the checkpoint
//! service's `CheckpointService` (`shared/proto/privoke/experimental/v3.proto`).
//!
//! Both are traits so that the cycle runs against scripted answers in the tests. [`GrpcFit`] and [`GrpcCheckpoint`] are the
//! mutual-TLS clients: they present the fuzzer's registered service certificate and refuse a server whose certificate the
//! configured CA did not sign. The message limits are the Python `OPTIONS` (2 MiB each way), and the per-call deadlines are
//! those of `fuzzer_server.py`: 15 seconds for health, resolution and status lookups, 120 seconds for a blob fetch or a commit,
//! and `V3_FIT_TIMEOUT` for a fit.

use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::experimental_v3::checkpoint_service_client::CheckpointServiceClient;
use privoke_contracts::proto::experimental_v3::training_service_client::TrainingServiceClient;
use privoke_contracts::v3::{CHUNK_BYTES, MAX_BLOB_BYTES};
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use tonic::transport::Channel;
use tonic::{Request, Status};

use crate::contract::{check_sha, digest};
use crate::error::{Result, invalid};

/// `OPTIONS`: the largest message either way.
pub const MESSAGE_LIMIT: usize = 2 * 1024 * 1024;
/// The deadline of a health, resolution or status call.
pub const QUICK: Duration = Duration::from_secs(15);
/// The deadline of a blob fetch.
pub const FETCH: Duration = Duration::from_secs(120);
/// The deadline of a commit.
pub const COMMIT: Duration = Duration::from_secs(120);

/// The V3 runtime as the fuzzer uses it.
#[tonic::async_trait]
pub trait FitBackend: Send + Sync {
    /// `FitCandidate`.
    async fn fit_candidate(&self, request: v3::FitRequest, timeout: Duration) -> std::result::Result<v3::FitResponse, Status>;
    /// `GetFitStatus`.
    async fn fit_status(&self, request_id: &str) -> std::result::Result<v3::Receipt, Status>;
    /// `Health`.
    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status>;
}

/// The checkpoint service as the fuzzer uses it.
#[tonic::async_trait]
pub trait CheckpointBackend: Send + Sync {
    /// `ResolveCurrent`.
    async fn resolve_current(&self, model_id: &str) -> std::result::Result<v3::Ref, Status>;
    /// `FetchBlob`: every chunk of the stream, in order. The transport is validated by [`assemble_blob`].
    async fn fetch_blob(&self, sha256: &str) -> std::result::Result<Vec<v3::Chunk>, Status>;
    /// `CommitCandidate`.
    async fn commit_candidate(&self, commit: v3::Commit) -> std::result::Result<v3::Receipt, Status>;
    /// `GetCommitStatus`.
    async fn commit_status(&self, request_id: &str) -> std::result::Result<v3::Receipt, Status>;
    /// `Health`.
    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status>;
}

/// `fetch(stub, sha)`: the ordered, bounded, hash-checked reassembly of a blob stream.
pub fn assemble_blob(chunks: &[v3::Chunk], sha256: &str) -> Result<Vec<u8>> {
    check_sha(sha256)?;
    let mut payload: Vec<u8> = Vec::new();
    let mut offset: u64 = 0;
    let mut total: Option<u64> = None;
    for part in chunks {
        if part.sha256 != sha256
            || part.offset != offset
            || part.data.is_empty()
            || part.data.len() > CHUNK_BYTES
            || part.total_bytes == 0
            || part.total_bytes > MAX_BLOB_BYTES
            || total.is_some_and(|declared| part.total_bytes != declared)
        {
            return invalid("Invalid ordered bounded blob transport.");
        }
        total = Some(part.total_bytes);
        offset += part.data.len() as u64;
        if offset > part.total_bytes {
            return invalid("Blob exceeds declared length.");
        }
        payload.extend_from_slice(&part.data);
    }
    if total != Some(payload.len() as u64) || digest(&payload) != sha256 {
        return invalid("Incomplete or corrupt blob transport.");
    }
    Ok(payload)
}

/// `chunks(payload)` of `common.py`: the stream a checkpoint service sends for a blob.
pub fn blob_chunks(payload: &[u8]) -> Vec<v3::Chunk> {
    let sha256 = digest(payload);
    payload
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, data)| v3::Chunk {
            sha256: sha256.clone(),
            offset: (index * CHUNK_BYTES) as u64,
            total_bytes: payload.len() as u64,
            data: data.to_vec(),
            manifest_json: Vec::new(),
        })
        .collect()
}

async fn dial(target: &str, tls: &ClientTlsConfig) -> std::result::Result<Channel, Status> {
    connect(target, tls).await.map_err(|error| Status::unavailable(error.to_string()))
}

fn with_deadline<T>(message: T, timeout: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

/// The mutual-TLS client of the V3 runtime's `TrainingService`.
#[derive(Debug, Clone)]
pub struct GrpcFit {
    target: String,
    tls: ClientTlsConfig,
}

impl GrpcFit {
    /// A client for `target` (`host:port`).
    pub fn new(target: impl Into<String>, tls: ClientTlsConfig) -> Self {
        Self { target: target.into(), tls }
    }

    async fn client(&self) -> std::result::Result<TrainingServiceClient<Channel>, Status> {
        let channel = dial(&self.target, &self.tls).await?;
        Ok(TrainingServiceClient::new(channel).max_decoding_message_size(MESSAGE_LIMIT).max_encoding_message_size(MESSAGE_LIMIT))
    }
}

#[tonic::async_trait]
impl FitBackend for GrpcFit {
    async fn fit_candidate(&self, request: v3::FitRequest, timeout: Duration) -> std::result::Result<v3::FitResponse, Status> {
        let mut client = self.client().await?;
        Ok(client.fit_candidate(with_deadline(request, timeout)).await?.into_inner())
    }

    async fn fit_status(&self, request_id: &str) -> std::result::Result<v3::Receipt, Status> {
        let mut client = self.client().await?;
        let request = v3::StatusRequest { request_id: request_id.to_string() };
        Ok(client.get_fit_status(with_deadline(request, QUICK)).await?.into_inner())
    }

    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status> {
        let mut client = self.client().await?;
        Ok(client.health(with_deadline(v3::HealthRequest {}, QUICK)).await?.into_inner())
    }
}

/// The mutual-TLS client of the checkpoint service's `CheckpointService`.
#[derive(Debug, Clone)]
pub struct GrpcCheckpoint {
    target: String,
    tls: ClientTlsConfig,
}

impl GrpcCheckpoint {
    /// A client for `target` (`host:port`).
    pub fn new(target: impl Into<String>, tls: ClientTlsConfig) -> Self {
        Self { target: target.into(), tls }
    }

    async fn client(&self) -> std::result::Result<CheckpointServiceClient<Channel>, Status> {
        let channel = dial(&self.target, &self.tls).await?;
        Ok(CheckpointServiceClient::new(channel).max_decoding_message_size(MESSAGE_LIMIT).max_encoding_message_size(MESSAGE_LIMIT))
    }
}

#[tonic::async_trait]
impl CheckpointBackend for GrpcCheckpoint {
    async fn resolve_current(&self, model_id: &str) -> std::result::Result<v3::Ref, Status> {
        let mut client = self.client().await?;
        let request = v3::Model { model_id: model_id.to_string() };
        Ok(client.resolve_current(with_deadline(request, QUICK)).await?.into_inner())
    }

    async fn fetch_blob(&self, sha256: &str) -> std::result::Result<Vec<v3::Chunk>, Status> {
        let mut client = self.client().await?;
        let request = v3::Ref { sha256: sha256.to_string() };
        let mut stream = client.fetch_blob(with_deadline(request, FETCH)).await?.into_inner();
        let mut chunks = Vec::new();
        let mut received: u64 = 0;
        while let Some(chunk) = stream.message().await? {
            received += chunk.data.len() as u64;
            chunks.push(chunk);
            // A stream past the admitted blob size cannot validate; stop reading it.
            if received > MAX_BLOB_BYTES + CHUNK_BYTES as u64 {
                break;
            }
        }
        Ok(chunks)
    }

    async fn commit_candidate(&self, commit: v3::Commit) -> std::result::Result<v3::Receipt, Status> {
        let mut client = self.client().await?;
        Ok(client.commit_candidate(with_deadline(commit, COMMIT)).await?.into_inner())
    }

    async fn commit_status(&self, request_id: &str) -> std::result::Result<v3::Receipt, Status> {
        let mut client = self.client().await?;
        let request = v3::StatusRequest { request_id: request_id.to_string() };
        Ok(client.get_commit_status(with_deadline(request, QUICK)).await?.into_inner())
    }

    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status> {
        let mut client = self.client().await?;
        Ok(client.health(with_deadline(v3::HealthRequest {}, QUICK)).await?.into_inner())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_blob_streams_in_bounded_ordered_chunks_and_reassembles() {
        let payload: Vec<u8> = (0..(CHUNK_BYTES * 2 + 17)).map(|index| (index % 251) as u8).collect();
        let sha = digest(&payload);
        let chunks = blob_chunks(&payload);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[2].offset, (2 * CHUNK_BYTES) as u64);
        assert_eq!(assemble_blob(&chunks, &sha).unwrap(), payload);
    }

    #[test]
    fn a_disordered_short_or_corrupt_stream_is_refused() {
        let payload = vec![7u8; 100];
        let sha = digest(&payload);
        let chunks = blob_chunks(&payload);
        let mut gap = chunks.clone();
        gap[0].offset = 1;
        assert_eq!(assemble_blob(&gap, &sha).unwrap_err().0, "Invalid ordered bounded blob transport.");
        let mut foreign = chunks.clone();
        foreign[0].sha256 = digest(b"other");
        assert_eq!(assemble_blob(&foreign, &sha).unwrap_err().0, "Invalid ordered bounded blob transport.");
        let mut empty = chunks.clone();
        empty[0].data.clear();
        assert_eq!(assemble_blob(&empty, &sha).unwrap_err().0, "Invalid ordered bounded blob transport.");
        let mut long = chunks.clone();
        long[0].total_bytes = 10;
        assert_eq!(assemble_blob(&long, &sha).unwrap_err().0, "Blob exceeds declared length.");
        let mut short = chunks.clone();
        short[0].total_bytes = 200;
        assert_eq!(assemble_blob(&short, &sha).unwrap_err().0, "Incomplete or corrupt blob transport.");
        assert_eq!(assemble_blob(&[], &sha).unwrap_err().0, "Incomplete or corrupt blob transport.");
        let mut corrupt = chunks;
        corrupt[0].data[0] ^= 1;
        assert_eq!(assemble_blob(&corrupt, &sha).unwrap_err().0, "Incomplete or corrupt blob transport.");
        assert_eq!(assemble_blob(&blob_chunks(&payload), "not-a-sha").unwrap_err().0, "Expected a lowercase SHA-256 identity.");
    }
}
