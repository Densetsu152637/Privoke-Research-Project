//! The checkpoint service as the V3 runtime uses it (`shared/proto/privoke/experimental/v3.proto`, `CheckpointService`):
//! resolve the current snapshot of a model, fetch a blob, stage a candidate's evidence and blob, and report health.
//!
//! [`Checkpoint`] is a trait so that the engine runs against scripted answers in the tests. [`GrpcCheckpoint`] is the mutual-TLS
//! client: it presents the runtime's registered service certificate and refuses a server whose certificate the configured CA
//! did not sign. The message limits are the Python `OPTIONS` (2 MiB each way) and the deadlines are those of
//! `runtime_server.py`: 10 seconds for health and resolution, 120 seconds for a blob fetch or a staging call.

use std::time::Duration;

use privoke_contracts::proto::experimental_v3 as v3;
use privoke_contracts::proto::experimental_v3::checkpoint_service_client::CheckpointServiceClient;
use privoke_contracts::v3::{CHUNK_BYTES, MAX_BLOB_BYTES};
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use privoke_v3_fuzzer::backend::MESSAGE_LIMIT;
use privoke_v3_fuzzer::contract::digest;
use tonic::transport::Channel;
use tonic::{Request, Status};

/// The deadline of a health or resolution call.
pub const QUICK: Duration = Duration::from_secs(10);
/// The deadline of a blob fetch.
pub const FETCH: Duration = Duration::from_secs(120);
/// The deadline of a staging call.
pub const STAGE: Duration = Duration::from_secs(120);

/// The checkpoint service as the runtime uses it.
#[tonic::async_trait]
pub trait Checkpoint: Send + Sync {
    /// `ResolveCurrent`.
    async fn resolve_current(&self, model_id: &str) -> std::result::Result<v3::Ref, Status>;
    /// `FetchBlob`: every chunk of the stream, in order. The transport is validated by
    /// [`assemble_blob`](privoke_v3_fuzzer::backend::assemble_blob).
    async fn fetch_blob(&self, sha256: &str) -> std::result::Result<Vec<v3::Chunk>, Status>;
    /// `StageCheckpoint`: one client stream of chunks.
    async fn stage_checkpoint(&self, chunks: Vec<v3::Chunk>) -> std::result::Result<v3::Ref, Status>;
    /// `Health`.
    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status>;
}

/// `chunks(payload, manifest)` of `common.py`: the stream the runtime stages, the manifest on the first chunk only.
pub fn stage_chunks(payload: &[u8], manifest: &[u8]) -> Vec<v3::Chunk> {
    let sha256 = digest(payload);
    payload
        .chunks(CHUNK_BYTES)
        .enumerate()
        .map(|(index, data)| v3::Chunk {
            sha256: sha256.clone(),
            offset: (index * CHUNK_BYTES) as u64,
            total_bytes: payload.len() as u64,
            data: data.to_vec(),
            manifest_json: if index == 0 { manifest.to_vec() } else { Vec::new() },
        })
        .collect()
}

fn with_deadline<T>(message: T, timeout: Duration) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(timeout);
    request
}

/// The mutual-TLS client of the checkpoint service.
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
        let channel = connect(&self.target, &self.tls).await.map_err(|error| Status::unavailable(error.to_string()))?;
        Ok(CheckpointServiceClient::new(channel).max_decoding_message_size(MESSAGE_LIMIT).max_encoding_message_size(MESSAGE_LIMIT))
    }
}

#[tonic::async_trait]
impl Checkpoint for GrpcCheckpoint {
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

    async fn stage_checkpoint(&self, chunks: Vec<v3::Chunk>) -> std::result::Result<v3::Ref, Status> {
        let mut client = self.client().await?;
        Ok(client.stage_checkpoint(with_deadline(tokio_stream::iter(chunks), STAGE)).await?.into_inner())
    }

    async fn health(&self) -> std::result::Result<v3::HealthResponse, Status> {
        let mut client = self.client().await?;
        Ok(client.health(with_deadline(v3::HealthRequest {}, QUICK)).await?.into_inner())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use privoke_v3_fuzzer::backend::assemble_blob;

    use super::*;

    #[test]
    fn a_staged_blob_carries_its_manifest_on_the_first_chunk_only_and_reassembles() {
        let payload: Vec<u8> = (0..(CHUNK_BYTES + 5)).map(|index| (index % 253) as u8).collect();
        let chunks = stage_chunks(&payload, b"{\"manifest\":1}\n");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].manifest_json, b"{\"manifest\":1}\n");
        assert!(chunks[1].manifest_json.is_empty());
        assert_eq!(chunks[1].offset, CHUNK_BYTES as u64);
        assert_eq!(assemble_blob(&chunks, &digest(&payload)).unwrap(), payload);
        assert!(stage_chunks(&[], b"m").is_empty());
    }
}
