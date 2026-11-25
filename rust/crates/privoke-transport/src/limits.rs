//! Resource limits that replace nginx's `limit_req`, `limit_conn`, body cap and timeouts.

use std::time::Duration;

use tonic::transport::Server;

/// Token-bucket rate for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Sustained requests per second.
    pub per_second: u32,
    /// Burst allowance.
    pub burst: u32,
}

/// Limits for one listener. The defaults reproduce the nginx values of the cloud deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Per-RPC deadline (nginx `grpc_read_timeout` 60 s).
    pub request_timeout: Duration,
    /// Largest accepted request message (nginx `client_max_body_size` 1 MB). Apply with
    /// `max_decoding_message_size` on each generated server.
    pub max_message_bytes: usize,
    /// Simultaneous connections across all peers.
    pub max_connections: usize,
    /// Simultaneous connections from one source IP (nginx `limit_conn` 20).
    pub max_connections_per_ip: usize,
    /// Time a client has to finish the TLS handshake.
    pub handshake_timeout: Duration,
    /// Age after which a connection is drained, so a revoked peer cannot hold a stream open for long.
    pub max_connection_age: Duration,
    /// Time allowed for in-flight RPCs after `max_connection_age`.
    pub max_connection_age_grace: Duration,
    /// Per-peer request rate (nginx `limit_req` 20 r/s, burst 40).
    pub rate: RateLimit,
    /// Concurrent HTTP/2 streams per connection.
    pub max_concurrent_streams: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(60),
            max_message_bytes: 1024 * 1024,
            max_connections: 1024,
            max_connections_per_ip: 20,
            handshake_timeout: Duration::from_secs(10),
            max_connection_age: Duration::from_secs(600),
            max_connection_age_grace: Duration::from_secs(30),
            rate: RateLimit { per_second: 20, burst: 40 },
            max_concurrent_streams: 64,
        }
    }
}

impl Limits {
    /// Apply the server-level limits to a tonic server builder.
    pub fn apply(&self, server: Server) -> Server {
        server
            .timeout(self.request_timeout)
            .max_connection_age(self.max_connection_age)
            .max_connection_age_grace(self.max_connection_age_grace)
            .max_concurrent_streams(self.max_concurrent_streams)
    }
}
