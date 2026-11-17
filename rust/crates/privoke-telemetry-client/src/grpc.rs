//! Delivery over gRPC to the telemetry service: mutual TLS with the shared reporter credential (stage 4's public
//! listener), or plaintext to a loopback address (the workstation boundary of `stack_connection.grpc_channel`).
//!
//! The transport owns a current-thread runtime and is used from the reporter's worker thread only. The channel is
//! created on first use and again after a connection-level failure, so a collector that is down for a while costs the
//! reports sent meanwhile and nothing afterwards.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::proto::v1::TelemetryPacket;
use privoke_contracts::proto::v1::telemetry_service_client::TelemetryServiceClient;
use privoke_transport::ClientTlsConfig;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request};

use crate::error::ReporterError;
use crate::reporter::{DeliveryFailure, PacketTransport};

/// Environment variable names of the reporter credential, shared with the Python client runtime.
pub const REPORTER_CERT_FILE: &str = "PRIVOKE_TELEMETRY_TLS_CERT_FILE";
/// See [`REPORTER_CERT_FILE`].
pub const REPORTER_KEY_FILE: &str = "PRIVOKE_TELEMETRY_TLS_KEY_FILE";
/// The CA bundle that signed the server certificate.
pub const SERVER_CA_FILE: &str = "PRIVOKE_TLS_CA_FILE";

/// How the channel is secured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReporterChannel {
    /// No TLS. Only for a loopback target.
    Plaintext,
    /// Mutual TLS with the reporter credential.
    MutualTls(ClientTlsConfig),
}

/// Where and how the reporter delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReporterEndpoint {
    /// `host:port` of the public telemetry listener.
    pub target: String,
    /// The security of the channel.
    pub channel: ReporterChannel,
}

fn host_of(target: &str) -> &str {
    target.rsplit_once(':').map_or(target, |(host, _)| host).trim_matches(['[', ']'])
}

fn is_loopback_host(host: &str) -> bool {
    host.parse::<IpAddr>().map_or(host == "localhost", |address| address.is_loopback())
}

impl ReporterEndpoint {
    /// The endpoint `grpc_channel(target, credential="reporter")` would open, from an environment lookup: a loopback
    /// target is plaintext; any other target needs the reporter key pair and the server CA, and the host part of the
    /// target is the name the server certificate must carry. (The research-only plaintext opt-out of the oracle is
    /// not offered, and a CA bundle is required instead of the system roots.)
    pub fn from_environment(target: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, ReporterError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(ReporterError::Endpoint(
                "configure PRIVOKE_CLOUD_TARGET (or PRIVOKE_CLOUD_TELEMETRY_TARGET) in the client runtime .env".to_string(),
            ));
        }
        let host = host_of(target);
        if is_loopback_host(host) {
            return Ok(Self { target: target.to_string(), channel: ReporterChannel::Plaintext });
        }
        let value = |name: &str| lookup(name).map(|text| text.trim().to_string()).filter(|text| !text.is_empty());
        let (Some(cert), Some(key)) = (value(REPORTER_CERT_FILE), value(REPORTER_KEY_FILE)) else {
            return Err(ReporterError::Endpoint(format!("non-loopback connections require {REPORTER_CERT_FILE} and {REPORTER_KEY_FILE}")));
        };
        let Some(ca) = value(SERVER_CA_FILE) else {
            return Err(ReporterError::Endpoint(format!("non-loopback connections require {SERVER_CA_FILE}")));
        };
        Ok(Self {
            target: target.to_string(),
            channel: ReporterChannel::MutualTls(ClientTlsConfig {
                server_ca: PathBuf::from(ca),
                identity: Some((PathBuf::from(cert), PathBuf::from(key))),
                server_name: host.to_string(),
            }),
        })
    }
}

/// The Python `grpc.StatusCode` name of a tonic code, for example `StatusCode.UNAVAILABLE`.
pub fn status_code_name(code: Code) -> String {
    let debug = format!("{code:?}");
    let mut name = String::from("StatusCode.");
    for (index, character) in debug.chars().enumerate() {
        if index > 0 && character.is_ascii_uppercase() {
            name.push('_');
        }
        name.push(character.to_ascii_uppercase());
    }
    name
}

/// A [`PacketTransport`] over a tonic channel.
#[derive(Debug)]
pub struct GrpcTransport {
    runtime: tokio::runtime::Runtime,
    endpoint: ReporterEndpoint,
    client: Option<TelemetryServiceClient<Channel>>,
}

impl GrpcTransport {
    /// A transport to `endpoint`. Nothing connects until the first packet.
    pub fn new(endpoint: ReporterEndpoint) -> Result<Self, ReporterError> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        Ok(Self { runtime, endpoint, client: None })
    }
}

fn unavailable() -> DeliveryFailure {
    DeliveryFailure::Rpc { code: status_code_name(Code::Unavailable) }
}

async fn connect(endpoint: &ReporterEndpoint, timeout: Duration) -> Result<TelemetryServiceClient<Channel>, DeliveryFailure> {
    let channel = match &endpoint.channel {
        ReporterChannel::Plaintext => {
            let builder = Endpoint::from_shared(format!("http://{}", endpoint.target))
                .map_err(|error| DeliveryFailure::Other { class: format!("{error:?}") })?
                .connect_timeout(timeout);
            builder.connect().await.map_err(|_| unavailable())?
        }
        ReporterChannel::MutualTls(spec) => tokio::time::timeout(timeout, privoke_transport::client::connect(&endpoint.target, spec))
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?,
    };
    Ok(TelemetryServiceClient::new(channel))
}

impl PacketTransport for GrpcTransport {
    fn send(&mut self, packet: &TelemetryPacket, timeout: Duration) -> Result<bool, DeliveryFailure> {
        let Self { runtime, endpoint, client } = self;
        runtime.block_on(async {
            if client.is_none() {
                *client = Some(connect(endpoint, timeout).await?);
            }
            let Some(active) = client.as_mut() else {
                return Err(unavailable());
            };
            let mut request = Request::new(packet.clone());
            request.set_timeout(timeout);
            match tokio::time::timeout(timeout, active.record_telemetry(request)).await {
                Ok(Ok(response)) => Ok(response.into_inner().accepted),
                Ok(Err(status)) => {
                    // A broken connection is replaced on the next packet; an application answer keeps the channel.
                    if matches!(status.code(), Code::Unavailable | Code::Unknown | Code::Cancelled | Code::DeadlineExceeded) {
                        *client = None;
                    }
                    Err(DeliveryFailure::Rpc { code: status_code_name(status.code()) })
                }
                Err(_elapsed) => {
                    *client = None;
                    Err(DeliveryFailure::Rpc { code: status_code_name(Code::DeadlineExceeded) })
                }
            }
        })
    }
}
