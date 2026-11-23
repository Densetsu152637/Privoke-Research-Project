//! The `healthcheck` subcommand (stage V3-R7): one mutual-TLS `Health` call to the listener, for the container health check of a
//! distroless image. The listener has no plaintext mode, so the probe presents a registered service identity and verifies the
//! server certificate against the server CA.

use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::proto::experimental_v3::HealthRequest;
use privoke_contracts::proto::experimental_v3::training_service_client::TrainingServiceClient;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;

use crate::error::{Error, Result};

/// Where and how to probe.
#[derive(Debug, Clone, clap::Args)]
pub struct HealthcheckArgs {
    /// `host:port` of the listener. Defaults to loopback on `V3_PORT`.
    #[arg(long)]
    pub address: Option<String>,
    /// CA bundle that signed the server certificate (`V3_HEALTHCHECK_SERVER_CA`).
    #[arg(long)]
    pub server_ca: Option<PathBuf>,
    /// Client certificate of a registered service identity (`V3_HEALTHCHECK_CERT`).
    #[arg(long)]
    pub client_cert: Option<PathBuf>,
    /// Its private key (`V3_HEALTHCHECK_KEY`).
    #[arg(long)]
    pub client_key: Option<PathBuf>,
    /// The name the server certificate carries (`V3_HEALTHCHECK_SERVER_NAME`, default `localhost`).
    #[arg(long)]
    pub server_name: Option<String>,
}

/// The probe's resolved inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// `host:port`.
    pub address: String,
    /// The TLS client configuration.
    pub tls: ClientTlsConfig,
}

fn required(flag: &str, value: Option<PathBuf>, variable: &str) -> Result<PathBuf> {
    value
        .or_else(|| std::env::var_os(variable).filter(|text| !text.is_empty()).map(PathBuf::from))
        .ok_or_else(|| Error(format!("missing {flag} (or {variable})")))
}

impl HealthcheckArgs {
    /// Resolve flags and environment. `default_port` is the listener's `V3_PORT`.
    pub fn resolve(self, default_port: u16) -> Result<Probe> {
        let server_ca = required("--server-ca", self.server_ca, "V3_HEALTHCHECK_SERVER_CA")?;
        let cert = required("--client-cert", self.client_cert, "V3_HEALTHCHECK_CERT")?;
        let key = required("--client-key", self.client_key, "V3_HEALTHCHECK_KEY")?;
        let server_name = self
            .server_name
            .or_else(|| std::env::var("V3_HEALTHCHECK_SERVER_NAME").ok().filter(|text| !text.is_empty()))
            .unwrap_or_else(|| "localhost".to_string());
        let address = self.address.unwrap_or_else(|| format!("127.0.0.1:{default_port}"));
        Ok(Probe { address, tls: ClientTlsConfig { server_ca, identity: Some((cert, key)), server_name } })
    }
}

/// The listener port the probe defaults to: `V3_PORT`, else the service default.
pub fn listener_port() -> u16 {
    std::env::var("V3_PORT").ok().and_then(|text| text.trim().parse().ok()).unwrap_or(crate::config::DEFAULT_PORT)
}

/// Run the probe. Succeeds only when the runtime reports `ready`.
pub async fn run(args: HealthcheckArgs) -> Result<()> {
    let probe = args.resolve(listener_port())?;
    let call = async {
        let channel = connect(&probe.address, &probe.tls).await.map_err(|error| Error(error.to_string()))?;
        let response =
            TrainingServiceClient::new(channel).health(HealthRequest {}).await.map_err(|error| Error(error.to_string()))?.into_inner();
        if !response.ready {
            return Err(Error(format!("the runtime is not ready (role {:?})", response.role)));
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), call).await.map_err(|_| Error("health probe timed out".to_string()))?
}
