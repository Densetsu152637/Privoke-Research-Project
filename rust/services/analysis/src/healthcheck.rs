//! The `healthcheck` subcommand: one mutual-TLS `Health` call to this service, for the container health check.
//!
//! The service has no plaintext listener, so the probe presents a registered service identity that this service admits
//! (the container's own service certificate) and verifies the server certificate against the server CA.

use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::proto::v1::RuntimeHealthRequest;
use privoke_contracts::proto::v1::privoke_runtime_service_client::PrivokeRuntimeServiceClient;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;

use crate::error::{Error, Result};
use crate::fail;
use crate::service::SERVICE_NAME;

/// Where and how to probe.
#[derive(Debug, Clone, clap::Args)]
pub struct HealthcheckArgs {
    /// `host:port` of the service. Defaults to loopback on `ANALYSIS_PORT` (50054).
    #[arg(long)]
    pub address: Option<String>,
    /// CA bundle that signed the server certificate (`ANALYSIS_HEALTHCHECK_SERVER_CA`).
    #[arg(long)]
    pub server_ca: Option<PathBuf>,
    /// Client certificate of an admitted service identity (`ANALYSIS_HEALTHCHECK_CERT`).
    #[arg(long)]
    pub client_cert: Option<PathBuf>,
    /// Its private key (`ANALYSIS_HEALTHCHECK_KEY`).
    #[arg(long)]
    pub client_key: Option<PathBuf>,
    /// The name the server certificate carries (`ANALYSIS_HEALTHCHECK_SERVER_NAME`, default `localhost`).
    #[arg(long)]
    pub server_name: Option<String>,
}

fn required(flag: &str, value: Option<PathBuf>, variable: &str) -> Result<PathBuf> {
    value
        .or_else(|| std::env::var_os(variable).filter(|text| !text.is_empty()).map(PathBuf::from))
        .ok_or_else(|| Error(format!("missing {flag} (or {variable})")))
}

/// Runs the probe. Succeeds only for `service == "privoke-analysis-service"` and `status == "SERVING"`.
pub async fn run(args: HealthcheckArgs, default_port: u16) -> Result<()> {
    let server_ca = required("--server-ca", args.server_ca, "ANALYSIS_HEALTHCHECK_SERVER_CA")?;
    let cert = required("--client-cert", args.client_cert, "ANALYSIS_HEALTHCHECK_CERT")?;
    let key = required("--client-key", args.client_key, "ANALYSIS_HEALTHCHECK_KEY")?;
    let server_name = args
        .server_name
        .or_else(|| std::env::var("ANALYSIS_HEALTHCHECK_SERVER_NAME").ok().filter(|text| !text.is_empty()))
        .unwrap_or_else(|| "localhost".to_string());
    let address = args.address.unwrap_or_else(|| format!("127.0.0.1:{default_port}"));
    let spec = ClientTlsConfig { server_ca, identity: Some((cert, key)), server_name };
    let probe = async {
        let channel = connect(&address, &spec).await.map_err(|error| Error(error.to_string()))?;
        let response = PrivokeRuntimeServiceClient::new(channel)
            .health(RuntimeHealthRequest {})
            .await
            .map_err(|error| Error(error.to_string()))?
            .into_inner();
        if response.service != SERVICE_NAME || response.status != "SERVING" {
            fail!("unexpected health response service={:?} status={:?}", response.service, response.status);
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), probe).await.map_err(|_| Error("health probe timed out".into()))?
}
