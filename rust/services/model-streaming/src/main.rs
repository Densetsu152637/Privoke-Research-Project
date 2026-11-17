//! `model-streaming-service`: the cloud binary. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`;
//! it exits non-zero before binding anything if any of them is missing or invalid. There is no insecure mode.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_model_streaming::catalog::Catalog;
use privoke_model_streaming::config::ServiceConfig;
use privoke_model_streaming::healthcheck::{self, HealthcheckArgs};
use privoke_model_streaming::releases::{StandardReleases, is_standard_v3};
use privoke_model_streaming::server::{self, Listen};
use privoke_model_streaming::service::ModelService;
use privoke_model_streaming::util::log;
use privoke_transport::Limits;
use privoke_transport::startup::CloudTlsArgs;

#[derive(Debug, Parser)]
#[command(name = "model-streaming-service", version, about = "PriVoke model-streaming service")]
struct Args {
    #[command(flatten)]
    tls: CloudTlsArgs,
    /// Seconds between credential and registry file polls.
    #[arg(long, default_value_t = 30)]
    reload_poll_secs: u64,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe the internal listener once over mutual TLS and exit 0 only when it reports SERVING.
    Healthcheck(HealthcheckArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let config = match ServiceConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            log(format_args!("{error}"));
            return ExitCode::FAILURE;
        }
    };
    if let Some(Command::Healthcheck(probe)) = args.command {
        return match healthcheck::run(probe, config.internal_port).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log(format_args!("healthcheck failed: {error}"));
                ExitCode::FAILURE
            }
        };
    }
    match serve(args.tls, args.reload_poll_secs, config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

async fn serve(tls: CloudTlsArgs, poll_secs: u64, config: ServiceConfig) -> privoke_model_streaming::Result<()> {
    // Authentication inputs first: nothing is read or bound until the verifier exists.
    let transport = tls.into_config().map_err(|error| privoke_model_streaming::Error(error.to_string()))?;
    let mut catalog = Catalog::load(&config.artifact_dir, &config.latest_model_id)
        .map_err(|error| privoke_model_streaming::Error(format!("load model catalog: {error}")))?;
    if is_standard_v3(&config.latest_model_id) {
        catalog.releases = Some(
            StandardReleases::open(&config.release_dir)
                .map_err(|error| privoke_model_streaming::Error(format!("load standard V3 packages: {error}")))?,
        );
    }
    let model_ids = catalog.model_ids();
    let latest = catalog.latest_model_id().to_string();
    let service = ModelService::new(Arc::new(catalog));
    let listen = Listen { public: (config.bind, config.public_port).into(), internal: (config.bind, config.internal_port).into() };
    let mut handle = server::start(listen, service, transport, Limits::default(), Duration::from_secs(poll_secs.max(1))).await?;
    log(format_args!(
        "model-streaming-service listening public={} internal={} latest={latest:?} models={model_ids:?}",
        handle.public_addr, handle.internal_addr
    ));
    tokio::select! {
        result = handle.wait() => result,
        () = stop_signal() => handle.shutdown().await,
    }
}

#[cfg(unix)]
async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn stop_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
