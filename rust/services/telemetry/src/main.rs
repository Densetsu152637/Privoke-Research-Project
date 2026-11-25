//! `telemetry-service`: the cloud binary. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; it
//! exits non-zero before binding anything if any of them is missing or invalid, and it also refuses an unusable
//! database. There is no insecure mode.

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_telemetry::config::ServiceConfig;
use privoke_telemetry::daily::DailyCap;
use privoke_telemetry::healthcheck::{self, HealthcheckArgs};
use privoke_telemetry::server::{self, Listen};
use privoke_telemetry::service::TelemetryCollector;
use privoke_telemetry::storage::TelemetryStore;
use privoke_telemetry::util::log;
use privoke_telemetry::{Error, Result, SERVICE_NAME};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{Limits, RateLimit};

#[derive(Debug, Parser)]
#[command(name = "telemetry-service", version, about = "PriVoke telemetry service")]
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

async fn serve(tls: CloudTlsArgs, poll_secs: u64, config: ServiceConfig) -> Result<()> {
    // Authentication inputs first: nothing is opened or bound until the verifier exists.
    let transport = tls.into_config().map_err(|error| Error(error.to_string()))?;
    let store = TelemetryStore::open(&config.database_path).map_err(|error| Error(error.to_string()))?;
    let service = TelemetryCollector::new(store, DailyCap::new(config.daily_cap));
    let listen = Listen { public: (config.bind, config.public_port).into(), internal: (config.bind, config.internal_port).into() };
    let limits = Limits {
        max_message_bytes: config.max_message_bytes,
        rate: RateLimit { per_second: config.rate.per_second, burst: config.rate.burst },
        ..Limits::default()
    };
    let mut handle = server::start(listen, service, transport, limits, Duration::from_secs(poll_secs.max(1))).await?;
    // Ports only: a listening line must not carry an address a peer could be matched with.
    log(format_args!(
        "{SERVICE_NAME} listening public_port={} internal_port={} daily_cap_per_source={}",
        handle.public_addr.port(),
        handle.internal_addr.port(),
        config.daily_cap
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
