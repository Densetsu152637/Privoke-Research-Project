//! `analysis-service`: the quarantined analysis microservice. Requires `--cert`, `--key`, `--client-ca`, `--crl` and
//! `--registry`; it exits non-zero before binding anything if any of them is missing or invalid. There is no insecure
//! mode.

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_analysis::config::AnalysisConfig;
use privoke_analysis::healthcheck::{self, HealthcheckArgs};
use privoke_analysis::server;
use privoke_analysis::util::log;
use privoke_transport::startup::CloudTlsArgs;

#[derive(Debug, Parser)]
#[command(name = "analysis-service", version, about = "PriVoke quarantined analysis service")]
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
    /// Probe the listener once over mutual TLS and exit 0 only when it reports SERVING.
    Healthcheck(HealthcheckArgs),
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    if let Some(Command::Healthcheck(probe)) = args.command {
        let port =
            std::env::var("ANALYSIS_PORT").ok().and_then(|value| value.parse().ok()).unwrap_or(privoke_analysis::config::DEFAULT_PORT);
        return match healthcheck::run(probe, port).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log(format_args!("healthcheck failed: {error}"));
                ExitCode::FAILURE
            }
        };
    }
    match serve(args.tls, args.reload_poll_secs).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

async fn serve(tls: CloudTlsArgs, poll_secs: u64) -> privoke_analysis::Result<()> {
    let config = AnalysisConfig::from_env()?;
    // Authentication inputs first: nothing is fetched, started or bound until the verifier exists.
    let transport = tls.into_config().map_err(|error| privoke_analysis::Error(error.to_string()))?;
    let bind = (config.bind, config.port).into();
    let mut handle = server::start(&config, bind, transport, Duration::from_secs(poll_secs.max(1))).await?;
    log(format_args!(
        "analysis-service listening addr={} allowed={:?} default_model={:?}",
        handle.addr, config.allowed_services, config.default_model_id
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
