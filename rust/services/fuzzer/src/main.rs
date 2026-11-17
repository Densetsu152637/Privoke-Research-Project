//! `fuzzer-service`: the cloud binary. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; it exits
//! non-zero before it opens any state or binds a socket if any of them is missing or invalid. There is no insecure mode.
//! Subcommands: `train` (one cycle against a running fuzzer) and `healthcheck` (one mutual-TLS `Health` call).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_fuzzer::cli::{HealthcheckArgs, TrainArgs, run_healthcheck, run_train};
use privoke_fuzzer::config::{FuzzerConfig, client_tls_from_lookup};
use privoke_fuzzer::cycle::Engine;
use privoke_fuzzer::runtime::GrpcRuntime;
use privoke_fuzzer::server;
use privoke_fuzzer::service::FuzzerHandler;
use privoke_fuzzer::updates::GrpcUpdates;
use privoke_fuzzer::{Error, Result, SERVICE_NAME};
use privoke_transport::startup::CloudTlsArgs;

#[derive(Debug, Parser)]
#[command(name = "fuzzer-service", version, about = "PriVoke fuzzer service")]
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
    /// Request one training cycle from a running fuzzer and print the response.
    Train(TrainArgs),
    /// Probe the listener once over mutual TLS and exit 0 only when it reports SERVING.
    Healthcheck(HealthcheckArgs),
}

fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let outcome = match args.command {
        Some(Command::Train(train)) => match run_train(train).await {
            Ok(true) => Ok(()),
            Ok(false) => return ExitCode::FAILURE,
            Err(error) => Err(error),
        },
        Some(Command::Healthcheck(probe)) => {
            let port = FuzzerConfig::from_env().map_or(50053, |config| config.port);
            run_healthcheck(probe, port).await.map_err(|error| Error(format!("healthcheck failed: {error}")))
        }
        None => serve(args.tls, args.reload_poll_secs).await,
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

async fn serve(tls: CloudTlsArgs, poll_secs: u64) -> Result<()> {
    // Authentication inputs first: nothing is opened or bound until the verifier exists.
    let transport = tls.into_config().map_err(|error| Error(error.to_string()))?;
    let config = FuzzerConfig::from_env()?;
    let lookup = |name: &str| std::env::var(name).ok();
    let runtime_tls = client_tls_from_lookup(&config.privoke_runtime_target, "PRIVOKE_RUNTIME_TLS_SERVER_NAME", lookup)?;
    let updates_tls = client_tls_from_lookup(&config.param_update_target, "PARAM_UPDATE_TLS_SERVER_NAME", lookup)?;
    let timeout = Duration::try_from_secs_f64(config.timeout_seconds)
        .map_err(|_| Error("FUZZ_TIMEOUT_SECONDS must be finite and positive.".to_string()))?;
    let runtime = Arc::new(GrpcRuntime::new(config.privoke_runtime_target.clone(), runtime_tls, timeout));
    let updates = Arc::new(GrpcUpdates::new(config.param_update_target.clone(), updates_tls, timeout));
    let limits = server::limits_for(&config);
    let listen = SocketAddr::new(config.bind, config.port);
    let (model_id, port) = (config.model_id.clone(), config.port);
    let engine = Arc::new(Engine::new(config, runtime, updates));
    let mut handle = server::start(listen, FuzzerHandler::new(engine), transport, limits, Duration::from_secs(poll_secs.max(1))).await?;
    log(format_args!("{SERVICE_NAME} awaiting training requests port={port} model={model_id}"));
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
