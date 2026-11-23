//! `v3-runtime-service`: the experimental V3 runtime. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; it exits
//! non-zero before it opens any state or binds a socket if any of them is missing or invalid. There is no insecure mode.
//! The configuration is the environment of `runtime_server.py` (see [`privoke_v3_runtime::config`]).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_fuzzer::config::client_tls_from_lookup;
use privoke_transport::startup::CloudTlsArgs;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_runtime::assets::Admission;
use privoke_v3_runtime::checkpoint::GrpcCheckpoint;
use privoke_v3_runtime::config::RuntimeSettings;
use privoke_v3_runtime::fit::ScheduleSources;
use privoke_v3_runtime::server::{self, limits_for};
use privoke_v3_runtime::service::{Runtime, RuntimeParts, V3RuntimeHandler};
use privoke_v3_runtime::{Error, Result};

#[derive(Debug, Parser)]
#[command(name = "v3-runtime-service", version, about = "PriVoke experimental V3 runtime service")]
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
    /// Probe the listener once over mutual TLS and exit 0 only when it reports ready.
    Healthcheck(privoke_v3_runtime::healthcheck::HealthcheckArgs),
}

fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let outcome = match args.command {
        Some(Command::Healthcheck(probe)) => privoke_v3_runtime::healthcheck::run(probe).await,
        None => serve(args).await,
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: Args) -> Result<()> {
    // Authentication inputs first: nothing is opened or bound until the verifier exists.
    let transport = args.tls.into_config().map_err(|error| Error(error.to_string()))?;
    let settings = RuntimeSettings::from_env()?;
    let lookup = |name: &str| std::env::var(name).ok();
    let checkpoint_tls =
        client_tls_from_lookup(&settings.checkpoint_target, "V3_CHECKPOINT_TLS_SERVER_NAME", lookup).map_err(|error| Error(error.0))?;
    let checkpoint = Arc::new(GrpcCheckpoint::new(settings.checkpoint_target.clone(), checkpoint_tls));
    let parts = RuntimeParts {
        directory: settings.directory.clone(),
        threads: settings.threads,
        closure: Closure::Root(settings.source_root.clone()),
        admission: Admission::Pinned,
        schedules: ScheduleSources {
            root: settings.source_root.clone(),
            audience: settings.audience_manifest_path.clone().zip(settings.audience_manifest_sha256.clone()),
        },
    };
    let runtime = Arc::new(Runtime::new(parts, checkpoint).await?);
    let listen = SocketAddr::new(settings.bind, settings.port);
    let limits = limits_for(settings.request_timeout);
    let mut handle =
        server::start(listen, V3RuntimeHandler::new(runtime), transport, limits, Duration::from_secs(args.reload_poll_secs.max(1))).await?;
    log(format_args!("privoke-v3-runtime awaiting requests port={}", settings.port));
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
