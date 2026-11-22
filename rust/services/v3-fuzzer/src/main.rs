//! `v3-fuzzer-service`: the experimental V3 fuzzer. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; it exits
//! non-zero before it opens any state or binds a socket if any of them is missing or invalid. There is no insecure mode.
//! The configuration is the environment of `fuzzer_server.py` (see [`privoke_v3_fuzzer::config`]).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use privoke_fuzzer::config::client_tls_from_lookup;
use privoke_transport::startup::CloudTlsArgs;
use privoke_v3_fuzzer::backend::{GrpcCheckpoint, GrpcFit};
use privoke_v3_fuzzer::config::{V3Settings, load_policy, load_schedules};
use privoke_v3_fuzzer::cycle::{Engine, EngineParts};
use privoke_v3_fuzzer::server::{self, limits_for};
use privoke_v3_fuzzer::service::V3Handler;
use privoke_v3_fuzzer::source::Closure;
use privoke_v3_fuzzer::{Error, Result};

#[derive(Debug, Parser)]
#[command(name = "v3-fuzzer-service", version, about = "PriVoke experimental V3 fuzzer service")]
struct Args {
    #[command(flatten)]
    tls: CloudTlsArgs,
    /// Seconds between credential and registry file polls.
    #[arg(long, default_value_t = 30)]
    reload_poll_secs: u64,
}

fn log(message: std::fmt::Arguments<'_>) {
    eprintln!("{message}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match serve(args).await {
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
    let settings = V3Settings::from_env()?;
    let lookup = |name: &str| std::env::var(name).ok();
    let runtime_tls =
        client_tls_from_lookup(&settings.runtime_target, "V3_RUNTIME_TLS_SERVER_NAME", lookup).map_err(|error| Error(error.0))?;
    let checkpoint_tls =
        client_tls_from_lookup(&settings.checkpoint_target, "V3_CHECKPOINT_TLS_SERVER_NAME", lookup).map_err(|error| Error(error.0))?;
    let (policy, _) = load_policy(&settings.policy_file)?;
    let schedules = load_schedules(&settings)?;
    let fit = Arc::new(GrpcFit::new(settings.runtime_target.clone(), runtime_tls));
    let checkpoint = Arc::new(GrpcCheckpoint::new(settings.checkpoint_target.clone(), checkpoint_tls));
    let parts = EngineParts {
        policy,
        schedules,
        directory: settings.directory.clone(),
        fit_timeout: settings.fit_timeout,
        closure: Closure::Root(settings.source_root.clone()),
    };
    let engine = Arc::new(Engine::new(parts, fit, checkpoint).await?);
    let listen = SocketAddr::new(settings.bind, settings.port);
    let limits = limits_for(settings.request_timeout);
    let mut handle =
        server::start(listen, V3Handler::new(engine), transport, limits, Duration::from_secs(args.reload_poll_secs.max(1))).await?;
    log(format_args!("privoke-v3-fuzzer awaiting training requests port={} sampler={}", settings.port, settings.sampler.name()));
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
