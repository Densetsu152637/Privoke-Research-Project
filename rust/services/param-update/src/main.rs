//! `param-update-service`: the cloud binary. Requires `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`; it
//! exits non-zero before it opens a model or binds a socket if any of them is missing or invalid. There is no insecure
//! mode. Subcommands: `healthcheck` (one mutual-TLS `Health` call) and `bootstrap` (prepare the mutable model).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_model_streaming::contextual::{FULL_ENCODER_STRATEGY, STRATEGY_KEY};
use privoke_param_update::artifact_io;
use privoke_param_update::bootstrap::bootstrap_model;
use privoke_param_update::config::{ServiceConfig, V3Config};
use privoke_param_update::engine::{Engine, no_hook, system_clock};
use privoke_param_update::healthcheck::{self, HealthcheckArgs};
use privoke_param_update::scheduler::{self, FuzzerRequestConfig, GrpcFuzzer};
use privoke_param_update::server;
use privoke_param_update::service::ParamUpdateHandler;
use privoke_param_update::util::log;
use privoke_param_update::v3_policy::{DriftBounds, DriftGate};
use privoke_param_update::v3_publish::{Publisher, no_crash};
use privoke_param_update::v3_store::{ChainObserver, CheckpointHandler, CheckpointStore, CommitObserver, PinnedSources};
use privoke_param_update::{Error, Result, SERVICE_NAME};
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{Limits, RateLimit};

#[derive(Debug, Parser)]
#[command(name = "param-update-service", version, about = "PriVoke parameter-update service")]
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
    /// Prepare the selected mutable model as a full-encoder release (idempotent; run before the service starts).
    Bootstrap,
    /// Print the public key of a publication key file (64 hexadecimal characters of seed) for the client key sets.
    PublicationKey {
        /// The key file (`V3_PUBLICATION_KEY_FILE`).
        #[arg(long)]
        key_file: std::path::PathBuf,
    },
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
    let outcome = match args.command {
        Some(Command::Healthcheck(probe)) => {
            healthcheck::run(probe, config.port).await.map_err(|error| Error(format!("healthcheck failed: {error}")))
        }
        Some(Command::Bootstrap) => bootstrap(&config),
        Some(Command::PublicationKey { key_file }) => publication_key(&key_file),
        None => serve(args.tls, args.reload_poll_secs, config).await,
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(format_args!("{error}"));
            ExitCode::FAILURE
        }
    }
}

fn publication_key(path: &std::path::Path) -> Result<()> {
    let public = privoke_contracts::publication::public_key(&read_seed(path)?).map_err(|error| Error(error.to_string()))?;
    println!("{}", public.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
    Ok(())
}

fn bootstrap(config: &ServiceConfig) -> Result<()> {
    let prepared = bootstrap_model(
        &config.model_artifact_path,
        &config.storage_path,
        &config.model_id,
        config.bootstrap_max_tokens,
        &system_clock(),
        &no_hook(),
    )
    .map_err(|failure| Error(format!("bootstrap failed: {}", failure.detail())))?;
    log(format_args!("{SERVICE_NAME} bootstrap complete model={:?} version={:?}", prepared.typed.model_id, prepared.typed.version));
    Ok(())
}

/// The publication seed: 64 hexadecimal characters in a mounted secret file.
fn read_seed(path: &std::path::Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).map_err(|error| Error(format!("V3 publication key file: {error}")))?;
    let text = text.trim();
    let bytes: Option<Vec<u8>> = (text.len() == 64 && text.is_ascii())
        .then(|| (0..64).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok()).collect::<Option<Vec<u8>>>())
        .flatten();
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error("V3 publication key file must hold 64 hexadecimal characters.".to_string()))
}

/// Open the V3 checkpoint store and admit the configured ORIGINAL packages (the oracle's `CheckpointStore(V3_STORE, V3_INITIAL)`).
fn open_checkpoint(config: &V3Config) -> Result<CheckpointHandler> {
    let sources = PinnedSources::from_root(&config.source_root, config.audience.clone());
    let mut store =
        CheckpointStore::open(&config.store, Arc::new(sources)).map_err(|error| Error(format!("V3 checkpoint store: {error}")))?;
    let mut publisher = None;
    if let Some(publication) = &config.publication {
        let bounds = DriftBounds::load(&publication.drift_bounds).map_err(|error| Error(format!("V3 drift bounds: {error}")))?;
        log(format_args!("V3 drift bounds status={} evidence={}", bounds.status, bounds.evidence_sha256));
        let seed = read_seed(&publication.key_file)?;
        let signer = Arc::new(
            Publisher::new(&publication.root, &publication.key_id, seed, no_crash())
                .map_err(|error| Error(format!("V3 publisher: {error}")))?,
        );
        let observers: Vec<Arc<dyn CommitObserver>> = vec![Arc::new(DriftGate::new(bounds)), signer.clone()];
        store = store.with_observer(Arc::new(ChainObserver::new(observers)));
        publisher = Some(signer);
    }
    for initial in &config.initial {
        store.bootstrap(initial).map_err(|error| Error(format!("V3 checkpoint bootstrap of {}: {error}", initial.display())))?;
    }
    if let Some(signer) = publisher {
        let report = signer.reconcile(&store).map_err(|error| Error(format!("V3 publication reconciliation: {error}")))?;
        log(format_args!("V3 publication reconciled {report:?}"));
    }
    log(format_args!("{SERVICE_NAME} V3 checkpoint store ready directory={}", config.store.display()));
    Ok(CheckpointHandler::new(Arc::new(store)))
}

async fn serve(tls: CloudTlsArgs, poll_secs: u64, config: ServiceConfig) -> Result<()> {
    // Authentication inputs first: nothing is opened or bound until the verifier exists.
    let transport = tls.into_config().map_err(|error| Error(error.to_string()))?;
    let fuzzer = FuzzerRequestConfig::from_env()?;
    let scheduler_client = if fuzzer.prompt_count > 0 {
        let spec = scheduler::client_tls_from_lookup(&fuzzer, |key| std::env::var(key).ok())?;
        Some(GrpcFuzzer::new(fuzzer.target.clone(), spec))
    } else {
        None
    };
    if fuzzer.prompt_count > 0 && fuzzer.train_underlying {
        let loaded = artifact_io::load(&config.model_artifact_path).map_err(|failure| Error(failure.detail()))?;
        if loaded.typed.model_id != config.model_id
            || loaded.typed.metadata().get(STRATEGY_KEY).map(String::as_str) != Some(FULL_ENCODER_STRATEGY)
        {
            return Err(Error(
                "Automatic dual training requires the selected full-capable Tiny artifact; run model bootstrap before readiness."
                    .to_string(),
            ));
        }
    }
    let engine = Arc::new(Engine::with_system_clock(config.engine_config()).map_err(|failure| Error(failure.detail()))?);
    let limits = Limits {
        max_message_bytes: config.max_message_bytes,
        rate: RateLimit { per_second: config.rate.per_second, burst: config.rate.burst },
        ..Limits::default()
    };
    let listen = SocketAddr::new(config.bind, config.port);
    let checkpoint = config.v3.as_ref().map(open_checkpoint).transpose()?;
    let mut handle = server::start_with_checkpoint(
        listen,
        ParamUpdateHandler::new(engine),
        checkpoint,
        transport,
        limits,
        Duration::from_secs(poll_secs.max(1)),
    )
    .await?;
    log(format_args!("{SERVICE_NAME} listening port={} drift_policy={:?}", handle.addr.port(), config.drift));
    let scheduler_task = scheduler_client.map(|client| {
        tokio::spawn(async move {
            if let Err(error) = scheduler::run(&fuzzer, &client).await {
                log(format_args!("training scheduler stopped: {error}"));
            }
        })
    });
    let outcome = tokio::select! {
        result = handle.wait() => result,
        () = stop_signal() => handle.shutdown().await,
    };
    if let Some(task) = scheduler_task {
        task.abort();
    }
    outcome
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
