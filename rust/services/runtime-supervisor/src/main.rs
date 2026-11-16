//! `privoke-supervisor`: the workstation runtime supervisor.
//!
//! | Command | Does |
//! | --- | --- |
//! | (none), `native-host` | The native-messaging host on stdio. A browser starts it with its own arguments (the calling origin), which are ignored. |
//! | `serve` | The long-lived supervisor: the runtime child and the loopback control service. |
//! | `enrol`, `renew`, `install-cert`, `status` | The installation side of enrolment, on `privoke_pki::client`. |
//! | `fetch-model` | Download and verify the standard V3 package into the user cache. |

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::config::{self, Environment};
use privoke_supervisor::control::{ControlService, EndpointHealth, serve_loopback};
use privoke_supervisor::credentials::{self, InstallFiles};
use privoke_supervisor::fetch::{FetchConfig, Fetcher, StandardAdmission};
use privoke_supervisor::native_host::{self, HostConfig};
use privoke_supervisor::process::{DEFAULT_RUNTIME_PORT, OsLauncher, RuntimeProcessSupervisor, SupervisorSettings};
use time::OffsetDateTime;

#[derive(Debug, Parser)]
#[command(name = "privoke-supervisor", version, about = "PriVoke workstation runtime supervisor", args_conflicts_with_subcommands = true)]
struct Args {
    /// What a browser passes to a native host (the calling origin and so on). Ignored.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    launch: Vec<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the native-messaging host on stdio.
    NativeHost {
        /// What a browser passes (the calling origin and so on). Ignored.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        launch: Vec<String>,
    },
    /// Run the supervisor: the runtime child and the loopback control service.
    Serve,
    /// Create the installation id, key and CSR. Send the CSR, which is public, to the operator.
    Enrol {
        /// Credential directory (default: the per-user PriVoke credential directory).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Create a renewal key and CSR under the same installation id.
    Renew {
        /// Credential directory.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Store the certificate the operator returned, after checking it against the local key.
    InstallCert {
        /// Credential directory.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The certificate the operator signed.
        #[arg(long)]
        cert: PathBuf,
        /// The CA that signed the server certificate.
        #[arg(long)]
        server_ca: Option<PathBuf>,
        /// The shared telemetry reporter certificate.
        #[arg(long, requires = "reporter_key")]
        reporter_cert: Option<PathBuf>,
        /// The shared telemetry reporter key.
        #[arg(long, requires = "reporter_cert")]
        reporter_key: Option<PathBuf>,
    },
    /// Show when the certificate expires and what stops working then. Reads local files only.
    Status {
        /// Credential directory.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Download the standard V3 package over mutual TLS and verify it into the user cache.
    FetchModel {
        /// `latest` or a model id such as `privoke-v3-balanced`.
        #[arg(long, default_value = "latest")]
        model_id: String,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    let outcome = match args.command {
        None | Some(Command::NativeHost { .. }) => run_native_host(),
        Some(Command::Serve) => run_serve(),
        Some(Command::Enrol { dir }) => credential_command(dir, |dir| credentials::enrol(dir).map_err(|e| e.to_string())),
        Some(Command::Renew { dir }) => credential_command(dir, |dir| credentials::renew(dir).map_err(|e| e.to_string())),
        Some(Command::InstallCert { dir, cert, server_ca, reporter_cert, reporter_key }) => credential_command(dir, |dir| {
            let files = InstallFiles { server_ca, reporter: reporter_cert.zip(reporter_key) };
            credentials::install_cert(dir, &cert, &files, OffsetDateTime::now_utc()).map_err(|e| e.to_string())
        }),
        Some(Command::Status { dir }) => run_status(dir),
        Some(Command::FetchModel { model_id }) => run_fetch(&model_id),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn credential_command(dir: Option<PathBuf>, action: impl FnOnce(&Path) -> Result<String, String>) -> Result<(), String> {
    let dir = dir.unwrap_or_else(|| config::credential_dir(&config::process_environment()));
    println!("{}", action(&dir)?);
    Ok(())
}

fn run_status(dir: Option<PathBuf>) -> Result<(), String> {
    let dir = dir.unwrap_or_else(|| config::credential_dir(&config::process_environment()));
    let status = credentials::status(&dir, OffsetDateTime::now_utc()).map_err(|error| error.to_string())?;
    println!("{}", status.message);
    if credentials::needs_renewal(&status) {
        eprintln!("action needed: renew");
    }
    Ok(())
}

/// Where the repository (or installed tree) that holds `extension/client-runtime` is.
fn repository_root(environment: &Environment) -> Result<PathBuf, String> {
    if let Some(configured) = environment.get("PRIVOKE_REPOSITORY_ROOT").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return std::path::absolute(configured).map_err(|error| error.to_string());
    }
    let from_exe = std::env::current_exe().ok().and_then(|exe| native_host::find_repository_root(&exe));
    let from_cwd = std::env::current_dir().ok().and_then(|cwd| native_host::find_repository_root(&cwd));
    from_exe
        .or(from_cwd)
        .ok_or_else(|| "Set PRIVOKE_REPOSITORY_ROOT: the client runtime (extension/client-runtime) was not found.".to_string())
}

fn run_native_host() -> Result<(), String> {
    let environment = config::process_environment();
    let root = repository_root(&environment).ok();
    let entry = std::env::current_exe().map_err(|error| error.to_string())?;
    let log = native_host::default_log_path(environment.get("PRIVOKE_SUPERVISOR_LOG").map(String::as_str));
    #[allow(unused_mut)]
    let mut host = HostConfig::standard(entry, root, log);
    #[cfg(feature = "test-helpers")]
    apply_test_overrides(&mut host, &environment);
    let (stdin, stdout) = (io::stdin(), io::stdout());
    native_host::serve(&mut stdin.lock(), &mut stdout.lock(), &host).map_err(|error| error.to_string())
}

/// Ports, entry and timeout overrides so the transcript replay can run beside a real installation. Compiled only
/// with the `test-helpers` feature; a normal build has no way to move the ports or change the program it starts.
#[cfg(feature = "test-helpers")]
fn apply_test_overrides(host: &mut HostConfig, environment: &Environment) {
    let number = |name: &str| environment.get(name).and_then(|value| value.parse::<u64>().ok());
    if let Some(port) = number("PRIVOKE_TEST_HOST_BRIDGE_PORT").and_then(|v| u16::try_from(v).ok()) {
        host.bridge_port = port;
    }
    if let Some(port) = number("PRIVOKE_TEST_HOST_CONTROL_PORT").and_then(|v| u16::try_from(v).ok()) {
        host.control_port = port;
    }
    if let Some(entry) = environment.get("PRIVOKE_TEST_HOST_ENTRY") {
        host.supervisor_entry = PathBuf::from(entry);
    }
    if let Some(arguments) = environment.get("PRIVOKE_TEST_HOST_ARGS") {
        host.supervisor_args = arguments.split('\u{1f}').filter(|part| !part.is_empty()).map(Into::into).collect();
    }
    if let Some(seconds) = number("PRIVOKE_TEST_HOST_TIMEOUT_SECONDS") {
        host.startup_timeout = Duration::from_secs(seconds);
    }
}

fn run_serve() -> Result<(), String> {
    let mut environment = config::process_environment();
    let root = repository_root(&environment)?;
    let runtime_root = root.join("extension").join("client-runtime");
    config::load_runtime_environment(&runtime_root, &mut environment);

    let runtime_port = u16::try_from(config::positive_int(&environment, "PRIVOKE_LOCAL_RUNTIME_PORT", u64::from(DEFAULT_RUNTIME_PORT))?)
        .map_err(|_| "PRIVOKE_LOCAL_RUNTIME_PORT is not a port.".to_string())?;
    let control_port = u16::try_from(config::positive_int(&environment, "PRIVOKE_CONTROL_GRPC_PORT", 50056)?)
        .map_err(|_| "PRIVOKE_CONTROL_GRPC_PORT is not a port.".to_string())?;
    let health_timeout = config::positive_seconds(&environment, "MODEL_STREAMING_HEALTH_TIMEOUT_SECONDS", 3.0)?;
    let start_timeout = config::positive_seconds(&environment, "PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS", 30.0)?;
    let stop_timeout = config::positive_seconds(&environment, "PRIVOKE_RUNTIME_STOP_TIMEOUT_SECONDS", 10.0)?;
    let start_enabled = config::boolean(&environment, "PRIVOKE_RUNTIME_START_ENABLED", true)?;

    // The runtime's argv is fixed. Only a test build can replace it.
    #[allow(unused_mut)]
    let mut command: Option<Vec<String>> = None;
    #[cfg(feature = "test-helpers")]
    if let Some(text) = environment.get("PRIVOKE_TEST_RUNTIME_COMMAND") {
        command = Some(text.split('\u{1f}').map(str::to_string).collect());
    }
    let mut settings = SupervisorSettings::new(&runtime_root, environment, runtime_port, command);
    settings.startup_timeout = start_timeout;
    settings.stop_timeout = stop_timeout;
    let supervisor = Arc::new(RuntimeProcessSupervisor::new(settings, Box::new(OsLauncher)));

    if start_enabled {
        let status = supervisor.start().map_err(|error| error.to_string())?;
        println!("{}", status.message);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|error| error.to_string())?;
    let outcome = runtime.block_on(async {
        let service = ControlService::new(Arc::clone(&supervisor), Arc::new(EndpointHealth::new(Arc::clone(&supervisor), health_timeout)));
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], control_port));
        let (bound, listening) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(serve_loopback(address, service, bound, shutdown_signal()));
        if let Ok(local) = listening.await {
            println!("PriVoke runtime supervisor listening on {local}");
            let _ = io::stdout().flush();
        }
        server.await.map_err(|error| error.to_string())?.map_err(|error| error.to_string())
    });
    // Stop the child on every exit path; the confinement also stops it if this process is killed instead.
    let stopped = supervisor.stop();
    outcome?;
    stopped.map(|_| ()).map_err(|error| error.to_string())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn run_fetch(model_id: &str) -> Result<(), String> {
    let mut environment = config::process_environment();
    if let Ok(root) = repository_root(&environment) {
        config::load_runtime_environment(&root.join("extension").join("client-runtime"), &mut environment);
    }
    let endpoint = ModelEndpoint::from_environment(&environment).map_err(|error| error.to_string())?;
    let consumer_id = std::fs::read_to_string(config::credential_dir(&environment).join("installation.id"))
        .map(|text| text.trim().to_string())
        .unwrap_or_default();
    let download_timeout = config::positive_seconds(&environment, "MODEL_PACKAGE_TIMEOUT_SECONDS", 120.0)?;
    let rpc_timeout = config::positive_seconds(&environment, "MODEL_STREAMING_TIMEOUT_SECONDS", 10.0)?;
    let fetch = FetchConfig { consumer_id, rpc_timeout, download_timeout, cache_root: config::cache_root(&environment) };
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|error| error.to_string())?;
    let package = runtime.block_on(async {
        let channel = endpoint.connect(Duration::from_secs(10)).await.map_err(|error| error.to_string())?;
        Fetcher::new().fetch(channel, &endpoint.target, model_id, &StandardAdmission, &fetch).await.map_err(|error| error.to_string())
    })?;
    match package {
        Some(package) => {
            println!("model_id={}\nmanifest_sha256={}\ndirectory={}", package.model_id, package.pin, package.directory.display());
            Ok(())
        }
        None => Err("The server answered with a legacy model; this command fetches standard V3 packages only.".into()),
    }
}
