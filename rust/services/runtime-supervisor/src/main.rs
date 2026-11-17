//! `privoke-supervisor`: the workstation runtime controller.
//!
//! | Command | Does |
//! | --- | --- |
//! | (none), `native-host` | The native-messaging host on stdio: owns the sandboxed worker pool, opens no port. A browser starts it with its own arguments (the calling origin), which are ignored. |
//! | `enrol`, `renew`, `install-cert`, `status` | The installation side of enrolment, on `privoke_pki::client`. |
//! | `fetch-model` | Download and verify the standard V3 package into the user cache. |

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use privoke_supervisor::channel::ModelEndpoint;
use privoke_supervisor::config::{self, Environment};
use privoke_supervisor::controller::{Controller, run_session};
use privoke_supervisor::credentials::{self, InstallFiles};
use privoke_supervisor::fetch::{FetchConfig, Fetcher, StandardAdmission};
use privoke_supervisor::health::EndpointHealth;
use privoke_supervisor::native_host;
use privoke_supervisor::runtime::RuntimeController;
use privoke_supervisor::telemetry::Telemetry;
use privoke_supervisor::worker::WorkerSettings;
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
    let mut environment = config::process_environment();
    let root = repository_root(&environment)?;
    config::load_runtime_environment(&root.join("extension").join("client-runtime"), &mut environment);
    #[allow(unused_mut)]
    let mut settings = WorkerSettings::from_environment(&environment, &root)?;
    #[cfg(feature = "test-helpers")]
    apply_test_overrides(&mut settings, &environment);
    let health_timeout = config::positive_seconds(&environment, "MODEL_STREAMING_HEALTH_TIMEOUT_SECONDS", 3.0)?;
    // The Rust analysis worker serves what it claims (see `routing`); the Python worker serves the rest. It is
    // configured only when PRIVOKE_RUNTIME_ANALYSIS_ENGINE=rust.
    let rust_worker = WorkerSettings::rust_from_environment(&environment, &root)?;
    let mut controller_runtime = RuntimeController::new(settings, environment.clone());
    if let Some(rust_worker) = rust_worker {
        controller_runtime = controller_runtime.with_rust_worker(rust_worker);
    }
    let runtime = Arc::new(controller_runtime);
    let health = Arc::new(EndpointHealth::new(Arc::clone(&runtime), health_timeout));
    let mut controller = Controller::new(runtime, health);
    // The controller owns the telemetry reporter (the worker has none). It is off unless configured; a configuration
    // that cannot start a reporter leaves telemetry off and the controller running.
    match Telemetry::from_environment(&environment) {
        Ok(Some(telemetry)) => controller = controller.with_telemetry(telemetry),
        Ok(None) => {}
        Err(message) => eprintln!("Telemetry is off: {message}"),
    }
    // The pool starts its workers from this runtime's threads; they live as long as the session does.
    let threads = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|error| error.to_string())?;
    threads.block_on(run_session(io::stdin(), io::stdout(), controller)).map_err(|error| error.to_string())
}

/// Replaces the worker program, so tests can run the controller against a stand-in. Compiled only with the
/// `test-helpers` feature; a normal build has no way to change the program it starts.
#[cfg(feature = "test-helpers")]
fn apply_test_overrides(settings: &mut WorkerSettings, environment: &Environment) {
    if let Some(text) = environment.get("PRIVOKE_TEST_WORKER_COMMAND") {
        let mut parts = text.split('\u{1f}').filter(|part| !part.is_empty());
        if let Some(program) = parts.next() {
            settings.command = PathBuf::from(program);
            settings.args = parts.map(Into::into).collect();
        }
    }
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
