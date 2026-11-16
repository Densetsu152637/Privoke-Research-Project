//! A minimal cloud-shaped binary: the five fail-closed flags, a health service, and the full transport stack.
//!
//! It exists to test fail-closed startup and to smoke-test mutual TLS from other languages. It admits only the
//! installations named with `--admit-installation`.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use privoke_transport::startup::CloudTlsArgs;
use privoke_transport::{AuthLayer, LimiterKey, Limits, Policy, Registry, Role, SecureListener, SharedRegistry, secure_server};

#[derive(Debug, Parser)]
#[command(name = "privoke-listener-probe")]
struct Args {
    #[command(flatten)]
    tls: CloudTlsArgs,
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: SocketAddr,
    /// Installation UUIDs to admit.
    #[arg(long)]
    admit_installation: Vec<String>,
    /// Milliseconds between credential file polls.
    #[arg(long, default_value_t = 60_000)]
    reload_poll_ms: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let transport = match args.tls.into_config() {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let limits = Limits::default();
    let _reloader = transport.tls.spawn_watcher(Duration::from_millis(args.reload_poll_ms));
    let registry = args.admit_installation.iter().fold(Registry::new(), |registry, uuid| registry.with_installation(uuid));
    let policy = Policy::new().allow("/grpc.health.v1.Health/Check", &[Role::Consumer], LimiterKey::Identity);
    let auth = AuthLayer::new(policy, SharedRegistry::new(registry), limits.rate);
    let listener = match SecureListener::bind(args.listen, transport.tls, limits.clone()).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let Ok(address) = listener.local_addr() else {
        return ExitCode::FAILURE;
    };
    let (_reporter, health) = tonic_health::server::health_reporter();
    println!("listening {address}");
    let served = secure_server(&limits, auth).add_service(health).serve_with_incoming(listener.incoming()).await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
