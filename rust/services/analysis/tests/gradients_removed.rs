//! Stage V3-R8a, goal G5: the three gradient RPCs are `UNIMPLEMENTED` at the public gRPC surface, and no worker is ever
//! invoked for them (there is no Python fallback and no refusal retry).
//!
//! The server is the real [`RuntimeServer`] over a real [`WorkerPool`] of a stand-in W1 worker that appends one line per
//! request frame to a log. A control request first proves that the log records what the pool serves; the three gradient
//! calls then leave it untouched. No model is fetched either: the cache points at an address nothing listens on.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use privoke_analysis::config::ModelSource;
use privoke_analysis::frames::{self, Method};
use privoke_analysis::models::ModelCache;
use privoke_analysis::protocol::WorkerProtocol;
use privoke_analysis::raw::RuntimeServer;
use privoke_analysis::service::{AnalysisService, Rpc, policy};
use privoke_worker_pool::{PoolConfig, WorkerPool};
use tonic::codegen::{Service, http};

const WORKER: &str = env!("CARGO_BIN_EXE_privoke-analysis-test-worker");
const PREFIX: &str = "/privoke.v1.PrivokeRuntimeService/";
const GRADIENTS: [&str; 3] = ["ComputeSemanticGradients", "ComputeUnderlyingModelGradients", "ComputePresenceGradients"];

fn grpc_status(response: &http::Response<tonic::body::Body>) -> i32 {
    response.headers().get("grpc-status").expect("a gRPC status").to_str().unwrap().parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gradient_rpcs_are_unimplemented_and_no_worker_runs_for_them() {
    let directory = tempfile::tempdir().unwrap();
    let log = directory.path().join("requests.log");
    let mut config = PoolConfig::new(WORKER);
    config.args = vec!["--log".into(), log.clone().into()];
    let pool = WorkerPool::start(WorkerProtocol, config).unwrap();
    pool.wait_ready(Duration::from_secs(20)).await.unwrap();

    // The control: a request the pool serves is recorded, so an empty log below means "never invoked", not "not logging".
    let id = pool.next_id();
    pool.submit(id, frames::encode_request(Method::Health, id, 0, &[], b"").unwrap()).await.unwrap();
    let recorded = || std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(recorded(), format!("{}\n", Method::Health as u8));

    let source = ModelSource {
        target: "127.0.0.1:1".into(),
        server_ca: directory.path().join("ca.pem"),
        client_cert: directory.path().join("cert.pem"),
        client_key: directory.path().join("key.pem"),
        server_name: "localhost".into(),
    };
    let cache =
        Arc::new(ModelCache::new(directory.path().join("cache"), source, Duration::from_secs(1), BTreeMap::new(), "privoke-balanced"));
    // With no Rust worker configured every call that is served at all goes to the pool above (the Python slot).
    let service = AnalysisService::new(pool, None, cache, vec!["fuzzer".into()], vec![]);
    let mut server = RuntimeServer::new(service, 1024 * 1024);

    for name in GRADIENTS {
        let path = format!("{PREFIX}{name}");
        assert_eq!(Rpc::from_path(&path), None, "{name} is not a served RPC");
        // A well-formed gradient request with the semantic layer, as the removed fuzzer sent it.
        let request = http::Request::builder()
            .method("POST")
            .uri(path.as_str())
            .header("content-type", "application/grpc")
            .body(tonic::body::Body::default())
            .unwrap();
        let response = server.call(request).await.unwrap();
        assert_eq!(grpc_status(&response), tonic::Code::Unimplemented as i32, "{name}");
    }
    assert_eq!(recorded(), format!("{}\n", Method::Health as u8), "no worker saw a gradient request");

    // The transport policy never lets the three paths past the listener either.
    let policy = policy();
    for name in GRADIENTS {
        assert!(!policy.paths().any(|path| path == format!("{PREFIX}{name}")), "{name} is outside the policy");
    }
}
