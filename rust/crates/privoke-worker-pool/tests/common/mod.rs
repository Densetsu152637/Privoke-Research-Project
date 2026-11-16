//! Shared helpers: a pool of test workers and a typed `call`.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::time::{Duration, Instant};

use privoke_worker_pool::testing::JsonProtocol;
use privoke_worker_pool::{Backoff, PoolConfig, PoolError, WorkerPool};
use serde_json::{Value, json};

pub const WORKER: &str = env!("CARGO_BIN_EXE_privoke-worker-pool-test-worker");
pub const PARENT: &str = env!("CARGO_BIN_EXE_privoke-worker-pool-test-parent");

pub type Pool = WorkerPool<JsonProtocol>;

pub fn config(extra: &[&str]) -> PoolConfig {
    let mut cfg = PoolConfig::new(WORKER);
    cfg.args = extra.iter().map(OsString::from).collect();
    cfg.backoff = Backoff { initial: Duration::from_millis(40), max: Duration::from_millis(400) };
    cfg.request_deadline = Duration::from_secs(5);
    cfg.startup_timeout = Duration::from_secs(10);
    cfg
}

pub async fn ready_pool(cfg: PoolConfig) -> Pool {
    let pool = WorkerPool::start(JsonProtocol, cfg).unwrap();
    pool.wait_ready(Duration::from_secs(10)).await.unwrap();
    pool
}

/// Sends `{"id":N,"op":OP,...extra}` and returns the parsed result.
pub async fn call(pool: &Pool, op: &str, extra: Value) -> Result<Value, PoolError> {
    let id = pool.next_id();
    let mut request = json!({"id": id, "op": op});
    if let (Some(base), Some(more)) = (request.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let body = pool.submit(id, request.to_string().into_bytes()).await?;
    Ok(serde_json::from_str(&body).unwrap())
}

pub async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(15), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
