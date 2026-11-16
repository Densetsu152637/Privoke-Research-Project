//! A parent process for the "children die with the parent" test: `test-parent <worker> <workers>`.
//!
//! It starts a pool, asks one worker to start a child of its own, prints `PIDS <worker pids> <grandchild pid>` and then
//! waits to be killed.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use privoke_worker_pool::testing::JsonProtocol;
use privoke_worker_pool::{PoolConfig, WorkerPool};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let worker = args.next().expect("a worker path");
    let workers: usize = args.next().and_then(|v| v.parse().ok()).unwrap_or(2);
    let mut cfg = PoolConfig::new(worker);
    cfg.workers = workers;
    let pool = WorkerPool::start(JsonProtocol, cfg).expect("start the pool");
    let start = std::time::Instant::now();
    while pool.ready_workers() < workers {
        assert!(start.elapsed() < Duration::from_secs(30), "workers did not become ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let id = pool.next_id();
    let answer = pool.submit(id, format!(r#"{{"id":{id},"op":"grandchild"}}"#).into_bytes()).await.expect("grandchild");
    let answer: serde_json::Value = serde_json::from_str(&answer).expect("json");
    let mut pids = pool.worker_pids();
    pids.sort_unstable();
    let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
    println!("PIDS {} {}", pids.join(","), answer["child"]);
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
