//! The OS sandbox: workers die with the parent, limits kill a runaway worker, Linux denies the network, and the worker's
//! environment is clean. Windows has no network denial, and the last test says so.
//!
//! The process-limit test counts processes, so the tests that start many processes take a lock and run one at a time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{PARENT, WORKER, call, config, ready_pool, until};
use privoke_worker_pool::testing::JsonProtocol;
use privoke_worker_pool::{PoolError, SandboxPolicy, WorkerPool, network_denial_enforced};
use serde_json::json;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        let out = Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"]).output().unwrap();
        String::from_utf8_lossy(&out.stdout).contains(&format!("\"{pid}\""))
    }
    #[cfg(unix)]
    {
        // A zombie has exited; its parent just has not collected it (a container's test runner is often PID 1).
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| stat.rsplit(')').next().is_some_and(|rest| !rest.trim_start().starts_with('Z')))
    }
}

async fn wait_dead(what: &str, pid: u32) {
    until(what, || !alive(pid)).await;
}

/// Killing the parent kills every worker the pool started, with no cleanup code running in the parent.
#[tokio::test]
async fn children_die_with_the_parent() {
    let _serial = SERIAL.lock().await;
    let mut parent = Command::new(PARENT).arg(WORKER).arg("2").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(parent.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let mut fields = line.split_whitespace().skip(1);
    let workers: Vec<u32> = fields.next().unwrap().split(',').map(|p| p.parse().unwrap()).collect();
    let grandchild: u32 = fields.next().unwrap().parse().unwrap();
    assert_eq!(workers.len(), 2, "{line}");
    assert!(workers.iter().all(|&pid| alive(pid)) && alive(grandchild));

    parent.kill().unwrap(); // TerminateProcess or SIGKILL: nothing in the parent gets to clean up
    parent.wait().unwrap();

    for &pid in &workers {
        wait_dead("a worker to die with its parent", pid).await;
    }
    if cfg!(windows) {
        // The job holds the whole tree, so the worker's own child dies too.
        wait_dead("the worker's child to die with the job", grandchild).await;
    } else {
        // Linux: pdeathsig covers the workers the pool starts. A worker's own children are the worker's concern.
        let _ = Command::new("kill").arg("-9").arg(grandchild.to_string()).status();
    }
}

/// Dropping the pool kills the workers (kill-on-close on Windows, the kill on drop elsewhere).
#[tokio::test]
async fn dropping_the_pool_kills_the_workers() {
    let _serial = SERIAL.lock().await;
    let pool = ready_pool(config(&[])).await;
    let pid = pool.worker_pids()[0];
    assert!(alive(pid));
    drop(pool);
    wait_dead("the worker to die with the pool", pid).await;
}

/// A memory limit stops a runaway allocation: the worker dies, the request fails, and the pool restarts it.
#[tokio::test]
async fn a_memory_limit_kills_a_runaway_worker() {
    let _serial = SERIAL.lock().await;
    // The limit and the runaway request are sized together: the request is 2.5 times the limit, which is enough to be
    // refused under it and small enough that a CI runner grants the same allocation to the unlimited control worker (a
    // 1536 MB request was refused there once, which failed the control for a reason unrelated to the limit).
    const LIMIT_MB: u64 = 256;
    const RUNAWAY_MB: u64 = LIMIT_MB * 5 / 2;
    let mut cfg = config(&[]);
    cfg.sandbox.memory_limit_bytes = Some(LIMIT_MB << 20);
    let pool = ready_pool(cfg).await;
    // Inside the limit it works, so the limit is not simply too small to run anything.
    assert!(call(&pool, "alloc", json!({"mb": 32})).await.is_ok());
    let pid = pool.worker_pids()[0];
    let err = call(&pool, "alloc", json!({"mb": RUNAWAY_MB})).await.unwrap_err();
    assert!(matches!(err, PoolError::WorkerFailed(_)), "{err}");
    wait_dead("the runaway worker to die", pid).await;
    until("a restarted worker", || pool.starts() == 2 && pool.is_ready()).await;
    assert!(call(&pool, "echo", json!({"text": "back"})).await.is_ok());

    // Control: the same request without a limit succeeds, so it was the limit that stopped it.
    let free = ready_pool(config(&[])).await;
    assert!(call(&free, "alloc", json!({"mb": RUNAWAY_MB})).await.is_ok());
}

#[cfg(target_os = "linux")]
fn threads_of_this_user() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter(|e| e.metadata().is_ok_and(|m| m.uid() == me))
        .map(|e| std::fs::read_dir(e.path().join("task")).map_or(0, |d| d.count() as u32))
        .sum()
}

fn running_as_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .is_ok_and(|status| status.lines().any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0")))
}

/// A process limit stops a runaway fork: the worker cannot start more children than the limit allows.
#[tokio::test]
async fn a_process_limit_stops_a_runaway_worker() {
    let _serial = SERIAL.lock().await;
    const WANTED: u64 = 30;
    if cfg!(unix) && running_as_root() {
        // The kernel does not apply RLIMIT_NPROC to root. The Linux container run executes this test as uid 1000.
        eprintln!("skipped: RLIMIT_NPROC does not bind uid 0");
        return;
    }

    // Control: no limit, every child starts and lives.
    let free = ready_pool(config(&[])).await;
    assert_eq!(call(&free, "spawn_children", json!({"n": WANTED})).await.unwrap()["spawned"], WANTED);
    assert_eq!(call(&free, "alive_children", json!({})).await.unwrap()["alive"], WANTED);
    drop(free);

    let mut cfg = config(&[]);
    // Windows: the worker plus two children. Linux: the user's current threads plus a few, as the limit is per user.
    #[cfg(windows)]
    let allowed_children = 2u64;
    #[cfg(windows)]
    {
        cfg.sandbox.max_processes = Some(3);
    }
    #[cfg(target_os = "linux")]
    let allowed_children = 4u64;
    #[cfg(target_os = "linux")]
    {
        cfg.sandbox.max_processes = Some(threads_of_this_user() + 1 + allowed_children as u32);
    }
    let pool = ready_pool(cfg).await;
    let spawned = call(&pool, "spawn_children", json!({"n": WANTED})).await.unwrap()["spawned"].as_u64().unwrap();
    // Windows terminates a process created over the limit instead of failing the call, so count the survivors.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let alive_now = call(&pool, "alive_children", json!({})).await.unwrap()["alive"].as_u64().unwrap();
    assert!(spawned < WANTED || alive_now < WANTED, "the limit did nothing: {spawned} started, {alive_now} alive");
    assert!(alive_now <= allowed_children + 1, "{alive_now} children alive, the limit allows about {allowed_children}");
}

/// On Linux a worker's connect attempt fails under the seccomp filter, and works without it.
#[tokio::test]
async fn network_denial_blocks_connect_on_linux() {
    let _serial = SERIAL.lock().await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Control: an unconfined worker connects to the listener.
    let open = ready_pool(config(&[])).await;
    assert_eq!(call(&open, "connect", json!({"addr": addr})).await.unwrap()["connected"], true);

    if !network_denial_enforced() {
        // Windows: a Job Object gives lifetime and resource limits only. No network denial is claimed or tested.
        return;
    }
    let mut cfg = config(&[]);
    cfg.sandbox.deny_network = true;
    let denied = ready_pool(cfg).await;
    let result = call(&denied, "connect", json!({"addr": addr})).await.unwrap();
    assert_eq!(result["connected"], false, "{result}");
    // The worker itself keeps working: the filter denies sockets only.
    assert_eq!(call(&denied, "echo", json!({"text": "still serving"})).await.unwrap(), json!("still serving"));
    assert_eq!(call(&denied, "print", json!({})).await.unwrap(), json!("printed"));
    assert_eq!(denied.starts(), 1);
}

/// A clean environment holds only the baseline, `PYTHONHOME` and what the policy and the pool name.
#[tokio::test]
async fn clean_environment_and_explicit_pythonhome() {
    let _serial = SERIAL.lock().await;
    let home = std::env::temp_dir().join("privoke-fake-python-home");

    // Control: the parent's environment is inherited, so PATH reaches the worker.
    let inherited = ready_pool(config(&[])).await;
    let info = call(&inherited, "info", json!({})).await.unwrap();
    assert!(info["env"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().eq_ignore_ascii_case("PATH")));

    let mut cfg = config(&[]);
    cfg.sandbox = SandboxPolicy::strict(&home);
    cfg.sandbox.deny_network = false; // this test is about the environment
    cfg.envs.push(("PRIVOKE_TEST_MARKER".into(), "explicit".into()));
    let pool = ready_pool(cfg).await;
    let info = call(&pool, "info", json!({})).await.unwrap();
    let names: BTreeSet<String> = info["env"].as_array().unwrap().iter().map(|n| n.as_str().unwrap().to_ascii_uppercase()).collect();
    let mut allowed: BTreeSet<String> = ["PYTHONHOME", "PYTHONNOUSERSITE", "PRIVOKE_TEST_MARKER"].map(String::from).into();
    if cfg!(windows) {
        allowed.insert("SYSTEMROOT".into());
    }
    assert_eq!(names, allowed);
    assert_eq!(info["pythonhome"], home.to_string_lossy().as_ref());
    assert_eq!(info["nousersite"], "1");
    assert_eq!(info["marker"], "explicit");

    // An allow-listed name passes through the clean environment.
    let mut cfg = config(&[]);
    cfg.sandbox.clean_env = true;
    cfg.sandbox.inherit_env.push("PATH".into());
    let pool = ready_pool(cfg).await;
    let info = call(&pool, "info", json!({})).await.unwrap();
    assert!(info["env"].as_array().unwrap().iter().any(|n| n.as_str().unwrap().eq_ignore_ascii_case("PATH")));
    assert!(info["pythonhome"].is_null());
}

/// Unsafe policies are rejected before anything starts.
#[tokio::test]
async fn invalid_policies_are_rejected() {
    let mut cfg = config(&[]);
    cfg.sandbox.memory_limit_bytes = Some(0);
    assert!(WorkerPool::start(JsonProtocol, cfg).is_err());
    let started = Instant::now();
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// The documentation's claim, as a test: network denial is enforced on Linux and not on Windows.
#[test]
fn network_denial_is_claimed_only_where_it_is_enforced() {
    assert_eq!(network_denial_enforced(), cfg!(target_os = "linux"));
}
