//! A worker for the pool and sandbox tests. It speaks the JSON test protocol (`privoke_worker_pool::testing`).
//!
//! Options: `--startup-delay-ms N`, `--fatal REASON`, `--exit-at-start`, `--spawn-log PATH`, and `--idle`, which makes a
//! process that only sleeps (the children this worker spawns).
//!
//! Operations: `echo`, `crash`, `hang`, `sleep` (`ms`), `err`, `badid`, `print` (writes to stdout, which must not
//! corrupt the frames), `info`, `alloc` (`mb`), `spawn_children` (`n`), `alive_children`, `grandchild` and
//! `connect` (`addr`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use privoke_worker_pool::{read_frame_sync, worker_side, write_frame_sync};
use serde_json::{Value, json};

fn idle_child() -> std::io::Result<Child> {
    Command::new(std::env::current_exe()?).arg("--idle").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut delay, mut fatal, mut exit_at_start, mut spawn_log) = (0u64, None, false, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--idle" => sleep_forever(),
            "--startup-delay-ms" => delay = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--fatal" => fatal = args.next(),
            "--exit-at-start" => exit_at_start = true,
            "--spawn-log" => spawn_log = args.next(),
            _ => {}
        }
    }
    if let Some(path) = spawn_log {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis());
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{now}");
        }
    }
    if exit_at_start {
        std::process::exit(1);
    }
    std::thread::sleep(Duration::from_millis(delay));
    let mut frames = worker_side::claim_frame_output().expect("claim the frame output");
    let mut stdin = std::io::stdin().lock();
    if let Some(reason) = fatal {
        let _ = write_frame_sync(&mut frames, json!({"type": "fatal", "reason": reason}).to_string().as_bytes());
        std::process::exit(78);
    }
    if write_frame_sync(&mut frames, json!({"type": "ready", "pid": std::process::id()}).to_string().as_bytes()).is_err() {
        return;
    }
    let mut children: Vec<Child> = Vec::new();
    while let Ok(frame) = read_frame_sync(&mut stdin) {
        let request: Value = serde_json::from_slice(&frame).unwrap_or_default();
        let id = request["id"].as_u64().unwrap_or(0);
        let ok = |result: Value| json!({"id": id, "ok": true, "result": result});
        let reply = match request["op"].as_str().unwrap_or("") {
            "crash" => std::process::exit(3),
            "hang" => sleep_forever(),
            "err" => json!({"id": id, "ok": false, "error": "boom"}),
            "badid" => json!({"id": id + 1000, "ok": true, "result": {}}),
            "sleep" => {
                std::thread::sleep(Duration::from_millis(request["ms"].as_u64().unwrap_or(0)));
                ok(json!("slept"))
            }
            "print" => {
                println!("stray output that is not a frame");
                eprintln!("a line on stderr");
                ok(json!("printed"))
            }
            "info" => {
                let mut env: Vec<String> = std::env::vars_os().map(|(k, _)| k.to_string_lossy().into_owned()).collect();
                env.sort();
                ok(json!({
                    "pid": std::process::id(),
                    "env": env,
                    "pythonhome": std::env::var("PYTHONHOME").ok(),
                    "nousersite": std::env::var("PYTHONNOUSERSITE").ok(),
                    "marker": std::env::var("PRIVOKE_TEST_MARKER").ok(),
                }))
            }
            "alloc" => {
                let mb = request["mb"].as_u64().unwrap_or(1) as usize;
                // A failed allocation aborts the process, which is how a limit kills a runaway worker.
                let block = vec![1u8; mb << 20];
                std::hint::black_box(&block);
                ok(json!({"allocated_mb": mb}))
            }
            "spawn_children" => {
                let wanted = request["n"].as_u64().unwrap_or(0);
                let mut spawned = 0u64;
                for _ in 0..wanted {
                    match idle_child() {
                        Ok(child) => {
                            children.push(child);
                            spawned += 1;
                        }
                        Err(_) => break,
                    }
                }
                ok(json!({"spawned": spawned}))
            }
            "alive_children" => {
                let alive = children.iter_mut().filter_map(|c| c.try_wait().ok().flatten().is_none().then_some(())).count();
                ok(json!({"alive": alive, "started": children.len()}))
            }
            "grandchild" => match idle_child() {
                Ok(child) => {
                    let pid = child.id();
                    children.push(child);
                    ok(json!({"pid": std::process::id(), "child": pid}))
                }
                Err(e) => json!({"id": id, "ok": false, "error": e.to_string()}),
            },
            "connect" => {
                let addr: SocketAddr = request["addr"].as_str().unwrap_or("127.0.0.1:9").parse().expect("an address");
                match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(_) => ok(json!({"connected": true})),
                    Err(e) => ok(json!({"connected": false, "error": e.to_string()})),
                }
            }
            _ => ok(request["text"].clone()),
        };
        if write_frame_sync(&mut frames, reply.to_string().as_bytes()).is_err() {
            return;
        }
    }
}
