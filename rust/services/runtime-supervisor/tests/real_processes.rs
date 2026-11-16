//! Real processes: the port release and restart cases of the Windows regression tests, the proof that children die
//! with the supervisor, and the started/failed paths of the native host. The stand-in runtime is
//! `privoke-supervisor-test-child`, which listens on the port the supervisor gives it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Reaper, free_port, port_is_open, process_alive, wait_until};
use privoke_contracts::proto::v1::RuntimeHealthRequest;
use privoke_contracts::proto::v1::privoke_runtime_control_service_client::PrivokeRuntimeControlServiceClient;
use privoke_supervisor::native_host::{self, HostConfig};
use privoke_supervisor::process::{OsLauncher, RuntimeProcessSupervisor, SupervisorSettings};

const TEST_CHILD: &str = env!("CARGO_BIN_EXE_privoke-supervisor-test-child");
const SUPERVISOR: &str = env!("CARGO_BIN_EXE_privoke-supervisor");

fn real_supervisor(port: u16, mode: &str) -> RuntimeProcessSupervisor {
    let mut settings = SupervisorSettings::new(
        std::path::Path::new("."),
        std::env::vars().collect(),
        port,
        Some(vec![TEST_CHILD.to_string(), mode.to_string()]),
    );
    settings.startup_timeout = Duration::from_secs(20);
    RuntimeProcessSupervisor::new(settings, Box::new(OsLauncher))
}

fn cycle_three_times(mode: &str) {
    let port = free_port();
    let supervisor = real_supervisor(port, mode);
    for round in 0..3 {
        let started = supervisor.start().unwrap();
        assert!(started.enabled, "round {round}: {}", started.message);
        assert!(port_is_open(port));
        assert!(!supervisor.stop().unwrap().enabled);
        assert!(!port_is_open(port), "round {round}: the runtime outlived its launcher");
    }
}

#[test]
fn stopping_the_runtime_releases_the_port_and_allows_restart() {
    cycle_three_times("listen-env");
}

#[test]
fn stopping_a_launcher_that_started_the_runtime_releases_the_port() {
    // The Windows venv `python.exe` is a redirector: the process that holds the port is its child. Stopping only the
    // launcher would leave the port held, which is the regression the Python `taskkill /T` guarded against.
    cycle_three_times("with-grandchild");
}

#[test]
fn a_runtime_that_exits_at_once_is_reported_not_started() {
    let supervisor = real_supervisor(free_port(), "exit");
    let status = supervisor.start().unwrap();
    assert!(!status.enabled);
    assert!(status.message.contains("exited with code") || status.message.contains("did not listen"), "{}", status.message);
}

struct Serving {
    reaper: Reaper,
    _root: tempfile::TempDir,
    runtime_port: u16,
    control_port: u16,
}

fn serve(mode: &str) -> Serving {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("extension").join("client-runtime")).unwrap();
    let (runtime_port, control_port) = (free_port(), free_port());
    let command = [TEST_CHILD, mode].join("\u{1f}");
    let child = Command::new(SUPERVISOR)
        .arg("serve")
        .env("PRIVOKE_REPOSITORY_ROOT", root.path())
        .env("PRIVOKE_TEST_RUNTIME_COMMAND", command)
        .env("PRIVOKE_LOCAL_RUNTIME_PORT", runtime_port.to_string())
        .env("PRIVOKE_CONTROL_GRPC_PORT", control_port.to_string())
        .env("PRIVOKE_RUNTIME_START_TIMEOUT_SECONDS", "20")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut serving = Serving { reaper: Reaper(Some(child)), _root: root, runtime_port, control_port };
    // `serve` prints the runtime message, then the control address, once it listens.
    let stdout = serving.reaper.0.as_mut().unwrap().stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    // The child shares the supervisor's standard output, so its own lines (`PID n`) are interleaved.
    let mut seen = Vec::new();
    while !(seen.iter().any(|line: &String| line.contains("Client runtime started."))
        && seen.iter().any(|line: &String| line.contains(&format!("listening on 127.0.0.1:{control_port}"))))
    {
        assert!(seen.len() < 20, "serve did not report readiness: {seen:?}");
        let Some(line) = lines.next() else {
            let mut child = serving.reaper.0.take().unwrap();
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("serve exited early: {seen:?} {}", String::from_utf8_lossy(&output.stderr));
        };
        seen.push(line.unwrap());
    }
    // Keep draining so the pipe never blocks the supervisor.
    std::thread::spawn(move || lines.for_each(drop));
    serving
}

async fn child_pid(control_port: u16) -> u32 {
    let mut client = PrivokeRuntimeControlServiceClient::connect(format!("http://127.0.0.1:{control_port}")).await.unwrap();
    let status = client.status(RuntimeHealthRequest {}).await.unwrap().into_inner();
    assert!(status.enabled, "{}", status.message);
    status.process_id
}

async fn assert_children_die_with(mode: &str) {
    let mut serving = serve(mode);
    assert!(port_is_open(serving.runtime_port));
    let child = child_pid(serving.control_port).await;
    assert!(process_alive(child));
    assert_ne!(child, serving.reaper.id(), "the runtime is a separate process");

    // A hard kill: no signal handler, no destructor, no `stop`. Only the operating-system confinement can end the child.
    serving.reaper.kill();
    assert!(wait_until(Duration::from_secs(15), || !process_alive(child)), "{mode}: the runtime child outlived the supervisor");
    assert!(
        wait_until(Duration::from_secs(15), || !port_is_open(serving.runtime_port)),
        "{mode}: the runtime port is still held after the supervisor died"
    );
}

#[tokio::test]
async fn the_runtime_child_dies_with_the_supervisor() {
    assert_children_die_with("listen-env").await;
}

#[tokio::test]
async fn the_whole_runtime_tree_dies_with_the_supervisor() {
    // The launcher starts the process that holds the port, as the venv redirector does.
    assert_children_die_with("with-grandchild").await;
}

#[tokio::test]
async fn a_graceful_stop_leaves_nothing_running() {
    let mut serving = serve("with-grandchild");
    let child = child_pid(serving.control_port).await;
    // The control RPC to stop, then drop the supervisor process the way the host would on logout.
    let mut client = PrivokeRuntimeControlServiceClient::connect(format!("http://127.0.0.1:{}", serving.control_port)).await.unwrap();
    let status = client
        .set_runtime_enabled(privoke_contracts::proto::v1::SetRuntimeEnabledRequest { enabled: false, use_local_stack: None })
        .await
        .unwrap()
        .into_inner();
    assert!(!status.enabled);
    assert!(wait_until(Duration::from_secs(10), || !process_alive(child) && !port_is_open(serving.runtime_port)));
    serving.reaper.kill();
}

fn host(entry: &str, arguments: &[String], bridge_port: u16, log: &std::path::Path) -> HostConfig {
    let mut host = HostConfig::standard(entry.into(), None, log.to_path_buf());
    host.bridge_port = bridge_port;
    host.control_port = free_port();
    host.supervisor_args = arguments.iter().map(Into::into).collect();
    host.startup_timeout = Duration::from_secs(10);
    host
}

#[test]
fn ensure_supervisor_starts_the_entry_detached_and_reports_its_process() {
    let log_dir = tempfile::tempdir().unwrap();
    let bridge = free_port();
    let config = host(
        TEST_CHILD,
        &["listen".into(), bridge.to_string(), "4000".into()],
        bridge,
        &log_dir.path().join("nested").join("supervisor.log"),
    );
    let reply = native_host::ensure_supervisor(&config);
    assert!(reply.ok && reply.started, "{reply:?}");
    assert_eq!(reply.message, "PriVoke supervisor bridge started.");
    let pid = reply.process_id.expect("the started supervisor's process id");
    assert!(config.log_path.is_file(), "the log directory and file are created");
    assert!(reply.to_json().starts_with(&format!("{{\"ok\":true,\"started\":true,\"process_id\":{pid},\"message\":")));
    assert!(reply.to_json().contains("\"log_path\":"));
    // It was asked to stop after four seconds; end it now.
    let _ = Command::new(if cfg!(windows) { "taskkill" } else { "kill" })
        .args(if cfg!(windows) { vec!["/PID".to_string(), pid.to_string(), "/F".to_string()] } else { vec![pid.to_string()] })
        .output();
    assert!(wait_until(Duration::from_secs(10), || !process_alive(pid)));
    // A second call finds the bridge gone and starts again only because we ask; with the port taken it must not start.
    let blocker = std::net::TcpListener::bind(("127.0.0.1", bridge)).unwrap();
    let again = native_host::ensure_supervisor(&config);
    assert!(again.ok && !again.started, "{again:?}");
    drop(blocker);
}

#[test]
fn ensure_supervisor_reports_an_entry_that_exits_and_one_that_never_opens_the_bridge() {
    let log_dir = tempfile::tempdir().unwrap();
    let exits = host(TEST_CHILD, &["exit".into(), "3".into()], free_port(), &log_dir.path().join("a.log"));
    let reply = native_host::ensure_supervisor(&exits);
    assert!(!reply.ok && !reply.started, "{reply:?}");
    assert_eq!(reply.message, "PriVoke supervisor exited with code 3.");
    assert!(reply.log_path.is_some());

    let other = free_port();
    let mut silent = host(TEST_CHILD, &["listen".into(), other.to_string(), "1500".into()], free_port(), &log_dir.path().join("b.log"));
    silent.startup_timeout = Duration::from_millis(600);
    let reply = native_host::ensure_supervisor(&silent);
    assert!(!reply.ok && !reply.started, "{reply:?}");
    assert_eq!(reply.message, "PriVoke supervisor did not open its bridge within 10 seconds.");
}

#[test]
fn ensure_supervisor_reports_a_launch_failure_with_the_log_path() {
    let log_dir = tempfile::tempdir().unwrap();
    // A directory is not a launchable entry.
    let not_a_program = log_dir.path().join("not-a-program");
    std::fs::write(&not_a_program, b"not an executable").unwrap();
    let config = host(not_a_program.to_str().unwrap(), &[], free_port(), &log_dir.path().join("c.log"));
    let reply = native_host::ensure_supervisor(&config);
    assert!(!reply.ok && !reply.started, "{reply:?}");
    assert!(reply.message.starts_with("Could not launch the PriVoke supervisor:"), "{}", reply.message);
    assert_eq!(reply.log_path.as_deref(), Some(config.log_path.display().to_string().as_str()));
}
