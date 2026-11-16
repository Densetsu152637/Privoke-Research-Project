//! The port of `extension/runtime-supervisor/test/test_runtime_supervisor.py`, case for case, on a fake launcher.
//! The Windows process-tree cases that used real processes are in `real_processes.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use privoke_supervisor::process::{
    CheckOutcome, ChildHandle, LaunchSpec, Launcher, RuntimeProcessSupervisor, SupervisorError, SupervisorSettings, terminate_for_test,
};

#[derive(Default)]
struct World {
    next_pid: u32,
    /// (pid, environment, terminated)
    launches: Vec<(u32, BTreeMap<String, String>, bool)>,
    spawn_count: usize,
    /// The port reads as open while a live child exists, unless forced.
    force_port_open: Option<bool>,
    ready: bool,
    check: Option<CheckOutcome>,
    terminate_fails: bool,
    /// Children (by launch index) that have crashed with this exit code.
    crashed: BTreeMap<usize, i32>,
}

#[derive(Clone)]
struct FakeLauncher(Arc<Mutex<World>>);

struct FakeChild {
    pid: u32,
    index: usize,
    world: Arc<Mutex<World>>,
    exited: Option<i32>,
}

impl ChildHandle for FakeChild {
    fn id(&self) -> u32 {
        self.pid
    }
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Ok(self.exited.or_else(|| self.world.lock().unwrap().crashed.get(&self.index).copied()))
    }
    fn terminate(&mut self, _grace: Duration) -> io::Result<()> {
        let mut world = self.world.lock().unwrap();
        if world.terminate_fails {
            return Err(io::Error::other("taskkill failed"));
        }
        world.launches[self.index].2 = true;
        self.exited = Some(0);
        Ok(())
    }
}

impl Launcher for FakeLauncher {
    fn spawn(&mut self, spec: &LaunchSpec) -> io::Result<Box<dyn ChildHandle>> {
        let mut world = self.0.lock().unwrap();
        world.next_pid += 1;
        world.spawn_count += 1;
        let pid = world.next_pid;
        let index = world.launches.len();
        world.launches.push((pid, spec.env.clone(), false));
        Ok(Box::new(FakeChild { pid, index, world: Arc::clone(&self.0), exited: None }))
    }

    fn check(&mut self, _spec: &LaunchSpec, _timeout: Duration) -> io::Result<CheckOutcome> {
        Ok(self.0.lock().unwrap().check.clone().unwrap_or(CheckOutcome { code: 0, stdout: String::new(), stderr: String::new() }))
    }

    fn port_is_open(&mut self, _port: u16) -> bool {
        let world = self.0.lock().unwrap();
        match world.force_port_open {
            Some(forced) => forced,
            None => world.ready && world.launches.iter().any(|(_, _, terminated)| !terminated),
        }
    }
}

fn world() -> Arc<Mutex<World>> {
    Arc::new(Mutex::new(World { ready: true, ..World::default() }))
}

fn supervisor(world: &Arc<Mutex<World>>, command: Option<Vec<String>>, environment: BTreeMap<String, String>) -> RuntimeProcessSupervisor {
    let root = Path::new("/repository/extension/client-runtime");
    let mut settings = SupervisorSettings::new(root, environment, 50057, command);
    settings.startup_timeout = Duration::from_millis(300);
    settings.poll_interval = Duration::from_millis(10);
    settings.settle = Duration::from_millis(5);
    RuntimeProcessSupervisor::new(settings, Box::new(FakeLauncher(Arc::clone(world))))
}

fn runtime(command: &str) -> Option<Vec<String>> {
    Some(vec![command.to_string()])
}

#[test]
fn switching_stack_restarts_owned_child_and_preserves_loopback() {
    let world = world();
    let supervisor = supervisor(&world, runtime("test-runtime"), BTreeMap::new());
    supervisor.set_enabled(true, Some(false)).unwrap();
    supervisor.set_enabled(true, Some(true)).unwrap();
    {
        let world = world.lock().unwrap();
        assert!(world.launches[0].2, "the first child was terminated by the switch");
        assert_eq!(world.launches[1].1["PRIVOKE_USE_LOCAL_STACK"], "true");
        assert_eq!(world.launches[1].1["PRIVOKE_GRPC_HOST"], "127.0.0.1");
        assert_eq!(world.launches[1].1["PRIVOKE_GRPC_PORT"], "50057");
    }
    supervisor.set_enabled(true, Some(true)).unwrap();
    assert_eq!(world.lock().unwrap().spawn_count, 2, "asking for the same stack again launches nothing");
    supervisor.set_enabled(false, Some(false)).unwrap();
    assert!(world.lock().unwrap().launches[1].2);
    assert_eq!(supervisor.environment().unwrap()["PRIVOKE_USE_LOCAL_STACK"], "false");
}

#[test]
fn default_child_is_the_sibling_client_runtime() {
    let world = world();
    let supervisor = supervisor(&world, None, BTreeMap::new());
    let settings = supervisor.settings();
    let runtime_root = Path::new("/repository/extension/client-runtime");
    assert_eq!(Path::new(&settings.command[1]), runtime_root.join("src").join("grpc_main.py"));
    let check = settings.dependency_check.as_ref().unwrap();
    assert_eq!(Path::new(&check[1]), runtime_root.join("src").join("dependency_check.py"));
    assert_eq!(settings.runtime_port, 50057);
    let environment = supervisor.environment().unwrap();
    assert_eq!(environment["PRIVOKE_GRPC_PORT"], "50057");
    assert_eq!(environment["PRIVOKE_GRPC_HOST"], "127.0.0.1");
}

#[test]
fn forces_runtime_to_loopback() {
    let world = world();
    let environment = BTreeMap::from([("PRIVOKE_GRPC_HOST".to_string(), "0.0.0.0".to_string())]);
    let supervisor = supervisor(&world, None, environment);
    assert_eq!(supervisor.environment().unwrap()["PRIVOKE_GRPC_HOST"], "127.0.0.1");
}

#[test]
fn explicit_runtime_python_overrides_interpreter_discovery() {
    let world = world();
    let environment = BTreeMap::from([("PRIVOKE_RUNTIME_PYTHON".to_string(), "managed-python".to_string())]);
    let supervisor = supervisor(&world, None, environment);
    assert_eq!(supervisor.settings().command[0], "managed-python");
    assert_eq!(supervisor.settings().dependency_check.as_ref().unwrap()[0], "managed-python");
}

#[test]
fn starts_and_stops_the_runtime_child() {
    let world = world();
    let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
    let running = supervisor.start().unwrap();
    assert!(running.enabled);
    assert_eq!(running.status, "RUNNING");
    assert_eq!(running.process_id, 1);
    let stopped = supervisor.stop().unwrap();
    assert!(!stopped.enabled);
    assert_eq!(stopped.status, "STOPPED");
    assert_eq!(stopped.process_id, 0);
    assert!(world.lock().unwrap().launches[0].2);
}

#[test]
fn cleans_up_a_child_that_never_becomes_ready() {
    let world = world();
    world.lock().unwrap().ready = false;
    let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
    let status = supervisor.start().unwrap();
    assert!(!status.enabled);
    assert!(world.lock().unwrap().launches[0].2, "the child that never listened was terminated");
    assert!(status.message.contains("did not listen"), "{}", status.message);
}

#[test]
fn does_not_claim_an_unmanaged_process_as_its_runtime() {
    let world = world();
    world.lock().unwrap().force_port_open = Some(true);
    let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
    let status = supervisor.start().unwrap();
    assert!(!status.enabled);
    assert_eq!(world.lock().unwrap().spawn_count, 0);
    assert!(status.message.contains("not owned by this supervisor"), "{}", status.message);
}

#[test]
fn does_not_launch_runtime_when_required_dependencies_are_missing() {
    let world = world();
    world.lock().unwrap().check = Some(CheckOutcome {
        code: 1,
        stdout: String::new(),
        stderr: "Traceback...\nModuleNotFoundError: No module named 'presidio_analyzer'\n".into(),
    });
    let supervisor = supervisor(&world, None, BTreeMap::new());
    let status = supervisor.start().unwrap();
    assert!(!status.enabled);
    assert_eq!(world.lock().unwrap().spawn_count, 0);
    assert!(status.message.contains("presidio_analyzer"), "{}", status.message);
}

#[test]
fn a_failing_check_with_no_output_names_its_exit_code() {
    let world = world();
    world.lock().unwrap().check = Some(CheckOutcome { code: 7, stdout: String::new(), stderr: String::new() });
    let supervisor = supervisor(&world, None, BTreeMap::new());
    let status = supervisor.start().unwrap();
    assert!(status.message.contains("dependency check exited with code 7"), "{}", status.message);
}

#[test]
fn a_child_that_exits_is_reported_stopped_with_its_code_and_can_be_started_again() {
    let world = world();
    let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
    assert!(supervisor.start().unwrap().enabled);
    world.lock().unwrap().crashed.insert(0, 3);
    let status = supervisor.status().unwrap();
    assert!(!status.enabled);
    assert_eq!(status.status, "STOPPED");
    assert_eq!(status.message, "Client runtime exited with code 3.");
    assert_eq!(status.process_id, 0);
    world.lock().unwrap().launches[0].2 = true; // its port is gone with it
    assert!(supervisor.start().unwrap().enabled);
    assert_eq!(world.lock().unwrap().spawn_count, 2);
}

#[test]
fn an_invalid_stack_setting_is_a_configuration_error_not_a_guess() {
    let world = world();
    let environment = BTreeMap::from([("PRIVOKE_USE_LOCAL_STACK".to_string(), "sometimes".to_string())]);
    let supervisor = supervisor(&world, runtime("runtime"), environment);
    assert!(matches!(supervisor.set_enabled(true, Some(true)), Err(SupervisorError::Config(_))));
    assert_eq!(world.lock().unwrap().spawn_count, 0);
}

#[test]
fn failed_tree_termination_does_not_report_stopped() {
    let world = world();
    let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
    assert!(supervisor.start().unwrap().enabled);
    world.lock().unwrap().terminate_fails = true;
    let error = supervisor.stop().unwrap_err();
    assert_eq!(error, SupervisorError::StopFailed);
    assert!(error.to_string().contains("process tree"));
    assert!(supervisor.status().unwrap().enabled, "a child that could not be stopped is still reported as running");
    // Once the failure clears, the same supervisor can stop it.
    world.lock().unwrap().terminate_fails = false;
    assert!(!supervisor.stop().unwrap().enabled);
}

#[test]
fn partial_tree_failure_is_not_ignored_when_launcher_exits() {
    struct LauncherThenFails {
        exited: bool,
    }
    impl ChildHandle for LauncherThenFails {
        fn id(&self) -> u32 {
            9
        }
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(self.exited.then_some(0))
        }
        fn terminate(&mut self, _grace: Duration) -> io::Result<()> {
            // The launcher process exits, but part of the tree could not be stopped.
            self.exited = true;
            Err(io::Error::other("part of the tree survived"))
        }
    }
    let mut child = LauncherThenFails { exited: false };
    assert_eq!(terminate_for_test(&mut child, Duration::from_millis(10)), Err(SupervisorError::StopFailed));
}

#[test]
fn dropping_the_supervisor_stops_the_child() {
    let world = world();
    {
        let supervisor = supervisor(&world, runtime("runtime"), BTreeMap::new());
        supervisor.start().unwrap();
    }
    assert!(world.lock().unwrap().launches[0].2);
}
