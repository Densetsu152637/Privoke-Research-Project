//! The runtime child: start, stop, switch stack, report status. The port of `RuntimeProcessSupervisor`.
//!
//! All state lives on one long-lived actor thread. Every child is started from that thread, which the Linux
//! parent-death signal needs (see [`crate::confine`]), and one thread also serialises start and stop the way the
//! Python supervisor's lock did. [`RuntimeProcessSupervisor`] is the cheap handle that sends it requests; every
//! method blocks until the actor answers, so async callers use `spawn_blocking`.
//!
//! The child is the fixed-argv Python client runtime (`grpc_main.py`) listening on loopback. Its argv, working
//! directory and environment never come from a caller of the control service.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::confine::ConfinedChild;

/// Default loopback port of the workstation detector, separate from the Compose runtime on 50054.
pub const DEFAULT_RUNTIME_PORT: u16 = 50057;

/// What the control service reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatus {
    /// True while the child is running.
    pub enabled: bool,
    /// `RUNNING` or `STOPPED`.
    pub status: &'static str,
    /// Why the status is what it is.
    pub message: String,
    /// The child's process id, 0 when stopped.
    pub process_id: u32,
}

/// Why a supervisor request failed (as opposed to reporting a status).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SupervisorError {
    /// The configuration is invalid (for example a malformed boolean).
    #[error("{0}")]
    Config(String),
    /// The child's process tree could not be stopped, so it may still be running.
    #[error("Could not stop the owned client runtime process tree.")]
    StopFailed,
    /// The supervisor thread is gone.
    #[error("the runtime supervisor is shut down")]
    Closed,
}

/// What to launch.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Program and arguments. Fixed by the supervisor, never by a caller.
    pub argv: Vec<String>,
    /// Working directory.
    pub cwd: PathBuf,
    /// The complete environment of the child.
    pub env: BTreeMap<String, String>,
}

/// The result of the dependency check.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    /// Exit code.
    pub code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// A running child.
pub trait ChildHandle: Send {
    /// Process id.
    fn id(&self) -> u32;
    /// Exit code once exited.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    /// Stop the whole tree. An error means it may still run.
    fn terminate(&mut self, grace: Duration) -> io::Result<()>;
}

/// The operating-system side, replaceable in tests.
pub trait Launcher: Send {
    /// Start the child.
    fn spawn(&mut self, spec: &LaunchSpec) -> io::Result<Box<dyn ChildHandle>>;
    /// Run the dependency check to completion within `timeout`.
    fn check(&mut self, spec: &LaunchSpec, timeout: Duration) -> io::Result<CheckOutcome>;
    /// Whether something accepts connections on `127.0.0.1:port`.
    fn port_is_open(&mut self, port: u16) -> bool;
}

impl ChildHandle for ConfinedChild {
    fn id(&self) -> u32 {
        ConfinedChild::id(self)
    }
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        ConfinedChild::try_wait(self)
    }
    fn terminate(&mut self, grace: Duration) -> io::Result<()> {
        self.terminate_tree(grace)
    }
}

/// Real processes, confined so that they die with the supervisor.
#[derive(Debug, Default)]
pub struct OsLauncher;

fn command_for(spec: &LaunchSpec) -> io::Result<Command> {
    let (program, arguments) = spec.argv.split_first().ok_or_else(|| io::Error::other("empty command"))?;
    let mut command = Command::new(program);
    command.args(arguments).current_dir(&spec.cwd).env_clear().envs(&spec.env);
    Ok(command)
}

impl Launcher for OsLauncher {
    fn spawn(&mut self, spec: &LaunchSpec) -> io::Result<Box<dyn ChildHandle>> {
        let mut command = command_for(spec)?;
        Ok(Box::new(ConfinedChild::spawn(&mut command)?))
    }

    fn check(&mut self, spec: &LaunchSpec, timeout: Duration) -> io::Result<CheckOutcome> {
        let mut command = command_for(spec)?;
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = command.spawn()?;
        let read = |stream: Option<Box<dyn io::Read + Send>>| {
            std::thread::spawn(move || {
                let mut text = String::new();
                if let Some(mut stream) = stream {
                    let mut bytes = Vec::new();
                    let _ = stream.read_to_end(&mut bytes);
                    text = String::from_utf8_lossy(&bytes).into_owned();
                }
                text
            })
        };
        let out = read(child.stdout.take().map(|s| Box::new(s) as Box<dyn io::Read + Send>));
        let err = read(child.stderr.take().map(|s| Box::new(s) as Box<dyn io::Read + Send>));
        let deadline = Instant::now() + timeout;
        let code = loop {
            if let Some(status) = child.try_wait()? {
                break status.code().unwrap_or(-1);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(io::ErrorKind::TimedOut, "dependency check timed out"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        Ok(CheckOutcome { code, stdout: out.join().unwrap_or_default(), stderr: err.join().unwrap_or_default() })
    }

    fn port_is_open(&mut self, port: u16) -> bool {
        std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok()
    }
}

/// Everything fixed at construction.
#[derive(Debug, Clone)]
pub struct SupervisorSettings {
    /// The runtime argv.
    pub command: Vec<String>,
    /// The dependency check argv; `None` when the command was overridden.
    pub dependency_check: Option<Vec<String>>,
    /// Working directory of both (the client runtime root).
    pub cwd: PathBuf,
    /// Loopback port the runtime listens on.
    pub runtime_port: u16,
    /// How long the runtime may take to listen, and the dependency check to finish.
    pub startup_timeout: Duration,
    /// Grace for stopping the tree.
    pub stop_timeout: Duration,
    /// The child's environment, with the loopback host and port forced.
    pub environment: BTreeMap<String, String>,
    /// Port and exit polling interval.
    pub poll_interval: Duration,
    /// How long a child must stay alive after its port opens to count as started.
    pub settle: Duration,
}

impl SupervisorSettings {
    /// The default child is the sibling client runtime: `<root>/extension/client-runtime/src/grpc_main.py`, with
    /// `dependency_check.py` run first. `command` replaces the child and skips the check (tests only). The
    /// environment is forced to loopback and the runtime port.
    pub fn new(
        client_runtime_root: &Path,
        mut environment: BTreeMap<String, String>,
        runtime_port: u16,
        command: Option<Vec<String>>,
    ) -> Self {
        let python = runtime_python(client_runtime_root, &environment);
        let script = |name: &str| client_runtime_root.join("src").join(name).to_string_lossy().into_owned();
        let dependency_check = command.is_none().then(|| vec![python.clone(), script("dependency_check.py")]);
        let command = command.unwrap_or_else(|| vec![python, script("grpc_main.py")]);
        environment.insert("PRIVOKE_GRPC_PORT".into(), runtime_port.to_string());
        environment.insert("PRIVOKE_GRPC_HOST".into(), "127.0.0.1".into());
        Self {
            command,
            dependency_check,
            cwd: client_runtime_root.to_path_buf(),
            runtime_port,
            startup_timeout: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(10),
            environment,
            poll_interval: Duration::from_millis(100),
            settle: Duration::from_millis(100),
        }
    }
}

fn runtime_python(root: &Path, environment: &BTreeMap<String, String>) -> String {
    if let Some(configured) = environment.get("PRIVOKE_RUNTIME_PYTHON").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return configured.to_string();
    }
    for relative in [".venv/Scripts/python.exe", ".venv/bin/python"] {
        let candidate = root.join(relative);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if cfg!(windows) { "python".into() } else { "python3".into() }
}

/// Python's `_boolean` for `PRIVOKE_USE_LOCAL_STACK`: unset is false, anything outside the fixed words is an error.
pub fn use_local_stack(environment: &BTreeMap<String, String>) -> Result<bool, SupervisorError> {
    let value = environment.get("PRIVOKE_USE_LOCAL_STACK").map_or("false", |v| v.trim()).to_ascii_lowercase();
    match value.as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(SupervisorError::Config("PRIVOKE_USE_LOCAL_STACK must be a boolean.".into())),
    }
}

struct State {
    settings: SupervisorSettings,
    launcher: Box<dyn Launcher>,
    process: Option<Box<dyn ChildHandle>>,
    last_message: String,
}

impl State {
    fn spec(&self, argv: &[String]) -> LaunchSpec {
        LaunchSpec { argv: argv.to_vec(), cwd: self.settings.cwd.clone(), env: self.settings.environment.clone() }
    }

    fn current_status(&mut self) -> RuntimeStatus {
        let Some(process) = self.process.as_mut() else {
            return RuntimeStatus { enabled: false, status: "STOPPED", message: self.last_message.clone(), process_id: 0 };
        };
        if let Ok(Some(code)) = process.try_wait() {
            self.process = None;
            self.last_message = format!("Client runtime exited with code {code}.");
            return RuntimeStatus { enabled: false, status: "STOPPED", message: self.last_message.clone(), process_id: 0 };
        }
        RuntimeStatus { enabled: true, status: "RUNNING", message: self.last_message.clone(), process_id: process.id() }
    }

    fn start(&mut self) -> Result<RuntimeStatus, SupervisorError> {
        let current = self.current_status();
        if current.enabled {
            return Ok(current);
        }
        let port = self.settings.runtime_port;
        if self.launcher.port_is_open(port) {
            self.last_message = format!(
                "Client runtime port {port} is already in use by a process not owned by this supervisor. Stop that process and retry."
            );
            return Ok(self.current_status());
        }
        if let Some(error) = self.dependency_error() {
            self.last_message = format!("Client runtime dependencies are unavailable: {error}");
            return Ok(self.current_status());
        }
        let spec = self.spec(&self.settings.command.clone());
        let mut process = match self.launcher.spawn(&spec) {
            Ok(process) => process,
            Err(error) => {
                self.last_message = format!("Client runtime failed to start: {}", error_message(&error));
                return Ok(self.current_status());
            }
        };
        if !self.wait_until_ready(process.as_mut()) {
            let detail = match process.try_wait() {
                Ok(Some(code)) => format!("exited with code {code}"),
                _ => format!("did not listen on port {port} in time"),
            };
            self.last_message = format!("Client runtime {detail}.");
            let outcome = terminate(process.as_mut(), self.settings.stop_timeout);
            if outcome.is_err() {
                // Keep it: it may still run, and the next stop retries.
                self.process = Some(process);
                return Err(SupervisorError::StopFailed);
            }
            self.wait_port_released();
            return Ok(self.current_status());
        }
        self.process = Some(process);
        self.last_message = "Client runtime started.".into();
        Ok(self.current_status())
    }

    fn stop(&mut self) -> Result<RuntimeStatus, SupervisorError> {
        let alive = match self.process.as_mut() {
            Some(process) => !matches!(process.try_wait(), Ok(Some(_))),
            None => false,
        };
        if !alive {
            self.process = None;
            self.last_message = "Client runtime is stopped.".into();
            return Ok(self.current_status());
        }
        if let Some(process) = self.process.as_mut() {
            terminate(process.as_mut(), self.settings.stop_timeout)?;
        }
        self.process = None;
        self.wait_port_released();
        self.last_message = "Client runtime stopped.".into();
        Ok(self.current_status())
    }

    fn set_enabled(&mut self, enabled: bool, use_local: Option<bool>) -> Result<RuntimeStatus, SupervisorError> {
        if let Some(wanted) = use_local
            && wanted != use_local_stack(&self.settings.environment)?
        {
            self.stop()?;
            self.settings.environment.insert("PRIVOKE_USE_LOCAL_STACK".into(), wanted.to_string());
        }
        if enabled { self.start() } else { self.stop() }
    }

    /// The operating system closes a dead process's listening socket a moment after the process is gone. A restart
    /// right after a stop (a stack switch) must not mistake that for a foreign process on the port.
    fn wait_port_released(&mut self) {
        let deadline = Instant::now() + self.settings.stop_timeout.min(Duration::from_secs(5));
        while self.launcher.port_is_open(self.settings.runtime_port) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_until_ready(&mut self, process: &mut dyn ChildHandle) -> bool {
        let deadline = Instant::now() + self.settings.startup_timeout;
        while Instant::now() < deadline {
            if matches!(process.try_wait(), Ok(Some(_))) {
                return false;
            }
            if self.launcher.port_is_open(self.settings.runtime_port) {
                // A socket opened just before the child failed is not a healthy runtime: let it prove it stays alive.
                std::thread::sleep(self.settings.settle);
                return matches!(process.try_wait(), Ok(None));
            }
            std::thread::sleep(self.settings.poll_interval);
        }
        false
    }

    fn dependency_error(&mut self) -> Option<String> {
        let command = self.settings.dependency_check.clone()?;
        let spec = self.spec(&command);
        match self.launcher.check(&spec, self.settings.startup_timeout) {
            Err(error) => Some(error_message(&error)),
            Ok(outcome) if outcome.code == 0 => None,
            Ok(outcome) => {
                let text = if outcome.stderr.trim().is_empty() { &outcome.stdout } else { &outcome.stderr };
                Some(
                    text.trim()
                        .lines()
                        .last()
                        .map_or_else(|| format!("dependency check exited with code {}", outcome.code), str::to_string),
                )
            }
        }
    }
}

/// Stop a child's tree. An error, even when the launcher process has meanwhile exited, is not ignored: part of the
/// tree may still hold the port.
fn terminate(process: &mut dyn ChildHandle, grace: Duration) -> Result<(), SupervisorError> {
    if matches!(process.try_wait(), Ok(Some(_))) {
        return Ok(());
    }
    process.terminate(grace).map_err(|_| SupervisorError::StopFailed)
}

/// Exposed for the failure-injection tests.
#[doc(hidden)]
pub fn terminate_for_test(process: &mut dyn ChildHandle, grace: Duration) -> Result<(), SupervisorError> {
    terminate(process, grace)
}

fn error_message(error: &io::Error) -> String {
    let text = error.to_string();
    if text.trim().is_empty() { format!("{:?}", error.kind()) } else { text.trim().to_string() }
}

enum Request {
    Start,
    Stop,
    SetEnabled(bool, Option<bool>),
    Status,
    Environment,
}

enum Reply {
    Status(Result<RuntimeStatus, SupervisorError>),
    Environment(BTreeMap<String, String>),
}

/// The handle to the supervisor thread.
#[derive(Debug)]
pub struct RuntimeProcessSupervisor {
    requests: Option<Sender<(Request, Sender<Reply>)>>,
    thread: Option<JoinHandle<()>>,
    settings: Arc<SupervisorSettings>,
}

impl RuntimeProcessSupervisor {
    /// Start the actor thread. Nothing is launched until [`Self::start`] or [`Self::set_enabled`].
    pub fn new(settings: SupervisorSettings, launcher: Box<dyn Launcher>) -> Self {
        let shared = Arc::new(settings.clone());
        let (requests, inbox) = channel();
        let thread = std::thread::Builder::new()
            .name("runtime-supervisor".into())
            .spawn(move || {
                actor(State { settings, launcher, process: None, last_message: "Client runtime has not been started.".into() }, &inbox)
            })
            .ok();
        Self { requests: Some(requests), thread, settings: shared }
    }

    /// The settings as constructed (the live environment is [`Self::environment`]).
    pub fn settings(&self) -> &SupervisorSettings {
        &self.settings
    }

    fn call(&self, request: Request) -> Result<Reply, SupervisorError> {
        let (reply, answer) = channel();
        self.requests.as_ref().ok_or(SupervisorError::Closed)?.send((request, reply)).map_err(|_| SupervisorError::Closed)?;
        answer.recv().map_err(|_| SupervisorError::Closed)
    }

    fn status_call(&self, request: Request) -> Result<RuntimeStatus, SupervisorError> {
        match self.call(request)? {
            Reply::Status(status) => status,
            Reply::Environment(_) => Err(SupervisorError::Closed),
        }
    }

    /// Start the runtime (no-op while it runs).
    pub fn start(&self) -> Result<RuntimeStatus, SupervisorError> {
        self.status_call(Request::Start)
    }

    /// Stop the runtime and its tree.
    pub fn stop(&self) -> Result<RuntimeStatus, SupervisorError> {
        self.status_call(Request::Stop)
    }

    /// Start or stop. A change of `use_local` stops the child first and records the choice in the environment.
    pub fn set_enabled(&self, enabled: bool, use_local: Option<bool>) -> Result<RuntimeStatus, SupervisorError> {
        self.status_call(Request::SetEnabled(enabled, use_local))
    }

    /// The current status; notices a child that has exited.
    pub fn status(&self) -> Result<RuntimeStatus, SupervisorError> {
        self.status_call(Request::Status)
    }

    /// The live environment the child is launched with (it changes with `use_local`).
    pub fn environment(&self) -> Result<BTreeMap<String, String>, SupervisorError> {
        match self.call(Request::Environment)? {
            Reply::Environment(environment) => Ok(environment),
            Reply::Status(_) => Err(SupervisorError::Closed),
        }
    }

    /// Stop the runtime and end the thread. The child is also stopped when the handle is dropped.
    pub fn shutdown(&mut self) -> Result<(), SupervisorError> {
        let outcome = if self.requests.is_some() { self.stop().map(|_| ()) } else { Ok(()) };
        self.requests = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        outcome
    }
}

impl Drop for RuntimeProcessSupervisor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn actor(mut state: State, inbox: &Receiver<(Request, Sender<Reply>)>) {
    while let Ok((request, reply)) = inbox.recv() {
        let answer = match request {
            Request::Start => Reply::Status(state.start()),
            Request::Stop => Reply::Status(state.stop()),
            Request::SetEnabled(enabled, use_local) => Reply::Status(state.set_enabled(enabled, use_local)),
            Request::Status => Reply::Status(Ok(state.current_status())),
            Request::Environment => Reply::Environment(state.settings.environment.clone()),
        };
        let _ = reply.send(answer);
    }
    // Handle dropped: leave nothing running.
    if let Some(process) = state.process.as_mut() {
        let _ = terminate(process.as_mut(), state.settings.stop_timeout);
    }
}
