//! The native-messaging host: length-prefixed JSON on stdio. The port of `native_messaging_host.py`.
//!
//! Replay contract (the stage 0 transcripts in `tests/conformance/native_messaging.json`): the same bytes in produce
//! the same bytes out, and the same malformed inputs end the process without a reply.
//!
//! - Frames are a native-endian `u32` length and a UTF-8 JSON body of at most 1 MiB, in both directions.
//! - Only `{"action": "ensure_supervisor"}` is supported. Everything else that parses answers `Unsupported native
//!   launcher request.`, except a top-level `null`, which ends the session as end of input did in Python.
//! - A truncated header or body, an oversized length, invalid UTF-8 or invalid JSON ends the session with an error and
//!   no reply (the Python host raised); earlier replies stay written.
//! - Replies are written like `json.dumps(..., separators=(",", ":"))` with `ensure_ascii`.
//!
//! `ensure_supervisor` keeps the Python decision order: the bridge port open means already running; the control
//! port open means conflict; otherwise start the supervisor entry detached and wait for the bridge port. In the Rust
//! build the entry is `privoke-supervisor serve`. The gRPC-Web bridge is not rebuilt (plan, stage 7), so the readiness
//! port is whatever the extension waits on today; W4 replaces it with the native port.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::pyjson::{self, Json};

/// The registered native host name.
pub const HOST_NAME: &str = "org.privoke.runtime_launcher";
/// The largest frame accepted.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Where the extension's bridge listens today.
pub const BRIDGE_PORT: u16 = 8080;
/// Where the control service listens.
pub const CONTROL_PORT: u16 = 50056;

/// Everything the host needs to answer `ensure_supervisor`.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// The bridge port that means "ready".
    pub bridge_port: u16,
    /// The control port that must be free.
    pub control_port: u16,
    /// The supervisor program to start.
    pub supervisor_entry: PathBuf,
    /// Its arguments.
    pub supervisor_args: Vec<OsString>,
    /// Where its output goes.
    pub log_path: PathBuf,
    /// The repository root, passed to it as `PRIVOKE_REPOSITORY_ROOT`.
    pub repository_root: Option<PathBuf>,
    /// How long to wait for the bridge port.
    pub startup_timeout: Duration,
}

impl HostConfig {
    /// The default: this binary, `serve`, ports 8080 and 50056, ten seconds.
    pub fn standard(entry: PathBuf, repository_root: Option<PathBuf>, log_path: PathBuf) -> Self {
        Self {
            bridge_port: BRIDGE_PORT,
            control_port: CONTROL_PORT,
            supervisor_entry: entry,
            supervisor_args: vec![OsString::from("serve")],
            log_path,
            repository_root,
            startup_timeout: Duration::from_secs(10),
        }
    }
}

/// The reply object. Field order is the wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Whether the supervisor is (now) available.
    pub ok: bool,
    /// Whether this call started it.
    pub started: bool,
    /// The supervisor's process id, when started.
    pub process_id: Option<u32>,
    /// What happened.
    pub message: String,
    /// The supervisor log, when one was involved.
    pub log_path: Option<String>,
}

impl Reply {
    fn plain(ok: bool, message: impl Into<String>) -> Self {
        Self { ok, started: false, process_id: None, message: message.into(), log_path: None }
    }

    /// The compact, ASCII-escaped JSON body.
    pub fn to_json(&self) -> String {
        let mut out = format!("{{\"ok\":{},\"started\":{}", self.ok, self.started);
        if let Some(pid) = self.process_id {
            out.push_str(&format!(",\"process_id\":{pid}"));
        }
        out.push_str(&format!(",\"message\":{}", pyjson::dump_string(&self.message)));
        if let Some(path) = &self.log_path {
            out.push_str(&format!(",\"log_path\":{}", pyjson::dump_string(path)));
        }
        out.push('}');
        out
    }
}

/// Why a session ended abnormally. The text is what the Python exception said.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// A framing or content error in a request.
    #[error("{0}")]
    Protocol(String),
    /// The streams failed.
    #[error("{0}")]
    Io(String),
}

fn port_is_open(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok()
}

/// Answer `ensure_supervisor`: report, or start the supervisor and wait for it.
pub fn ensure_supervisor(config: &HostConfig) -> Reply {
    if port_is_open(config.bridge_port) {
        return Reply::plain(true, "PriVoke supervisor bridge is already running.");
    }
    if port_is_open(config.control_port) {
        return Reply::plain(
            false,
            format!(
                "PriVoke control port {} is in use, but the bridge on port {} is unavailable. Stop the conflicting process and retry.",
                config.control_port, config.bridge_port
            ),
        );
    }
    if !config.supervisor_entry.is_file() {
        return Reply::plain(false, format!("PriVoke supervisor entry point is missing: {}", config.supervisor_entry.display()));
    }
    let log = |reply: Reply| Reply { log_path: Some(config.log_path.display().to_string()), ..reply };
    if let Some(parent) = config.log_path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return log(Reply::plain(false, format!("Could not launch the PriVoke supervisor: {error}")));
    }
    let child = match spawn_detached(config) {
        Ok(child) => child,
        Err(error) => return log(Reply::plain(false, format!("Could not launch the PriVoke supervisor: {error}"))),
    };
    let mut child = child;
    let deadline = Instant::now() + config.startup_timeout;
    while Instant::now() < deadline {
        if port_is_open(config.bridge_port) {
            return log(Reply {
                ok: true,
                started: true,
                process_id: Some(child.id()),
                message: "PriVoke supervisor bridge started.".into(),
                log_path: None,
            });
        }
        if let Ok(Some(status)) = child.try_wait() {
            return log(Reply::plain(false, format!("PriVoke supervisor exited with code {}.", status.code().unwrap_or(-1))));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    log(Reply::plain(false, "PriVoke supervisor did not open its bridge within 10 seconds."))
}

fn spawn_detached(config: &HostConfig) -> io::Result<std::process::Child> {
    let open_log = || std::fs::OpenOptions::new().append(true).create(true).open(&config.log_path);
    let build = |flags: Option<u32>| -> io::Result<Command> {
        let mut command = Command::new(&config.supervisor_entry);
        command.args(&config.supervisor_args).stdin(Stdio::null()).stdout(open_log()?).stderr(open_log()?);
        command.env("PRIVOKE_RUNTIME_START_ENABLED", "false");
        if let Some(root) = &config.repository_root {
            command.env("PRIVOKE_REPOSITORY_ROOT", root);
        }
        if let Some(parent) = config.supervisor_entry.parent().filter(|parent| parent.is_dir()) {
            command.current_dir(parent);
        }
        #[cfg(windows)]
        if let Some(flags) = flags {
            use std::os::windows::process::CommandExt;
            command.creation_flags(flags);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let _ = flags;
            command.process_group(0);
        }
        Ok(command)
    };
    // CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, keeping the long-lived supervisor independent of this short-lived
    // host without a console window; plus CREATE_BREAKAWAY_FROM_JOB when the browser's job permits it.
    const DETACH: u32 = 0x0000_0200 | 0x0800_0000;
    const BREAKAWAY: u32 = 0x0100_0000;
    match build(Some(DETACH | BREAKAWAY))?.spawn() {
        Err(error) if cfg!(windows) && error.kind() == io::ErrorKind::PermissionDenied => build(Some(DETACH))?.spawn(),
        other => other,
    }
}

/// One message to a reply. `None` means "no reply and end the session" (a top-level `null`).
pub fn handle_message(message: &Json, config: &HostConfig) -> Reply {
    if let Json::Object { action: Some(action) } = message
        && **action == Json::String("ensure_supervisor".into())
    {
        return ensure_supervisor(config);
    }
    Reply::plain(false, "Unsupported native launcher request.")
}

/// Serve until end of input.
pub fn serve(input: &mut impl Read, output: &mut impl Write, config: &HostConfig) -> Result<(), HostError> {
    while let Some(message) = read_message(input)? {
        if message == Json::Null {
            // `json.loads("null")` is `None`, which the Python loop read as end of input.
            return Ok(());
        }
        write_message(output, &handle_message(&message, config).to_json())?;
    }
    Ok(())
}

fn read_up_to(input: &mut impl Read, count: usize) -> Result<Vec<u8>, HostError> {
    let mut buffer = vec![0u8; count];
    let mut filled = 0;
    while filled < count {
        match input.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(HostError::Io(error.to_string())),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// `None` at end of input.
fn read_message(input: &mut impl Read) -> Result<Option<Json>, HostError> {
    let header = read_up_to(input, 4)?;
    if header.is_empty() {
        return Ok(None);
    }
    let Ok(header) = <[u8; 4]>::try_from(header.as_slice()) else {
        return Err(HostError::Protocol("Incomplete native messaging header.".into()));
    };
    let length = u32::from_ne_bytes(header) as usize;
    if length > MAX_MESSAGE_BYTES {
        return Err(HostError::Protocol("Native messaging request is too large.".into()));
    }
    let payload = read_up_to(input, length)?;
    if payload.len() != length {
        return Err(HostError::Protocol("Incomplete native messaging request.".into()));
    }
    let text = std::str::from_utf8(&payload).map_err(|error| {
        let position = error.valid_up_to();
        HostError::Protocol(format!(
            "'utf-8' codec can't decode byte 0x{:02x} in position {position}: invalid start byte",
            payload[position]
        ))
    })?;
    pyjson::parse(text).map(Some).map_err(HostError::Protocol)
}

fn write_message(output: &mut impl Write, body: &str) -> Result<(), HostError> {
    let io = |error: io::Error| HostError::Io(error.to_string());
    let length = u32::try_from(body.len()).map_err(|_| HostError::Io("reply too large".into()))?;
    output.write_all(&length.to_ne_bytes()).map_err(io)?;
    output.write_all(body.as_bytes()).map_err(io)?;
    output.flush().map_err(io)
}

/// The default log location: `PRIVOKE_SUPERVISOR_LOG`, else `<temp>/PriVoke/runtime-supervisor.log`.
pub fn default_log_path(configured: Option<&str>) -> PathBuf {
    match configured.map(str::trim).filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => std::env::temp_dir().join("PriVoke").join("runtime-supervisor.log"),
    }
}

/// The directory that contains `extension/client-runtime/src/grpc_main.py`, found from `start` upwards.
pub fn find_repository_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|candidate| candidate.join("extension").join("client-runtime").join("src").join("grpc_main.py").is_file())
        .map(Path::to_path_buf)
}
