//! Helpers shared by the integration tests. Not every test file uses every helper.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub fn hex_decode(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

/// A port that was free a moment ago, and that no other test in this process was given: two tests that ask at the same
/// time would otherwise be handed the same ephemeral port after the first listener is dropped.
pub fn free_port() -> u16 {
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    let mut given = GIVEN.lock().unwrap();
    loop {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        if !given.contains(&port) {
            given.push(port);
            return port;
        }
    }
}

pub fn port_is_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200)).is_ok()
}

pub fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    condition()
}

/// Whether a process id is alive.
pub fn process_alive(pid: u32) -> bool {
    if cfg!(windows) {
        let output = Command::new("tasklist").args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"]).output().unwrap();
        String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
    } else {
        Command::new("kill").args(["-0", &pid.to_string()]).stderr(Stdio::null()).status().is_ok_and(|status| status.success())
    }
}

/// A child process that is killed when the guard drops, so a failing test leaves nothing behind.
pub struct Reaper(pub Option<Child>);

impl Reaper {
    pub fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }

    /// Kill without any cleanup by the child, as a crash or `taskkill /F` would.
    pub fn kill(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for Reaper {
    fn drop(&mut self) {
        self.kill();
    }
}

pub mod pki;
