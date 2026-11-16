//! Test stand-ins for the runtime child and the supervisor entry. Built only with the `test-helpers` feature.
//!
//! - `listen <port> [lifetime_ms]`: bind `127.0.0.1:<port>`, answer connections by closing them, sleep, exit.
//! - `listen-env`: as `listen`, on the port in `PRIVOKE_GRPC_PORT` (how the supervisor passes the runtime port), and
//!   print `PID <pid>` to stdout.
//! - `with-grandchild`: start `listen-env` as a child of its own, then wait. Models the Windows venv launcher that
//!   starts the real interpreter.
//! - `exit <code>`: exit at once.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

fn listen(port: u16, lifetime: Duration) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = std::time::Instant::now() + lifetime;
    while std::time::Instant::now() < deadline {
        let _ = listener.accept();
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("listen") => {
            let port: u16 = args.next().expect("port").parse().expect("port number");
            let lifetime = args.next().map_or(Duration::from_secs(120), |ms| Duration::from_millis(ms.parse().expect("ms")));
            listen(port, lifetime);
        }
        Some("listen-env") => {
            let port: u16 = std::env::var("PRIVOKE_GRPC_PORT").expect("PRIVOKE_GRPC_PORT").parse().expect("port number");
            println!("PID {}", std::process::id());
            listen(port, Duration::from_secs(120));
        }
        Some("with-grandchild") => {
            let me = std::env::current_exe().expect("exe");
            let mut child = Command::new(me).arg("listen-env").spawn().expect("grandchild");
            println!("PID {}", std::process::id());
            let _ = child.wait();
        }
        Some("exit") => std::process::exit(args.next().map_or(0, |code| code.parse().expect("code"))),
        _ => std::process::exit(2),
    }
}
