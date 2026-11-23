//! A stand-in for the W1 worker that records every request it is asked to serve. Built only with the `test-helpers`
//! feature. It lets a test prove that a call never reached a worker: each request frame appends one line (the W1 method
//! tag) to the file named by `--log`, and is answered with an empty response.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Write};

use privoke_analysis::frames::{self, HEADER_LEN, Kind, VERSION};
use privoke_worker_pool::{read_frame_sync, write_frame_sync};

/// A W1 frame (header and payload) in the codec's layout.
fn frame(kind: Kind, method: u8, id: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[VERSION, kind as u8, method, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let mut log = None;
    while let Some(argument) = arguments.next() {
        if argument == "--log" {
            log = arguments.next();
        }
    }
    let log = log.expect("--log <file> is required");
    let mut out = io::stdout().lock();
    let mut input = io::stdin().lock();
    write_frame_sync(&mut out, &frame(Kind::Ready, 0, 0, br#"{"implementation": "stand-in", "protocol_version": 1}"#)).expect("write");
    while let Ok(bytes) = read_frame_sync(&mut input) {
        let Ok((header, _)) = frames::decode(&bytes) else { std::process::exit(5) };
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&log).expect("the log opens");
        writeln!(file, "{}", header.method).expect("the log is written");
        write_frame_sync(&mut out, &frame(Kind::Response, header.method, header.request_id, b"")).expect("write");
    }
}
