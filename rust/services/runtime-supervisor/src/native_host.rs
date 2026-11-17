//! Native-messaging framing: a native-endian `u32` length and a UTF-8 JSON body, in both directions.
//!
//! Browsers cap what a host sends at 1 MB, so [`MAX_MESSAGE_BYTES`] bounds both directions. A truncated header or
//! body, or a length above the cap, ends the session with an error and no reply: the extension sees the port close
//! and fails every pending request.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The registered native host name. The stage 7 name `org.privoke.runtime_launcher` belongs to the Python launcher,
/// which stays registered for the oracle; the controller has its own so both can coexist on one machine.
pub const HOST_NAME: &str = "org.privoke.runtime_controller";
/// The largest frame accepted or sent: the browsers' own limit for a message from a host.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Why a session ended abnormally.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostError {
    /// A framing or content error in a request.
    #[error("{0}")]
    Protocol(String),
    /// The streams failed.
    #[error("{0}")]
    Io(String),
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

/// The next frame's body, or `None` at end of input on a frame boundary.
pub fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>, HostError> {
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
    Ok(Some(payload))
}

/// Writes one frame. A body above the cap is refused here, so the browser never sees a message it would drop.
pub fn write_frame(output: &mut impl Write, body: &[u8]) -> Result<(), HostError> {
    let io = |error: io::Error| HostError::Io(error.to_string());
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(HostError::Protocol("reply too large".into()));
    }
    let length = u32::try_from(body.len()).map_err(|_| HostError::Protocol("reply too large".into()))?;
    output.write_all(&length.to_ne_bytes()).map_err(io)?;
    output.write_all(body).map_err(io)?;
    output.flush().map_err(io)
}

/// The default log location: `PRIVOKE_SUPERVISOR_LOG`, else `<temp>/PriVoke/runtime-supervisor.log`.
pub fn default_log_path(configured: Option<&str>) -> PathBuf {
    match configured.map(str::trim).filter(|value| !value.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => std::env::temp_dir().join("PriVoke").join("runtime-supervisor.log"),
    }
}

/// The directory that contains `extension/client-runtime/src/worker_main.py`, found from `start` upwards.
pub fn find_repository_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|candidate| candidate.join("extension").join("client-runtime").join("src").join("worker_main.py").is_file())
        .map(Path::to_path_buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(body.len()).unwrap().to_ne_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn frames_round_trip_and_end_cleanly_on_a_boundary() {
        let mut stream = framed(b"{\"a\":1}");
        stream.extend(framed(b"{}"));
        let mut input = stream.as_slice();
        assert_eq!(read_frame(&mut input).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(read_frame(&mut input).unwrap().unwrap(), b"{}");
        assert_eq!(read_frame(&mut input).unwrap(), None);
        let mut out = Vec::new();
        write_frame(&mut out, b"{}").unwrap();
        assert_eq!(out, framed(b"{}"));
    }

    #[test]
    fn truncated_oversized_and_unwritable_frames_are_errors() {
        assert!(matches!(read_frame(&mut [1u8, 0].as_slice()), Err(HostError::Protocol(_))));
        let mut short = framed(b"abcdef");
        short.truncate(7);
        assert!(matches!(read_frame(&mut short.as_slice()), Err(HostError::Protocol(_))));
        let huge = u32::try_from(MAX_MESSAGE_BYTES + 1).unwrap().to_ne_bytes();
        assert!(matches!(read_frame(&mut huge.as_slice()), Err(HostError::Protocol(_))));
        assert!(write_frame(&mut Vec::new(), &vec![b'x'; MAX_MESSAGE_BYTES + 1]).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![b'x'; MAX_MESSAGE_BYTES]).is_ok());
    }
}
