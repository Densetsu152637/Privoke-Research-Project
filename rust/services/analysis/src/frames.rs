//! The W1 worker frame codec (`docs/runtime/worker-protocol.md`): a 20-byte big-endian header and a payload.
//!
//! The pool frames each of these with its own 4-byte length (see `worker_shim.py`); this module only builds and reads
//! the inner W1 frame.

/// Header size in bytes.
pub const HEADER_LEN: usize = 20;
/// The protocol version this codec speaks.
pub const VERSION: u8 = 1;
/// Request flag: the payload starts with a metadata block.
pub const FLAG_METADATA: u8 = 1;
/// The most metadata entries a block may hold.
pub const MAX_METADATA_ENTRIES: usize = 16;

/// What a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Controller to worker.
    Request = 1,
    /// Worker answer.
    Response = 2,
    /// Worker error.
    Error = 3,
    /// First frame of a worker.
    Ready = 4,
}

/// Method tags of the W1 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `AnalyzePrompt`.
    AnalyzePrompt = 1,
    /// `DetectAnnotationPresence`.
    DetectAnnotationPresence = 2,
    /// `Health`.
    Health = 3,
    /// `ComputeSemanticGradients`.
    ComputeSemanticGradients = 4,
    /// `ComputeUnderlyingModelGradients`.
    ComputeUnderlyingModelGradients = 5,
    /// `ComputePresenceGradients`.
    ComputePresenceGradients = 6,
}

/// A decoded header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The kind byte, undecoded.
    pub kind: u8,
    /// The method tag.
    pub method: u8,
    /// The flags.
    pub flags: u8,
    /// The request id.
    pub request_id: u64,
}

/// Builds a request frame. `metadata` is the invocation metadata the worker reads (the training admission header).
pub fn encode_request(
    method: Method,
    request_id: u64,
    deadline_ms: u32,
    metadata: &[(String, String)],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let block = if metadata.is_empty() { Vec::new() } else { encode_metadata(metadata)? };
    let flags = if metadata.is_empty() { 0 } else { FLAG_METADATA };
    let body_len = block.len() + payload.len();
    let body_len32 = u32::try_from(body_len).map_err(|_| "request payload is too large".to_string())?;
    let mut frame = Vec::with_capacity(HEADER_LEN + body_len);
    frame.extend_from_slice(&body_len32.to_be_bytes());
    frame.extend_from_slice(&[VERSION, Kind::Request as u8, method as u8, flags]);
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&deadline_ms.to_be_bytes());
    frame.extend_from_slice(&block);
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// `u16 count`, then per entry `u16 key_len`, key, `u32 value_len`, value.
fn encode_metadata(entries: &[(String, String)]) -> Result<Vec<u8>, String> {
    if entries.len() > MAX_METADATA_ENTRIES {
        return Err("too many metadata entries".into());
    }
    let mut block = Vec::new();
    block.extend_from_slice(&u16::try_from(entries.len()).map_err(|_| "too many metadata entries".to_string())?.to_be_bytes());
    for (key, value) in entries {
        block.extend_from_slice(&u16::try_from(key.len()).map_err(|_| "metadata key is too long".to_string())?.to_be_bytes());
        block.extend_from_slice(key.as_bytes());
        block.extend_from_slice(&u32::try_from(value.len()).map_err(|_| "metadata value is too long".to_string())?.to_be_bytes());
        block.extend_from_slice(value.as_bytes());
    }
    Ok(block)
}

/// Splits a whole frame into its header and payload, checking the length field against the frame.
pub fn decode(frame: &[u8]) -> Result<(Header, &[u8]), String> {
    if frame.len() < HEADER_LEN {
        return Err(format!("frame of {} bytes is shorter than the {HEADER_LEN}-byte header", frame.len()));
    }
    let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if declared != frame.len() - HEADER_LEN {
        return Err(format!("frame declares {declared} payload bytes but carries {}", frame.len() - HEADER_LEN));
    }
    if frame[4] != VERSION {
        return Err(format!("unsupported frame version {}", frame[4]));
    }
    let mut id = [0u8; 8];
    id.copy_from_slice(&frame[8..16]);
    Ok((Header { kind: frame[5], method: frame[6], flags: frame[7], request_id: u64::from_be_bytes(id) }, &frame[HEADER_LEN..]))
}

/// The gRPC status for a worker error code. Codes that point at this service's own framing (an unknown method, a bad
/// version) are internal errors: the client cannot cause them.
pub fn status_for_worker_code(code: &str, message: &str) -> tonic::Status {
    use tonic::Status;
    match code {
        "INVALID_PAYLOAD" | "INVALID_LAYERS" | "INVALID_METADATA" | "INVALID_FLAGS" => Status::invalid_argument(message.to_string()),
        "FRAME_TOO_LARGE" | "RESPONSE_TOO_LARGE" => Status::resource_exhausted(message.to_string()),
        "DEADLINE_EXCEEDED" => Status::deadline_exceeded(message.to_string()),
        _ => Status::internal(format!("worker error {code}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn request_header_is_twenty_big_endian_bytes() {
        let frame = encode_request(Method::ComputePresenceGradients, 0x0102_0304_0506_0708, 7, &[], b"abc").unwrap();
        assert_eq!(&frame[..20], &[0, 0, 0, 3, 1, 1, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 7]);
        assert_eq!(&frame[20..], b"abc");
        let (header, payload) = decode(&frame).unwrap();
        assert_eq!((header.kind, header.method, header.flags, header.request_id), (1, 6, 0, 0x0102_0304_0506_0708));
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn metadata_block_precedes_the_message_and_sets_the_flag() {
        let frame = encode_request(Method::ComputeSemanticGradients, 9, 0, &[("k".into(), "vv".into())], b"M").unwrap();
        let (header, payload) = decode(&frame).unwrap();
        assert_eq!(header.flags, FLAG_METADATA);
        assert_eq!(payload, [0, 1, 0, 1, b'k', 0, 0, 0, 2, b'v', b'v', b'M']);
    }

    #[test]
    fn length_mismatch_and_short_frames_are_refused() {
        let mut frame = encode_request(Method::Health, 1, 0, &[], b"").unwrap();
        frame.push(0);
        assert!(decode(&frame).is_err());
        assert!(decode(&[0; 5]).is_err());
    }
}
