//! The W1 worker frame protocol (`docs/runtime/worker-protocol.md`, reference codec
//! `extension/client-runtime/src/worker_protocol.py`): a 20-byte big-endian header and a payload.
//!
//! The pool (W2) hands this worker one whole W1 frame per pool frame, so the codec here works on a complete frame:
//! it checks the header, applies the method's limits and returns the request. Everything the Python reader rejects is
//! rejected with the same code.

/// The protocol version.
pub const VERSION: u8 = 1;
/// The size of a header.
pub const HEADER_LEN: usize = 20;
/// The largest payload any frame may declare.
pub const HARD_MAX_PAYLOAD: usize = 64 * 1024 * 1024;

/// Frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Controller to worker.
    Request = 1,
    /// A successful answer.
    Response = 2,
    /// A protocol or worker fault.
    Error = 3,
    /// The first frame of a worker.
    Ready = 4,
}

/// The method tags of `PrivokeRuntimeService`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
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

impl Method {
    /// The method for a tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            1 => Self::AnalyzePrompt,
            2 => Self::DetectAnnotationPresence,
            3 => Self::Health,
            4 => Self::ComputeSemanticGradients,
            5 => Self::ComputeUnderlyingModelGradients,
            6 => Self::ComputePresenceGradients,
            _ => return None,
        })
    }

    /// The gRPC method name.
    pub fn name(self) -> &'static str {
        match self {
            Self::AnalyzePrompt => "AnalyzePrompt",
            Self::DetectAnnotationPresence => "DetectAnnotationPresence",
            Self::Health => "Health",
            Self::ComputeSemanticGradients => "ComputeSemanticGradients",
            Self::ComputeUnderlyingModelGradients => "ComputeUnderlyingModelGradients",
            Self::ComputePresenceGradients => "ComputePresenceGradients",
        }
    }

    /// True for the gradient methods, which may carry a metadata block.
    pub fn is_gradient(self) -> bool {
        matches!(self, Self::ComputeSemanticGradients | Self::ComputeUnderlyingModelGradients | Self::ComputePresenceGradients)
    }

    /// The method's limits (`METHOD_LIMITS`).
    pub fn limits(self) -> Limits {
        const KIB: usize = 1024;
        const MIB: usize = 1024 * KIB;
        match self {
            Self::AnalyzePrompt | Self::DetectAnnotationPresence => {
                Limits { max_request: 256 * KIB, max_response: MIB, default_deadline_ms: 25_000, max_deadline_ms: 25_000 }
            }
            Self::Health => Limits { max_request: KIB, max_response: 4 * KIB, default_deadline_ms: 5_000, max_deadline_ms: 5_000 },
            Self::ComputeSemanticGradients | Self::ComputePresenceGradients => {
                Limits { max_request: 4 * MIB, max_response: 64 * MIB, default_deadline_ms: 120_000, max_deadline_ms: 900_000 }
            }
            Self::ComputeUnderlyingModelGradients => {
                Limits { max_request: 4 * MIB, max_response: 64 * MIB, default_deadline_ms: 300_000, max_deadline_ms: 900_000 }
            }
        }
    }
}

/// Size and time limits of a method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest request payload.
    pub max_request: usize,
    /// The largest response payload.
    pub max_response: usize,
    /// The deadline when the request names none.
    pub default_deadline_ms: u32,
    /// The longest deadline a request may ask for.
    pub max_deadline_ms: u32,
}

/// Error codes (`CODE_*` of `worker_protocol.py`).
pub mod code {
    /// A frame whose declared length disagrees with its size, or that is shorter than a header.
    pub const MALFORMED_FRAME: &str = "MALFORMED_FRAME";
    /// A protocol version other than 1.
    pub const UNSUPPORTED_VERSION: &str = "UNSUPPORTED_VERSION";
    /// A frame that is not a request.
    pub const INVALID_KIND: &str = "INVALID_KIND";
    /// A method tag the protocol does not define, or one this worker does not serve.
    pub const UNKNOWN_METHOD: &str = "UNKNOWN_METHOD";
    /// Unknown flag bits, or metadata on a method that takes none.
    pub const INVALID_FLAGS: &str = "INVALID_FLAGS";
    /// A payload above the method's request limit.
    pub const FRAME_TOO_LARGE: &str = "FRAME_TOO_LARGE";
    /// A payload that is not the method's request message.
    pub const INVALID_PAYLOAD: &str = "INVALID_PAYLOAD";
    /// An empty layer list, or the runtime layer.
    pub const INVALID_LAYERS: &str = "INVALID_LAYERS";
    /// A layer selection this worker does not serve (the supervisor routes it to the Python worker).
    pub const UNSUPPORTED_LAYERS: &str = "UNSUPPORTED_LAYERS";
    /// A malformed metadata block (gradient methods).
    pub const INVALID_METADATA: &str = "INVALID_METADATA";
    /// A request this worker declines before it executes anything: the shape is not one this worker serves, so the
    /// controller sends the same call to the Python worker. Nothing has run when this code is sent.
    pub const UNSUPPORTED_ROUTE: &str = "UNSUPPORTED_ROUTE";
    /// A response above the method's limit.
    pub const RESPONSE_TOO_LARGE: &str = "RESPONSE_TOO_LARGE";
    /// A handler that finished after its deadline.
    pub const DEADLINE_EXCEEDED: &str = "DEADLINE_EXCEEDED";
    /// An unexpected failure inside a handler.
    pub const INTERNAL: &str = "INTERNAL";
    /// The sandbox self-check found network capability.
    pub const SANDBOX_VIOLATION: &str = "SANDBOX_VIOLATION";
    /// The worker could not start.
    pub const STARTUP_FAILED: &str = "STARTUP_FAILED";
}

/// A rejected frame: the code, the message and the request id to answer under.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct FrameError {
    /// One of [`code`].
    pub code: &'static str,
    /// What was wrong.
    pub message: String,
    /// The offending request's id, 0 when none could be read.
    pub request_id: u64,
}

impl FrameError {
    /// A new error.
    pub fn new(code: &'static str, message: impl Into<String>, request_id: u64) -> Self {
        Self { code, message: message.into(), request_id }
    }
}

/// A request frame that passed the header checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The controller's request id.
    pub request_id: u64,
    /// The deadline in milliseconds, clamped to the method's maximum; the default when the frame names none.
    pub deadline_ms: u32,
    /// The metadata block of a gradient request (the training admission header), empty when the frame has none.
    pub metadata: Vec<(String, String)>,
    /// The protobuf message.
    pub payload: Vec<u8>,
}

/// The most entries, the longest key and the longest value of a metadata block (`worker_protocol.py`).
pub const METADATA_MAX_ENTRIES: usize = 16;
/// The longest metadata key in bytes.
pub const METADATA_MAX_KEY_BYTES: usize = 64;
/// The longest metadata value in bytes.
pub const METADATA_MAX_VALUE_BYTES: usize = 16 * 1024;

fn take<'a>(payload: &'a [u8], offset: &mut usize, count: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(count)?;
    let slice = payload.get(*offset..end)?;
    *offset = end;
    Some(slice)
}

/// Builds the metadata block that precedes the protobuf message when the frame's metadata flag is set.
pub fn encode_metadata(pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u16::try_from(pairs.len()).unwrap_or(u16::MAX).to_be_bytes());
    for (key, value) in pairs {
        out.extend_from_slice(&u16::try_from(key.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// `split_metadata`: the pairs and the protobuf bytes behind them.
/// A metadata block's key and value pairs.
pub type MetadataPairs = Vec<(String, String)>;

/// `split_metadata`, as above.
pub fn split_metadata(payload: &[u8], request_id: u64) -> Result<(MetadataPairs, &[u8]), FrameError> {
    let bad = |reason: &str| FrameError::new(code::INVALID_METADATA, format!("Malformed metadata block: {reason}"), request_id);
    let mut offset = 0usize;
    let head = take(payload, &mut offset, 2).ok_or_else(|| bad("truncated"))?;
    let count = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if count > METADATA_MAX_ENTRIES {
        return Err(bad("too many entries"));
    }
    let mut pairs = Vec::with_capacity(count);
    for _ in 0..count {
        let head = take(payload, &mut offset, 2).ok_or_else(|| bad("truncated"))?;
        let key_length = usize::from(u16::from_be_bytes([head[0], head[1]]));
        if key_length == 0 || key_length > METADATA_MAX_KEY_BYTES {
            return Err(bad("bad key length"));
        }
        let key = take(payload, &mut offset, key_length).ok_or_else(|| bad("bad key length"))?;
        let key = std::str::from_utf8(key).map_err(|_| bad("key is not UTF-8"))?;
        let head = take(payload, &mut offset, 4).ok_or_else(|| bad("truncated"))?;
        let value_length = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
        if value_length > METADATA_MAX_VALUE_BYTES {
            return Err(bad("bad value length"));
        }
        let value = take(payload, &mut offset, value_length).ok_or_else(|| bad("bad value length"))?;
        let value = std::str::from_utf8(value).map_err(|_| bad("value is not UTF-8"))?;
        pairs.push((key.to_string(), value.to_string()));
    }
    Ok((pairs, &payload[offset..]))
}

/// Builds a frame.
pub fn encode_frame(kind: Kind, method: u8, request_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap_or(u32::MAX).to_be_bytes());
    frame.extend_from_slice(&[VERSION, kind as u8, method, 0]);
    frame.extend_from_slice(&request_id.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(payload);
    frame
}

/// `json.dumps(text, ensure_ascii=True)` of a string.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{:04x}", *unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// An `ERROR` frame: the payload is `{"code": ..., "message": ...}` as Python writes it (sorted keys, ASCII).
pub fn encode_error(request_id: u64, code: &str, message: &str) -> Vec<u8> {
    let body = format!("{{\"code\": {}, \"message\": {}}}", json_string(code), json_string(message));
    encode_frame(Kind::Error, 0, request_id, body.as_bytes())
}

/// Reads and checks one whole request frame. The error carries the code and the id to answer under.
pub fn decode_request(frame: &[u8]) -> Result<Request, FrameError> {
    if frame.len() < HEADER_LEN {
        return Err(FrameError::new(code::MALFORMED_FRAME, format!("A frame of {} bytes is shorter than its header.", frame.len()), 0));
    }
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let (version, kind, method, flags) = (frame[4], frame[5], frame[6], frame[7]);
    let mut id = [0u8; 8];
    id.copy_from_slice(&frame[8..16]);
    let request_id = u64::from_be_bytes(id);
    let deadline = u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]);
    if length != frame.len() - HEADER_LEN || length > HARD_MAX_PAYLOAD {
        return Err(FrameError::new(
            code::MALFORMED_FRAME,
            format!("The frame declares {length} payload bytes but carries {}.", frame.len() - HEADER_LEN),
            request_id,
        ));
    }
    if version != VERSION {
        return Err(FrameError::new(code::UNSUPPORTED_VERSION, format!("Unsupported protocol version {version}."), request_id));
    }
    if kind != Kind::Request as u8 {
        return Err(FrameError::new(code::INVALID_KIND, format!("Only request frames are accepted, got kind {kind}."), request_id));
    }
    let Some(method) = Method::from_tag(method) else {
        return Err(FrameError::new(code::UNKNOWN_METHOD, format!("Unknown method tag {method}."), request_id));
    };
    if flags & !1 != 0 {
        return Err(FrameError::new(code::INVALID_FLAGS, format!("Unknown flag bits {:#04x}.", flags & !1), request_id));
    }
    if flags & 1 != 0 && !method.is_gradient() {
        return Err(FrameError::new(code::INVALID_FLAGS, "Metadata is accepted only on gradient methods.", request_id));
    }
    let limits = method.limits();
    if length > limits.max_request {
        return Err(FrameError::new(
            code::FRAME_TOO_LARGE,
            format!("{} request payload of {length} bytes exceeds the {} byte limit.", method.name(), limits.max_request),
            request_id,
        ));
    }
    let deadline_ms = if deadline == 0 { limits.default_deadline_ms } else { deadline.min(limits.max_deadline_ms) };
    let body = &frame[HEADER_LEN..];
    let (metadata, payload) = if flags & 1 != 0 { split_metadata(body, request_id)? } else { (Vec::new(), body) };
    Ok(Request { method, request_id, deadline_ms, metadata, payload: payload.to_vec() })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn request_frame(method: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = encode_frame(Kind::Request, method, 77, payload);
        frame[7] = flags;
        frame
    }

    #[test]
    fn a_request_round_trips_and_gets_the_default_deadline() {
        let request = decode_request(&request_frame(1, 0, b"abc")).unwrap();
        assert_eq!((request.method, request.request_id, request.deadline_ms), (Method::AnalyzePrompt, 77, 25_000));
        assert_eq!(request.payload, b"abc");
        let mut frame = request_frame(1, 0, b"");
        frame[16..20].copy_from_slice(&90_000u32.to_be_bytes());
        assert_eq!(decode_request(&frame).unwrap().deadline_ms, 25_000);
    }

    #[test]
    fn rejections_carry_the_python_codes_and_the_request_id() {
        let code_of = |frame: Vec<u8>| decode_request(&frame).unwrap_err();
        assert_eq!(code_of(request_frame(9, 0, b"")).code, code::UNKNOWN_METHOD);
        assert_eq!(code_of(request_frame(1, 2, b"")).code, code::INVALID_FLAGS);
        assert_eq!(code_of(request_frame(1, 1, b"")).code, code::INVALID_FLAGS);
        assert_eq!(code_of(request_frame(3, 0, &[0; 2000])).code, code::FRAME_TOO_LARGE);
        let mut wrong_version = request_frame(1, 0, b"");
        wrong_version[4] = 2;
        assert_eq!(code_of(wrong_version).code, code::UNSUPPORTED_VERSION);
        let mut response = request_frame(1, 0, b"");
        response[5] = 2;
        let error = code_of(response);
        assert_eq!((error.code, error.request_id), (code::INVALID_KIND, 77));
        let mut short = request_frame(1, 0, b"abc");
        short.pop();
        assert_eq!(code_of(short).code, code::MALFORMED_FRAME);
        assert_eq!(code_of(vec![0; 5]).code, code::MALFORMED_FRAME);
    }

    #[test]
    fn a_metadata_block_is_split_off_gradient_requests() {
        let mut payload = encode_metadata(&[("x-privoke-training-admission-v1", "{\"schema\": 2}"), ("k", "")]);
        payload.extend_from_slice(b"proto");
        let request = decode_request(&request_frame(4, 1, &payload)).unwrap();
        assert_eq!(request.payload, b"proto");
        assert_eq!(
            request.metadata,
            vec![("x-privoke-training-admission-v1".to_string(), "{\"schema\": 2}".to_string()), ("k".to_string(), String::new())]
        );
        // Without the flag the payload is the message and nothing is split off.
        let plain = decode_request(&request_frame(4, 0, b"proto")).unwrap();
        assert!(plain.metadata.is_empty() && plain.payload == b"proto");
    }

    #[test]
    fn a_malformed_metadata_block_is_invalid_metadata_with_the_request_id() {
        let code_of = |payload: &[u8]| decode_request(&request_frame(4, 1, payload)).unwrap_err();
        assert_eq!(code_of(&[0]).code, code::INVALID_METADATA);
        assert_eq!(code_of(&[0, 1, 0, 0]).code, code::INVALID_METADATA);
        assert_eq!(code_of(&[0, 17]).code, code::INVALID_METADATA);
        let mut truncated = encode_metadata(&[("key", "value")]);
        truncated.pop();
        let error = code_of(&truncated);
        assert_eq!((error.code, error.request_id), (code::INVALID_METADATA, 77));
        let long_key = "k".repeat(65);
        assert_eq!(code_of(&encode_metadata(&[(long_key.as_str(), "v")])).code, code::INVALID_METADATA);
    }

    #[test]
    fn error_frames_match_python_json() {
        let frame = encode_error(5, "INVALID_LAYERS", "no \"layers\" \u{e9}\u{1f600}");
        assert_eq!(&frame[..4], &((frame.len() - HEADER_LEN) as u32).to_be_bytes());
        assert_eq!(&frame[4..8], &[1, 3, 0, 0]);
        let body = std::str::from_utf8(&frame[HEADER_LEN..]).unwrap();
        assert_eq!(body, "{\"code\": \"INVALID_LAYERS\", \"message\": \"no \\\"layers\\\" \\u00e9\\ud83d\\ude00\"}");
    }
}
