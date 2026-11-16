"""Frame protocol for the PriVoke inference worker (stage W1).

Pure standard library: no protobuf, torch or network imports, so a controller,
a test harness or the stage 11 spaCy worker can share it. The specification is
``docs/runtime/worker-protocol.md``; this module is its reference encoder and
decoder. Frames carry opaque payload bytes. For the ``PrivokeRuntimeService``
methods the payload is the serialized protobuf message of the matching gRPC
method, so the worker adds no second encoding of any analysis message.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO, Mapping, Sequence

PROTOCOL_VERSION = 1

# payload_len u32 | version u8 | kind u8 | method u8 | flags u8 | request_id u64 | deadline_ms u32
HEADER = struct.Struct(">IBBBBQI")
HEADER_SIZE = HEADER.size  # 20

KIB = 1024
MIB = 1024 * KIB

# Largest payload any frame may declare. A length above this cannot be skipped, so the
# stream is abandoned (fatal) instead of resynchronised.
HARD_MAX_PAYLOAD = 64 * MIB

FLAG_METADATA = 0x01
KNOWN_FLAGS = FLAG_METADATA

METADATA_MAX_ENTRIES = 16
METADATA_MAX_KEY_BYTES = 64
METADATA_MAX_VALUE_BYTES = 16 * KIB


class Kind(IntEnum):
    REQUEST = 1
    RESPONSE = 2
    ERROR = 3
    READY = 4


class Method(IntEnum):
    ANALYZE_PROMPT = 1
    DETECT_ANNOTATION_PRESENCE = 2
    HEALTH = 3
    COMPUTE_SEMANTIC_GRADIENTS = 4
    COMPUTE_UNDERLYING_MODEL_GRADIENTS = 5
    COMPUTE_PRESENCE_GRADIENTS = 6
    # 0x10..0x1f are reserved for the stage 11 spaCy worker, 0x20..0x3f for later stages.


GRADIENT_METHODS = frozenset({
    Method.COMPUTE_SEMANTIC_GRADIENTS,
    Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS,
    Method.COMPUTE_PRESENCE_GRADIENTS,
})

# gRPC method name -> tag, for documentation and conformance capture.
GRPC_METHOD_NAMES = {
    Method.ANALYZE_PROMPT: "AnalyzePrompt",
    Method.DETECT_ANNOTATION_PRESENCE: "DetectAnnotationPresence",
    Method.HEALTH: "Health",
    Method.COMPUTE_SEMANTIC_GRADIENTS: "ComputeSemanticGradients",
    Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS: "ComputeUnderlyingModelGradients",
    Method.COMPUTE_PRESENCE_GRADIENTS: "ComputePresenceGradients",
}


@dataclass(frozen=True)
class MethodLimits:
    max_request_payload: int
    max_response_payload: int
    default_deadline_ms: int
    max_deadline_ms: int


# Request caps mirror the gRPC server's receive cap (262,144 bytes) for the small methods.
# Gradient requests carry up to 1,024 examples and 200,000 characters of text (at most four
# UTF-8 bytes each) and so need a larger cap. The 64 MiB response cap exceeds the 38.4 MB
# float32 payload of a full-encoder update of the 9.6M-parameter pretrained-V3 encoder
# (measured legacy payloads are below 0.5 MiB; see docs/runtime/worker-protocol.md).
# Deadlines for analysis stay below the supervisor's 30 s bridge deadline.
METHOD_LIMITS: Mapping[Method, MethodLimits] = {
    Method.ANALYZE_PROMPT: MethodLimits(256 * KIB, 1 * MIB, 25_000, 25_000),
    Method.DETECT_ANNOTATION_PRESENCE: MethodLimits(256 * KIB, 1 * MIB, 25_000, 25_000),
    Method.HEALTH: MethodLimits(1 * KIB, 4 * KIB, 5_000, 5_000),
    Method.COMPUTE_SEMANTIC_GRADIENTS: MethodLimits(4 * MIB, 64 * MIB, 120_000, 900_000),
    Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS: MethodLimits(4 * MIB, 64 * MIB, 300_000, 900_000),
    Method.COMPUTE_PRESENCE_GRADIENTS: MethodLimits(4 * MIB, 64 * MIB, 120_000, 900_000),
}

# Error codes (string, stable). ``fatal`` codes are always followed by worker exit.
CODE_MALFORMED_FRAME = "MALFORMED_FRAME"
CODE_UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
CODE_INVALID_KIND = "INVALID_KIND"
CODE_UNKNOWN_METHOD = "UNKNOWN_METHOD"
CODE_INVALID_FLAGS = "INVALID_FLAGS"
CODE_INVALID_METADATA = "INVALID_METADATA"
CODE_FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
CODE_INVALID_PAYLOAD = "INVALID_PAYLOAD"
CODE_INVALID_LAYERS = "INVALID_LAYERS"
CODE_RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
CODE_DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
CODE_INTERNAL = "INTERNAL"
CODE_STREAM_TRUNCATED = "STREAM_TRUNCATED"
CODE_UNRECOVERABLE_FRAME = "UNRECOVERABLE_FRAME"


class FrameError(Exception):
    """A rejected frame. The stream is positioned at the next frame boundary."""

    def __init__(self, code: str, message: str, request_id: int = 0):
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


class StreamBroken(Exception):
    """The stream cannot be resynchronised (truncated frame or absurd length)."""

    def __init__(self, code: str, message: str, request_id: int = 0):
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True)
class Frame:
    kind: int
    method: int
    flags: int
    request_id: int
    deadline_ms: int
    payload: bytes


@dataclass(frozen=True)
class Request:
    method: Method
    request_id: int
    deadline_ms: int
    metadata: tuple[tuple[str, str], ...]
    payload: bytes


def encode_frame(kind: int, method: int, request_id: int, payload: bytes = b"", *,
                 flags: int = 0, deadline_ms: int = 0) -> bytes:
    if len(payload) > HARD_MAX_PAYLOAD:
        raise ValueError("Frame payload exceeds the protocol hard maximum.")
    return HEADER.pack(len(payload), PROTOCOL_VERSION, int(kind), int(method), flags,
                       request_id, deadline_ms) + payload


def encode_metadata(pairs: Sequence[tuple[str, str]]) -> bytes:
    """Metadata block placed before the protobuf payload when ``FLAG_METADATA`` is set."""
    if len(pairs) > METADATA_MAX_ENTRIES:
        raise ValueError("Too many metadata entries.")
    out = [struct.pack(">H", len(pairs))]
    for key, value in pairs:
        key_bytes, value_bytes = key.encode("utf-8"), value.encode("utf-8")
        if not 0 < len(key_bytes) <= METADATA_MAX_KEY_BYTES or len(value_bytes) > METADATA_MAX_VALUE_BYTES:
            raise ValueError("Metadata entry exceeds its bounds.")
        out.append(struct.pack(">H", len(key_bytes)) + key_bytes + struct.pack(">I", len(value_bytes)) + value_bytes)
    return b"".join(out)


def split_metadata(payload: bytes, request_id: int = 0) -> tuple[tuple[tuple[str, str], ...], bytes]:
    """Return ``(pairs, protobuf_bytes)`` from a payload that has ``FLAG_METADATA`` set."""
    try:
        (count,) = struct.unpack_from(">H", payload, 0)
        if count > METADATA_MAX_ENTRIES:
            raise ValueError("too many entries")
        offset, pairs = 2, []
        for _ in range(count):
            (klen,) = struct.unpack_from(">H", payload, offset)
            offset += 2
            if not 0 < klen <= METADATA_MAX_KEY_BYTES or offset + klen > len(payload):
                raise ValueError("bad key length")
            key = payload[offset:offset + klen].decode("utf-8")
            offset += klen
            (vlen,) = struct.unpack_from(">I", payload, offset)
            offset += 4
            if vlen > METADATA_MAX_VALUE_BYTES or offset + vlen > len(payload):
                raise ValueError("bad value length")
            value = payload[offset:offset + vlen].decode("utf-8")
            offset += vlen
            pairs.append((key, value))
    except (struct.error, ValueError, UnicodeDecodeError) as exc:
        raise FrameError(CODE_INVALID_METADATA, f"Malformed metadata block: {exc}", request_id) from None
    return tuple(pairs), payload[offset:]


def encode_error(request_id: int, code: str, message: str) -> bytes:
    body = json.dumps({"code": code, "message": message}, sort_keys=True, ensure_ascii=True).encode("ascii")
    return encode_frame(Kind.ERROR, 0, request_id, body)


def decode_error(frame: Frame) -> dict:
    return json.loads(frame.payload.decode("utf-8"))


def read_exact(stream: BinaryIO, count: int) -> bytes:
    """Read exactly ``count`` bytes; return fewer only at end of stream."""
    chunks, remaining = [], count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def discard(stream: BinaryIO, count: int) -> bool:
    """Skip ``count`` bytes in bounded steps. False when the stream ended first."""
    while count:
        chunk = stream.read(min(count, MIB))
        if not chunk:
            return False
        count -= len(chunk)
    return True


def read_request(stream: BinaryIO) -> Request | None:
    """Read one request frame.

    Returns ``None`` on a clean end of stream (the controller closed the pipe at a frame
    boundary). Raises ``FrameError`` for a frame that is rejected but fully consumed, and
    ``StreamBroken`` when the stream cannot be trusted any more.
    """
    head = read_exact(stream, HEADER_SIZE)
    if not head:
        return None
    if len(head) < HEADER_SIZE:
        raise StreamBroken(CODE_STREAM_TRUNCATED, "Stream ended inside a frame header.")
    length, version, kind, method, flags, request_id, deadline_ms = HEADER.unpack(head)
    if length > HARD_MAX_PAYLOAD:
        raise StreamBroken(CODE_UNRECOVERABLE_FRAME,
                           f"Declared payload of {length} bytes exceeds the {HARD_MAX_PAYLOAD} byte hard maximum.",
                           request_id)

    problem = None
    method_tag = None
    if version != PROTOCOL_VERSION:
        problem = (CODE_UNSUPPORTED_VERSION, f"Unsupported protocol version {version}.")
    elif kind != Kind.REQUEST:
        problem = (CODE_INVALID_KIND, f"Only request frames are accepted, got kind {kind}.")
    else:
        try:
            method_tag = Method(method)
        except ValueError:
            problem = (CODE_UNKNOWN_METHOD, f"Unknown method tag {method}.")
    if problem is None and flags & ~KNOWN_FLAGS:
        problem = (CODE_INVALID_FLAGS, f"Unknown flag bits {flags & ~KNOWN_FLAGS:#04x}.")
    if problem is None and flags & FLAG_METADATA and method_tag not in GRADIENT_METHODS:
        problem = (CODE_INVALID_FLAGS, "Metadata is accepted only on gradient methods.")
    if problem is None and length > METHOD_LIMITS[method_tag].max_request_payload:
        problem = (CODE_FRAME_TOO_LARGE,
                   f"{method_tag.name} request payload of {length} bytes exceeds the "
                   f"{METHOD_LIMITS[method_tag].max_request_payload} byte limit.")

    if problem is not None:
        if not discard(stream, length):
            raise StreamBroken(CODE_STREAM_TRUNCATED, "Stream ended inside a rejected frame payload.", request_id)
        raise FrameError(problem[0], problem[1], request_id)

    payload = read_exact(stream, length)
    if len(payload) < length:
        raise StreamBroken(CODE_STREAM_TRUNCATED, "Stream ended inside a frame payload.", request_id)
    metadata: tuple[tuple[str, str], ...] = ()
    if flags & FLAG_METADATA:
        metadata, payload = split_metadata(payload, request_id)
    return Request(method_tag, request_id, deadline_ms, metadata, payload)


def read_frame(stream: BinaryIO, max_payload: int = HARD_MAX_PAYLOAD) -> Frame | None:
    """Controller-side reader for any frame kind (responses, errors, ready). None on EOF."""
    head = read_exact(stream, HEADER_SIZE)
    if not head:
        return None
    if len(head) < HEADER_SIZE:
        raise StreamBroken(CODE_STREAM_TRUNCATED, "Stream ended inside a frame header.")
    length, version, kind, method, flags, request_id, deadline_ms = HEADER.unpack(head)
    if version != PROTOCOL_VERSION:
        raise StreamBroken(CODE_UNSUPPORTED_VERSION, f"Unsupported protocol version {version}.", request_id)
    if length > min(max_payload, HARD_MAX_PAYLOAD):
        raise StreamBroken(CODE_UNRECOVERABLE_FRAME, f"Declared payload of {length} bytes is too large.", request_id)
    payload = read_exact(stream, length)
    if len(payload) < length:
        raise StreamBroken(CODE_STREAM_TRUNCATED, "Stream ended inside a frame payload.", request_id)
    return Frame(kind, method, flags, request_id, deadline_ms, payload)
