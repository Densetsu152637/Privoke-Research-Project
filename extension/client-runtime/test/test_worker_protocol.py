"""Frame codec tests for the worker pipe protocol (no worker process, no heavy imports)."""
from __future__ import annotations

import io
import struct
import unittest

from src import worker_protocol as proto


def request_frame(method=proto.Method.HEALTH, payload=b"", request_id=7, **kwargs):
    return proto.encode_frame(proto.Kind.REQUEST, method, request_id, payload, **kwargs)


class FrameCodecTests(unittest.TestCase):
    def test_header_layout_is_fixed_and_big_endian(self):
        frame = proto.encode_frame(proto.Kind.REQUEST, proto.Method.ANALYZE_PROMPT, 0x0102030405060708,
                                   b"abc", deadline_ms=0x0A0B0C0D)
        self.assertEqual(proto.HEADER_SIZE, 20)
        self.assertEqual(frame[:20].hex(), "00000003" "01" "01" "01" "00" "0102030405060708" "0a0b0c0d")
        self.assertEqual(frame[20:], b"abc")

    def test_request_round_trip_with_and_without_metadata(self):
        plain = proto.read_request(io.BytesIO(request_frame(proto.Method.ANALYZE_PROMPT, b"\x0a\x01x", deadline_ms=900)))
        self.assertEqual((plain.method, plain.request_id, plain.deadline_ms, plain.metadata, plain.payload),
                         (proto.Method.ANALYZE_PROMPT, 7, 900, (), b"\x0a\x01x"))
        pairs = (("privoke-training-admission-bin", "{\"schema\":4}"), ("k", ""))
        block = proto.encode_metadata(pairs)
        with_metadata = proto.read_request(io.BytesIO(request_frame(
            proto.Method.COMPUTE_UNDERLYING_MODEL_GRADIENTS, block + b"\x0a\x01x", flags=proto.FLAG_METADATA)))
        self.assertEqual(with_metadata.metadata, pairs)
        self.assertEqual(with_metadata.payload, b"\x0a\x01x")

    def test_clean_end_of_stream_is_none(self):
        self.assertIsNone(proto.read_request(io.BytesIO(b"")))

    def test_consecutive_frames_decode_in_order(self):
        stream = io.BytesIO(request_frame(request_id=1) + request_frame(request_id=2, payload=b"") + request_frame(request_id=3))
        self.assertEqual([proto.read_request(stream).request_id for _ in range(3)], [1, 2, 3])
        self.assertIsNone(proto.read_request(stream))

    def test_rejected_frames_are_consumed_so_the_next_frame_decodes(self):
        bad_cases = {
            proto.CODE_UNKNOWN_METHOD: proto.HEADER.pack(3, 1, 1, 0xEE, 0, 5, 0) + b"xyz",
            proto.CODE_UNSUPPORTED_VERSION: proto.HEADER.pack(3, 9, 1, 3, 0, 5, 0) + b"xyz",
            proto.CODE_INVALID_KIND: proto.HEADER.pack(3, 1, 2, 3, 0, 5, 0) + b"xyz",
            proto.CODE_INVALID_FLAGS: proto.HEADER.pack(3, 1, 1, 3, 0x80, 5, 0) + b"xyz",
            proto.CODE_FRAME_TOO_LARGE: proto.HEADER.pack(proto.METHOD_LIMITS[proto.Method.HEALTH].max_request_payload + 1,
                                                          1, 1, 3, 0, 5, 0) + bytes(proto.METHOD_LIMITS[proto.Method.HEALTH].max_request_payload + 1),
        }
        for code, bad in bad_cases.items():
            with self.subTest(code=code):
                stream = io.BytesIO(bad + request_frame(request_id=99))
                with self.assertRaises(proto.FrameError) as caught:
                    proto.read_request(stream)
                self.assertEqual(caught.exception.code, code)
                self.assertEqual(caught.exception.request_id, 5)
                self.assertEqual(proto.read_request(stream).request_id, 99)

    def test_metadata_on_a_non_gradient_method_and_malformed_metadata_are_rejected(self):
        stream = io.BytesIO(request_frame(proto.Method.HEALTH, proto.encode_metadata([("k", "v")]),
                                          flags=proto.FLAG_METADATA) + request_frame(request_id=2))
        with self.assertRaises(proto.FrameError) as caught:
            proto.read_request(stream)
        self.assertEqual(caught.exception.code, proto.CODE_INVALID_FLAGS)
        self.assertEqual(proto.read_request(stream).request_id, 2)
        for block in (b"\x00", struct.pack(">H", 1) + struct.pack(">H", 50) + b"short", struct.pack(">H", 17)):
            with self.subTest(block=block.hex()):
                frame = request_frame(proto.Method.COMPUTE_SEMANTIC_GRADIENTS, block, flags=proto.FLAG_METADATA)
                with self.assertRaises(proto.FrameError) as caught:
                    proto.read_request(io.BytesIO(frame))
                self.assertEqual(caught.exception.code, proto.CODE_INVALID_METADATA)

    def test_truncated_frames_and_absurd_lengths_break_the_stream(self):
        whole = request_frame(payload=b"")
        for cut in (5, 19):
            with self.assertRaises(proto.StreamBroken) as caught:
                proto.read_request(io.BytesIO(whole[:cut]))
            self.assertEqual(caught.exception.code, proto.CODE_STREAM_TRUNCATED)
        body = request_frame(proto.Method.ANALYZE_PROMPT, b"x" * 10)
        with self.assertRaises(proto.StreamBroken):
            proto.read_request(io.BytesIO(body[:-4]))
        huge = proto.HEADER.pack(proto.HARD_MAX_PAYLOAD + 1, 1, 1, 3, 0, 5, 0)
        with self.assertRaises(proto.StreamBroken) as caught:
            proto.read_request(io.BytesIO(huge))
        self.assertEqual(caught.exception.code, proto.CODE_UNRECOVERABLE_FRAME)

    def test_error_frame_shape(self):
        frame = proto.read_frame(io.BytesIO(proto.encode_error(41, proto.CODE_INVALID_LAYERS, "no layers")))
        self.assertEqual((frame.kind, frame.request_id), (proto.Kind.ERROR, 41))
        self.assertEqual(proto.decode_error(frame), {"code": "INVALID_LAYERS", "message": "no layers"})

    def test_limits_cover_the_largest_gradient_payload(self):
        # float32 payload of the 9.6M-parameter pretrained-V3 encoder plus names and shapes.
        v3_full_encoder = 9_600_000 * 4 + 64 * 1024
        for method in proto.GRADIENT_METHODS:
            limits = proto.METHOD_LIMITS[method]
            self.assertGreater(limits.max_response_payload, v3_full_encoder)
            self.assertLessEqual(limits.max_response_payload, proto.HARD_MAX_PAYLOAD)
            self.assertGreaterEqual(limits.max_deadline_ms, limits.default_deadline_ms)
        for method in (proto.Method.ANALYZE_PROMPT, proto.Method.DETECT_ANNOTATION_PRESENCE, proto.Method.HEALTH):
            self.assertLess(proto.METHOD_LIMITS[method].max_deadline_ms, 30_000)  # supervisor bridge deadline
        self.assertEqual(set(proto.METHOD_LIMITS), set(proto.Method))


if __name__ == "__main__":
    unittest.main()
