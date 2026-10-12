"""Bootstrapping and bounded network helpers for the isolated v3 servers."""
from __future__ import annotations
import os
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[3]
GENERATED = Path(os.getenv("V3_GENERATED", str(ROOT / "extension/client-runtime/generated")))
sys.path[:0] = [str(GENERATED), str(ROOT / "shared/python"), str(ROOT / "extension/client-runtime"), str(ROOT / "services/privoke-fuzzer/src")]
import grpc
from privoke.experimental import v3_pb2 as pb, v3_pb2_grpc as rpc
from privoke.v1 import runtime_pb2, runtime_pb2_grpc, parameters_pb2
from privoke_model.v3_contract import CHUNK_BYTES, MAX_BLOB_BYTES, canonical, digest, check_sha

OPTIONS = (("grpc.max_receive_message_length", 2 * 1024 * 1024), ("grpc.max_send_message_length", 2 * 1024 * 1024))

def channel(target):
    return grpc.insecure_channel(target, options=OPTIONS)

def chunks(payload, manifest=b""):
    sha = digest(payload)
    for offset in range(0, len(payload), CHUNK_BYTES):
        yield pb.Chunk(sha256=sha, offset=offset, total_bytes=len(payload), data=payload[offset:offset + CHUNK_BYTES], manifest_json=manifest if offset == 0 else b"")

def fetch(stub, sha):
    check_sha(sha)
    parts, offset, total = [], 0, None
    for part in stub.FetchBlob(pb.Ref(sha256=sha), timeout=120):
        if (part.sha256 != sha or part.offset != offset or not part.data or len(part.data) > CHUNK_BYTES
                or not 0 < part.total_bytes <= MAX_BLOB_BYTES or (total is not None and part.total_bytes != total)):
            raise ValueError("Invalid ordered bounded blob transport.")
        total = part.total_bytes; offset += len(part.data)
        if offset > total: raise ValueError("Blob exceeds declared length.")
        parts.append(part.data)
    payload = b"".join(parts)
    if total != len(payload) or digest(payload) != sha: raise ValueError("Incomplete or corrupt blob transport.")
    return payload

def serve(servicer, register, port):
    from concurrent.futures import ThreadPoolExecutor
    server = grpc.server(ThreadPoolExecutor(max_workers=4), options=OPTIONS)
    register(servicer, server)
    address = os.getenv("V3_BIND", "127.0.0.1") + ":" + str(port)
    if server.add_insecure_port(address) == 0: raise RuntimeError("Cannot bind isolated v3 server.")
    server.start(); server.wait_for_termination()
