"""Adapter between the worker pool's framing and the W1 worker (stage W3).

The Rust pool (``privoke-worker-pool``) talks to its child on stdin and stdout with ``u32 little-endian length`` plus
payload frames. The W1 worker (``extension/client-runtime/src/worker_main.py``) reads and writes its own 20-byte-header
frames on two dedicated pipe descriptors. This script runs the unchanged W1 worker in-process and pumps frames between
the two framings, so the worker code is exactly the one the W1 tests exercise:

    pool stdin  --[len][W1 frame]-->  pump  --W1 frame-->  request pipe  --> worker_main
    pool stdout <-[len][W1 frame]--   pump  <-W1 frame--   response pipe <-- worker_main

It also swaps the worker's model provider for one that reads the snapshots the Rust service caches
(``<model_id>.snapshot.pb``, a serialized ``ModelParametersResponse``), so models reach the worker as read-only files
and the worker needs no network. The worker's own artifact and V3 package readers stay available as the fallback.

Usage: ``python worker_shim.py --runtime-root DIR -- <worker_main.py arguments without the pipe descriptors>``
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import threading
from pathlib import Path

SNAPSHOT_SUFFIX = ".snapshot.pb"
HEADER_LEN = 20
MAX_FRAME = 64 * 1024 * 1024


def _read_exact(stream, count: int) -> bytes | None:
    """Exactly ``count`` bytes, ``None`` on a clean end of stream before the first byte, an error mid-read."""
    chunks = []
    remaining = count
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            if remaining == count:
                return None
            raise EOFError("stream ended inside a frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _pump_requests(pool_in, request_write: int) -> None:
    """Pool frames to the worker's request pipe. The end of the pool's stdin closes the pipe: a clean shutdown."""
    try:
        while True:
            header = _read_exact(pool_in, 4)
            if header is None:
                break
            (length,) = struct.unpack("<I", header)
            if length > MAX_FRAME:
                break
            frame = _read_exact(pool_in, length) if length else b""
            if frame:
                _write_all(request_write, frame)
    except (OSError, EOFError):
        pass
    finally:
        try:
            os.close(request_write)
        except OSError:
            pass


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _pump_responses(response_read: int, pool_out) -> None:
    """The worker's response frames to the pool, each prefixed with the pool's length."""
    stream = os.fdopen(response_read, "rb", buffering=0)
    try:
        while True:
            header = _read_exact(stream, HEADER_LEN)
            if header is None:
                break
            (payload_len,) = struct.unpack(">I", header[:4])
            if payload_len > MAX_FRAME:
                break
            payload = _read_exact(stream, payload_len) if payload_len else b""
            frame = header + (payload or b"")
            pool_out.write(struct.pack("<I", len(frame)) + frame)
            pool_out.flush()
    except (OSError, EOFError, ValueError):
        pass


def _install_snapshot_provider(worker_main) -> None:
    """Make the worker prefer cached ``ModelParametersResponse`` snapshots over artifact files."""
    base = worker_main.LocalModelProvider

    class SnapshotModelProvider(base):
        def fetch(self, model_id: str):
            resolved = model_id
            if model_id == "latest":
                if not self.latest_model_id:
                    raise ValueError("latest is not resolvable in the worker; name the model explicitly.")
                resolved = self.latest_model_id
            if not worker_main.MODEL_ID_PATTERN.fullmatch(resolved or ""):
                raise ValueError("model_id is not a valid model identifier.")
            for root in self.roots:
                path = root / (resolved + SNAPSHOT_SUFFIX)
                if path.is_file():
                    return self._snapshot(resolved, path)
            return super().fetch(resolved)

        def _snapshot(self, model_id: str, path: Path):
            from privoke.v1 import parameters_pb2
            from src.LLM.privoke.parameter_stream import ParameterSnapshot

            message = parameters_pb2.ModelParametersResponse.FromString(path.read_bytes())
            if message.model_id != model_id:
                raise ValueError("Cached snapshot model_id differs from its file name.")
            return ParameterSnapshot(
                model_id=message.model_id,
                version=message.version,
                generated_at_unix=int(message.generated_at_unix),
                parameters={item.name: tuple(float(value) for value in item.values) for item in message.parameters},
                shapes={item.name: tuple(int(size) for size in item.shape) for item in message.parameters},
                metadata=dict(message.metadata),
            )

    worker_main.LocalModelProvider = SnapshotModelProvider


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Pool framing adapter for the W1 worker.")
    parser.add_argument("--runtime-root", required=True, help="The extension/client-runtime directory.")
    parser.add_argument("worker_arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    worker_arguments = [argument for argument in options.worker_arguments if argument != "--"] if options.worker_arguments[:1] == ["--"] else options.worker_arguments
    runtime_root = str(Path(options.runtime_root).resolve())

    # Claim the pool's pipes before anything can write to stdout; then point fd 1 at stderr like the worker does.
    pool_in = os.fdopen(os.dup(0), "rb", buffering=0)
    pool_out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)

    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    if os.name == "nt":
        import msvcrt

        request_number, response_number = msvcrt.get_osfhandle(request_read), msvcrt.get_osfhandle(response_write)
    else:
        request_number, response_number = request_read, response_write

    if runtime_root not in sys.path:
        sys.path.insert(0, runtime_root)
    from src import worker_main

    _install_snapshot_provider(worker_main)
    threading.Thread(target=_pump_requests, args=(pool_in, request_write), daemon=True).start()
    responses = threading.Thread(target=_pump_responses, args=(response_read, pool_out), daemon=True)
    responses.start()

    code = worker_main.main(["--request-fd", str(request_number), "--response-fd", str(response_number), *worker_arguments])

    # The worker closed its end of the response pipe on exit, which ends the pump once it has delivered the last frame
    # (a start-up error, for instance). Wait for that before the process ends.
    responses.join(timeout=10)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
