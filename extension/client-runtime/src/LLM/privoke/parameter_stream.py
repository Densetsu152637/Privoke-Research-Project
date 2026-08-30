from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import grpc

from ...env import env_float

GENERATED_DIR = Path(__file__).resolve().parents[3] / "generated"
if str(GENERATED_DIR) not in sys.path:
    sys.path.insert(0, str(GENERATED_DIR))

from privoke.v1 import parameters_pb2, parameters_pb2_grpc


@dataclass(frozen=True)
class ParameterSnapshot:
    """A streamed model-parameter snapshot from model-streaming-service."""

    model_id: str
    version: str
    generated_at_unix: int
    parameters: Dict[str, Tuple[float, ...]]
    shapes: Dict[str, Tuple[int, ...]]
    metadata: Dict[str, str]

    @property
    def parameter_count(self) -> int:
        return len(self.parameters)

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for name in sorted(self.parameters):
            digest.update(name.encode("utf-8"))
            digest.update(repr(self.shapes.get(name, ())).encode("utf-8"))
            for value in self.parameters[name]:
                digest.update(repr(float(value)).encode("utf-8"))
        return digest.hexdigest()[:16]

    @property
    def cache_key(self) -> str:
        return f"{self.model_id}:{self.version}:{self.fingerprint}"

    def flat_values(self) -> Tuple[float, ...]:
        values = []
        for name in sorted(self.parameters):
            values.extend(self.parameters[name])
        return tuple(values)


class ModelParameterStreamer:
    """
    Client for model-streaming-service.

    The generated protobuf package is created by the extension/client-runtime
    Dockerfile and dev-compose command. The generated stubs and grpcio dependency must be
    present before this module is imported.
    """

    DEFAULT_TARGET = "127.0.0.1:50051"
    DEFAULT_CONSUMER_ID = "client-runtime"
    DEFAULT_MODEL_ID = "privoke-baseline"
    DEFAULT_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        target: str | None = None,
        model_id: str | None = None,
        consumer_id: str | None = None,
        timeout_seconds: float | None = None,
    ):
        self.target = target or os.getenv(
            "MODEL_STREAMING_TARGET",
            self.DEFAULT_TARGET,
        )
        self.model_id = model_id or os.getenv("MODEL_ID", self.DEFAULT_MODEL_ID)
        self.consumer_id = consumer_id or os.getenv(
            "MODEL_STREAMING_CONSUMER_ID",
            self.DEFAULT_CONSUMER_ID,
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else env_float(
                "MODEL_STREAMING_TIMEOUT_SECONDS",
                self.DEFAULT_TIMEOUT_SECONDS,
            )
        )
        if self.timeout_seconds <= 0:
            raise ValueError("MODEL_STREAMING_TIMEOUT_SECONDS must be greater than zero.")

    def fetch(self) -> ParameterSnapshot:
        with grpc.insecure_channel(
            self.target,
            options=(("grpc.max_receive_message_length", 8 * 1024 * 1024),),
        ) as channel:
            client = parameters_pb2_grpc.ModelStreamingServiceStub(channel)
            chunks = client.StreamModelParameters(
                parameters_pb2.ModelParametersRequest(
                    consumer_id=self.consumer_id,
                    model_id=self.model_id,
                ),
                timeout=self.timeout_seconds,
            )

            model_id = ""
            version = ""
            generated_at_unix = 0
            expected_chunks = None
            received_chunks = 0
            parameter_values: Dict[str, list[float]] = {}
            shapes: Dict[str, Tuple[int, ...]] = {}
            metadata: Dict[str, str] = {}
            for chunk in chunks:
                if chunk.chunk_index != received_chunks:
                    raise RuntimeError("Model parameter stream is out of order.")
                if expected_chunks is None:
                    expected_chunks = int(chunk.total_chunks)
                    model_id = chunk.model_id
                    version = chunk.version
                    generated_at_unix = int(chunk.generated_at_unix)
                elif (
                    chunk.model_id != model_id
                    or chunk.version != version
                    or int(chunk.generated_at_unix) != generated_at_unix
                    or int(chunk.total_chunks) != expected_chunks
                ):
                    raise RuntimeError("Model parameter stream changed snapshot mid-stream.")
                parameter = chunk.parameter
                name = parameter.name
                shape = tuple(int(size) for size in parameter.shape)
                current_values = parameter_values.setdefault(name, [])
                if name in shapes and shapes[name] != shape:
                    raise RuntimeError(f"Streamed tensor '{name}' changed shape mid-stream.")
                if int(parameter.value_offset) != len(current_values):
                    raise RuntimeError(f"Streamed tensor '{name}' has a discontinuous offset.")
                shapes[name] = shape
                current_values.extend(float(value) for value in parameter.values)
                metadata.update(dict(chunk.metadata))
                received_chunks += 1

        if expected_chunks is None or received_chunks != expected_chunks:
            raise RuntimeError("Model parameter stream ended before all chunks arrived.")
        if model_id != self.model_id:
            raise RuntimeError(
                "model-streaming-service returned model "
                f"'{model_id}' for requested model '{self.model_id}'."
            )

        for name, values in parameter_values.items():
            expected_size = 1
            if not shapes[name]:
                raise RuntimeError(f"Streamed tensor '{name}' has no shape.")
            for size in shapes[name]:
                if size <= 0:
                    raise RuntimeError(
                        f"Streamed tensor '{name}' has an invalid shape."
                    )
                expected_size *= int(size)
            if expected_size != len(values):
                raise RuntimeError(
                    f"Streamed tensor '{name}' shape does not match its values."
                )

        return ParameterSnapshot(
            model_id=model_id,
            version=version,
            generated_at_unix=generated_at_unix,
            parameters={
                name: tuple(values)
                for name, values in parameter_values.items()
            },
            shapes=shapes,
            metadata=metadata,
        )
