from __future__ import annotations

import hashlib
import json
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import grpc
from privoke_service.stack_connection import grpc_channel, stack_target
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.artifact import MAX_ARTIFACT_BYTES, MAX_PARAMETER_VALUES, float32
from privoke_model.scratch_presence import (
    SCRATCH_PRESENCE_ARCHITECTURE,
    SCRATCH_PRESENCE_MODEL_IDS,
    scratch_presence_tensor_shapes,
    validate_scratch_presence_stream_metadata,
)

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
        return sum(len(values) for values in self.parameters.values())

    @property
    def fingerprint(self) -> str:
        return parameter_fingerprint(self.parameters, self.shapes)

    @property
    def cache_key(self) -> str:
        fields = {name: self.metadata.get(name) for name in (
                "architecture", "model_config", "trainable_parameters", "contextual_training_strategy",
                "contextual_training_objective",
            )}
        # Preserve the exact legacy cache identity when this opt-in is absent.
        if "contextual_training_optimizer" in self.metadata:
            fields["contextual_training_optimizer"] = self.metadata["contextual_training_optimizer"]
        contract = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        contract_hash = hashlib.sha256(contract.encode("utf-8")).hexdigest()
        return f"{self.model_id}:{self.version}:{self.fingerprint}:{contract_hash}"

    def flat_values(self) -> Tuple[float, ...]:
        values = []
        for name in sorted(self.parameters):
            values.extend(self.parameters[name])
        return tuple(values)


class _ScratchStreamGuard:
    """Validate first declarations and each bounded chunk before accumulation."""

    CHUNK_VALUES = 1024

    def __init__(self, requested_id: str, chunk):
        if requested_id not in SCRATCH_PRESENCE_MODEL_IDS or chunk.model_id != requested_id:
            raise RuntimeError("Scratch streams require their exact explicitly requested model ID.")
        metadata = dict(chunk.metadata)
        if sum(len(key.encode("utf-8")) + len(value.encode("utf-8")) for key, value in metadata.items()) > MAX_ARTIFACT_BYTES:
            raise RuntimeError("Scratch stream metadata exceeds the byte budget.")
        config = validate_scratch_presence_stream_metadata(chunk.model_id, chunk.version, metadata)
        self.shapes = scratch_presence_tensor_shapes(config)
        self.names = sorted(self.shapes)
        self.total_values = sum(math.prod(shape) for shape in self.shapes.values())
        self.total_chunks = sum((math.prod(shape) + self.CHUNK_VALUES - 1) // self.CHUNK_VALUES
                                for shape in self.shapes.values())
        if self.total_values > MAX_PARAMETER_VALUES or int(chunk.total_chunks) != self.total_chunks:
            raise RuntimeError("Scratch stream total chunks or values exceed its exact inventory.")
        if not 0 < int(chunk.generated_at_unix) <= 2**63 - 1:
            raise RuntimeError("Scratch stream timestamp is invalid.")
        self.name_index = 0
        self.offset = 0
        self.received_values = 0
        self.received_bytes = 0

    def accept(self, chunk, chunk_index: int) -> None:
        if chunk_index and chunk.metadata:
            raise RuntimeError("Scratch stream metadata must appear only on the first chunk.")
        size = chunk.ByteSize()
        if size < 0 or self.received_bytes + size > MAX_ARTIFACT_BYTES:
            raise RuntimeError("Scratch stream exceeds its total byte budget.")
        parameter = chunk.parameter
        if self.name_index >= len(self.names) or parameter.name != self.names[self.name_index]:
            raise RuntimeError("Scratch stream tensor order does not match its exact inventory.")
        shape = self.shapes[parameter.name]
        if tuple(parameter.shape) != shape:
            raise RuntimeError("Scratch stream tensor shape does not match its exact inventory.")
        remaining = math.prod(shape) - self.offset
        values_count = len(parameter.values)
        if int(parameter.value_offset) != self.offset or values_count != min(self.CHUNK_VALUES, remaining):
            raise RuntimeError("Scratch stream chunk values or offset are invalid.")
        if self.received_values + values_count > self.total_values:
            raise RuntimeError("Scratch stream exceeds its exact value budget.")
        if any(not math.isfinite(value) or float32(value) != value for value in parameter.values):
            raise RuntimeError("Scratch stream values must be exact finite float32.")
        self.received_bytes += size
        self.received_values += values_count
        self.offset += values_count
        if self.offset == math.prod(shape):
            self.name_index += 1
            self.offset = 0

    def finish(self) -> None:
        if self.name_index != len(self.names) or self.offset or self.received_values != self.total_values:
            raise RuntimeError("Scratch stream did not complete its exact tensor inventory.")


class ModelParameterStreamer:
    """
    Client for model-streaming-service.

    The generated protobuf package is created by the extension/client-runtime
    Dockerfile and dev-compose command. The generated stubs and grpcio dependency must be
    present before this module is imported.
    """

    DEFAULT_TARGET = "127.0.0.1:50051"
    DEFAULT_CONSUMER_ID = "client-runtime"
    DEFAULT_MODEL_ID = "latest"
    DEFAULT_TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        target: str | None = None,
        model_id: str | None = None,
        consumer_id: str | None = None,
        timeout_seconds: float | None = None,
    ):
        self.target = target if target is not None else stack_target("MODEL_STREAMING")
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
        with grpc_channel(
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
            scratch_guard = None
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
                # Requested identity and the first architecture independently anchor
                # the scratch guard; late discriminator replacement is never merged.
                chunk_metadata = dict(chunk.metadata)
                if received_chunks == 0 and (
                    self.model_id.startswith("privoke-scratch-presence-")
                    or chunk_metadata.get("architecture") == SCRATCH_PRESENCE_ARCHITECTURE
                ):
                    scratch_guard = _ScratchStreamGuard(self.model_id, chunk)
                elif scratch_guard is None and chunk_metadata.get("architecture") == SCRATCH_PRESENCE_ARCHITECTURE:
                    raise RuntimeError("Scratch architecture must be declared in the first chunk.")
                if scratch_guard is not None:
                    scratch_guard.accept(chunk, received_chunks)
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
                metadata.update(chunk_metadata)
                received_chunks += 1

        if expected_chunks is None or received_chunks != expected_chunks:
            raise RuntimeError("Model parameter stream ended before all chunks arrived.")
        if scratch_guard is not None:
            scratch_guard.finish()
        if self.model_id != self.DEFAULT_MODEL_ID and model_id != self.model_id:
            raise RuntimeError(
                "model-streaming-service returned model "
                f"'{model_id}' for requested model '{self.model_id}'."
            )
        if not version or generated_at_unix <= 0:
            raise RuntimeError("Model parameter stream has invalid snapshot metadata.")

        for name, values in parameter_values.items():
            if not name:
                raise RuntimeError("Model parameter stream has an unnamed tensor.")
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
            if not all(math.isfinite(value) for value in values):
                raise RuntimeError(f"Streamed tensor '{name}' has non-finite values.")

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
