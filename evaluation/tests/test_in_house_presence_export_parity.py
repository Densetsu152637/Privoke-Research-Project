"""Synthetic codec/stream/runtime parity for scratch-presence artifacts."""
from __future__ import annotations

import hashlib
import json
import math
import sys
import types
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "extension" / "client-runtime"
for path in (ROOT / "evaluation", ROOT / "shared" / "python", RUNTIME,
             ROOT / "models", RUNTIME / "generated"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

# The real package initializer eagerly imports unrelated contextual training.
# Use a namespace package to load the actual two runtime modules under test.
for name, directory in (
    ("src.LLM", RUNTIME / "src" / "LLM"),
    ("src.LLM.privoke", RUNTIME / "src" / "LLM" / "privoke"),
):
    if name not in sys.modules:
        package = types.ModuleType(name)
        package.__path__ = [str(directory)]
        sys.modules[name] = package
import src
src.LLM = sys.modules["src.LLM"]
src.LLM.privoke = sys.modules["src.LLM.privoke"]

from privoke_model.artifact import validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.scratch_presence import (
    SCRATCH_PRESENCE_ARCHITECTURE,
    SCRATCH_PROFILES,
    scratch_presence_tensor_shapes,
    scratch_presence_trainable_names,
)
from privoke.v1 import parameters_pb2
from src.LLM.privoke.parameter_stream import ModelParameterStreamer
from src.LLM.privoke.scratch_presence_model import StreamedScratchPresenceModel
from src.detection.preprocessing import normalize_text
from privoke_eval.in_house_presence_training import (
    ScratchPresenceTrainer,
    create_paired_trainers,
)


class _TransportChannel:
    def unary_stream(self, method, *, request_serializer, response_deserializer, **kwargs):
        self.method = method
        self.request_serializer = request_serializer

        def invoke(request, timeout=None, **call_kwargs):
            self.request = request
            self.request_bytes = request_serializer(request)
            self.timeout = timeout
            self.call_kwargs = call_kwargs
            return iter(response_deserializer(chunk.SerializeToString()) for chunk in self.chunks)

        return invoke


def _stream_messages(payload: dict[str, object], artifact_file_sha256: str):
    config = payload["config"]
    metadata = dict(payload["metadata"])
    metadata.update({
        "served_by": "model-streaming-service",
        "consumer_id": "synthetic-export-parity-test",
        "architecture": SCRATCH_PRESENCE_ARCHITECTURE,
        "model_config": json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
        "artifact_checksum": payload["checksum"],
        "artifact_file_checksum": artifact_file_sha256,
        "trainable_parameters": ",".join(scratch_presence_trainable_names(config)),
        "task": config["task"], "profile": config["profile"],
        "training_mode": config["training_mode"],
        "text_normalization": config["normalization"], "tokenizer": config["tokenizer"],
        "pooling": config["pooling"], "arithmetic": config["arithmetic"],
    })
    chunks = []
    for name in sorted(payload["parameters"]):
        tensor = payload["parameters"][name]
        values, shape = tensor["values"], tensor["shape"]
        for offset in range(0, len(values), 1024):
            chunks.append(parameters_pb2.ModelParameterChunk(
                model_id=payload["model_id"], version=payload["version"],
                generated_at_unix=payload["generated_at_unix"],
                parameter=parameters_pb2.ParameterChunk(
                    name=name, shape=shape, value_offset=offset,
                    values=values[offset:offset + 1024],
                ),
                metadata=metadata if not chunks else {}, chunk_index=len(chunks),
            ))
    for chunk in chunks:
        chunk.total_chunks = len(chunks)
    return chunks


def _trainer_logit(trainer: ScratchPresenceTrainer, text: str) -> float:
    ids, mask = trainer.tensor_batch([text])
    return float(trainer.logits(ids, mask)[0].detach())


class ScratchPresenceExportParityTests(unittest.TestCase):
    def test_all_profiles_modes_survive_json_protobuf_stream_and_actual_wrapper(self):
        texts = (
            "", "Ｆｕｌｌｗｉｄｔｈ Alice [at] example.test 🧪", "x",
            "synthetic phrase " * 180,
        )
        targets = (False, True, False, True)
        provenance = {
            "source_revision": "a" * 40,
            "study_plan_sha256": "b" * 64,
            "prepared_manifest_sha256": "c" * 64,
            "trainer_contract_sha256": "d" * 64,
        }

        for profile in SCRATCH_PROFILES:
            head, full = create_paired_trainers(profile)
            for trainer in (head, full):
                with self.subTest(profile=profile, mode=trainer.config["training_mode"]):
                    trainer.step(texts, targets)
                    arrays = trainer.export_parameters()
                    shapes = scratch_presence_tensor_shapes(trainer.config)
                    expected_flat = {name: array.ravel().tolist() for name, array in arrays.items()}
                    expected_fingerprint = parameter_fingerprint(expected_flat, shapes)
                    artifact = trainer.build_artifact(
                        **provenance, checkpoint_epoch=1, generated_at_unix=1_800_000_000,
                    )
                    canonical = json.dumps(
                        artifact, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False,
                    ).encode("utf-8")
                    decoded = json.loads(canonical.decode("utf-8"))
                    validate_artifact(decoded)
                    file_sha256 = hashlib.sha256(canonical).hexdigest()

                    # Exercise generated wire messages and the real generated stub,
                    # replacing only the network transport with an in-memory stream.
                    channel = _TransportChannel()
                    channel.chunks = _stream_messages(decoded, file_sha256)
                    with patch("src.LLM.privoke.parameter_stream.grpc_channel", return_value=nullcontext(channel)):
                        snapshot = ModelParameterStreamer(
                            target="127.0.0.1:50051", model_id=decoded["model_id"],
                            consumer_id="synthetic-export-parity-test",
                        ).fetch()

                    self.assertEqual(channel.request.model_id, decoded["model_id"])
                    self.assertEqual(channel.request.consumer_id, "synthetic-export-parity-test")
                    self.assertTrue(channel.request_bytes)
                    self.assertEqual(channel.timeout, 10.0)
                    self.assertEqual(snapshot.model_id, decoded["model_id"])
                    self.assertEqual(snapshot.version, decoded["version"])
                    self.assertEqual(snapshot.generated_at_unix, decoded["generated_at_unix"])
                    self.assertEqual(snapshot.metadata["artifact_checksum"], decoded["checksum"])
                    self.assertEqual(snapshot.metadata["artifact_file_checksum"], file_sha256)
                    self.assertEqual(snapshot.metadata["architecture"], SCRATCH_PRESENCE_ARCHITECTURE)
                    self.assertEqual(snapshot.metadata["training_mode"], trainer.config["training_mode"])
                    self.assertEqual(snapshot.metadata["profile"], profile)
                    self.assertEqual(snapshot.metadata, dict(channel.chunks[0].metadata))
                    self.assertEqual(snapshot.metadata["model_config"], json.dumps(
                        trainer.config, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ))
                    self.assertEqual(snapshot.shapes, shapes)
                    self.assertEqual(set(snapshot.parameters), set(arrays))
                    for name, array in arrays.items():
                        transported = np.asarray(snapshot.parameters[name], dtype=np.float32)
                        self.assertEqual(transported.tobytes(), array.ravel().tobytes())
                    self.assertEqual(snapshot.fingerprint, expected_fingerprint)

                    runtime_model = StreamedScratchPresenceModel(snapshot)
                    self.assertEqual(runtime_model.threshold, 0.5)
                    batch_ids, batch_mask = trainer.tensor_batch(texts)
                    batched_logits = trainer.logits(batch_ids, batch_mask).detach().tolist()
                    for index, raw in enumerate(texts):
                        runtime_raw = runtime_model.predict_probability(raw)
                        normalized = normalize_text(raw)
                        runtime_normalized = runtime_model.predict_normalized_probability(normalized)
                        self.assertEqual(runtime_raw, runtime_normalized)
                        reference_logit = np.float32(batched_logits[index])
                        individual_logit = np.float32(_trainer_logit(trainer, raw))
                        self.assertLessEqual(abs(float(reference_logit - individual_logit)), 2e-6)
                        expected_probability = float(
                            1.0 / (1.0 + np.exp(-np.clip(reference_logit, -30.0, 30.0)))
                        )
                        tolerance = 2e-6 + 2e-5 * abs(expected_probability)
                        self.assertLessEqual(abs(runtime_raw - expected_probability), tolerance)
                        self.assertEqual(runtime_model.classify(raw), runtime_raw >= 0.5)
                        thresholds = (
                            0.0,
                            1.0,
                            runtime_raw,
                            float(np.nextafter(runtime_raw, -math.inf)),
                            float(np.nextafter(runtime_raw, math.inf)),
                        )
                        expected_decisions = (True, False, True, True, False)
                        self.assertTrue(0.0 < runtime_raw < 1.0)
                        self.assertEqual(
                            tuple(runtime_raw >= threshold for threshold in thresholds),
                            expected_decisions,
                        )


if __name__ == "__main__":
    unittest.main()
