"""Local, hash-verified frozen encoder and offline contextual classification heads."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import MappingProxyType

import numpy as np
from privoke_model.pretrained_context import (
    BACKBONE_SHA256, TOKENIZER_SHA256, HIDDEN_SIZE, MAX_TOKENS,
    validate_pretrained_config, validate_pretrained_parameters,
)

from .detection.preprocessing import normalize_text
from .model import ModelPrediction, _sigmoid, _softmax

DEPENDENCY_VERSIONS = {"onnxruntime": "1.23.2", "tokenizers": "0.22.1", "numpy": "2.2.6"}
INPUT_SIGNATURE = [(name, "tensor(int64)", ["batch_size", "sequence_length"])
                   for name in ("input_ids", "attention_mask", "token_type_ids")]
OUTPUT_SIGNATURE = [("last_hidden_state", "tensor(float)", ["batch_size", "sequence_length", HIDDEN_SIZE])]


def _verified_bytes(directory: Path, name: str, expected_sha256: str, maximum: int) -> bytes:
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("Pretrained encoder asset must be a regular local file.")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if not raw or len(raw) > maximum or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Pretrained encoder asset size or SHA-256 does not match.")
    return raw


class FrozenPretrainedEncoder:
    """Own verified asset bytes indirectly through one CPU session/tokenizer.

    No hub loaders or network clients are used. Construction verifies bytes before
    either parser receives them, so reopening mutable filenames cannot race parsing.
    """

    def __init__(self, asset_directory: str | Path | None = None):
        selected = asset_directory if asset_directory is not None else os.getenv("PRIVOKE_PRETRAINED_CONTEXT_DIR")
        if not selected:
            raise ValueError("PRIVOKE_PRETRAINED_CONTEXT_DIR must name verified local encoder assets.")
        directory = Path(selected)
        model_bytes = _verified_bytes(directory, "model.onnx", BACKBONE_SHA256, 100 * 1024 * 1024)
        tokenizer_bytes = _verified_bytes(directory, "tokenizer.json", TOKENIZER_SHA256, 2 * 1024 * 1024)
        try:
            import onnxruntime as ort
            import tokenizers
        except ImportError as exc:
            raise RuntimeError("Experimental pretrained inference dependencies are unavailable.") from exc
        if (ort.__version__ != DEPENDENCY_VERSIONS["onnxruntime"]
                or tokenizers.__version__ != DEPENDENCY_VERSIONS["tokenizers"]
                or np.__version__ != DEPENDENCY_VERSIONS["numpy"]):
            raise RuntimeError("Experimental pretrained inference dependency versions do not match.")
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        self._session = ort.InferenceSession(model_bytes, sess_options=options, providers=["CPUExecutionProvider"])
        inputs = [(item.name, item.type, item.shape) for item in self._session.get_inputs()]
        outputs = [(item.name, item.type, item.shape) for item in self._session.get_outputs()]
        if inputs != INPUT_SIGNATURE or outputs != OUTPUT_SIGNATURE or self._session.get_providers() != ["CPUExecutionProvider"]:
            raise ValueError("Pretrained ONNX graph signature/provider does not match its admitted contract.")
        self._tokenizer = tokenizers.Tokenizer.from_str(tokenizer_bytes.decode("utf-8", errors="strict"))
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()

    def encode(self, text: str) -> np.ndarray:
        """Offline/raw-text entry point; apply detector normalization once."""
        return self.encode_normalized(normalize_text(text))

    def encode_normalized(self, text: str) -> np.ndarray:
        """Return a feature vector for text already normalized by the pipeline.

        Token counts include CLS/SEP. Overlength input is an explicit layer error;
        this experimental architecture never silently discards a prompt suffix.
        """
        encoding = self._tokenizer.encode(text, add_special_tokens=True)
        length = len(encoding.ids)
        if not 2 <= length <= MAX_TOKENS:
            raise ValueError("Pretrained contextual input exceeds its 256-token context including special tokens.")
        inputs = {"input_ids": np.asarray([encoding.ids], dtype=np.int64),
                  "attention_mask": np.asarray([encoding.attention_mask], dtype=np.int64),
                  "token_type_ids": np.asarray([encoding.type_ids], dtype=np.int64)}
        if any(value.shape != (1, length) for value in inputs.values()) or not np.all(inputs["attention_mask"] == 1):
            raise ValueError("Pretrained tokenizer returned an invalid unpadded encoding.")
        outputs = self._session.run(["last_hidden_state"], inputs)
        if len(outputs) != 1:
            raise ValueError("Pretrained encoder output count does not match.")
        hidden = np.asarray(outputs[0])
        if hidden.dtype != np.float32 or hidden.shape != (1, length, HIDDEN_SIZE) or not np.isfinite(hidden).all():
            raise ValueError("Pretrained encoder output shape, dtype or values are invalid.")
        mask = inputs["attention_mask"].astype(np.float32)[..., None]
        pooled = (hidden * mask).sum(axis=1) / mask.sum(axis=1)
        norm = np.linalg.norm(pooled, axis=1, keepdims=True)
        if not np.isfinite(norm).all() or np.any(norm <= 0):
            raise ValueError("Pretrained encoder produced an invalid pooled norm.")
        features = (pooled / norm)[0].astype(np.float32)
        if not np.isfinite(features).all():
            raise ValueError("Pretrained encoder features must be finite.")
        return features

    def features(self, texts) -> np.ndarray:
        """Offline fitter API: deterministic rows, shape [N, 384], no head changes."""
        rows = [self.encode(text) for text in texts]
        return np.stack(rows) if rows else np.empty((0, HIDDEN_SIZE), dtype=np.float32)


class PretrainedContextModel:
    compute_device = "cpu"

    def __init__(self, config, parameters, shapes, encoder: FrozenPretrainedEncoder):
        validated = validate_pretrained_config(config)
        self.config = MappingProxyType({name: tuple(value) if isinstance(value, list) else value
                                       for name, value in validated.items()})
        validate_pretrained_parameters(parameters, shapes, {name: False for name in parameters})
        self.parameters = MappingProxyType({name: np.frombuffer(np.asarray(values, dtype=np.float32).tobytes(), dtype=np.float32)
                                           .reshape(shapes[name]) for name, values in parameters.items()})
        self.encoder = encoder

    def predict(self, text: str) -> ModelPrediction:
        pooled = self.encoder.encode_normalized(text)
        logits = {task: pooled @ self.parameters[f"head.{task}.weight"] + self.parameters[f"head.{task}.bias"]
                  for task in ("sensitivity", "visibility", "category")}
        if any(not np.isfinite(values).all() for values in logits.values()):
            raise ValueError("Pretrained contextual heads produced non-finite logits.")
        sensitivity = _softmax(logits["sensitivity"])
        visibility = _softmax(logits["visibility"])
        categories = _sigmoid(logits["category"])
        return ModelPrediction(
            sensitivity=self.config["sensitivity_labels"][int(np.argmax(sensitivity))],
            visibility=self.config["visibility_labels"][int(np.argmax(visibility))],
            categories=tuple(label for label, probability in zip(self.config["category_labels"], categories)
                             if probability >= self.config["category_threshold"]),
            sensitivity_probabilities=tuple(float(value) for value in sensitivity),
            visibility_probabilities=tuple(float(value) for value in visibility),
            category_probabilities=tuple(float(value) for value in categories),
            pooled=tuple(float(value) for value in pooled),
        )
