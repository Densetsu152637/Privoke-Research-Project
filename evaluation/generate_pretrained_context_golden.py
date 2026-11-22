"""Golden output of the pretrained contextual encoder for the Rust port (stage 17, RUST-S17B).

The Python runtime runs a frozen MiniLM backbone in onnxruntime (``src/pretrained_context.py``). The host that made this
golden has no onnxruntime, so the backbone is **not** run through onnxruntime here. What is recorded instead:

* A small synthetic backbone with the structure of the pinned export: a plain PyTorch export of a Hugging Face
  ``BertModel`` whose graph names every constant, with the anonymous ``onnx::MatMul_N`` weights stored ``[input][output]``.
  The generator writes it as a real ONNX file (hand-encoded protobuf) so the Rust reader is tested on bytes it did not
  produce, and runs the same computation in **numpy float32** as an independent reference (the graph: embeddings, layer
  norm with epsilon 1e-12, attention with the query and key each scaled by ``head_size ** -0.25``, exact GELU).
* The unchanged Python heads and decision rules: ``PretrainedContextModel.predict`` (the real class, with the numpy
  reference standing in for the onnxruntime encoder) and ``StreamedPretrainedContextModel.classify`` (the real findings
  and metadata), on the artifact that ``build_head_artifact`` writes.
* The encoder's own checks (tokenisation without truncation or padding, the context-length error, the pooling and the
  L2 norm) are copies of the lines of ``FrozenPretrainedEncoder.encode_normalized`` around the stand-in graph run.

What this golden does not show: agreement of the Rust encoder with onnxruntime on the real ``model.onnx`` (the host has
neither), and the real tokenizer file. The synthetic tokenizer is built with the ``tokenizers`` wheel the runtime pins and
carries truncation and padding settings, which the encoder must switch off.

Usage (the client runtime environment; the ``parameters`` protobuf client must exist, see ``setup-host.py``, or point
``PRIVOKE_GENERATED`` at a directory generated from ``shared/proto``)::

    python evaluation/generate_pretrained_context_golden.py --out rust/crates/privoke-semantic/tests/fixtures/context_golden.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "rust" / "crates" / "privoke-semantic" / "tests" / "fixtures" / "context_golden.json"

HIDDEN = 384
LAYERS = 1
HEADS = 12
INTERMEDIATE = 48
POSITIONS = 40
EPS = 1e-12
ENCODER_MAX_TOKENS = 12
MODEL_MAX_TOKENS = 256
SEEDS = tuple(range(1, 40))
SCALES = (1.5, 2.5, 1.0, 3.5)

WORDS = (
    "the a my is at in and for with to of i me name phone number email call live work john smith maria london acme corp "
    "salary card password diagnosed diabetes depression doctor hospital home address street bank account secret meeting "
    "tomorrow friday hello world . , @ - : ! ? 0 1 2 3 4 5 6 7 8 9"
).split()
SUBWORDS = ("s", "ing", "ed", "er", "ly", "0", "1", "2", "3")

TEXTS = [
    "hello world",
    "my name is john smith",
    "call me at 555 0123 tomorrow",
    "i was diagnosed with diabetes",
    "email maria at home",
    "the doctor said i work for acme",
    "My PASSWORD is secret!",
    "bank account number 1 2 3 4 5 6",
    "zzz unknown words qqq",
    "calling meetings tomorrow, johns phone: 5550",
    "",
    "a",
    # more than 8 tokens: the tokenizer file's own truncation setting (8) must not apply
    "my name is john smith and i live in london and work for acme",
    # more than ENCODER_MAX_TOKENS tokens: the context-length error
    "the the the the the the the the the the the the the the the the",
]


def bootstrap() -> None:
    paths = [REPO / "extension" / "client-runtime", REPO / "shared" / "python"]
    generated = os.environ.get("PRIVOKE_GENERATED")
    paths.append(Path(generated) if generated else REPO / "extension" / "client-runtime" / "generated")
    for path in reversed(paths):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------------------------------
# The synthetic tokenizer
# --------------------------------------------------------------------------------------------------------------


def make_tokenizer_json() -> tuple[str, int]:
    from tokenizers import Tokenizer, models, normalizers, pre_tokenizers, processors

    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]", *WORDS, *("##" + piece for piece in SUBWORDS)]
    tokenizer = Tokenizer(models.WordPiece({token: index for index, token in enumerate(vocab)}, unk_token="[UNK]"))
    tokenizer.normalizer = normalizers.BertNormalizer(lowercase=True)
    tokenizer.pre_tokenizer = pre_tokenizers.BertPreTokenizer()
    tokenizer.post_processor = processors.TemplateProcessing(
        single="[CLS] $A [SEP]", pair="[CLS] $A [SEP] $B:1 [SEP]:1", special_tokens=[("[CLS]", 2), ("[SEP]", 3)])
    # Like the real tokenizer.json, this one carries settings the runtime switches off.
    tokenizer.enable_truncation(max_length=8)
    tokenizer.enable_padding(length=16, pad_id=0, pad_token="[PAD]")
    return tokenizer.to_str(), len(vocab)


# --------------------------------------------------------------------------------------------------------------
# The synthetic backbone, as ONNX bytes and as numpy arrays
# --------------------------------------------------------------------------------------------------------------


def make_weights(seed: int, vocab: int):
    import numpy as np
    rng = np.random.default_rng(seed)

    def normal(*shape, scale=0.08):
        return (rng.standard_normal(shape) * scale).astype(np.float32)

    def norm_weight(width):
        return (1.0 + 0.1 * rng.standard_normal(width)).astype(np.float32)

    weights = {
        "embeddings.word_embeddings.weight": normal(vocab, HIDDEN, scale=0.5),
        "embeddings.position_embeddings.weight": normal(POSITIONS, HIDDEN, scale=0.5),
        "embeddings.token_type_embeddings.weight": normal(2, HIDDEN, scale=0.5),
        "embeddings.LayerNorm.weight": norm_weight(HIDDEN),
        "embeddings.LayerNorm.bias": normal(HIDDEN, scale=0.1),
    }
    for layer in range(LAYERS):
        base = f"encoder.layer.{layer}"
        for part in ("attention.self.query", "attention.self.key", "attention.self.value", "attention.output.dense"):
            weights[f"{base}.{part}.weight"] = normal(HIDDEN, HIDDEN, scale=0.06)   # [out][in] as Hugging Face names it
            weights[f"{base}.{part}.bias"] = normal(HIDDEN, scale=0.05)
        weights[f"{base}.attention.output.LayerNorm.weight"] = norm_weight(HIDDEN)
        weights[f"{base}.attention.output.LayerNorm.bias"] = normal(HIDDEN, scale=0.1)
        weights[f"{base}.intermediate.dense.weight"] = normal(INTERMEDIATE, HIDDEN, scale=0.06)
        weights[f"{base}.intermediate.dense.bias"] = normal(INTERMEDIATE, scale=0.05)
        weights[f"{base}.output.dense.weight"] = normal(HIDDEN, INTERMEDIATE, scale=0.1)
        weights[f"{base}.output.dense.bias"] = normal(HIDDEN, scale=0.05)
        weights[f"{base}.output.LayerNorm.weight"] = norm_weight(HIDDEN)
        weights[f"{base}.output.LayerNorm.bias"] = normal(HIDDEN, scale=0.1)
    return weights


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def field(number: int, wire: int, payload: bytes | int) -> bytes:
    key = varint((number << 3) | wire)
    if wire == 0:
        return key + varint(payload)
    return key + varint(len(payload)) + payload


def tensor_proto(name: str, array) -> bytes:
    import numpy as np
    out = b"".join(field(1, 0, int(dim)) for dim in array.shape)
    out += field(2, 0, 1) + field(8, 2, name.encode()) + field(9, 2, np.ascontiguousarray(array, dtype="<f4").tobytes())
    return out


def node_proto(name: str, op: str, inputs, outputs) -> bytes:
    out = b"".join(field(1, 2, item.encode()) for item in inputs)
    out += b"".join(field(2, 2, item.encode()) for item in outputs)
    return out + field(3, 2, name.encode()) + field(4, 2, op.encode())


MATMULS = (("attention/self/query", "attention.self.query"), ("attention/self/key", "attention.self.key"),
           ("attention/self/value", "attention.self.value"), ("attention/output/dense", "attention.output.dense"),
           ("intermediate/dense", "intermediate.dense"), ("output/dense", "output.dense"))


def make_onnx(weights) -> bytes:
    """The export's constants and the nodes that name the matrix weights; no other node is needed to read it."""
    nodes, initializers, counter = [], [], 977
    nodes.append(node_proto("/Shape", "Shape", ["input_ids"], ["/Shape_output_0"]))
    for name, array in weights.items():
        if name.endswith(".weight") and ("attention.self." in name or "dense" in name):
            continue
        initializers.append(tensor_proto(name, array))
    for layer in range(LAYERS):
        for path, hf in MATMULS:
            weight = weights[f"encoder.layer.{layer}.{hf}.weight"]
            anonymous = f"onnx::MatMul_{counter}"
            counter += 1
            nodes.append(node_proto(f"/encoder/layer.{layer}/{path}/MatMul", "MatMul", ["/x", anonymous], [f"/y{counter}"]))
            initializers.append(tensor_proto(anonymous, weight.T))        # stored [input][output]
        nodes.append(node_proto(f"/encoder/layer.{layer}/attention/self/MatMul", "MatMul", ["/q", "/k"], ["/scores"]))
    graph = b"".join(field(1, 2, item) for item in nodes) + field(2, 2, b"main_graph")
    graph += b"".join(field(5, 2, item) for item in initializers)
    return field(1, 0, 7) + field(2, 2, b"pytorch") + field(7, 2, graph)


def bert_forward(weights, ids):
    """The exported graph in numpy float32: the independent reference of the Rust encoder."""
    import numpy as np
    f32 = np.float32
    n, head = len(ids), HIDDEN // HEADS
    erf = np.vectorize(math.erf, otypes=[np.float64])

    def layer_norm(x, w, b):
        mean = x.mean(axis=-1, keepdims=True)
        centred = x - mean
        variance = (centred ** 2).mean(axis=-1, keepdims=True)
        return centred / np.sqrt(variance + f32(EPS)) * w + b

    def dense(x, name):
        return x @ weights[name + ".weight"].T + weights[name + ".bias"]

    x = weights["embeddings.word_embeddings.weight"][ids] + weights["embeddings.token_type_embeddings.weight"][0]
    x = x + weights["embeddings.position_embeddings.weight"][:n]
    x = layer_norm(x.astype(f32), weights["embeddings.LayerNorm.weight"], weights["embeddings.LayerNorm.bias"])
    scale = f32(head ** -0.25)
    for layer in range(LAYERS):
        base = f"encoder.layer.{layer}"
        split = lambda t: t.reshape(n, HEADS, head).transpose(1, 0, 2)
        q, k, v = (split(dense(x, f"{base}.attention.self.{part}")) for part in ("query", "key", "value"))
        scores = (q * scale) @ (k * scale).transpose(0, 2, 1)
        shifted = scores - scores.max(axis=-1, keepdims=True)
        probabilities = np.exp(shifted) / np.exp(shifted).sum(axis=-1, keepdims=True)
        context = (probabilities @ v).transpose(1, 0, 2).reshape(n, HIDDEN)
        attended = layer_norm(dense(context, f"{base}.attention.output.dense") + x,
                              weights[f"{base}.attention.output.LayerNorm.weight"], weights[f"{base}.attention.output.LayerNorm.bias"])
        inner = dense(attended, f"{base}.intermediate.dense")
        inner = (inner * f32(0.5) * (f32(1.0) + erf(inner / f32(math.sqrt(2.0))).astype(f32))).astype(f32)
        x = layer_norm(dense(inner, f"{base}.output.dense") + attended,
                       weights[f"{base}.output.LayerNorm.weight"], weights[f"{base}.output.LayerNorm.bias"])
    return x.astype(f32)


class OfflineEncoder:
    """``FrozenPretrainedEncoder`` with the numpy graph in place of the onnxruntime session; the other lines are the class's."""

    def __init__(self, tokenizer_json: str, weights, max_tokens: int):
        import tokenizers
        self._max_tokens = max_tokens
        self._weights = weights
        self._tokenizer = tokenizers.Tokenizer.from_str(tokenizer_json)
        self._tokenizer.no_truncation()
        self._tokenizer.no_padding()

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    def token_count(self, text: str) -> int:
        return len(self._tokenizer.encode(text, add_special_tokens=True).ids)

    def encode_normalized(self, text: str):
        import numpy as np
        encoding = self._tokenizer.encode(text, add_special_tokens=True)
        length = len(encoding.ids)
        if not 2 <= length <= self.max_tokens:
            raise ValueError(f"Pretrained contextual input exceeds its {self.max_tokens}-token context including special tokens.")
        hidden = bert_forward(self._weights, np.asarray(encoding.ids, dtype=np.int64))[None]
        mask = np.asarray([encoding.attention_mask], dtype=np.int64).astype(np.float32)[..., None]
        pooled = (hidden * mask).sum(axis=1) / mask.sum(axis=1)
        norm = np.linalg.norm(pooled, axis=1, keepdims=True)
        if not np.isfinite(norm).all() or np.any(norm <= 0):
            raise ValueError("Pretrained encoder produced an invalid pooled norm.")
        return (pooled / norm)[0].astype(np.float32)


# --------------------------------------------------------------------------------------------------------------
# Heads, model and findings: the unchanged Python classes
# --------------------------------------------------------------------------------------------------------------


def make_heads(seed: int, scale: float, features):
    """Random heads, centred on the mean feature of the cases so that the logits follow what differs between texts.

    A random backbone maps every text near the same point, so uncentred heads would give every text the same decision."""
    import numpy as np
    from privoke_model.pretrained_context import head_tensor_shapes
    rng = np.random.default_rng(seed + 1000)
    centre = features.mean(axis=0)
    spread = float(np.mean(np.linalg.norm(features - centre, axis=1))) or 1.0
    heads = {}
    for name, shape in head_tensor_shapes().items():
        heads[name] = (rng.standard_normal(shape) * (scale / spread)).astype(np.float32)
    for task in ("sensitivity", "visibility", "category"):
        heads[f"head.{task}.bias"] = (heads[f"head.{task}.bias"] * spread - centre @ heads[f"head.{task}.weight"]).astype(np.float32)
    heads["head.category.bias"] = heads["head.category.bias"] - np.float32(0.5)
    return {name: values.reshape(-1).tolist() for name, values in heads.items()}


def snapshot_for(artifact: dict):
    from src.LLM.privoke.parameter_stream import ParameterSnapshot
    shapes = {name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()}
    parameters = {name: tuple(tensor["values"]) for name, tensor in artifact["parameters"].items()}
    metadata = {**artifact["metadata"], "architecture": artifact["architecture"], "trainable_parameters": "",
                "artifact_checksum": artifact["checksum"], "model_config": json.dumps(artifact["config"], sort_keys=True)}
    return ParameterSnapshot(artifact["model_id"], artifact["version"], artifact["generated_at_unix"], parameters, shapes, metadata)


def finite_floats(values):
    return [float(v) for v in values]


def case_record(text, encoder, model, streamed, snapshot):
    record = {"text": text, "tokens": encoder.token_count(text)}
    try:
        prediction = model.predict(text)
    except ValueError as error:
        record["error"] = str(error)
        return record
    record["pooled"] = finite_floats(prediction.pooled)
    record["prediction"] = {
        "sensitivity": prediction.sensitivity, "visibility": prediction.visibility, "categories": list(prediction.categories),
        "sensitivity_probabilities": finite_floats(prediction.sensitivity_probabilities),
        "visibility_probabilities": finite_floats(prediction.visibility_probabilities),
        "category_probabilities": finite_floats(prediction.category_probabilities), "confidence": float(prediction.confidence),
    }
    findings = streamed.classify(text)
    record["findings"] = [{
        "packed": int(result.classification.pack()), "confidence": result.confidence, "reasoning": result.reasoning,
        "span": list(result.span) if result.span is not None else None, "section_of_text": result.section_of_text,
        "metadata": {key: value if isinstance(value, str) else json.dumps(value, sort_keys=True) for key, value in result.metadata.items()},
    } for result in findings]
    return record


def margins_ok(record, threshold) -> bool:
    prediction = record.get("prediction")
    if prediction is None:
        return True
    for probs in (prediction["sensitivity_probabilities"], prediction["visibility_probabilities"]):
        ordered = sorted(probs, reverse=True)
        if ordered[0] - ordered[1] < 1e-3:
            return False
    raw = max(prediction["sensitivity_probabilities"] + prediction["category_probabilities"])
    # The reported confidence rounds to three decimals: keep clear of a rounding boundary, where float32 noise could flip it.
    if raw < 0.999 and abs((raw * 1000) % 1 - 0.5) < 0.02:
        return False
    return all(abs(p - threshold) > 1e-3 for p in prediction["category_probabilities"])


def build(seed: int, scale: float):
    import numpy as np
    from privoke_model.pretrained_context import PRETRAINED_CONTEXT_MODEL_ID, build_head_artifact
    from src.LLM.privoke.pretrained_context_model import StreamedPretrainedContextModel
    from src.pretrained_context import PretrainedContextModel

    tokenizer_json, vocab = make_tokenizer_json()
    weights = make_weights(seed, vocab)
    onnx = make_onnx(weights)
    long_encoder = OfflineEncoder(tokenizer_json, weights, MODEL_MAX_TOKENS)
    features = np.stack([long_encoder.encode_normalized(text) for text in TEXTS if long_encoder.token_count(text) >= 2])
    heads = make_heads(seed, scale, features)
    artifact = build_head_artifact(heads, version="test-1.0+ctx", generated_at_unix=1_700_000_000,
                                   metadata={"note": "synthetic golden"}, category_threshold=0.5, max_tokens=MODEL_MAX_TOKENS)
    snapshot = snapshot_for(artifact)

    short = OfflineEncoder(tokenizer_json, weights, ENCODER_MAX_TOKENS)
    long = OfflineEncoder(tokenizer_json, weights, MODEL_MAX_TOKENS)
    encoder_cases = []
    for text in TEXTS:
        record = {"text": text, "tokens": short.token_count(text)}
        try:
            record["features"] = finite_floats(short.encode_normalized(text))
        except ValueError as error:
            record["error"] = str(error)
        encoder_cases.append(record)

    streamed = StreamedPretrainedContextModel(snapshot, long)
    model = streamed.model
    assert isinstance(model, PretrainedContextModel)
    model_cases = [case_record(text, long, model, streamed, snapshot) for text in TEXTS]
    # Heads that decide the empty classification (S0, PU, no category) for every text: no finding is reported.
    from privoke_model.pretrained_context import head_tensor_shapes
    clean_heads = {name: [0.0] * math.prod(shape) for name, shape in head_tensor_shapes().items()}
    clean_heads["head.sensitivity.bias"] = [10.0, 0.0, 0.0, 0.0]
    clean_heads["head.visibility.bias"] = [0.0, 0.0, 0.0, 0.0, 0.0, 10.0]
    clean_heads["head.category.bias"] = [-10.0] * 10
    clean_artifact = build_head_artifact(clean_heads, version="clean-1.0", generated_at_unix=1_700_000_001,
                                         metadata={"note": "synthetic golden, empty classification"}, max_tokens=MODEL_MAX_TOKENS)
    clean_snapshot = snapshot_for(clean_artifact)
    clean_streamed = StreamedPretrainedContextModel(clean_snapshot, long)
    clean_cases = [case_record(text, long, clean_streamed.model, clean_streamed, clean_snapshot) for text in TEXTS[:4]]
    identity = {"model_id": snapshot.model_id, "model_version": snapshot.version,
                "artifact_checksum": snapshot.metadata["artifact_checksum"], "parameter_fingerprint": snapshot.fingerprint,
                "architecture": snapshot.metadata.get("architecture", "unknown")}
    for name in ("backbone_sha256", "tokenizer_sha256"):
        if name in snapshot.metadata:
            identity[name] = snapshot.metadata[name]
    context_identity = {"privoke.pretrained_context." + key: value for key, value in {
        "model_id": snapshot.model_id, "model_version": snapshot.version, "artifact_checksum": snapshot.metadata["artifact_checksum"],
        "parameter_fingerprint": snapshot.fingerprint, "backbone_sha256": model.config["backbone_sha256"],
        "tokenizer_sha256": model.config["tokenizer_sha256"]}.items()}
    document = {
        "schema": "privoke-pretrained-context-golden-1",
        "source": "src/pretrained_context.py (PretrainedContextModel) and LLM/privoke/pretrained_context_model.py, unchanged; "
                  "the backbone is a numpy float32 reference of the exported graph, not onnxruntime",
        "numpy": np.__version__, "seed": seed, "head_scale": scale,
        "backbone": {"hidden_size": HIDDEN, "num_hidden_layers": LAYERS, "num_attention_heads": HEADS, "intermediate_size": INTERMEDIATE,
                     "max_position_embeddings": POSITIONS, "vocab_size": vocab, "type_vocab_size": 2, "layer_norm_eps": EPS},
        "model_id": PRETRAINED_CONTEXT_MODEL_ID,
        "onnx_b64": base64.b64encode(onnx).decode(), "onnx_sha256": sha256(onnx),
        "tokenizer_json": tokenizer_json, "tokenizer_sha256": sha256(tokenizer_json.encode()),
        "artifact": json.dumps(artifact, ensure_ascii=False, sort_keys=True),
        "encoder_max_tokens": ENCODER_MAX_TOKENS, "model_max_tokens": MODEL_MAX_TOKENS,
        "encoder_cases": encoder_cases, "model_cases": model_cases,
        "semantic_identity": identity, "context_identity": context_identity,
        "clean": {"artifact": json.dumps(clean_artifact, ensure_ascii=False, sort_keys=True), "cases": clean_cases},
    }
    return document, model_cases


def run(out: Path) -> None:
    bootstrap()
    for scale in SCALES:
        for seed in SEEDS:
            document, cases = build(seed, scale)
            produced = [bool(case.get("findings")) for case in cases]
            errors = [case for case in document["encoder_cases"] if "error" in case]
            if all(margins_ok(case, 0.5) for case in cases) and any(produced) and errors:
                break
        else:
            continue
        break
    else:
        raise SystemExit("no seed and scale give decision margins above 1e-3 with findings and a length error")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=None, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} (seed {document['seed']}, {len(cases)} cases, {sum(produced)} with findings, {len(errors)} errors, "
          f"{out.stat().st_size} bytes)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    run(parser.parse_args().out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
