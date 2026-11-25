"""Golden features of the pinned pretrained contextual encoder, from onnxruntime on the real ``model.onnx``.

Host Python only. It reproduces ``FrozenPretrainedEncoder.encode_normalized`` of
``extension/client-runtime/src/pretrained_context.py`` (the same verified assets, one CPU session on one thread,
unpadded, untruncated tokenisation, mean over all tokens in float32, L2 normalisation, float32 features) without
importing the runtime package, and records the 384 float32 features of each text as hex.

The texts are the prompts of the committed ``rust/services/runtime/tests/fixtures/runtime_semantic_golden.json`` (the
``llm_only`` requests, read from the ``text`` field of each serialised ``AnalyzePromptRequest``), plus three texts built
by repeating committed prompts to reach longer contexts. No other text is used. They are passed to the encoder as they
are: the encoder takes already-normalised text, and normalisation is not what is compared.

The output is local evidence (``rust/crates/privoke-semantic/tests/local/``, git-ignored); the test that reads it is
``rust/crates/privoke-semantic/tests/context_onnx_real.rs``. Dependency versions are those the runtime pins
(onnxruntime 1.23.2, tokenizers 0.22.1, numpy 2.2.6); the script refuses others.

Usage: python evaluation/generate_context_encoder_onnx_golden.py --assets DIR [--output FILE]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "rust/services/runtime/tests/fixtures/runtime_semantic_golden.json"
DEFAULT_OUTPUT = ROOT / "rust/crates/privoke-semantic/tests/local/context_onnx_golden.json"
BACKBONE_SHA256 = "6fd5d72fe4589f189f8ebc006442dbb529bb7ce38f8082112682524616046452"
TOKENIZER_SHA256 = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"
PINNED = {"onnxruntime": "1.23.2", "tokenizers": "0.22.1", "numpy": "2.2.6"}
HIDDEN = 384
MAX_TOKENS = 512


def varint(data: bytes, index: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
        shift += 7


def request_text(serialised: bytes) -> str:
    """Field 1 (``text``) of a serialised ``AnalyzePromptRequest``, empty when the request has none."""
    index = 0
    while index < len(serialised):
        key, index = varint(serialised, index)
        number, wire = key >> 3, key & 7
        if wire == 0:
            _, index = varint(serialised, index)
        elif wire == 2:
            length, index = varint(serialised, index)
            if number == 1:
                return serialised[index:index + length].decode("utf-8")
            index += length
        elif wire == 1:
            index += 8
        elif wire == 5:
            index += 4
        else:
            raise ValueError("unsupported wire type in a fixture request")
    return ""


def fixture_texts() -> list[str]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    texts: list[str] = []
    for case in document["cases"]:
        if case["scope"] != "llm_only":
            continue
        text = request_text(base64.b64decode(case["request"]))
        if text and text not in texts:
            texts.append(text)
    if len(texts) < 20:
        raise SystemExit(f"only {len(texts)} fixture texts found")
    longest = sorted(texts, key=len)[-3:]
    texts.append(" ".join(texts[:8]))
    texts.append(" ".join(longest * 3))
    texts.append((" ".join(texts[:12]) + " ") * 2)
    return texts


def verified(directory: Path, name: str, expected: str) -> bytes:
    raw = (directory / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit(f"{name} does not match its pinned SHA-256")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--assets", required=True, type=Path, help="directory with model.onnx and tokenizer.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    options = parser.parse_args()

    import numpy as np
    import onnxruntime as ort
    import tokenizers

    found = {"onnxruntime": ort.__version__, "tokenizers": tokenizers.__version__, "numpy": np.__version__}
    if found != PINNED:
        raise SystemExit(f"dependency versions {found} differ from the pinned {PINNED}")
    model = verified(options.assets, "model.onnx", BACKBONE_SHA256)
    tokenizer_bytes = verified(options.assets, "tokenizer.json", TOKENIZER_SHA256)
    session_options = ort.SessionOptions()
    session_options.intra_op_num_threads = 1
    session_options.inter_op_num_threads = 1
    session = ort.InferenceSession(model, sess_options=session_options, providers=["CPUExecutionProvider"])
    tokenizer = tokenizers.Tokenizer.from_str(tokenizer_bytes.decode("utf-8"))
    tokenizer.no_truncation()
    tokenizer.no_padding()

    rows = []
    for text in fixture_texts():
        encoding = tokenizer.encode(text, add_special_tokens=True)
        length = len(encoding.ids)
        if not 2 <= length <= MAX_TOKENS:
            continue
        inputs = {"input_ids": np.asarray([encoding.ids], dtype=np.int64),
                  "attention_mask": np.asarray([encoding.attention_mask], dtype=np.int64),
                  "token_type_ids": np.asarray([encoding.type_ids], dtype=np.int64)}
        hidden = np.asarray(session.run(["last_hidden_state"], inputs)[0])
        assert hidden.dtype == np.float32 and hidden.shape == (1, length, HIDDEN) and np.isfinite(hidden).all()
        mask = inputs["attention_mask"].astype(np.float32)[..., None]
        pooled = (hidden * mask).sum(axis=1) / mask.sum(axis=1)
        norm = np.linalg.norm(pooled, axis=1, keepdims=True)
        features = (pooled / norm)[0].astype(np.float32)
        rows.append({"text": text, "tokens": length, "features_f32_hex": features.tobytes().hex()})

    document = {
        "schema": 1,
        "scope_note": "Features of the pinned encoder from onnxruntime on the real model.onnx, for the committed fixture texts only. "
                      "Local evidence; not part of any product claim.",
        "backbone_sha256": BACKBONE_SHA256,
        "tokenizer_sha256": TOKENIZER_SHA256,
        "versions": found,
        "python": sys.version.split()[0],
        "rows": rows,
    }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} rows to {options.output} (tokens {min(r['tokens'] for r in rows)} to {max(r['tokens'] for r in rows)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
