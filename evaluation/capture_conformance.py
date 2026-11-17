#!/usr/bin/env python
"""Capture the Rust-rewrite conformance corpus from the Python and Go reference services.

Stage 0 of docs/plans/rust-server-rewrite.md. The corpus is written to
``tests/conformance/`` and is the oracle the Rust crates replay (goal G5). Capture is
deterministic: no wall-clock value, port, temporary path or random seed that is not fixed
here reaches a corpus file, so two runs on one machine give byte-identical output.

Surfaces (each runs in its own interpreter, because the service modules share flat names):

* ``canonical``: Python ``json.dumps`` variants and float ``repr`` (contracts crate).
* ``contracts``: contract-config canonical JSON, artifact checksums, tensor fingerprints.
* ``update_sequence``: ``ParamUpdateService`` over a fixed update sequence, receipts, audit.
* ``telemetry``: ``TelemetryCollector`` packets, validation outcomes, stored marginals, summary.
* ``model_streaming``: the Go service (repository image, hosted with ``docker run`` on a
  loopback port exactly as ``evaluation/update_security.py`` does) for legacy chunk
  sequences, V3 manifests and assets, and negative cases. Large binaries are hashes.
* ``native_messaging`` and ``grpc_web``: runtime-supervisor transcripts from the real
  Python host and bridge, driven without a browser.

Nothing here is a test of model quality. Every value is observed from the reference code.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import math
import os
import random
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from host_environment import configure_imports  # noqa: E402

configure_imports()

DEFAULT_OUT = ROOT / "tests" / "conformance"
REFERENCE_TAG = "rust-reference-20261117"
DEFAULT_IMAGE = "privoke-updsec-model-dev:20261116"
SURFACES = ("canonical", "contracts", "update_sequence", "telemetry", "model_streaming", "native_messaging", "grpc_web")
LEGACY_MODELS = ("privoke-baseline", "privoke-balanced", "privoke-efficient", "privoke-quality")
V3_MODELS = ("privoke-v3-efficient", "privoke-v3-balanced", "privoke-v3-quality")
V3_ASSETS = ("model.safetensors", "config.json", "vocab.txt", "evidence.json")
CORPUS_SCHEMA = 1
# Paths whose bytes define the reference behaviour. Capture refuses to run if they differ from the tag.
REFERENCE_PATHS = ("shared/proto", "shared/python/privoke_model", "shared/python/privoke_service", "services/param-update-service/app",
                   "services/telemetry-service/app", "services/model-streaming-service/cmd", "extension/runtime-supervisor/src", "models/privoke-baseline.json",
                   "models/privoke-balanced.json", "models/privoke-efficient.json", "models/privoke-quality.json")


# --------------------------------------------------------------------------------------
# Deterministic output
# --------------------------------------------------------------------------------------

def dump_json(value) -> bytes:
    """The only serialisation of corpus files: sorted keys, ASCII, LF, final newline."""
    return (json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def write_json(out: Path, name: str, value) -> None:
    path = out / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dump_json(value))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_lf(data: bytes) -> str:
    """Hash with Windows text-mode CRLF folded to LF (artifact JSON never holds a raw CR or LF in a string)."""
    return sha256(data.replace(b"\r\n", b"\n"))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def f64_bits(value: float) -> str:
    return format(struct.unpack(">Q", struct.pack(">d", value))[0], "016x")


def float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]


# --------------------------------------------------------------------------------------
# Canonical JSON variants (the exact json.dumps expressions of the reference code)
# --------------------------------------------------------------------------------------

VARIANTS = ("ascii", "utf8", "utf8_go", "utf8_lf")
VARIANT_SOURCES = {
    "ascii": "privoke_model.full_adam.canonical; param-update receipts; contextual_training admission header",
    "utf8": "privoke_model.fingerprint.parameter_fingerprint (without sort_keys, applied to a list)",
    "utf8_go": "privoke_model.artifact.artifact_checksum (U+2028 and U+2029 escaped as Go's encoder does)",
    "utf8_lf": "privoke_model.v3_contract.canonical and privoke_model.sensitive_retention.canonical_bytes",
}


def canonical_text(value, variant: str) -> str:
    """Return the canonical text, or raise ValueError/UnicodeError exactly where Python does."""
    if variant == "ascii":
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    text.encode("utf-8")  # strict: a lone surrogate is an error, as in every Python hasher
    if variant == "utf8":
        return text
    if variant == "utf8_go":
        return text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    if variant == "utf8_lf":
        return text + "\n"
    raise ValueError(variant)


def cross_check_variants(value) -> None:
    """Fail capture if the local variant functions drift from the reference modules."""
    from privoke_model import full_adam, sensitive_retention, v3_contract
    from privoke_model.artifact import artifact_checksum

    assert full_adam.canonical(value) == canonical_text(value, "ascii")
    assert v3_contract.canonical(value) == canonical_text(value, "utf8_lf").encode("utf-8")
    assert sensitive_retention.canonical_bytes(value) == canonical_text(value, "utf8_lf").encode("utf-8")
    assert artifact_checksum(value) == sha256(canonical_text(value, "utf8_go").encode("utf-8"))


# --------------------------------------------------------------------------------------
# Surface: canonical
# --------------------------------------------------------------------------------------

CANONICAL_INPUTS = [
    "{}", "[]", "null", "true", "false", "0", "-0", "1", "-1", "12345678901234567890", "-9223372036854775809",
    "100000000000000000000000000000", "0.0", "-0.0", "1.0", "0.5", "0.1", "1e5", "1E5", "1e-5", "1.5e-7", "1e16", "1e15",
    "123456789012345678.0", "1e22", "1e23", "5e-324", "2.2250738585072014e-308", "1.7976931348623157e308",
    "1e-8", "0.003", "0.9", "0.999", "0.05", "0.0001", "0.00001", "1.0e+2", "-1.5E+3", "4.35", "2.675",
    "0.30000000000000004", "9007199254740993", "9007199254740993.0",
    '""', '"a"', '"\\"\\\\\\/\\b\\f\\n\\r\\t"', '"\\u0000\\u001f\\u007f\\u0080"', '"\\u00e9\\u4e2d\\ud83d\\ude00"',
    '"\\u2028\\u2029"', '"line\\u2028sep and para\\u2029sep"', '"\u00e9\u4e2d\U0001f600"', '"\\ud83d\\ude00"',
    '{"b":1,"a":2}', '{"\\u00e9":1,"z":2,"A":3,"\\ud83d\\ude00":4,"\\uffff":5}', '{"a":{"d":1,"c":[3,2,1]},"b":null}',
    '{"k":1,"k":2}', '{"a":[],"b":{}}', '[1,2.0,"3",null,true,{"x":[]}]', '[1.0,2.5,-0.0,1e-8,3e20,1e21]',
    '{"adam":{"eta":0.003,"beta2":0.999,"epsilon":1e-8},"steps":64}', '{"nested":{"deep":{"deeper":{"deepest":[0.1,0.2,0.30000000000000004]}}}}',
    '"\\ud800"', '"\\udc00x"', "1e400", "-1e400", "NaN", "Infinity", "-Infinity",
]


def float_repr_cases() -> list[list[str]]:
    rng = random.Random(20261117)
    values: list[float] = [0.0, -0.0, 1.0, -1.0, 0.1, 0.2, 0.3, 0.5, 1 / 3, 2 / 3, 5e-324, 2.2250738585072014e-308, 1.7976931348623157e308,
                           1e15, 1e16, 1e17, 9999999999999998.0, 999999999999999.9, 1e-4, 1e-5, 9.5e-5, 1e22, 1e23, 1e21, 123456789012345680.0,
                           4.35, 2.675, 0.003, 1e-8, 1e-7, 1e-6, 5e-7, 3.4028234663852886e38, 1.1754943508222875e-38, 1e-45, 8388608.0,
                           16777216.0, 16777217.0, 1e100, 1e-100, 123456.789, 0.30000000000000004]
    values += [10.0 ** k for k in range(-30, 31)]
    values += [2.0 ** k for k in range(-1074, 1024, 37)]
    values += [float32(rng.uniform(-4, 4)) for _ in range(150)]
    values += [round(rng.uniform(-10, 10), rng.randint(1, 8)) for _ in range(150)]
    values += [rng.uniform(-1, 1) * 10.0 ** rng.randint(-12, 12) for _ in range(200)]
    while len(values) < 900:
        candidate = struct.unpack(">d", struct.pack(">Q", rng.getrandbits(64)))[0]
        if math.isfinite(candidate):
            values.append(candidate)
    seen, rows = set(), []
    for value in values:
        bits = f64_bits(value)
        if bits not in seen:
            seen.add(bits)
            rows.append([bits, repr(value)])
    return rows


def capture_canonical(out: Path) -> None:
    cases = []
    for index, text in enumerate(CANONICAL_INPUTS):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:  # pragma: no cover - inputs are fixed
            raise AssertionError(f"capture input is not JSON for Python: {text!r}: {error}")
        for variant in VARIANTS:
            record = {"id": f"c{index:03d}-{variant}", "input_json": text, "variant": variant}
            try:
                record["expected"] = canonical_text(value, variant)
            except (ValueError, UnicodeError) as error:
                record["expected_error"] = type(error).__name__
                if variant == "utf8_go" and isinstance(value, float) and not math.isfinite(value):
                    # artifact_checksum allows NaN; Rust rejects it. Not a reachable artifact (validation rejects it).
                    record["expected_error"] = "non_finite_rejected_by_rust"
            if "expected" in record and isinstance(value, float) and not math.isfinite(value):
                continue
            cases.append(record)
    # Lone surrogates: Python's ASCII variant emits them; Rust strings cannot hold them, so Rust must reject.
    for case in cases:
        if case["input_json"] in ('"\\ud800"', '"\\udc00x"') and case["variant"] == "ascii":
            case["rust_rejects_lone_surrogate"] = True
    # Sanity: reference modules agree with the local variant functions on a nested sample.
    cross_check_variants(json.loads('{"b":[1,2.5,{"\\u00e9":"\\u2028"}],"a":null}'))
    duplicate = {"id": "dup-last-wins", "input_json": '{"k":1,"k":2}', "variant": "ascii", "expected": '{"k":2}', "duplicates": "last_wins"}
    write_json(out, "canonical_json.json", {"schema": CORPUS_SCHEMA, "variants": VARIANT_SOURCES, "cases": cases + [duplicate]})
    write_json(out, "float_repr.json", {"schema": CORPUS_SCHEMA, "note": "[IEEE-754 double bits as hex, Python repr]", "cases": float_repr_cases()})


# --------------------------------------------------------------------------------------
# Surface: contracts
# --------------------------------------------------------------------------------------

def tensor_pairs(artifact: dict) -> tuple[dict, dict]:
    values = {name: tensor["values"] for name, tensor in artifact["parameters"].items()}
    shapes = {name: tensor["shape"] for name, tensor in artifact["parameters"].items()}
    return values, shapes


def capture_contracts(out: Path) -> None:
    from privoke_model import contextual_training, full_adam, sensitive_retention, v3_contract, window_training
    from privoke_model.artifact import artifact_checksum, validate_artifact
    from privoke_model.fingerprint import parameter_fingerprint

    admission = {"schema": 1, "expected_backtracking_policy": contextual_training.BACKTRACKING_POLICY,
                 "expected_objective": contextual_training.CLASS_BALANCED_SUM_CATEGORY_DECISION_MARGIN_OBJECTIVE,
                 "expected_scales": list(contextual_training.BACKTRACKING_SCALES), "decrease": contextual_training.BACKTRACKING_DECREASE}
    configs = [
        ("full_adam.CONFIG", "ascii", full_adam.CONFIG, full_adam.canonical(full_adam.CONFIG)),
        ("window_training.CONFIG", "ascii", window_training.CONFIG, window_training.canonical(window_training.CONFIG)),
        ("sensitive_retention.BOUNDARY", "utf8_lf", sensitive_retention.BOUNDARY, sensitive_retention.canonical_bytes(sensitive_retention.BOUNDARY).decode()),
        ("sensitive_retention.NORMALIZATION", "utf8_lf", sensitive_retention.NORMALIZATION, sensitive_retention.canonical_bytes(sensitive_retention.NORMALIZATION).decode()),
        ("v3_contract.POLICY", "utf8_lf", v3_contract.POLICY, v3_contract.canonical(v3_contract.POLICY).decode()),
        ("v3_contract.POLICY[pilot]", "utf8_lf", {**v3_contract.POLICY, "steps": 2, "window_batches": 1, "epochs": 2}, None),
        ("v3_contract.TIERS", "utf8_lf", v3_contract.TIERS, v3_contract.canonical(v3_contract.TIERS).decode()),
        ("v3_contract.LABELS", "utf8_lf", v3_contract.LABELS, v3_contract.canonical(v3_contract.LABELS).decode()),
        ("v3_contract.SOURCE_PINS", "utf8_lf", v3_contract.SOURCE_PINS, v3_contract.canonical(v3_contract.SOURCE_PINS).decode()),
        ("contextual_training.admission-header-record", "ascii", admission, json.dumps(admission, sort_keys=True, separators=(",", ":"), allow_nan=False)),
    ]
    contract_cases = []
    for name, variant, value, reference in configs:
        text = json.dumps(value, separators=(",", ":"))
        expected = canonical_text(json.loads(text), variant)
        assert reference is None or reference == expected, name
        contract_cases.append({"name": name, "variant": variant, "input_json": text, "expected": expected})
    derived = []
    for seed, purpose, index in ((0, "train", 0), (7, "guard", 3), (20261117, "window", 63), (2 ** 32 - 1, "é", 1)):
        derived.append({"seed": seed, "purpose": purpose, "index": index, "expected": window_training.derived_seed(seed, purpose, index)})
    receipt_keys = []
    sys.path.insert(0, str(ROOT / "services/param-update-service/app"))
    from receipts import receipt_key
    for parts in (("source", "req-1", ""), ("source", "req-1", "origin"), ("s\u00e9", "r\u4e2d\U0001f600", ""), ("", "", "")):
        receipt_keys.append({"source_id": parts[0], "request_id": parts[1], "request_source_id": parts[2],
                             "expected": receipt_key(parts[0], parts[1], parts[2])})
    write_json(out, "contract_configs.json", {"schema": CORPUS_SCHEMA, "configs": contract_cases, "derived_seeds": derived,
                                              "receipt_keys": receipt_keys,
                                              "constants": {"v3_standard_pins": __import__("privoke_model.standard_v3", fromlist=["x"]).STANDARD_PINS}})

    checksum_cases = []
    rng = random.Random(8675309)
    for index in range(40):
        payload = {"schema_version": 1, "model_id": f"m\u00e9-{index}", "version": f"v{index}\u2028",
                   "parameters": {f"p{n}": {"shape": [2, 2], "values": [round(rng.uniform(-1, 1), 8) for _ in range(4)]} for n in range(rng.randint(1, 4))},
                   "metadata": {"k\u4e2d": "v\U0001f600", "n": str(index)}, "generated_at_unix": 1700000000 + index}
        checksum_cases.append({"input_json": json.dumps(payload), "expected": artifact_checksum(payload)})
    artifacts, fingerprints = [], []
    for model in LEGACY_MODELS:
        path = ROOT / "models" / f"{model}.json"
        raw = path.read_bytes()
        artifact = json.loads(raw.decode("utf-8"))
        validate_artifact(artifact)
        body = {k: v for k, v in artifact.items() if k != "checksum"}
        assert artifact_checksum(body) == artifact["checksum"]
        values, shapes = tensor_pairs(artifact)
        total = sum(len(v) for v in values.values())
        artifacts.append({"path": f"models/{model}.json", "file_sha256_lf": sha256_lf(raw), "model_id": artifact["model_id"], "version": artifact["version"],
                          "declared_checksum": artifact["checksum"], "tensors": len(values), "values": total,
                          "fingerprint_with_shapes": parameter_fingerprint(values, shapes), "fingerprint_without_shapes": parameter_fingerprint(values)})
    synthetic = [
        {"name": "empty", "parameters": {}, "shapes": {}},
        {"name": "one", "parameters": {"w": [0.0, -0.0, 1.0]}, "shapes": {"w": [3]}},
        {"name": "unicode-order", "parameters": {"\u00e9": [1.0], "z": [2.0], "A": [3.0], "\U0001f600": [4.0], "\uffff": [5.0]},
         "shapes": {"\u00e9": [1], "z": [1], "A": [1], "\U0001f600": [1], "\uffff": [1]}},
        {"name": "float32-widened", "parameters": {"t": [float32(0.1), float32(1e-8), float32(3.4028234663852886e38), float32(-1.5e-5), float32(16777217.0)]}, "shapes": {"t": [5]}},
        {"name": "ints-become-floats", "parameters": {"i": [1, 2, 3, 100000000, 10 ** 16]}, "shapes": {"i": [5]}},
        {"name": "partial-shapes", "parameters": {"a": [1.5], "b": [2.5]}, "shapes": {"a": [1]}},
        {"name": "matrix", "parameters": {"m": [rng.uniform(-1, 1) for _ in range(12)]}, "shapes": {"m": [3, 4]}},
    ]
    for item in synthetic:
        fingerprints.append({"name": item["name"], "parameters_json": json.dumps(item["parameters"]), "shapes_json": json.dumps(item["shapes"]),
                             "expected_with_shapes": parameter_fingerprint(item["parameters"], item["shapes"]),
                             "expected_without_shapes": parameter_fingerprint(item["parameters"])})
    write_json(out, "checksums.json", {"schema": CORPUS_SCHEMA, "synthetic": checksum_cases, "artifacts": artifacts})
    write_json(out, "fingerprints.json", {"schema": CORPUS_SCHEMA, "synthetic": fingerprints})


# --------------------------------------------------------------------------------------
# Fake gRPC contexts (the services only call abort)
# --------------------------------------------------------------------------------------

class Aborted(Exception):
    def __init__(self, code, details):
        super().__init__(details)
        self.code, self.details = code, details


class FakeContext:
    def abort(self, code, details):
        raise Aborted(code, details)


def call_outcome(function, request):
    try:
        return {"status": "OK", "response": function(request, FakeContext())}
    except Aborted as error:
        return {"status": error.code.name, "details": error.details}


# --------------------------------------------------------------------------------------
# Surface: update_sequence
# --------------------------------------------------------------------------------------

class FakeClock:
    """Replaces the `time` module inside privoke_model.artifact and the bootstrap, one tick per call."""

    def __init__(self, start: int):
        self.value = start

    def time(self) -> float:
        self.value += 1
        return float(self.value)


def capture_update_sequence(out: Path) -> None:
    sys.path.insert(0, str(ROOT / "services/param-update-service/app"))
    sys.path.insert(0, str(ROOT / "services/param-update-service/generated"))
    import bootstrap
    import server as updater
    from privoke.v1 import parameters_pb2 as pb
    from privoke_model import artifact as artifact_module

    clock = FakeClock(1_800_000_000)
    artifact_module.time = clock
    bootstrap.time = clock
    work = Path(tempfile.mkdtemp(prefix="conformance-update-"))
    try:
        model_path = work / "privoke-balanced.json"
        audit_path = work / "updates.jsonl"
        shutil.copyfile(ROOT / "models" / "privoke-balanced.json", model_path)
        bootstrap.bootstrap_model(model_path, audit_path, "privoke-balanced", max_tokens=256)
        snapshot = lambda: {"sha256_lf": sha256_lf(model_path.read_bytes())}  # noqa: E731
        base_artifact = json.loads(model_path.read_bytes().decode("utf-8"))
        initial = {"version": base_artifact["version"], "checksum": base_artifact["checksum"], **snapshot(),
                   "trainable": sorted(n for n, t in base_artifact["parameters"].items() if t.get("trainable")),
                   "generated_at_unix": base_artifact["generated_at_unix"]}
        service = updater.ParamUpdateService(audit_path, expected_model_id="privoke-balanced", max_abs_gradient=1.0, model_artifact_path=model_path)
        rng = random.Random(20261117)

        def gradient(name, count, scale=0.05, shape=None):
            return pb.Parameter(name=name, values=[round(rng.uniform(-scale, scale), 6) for _ in range(count)], shape=shape or [count])

        def request(source="conformance-trainer", base=None, gradients=None, metadata=None, model="privoke-balanced"):
            current = json.loads(model_path.read_bytes().decode("utf-8"))["version"]
            return pb.ParameterUpdateRequest(source_id=source, model_id=model, base_version=base if base is not None else current,
                                             gradients=gradients if gradients is not None else [], metadata=metadata or {})

        steps = []

        def submit(label, req):
            before = snapshot()["sha256_lf"]
            result = call_outcome(service.SubmitParameterUpdate, req)
            record = {"label": label, "request_b64": b64(req.SerializeToString(deterministic=True)), "status": result["status"]}
            if result["status"] == "OK":
                ack = result["response"]
                record["ack"] = {"accepted": ack.accepted, "model_id": ack.model_id, "applied_version": ack.applied_version, "message": ack.message}
            else:
                record["details"] = result["details"]
            after = json.loads(model_path.read_bytes().decode("utf-8"))
            record["artifact_after"] = {"version": after["version"], "checksum": after["checksum"], "sha256_lf": snapshot()["sha256_lf"],
                                        "generated_at_unix": after["generated_at_unix"], "changed": snapshot()["sha256_lf"] != before}
            steps.append(record)
            return result

        meta1 = {"request_id": "conf-0001", "request_source_id": "origin-a", "training_request_fingerprint": "fp-0001", "generated_prompt_count": "32"}
        first = request(gradients=[gradient("head.sensitivity.bias", 4), gradient("head.visibility.bias", 6)], metadata=meta1)
        submit("valid-with-receipt", first)
        submit("valid-without-request-id", request(gradients=[gradient("head.category.bias", 10)]))
        submit("replay-of-first-is-idempotent", first)
        submit("stale-base-version", request(base="v0.4.0-stale", gradients=[gradient("head.category.bias", 10)]))
        bound = pb.Parameter(name="head.sensitivity.weight", values=[1.0 if i % 2 else -1.0 for i in range(128)], shape=[32, 4])
        submit("values-at-bound", request(gradients=[bound], metadata={"request_id": "conf-0002", "generated_prompt_count": "1024"}))
        submit("over-bound", request(gradients=[pb.Parameter(name="head.category.bias", values=[1.0000001] + [0.0] * 9, shape=[10])]))
        submit("nan", request(gradients=[pb.Parameter(name="head.category.bias", values=[float("nan")] + [0.0] * 9, shape=[10])]))
        submit("infinity", request(gradients=[pb.Parameter(name="head.category.bias", values=[float("inf")] + [0.0] * 9, shape=[10])]))
        submit("wrong-shape-same-size", request(gradients=[pb.Parameter(name="head.sensitivity.weight", values=[0.0] * 128, shape=[4, 32])]))
        submit("shape-value-mismatch", request(gradients=[pb.Parameter(name="head.category.bias", values=[0.0] * 9, shape=[10])]))
        submit("unknown-tensor", request(gradients=[pb.Parameter(name="head.unknown", values=[0.0], shape=[1])]))
        submit("encoder-tensor-trainable-after-bootstrap", request(gradients=[pb.Parameter(name="layers.0.attention.key.weight", values=[0.0] * 1024, shape=[32, 32])]))
        submit("duplicate-tensor", request(gradients=[gradient("head.category.bias", 10), gradient("head.category.bias", 10)]))
        submit("no-gradients", request())
        submit("wrong-model-id", request(model="privoke-baseline", gradients=[gradient("head.category.bias", 10)]))
        submit("empty-source-id", request(source="", gradients=[gradient("head.category.bias", 10)]))
        submit("control-character-metadata", request(gradients=[gradient("head.category.bias", 10)], metadata={"k": "bad\x01value"}))
        submit("request-id-reuse-different-payload", request(gradients=[gradient("head.visibility.bias", 6)], metadata=meta1))
        submit("valid-after-rejections", request(gradients=[gradient("head.visibility.bias", 6), gradient("head.category.bias", 10)],
                                                 metadata={"request_id": "conf-0003", "training_request_fingerprint": "fp-0003", "generated_prompt_count": "5"}))

        statuses = []
        for label, req in (
                ("found-first", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", request_id="conf-0001", request_source_id="origin-a", model_id="privoke-balanced", request_fingerprint="fp-0001")),
                ("found-third", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", request_id="conf-0003", model_id="privoke-balanced", request_fingerprint="fp-0003")),
                ("not-found", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", request_id="never", model_id="privoke-balanced")),
                ("fingerprint-mismatch", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", request_id="conf-0001", request_source_id="origin-a", model_id="privoke-balanced", request_fingerprint="other")),
                ("wrong-model", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", request_id="conf-0001", model_id="privoke-baseline")),
                ("missing-request-id", pb.ParameterUpdateStatusRequest(source_id="conformance-trainer", model_id="privoke-balanced"))):
            result = call_outcome(service.GetParameterUpdateStatus, req)
            record = {"label": label, "request_b64": b64(req.SerializeToString(deterministic=True)), "status": result["status"]}
            if result["status"] == "OK":
                response = result["response"]
                record["response"] = {"found": response.found, "ack_accepted": response.ack.accepted, "ack_model_id": response.ack.model_id,
                                      "ack_applied_version": response.ack.applied_version, "ack_message": response.ack.message,
                                      "base_version": response.base_version, "prompts_generated": response.prompts_generated}
            else:
                record["details"] = result["details"]
            statuses.append(record)
        health = service.Health(pb.HealthRequest(), FakeContext())

        receipts_path = audit_path.with_name(audit_path.name + ".receipts.sqlite3")
        connection = sqlite3.connect(receipts_path)
        receipts = [{"key": key, "receipt": json.loads(receipt)} for key, receipt in connection.execute("SELECT key, receipt FROM update_receipts ORDER BY key")]
        connection.close()
        audit_lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
        final = json.loads(model_path.read_bytes().decode("utf-8"))
        final_state = {"version": final["version"], "checksum": final["checksum"], **snapshot(), "metadata": final["metadata"],
                       "generated_at_unix": final["generated_at_unix"], "parameters_fingerprint": __import__("privoke_model.fingerprint", fromlist=["x"]).parameter_fingerprint(
                           {n: t["values"] for n, t in final["parameters"].items()}, {n: t["shape"] for n, t in final["parameters"].items()})}
        write_json(out, "update_sequence.json", {
            "schema": CORPUS_SCHEMA,
            "note": "Artifact bytes are hashed with CRLF folded to LF (the Python writer uses text mode). generated_at_unix comes from a fixed one-tick-per-call clock.",
            "clock_start": 1_800_000_000, "max_abs_gradient": 1.0, "expected_model_id": "privoke-balanced",
            "base_artifact": {"path": "models/privoke-balanced.json", "bootstrap": {"max_tokens": 256, "source_revision": bootstrap.PREPARATION_CODE_REVISION}},
            "initial_after_bootstrap": initial, "steps": steps, "status_lookups": statuses,
            "health": {"service": health.service, "status": health.status}, "receipts": receipts, "audit_lines": audit_lines, "final": final_state})
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------------------
# Surface: telemetry
# --------------------------------------------------------------------------------------

def capture_telemetry(out: Path) -> None:
    sys.path.insert(0, str(ROOT / "services/telemetry-service/app"))
    sys.path.insert(0, str(ROOT / "services/telemetry-service/generated"))
    import server as collector_module
    from storage import TelemetryStore
    from validation import ALLOWED_VALUES
    from privoke.v1 import telemetry_pb2 as pb

    work = Path(tempfile.mkdtemp(prefix="conformance-telemetry-"))
    try:
        store = TelemetryStore(work / "telemetry-ldp-v1.sqlite3")
        collector = collector_module.TelemetryCollector(store)
        rng = random.Random(20261117)
        packets = []

        def packet(**overrides):
            fields = {"time_bucket": "08-12_UTC", "action": "ALLOW", "primary_category": "NONE", "risk_bucket": "0.0-0.2", "model_version": "v0.3.0",
                      "privacy_mechanism": "grr_rr_v1", "privacy_epsilon": 1.0}
            fields.update(overrides)
            return pb.TelemetryPacket(**fields)

        for index in range(180):
            epsilon = rng.choice((0.5, 0.75, 1.0, 1.25, 2.0, 1.333333))
            fields = {name: rng.choice(sorted(ALLOWED_VALUES[name])) for name in ("time_bucket", "action", "primary_category", "risk_bucket", "model_version")}
            packets.append((f"valid-{index:03d}", packet(privacy_epsilon=epsilon, **fields)))
        invalid = [("bad-mechanism", packet(privacy_mechanism="other")), ("empty-mechanism", packet(privacy_mechanism="")),
                   ("epsilon-below-minimum", packet(privacy_epsilon=0.4999)), ("epsilon-above-maximum", packet(privacy_epsilon=2.0000001)),
                   ("epsilon-nan", packet(privacy_epsilon=float("nan"))), ("epsilon-infinity", packet(privacy_epsilon=float("inf"))),
                   ("epsilon-seven-decimals", packet(privacy_epsilon=1.0000001)), ("epsilon-at-minimum", packet(privacy_epsilon=0.5)),
                   ("epsilon-at-maximum", packet(privacy_epsilon=2.0)), ("bad-action", packet(action="DENY")), ("empty-category", packet(primary_category="")),
                   ("bad-time-bucket", packet(time_bucket="24-28_UTC")), ("bad-risk-bucket", packet(risk_bucket="0.2-0.3")),
                   ("bad-model-version", packet(model_version="v9.9.9")), ("lower-case-action", packet(action="allow"))]
        records = []
        for label, message in packets + invalid:
            result = call_outcome(collector.RecordTelemetry, message)
            entry = {"label": label, "request_b64": b64(message.SerializeToString(deterministic=True)), "status": result["status"]}
            if result["status"] == "OK":
                entry["response"] = {"accepted": result["response"].accepted, "message": result["response"].message}
            else:
                entry["details"] = result["details"]
            records.append(entry)
        connection = sqlite3.connect(store.path)
        strata = [list(row) for row in connection.execute("SELECT epsilon_micros, sample_count FROM telemetry_strata ORDER BY epsilon_micros")]
        counts = [list(row) for row in connection.execute("SELECT epsilon_micros, dimension, value, observed_count FROM telemetry_counts ORDER BY epsilon_micros, dimension, value")]
        connection.close()
        summary = collector.GetTelemetrySummary(pb.GetTelemetrySummaryRequest(), FakeContext())
        dimensions = [{"dimension": d.dimension, "values": [{"value": v.value, "estimated_count_repr": repr(v.estimated_count), "estimated_count_bits": f64_bits(v.estimated_count),
                                                            "observed_noisy_count": v.observed_noisy_count} for v in d.values]} for d in summary.dimensions]
        health = collector.Health(pb.TelemetryHealthRequest(), FakeContext())
        empty = collector_module.TelemetryCollector(TelemetryStore(work / "empty.sqlite3")).GetTelemetrySummary(pb.GetTelemetrySummaryRequest(), FakeContext())
        write_json(out, "telemetry.json", {
            "schema": CORPUS_SCHEMA, "estimator_tolerance_ulps": 4, "records": records, "strata": strata, "counts": counts,
            "summary": {"sample_count": summary.sample_count, "dimensions": dimensions, "serialized_sha256": sha256(summary.SerializeToString(deterministic=True))},
            "empty_summary": {"sample_count": empty.sample_count, "dimensions": len(empty.dimensions),
                              "all_zero": all(v.estimated_count == 0.0 and v.observed_noisy_count == 0 for d in empty.dimensions for v in d.values)},
            "health": {"service": health.service, "status": health.status}})
    finally:
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------------------
# Surface: model_streaming (Go service in Docker on loopback)
# --------------------------------------------------------------------------------------

def message_sha(message) -> str:
    return sha256(message.SerializeToString(deterministic=True))


def values_sha(values) -> str:
    return sha256(b"".join(struct.pack("<f", value) for value in values))


class GoService:
    def __init__(self, image: str, models_dir: Path, release_dir: Path | None, latest: str = "privoke-v3-balanced"):
        self.port = free_port()
        self.container = f"rustconf-{os.getpid()}-{self.port}"
        command = ["docker", "run", "-d", "--rm", "--name", self.container, "-p", f"127.0.0.1:{self.port}:50051",
                   "-e", "MODEL_STREAMING_PORT=50051", "-e", f"MODEL_LATEST_ID={latest}", "-e", "MODEL_ARTIFACT_DIR=/models",
                   "-e", "MODEL_RELEASE_DIR=/model-releases", "-v", f"{models_dir}:/models:ro"]
        if release_dir is not None:
            command += ["-v", f"{release_dir}:/model-releases:ro"]
        command += [image, "/usr/local/bin/model-streaming-service-dev"]
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait(self, timeout=120):
        import grpc
        from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with grpc.insecure_channel(f"127.0.0.1:{self.port}") as channel:
                    if rpc.ModelStreamingServiceStub(channel).Health(pb.HealthRequest(), timeout=2).status == "SERVING":
                        return
            except grpc.RpcError:
                pass
            time.sleep(0.5)
        logs = subprocess.run(["docker", "logs", "--tail", "20", self.container], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
        raise RuntimeError(f"model-streaming-service not serving: {logs[-500:]}")

    def close(self):
        subprocess.run(["docker", "rm", "-f", self.container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def grpc_outcome(call, *args):
    import grpc

    try:
        return "OK", call(*args, timeout=120)
    except grpc.RpcError as error:
        return error.code().name, error.details()


def stream_outcome(call, request):
    import grpc

    try:
        return "OK", list(call(request, timeout=300))
    except grpc.RpcError as error:
        return error.code().name, error.details()


def capture_model_streaming(out: Path, image: str, release_dir: Path | None, skip_docker: bool) -> None:
    if skip_docker:
        write_json(out, "model_streaming.json", {"schema": CORPUS_SCHEMA, "not_run": "docker skipped"})
        return
    import grpc
    from privoke.v1 import parameters_pb2 as pb, parameters_pb2_grpc as rpc

    work = Path(tempfile.mkdtemp(prefix="conformance-stream-"))
    service = None
    try:
        models_dir = work / "models"
        models_dir.mkdir()
        for model in LEGACY_MODELS:
            shutil.copyfile(ROOT / "models" / f"{model}.json", models_dir / f"{model}.json")
        service = GoService(image, models_dir.resolve(), release_dir.resolve() if release_dir else None)
        service.wait()
        options = (("grpc.max_receive_message_length", 128 * 1024 * 1024), ("grpc.enable_http_proxy", 0))
        channel = grpc.insecure_channel(f"127.0.0.1:{service.port}", options=options)
        stub = rpc.ModelStreamingServiceStub(channel)

        legacy = {}
        for model in LEGACY_MODELS:
            request = pb.ModelParametersRequest(consumer_id="conformance-consumer", model_id=model)
            status, response = grpc_outcome(stub.GetModelParameters, request)
            assert status == "OK", (model, status, response)
            chunk_status, chunks = stream_outcome(stub.StreamModelParameters, request)
            assert chunk_status == "OK", (model, chunk_status, chunks)
            rows = []
            for chunk in chunks:
                rows.append({"chunk_index": chunk.chunk_index, "total_chunks": chunk.total_chunks, "name": chunk.parameter.name,
                             "shape": list(chunk.parameter.shape), "value_offset": chunk.parameter.value_offset, "value_count": len(chunk.parameter.values),
                             "values_sha256_f32le": values_sha(chunk.parameter.values), "model_id": chunk.model_id, "version": chunk.version,
                             "generated_at_unix": chunk.generated_at_unix, "metadata": dict(chunk.metadata), "message_sha256": message_sha(chunk)})
            assert all(row["total_chunks"] == len(rows) for row in rows)
            legacy[model] = {
                "get_model_parameters": {"model_id": response.model_id, "version": response.version, "generated_at_unix": response.generated_at_unix,
                                         "metadata": dict(response.metadata), "message_sha256": message_sha(response),
                                         "parameters": [{"name": p.name, "shape": list(p.shape), "values": len(p.values), "values_sha256_f32le": values_sha(p.values)} for p in response.parameters]},
                "stream": {"chunk_count": len(rows), "total_values": sum(r["value_count"] for r in rows),
                           "stream_sha256": sha256("".join(r["message_sha256"] for r in rows).encode("ascii")), "chunks": rows}}
        stub_health = stub.Health(pb.HealthRequest(), timeout=5)

        def outcome(label, call, request, streaming=False):
            status, payload = (stream_outcome if streaming else grpc_outcome)(call, request)
            record = {"label": label, "rpc": call._method.decode().rsplit("/", 1)[-1], "request_b64": b64(request.SerializeToString(deterministic=True)), "status": status}
            if status != "OK":
                record["details"] = payload
            elif streaming:
                record["response_chunks"] = len(payload)
            else:
                record["response_message_sha256"] = message_sha(payload)
                if hasattr(payload, "manifest_sha256"):
                    record["response"] = {"model_id": payload.model_id, "architecture": payload.architecture, "manifest_sha256": payload.manifest_sha256, "assets": len(payload.assets)}
            return record

        failure = outcome
        mp = lambda model_id, consumer="conformance-consumer": pb.ModelParametersRequest(consumer_id=consumer, model_id=model_id)  # noqa: E731
        negative = [
            failure("legacy-unknown-model", stub.GetModelParameters, mp("does-not-exist")),
            failure("legacy-stream-unknown-model", stub.StreamModelParameters, mp("does-not-exist"), True),
            failure("legacy-traversal", stub.GetModelParameters, mp("../models/privoke-balanced")),
            failure("legacy-slash-in-id", stub.GetModelParameters, mp("a/b")),
            failure("legacy-control-character", stub.GetModelParameters, mp("bad\x00id")),
            failure("legacy-overlong-id", stub.GetModelParameters, mp("m" * 257)),
            failure("legacy-overlong-consumer", stub.GetModelParameters, mp("privoke-balanced", "c" * 257)),
            failure("legacy-control-consumer", stub.GetModelParameters, mp("privoke-balanced", "bad\x01consumer")),
            failure("legacy-v3-model", stub.GetModelParameters, mp("privoke-v3-balanced")),
            failure("legacy-latest-alias-is-v3", stub.GetModelParameters, mp("latest")),
            failure("legacy-empty-model-id", stub.GetModelParameters, mp("")),
            failure("package-unknown-model", stub.GetModelPackage, mp("does-not-exist")),
            failure("package-traversal", stub.GetModelPackage, mp("../privoke-v3-balanced")),
            failure("package-legacy-model-returns-identity-only", stub.GetModelPackage, mp("privoke-balanced")),
            failure("package-latest-alias", stub.GetModelPackage, mp("latest")),
            failure("package-empty-model-id-is-latest", stub.GetModelPackage, mp("")),
            failure("asset-wrong-pin", stub.StreamModelAsset, pb.ModelAssetRequest(consumer_id="c", model_id="privoke-v3-balanced", manifest_sha256="0" * 64, asset_name="config.json"), True),
            failure("asset-missing-pin", stub.StreamModelAsset, pb.ModelAssetRequest(consumer_id="c", model_id="privoke-v3-balanced", asset_name="config.json"), True),
            failure("asset-not-allowlisted", stub.StreamModelAsset, pb.ModelAssetRequest(consumer_id="c", model_id="privoke-v3-balanced", manifest_sha256="99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589", asset_name="../manifest.json"), True),
            failure("asset-legacy-model", stub.StreamModelAsset, pb.ModelAssetRequest(consumer_id="c", model_id="privoke-balanced", manifest_sha256="0" * 64, asset_name="config.json"), True),
        ]

        v3 = {}
        if release_dir is None:
            v3 = {"not_run": "no --release-dir supplied"}
        else:
            for model in V3_MODELS:
                package_dir = release_dir / model
                manifest_bytes = (package_dir / "manifest.json").read_bytes()
                status, package = grpc_outcome(stub.GetModelPackage, mp(model))
                assert status == "OK", (model, status, package)
                assets = {}
                for asset in V3_ASSETS:
                    request = pb.ModelAssetRequest(consumer_id="conformance-consumer", model_id=model, manifest_sha256=package.manifest_sha256, asset_name=asset)
                    chunk_status, chunks = stream_outcome(stub.StreamModelAsset, request)
                    assert chunk_status == "OK", (model, asset, chunk_status, chunks)
                    digest, total = hashlib.sha256(), 0
                    rows = []
                    for chunk in chunks:
                        digest.update(chunk.data)
                        total += len(chunk.data)
                        rows.append({"offset": chunk.offset, "length": len(chunk.data), "data_sha256": sha256(chunk.data), "total_bytes": chunk.total_bytes,
                                     "sha256": chunk.sha256, "model_id": chunk.model_id, "manifest_sha256": chunk.manifest_sha256, "asset_name": chunk.asset_name,
                                     "message_sha256": message_sha(chunk)})
                    assets[asset] = {"bytes": total, "sha256": digest.hexdigest(), "chunk_count": len(rows),
                                     "stream_sha256": sha256("".join(r["message_sha256"] for r in rows).encode("ascii")), "chunks": rows}
                v3[model] = {"manifest_json": manifest_bytes.decode("utf-8"), "manifest_file_sha256": sha256(manifest_bytes),
                             "get_model_package": {"model_id": package.model_id, "architecture": package.architecture, "manifest_sha256": package.manifest_sha256,
                                                   "manifest_matches_file": package.manifest_json == manifest_bytes,
                                                   "assets": [{"name": a.name, "sha256": a.sha256, "size_bytes": a.size_bytes} for a in package.assets],
                                                   "message_sha256": message_sha(package)},
                             "stream_asset": assets}
        channel.close()
        image_id = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()
        write_json(out, "model_streaming.json", {
            "schema": CORPUS_SCHEMA,
            "note": "message_sha256 hashes deterministic re-serialisation of the parsed message (map keys sorted); Go map order is not stable on the wire.",
            "image": image, "image_id": image_id, "latest_model_id": "privoke-v3-balanced", "parameter_chunk_values": 1024, "asset_chunk_bytes": 1024 * 1024,
            "health": {"service": stub_health.service, "status": stub_health.status}, "legacy": legacy, "requests": negative, "v3": v3})
    finally:
        if service is not None:
            service.close()
        shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------------------
# Surface: native_messaging
# --------------------------------------------------------------------------------------

def capture_native_messaging(out: Path) -> None:
    sys.path.insert(0, str(ROOT / "extension/runtime-supervisor/src"))
    import native_messaging_host as host

    def frame(payload: bytes) -> bytes:
        return struct.pack("=I", len(payload)) + payload

    def exchange(label, request_bytes, patches=None):
        patches = patches or {}
        saved = {name: getattr(host, name) for name in patches}
        for name, value in patches.items():
            setattr(host, name, value)
        output = io.BytesIO()
        error = None
        try:
            host.serve(io.BytesIO(request_bytes), output)
        except (ValueError, json.JSONDecodeError, UnicodeError) as exc:
            error = {"type": type(exc).__name__, "message": str(exc)}
            if not str(exc).startswith(("Incomplete", "Native messaging")):
                error["message_is_informational"] = True  # Python decoder wording; Rust need only fail the same inputs
        finally:
            for name, value in saved.items():
                setattr(host, name, value)
        record = {"label": label, "request_hex": request_bytes.hex(), "response_hex": output.getvalue().hex()}
        if error:
            record["error"] = error
        else:
            responses, data, cursor = [], output.getvalue(), 0
            while cursor < len(data):
                length = struct.unpack("=I", data[cursor:cursor + 4])[0]
                responses.append(json.loads(data[cursor + 4:cursor + 4 + length].decode("utf-8")))
                cursor += 4 + length
            record["responses"] = responses
        return record

    j = lambda value: frame(json.dumps(value, separators=(",", ":")).encode("utf-8"))  # noqa: E731
    root = "/privoke-conformance-absent"
    saved_root = os.environ.get("PRIVOKE_REPOSITORY_ROOT")
    os.environ["PRIVOKE_REPOSITORY_ROOT"] = root
    try:
        def missing_path_exchange(label, ports_open):
            record = exchange(label, j({"action": "ensure_supervisor"}), {"_port_is_open": lambda port: port in ports_open})
            for response in record.get("responses", []):
                if "message" in response:
                    response["message"] = response["message"].replace("\\", "/").replace(str(Path(root).resolve()).replace("\\", "/"), "<ROOT>")
            record["response_hex"] = "normalised-see-responses"
            return record

        records = [
            exchange("unsupported-action", j({"action": "other"})),
            exchange("missing-action", j({})),
            exchange("array-message", j([1, 2, 3])),
            exchange("string-message", j("ensure_supervisor")),
            exchange("null-message", j(None)),
            exchange("bridge-already-running", j({"action": "ensure_supervisor"}), {"_port_is_open": lambda port: port == host.BRIDGE_PORT}),
            exchange("control-port-conflict", j({"action": "ensure_supervisor"}), {"_port_is_open": lambda port: port == host.CONTROL_PORT}),
            exchange("two-messages-in-sequence", j({"action": "other"}) + j({"action": "ensure_supervisor"}), {"_port_is_open": lambda port: port == host.BRIDGE_PORT}),
            exchange("unicode-payload", j({"action": "\u00e9\u4e2d\U0001f600"})),
            exchange("empty-stream", b""),
            exchange("truncated-header", b"\x05\x00"),
            exchange("truncated-body", struct.pack("=I", 10) + b"{}"),
            exchange("oversized-length", struct.pack("=I", host.MAX_MESSAGE_BYTES + 1)),
            exchange("invalid-utf8", frame(b"\xff\xfe")),
            exchange("invalid-json", frame(b"{not json")),
            exchange("max-length-boundary-accepted-length-zero-payload-is-invalid-json", frame(b"")),
            missing_path_exchange("supervisor-entry-missing", set()),
        ]
        write_json(out, "native_messaging.json", {
            "schema": CORPUS_SCHEMA, "host_name": host.HOST_NAME, "max_message_bytes": host.MAX_MESSAGE_BYTES,
            "bridge_port": host.BRIDGE_PORT, "control_port": host.CONTROL_PORT, "header_byte_order": "native (x86-64 little-endian captured)",
            "transcripts": records})
    finally:
        if saved_root is None:
            os.environ.pop("PRIVOKE_REPOSITORY_ROOT", None)
        else:
            os.environ["PRIVOKE_REPOSITORY_ROOT"] = saved_root


# --------------------------------------------------------------------------------------
# Surface: grpc_web (real bridge, real control servicer, no browser)
# --------------------------------------------------------------------------------------

def capture_grpc_web(out: Path) -> None:
    from concurrent import futures
    import grpc
    import http.client

    supervisor_root = ROOT / "extension/runtime-supervisor"
    sys.path.insert(0, str(supervisor_root))
    sys.path.insert(0, str(supervisor_root / "generated"))
    from privoke.v1 import runtime_pb2 as pb, runtime_pb2_grpc as rpc
    import src.main as supervisor_main
    from src.grpc_web_bridge import GrpcWebBridge
    from src.runtime_supervisor import RuntimeProcessStatus

    class FixedSupervisor:
        def __init__(self):
            self.enabled = False

        def status(self):
            return RuntimeProcessStatus(self.enabled, "RUNNING" if self.enabled else "STOPPED", "fixed conformance status", 4242 if self.enabled else 0)

        def set_enabled(self, enabled, use_local=None):
            self.enabled = enabled
            return self.status()

    control_port = free_port()
    supervisor = FixedSupervisor()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    rpc.add_PrivokeRuntimeControlServiceServicer_to_server(
        supervisor_main.PrivokeRuntimeControlService(supervisor, lambda: ("model-streaming-service", "SERVING")), server)
    server.add_insecure_port(f"127.0.0.1:{control_port}")
    server.start()
    unused_runtime_port = free_port()
    bridge = GrpcWebBridge(port=0, control_target=f"127.0.0.1:{control_port}", runtime_target=f"127.0.0.1:{unused_runtime_port}")
    bridge.start()

    def data_frame(payload: bytes) -> bytes:
        return b"\x00" + len(payload).to_bytes(4, "big") + payload

    def http_exchange(label, method, path, body=b"", origin=None, extra_headers=None):
        headers = {"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"} if method == "POST" else {}
        if origin is not None:
            headers["Origin"] = origin
        headers.update(extra_headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", bridge.port, timeout=60)
        connection.request(method, path, body=body if method == "POST" else None, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        keep = ("content-type", "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age",
                "access-control-expose-headers", "vary")
        record = {"label": label, "request": {"method": method, "path": path, "origin": origin, "headers": {k: v for k, v in headers.items() if k != "Origin"}, "body_hex": body.hex()},
                  "response": {"status": response.status, "headers": {k: v for k, v in sorted((k.lower(), v) for k, v in response.getheaders()) if k in keep}, "body_hex": payload.hex()}}
        if response.status >= 400:
            record["response"]["body_hex"] = "informational"  # http.server error page text depends on the Python version
            record["response"]["body_sha256_informational"] = sha256(payload)
        connection.close()
        return record

    def unframe(hex_body):
        data, frames, cursor = bytes.fromhex(hex_body), [], 0
        while cursor < len(data):
            length = int.from_bytes(data[cursor + 1:cursor + 5], "big")
            frames.append({"flag": data[cursor], "payload_hex": data[cursor + 5:cursor + 5 + length].hex()})
            cursor += 5 + length
        return frames

    ext = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
    control = "/privoke.v1.PrivokeRuntimeControlService/"
    runtime = "/privoke.v1.PrivokeRuntimeService/"
    try:
        exchanges = [
            http_exchange("preflight-extension-origin", "OPTIONS", control + "Status", origin=ext, extra_headers={"Access-Control-Request-Method": "POST"}),
            http_exchange("preflight-localhost-origin", "OPTIONS", control + "Status", origin="http://localhost"),
            http_exchange("preflight-127-origin", "OPTIONS", control + "Status", origin="http://127.0.0.1"),
            http_exchange("preflight-moz-extension", "OPTIONS", control + "Status", origin="moz-extension://{12345678-1234-1234-1234-123456789abc}"),
            http_exchange("preflight-foreign-origin", "OPTIONS", control + "Status", origin="https://example.com"),
            http_exchange("preflight-no-origin", "OPTIONS", control + "Status"),
            http_exchange("preflight-near-miss-origin", "OPTIONS", control + "Status", origin="http://localhost:8080"),
            http_exchange("status-stopped", "POST", control + "Status", data_frame(pb.RuntimeHealthRequest().SerializeToString()), origin=ext),
            http_exchange("enable-runtime", "POST", control + "SetRuntimeEnabled", data_frame(pb.SetRuntimeEnabledRequest(enabled=True).SerializeToString()), origin=ext),
            http_exchange("status-running", "POST", control + "Status", data_frame(pb.RuntimeHealthRequest().SerializeToString()), origin="http://127.0.0.1"),
            http_exchange("model-streaming-health", "POST", control + "ModelStreamingHealth", data_frame(pb.RuntimeHealthRequest().SerializeToString()), origin=ext),
            http_exchange("disable-runtime", "POST", control + "SetRuntimeEnabled", data_frame(pb.SetRuntimeEnabledRequest(enabled=False).SerializeToString()), origin=ext),
            http_exchange("control-unknown-method-grpc-unimplemented", "POST", control + "Nope", data_frame(b""), origin=ext),
            http_exchange("runtime-service-unreachable", "POST", runtime + "AnalyzeText", data_frame(b""), origin=ext),
            http_exchange("post-foreign-origin", "POST", control + "Status", data_frame(b""), origin="https://example.com"),
            http_exchange("post-no-origin", "POST", control + "Status", data_frame(b"")),
            http_exchange("unknown-path", "POST", "/other.Service/Method", data_frame(b""), origin=ext),
            http_exchange("bad-frame-flag", "POST", control + "Status", b"\x01\x00\x00\x00\x00", origin=ext),
            http_exchange("bad-frame-length", "POST", control + "Status", b"\x00\x00\x00\x00\x09ab", origin=ext),
            http_exchange("short-body", "POST", control + "Status", b"\x00\x00", origin=ext),
        ]
        for exchange in exchanges:
            body = exchange["response"]["body_hex"]
            exchange["response"]["frames"] = unframe(body) if exchange["response"]["status"] == 200 else []
        # The unreachable-runtime message comes from the gRPC core and differs by platform.
        for exchange in exchanges:
            if exchange["label"] == "runtime-service-unreachable":
                exchange["response"]["body_hex"] = "informational"
                exchange["response"]["frames"] = [{"flag": f["flag"], "payload_hex": "informational"} for f in exchange["response"]["frames"]]
        write_json(out, "grpc_web.json", {
            "schema": CORPUS_SCHEMA, "control_timeout_seconds": 35.0, "runtime_timeout_seconds": 30.0,
            "note": "Real GrpcWebBridge in front of the real PrivokeRuntimeControlService with a fixed supervisor. PrivokeRuntimeService needs torch and is exercised only as an unreachable upstream.",
            "exchanges": exchanges})
    finally:
        bridge.stop()
        server.stop(0).wait()


# --------------------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------------------

def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, text=True, stdout=subprocess.PIPE).stdout.strip()


def verify_reference_sources() -> dict:
    commit = git("rev-parse", f"{REFERENCE_TAG}^{{commit}}")
    result = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", commit, "--", *REFERENCE_PATHS])
    if result.returncode:
        raise SystemExit(f"Reference paths differ from {REFERENCE_TAG}; capture would describe a different revision.")
    return {"tag": REFERENCE_TAG, "commit": commit, "paths_identical_to_reference": list(REFERENCE_PATHS)}


def run_surface(name: str, args) -> None:
    out = Path(args.out)
    release_dir = Path(args.release_dir) if args.release_dir else None
    handlers = {"canonical": lambda: capture_canonical(out), "contracts": lambda: capture_contracts(out),
                "update_sequence": lambda: capture_update_sequence(out), "telemetry": lambda: capture_telemetry(out),
                "model_streaming": lambda: capture_model_streaming(out, args.image, release_dir, args.skip_docker),
                "native_messaging": lambda: capture_native_messaging(out), "grpc_web": lambda: capture_grpc_web(out)}
    handlers[name]()


SURFACE_FILES = {"canonical": ("canonical_json.json", "float_repr.json"), "contracts": ("contract_configs.json", "checksums.json", "fingerprints.json"),
                 "update_sequence": ("update_sequence.json",), "telemetry": ("telemetry.json",), "model_streaming": ("model_streaming.json",),
                 "native_messaging": ("native_messaging.json",), "grpc_web": ("grpc_web.json",)}
DEFERRED_GAPS = [
    {"surface": "native_messaging", "gap": "Browser-launched native-messaging transcripts and the started=true launch path",
     "reason": "The supervisor-spawning path starts a long-lived detached process and a browser-brokered native-messaging connection; neither runs on the host without the browser.",
     "covered_instead": "Host framing, rejection and already-running/port-conflict responses, driven through the real host module."},
    {"surface": "grpc_web", "gap": "PrivokeRuntimeService responses through the bridge",
     "reason": "The runtime service needs the torch inference stack; only its unreachable-upstream behaviour is captured. The bridge is byte-transparent to the response payload.",
     "covered_instead": "Control-service RPCs, CORS preflight, origin allowlist and framing errors through the real bridge."},
    {"surface": "update_sequence", "gap": "Concurrent, kill-and-recover and fuzzer-request behaviour",
     "reason": "Those are process and timing behaviours recorded as rows in UPDSEC-20261116, not byte-deterministic corpus entries.",
     "covered_instead": "Fixed sequential sequence with receipts, audit lines and rejection messages."},
    {"surface": "model_streaming", "gap": "Scratch-presence and pretrained-context catalog models",
     "reason": "Their artifacts are not tracked in git (models/experiments is local), so the corpus cannot be rebuilt from the repository.",
     "covered_instead": "The four tracked legacy artifacts and the three pinned V3 releases."},
]


def build_manifest(out: Path, reference: dict) -> None:
    files = {}
    for surface, names in SURFACE_FILES.items():
        for name in names:
            path = out / name
            if not path.is_file():
                raise SystemExit(f"surface {surface} did not write {name}")
            files[name] = {"surface": surface, "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
    import grpc
    import google.protobuf

    streaming = json.loads((out / "model_streaming.json").read_text(encoding="utf-8"))
    manifest = {
        "schema": CORPUS_SCHEMA, "corpus": "rust-rewrite-conformance", "reference": reference, "files": files,
        "capture": {"script": "evaluation/capture_conformance.py", "python": sys.version.split()[0], "grpcio": grpc.__version__, "protobuf": google.protobuf.__version__,
                    "go_service_image": streaming.get("image"), "go_service_image_id": streaming.get("image_id")},
        "determinism": "Two consecutive runs produce identical files (git diff --exit-code tests/conformance).",
        "deferred_gaps": DEFERRED_GAPS,
        "binary_policy": "Binary assets (V3 safetensors, vocab, evidence, config) are stored as SHA-256 and sizes; manifests are small canonical JSON and are stored in full.",
        "large_artifact_policy": "Mutable model artifacts are referenced by repository path and hashed with CRLF folded to LF.",
    }
    write_json(out, "manifest.json", manifest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="corpus directory")
    parser.add_argument("--surface", choices=SURFACES, help="run one surface in this process (used by the orchestrator)")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="model-streaming-service dev image built from the reference revision")
    parser.add_argument("--release-dir", default=None, help="prepared standard V3 releases (models/standard-releases)")
    parser.add_argument("--skip-docker", action="store_true", help="do not host the Go service (the model_streaming file records not_run)")
    parser.add_argument("--no-reference-check", action="store_true", help="skip comparing source paths with the reference tag")
    args = parser.parse_args()
    if args.surface:
        run_surface(args.surface, args)
        return 0
    reference = {"tag": REFERENCE_TAG} if args.no_reference_check else verify_reference_sources()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for surface in SURFACES:
        command = [sys.executable, str(Path(__file__).resolve()), "--surface", surface, "--out", str(out), "--image", args.image]
        if args.release_dir:
            command += ["--release-dir", args.release_dir]
        if args.skip_docker:
            command.append("--skip-docker")
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
        result = subprocess.run(command, env=environment)
        if result.returncode:
            raise SystemExit(f"surface {surface} failed with exit code {result.returncode}")
        print(f"captured {surface}", flush=True)
    build_manifest(out, reference)
    print(f"corpus written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
