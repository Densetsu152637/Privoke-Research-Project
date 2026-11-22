"""Golden output of the Python model fetch, for the Rust fetch of stage 17 (D11, RUST-S17B).

Two Python code paths are run unchanged against an in-process fake model-streaming client (no socket, no network):

* ``LLM/privoke/v3_package.py::fetch_package`` (the standard V3 package fetch) on a synthetic package, with every
  rule of the fetch broken once: the cache directory it writes, the bytes of every file in it, the order of the asset
  requests, the files left behind after a rejection, and the exact error text.
* ``LLM/privoke/parameter_stream.py::ModelParameterStreamer.fetch`` (the legacy float stream) on the four tracked
  legacy models (``models/privoke-*.json``) and on synthetic snapshots that break one rule each.

Findings recorded in the output:

* The legacy path writes **no cache**: the client holds the snapshot in memory only. There are no legacy cache bytes to
  compare. What is recorded instead is what the client ends up holding for each tracked model (tensor names, shapes,
  float32 digests, the parameter fingerprint), which the Rust analysis service's cached snapshot must equal.
* The synthetic V3 package replaces only the *pin set* (a manifest listing ``name=sha256`` lines pinned by its own
  hash) so that each fetch rule can be broken on its own; the real pinned manifests and the manifest contract are
  covered by the stage 2/3 tests and the end-to-end Rust fetch tests on the prepared releases.

Usage (host Python with the client runtime requirements; the protobuf client of ``parameters.proto`` must exist,
see ``evaluation/setup-host.py``, or point ``PRIVOKE_GENERATED`` at a directory generated from ``shared/proto``)::

    python evaluation/generate_model_fetch_golden.py --out rust/services/runtime-supervisor/tests/fixtures/model_fetch_golden.json
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import struct
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "rust" / "services" / "runtime-supervisor" / "tests" / "fixtures" / "model_fetch_golden.json"
TRACKED_MODELS = ("privoke-baseline", "privoke-efficient", "privoke-balanced", "privoke-quality")
MODEL = "test-model"
ASSET_NAMES = ("model.safetensors", "config.json", "vocab.txt", "evidence.json")
CHUNK = 1024 * 1024
PARAMETER_CHUNK_VALUES = 1024


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
# The synthetic V3 package and the fake client
# --------------------------------------------------------------------------------------------------------------


def honest_assets() -> dict[str, bytes]:
    """The same bytes as the Rust test builds: 2.5 MiB of weights so the stream crosses the 1 MiB chunk twice."""
    weights = bytes(index % 251 for index in range(2 * 1024 * 1024 + 512 * 1024))
    return {
        "model.safetensors": weights,
        "config.json": b'{"hidden_size":8}',
        "vocab.txt": b"[PAD]\n[UNK]\nhello\n",
        "evidence.json": b'{"evidence":true}',
    }


def manifest_for(assets: dict[str, bytes]) -> bytes:
    return "\n".join(f"{name}={sha256(assets[name])}" for name in ASSET_NAMES).encode()


class Scenario:
    """One scripted server: an honest one, with the mutation of a case applied."""

    def __init__(self, parameters_pb2, mutation: str):
        self.pb = parameters_pb2
        self.mutation = mutation
        self.assets = honest_assets()
        self.manifest = manifest_for(self.assets)
        self.pin = sha256(self.manifest)
        self.package_calls = 0
        self.asset_calls: list[str] = []
        self.consumers: list[str] = []

    # -- packages ---------------------------------------------------------------------------------------------
    def honest_package(self):
        pb = self.pb
        return pb.ModelPackageResponse(
            model_id=MODEL, architecture=self.architecture(), manifest_sha256=self.pin, manifest_json=self.manifest,
            assets=[pb.ModelPackageAsset(name=name, sha256=sha256(self.assets[name]), size_bytes=len(self.assets[name]))
                    for name in ASSET_NAMES])

    def architecture(self) -> str:
        from privoke_model.v3_contract import ARCHITECTURE
        return ARCHITECTURE

    def package(self, call: int):
        pb, package, mutation = self.pb, self.honest_package(), self.mutation
        if call >= 2:
            if mutation == "manifest_changes_during_download":
                package.model_id = "changed-model"
            return package
        if mutation == "manifest_not_pinned":
            tampered = bytearray(package.manifest_json)
            tampered[0] ^= 1
            package.manifest_json = bytes(tampered)
        elif mutation == "response_pin_differs":
            package.manifest_sha256 = "0" * 64
        elif mutation == "response_model_id_differs":
            package.model_id = "other-model"
        elif mutation == "asset_missing":
            del package.assets[3]
        elif mutation == "asset_extra":
            package.assets.add(name="extra.bin", sha256="0" * 64, size_bytes=1)
        elif mutation == "asset_duplicate":
            package.assets[3].CopyFrom(package.assets[2])
        elif mutation == "asset_sha_differs":
            package.assets[0].sha256 = "0" * 64
        elif mutation == "asset_size_zero":
            package.assets[1].size_bytes = 0
        elif mutation == "asset_size_too_large":
            from privoke_model.v3_contract import MAX_BLOB_BYTES
            package.assets[0].size_bytes = MAX_BLOB_BYTES + 1
        elif mutation in ("legacy_family_latest", "legacy_family_v3_request"):
            package.architecture = "privoke_tiny_transformer_v1"
            package.manifest_json = b""
            del package.assets[:]
        elif mutation == "legacy_family_with_manifest":
            package.architecture = "privoke_tiny_transformer_v1"
        return package

    # -- streams ----------------------------------------------------------------------------------------------
    def stream(self, name: str):
        pb, mutation = self.pb, self.mutation
        data = self.assets[name]
        total, digest = len(data), sha256(data)
        chunks = [pb.ModelAssetChunk(model_id=MODEL, manifest_sha256=self.pin, asset_name=name, sha256=digest,
                                     offset=offset, total_bytes=total, data=data[offset:offset + CHUNK])
                  for offset in range(0, total, CHUNK)]
        if not mutation.startswith("stream_") or name != "model.safetensors":
            return chunks
        if mutation == "stream_flipped_byte":
            flipped = bytearray(chunks[1].data)
            flipped[10] ^= 1
            chunks[1].data = bytes(flipped)
        elif mutation == "stream_truncated":
            chunks = chunks[:-1]
        elif mutation == "stream_offset_gap":
            chunks[1].offset += 1
        elif mutation == "stream_model_id":
            chunks[0].model_id = "other-model"
        elif mutation == "stream_manifest_sha":
            chunks[1].manifest_sha256 = "0" * 64
        elif mutation == "stream_asset_name":
            chunks[0].asset_name = "config.json"
        elif mutation == "stream_sha":
            chunks[1].sha256 = "0" * 64
        elif mutation == "stream_total_bytes":
            chunks[0].total_bytes += 1
        elif mutation == "stream_empty_chunk":
            empty = pb.ModelAssetChunk()
            empty.CopyFrom(chunks[1])
            empty.data = b""
            chunks.insert(1, empty)
        elif mutation == "stream_oversize_chunk":
            merged = pb.ModelAssetChunk()
            merged.CopyFrom(chunks[0])
            merged.data = data[:2 * CHUNK]
            chunks = [merged, *chunks[2:]]
        elif mutation == "stream_extra_data":
            extra = pb.ModelAssetChunk()
            extra.CopyFrom(chunks[-1])
            extra.offset = total
            extra.data = b"x"
            chunks.append(extra)
        return chunks


class FakeClient:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario

    def GetModelPackage(self, request, timeout=None):
        scenario = self.scenario
        scenario.package_calls += 1
        scenario.consumers.append(request.consumer_id)
        return scenario.package(scenario.package_calls)

    def StreamModelAsset(self, request, timeout=None):
        scenario = self.scenario
        scenario.asset_calls.append(request.asset_name)
        return iter(scenario.stream(request.asset_name))


# The cases. ``request`` is the model id the client asks for.
V3_CASES = [
    ("honest", "latest"),
    ("honest_named_request", MODEL),
    ("cached_assets_complete", "latest"),
    ("cached_asset_corrupted", "latest"),
    ("cached_manifest_differs", "latest"),
    ("manifest_not_pinned", "latest"),
    ("response_pin_differs", "latest"),
    ("response_model_id_differs", "latest"),
    ("asset_missing", "latest"),
    ("asset_extra", "latest"),
    ("asset_duplicate", "latest"),
    ("asset_sha_differs", "latest"),
    ("asset_size_zero", "latest"),
    ("asset_size_too_large", "latest"),
    ("stream_flipped_byte", "latest"),
    ("stream_truncated", "latest"),
    ("stream_offset_gap", "latest"),
    ("stream_model_id", "latest"),
    ("stream_manifest_sha", "latest"),
    ("stream_asset_name", "latest"),
    ("stream_sha", "latest"),
    ("stream_total_bytes", "latest"),
    ("stream_empty_chunk", "latest"),
    ("stream_oversize_chunk", "latest"),
    ("stream_extra_data", "latest"),
    ("manifest_changes_during_download", "latest"),
    ("legacy_family_latest", "latest"),
    ("legacy_family_with_manifest", "latest"),
    ("legacy_family_v3_request", "privoke-v3-balanced"),
]


def synthetic_admission(v3_package, standard_v3):
    """The pin set of the synthetic package: ``test-model`` is pinned to the hash of one manifest of ``name=sha`` lines."""

    def admitted_manifest(payload, model_id=None):
        scenario_pin = admitted_manifest.pin
        if hashlib.sha256(payload).hexdigest() != scenario_pin:
            raise ValueError("Model is not a pinned standard AU3 release")
        if model_id and model_id not in ("latest", MODEL):
            raise ValueError("Model package identity differs from request")
        keys = {"model.safetensors": "blob", "config.json": "config", "vocab.txt": "vocab", "evidence.json": "evidence"}
        manifest = {"model_id": MODEL}
        for line in payload.decode().splitlines():
            name, digest = line.split("=")
            manifest[keys[name]] = digest
        return manifest

    admitted_manifest.pin = ""

    def verify_package(directory, model_id=None):
        manifest = admitted_manifest(standard_v3.safe_file(directory, "manifest.json").read_bytes(), model_id)
        for name, key in standard_v3.ASSETS.items():
            path = standard_v3.safe_file(directory, name)
            if not 0 < path.stat().st_size or standard_v3.digest_file(path) != manifest[key]:
                raise ValueError("Model package asset size/hash differs from pinned manifest")
        return manifest

    return admitted_manifest, verify_package


def listing(directory: Path) -> dict:
    """What a loader could see in the package directory, with hidden temporaries normalised."""
    if not directory.is_dir():
        return {"directory_exists": False, "files": {}, "hidden": []}
    files, hidden = {}, []
    for entry in sorted(directory.iterdir()):
        if entry.name.startswith("."):
            hidden.append(entry.name.split("-")[0] + "-*")
        else:
            data = entry.read_bytes()
            files[entry.name] = {"sha256": sha256(data), "size": len(data)}
    return {"directory_exists": True, "files": files, "hidden": sorted(hidden)}


def run_v3_case(modules, mutation: str, requested: str) -> dict:
    pb, v3_package, standard_v3 = modules.pb, modules.v3_package, modules.standard_v3
    scenario = Scenario(pb, mutation)
    admit, verify = synthetic_admission(v3_package, standard_v3)
    admit.pin = scenario.pin
    outcome: dict = {"name": mutation, "request_model_id": requested}
    with tempfile.TemporaryDirectory() as cache:
        os.environ["MODEL_PACKAGE_CACHE_DIR"] = cache
        directory = Path(cache) / MODEL / scenario.pin
        saved = (v3_package.admitted_manifest, v3_package.verify_package, v3_package.STANDARD_PINS)
        v3_package.admitted_manifest, v3_package.verify_package = admit, verify
        v3_package.STANDARD_PINS = {MODEL: scenario.pin}
        v3_package._PACKAGES.clear()
        try:
            if mutation in ("cached_assets_complete", "cached_asset_corrupted", "cached_manifest_differs"):
                directory.mkdir(parents=True)
                for name in ASSET_NAMES:
                    (directory / name).write_bytes(scenario.assets[name])
                if mutation == "cached_assets_complete":
                    (directory / "manifest.json").write_bytes(scenario.manifest)
                elif mutation == "cached_manifest_differs":
                    (directory / "manifest.json").write_bytes(scenario.manifest + b"\n")
                else:
                    (directory / "vocab.txt").write_bytes(b"corrupted")
            client = FakeClient(scenario)
            request = pb.ModelParametersRequest(consumer_id="installation-1", model_id=requested)
            try:
                package = v3_package.fetch_package(client, request, target="fake:0", timeout=1.0)
                outcome["outcome"] = "none" if package is None else "package"
                if package is not None:
                    outcome["package"] = {"model_id": package.model_id, "pin": package.version}
                    first_assets = list(scenario.asset_calls)
                    outcome["asset_calls"], outcome["package_calls"] = first_assets, scenario.package_calls
                    again = v3_package.fetch_package(client, request, target="fake:0", timeout=1.0)
                    outcome["second_fetch_same_package"] = again is package
                    outcome["second_fetch_asset_calls"] = scenario.asset_calls[len(first_assets):]
            except ValueError as error:
                outcome["outcome"] = "error"
                outcome["error"] = str(error)
            outcome.update(listing(directory))
        finally:
            v3_package.admitted_manifest, v3_package.verify_package, v3_package.STANDARD_PINS = saved
    if outcome.get("outcome") != "package":
        outcome["asset_calls"], outcome["package_calls"] = list(scenario.asset_calls), scenario.package_calls
    outcome["consumers"] = sorted(set(scenario.consumers))
    return outcome


# --------------------------------------------------------------------------------------------------------------
# The legacy float stream
# --------------------------------------------------------------------------------------------------------------


def f32(value: float) -> float:
    return struct.unpack("!f", struct.pack("!f", value))[0]


def f32_digest(values) -> str:
    return sha256(struct.pack(f"<{len(values)}f", *values))


def number(value):
    """JSON cannot hold NaN or infinity: they travel as strings in a case description."""
    if isinstance(value, str):
        return float(value)
    return value


def snapshot_chunks(pb, spec: dict) -> list:
    """The chunk stream model-streaming sends for a snapshot spec (metadata on the first chunk only)."""
    tensors = spec["tensors"]
    totals = [max(1, math.ceil(len(t["values"]) / PARAMETER_CHUNK_VALUES)) for t in tensors]
    total_chunks = sum(totals)
    chunks = []
    for tensor, count in zip(tensors, totals):
        values = [number(v) for v in tensor["values"]]
        for index in range(count):
            offset = index * PARAMETER_CHUNK_VALUES
            chunk = pb.ModelParameterChunk(
                model_id=spec["model_id"], version=spec["version"], generated_at_unix=spec["generated_at_unix"],
                chunk_index=len(chunks), total_chunks=total_chunks,
                parameter=pb.ParameterChunk(name=tensor["name"], shape=tensor["shape"], value_offset=offset,
                                            values=values[offset:offset + PARAMETER_CHUNK_VALUES]))
            if not chunks:
                chunk.metadata.update(spec["metadata"])
            chunks.append(chunk)
    return chunks


class FakeStreamClient:
    def __init__(self, chunks):
        self.chunks = chunks

    def StreamModelParameters(self, request, timeout=None):
        return iter(self.chunks)


@contextlib.contextmanager
def fake_channel(*_args, **_kwargs):
    yield object()


def python_stream_fetch(modules, requested: str, chunks) -> dict:
    parameter_stream = modules.parameter_stream
    saved = (parameter_stream.grpc_channel, parameter_stream.parameters_pb2_grpc)
    parameter_stream.grpc_channel = fake_channel
    parameter_stream.parameters_pb2_grpc = SimpleNamespace(ModelStreamingServiceStub=lambda _channel: FakeStreamClient(chunks))
    try:
        streamer = parameter_stream.ModelParameterStreamer(target="fake:0", model_id=requested, consumer_id="installation-1",
                                                           timeout_seconds=1.0)
        snapshot = streamer.fetch()
        return {"accepted": True, "snapshot": snapshot}
    except (RuntimeError, ValueError) as error:
        return {"accepted": False, "error": str(error)}
    finally:
        parameter_stream.grpc_channel, parameter_stream.parameters_pb2_grpc = saved


def snapshot_record(snapshot) -> dict:
    return {
        "model_id": snapshot.model_id, "version": snapshot.version, "generated_at_unix": snapshot.generated_at_unix,
        "parameter_count": snapshot.parameter_count, "fingerprint": snapshot.fingerprint,
        "artifact_checksum": snapshot.metadata.get("artifact_checksum", ""),
        "tensors": [{"name": name, "shape": list(snapshot.shapes[name]), "count": len(snapshot.parameters[name]),
                     "f32_sha256": f32_digest(snapshot.parameters[name])} for name in sorted(snapshot.parameters)],
    }


def tracked_spec(model_id: str) -> dict:
    from privoke_model.artifact import load_artifact
    payload = load_artifact(REPO / "models" / f"{model_id}.json")
    tensors = [{"name": name, "shape": list(payload["parameters"][name]["shape"]),
                "values": [f32(float(v)) for v in payload["parameters"][name]["values"]]}
               for name in sorted(payload["parameters"])]
    return {"model_id": payload["model_id"], "version": payload["version"], "generated_at_unix": payload["generated_at_unix"],
            "metadata": {"artifact_checksum": payload["checksum"], "architecture": payload["architecture"]}, "tensors": tensors}


def synthetic_legacy_spec() -> dict:
    return {"model_id": "privoke-test", "version": "v1", "generated_at_unix": 5, "metadata": {"artifact_checksum": "ab" * 32},
            "tensors": [{"name": "a", "shape": [2, 2], "values": [1.0, 2.0, 3.0, 4.0]},
                        {"name": "b", "shape": [1], "values": [0.5]}]}


def legacy_cases(modules) -> list[dict]:
    """Snapshot rules, each broken once. ``unary`` cases can be expressed as one ModelParametersResponse (the Rust
    analysis service fetches that way); the others are properties of the chunk stream and have no unary form."""
    base = synthetic_legacy_spec

    def edit(change):
        spec = base()
        change(spec)
        return spec

    unary = {
        "legacy_honest": base(),
        "shape_mismatch": edit(lambda s: s["tensors"][0].update(shape=[3, 2])),
        "non_finite_nan": edit(lambda s: s["tensors"][1].update(values=["nan"])),
        "non_finite_inf": edit(lambda s: s["tensors"][0]["values"].__setitem__(2, "inf")),
        "non_finite_negative_inf": edit(lambda s: s["tensors"][0]["values"].__setitem__(0, "-inf")),
        "unnamed_tensor": edit(lambda s: s["tensors"][0].update(name="")),
        "zero_dimension": edit(lambda s: s["tensors"][0].update(shape=[0, 4])),
        "empty_shape": edit(lambda s: s["tensors"][1].update(shape=[])),
        "no_version": edit(lambda s: s.update(version="")),
        "no_timestamp": edit(lambda s: s.update(generated_at_unix=0)),
    }
    cases = []
    for name, spec in unary.items():
        outcome = python_stream_fetch(modules, spec["model_id"], snapshot_chunks(modules.pb, spec))
        record = {"name": name, "kind": "unary", "spec": spec, "accepted": outcome["accepted"]}
        if not outcome["accepted"]:
            record["error"] = outcome["error"]
        cases.append(record)
    # Stream-only properties (no unary form): recorded with the Python answer, not replayed by the Rust test.
    honest = base()
    chunks = snapshot_chunks(modules.pb, honest)
    other = snapshot_chunks(modules.pb, honest)

    def stream_case(name, chunk_list, requested=None):
        outcome = python_stream_fetch(modules, requested or honest["model_id"], chunk_list)
        record = {"name": name, "kind": "stream_only", "accepted": outcome["accepted"]}
        if not outcome["accepted"]:
            record["error"] = outcome["error"]
        cases.append(record)

    swapped = list(other)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    stream_case("out_of_order", swapped)
    gap = snapshot_chunks(modules.pb, honest)
    gap[0].parameter.value_offset = 1
    stream_case("discontinuous_offset", gap)
    changed = snapshot_chunks(modules.pb, honest)
    changed[1].version = "v2"
    stream_case("snapshot_changes_mid_stream", changed)
    stream_case("truncated_stream", chunks[:-1])
    stream_case("model_id_differs", snapshot_chunks(modules.pb, honest), requested="privoke-other")
    return cases


def run(out: Path) -> None:
    bootstrap()
    import privoke_model.standard_v3 as standard_v3
    from privoke.v1 import parameters_pb2
    from privoke_model.v3_contract import ARCHITECTURE, MAX_BLOB_BYTES
    from src.LLM.privoke import parameter_stream, v3_package
    modules = SimpleNamespace(pb=parameters_pb2, standard_v3=standard_v3, v3_package=v3_package, parameter_stream=parameter_stream)

    v3_cases = []
    for mutation, requested in V3_CASES:
        v3_cases.append(run_v3_case(modules, mutation, requested))

    tracked = []
    for model_id in TRACKED_MODELS:
        spec = tracked_spec(model_id)
        outcome = python_stream_fetch(modules, model_id, snapshot_chunks(parameters_pb2, spec))
        if not outcome["accepted"]:
            raise SystemExit(f"{model_id}: the Python fetch refused a tracked model: {outcome['error']}")
        tracked.append(snapshot_record(outcome["snapshot"]))

    document = {
        "schema": "privoke-model-fetch-golden-1",
        "source": "extension/client-runtime/src/LLM/privoke/v3_package.py and parameter_stream.py, unchanged, against an in-process fake client",
        "v3": {
            "model": MODEL, "architecture": ARCHITECTURE, "max_blob_bytes": MAX_BLOB_BYTES, "chunk_bytes": CHUNK,
            "asset_order": list(ASSET_NAMES),
            "cases": v3_cases,
        },
        "legacy": {
            "python_disk_cache": "none: the client keeps the streamed snapshot in memory only",
            "parameter_chunk_values": PARAMETER_CHUNK_VALUES,
            "tracked": tracked,
            "cases": legacy_cases(modules),
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} ({len(v3_cases)} V3 cases, {len(tracked)} tracked models, {len(document['legacy']['cases'])} legacy cases)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    run(parser.parse_args().out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
