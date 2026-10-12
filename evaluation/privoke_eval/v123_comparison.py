"""Existing-checkpoint package comparison; all orchestration and scoring run on host.

No fitting, promotion, protected inputs, or old-study catalog mutation is exposed.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from . import pretrained_v3_scoring as scoring
from .pretrained_v3_study import ROOT, canonical, channel, digest, exclusive, runtime_pb2, runtime_pb2_grpc
from privoke_contracts.classification import Classification
from privoke_model.artifact import load_artifact, float32
from privoke_model.fingerprint import parameter_fingerprint

RUN = "v123_comparison_20261013"
IMAGE = "sha256:4a5624eda0c0cd7dfb3da2366e3d18e720eda4a82797bf4e92320fa0987e9bd1"
RESULTS = ROOT / "evaluation/results" / RUN
PROTOCOL_PATH = RESULTS / "protocol/protocol-02.json"
PREFLIGHT_PATH = RESULTS / "preflight-02"
PRIOR_PROTOCOL_SHA256 = "a2c859489cfa5e7f7e26cb4922b1e5597d8254374e24fdd407483c7ae4e458fc"
MODELS = ROOT / "models/experiments" / RUN
COMPOSE = ROOT / "evaluation/compose.v123-comparison.yml"
PROJECT = "privoke-v123-comparison"
PORT = 50271
THREAD_ENV = {name: "1" for name in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS")}
EXTRA_GENERATED = ("extension/client-runtime/generated/privoke/v1/telemetry_pb2.py", "extension/client-runtime/generated/privoke/v1/telemetry_pb2_grpc.py")
TINY_HASHES = {
    "v1-efficient": "c8992bda8a75f5ee7165a3debabaef1a229c4f661be2f5792de65c0aefcf9a5b",
    "v1-balanced": "dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51",
    "v1-quality": "c3126ae0ae238d3967226b6c616491fb90e9b766a3fbb6e066203cb92f2ed8c8",
    "v2-original": "1fca4eff13ac6892395c07b13158761612e7a95cfa6659ba712fcf6e70392ffc",
    "v2-legacy-42": "be458591fb0c88f210d39473e1b05bc2b30a3772faba8070e2bf60670932489d",
    "v2-legacy-43": "82b58666058076d27d8717f04562063c82ff4575ce5300f763fcbee22eb9a332",
    "v2-legacy-44": "46ea31e66b178bd56d34a46123eda188ccbb12243a495b973b16d9a572693266",
    "v2-window-42": "863408658a5a83d3258bebb044106604cd608bcead88f4c52edd0ac2dd088fd6",
    "v2-window-43": "f1b4af6d4f917c2311fddf22a2b594d7622c4d94a419f6529856b6228f5cc418",
    "v2-window-44": "17f8bd81641843878925ed919f36a332bed4a584fb64c5a37e4ff1084e256bf4",
}
V3_PINS = {
    "efficient": ("7584892ff85ff6530a7199dc17e3da904c308f5f425238e7af17423a495d26d6", "3e60f251144c975dbf947d06bc25e0e35ae56006fae3c8d08af1f6add444bc0b"),
    "balanced": ("4fbc23e20cf222d08703bbbb714fb5e24d054343f880d671e3fc90ed85f085d0", "bb1627fa5cdde65dc4d313e0525f1ee4d2f59c697fe0d1a9bdbd56e57f91de1f"),
    "quality": ("89a86c1d031f6cdf7a94afb5adeb2ad36e5fef0449d66a58f36a6f4ca9a0d62d", "812f24d35c99f2f6b77e692d3dfd2cb7f95bc3cbab8ad8df401bfca6dace1a1d"),
    "quality-original": ("57af677fadb69013a749ff1dce2159cb3191de8c386705dbba278e38231532ac", "c86f710946090e31cb9b15d2e2fc476fb23ac74286cbae59e4d5aa286c90210e"),
}


def read(path):
    return json.loads(Path(path).read_bytes())


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def retain(path, data):
    path = Path(path)
    payload = data if isinstance(data, bytes) else canonical(data)
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError("Immutable comparison evidence differs: " + str(path))
    else:
        exclusive(path, payload)


def tiny_parameters(artifact):
    return ({name: tuple(float32(v) for v in tensor["values"]) for name, tensor in artifact["parameters"].items()},
            {name: tuple(tensor["shape"]) for name, tensor in artifact["parameters"].items()})


def tiny_entry(name, path, expected):
    if file_hash(path) != expected:
        raise ValueError("Artifact bytes differ: " + name)
    artifact = load_artifact(path)
    parameters, shapes = tiny_parameters(artifact)
    count = sum(map(len, parameters.values()))
    metadata = artifact["metadata"]
    revision = int(metadata.get("training_revision", "0"))
    return {"name": name, "family": name[:2], "server_family": "tiny", "tier": name.split("-")[1] if name.startswith("v1-") else "balanced",
            "source": str(path.relative_to(ROOT)).replace("\\", "/"), "file_sha256": expected,
            "identity": {"model_id": artifact["model_id"], "model_version": artifact["version"], "artifact_checksum": artifact["checksum"], "parameter_fingerprint": parameter_fingerprint(parameters, shapes)},
            "architecture": artifact["architecture"], "config": artifact["config"], "metadata": metadata,
            "parameter_count": count, "raw_float32_bytes": count * 4, "serialized_deploy_asset_bytes": path.stat().st_size,
            "revision": revision, "zero_parameter_values": sum(v == 0 for values in parameters.values() for v in values), "update_status": "original" if name.endswith("original") or name.startswith("v1-") else "updated" if revision else "no_update",
            "guard_rows_configured": 16 if "window" in name else None,
            "native_window": {"cap": artifact["config"]["max_tokens"], "special_tokens": 1, "tokenizer": "native_regex_hash", "reject_overlength": metadata.get("contextual_training_strategy") == "contextual_full_encoder_sgd_v1"}}


def registry():
    entries = []
    for name, expected in TINY_HASHES.items():
        if name.startswith("v1-"):
            path = ROOT / "models" / ("privoke-" + name[3:] + ".json")
        elif name == "v2-original":
            path = ROOT / "models/experiments/task_query_window_20261012/initials/v2/original.json"
        else:
            path = ROOT / "models/experiments/task_query_window_20261012/cells" / name / "effective-artifact.json"
        entries.append(tiny_entry(name, path, expected))
    for tier, (blob, manifest_sha) in V3_PINS.items():
        base = ROOT / "models/experiments/pretrained_v3_20261012"
        path = base / ("initials/quality" if tier.endswith("original") else "final-models/" + tier)
        manifest = read(path / "manifest.json")
        pins = {filename: file_hash(path / filename) for filename in ("manifest.json", "model.safetensors", "config.json", "vocab.txt")}
        if pins["manifest.json"] != manifest_sha or pins["model.safetensors"] != blob or pins["config.json"] != manifest["config"] or pins["vocab.txt"] != manifest["vocab"]:
            raise ValueError("V3 pinned assets differ: " + tier)
        identity = {"model_id": manifest["model_id"], "model_version": manifest_sha, "artifact_checksum": manifest_sha,
                    "parameter_fingerprint": blob, "parameter_count": str(manifest["parameter_count"]), "backbone_sha256": manifest["source"]["weights_sha256"], "tokenizer_sha256": manifest["vocab"], "architecture": manifest["architecture"]}
        entries.append({"name": "v3-" + tier, "family": "v3", "server_family": "v3", "tier": tier.split("-")[0],
                        "source": path.relative_to(ROOT).as_posix(), "assets": pins, "identity": identity, "manifest": manifest,
                        "config": read(path / "config.json"), "parameter_count": manifest["parameter_count"], "raw_float32_bytes": manifest["parameter_count"] * 4,
                        "serialized_deploy_asset_bytes": sum((path / f).stat().st_size for f in pins),
                        "update_status": "original_control" if tier.endswith("original") else "raw_guard_rejected" if tier == "quality" else "applied_guard_passed",
                        "native_window": {"cap": 512, "special_tokens": 2, "tokenizer": "BertTokenizerFast", "reject_overlength": True}})
    return entries


def native_length(entry, text, tokenizer=None):
    # Length auditing normalizes locally; requests always retain original wire text.
    from src.detection.preprocessing import normalize_with_offsets
    normalized = normalize_with_offsets(text).text
    if entry["server_family"] == "tiny":
        from src.transformer_encoder import TOKEN_PATTERN
        return len(TOKEN_PATTERN.findall(normalized)) + 1
    return len(tokenizer(normalized, truncation=False, add_special_tokens=True)["input_ids"])


def workload(entries):
    from transformers import BertTokenizerFast
    v3 = next(e for e in entries if e["server_family"] == "v3")
    tokenizer = BertTokenizerFast(vocab_file=str(ROOT / v3["source"] / "vocab.txt"), do_lower_case=True)
    cases, windows = [], {entry["name"]: {"over_cap": [], "truncated": [], "rejected": []} for entry in entries}
    for kind, spec in scoring.ENDPOINTS.items():
        eligible_length = []
        for index, row in enumerate(scoring.endpoint_rows(kind, spec)):
            lengths = {entry["name"]: native_length(entry, row["text"], tokenizer) for entry in entries}
            case = {"endpoint": kind, "index": index, "id": scoring.truth_record(row, kind)["id"], "lengths": lengths}
            cases.append(case)
            for entry in entries:
                if lengths[entry["name"]] > entry["native_window"]["cap"]:
                    target = windows[entry["name"]]
                    target["over_cap"].append(case["id"])
                    target["rejected" if entry["native_window"]["reject_overlength"] else "truncated"].append(case["id"])
            if all(lengths[e["name"]] <= e["native_window"]["cap"] for e in entries):
                eligible_length.append(case)
        ordered = sorted(eligible_length, key=lambda c: (max(c["lengths"].values()), str(c["id"])))
        if len(ordered) < 8:
            raise ValueError("Insufficient common-fit inputs: " + kind)
        # Eight equal-rank length strata per endpoint; midpoint selection uses inputs only.
        for stratum in range(8):
            selected = dict(ordered[((2 * stratum + 1) * len(ordered)) // 16], stratum=stratum)
            if "selected" not in windows:
                windows["selected"] = []
            windows["selected"].append(selected)
    prompts = windows.pop("selected")
    return {"selection": "8 midpoint rank strata per endpoint among native-length intersection; input-only", "prompts": prompts,
            "windows": windows, "all_case_lengths": cases, "pass_order": [[(i + p * 7) % 32 for i in range(32)] for p in range(11)]}


def source_files():
    from .pretrained_v3_plan import source_closure
    old = source_closure()
    if digest(canonical(old)) != "899b9ae53f0917fc36a1a6e79a63060e09ebd419d1e9ca27675952b89e67acec":
        raise ValueError("Closed v3 source closure changed")
    names = ["evaluation/privoke_eval/v123_comparison.py", "evaluation/run-v123-comparison.py", "evaluation/v123-comparison-server.py", "evaluation/compose.v123-comparison.yml", "evaluation/tests/test_v123_comparison.py"]
    return {**old, **{name: file_hash(ROOT / name) for name in names}}


def prepare():
    """Freeze before any quality RPC; repeated preparation must be byte-identical."""
    entries = registry()
    if file_hash(RESULTS / "protocol/protocol.json") != PRIOR_PROTOCOL_SHA256:
        raise ValueError("Retained first protocol changed")
    frozen = {"schema": 1, "study_id": RUN, "image_id": IMAGE, "source_files": source_files(), "registry": entries,
              "supersedes_protocol_sha256": PRIOR_PROTOCOL_SHA256,
              "configuration_revision": "02: two unchanged generated telemetry modules mounted readonly; first preflight failed import before any RPC; same model/fixture/metric/performance policy",
              "extra_generated_mounts": {name: file_hash(ROOT / name) for name in EXTRA_GENERATED},
              "method_review_sha256": file_hash(RESULTS / "method-review/method-review.json"),
              "endpoints": scoring.ENDPOINTS, "requested_per_model": 934, "eligible_per_model": 927,
              "total_requested": 13076, "total_eligible": 12978, "missing_tiers": ["v2-efficient", "v2-quality"],
              "workload": workload(entries), "performance": {"replicates": 3, "warmup_passes": 1, "measured_passes": 10, "batch": 1, "concurrency": 1, "threads": THREAD_ENV, "tiny_ttl_seconds": 604800, "device": "cpu", "readiness_timeout_seconds": 180,
              "latency": "host perf_counter_ns around complete RPC; server elapsed secondary; errors separate", "cold": "startup/readiness includes immutable snapshot preload; first RPC separate and already loaded", "memory": "PID1 Linux VmRSS/VmHWM kB*1024; loaded baseline after ready; lifetime peak through measured phase before accuracy", "accuracy": "934 original-field requests in replicate1 after cost capture"},
              "interpretation": "Native serving package comparison; differing hint postprocessing and NumPy/Torch backends prohibit causal architecture ranking; DEVELOPMENT only; no promotion/fit.",
              "host": {"python": sys.version, "executable": sys.executable, "platform": platform.platform(), "processor": platform.processor(), "cpu_count": os.cpu_count()}}
    retain(PROTOCOL_PATH, frozen)
    return frozen


def validate_protocol():
    plan = read(PROTOCOL_PATH)
    if plan["source_files"] != source_files() or plan["registry"] != registry() or plan["endpoints"] != scoring.ENDPOINTS or plan["image_id"] != IMAGE:
        raise ValueError("Frozen comparison input/source identity differs")
    if plan["method_review_sha256"] != "ee9b9cbf09b6ba8675e5a6ca22decd7463cc3d788ec123dd5c369e922d3f823b":
        raise ValueError("Accepted method review differs")
    if plan["extra_generated_mounts"] != {name: file_hash(ROOT / name) for name in EXTRA_GENERATED} or file_hash(RESULTS / "protocol/protocol.json") != plan["supersedes_protocol_sha256"]:
        raise ValueError("Comparison configuration lineage/mounted generated bytes differ")
    return plan


def private_assets(entry):
    """Copy immutable deployment assets; never open an old catalog writable."""
    target = MODELS / entry["name"]
    target.mkdir(parents=True, exist_ok=True)
    source = ROOT / entry["source"]
    if entry["server_family"] == "tiny":
        retain(target / "artifact.json", source.read_bytes())
    else:
        for filename, expected in entry["assets"].items():
            if file_hash(source / filename) != expected:
                raise ValueError("Source asset changed")
            retain(target / filename, (source / filename).read_bytes())
        original = ROOT / "models/experiments/pretrained_v3_20261012/cells" / (entry["tier"] + "-full_encoder-42/checkpoint")
        catalog = target / "checkpoint"
        if not (catalog / "catalog.sqlite").exists():
            catalog.mkdir(exist_ok=True)
            with sqlite3.connect(original.joinpath("catalog.sqlite").as_uri() + "?mode=ro", uri=True) as old:
                with sqlite3.connect(catalog / "catalog.sqlite") as new:
                    old.backup(new)
            shutil.copytree(original / "blobs", catalog / "blobs")
            retain(target / "catalog-copy.json", {"source": original.relative_to(ROOT).as_posix(), "source_catalog_sha256": file_hash(original / "catalog.sqlite"), "private_catalog_sha256": file_hash(catalog / "catalog.sqlite"), "blobs": {p.name: file_hash(p) for p in sorted((original / "blobs").iterdir())}})
        sha = entry["identity"]["artifact_checksum"]
        if file_hash(catalog / "blobs" / sha) != sha:
            raise ValueError("Pinned snapshot absent from private catalog")
    return target


def request_for(entry, row, request_id):
    return runtime_pb2.AnalyzePromptRequest(request_id=request_id, text=row["text"], source=row.get("source") or "", target_app=row.get("target_app") or "",
        visibility_hint=row.get("visibility_hint") or "", semantic_model_id=entry["identity"]["model_id"], layers=[4],
        metadata={**(row.get("metadata") or {}), **({"purpose": str(row["purpose"])} if row.get("purpose") is not None else {}), **({"v3_checkpoint": entry["identity"]["artifact_checksum"]} if entry["server_family"] == "v3" else {})})


def response_record(response, entry, request):
    if response.request_id != request.request_id:
        raise ValueError("Response request identity differs")
    layers = list(response.layers)
    if layers and [layer.layer for layer in layers] != [4]:
        raise ValueError("Actual semantic isolation violated")
    failed = bool(response.error) or bool(layers and (layers[0].status != "ok" or layers[0].error))
    if not failed and (len(layers) != 1 or layers[0].status != "ok"):
        raise ValueError("Successful response lacks sole semantic execution")
    expected = {"privoke.semantic." + key: str(value) for key, value in entry["identity"].items()}
    actual = dict(response.metadata)
    if any(actual.get(key) != value for key, value in expected.items() if not failed or key in actual):
        raise ValueError("Native model identity differs")
    if failed:
        return {"status": "error", "failure_stage": "runtime" if layers else "pre_execution", "error": response.error or layers[0].error, "classification": None, "action": None, "actual_layers": [layer.layer for layer in layers], "metadata": actual}
    classification = Classification(response.classification.packed).to_dict()
    named = {"sensitivity": response.classification.sensitivity, "visibility": response.classification.visibility, "categories": list(response.classification.categories)}
    if named != classification:
        raise ValueError("Packed/named classification differs")
    if response.action not in ("ALLOW", "WARN", "BLOCK"):
        raise ValueError("Unknown native action")
    return {"status": "ok", "classification": classification, "action": response.action, "elapsed_ms": response.elapsed_ms, "actual_layers": [4], "metadata": actual}


def invoke(stub, entry, row, output, request_id):
    output = Path(output)
    request = request_for(entry, row, request_id)
    payload = request.SerializeToString(deterministic=True)
    if (output / "record.json").exists():
        if (output / "request.pb").read_bytes() != payload:
            raise ValueError("Retained request differs")
        return audit_call(entry, row, output, request_id)
    if (output / "request.pb").exists():
        raise ValueError("Unknown reserved RPC outcome; no blind replay: " + str(output))
    exclusive(output / "request.pb", payload)
    started = time.perf_counter_ns()
    try:
        response = stub.AnalyzePrompt(request, timeout=120)
    except Exception as error:
        ended = time.perf_counter_ns()
        retain(output / "error.json", {"type": type(error).__name__, "error": str(error)})
        result = {"status": "transport_error", "failure_stage": "transport", "error": str(error), "classification": None, "action": None}
    else:
        ended = time.perf_counter_ns()
        retain(output / "response.pb", response.SerializeToString(deterministic=True))
        result = response_record(response, entry, request)
    retain(output / "timing.json", {"started_perf_counter_ns": started, "ended_perf_counter_ns": ended})
    result.update(host_elapsed_ns=ended-started, request_sha256=digest(payload), requested_identity=entry["identity"])
    retain(output / "record.json", result)
    return result


def audit_call(entry, row, output, request_id):
    """Reconcile one retained original request, raw outcome and monotonic timing."""
    output = Path(output)
    payload = request_for(entry, row, request_id).SerializeToString(deterministic=True)
    if (output / "request.pb").read_bytes() != payload:
        raise ValueError("Retained request differs")
    request = runtime_pb2.AnalyzePromptRequest.FromString(payload)
    files = {p.name for p in output.iterdir() if p.is_file()}
    common = {"request.pb", "timing.json", "record.json"}
    if files == common | {"response.pb"}:
        result = response_record(runtime_pb2.AnalyzePromptResponse.FromString((output / "response.pb").read_bytes()), entry, request)
    elif files == common | {"error.json"}:
        error = read(output / "error.json")
        result = {"status": "transport_error", "failure_stage": "transport", "error": error["error"], "classification": None, "action": None}
    else:
        raise ValueError("Missing or extraneous retained case artifacts")
    timing = read(output / "timing.json")
    duration = timing["ended_perf_counter_ns"] - timing["started_perf_counter_ns"]
    if duration < 0:
        raise ValueError("Negative retained monotonic duration")
    result.update(host_elapsed_ns=duration, request_sha256=digest(payload), requested_identity=entry["identity"])
    if read(output / "record.json") != result:
        raise ValueError("Retained case record differs from raw outcome/timing")
    return result


def endpoint_summary(records, kind):
    result = scoring.summarize_records(records, kind)
    result["all_requested_errors"] = sum(r["status"] != "ok" for r in records)
    result["failure_stages"] = {stage: sum(r.get("failure_stage") == stage for r in records) for stage in ("transport", "pre_execution", "runtime")}
    return result


def performance_summary(records):
    successful = sorted(r["host_elapsed_ns"] for r in records if r["status"] == "ok")
    total = sum(r["host_elapsed_ns"] for r in records)
    def quantile(q):
        if not successful:
            return None
        position = (len(successful) - 1) * q
        low = int(position)
        return (successful[low] + (successful[min(low + 1, len(successful)-1)] - successful[low]) * (position-low)) / 1e6
    return {"requested": len(records), "successful": len(successful), "failed": len(records)-len(successful), "p50_ms_successful": quantile(.5), "p95_ms_successful": quantile(.95), "rpc_active_successful_requests_per_second": len(successful)/(total/1e9) if total else None, "throughput_scope": "RPC-active proxy excludes ledger I/O and loop overhead", "total_request_ns": total,
            "failed_host_elapsed_ns": [r["host_elapsed_ns"] for r in records if r["status"] != "ok"]}


def performance_ranges(costs):
    successful = [cost for cost in costs if cost["successful"]]
    return {"successful_replicates": len(successful), "status": "measured" if successful else "no_successful_timed_calls",
            **{key + "_range": [min(c[key] for c in successful), max(c[key] for c in successful)] if successful else [None, None] for key in ("p50_ms_successful", "p95_ms_successful")}}


def proc_memory(text):
    values = {}
    for name in ("VmRSS", "VmHWM"):
        match = re.search(r"^" + name + r":\s+(\d+) kB$", text, re.MULTILINE)
        if not match:
            raise ValueError("Missing Linux process memory metric: " + name)
        values[name + "_bytes"] = int(match[1]) * 1024
    return values


def compose(state, assets, *args):
    env = dict(os.environ, V123_STATE=str(Path(state).resolve()), V123_ASSETS=str(Path(assets).resolve()), V123_HELPER=str(ROOT / "evaluation/v123-comparison-server.py"), V123_TELEMETRY=str(ROOT / "extension/client-runtime/generated/privoke/v1"))
    result = subprocess.run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args], cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Compose " + " ".join(args) + ": " + result.stderr)
    return result.stdout


def memory_observation(state, assets, output, phase):
    cmdline = compose(state, assets, "exec", "-T", "runtime", "cat", "/proc/1/cmdline")
    if "v123-comparison-server.py" not in cmdline:
        raise ValueError("PID1 is not the comparison runtime")
    raw = compose(state, assets, "exec", "-T", "runtime", "cat", "/proc/1/status")
    retain(output / (phase + "-proc-status.txt"), raw.encode())
    value = dict(proc_memory(raw), pid1_cmdline=cmdline, phase=phase, scope="Linux runtime PID1 lifetime RSS, kB times 1024", observed_unix_ns=time.time_ns())
    retain(output / (phase + "-memory.json"), value)
    return value


def launch(entry, output):
    assets = private_assets(entry)
    state = output / "state"
    state.mkdir(parents=True, exist_ok=False)
    retain(state / "entry.json", entry)
    retain(state / "server-inputs.json", {name: file_hash(ROOT / name) for name in EXTRA_GENERATED})
    retain(output / "resolved-compose.json", compose(state, assets, "config", "--format", "json").encode())
    started = time.perf_counter_ns()
    services = ("checkpoint", "runtime") if entry["server_family"] == "v3" else ("runtime",)
    compose(state, assets, "up", "-d", "--no-build", "--pull", "never", "--force-recreate", *services)
    deadline = time.monotonic() + 180
    before = memory_observation(state, assets, output, "before-ready")
    while time.monotonic() < deadline:
        if (state / "ready.json").exists():
            ready = read(state / "ready.json")
            if ready["identity"] != entry["identity"] or ready["device"] != "cpu" or ready["thread_env"] != THREAD_ENV or ready["threads"] != 1:
                raise ValueError("Runtime device/thread/identity attestation differs")
            if ready["helper_sha256"] != file_hash(ROOT / "evaluation/v123-comparison-server.py") or ready["mounted_modules"] != read(state / "server-inputs.json") or ready["source_closure"] != "126878ce5ebf0896a91b9f878abe444e76453b44aadcc284c4a3e61e42aec95a":
                raise ValueError("Actual copied/mounted runtime source identity differs")
            if not ready["threadpools"] or any(pool["num_threads"] != 1 for pool in ready["threadpools"]):
                raise ValueError("Actual numerical thread pools unavailable or not single threaded")
            ids = compose(state, assets, "ps", "-q", "runtime").strip()
            inspected = subprocess.run(["docker", "inspect", ids], capture_output=True, text=True, check=True).stdout
            info = json.loads(inspected)[0]
            if info["Image"] != IMAGE:
                raise ValueError("Actual server image differs")
            retain(output / "runtime-inspect.json", inspected.encode())
            baseline = memory_observation(state, assets, output, "loaded-baseline")
            retain(output / "startup.json", {"ready_elapsed_ns": time.perf_counter_ns()-started, "attestation": ready, "before": before, "loaded_baseline": baseline})
            return state, assets
        time.sleep(1)
    raise TimeoutError("Comparison runtime readiness exceeded 180 seconds")


def execute_entry(entry, plan, *, smoke=False):
    """Fresh isolated processes per replicate; performance peak ends before accuracy."""
    base = (PREFLIGHT_PATH if smoke else RESULTS / "benchmark") / entry["name"]
    for replicate in range(1 if smoke else 3):
        output = base / ("replicate-%d" % (replicate + 1))
        if output.exists():
            if (output / "complete.json").exists():
                continue
            raise ValueError("Retained incomplete attempt; no implicit lifecycle retry: " + str(output))
        output.mkdir(parents=True)
        assets = private_assets(entry)
        state = output / "state"
        try:
            state, assets = launch(entry, output)
            with channel("127.0.0.1:" + str(PORT)) as conn:
                stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(conn)
                first = invoke(stub, entry, {"text": "Synthetic startup probe."}, output / "cold", entry["name"] + "-cold-" + str(replicate))
                if first["status"] != "ok":
                    raise ValueError("Smoke/cold RPC failed")
                memory_observation(state, assets, output, "after-cold")
                if not smoke:
                    timed = []
                    for pass_index, order in enumerate(plan["workload"]["pass_order"]):
                        for position, prompt_index in enumerate(order):
                            ref = plan["workload"]["prompts"][prompt_index]
                            row = scoring.endpoint_rows(ref["endpoint"], plan["endpoints"][ref["endpoint"]])[ref["index"]]
                            value = invoke(stub, entry, row, output / "timing" / ("%02d-%02d" % (pass_index, position)), "%s-%d-%d-%d" % (entry["name"], replicate, pass_index, position))
                            if pass_index:
                                timed.append(value)
                        if pass_index == 0:
                            memory_observation(state, assets, output, "after-warm")
                    peak = memory_observation(state, assets, output, "after-measured")
                    baseline = read(output / "loaded-baseline-memory.json")
                    retain(output / "performance.json", dict(performance_summary(timed), memory=peak, lifetime_peak_minus_loaded_baseline_rss_bytes=peak["VmHWM_bytes"]-baseline["VmRSS_bytes"], memory_delta_scope="Includes startup high water; not isolated inference allocation"))
                    if replicate == 0:
                        for kind, spec in plan["endpoints"].items():
                            records = []
                            for index, row in enumerate(scoring.endpoint_rows(kind, spec)):
                                value = invoke(stub, entry, row, output / "accuracy" / kind / ("%04d" % index), "%s-%s-%d" % (entry["name"], kind, index))
                                records.append(dict(scoring.truth_record(row, kind), **value))
                            retain(output / "accuracy" / kind / "summary.json", endpoint_summary(records, kind))
                        memory_observation(state, assets, output, "after-accuracy")
                retain(output / "complete.json", {"entry": entry["name"], "replicate": replicate + 1, "smoke": smoke, "protocol_sha256": file_hash(PROTOCOL_PATH)})
        finally:
            if state.exists():
                for args, name in [(("logs", "--no-color", "--tail", "100", "runtime", "checkpoint"), "logs.txt"), (("stop", "runtime", "checkpoint"), "stop.txt"), (("ps", "--all", "--format", "json"), "stopped.json")]:
                    retain(output / name, compose(state, assets, *args).encode())


def analyze():
    """Rebuild endpoint metrics and paired comparisons from retained case ledgers."""
    plan = validate_protocol()
    results, records = {}, {}
    for entry in plan["registry"]:
        name = entry["name"]
        base = RESULTS / "benchmark" / name
        costs = []
        for replicate in range(1, 4):
            output = base / ("replicate-%d" % replicate)
            complete = read(output / "complete.json")
            if complete != {"entry": name, "replicate": replicate, "smoke": False, "protocol_sha256": file_hash(PROTOCOL_PATH)}:
                raise ValueError("Replicate completion identity differs")
            timing = []
            for p, order in enumerate(plan["workload"]["pass_order"]):
                for i, prompt_index in enumerate(order):
                    ref = plan["workload"]["prompts"][prompt_index]
                    row = scoring.endpoint_rows(ref["endpoint"], plan["endpoints"][ref["endpoint"]])[ref["index"]]
                    value = audit_call(entry, row, output / "timing" / ("%02d-%02d" % (p, i)), "%s-%d-%d-%d" % (name, replicate-1, p, i))
                    if p:
                        timing.append(value)
            summary = performance_summary(timing)
            stored = read(output / "performance.json")
            if any(stored[key] != value for key, value in summary.items()):
                raise ValueError("Performance summary differs")
            baseline = proc_memory((output / "loaded-baseline-proc-status.txt").read_text())
            peak = proc_memory((output / "after-measured-proc-status.txt").read_text())
            for phase, parsed in (("loaded-baseline", baseline), ("after-measured", peak)):
                retained = read(output / (phase + "-memory.json"))
                if any(retained[k] != v for k, v in parsed.items()) or "v123-comparison-server.py" not in retained["pid1_cmdline"]:
                    raise ValueError("Memory observation differs from raw process status")
            if any(stored["memory"][k] != v for k, v in peak.items()) or stored["lifetime_peak_minus_loaded_baseline_rss_bytes"] != peak["VmHWM_bytes"]-baseline["VmRSS_bytes"]:
                raise ValueError("Cost memory summary differs")
            costs.append(stored)
        results[name] = dict(performance_ranges(costs), cost_replicates=costs, endpoints={})
        records[name] = {}
        for kind, spec in plan["endpoints"].items():
            values = []
            for index, row in enumerate(scoring.endpoint_rows(kind, spec)):
                directory = base / "replicate-1/accuracy" / kind / ("%04d" % index)
                value = audit_call(entry, row, directory, "%s-%s-%d" % (name, kind, index))
                values.append(dict(scoring.truth_record(row, kind), **value))
            records[name][kind] = values
            results[name]["endpoints"][kind] = endpoint_summary(values, kind)
    pairs = {}
    from itertools import combinations
    for left, right in combinations(plan["registry"], 2):
        # Available-tier comparisons, plus the quality ORIGINAL/raw control pair.
        if left["tier"] == right["tier"]:
            pairs[left["name"] + "__" + right["name"]] = {kind: scoring.paired_difference(records[left["name"]][kind], records[right["name"]][kind], kind) for kind in plan["endpoints"]}
    inventory = {p.relative_to(RESULTS).as_posix(): file_hash(p) for p in sorted((RESULTS / "benchmark").rglob("*")) if p.is_file() and "state" not in p.relative_to(RESULTS / "benchmark").parts}
    result = {"protocol_sha256": file_hash(PROTOCOL_PATH), "results": results, "paired": pairs, "evidence_inventory": inventory}
    retain(RESULTS / "analysis.json", result)
    return result


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "smoke", "run", "analyze"))
    parser.add_argument("--model", choices=list(TINY_HASHES) + ["v3-" + tier for tier in V3_PINS])
    args = parser.parse_args(argv)
    if args.command == "prepare":
        plan = prepare()
        print(json.dumps({"protocol_sha256": file_hash(PROTOCOL_PATH), "models": len(plan["registry"]), "requested": plan["total_requested"]}))
        return
    plan = validate_protocol()
    if args.command == "analyze":
        analyze()
        return
    if args.command == "smoke":
        selected = [e for e in plan["registry"] if e["name"] in ("v1-balanced", "v2-original", "v3-efficient")]
    else:
        if not args.model:
            parser.error("run requires explicit --model after root benchmark acceptance")
        selected = [e for e in plan["registry"] if e["name"] == args.model]
    for entry in selected:
        execute_entry(entry, plan, smoke=args.command == "smoke")
        print(entry["name"] + " complete", flush=True)
