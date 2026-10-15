"""PIPE3 host product-cascade comparison; no fitting or checkpoint selection."""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

STUDY_ID = "pipeline_v1_v3_20261014"
TIERS = ("efficient", "balanced", "quality")
NAMES = tuple(family + "-" + tier for family in ("v3", "v1") for tier in TIERS)
LAYERS = [2, 3, 4]
REPEATS = 3
ROWS = 1560
DATA_SHA = "41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0"
FRESH_SHA = "e965c21a0d43babc0984f46eb70785c8d66d878e00e647eefb9565f219b2da0c"
AU3_REGISTRY_SHA = "cb0529d59261d9bcc0d8450a0f6739f66ffeabde0fd1ad20bbae1cd0bef67a37"
V3_PINS = dict(zip(TIERS, (
    "1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd",
    "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589",
    "bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39")))
TINY_PINS = dict(zip(TIERS, (
    "c8992bda8a75f5ee7165a3debabaef1a229c4f661be2f5792de65c0aefcf9a5b",
    "dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51",
    "c3126ae0ae238d3967226b6c616491fb90e9b766a3fbb6e066203cb92f2ed8c8")))
OWN_SOURCES = ("evaluation/privoke_eval/pipeline_v1_v3.py",
               "evaluation/privoke_eval/pipeline_v1_v3_serving.py",
               "evaluation/run-pipeline-v1-v3.py", "evaluation/pipeline-v1-v3-server.py",
               "evaluation/tests/test_pipeline_v1_v3.py")
THREAD_KEYS = ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS")
PRODUCT_ENV = {**{key: "4" for key in THREAD_KEYS}, "PRIVOKE_WAIT_FOR_REGEX": "true",
               "PRIVOKE_REGEX_PRESIDIO": "true", "PRIVOKE_REGEX_GITLEAKS": "true",
               "MODEL_STREAMING_CACHE_TTL_SECONDS": "604800", "LLM_CHOICE": "streamed",
               "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "PRIVOKE_MODEL_DEVICE": "cpu"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def retain(path, value):
    path = Path(path)
    payload = value if isinstance(value, bytes) else canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        require(path.read_bytes() == payload, "Immutable evidence differs: " + str(path))
    else:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())


def configure(root):
    root = Path(root).resolve()
    for relative in ("shared/python", "extension/client-runtime/generated", "extension/client-runtime",
                     "services/privoke-fuzzer/src", "services/pretrained-v3/src"):
        value = str(root / relative)
        if value not in sys.path:
            sys.path.insert(0, value)
    return root


def source_files(root):
    root = Path(root)
    names = set(OWN_SOURCES)
    for relative in ("extension/client-runtime/src", "extension/client-runtime/generated", "shared/python", "shared/proto",
                     "services/pretrained-v3/src", "services/privoke-fuzzer/src/prompt_generation"):
        names.update(p.relative_to(root).as_posix() for p in (root / relative).rglob("*")
                     if p.is_file() and p.suffix in (".py", ".proto", ".toml", ".json") and "__pycache__" not in p.parts)
    names.update("evaluation/privoke_eval/" + name for name in (
        "audience_v3.py", "audience_v3_data.py", "audience_v3_comparison.py", "privacy_heads_v3.py",
        "privacy_heads_v3_comparison.py", "privacy_encoder_v3.py", "privacy_encoder_v3_comparison.py"))
    return {name: file_hash(root / name) for name in sorted(names)}


def environment():
    import torch
    packages = {name: importlib.metadata.version(name) for name in (
        "torch", "numpy", "transformers", "tokenizers", "safetensors", "grpcio", "protobuf",
        "spacy", "en-core-web-sm", "presidio-analyzer", "regex", "python-dotenv")}
    spec = importlib.util.find_spec("en_core_web_sm")
    require(spec is not None and spec.origin, "Real en_core_web_sm package missing")
    model_root = Path(spec.origin).parent
    ner_files = {p.relative_to(model_root).as_posix(): file_hash(p) for p in sorted(model_root.rglob("*"))
                 if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    return {"python": sys.version, "executable": str(Path(sys.executable).resolve()), "platform": platform.platform(),
            "packages": packages, "ner_assets": ner_files, "ner_assets_sha256": digest(canonical(ner_files)),
            "cpu_count": os.cpu_count(), "processor": platform.processor(), "torch_threads": torch.get_num_threads(),
            "deterministic": torch.are_deterministic_algorithms_enabled(), "device": "cpu",
            "product_env": {key: os.getenv(key) for key in PRODUCT_ENV}}


def configure_numeric():
    import torch
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    require(all(os.getenv(k) == v for k, v in PRODUCT_ENV.items()), "Product environment must be pinned before imports")


def resource_snapshot():
    value = {"pid": os.getpid(), "process_cpu_seconds": time.process_time(), "monotonic_ns": time.perf_counter_ns()}
    try:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            class Counters(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage",
                    "PeakPagefileUsage", "PrivateUsage")]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            memory_info = ctypes.WinDLL("psapi").GetProcessMemoryInfo
            memory_info.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
            memory_info.restype = wintypes.BOOL
            require(memory_info(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb), "GetProcessMemoryInfo failed")
            value.update(rss_bytes=counters.WorkingSetSize, peak_rss_bytes=counters.PeakWorkingSetSize,
                         private_bytes=counters.PrivateUsage, resource_mechanism="Windows PROCESS_MEMORY_COUNTERS_EX")
        else:
            import resource
            value.update(peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                         resource_mechanism="getrusage; Linux peak RSS")
    except Exception as error:
        value["memory_unavailable"] = type(error).__name__ + ": " + str(error)
    return value


def model_identity(manifest, sha):
    return {"model_id": manifest["model_id"], "model_version": sha, "artifact_checksum": sha,
            "parameter_fingerprint": manifest["blob"], "parameter_count": str(manifest["parameter_count"]),
            "backbone_sha256": manifest["source"]["weights_sha256"], "tokenizer_sha256": manifest["vocab"],
            "architecture": manifest["architecture"]}


def rules_inventory(detector):
    return [{"name": rule.name, "pattern": rule.pattern.pattern, "flags": int(rule.pattern.flags),
             "signal": rule.signal, "packed": rule.classification.pack()} for rule in detector.rules]


def validate_assets(entry):
    directory = Path(entry["directory"])
    require(all(file_hash(directory / name) == sha for name, sha in entry["assets"].items()), "Private model assets changed")
    require(all(file_hash(Path(entry["source"]) / name) == sha for name, sha in entry["assets"].items()), "Original model assets changed")
    if entry["family"] == "v3":
        from privoke_model.v3_contract import validate_manifest
        manifest = validate_manifest(read(directory / "manifest.json"))
        require(model_identity(manifest, entry["assets"]["manifest.json"]) == entry["identity"], "V3 identity changed")


def native_lengths(entries, rows):
    from src.detection.preprocessing import normalize_with_offsets
    from src.transformer_encoder import TOKEN_PATTERN
    from transformers import BertTokenizerFast
    first = entries[0]
    tokenizer = BertTokenizerFast(vocab_file=str(Path(first["directory"]) / "vocab.txt"), do_lower_case=True)
    result = {}
    for row in rows:
        normalized = normalize_with_offsets(row["text"]).text
        tiny = len(TOKEN_PATTERN.findall(normalized)) + 1
        bert = len(tokenizer(normalized, add_special_tokens=True, truncation=False)["input_ids"])
        result[row["id"]] = {"tiny": tiny, "v3": bert}
    return result


def prepare(root, results, models):
    root, results, models = configure(root), Path(results).resolve(), Path(models).resolve()
    configure_numeric()
    from privoke_model.artifact import load_artifact, float32
    from privoke_model.fingerprint import parameter_fingerprint
    from . import audience_v3_data as data
    manifest_path = root / "evaluation/results/audience_v3_20261013/data/release-07/manifest.json"
    registry_path = root / "evaluation/results/audience_v3_20261013/runs/cpu-02/comparison/registry.json"
    environment_proof = root / "evaluation/results" / STUDY_ID / "environment/environment-provenance.json"
    require(environment_proof.is_file(), "Accepted isolated environment provenance required")
    require(file_hash(manifest_path) == DATA_SHA and file_hash(registry_path) == AU3_REGISTRY_SHA, "AU3 source seals differ")
    manifest = read(manifest_path)
    require(manifest["files"]["fresh_eval"]["sha256"] == FRESH_SHA, "FRESH pin differs")
    rows = data.load_partition(manifest_path, "fresh_eval", evaluation_authorized=True)
    require(len(rows) == ROWS and len({r["id"] for r in rows}) == ROWS and all(not r.get("visibility_hint") for r in rows), "Benchmark rows/hints differ")
    entries = []
    for old in read(registry_path)["entries"]:
        if old["phase"] != "after":
            continue
        tier = old["tier"]
        require(old["manifest_sha256"] == V3_PINS[tier], "Not selected AU3 checkpoint")
        source = Path(old["directory"])
        native = read(source / "manifest.json")
        assets = {"manifest.json": V3_PINS[tier], "model.safetensors": native["blob"], "config.json": native["config"],
                  "vocab.txt": native["vocab"], "evidence.json": native["evidence"]}
        entries.append({"name": "v3-" + tier, "tier": tier, "family": "v3", "source": str(source),
                        "directory": str(models / ("v3-" + tier)), "assets": assets, "identity": model_identity(native, V3_PINS[tier]),
                        "parameter_count": native["parameter_count"], "native_cap": 512,
                        "epochs": {"encoder": dict(zip(TIERS, (30, 20, 8)))[tier], "pooler": dict(zip(TIERS, (30, 20, 8)))[tier],
                                   "heads": dict(zip(TIERS, (42, 27, 12)))[tier], "upstream_pretraining": None,
                                   "au3_completed": dict(zip(TIERS, (16, 11, 9)))[tier], "au3_selected": dict(zip(TIERS, (11, 6, 4)))[tier]}})
    for tier in TIERS:
        source = root / "models" / ("privoke-" + tier + ".json")
        require(file_hash(source) == TINY_PINS[tier], "V1 source changed")
        artifact = load_artifact(source)
        parameters = {k: tuple(float32(v) for v in t["values"]) for k, t in artifact["parameters"].items()}
        shapes = {k: tuple(t["shape"]) for k, t in artifact["parameters"].items()}
        entries.append({"name": "v1-" + tier, "tier": tier, "family": "v1", "source": str(source.parent),
                        "directory": str(models / ("v1-" + tier)), "assets": {source.name: TINY_PINS[tier]},
                        "identity": {"model_id": artifact["model_id"], "model_version": artifact["version"],
                                     "artifact_checksum": artifact["checksum"], "parameter_fingerprint": parameter_fingerprint(parameters, shapes)},
                        "parameter_count": sum(map(len, parameters.values())), "native_cap": artifact["config"]["max_tokens"],
                        "config": artifact["config"], "epochs": {"encoder": 0, "pooler": None,
                        "heads": int(artifact["metadata"]["training_epochs"]), "upstream_pretraining": None,
                        "encoder_origin": "deterministic_bootstrap_untrained"}})
    entries.sort(key=lambda e: NAMES.index(e["name"]))
    require(tuple(e["name"] for e in entries) == NAMES, "Six model order differs")
    for entry in entries:
        for name, sha in entry["assets"].items():
            payload = (Path(entry["source"]) / name).read_bytes()
            require(digest(payload) == sha, "Source asset differs")
            retain(Path(entry["directory"]) / name, payload)
        validate_assets(entry)
    sources = source_files(root)
    from src.regex.rule_detector import RuleDetector
    effective_rules = rules_inventory(RuleDetector())
    protocol = {"schema": 1, "study_id": STUDY_ID, "repository": str(root), "models": str(models),
                "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
                "source_files": sources, "source_closure": digest(canonical(sources)), "environment": environment(),
                "environment_provenance": {"path": str(environment_proof), "sha256": file_hash(environment_proof)},
                "entries": entries, "data_manifest": str(manifest_path), "data_manifest_sha256": DATA_SHA,
                "fresh_eval_sha256": FRESH_SHA, "au3_registry_sha256": AU3_REGISTRY_SHA,
                "layers": LAYERS, "regex_execution_order": 1, "repeats": REPEATS, "rows": ROWS,
                "model_order": list(NAMES), "accuracy_requests": len(NAMES) * ROWS * REPEATS,
                "native_lengths": native_lengths(entries, rows), "warmup_train_indices": [0, 1, 2, 3],
                "effective_regex_rules": effective_rules, "effective_regex_rules_sha256": digest(canonical(effective_rules)),
                "meaning": "reused_assistant_provisional_AU3_FRESH_product_package_comparison_normal_cascade",
                "timing": "V3 first then V1; one loaded server/model, three passes; warmups separate; descriptive CPU package cost",
                "repeat_policy": "first-pass accuracy primary; repeated identical cases measure agreement and timing, not independence"}
    retain(results / "protocol.json", protocol)
    return protocol


def validate(results):
    protocol = read(Path(results) / "protocol.json")
    root = configure(protocol["repository"])
    require(protocol["study_id"] == STUDY_ID and protocol["schema"] == 1 and protocol["layers"] == LAYERS
            and protocol["regex_execution_order"] == 1 and protocol["repeats"] == REPEATS and protocol["rows"] == ROWS
            and protocol["model_order"] == list(NAMES) and [e["name"] for e in protocol["entries"]] == list(NAMES), "Protocol shape drift")
    require(source_files(root) == protocol["source_files"] and digest(canonical(protocol["source_files"])) == protocol["source_closure"], "Working source closure drift")
    require(file_hash(protocol["data_manifest"]) == DATA_SHA == protocol["data_manifest_sha256"], "Data manifest drift")
    require(file_hash(protocol["environment_provenance"]["path"]) == protocol["environment_provenance"]["sha256"], "Environment provenance drift")
    for entry in protocol["entries"]:
        validate_assets(entry)
    return protocol


def rows_for(protocol, role="fresh_eval"):
    from .audience_v3_data import load_partition
    return load_partition(protocol["data_manifest"], role, evaluation_authorized=role == "fresh_eval")


def request_for(entry, row, request_id):
    from privoke.v1 import runtime_pb2
    return runtime_pb2.AnalyzePromptRequest(request_id=request_id, text=row["text"], source=row.get("source") or "",
        target_app=row.get("target_app") or "", layers=LAYERS, regex_execution_order=1,
        semantic_model_id=entry["identity"]["model_id"], metadata={"pipeline_study": STUDY_ID, "pipeline_model": entry["name"]})


def request_id(protocol_sha, name, repeat, row_id, warmup=False):
    return "pipe3-" + digest(canonical([protocol_sha, name, repeat, row_id, warmup]))[:40]


def classification(value):
    from privoke_contracts.classification import Classification
    named = {"sensitivity": value.sensitivity, "visibility": value.visibility, "categories": list(value.categories)}
    require(Classification(value.packed).to_dict() == named, "Named and packed classification differ")
    return named


def detection(result, text):
    value = {"classification": classification(result.classification), "action": result.action,
             "section_of_text": result.section_of_text, "span": [result.span_start, result.span_end] if result.has_span else None,
             "confidence": result.confidence if result.has_confidence else None, "reasoning": result.reasoning, "metadata": dict(result.metadata)}
    require(result.action in ("ALLOW", "WARN", "BLOCK"), "Invalid finding action")
    require(not result.has_confidence or math.isfinite(result.confidence) and 0 <= result.confidence <= 1, "Invalid confidence")
    if result.has_span:
        require(0 <= result.span_start < result.span_end <= len(text)
                and text[result.span_start:result.span_end] == result.section_of_text, "Invalid remapped finding span")
    return value


def response_outcome(payload, entry, request):
    """Invalid received wires remain terminal errors; early skips are not executions."""
    from privoke.v1 import runtime_pb2
    actual, metadata, traces = [], {}, []
    try:
        response = runtime_pb2.AnalyzePromptResponse.FromString(payload)
        actual, metadata = [x.layer for x in response.layers], dict(response.metadata)
        require(response.request_id == request.request_id and actual == LAYERS, "Missing/duplicate/different layers or request identity")
        traces = [{"layer": x.layer, "status": x.status, "error": x.error,
                   "findings": [detection(r, request.text) for r in x.results]} for x in response.layers]
        require(all(t["status"] in ("ok", "skipped", "error") for t in traces), "Unknown layer status")
        semantic = traces[2]
        if semantic["status"] == "ok":
            keys = ("model_id", "model_version", "artifact_checksum", "parameter_fingerprint")
            require(all(metadata.get("privoke.semantic." + k) == entry["identity"][k] for k in keys), "Executed semantic identity differs")
        skipped = any(t["status"] == "skipped" for t in traces)
        if skipped:
            require([t["status"] for t in traces] == ["ok", "skipped", "skipped"]
                    and any(r["action"] == "BLOCK" for r in traces[0]["findings"])
                    and all(t["error"] == "Skipped after regex returned BLOCK." and not t["findings"] for t in traces[1:]),
                    "Invalid cascade skip")
            require(not any(k.startswith("privoke.semantic.") for k in metadata), "Skipped semantic must not impersonate execution")
        require(all(t["status"] != "ok" or not t["error"] for t in traces), "Successful layer carries error")
        if response.error or any(t["status"] == "error" for t in traces):
            return {"status": "runtime_error", "error": response.error or "Layer error", "actual_layers": actual,
                    "traces": traces, "metadata": metadata, "classification": None, "action": None,
                    "returned_action": response.action, "server_elapsed_ms": response.elapsed_ms}
        require(skipped or all(t["status"] == "ok" for t in traces), "Incomplete product execution")
        require(response.action in ("ALLOW", "WARN", "BLOCK") and response.allowed == (response.action != "BLOCK"), "Action/allowed mismatch")
        evidence = detection(response.evidence, request.text) if response.HasField("evidence") else None
        expected_mask = ""
        if response.action == "WARN" and evidence and evidence["span"]:
            start, end = evidence["span"]
            expected_mask = request.text[:start] + "[PRIVOKE_MASKED]" + request.text[end:]
        require(response.masked_text == expected_mask, "Native warning mask/span differs")
        require(math.isfinite(response.elapsed_ms) and response.elapsed_ms >= 0, "Invalid server elapsed time")
        origins = [] if not evidence else [t["layer"] for t in traces if any(
            r["span"] == evidence["span"] and r["section_of_text"] == evidence["section_of_text"] for r in t["findings"])]
        return {"status": "ok", "actual_layers": actual, "classification": classification(response.classification),
                "action": response.action, "metadata": metadata, "traces": traces, "evidence": evidence,
                "evidence_span_origins": origins, "masked_text": response.masked_text, "server_elapsed_ms": response.elapsed_ms}
    except Exception as error:
        return {"status": "invalid_response", "error": type(error).__name__ + ": " + str(error), "actual_layers": actual,
                "metadata": metadata, "traces": traces, "classification": None, "action": None}


class Journal:
    """Hash-chained append-only request reservations and terminal raw outcomes."""
    def __init__(self, path):
        self.path = Path(path)
        self.events, self.calls, self.previous = [], {}, "0" * 64
        if self.path.exists():
            payload = self.path.read_bytes()
            require(not payload or payload.endswith(b"\n"), "Partial journal; reconcile without replay")
            for line in payload.splitlines():
                event = json.loads(line)
                claimed = event.pop("sha256")
                require(event["sequence"] == len(self.events) and event["previous"] == self.previous
                        and digest(canonical(event)) == claimed, "Journal chain/sequence/hash differs")
                self._apply(event)
                self.events.append(dict(event, sha256=claimed))
                self.previous = claimed
        require(all("terminal" in call for call in self.calls.values()), "Unknown reserved RPC outcome; reconcile without replay")

    def _apply(self, event):
        key = event["request_id"]
        require(event["kind"] in ("reserve", "terminal"), "Unknown journal event")
        if event["kind"] == "reserve":
            require(key not in self.calls and all("terminal" in c for c in self.calls.values()), "Duplicate or unresolved reservation")
            request = base64.b64decode(event["request_pb"], validate=True)
            require(digest(request) == event["request_sha256"], "Reserved request bytes differ")
            self.calls[key] = {"reserve": event}
        else:
            require(key in self.calls and "terminal" not in self.calls[key], "Terminal without unique reservation")
            require(type(event["started_ns"]) is int and type(event["ended_ns"]) is int
                    and 0 <= event["started_ns"] <= event["ended_ns"], "Invalid monotonic timing")
            require(("response_pb" in event) != ("transport_error" in event), "Conflicting/missing terminal wire")
            if "response_pb" in event:
                require(digest(base64.b64decode(event["response_pb"], validate=True)) == event["response_sha256"], "Terminal response bytes differ")
            self.calls[key]["terminal"] = event

    def append(self, kind, request_id, **fields):
        event = dict(fields, kind=kind, request_id=request_id, sequence=len(self.events), previous=self.previous)
        # Validate before writing; publication occurs only after durable append.
        self._apply(event)
        event["sha256"] = digest(canonical(event))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as handle:
            handle.write(canonical(event))
            handle.flush()
            os.fsync(handle.fileno())
        self.events.append(event)
        self.previous = event["sha256"]


def record_for(call, entry, row, expected_request):
    payload = base64.b64decode(call["reserve"]["request_pb"], validate=True)
    require(payload == expected_request.SerializeToString(deterministic=True), "Journal stimulus differs from fixed protocol")
    terminal = call["terminal"]
    if "response_pb" in terminal:
        outcome = response_outcome(base64.b64decode(terminal["response_pb"], validate=True), entry, expected_request)
    else:
        outcome = {"status": "transport_error", "error": terminal["transport_error"], "classification": None,
                   "action": None, "actual_layers": [], "traces": [], "metadata": {}}
    return dict(outcome, id=row["id"], family_id=row["family_id"], group_id=row["group_id"],
                target=row["classification"], allowed_actions=row["allowed_actions"], host_elapsed_ns=terminal["ended_ns"] - terminal["started_ns"])


def invoke(stub, journal, entry, row, key, *, repeat, index, warmup=False):
    request = request_for(entry, row, key)
    if key not in journal.calls:
        payload = request.SerializeToString(deterministic=True)
        journal.append("reserve", key, request_pb=base64.b64encode(payload).decode(), request_sha256=digest(payload),
                       model=entry["name"], repeat=repeat, index=index, case_id=row["id"], warmup=warmup)
        started = time.perf_counter_ns()
        try:
            response = stub.AnalyzePrompt(request, timeout=120)
            ended = time.perf_counter_ns()
            wire = response.SerializeToString(deterministic=True)
        except Exception as error:
            ended = time.perf_counter_ns()
            journal.append("terminal", key, started_ns=started, ended_ns=ended,
                           transport_error=type(error).__name__ + ": " + str(error))
        else:
            journal.append("terminal", key, started_ns=started, ended_ns=ended,
                           response_pb=base64.b64encode(wire).decode(), response_sha256=digest(wire))
    require("terminal" in journal.calls[key], "Unknown dispatched outcome; reconcile without replay")
    return record_for(journal.calls[key], entry, row, request)


def distribution(values):
    values = sorted(values)
    return {"n": len(values), "min": values[0] if values else None, "max": values[-1] if values else None,
            "median": statistics.median(values) if values else None,
            **{"p" + str(p): values[max(0, math.ceil(p / 100 * len(values)) - 1)] if values else None for p in (90, 95, 99)},
            "total": sum(values)}


def summarize(records):
    from .audience_v3_comparison import summarize as contextual_summary
    result = contextual_summary(records)
    statuses, findings, errors = Counter(), Counter(), Counter()
    for record in records:
        for layer in record["traces"]:
            statuses[str(layer["layer"]) + ":" + layer["status"]] += 1
            findings[str(layer["layer"])] += len(layer["findings"])
            if layer["status"] == "error":
                errors[str(layer["layer"]) + ":" + layer["error"]] += 1
    result.update(status_counts=dict(Counter(r["status"] for r in records)), layer_status_counts=dict(statuses),
                  layer_finding_counts=dict(findings), layer_errors=dict(errors),
                  semantic_executed=sum(any(t["layer"] == 4 and t["status"] == "ok" for t in r["traces"]) for r in records),
                  regex_early_block=sum(any(t["status"] == "skipped" for t in r["traces"]) for r in records),
                  warning_masks=sum(bool(r.get("masked_text")) for r in records),
                  evidence_span_origins=dict(Counter(str(layer) for r in records for layer in r.get("evidence_span_origins", []))),
                  host_rpc_ms=distribution([r["host_elapsed_ns"] / 1e6 for r in records]),
                  server_elapsed_ms=distribution([r["server_elapsed_ms"] for r in records if "server_elapsed_ms" in r]))
    return result


def repeat_agreement(passes):
    require(len(passes) == REPEATS and all(len(p) == len(passes[0]) for p in passes), "Repeat denominator differs")
    fields = ("status", "classification", "action", "masked_text", "traces", "evidence")
    disagreements = {key: [] for key in fields}
    for index, records in enumerate(zip(*passes)):
        require(len({r["id"] for r in records}) == 1, "Repeat case order differs")
        for key in fields:
            if any(r.get(key) != records[0].get(key) for r in records[1:]):
                disagreements[key].append(records[0]["id"])
    return {"cases": len(passes[0]), "passes": REPEATS, "disagreements": disagreements,
            "all_fields_identical": not any(disagreements.values()), "accuracy_denominator": len(passes[0])}


def validate_ready(protocol, protocol_sha, entry, ready):
    require(ready["protocol_sha256"] == protocol_sha and ready["identity"] == entry["identity"]
            and ready["source_closure"] == protocol["source_closure"] and ready["training_disabled"]
            and ready["native_product_pipeline"] and ready["name"] == entry["name"] and ready["environment"] == protocol["environment"], "Server readiness differs")
    require(ready["effective_regex_rules"] == protocol["effective_regex_rules"]
            and ready["effective_regex_rules_sha256"] == protocol["effective_regex_rules_sha256"]
            == digest(canonical(ready["effective_regex_rules"])) and ready["regex_rule_count"] == len(ready["effective_regex_rules"]),
            "Actual effective regex inventory/hash differs")


def ready_for(results, name, ready_file):
    protocol, ready = validate(results), read(ready_file)
    entry = next(e for e in protocol["entries"] if e["name"] == name)
    validate_ready(protocol, file_hash(Path(results) / "protocol.json"), entry, ready)
    return protocol, entry, ready


def capture_resources(channel, path, expected_pid):
    path = Path(path)
    if path.exists():
        value = read(path)
    else:
        probe = channel.unary_unary("/privoke.research.PipelineEvidence/Resources")
        value = json.loads(probe(b"resources", timeout=10))
        retain(path, value)
    require(value["pid"] == expected_pid, "Resource snapshot server PID differs")
    return value


def preflight(results, name, target, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    protocol, entry, ready = ready_for(results, name, ready_file)
    output = Path(results) / "preflight" / name
    journal = Journal(output / "raw.jsonl")
    cases = [{"id": "regex-block", "text": "My credit card number is 4111 1111 1111 1111."},
             {"id": "all-layers", "text": "The blue teapot rests beside the window."}]
    records = []
    with grpc.insecure_channel(target) as channel:
        grpc.channel_ready_future(channel).result(timeout=60)
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        for index, case in enumerate(cases):
            row = dict(case, group_id="preflight", family_id="preflight", classification={"sensitivity": "S0", "visibility": "PU", "categories": []}, allowed_actions=["ALLOW", "WARN", "BLOCK"])
            records.append(invoke(stub, journal, entry, row, "pipe3-preflight-" + name + "-" + str(index), repeat=-1, index=index))
    require(all(r["status"] == "ok" for r in records), "Actual native preflight failed")
    require([t["status"] for t in records[0]["traces"]] == ["ok", "skipped", "skipped"]
            and [t["status"] for t in records[1]["traces"]] == ["ok", "ok", "ok"], "Native cascade branches unproven")
    proof = {"name": name, "protocol_sha256": file_hash(Path(results) / "protocol.json"),
             "ready_sha256": file_hash(ready_file), "journal_sha256": file_hash(journal.path), "records": records}
    retain(output / "proof.json", proof)
    return proof


def evaluate(results, name, target, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    protocol, entry, ready = ready_for(results, name, ready_file)
    protocol_sha = file_hash(Path(results) / "protocol.json")
    gate = read(Path(results) / "execution-acceptance.json")
    require(gate["status"] == "accepted" and gate["protocol_sha256"] == protocol_sha, "Root execution acceptance required")
    for previous in NAMES[:NAMES.index(name)]:
        require((Path(results) / "models" / previous / "complete.json").is_file(), "Fixed V3-then-V1 order required")
    proof = read(Path(results) / "preflight" / name / "proof.json")
    require(proof["protocol_sha256"] == protocol_sha, "Actual model cascade preflight required")
    output = Path(results) / "models" / name
    output.mkdir(parents=True, exist_ok=True)
    lock = output / "exclusive.lock"
    with lock.open("x") as handle:
        handle.write(str(os.getpid()))
    try:
        retain(output / "ready.json", ready)
        journal = Journal(output / "raw.jsonl")
        rows = rows_for(protocol)
        warmups = rows_for(protocol, "train")[:4]
        passes = []
        with grpc.insecure_channel(target) as channel:
            grpc.channel_ready_future(channel).result(timeout=60)
            stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
            for index, row in enumerate(warmups):
                record = invoke(stub, journal, entry, row, request_id(protocol_sha, name, -1, row["id"], True), repeat=-1, index=index, warmup=True)
                require(record["status"] == "ok", "TRAIN warmup failed")
            capture_resources(channel, output / "postwarmup-resources.json", ready["pid"])
            for repeat in range(REPEATS):
                records = []
                for index, row in enumerate(rows):
                    records.append(invoke(stub, journal, entry, row, request_id(protocol_sha, name, repeat, row["id"]), repeat=repeat, index=index))
                    if (index + 1) % 100 == 0:
                        print(f"{name} pass {repeat + 1}: {index + 1}/{ROWS}", flush=True)
                passes.append(records)
                retain(output / ("pass-" + str(repeat + 1) + ".json"), summarize(records))
            capture_resources(channel, output / "end-resources.json", ready["pid"])
        agreement = repeat_agreement(passes)
        retain(output / "repeat-agreement.json", agreement)
        result = {"name": name, "protocol_sha256": protocol_sha, "accuracy_requests": REPEATS * ROWS,
                  "warmup_requests": 4, "raw_sha256": file_hash(journal.path), "repeat_agreement_sha256": file_hash(output / "repeat-agreement.json"),
                  "pass_summaries": {str(i + 1): file_hash(output / ("pass-" + str(i + 1) + ".json")) for i in range(REPEATS)}}
        retain(output / "complete.json", result)
        return result
    finally:
        lock.unlink()


def audit(results):
    from .audience_v3_comparison import paired
    protocol = validate(results)
    rows, train = rows_for(protocol), rows_for(protocol, "train")[:4]
    sha = file_hash(Path(results) / "protocol.json")
    summaries, first, agreements, inventory = {}, {}, {}, {}
    for entry in protocol["entries"]:
        name = entry["name"]
        output = Path(results) / "models" / name
        validate_ready(protocol, sha, entry, read(output / "ready.json"))
        journal = Journal(output / "raw.jsonl")
        expected, passes = set(), []
        for index, row in enumerate(train):
            key = request_id(sha, name, -1, row["id"], True)
            expected.add(key)
            require(record_for(journal.calls[key], entry, row, request_for(entry, row, key))["status"] == "ok", "Warmup audit failed")
        for repeat in range(REPEATS):
            records = []
            for index, row in enumerate(rows):
                key = request_id(sha, name, repeat, row["id"])
                expected.add(key)
                call = journal.calls[key]
                reserve = call["reserve"]
                require((reserve["model"], reserve["repeat"], reserve["index"], reserve["case_id"], reserve["warmup"])
                        == (name, repeat, index, row["id"], False), "Journal case binding differs")
                records.append(record_for(call, entry, row, request_for(entry, row, key)))
            summary = summarize(records)
            require(summary == read(output / ("pass-" + str(repeat + 1) + ".json")), "Pass summary differs from raw")
            passes.append(records)
        require(set(journal.calls) == expected and len(expected) == REPEATS * ROWS + 4, "Missing or extra raw requests")
        agreement = repeat_agreement(passes)
        require(agreement == read(output / "repeat-agreement.json"), "Repeat agreement differs")
        complete = read(output / "complete.json")
        require(complete["protocol_sha256"] == sha and complete["raw_sha256"] == file_hash(journal.path)
                and complete["accuracy_requests"] == REPEATS * ROWS and complete["warmup_requests"] == 4
                and complete["pass_summaries"] == {str(i + 1): file_hash(output / ("pass-" + str(i + 1) + ".json")) for i in range(REPEATS)}
                and complete["repeat_agreement_sha256"] == file_hash(output / "repeat-agreement.json"), "Completion seal differs")
        summaries[name] = [summarize(p) for p in passes]
        first[name], agreements[name] = passes[0], agreement
        inventory.update({p.relative_to(Path(results)).as_posix(): file_hash(p) for p in output.iterdir() if p.is_file()})
    result = {"schema": 1, "study_id": STUDY_ID, "protocol_sha256": sha, "accuracy_requests": len(NAMES) * REPEATS * ROWS,
              "accuracy_denominator_per_model": ROWS, "warmup_requests": len(NAMES) * 4,
              "summaries": summaries, "repeat_agreement": agreements,
              "paired_first_pass_v3_minus_v1": {tier: paired(first["v1-" + tier], first["v3-" + tier], rows) for tier in TIERS},
              "window_audit": {entry["name"]: {"cap": entry["native_cap"], "over_cap_ids": [r["id"] for r in rows if protocol["native_lengths"][r["id"]]["v3" if entry["family"] == "v3" else "tiny"] > entry["native_cap"]],
                  "actually_executed_over_cap_ids": [r["id"] for r in first[entry["name"]] if any(t["layer"] == 4 and t["status"] == "ok" for t in r["traces"]) and protocol["native_lengths"][r["id"]]["v3" if entry["family"] == "v3" else "tiny"] > entry["native_cap"]]}
                  for entry in protocol["entries"]},
              "raw_inventory_sha256": digest(canonical(inventory)),
              "limitations": ["Reused assistant-provisional synthetic labels; correlated families and expressions.",
                  "Three passes repeat identical cases; no additional independent accuracy samples.",
                  "Normal regex-first early BLOCK skips later detectors; semantic scores cannot be inferred for skipped cases.",
                  "Same maintained regex/NER in V1 and V3 packages; version contrast changes semantic package only.",
                  "V3-first user-selected order and host load confound descriptive package timings.",
                  "Errors count incorrect; fail-closed BLOCK is not successful classification; no fitting or selection."]}
    retain(Path(results) / "raw-inventory.json", inventory)
    retain(Path(results) / "analysis.json", result)
    return result
