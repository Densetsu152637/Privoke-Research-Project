"""EN3 after-only RPCs paired with immutable PH3 raw BEFORE on reused DEVELOPMENT."""
from pathlib import Path

from . import privacy_encoder_v3 as en
from . import privacy_heads_v3_comparison as raw

BEFORE_ANALYSIS = "98edb4166bf97742d9c766456ffc14b5d8af20bf205f00486fa54584183699ce"
BEFORE_REGISTRY = "d124ef10d1e37a08d126c17fd714e03ba4cc66e8a99bb864c7183ab99f3a9363"
BEFORE_INVENTORY = "020d560fb205f2622bb6ab3187a981daffcf62d70b0d3b4545a5d055e88681a2"


def old_root(binding):
    return Path(binding["repository"])/"evaluation/results"/en.ph.STUDY_ID


def model_identity(manifest, manifest_sha):
    return {"model_id": manifest["model_id"], "model_version": manifest_sha,
            "artifact_checksum": manifest_sha, "parameter_fingerprint": manifest["blob"],
            "parameter_count": str(manifest["parameter_count"]),
            "backbone_sha256": manifest["source"]["weights_sha256"],
            "tokenizer_sha256": manifest["vocab"], "architecture": manifest["architecture"]}


def before_metadata(binding):
    root = old_root(binding)
    for file, expected in (("analysis.json", BEFORE_ANALYSIS), ("registry.json", BEFORE_REGISTRY),
                           ("raw-inventory.json", BEFORE_INVENTORY)):
        en.require(en.file_hash(root/"comparison"/file) == expected, "Imported PH3 commitment changed: "+file)
    return en.read(root/"comparison/registry.json")


def freeze_registry(results):
    protocol, binding, _, _ = en.validate(results, check_environment=False)
    entries, seals = [], {}
    for tier in en.TIERS:
        en.audit_training(results, tier)
        outputs = en.read(Path(results)/"exports"/(tier+".json"))
        # Require an actual reload verification from the old Torch2.11 CPU serving environment.
        verifications = list((Path(results)/"export-verification").glob(tier+"-*.json"))
        en.require(any(en.read(f)["environment"]["packages"]["torch"].startswith("2.11.")
                       and en.read(f)["identity"] == en.identity(results, protocol, tier)
                       and en.read(f)["status"] == "passed" for f in verifications), "Old CPU native reload proof required")
        item = outputs["selected"]
        manifest = en.read(Path(item["directory"])/"manifest.json")
        entries.append({"name": "en3-"+tier, "family": "v3", "tier": tier, **item,
                        "identity": model_identity(manifest, item["manifest_sha256"]),
                        "adapted_encoder_inventory_sha256": en.ph.digest(en.canonical({
                            k: v for k, v in manifest["tensors"].items() if k.startswith("encoder.")}))})
        seals[tier] = {"exports": en.file_hash(Path(results)/"exports"/(tier+".json")),
                       "audit": en.file_hash(Path(results)/"training-audit"/(tier+".json")),
                       "cpu_verifications": {f.name: en.file_hash(f) for f in verifications}}
    old = before_metadata(binding)
    for tier in en.TIERS:
        entry = next(e for e in old["entries"] if e["name"] == "v3-"+tier)
        en.require(entry["manifest_sha256"] == en.SELECTED_PINS[tier], "BEFORE model is not initial parent")
    value = {"schema": 1, "study_id": en.STUDY_ID, "protocol_sha256": en.file_hash(Path(results)/"protocol.json"),
             "source_closure": protocol["source_closure"], "exports_seal": seals, "entries": entries,
             "development": protocol["dataset_files"]["fresh_eval"], "layers": [4], "visibility_hints": "",
             "before": {"analysis": BEFORE_ANALYSIS, "registry": BEFORE_REGISTRY, "raw_inventory": BEFORE_INVENTORY},
             "claim": "reused_DEVELOPMENT_after_training_no_new_independence_no_latency_speedup"}
    en.retain(Path(results)/"comparison/registry.json", value)
    return value


def validate_registry(results):
    protocol, binding, _, _ = en.validate(results, check_environment=False)
    registry = en.read(Path(results)/"comparison/registry.json")
    en.require(registry["study_id"] == en.STUDY_ID and registry["layers"] == [4] and registry["visibility_hints"] == ""
               and registry["protocol_sha256"] == en.file_hash(Path(results)/"protocol.json")
               and registry["source_closure"] == protocol["source_closure"]
               and registry["development"] == protocol["dataset_files"]["fresh_eval"], "EN3 registry drift")
    en.require([e["name"] for e in registry["entries"]] == ["en3-"+t for t in en.TIERS], "Exactly three AFTER packages required")
    en.require(registry["before"] == {"analysis": BEFORE_ANALYSIS, "registry": BEFORE_REGISTRY, "raw_inventory": BEFORE_INVENTORY},
               "BEFORE pins changed")
    before_metadata(binding)
    for tier, entry in zip(en.TIERS, registry["entries"]):
        seal = registry["exports_seal"][tier]
        en.require(seal["exports"] == en.file_hash(Path(results)/"exports"/(tier+".json"))
                   and seal["audit"] == en.file_hash(Path(results)/"training-audit"/(tier+".json")), "All-tier export seal changed")
        for name, sha in seal["cpu_verifications"].items():
            en.require(en.file_hash(Path(results)/"export-verification"/name) == sha, "CPU verification changed")
        outputs = en.read(Path(results)/"exports"/(tier+".json"))
        for kind, sealed in outputs.items():
            en.require(kind in ("selected", "terminal"), "Unknown export kind")
            assets = Path(sealed["directory"])
            header = en.read(assets/"manifest.json")
            en.require(en.file_hash(assets/"manifest.json") == sealed["manifest_sha256"], "Sealed manifest changed")
            for filename, key in (("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab"), ("evidence.json", "evidence")):
                en.require(en.file_hash(assets/filename) == header[key], "Selected/terminal seal asset changed")
            en.require(en.file_hash(assets/"cpu-reload-parity.json") == sealed["cpu_parity_sha256"], "CPU parity seal changed")
            if sealed["cuda_parity_sha256"]:
                en.require(en.file_hash(assets/"cuda-cpu-parity.json") == sealed["cuda_parity_sha256"], "CUDA parity seal changed")
        en.require(set(outputs) == {"selected", "terminal"}, "Both full-model exports required")
        item = outputs["selected"]
        en.require(all(entry[k] == v for k, v in item.items()), "Registry export differs")
        path = Path(entry["directory"])
        manifest = en.read(path/"manifest.json")
        en.require(en.file_hash(path/"manifest.json") == entry["manifest_sha256"], "Manifest changed")
        for filename, key in (("model.safetensors", "blob"), ("config.json", "config"), ("vocab.txt", "vocab"), ("evidence.json", "evidence")):
            en.require(en.file_hash(path/filename) == manifest[key], "Serving asset changed")
        en.require(entry["identity"] == model_identity(manifest, entry["manifest_sha256"]), "Registry model identity changed")
    return registry, binding


def development_rows(results):
    # The only DEVELOPMENT payload entry point follows the complete three-tier export/audit seal.
    registry, binding = validate_registry(results)
    rows = en.ph.load_partition(binding["data_manifest"], "fresh_eval", evaluation_authorized=True)
    en.require(len(rows) == 1560 and len({r["id"] for r in rows}) == 1560, "DEVELOPMENT ID coverage changed")
    en.require(all(not r.get("visibility_hint") for r in rows), "Primary hints must be empty")
    return registry, binding, rows


def request_id(name, row, index, *, warmup=False, before=False):
    prefix = "ph3" if before else "en3"
    if warmup:
        prefix += "-warmup"
    return prefix+"-"+en.ph.digest(en.canonical([name, row["id"], index]))[:32 if warmup else 40]


def imported_before(binding, tier, rows):
    """Audit existing protobuf text/labels/response identity; do not replay old RPCs."""
    root = old_root(binding)
    old = before_metadata(binding)
    entry = next(e for e in old["entries"] if e["name"] == "v3-"+tier)
    inventory = en.read(root/"comparison/raw-inventory.json")
    output = root/"comparison/models"/entry["name"]/"rows"
    en.require({p.name for p in output.iterdir()} == {f"{i:04d}" for i in range(len(rows))}, "Imported row coverage differs")
    records = []
    for index, row in enumerate(rows):
        directory = output/f"{index:04d}"
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            en.require(path.is_file() and inventory.get(relative) == en.file_hash(path), "Imported raw file changed")
        records.append(raw.audit_call(entry, row, directory, request_id(entry["name"], row, index, before=True)))
    summary = raw.summarize(records)
    en.require(summary == en.read(root/"comparison/analysis.json")["results"][entry["name"]], "Imported BEFORE summary differs")
    return records, summary


def evaluate(results, tier, target, ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    registry, binding, rows = development_rows(results)
    entry = next(e for e in registry["entries"] if e["tier"] == tier)
    # Validate BEFORE one-to-one stimuli before issuing any AFTER accuracy calls.
    imported_before(binding, tier, rows)
    ready = en.read(ready_file)
    en.require(ready["identity"] == entry["identity"] and ready["registry_sha256"] == en.file_hash(Path(results)/"comparison/registry.json")
               and ready["source_closure"] == registry["source_closure"] and ready["training_disabled"], "Server readiness mismatch")
    output = Path(results)/"comparison/models"/entry["name"]
    en.retain(output/"server-ready.json", ready)
    records = []
    with grpc.insecure_channel(target) as channel:
        grpc.channel_ready_future(channel).result(timeout=180)
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
        warmup = en.ph.load_partition(binding["data_manifest"], "train")[:4]
        for index, row in enumerate(warmup):
            result = raw.invoke(stub, entry, row, output/"warmup"/f"{index:04d}", request_id(entry["name"], row, index, warmup=True))
            en.require(result["status"] == "ok", "TRAIN warmup failed")
        for index, row in enumerate(rows):
            records.append(raw.invoke(stub, entry, row, output/"rows"/f"{index:04d}", request_id(entry["name"], row, index)))
            if index % 100 == 0:
                print(f"{entry['name']}: {index+1}/{len(rows)}", flush=True)
    result = raw.summarize(records)
    en.retain(output/"summary.json", result)
    en.retain(output/"complete.json", {"registry_sha256": en.file_hash(Path(results)/"comparison/registry.json"),
                                       "requested": len(rows), "summary_sha256": en.file_hash(output/"summary.json")})
    return result


def audit(results):
    registry, binding, rows = development_rows(results)
    summaries, pairs, inventory = {}, {}, {}
    for entry in registry["entries"]:
        before, before_summary = imported_before(binding, entry["tier"], rows)
        output = Path(results)/"comparison/models"/entry["name"]
        en.require({p.name for p in (output/"rows").iterdir()} == {f"{i:04d}" for i in range(len(rows))}, "AFTER row coverage differs")
        records = []
        for index, row in enumerate(rows):
            directory = output/"rows"/f"{index:04d}"
            records.append(raw.audit_call(entry, row, directory, request_id(entry["name"], row, index)))
            for path in directory.iterdir():
                inventory[path.relative_to(Path(results)).as_posix()] = en.file_hash(path)
        for index, row in enumerate(en.ph.load_partition(binding["data_manifest"], "train")[:4]):
            outcome = raw.audit_call(entry, row, output/"warmup"/f"{index:04d}", request_id(entry["name"], row, index, warmup=True))
            en.require(outcome["status"] == "ok", "Warmup did not reconcile")
        summary = raw.summarize(records)
        en.require(summary == en.read(output/"summary.json"), "AFTER summary differs")
        en.require(en.read(output/"complete.json") == {"registry_sha256": en.file_hash(Path(results)/"comparison/registry.json"),
                   "requested": len(rows), "summary_sha256": en.file_hash(output/"summary.json")}, "Completion mismatch")
        summaries[entry["tier"]] = {"before_PH3_imported": before_summary, "after_EN3": summary}
        pairs[entry["tier"]] = raw.paired(before, records)
    result = {"schema": 1, "study_id": en.STUDY_ID, "claim": registry["claim"], "before_commitments": registry["before"],
              "registry_sha256": en.file_hash(Path(results)/"comparison/registry.json"), "results": summaries,
              "paired_after_minus_before": pairs, "new_accuracy_requests": 4680, "imported_accuracy_cases": 4680,
              "raw_file_inventory_sha256": en.ph.digest(en.canonical(inventory)),
              "limitations": ["Opened PH3 fixture reused as DEVELOPMENT; no new independent test.",
                              "Same-case accuracy pairing, unequal runs; no latency speedup or causal architecture claim.",
                              "Errors count incorrect; action-harm comparable and error-pair denominators retained."]}
    en.retain(Path(results)/"comparison/raw-inventory.json", inventory)
    en.retain(Path(results)/"comparison/analysis.json", result)
    return result
