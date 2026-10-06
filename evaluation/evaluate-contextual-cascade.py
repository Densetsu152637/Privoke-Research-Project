"""Staged, validation-calibrated live full-pipeline cascade experiment."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_model.artifact import float32, load_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_eval.presence_evidence import artifact_identity, load_frozen_fit
from privoke_eval.presence_training import binary_metrics, source_family

PROFILES = ("efficient", "balanced", "quality")
CONTROLS = ("original", "current")
PAIRS = tuple(f"{control}-{profile}" for control in CONTROLS for profile in PROFILES)
DATA = {"validation": (968, "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"),
        "development": (502, "45f91e320482dde4d0724cdf42a341649d52e33aeae326f059c714edc97cc706")}
CHECKSUMS = {"original": "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c",
             "current": "8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015"}
FIT_PROTOCOL = "d4c1035c42ef49b0af7992f76bc5332645f2047b3dc313b2679c58a3f14a5f75"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write((json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def inside_results(path):
    path = Path(path).resolve()
    if (ROOT / "evaluation/results").resolve() not in path.parents:
        raise ValueError("Study paths must remain under evaluation/results.")
    return path


def contextual_identity(artifact):
    """Bind the tensors after the existing float32 protobuf transport conversion."""
    return {"model_id": artifact["model_id"], "model_version": artifact["version"],
            "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint(
                {k: tuple(float32(value) for value in v["values"])
                 for k, v in artifact["parameters"].items()},
                {k: v["shape"] for k, v in artifact["parameters"].items()})}


def bind_inputs(args):
    fit_root = inside_results(args.fit_root)
    fitted = load_frozen_fit(fit_root / "profiles/efficient/selection.json", fit_root / "run-manifest.json",
                             fit_source_revision=args.fit_source_revision, protocol_sha256=FIT_PROTOCOL)
    controls = {}
    for name in CONTROLS:
        path = Path(getattr(args, f"{name}_artifact")).resolve()
        artifact = load_artifact(path)
        if (artifact["checksum"] != CHECKSUMS[name] or artifact["model_id"] != "privoke-balanced"
                or artifact["architecture"] != "privoke_tiny_transformer_v1"):
            raise ValueError("Contextual control artifact identity mismatch.")
        controls[name] = {"path": str(path), "file_sha256": sha(path), "identity": contextual_identity(artifact)}
    presence = {}
    for profile, record in fitted["profiles"].items():
        artifact = record["artifact"]
        presence[profile] = {"identity": artifact_identity(artifact), "file_sha256": record["artifact_sha256"],
                             "artifact_bytes": Path(record["artifact_path"]).stat().st_size,
                             "parameter_count": sum(len(v["values"]) for v in artifact["parameters"].values()),
                             "word_features": len(artifact["config"]["branches"]["word"]["features"]),
                             "char_features": len(artifact["config"]["branches"]["char"]["features"])}
    return {"source_revision": args.source_revision, "fit_source_revision": args.fit_source_revision,
            "protocol_sha256": args.protocol_sha256, "fit_protocol_sha256": FIT_PROTOCOL,
            "fit_manifest_sha256": fitted["manifest_sha256"], "controls": controls, "presence": presence,
            "runtime_image_id": args.runtime_image_id, "evaluator_image_id": args.evaluator_image_id,
            "caller_sha256": sha(Path(__file__)),
            "target": args.target, "datasets": {k: list(v) for k, v in DATA.items()}}


def dataset(path, partition):
    count, digest = DATA[partition]
    if sha(path) != digest:
        raise ValueError("Dataset digest differs from the prospective partition.")
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]
    seen = set()
    for row in rows:
        if (not isinstance(row.get("id"), str) or not row["id"] or row["id"] in seen
                or type(row.get("expected_has_pii")) is not bool
                or not isinstance(row.get("group_id"), str) or not row["group_id"]):
            raise ValueError("Invalid ID, binary truth or group in partition.")
        seen.add(row["id"])
    if len(rows) != count:
        raise ValueError("Partition row count differs.")
    return rows


def layer(payload, name):
    matches = [x for x in payload["layers"] if x["layer"] == name]
    if len(matches) != 1:
        raise ValueError("Missing or duplicate requested layer.")
    return matches[0]


def ordinary_layer(record):
    return {k: v for k, v in record.items() if k != "semantic_presence_gate"}


def summary(payload):
    value = {k: payload[k] for k in ("classification", "action", "allowed", "masked_text")}
    # Protobuf omits an unset message even when scalar defaults are printed.
    value["evidence"] = payload.get("evidence")
    return value


def detection(payload):
    value = payload["classification"]
    if value["sensitivity"] not in ("S0", "S1", "S2", "S3") or payload["action"] not in ("ALLOW", "WARN", "BLOCK"):
        raise ValueError("Invalid runtime classification or action.")
    return value["sensitivity"] != "S0" or bool(value["categories"])


def validate_payload(payload, semantic_identity=None):
    if payload.get("error") or any(x.get("status") == "error" or x.get("error") and x.get("status") != "skipped" for x in payload.get("layers", [])):
        raise ValueError("Runtime errors are not calibration or endpoint evidence.")
    detection(payload)
    for record in payload["layers"]:
        if record["status"] not in ("ok", "skipped"):
            raise ValueError("Invalid layer status.")
        if record["layer"] == "semantic" and semantic_identity:
            for result in record["results"]:
                metadata = result["metadata"]
                if any(metadata.get(k) != v for k, v in semantic_identity.items()):
                    raise ValueError("Returned contextual model identity mismatch.")


def checked_trace(payload, presence_identity, threshold):
    semantic = layer(payload, "semantic")
    trace = semantic.get("semantic_presence_gate")
    if not trace:
        raise ValueError("Gate response omitted its typed trace.")
    if semantic["status"] == "skipped":
        reason = "Skipped after regex returned BLOCK."
        regex, ner = layer(payload, "regex"), layer(payload, "ner")
        if (regex["status"] != "ok" or regex.get("error") or payload["action"] != "BLOCK"
                or payload["allowed"] is not False
                or not any(result.get("action") == "BLOCK" for result in regex["results"])
                or ner["status"] != "skipped" or ner["results"] or ner.get("error") != reason
                or semantic["results"] or semantic.get("error") != reason
                or trace.get("status") != "not_run" or trace.get("semantic_results") != []
                or trace.get("predicted_label") != "unspecified" or trace.get("error") != reason
                or trace.get("model_id") != presence_identity["model_id"]
                or trace.get("decision_threshold") != threshold
                or "probability" in trace or "model_threshold" in trace
                or any(trace.get(key) for key in ("model_version", "artifact_checksum", "parameter_fingerprint",
                                                   "contextual_model_id", "contextual_model_version",
                                                   "contextual_artifact_checksum", "contextual_parameter_fingerprint"))):
            raise ValueError("NOT_RUN gate does not match the requested regex BLOCK shortcut.")
        return None
    if semantic["status"] != "ok" or semantic.get("error") or trace["status"] != "applied" or trace["error"]:
        raise ValueError("Gate did not complete successfully.")
    if any(trace.get(k) != v for k, v in presence_identity.items() if k != "threshold"):
        raise ValueError("Returned presence model identity mismatch.")
    probability = trace["probability"]
    if (type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1
            or trace["model_threshold"] != presence_identity["threshold"]
            or trace["decision_threshold"] != threshold
            or trace["predicted_label"] != ("present" if probability >= threshold else "absent")):
        raise ValueError("Invalid gate probability, thresholds or label.")
    return trace


def verify_live(ordinary, gated, identities, threshold):
    validate_payload(ordinary, identities["semantic"])
    validate_payload(gated, identities["semantic"])
    if layer(ordinary, "semantic")["status"] != layer(gated, "semantic")["status"]:
        raise ValueError("Ordinary and gated semantic execution statuses differ.")
    trace = checked_trace(gated, identities["presence"], threshold)
    for name in ("regex", "ner"):
        if ordinary_layer(layer(ordinary, name)) != ordinary_layer(layer(gated, name)):
            raise ValueError("Gate changed a regex/NER finding.")
    if trace is None and ordinary_layer(layer(ordinary, "semantic")) != ordinary_layer(layer(gated, "semantic")):
        raise ValueError("Ordinary and gated semantic shortcuts differ.")
    if trace:
        for key, expected in identities["semantic"].items():
            if trace.get("contextual_" + key) != expected:
                raise ValueError("Gate contextual snapshot identity mismatch, including clean outputs.")
        raw = layer(ordinary, "semantic")["results"]
        if trace["semantic_results"] != raw:
            raise ValueError("Gate raw semantic findings changed.")
        retained = raw if trace["probability"] >= threshold else []
        if layer(gated, "semantic")["results"] != retained:
            raise ValueError("Gate retained semantic contribution violates its decision.")
    return trace


def verify_triplet(ordinary, gated, nonsemantic, identities):
    for value in (ordinary, gated, nonsemantic):
        validate_payload(value, identities["semantic"])
    if summary(ordinary) != summary(gated):
        raise ValueError("Gate-zero classification/action differs from ordinary control.")
    for name in ("regex", "ner"):
        if ordinary_layer(layer(ordinary, name)) != ordinary_layer(layer(gated, name)) or ordinary_layer(layer(ordinary, name)) != ordinary_layer(layer(nonsemantic, name)):
            raise ValueError("Regex/NER findings changed between matched requests.")
    if ordinary_layer(layer(ordinary, "semantic")) != ordinary_layer(layer(gated, "semantic")):
        raise ValueError("Gate-zero semantic findings differ from control.")
    trace = checked_trace(gated, identities["presence"], 0.0)
    if trace and trace["semantic_results"] != layer(ordinary, "semantic")["results"]:
        raise ValueError("Raw semantic trace differs from ordinary findings.")
    return trace


def project(row, threshold):
    trace = row["trace"]
    return row["ordinary"] if trace is None or trace["probability"] >= threshold else row["nonsemantic"]


def verify_selected_validation(current, previous, threshold):
    """A live selected row must preserve the collected execution and projection."""
    trace, collected_trace = current["trace"], previous["trace"]
    if (trace is None) != (collected_trace is None):
        raise ValueError("Presence trace execution changed after calibration.")
    if (summary(current["ordinary"]) != summary(previous["ordinary"])
            or summary(current["gated"]) != summary(project(previous, threshold))):
        raise ValueError("Live selected validation differs from its projected API outcome.")
    if trace and trace["probability"] != collected_trace["probability"]:
        raise ValueError("Presence probability changed after calibration.")


def metrics(rows, getter):
    return binary_metrics([r["expected_has_pii"] for r in rows], [float(detection(getter(r))) for r in rows], .5)


def calibrate(rows):
    thresholds = {0.0, 1.0}
    for row in rows:
        if row["trace"]:
            p = row["trace"]["probability"]
            thresholds.add(p)
            if p < 1:
                thresholds.add(math.nextafter(p, math.inf))
    candidates = [{"threshold": t, "metrics": metrics(rows, lambda r: project(r, t))} for t in sorted(thresholds)]
    eligible = [x for x in candidates if x["metrics"]["recall"] is not None and x["metrics"]["recall"] >= .9]
    if not eligible:
        return {"status": "ineligible", "chosen": None, "candidates": candidates,
                "reason": "No full-pipeline validation threshold meets the recall floor."}
    chosen = max(eligible, key=lambda x: (x["metrics"]["specificity"], x["metrics"]["recall"], x["threshold"]))
    return {"status": "eligible", "chosen": chosen, "candidates": candidates}


def paired_report(rows, getter, *, projection_threshold=None):
    families = defaultdict(list)
    transitions, lost, gained = Counter(), [], []
    for row in rows:
        families[source_family(row["group_id"])].append(row)
        a, b = row["ordinary"], getter(row)
        transitions[f"{a['action']}->{b['action']}"] += 1
        if detection(a) and not detection(b):
            lost.append(row["id"])
        elif not detection(a) and detection(b):
            gained.append(row["id"])
    return {"metrics": metrics(rows, getter), "ordinary_metrics": metrics(rows, lambda r: r["ordinary"]),
            "lost_detection_ids": lost, "gained_detection_ids": gained, "action_transitions": dict(transitions),
            "source_family_metrics": {family: metrics(group, getter) for family, group in sorted(families.items())},
            "suppressed_semantic_ids": [r["id"] for r in rows if r.get("trace") and
                                        (r["trace"]["probability"] < projection_threshold if projection_threshold is not None
                                         else r["trace"].get("predicted_label") == "absent")],
            "actual_trace_absent_ids": [r["id"] for r in rows if r.get("trace") and r["trace"].get("predicted_label") == "absent"],
            "paired_group_bootstrap_intervals": None,
            "interval_limitation": "Group-bootstrap differences were not computed by this bounded caller."}


def request_for(pb, text, request_id, semantic_id, *, presence_id=None, threshold=None, nonsemantic=False,
                visibility_hint=None):
    kwargs = {"text": text, "request_id": request_id, "source": "contextual-cascade-evaluation",
              "semantic_model_id": semantic_id,
              "layers": [pb.DETECTION_LAYER_REGEX, pb.DETECTION_LAYER_NER] if nonsemantic else [],
              "regex_execution_order": pb.REGEX_EXECUTION_ORDER_FIRST}
    if visibility_hint is not None:
        if visibility_hint not in ("P0", "P1", "P2", "P3", "P4", "PU"):
            raise ValueError("Explicit visibility hint must be a valid contract label.")
        kwargs["visibility_hint"] = visibility_hint
    if presence_id is not None:
        if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("An explicit valid gate decision threshold is required.")
        kwargs["semantic_presence_gate"] = pb.SemanticPresenceGate(model_id=presence_id, threshold=threshold)
    return pb.AnalyzePromptRequest(**kwargs)


class RuntimeClient:
    def __init__(self, target):
        generated = ROOT / "extension/client-runtime/generated"
        if generated.is_dir():
            sys.path.insert(0, str(generated))
        import grpc
        from google.protobuf.json_format import MessageToDict
        from privoke.v1 import runtime_pb2, runtime_pb2_grpc
        self.pb, self.convert = runtime_pb2, MessageToDict
        self.channel = grpc.insecure_channel(target)
        self.stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(self.channel)

    def analyze(self, row, request_id, semantic_id, **kwargs):
        request = request_for(self.pb, row["text"], request_id, semantic_id, **kwargs)
        response = self.stub.AnalyzePrompt(request, timeout=120)
        try:
            raw = self.convert(response, preserving_proto_field_name=True, always_print_fields_with_no_presence=True)
        except TypeError:
            raw = self.convert(response, preserving_proto_field_name=True, including_default_value_fields=True)
        if response.request_id != request_id:
            raise ValueError("Runtime response request ID mismatch.")
        parsed = dict(raw)
        parsed["layers"] = []
        for record in raw["layers"]:
            item = dict(record)
            item["layer"] = {self.pb.DETECTION_LAYER_REGEX: "regex", self.pb.DETECTION_LAYER_NER: "ner", self.pb.DETECTION_LAYER_SEMANTIC: "semantic"}[getattr(self.pb, record["layer"])]
            if "semantic_presence_gate" in record:
                trace = dict(record["semantic_presence_gate"])
                trace["status"] = {self.pb.SEMANTIC_PRESENCE_GATE_STATUS_NOT_RUN: "not_run", self.pb.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED: "applied", self.pb.SEMANTIC_PRESENCE_GATE_STATUS_ERROR: "error"}[getattr(self.pb, trace["status"])]
                trace["predicted_label"] = {self.pb.ANNOTATION_PRESENCE_PRESENT: "present", self.pb.ANNOTATION_PRESENCE_ABSENT: "absent", self.pb.ANNOTATION_PRESENCE_UNSPECIFIED: "unspecified"}[getattr(self.pb, trace["predicted_label"])]
                item["semantic_presence_gate"] = trace
            parsed["layers"].append(item)
        request_json = self.convert(request, preserving_proto_field_name=True)
        return parsed, {"request": request_json, "response": raw,
                        "request_binary_sha256": hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest()}

    def close(self):
        self.channel.close()


def record_rpc(client, row, directory, tag, semantic_id, **kwargs):
    request_id = f"cascade-{directory.as_posix()}-{tag}-{row['id']}"
    request_id = "cascade-" + hashlib.sha256(request_id.encode()).hexdigest()[:48]
    payload, raw = client.analyze(row, request_id, semantic_id, **kwargs)
    write(directory / "raw" / f"{tag}-{hashlib.sha256(row['id'].encode()).hexdigest()}.json", raw)
    return payload


def complete_report(directory, rows, getter, binding, pair, stage):
    report = {"status": "complete", "errors": [], "pair": pair, "stage": stage, "binding": binding,
              **paired_report(rows, getter), "rows": len(rows),
              "predictions_sha256": sha(directory / "predictions.json"),
              "raw_rpc_sha256": {p.name: sha(p) for p in sorted((directory / "raw").glob("*.json"))}}
    if (directory / "selection-binding.json").exists():
        report["selection_binding_sha256"] = sha(directory / "selection-binding.json")
    durations = [getter(r)["elapsed_ms"] for r in rows]
    report["internal_latency_ms"] = {"median": statistics.median(durations),
                                     "p95": sorted(durations)[math.ceil(.95 * len(durations)) - 1]}
    write(directory / "report.json", report)


def verified_rows(directory, reference, binding, pair):
    report = read(directory / "report.json")
    if report.get("status") != "complete" or report.get("errors") or report.get("binding") != binding or report.get("pair") != pair or report.get("stage") != directory.parent.name or sha(directory / "predictions.json") != report.get("predictions_sha256"):
        raise ValueError("Incomplete, changed or differently bound prior phase.")
    rows = read(directory / "predictions.json")
    if [(r["id"], r["group_id"], r["expected_has_pii"]) for r in rows] != [(r["id"], r["group_id"], r["expected_has_pii"]) for r in reference]:
        raise ValueError("Prior phase IDs/truth/groups differ from pinned input.")
    if report["metrics"] != metrics(rows, lambda r: r["gated"]):
        raise ValueError("Prior report confusion counts differ from raw predictions.")
    if {p.name: sha(p) for p in sorted((directory / "raw").glob("*.json"))} != report.get("raw_rpc_sha256"):
        raise ValueError("Raw RPC evidence changed after phase completion.")
    return rows


def run_stage(args, client_factory=RuntimeClient):
    root = inside_results(args.study_root)
    binding = bind_inputs(args)
    manifest_path = root / "study-manifest.json"
    if not root.exists():
        if args.phase != "collect-validation":
            raise ValueError("Study must begin with validation collection.")
        root.mkdir(parents=True)
        write(manifest_path, {"binding": binding, "pairs": PAIRS, "started_at": time.time(),
                              "hardware": {"platform": platform.platform(), "cpu_count": os.cpu_count()}})
    elif read(manifest_path).get("binding") != binding:
        raise ValueError("Study source/artifact/image/protocol binding changed.")
    validation = dataset(args.validation_file, "validation")
    if args.phase == "calibrate":
        directory = root / "calibration"
        directory.mkdir(exist_ok=False)
        choices = {}
        for pair in PAIRS:
            rows = verified_rows(root / "collect-validation" / pair, validation, binding, pair)
            result = calibrate(rows)
            profile = pair.split("-", 1)[1]
            artifact_threshold = binding["presence"][profile]["identity"]["threshold"]
            result["artifact_threshold_projection"] = paired_report(rows, lambda r: project(r, artifact_threshold),
                                                                    projection_threshold=artifact_threshold)
            result["collection_report_sha256"] = sha(root / "collect-validation" / pair / "report.json")
            choices[pair] = result
        write(directory / "selection.json", {"status": "frozen", "binding": binding, "choices": choices,
                                              "frozen_before_development": True})
        return
    pair = f"{args.control}-{args.profile}"
    selection = None
    threshold = 0.0
    if args.phase != "collect-validation":
        selection = read(root / "calibration/selection.json")
        if selection.get("status") != "frozen" or selection.get("binding") != binding or set(selection.get("choices", {})) != set(PAIRS) or selection.get("frozen_before_development") is not True:
            raise ValueError("All six validation-only choices must be frozen.")
        choice = selection["choices"][pair]
        threshold = choice["chosen"]["threshold"] if choice["chosen"] else None
        for key in PAIRS:
            rows = verified_rows(root / "collect-validation" / key, validation, binding, key)
            recalibrated = calibrate(rows)
            if (sha(root / "collect-validation" / key / "report.json") != selection["choices"][key]["collection_report_sha256"]
                    or recalibrated["chosen"] != selection["choices"][key]["chosen"]
                    or recalibrated["status"] != selection["choices"][key]["status"]):
                raise ValueError("Frozen threshold does not match validation-only calibration.")
        if args.phase == "evaluate-development":
            for key in PAIRS:
                if selection["choices"][key]["status"] == "ineligible":
                    skipped = read(root / "evaluate-validation" / key / "skipped.json")
                    if skipped != {"status": "skipped_ineligible", "pair": key, "binding": binding,
                                   "selection_sha256": sha(root / "calibration/selection.json")}:
                        raise ValueError("Ineligible pair lacks its frozen skip record.")
                    continue
                verified = verified_rows(root / "evaluate-validation" / key, validation, binding, key)
                proof = root / "evaluate-validation" / key / "selection-binding.json"
                report = read(root / "evaluate-validation" / key / "report.json")
                expected_proof = {"selection_sha256": sha(root / "calibration/selection.json"),
                                  "decision_threshold": selection["choices"][key]["chosen"]["threshold"]}
                if read(proof) != expected_proof or sha(proof) != report.get("selection_binding_sha256"):
                    raise ValueError("Live validation is not bound to the frozen threshold.")
                collection = verified_rows(root / "collect-validation" / key, validation, binding, key)
                if any(summary(x["gated"]) != summary(project(y, expected_proof["decision_threshold"])) for x, y in zip(verified, collection)):
                    raise ValueError("Prior live validation disagrees with frozen projection.")
        if choice["status"] == "ineligible":
            directory = root / args.phase / pair
            directory.mkdir(parents=True, exist_ok=False)
            write(directory / "skipped.json", {"status": "skipped_ineligible", "pair": pair, "binding": binding,
                                               "selection_sha256": sha(root / "calibration/selection.json")})
            return
    reference = dataset(args.development_file, "development") if args.phase == "evaluate-development" else validation
    directory = root / args.phase / pair
    directory.mkdir(parents=True, exist_ok=False)
    identities = {"semantic": binding["controls"][args.control]["identity"], "presence": binding["presence"][args.profile]["identity"]}
    client = None
    rows = []
    try:
        client = client_factory(args.target)
        previous = verified_rows(root / "collect-validation" / pair, validation, binding, pair) if args.phase == "evaluate-validation" else None
        for index, row in enumerate(reference):
            ordinary = record_rpc(client, row, directory, "ordinary", identities["semantic"]["model_id"])
            gated = record_rpc(client, row, directory, "gated", identities["semantic"]["model_id"], presence_id=identities["presence"]["model_id"], threshold=threshold)
            trace = verify_live(ordinary, gated, identities, threshold)
            result = {"id": row["id"], "group_id": row["group_id"], "expected_has_pii": row["expected_has_pii"],
                      "ordinary": ordinary, "gated": gated, "trace": trace}
            if args.phase == "collect-validation":
                nonsemantic = record_rpc(client, row, directory, "nonsemantic", identities["semantic"]["model_id"], nonsemantic=True)
                verify_triplet(ordinary, gated, nonsemantic, identities)
                result["nonsemantic"] = nonsemantic
            elif previous is not None:
                verify_selected_validation(result, previous[index], threshold)
            rows.append(result)
        dataset(args.validation_file, "validation")
        if args.phase == "evaluate-development":
            dataset(args.development_file, "development")
        if bind_inputs(args) != binding:
            raise ValueError("Fit/control artifacts or source binding changed during phase.")
        write(directory / "predictions.json", rows)
        if selection:
            write(directory / "selection-binding.json", {"selection_sha256": sha(root / "calibration/selection.json"), "decision_threshold": threshold})
        complete_report(directory, rows, lambda r: r["gated"], binding, pair, args.phase)
    except Exception as exc:
        write(directory / "failure.json", {"status": "failed", "error": str(exc), "completed_rows": len(rows), "binding": binding})
        raise
    finally:
        if client:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("collect-validation", "calibrate", "evaluate-validation", "evaluate-development"), required=True)
    for name in ("study-root", "fit-root", "original-artifact", "current-artifact", "validation-file", "development-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-revision", "fit-source-revision", "protocol-sha256", "runtime-image-id", "evaluator-image-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--target", default=os.getenv("PRIVOKE_RUNTIME_TARGET", "127.0.0.1:50054"))
    parser.add_argument("--protocol-file", type=Path, required=True,
                        help="Verified prospective protocol copy accessible in the evaluator container.")
    parser.add_argument("--control", choices=CONTROLS)
    parser.add_argument("--profile", choices=PROFILES)
    args = parser.parse_args(argv)
    if args.phase != "calibrate" and (not args.control or not args.profile):
        parser.error("Non-calibration stages require an explicit control and profile.")
    for value in (args.runtime_image_id, args.evaluator_image_id):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            parser.error("Supply actual docker inspect Image digests, not image tags.")
    if (ROOT / ".git").exists():
        actual = subprocess.check_output(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if actual != args.source_revision:
            parser.error("Source revision differs from the committed checkout.")
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision) or sha(args.protocol_file) != args.protocol_sha256:
        parser.error("Source revision or prospective protocol differs from the committed checkout.")
    run_stage(args)


if __name__ == "__main__":
    main()
