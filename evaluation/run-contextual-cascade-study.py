"""Run the frozen contextual-presence cascade through staged Compose jobs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RESULTS = (ROOT / "evaluation/results").resolve()
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))
COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml",
           "-f", "evaluation/compose.public-negatives.yml", "-f", "evaluation/compose.presence.yml"]
PROFILES = ("efficient", "balanced", "quality")
CONTROLS = ("original", "current")
PAIRS = tuple(f"{control}-{profile}" for control in CONTROLS for profile in PROFILES)
FIXTURE_SHA256 = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
RUBRIC_SHA256 = "30ce98dbac3de4943839123d9e8de41c6c5190124399c6e5821cfe5f391e6d56"
FIXTURE_REVIEW_SHA256 = "ed2984781bf375bfc080a9d406f29a9bbd2b3aaa1b61f6afe347dd502521fb42"
FIXTURE_COPY_PROVENANCE_SHA256 = "23123082d6a440c15e6588439e5a0efbd29697a2f9ad66bb8d19f8d7d3a7dbb6"
CASCADE_PROTOCOL_SHA256 = "2030fd53264bd5000775c1ddfbfd1e7dccc7267f395f89e66410b76e057ce720"
CONTEXT_CHECKSUMS = {"original": "8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c",
                     "current": "8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015"}
PRESENCE_IDS = {p: f"privoke-presence-{p}" for p in PROFILES}
CATALOG_IDS = ("privoke-balanced", *PRESENCE_IDS.values())

ADMIN_READ = """import base64,json,sys
from pathlib import Path
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
mid=sys.argv[1]; assert mid in ids; p=Path('/models')/(mid+'.json')
print(json.dumps({'exists':p.is_file(),'raw_b64':base64.b64encode(p.read_bytes()).decode('ascii') if p.is_file() else None}))
"""
ADMIN_INSTALL = """import json,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact,write_artifact_atomic
mid,expected=sys.argv[1:3]
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
assert mid in ids; raw=sys.stdin.buffer.read(); obj=json.loads(raw.decode('utf-8')); validate_artifact(obj)
assert obj.get('model_id')==mid and obj.get('checksum')==expected
if mid=='privoke-balanced': assert expected in ('8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c','8c139431ba8605a3d6817d24d233cce78fc22a086fdeb3ee99702ada86c80015')
write_artifact_atomic(Path('/models')/(mid+'.json'),obj)
"""
ADMIN_RESTORE = """import json,os,sys
from pathlib import Path
from privoke_model.artifact import validate_artifact
ids=('privoke-balanced','privoke-presence-efficient','privoke-presence-balanced','privoke-presence-quality')
mid=sys.argv[1]; assert mid in ids; raw=sys.stdin.buffer.read(); obj=json.loads(raw.decode('utf-8')); validate_artifact(obj); assert obj.get('model_id')==mid
p=Path('/models')/(mid+'.json'); t=p.with_name(p.name+'.restore-'+str(os.getpid()))
with t.open('xb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
os.replace(t,p); fd=os.open(str(p.parent),os.O_RDONLY)
try: os.fsync(fd)
finally: os.close(fd)
"""
IDENTITY_PROBE = """import json,sys,grpc,time,math
sys.path.insert(0,'/workspace/extension/client-runtime/generated')
from privoke.v1 import runtime_pb2 as pb,runtime_pb2_grpc as stubs
e=json.load(sys.stdin); q=pb.AnalyzePromptRequest(request_id='cascade-identity-probe',text='A public example sentence.',source='contextual-cascade-probe',semantic_model_id=e['context']['model_id'],semantic_presence_gate=pb.SemanticPresenceGate(model_id=e['presence']['model_id'],threshold=0.0),regex_execution_order=pb.REGEX_EXECUTION_ORDER_FIRST,layers=[pb.DETECTION_LAYER_SEMANTIC])
deadline=time.monotonic()+e.pop('_probe_retry_seconds',10.0); last=None; success=False
with grpc.insecure_channel('client-runtime:50054') as ch:
 s=stubs.PrivokeRuntimeServiceStub(ch)
 while time.monotonic()<deadline:
  try:
   r=s.AnalyzePrompt(q,timeout=3)
   x=next((z for z in r.layers if z.layer==pb.DETECTION_LAYER_SEMANTIC),None)
   layers_ok=(len(r.layers)==1 and all(z.status=='ok' and not z.error for z in r.layers))
   if r.request_id==q.request_id and not r.error and layers_ok and x is not None and x.status=='ok' and not x.error and x.HasField('semantic_presence_gate'):
    t=x.semantic_presence_gate
    got={'context':{'model_id':t.contextual_model_id,'model_version':t.contextual_model_version,'artifact_checksum':t.contextual_artifact_checksum,'parameter_fingerprint':t.contextual_parameter_fingerprint},'presence':{'model_id':t.model_id,'model_version':t.model_version,'artifact_checksum':t.artifact_checksum,'parameter_fingerprint':t.parameter_fingerprint,'threshold':t.model_threshold},'status':int(t.status),'error':t.error,'decision_threshold':t.decision_threshold}
    fields=('probability','model_threshold','decision_threshold')
    optional=all(t.HasField(k) for k in fields)
    finite=optional and all(math.isfinite(getattr(t,k)) and 0.0<=getattr(t,k)<=1.0 for k in fields)
    if (got['context']==e['context'] and {k:got['presence'][k] for k in e['presence']}==e['presence']
        and got['status']==pb.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED and not got['error']
        and finite and t.predicted_label==pb.ANNOTATION_PRESENCE_PRESENT
        and t.decision_threshold==0.0):
     print(json.dumps({'context':got['context'],'presence':got['presence']},sort_keys=True)); success=True; break
    last='identity_or_gate_mismatch'
   else: last='runtime_error_or_missing_gate_trace'
  except grpc.RpcError: last='runtime_rpc_error'
  time.sleep(min(0.5,max(0.0,deadline-time.monotonic())))
if not success: raise RuntimeError('typed runtime probe did not converge: '+str(last))
"""
FIT_PREFLIGHT = """import argparse,importlib.util,json,sys
sys.path.insert(0,'/workspace/shared/python'); sys.path.insert(0,'/workspace/evaluation')
p='/workspace/evaluation/evaluate-contextual-cascade.py'; s=importlib.util.spec_from_file_location('cascade_fit_preflight',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
a=argparse.Namespace(fit_root=sys.argv[1],fit_source_revision=sys.argv[2],original_artifact=sys.argv[3],current_artifact=sys.argv[4],source_revision=sys.argv[5],protocol_sha256=sys.argv[6],runtime_image_id=sys.argv[7],evaluator_image_id=sys.argv[8],target='client-runtime:50054')
v=m.bind_inputs(a); open(sys.argv[9],'x',encoding='utf-8').write(json.dumps(v,sort_keys=True,allow_nan=False))
"""
FIXTURE_PREFLIGHT = """import importlib.util,json,sys
sys.path.insert(0,'/workspace/shared/python'); sys.path.insert(0,'/workspace/evaluation')
p='/workspace/evaluation/evaluate-contextual-regressions.py'; s=importlib.util.spec_from_file_location('fixture_integrity_preflight',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
study,validation,cases,rubric,review,receipt=sys.argv[1:]
binding,selection,selection_sha=m.frozen_study(study,validation)
review_obj=m.CASCADE.read(review)
fixture_sha=m.CASCADE.sha(cases); rubric_sha=m.CASCADE.sha(rubric); review_sha=m.CASCADE.sha(review)
if review_obj.get('status')!='reviewed' or review_obj.get('case_file_sha256')!=fixture_sha or review_obj.get('rubric_sha256')!=rubric_sha: raise ValueError('Fixture review binding mismatch')
rows=m.load_cases(cases,review_obj.get('case_counts') or review_obj.get('expected_counts') or review_obj.get('reviewed_counts'))
value={'binding':binding,'selection_sha256':selection_sha,'choices':{k:{'status':v['status'],'chosen':v.get('chosen')} for k,v in selection['choices'].items()},'fixture_sha256':fixture_sha,'rubric_sha256':rubric_sha,'review_sha256':review_sha,'case_counts':{'total':len(rows),'families':len({r['family_id'] for r in rows}),'controls':sum(not r['ambiguous'] and r['required_sensitive'] is False for r in rows),'disclosure_candidates':sum(not r['ambiguous'] and r['required_sensitive'] is True for r in rows),'ambiguous_excluded':sum(r['ambiguous'] for r in rows),'context_truth_eligible':sum(r.get('context_truth_eligible',not r['ambiguous']) for r in rows),'action_accuracy_eligible':sum(r.get('action_accuracy_eligible',not r['ambiguous']) for r in rows),'visibility_hints':sum(r.get('visibility_hint') is not None for r in rows)},'professor_confirmation':review_obj.get('professor_confirmation')}
open(receipt,'x',encoding='utf-8').write(json.dumps(value,sort_keys=True,allow_nan=False))
"""


def sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(Path(path).read_bytes())


def read_json(path: Path) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Expected JSON object.")
    return value


def linux_scorer_binding(host_binding: dict) -> dict:
    """Map only bound control artifact locators; preserve every identity and digest."""
    mapped = json.loads(json.dumps(host_binding, allow_nan=False))
    if set(mapped.get("controls", {})) != set(CONTROLS):
        raise ValueError("Primary host binding lacks the fixed contextual controls.")
    for name in CONTROLS:
        path = inside_results(Path(host_binding["controls"][name]["path"]))
        mapped["controls"][name]["path"] = container_path(path)
    return mapped


def load_completed_primary(path: Path) -> dict:
    """Require a terminal, restored primary study before fixture orchestration."""
    path = inside_results(path)
    manifest_path = path / "study-run-manifest.json"
    manifest = read_json(manifest_path)
    if (manifest.get("status") != "complete" or manifest.get("restoration_verified") is not True
            or manifest.get("admin_mutation_outcome_unknown") is not False
            or manifest.get("evaluator_job_outcome_unknown") is not False):
        raise ValueError("Fixture mode requires a complete, restored primary controller run.")
    binding = manifest.get("binding")
    if not isinstance(binding, dict) or set(binding.get("controls", {})) != set(CONTROLS) or set(binding.get("presence", {})) != set(PROFILES):
        raise ValueError("Primary controller binding does not contain the fixed controls and profiles.")
    scorer_binding = linux_scorer_binding(binding)
    if manifest.get("images_before") != manifest.get("images_after"):
        raise ValueError("Primary runtime/evaluator image identity changed during the run.")
    if manifest["images_after"].get("client-runtime") != binding.get("runtime_image_id"):
        raise ValueError("Primary runtime image differs from its binding.")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", binding.get("evaluator_image_id", "")):
        raise ValueError("Primary evaluator image binding is not an immutable digest.")
    manifest_jobs = manifest.get("jobs", [])
    if not manifest_jobs or any(x.get("image_id") != binding["evaluator_image_id"] for x in manifest_jobs):
        raise ValueError("Primary evaluator jobs do not all use the frozen evaluator image.")

    study_root = path / "cascade-evidence"
    selection_path = study_root / "calibration/selection.json"
    selection = read_json(selection_path)
    if (selection.get("status") != "frozen" or selection.get("binding") != scorer_binding
            or set(selection.get("choices", {})) != set(PAIRS)
            or selection.get("frozen_before_development") is not True
            or sha_file(selection_path) != manifest.get("calibration_sha256")):
        raise ValueError("Primary frozen selection is missing or differs from its controller receipt.")
    nested = read_json(study_root / "study-manifest.json")
    if nested.get("binding") != scorer_binding:
        raise ValueError("Primary nested cascade evidence has a different input binding.")
    if read_json(path / "input-binding.json") != binding:
        raise ValueError("Primary input-binding receipt differs from the completed controller binding.")

    choices = selection["choices"]
    expected = {"collect-validation": "complete"}
    actual = {}
    for record in manifest.get("phase_jobs", []):
        stage, pair = record.get("stage"), record.get("pair")
        if stage in ("collect-validation", "evaluate-validation", "evaluate-development"):
            key = (stage, pair)
            if key in actual or pair not in PAIRS:
                raise ValueError("Primary controller has duplicate or unexpected endpoint jobs.")
            actual[key] = record.get("status")
    for stage in ("collect-validation", "evaluate-validation", "evaluate-development"):
        for pair in PAIRS:
            status = actual.get((stage, pair))
            if stage == "collect-validation":
                wanted = "complete"
            else:
                wanted = "skipped_ineligible" if choices[pair].get("status") == "ineligible" else "complete"
            if status != wanted:
                raise ValueError("Primary controller lacks all-six terminal validation/development outcomes.")
    return {"path": path, "manifest": manifest, "manifest_sha256": sha_file(manifest_path),
        "study_root": study_root, "binding": binding, "selection": selection,
        "scorer_binding": scorer_binding, "selection_sha256": sha_file(selection_path)}


def copy_fixture_support(support_root: Path, output: Path) -> dict:
    support_root = inside_results(support_root)
    expected = {"fixture.jsonl": FIXTURE_SHA256, "rubric.md": RUBRIC_SHA256,
                "fixture-review.json": FIXTURE_REVIEW_SHA256,
                "execution-copy-provenance.json": FIXTURE_COPY_PROVENANCE_SHA256}
    copied = output / "support"
    copied.mkdir(parents=True, exist_ok=False)
    receipt = {}
    for name, wanted in expected.items():
        source = inside_results(support_root / name)
        raw = source.read_bytes()
        digest = sha_bytes(raw)
        if digest != wanted:
            raise ValueError("Reviewed fixture support copy differs from its frozen SHA-256.")
        destination = copied / name
        with destination.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        receipt[name] = {"sha256": digest, "bytes": len(raw),
                         "relative_path": destination.relative_to(output).as_posix()}
    return receipt


def save_json(path: Path, value: dict, *, exclusive: bool = False) -> None:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    if exclusive:
        with path.open("xb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    else:
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)


def inside_results(path: Path, *, fresh: bool = False) -> Path:
    path = Path(path).resolve()
    if RESULTS not in path.parents:
        raise ValueError("Study inputs and outputs must be children of evaluation/results.")
    if fresh and path.exists():
        raise FileExistsError("Refusing to reuse an existing study path.")
    return path


def current_revision() -> str:
    result = subprocess.run(["git", "-c", f"safe.directory={ROOT.as_posix()}", "rev-parse", "HEAD"],
                            cwd=ROOT, check=True, capture_output=True, text=True)
    value = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError("Git HEAD is not a full object ID.")
    return value


def load_caller():
    path = ROOT / "evaluation/evaluate-contextual-cascade.py"
    spec = importlib.util.spec_from_file_location("contextual_cascade_caller", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot import the frozen contextual cascade caller.")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def validate_fixture_pair_output(*, output_dir: Path, pair: str, eligible: bool,
                                 expected_binding: dict, cases: list[dict],
                                 presence_identity: dict, decision_threshold: float) -> dict:
    """Validate the existing fixture scorer's binding and raw evidence without rescoring policy."""
    output_dir = Path(output_dir)
    binding_path = output_dir / "binding.json"
    binding = read_json(binding_path)
    for key, expected in expected_binding.items():
        if binding.get(key) != expected:
            raise ValueError("Fixture pair binding differs from the frozen primary/support receipt.")
    if not eligible:
        skipped_path = output_dir / "skipped.json"
        skipped = read_json(skipped_path)
        if skipped != {**binding, "status": "skipped_ineligible"}:
            raise ValueError("Ineligible fixture pair lacks its exact frozen skip receipt.")
        raw_dir = output_dir / "raw"
        if raw_dir.exists() and list(raw_dir.glob("*.json")):
            raise ValueError("An ineligible fixture pair unexpectedly performed runtime inference.")
        return {"status": "skipped_ineligible", "report_sha256": sha_file(skipped_path)}

    report_path = output_dir / "report.json"
    report = read_json(report_path)
    case_ids = [case.get("case_id") for case in cases]
    if ({key: report.get(key) for key in expected_binding} != expected_binding
            or report.get("status") != "complete" or report.get("errors") != []
            or report.get("rows") != 48 or len(case_ids) != 48
            or report.get("pair") != pair
            or report.get("decision_threshold") != decision_threshold):
        raise ValueError("Fixture score report is incomplete or not bound to the fixed pair.")
    predictions_path = output_dir / "predictions.json"
    predictions = json.loads(predictions_path.read_text(encoding="utf-8"))
    if not isinstance(predictions, list) or len(predictions) != 48:
        raise ValueError("Fixture predictions are missing or have the wrong row count.")
    ids = [row.get("case", {}).get("case_id") for row in predictions]
    if len(set(ids)) != 48 or set(ids) != set(case_ids) or report.get("predictions_sha256") != sha_file(predictions_path):
        raise ValueError("Fixture prediction identities/hash differ from reviewed cases.")
    raw_dir = output_dir / "raw"
    expected_names = {f"{tag}-{hashlib.sha256(case_id.encode()).hexdigest()}.json"
                      for tag in ("ordinary", "gated") for case_id in case_ids}
    raw_paths = sorted(raw_dir.glob("*.json"))
    actual_raw_hashes = {path.name: sha_file(path) for path in raw_paths}
    if set(actual_raw_hashes) != expected_names or report.get("raw_rpc_sha256") != actual_raw_hashes:
        raise ValueError("Fixture raw RPC evidence is incomplete or differs from report hashes.")
    result_path = container_path(output_dir)
    prediction_by_id = {row["case"]["case_id"]: row for row in predictions}
    if any(prediction_by_id[case["case_id"]].get("case") != case for case in cases):
        raise ValueError("Fixture prediction annotations differ from the frozen reviewed cases.")
    if len([case for case in cases if case.get("visibility_hint") is not None]) != 4:
        raise ValueError("Fixture case list differs from the fixed four visibility-hint contract.")
    verifier = load_caller()
    for case in cases:
        case_id = case["case_id"]
        row_hash = hashlib.sha256(case_id.encode()).hexdigest()
        for tag in ("ordinary", "gated"):
            record = read_json(raw_dir / f"{tag}-{row_hash}.json")
            request_id = "cascade-" + hashlib.sha256(
                f"cascade-{result_path}-{tag}-{case_id}".encode()).hexdigest()[:48]
            request = record.get("request", {})
            response = record.get("response", {})
            if (request.get("request_id") != request_id
                    or response.get("request_id") != request_id
                    or request.get("text") != case.get("text")
                    or request.get("visibility_hint") != case.get("visibility_hint")
                    or not re.fullmatch(r"[0-9a-f]{64}", record.get("request_binary_sha256", ""))):
                raise ValueError("Fixture raw request/response is not bound to the reviewed case.")
            gate_request = request.get("semantic_presence_gate")
            if tag == "gated":
                if (not isinstance(gate_request, dict)
                        or gate_request.get("model_id") != presence_identity["model_id"]
                        or gate_request.get("threshold") != decision_threshold):
                    raise ValueError("Fixture gated request differs from the selected profile/threshold.")
            elif gate_request is not None:
                raise ValueError("Ordinary fixture request unexpectedly includes a presence gate.")
            if response.get("error") or not isinstance(response.get("layers"), list):
                raise ValueError("Fixture raw response contains an error or lacks layers.")
            for layer in response["layers"]:
                status = str(layer.get("status", ""))
                kind = str(layer.get("layer", "")).lower()
                error = layer.get("error")
                if status.lower() == "error" or status.upper().endswith("_ERROR"):
                    raise ValueError("Fixture raw response contains a runtime layer error.")
                if status == "skipped":
                    if (not (kind.endswith("_ner") or kind.endswith("_semantic"))
                            or error != "Skipped after regex returned BLOCK."):
                        raise ValueError("Fixture raw response contains an undocumented skipped layer.")
                elif error:
                    raise ValueError("Fixture raw response contains a runtime layer error.")

            # The existing scorer only normalizes the layer enum and the two gate enums.
            normalized = json.loads(json.dumps(response, allow_nan=False))
            for layer in normalized["layers"]:
                kind = layer.get("layer")
                if isinstance(kind, str):
                    upper = kind.upper()
                    layer["layer"] = next((value for suffix, value in
                        (("_REGEX", "regex"), ("_NER", "ner"), ("_SEMANTIC", "semantic"))
                        if upper.endswith(suffix)), kind)
                trace = layer.get("semantic_presence_gate")
                if isinstance(trace, dict):
                    status = trace.get("status")
                    if isinstance(status, str):
                        upper = status.upper()
                        if upper.endswith("_APPLIED"):
                            trace["status"] = "applied"
                        elif upper.endswith("_NOT_RUN"):
                            trace["status"] = "not_run"
                        elif upper.endswith("_ERROR"):
                            trace["status"] = "error"
                    label = trace.get("predicted_label")
                    if isinstance(label, str):
                        upper = label.upper()
                        if upper.endswith("_PRESENT"):
                            trace["predicted_label"] = "present"
                        elif upper.endswith("_ABSENT"):
                            trace["predicted_label"] = "absent"
                        elif upper.endswith("_UNSPECIFIED"):
                            trace["predicted_label"] = "unspecified"
            prediction = prediction_by_id[case_id][tag]
            if ({k: v for k, v in normalized.items() if k != "layers"}
                    != {k: v for k, v in prediction.items() if k != "layers"}
                    or normalized["layers"] != prediction.get("layers")):
                raise ValueError("Fixture prediction differs from its normalized raw RPC response.")
            if tag == "gated":
                semantic_identity = expected_binding["study_binding"]["controls"][
                    pair.split("-", 1)[0]]["identity"]
                verified_trace = verifier.verify_live(
                    prediction_by_id[case_id]["ordinary"], prediction_by_id[case_id]["gated"],
                    {"semantic": semantic_identity, "presence": presence_identity}, decision_threshold)
                if verified_trace != prediction_by_id[case_id].get("trace"):
                    raise ValueError("Fixture prediction trace differs from the verified gated response.")
            if tag == "gated":
                semantic = next((layer for layer in response["layers"]
                                 if str(layer.get("layer", "")).upper().endswith("SEMANTIC")), None)
                trace = semantic.get("semantic_presence_gate") if semantic else None
                status = str(trace.get("status", "")).lower() if isinstance(trace, dict) else ""
                trace_applied = status == "applied" or status.endswith("_applied")
                trace_not_run = status == "not_run" or status.endswith("_not_run")
                if (not isinstance(trace, dict) or trace.get("model_id") != presence_identity["model_id"]
                        or trace.get("decision_threshold") != decision_threshold
                        or not (trace_applied or trace_not_run)):
                    raise ValueError("Fixture gate response differs from the frozen profile/threshold.")
                if trace_applied:
                    if (trace.get("model_threshold") != presence_identity["threshold"]
                            or any(trace.get(key) != value for key, value in presence_identity.items()
                                   if key != "threshold")):
                        raise ValueError("Fixture gate response presence identity is not the selected artifact.")
    return {"status": "complete", "report_sha256": sha_file(report_path),
            "predictions_sha256": sha_file(predictions_path), "raw_rpc_count": len(raw_paths)}


def container_path(path: Path) -> str:
    return "/workspace/evaluation/results/" + Path(path).resolve().relative_to(RESULTS).as_posix()


def safe_error(exc: Exception) -> dict:
    return {"error_type": type(exc).__name__, "error_sha256": sha_bytes(str(exc).encode("utf-8"))}


def validate_frozen_inputs(*, fit_root: Path, fit_source_revision: str,
                           original_artifact: Path, current_artifact: Path,
                           validation_file: Path, development_file: Path,
                           protocol_file: Path, protocol_sha256: str,
                           source_revision: str, verify_current_revision: bool = True) -> dict:
    caller = load_caller()
    if verify_current_revision and current_revision() != source_revision:
        raise ValueError("Current source revision differs from the requested execution revision.")
    if protocol_sha256 != CASCADE_PROTOCOL_SHA256 or sha_file(protocol_file) != protocol_sha256:
        raise ValueError("Cascade protocol differs from its frozen SHA-256.")
    fit_root = inside_results(fit_root)
    for path in (original_artifact, current_artifact, validation_file, development_file, protocol_file):
        inside_results(path)
    # Validate fit bytes and selected artifact identities without host-side float replay.
    from privoke_model.artifact import load_artifact
    from privoke_eval.presence_evidence import artifact_identity
    from privoke_model.fingerprint import parameter_fingerprint
    fit_manifest_path = fit_root / "run-manifest.json"
    fit = read_json(fit_manifest_path)
    if (fit.get("status") != "complete" or fit.get("source_revision") != fit_source_revision
            or fit.get("protocol_sha256") != caller.FIT_PROTOCOL
            or fit.get("selections_frozen_before_development_scoring") is not True
            or fit.get("errors") not in (None, [])
            or set(fit.get("profiles", {})) != set(PROFILES)):
        raise ValueError("Presence fit is incomplete or has a wrong source/protocol/profile set.")
    presence = {}
    for profile in PROFILES:
        selection_path = fit_root / "profiles" / profile / "selection.json"
        selection = read_json(selection_path)
        if selection != fit["profiles"][profile] or selection.get("status") != "selected":
            raise ValueError("Frozen profile selection differs from its fit manifest.")
        artifact_path = (fit_root / selection["selected_artifact_file"]).resolve()
        if fit_root.resolve() not in artifact_path.parents or sha_file(artifact_path) != selection.get("selected_artifact_sha256"):
            raise ValueError("Frozen profile artifact path/hash mismatch.")
        artifact = load_artifact(artifact_path)
        identity = artifact_identity(artifact)
        if (artifact.get("model_id") != f"privoke-presence-{profile}"
                or artifact.get("config", {}).get("profile") != profile
                or artifact.get("metadata", {}).get("source_revision") != fit_source_revision
                or artifact.get("metadata", {}).get("protocol_sha256") != caller.FIT_PROTOCOL
                or selection.get("source_revision") != fit_source_revision
                or selection.get("protocol_sha256") != caller.FIT_PROTOCOL
                or selection.get("artifact_identity") != identity):
            raise ValueError("Frozen presence artifact identity/profile mismatch.")
        presence[profile] = {"identity": identity, "file_sha256": sha_file(artifact_path),
            "artifact_bytes": artifact_path.stat().st_size,
            "parameter_count": sum(len(v["values"]) for v in artifact["parameters"].values()),
            "word_features": len(artifact["config"]["branches"]["word"]["features"]),
            "char_features": len(artifact["config"]["branches"]["char"]["features"]),
            "artifact_path": str(artifact_path), "artifact": artifact}
    controls = {}
    for name, path in (("original", original_artifact), ("current", current_artifact)):
        artifact = load_artifact(path)
        if (artifact.get("checksum") != caller.CHECKSUMS[name]
                or artifact.get("model_id") != "privoke-balanced"
                or artifact.get("architecture") != "privoke_tiny_transformer_v1"):
            raise ValueError("Contextual control artifact identity mismatch.")
        controls[name] = {"path": str(Path(path).resolve()), "file_sha256": sha_file(path),
                          "identity": caller.contextual_identity(artifact), "artifact": artifact}
    validation = caller.dataset(validation_file, "validation")
    development = caller.dataset(development_file, "development")
    return {"caller": caller, "fit_root": fit_root, "fit_manifest_sha256": sha_file(fit_manifest_path),
        "fit": fit, "presence": presence, "controls": controls,
        "datasets": {"validation": validation, "development": development},
        "dataset_hashes": {"validation": sha_file(validation_file), "development": sha_file(development_file)},
        "paths": {"validation": str(Path(validation_file).resolve()),
                  "development": str(Path(development_file).resolve())},
        "source_revision": source_revision, "fit_source_revision": fit_source_revision,
        "protocol_sha256": protocol_sha256, "protocol_file": str(protocol_file.resolve())}


class DockerBackend:
    """Fixed Compose and model-admin boundary; callers never construct shell commands."""
    def __init__(self, output: Path, *, env: dict[str, str] | None = None):
        self.output = output
        self.env = dict(os.environ if env is None else env)
        self.calls: list[dict] = []
        self.job_images: set[str] = set()
        self.jobs: list[dict] = []
        self.admin_mutation_outcome_unknown = False
        self.evaluator_job_outcome_unknown = False
        self.runtime_cache_ttl_seconds = 1.0
        self._last_named_job_removed = False

    def call(self, args: list[str], *, data: bytes | None = None, direct: bool = False,
             timeout: int = 180, admin_mutation: bool = False) -> str:
        argv = list(args) if direct else COMPOSE + list(args)
        try:
            result = subprocess.run(argv, cwd=ROOT, env=self.env, input=data,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if admin_mutation:
                self.admin_mutation_outcome_unknown = True
            self.calls.append({"argv": argv, "returncode": None, "timed_out": True,
                "stdout_sha256": sha_bytes(exc.output or b""), "stderr_sha256": sha_bytes(exc.stderr or b""),
                "admin_mutation": admin_mutation})
            raise
        out, err = result.stdout or b"", result.stderr or b""
        self.calls.append({"argv": argv, "returncode": result.returncode,
                           "stdout_sha256": sha_bytes(out), "stderr_sha256": sha_bytes(err),
                           "admin_mutation": admin_mutation})
        if result.returncode:
            if admin_mutation:
                self.admin_mutation_outcome_unknown = True
            raise RuntimeError(f"Command failed with exit {result.returncode}; stderr sha256={sha_bytes(err)}")
        return out.decode("utf-8").strip()

    def _assert_mutations_safe(self) -> None:
        if self.admin_mutation_outcome_unknown or self.evaluator_job_outcome_unknown:
            raise RuntimeError("A prior remote operation is unresolved; model writes are stopped.")

    def _quiesce_named_job(self, name: str) -> bool:
        """Remove only this invocation's named one-off and verify it is absent."""
        self._last_named_job_removed = False
        try:
            ids = self.call(["docker", "ps", "--all", "--quiet", "--filter", f"name=^{name}$"], direct=True).splitlines()
            if any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in ids):
                return False
            for item in ids:
                self.call(["docker", "rm", "-f", item], direct=True, timeout=30)
            remaining = self.call(["docker", "ps", "--all", "--quiet", "--filter", f"name=^{name}$"], direct=True).splitlines()
            self._last_named_job_removed = bool(ids) and not remaining
            return not remaining
        except Exception:
            return False

    def ensure_services(self) -> None:
        for service in ("client-runtime", "model-streaming-service", "param-update-service"):
            ids = self.call(["ps", "--status", "running", "--quiet", service]).splitlines()
            if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
                raise ValueError("Required existing Compose service is not running exactly once.")
            state = json.loads(self.call(["docker", "inspect", "--format", "{{json .State}}", ids[0]], direct=True))
            if state.get("Running") is not True or state.get("Status") != "running":
                raise ValueError("Required existing Compose service is not running.")
            if state.get("Health") and state["Health"].get("Status") != "healthy":
                raise ValueError("Required existing Compose service is not healthy.")
        runtime_ids = self.call(["ps", "--all", "--quiet", "client-runtime"]).splitlines()
        runtime_env = json.loads(self.call(["docker", "inspect", "--format", "{{json .Config.Env}}", runtime_ids[0]], direct=True))
        ttl_text = next((item.split("=", 1)[1] for item in runtime_env
                         if isinstance(item, str) and item.startswith("MODEL_STREAMING_CACHE_TTL_SECONDS=")), "1.0")
        try:
            ttl = float(ttl_text)
        except (TypeError, ValueError) as exc:
            raise ValueError("Runtime cache TTL is invalid.") from exc
        if not math.isfinite(ttl) or ttl < 0 or ttl > 60:
            raise ValueError("Runtime cache TTL is outside the bounded probe window.")
        self.runtime_cache_ttl_seconds = ttl
        updater = self.call(["ps", "--all", "--quiet", "param-update-service"]).splitlines()
        env = json.loads(self.call(["docker", "inspect", "--format", "{{json .Config.Env}}", updater[0]], direct=True)) if len(updater) == 1 else []
        if "FUZZER_PROMPT_COUNT=0" not in env:
            raise ValueError("Existing parameter updater is not configured with startup training disabled.")
        for writer in ("presence-fuzzer", "presence-update-service"):
            if self.call(["ps", "--status", "running", "--quiet", writer]).splitlines():
                raise ValueError("A presence training/update writer is running during the cascade study.")

    def images(self) -> dict:
        result = {}
        for service in ("client-runtime", "model-streaming-service", "param-update-service"):
            ids = self.call(["ps", "--all", "--quiet", service]).splitlines()
            if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
                raise ValueError("Compose must expose exactly one container for each fixed service.")
            image = self.call(["docker", "inspect", "--format", "{{.Image}}", ids[0]], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
                raise ValueError("Service did not expose an immutable image ID.")
            result[service] = image
        return result

    def evaluator_image(self) -> str:
        config = json.loads(self.call(["config", "--format", "json"]))
        service = config.get("services", {}).get("evaluation-tests")
        project = config.get("name")
        if not isinstance(service, dict) or not isinstance(project, str) or not project:
            raise ValueError("Compose did not resolve the fixed evaluation service image.")
        image_ref = service.get("image") or f"{project}-evaluation-tests"
        if not isinstance(image_ref, str) or not image_ref:
            raise ValueError("Compose evaluation image reference is invalid.")
        image_id = self.call(["docker", "image", "inspect", "--format", "{{.Id}}", image_ref], direct=True)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("Prebuilt evaluation image is unavailable or did not expose an immutable ID.")
        return image_id

    def read_raw(self, model_id: str) -> bytes:
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed four-file catalog allowlist.")
        record = json.loads(self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_READ, model_id]))
        if record.get("exists") is not True:
            raise FileNotFoundError("A required frozen catalog artifact is missing.")
        return base64.b64decode(record["raw_b64"], validate=True)

    def write_artifact(self, artifact: dict, *, expected_checksum: str) -> None:
        self._assert_mutations_safe()
        model_id = artifact.get("model_id")
        if model_id not in CATALOG_IDS or artifact.get("checksum") != expected_checksum:
            raise ValueError("Artifact is outside the fixed model/checksum allowlist.")
        payload = (json.dumps(artifact, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"), allow_nan=False) + "\n").encode()
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_INSTALL,
                   model_id, expected_checksum], data=payload, admin_mutation=True)
        current = self.read_raw(model_id)
        if json.loads(current) != artifact:
            raise ValueError("Installed model differs from the selected frozen artifact.")

    def restore_exact(self, model_id: str, raw: bytes) -> None:
        self._assert_mutations_safe()
        if model_id not in CATALOG_IDS:
            raise ValueError("Model ID is outside the fixed four-file catalog allowlist.")
        self.call(["exec", "-T", "param-update-service", "python", "-c", ADMIN_RESTORE, model_id],
                  data=raw, admin_mutation=True)

    def probe(self, expected: dict) -> None:
        payload = json.dumps({**expected, "_probe_retry_seconds": max(10.0, self.runtime_cache_ttl_seconds + 2.0)}, sort_keys=True).encode()
        observed = json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", IDENTITY_PROBE], data=payload, timeout=90))
        if observed != expected:
            raise ValueError("Runtime identity probe differs from the frozen model pair.")

    def preflight_fit(self, *, inputs: dict, binding: dict, output: Path) -> dict:
        receipt = output / "linux-fit-preflight.json"
        args = ["run", "--rm", "--no-deps", "-T", "evaluation-tests", "python", "-c", FIT_PREFLIGHT,
            container_path(inputs["fit_root"]), binding["fit_source_revision"],
            container_path(Path(inputs["controls"]["original"]["path"])),
            container_path(Path(inputs["controls"]["current"]["path"])),
            binding["source_revision"], binding["protocol_sha256"], binding["runtime_image_id"],
            binding["evaluator_image_id"], container_path(receipt)]
        self.call(args, timeout=600)
        value = read_json(receipt)
        expected = {"source_revision": binding["source_revision"],
            "fit_source_revision": binding["fit_source_revision"],
            "protocol_sha256": binding["protocol_sha256"],
            "fit_protocol_sha256": binding["fit_protocol_sha256"],
            "fit_manifest_sha256": binding["fit_manifest_sha256"],
            "runtime_image_id": binding["runtime_image_id"],
            "evaluator_image_id": binding["evaluator_image_id"], "target": binding["target"],
            "caller_sha256": binding["caller_sha256"],
            "controls": binding["controls"], "presence": binding["presence"],
            "datasets": binding["datasets"]}
        # The evaluator sees mounted /workspace paths; compare every identity/hash field,
        # while the host binding retains its native absolute locators.
        observed = dict(value)
        for name in CONTROLS:
            if name in observed.get("controls", {}):
                observed["controls"][name].pop("path", None)
        expected["controls"] = {k: {kk: vv for kk, vv in v.items() if kk != "path"}
                                 for k, v in expected["controls"].items()}
        if observed != expected:
            raise ValueError("Linux strict fit preflight differs from host hash-bound identity.")
        return {"sha256": sha_file(receipt), "binding": observed}

    def run_stage(self, *, stage: str, pair: str | None, study_root: Path,
                  inputs: dict, binding: dict, output: Path) -> dict:
        name = f"cascade-{output.name}-{uuid.uuid4().hex[:8]}"
        args = ["run", "-d", "--no-deps", "-T", "--name", name,
                "evaluation-tests", "python", "/workspace/evaluation/evaluate-contextual-cascade.py",
                "--phase", stage, "--study-root", container_path(study_root),
                "--fit-root", container_path(inputs["fit_root"]),
                "--original-artifact", container_path(Path(inputs["controls"]["original"]["path"])),
                "--current-artifact", container_path(Path(inputs["controls"]["current"]["path"])),
                "--validation-file", container_path(Path(inputs["paths"]["validation"])),
                "--development-file", container_path(Path(inputs["paths"]["development"])),
                "--source-revision", binding["source_revision"],
                "--fit-source-revision", binding["fit_source_revision"],
                "--protocol-sha256", binding["protocol_sha256"],
                "--runtime-image-id", binding["runtime_image_id"],
                "--evaluator-image-id", binding["evaluator_image_id"],
                "--target", "client-runtime:50054", "--protocol-file", container_path(Path(inputs["protocol_file"]))]
        if pair:
            control, profile = pair.split("-", 1)
            args += ["--control", control, "--profile", profile]
        return self._job(args, name=name, stage=stage, pair=pair, study_root=study_root, output=output)

    def run_fixture_preflight(self, *, primary_root: Path, validation_file: Path,
                              support: dict, receipt: Path, output: Path) -> dict:
        name = f"cascade-{output.name}-fixture-preflight-{uuid.uuid4().hex[:8]}"
        args = ["run", "-d", "--no-deps", "-T", "--name", name,
            "evaluation-tests", "python", "-c", FIXTURE_PREFLIGHT,
            container_path(primary_root), container_path(validation_file),
            container_path(output / support["fixture.jsonl"]["relative_path"]),
            container_path(output / support["rubric.md"]["relative_path"]),
            container_path(output / support["fixture-review.json"]["relative_path"]),
            container_path(receipt)]
        return self._job(args, name=name, stage="fixture-preflight", pair=None,
            study_root=primary_root, output=output,
            result_reader=lambda: {"status": "frozen_study_verified", "receipt": read_json(receipt),
                                   "report_sha256": sha_file(receipt)})

    def run_fixture_stage(self, *, primary_root: Path, validation_file: Path,
                          support: dict, pair: str, output_dir: Path,
                          expected_binding: dict, eligible: bool, cases: list[dict],
                          presence_identity: dict, decision_threshold: float | None,
                          source_revision: str, runtime_image_id: str,
                          evaluator_image_id: str, output: Path) -> dict:
        name = f"cascade-{output.name}-fixture-{pair}-{uuid.uuid4().hex[:8]}"
        if Path(output_dir).exists():
            raise FileExistsError("Refusing reused fixture pair output.")
        args = ["run", "-d", "--no-deps", "-T", "--name", name,
            "evaluation-tests", "python", "/workspace/evaluation/evaluate-contextual-regressions.py",
            "--study-root", container_path(primary_root),
            "--validation-file", container_path(validation_file),
            "--case-file", container_path(output / support["fixture.jsonl"]["relative_path"]),
            "--rubric-file", container_path(output / support["rubric.md"]["relative_path"]),
            "--fixture-review-file", container_path(output / support["fixture-review.json"]["relative_path"]),
            "--output-dir", container_path(output_dir), "--control", pair.split("-", 1)[0],
            "--profile", pair.split("-", 1)[1], "--source-revision", source_revision,
            "--runtime-image-id", runtime_image_id, "--evaluator-image-id", evaluator_image_id,
            "--target", "client-runtime:50054"]
        return self._job(args, name=name, stage="fixture-score", pair=pair,
            study_root=primary_root, output=output,
            result_reader=lambda: validate_fixture_pair_output(output_dir=output_dir, pair=pair,
                eligible=eligible, expected_binding=expected_binding, cases=cases,
                presence_identity=presence_identity, decision_threshold=decision_threshold))

    def _job(self, args: list[str], *, name: str, stage: str, pair: str | None,
             study_root: Path, output: Path, result_reader=None) -> dict:
        try:
            container = self.call(args, timeout=120)
        except Exception as exc:
            quiescent = self._quiesce_named_job(name)
            if (not quiescent or isinstance(exc, subprocess.TimeoutExpired) and not self._last_named_job_removed):
                self.evaluator_job_outcome_unknown = True
            raise
        if not re.fullmatch(r"[0-9a-f]{12,64}", container):
            quiescent = self._quiesce_named_job(name)
            if not quiescent or not self._last_named_job_removed:
                self.evaluator_job_outcome_unknown = True
            raise ValueError("Compose did not return the one-off evaluator container ID.")
        record = {"container_id": container, "stage": stage, "pair": pair,
                  "image_id": None, "exit_code": None, "logs_sha256": None}
        active_error = None
        try:
            record["image_id"] = self.call(["docker", "inspect", "--format", "{{.Image}}", container], direct=True)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", record["image_id"]):
                raise ValueError("Evaluator job did not expose an immutable image ID.")
            expected_image = self.env.get("CASCADE_EXPECTED_EVALUATOR_IMAGE_ID")
            if expected_image and record["image_id"] != expected_image:
                raise ValueError("Evaluator job image differs from the frozen preflight image.")
            self.job_images.add(record["image_id"])
            record["exit_code"] = int(self.call(["docker", "wait", container], direct=True, timeout=1400))
            logs = self.call(["docker", "logs", container], direct=True, timeout=30)
            record["logs_sha256"] = sha_bytes(logs.encode())
            if record["exit_code"]:
                raise RuntimeError("Evaluator stage exited unsuccessfully.")
        except Exception as exc:
            active_error = exc
        finally:
            if not self._quiesce_named_job(name):
                self.evaluator_job_outcome_unknown = True
                if active_error is None:
                    active_error = RuntimeError("Named evaluator container could not be proven quiescent.")
            self.jobs.append(record)
        if active_error:
            raise active_error
        if result_reader is not None:
            return {**result_reader(), **record}
        if stage == "calibrate":
            selection = read_json(study_root / "calibration/selection.json")
            return {"status": selection.get("status"), "choices": selection.get("choices"), **record}
        assert pair is not None
        pair_dir = study_root / stage / pair
        skipped = pair_dir / "skipped.json"
        if skipped.is_file():
            return {"status": read_json(skipped).get("status"), **record}
        report = read_json(pair_dir / "report.json")
        if report.get("status") != "complete" or report.get("pair") != pair or report.get("stage") != stage:
            raise ValueError("Evaluator stage report is incomplete or mismatched.")
        return {"status": report["status"], "report_sha256": sha_file(pair_dir / "report.json"), **record}


def make_binding(inputs: dict, runtime_image_id: str, evaluator_image_id: str) -> dict:
    return {"source_revision": inputs["source_revision"],
        "fit_source_revision": inputs["fit_source_revision"],
        "protocol_sha256": inputs["protocol_sha256"],
        "fit_protocol_sha256": inputs["caller"].FIT_PROTOCOL,
        "fit_manifest_sha256": inputs["fit_manifest_sha256"],
        "controls": {name: {key: value[key] for key in ("path", "file_sha256", "identity")}
                     for name, value in inputs["controls"].items()},
        "presence": {name: {key: value[key] for key in
                            ("identity", "file_sha256", "artifact_bytes", "parameter_count", "word_features", "char_features")}
                     for name, value in inputs["presence"].items()},
        "runtime_image_id": runtime_image_id, "evaluator_image_id": evaluator_image_id,
        "caller_sha256": sha_file(ROOT / "evaluation/evaluate-contextual-cascade.py"),
        "target": "client-runtime:50054",
        "datasets": {name: list(value) for name, value in inputs["caller"].DATA.items()}}


def check_prior_catalog(raws: dict[str, bytes], inputs: dict) -> dict[str, dict]:
    from privoke_model.artifact import validate_artifact
    from privoke_eval.presence_evidence import artifact_identity
    decoded = {}
    for model_id, raw in raws.items():
        artifact = json.loads(raw.decode("utf-8"))
        if not isinstance(artifact, dict) or artifact.get("model_id") != model_id:
            raise ValueError("Existing catalog bytes have a mismatched model ID.")
        validate_artifact(artifact)
        decoded[model_id] = artifact
    contextual = decoded["privoke-balanced"]
    if contextual.get("checksum") != CONTEXT_CHECKSUMS["current"]:
        raise ValueError("Runtime does not begin at the exact selected current contextual checksum.")
    for profile in PROFILES:
        model_id = PRESENCE_IDS[profile]
        if artifact_identity(decoded[model_id]) != inputs["presence"][profile]["identity"]:
            raise ValueError("Installed presence artifact differs from its frozen fit profile.")
    return decoded


def write_backups(output: Path, raws: dict[str, bytes]) -> dict:
    folder = output / "private-backups"
    folder.mkdir(parents=True, exist_ok=False)
    records = {}
    for model_id in CATALOG_IDS:
        raw = raws[model_id]
        path = folder / f"{model_id}.json.b64"
        payload = base64.b64encode(raw) + b"\n"
        with path.open("xb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        records[model_id] = {"relative_path": path.relative_to(output).as_posix(),
                             "raw_sha256": sha_bytes(raw), "backup_sha256": sha_bytes(payload),
                             "bytes": len(raw)}
    return records


def _persist(output: Path, state: dict) -> None:
    save_json(output / "study-run-manifest.json", state)


def _record_job(output: Path, state: dict, stage: str, pair: str | None, result: dict) -> None:
    state["phase_jobs"].append({"stage": stage, "pair": pair, **{k: result[k] for k in
        ("status", "report_sha256", "container_id", "image_id", "exit_code", "logs_sha256") if k in result}})
    _persist(output, state)


def _run_group(*, backend, output: Path, study_root: Path, inputs: dict,
               binding: dict, state: dict, stage: str, control: str,
               prior_raw: dict[str, bytes], choices: dict | None = None) -> None:
    target_context = inputs["controls"][control]
    current_identity = inputs["controls"]["current"]["identity"]
    backend.write_artifact(target_context["artifact"], expected_checksum=target_context["artifact"]["checksum"])
    try:
        for profile in PROFILES:
            pair = f"{control}-{profile}"
            choice = (choices or {}).get(pair)
            ineligible = stage in ("evaluate-validation", "evaluate-development") and choice and choice.get("status") == "ineligible"
            presence = inputs["presence"][profile]
            if not ineligible:
                backend.write_artifact(presence["artifact"], expected_checksum=presence["identity"]["artifact_checksum"])
                backend.probe({"context": target_context["identity"], "presence": presence["identity"]})
            result = backend.run_stage(stage=stage, pair=pair, study_root=study_root,
                                       inputs=inputs, binding=binding, output=output)
            if stage == "collect-validation" and result.get("status") != "complete":
                raise ValueError("A validation collection did not complete successfully.")
            if stage in ("evaluate-validation", "evaluate-development"):
                expected = "skipped_ineligible" if ineligible else "complete"
                if result.get("status") != expected:
                    raise ValueError("A selected endpoint differs from frozen eligibility.")
            _record_job(output, state, stage, pair, result)
    finally:
        if not backend.admin_mutation_outcome_unknown and not getattr(backend, "evaluator_job_outcome_unknown", False):
            backend.restore_exact("privoke-balanced", prior_raw["privoke-balanced"])
            if not backend.admin_mutation_outcome_unknown:
                if sha_bytes(backend.read_raw("privoke-balanced")) != state["prior_sha256"]["privoke-balanced"]:
                    raise ValueError("Contextual control bytes did not restore at checkpoint.")
                backend.probe({"context": current_identity,
                               "presence": inputs["presence"][PROFILES[-1]]["identity"]})


def _run_fixture_group(*, backend, output: Path, primary_root: Path, inputs: dict,
                       state: dict, plan: dict, control: str,
                       prior_raw: dict[str, bytes]) -> None:
    context = inputs["controls"][control]
    current_identity = inputs["controls"]["current"]["identity"]
    backend.write_artifact(context["artifact"], expected_checksum=context["artifact"]["checksum"])
    try:
        for profile in PROFILES:
            pair = f"{control}-{profile}"
            choice = plan["selection"]["choices"][pair]
            if choice.get("status") not in ("eligible", "ineligible"):
                raise ValueError("Primary selection contains an unsupported fixture eligibility state.")
            eligible = choice["status"] == "eligible"
            decision_threshold = None
            if eligible:
                selected = choice.get("chosen")
                decision_threshold = selected.get("threshold") if isinstance(selected, dict) else None
                if (type(decision_threshold) not in (int, float) or not math.isfinite(decision_threshold)
                        or not 0 <= decision_threshold <= 1):
                    raise ValueError("Eligible fixture pair lacks its finite frozen decision threshold.")
                presence = inputs["presence"][profile]
                backend.write_artifact(presence["artifact"],
                    expected_checksum=presence["identity"]["artifact_checksum"])
                state["installed_presence_profile"] = profile
                backend.probe({"context": context["identity"], "presence": presence["identity"]})
            state["phase"] = f"fixtures:{pair}"; _persist(output, state)
            result = backend.run_fixture_stage(primary_root=primary_root,
                validation_file=Path(plan["validation_file"]), support=plan["support"], pair=pair,
                output_dir=output / "pairs" / pair,
                expected_binding=plan["pair_bindings"][pair], eligible=eligible,
                cases=plan["case_rows"],
                presence_identity=inputs["presence"][profile]["identity"],
                decision_threshold=decision_threshold,
                source_revision=plan["source_revision"],
                runtime_image_id=plan["runtime_image_id"],
                evaluator_image_id=plan["evaluator_image_id"], output=output)
            expected_status = "complete" if eligible else "skipped_ineligible"
            if result.get("status") != expected_status:
                raise ValueError("Fixture score result differs from the frozen primary eligibility.")
            _record_job(output, state, "fixture-score", pair, result)
    finally:
        if not backend.admin_mutation_outcome_unknown and not getattr(backend, "evaluator_job_outcome_unknown", False):
            backend.restore_exact("privoke-balanced", prior_raw["privoke-balanced"])
            if not backend.admin_mutation_outcome_unknown:
                if sha_bytes(backend.read_raw("privoke-balanced")) != state["prior_sha256"]["privoke-balanced"]:
                    raise ValueError("Contextual control bytes did not restore at fixture checkpoint.")
                profile = state["installed_presence_profile"]
                backend.probe({"context": current_identity,
                               "presence": inputs["presence"][profile]["identity"]})
                state.setdefault("fixture_readiness_checks", []).append({
                    "control": control, "context_checksum": current_identity["artifact_checksum"],
                    "presence_profile": profile, "status": "verified"})
                _persist(output, state)


def run_sequence(*, backend, output: Path, study_root: Path,
                 inputs: dict, binding: dict, fixture_plan: dict | None = None) -> dict:
    """Run staged requests and always restore byte-exact prior catalog state."""
    state = {"schema_version": 1, "status": "running", "phase": "preflight",
        "binding": binding, "phase_jobs": [], "errors": [], "restoration_verified": False,
        "admin_mutation_outcome_unknown": False, "images_before": None, "images_after": None}
    if fixture_plan is not None:
        state["mode"] = "secondary_contextual_fixtures"
        state["secondary_binding"] = fixture_plan["secondary_binding"]
    _persist(output, state)
    backups_written = False
    try:
        backend.ensure_services()
        images = backend.images()
        evaluator_image = backend.evaluator_image()
        if evaluator_image != binding["evaluator_image_id"]:
            raise ValueError("Prebuilt evaluator image changed after input binding.")
        if images["client-runtime"] != binding["runtime_image_id"]:
            raise ValueError("Runtime image differs from the frozen preflight identity.")
        state["linux_fit_preflight"] = backend.preflight_fit(inputs=inputs, binding=binding, output=output)
        _persist(output, state)
        if fixture_plan is not None:
            state["phase"] = "fixture-frozen-study-preflight"; _persist(output, state)
            result = backend.run_fixture_preflight(primary_root=study_root,
                validation_file=Path(fixture_plan["validation_file"]), support=fixture_plan["support"],
                receipt=output / "fixture-frozen-preflight.json", output=output)
            receipt = result.get("receipt", {})
            scorer_binding = fixture_plan["primary"]["scorer_binding"]
            if (result.get("status") != "frozen_study_verified"
                    or receipt.get("binding") != scorer_binding
                    or receipt.get("selection_sha256") != fixture_plan["primary"]["selection_sha256"]
                    or receipt.get("fixture_sha256") != fixture_plan["support"]["fixture.jsonl"]["sha256"]
                    or receipt.get("rubric_sha256") != fixture_plan["support"]["rubric.md"]["sha256"]
                    or receipt.get("review_sha256") != fixture_plan["support"]["fixture-review.json"]["sha256"]
                    or receipt.get("case_counts") != fixture_plan["case_counts"]
                    or receipt.get("choices") != fixture_plan["choices_compact"]):
                raise ValueError("Linux fixture/frozen-selection preflight differs from host-bound receipts.")
            state["fixture_preflight_sha256"] = result.get("report_sha256")
            _record_job(output, state, "fixture-frozen-preflight", None, result)
        state["images_before"] = images
        prior_raw = {model_id: backend.read_raw(model_id) for model_id in CATALOG_IDS}
        prior_catalog = check_prior_catalog(prior_raw, inputs)
        if fixture_plan is not None:
            state["installed_presence_profile"] = next(profile for profile in PROFILES
                if prior_catalog[PRESENCE_IDS[profile]]["checksum"]
                == inputs["presence"][profile]["identity"]["artifact_checksum"])
            state["fixture_readiness_checks"] = []
        state["prior_sha256"] = {key: sha_bytes(value) for key, value in prior_raw.items()}
        state["private_backups"] = write_backups(output, prior_raw)
        backups_written = True
        _persist(output, state)
        if fixture_plan is None:
            for control in CONTROLS:
                state["phase"] = f"collect-validation:{control}"; _persist(output, state)
                _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                           binding=binding, state=state, stage="collect-validation", control=control,
                           prior_raw=prior_raw)
            state["phase"] = "calibrate"; _persist(output, state)
            calibration = backend.run_stage(stage="calibrate", pair=None, study_root=study_root,
                                            inputs=inputs, binding=binding, output=output)
            if calibration.get("status") != "frozen" or set(calibration.get("choices", {})) != set(PAIRS):
                raise ValueError("Calibration did not freeze exactly six choices.")
            choices = calibration["choices"]
            for pair in PAIRS:
                choice = choices[pair]
                status = choice.get("status")
                if status not in ("eligible", "ineligible"):
                    raise ValueError("Frozen choice has an unsupported eligibility state.")
                if status == "eligible":
                    selected = choice.get("chosen")
                    threshold = selected.get("threshold") if isinstance(selected, dict) else None
                    if type(threshold) not in (int, float) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
                        raise ValueError("Eligible frozen choice lacks a finite calibrated threshold.")
                elif choice.get("chosen") is not None:
                    raise ValueError("Ineligible frozen choice must not contain a selected threshold.")
            state["calibration_sha256"] = sha_file(study_root / "calibration/selection.json")
            state["eligibility"] = {pair: choices[pair].get("status") for pair in PAIRS}
            _record_job(output, state, "calibrate", None, calibration)
            for control in CONTROLS:
                state["phase"] = f"evaluate-validation:{control}"; _persist(output, state)
                _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                           binding=binding, state=state, stage="evaluate-validation", control=control,
                           prior_raw=prior_raw, choices=choices)
            validation_status = {f"{job['stage']}:{job['pair']}": job["status"] for job in state["phase_jobs"]
                                 if job["stage"] == "evaluate-validation"}
            if set(validation_status) != {f"evaluate-validation:{pair}" for pair in PAIRS}:
                raise ValueError("Development cannot begin until all six validation outcomes are recorded.")
            for pair in PAIRS:
                expected = "skipped_ineligible" if choices[pair].get("status") == "ineligible" else "complete"
                if validation_status[f"evaluate-validation:{pair}"] != expected:
                    raise ValueError("Validation endpoint status does not match frozen eligibility.")
            for control in CONTROLS:
                state["phase"] = f"evaluate-development:{control}"; _persist(output, state)
                _run_group(backend=backend, output=output, study_root=study_root, inputs=inputs,
                           binding=binding, state=state, stage="evaluate-development", control=control,
                           prior_raw=prior_raw, choices=choices)
        else:
            state["primary_manifest_sha256"] = fixture_plan["primary"]["manifest_sha256"]
            state["primary_selection_sha256"] = fixture_plan["primary"]["selection_sha256"]
            state["fixture_eligibility"] = {pair: fixture_plan["selection"]["choices"][pair]["status"]
                                            for pair in PAIRS}
            for control in CONTROLS:
                state["phase"] = f"fixtures:{control}"; _persist(output, state)
                _run_fixture_group(backend=backend, output=output, primary_root=study_root,
                    inputs=inputs, state=state, plan=fixture_plan, control=control, prior_raw=prior_raw)
            fixture_plan["integrity_check"]()
        state["images_after"] = backend.images()
        if state["images_after"] != state["images_before"] or backend.job_images != {binding["evaluator_image_id"]}:
            raise ValueError("Runtime/evaluator image identity changed during fixed study.")
        state["status"] = "complete"; state["phase"] = "complete"
    except Exception as exc:
        state["status"] = "failed"; state["failure_stage"] = state.get("phase")
        state["errors"].append(safe_error(exc))
    finally:
        unknown = (backend.admin_mutation_outcome_unknown
                   or getattr(backend, "evaluator_job_outcome_unknown", False))
        state["admin_mutation_outcome_unknown"] = unknown
        if backups_written and not unknown:
            restoration_errors = []
            for model_id in CATALOG_IDS:
                if backend.admin_mutation_outcome_unknown:
                    restoration_errors.append({"model_id": model_id,
                        "error_type": "RemoteOperationOutcomeUnknown",
                        "reason": "A timed-out restore may still be active; subsequent writes were stopped."})
                    break
                try:
                    backend.restore_exact(model_id, prior_raw[model_id])
                    if backend.admin_mutation_outcome_unknown:
                        restoration_errors.append({"model_id": model_id,
                            "error_type": "RemoteOperationOutcomeUnknown",
                            "reason": "A timed-out restore may still be active; subsequent writes were stopped."})
                        break
                    if sha_bytes(backend.read_raw(model_id)) != state["prior_sha256"][model_id]:
                        raise ValueError("Restored bytes differ from exact prior artifact.")
                except Exception as exc:
                    restoration_errors.append({"model_id": model_id, **safe_error(exc)})
            if not backend.admin_mutation_outcome_unknown and not restoration_errors:
                try:
                    for profile in PROFILES:
                        backend.probe({"context": inputs["controls"]["current"]["identity"],
                                       "presence": inputs["presence"][profile]["identity"]})
                except Exception as exc:
                    restoration_errors.append({"model_id": "runtime-probe", **safe_error(exc)})
            state["restoration_failures"] = restoration_errors
            state["restoration_verified"] = not backend.admin_mutation_outcome_unknown and not restoration_errors
        else:
            state["restoration_failures"] = ([{"error_type": "RemoteOperationOutcomeUnknown",
                "reason": "A timed-out writer or evaluator job may still be active; restoration is not claimed."}] if unknown else [])
            state["restoration_verified"] = False
        if not state["restoration_verified"]:
            state["status"] = "failed"
        state["admin_mutation_outcome_unknown"] = backend.admin_mutation_outcome_unknown
        state["evaluator_job_outcome_unknown"] = getattr(backend, "evaluator_job_outcome_unknown", False)
        state["docker_calls"] = getattr(backend, "calls", [])
        state["jobs"] = getattr(backend, "jobs", [])
        state["finished_unix"] = time.time()
        _persist(output, state)
    return state


def run_study(*, fit_root: Path, fit_source_revision: str,
              original_artifact: Path, current_artifact: Path,
              validation_file: Path, development_file: Path,
              protocol_file: Path, protocol_sha256: str, source_revision: str,
              output: Path, backend=None) -> dict:
    output = inside_results(output, fresh=True)
    inputs = validate_frozen_inputs(fit_root=fit_root, fit_source_revision=fit_source_revision,
        original_artifact=original_artifact, current_artifact=current_artifact,
        validation_file=validation_file, development_file=development_file,
        protocol_file=protocol_file, protocol_sha256=protocol_sha256, source_revision=source_revision)
    backend = backend or DockerBackend(output)
    backend.ensure_services()
    images = backend.images()
    evaluator_image = backend.evaluator_image()
    binding = make_binding(inputs, images["client-runtime"], evaluator_image)
    protocol_copy = output / "contextual-cascade-protocol.md"
    save_json(output / "input-binding.json", binding, exclusive=True)
    protocol_copy.parent.mkdir(parents=True, exist_ok=True)
    with protocol_copy.open("xb") as stream:
        stream.write(Path(protocol_file).read_bytes()); stream.flush(); os.fsync(stream.fileno())
    if sha_file(protocol_copy) != protocol_sha256:
        raise ValueError("Private protocol copy differs from its frozen SHA-256.")
    inputs["protocol_file"] = str(protocol_copy)
    if isinstance(backend, DockerBackend):
        backend.env["CASCADE_EXPECTED_EVALUATOR_IMAGE_ID"] = evaluator_image
    return run_sequence(backend=backend, output=output, study_root=output / "cascade-evidence",
                        inputs=inputs, binding=binding)


def run_fixture_study(*, completed_controller_output: Path, fit_root: Path,
                      validation_file: Path, development_file: Path,
                      support_root: Path, source_revision: str,
                      output: Path, backend=None) -> dict:
    """Run the fixed secondary 48-case scorer only after a verified primary completion."""
    output = inside_results(output, fresh=True)
    if current_revision() != source_revision:
        raise ValueError("Secondary execution revision differs from the current checkout.")
    primary = load_completed_primary(completed_controller_output)
    binding = primary["binding"]
    scorer_binding = primary["scorer_binding"]
    if binding.get("protocol_sha256") != CASCADE_PROTOCOL_SHA256:
        raise ValueError("Completed primary run is bound to another contextual-cascade protocol.")
    validation_file, development_file = inside_results(validation_file), inside_results(development_file)
    protocol_copy = primary["path"] / "contextual-cascade-protocol.md"
    inputs = validate_frozen_inputs(fit_root=fit_root,
        fit_source_revision=binding["fit_source_revision"],
        original_artifact=Path(binding["controls"]["original"]["path"]),
        current_artifact=Path(binding["controls"]["current"]["path"]),
        validation_file=validation_file, development_file=development_file,
        protocol_file=protocol_copy, protocol_sha256=binding["protocol_sha256"],
        source_revision=binding["source_revision"], verify_current_revision=False)
    if make_binding(inputs, binding["runtime_image_id"], binding["evaluator_image_id"]) != binding:
        raise ValueError("Reconstructed primary artifact binding differs from the completed run.")
    # A fresh destination is created only after all static primary/model bindings pass.
    output.mkdir(parents=True, exist_ok=False)
    support_receipt = copy_fixture_support(support_root, output)
    primary_receipts = output / "primary-receipts"
    primary_receipts.mkdir(parents=True, exist_ok=False)
    copy_receipts = {"controller_manifest.json": primary["path"] / "study-run-manifest.json",
                     "input-binding.json": primary["path"] / "input-binding.json",
                     "study-manifest.json": primary["study_root"] / "study-manifest.json",
                     "selection.json": primary["study_root"] / "calibration/selection.json"}
    for name, source in copy_receipts.items():
        raw = source.read_bytes()
        with (primary_receipts / name).open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())

    case_path = output / support_receipt["fixture.jsonl"]["relative_path"]
    case_rows = [json.loads(line) for line in case_path.read_text(encoding="utf-8").splitlines() if line]
    case_ids = [row.get("case_id") for row in case_rows]
    if len(case_ids) != 48 or len(set(case_ids)) != 48 or any(not isinstance(x, str) or not x for x in case_ids):
        raise ValueError("Copied reviewed fixtures do not have 48 unique case IDs.")
    review = read_json(output / support_receipt["fixture-review.json"]["relative_path"])
    case_counts = review.get("case_counts")
    if case_counts != {"total": 48, "families": 12, "controls": 24,
            "disclosure_candidates": 17, "ambiguous_excluded": 7,
            "context_truth_eligible": 41, "action_accuracy_eligible": 41, "visibility_hints": 4}:
        raise ValueError("Reviewed fixture composition does not match the fixed 48-case contract.")

    backend = backend or DockerBackend(output)
    if isinstance(backend, DockerBackend):
        backend.env["CASCADE_EXPECTED_EVALUATOR_IMAGE_ID"] = binding["evaluator_image_id"]
    pair_bindings = {}
    for pair in PAIRS:
        control, profile = pair.split("-", 1)
        pair_bindings[pair] = {"source_revision": source_revision,
            "study_binding": scorer_binding, "selection_sha256": primary["selection_sha256"], "pair": pair,
            "case_file_sha256": support_receipt["fixture.jsonl"]["sha256"],
            "rubric_sha256": support_receipt["rubric.md"]["sha256"],
            "fixture_review_sha256": support_receipt["fixture-review.json"]["sha256"],
            "caller_sha256": sha_file(ROOT / "evaluation/evaluate-contextual-regressions.py"),
            "cascade_helper_sha256": sha_file(ROOT / "evaluation/evaluate-contextual-cascade.py"),
            "runtime_image_id": binding["runtime_image_id"],
            "evaluator_image_id": binding["evaluator_image_id"],
            "validation_file_sha256": sha_file(validation_file)}
    secondary_binding = {"schema_version": 1, "mode": "secondary_contextual_fixtures",
        "primary_controller_manifest_sha256": primary["manifest_sha256"],
        "primary_selection_sha256": primary["selection_sha256"],
        "primary_input_binding_sha256": sha_file(primary["path"] / "input-binding.json"),
        "primary_study_manifest_sha256": sha_file(primary["study_root"] / "study-manifest.json"),
        "primary_source_revision": binding["source_revision"], "execution_source_revision": source_revision,
        "scorer_binding_sha256": sha_bytes(json.dumps(scorer_binding, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()),
        "execution_controller_sha256": sha_file(Path(__file__)),
        "fixture_scorer_sha256": pair_bindings[PAIRS[0]]["caller_sha256"],
        "cascade_helper_sha256": pair_bindings[PAIRS[0]]["cascade_helper_sha256"],
        "runtime_image_id": binding["runtime_image_id"], "evaluator_image_id": binding["evaluator_image_id"],
        "support": support_receipt, "professor_confirmation": review.get("professor_confirmation")}
    choices_compact = {pair: {"status": primary["selection"]["choices"][pair]["status"],
        "chosen": primary["selection"]["choices"][pair].get("chosen")} for pair in PAIRS}
    case_ids_sha256 = sha_bytes("\n".join(case_ids).encode())

    def integrity_check() -> None:
        if current_revision() != source_revision:
            raise ValueError("Execution checkout changed during fixture scoring.")
        if sha_file(primary["path"] / "study-run-manifest.json") != primary["manifest_sha256"]:
            raise ValueError("Completed primary controller manifest changed during fixture scoring.")
        if sha_file(primary["study_root"] / "calibration/selection.json") != primary["selection_sha256"]:
            raise ValueError("Primary frozen choices changed during fixture scoring.")
        if (sha_file(primary["path"] / "input-binding.json") != secondary_binding["primary_input_binding_sha256"]
                or sha_file(primary["study_root"] / "study-manifest.json")
                    != secondary_binding["primary_study_manifest_sha256"]):
            raise ValueError("Primary immutable input/study receipts changed during fixture scoring.")
        if sha_file(validation_file) != dict(binding["datasets"])["validation"][1]:
            raise ValueError("Pinned validation data changed during fixture scoring.")
        for item in support_receipt.values():
            if sha_file(output / item["relative_path"]) != item["sha256"]:
                raise ValueError("Copied fixture support changed during scoring.")
        if sha_bytes("\n".join(case_ids).encode()) != case_ids_sha256:
            raise ValueError("Fixture case identity set changed during scoring.")

    plan = {"primary": primary, "secondary_binding": secondary_binding,
        "validation_file": str(validation_file), "support": support_receipt,
        "selection": primary["selection"], "choices_compact": choices_compact,
        "case_counts": case_counts, "case_ids": case_ids, "case_rows": case_rows,
        "scorer_binding": scorer_binding, "pair_bindings": pair_bindings,
        "source_revision": source_revision, "runtime_image_id": binding["runtime_image_id"],
        "evaluator_image_id": binding["evaluator_image_id"], "integrity_check": integrity_check}
    return run_sequence(backend=backend, output=output, study_root=primary["study_root"],
        inputs=inputs, binding=binding, fixture_plan=plan)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--fit-root", type=Path, required=True)
    result.add_argument("--fit-source-revision")
    result.add_argument("--original-artifact", type=Path)
    result.add_argument("--current-artifact", type=Path)
    result.add_argument("--validation-file", type=Path, required=True)
    result.add_argument("--development-file", type=Path, required=True)
    result.add_argument("--protocol-file", type=Path)
    result.add_argument("--protocol-sha256")
    result.add_argument("--completed-controller-output", type=Path)
    result.add_argument("--support-root", type=Path)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.completed_controller_output is not None:
        if args.support_root is None:
            raise SystemExit("Fixture mode requires --support-root.")
        if any(value is not None for value in (args.fit_source_revision, args.original_artifact,
                args.current_artifact, args.protocol_file, args.protocol_sha256)):
            raise SystemExit("Fixture mode derives frozen inputs from the completed primary run.")
        state = run_fixture_study(completed_controller_output=args.completed_controller_output,
            fit_root=args.fit_root, validation_file=args.validation_file,
            development_file=args.development_file, support_root=args.support_root,
            source_revision=args.source_revision, output=args.output)
    else:
        if args.support_root is not None:
            raise SystemExit("--support-root is only valid with --completed-controller-output.")
        if (args.fit_source_revision is None or args.original_artifact is None or args.current_artifact is None
                or args.protocol_file is None or args.protocol_sha256 is None):
            raise SystemExit("Primary mode requires fit-source, both artifacts, and protocol arguments.")
        if not re.fullmatch(r"[0-9a-f]{64}", args.protocol_sha256):
            raise SystemExit("--protocol-sha256 must be lowercase SHA-256.")
        state = run_study(fit_root=args.fit_root, fit_source_revision=args.fit_source_revision,
            original_artifact=args.original_artifact, current_artifact=args.current_artifact,
            validation_file=args.validation_file, development_file=args.development_file,
            protocol_file=args.protocol_file, protocol_sha256=args.protocol_sha256,
            source_revision=args.source_revision, output=args.output)
    print(json.dumps({"status": state["status"], "restoration_verified": state["restoration_verified"],
                      "admin_mutation_outcome_unknown": state["admin_mutation_outcome_unknown"],
                      "phase_jobs": len(state["phase_jobs"]),
                      "failure_stage": state.get("failure_stage")}, sort_keys=True))
    return 0 if state["status"] == "complete" and state["restoration_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
