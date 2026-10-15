"""Authenticated window RPC, retained trace admission and compact publication."""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path

import grpc

from privoke_model import window_training as contract
from privoke_model.full_adam import canonical
from privoke_model.contextual_training import training_admission_metadata, parse_training_admission_metadata
from privoke_model.fingerprint import parameter_fingerprint


def persist_inputs(window, release, directory):
    from .evidence import _write_presence_attempt
    record = {"schema":1,"window":window,"bank":base64.b64encode(release.bank_payload).decode(),
        "references":base64.b64encode(release.reference_payload).decode(),
        "manifest":base64.b64encode(release.manifest_payload).decode(),"teacher_path":release.teacher_path,"teacher_sha256":release.teacher_sha256}
    path = _write_presence_attempt(Path(directory)/"window-inputs"/contract.sha256(contract.canonical_bytes(window)),record)
    return {"path":str(path),"sha256":contract.sha256(path.read_bytes())}


def retained_inputs(evidence, *, resolve_path=None):
    """Read original retained bytes, optionally through a read-only host mapping."""
    resolve = resolve_path or Path
    raw = resolve(evidence["path"]).read_bytes()
    if contract.sha256(raw) != evidence["sha256"]:
        raise ValueError("Retained window/component input bytes differ.")
    record = json.loads(raw)
    teacher_path = str(resolve(record["teacher_path"])) if resolve_path is not None else record["teacher_path"]
    release = contract.ComponentRelease(*(base64.b64decode(record[k],validate=True) for k in ("bank","references","manifest")),teacher_path,record["teacher_sha256"])
    window=contract.validate_window(record["window"])
    if (contract.sha256(contract.canonical_bytes(window))!=os.getenv("FUZZ_WINDOW_MANIFEST_SHA256")
            or release.sha256!=os.getenv("FUZZ_COMPONENT_MANIFEST_SHA256")
            or release.teacher_sha256!=os.getenv("FUZZ_COMPONENT_TEACHER_SHA256")):
        raise ValueError("Retained inputs differ from independently configured accepted window/component/teacher pins.")
    return window, contract.validate_component_release(release,trusted_sha256=os.getenv("FUZZ_COMPONENT_MANIFEST_SHA256"))


def validate_response(request, response, admission, window, release):
    from privoke.v1 import runtime_pb2
    from privoke_model.contextual_training import full_encoder_tensor_shapes
    from privoke_model.readout import validate_readout_identity
    if (list(request.layers) != [runtime_pb2.DETECTION_LAYER_SEMANTIC] or response.request_id != request.request_id
            or response.model_id != request.model_id or not response.base_version or response.error):
        raise ValueError("Window RPC identity/explicit semantic-only execution differs.")
    contract.validate_admission(admission, response.metadata)
    # Runtime wire examples use protobuf targets, distinct from Python classification objects.
    actual = [{"text":e.text,"packed":int(e.target.packed),"weight":e.weight} for e in request.examples if e.has_target]
    guard = [{"text":e.text,"packed":int(e.target.packed),"weight":e.weight} for e in request.heldout_examples if e.has_target]
    if actual != contract.row_wire(contract.flat_rows(window)) or guard != contract.row_wire(window["guard"]):
        raise ValueError("Physical request differs from frozen ordered wire rows.")
    names = [p.name for p in response.gradients]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate selected tensor delta.")
    gradients = {p.name:tuple(p.values) for p in response.gradients}
    shapes = {p.name:tuple(p.shape) for p in response.gradients}
    config = json.loads(response.metadata["model_config"])
    if canonical(config)!=canonical(release.manifest["teacher"]["config"]):
        raise ValueError("Returned complete CURRENT config/readout differs from authenticated ORIGINAL references.")
    validate_readout_identity(response.metadata["architecture"],config)
    expected = full_encoder_tensor_shapes(config)
    if response.metadata.get("training_scope") != "full_encoder" or response.metadata.get("executed_contextual_training_optimizer") != contract.POLICY:
        raise ValueError("Window route requires actual FULL execution.")
    if gradients and (shapes != expected or any(len(gradients[n]) != math.prod(expected[n])
            or any(not math.isfinite(v) or abs(v)>.05 for v in gradients[n]) for n in expected)):
        raise ValueError("Selected FULL tensor inventory/shapes/cap differs.")
    if (json.loads(response.metadata["trained_parameter_names"]) != sorted(expected)
            or response.metadata["trained_parameter_inventory_fingerprint"] != parameter_fingerprint({n:() for n in expected},expected)):
        raise ValueError("Window output inventory differs from independently derived architecture.")
    trace = contract.validate_trace(response.metadata,window=window,release=release,gradients=gradients,shapes=expected)
    phases = contract.execution_phases(trace)
    if len(response.executions) != len(phases) or any(e.phase!=name or e.examples!=count or e.layer!=4 or e.status!="ok" or e.error
            for e,(name,count) in zip(response.executions,phases)):
        raise ValueError("Window response actual semantic phases/counts differ.")
    selected = next(c for c in trace["checkpoints"] if c["step"]==trace["selected_step"])
    expected_metrics = {"examples":512.,"candidate_train_exact_match_rate":contract.packed_exact_rate(contract.flat_rows(window),selected),
        "exact_match_rate":contract.packed_exact_rate(contract.flat_rows(window),trace["checkpoints"][0]),
        "candidate_train_objective_loss":selected["loss"],"base_train_objective_loss":trace["checkpoints"][0]["loss"]}
    if dict(response.metrics)!=expected_metrics:
        raise ValueError("Window selected metrics differ from retained TRAIN scores.")
    return trace


def compute(client, examples, *, heldout_examples, model_id, request_id, window, release, admission,
            learning_rate, max_gradient):
    from privoke.v1 import runtime_pb2, runtime_pb2_grpc
    from .full_adam_evidence import reserve_physical_attempt, persist_reservation_rejection
    from .evidence import persist_backtracking_attempt, persist_backtracking_admission
    contract.validate_request(window,examples,heldout_examples)
    contract.validate_component_release(release,model_id=model_id,trusted_sha256=os.getenv("FUZZ_COMPONENT_MANIFEST_SHA256"))
    if release.teacher_sha256!=os.getenv("FUZZ_COMPONENT_TEACHER_SHA256"):
        raise ValueError("Fuzzer component teacher SHA differs from independently configured accepted pin.")
    if (contract.sha256(contract.canonical_bytes(window))!=os.getenv("FUZZ_WINDOW_MANIFEST_SHA256")
            or learning_rate!=.003 or max_gradient!=.05 or admission["expected_component_manifest_sha256"]!=release.sha256
            or admission["expected_window_manifest_sha256"]!=os.getenv("FUZZ_WINDOW_MANIFEST_SHA256")):
        raise ValueError("Window client effective settings/pins differ before reservation.")
    directory = os.getenv("PRIVOKE_FUZZER_DUMP_DIR")
    if not directory:
        raise ValueError("Window compute requires durable evidence directory.")
    inputs = persist_inputs(window,release,directory)
    def wire(row):
        return runtime_pb2.RuntimeTrainingExample(text=row.text,has_target=True,weight=row.weight,
            target=runtime_pb2.RuntimeClassification(packed=row.expected_packed_classification))
    request = runtime_pb2.ComputeSemanticGradientsRequest(request_id=request_id,model_id=model_id,layers=[4],
        examples=[wire(r) for r in examples],heldout_examples=[wire(r) for r in heldout_examples],
        learning_rate=learning_rate,max_gradient=max_gradient)
    header = training_admission_metadata(admission)
    try:
        reserve_physical_attempt(request,[list(p) for p in header],directory)
    except OSError as exc:
        persist_reservation_rejection(request,[list(p) for p in header],directory,exc)
        raise
    response, attempt = None, None
    try:
        with grpc.insecure_channel(client.target) as channel:
            response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel).ComputeUnderlyingModelGradients(
                request,timeout=max(client.timeout_seconds,180.),metadata=header)
        attempt = persist_backtracking_attempt(request,response,scope="full_encoder",expectations=admission,invocation_metadata=header)
        trace = validate_response(request,response,admission,window,release)
    except (ValueError,OSError,grpc.RpcError) as exc:
        if attempt is None:
            attempt = persist_backtracking_attempt(request,response,scope="full_encoder",expectations=admission,invocation_metadata=header,error=exc)
        persist_backtracking_admission(attempt,response,status="unadmitted",error=exc)
        raise
    # Existing admission writer assumes nonempty gradients. Known BASE/no-update is a distinct terminal receipt.
    from .evidence import _write_presence_attempt
    _write_presence_attempt(attempt.parent.parent/"window-admission",{"schema":1,"physical_attempt":str(attempt),
        "status":trace["status"],"trace_sha256":contract.sha256(response.metadata[contract.TRACE_KEY].encode())})
    return {"model_id":response.model_id,"base_version":response.base_version,
        "gradients":{p.name:tuple(p.values) for p in response.gradients},"shapes":{p.name:tuple(p.shape) for p in response.gradients},
        "metrics":dict(response.metrics),"metadata":dict(response.metadata),
        "execution_evidence":{"rpc":"ComputeUnderlyingModelGradients","request_layers":[4],
            "request_protobuf_base64":base64.b64encode(request.SerializeToString(deterministic=True)).decode(),
            "response_protobuf_base64":base64.b64encode(response.SerializeToString(deterministic=True)).decode(),
            "invocation_metadata":[list(p) for p in header],"physical_attempt":str(attempt),"window_inputs":inputs}}


def validate_update(update, *, resolve_path=None):
    from privoke.v1 import runtime_pb2
    evidence=update.execution_evidence
    record=json.loads((resolve_path or Path)(evidence["physical_attempt"]).read_text())
    for key in ("request_protobuf_base64","response_protobuf_base64","invocation_metadata"):
        if record[key]!=evidence[key]:
            raise ValueError("Window retained physical attempt differs from raw request/response/header.")
    request=runtime_pb2.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"],validate=True))
    response=runtime_pb2.ComputeSemanticGradientsResponse.FromString(base64.b64decode(evidence["response_protobuf_base64"],validate=True))
    if (record["request_protobuf_sha256"]!=contract.sha256(request.SerializeToString(deterministic=True))
            or record["request_id"]!=request.request_id or record["model_id"]!=request.model_id
            or record["training_stage"]!="full_encoder" or evidence["request_layers"]!=[4]):
        raise ValueError("Window physical attempt identity/hash/semantic selection differs.")
    if (dict(response.metadata)!=dict(update.metadata) or dict(response.metrics)!=dict(update.metrics)
            or {p.name:tuple(p.values) for p in response.gradients}!=dict(update.gradients)
            or {p.name:tuple(p.shape) for p in response.gradients}!=dict(update.parameter_shapes)
            or update.model_id!=response.model_id or update.base_version!=response.base_version or evidence["rpc"]!="ComputeUnderlyingModelGradients"):
        raise ValueError("Window update differs from actual immutable runtime response.")
    window,release=retained_inputs(evidence["window_inputs"],resolve_path=resolve_path)
    return validate_response(request,response,parse_training_admission_metadata(evidence["invocation_metadata"]),window,release)


def publication_metadata(update, metadata, extra, directory):
    from .evidence import cycle_identity
    from privoke.v1 import parameters_pb2
    trace=validate_update(update)
    if trace["status"]!="selected":
        raise ValueError("BASE/no_update outcome cannot publish parameters.")
    request=parameters_pb2.FuzzerTrainingRequest(source_id=extra["request_source_id"],request_id=extra["request_id"])
    path=Path(directory)/"training-cycles"/cycle_identity(request,"full_encoder")/(trace["base"]+".json")
    retained=json.loads(path.read_text())
    if (retained["metadata"]!=dict(update.metadata) or retained["metrics"]!=dict(update.metrics)
            or retained["execution_evidence"]!=update.execution_evidence or retained["gate_passed"] is not True
            or retained["request_id"]!=request.request_id or retained["source_id"]!=request.source_id
            or retained["model_id"]!=update.model_id or retained["base_version"]!=update.base_version
            or retained["training_stage"]!="full_encoder"):
        raise ValueError("Publication differs from durably retained completed cycle.")
    result=dict(metadata)
    del result[contract.TRACE_KEY]
    result["training_evidence_sha256"]=contract.sha256(canonical({k:retained[k] for k in
        ("metadata","metrics","execution_evidence","gate_passed","request_id","source_id","model_id","base_version")}).encode())
    if len(result)>64 or any(len(v.encode())>2048 for v in result.values()):
        raise ValueError("Window compact publication exceeds unchanged metadata quota.")
    return result
