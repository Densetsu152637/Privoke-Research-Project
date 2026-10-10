"""Focused automatic Tiny training acceptance; no detector/telemetry orchestration.

Called by stack_smoke. Services and their lifecycle belong to the caller. Local
trace files contain actual training RPC messages, not inference layer traces.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import time
from pathlib import Path

from google.protobuf.json_format import MessageToDict
from privoke.v1 import parameters_pb2 as P, runtime_pb2 as R
from privoke_model.artifact import float32, load_artifact, updated_parameter_values
from privoke_model.contextual_training import (
    FULL_ENCODER_STRATEGY, HEAD_NAMES, contextual_trainable_names,
    full_encoder_tensor_shapes,
)
from privoke_model.fingerprint import parameter_fingerprint


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")


def fingerprint(parameters, shapes):
    return parameter_fingerprint({n: [float32(v) for v in values] for n, values in parameters.items()}, shapes)


def artifact_state(artifact):
    shapes = {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()}
    parameters = {n: tuple(float32(v) for v in t["values"]) for n, t in artifact["parameters"].items()}
    return {"model_id": artifact["model_id"], "version": artifact["version"], "parameters": parameters,
            "shapes": shapes, "fingerprint": fingerprint(parameters, shapes), "config": artifact["config"]}


def streamed_state(response):
    require(len({p.name for p in response.parameters}) == len(response.parameters), "Duplicate streamed tensors")
    config = json.loads(response.metadata["model_config"])
    shapes = {p.name: tuple(p.shape) for p in response.parameters}
    parameters = {p.name: tuple(p.values) for p in response.parameters}
    require(shapes == full_encoder_tensor_shapes(config), "Streamed full tensor inventory/shapes differ")
    require(all(math.isfinite(v) for values in parameters.values() for v in values), "Nonfinite stream")
    require(all(len(parameters[n]) == math.prod(shape) for n, shape in shapes.items()), "Stream tensor length differs")
    return {"model_id": response.model_id, "version": response.version, "parameters": parameters,
            "shapes": shapes, "config": config, "fingerprint": fingerprint(parameters, shapes),
            "checksum": response.metadata["artifact_checksum"]}


def decode_trace(trace):
    require(trace["schema_version"] == 1 and trace["training_stage"] in ("heads", "full_encoder"), "Unsupported trace schema/stage")
    evidence = trace["execution_evidence"]
    request = R.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"], validate=True))
    response = R.ComputeSemanticGradientsResponse.FromString(base64.b64decode(evidence["response_protobuf_base64"], validate=True))
    require(list(request.layers) == [R.DETECTION_LAYER_SEMANTIC], "Training request is not explicitly semantic-only")
    require(evidence["request_layers"] == list(request.layers), "Trace layer projection differs from actual request")
    expected_rpc = "ComputeSemanticGradients" if trace["training_stage"] == "heads" else "ComputeUnderlyingModelGradients"
    require(evidence["rpc"] == expected_rpc, "Actual training endpoint differs from stage")
    actual_executions = [{"phase":e.phase,"layer":e.layer,"status":e.status,"examples":e.examples,"error":e.error} for e in response.executions]
    require(evidence["executions"] == actual_executions, "Trace execution projection differs from actual response")
    require(not response.error and response.request_id == request.request_id, "Training RPC error/request mismatch")
    require(response.model_id == request.model_id == trace["model_id"], "Training model differs")
    require(response.base_version == trace["base_version"], "Trace base version differs")
    expected_counts = {"training": len(request.examples), "base_heldout": len(request.heldout_examples), "candidate_heldout": len(request.heldout_examples)}
    require(all(expected_counts.values()), "Both labeled training and guard rows required")
    require(len(response.executions) == 3 and {e.phase for e in response.executions} == set(expected_counts), "Missing/duplicate actual execution phases")
    for execution in response.executions:
        require(execution.layer == R.DETECTION_LAYER_SEMANTIC and execution.status == "ok" and not execution.error,
                "Actual training phase failed or selected another layer")
        require(execution.examples == expected_counts[execution.phase], "Actual phase row count differs")
    require(all(trace["metadata"].get(k)==v for k,v in response.metadata.items()) and all(trace["metrics"].get(k)==v for k,v in response.metrics.items()), "Trace dropped/overrode actual runtime metadata/metrics")
    require(all(math.isfinite(v) for v in response.metrics.values()) and all(math.isfinite(v) for v in trace["metrics"].values()), "Nonfinite actual/fuzzer metrics")
    require(response.metadata["training_scope"] == trace["training_stage"], "Training scope differs")
    require(all(e.has_target and math.isfinite(e.weight) and e.weight>0 for e in (*request.examples,*request.heldout_examples)),"Actual rows must carry explicit targets and positive finite weights")
    return request, response


def apply_actual_stage(base, trace):
    request, response = decode_trace(trace)
    config = json.loads(response.metadata["model_config"])
    require(config == base["config"], "Actual model configuration changed between stages")
    expected = HEAD_NAMES if trace["training_stage"] == "heads" else contextual_trainable_names(config, FULL_ENCODER_STRATEGY)
    require(len(response.gradients) == len(expected) and {p.name for p in response.gradients} == set(expected), "Actual delta inventory differs from stage")
    require(json.loads(response.metadata["trained_parameter_names"]) == sorted(expected), "Claimed trained inventory differs")
    require(response.base_version == base["version"] and response.metadata["base_parameter_fingerprint"] == base["fingerprint"], "Stage used stale base")
    updated = dict(base["parameters"])
    for delta in response.gradients:
        require(tuple(delta.shape) == base["shapes"][delta.name], "Actual delta shape differs")
        require(all(math.isfinite(v) for v in delta.values), "Nonfinite actual delta")
        require(len(delta.values)==math.prod(base["shapes"][delta.name]), "Actual delta value count differs")
        updated[delta.name] = tuple(float32(v) for v in updated_parameter_values(base["parameters"][delta.name], delta.values))
    candidate_fp = fingerprint(updated, base["shapes"])
    inventory_fp = parameter_fingerprint({n:() for n in expected},{n:base["shapes"][n] for n in expected})
    require(response.metadata["trained_parameter_inventory_fingerprint"]==inventory_fp,"Actual inventory fingerprint differs")
    require(candidate_fp == response.metadata["updated_parameter_fingerprint"], "Actual candidate fingerprint differs from reconstructed deltas")
    ack = trace["ack"]
    require(trace["gate_passed"] is True and ack["accepted"] is True and ack["model_id"] == base["model_id"], "Stage not accepted/published")
    require(ack["applied_version"] and ack["applied_version"] != base["version"], "Publication version did not advance")
    return dict(base, parameters=updated, version=ack["applied_version"], fingerprint=candidate_fp)


def verify_pair(initial, head, full, final):
    require(head["request_id"] != full["request_id"] and full["source_id"] == hashlib.sha256(("underlying-v1:"+head["source_id"]).encode()).hexdigest(), "Stage IDs/source namespaces differ")
    require(head["training_stage"] == "heads" and full["training_stage"] == "full_encoder", "Stage ordering differs")
    s0 = artifact_state(initial)
    s1 = apply_actual_stage(s0, head)
    encoder = set(s0["parameters"]) - HEAD_NAMES
    require(all(s0["parameters"][n] == s1["parameters"][n] for n in encoder), "Head stage mutated encoder")
    require(any(s0["parameters"][n] != s1["parameters"][n] for n in HEAD_NAMES), "Head stage changed no head value")
    s2 = apply_actual_stage(s1, full)
    for name in ("token_embedding", "position_embedding"):
        require(s1["parameters"][name] != s2["parameters"][name], f"Full stage did not change {name}")
    prefix = "layers.0." if initial["config"]["num_layers"] > 1 else ""
    require(initial["config"]["num_layers"] > 1 and any(s1["parameters"][n] != s2["parameters"][n] for n in encoder if n.startswith(prefix)), "Full stage changed no earlier block")
    require(any(s1["parameters"][n] != s2["parameters"][n] for n in HEAD_NAMES), "Full stage changed no head")
    require(final["model_id"] == s2["model_id"] and final["version"] == s2["version"] and final["config"] == s2["config"], "Final stream identity/config differs")
    require(final["parameters"] == s2["parameters"] and final["shapes"] == s2["shapes"] and final["fingerprint"] == s2["fingerprint"], "Published S2 differs from exact actual candidate")
    return {"observed_streamed_s0": s0["fingerprint"], "reconstructed_s1": s1["fingerprint"],
            "observed_full_base_version": full["base_version"], "observed_full_base_checksum": full["metadata"]["artifact_checksum"],
            "observed_streamed_s2": final["fingerprint"], "head_version": s1["version"], "full_version": s2["version"]}


def accepted_traces(directory):
    traces = []
    for path in sorted(Path(directory).glob("training-cycles/*/*.json")):
        trace = read_json(path)
        if trace.get("ack", {}).get("accepted") is True:
            namespace=hashlib.sha256(json.dumps([trace["training_stage"],trace["source_id"],trace["request_id"]],separators=(",",":")).encode()).hexdigest()
            require(path.parent.name==namespace and path.stem==trace["metadata"]["base_parameter_fingerprint"],"Trace path is not namespace/base bound")
            traces.append((path, trace))
    return traces


def wait_pair(directory, timeout):
    deadline = time.monotonic() + timeout
    while True:
        traces = accepted_traces(directory)
        if len(traces) >= 2:
            require(len(traces) == 2, "Expected one automatic cycle with two accepted stages")
            by_stage = {t["training_stage"]: (p, t) for p, t in traces}
            require(set(by_stage) == {"heads", "full_encoder"}, "Expected one accepted trace per stage")
            return by_stage["heads"], by_stage["full_encoder"]
        require(time.monotonic() < deadline, "Automatic stage pair did not complete before deadline")
        time.sleep(.2)


def snapshot(model_stub, model_id):
    return streamed_state(model_stub.GetModelParameters(P.ModelParametersRequest(model_id=model_id, consumer_id="semantic-training-smoke"), timeout=30))


def check_inference(runtime_stub, model_id, expected_version, expected_fp):
    response = runtime_stub.AnalyzePrompt(R.AnalyzePromptRequest(text="My private diagnosis needs medication.",
        request_id="semantic-training-smoke-reload", semantic_model_id=model_id, layers=[R.DETECTION_LAYER_SEMANTIC]), timeout=30)
    require(not response.error and len(response.layers) == 1, "Semantic reload probe failed")
    layer = response.layers[0]
    require(layer.layer == R.DETECTION_LAYER_SEMANTIC and layer.status == "ok" and not layer.error and not layer.HasField("semantic_presence_gate"), "Actual semantic reload execution differs")
    require(bool(layer.results), "Fixed synthetic model must provide reload finding identity")
    for finding in layer.results:
        require(finding.metadata["model_id"] == model_id and finding.metadata["model_version"] == expected_version and finding.metadata["parameter_fingerprint"] == expected_fp, "Runtime did not reload exact published candidate")
    return MessageToDict(response, preserving_proto_field_name=True)


def boundary_requests(runtime_stub, model_id, expected):
    """Fixed 97/256/257 counts include Tiny's one start token; never publish."""
    from src.transformer_encoder import TOKEN_PATTERN
    records = []
    for count in (97, 256, 257):
        text = " ".join(["hello"] * (count - 1))
        require(len(TOKEN_PATTERN.findall(text.lower())) + 1 == count, "Boundary fixture token count differs")
        request = R.ComputeSemanticGradientsRequest(model_id=model_id, request_id=f"boundary-{count}",
            examples=[R.RuntimeTrainingExample(text=text, has_target=True, target=R.RuntimeClassification(sensitivity="S3",visibility="P0",categories=["HEALTH"]),weight=1)],
            heldout_examples=[R.RuntimeTrainingExample(text="Guard private diagnosis",has_target=True,target=R.RuntimeClassification(sensitivity="S3",visibility="P0",categories=["HEALTH"]),weight=1),
                              R.RuntimeTrainingExample(text="Guard public weather",has_target=True,target=R.RuntimeClassification(sensitivity="S0",visibility="PU"),weight=1)],
            learning_rate=.003,max_gradient=.00001,layers=[R.DETECTION_LAYER_SEMANTIC])
        for method in ("ComputeSemanticGradients", "ComputeUnderlyingModelGradients"):
            response = getattr(runtime_stub, method)(request,timeout=120)
            if count <= 256:
                require(not response.error and len(response.executions)==3, f"{method} rejected supported length")
                counts={"training":len(request.examples),"base_heldout":len(request.heldout_examples),"candidate_heldout":len(request.heldout_examples)}
                require({e.phase for e in response.executions}==set(counts),"Boundary training phases differ")
                require(all(e.layer==R.DETECTION_LAYER_SEMANTIC and e.status=="ok" and not e.error and e.examples==counts[e.phase] for e in response.executions), "Boundary training execution differs")
                require(all(math.isfinite(v) for delta in response.gradients for v in delta.values),"Nonfinite boundary gradients")
                require(response.metadata["base_parameter_fingerprint"]==expected["fingerprint"] and response.base_version==expected["version"],"Boundary training used another base")
            else:
                require(bool(response.error) and "256" in response.error and not response.gradients, "Overlength training did not fail closed")
            records.append({"tokens":count,"rpc":method,"request":MessageToDict(request,preserving_proto_field_name=True),"response":MessageToDict(response,preserving_proto_field_name=True)})
        inference_request=R.AnalyzePromptRequest(text=text,request_id=f"boundary-inference-{count}",semantic_model_id=model_id,layers=[R.DETECTION_LAYER_SEMANTIC])
        response=runtime_stub.AnalyzePrompt(inference_request,timeout=30)
        require(len(response.layers)==1 and response.layers[0].layer==R.DETECTION_LAYER_SEMANTIC, "Boundary inference selected other layer")
        require(not response.layers[0].HasField("semantic_presence_gate"),"Unexpected boundary presence gate")
        if count <=256:
            require(not response.error and response.layers[0].status=="ok" and not response.layers[0].error,"Supported inference length rejected")
            require(bool(response.layers[0].results),"Fixed biased boundary fixture must expose loaded identity")
            require(all(f.metadata.get("model_version")==expected["version"] and f.metadata.get("parameter_fingerprint")==expected["fingerprint"] for f in response.layers[0].results),"Boundary inference used another snapshot")
        else: require(bool(response.error) and response.layers[0].status=="error" and "256" in response.layers[0].error, "Overlength inference silently truncated")
        records.append({"tokens":count,"rpc":"AnalyzePrompt","request":MessageToDict(inference_request,preserving_proto_field_name=True),"response":MessageToDict(response,preserving_proto_field_name=True)})
    return records


def prepare_fixture(state_dir, revision):
    """Fixed seeded random fixture; no optimization, model download or promotion."""
    import dataclasses
    import numpy as np
    import sys
    from privoke_model.artifact import ARCHITECTURE_NAME, artifact_checksum, validate_artifact
    from privoke_model.contextual_training import prepare_full_encoder_artifact
    from src.model import ModelConfig, TinyTransformerModel
    sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "models"))
    from generate_baseline import initial_parameters, SENSITIVITIES, VISIBILITIES, CATEGORIES
    config = ModelConfig(128, 8, 16, 96, SENSITIVITIES, VISIBILITIES, CATEGORIES, .5, 2, 2)
    rng = np.random.default_rng(1337)
    arrays = initial_parameters(config, rng)
    for task in ("sensitivity", "visibility", "category"):
        name = f"head.{task}.weight"
        arrays[name] = rng.normal(0, .02, arrays[name].shape).astype(np.float32)
    arrays["head.sensitivity.bias"][:] = [-2, -2, -2, 4]
    arrays["head.visibility.bias"][:] = [4, -2, -2, -2, -2, -2]
    arrays["head.category.bias"][:] = -4
    arrays["head.category.bias"][0] = 4
    original = {"schema_version":1,"model_id":"privoke-balanced","version":"smoke-synthetic-96",
        "generated_at_unix":1,"architecture":ARCHITECTURE_NAME,"config":dataclasses.asdict(config),
        "metadata":{"purpose":"fixed_synthetic_transport_fixture_no_optimization_no_quality_claim"},
        "parameters":{n:{"shape":list(a.shape),"values":[float32(v) for v in a.ravel()],"trainable":n in HEAD_NAMES} for n,a in arrays.items()}}
    original["checksum"] = artifact_checksum(original)
    validate_artifact(original)
    prepared = prepare_full_encoder_artifact(original,version="smoke-synthetic-256",generated_at_unix=2,source_revision=revision,max_tokens=256)
    def model(artifact):
        return TinyTransformerModel(ModelConfig.from_mapping(artifact["config"]),
            {n:t["values"] for n,t in artifact["parameters"].items()},
            {n:t["shape"] for n,t in artifact["parameters"].items()},device="cpu")
    short="My private diagnosis needs medication."
    old_prediction=model(original).predict(short)
    new_prediction=model(prepared).predict(short)
    require(old_prediction==new_prediction,"Context preparation changed an existing short-input output")
    for n,tensor in original["parameters"].items():
        if n=="position_embedding":require(prepared["parameters"][n]["values"][:len(tensor["values"])]==tensor["values"],"Position prefix changed")
        else:require(prepared["parameters"][n]==dict(tensor,trainable=True),"Preparation changed original non-position values")
    require(artifact_state(original)["fingerprint"]!=artifact_state(prepared)["fingerprint"],"Shape extension must change fingerprint")
    directory = Path(state_dir)
    require(not directory.exists(), "Fixture state must be new; preserve previous attempts")
    directory.mkdir(parents=True)
    write_new(directory/"original-96.json",original)
    write_new(directory/"initial-256.json",prepared)
    write_new(directory/"catalog/privoke-balanced.json",prepared)
    # Fixed distinct templates allow the authoritative fuzzer partitioner to
    # create its disjoint training/guard examples; no corpus or selection search.
    rows = []
    for index in range(16):
        sensitive = index % 2 == 0
        rows.append({"text":f"Synthetic case {index}: "+("My private diagnosis requires medication." if sensitive else "An anonymous public weather bulletin is available."),
            "classification":{"sensitivity":"S3" if sensitive else "S0","visibility":"P0" if sensitive else "PU","categories":["HEALTH"] if sensitive else []},
            "metadata":{"purpose":"synthetic_training_mechanics","group_id":f"synthetic-{index}"}})
    write_new(directory/"prompts.json",rows)
    for subdir in ("updates","fuzzer"):
        (directory/subdir).mkdir()
    write_new(directory/"fixture.json",{"source_revision":revision,"seed":1337,"old_max_tokens":96,"new_max_tokens":256,
        "original_sha256":sha(directory/"original-96.json"),"prepared_sha256":sha(directory/"initial-256.json"),
        "parameters":sum(len(t["values"]) for t in prepared["parameters"].values()),"training":False,"quality_claim":False,"short_output_parity":True,"old_position_prefix_preserved":True,"input_mode":"fixed sixteen templates via FUZZ_PROMPT_DATASET_PATH and maintained procedural generate_training_partition(8,4,seed=1); no curriculum manifest or quality study"})


def run_focused(args, targets):
    import grpc
    from privoke.v1 import parameters_pb2_grpc as PG, runtime_pb2_grpc as RG
    state = Path(args.training_state_dir)
    if args.training_action == "prepare":
        prepare_fixture(state,args.training_source_revision)
        return
    output = Path(args.training_output)
    require(not output.exists(), "Result already exists; never silently rerun acceptance requests")
    initial = load_artifact(state/"initial-256.json")
    with grpc.insecure_channel(targets["model"],options=[("grpc.max_receive_message_length",8*1024*1024)]) as model_channel, grpc.insecure_channel(targets["runtime"]) as runtime_channel:
        models = PG.ModelStreamingServiceStub(model_channel)
        runtime = RG.PrivokeRuntimeServiceStub(runtime_channel)
        require(models.Health(P.HealthRequest(),timeout=15).status=="SERVING", "Model service not ready")
        require(runtime.Health(R.RuntimeHealthRequest(),timeout=15).status=="SERVING", "Runtime not ready")
        if args.training_action == "capture":
            actual = models.GetModelParameters(P.ModelParametersRequest(model_id=initial["model_id"],consumer_id="smoke-s0"),timeout=30)
            actual_state = streamed_state(actual)
            expected = artifact_state(initial)
            require(actual_state["fingerprint"]==expected["fingerprint"] and actual_state["version"]==expected["version"] and actual_state["checksum"]==initial["checksum"], "Automatic scheduler started before S0 capture")
            inference=check_inference(runtime,initial["model_id"],actual_state["version"],actual_state["fingerprint"])
            write_new(output,{"status":"captured_s0","inference":inference,"snapshot_protobuf_base64":base64.b64encode(actual.SerializeToString()).decode(),"initial_artifact_sha256":sha(state/"initial-256.json")})
            return
        if args.training_action == "boundaries":
            before = snapshot(models,initial["model_id"])
            records = boundary_requests(runtime,initial["model_id"],before)
            require(snapshot(models,initial["model_id"])==before,"Gradient boundary checks published/mutated serving parameters")
            write_new(output,{"status":"passed","scope":"functional_boundaries_no_publication","records":records})
            return
        captured = read_json(state/"captured-s0.json")
        actual_s0 = streamed_state(P.ModelParametersResponse.FromString(base64.b64decode(captured["snapshot_protobuf_base64"],validate=True)))
        require(actual_s0["fingerprint"]==artifact_state(initial)["fingerprint"] and captured["initial_artifact_sha256"]==sha(state/"initial-256.json"),"Captured S0 differs from fixture")
        if args.training_action == "negative":
            verify_negative(state,models,output,args.training_wait_seconds)
            return
        (head_path,head),(full_path,full) = wait_pair(state/"fuzzer",args.training_wait_seconds)
        cycle = read_cycle(state/"updates/training-cycles.sqlite3")
        validate_cycle(cycle,head,full)
        final = snapshot(models,initial["model_id"])
        if args.training_action == "admission":
            reject_stale_and_conflicting(cycle,head,targets,models,final,state,output)
            return
        if args.training_action in ("replay","restart"):
            replay_stages(cycle,targets["fuzzer"],models,final,state,output,runtime if args.training_action=="restart" else None)
            return
        proof = verify_pair(initial,head,full,final)
        # Runtime reload uses TTL=1, bounded waiting rather than a fabricated cache trace.
        time.sleep(1.1)
        inference = check_inference(runtime,initial["model_id"],final["version"],final["fingerprint"])
        write_new(output,{"status":"passed","scope":"automatic_two_stage_training_mechanics","proof":proof,
            "captured_s0_sha256":sha(state/"captured-s0.json"),"head_trace":str(head_path),"head_trace_sha256":sha(head_path),
            "full_trace":str(full_path),"full_trace_sha256":sha(full_path),"final_snapshot":final,"inference":inference,
            "scheduler_cycle":cycle,"quality_claim":False,"note":"S0/S2 actually streamed; S1 reconstructed from actual head deltas; FULL runtime base bound to reconstructed S1."})


def read_cycle(path):
    import sqlite3
    from contextlib import closing
    # Read-only observation; never repair/advance a production scheduler ledger.
    uri=Path(path).resolve().as_uri()+"?mode=ro"
    deadline=time.monotonic()+30
    while True:
        with closing(sqlite3.connect(uri,uri=True)) as connection:
            rows=connection.execute("SELECT sequence,fingerprint,state,record FROM cycles ORDER BY sequence").fetchall()
        if rows and rows[-1][2] != "pending":break
        require(time.monotonic()<deadline,"Scheduler terminal acknowledgment was not persisted")
        time.sleep(.1)
    require(len(rows)==1,"Expected exactly one automatic scheduler cycle")
    sequence,fp,state,record=rows[0]
    record=json.loads(record)
    require((record["sequence"],record["fingerprint"],record["state"])==(sequence,fp,state),"Scheduler row/record identity differs")
    return record


def validate_cycle(cycle,head,full):
    require(cycle["state"]=="complete" and set(cycle["stages"])=={"heads","full_encoder"},"Automatic dual cycle incomplete")
    for stage,trace in (("heads",head),("full_encoder",full)):
        stored=cycle["stages"][stage]
        request=P.FuzzerTrainingRequest.FromString(bytes.fromhex(stored["request_protobuf_hex"]))
        response=P.FuzzerTrainingResponse.FromString(bytes.fromhex(stored["response_protobuf_hex"]))
        require(stored["state"]=="accepted" and request.request_id==stored["request_id"]==trace["request_id"],"Scheduler stage request differs")
        require(request.source_id==cycle["source_id"] and request.model_id==cycle["model_id"]==trace["model_id"] and request.seed==cycle["seed"],"Immutable automatic request fields differ")
        require(request.metadata["require_full_capability"]=="true","Automatic head did not require full capability")
        require(response.accepted and response.model_id==trace["model_id"] and response.base_version==trace["base_version"] and response.applied_version==trace["ack"]["applied_version"],"Automatic response differs from accepted publication")
        if stage=="full_encoder":require(request.metadata["expected_base_version"]==head["ack"]["applied_version"],"Automatic FULL not linked to committed HEAD")


def replay_stages(cycle,target,models,expected,state,output,runtime=None):
    import grpc
    from privoke.v1 import parameters_pb2_grpc as PG
    catalog=state/"catalog/privoke-balanced.json"
    before=sha(catalog)
    audit=state/"updates/updates.jsonl"
    audit_before=sha(audit)
    replies=[]
    with grpc.insecure_channel(target) as channel:
        client=PG.FuzzerServiceStub(channel)
        for stage in ("heads","full_encoder"):
            stored=cycle["stages"][stage]
            request=P.FuzzerTrainingRequest.FromString(bytes.fromhex(stored["request_protobuf_hex"]))
            method=client.RunTrainingCycle if stage=="heads" else client.RunUnderlyingTrainingCycle
            response=method(request,timeout=30)
            require(response.accepted and response.metadata.get("replayed")=="true" and response.applied_version==stored["applied_version"],"Committed stage replay retrained/changed outcome")
            require(snapshot(models,request.model_id)==expected and sha(catalog)==before and sha(audit)==audit_before,"Replay mutated model/audit")
            replies.append(MessageToDict(response,preserving_proto_field_name=True))
    require(read_cycle(state/"updates/training-cycles.sqlite3")==cycle,"Replay changed scheduler completion/IDs")
    inference=check_inference(runtime,expected["model_id"],expected["version"],expected["fingerprint"]) if runtime is not None else None
    write_new(output,{"status":"passed","scope":"durable_stage_replay","post_restart_inference":inference,"cycle":cycle,"responses":replies,"unchanged_artifact_sha256":before,"unchanged_audit_sha256":audit_before})


def verify_negative(state,models,output,timeout):
    initial=load_artifact(state/"initial-256.json")
    expected=artifact_state(initial)
    deadline=time.monotonic()+timeout
    while True:
        paths=list((state/"fuzzer").glob("training-cycles/*/*.json"))
        rejected=[(p,read_json(p)) for p in paths if read_json(p).get("gate_passed") is False]
        if rejected:break
        require(time.monotonic()<deadline,"Predetermined strict-guard negative did not reject")
        time.sleep(.2)
    require(len(rejected)==1 and len(paths)==1,"Rejected HEAD unexpectedly advanced/retried")
    path,trace=rejected[0]
    _,actual_response=decode_trace(trace)
    require(actual_response.metrics["candidate_heldout_exact_match_rate"]<1,"Strict negative did not fail its declared guard")
    require(trace["training_stage"]=="heads" and not trace.get("ack"),"Rejected guard published or was wrong stage")
    actual=snapshot(models,initial["model_id"])
    require(actual["fingerprint"]==expected["fingerprint"] and actual["version"]==expected["version"] and actual["checksum"]==initial["checksum"],"Guard rejection published state")
    require(sha(state/"catalog/privoke-balanced.json")==sha(state/"initial-256.json"),"Rejected candidate changed artifact bytes")
    audit=state/"updates/updates.jsonl"
    require(not audit.exists() or not audit.read_bytes(),"Rejected guard submitted/published an update")
    cycle=read_cycle(state/"updates/training-cycles.sqlite3")
    require(cycle["state"]=="rejected" and cycle["stages"]["heads"]["state"]!="accepted" and cycle["stages"]["full_encoder"]["state"]=="pending","Guard rejection scheduler state differs")
    write_new(output,{"status":"passed","scope":"strict_negative_guard_no_publication","guard_minimum_exact_match_rate":1,"trace_sha256":sha(path),"cycle":cycle,"snapshot_fingerprint":actual["fingerprint"],"quality_claim":False})


def reject_stale_and_conflicting(cycle,head,targets,models,expected,state,output):
    import grpc
    from privoke.v1 import parameters_pb2_grpc as PG
    catalog=state/"catalog/privoke-balanced.json"
    audit=state/"updates/updates.jsonl"
    before=(sha(catalog),sha(audit))
    _,delta_response=decode_trace(head)
    stale=P.ParameterUpdateRequest(source_id="ft5-fuzzer",model_id=head["model_id"],base_version=head["base_version"],metadata=dict(delta_response.metadata))
    stale.metadata.update(request_id="ft5-deliberately-stale",request_source_id="ft5-admission",training_request_fingerprint="ft5-stale-fixed-payload")
    for delta in delta_response.gradients:stale.gradients.add(name=delta.name,shape=delta.shape,values=delta.values)
    conflicting=P.FuzzerTrainingRequest.FromString(bytes.fromhex(cycle["stages"]["heads"]["request_protobuf_hex"]))
    conflicting.seed+=1
    records=[]
    with grpc.insecure_channel(targets["updates"]) as uc,grpc.insecure_channel(targets["fuzzer"]) as fc:
        calls=(("stale_base",PG.ParamUpdateServiceStub(uc).SubmitParameterUpdate,stale),
               ("conflicting_stage_id",PG.FuzzerServiceStub(fc).RunTrainingCycle,conflicting))
        for name,method,request in calls:
            try:
                method(request,timeout=30)
            except grpc.RpcError as exc:
                require(exc.code() in (grpc.StatusCode.INVALID_ARGUMENT,grpc.StatusCode.FAILED_PRECONDITION,grpc.StatusCode.ALREADY_EXISTS),"Unexpected admission error/status")
                records.append({"case":name,"request":MessageToDict(request,preserving_proto_field_name=True),"code":exc.code().name,"details":exc.details()})
            else:raise AssertionError("Invalid admission request was accepted")
            require(snapshot(models,expected["model_id"])==expected and (sha(catalog),sha(audit))==before,"Rejected request changed model/audit")
    write_new(output,{"status":"passed","scope":"stale_and_conflicting_no_publication","records":records,"unchanged_artifact_sha256":before[0],"unchanged_audit_sha256":before[1]})
