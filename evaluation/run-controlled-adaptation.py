"""AD14 bounded matched pretrained adaptation: host-only Torch, no publication."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import threading
import time


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def retain(path, value):
    path = Path(path)
    payload = value if isinstance(value, bytes) else canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError("Immutable evidence differs: " + str(path))
    else:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())


def initialize(root):
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        os.environ[key] = "4"
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", CUBLAS_WORKSPACE_CONFIG=":4096:8")
    sys.path[:0] = [str(root / p) for p in ("evaluation", "services/pretrained-v3/src", "shared/python", "extension/client-runtime/generated", "extension/client-runtime", "services/privoke-fuzzer/src")]
    import torch
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    from common import pb, runtime_pb2
    from src.v3.model import PretrainedV3
    return torch, pb, runtime_pb2, PretrainedV3


def environment():
    import torch
    return {"python": sys.version, "executable": sys.executable, "packages": {name: importlib.metadata.version(name) for name in ("torch", "numpy", "transformers", "tokenizers", "safetensors", "grpcio", "protobuf")},
        "gpu": torch.cuda.get_device_name(), "vram_bytes": torch.cuda.get_device_properties(0).total_memory, "threads": torch.get_num_threads(), "deterministic": torch.are_deterministic_algorithms_enabled()}


def schedules(root, steps):
    from privoke_model.v3_contract import POLICY
    from fuzzer_training import schedule, validate_schedule
    policy = dict(POLICY, steps=steps, epochs=steps // 8)
    if steps == 2:
        policy.update(window_batches=1, epochs=2)
    values = {}
    for seed in ((42,) if steps == 2 else (42,43,44)):
        train, guard, source = schedule(seed, policy, sampler="audience_common_frozen_stream_v1")
        validate_schedule(train, guard, source, policy)
        values[str(seed)] = (train, guard, source)
    return policy, values


def prepare(root, output, models):
    from common import source_inventory
    from privoke_eval import audience_v3_data as data
    from privoke_model.training_data import training_text_key
    from privoke_model.v3_contract import validate_manifest
    data_path = root / "evaluation/results/audience_v3_20261013/data/release-07/manifest.json"
    manifest, train_all, assessment = data.validate_training_data(data_path, root)
    initial = root / "models/experiments/pretrained_v3_20261012/initials/balanced"
    base = validate_manifest(json.loads((initial / "manifest.json").read_bytes()))
    if base["scope"] != "original" or base["blob"] != "bfb59899774b9858292010b4cddc4e79cc4010e61b3c0216b896482c70626d15":
        raise ValueError("Independently pinned balanced ORIGINAL differs")
    original = models / "original"
    for filename, key in (("model.safetensors","blob"),("config.json","config"),("vocab.txt","vocab")):
        if sha(initial / filename) != base[key]:
            raise ValueError("Original source bytes differ")
        retain(original / filename, (initial / filename).read_bytes())
    retain(original / "manifest.json", (initial / "manifest.json").read_bytes())
    all_schedules={steps:schedules(root,steps) for steps in (2,64)}
    exposed_groups=set()
    exposed_keys=set()
    for policy, values in all_schedules.values():
        for train, guard, source in values.values():
            exposed_groups.update(source["train_groups"])
            exposed_groups.update(source["guard_groups"])
            exposed_keys.update(training_text_key(r.text) for r in (*train,*guard))
    original_assessment_rows=len(assessment)
    assessment=[r for r in assessment if r["group_id"] not in exposed_groups and training_text_key(r["text"]) not in exposed_keys]
    if not assessment:raise ValueError("No independent assessment rows remain after whole-group guard exclusion")
    retain(output / "assessment-ids.json",[r["id"] for r in assessment])
    checks = {}
    for steps, (policy, values) in all_schedules.items():
        for seed, (train, guard, source) in values.items():
            train_groups = set(source["train_groups"])
            guard_groups = set(source["guard_groups"])
            assessment_groups = {r["group_id"] for r in assessment}
            exposed = {training_text_key(r.text) for r in (*train,*guard)}
            assessment_keys = {training_text_key(r["text"]) for r in assessment}
            if train_groups & assessment_groups or guard_groups & assessment_groups or exposed & assessment_keys:
                raise ValueError("Generated TRAIN/guard overlaps assessment groups or normalized text")
            for scope in ("heads", "full_encoder"):
                directory = models / f"steps{steps}-{scope}-{seed}"
                retain(directory / "initial-catalog.json", {"independent_original": str(original), "manifest_sha256": sha(original / "manifest.json"), "assets": {f: sha(original / f) for f in ("model.safetensors","config.json","vocab.txt")}})
            retain(output / f"steps{steps}-seed{seed}-source.json", source)
            checks[f"steps{steps}-{seed}"] = {"train_wire_sha256": source["train_wire_sha256"], "guard_wire_sha256": source["guard_wire_sha256"],
                "source_sha256": sha(output / f"steps{steps}-seed{seed}-source.json"), "train_groups": len(train_groups), "guard_groups": len(guard_groups), "assessment_groups": len(assessment_groups),
                "overlap_groups": 0, "overlap_normalized_texts": 0, "train_occurrences": len(train), "steps": steps, "exposures": steps * 64}
    files = source_inventory()
    files.update({"evaluation/privoke_eval/audience_v3_data.py": sha(root / "evaluation/privoke_eval/audience_v3_data.py")})
    p = {"study_id": "AD14-bounded-matched", "repository": str(root), "models": str(models), "base_manifest_sha256": sha(original / "manifest.json"), "base_blob": base["blob"],
        "original": str(original), "base_ancestry": "intact official pretrained encoder/pooler + zero affine task heads; no PriVoke optimizer training", "random_model_initialization": False,
        "script_sha256": sha(__file__), "ablation_helper_sha256":sha(Path(__file__).with_name("run-controlled-product-ablation.py")), "source_files": files, "source_closure": hashlib.sha256(canonical(files)).hexdigest(), "environment": environment(),
        "data_manifest": str(data_path), "data_manifest_sha256": sha(data_path), "data_exclusion_proof": manifest["audit"],
        "assessment_role": "validation", "assessment_exclusion": {"method":"complete TRAIN and guard group union across all predeclared seeds, then normalized text union, before prediction", "original_rows":original_assessment_rows, "excluded_rows":original_assessment_rows-len(assessment), "ids_sha256":sha(output / "assessment-ids.json")}, "assessment_rows": len(assessment), "assessment_sha256": hashlib.sha256(canonical(assessment)).hexdigest(), "schedules": checks,
        "pilot": {"seed":42,"steps":2,"scopes":["heads","full_encoder"],"assessment_scoring":False,"resource_gate":{"maximum_fit_seconds_per_cell":120,"maximum_cuda_allocated_bytes":8589934592}},
        "main": {"seeds":[42,43,44],"steps":64,"scopes":["heads","full_encoder"],"unchanged_control":True,"terminal_only":True,"no_tuning":True},
        "treatment": "Only encoder trainability/additional encoder optimizer group differs; paired base/heads/data/order/head optimizer/objective/steps are identical",
        "fit_policy": all_schedules[64][0], "semantic_request_layers":[4], "actual_sole_successful_layer_required":True,
        "interpretation": "Reused assistant-provisional AU3 validation; descriptive fixed-base adaptation and resource evidence, not human privacy or pretraining causal evidence",
        "primary": ["FULL minus matched HEADS per seed joint/action/binary correctness and directional action harms", "each raw candidate minus unchanged ORIGINAL"],
        "guard_outcomes": "Retain all raw candidates regardless of guard result; no publication or promotion; effective rejected mapping remains ORIGINAL"}
    retain(output / "protocol.json", p)
    for name in files:
        retain(output / "source-capture" / name, (root / name).read_bytes())
    retain(output / "source-capture/adaptation-script.py", Path(__file__).read_bytes())
    return {"protocol_sha256":sha(output / "protocol.json"),"checks":checks,"source_closure":p["source_closure"]}


def validate(root, output):
    p = json.loads((output / "protocol.json").read_bytes())
    if sha(__file__) != p["script_sha256"] or environment() != p["environment"]:
        raise ValueError("Harness/environment drift after freeze")
    if any(sha(root / name) != value for name,value in p["source_files"].items()):
        raise ValueError("Runtime/source drift")
    if sha(p["data_manifest"]) != p["data_manifest_sha256"] or sha(Path(p["original"]) / "manifest.json") != p["base_manifest_sha256"]:
        raise ValueError("Data/base drift")
    return p


def load(p):
    path=Path(p["original"])
    manifest=json.loads((path / "manifest.json").read_bytes())
    model=MODEL.load(manifest,path / "model.safetensors",path / "config.json",path / "vocab.txt",device="cuda")
    if any(bool(t.any()) for t in model.heads.values()):
        raise ValueError("ORIGINAL task heads are not zero")
    return manifest,model


def run_fits(root,output,phase):
    from src.v3.training import fit,assess
    p=validate(root,output)
    steps=2 if phase=="pilot" else 64
    if phase=="main" and not (output / "pilot-accepted.json").exists():
        raise ValueError("Root-reviewed resource pilot acceptance required before main fits")
    policy,values=schedules(root,steps)
    results={}
    for seed,(train,guard,source) in values.items():
        if hashlib.sha256(canonical(source)).hexdigest()!=p["schedules"][f"steps{steps}-{seed}"]["source_sha256"]:
            raise ValueError("Actual source schedule drift")
        for scope in ("heads","full_encoder"):
            name=f"steps{steps}-{scope}-{seed}"
            directory=Path(p["models"]) / name
            reservation=directory / "reservation.json"
            if reservation.exists():
                raise ValueError("Physical fit already reserved; do not replay: " + name)
            manifest,model=load(p)
            request=PB.FitRequest(request_id="ad14-"+name,model_id=manifest["model_id"],base=p["base_manifest_sha256"],scope=1 if scope=="heads" else 2,
                layers=[4],train=train,guard=guard,policy_json=canonical(policy),source_commitment=hashlib.sha256(canonical(source)).hexdigest(),source_json=canonical(source))
            if list(request.layers)!=[4]:raise ValueError("Semantic fit layer isolation lost")
            retain(directory / "request.pb",request.SerializeToString(deterministic=True))
            retain(reservation,{"status":"reserved","request_sha256":sha(directory / "request.pb"),"created_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())})
            try:
                evidence=fit(model,request,policy)
                if evidence["phases"]["training"]["layer"]!=4 or evidence["phases"]["training"]["status"]!="ok":raise ValueError("Actual training semantic phase absent")
                tensors=model.export(directory / "candidate.safetensors")
                candidate=dict(manifest,parent=p["base_manifest_sha256"],original=p["base_manifest_sha256"],blob=sha(directory / "candidate.safetensors"),tensors=tensors,scope=scope,evidence="0"*64)
                reloaded=MODEL.load(candidate,directory / "candidate.safetensors",Path(p["original"])/"config.json",Path(p["original"])/"vocab.txt",device="cuda")
                if assess(reloaded,guard)!=evidence["candidate_guard"]:raise ValueError("Serialized guard parity failed")
                evidence.update(serialized_guard_parity=True,source=source)
                retain(directory / "evidence.json",evidence)
                candidate["evidence"]=sha(directory / "evidence.json")
                retain(directory / "manifest.json",candidate)
                terminal={"status":"completed","candidate_sha256":candidate["blob"],"evidence_sha256":candidate["evidence"],"seconds":evidence["seconds"],"cuda_peak_bytes":evidence["cuda_peak_bytes"],"action_harms":evidence["action_harms"],"counts":evidence["counts"],"changes":evidence["changes"]}
                retain(directory / "terminal.json",terminal)
                results[name]=terminal
                print(name,terminal["seconds"],terminal["cuda_peak_bytes"],flush=True)
                del model,reloaded
                TORCH.cuda.empty_cache()
            except BaseException as error:
                retain(directory / "failure.json",{"type":type(error).__name__,"error":str(error)})
                raise
    retain(output / (phase+"-results.json"),results)
    return results


def evaluate(root, output):
    import importlib.util
    from privoke_eval import pipeline_v1_v3 as c
    from privoke_eval.audience_v3_data import load_partition
    from runtime_server import RuntimeServer
    p=validate(root,output)
    c.configure(root)
    helper_path=Path(__file__).with_name("run-controlled-product-ablation.py")
    if sha(helper_path)!=p["ablation_helper_sha256"]:raise ValueError("Scoring helper drift")
    spec=importlib.util.spec_from_file_location("ablation_scoring",helper_path)
    helper=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.CORE=c
    selected_ids=json.loads((output / "assessment-ids.json").read_bytes())
    rows=[r for r in load_partition(p["data_manifest"],"validation") if r["id"] in set(selected_ids)]
    if hashlib.sha256(canonical(rows)).hexdigest()!=p["assessment_sha256"]:raise ValueError("Assessment drift")
    names=["original"]+[f"steps64-{scope}-{seed}" for seed in (42,43,44) for scope in ("heads","full_encoder")]
    records={}
    for name in names:
        directory=Path(p["original"]) if name=="original" else Path(p["models"]) / name
        manifest=json.loads((directory / "manifest.json").read_bytes())
        checkpoint=directory / ("model.safetensors" if name=="original" else "candidate.safetensors")
        model=MODEL.load(manifest,checkpoint,Path(p["original"])/"config.json",Path(p["original"])/"vocab.txt",device="cuda")
        identity={"model_id":manifest["model_id"],"model_version":sha(directory / "manifest.json"),"artifact_checksum":sha(directory / "manifest.json"),"parameter_fingerprint":manifest["blob"]}
        class Fixed(RuntimeServer):
            def __init__(self):
                self.lock=threading.RLock()
                self.cache={identity["artifact_checksum"]:(manifest,model)}
        native=Fixed()
        journal=c.Journal(output / "assessment" / name / "journal.jsonl")
        values=[]
        for index,row in enumerate(rows):
            key="ad14-eval-"+hashlib.sha256(canonical([name,row["id"],p["base_manifest_sha256"]])).hexdigest()[:32]
            req=RUNTIME.AnalyzePromptRequest(request_id=key,text=row["text"],layers=[4],semantic_model_id=manifest["model_id"],metadata={"v3_checkpoint":identity["artifact_checksum"]})
            if key not in journal.calls:
                wire=req.SerializeToString(deterministic=True)
                journal.append("reserve",key,request_pb=base64.b64encode(wire).decode(),request_sha256=hashlib.sha256(wire).hexdigest(),case_id=row["id"],index=index)
                started=time.perf_counter_ns()
                response=native.AnalyzePrompt(req,None)
                wire=response.SerializeToString(deterministic=True)
                journal.append("terminal",key,started_ns=started,ended_ns=time.perf_counter_ns(),response_pb=base64.b64encode(wire).decode(),response_sha256=hashlib.sha256(wire).hexdigest())
            wire=base64.b64decode(journal.calls[key]["terminal"]["response_pb"])
            value=helper.outcome(wire,{"identity":identity},req)
            values.append(dict(value,id=row["id"],family_id=row["family_id"],group_id=row["group_id"],target=row["classification"],allowed_actions=row["allowed_actions"]))
        c.require(len(values)==p["assessment_rows"],"Incomplete assessment")
        retain(output / "assessment" / name / "records.json",values)
        records[name]=values
        print("assessment",name,dict(Counter(r["status"] for r in values)),flush=True)
        del model,native
        TORCH.cuda.empty_cache()
    result={"protocol_sha256":sha(output / "protocol.json"),"rows":p["assessment_rows"],"summaries":{name:{"statuses":dict(Counter(r["status"] for r in values)),"correct":{m:sum(helper.metric(r,m) for r in values) for m in ("binary","action","joint")}} for name,values in records.items()},
        "candidate_minus_original":{name:helper.contrast(records["original"],values) for name,values in records.items() if name!="original"},
        "full_minus_heads":{str(seed):helper.contrast(records[f"steps64-heads-{seed}"],records[f"steps64-full_encoder-{seed}"]) for seed in (42,43,44)},
        "journal_hashes":{name:sha(output / "assessment" / name / "journal.jsonl") for name in records},
        "interpretation":p["interpretation"]}
    retain(output / "analysis.json",result)
    return result

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("prepare","pilot","main","evaluate"))
    parser.add_argument("--repository",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--models",type=Path,required=True)
    args=parser.parse_args()
    TORCH,PB,RUNTIME,MODEL=initialize(args.repository)
    result=prepare(args.repository,args.output,args.models) if args.action=="prepare" else evaluate(args.repository,args.output) if args.action=="evaluate" else run_fits(args.repository,args.output,args.action)
    print(canonical(result).decode())
