"""PH3 host-only frozen-encoder privacy heads; legacy studies remain immutable."""
from __future__ import annotations
import copy
from contextlib import contextmanager
import hashlib
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import platform
import random
import sys
import time
import torch
from torch.nn import functional as F

STUDY_ID = "privacy_heads_v3_20261013"
TIERS = ("efficient", "balanced", "quality")
LABELS = {"sensitivity": ["S0","S1","S2","S3"], "visibility": ["P0","P1","P2","P3","P4","PU"],
          "category": ["HEALTH","POLITICS","RELIGION","CRIMINAL","FINANCIAL","SEXUAL","CHILD","LOCATION","IDENTITY","THIRD_PARTY"]}
INITIAL_PINS = {
 "efficient": ("a60ab3c01592dd3d759950f35fad1a291aa94e57c954cf6beffa4e97d66a686e","5ae1b1e879e3330df62f926f7813919d6aa26baf5794bcaa0bde486b3aa068a3"),
 "balanced": ("81b3d20e1c695b81a159ec23b3b06567e548a84909f5de21fe8936966ec13fff","bfb59899774b9858292010b4cddc4e79cc4010e61b3c0216b896482c70626d15"),
 "quality": ("c86f710946090e31cb9b15d2e2fc476fb23ac74286cbae59e4d5aa286c90210e","57af677fadb69013a749ff1dce2159cb3191de8c386705dbba278e38231532ac")}
POLICY = {"schema":1, "scope":"heads", "layers":[4], "seed":42, "optimizer":"adamw",
 "head_lr":.001, "betas":[.9,.999], "eps":1e-8, "weight_decay":0., "clip_norm":1.,
 "batch_rows":64, "min_epochs":30, "max_epochs":200, "patience":20, "min_delta":.0001,
 "dropout":False, "category_threshold":.5, "device":"cpu",
 "class_weight":"inverse_sqrt_train_frequency_mean1_clip_0.5_4",
 "category_pos_weight":"sqrt_train_negative_over_positive_clip_1_8",
 "objective":"weighted_sensitivity_ce+weighted_visibility_ce+mean_category_posweighted_bce",
 "selection":"validation_loss_strict_improvement_keep_earliest_within_delta",
 "train_rows":6240, "validation_rows":1560, "fresh_eval_rows":1560}
NEW_SOURCES = ("evaluation/privoke_eval/privacy_heads_v3.py","evaluation/run-privacy-heads-v3.py",
 "evaluation/privoke_eval/privacy_heads_v3_serving.py","evaluation/privacy-heads-v3-server.py",
 "evaluation/privoke_eval/privacy_heads_v3_comparison.py",
 "services/privoke-fuzzer/src/prompt_generation/privacy_heads_curriculum.py",
 "evaluation/prepare-privacy-heads-v3.py")

def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()

def digest(payload):
    return hashlib.sha256(payload).hexdigest()

def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle,"sha256").hexdigest()

def read(path):
    return json.loads(Path(path).read_bytes())

def require(condition, reason):
    if not condition:
        raise ValueError(reason)

def relative_file(parent, value):
    parent = Path(parent).resolve()
    path = (parent/value).resolve()
    require(path.is_relative_to(parent),"Manifest path escapes declared directory")
    return path

def retain(path,value):
    path = Path(path)
    payload = value if isinstance(value,bytes) else canonical(value)
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        require(path.read_bytes()==payload,"Immutable evidence differs: "+str(path))
        return
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())

def atomic_write(path,payload):
    """Only publish completed bytes; a crash never leaves a partial pointer."""
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary = path.with_name(path.name+".tmp-"+str(os.getpid()))
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary,path)
    finally:
        temporary.unlink(missing_ok=True)

@contextmanager
def exclusive_run(path):
    """A stale lock requires operator reconciliation, not blind replay."""
    path = Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x") as handle:
        handle.write(str(os.getpid()))
    try:
        yield
    finally:
        path.unlink()

def configure_repository(root):
    root = Path(root).resolve()
    for relative in ("shared/python","extension/client-runtime/generated","extension/client-runtime",
                     "services/privoke-fuzzer/src","services/pretrained-v3/src"):
        value = str(root/relative)
        if value not in sys.path:
            sys.path.insert(0,value)
    from privoke_model.v3_contract import LABELS as native
    require(native==LABELS,"Native label order differs")
    return root

def deterministic(threads=4):
    require(type(threads) is int and 1<=threads<=32,"Invalid thread count")
    torch.set_num_threads(threads)
    torch.use_deterministic_algorithms(True)
    random.seed(POLICY["seed"])
    torch.manual_seed(POLICY["seed"])

def environment():
    packages = {name:importlib.metadata.version(name) for name in
                ("torch","numpy","transformers","tokenizers","safetensors","grpcio","protobuf")}
    return {"python":sys.version,"executable":sys.executable,"platform":platform.platform(),
            "packages":packages,"torch_threads":torch.get_num_threads(),"device":"cpu",
            "deterministic":torch.are_deterministic_algorithms_enabled()}

def source_inventory(root):
    root,files = Path(root),set()
    for prefix in ("shared/python","shared/proto","extension/client-runtime/src","extension/client-runtime/generated",
                   "services/privoke-fuzzer/src","services/pretrained-v3/src"):
        files.update(p for p in (root/prefix).rglob("*")
                     if p.is_file() and p.suffix in (".py",".proto") and "__pycache__" not in p.parts)
    for relative in NEW_SOURCES:
        path = root/relative
        require(path.is_file(),"Missing integrated PH3 source: "+relative)
        files.add(path)
    return {p.relative_to(root).as_posix():file_hash(p) for p in sorted(files)}

def validate_row(row,partition):
    from privoke_contracts.classification import Classification
    required = {"id","group_id","family_id","partition","text","classification","packed","allowed_actions","metadata"}
    require(required<=row.keys(),"Missing explicit row fields")
    require(row["partition"]==partition and partition in ("train","validation","fresh_eval"),"Partition mismatch")
    require(all(isinstance(row[k],str) and row[k].strip() for k in ("id","group_id","family_id","text")),
            "Empty identity/text")
    require(type(row["packed"]) is int,"Packed target is not an integer")
    value = Classification(row["packed"])
    require(value.pack()==row["packed"] and value.to_dict()==row["classification"],"Named/packed target disagree")
    require("packed_classification" not in row or row["packed_classification"]==row["packed"],"Packed alias disagrees")
    require(isinstance(row["metadata"],dict) and row["metadata"],"Missing provenance")
    actions = row["allowed_actions"]
    require(isinstance(actions,list) and actions and len(set(actions))==len(actions)
            and set(actions)<={"ALLOW","WARN","BLOCK"},"Invalid action set")
    return row

def load_partition(manifest_path,role,*,evaluation_authorized=False):
    require(role in ("train","validation") or (role=="fresh_eval" and evaluation_authorized),
            "Fresh evaluation cannot be read during preparation/cache/fit")
    manifest_path = Path(manifest_path)
    manifest = read(manifest_path)
    require(manifest.get("schema")==1 and manifest.get("study_id")==STUDY_ID,"Wrong data manifest")
    item = manifest["files"][role]
    path = relative_file(manifest_path.parent,item["path"])
    require(file_hash(path)==item["sha256"],"Dataset bytes changed: "+role)
    rows = [validate_row(json.loads(line),role) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(len(rows)==item["rows"] and len({r["id"] for r in rows})==len(rows),"Row/ID count mismatch")
    require(len({r["group_id"] for r in rows})==item["groups"],"Group count mismatch")
    return rows

def validate_training_data(manifest_path,root):
    from privoke_model.training_data import training_text_key
    manifest = read(manifest_path)
    require(manifest.get("schema")==1 and manifest.get("study_id")==STUDY_ID,"Wrong data manifest")
    require(set(manifest["files"])=={"train","validation","fresh_eval"},"Exactly three roles required")
    require(manifest["audit"]["status"]=="passed","Structural data audit has not passed")
    for name,sha in manifest["source_files"].items():
        require(file_hash(relative_file(root,name))==sha,"Dataset source drift: "+name)
    audit = manifest["audit"]
    require("proof_path" in audit and "sha256" in audit,"Dataset exclusion proof required")
    require(file_hash(relative_file(Path(manifest_path).parent,audit["proof_path"]))==audit["sha256"],
            "Dataset proof changed")
    train,validation = load_partition(manifest_path,"train"),load_partition(manifest_path,"validation")
    for role,rows in (("train",train),("validation",validation)):
        require(len(rows)==POLICY[role+"_rows"],"PH3 row budget differs")
        keys = [training_text_key(r["text"]) for r in rows]
        require(len(set(keys))==len(keys),"Duplicate normalized text: "+role)
        for task in ("sensitivity","visibility"):
            require({r["classification"][task] for r in rows}==set(LABELS[task]),"Missing class: "+role+"/"+task)
        for category in LABELS["category"]:
            positives = sum(category in r["classification"]["categories"] for r in rows)
            require(0<positives<len(rows),"Missing category positive/negative supervision")
    for key in ("group_id","family_id"):
        require(not ({r[key] for r in train}&{r[key] for r in validation}),"TRAIN/validation family leakage")
    require(not ({training_text_key(r["text"]) for r in train}&{training_text_key(r["text"]) for r in validation}),
            "TRAIN/validation text leakage")
    require(manifest["files"]["fresh_eval"]["rows"]==POLICY["fresh_eval_rows"],"Sealed eval budget differs")
    return manifest,train,validation

def targets(rows):
    return {"sensitivity":torch.tensor([LABELS["sensitivity"].index(r["classification"]["sensitivity"]) for r in rows],dtype=torch.long),
            "visibility":torch.tensor([LABELS["visibility"].index(r["classification"]["visibility"]) for r in rows],dtype=torch.long),
            "category":torch.tensor([[float(c in r["classification"]["categories"]) for c in LABELS["category"]] for r in rows],dtype=torch.float32)}

def class_weights(truth):
    result = {}
    for task in ("sensitivity","visibility"):
        counts = torch.bincount(truth[task],minlength=len(LABELS[task])).float()
        require(bool((counts>0).all()),"Missing TRAIN class")
        weight = counts.rsqrt()
        result[task] = (weight/weight.mean()).clamp(.5,4.)
    positives = truth["category"].sum(0)
    negatives = len(truth["category"])-positives
    require(bool(((positives>0)&(negatives>0)).all()),"Categories need TRAIN positive/negative supervision")
    result["category"] = (negatives/positives).sqrt().clamp(1.,8.)
    return result

def loss_parts(logits,truth,weights):
    """Weighted CE sums / selected target-weight sum; BCE mean / rows*10."""
    parts = {}
    for task in ("sensitivity","visibility"):
        numerator = F.cross_entropy(logits[task],truth[task],weight=weights[task],reduction="sum")
        parts[task] = numerator/weights[task][truth[task]].sum()
    parts["category"] = F.binary_cross_entropy_with_logits(logits["category"],truth["category"],
                                                          pos_weight=weights["category"],reduction="mean")
    require(all(bool(torch.isfinite(v)) for v in parts.values()),"Nonfinite task loss")
    return parts

def affine(features,heads):
    return {task:features@heads[task+"_weight"].T+heads[task+"_bias"] for task in LABELS}

def head_state(heads):
    return {name:value.detach().cpu().clone() for name,value in heads.items()}

def tensor_hash(value):
    return digest(value.detach().cpu().contiguous().numpy().tobytes())

def tensor_inventory(state):
    result = {}
    for name,value in state.items():
        require(value.dtype==torch.float32 and bool(torch.isfinite(value).all()),"Expected finite F32 tensor")
        result[name] = {"shape":list(value.shape),"dtype":"F32","sha256":tensor_hash(value)}
    return result

def frozen_proof(before,after):
    require(set(before)==set(after),"Tensor inventory changed")
    changed = sorted(name for name in before if before[name]!=after[name])
    require(all(name.startswith("heads.") for name in changed),"Frozen encoder tensor changed")
    encoder = {k:v for k,v in before.items() if k.startswith("encoder.")}
    require(encoder,"Missing encoder inventory")
    return {"encoder_tensor_count":len(encoder),"encoder_inventory_sha256":digest(canonical(encoder)),
            "all_encoder_tensors_equal":True,"changed_tensors":changed}

def load_initial(root,tier,directory=None):
    from privoke_model.v3_contract import validate_manifest
    from src.v3.model import PretrainedV3
    require(tier in TIERS,"Unknown tier")
    directory = Path(directory or Path(root)/"models/experiments/pretrained_v3_20261012/initials"/tier)
    manifest = validate_manifest(read(directory/"manifest.json"))
    require(file_hash(directory/"manifest.json")==INITIAL_PINS[tier][0]
            and file_hash(directory/"model.safetensors")==INITIAL_PINS[tier][1],"Pinned ORIGINAL changed")
    require(manifest["scope"]=="original","Requires linguistic ORIGINAL")
    model = PretrainedV3.load(manifest,directory/"model.safetensors",directory/"config.json",directory/"vocab.txt",device="cpu")
    require(all(not bool(torch.count_nonzero(p)) for p in model.heads.values()),"ORIGINAL heads are not zero")
    for parameter in model.encoder.parameters():
        parameter.requires_grad_(False)
    model.eval()
    require(sum(p.numel() for p in model.heads.parameters())==20*(model.encoder.config.hidden_size+1),
            "Trainable parameter count differs")
    return manifest,model

def prepare(root,results,models,manifest_path,*,feature_batch=16,threads=4):
    root = configure_repository(root)
    results,models = Path(results).resolve(),Path(models).resolve()
    deterministic(threads)
    require(type(feature_batch) is int and 1<=feature_batch<=64,"Invalid feature batch")
    dataset,_,_ = validate_training_data(manifest_path,root)
    sources,initials = source_inventory(root),{}
    for name,sha in sources.items():
        retain(results/"source-bytes"/sha,(root/name).read_bytes())
    for tier in TIERS:
        directory = root/"models/experiments/pretrained_v3_20261012/initials"/tier
        manifest,model = load_initial(root,tier,directory)
        del model
        for filename in ("manifest.json","model.safetensors","config.json","vocab.txt"):
            retain(models/"initials"/tier/filename,(directory/filename).read_bytes())
        initials[tier] = {"manifest":INITIAL_PINS[tier][0],"blob":manifest["blob"],
                          "tensors":manifest["tensors"],"source":manifest["source"]}
    protocol = {"schema":1,"study_id":STUDY_ID,"revision":"PH3-R1","policy":POLICY,
                "feature_batch":feature_batch,"threads":threads,"environment":environment(),
                "source_files":sources,"source_closure":digest(canonical(sources)),
                "dataset_manifest_sha256":file_hash(manifest_path),"dataset_files":dataset["files"],
                "initials":initials,"publication":"research_only_no_production_guard_or_promotion"}
    retain(results/"protocol.json",protocol)
    retain(results/"bindings.json",{"repository":str(root),"models":str(models),
                                   "dataset_manifest":str(Path(manifest_path).resolve())})
    return protocol

def validate_protocol(results):
    results = Path(results)
    protocol,binding = read(results/"protocol.json"),read(results/"bindings.json")
    root = configure_repository(binding["repository"])
    require(protocol["schema"]==1 and protocol["study_id"]==STUDY_ID and protocol["policy"]==POLICY,"PH3 protocol differs")
    deterministic(protocol["threads"])
    require(environment()==protocol["environment"],"Host environment drift")
    require(source_inventory(root)==protocol["source_files"],"Integrated source drift")
    require(digest(canonical(protocol["source_files"]))==protocol["source_closure"],"Source commitment differs")
    require(file_hash(binding["dataset_manifest"])==protocol["dataset_manifest_sha256"],"Dataset manifest changed")
    manifest,train,validation = validate_training_data(binding["dataset_manifest"],root)
    require(manifest["files"]==protocol["dataset_files"],"Dataset role commitments differ")
    return protocol,binding,train,validation

def require_approval(results,name):
    path = Path(results)/name
    approval = read(path)
    require(approval.get("status")=="accepted" and approval.get("protocol_sha256")==file_hash(Path(results)/"protocol.json"),
            "Root acceptance missing or bound to another protocol: "+name)
    return file_hash(path)

def pooled(model,texts):
    with torch.no_grad():
        return model.encoder(**model.tokenize(texts)).pooler_output.detach().cpu().contiguous()

def parity_probe(model,rows,features,batch):
    saved,probes,maximum = head_state(model.heads),[],0.
    try:
        for mode in ("original_zero_heads","synthetic_head_update"):
            if mode=="synthetic_head_update":
                with torch.no_grad():
                    for index,parameter in enumerate(model.heads.values()):
                        values = torch.arange(parameter.numel(),dtype=torch.float32).reshape(parameter.shape)
                        parameter.copy_(((values%17)-8)*.003+index*.001)
            for begin in range(0,min(len(rows),batch*2),batch):
                texts = [r["text"] for r in rows[begin:begin+batch]]
                with torch.no_grad():
                    native,cached = model(texts),affine(features[begin:begin+len(texts)],model.heads)
                for task in LABELS:
                    maximum = max(maximum,float((native[task]-cached[task]).abs().max()))
                    require(torch.allclose(native[task],cached[task],atol=1e-5,rtol=1e-5),"Native/cache logits disagree")
                    if task=="category":
                        require(torch.equal(native[task]>=0,cached[task]>=0),"Native/cache category disagreement")
                    else:
                        require(torch.equal(native[task].argmax(-1),cached[task].argmax(-1)),"Native/cache argmax disagreement")
                probes.append({"phase":mode,"begin":begin,"rows":len(texts)})
    finally:
        with torch.no_grad():
            for name,value in saved.items():
                model.heads[name].copy_(value)
    return {"atol":1e-5,"rtol":1e-5,"max_abs_logit_error":maximum,"probes":probes}

def torch_bytes(value):
    buffer = io.BytesIO()
    torch.save(value,buffer)
    return buffer.getvalue()

def load_torch(path):
    return torch.load(path,map_location="cpu",weights_only=True)

def cache(results,tier):
    protocol,binding,train,validation = validate_protocol(results)
    require_approval(results,"resource-acceptance.json")
    if (Path(results)/"cache"/tier/"complete.json").exists():
        _,existing = load_cache(results,tier,protocol,binding)
        return existing
    models = Path(binding["models"])
    manifest,model = load_initial(binding["repository"],tier,models/"initials"/tier)
    data,start = {},time.monotonic()
    for role,rows in (("train",train),("validation",validation)):
        chunks = [pooled(model,[r["text"] for r in rows[begin:begin+protocol["feature_batch"]]])
                  for begin in range(0,len(rows),protocol["feature_batch"])]
        features = torch.cat(chunks)
        require(bool(torch.isfinite(features).all()) and len(features)==len(rows),"Nonfinite/incomplete feature cache")
        parity = parity_probe(model,rows,features,protocol["feature_batch"])
        data[role] = {"features":features,"targets":targets(rows)}
        retain(Path(results)/"cache"/tier/(role+"-parity.json"),parity)
    proof = frozen_proof(manifest["tensors"],tensor_inventory(model.state_dict()))
    identity = {"protocol_sha256":file_hash(Path(results)/"protocol.json"),"tier":tier,"base":INITIAL_PINS[tier][0],
                "dataset_files":protocol["dataset_files"],"feature_batch":protocol["feature_batch"],"encoder_proof":proof}
    path = models/"cache"/tier/"features.pt"
    payload = torch_bytes({"identity":identity,**data})
    retain(path,payload)
    record = {"identity":identity,"sha256":file_hash(path),"bytes":len(payload),"seconds":time.monotonic()-start,
              "train_feature_std":float(data["train"]["features"].std()),
              "train_feature_mean_norm":float(data["train"]["features"].norm(dim=-1).mean())}
    retain(Path(results)/"cache"/tier/"complete.json",record)
    return record

def load_cache(results,tier,protocol,binding):
    path = Path(binding["models"])/"cache"/tier/"features.pt"
    record = read(Path(results)/"cache"/tier/"complete.json")
    require(file_hash(path)==record["sha256"],"Feature bytes drift")
    data = load_torch(path)
    require(data["identity"]==record["identity"]
            and data["identity"]["protocol_sha256"]==file_hash(Path(results)/"protocol.json")
            and data["identity"]["tier"]==tier and data["identity"]["dataset_files"]==protocol["dataset_files"],
            "Cache binding mismatch")
    for role in ("train","validation"):
        require(len(data[role]["features"])==POLICY[role+"_rows"] and bool(torch.isfinite(data[role]["features"]).all()),
                "Invalid cached features")
    return data,record

def update_selection(state,value,epoch,heads,policy):
    require(math.isfinite(value),"Nonfinite validation selection loss")
    if value<state["best_loss"]-policy["min_delta"]:
        state.update(best_loss=value,best_epoch=epoch,best_heads=head_state(heads),stale_epochs=0)
        return True
    state["stale_epochs"]+=1
    return False

def make_optimizer(heads,policy=POLICY):
    return torch.optim.AdamW(list(heads.parameters()),lr=policy["head_lr"],betas=tuple(policy["betas"]),
                             eps=policy["eps"],weight_decay=policy["weight_decay"])

def one_epoch(heads,optimizer,features,truth,weights,epoch,policy=POLICY):
    order = torch.randperm(len(features),generator=torch.Generator().manual_seed(policy["seed"]+epoch))
    losses,gradients,exposures = [],[],0
    for begin in range(0,len(features),policy["batch_rows"]):
        indices = order[begin:begin+policy["batch_rows"]]
        optimizer.zero_grad(set_to_none=True)
        parts = loss_parts(affine(features[indices],heads),{k:v[indices] for k,v in truth.items()},weights)
        sum(parts.values()).backward()
        require(all(p.grad is not None and bool(torch.isfinite(p.grad).all()) for p in heads.parameters()),
                "Missing/nonfinite head gradient")
        norm = torch.nn.utils.clip_grad_norm_(list(heads.parameters()),policy["clip_norm"],error_if_nonfinite=True)
        optimizer.step()
        require(all(bool(torch.isfinite(p).all()) for p in heads.parameters()),"Nonfinite head parameter")
        exposures+=len(indices)
        losses.append({k:float(v.detach()) for k,v in parts.items()})
        gradients.append(float(norm))
    return {"epoch":epoch,"optimizer_steps":len(losses),"train_exposures":exposures,
            "permutation_sha256":digest(order.numpy().tobytes()),"batch_task_losses":losses,
            "gradient_norms_before_clip":gradients}

def validation_metrics(features,truth,heads,weights):
    with torch.no_grad():
        logits = affine(features,heads)
        weighted = loss_parts(logits,truth,weights)
        unweighted = loss_parts(logits,truth,{k:torch.ones_like(v) for k,v in weights.items()})
        predicted,positive = logits["category"]>=0,truth["category"].bool()
        s,v = logits["sensitivity"].argmax(-1),logits["visibility"].argmax(-1)
        category_exact = (predicted==positive).all(-1)
        exact = category_exact&(s==truth["sensitivity"])&(v==truth["visibility"])
        bearing = positive.any(-1)
        sensitive = bearing|(truth["sensitivity"]!=0)
        def count(mask,correct):
            return {"correct":int((mask&correct).sum()),"denominator":int(mask.sum())}
        all_rows = torch.ones(len(features),dtype=torch.bool)
        components = {"sensitivity":count(all_rows,s==truth["sensitivity"]),
                      "visibility":count(all_rows,v==truth["visibility"]),"packed_exact":count(all_rows,exact),
                      "category_bearing_category_exact":count(bearing,category_exact),
                      "category_bearing_packed_exact":count(bearing,exact),
                      "contextual_sensitive_packed_exact":count(sensitive,exact)}
        categories = {name:{"tp":int((predicted[:,i]&positive[:,i]).sum()),
                            "fp":int((predicted[:,i]&~positive[:,i]).sum()),
                            "fn":int((~predicted[:,i]&positive[:,i]).sum())}
                      for i,name in enumerate(LABELS["category"])}
    return {"weighted_objective":sum(float(x) for x in weighted.values()),
            "weighted_task_losses":{k:float(v) for k,v in weighted.items()},
            "unweighted_task_losses":{k:float(v) for k,v in unweighted.items()},
            "classification_components":components,"categories":categories}

def save_checkpoint(directory,state):
    payload = torch_bytes(state)
    sha = digest(payload)
    retain(Path(directory)/(sha+".pt"),payload)
    atomic_write(Path(directory)/"latest.json",canonical({"sha256":sha,"epoch":state["epoch"]}))
    return sha

def restore_checkpoint(directory,expected_identity):
    pointer = read(Path(directory)/"latest.json")
    path = Path(directory)/(pointer["sha256"]+".pt")
    require(file_hash(path)==pointer["sha256"],"Checkpoint bytes drift")
    state = load_torch(path)
    require(state["identity"]==expected_identity and state["epoch"]==pointer["epoch"],"Resume identity mismatch")
    return state

def fit(results,tier,*,resume=False):
    protocol,binding,_,_ = validate_protocol(results)
    approval = require_approval(results,"prefit-acceptance.json")
    data,record = load_cache(results,tier,protocol,binding)
    models = Path(binding["models"])
    manifest,model = load_initial(binding["repository"],tier,models/"initials"/tier)
    heads,optimizer = model.heads,make_optimizer(model.heads)
    require(all(not p.requires_grad and p.grad is None for p in model.encoder.parameters()),"Encoder not frozen")
    require({id(p) for g in optimizer.param_groups for p in g["params"]}=={id(p) for p in heads.parameters()},
            "Optimizer includes encoder")
    weights = class_weights(data["train"]["targets"])
    identity = {"protocol_sha256":file_hash(Path(results)/"protocol.json"),"tier":tier,"base":INITIAL_PINS[tier][0],
                "cache_sha256":record["sha256"],"prefit_acceptance_sha256":approval,
                "weights":{k:v.tolist() for k,v in weights.items()}}
    checkpoints = models/"cells"/tier/"checkpoints"
    complete = Path(results)/"fits"/tier/"complete.json"
    require(not complete.exists(),"Tier completed; audit instead of refitting")
    state = {"identity":identity,"epoch":0,"optimizer_steps":0,"train_exposures":0,"best_loss":float("inf"),
             "best_epoch":0,"best_heads":head_state(heads),"stale_epochs":0,"heads":head_state(heads),
             "optimizer":optimizer.state_dict(),"torch_rng":torch.get_rng_state(),"python_rng":random.getstate()}
    if resume:
        state = restore_checkpoint(checkpoints,identity)
        if "epoch_record" in state:
            retain(Path(results)/"fits"/tier/"epochs"/f"{state['epoch']:04d}.json",
                   dict(state["epoch_record"],checkpoint=read(checkpoints/"latest.json")["sha256"]))
        heads.load_state_dict(state["heads"],strict=True)
        optimizer.load_state_dict(state["optimizer"])
        torch.set_rng_state(state["torch_rng"])
        random.setstate(state["python_rng"])
    else:
        require(not (checkpoints/"latest.json").exists(),"Existing fit requires explicit resume")
    started = time.monotonic()
    with exclusive_run(models/"cells"/tier/"fit.lock"):
        already_stopped = state["epoch"]>=POLICY["min_epochs"] and state["stale_epochs"]>=POLICY["patience"]
        last_epoch = state["epoch"] if already_stopped else POLICY["max_epochs"]
        for epoch in range(state["epoch"]+1,last_epoch+1):
            validate_protocol(results)
            work = one_epoch(heads,optimizer,data["train"]["features"],data["train"]["targets"],weights,epoch)
            metrics = validation_metrics(data["validation"]["features"],data["validation"]["targets"],heads,weights)
            selected = update_selection(state,metrics["weighted_objective"],epoch,heads,POLICY)
            state.update(epoch=epoch,optimizer_steps=state["optimizer_steps"]+work["optimizer_steps"],
                         train_exposures=state["train_exposures"]+work["train_exposures"],heads=head_state(heads),
                         optimizer=copy.deepcopy(optimizer.state_dict()),torch_rng=torch.get_rng_state(),python_rng=random.getstate())
            proof = frozen_proof(manifest["tensors"],tensor_inventory(model.state_dict()))
            require(all(p.grad is None for p in model.encoder.parameters()),"Encoder received gradient")
            state["epoch_record"] = {"work":work,"validation":metrics,"selected":selected,"best_epoch":state["best_epoch"],
                                     "best_loss":state["best_loss"],"stale_epochs":state["stale_epochs"],"frozen":proof}
            checkpoint = save_checkpoint(checkpoints,state)
            retain(Path(results)/"fits"/tier/"epochs"/f"{epoch:04d}.json",dict(state["epoch_record"],checkpoint=checkpoint))
            print(json.dumps({"tier":tier,"epoch":epoch,"validation_loss":metrics["weighted_objective"],
                              "best_epoch":state["best_epoch"],"patience":state["stale_epochs"]}),flush=True)
            if epoch>=POLICY["min_epochs"] and state["stale_epochs"]>=POLICY["patience"]:
                break
        reason = "validation_patience" if state["stale_epochs"]>=POLICY["patience"] else "max_epochs"
        summary = {"identity":identity,"epoch":state["epoch"],"best_epoch":state["best_epoch"],"best_loss":state["best_loss"],
                   "optimizer_steps":state["optimizer_steps"],"train_exposures":state["train_exposures"],"stop_reason":reason,
                   "checkpoint":read(checkpoints/"latest.json")["sha256"],"seconds_this_invocation":time.monotonic()-started,
                   "resumed":resume,"publication":"research_only"}
        retain(complete,summary)
    return summary

def export(results,tier):
    protocol,binding,_,validation = validate_protocol(results)
    summary = read(Path(results)/"fits"/tier/"complete.json")
    require(summary["epoch"]>=POLICY["min_epochs"],"Incomplete training cannot export")
    models = Path(binding["models"])
    state = restore_checkpoint(models/"cells"/tier/"checkpoints",summary["identity"])
    require(read(models/"cells"/tier/"checkpoints/latest.json")["sha256"]==summary["checkpoint"],"Terminal checkpoint differs")
    original,model = load_initial(binding["repository"],tier,models/"initials"/tier)
    outputs = {}
    for kind,key,epoch in (("selected","best_heads",state["best_epoch"]),("terminal","heads",state["epoch"])):
        model.heads.load_state_dict(state[key],strict=True)
        directory = models/"exports"/tier/kind
        directory.mkdir(parents=True,exist_ok=True)
        temporary = directory/("export-"+str(os.getpid())+".tmp")
        try:
            inventory = model.export(temporary)
            payload = temporary.read_bytes()
        finally:
            temporary.unlink(missing_ok=True)
        proof = frozen_proof(original["tensors"],inventory)
        require(proof["changed_tensors"],"Export has no learned head changes")
        evidence = {"schema":1,"study_id":STUDY_ID,"scope":"heads","layers":[4],"tier":tier,"base":INITIAL_PINS[tier][0],
                    "protocol_sha256":file_hash(Path(results)/"protocol.json"),
                    "dataset_manifest_sha256":protocol["dataset_manifest_sha256"],"source_closure":protocol["source_closure"],
                    "policy":POLICY,"fit_summary_sha256":file_hash(Path(results)/"fits"/tier/"complete.json"),
                    "checkpoint":summary["checkpoint"],"epoch":epoch,"kind":kind,"candidate_blob":digest(payload),
                    "frozen":proof,"selection":"validation_only_no_fresh_eval_access",
                    "publication":"research_only_no_legacy_guard_or_promotion"}
        evidence_bytes = canonical(evidence)
        manifest = dict(original,parent=INITIAL_PINS[tier][0],original=INITIAL_PINS[tier][0],scope="heads",
                        blob=digest(payload),tensors=inventory,evidence=digest(evidence_bytes))
        retain(directory/"model.safetensors",payload)
        retain(directory/"evidence.json",evidence_bytes)
        retain(directory/"manifest.json",manifest)
        for filename in ("config.json","vocab.txt"):
            retain(directory/filename,(models/"initials"/tier/filename).read_bytes())
        from src.v3.model import PretrainedV3
        reloaded = PretrainedV3.load(manifest,directory/"model.safetensors",directory/"config.json",directory/"vocab.txt",device="cpu")
        frozen_proof(original["tensors"],tensor_inventory(reloaded.state_dict()))
        texts = [r["text"] for r in validation[:8]]
        require(reloaded.predictions(texts)==model.predictions(texts),"Serialized/native predictions differ")
        outputs[kind] = {"directory":str(directory),"manifest_sha256":file_hash(directory/"manifest.json"),
                         "blob":manifest["blob"],"evidence":manifest["evidence"],"epoch":epoch}
    retain(Path(results)/"exports"/(tier+".json"),outputs)
    return outputs

def validate_export(results,tier,kind="selected"):
    """Independent PH3 admission; never claim legacy study admission."""
    protocol,binding,_,_ = validate_protocol(results)
    from privoke_model.v3_contract import validate_manifest
    from src.v3.model import PretrainedV3
    models = Path(binding["models"])
    output = read(Path(results)/"exports"/(tier+".json"))[kind]
    directory = Path(output["directory"])
    require(directory.resolve().is_relative_to(models.resolve()),"Export outside PH3 storage")
    manifest,evidence = validate_manifest(read(directory/"manifest.json")),read(directory/"evidence.json")
    require(file_hash(directory/"manifest.json")==output["manifest_sha256"]
            and file_hash(directory/"evidence.json")==manifest["evidence"]
            and file_hash(directory/"model.safetensors")==manifest["blob"],"Export asset hash differs")
    expected = {"schema":1,"study_id":STUDY_ID,"scope":"heads","layers":[4],"tier":tier,"base":INITIAL_PINS[tier][0],
                "protocol_sha256":file_hash(Path(results)/"protocol.json"),
                "dataset_manifest_sha256":protocol["dataset_manifest_sha256"],"source_closure":protocol["source_closure"],
                "policy":POLICY,"kind":kind,"candidate_blob":manifest["blob"],
                "selection":"validation_only_no_fresh_eval_access","publication":"research_only_no_legacy_guard_or_promotion"}
    require(all(evidence.get(k)==v for k,v in expected.items()),"PH3 evidence binding differs")
    require(manifest["parent"]==manifest["original"]==INITIAL_PINS[tier][0] and manifest["scope"]=="heads","Lineage mismatch")
    summary_path = Path(results)/"fits"/tier/"complete.json"
    summary = read(summary_path)
    require(file_hash(summary_path)==evidence["fit_summary_sha256"] and summary["checkpoint"]==evidence["checkpoint"]
            and evidence["epoch"]==(summary["best_epoch"] if kind=="selected" else summary["epoch"]),"Selection commitment differs")
    checkpoint_dir = models/"cells"/tier/"checkpoints"
    state = restore_checkpoint(checkpoint_dir,summary["identity"])
    require(summary["epoch"]==state["epoch"] and state["epoch"]>=POLICY["min_epochs"],"Incomplete checkpoint")
    for epoch in range(1,state["epoch"]+1):
        metric = read(Path(results)/"fits"/tier/"epochs"/f"{epoch:04d}.json")
        path = checkpoint_dir/(metric["checkpoint"]+".pt")
        require(file_hash(path)==metric["checkpoint"],"Epoch checkpoint missing/corrupt")
    model = PretrainedV3.load(manifest,directory/"model.safetensors",directory/"config.json",directory/"vocab.txt",device="cpu")
    inventory = tensor_inventory(model.state_dict())
    require(inventory==manifest["tensors"],"Export tensor inventory differs")
    require(evidence["frozen"]==frozen_proof(protocol["initials"][tier]["tensors"],inventory),"Frozen proof differs")
    desired = state["best_heads" if kind=="selected" else "heads"]
    require(all(torch.equal(model.heads[k].detach(),v) for k,v in desired.items()),"Export not selected checkpoint")
    return {"manifest":manifest,"manifest_sha256":output["manifest_sha256"],"directory":str(directory),"evidence":evidence}

def resource_probe(root,results,manifest_path,*,threads=4):
    """Measure native CPU pooling on TRAIN only; never fit or open fresh eval."""
    root = configure_repository(root)
    deterministic(threads)
    _,train,_ = validate_training_data(manifest_path,root)
    sources = source_inventory(root)
    selected = train[:32]
    report = {"schema":1,"study_id":STUDY_ID,"purpose":"train_only_resource_and_mechanics",
              "dataset_manifest_sha256":file_hash(manifest_path),"source_closure":digest(canonical(sources)),
              "environment":environment(),"tiers":{},"fresh_eval_access":False}
    for tier in TIERS:
        manifest,model = load_initial(root,tier)
        trials = []
        for batch in (4,8,16):
            start = time.perf_counter()
            features = torch.cat([pooled(model,[r["text"] for r in selected[begin:begin+batch]])
                                  for begin in range(0,len(selected),batch)])
            seconds = time.perf_counter()-start
            require(bool(torch.isfinite(features).all()) and float(features.std())>0,
                    "Invalid/nonvarying pretrained pooled features")
            parity = parity_probe(model,selected,features,batch)
            trials.append({"batch":batch,"seconds":seconds,"rows":len(selected),
                           "rows_per_second":len(selected)/seconds,"parity":parity,
                           "feature_std":float(features.std()),"mean_norm":float(features.norm(dim=-1).mean())})
        report["tiers"][tier] = {"trials":trials,
             "frozen":frozen_proof(manifest["tensors"],tensor_inventory(model.state_dict()))}
    # One common batch from aggregate measured time, never quality selection.
    totals = {batch:sum(next(r["seconds"] for r in report["tiers"][t]["trials"] if r["batch"]==batch)
                         for t in TIERS) for batch in (4,8,16)}
    report["recommended_feature_batch"] = min(totals,key=totals.get)
    retain(Path(results)/"resource-probe.json",report)
    return report


def audit_training(results,tier):
    """Reconcile validation selection, work totals and frozen exported bytes."""
    protocol,binding,_,_ = validate_protocol(results)
    summary = read(Path(results)/"fits"/tier/"complete.json")
    models = Path(binding["models"])
    data,record = load_cache(results,tier,protocol,binding)
    weights = class_weights(data["train"]["targets"])
    state = restore_checkpoint(models/"cells"/tier/"checkpoints",summary["identity"])
    require(summary["identity"]["weights"]=={k:v.tolist() for k,v in weights.items()},"TRAIN loss weights differ")
    replay = {"best_loss":float("inf"),"best_epoch":0,"best_heads":{},"stale_epochs":0}
    steps,exposures = 0,0
    for epoch in range(1,state["epoch"]+1):
        item = read(Path(results)/"fits"/tier/"epochs"/f"{epoch:04d}.json")
        path = models/"cells"/tier/"checkpoints"/(item["checkpoint"]+".pt")
        require(file_hash(path)==item["checkpoint"],"Epoch checkpoint missing/corrupt")
        candidate = load_torch(path)
        require(candidate["identity"]==summary["identity"] and candidate["epoch"]==epoch,"Epoch identity mismatch")
        heads = torch.nn.ParameterDict({k:torch.nn.Parameter(v) for k,v in candidate["heads"].items()})
        metrics = validation_metrics(data["validation"]["features"],data["validation"]["targets"],heads,weights)
        require(metrics==item["validation"],"Validation metrics do not reproduce from checkpoint")
        selected = update_selection(replay,metrics["weighted_objective"],epoch,heads,POLICY)
        require(selected==item["selected"] and replay["best_epoch"]==item["best_epoch"]
                and replay["best_loss"]==item["best_loss"] and replay["stale_epochs"]==item["stale_epochs"],
                "Selection/patience replay differs")
        work = item["work"]
        expected_steps = math.ceil(POLICY["train_rows"]/POLICY["batch_rows"])
        require(work["epoch"]==epoch and work["optimizer_steps"]==expected_steps
                and work["train_exposures"]==POLICY["train_rows"],"Actual full-epoch work differs")
        require(len(work["batch_task_losses"])==len(work["gradient_norms_before_clip"])==expected_steps
                and all(math.isfinite(v) for row in work["batch_task_losses"] for v in row.values())
                and all(math.isfinite(v) for v in work["gradient_norms_before_clip"]),"Missing/nonfinite work trace")
        steps+=expected_steps
        exposures+=POLICY["train_rows"]
        require(candidate["optimizer_steps"]==steps and candidate["train_exposures"]==exposures,"Cumulative work differs")
        require(epoch==state["epoch"] or epoch<POLICY["min_epochs"] or replay["stale_epochs"]<POLICY["patience"],
                "Fit continued beyond its declared stopping point")
    require(POLICY["min_epochs"]<=state["epoch"]<=POLICY["max_epochs"],"Epoch bound differs")
    require(replay["best_epoch"]==summary["best_epoch"]==state["best_epoch"]
            and replay["best_loss"]==summary["best_loss"]==state["best_loss"],"Terminal selection mismatch")
    require(steps==summary["optimizer_steps"] and exposures==summary["train_exposures"],"Summary work differs")
    reason = "validation_patience" if replay["stale_epochs"]>=POLICY["patience"] else "max_epochs"
    require(summary["stop_reason"]==reason and
            (reason=="validation_patience" or state["epoch"]==POLICY["max_epochs"]),"Invalid stopping criterion")
    exports = {kind:validate_export(results,tier,kind)["manifest_sha256"] for kind in ("selected","terminal")}
    report = {"tier":tier,"epochs":state["epoch"],"best_epoch":replay["best_epoch"],"optimizer_steps":steps,
              "train_exposures":exposures,"cache":record["sha256"],"exports":exports,"status":"passed"}
    retain(Path(results)/"audit"/(tier+".json"),report)
    return report
