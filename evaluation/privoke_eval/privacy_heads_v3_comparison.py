"""Fresh six-model native semantic comparison after all PH3 exports are fixed."""
from __future__ import annotations
from collections import Counter
import math
from pathlib import Path
import statistics
import time
from . import privacy_heads_v3 as core

TINY_PINS = {
 "efficient":"c8992bda8a75f5ee7165a3debabaef1a229c4f661be2f5792de65c0aefcf9a5b",
 "balanced":"dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51",
 "quality":"c3126ae0ae238d3967226b6c616491fb90e9b766a3fbb6e066203cb92f2ed8c8",
}
ACTION_RANK = {"ALLOW":0,"WARN":1,"BLOCK":2}


def tiny_entry(root,models,tier):
    from privoke_model.artifact import load_artifact,float32
    from privoke_model.fingerprint import parameter_fingerprint
    source = Path(root)/"models"/("privoke-"+tier+".json")
    core.require(core.file_hash(source)==TINY_PINS[tier],"Unchanged V1 bytes differ")
    artifact = load_artifact(source)
    parameters = {k:tuple(float32(x) for x in v["values"]) for k,v in artifact["parameters"].items()}
    shapes = {k:tuple(v["shape"]) for k,v in artifact["parameters"].items()}
    path = Path(models)/"v1"/tier/"artifact.json"
    core.retain(path,source.read_bytes())
    return {"name":"v1-"+tier,"family":"v1","tier":tier,"directory":str(path.parent),
            "file_sha256":TINY_PINS[tier],"source":str(source),
            "parameter_count":sum(map(len,parameters.values())),
            "native_cap":artifact["config"]["max_tokens"],"config":artifact["config"],
            "identity":{"model_id":artifact["model_id"],"model_version":artifact["version"],
                        "artifact_checksum":artifact["checksum"],
                        "parameter_fingerprint":parameter_fingerprint(parameters,shapes)}}


def freeze_registry(results):
    """Seal all exports before opening or making predictions on fresh evaluation."""
    protocol,binding,_,_ = core.validate_protocol(results)
    entries,seal = [],{}
    for tier in core.TIERS:
        core.audit_training(results,tier)
        admitted = core.validate_export(results,tier)
        manifest = admitted["manifest"]
        identity = {"model_id":manifest["model_id"],"model_version":admitted["manifest_sha256"],
                    "artifact_checksum":admitted["manifest_sha256"],"parameter_fingerprint":manifest["blob"],
                    "parameter_count":str(manifest["parameter_count"]),"backbone_sha256":manifest["source"]["weights_sha256"],
                    "tokenizer_sha256":manifest["vocab"],"architecture":manifest["architecture"]}
        entries.append({"name":"v3-"+tier,"family":"v3","tier":tier,"directory":admitted["directory"],
                        "manifest_sha256":admitted["manifest_sha256"],"identity":identity,
                        "parameter_count":manifest["parameter_count"],"native_cap":512})
        seal[tier] = {"export":core.file_hash(Path(results)/"exports"/(tier+".json")),
                      "audit":core.file_hash(Path(results)/"audit"/(tier+".json"))}
        # Source ORIGINALs must still exist byte-identical after all fitting.
        _,model = core.load_initial(binding["repository"],tier)
        del model
    entries = [tiny_entry(binding["repository"],binding["models"],tier) for tier in core.TIERS]+entries
    registry = {"schema":1,"study_id":core.STUDY_ID,"protocol_sha256":core.file_hash(Path(results)/"protocol.json"),
                "source_closure":protocol["source_closure"],"exports_seal":seal,"entries":entries,
                "fresh_eval":protocol["dataset_files"]["fresh_eval"],"layers":[4],"visibility_hints":"",
                "performance":{"batch":1,"concurrency":1,"warmup_train_rows":4,
                               "latency":"host full RPC; fresh accuracy loop, descriptive workload cost"},
                "claim":"new assistant-provisional synthetic fixture; native package comparison; no promotion"}
    core.retain(Path(results)/"comparison/registry.json",registry)
    return registry


def validate_registry(results):
    protocol,binding,_,_ = core.validate_protocol(results)
    path = Path(results)/"comparison/registry.json"
    registry = core.read(path)
    core.require(registry["schema"]==1 and registry["study_id"]==core.STUDY_ID
                 and registry["protocol_sha256"]==core.file_hash(Path(results)/"protocol.json")
                 and registry["source_closure"]==protocol["source_closure"]
                 and registry["fresh_eval"]==protocol["dataset_files"]["fresh_eval"]
                 and registry["layers"]==[4] and registry["visibility_hints"]=="","Comparison registry changed")
    core.require([e["name"] for e in registry["entries"]]==
                 ["v1-"+t for t in core.TIERS]+["v3-"+t for t in core.TIERS],"Six fixed models required")
    for tier in core.TIERS:
        core.require(registry["exports_seal"][tier]=={
            "export":core.file_hash(Path(results)/"exports"/(tier+".json")),
            "audit":core.file_hash(Path(results)/"audit"/(tier+".json"))},"Export seal changed")
    for entry in registry["entries"]:
        directory = Path(entry["directory"])
        if entry["family"]=="v1":
            core.require(core.file_hash(directory/"artifact.json")==entry["file_sha256"]==TINY_PINS[entry["tier"]]
                         and core.file_hash(entry["source"])==entry["file_sha256"],"V1 bytes changed")
        else:
            core.require(core.file_hash(directory/"manifest.json")==entry["manifest_sha256"],"V3 manifest changed")
            manifest = core.read(directory/"manifest.json")
            for filename,key in (("model.safetensors","blob"),("config.json","config"),("vocab.txt","vocab"),
                                 ("evidence.json","evidence")):
                core.require(core.file_hash(directory/filename)==manifest[key],"V3 serving asset changed")
    return registry,binding


def evaluation_rows(results):
    registry,binding = validate_registry(results)
    # This is the sole payload-opening path, after checking the complete six-entry seal.
    rows = core.load_partition(binding["dataset_manifest"],"fresh_eval",evaluation_authorized=True)
    _,train,validation = core.validate_training_data(binding["dataset_manifest"],binding["repository"])
    from privoke_model.training_data import training_text_key
    for field in ("group_id","family_id"):
        core.require(not ({r[field] for r in rows}&{r[field] for r in train+validation}),"Fresh evaluation family leakage")
    core.require(not ({training_text_key(r["text"]) for r in rows}&
                      {training_text_key(r["text"]) for r in train+validation}),"Fresh evaluation text leakage")
    core.require(all(not r.get("visibility_hint") for r in rows),"Primary evaluation hints must be empty")
    return registry,rows


def request_for(entry,row,request_id):
    from privoke.v1 import runtime_pb2
    return runtime_pb2.AnalyzePromptRequest(request_id=request_id,text=row["text"],layers=[4],
        semantic_model_id=entry["identity"]["model_id"],
        metadata={"ph3_registry_model":entry["name"],**({"v3_checkpoint":entry["manifest_sha256"]}
                                                     if entry["family"]=="v3" else {})})


def response_record(response,entry,request):
    from privoke_contracts.classification import Classification
    core.require(response.request_id==request.request_id,"Response belongs to another request")
    actual_layers = [x.layer for x in response.layers]
    core.require(not actual_layers or actual_layers==[4],"Semantic layer isolation violated")
    failed = bool(response.error) or bool(response.layers and
             (response.layers[0].status!="ok" or response.layers[0].error))
    expected = {"privoke.semantic."+k:str(v) for k,v in entry["identity"].items()}
    metadata = dict(response.metadata)
    core.require(all(metadata.get(k)==v for k,v in expected.items() if not failed or k in metadata),
                 "Returned native identity differs")
    if failed:
        return {"status":"error","actual_layers":actual_layers,"error":response.error or response.layers[0].error,
                "classification":None,"action":None,"metadata":metadata}
    core.require(actual_layers==[4] and response.layers[0].status=="ok","Missing actual semantic execution")
    value = Classification(response.classification.packed).to_dict()
    named = {"sensitivity":response.classification.sensitivity,"visibility":response.classification.visibility,
             "categories":list(response.classification.categories)}
    core.require(value==named and response.action in ACTION_RANK,"Invalid named/packed native classification/action")
    return {"status":"ok","actual_layers":[4],"classification":value,"action":response.action,
            "metadata":metadata,"server_elapsed_ms":response.elapsed_ms}


def contextual_sensitive(value):
    return value["sensitivity"]!="S0" or bool(value["categories"])


def case_metrics(record):
    names = ("sensitivity","visibility","category_exact","packed_exact","action","joint",
             "contextual_sensitive")
    result = {k:False for k in names}
    if record["status"]!="ok":
        return result
    truth,prediction = record["target"],record["classification"]
    result["sensitivity"] = prediction["sensitivity"]==truth["sensitivity"]
    result["visibility"] = prediction["visibility"]==truth["visibility"]
    result["category_exact"] = set(prediction["categories"])==set(truth["categories"])
    result["packed_exact"] = all(result[k] for k in ("sensitivity","visibility","category_exact"))
    result["action"] = record["action"] in record["allowed_actions"]
    result["joint"] = result["packed_exact"] and result["action"]
    result["contextual_sensitive"] = contextual_sensitive(prediction)==contextual_sensitive(truth)
    return result


def category_scores(records):
    categories = {}
    for category in core.LABELS["category"]:
        tp=fp=fn=0
        for record in records:
            truth = category in record["target"]["categories"]
            prediction = record["status"]=="ok" and category in record["classification"]["categories"]
            tp+=int(truth and prediction)
            fp+=int(not truth and prediction)
            fn+=int(truth and not prediction)
        precision = tp/(tp+fp) if tp+fp else None
        recall = tp/(tp+fn) if tp+fn else None
        # No predictions with positive support is a zero F1, not an omitted class.
        f1 = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
        categories[category] = {"tp":tp,"fp":fp,"fn":fn,"support":tp+fn,
                                "precision":precision,"recall":recall,"f1":f1}
    defined = [r["f1"] for r in categories.values() if r["f1"] is not None]
    totals = {k:sum(r[k] for r in categories.values()) for k in ("tp","fp","fn")}
    denominator = 2*totals["tp"]+totals["fp"]+totals["fn"]
    return {"per_category":categories,"macro_f1":sum(defined)/len(defined) if defined else None,
            "macro_defined_categories":len(defined),"micro":dict(totals,
              precision=totals["tp"]/(totals["tp"]+totals["fp"]) if totals["tp"]+totals["fp"] else None,
              recall=totals["tp"]/(totals["tp"]+totals["fn"]) if totals["tp"]+totals["fn"] else None,
              f1=2*totals["tp"]/denominator if denominator else None)}


def action_distance(record):
    if record["status"]!="ok":
        return None
    predicted = ACTION_RANK[record["action"]]
    allowed = [ACTION_RANK[a] for a in record["allowed_actions"]]
    return {"under":max(0,min(allowed)-predicted),"over":max(0,predicted-max(allowed))}


def summarize(records):
    names = case_metrics({"status":"error"})
    masks = {
        "all":lambda r:True,
        "category_bearing_disclosures":lambda r:bool(r["target"]["categories"]),
        "multilabel_disclosures":lambda r:len(r["target"]["categories"])>1,
        "contextual_sensitive_including_S1":lambda r:contextual_sensitive(r["target"]),
        "clean_S0":lambda r:not contextual_sensitive(r["target"]),
        "visibility_PU":lambda r:r["target"]["visibility"]=="PU",
        "visibility_explicit":lambda r:r["target"]["visibility"]!="PU",
    }
    slices = {}
    for name,predicate in masks.items():
        selected = [r for r in records if predicate(r)]
        slices[name] = {key:{"correct":sum(case_metrics(r)[key] for r in selected),"denominator":len(selected)}
                        for key in names}
        slices[name]["errors"] = sum(r["status"]!="ok" for r in selected)
    confusion = {}
    for task in ("sensitivity","visibility"):
        matrix = {truth:{p:0 for p in core.LABELS[task]+["ERROR"]} for truth in core.LABELS[task]}
        for record in records:
            prediction = record["classification"][task] if record["status"]=="ok" else "ERROR"
            matrix[record["target"][task]][prediction]+=1
        confusion[task] = matrix
    distances = [action_distance(r) for r in records]
    times = sorted(r["host_elapsed_ns"]/1e6 for r in records if r["status"]=="ok")
    harms = {key:sum(d[key] for d in distances if d is not None) for key in ("under","over")}
    harms.update(comparable=sum(d is not None for d in distances),errors=sum(d is None for d in distances))
    return {"requested":len(records),"independent_groups":len({r["group_id"] for r in records}),
            "slices":slices,"contextual_sensitive_recall":slices["contextual_sensitive_including_S1"]["contextual_sensitive"],
            "clean_specificity":slices["clean_S0"]["contextual_sensitive"],"categories":category_scores(records),"confusion":confusion,"action_distance":harms,
            "latency_ms":{"successful":len(times),"median":statistics.median(times) if times else None,
                          "p95":times[max(0,math.ceil(.95*len(times))-1)] if times else None,
                          "meaning":"descriptive batch1 RPC during fresh accuracy loop; not a controlled SLA"}}


def invoke(stub,entry,row,directory,request_id):
    directory = Path(directory)
    request = request_for(entry,row,request_id)
    payload = request.SerializeToString(deterministic=True)
    if (directory/"record.json").exists():
        return audit_call(entry,row,directory,request_id)
    core.require(not (directory/"request.pb").exists(),"Unknown reserved RPC outcome; reconcile without replay")
    core.retain(directory/"request.pb",payload)
    started = time.perf_counter_ns()
    try:
        response = stub.AnalyzePrompt(request,timeout=120)
    except Exception as error:
        ended = time.perf_counter_ns()
        elapsed = ended-started
        core.retain(directory/"transport-error.json",{"type":type(error).__name__,"error":str(error)})
        outcome = {"status":"transport_error","error":str(error),"classification":None,"action":None,
                   "actual_layers":[],"metadata":{}}
    else:
        ended = time.perf_counter_ns()
        elapsed = ended-started
        core.retain(directory/"response.pb",response.SerializeToString(deterministic=True))
        outcome = response_record(response,entry,request)
    core.retain(directory/"timing.json",{"started_perf_counter_ns":started,"ended_perf_counter_ns":ended})
    record = dict(outcome,id=row["id"],group_id=row["group_id"],family_id=row["family_id"],
                  target=row["classification"],allowed_actions=row["allowed_actions"],
                  request_sha256=core.digest(payload),host_elapsed_ns=elapsed)
    core.retain(directory/"record.json",record)
    return record


def audit_call(entry,row,directory,request_id):
    from privoke.v1 import runtime_pb2
    directory = Path(directory)
    record = core.read(directory/"record.json")
    payload = (directory/"request.pb").read_bytes()
    expected = request_for(entry,row,request_id).SerializeToString(deterministic=True)
    core.require(payload==expected and record["request_sha256"]==core.digest(payload),"Wire stimulus differs")
    core.require(all(record[k]==v for k,v in {"id":row["id"],"group_id":row["group_id"],
        "family_id":row["family_id"],"target":row["classification"],"allowed_actions":row["allowed_actions"]}.items()),
        "Retained truth/identity differs")
    timing = core.read(directory/"timing.json")
    core.require(type(record["host_elapsed_ns"]) is int and record["host_elapsed_ns"]>=0
                 and record["host_elapsed_ns"]==timing["ended_perf_counter_ns"]-timing["started_perf_counter_ns"],
                 "Invalid RPC timing")
    expected_files = {"request.pb","record.json","timing.json",
                      "transport-error.json" if record["status"]=="transport_error" else "response.pb"}
    core.require({p.name for p in directory.iterdir()}==expected_files,"Missing/extraneous row evidence")
    if record["status"]=="transport_error":
        core.require((directory/"transport-error.json").is_file() and not (directory/"response.pb").exists(),
                     "Transport outcome evidence differs")
    else:
        response = runtime_pb2.AnalyzePromptResponse.FromString((directory/"response.pb").read_bytes())
        outcome = response_record(response,entry,runtime_pb2.AnalyzePromptRequest.FromString(payload))
        core.require(all(record.get(k)==v for k,v in outcome.items()),"Raw response/record differs")
    return record


def evaluate(results,name,target,*,ready_file):
    import grpc
    from privoke.v1 import runtime_pb2_grpc
    registry,rows = evaluation_rows(results)
    entry = next(e for e in registry["entries"] if e["name"]==name)
    ready = core.read(ready_file)
    core.require(ready["identity"]==entry["identity"]
                 and ready["registry_sha256"]==core.file_hash(Path(results)/"comparison/registry.json")
                 and ready["source_closure"]==registry["source_closure"],"Server readiness/identity differs")
    output = Path(results)/"comparison"/"models"/name
    core.retain(output/"server-ready.json",ready)
    records = []
    with grpc.insecure_channel(target) as connection:
        grpc.channel_ready_future(connection).result(timeout=180)
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(connection)
        _,binding = validate_registry(results)
        warmup = core.load_partition(binding["dataset_manifest"],"train")[:registry["performance"]["warmup_train_rows"]]
        for index,row in enumerate(warmup):
            request_id = "ph3-warmup-"+core.digest(core.canonical([name,row["id"],index]))[:32]
            outcome = invoke(stub,entry,row,output/"warmup"/f"{index:04d}",request_id)
            core.require(outcome["status"]=="ok","Native TRAIN warmup failed; no fresh scoring attempted")
        for index,row in enumerate(rows):
            request_id = "ph3-"+core.digest(core.canonical([name,row["id"],index]))[:40]
            records.append(invoke(stub,entry,row,output/"rows"/f"{index:04d}",request_id))
            if index%100==0:
                print(f"{name}: {index+1}/{len(rows)}",flush=True)
    summary = summarize(records)
    core.retain(output/"summary.json",summary)
    core.retain(output/"complete.json",{"registry_sha256":core.file_hash(Path(results)/"comparison/registry.json"),
                                      "requested":len(rows),"summary_sha256":core.file_hash(output/"summary.json")})
    return summary


def paired(before,after):
    core.require([(r["id"],r["target"],r["allowed_actions"]) for r in before]==
                 [(r["id"],r["target"],r["allowed_actions"]) for r in after],"Paired stimuli differ")
    result = {}
    slices = {"all":lambda r:True,"category_bearing":lambda r:bool(r["target"]["categories"]),
              "contextual_sensitive":lambda r:contextual_sensitive(r["target"])}
    for label,predicate in slices.items():
        pairs = [(a,b) for a,b in zip(before,after) if predicate(a)]
        result[label] = {}
        for key in case_metrics({"status":"error"}):
            improved = sum(not case_metrics(a)[key] and case_metrics(b)[key] for a,b in pairs)
            regressed = sum(case_metrics(a)[key] and not case_metrics(b)[key] for a,b in pairs)
            result[label][key] = {"improved":improved,"regressed":regressed,"net_correct":improved-regressed,
                                  "denominator":len(pairs)}
    comparable = [(action_distance(a),action_distance(b)) for a,b in zip(before,after)
                  if a["status"]==b["status"]=="ok"]
    result["action_harms"] = {k:sum(b[k]>a[k] for a,b in comparable) for k in ("under","over")}
    result["action_harms"].update(comparable=len(comparable),error_pairs=len(before)-len(comparable))
    return result


def audit_comparison(results):
    registry,rows = evaluation_rows(results)
    records,summaries,files = {},{},{}
    for entry in registry["entries"]:
        output = Path(results)/"comparison/models"/entry["name"]
        current = []
        for index,row in enumerate(rows):
            directory = output/"rows"/f"{index:04d}"
            request_id = "ph3-"+core.digest(core.canonical([entry["name"],row["id"],index]))[:40]
            current.append(audit_call(entry,row,directory,request_id))
            for path in directory.iterdir():
                core.require(path.is_file(),"Unexpected nested row evidence")
                files[path.relative_to(Path(results)).as_posix()] = core.file_hash(path)
        core.require({p.name for p in (output/"rows").iterdir()}=={f"{i:04d}" for i in range(len(rows))},
                     "Missing/extraneous fresh row directories")
        summary = summarize(current)
        core.require(summary==core.read(output/"summary.json"),"Summary does not reconcile with raw wire evidence")
        complete = core.read(output/"complete.json")
        core.require(complete=={"registry_sha256":core.file_hash(Path(results)/"comparison/registry.json"),
                               "requested":len(rows),"summary_sha256":core.file_hash(output/"summary.json")},
                     "Completion commitment differs")
        records[entry["name"]],summaries[entry["name"]] = current,summary
    comparisons = {tier:paired(records["v1-"+tier],records["v3-"+tier]) for tier in core.TIERS}
    analysis = {"schema":1,"study_id":core.STUDY_ID,"registry_sha256":core.file_hash(Path(results)/"comparison/registry.json"),
                "results":summaries,"paired_v3_minus_v1":comparisons,
                "raw_file_inventory_sha256":core.digest(core.canonical(files)),"requested":len(rows)*6,
                "limitations":["Assistant-provisional synthetic labels; renditions share families.",
                               "Native package/training history differences prevent causal generation ranking.",
                               "Errors count incorrect; contextual sensitivity is not annotation/PII presence.",
                               "No production promotion or external real-world certification."]}
    core.retain(Path(results)/"comparison/analysis.json",analysis)
    core.retain(Path(results)/"comparison/raw-inventory.json",files)
    return analysis
