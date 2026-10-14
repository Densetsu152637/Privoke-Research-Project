"""Host EX14 controller. Fixed official-category reference, no training."""
from __future__ import annotations
import argparse
import base64
from collections import Counter
from dataclasses import replace
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from privoke_eval import external_native_category as ex

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "evaluation/results/external_native_identifiers_20261014"
PROTOCOL = Path(__file__).resolve().parents[1] / "paper/research/external-native-identifiers-20261014.json"
PROTOCOL_SHA = "1023d0ab0fb17b69320f2c7515b9cd9c8140a4769467400521f70a5aa86373ef"


def configure():
    for relative in ("shared/python", "extension/client-runtime/generated", "extension/client-runtime", "services/pretrained-v3/src"):
        sys.path.insert(0, str(ROOT / relative))
    for key in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS", "BLIS_NUM_THREADS"):
        os.environ[key] = "4"
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", PRIVOKE_MODEL_DEVICE="cpu", LLM_CHOICE="streamed", MODEL_STREAMING_CACHE_TTL_SECONDS="604800")


def verify_protocol():
    ex.require(ex.file_hash(PROTOCOL) == PROTOCOL_SHA, "Prospective protocol changed")
    return ex.read(PROTOCOL)


def supervision_protection(protected):
    from privoke_eval.clean_augmentation_grouping import ProtectedKeys, opaque_exclusion_key
    from privoke_model.training_data import training_text_key
    files = [
        ("privacy_heads_v3_20261013/data/release-03/manifest.json", "9f443b0123c65caec2fbf9aa9ff213578841f28068e094e91593e3cc7de08da1"),
        ("audience_v3_20261013/data/release-07/manifest.json", "41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0")]
    keys = {name:set(getattr(protected,name)) for name in ("ids","groups","exact_text_sha256","normalized_texts")}
    receipts=[]
    for relative, sha in files:
        manifest_path = ROOT / "evaluation/results" / relative
        ex.require(ex.file_hash(manifest_path) == sha, "Supervision manifest differs")
        manifest = ex.read(manifest_path)
        for split in ("train", "validation"):
            item = manifest["files"][split]
            path = manifest_path.parent / item["path"]
            ex.require(ex.file_hash(path) == item["sha256"], "Supervision row file differs")
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            ex.require(len(rows) == item["rows"], "Supervision row count differs")
            for row in rows:
                text=row["text"]
                keys["exact_text_sha256"].add(ex.digest(text.encode()))
                keys["normalized_texts"].add(opaque_exclusion_key("text_key",training_text_key(text)))
                for field,kind in (("id","id"),("group","group"),("group_id","group")):
                    if isinstance(row.get(field),str): keys["ids" if kind=="id" else "groups"].add(opaque_exclusion_key(kind,row[field]))
            receipts.append({"manifest":str(manifest_path),"manifest_sha256":sha,"split":split,"rows":len(rows),"sha256":item["sha256"]})
    return ProtectedKeys(**{k:frozenset(v) for k,v in keys.items()}), receipts


def freeze():
    protocol=verify_protocol()
    owned=Path(__file__).resolve().parents[0]
    paths=[Path(__file__),owned/"privoke_eval/external_native_category.py",owned/"tests/test_external_native_category.py",PROTOCOL,
           ROOT/"models/generate_baseline.py",ROOT/"evaluation/results/clean_augmentation_protected_20261004_v1/protected-union.json",
           ROOT/"evaluation/results/clean_augmentation_protected_20261004_v1/manifest.json",
           ROOT/"evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json"]
    pins={str(path):ex.file_hash(path) for path in paths}
    ex.require(pins[str(ROOT/"models/generate_baseline.py")]=="282f1ec49252dcadb94959077a5be0a6001ec7ff783693887ff40951540a8022","V1 anchor source drift")
    source_pins={
      "privacy_heads_v3_20261013/data/release-03/manifest.json":"9f443b0123c65caec2fbf9aa9ff213578841f28068e094e91593e3cc7de08da1",
      "privacy_heads_v3_20261013/data/release-03/train.jsonl":"374de9e0929a098ecef160ebaec03df1de57df2269c00ffdd493eb946a3c98ec",
      "privacy_heads_v3_20261013/data/release-03/validation.jsonl":"7301d57c70ff1d1d57ca2a3bdaa383933f670c92297127835dca247d24120745",
      "audience_v3_20261013/data/release-07/manifest.json":"41cfd9e476f3d0a17c2a4997efab2afbb6b044c5fbd55217b0614525a2571fe0",
      "audience_v3_20261013/data/release-07/train.jsonl":"e28bd8b56eb2e8b9b0aa395c8415de77082f9dd258e4fd8e8ebb648e7d6bda10",
      "audience_v3_20261013/data/release-07/validation.jsonl":"32a1231bd74ca7f1e1c373a9b3b45294c428d7d471d899a69d21b772824ed3c2"}
    for relative,sha in source_pins.items():
        path=ROOT/"evaluation/results"/relative
        ex.require(ex.file_hash(path)==sha,"Known supervision pin drift")
        pins[str(path)]=sha
    for entry in entries().values():
        for filename,sha in entry["assets"].items():
            ex.require(ex.file_hash(Path(entry["directory"])/filename)==sha,"Fixed model bytes drift")
    result={"status":"implementation_frozen_before_source_row_parsing","protocol_sha256":PROTOCOL_SHA,"file_pins":pins,
            "runtime_sources":runtime_sources(),"model_entries":entries(),"checks":"four synthetic helper tests passed; controller AST passed",
            "known_supervision":"V1 anchors included in original protected union; PH3 and EN3 share supervision; AU3 contains PH3 rehearsal plus audience coverage",
            "limitations":"Native typed value closure uses supplied values NFKC/casefold/whitespace, not punctuation equivalence or independent templates; unknown pretraining overlap.","inference_calls":0,"candidate_rows_parsed":0,"python":sys.version}
    ex.retain(RESULTS/"implementation-freeze.json",result)
    return {"implementation_freeze_sha256":ex.file_hash(RESULTS/"implementation-freeze.json"),"files":len(pins),"inference_calls":0}

def prepare():
    protocol=verify_protocol()
    implementation=ex.read(RESULTS/"implementation-freeze.json")
    ex.require(all(ex.file_hash(path)==sha for path,sha in implementation["file_pins"].items()),"Implementation/source freeze changed")
    from privoke_eval.advpii_native import parse_native_rows, validate_arrow_schema
    from privoke_eval.advpii_structure import verify_parquet_bytes, validate_protected_union
    from privoke_eval.clean_augmentation_grouping import build_components
    from privoke_model.training_data import training_text_key
    import pyarrow.parquet as pq
    source=ROOT / "evaluation/results/advpii_download_20261004_v1/source.parquet"
    verify_parquet_bytes(source)
    for filename,sha in (("official-README.md",protocol["dataset"]["card_sha256"]),("official-validate_release.py",protocol["dataset"]["validator_sha256"])):
        ex.require(ex.file_hash(RESULTS/filename)==sha,"Official source copy differs")
    protection=ROOT/"evaluation/results/clean_augmentation_protected_20261004_v1"
    protected, original_receipt=validate_protected_union(protection/"protected-union.json",protection/"manifest.json",protocol["protection"]["receipt_sha256"])
    ex.require(ex.file_hash(ROOT/"evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json")==protocol["protection"]["exclusion_index_sha256"],"Opaque index changed")
    protected, supervision=supervision_protection(protected)
    # This is the first source-row parsing after independent/root freeze acceptance.
    table=pq.read_table(source)
    validate_arrow_schema(table.schema)
    raw=table.to_pylist()
    parsed=parse_native_rows(raw)
    closure=build_components([p.grouping_row for p in parsed],protected)
    by_uid={r["uid"]:r for r in raw}
    categories={p.grouping_row.uid:p.native_category for p in parsed}
    eligible={p.grouping_row.uid for p in parsed if not p.structural_reasons}
    conflicts=ex.category_conflicts(closure.components,categories,by_uid,training_text_key)
    components=[replace(c,exclusion_reasons=tuple(sorted(set(c.exclusion_reasons)|({"native_category_conflict"} if c.component_id in conflicts else set())))) for c in closure.components]
    selected, capacity=ex.select_components(components,categories,eligible)
    binary=Counter(r["source_positive"] for r in selected)
    ex.require(min(binary.values())>=200,"Too few components per class")
    rows=[dict(item,text=by_uid[item["uid"]]["llm_input"],attack_target=by_uid[item["uid"]]["attack_target"],native_span_types=sorted({s["type"] for s in by_uid[item["uid"]]["pii_spans"]})) for item in selected]
    ex.retain(RESULTS/"selected.jsonl",b"".join(ex.canonical(r) for r in rows))
    proof={"study_id":protocol["study_id"],"prospective_protocol_sha256":PROTOCOL_SHA,"source_sha256":ex.file_hash(source),"source_rows":len(raw),"source_category_counts":dict(Counter(categories.values())),"source_components":len(components),"structural_reason_counts":dict(Counter(reason for p in parsed for reason in p.structural_reasons)),"protected_component_counts":dict(closure.component_reason_counts),"native_conflicting_components":len(conflicts),"capacity_components_before_global_allocation":capacity,"selected_category_counts":dict(Counter(r["category"] for r in rows)),"selected_components":len({r["component_id"] for r in rows}),"selected_sha256":ex.file_hash(RESULTS/"selected.jsonl"),"protection":original_receipt,"supervision_extension":supervision,"extended_key_counts":{k:len(getattr(protected,k)) for k in ("ids","groups","exact_text_sha256","normalized_texts")},"extended_keys_sha256":ex.digest(ex.canonical({k:sorted(getattr(protected,k)) for k in ("ids","groups","exact_text_sha256","normalized_texts")})),"python":sys.version,"pyarrow":importlib.metadata.version("pyarrow"),"label_status":"official machine-generated source category; no human review","no_locked_final_access":True}
    ex.retain(RESULTS/"selection-proof.json",proof)
    return proof


def runtime_sources():
    from privoke_eval import pipeline_v1_v3 as pipe
    sources=pipe.source_files(ROOT)
    own=Path(__file__).resolve().parents[0]
    for path in (Path(__file__),own/"privoke_eval/external_native_category.py"):
        sources["task-owned/"+path.relative_to(own.parent).as_posix()]=ex.file_hash(path)
    return sources


def entries():
    source=ROOT/"evaluation/results/pipeline_v1_v3_20261014/runs/cpu-01/protocol.json"
    protocol=ex.read(source)
    return {entry["name"]:entry for entry in protocol["entries"] if entry["name"] in ("v1-balanced","v3-balanced")}


def host_versions():
    return {name:importlib.metadata.version(name) for name in (
        "numpy","torch","transformers","tokenizers","safetensors","grpcio","protobuf","spacy","en-core-web-lg","presidio-analyzer","python-dotenv")}


def dependency_files():
    toolroot=Path(__file__).resolve().parents[1]
    relatives=("evaluation/run-external-native-category.py","evaluation/privoke_eval/external_native_category.py",
               "evaluation/tests/test_external_native_category.py","paper/research/external-native-identifiers-20261014.json",
               "evaluation/privoke_eval/advpii_native.py","evaluation/privoke_eval/advpii_structure.py",
               "evaluation/privoke_eval/clean_augmentation_grouping.py","evaluation/privoke_eval/clean_augmentation_protection.py",
               "evaluation/privoke_eval/clean_augmentation_protection_io.py")
    return {relative:ex.file_hash(toolroot/relative) for relative in relatives}


def baseline_assets():
    import importlib.util
    directory=Path(importlib.util.find_spec("en_core_web_lg").origin).parent
    return {p.relative_to(directory).as_posix():ex.file_hash(p) for p in sorted(directory.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and p.suffix!=".pyc"}


def inference_freeze():
    verify_protocol()
    original=ex.read(RESULTS/"implementation-freeze.json")
    # The sole controller amendment adds binding guards/portable root; preserve the original receipt.
    for path,sha in original["file_pins"].items():
        if Path(path).resolve()!=Path(__file__).resolve():
            ex.require(ex.file_hash(path)==sha,"Original non-controller binding changed")
    current_sources=runtime_sources()
    for relative,sha in original["runtime_sources"].items():
        if relative.startswith(str(Path(__file__).resolve().parents[1])):
            if Path(relative).resolve()!=Path(__file__).resolve():
                ex.require(ex.file_hash(relative)==sha,"Original owned helper changed")
        else:
            ex.require(current_sources.get(relative)==sha,"Original runtime source changed")
    toolroot=Path(__file__).resolve().parents[1]
    dependencies=dependency_files()
    prior=ex.read(ROOT/"evaluation/results/advpii_structure_20261004_v1/run-manifest.json")
    for relative,key in (("evaluation/privoke_eval/advpii_native.py","parser_sha256"),("evaluation/privoke_eval/clean_augmentation_grouping.py","grouping_sha256"),("evaluation/privoke_eval/advpii_structure.py","aggregation_sha256")):
        ex.require(dependencies[relative]==prior["code_sha256"][key],"Preparation dependency differs from pinned prior parser/grouping audit")
    snapshots={}
    for relative,sha in current_sources.items():
        path=toolroot/relative.removeprefix("task-owned/") if relative.startswith("task-owned/") else ROOT/relative
        payload=path.read_bytes()
        ex.require(ex.digest(payload)==sha,"Source bytes changed while freezing")
        snapshot=RESULTS/"source-snapshots"/(sha+".bin")
        if snapshot.exists():ex.require(snapshot.read_bytes()==payload,"Source snapshot differs")
        else:ex.retain(snapshot,payload)
        snapshots[relative]={"sha256":sha,"snapshot":"source-snapshots/"+snapshot.name}
    for relative,sha in dependencies.items():
        path=toolroot/relative
        snapshot=RESULTS/"source-snapshots"/(sha+".bin")
        if not snapshot.exists():ex.retain(snapshot,path.read_bytes())
        snapshots["task-owned/"+relative]={"sha256":sha,"snapshot":"source-snapshots/"+snapshot.name}
    result={"status":"amended_inference_seal_before_predictions","original_implementation_freeze_sha256":ex.file_hash(RESULTS/"implementation-freeze.json"),
        "amendment":"Controller adds persistent seal guards, package/asset binding and portable repository argument; preparation algorithm/helpers and selected rows unchanged.",
        "protocol_sha256":PROTOCOL_SHA,"selection_proof_sha256":ex.file_hash(RESULTS/"selection-proof.json"),"selected_sha256":ex.file_hash(RESULTS/"selected.jsonl"),
        "runtime_sources":current_sources,"dependency_files":dependencies,"model_entries":entries(),"host_packages":host_versions(),
        "baseline_assets":baseline_assets(),"source_snapshots":snapshots,"inference_calls":0,
        "original_input_pins":{path:sha for path,sha in original["file_pins"].items() if Path(path).resolve()!=Path(__file__).resolve()}}
    ex.retain(RESULTS/"inference-freeze.json",result)
    return {"inference_freeze_sha256":ex.file_hash(RESULTS/"inference-freeze.json"),"source_files":len(snapshots),"inference_calls":0}


def verify_inference_seal():
    verify_protocol()
    seal=ex.read(RESULTS/"inference-freeze.json")
    ex.require(runtime_sources()==seal["runtime_sources"],"Sealed runtime source closure differs")
    ex.require(dependency_files()==seal["dependency_files"],"Sealed preparation/controller dependencies differ")
    ex.require(entries()==seal["model_entries"],"Sealed fixed model entries differ")
    for entry in entries().values():
        for filename,sha in entry["assets"].items():
            ex.require(ex.file_hash(Path(entry["directory"])/filename)==sha,"Sealed immutable model asset differs")
    ex.require(host_versions()==seal["host_packages"],"Sealed host packages differ")
    ex.require(baseline_assets()==seal["baseline_assets"],"Sealed native baseline asset differs")
    ex.require(ex.file_hash(RESULTS/"selected.jsonl")==seal["selected_sha256"] and ex.file_hash(RESULTS/"selection-proof.json")==seal["selection_proof_sha256"],"Sealed selection receipt differs")
    for path,sha in seal["original_input_pins"].items():
        ex.require(ex.file_hash(path)==sha,"Sealed input pin differs")
    return seal

def serve(name,port):
    verify_inference_seal()
    ex.require(port in (50201,50202),"Dedicated loopback ports required")
    from privoke_eval import pipeline_v1_v3 as pipe
    from privoke_eval.pipeline_v1_v3_serving import load_semantic, disabled
    import grpc
    import torch
    from privoke.v1 import runtime_pb2_grpc
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    entry=entries()[name]
    pipe.validate_assets(entry)
    model=load_semantic(entry)
    if name=="v3-balanced":
        from runtime_server import RuntimeServer
        class FixedSemantic(RuntimeServer):
            def __init__(self):
                self.lock=threading.RLock()
                self.cache={entry["identity"]["artifact_checksum"]:(ex.read(Path(entry["directory"])/"manifest.json"),model.model)}
        native=FixedSemantic()
    else:
        from src.config import GLOBAL_CONFIG
        from src.LLM.privoke.parameter_stream import ModelParameterStreamer
        from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE, _CachedModel
        from src.hosting.grpc_server import PrivokeRuntimeService
        GLOBAL_CONFIG.llm_choice="streamed"
        streamer=ModelParameterStreamer(model_id=entry["identity"]["model_id"])
        key=(streamer.target,streamer.model_id)
        GLOBAL_STREAMED_MODEL_CACHE.clear()
        GLOBAL_STREAMED_MODEL_CACHE._models[key]=_CachedModel(entry["identity"]["parameter_fingerprint"],model,time.monotonic())
        native=PrivokeRuntimeService()
    class Sealed(runtime_pb2_grpc.PrivokeRuntimeServiceServicer):
        def AnalyzePrompt(self,request,context):
            if list(request.layers)!=[4] or request.visibility_hint or request.HasField("semantic_presence_gate") or request.semantic_model_id!=entry["identity"]["model_id"]:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,"Explicit semantic-only no-hint fixed-model request required")
            if name=="v3-balanced" and request.metadata.get("v3_checkpoint")!=entry["identity"]["artifact_checksum"]:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT,"Fixed checkpoint required")
            return native.AnalyzePrompt(request,context)
        ComputeSemanticGradients=staticmethod(disabled)
        ComputeUnderlyingModelGradients=staticmethod(disabled)
        ComputePresenceGradients=staticmethod(disabled)
        DetectAnnotationPresence=staticmethod(disabled)
    server=grpc.server(ThreadPoolExecutor(max_workers=1))
    runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server(Sealed(),server)
    ex.require(server.add_insecure_port("127.0.0.1:"+str(port)),"Port unavailable")
    server.start()
    ready={"name":name,"port":port,"pid":os.getpid(),"identity":entry["identity"],"assets":entry["assets"],"source_files":runtime_sources(),"device":"cpu","training_disabled":True,"layers":[4],"visibility_hints":"empty","python":sys.version}
    ex.retain(RESULTS/(name+"-ready.json"),ready)
    print("EX14 ready "+name,flush=True)
    try: server.wait_for_termination()
    finally: server.stop(2).wait()


def selected_rows():
    proof=ex.read(RESULTS/"selection-proof.json")
    ex.require(ex.file_hash(RESULTS/"selected.jsonl")==proof["selected_sha256"],"Selection changed")
    return [json.loads(line) for line in (RESULTS/"selected.jsonl").read_text(encoding="utf-8").splitlines()]


def evaluate(name,port):
    verify_inference_seal()
    import grpc
    from privoke.v1 import runtime_pb2,runtime_pb2_grpc
    entry=entries()[name]
    ready=ex.read(RESULTS/(name+"-ready.json"))
    ex.require(ready["identity"]==entry["identity"] and ready["source_files"]==runtime_sources(),"Server/source identity changed")
    output=RESULTS/(name+"-receipts.jsonl")
    channel=grpc.insecure_channel("127.0.0.1:"+str(port))
    stub=runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel)
    completed=[]
    with output.open("xb") as handle:
        for row in selected_rows():
            request=runtime_pb2.AnalyzePromptRequest(request_id=f"ex14-{name}-{row['uid']}",text=row["text"],layers=[4],semantic_model_id=entry["identity"]["model_id"],metadata={"v3_checkpoint":entry["identity"]["artifact_checksum"]} if name.startswith("v3") else {})
            capture={k:row[k] for k in ("uid","category","source_positive","component_id")}
            capture["request_pb"]=base64.b64encode(request.SerializeToString(deterministic=True)).decode()
            start=time.perf_counter_ns()
            try:
                response=stub.AnalyzePrompt(request,timeout=60)
                capture["response_pb"]=base64.b64encode(response.SerializeToString(deterministic=True)).decode()
                ex.require(response.request_id==request.request_id and not response.error,"Runtime response error: "+response.error)
                ex.require([layer.layer for layer in response.layers]==[4] and response.layers[0].status=="ok" and not response.layers[0].error,"Actual semantic-only execution failed")
                identity={k.removeprefix("privoke.semantic."):v for k,v in response.metadata.items() if k.startswith("privoke.semantic.")}
                ex.require(all(identity.get(k)==v for k,v in entry["identity"].items()),"Actual model identity mismatch")
                capture.update(predicted=bool(response.layers[0].results),action=response.action,actual_identity=identity)
            except Exception as error:
                capture.update(predicted=None,error=type(error).__name__+": "+str(error))
            capture["rpc_ms"]=(time.perf_counter_ns()-start)/1e6
            handle.write(ex.canonical(capture)); handle.flush()
            completed.append(capture)
            if len(completed)%250==0: print(name,len(completed),flush=True)
    channel.close()
    ex.require(ready["source_files"]==runtime_sources(),"Source changed during inference")
    result={"name":name,"all":ex.confusion(completed),"strata":{category:ex.confusion([r for r in completed if r["category"]==category]) for category in ("positive","negative","hard_negative")},"receipts_sha256":ex.file_hash(output)}
    ex.retain(RESULTS/(name+"-summary.json"),result)
    return result


def baseline():
    verify_inference_seal()
    import spacy
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    spacy.require_cpu()
    ex.require(importlib.metadata.version("en-core-web-lg")=="3.7.1","Native baseline model version differs")
    engine=NlpEngineProvider(nlp_configuration={"nlp_engine_name":"spacy","models":[{"lang_code":"en","model_name":"en_core_web_lg"}]}).create_engine()
    analyzer=AnalyzerEngine(nlp_engine=engine,supported_languages=["en"])
    entities=verify_protocol()["baseline"]["entities"]
    supported=analyzer.get_supported_entities(language="en")
    ex.require(set(entities)<=set(supported),"Native Presidio taxonomy unavailable")
    model_root=Path(importlib.util.find_spec("en_core_web_lg").origin).parent
    model_files={p.relative_to(model_root).as_posix():ex.file_hash(p) for p in sorted(model_root.rglob("*")) if p.is_file() and "__pycache__" not in p.parts and p.suffix!=".pyc"}
    completed=[]
    with (RESULTS/"presidio-five-type-lg-receipts.jsonl").open("xb") as handle:
        for row in selected_rows():
            capture={k:row[k] for k in ("uid","category","source_positive","component_id")}
            try:
                findings=analyzer.analyze(text=row["text"],language="en",entities=entities,score_threshold=0.0)
                capture.update(predicted=bool(findings),findings=[{"entity_type":r.entity_type,"start":r.start,"end":r.end,"score":r.score} for r in findings])
            except Exception as error: capture.update(predicted=None,error=type(error).__name__+": "+str(error))
            handle.write(ex.canonical(capture)); handle.flush(); completed.append(capture)
            if len(completed)%250==0: print("presidio",len(completed),flush=True)
    result={"name":"presidio-five-type-lg","all":ex.confusion(completed),"strata":{category:ex.confusion([r for r in completed if r["category"]==category]) for category in ("positive","negative","hard_negative")},"entities":entities,"supported_entities":supported,"model_version":"3.7.1","model_files":model_files,"model_files_sha256":ex.digest(ex.canonical(model_files)),"presidio_version":importlib.metadata.version("presidio-analyzer"),"spacy_version":spacy.__version__,"score_threshold":0.0}
    ex.retain(RESULTS/"presidio-five-type-lg-summary.json",result)
    return result


def audit():
    verify_inference_seal()
    rows=selected_rows()
    outputs={}
    for name in ("v1-balanced","v3-balanced","presidio-five-type-lg"):
        path=RESULTS/(name+"-receipts.jsonl")
        records=[json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        ex.require(len(records)==len(rows) and all(a["uid"]==b["uid"] and a["category"]==b["category"] and a["component_id"]==b["component_id"] for a,b in zip(records,rows)),"Incomplete/unpaired endpoint")
        if name.startswith("v"):
            from privoke.v1 import runtime_pb2
            for record,row in zip(records,rows):
                request=runtime_pb2.AnalyzePromptRequest.FromString(base64.b64decode(record["request_pb"]))
                ex.require(request.text==row["text"] and list(request.layers)==[4] and not request.visibility_hint,"Request changed source/layers/hints")
                if record.get("predicted") is not None:
                    response=runtime_pb2.AnalyzePromptResponse.FromString(base64.b64decode(record["response_pb"]))
                    ex.require(not response.error and [v.layer for v in response.layers]==[4] and response.layers[0].status=="ok" and bool(response.layers[0].results)==record["predicted"],"Response replay differs")
        outputs[name]=records
    result={"status":"complete","protocol_sha256":PROTOCOL_SHA,"selection":ex.read(RESULTS/"selection-proof.json"),"arms":{name:{"all":ex.confusion(records),"strata":{category:ex.confusion([r for r in records if r["category"]==category]) for category in ("positive","negative","hard_negative")},"receipts_sha256":ex.file_hash(RESULTS/(name+"-receipts.jsonl"))} for name,records in outputs.items()},"paired_v3_minus_v1":ex.paired_bootstrap(outputs["v1-balanced"],outputs["v3-balanced"]),"scope":"Official source-category proxy; ontology mismatch, no contextual or broad privacy truth"}
    ex.retain(RESULTS/"audit.json",result)
    return result


def main():
    global ROOT,RESULTS
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("freeze","inference-freeze","prepare","serve","evaluate","baseline","audit"))
    parser.add_argument("--name",choices=("v1-balanced","v3-balanced"))
    parser.add_argument("--port",type=int,default=50201)
    parser.add_argument("--repository",type=Path,default=ROOT)
    args=parser.parse_args()
    ROOT=args.repository.resolve()
    RESULTS=ROOT/"evaluation/results/external_native_identifiers_20261014"
    configure()
    if args.action=="serve": serve(args.name,args.port); return
    if args.action=="inference-freeze": print(ex.canonical(inference_freeze()).decode(),end=""); return
    result=evaluate(args.name,args.port) if args.action=="evaluate" else globals()[args.action]()
    print(ex.canonical(result).decode(),end="")

if __name__=="__main__": main()
