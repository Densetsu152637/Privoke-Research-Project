"""Staged, bounded contextual fuzzer study; only explicit execution modes mutate services."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "evaluation"))
from host_environment import configure_imports
configure_imports()
from privoke_model.artifact import float32, load_artifact
from privoke_model.fingerprint import parameter_fingerprint

PROFILES = ("efficient", "balanced", "quality")
SEEDS = (42, 1337, 2026)
RATES = (.003, .01, .03)
STRATEGIES = ("heads", "last_block")
VALIDATION_SHA = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
DEVELOPMENT_SHA = "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095"
FIXTURE_SHA = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
SERVICES = ("client-runtime", "model-streaming-service", "param-update-service", "privoke-fuzzer")
STUDY_SERVICES = ("contextual-study-updater", "contextual-study-fuzzer")
RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
RAW_PUBLICATION_CODE = """import os,sys,tempfile
from pathlib import Path
p=Path(sys.argv[1]);raw=sys.stdin.buffer.read()
fd,tmp=tempfile.mkstemp(dir=p.parent)
with os.fdopen(fd,'wb') as f:
 os.fchmod(f.fileno(),0o644)
 f.write(raw);f.flush();os.fsync(f.fileno())
os.replace(tmp,p)
directory=os.open(p.parent,os.O_RDONLY)
try: os.fsync(directory)
finally: os.close(directory)
"""


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    """Atomic state checkpoint; callers reserve fresh attempt directories first."""
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def computation_sources():
    """Bind the actual scorer and relevant serving/training source, including dirty edits."""
    paths = {ROOT / "evaluation" / name for name in
             ("run-ablations.py", "evaluate.py", "host_environment.py", "requirements.txt")}
    for directory in ("evaluation/privoke_eval", "extension/client-runtime/src",
                      "shared/python", "services/privoke-fuzzer/src",
                      "services/param-update-service/app", "services/model-streaming-service/cmd/server"):
        paths.update(p for p in (ROOT / directory).rglob("*")
                     if p.is_file() and p.suffix in (".py", ".go") and "__pycache__" not in p.parts)
    paths.update(ROOT / name for name in ("docker-compose.yml", "evaluation/compose.tests.yml",
                 "evaluation/Dockerfile.fuzzer-bases", "evaluation/Dockerfile.fuzzer-runtime",
                 "evaluation/requirements-fuzzer-training.txt"))
    return sorted(paths)


def verify_guarded_publication(original, published, response):
    # Training metadata uses the legacy value-only framing; serving identity
    # additionally frames tensor shapes. Keep both contracts explicit.
    before, after = training_value_fingerprint(original), training_value_fingerprint(published)
    if (published["model_id"] != original["model_id"]
            or {n: t["shape"] for n, t in original["parameters"].items()} != {n: t["shape"] for n, t in published["parameters"].items()}
            or response["metadata"].get("base_parameter_fingerprint") != before
            or response["metadata"].get("updated_parameter_fingerprint") != after):
        raise ValueError("Published candidate differs from the exact base/candidate guarded by training.")


def training_value_fingerprint(artifact):
    return parameter_fingerprint({n: tuple(float32(v) for v in t["values"])
                                  for n, t in artifact["parameters"].items()})


def bound_rows(path, commitment, count, positives=None):
    if Path(path).name == "final.jsonl" or sha(path) != commitment:
        raise ValueError("Endpoint byte commitment mismatch or forbidden final endpoint.")
    result = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(result) != count:
        raise ValueError("Endpoint row count mismatch.")
    if positives is not None:
        if len({r["id"] for r in result}) != count or any(type(r.get("expected_has_pii")) is not bool or not r.get("group_id") for r in result) or sum(r["expected_has_pii"] for r in result) != positives:
            raise ValueError("Endpoint identity, grouped truth or class count mismatch.")
    return result


def artifact_identity(artifact):
    return {"model_id": artifact["model_id"], "model_version": artifact["version"], "artifact_checksum": artifact["checksum"], "parameter_fingerprint": parameter_fingerprint({k: tuple(float32(x) for x in v["values"]) for k, v in artifact["parameters"].items()}, {k: v["shape"] for k, v in artifact["parameters"].items()})}


def verified_report(report, reference, artifact):
    predictions = report["metadata"]["predictions"]
    expected = {str(r.get("example_id", f"local-jsonl:{r['id']}")): (r["expected_has_pii"], r["group_id"]) for r in reference}
    actual = {r["example_id"]: (r["expected_has_pii"], r["group_id"]) for r in predictions}
    if report.get("errors") or len(predictions) != len(expected) or actual != expected or any(r.get("status") != "ok" or type(r.get("detected_sensitive")) is not bool for r in predictions):
        raise ValueError("Incomplete, erroneous or unmatched candidate report.")
    identity = artifact_identity(artifact)
    semantic_seen = 0
    for row in predictions:
        for layer in row.get("layers", []):
            if layer.get("layer") != "DETECTION_LAYER_SEMANTIC" or layer.get("status") != "ok":
                continue
            for result in layer.get("results", []):
                if any(result.get("metadata", {}).get(k) != v for k, v in identity.items()):
                    raise ValueError("Returned semantic identity changed.")
                semantic_seen += 1
    if semantic_seen == 0:
        raise ValueError("No returned semantic identity evidence.")
    counts = {"tp": sum(r["expected_has_pii"] and r["detected_sensitive"] for r in predictions), "tn": sum(not r["expected_has_pii"] and not r["detected_sensitive"] for r in predictions), "fp": sum(not r["expected_has_pii"] and r["detected_sensitive"] for r in predictions), "fn": sum(r["expected_has_pii"] and not r["detected_sensitive"] for r in predictions)}
    for short, name in (("tp", "true_positives"), ("tn", "true_negatives"), ("fp", "false_positives"), ("fn", "false_negatives")):
        if report["metrics"][name] != counts[short]:
            raise ValueError("Report aggregates disagree with raw predictions.")
    return counts


def candidate_key(record, baseline):
    counts = record["validation"]["pipeline"]
    if counts["tp"] / 475 < .9 or counts["tn"] <= baseline["tn"]:
        return None
    return (counts["tn"], counts["tp"], -1, -record["rate"], -record["seed"], -PROFILES.index(record["profile"]), -STRATEGIES.index(record["strategy"]))


def fixture_gate(cases, baseline, candidate):
    if set(baseline) != {c["case_id"] for c in cases} or set(candidate) != set(baseline):
        raise ValueError("Fixture evidence is incomplete.")
    losses, clean_added = [], []
    for case in cases:
        if case["ambiguous"]:
            continue
        before, after = baseline[case["case_id"]]["action"], candidate[case["case_id"]]["action"]
        if before not in RANK or after not in RANK:
            raise ValueError("Invalid contextual action evidence.")
        required = case.get("minimum_action") or case.get("expected_action")
        if case["required_sensitive"] is True and required in ("WARN", "BLOCK") and RANK[before] >= RANK[required] > RANK[after]:
            losses.append(case["case_id"])
        if case["required_sensitive"] is False and before == "ALLOW" and after != "ALLOW":
            clean_added.append(case["case_id"])
    return {"private_action_losses": losses, "added_clean_interventions": clean_added, "passed": not losses and not clean_added, "scope": "41 provisional cases; seven ambiguous excluded; baseline failures remain visible"}


def by_dataset(report):
    """Source strata within PIIMB, never a claim about complete upstream datasets."""
    result = {}
    for row in report["metadata"]["predictions"]:
        family = row["group_id"].removeprefix("piimb:").split(":", 1)[0]
        if family in ("ai4privacy-en", "ai4privacy-multi"):
            family = "ai4privacy-openpii"
        counts = result.setdefault(family, {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
        counts["tp" if row["detected_sensitive"] else "fn"] += bool(row["expected_has_pii"])
        counts["fp" if row["detected_sensitive"] else "tn"] += not row["expected_has_pii"]
    for counts in result.values():
        positive, clean = counts["tp"] + counts["fn"], counts["tn"] + counts["fp"]
        counts.update(positive_support=positive, clean_support=clean, recall=counts["tp"] / positive if positive else None, specificity=counts["tn"] / clean if clean else None)
    return result


def attempts(prefix):
    for number, (profile, strategy, rate, seed) in enumerate(itertools.product(PROFILES, STRATEGIES, RATES, SEEDS)):
        yield {"index": number, "profile": profile, "strategy": strategy, "rate": rate, "seed": seed, "request_id": f"{prefix}-{number:02d}", "source_id": "contextual-study-20261006", "prompt_count": 256, "heldout_count": 16, "max_gradient": .05, "transforms": 0}


class UnknownUpdateOutcome(RuntimeError):
    """Never retry an ambiguous request or proceed to another candidate."""


class Driver:
    def __init__(self, args, state):
        self.args, self.state = args, state
        self.environment = {**os.environ, "CONTEXTUAL_STUDY_ID": state["prefix"], "CONTEXTUAL_STUDY_CURRICULUM": str(Path(state["prepared"]).resolve() / "prompts.jsonl")}
        self.environment["PRIVOKE_RUNTIME_TARGET"] = state["runtime_target"]
        self.base_compose = ["docker", "compose", "--project-directory", str(ROOT), "--project-name", args.project_name, "-f", "docker-compose.yml", "-f", "evaluation/compose.tests.yml"]
        for override in state.get("base_overrides", []):
            self.base_compose += ["-f", override]
        self.compose = self.base_compose + ["-f", "evaluation/compose.contextual-fuzzer-study.yml"]
        self.log = None

    def command(self, args, *, content=None, timeout=180):
        result = subprocess.run(args, cwd=ROOT, env=self.environment, input=content, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if self.log:
            self.log.write(result.stderr.decode("utf-8", errors="replace"))
            self.log.flush()
        if result.returncode:
            raise RuntimeError(f"Command exited {result.returncode}: {result.stderr.decode('utf-8', errors='replace')[-2000:]}")
        return result.stdout

    def call(self, args, **kwargs):
        return self.command(self.compose + args, **kwargs)

    def images(self):
        result = {}
        for service in SERVICES:
            container = self.command(self.base_compose + ["ps", "-q", service]).decode().strip()
            if not container or "\n" in container:
                raise ValueError("One running container required for every serving service.")
            result[service] = self.command(["docker", "inspect", "--format", "{{.Image}}", container]).decode().strip()
        return result

    def configure_images(self, images):
        desired = self.state.get("study_images")
        if desired is None:
            desired = {}
            for service, option in (("client-runtime", "runtime_image"), ("model-streaming-service", "streamer_image"), ("param-update-service", "updater_image"), ("privoke-fuzzer", "fuzzer_image")):
                source = getattr(self.args, option) or images[service]
                desired[service] = self.command(["docker", "image", "inspect", "--format", "{{.Id}}", source]).decode().strip()
            self.state["study_images"] = desired
        for service, variable in (("client-runtime", "RUNTIME"), ("model-streaming-service", "STREAMER"), ("param-update-service", "UPDATER"), ("privoke-fuzzer", "FUZZER")):
            self.environment[f"CONTEXTUAL_STUDY_{variable}_IMAGE"] = desired[service]

    def restore_services(self):
        path = Path(self.args.output) / "restore-images.json"
        expected = {"services": {service: {"image": image} for service, image in self.state["images"].items()}}
        if not path.exists():
            write(path, expected)
        elif read(path) != expected:
            raise ValueError("Immutable restoration image override changed.")
        self.command(self.base_compose + ["-f", str(path), "up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "120", *SERVICES])

    def live(self, profile):
        code = "import sys;from pathlib import Path;sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes())"
        return self.command(self.base_compose + ["exec", "-T", "param-update-service", "python", "-c", code, f"/models/privoke-{profile}.json"])

    def install_raw(self, profile, content):
        # Atomic replacement preserves exact bytes; running root-owned updater has catalog permission.
        code = RAW_PUBLICATION_CODE
        self.command(self.base_compose + ["exec", "-T", "param-update-service", "python", "-c", code, f"/models/privoke-{profile}.json"], content=content)

    def refresh(self):
        self.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "120", "model-streaming-service", "client-runtime"])

    def resources(self):
        code = "import json,os,platform;from pathlib import Path;import torch;print(json.dumps({'python':platform.python_version(),'machine':platform.machine(),'cpu_count':os.cpu_count(),'torch':torch.__version__,'torch_threads':torch.get_num_threads(),'limits':{name:Path('/sys/fs/cgroup/'+name).read_text().strip() for name in ['cpu.max','memory.max','cpuset.cpus.effective'] if Path('/sys/fs/cgroup/'+name).exists()}}))"
        return json.loads(self.call(["exec", "-T", "client-runtime", "python", "-c", code]))

    def stop_jobs(self):
        self.call(["stop", "--timeout", "30", *STUDY_SERVICES])
        if self.call(["ps", "--status", "running", "-q", *STUDY_SERVICES]).strip():
            raise UnknownUpdateOutcome("Study workers have not proven quiescent; catalog restoration blocked.")

    def train(self, record):
        sampling = record.get("sampling_strategy")
        if sampling not in (None, "uniform", "contextual_role_quota_v1"):
            raise ValueError("Unknown optional study sampling strategy.")
        self.environment["CONTEXTUAL_STUDY_MODEL_ID"] = f"privoke-{record['profile']}"
        self.environment["CONTEXTUAL_STUDY_RATE"] = str(record["rate"])
        self.call(["run", "--rm", "--no-deps", "contextual-study-storage"])
        self.call(["up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "120", *STUDY_SERVICES])
        inventory_code = """import json,sys,hashlib
from collections import Counter
from prompt_generation.generator import generate_training_partition
from privoke_model.training_data import training_text_key
value=json.load(sys.stdin)
sampling=value.get('sampling_strategy')
if sampling in (None,'uniform'):
 train,heldout=generate_training_partition(256,16,value['seed'],'/curriculum/prompts.jsonl')
else:
 train,heldout=generate_training_partition(256,16,value['seed'],'/curriculum/prompts.jsonl',sampling_strategy=sampling)
summary=lambda batch: {'rows':len(batch),'sensitivity_counts':dict(Counter(x.expected_classification.sensitivity().name for x in batch)),'role_counts':dict(Counter(x.metadata.get('training_role','unknown') for x in batch)),'groups':len({x.metadata['group_id'] for x in batch}),'opaque_group_labels':{hashlib.sha256(group.encode()).hexdigest():sorted({x.expected_classification.sensitivity().name for x in batch if x.metadata['group_id']==group}) for group in sorted({x.metadata['group_id'] for x in batch})},'texts_sha256':hashlib.sha256(json.dumps([training_text_key(x.text) for x in batch],ensure_ascii=False).encode()).hexdigest()}
def ordered_commitment(batch):
 return hashlib.sha256(json.dumps([{'text':x.text,'text_key':training_text_key(x.text),'group_id':x.metadata['group_id'],'target':{'sensitivity':x.expected_classification.sensitivity().name,'visibility':x.expected_classification.visibility().name,'categories':[c.name for c in x.expected_classification.categories()]},'original_weight':x.weight} for x in batch],sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
original_summary=summary
summary=lambda batch: {**original_summary(batch),'ordered_samples_sha256':ordered_commitment(batch)}
inventory={'train':summary(train),'heldout':summary(heldout),'group_overlap':len({x.metadata['group_id'] for x in train}&{x.metadata['group_id'] for x in heldout})}
if sampling not in (None,'uniform'):
 from prompt_generation.generator import contextual_sampling_audit
 inventory['sampling_audit']=contextual_sampling_audit(train)
 inventory['train']['contextual_class_counts']={'sensitive':sum(x.expected_classification.is_sensitive() for x in train),'clean':sum(not x.expected_classification.is_sensitive() for x in train)}
print(json.dumps(inventory))
"""
        inventory = json.loads(self.call(["exec", "-T", "contextual-study-fuzzer", "python", "-c", inventory_code], content=json.dumps(record).encode()))
        if inventory["group_overlap"] != 0 or inventory["heldout"]["groups"] != 16:
            raise ValueError("Actual fuzzer partition has insufficient/disjoint heldout groups.")
        code = """import hashlib,json,sys,grpc
from privoke.v1 import parameters_pb2 as pb,parameters_pb2_grpc as api
value=json.load(sys.stdin)
req=pb.FuzzerTrainingRequest(request_id=value['request_id'],source_id=value['source_id'],model_id='privoke-'+value['profile'],prompt_count=256,seed=value['seed'],metadata={'initiator':'contextual-study-controller'})
if value.get('sampling_strategy') not in (None,'uniform'):
 req.metadata['contextual_sampling_strategy']=value['sampling_strategy']
fingerprint=hashlib.sha256(req.SerializeToString(deterministic=True)).hexdigest()
result={'request_fingerprint':fingerprint,'request':value}
try:
 with grpc.insecure_channel('127.0.0.1:50053') as channel:
  response=api.FuzzerServiceStub(channel).RunTrainingCycle(req,timeout=300)
 result.update(accepted=response.accepted,base_version=response.base_version,applied_version=response.applied_version,model_id=response.model_id,prompts_generated=response.prompts_generated,metadata=dict(response.metadata),message=response.message)
except grpc.RpcError as exc:
 result.update(error_code=exc.code().name,error=exc.details(),accepted=False)
with grpc.insecure_channel('contextual-study-updater:50052') as channel:
 status=api.ParamUpdateServiceStub(channel).GetParameterUpdateStatus(pb.ParameterUpdateStatusRequest(source_id='contextual-study-fuzzer',request_id=req.request_id,request_source_id=req.source_id,model_id=req.model_id,request_fingerprint=fingerprint),timeout=30)
 result['receipt']={'found':status.found,'accepted':status.ack.accepted,'model_id':status.ack.model_id,'applied_version':status.ack.applied_version,'base_version':status.base_version,'prompts_generated':status.prompts_generated}
print(json.dumps(result))
"""
        try:
            result = json.loads(self.call(["exec", "-T", "contextual-study-fuzzer", "python", "-c", code], content=json.dumps(record).encode(), timeout=360))
        except Exception as exc:
            raise UnknownUpdateOutcome("Training/receipt outcome unknown; stop study, preserve evidence, no request retry.") from exc
        if result.get("error_code") and result["error_code"] not in {"FAILED_PRECONDITION", "INVALID_ARGUMENT"}:
            raise UnknownUpdateOutcome(f"Ambiguous training result: {result['error_code']}")
        receipt = result["receipt"]
        if result["accepted"] and (not receipt["found"] or not receipt["accepted"] or receipt["model_id"] != result["model_id"] or receipt["applied_version"] != result["applied_version"] or receipt["base_version"] != result["base_version"] or receipt["prompts_generated"] != result["prompts_generated"]):
            raise UnknownUpdateOutcome("Accepted acknowledgment is not bound to its durable receipt.")
        if not result["accepted"] and receipt["found"]:
            raise UnknownUpdateOutcome("Rejected response conflicts with a durable committed receipt.")
        result["partition_inventory"] = inventory
        return result

    def measure(self, artifact_path, dataset_path, reference, run_name):
        active = self.images()
        if any(active[service] != self.state["study_images"][service] for service in ("client-runtime", "model-streaming-service")):
            raise ValueError("Runtime/streamer immutable image IDs drifted during measurement.")
        self.command([sys.executable, str(ROOT / "evaluation/run-ablations.py"), "--dataset-file", str(dataset_path), "--run-name", run_name, "--layers", "semantic", "pipeline", "--model-artifact", str(artifact_path), "--bootstrap-iterations", "0"], timeout=3600)
        directory = ROOT / "evaluation/results" / run_name
        counts, reports = {}, {}
        artifact = load_artifact(artifact_path)
        for layer in ("semantic", "pipeline"):
            files = list(directory.glob(f"local-jsonl_{layer}_*_results.json"))
            if len(files) != 1:
                raise ValueError("Matched report missing or duplicated.")
            counts[layer] = verified_report(read(files[0]), reference, artifact)
            reports[layer] = {"path": str(files[0]), "sha256": sha(files[0])}
        write(directory / "by-dataset.json", {layer: by_dataset(read(value["path"])) for layer, value in reports.items()})
        return counts, reports

    def fixture(self, artifact_path, cases, path, *, resume=False):
        import grpc
        from google.protobuf.json_format import MessageToDict
        from privoke.v1 import runtime_pb2 as pb, runtime_pb2_grpc as api
        artifact = load_artifact(artifact_path)
        identity = artifact_identity(artifact)
        path = Path(path)
        if path.exists() and not resume:
            raise ValueError("Existing fixture evidence requires an audited continuation.")
        result = read(path) if resume and path.exists() else {}
        if list(result) != [case["case_id"] for case in cases[:len(result)]]:
            raise ValueError("Fixture continuation is not an exact completed prefix.")

        def verified_observation(case, observation):
            request_id = "ctx-fixture-" + hashlib.sha256((str(path) + case["case_id"]).encode()).hexdigest()[:40]
            raw = observation["raw"]
            if (observation.get("request_id") != request_id or raw.get("request_id") != request_id
                    or observation.get("action") not in RANK or raw.get("action") != observation["action"]
                    or raw.get("error")):
                raise ValueError("Contextual fixture request failed.")
            observations = 0
            for layer in raw.get("layers", []):
                if layer.get("status") not in {"ok", "skipped"} or (layer.get("error") and layer.get("status") != "skipped"):
                    raise ValueError("Contextual fixture request failed.")
                if layer.get("layer") == "DETECTION_LAYER_SEMANTIC" and layer.get("status") == "ok":
                    # The frozen streamed classifier returns [] for S0/PU/no categories.
                    # Such a successful negative response has no per-case identity item.
                    for item in layer.get("results", []):
                        if any(item.get("metadata", {}).get(k) != v for k, v in identity.items()):
                            raise ValueError("Fixture semantic model identity mismatch.")
                        observations += 1
            return observations

        identity_observations = sum(verified_observation(case, result[case["case_id"]])
                                    for case in cases[:len(result)])
        with grpc.insecure_channel(self.args.runtime_target) as channel:
            client = api.PrivokeRuntimeServiceStub(channel)
            for case in cases:
                if case["case_id"] in result:
                    continue
                request_id = "ctx-fixture-" + hashlib.sha256((str(path) + case["case_id"]).encode()).hexdigest()[:40]
                kwargs = {"text": case["text"], "request_id": request_id, "source": "contextual-fuzzer-study", "semantic_model_id": artifact["model_id"]}
                if case.get("visibility_hint") is not None:
                    kwargs["visibility_hint"] = case["visibility_hint"]
                response = client.AnalyzePrompt(pb.AnalyzePromptRequest(**kwargs), timeout=120)
                if response.error or response.request_id != request_id or response.action not in RANK or any(layer.status not in {"ok", "skipped"} or (layer.error and layer.status != "skipped") for layer in response.layers):
                    raise ValueError("Contextual fixture request failed.")
                raw = MessageToDict(response, preserving_proto_field_name=True)
                observation = {"action": response.action, "raw": raw, "request_id": request_id}
                identity_observations += verified_observation(case, observation)
                result[case["case_id"]] = observation
                write(path, result)
        if not identity_observations:
            raise ValueError("Fixture supplies no returned semantic model identity evidence.")
        return result


@contextmanager
def restored_catalog(driver, backups):
    """Stop potential publishers before restoring all exact original payloads."""
    try:
        yield
    finally:
        driver.stop_jobs()
        for profile, content in backups.items():
            driver.install_raw(profile, content)
        driver.restore_services()
        if any(driver.live(profile) != content for profile, content in backups.items()):
            raise RuntimeError("Exact original catalog restoration failed.")


def bound_inputs(state):
    prepared = read(Path(state["prepared"]) / "manifest.json")
    if sha(Path(state["prepared"]) / "prompts.jsonl") != prepared["curriculum_sha256"] or sha(Path(state["prepared"]) / "manifest.json") != state["preparation_manifest_sha256"]:
        raise ValueError("Frozen training preparation changed.")
    validation = bound_rows(state["validation"], VALIDATION_SHA, 968, 475)
    return validation


def baseline(args, state, driver):
    directory = Path(args.output)
    validation = bound_inputs(state)
    backups = {p: driver.live(p) for p in PROFILES}
    images = driver.images()
    automatic = driver.command(driver.base_compose + ["exec", "-T", "param-update-service", "python", "-c", "import os;print(os.environ['FUZZER_PROMPT_COUNT'])"]).decode().strip()
    if automatic != "0":
        raise ValueError("Original updater automatic startup training must be disabled.")
    driver.configure_images(images)
    state["images"] = images
    state["live_backups"] = {}
    (directory / "original-live").mkdir()
    for profile, content in backups.items():
        path = directory / "original-live" / f"{profile}.json"
        path.write_bytes(content)
        state["live_backups"][profile] = {"path": str(path.resolve()), "sha256": sha(path), "identity": artifact_identity(load_artifact(path))}
    write(directory / "state.json", state)
    with restored_catalog(driver, backups):
        state["baselines"] = {}
        for profile in PROFILES:
            source = ROOT / "models" / f"privoke-{profile}.json"
            artifact = load_artifact(source)
            if artifact["model_id"] != f"privoke-{profile}" or artifact["version"] != "v0.3.0":
                raise ValueError("Independent original profile base changed.")
            frozen = directory / f"original-{profile}.json"
            frozen.write_bytes(source.read_bytes())
            driver.install_raw(profile, frozen.read_bytes())
            driver.refresh()
            if "resources" not in state:
                state["resources"] = driver.resources()
            counts, reports = driver.measure(frozen, state["validation"], validation, f"{state['prefix']}-base-{profile}")
            state["baselines"][profile] = {"artifact": str(frozen.resolve()), "sha256": sha(frozen), "validation": counts, "reports": reports}
            write(directory / "state.json", state)
    if driver.images() != images:
        raise ValueError("Serving images changed during baseline.")
    state["baseline_complete"] = True
    state["restoration_verified"] = True
    write(directory / "state.json", state)


def candidates(args, state, driver):
    if not state.get("baseline_complete") or state.get("failure") or state.get("unknown_outcome") or state.get("selection"):
        raise ValueError("Candidate phase requires complete baselines and no unknown/frozen outcome.")
    validation = bound_inputs(state)
    backups = {p: Path(v["path"]).read_bytes() for p, v in state["live_backups"].items()}
    if any(sha(v["path"]) != v["sha256"] or driver.live(p) != backups[p] for p, v in state["live_backups"].items()) or driver.images() != state["images"]:
        raise ValueError("Original live catalog or immutable serving images changed between stages.")
    driver.configure_images(state["images"])
    state["restoration_verified"] = False
    write(Path(args.output) / "state.json", state)
    completed = {r["index"] for r in state["records"]}
    remaining = [r for r in state["planned_attempts"] if r["index"] not in completed][:args.limit]
    with restored_catalog(driver, backups):
        for record in remaining:
            target = Path(args.output) / f"attempt-{record['index']:02d}"
            target.mkdir()  # Existing/in-flight attempt refuses request ID reuse.
            write(target / "request.json", record)
            original_path = Path(state["baselines"][record["profile"]]["artifact"])
            if sha(original_path) != state["baselines"][record["profile"]]["sha256"]:
                raise ValueError("Frozen original base changed.")
            original = load_artifact(original_path)
            if record["strategy"] == "last_block":
                from privoke_model.contextual_training import prepare_contextual_training_artifact
                original = prepare_contextual_training_artifact(original, strategy="contextual_last_block_sgd_v1")
            base_path = target / "base.json"
            base_path.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8", newline="\n")
            driver.install_raw(record["profile"], base_path.read_bytes())
            driver.refresh()
            started = time.monotonic()
            try:
                response = driver.train(record)
            except UnknownUpdateOutcome as exc:
                state["unknown_outcome"] = {"attempt": record["index"], "message": str(exc)}
                write(Path(args.output) / "state.json", state)
                raise
            write(target / "response.json", response)
            result = {**record, "accepted": response["accepted"], "response_path": str((target / "response.json").resolve()), "response_sha256": sha(target / "response.json")}
            if response["accepted"]:
                if response["base_version"] != original["version"] or response["model_id"] != original["model_id"]:
                    raise ValueError("Training acknowledgment used a different base.")
                candidate = target / "candidate.json"
                candidate.write_bytes(driver.live(record["profile"]))
                payload = load_artifact(candidate)
                if payload["version"] != response["applied_version"]:
                    raise ValueError("Published snapshot and receipt differ.")
                verify_guarded_publication(original, payload, response)
                driver.refresh()
                counts, reports = driver.measure(candidate, state["validation"], validation, f"{state['prefix']}-v-{record['index']:02d}")
                result.update(artifact=str(candidate.resolve()), artifact_sha256=sha(candidate), identity=artifact_identity(payload), validation=counts, reports=reports)
                result["eligible"] = candidate_key(result, state["baselines"][record["profile"]]["validation"]["pipeline"]) is not None
            result["wall_seconds"] = time.monotonic() - started
            state["records"].append(result)
            write(Path(args.output) / "state.json", state)
            driver.stop_jobs()
    if driver.images() != state["images"]:
        raise ValueError("Serving images changed during candidate stage.")
    state["restoration_verified"] = True
    write(Path(args.output) / "state.json", state)


def freeze(args, state):
    validation = bound_inputs(state)
    if len(state["records"]) != 54 or {r["index"] for r in state["records"]} != set(range(54)) or state.get("failure") or state.get("unknown_outcome") or not state.get("restoration_verified"):
        raise ValueError("All 54 predeclared attempts must terminate with verified restoration before selection.")
    for record in state["records"]:
        planned = state["planned_attempts"][record["index"]]
        if any(record[key] != value for key, value in planned.items()) or sha(record["response_path"]) != record["response_sha256"]:
            raise ValueError("Attempt settings or receipt response bytes changed.")
        response = read(record["response_path"])
        if response["accepted"] != record["accepted"]:
            raise ValueError("Attempt status and preserved acknowledgment differ.")
        if record["accepted"]:
            if sha(record["artifact"]) != record["artifact_sha256"]:
                raise ValueError("Candidate bytes changed before selection.")
            artifact = load_artifact(record["artifact"])
            for layer, evidence in record["reports"].items():
                if sha(evidence["path"]) != evidence["sha256"] or verified_report(read(evidence["path"]), validation, artifact) != record["validation"][layer]:
                    raise ValueError("Validation evidence changed before selection.")
    eligible = [(candidate_key(r, state["baselines"][r["profile"]]["validation"]["pipeline"]), r) for r in state["records"] if r["accepted"]]
    eligible = [(key, r) for key, r in eligible if key is not None]
    winner = max(eligible, key=lambda item: item[0])[1] if eligible else None
    selection = {"rule": "Validation TP>=428/475 and TN strictly above same-profile original; TN,TP,fewer cycles,lower LR,seed,smaller profile,heads tie preference", "winner": winner, "candidate_count": 54, "development_access_for_selection": False}
    path = Path(args.output) / "selection.json"
    if path.exists():
        raise ValueError("Selection already frozen.")
    write(path, selection)
    state["selection"] = {"path": str(path.resolve()), "sha256": sha(path)}
    write(Path(args.output) / "state.json", state)


def finalize(args, state, driver):
    if state.get("failure") or state.get("finalized") or not state.get("selection") or sha(state["selection"]["path"]) != state["selection"]["sha256"]:
        raise ValueError("Missing/changed selection or endpoint already measured.")
    winner = read(state["selection"]["path"])["winner"]
    if winner is None:
        state["finalized"] = {"retained": False, "reason": "No eligible validation candidate; original live catalog retained."}
        write(Path(args.output) / "state.json", state)
        return
    development = bound_rows(state["development"], DEVELOPMENT_SHA, 502, 264)
    cases = bound_rows(state["fixture"], FIXTURE_SHA, 48)
    backups = {p: Path(v["path"]).read_bytes() for p, v in state["live_backups"].items()}
    if driver.images() != state["images"] or any(driver.live(p) != content for p, content in backups.items()):
        raise ValueError("Catalog/images changed before final development check.")
    driver.configure_images(state["images"])
    directory = Path(args.output)
    state["restoration_verified"] = False
    write(directory / "state.json", state)
    with restored_catalog(driver, backups):
        driver.refresh()
        reference_path = Path(state["live_backups"]["balanced"]["path"])
        reference_counts, reference_reports = driver.measure(reference_path, state["development"], development, f"{state['prefix']}-d-live")
        before = driver.fixture(reference_path, cases, directory / "fixture-live.json")
        artifact_path = Path(winner["artifact"])
        if sha(artifact_path) != winner["artifact_sha256"]:
            raise ValueError("Frozen winner artifact changed.")
        driver.install_raw(winner["profile"], artifact_path.read_bytes())
        driver.refresh()
        candidate_counts, candidate_reports = driver.measure(artifact_path, state["development"], development, f"{state['prefix']}-d-winner")
        after = driver.fixture(artifact_path, cases, directory / "fixture-winner.json")
        contextual = fixture_gate(cases, before, after)
        counts = candidate_counts["pipeline"]
        retained = counts["tp"] / 264 >= .9 and counts["tn"] > reference_counts["pipeline"]["tn"] and contextual["passed"]
        state["finalized"] = {"retained": retained, "reference": reference_counts, "candidate": candidate_counts, "reference_reports": reference_reports, "candidate_reports": candidate_reports, "contextual_gate": contextual, "retained_research_artifact": winner["artifact"] if retained else None, "catalog_policy": "Original live bytes restored; retained artifact is a research selection, no default promotion.", "final_access": False}
        write(directory / "final-assessment.json", state["finalized"])
    if driver.images() != state["images"]:
        raise ValueError("Serving images changed during endpoint measurement.")
    state["restoration_verified"] = True
    write(directory / "state.json", state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "initialize", "baseline", "candidates", "freeze", "finalize"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--source-results", type=Path)
    parser.add_argument("--prefix", default="ctxfuzz20261006")
    parser.add_argument("--project-name", default="privoke-research-project")
    parser.add_argument("--runtime-target", default="127.0.0.1:50054")
    parser.add_argument("--base-override", action="append", default=[], help="Existing serving overlays, preserved in order throughout study and restoration.")
    for image in ("runtime", "streamer", "updater", "fuzzer"):
        parser.add_argument(f"--{image}-image", help="Root-built study image; resolved to immutable ID before changes, never built by controller.")
    parser.add_argument("--limit", type=int, default=1, help="Number of next fixed attempts in this stage, 1..54; selection always requires all 54.")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", args.prefix) or not 1 <= args.limit <= 54:
        parser.error("Prefix must be 1..32 safe characters; stage limit must be 1..54.")
    args.output = args.output.resolve()
    results_root = (ROOT / "evaluation/results").resolve()
    if args.output.parent != results_root:
        parser.error("Study output must be a fresh direct child of this checkout's evaluation/results.")
    if args.mode in ("plan", "initialize"):
        if not args.prepared or not args.source_results:
            parser.error("Plan/initialize require prepared curriculum and source-results paths.")
        state = {"schema_version": 1, "prefix": args.prefix, "prepared": str(args.prepared.resolve()), "preparation_manifest_sha256": sha(args.prepared / "manifest.json"), "validation": str((args.source_results / "representation_20261004_v3/prepared/validation.jsonl").resolve()), "development": str((args.source_results / "locked-public/development.jsonl").resolve()), "fixture": str((args.source_results / "contextual_fixtures_20261004_v1/support/fixture.jsonl").resolve()), "planned_attempts": list(attempts(args.prefix)), "records": [], "restoration_verified": False, "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "controller_sha256": sha(__file__), "overlay_sha256": sha(ROOT / "evaluation/compose.contextual-fuzzer-study.yml"), "protocol_canonical_lf_sha256": hashlib.sha256((ROOT / "docs/fuzzer-model-study-20261006.md").read_text(encoding="utf-8").replace("\r\n", "\n").encode()).hexdigest()}
        state.update(base_overrides=args.base_override, project_name=args.project_name, runtime_target=args.runtime_target)
        bound_inputs(state)
        print(json.dumps(state, indent=2))
        if args.mode == "plan":
            return
        if args.output.exists():
            raise SystemExit("Refusing existing study output.")
        args.output.mkdir(parents=True)
        source_freeze = args.output / "source-freeze"
        source_freeze.mkdir()
        state["source_freeze"] = {}
        for label, source_path in (("protocol.md", ROOT / "docs/fuzzer-model-study-20261006.md"), ("controller.py", Path(__file__)), ("overlay.yml", ROOT / "evaluation/compose.contextual-fuzzer-study.yml"), ("preparation-manifest.json", args.prepared / "manifest.json"), ("preparer.py", ROOT / "evaluation/prepare-contextual-fuzzer-study.py")):
            frozen = source_freeze / label
            frozen.write_bytes(source_path.read_bytes())
            state["source_freeze"][label] = {"path": str(frozen.resolve()), "sha256": sha(frozen)}
        state["base_override_sha256"] = {p: sha(ROOT / p) for p in args.base_override}
        state["computation_source_sha256"] = {}
        for source_path in computation_sources():
            relative = source_path.relative_to(ROOT)
            frozen = source_freeze / "tree" / relative
            frozen.parent.mkdir(parents=True, exist_ok=True)
            frozen.write_bytes(source_path.read_bytes())
            state["computation_source_sha256"][relative.as_posix()] = sha(source_path)
        write(args.output / "state.json", state)
        return
    state = read(args.output / "state.json")
    if (subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != state["source_revision"]
            or {p.relative_to(ROOT).as_posix(): sha(p) for p in computation_sources()} != state["computation_source_sha256"]):
        raise ValueError("Serving/training/scoring source changed after experiment initialization.")
    if args.project_name != state["project_name"] or args.runtime_target != state["runtime_target"] or args.base_override and args.base_override != state["base_overrides"]:
        raise ValueError("Project/runtime target/ordered base overlays differ from initialization.")
    args.project_name, args.runtime_target = state["project_name"], state["runtime_target"]
    if any(sha(p) != value["sha256"] for p, value in ((v["path"], v) for v in state["source_freeze"].values())) or any(sha(ROOT / p) != commitment for p, commitment in state["base_override_sha256"].items()):
        raise ValueError("Frozen source or serving override bytes changed.")
    if sha(__file__) != state["controller_sha256"] or sha(ROOT / "evaluation/compose.contextual-fuzzer-study.yml") != state["overlay_sha256"]:
        raise ValueError("Controller/overlay source changed after study freeze.")
    if hashlib.sha256((ROOT / "docs/fuzzer-model-study-20261006.md").read_text(encoding="utf-8").replace("\r\n", "\n").encode()).hexdigest() != state["protocol_canonical_lf_sha256"] or state["planned_attempts"] != list(attempts(state["prefix"])):
        raise ValueError("Protocol or predeclared attempts changed after study freeze.")
    if args.mode == "freeze":
        freeze(args, state)
        return
    if args.mode == "baseline" and state.get("live_backups"):
        raise ValueError("Baseline started already; preserve failed evidence and use a fresh study.")
    driver = Driver(args, state)
    with (args.output / "study.log").open("a", encoding="utf-8") as log:
        driver.log = log
        try:
            {"baseline": baseline, "candidates": candidates, "finalize": finalize}[args.mode](args, state, driver)
        except Exception as exc:
            state["failure"] = {"phase": args.mode, "type": type(exc).__name__, "message": str(exc)}
            write(args.output / "state.json", state)
            raise


if __name__ == "__main__":
    main()
