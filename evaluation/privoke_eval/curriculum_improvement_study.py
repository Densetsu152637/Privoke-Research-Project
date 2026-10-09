"""Prospective isolated matrix supervisor; prepare, execute, and audit are explicit.

Preparation requires committed source. Execution never resets an existing model,
replaces a pending request, promotes a model, or opens protected final data.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from host_environment import ROOT, configure_imports
configure_imports()
from privoke_model.artifact import float32, load_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_eval import continual_fuzzer_study as continual
from privoke_eval import synthetic_curriculum as synthetic
from privoke_eval.curriculum_improvement_evidence import (
    audit_allocations, binary_counts, contextual_changes, contextual_metrics,
    digest, matched, restriction_harms, seed_statistics,
)

PROFILES = ("efficient", "balanced", "quality")
SEEDS = (42, 43, 44)
ARMS = {"A": ("current", "deterministic_v1", .35), "B": ("revised", "deterministic_v1", .35),
        "C": ("current", "seeded_family_v1", .35), "D": ("revised", "seeded_family_v1", .35),
        "E": ("revised", "seeded_family_v1", 1.0)}
SERVICES = ("model-streaming-service", "param-update-service", "client-runtime", "privoke-fuzzer", "telemetry-service")
SUFFIXES = ("model", "updater", "runtime", "fuzzer", "telemetry")
RESOURCES = {"current": ("synthetic-teacher-templates.json", "b6257d9166e6e435105e1fc914c169e0f31990f4a4671adc93ead0addf1d80e6"),
             "revised": ("synthetic-teacher-templates-v2.json", "044b94cc9a0723b3ad196c9060db690560f37d3a15dba67db6bc9d48fdeb1583"),
             "assessment": ("contextual-assessment-20261009.json", "4b90449d9ca625b2eaa498ae1af2542dc1632a79ea2733356c86a19035e5a435")}
FIXTURE_SHA = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
ENV_PREFIXES = ("FUZZ", "PARAM_", "MODEL_", "PRIVOKE_", "TELEMETRY_", "OMP_", "MKL_", "PYTHONPATH")
HARD_POSITIVE_CONTRASTS = {"mixed_discussion_actual_disclosure_vs_discussion", "quoted_actual_fact_vs_fictional_quote",
                           "public_actual_disclosure_vs_hypothetical", "hypothetical_frame_actual_fact_vs_invented_fact"}


def now():
    return datetime.now(timezone.utc).isoformat()


def command(args, *, env=None, log=None):
    """Execute without shell interpolation; logs retain failures and interruptions."""
    if log:
        with Path(log).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps([str(a) for a in args]) + "\n")
            stream.flush()
            subprocess.run(list(map(str, args)), cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        return ""
    return subprocess.check_output(list(map(str, args)), cwd=ROOT, env=env, text=True)


def source_inventory():
    paths = {ROOT / name for name in ("docker-compose.yml", "evaluation/compose.tests.yml", "evaluation/compose.continual-fuzzer-study.yml",
             "evaluation/host_environment.py", "evaluation/run-curriculum-improvement-study.py", "evaluation/fit-contextual-representation-arm.py",
             "evaluation/run-continual-fuzzer-study.py",
             "evaluation/Dockerfile.curriculum-improvement", "evaluation/requirements-training.txt")}
    for directory in ("evaluation/privoke_eval", "shared/python", "extension/client-runtime/src", "services/privoke-fuzzer/src", "services/param-update-service/app"):
        paths.update(p for p in (ROOT / directory).rglob("*.py") if "__pycache__" not in p.parts)
    paths.update(ROOT / "models" / f"privoke-{profile}.json" for profile in PROFILES)
    paths.update(ROOT / "evaluation/datasets" / name for name, _ in RESOURCES.values())
    return {str(path.relative_to(ROOT)).replace("\\", "/"): continual.sha(path) for path in sorted(paths)}


def require_committed_sources(inventory):
    revision = command(["git", "rev-parse", "HEAD"]).strip()
    # Compare bytes to the committed blob, allowing repository checkout CRLF rules.
    dirty = command(["git", "status", "--porcelain", "--", *inventory]).strip()
    if dirty:
        raise ValueError("Commit all computation/input sources before protocol freeze.")
    return revision


def attest_image_sources(images, inventory):
    """Read copied computation files inside immutable serving images before freeze."""
    result = {}
    for service, prefix in (("privoke-fuzzer", "services/privoke-fuzzer/src/"),
                            ("param-update-service", "services/param-update-service/app/"),
                            ("client-runtime", "extension/client-runtime/src/")):
        expected = {"/workspace/" + name: value for name, value in inventory.items()
                    if name.startswith(prefix) or name.startswith("shared/python/")}
        if service == "privoke-fuzzer":
            name = "evaluation/privoke_eval/synthetic_curriculum.py"
            expected["/workspace/" + name] = inventory[name]
        code = "import hashlib,json,sys; expected=json.loads(sys.argv[1]); print(json.dumps({p:hashlib.sha256(open(p,'rb').read()).hexdigest() for p in expected},sort_keys=True))"
        observed = json.loads(command(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "python",
                                       images[service], "-B", "-c", code, json.dumps(expected)]))
        if observed != expected:
            raise ValueError(f"{service} image computation files differ from committed source.")
        result[service] = observed
    return result


def matrix(study_id):
    cells = []
    for profile in PROFILES:
        for arm, (curriculum, policy, weight) in ARMS.items():
            for seed in SEEDS:
                key = f"{profile}-{arm.lower()}-{seed}"
                cells.append({"id": key, "kind": "live", "profile": profile, "arm": arm, "replicate_seed": seed,
                              "curriculum": curriculum, "policy": policy, "sampler_seed": seed if policy != "deterministic_v1" else 0,
                              "replay_weight": weight, "project": f"{study_id}-{key}"})
        for seed in SEEDS:
            for mode in ("head_only", "end_to_end"):
                key = f"{profile}-{mode.replace('_', '-')}-{seed}"
                cells.append({"id": key, "kind": "offline", "profile": profile, "mode": mode,
                              "replicate_seed": seed, "curriculum": "revised", "project": f"{study_id}-{key}"})
    return cells


def pinned_jsonl(path, commitment):
    path = continual.permitted_path(path)
    if continual.sha(path) != commitment:
        raise ValueError("Endpoint byte commitment differs.")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def prepare(args):
    output = continual.permitted_path(args.output)
    if not re.fullmatch(r"privoke-improve-[a-z0-9-]+", args.study_id):
        raise ValueError("Unique lowercase privoke-improve- study ID required.")
    inventory = source_inventory()
    revision = require_committed_sources(inventory)
    for name, commitment in RESOURCES.values():
        if continual.sha(ROOT / "evaluation/datasets" / name) != commitment:
            raise ValueError("Reviewed resource bytes changed.")
    dataset = continual.permitted_path(args.dataset)
    development = pinned_jsonl(dataset, continual.DEVELOPMENT_SHA)
    if dataset.name != "development.jsonl" or len(development) != 502:
        raise ValueError("Only the pinned 502-row development endpoint is allowed.")
    fixtures = pinned_jsonl(args.fixture, FIXTURE_SHA)
    if len(fixtures) != 48 or sum(row["ambiguous"] for row in fixtures) != 7:
        raise ValueError("Expected 48 fixture rows, seven ambiguous.")
    pools = [synthetic.build_curriculum(continual.read_json(ROOT / "evaluation/datasets" / RESOURCES[k][0])) for k in ("current", "revised")]
    assessment_resource = ROOT / "evaluation/datasets" / RESOURCES["assessment"][0]
    assessment = synthetic.build_assessment(continual.read_json(assessment_resource), pools)
    synthetic.verify_exclusions({"assessment": assessment}, continual.read_json(args.exclusion_index), development)
    images = json.loads(args.images.read_text(encoding="utf-8"))
    if set(images) != set(SERVICES) | {"offline-training"}:
        raise ValueError("Images JSON must pin five serving services and offline-training.")
    if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in images.values()):
        raise ValueError("Only immutable full image IDs are allowed.")
    for image in images.values():
        observed = json.loads(command(["docker", "image", "inspect", image]))[0]
        if observed["Id"] != image:
            raise ValueError("Image identity differs.")
    attestation = attest_image_sources(images, inventory)
    output.mkdir(parents=True, exist_ok=False)
    for name in ("current", "revised"):
        synthetic.prepare(output / "curricula" / name, ROOT / "evaluation/datasets" / RESOURCES[name][0],
                          args.exclusion_index, dataset, continual.DEVELOPMENT_SHA, 9102026, assessment_resource)
    inputs = {"dataset": {"path": str(dataset), "sha256": continual.DEVELOPMENT_SHA},
              "fixture": {"path": str(Path(args.fixture).resolve()), "sha256": FIXTURE_SHA},
              "exclusion_index": {"path": str(Path(args.exclusion_index).resolve()), "sha256": continual.sha(args.exclusion_index)}}
    for name in ("current", "revised"):
        directory = output / "curricula" / name
        manifest = continual.read_json(directory / "manifest.json")
        inputs[name] = {"manifest": str(directory / "manifest.json"), "manifest_sha256": continual.sha(directory / "manifest.json"),
                        "files": {entry["path"]: entry["sha256"] for entry in [*manifest["splits"].values(), manifest["assessment"]]}}
    protocol = {"schema_version": 1, "study_id": args.study_id, "created_at": now(), "source_revision": revision,
                "source_files": inventory, "images": images, "image_source_attestation": attestation, "inputs": inputs, "cells": matrix(args.study_id),
                "live": {"attempts": 20, "trainer_seed": 1337, "prompt_count": 256, "new_rows": 192, "replay_rows": 64,
                         "learning_rate": .003, "gradient_clamp": .05, "transforms": 0, "mining": False, "checkpoints": [0, 20]},
                "offline": {"steps": 20, "batch_size": 32, "presentations": 640, "optimizer": "Adam", "learning_rate": .001,
                            "weight_decay": .0001, "max_gradient_norm": 1.0, "replay": False, "gate": False,
                            "schedule": "seeded shuffled without replacement revised TRAIN; same schedule per head/full pair; partial epoch"},
                "analysis": {"bootstrap_iterations": 2000, "bootstrap_seed": 10102026,
                             "primary_contextual_metric": "pipeline joint sensitivity/visibility/category exact accuracy",
                             "eligibility": "pipeline recall>=.90; strict specificity gain; contextual primary no decline; no new/worsened casewise fixture harm",
                             "contrasts": ["B-A", "D-C", "C-A", "D-B", "(D-C)-(B-A)", "D-A", "E-D"],
                             "seed_uncertainty": "individual, mean, range, sample SD; deterministic replicas may be identical, not independent"},
                "limitations": ["Assistant-provisional contextual truth; overlapping semantic archetypes, not broad generalization.",
                                "Revised curriculum package changes wording, visibility and category mix; not isolated diversity.",
                                "Annotation-presence development labels differ from contextual truth.",
                                "Offline matched Adam comparison has different budget/optimizer/gate from live study.",
                                "No automatic model promotion; protected final never read."]}
    continual.write_json(output / "protocol.json", protocol)
    continual.write_json(output / "supervisor.json", {"status": "prepared", "protocol_sha256": continual.sha(output / "protocol.json"), "cells": {}})
    return protocol


def verify_freeze(output):
    protocol = continual.read_json(output / "protocol.json")
    state = continual.read_json(output / "supervisor.json")
    if state["protocol_sha256"] != continual.sha(output / "protocol.json") or protocol["source_files"] != source_inventory():
        raise ValueError("Frozen protocol or source bytes changed.")
    if require_committed_sources(protocol["source_files"]) != protocol["source_revision"]:
        raise ValueError("Execution revision changed after protocol freeze.")
    for key in ("dataset", "fixture", "exclusion_index"):
        item = protocol["inputs"][key]
        if continual.sha(continual.permitted_path(item["path"])) != item["sha256"]:
            raise ValueError("Frozen input bytes changed.")
    for key in ("current", "revised"):
        item = protocol["inputs"][key]
        path = Path(item["manifest"])
        if continual.sha(path) != item["manifest_sha256"] or any(continual.sha(path.parent / name) != value for name, value in item["files"].items()):
            raise ValueError("Prepared curriculum or assessment bytes changed.")
    return protocol, state


def artifact_identity(artifact):
    return {"model_id": artifact["model_id"], "model_version": artifact["version"], "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint({name: [float32(v) for v in tensor["values"]] for name, tensor in artifact["parameters"].items()},
                                                           {name: tensor["shape"] for name, tensor in artifact["parameters"].items()})}


def assert_baseline(snapshot, artifact):
    if snapshot["identity"] != artifact_identity(artifact):
        raise ValueError("Fresh volume did not restore the exact checked-in profile baseline.")
    for name, tensor in artifact["parameters"].items():
        if snapshot["parameters"][name] != {"values": [float32(v) for v in tensor["values"]], "shape": tensor["shape"]}:
            raise ValueError("Baseline parameter values differ.")


def contextual_rows(client, rows, model_id, identity, tag, fixture=False):
    result = {}
    for layer in ("semantic", "pipeline"):
        predictions, seen = [], False
        for row in rows:
            key = row["case_id"] if fixture else row["id"]
            response = client.analyze(row, model_id, layer, "improve-" + digest([tag, layer, key])[:40])
            if any(value != identity for value in response["identities"]):
                raise ValueError("Contextual endpoint served a different model identity.")
            seen |= bool(response["identities"])
            raw = response["raw"]
            target = row.get("classification")
            quantitative = not row["ambiguous"] if fixture else True
            if fixture:
                target = {"sensitivity": row.get("expected_sensitivity"), "visibility": row.get("expected_visibility"),
                          "categories": row.get("expected_categories", [])}
                quantitative = quantitative and row.get("action_accuracy_eligible", True) and row.get("context_truth_eligible", True)
                action = row.get("minimum_action") or row.get("expected_action")
                allowed = row.get("allowed_actions") or ([action] if action else ["ALLOW", "WARN", "BLOCK"])
                if not row.get("allowed_actions") and row.get("minimum_action"):
                    allowed = [a for a in ("ALLOW", "WARN", "BLOCK") if ("ALLOW", "WARN", "BLOCK").index(a) >= ("ALLOW", "WARN", "BLOCK").index(action)]
            else:
                allowed = row["allowed_actions"]
            predictions.append({"id": key, "group_id": row.get("group_id", row.get("family_id", key)), "status": "ok", "quantitative": quantitative,
                                "hard_positive": row.get("metadata", {}).get("contrast") in HARD_POSITIVE_CONTRASTS and target["sensitivity"] != "S0",
                                "target": target, "allowed_actions": allowed, "classification": raw["classification"], "action": raw["action"],
                                "raw": raw, "identities": response["identities"]})
        if not seen or client.snapshot(model_id)["identity"] != identity:
            raise ValueError("Contextual endpoint lacks identity or model changed during measurement.")
        result[layer] = {"predictions": predictions}
        result[layer]["metrics"] = contextual_metrics(predictions)
    return result


def operations(project):
    inspected = json.loads(command(["docker", "inspect", *[f"{project}-{suffix}" for suffix in SUFFIXES]]))
    return {"containers": {row["Name"].lstrip("/"): {"image_id": row["Image"],
              "environment": {k: v for k, v in (entry.split("=", 1) for entry in row["Config"]["Env"] if "=" in entry) if k.startswith(ENV_PREFIXES)},
              "mounts": [{"type": item["Type"], "name": item.get("Name"), "source": item["Source"], "destination": item["Destination"]} for item in row["Mounts"]]}
              for row in inspected}}


def validate_operations(operations_record, cell, protocol):
    expected = {"fuzzer": {"MODEL_ID": f"privoke-{cell['profile']}", "FUZZ_TRAINING_LEARNING_RATE": "0.003",
                "FUZZ_TRAINING_MAX_GRADIENT": "0.05", "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE": "0", "FUZZ_HELDOUT_PROMPT_COUNT": "16",
                "FUZZ_CURRICULUM_REPLAY_FRACTION": "0.25", "FUZZ_TRAINING_REPLAY_WEIGHT": str(cell.get("replay_weight", .35)),
                "FUZZ_CURRICULUM_MANIFEST_PATH": "/curriculum/manifest.json", "FUZZ_MAX_CONCURRENT_CYCLES": "1"},
                "updater": {"MODEL_ID": f"privoke-{cell['profile']}", "FUZZER_PROMPT_COUNT": "0"},
                "runtime": {"PRIVOKE_MODEL_DEVICE": "cpu", "MODEL_STREAMING_CACHE_TTL_SECONDS": "1", "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "TELEMETRY_ENABLED": "false"}}
    for suffix, variables in expected.items():
        actual = operations_record["containers"][f"{cell['project']}-{suffix}"]["environment"]
        if any(actual.get(key) != value for key, value in variables.items()):
            raise ValueError("Effective service settings differ from prospective protocol.")
    for service, suffix in zip(SERVICES, SUFFIXES):
        container = operations_record["containers"][f"{cell['project']}-{suffix}"]
        if container["image_id"] != protocol["images"][service]:
            raise ValueError("Serving image differs from protocol.")
        if any(mount["type"] == "volume" and mount.get("name") and not mount["name"].startswith(cell["project"] + "-")
               for mount in container.get("mounts", [])):
            raise ValueError("Cell uses a volume outside its unique project namespace.")


def compose_configuration(output, protocol, cell):
    directory = output / "cells" / cell["id"]
    directory.mkdir(parents=True, exist_ok=True)
    override = {"services": {name: {"image": protocol["images"][name], "pull_policy": "never"} for name in SERVICES}}
    override["services"]["storage-permissions"] = {"image": protocol["images"]["param-update-service"], "pull_policy": "never"}
    override["services"]["client-runtime"]["volumes"] = ["telemetry-client-state:/var/lib/privoke"]
    override["services"]["privoke-fuzzer"]["environment"] = {"FUZZ_TRAINING_REPLAY_WEIGHT": str(cell.get("replay_weight", .35)),
                                                            "FUZZ_TRAINING_MAX_GRADIENT": "0.05"}
    path = directory / "compose.json"
    if path.exists() and continual.read_json(path) != override:
        raise ValueError("Saved Compose override differs.")
    continual.write_json(path, override)
    env = dict(os.environ, CONTINUAL_STUDY_ID=cell["project"], CONTINUAL_STUDY_MODEL_ID=f"privoke-{cell['profile']}",
               CONTINUAL_STUDY_CURRICULUM=str(Path(protocol["inputs"][cell["curriculum"]]["manifest"]).parent))
    compose = ["docker", "compose", "--project-name", cell["project"], "-f", ROOT / "docker-compose.yml",
               "-f", ROOT / "evaluation/compose.tests.yml", "-f", ROOT / "evaluation/compose.continual-fuzzer-study.yml", "-f", path]
    return directory, compose, env


def endpoints(client, protocol, cell, identity, directory, checkpoint, *, development=True):
    path = directory / f"context-{checkpoint:03d}.json"
    fixture_path = directory / f"fixture-{checkpoint:03d}.json"
    for destination, rows, is_fixture in ((path, pinned_jsonl(Path(protocol["inputs"]["revised"]["manifest"]).parent / "assessment.jsonl",
             protocol["inputs"]["revised"]["files"]["assessment.jsonl"]), False),
             (fixture_path, pinned_jsonl(protocol["inputs"]["fixture"]["path"], FIXTURE_SHA), True)):
        if destination.exists():
            saved = continual.read_json(destination)
            if saved["identity"] != identity:
                raise ValueError("Archived endpoint identity differs on resume.")
            continue
        report = contextual_rows(client, rows, f"privoke-{cell['profile']}", identity, f"{cell['id']}:{checkpoint}", is_fixture)
        continual.write_json(destination, {"identity": identity, "layers": report})
    if development:
        destination = directory / f"development-{checkpoint:03d}.json"
        if not destination.exists():
            rows = pinned_jsonl(protocol["inputs"]["dataset"]["path"], continual.DEVELOPMENT_SHA)
            continual.write_json(destination, continual.measure(client, rows, f"privoke-{cell['profile']}", identity, f"{cell['id']}:{checkpoint}"))


def baseline_equivalence(output, profile, checkpoints):
    path = output / f"baseline-{profile}.json"
    compact = {name: {layer: [{k: row.get(k) for k in ("id", "group_id", "status", "detected_sensitive", "classification", "action", "target", "allowed_actions", "quantitative")}
                            | {"classification": row.get("classification", row.get("raw", {}).get("classification")),
                               "action": row.get("action", row.get("raw", {}).get("action"))} for row in data["predictions"]]
                     for layer, data in layers.items()} for name, layers in checkpoints.items()}
    if path.exists():
        if continual.read_json(path) != compact:
            raise ValueError("Same-profile baseline predictions differ across matrix cells.")
    else:
        continual.write_json(path, compact)


def verify_baseline_endpoints(output, profile, directory, live_directory=None):
    development = continual.read_json(live_directory / "checkpoint-000.json" if live_directory else directory / "development-000.json")
    baseline_equivalence(output, profile, {"development": development,
                         "context": continual.read_json(directory / "context-000.json")["layers"],
                         "fixture": continual.read_json(directory / "fixture-000.json")["layers"]})


def archive_cell(directory):
    inventory = {str(p.relative_to(directory)).replace("\\", "/"): continual.sha(p) for p in sorted(directory.rglob("*"))
                 if p.is_file() and p.name not in {"archive.json", "execution.log"}}
    continual.write_json(directory / "archive.json", inventory)
    return continual.sha(directory / "archive.json")


def execute(args):
    output = continual.permitted_path(args.output)
    protocol, state = verify_freeze(output)
    candidates = [cell for cell in protocol["cells"] if not args.cell or cell["id"] == args.cell]
    if not candidates:
        raise ValueError("Unknown cell ID.")
    for cell in candidates:
        verify_freeze(output)
        existing = state["cells"].get(cell["id"])
        if existing and existing.get("blocked_collision"):
            raise ValueError("Cell resource collision requires explicit ownership repair; cannot resume.")
        if existing and existing["status"] == "complete":
            verify_archive(output / "cells" / cell["id"], existing["archive_sha256"])
            continue
        directory, compose, env = compose_configuration(output, protocol, cell)
        cell_state = existing or {"status": "reserved", "started_at": now(), "project": cell["project"]}
        state["cells"][cell["id"]] = cell_state
        state.update(status="running", current_cell=cell["id"])
        continual.write_json(output / "supervisor.json", state)
        log = directory / "execution.log"
        owns_services = bool(existing)
        try:
            names = [f"{cell['project']}-{suffix}" for suffix in SUFFIXES]
            volumes = [f"{cell['project']}-{suffix}" for suffix in ("model-data", "update-data", "telemetry-data", "client-state", "fuzzer-dumps")]
            if not existing:
                occupied = command(["docker", "volume", "ls", "--format", "{{.Name}}"])
                if any(name in occupied.splitlines() for name in volumes) or any(name in command(["docker", "ps", "-a", "--format", "{{.Names}}"]).splitlines() for name in names):
                    cell_state["blocked_collision"] = True
                    raise ValueError("Fresh cell project/volumes already exist; refusing reuse.")
            owns_services = True
            command(compose + ["config", "--services"], env=env, log=log)
            command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", *SERVICES], env=env, log=log)
            current_ops = operations(cell["project"])
            validate_operations(current_ops, cell, protocol)
            op_path = directory / "operations.json"
            if op_path.exists():
                if continual.read_json(op_path) != current_ops:
                    raise ValueError("Operations changed on resume.")
            else:
                continual.write_json(op_path, current_ops)
            for service, suffix in zip(SERVICES, SUFFIXES):
                if current_ops["containers"][f"{cell['project']}-{suffix}"]["image_id"] != protocol["images"][service]:
                    raise ValueError("Serving image differs from protocol.")
            client = continual.RpcClient("127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50051")
            model_id = f"privoke-{cell['profile']}"
            artifact = load_artifact(ROOT / "models" / f"{model_id}.json")
            try:
                if cell_state["status"] == "reserved":
                    assert_baseline(client.snapshot(model_id), artifact)
                    command(["docker", "cp", f"{cell['project']}-updater:/models/{model_id}.json", directory / "initial-artifact.json"], log=log)
                    if continual.sha(directory / "initial-artifact.json") != continual.sha(ROOT / "models" / f"{model_id}.json"):
                        raise ValueError("Initial artifact byte SHA differs from checked-in baseline.")
                    cell_state["status"] = "baseline_verified"
                    continual.write_json(output / "supervisor.json", state)
                if cell["kind"] == "live":
                    run_live(output, protocol, state, cell, cell_state, directory, env, client, op_path, log)
                else:
                    run_offline(output, protocol, state, cell, cell_state, directory, client, log)
            finally:
                client.close()
            command(["docker", "cp", f"{cell['project']}-updater:/models/{model_id}.json", directory / "published-artifact.json"], log=log)
            command(["docker", "cp", f"{cell['project']}-updater:/data", directory / "parameter-update-data"], log=log)
            if cell["kind"] == "live":
                command(["docker", "cp", f"{cell['project']}-fuzzer:/workspace/dumps/privoke-fuzzer/curriculum.sqlite3", directory / "curriculum.sqlite3"], log=log)
            cell_state.update(status="complete", finished_at=now(), archive_sha256=archive_cell(directory))
        except BaseException as exc:
            cell_state.update(last_error=str(exc), interrupted_at=now())
            state["status"] = "interrupted"
            raise
        finally:
            continual.write_json(output / "supervisor.json", state)
            if owns_services:
                command(compose + ["stop", *SERVICES], env=env, log=log)
    state["status"] = "complete" if len(state["cells"]) == len(protocol["cells"]) and all(c["status"] == "complete" for c in state["cells"].values()) else "partial"
    continual.write_json(output / "supervisor.json", state)


def run_live(output, protocol, state, cell, cell_state, directory, env, client, op_path, log):
    model_id = f"privoke-{cell['profile']}"
    identity = artifact_identity(load_artifact(ROOT / "models" / f"{model_id}.json"))
    if cell_state["status"] == "baseline_verified":
        endpoints(client, protocol, cell, identity, directory, 0)
        verify_baseline_endpoints(output, cell["profile"], directory)
        cell_state["status"] = "training"
        continual.write_json(output / "supervisor.json", state)
    destination = directory / "controller"
    args = [sys.executable, ROOT / "evaluation/run-continual-fuzzer-study.py", "--model-id", model_id, "--cycles", "20", "--checkpoints", "0,20",
            "--no-mining", "--seed", "1337", "--curriculum-sampler-policy", cell["policy"], "--curriculum-sampler-seed", str(cell["sampler_seed"]),
            "--dataset-file", protocol["inputs"]["dataset"]["path"], "--curriculum-manifest", protocol["inputs"][cell["curriculum"]]["manifest"],
            "--output", destination, "--operational-manifest", op_path]
    manifest = destination / "run-manifest.json"
    if manifest.exists() and continual.read_json(manifest)["status"] != "complete":
        args += ["--resume"]
    if not manifest.exists() or continual.read_json(manifest)["status"] != "complete":
        command(args, env=env, log=log)
    verify_baseline_endpoints(output, cell["profile"], directory, destination / model_id)
    endpoints(client, protocol, cell, client.snapshot(model_id)["identity"], directory, 20, development=False)


def run_offline(output, protocol, state, cell, cell_state, directory, client, log):
    model_id = f"privoke-{cell['profile']}"
    baseline = artifact_identity(load_artifact(ROOT / "models" / f"{model_id}.json"))
    if cell_state["status"] == "baseline_verified":
        endpoints(client, protocol, cell, baseline, directory, 0)
        verify_baseline_endpoints(output, cell["profile"], directory)
        cell_state["status"] = "fitting"
        continual.write_json(output / "supervisor.json", state)
    fit = directory / "offline"
    if not (fit / "fit-receipt.json").exists():
        if fit.exists():
            raise ValueError("Interrupted offline fit retained; audit before starting a new fit attempt.")
        command(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
                 "--mount", f"type=bind,source={ROOT / 'evaluation/privoke_eval'},target=/workspace/evaluation/privoke_eval,readonly",
                 "--mount", f"type=bind,source={ROOT / 'evaluation/host_environment.py'},target=/workspace/evaluation/host_environment.py,readonly",
                 "--mount", f"type=bind,source={ROOT / 'evaluation/fit-contextual-representation-arm.py'},target=/workspace/evaluation/fit-contextual-representation-arm.py,readonly",
                 "--mount", f"type=bind,source={ROOT / 'shared/python'},target=/workspace/shared/python,readonly",
                 "--mount", f"type=bind,source={ROOT / 'extension/client-runtime/src'},target=/workspace/extension/client-runtime/src,readonly",
                 "--mount", f"type=bind,source={ROOT / 'models' / (model_id + '.json')},target=/baseline.json,readonly",
                 "--mount", f"type=bind,source={Path(protocol['inputs']['revised']['manifest']).parent / 'train.jsonl'},target=/input/train.jsonl,readonly",
                 "--mount", f"type=bind,source={directory},target=/output",
                 "-e", "PYTHONPATH=/workspace/evaluation:/workspace/shared/python:/workspace/extension/client-runtime",
                 protocol["images"]["offline-training"], "python", "-B", "/workspace/evaluation/fit-contextual-representation-arm.py",
                 "--baseline", "/baseline.json", "--train", "/input/train.jsonl",
                 "--output", "/output/offline", "--mode", cell["mode"], "--seed", str(cell["replicate_seed"])], log=log)
    receipt = continual.read_json(fit / "fit-receipt.json")
    candidate = load_artifact(fit / "artifact.json")
    expected = artifact_identity(candidate)
    if cell_state["status"] == "fitting":
        if client.snapshot(model_id)["identity"] != baseline:
            raise ValueError("Offline candidate install requires unchanged baseline.")
        # Record intended exact publication first; ambiguous copy is recoverable by identity.
        cell_state.update(status="installing", intended_identity=expected)
        continual.write_json(output / "supervisor.json", state)
    if cell_state["status"] == "installing":
        observed = client.snapshot(model_id)["identity"]
        if observed == baseline:
            staging = f"/models/.offline-{cell['id']}.json"
            command(["docker", "cp", fit / "artifact.json", f"{cell['project']}-updater:{staging}"], log=log)
            command(["docker", "exec", f"{cell['project']}-updater", "python", "-c", "import os,sys; os.replace(sys.argv[1],sys.argv[2])",
                     staging, f"/models/{model_id}.json"], log=log)
            time.sleep(2.1)
        elif observed != expected:
            raise ValueError("Offline publication outcome differs from baseline and intended candidate.")
        if client.snapshot(model_id)["identity"] != expected:
            raise ValueError("Offline artifact not served at the validated exact identity.")
        cell_state["status"] = "measuring"
        continual.write_json(output / "supervisor.json", state)
    if receipt["artifact_sha256"] != continual.sha(fit / "artifact.json"):
        raise ValueError("Offline exported artifact changed.")
    endpoints(client, protocol, cell, expected, directory, 20)


def verify_archive(directory, commitment):
    path = directory / "archive.json"
    if continual.sha(path) != commitment:
        raise ValueError("Archive inventory changed.")
    for relative, expected in continual.read_json(path).items():
        target = (directory / relative).resolve()
        target.relative_to(directory.resolve())
        if continual.sha(target) != expected:
            raise ValueError("Archived raw evidence changed.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "execute", "audit"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--study-id")
    parser.add_argument("--images", type=Path)
    parser.add_argument("--dataset", type=Path, default=ROOT / "evaluation/results/locked-public/development.jsonl")
    parser.add_argument("--fixture", type=Path, default=ROOT / "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl")
    parser.add_argument("--exclusion-index", type=Path, default=ROOT / "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json")
    parser.add_argument("--cell", help="Optional exact cell; first full arm benchmarks elapsed cost.")
    args = parser.parse_args(argv)
    if args.phase == "prepare":
        if not args.study_id or not args.images:
            parser.error("prepare requires --study-id and --images")
        prepare(args)
    elif args.phase == "execute":
        execute(args)
    else:
        from privoke_eval.curriculum_improvement_report import audit
        audit(continual.permitted_path(args.output))
    return 0
