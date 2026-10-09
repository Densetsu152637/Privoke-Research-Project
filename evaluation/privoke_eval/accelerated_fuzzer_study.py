"""Prospective normal-batch schedule; no historical imports or model promotion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from privoke_eval import continual_fuzzer_study as continual
from privoke_eval import curriculum_improvement_study as prior
from privoke_eval import synthetic_curriculum as synthetic
from privoke_model.artifact import load_artifact

ROOT = prior.ROOT
CHECKPOINTS = [0, 24, 72, 168]
BUDGET = {"attempts": 168, "prompt_count": 32, "new_rows": 24, "replay_rows": 8,
          "heldout_rows": 16, "trainer_seed": 1337, "checkpoints": CHECKPOINTS,
          "learning_rate": .003, "gradient_clamp": .05, "replay_weight": .35,
          "replay_fraction": .25, "transforms": 0, "mining": False}
DECISION = {"decision_checkpoint": 168, "descriptive_checkpoints": [24, 72],
    "per_seed": "context joint strictly exceeds own baseline and shared control final; annotation recall and disclosure joint/sensitivity/visibility/category/action accuracy do not decline against either reference; no new/worsened fixture restriction or incorrect action against either reference",
    "profile": "at least two of three revised realizations pass, and no revised realization adds fixture harm against its baseline",
    "qualification": "separate recall>=0.90, strict specificity gain, no contextual joint decline, no fixture harm against own baseline",
    "interpretation": "engineering iteration criterion; exploratory descriptive comparisons; no significance or promotion claim"}


def matrix(study_id):
    cells = []
    for profile in prior.PROFILES:
        for seed in (None, 42, 43, 44):
            key = f"{profile}-control" if seed is None else f"{profile}-revised-{seed}"
            cells.append({"id": key, "kind": "live", "profile": profile,
                          "curriculum": "current" if seed is None else "revised",
                          "policy": "deterministic_v1" if seed is None else "seeded_family_v1",
                          "sampler_seed": seed or 0, "replay_weight": .35,
                          "project": f"{study_id}-{key}", "shared_control": seed is None})
    return cells


def source_inventory():
    result = prior.source_inventory()
    for name in ("evaluation/run-accelerated-fuzzer-study.py",):
        result[name] = continual.sha(ROOT / name)
    return dict(sorted(result.items()))


def prepare(args):
    output = continual.permitted_path(args.output)
    if not re.fullmatch(r"privoke-accelerated-[a-z0-9-]+", args.study_id or ""):
        raise ValueError("Unique lowercase privoke-accelerated- study ID required.")
    inventory = source_inventory()
    revision = prior.require_committed_sources(inventory)
    for name, commitment in prior.RESOURCES.values():
        if continual.sha(ROOT / "evaluation/datasets" / name) != commitment:
            raise ValueError("Reviewed resource bytes changed.")
    images = continual.read_json(args.images)
    if set(images) != set(prior.SERVICES) or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in images.values()):
        raise ValueError("Pin exactly five serving services to full immutable image IDs.")
    for image in images.values():
        if json.loads(prior.command(["docker", "image", "inspect", image]))[0]["Id"] != image:
            raise ValueError("Image identity differs.")
    attestation = prior.attest_image_sources(images, inventory)
    inputs = {}
    for key in ("current", "revised"):
        path = continual.permitted_path(getattr(args, key))
        _, _, commitment = continual.load_inputs(args.dataset, continual.DEVELOPMENT_SHA, path)
        manifest = continual.read_json(path)
        files = {entry["path"]: entry["sha256"] for entry in manifest["splits"].values()}
        assessment = manifest.get("assessment")
        if assessment:
            files[assessment["path"]] = assessment["sha256"]
        inputs[key] = {"manifest": str(path), "manifest_sha256": continual.sha(path), "files": files}
        if [commitment["splits"][role]["rows"] for role in ("train", "heldout", "replay")] != [672, 16, 64]:
            raise ValueError("Expected 672 TRAIN, 16 guard and 64 replay rows.")
    for key, path, expected in (("dataset", args.dataset, continual.DEVELOPMENT_SHA),
                                ("fixture", args.fixture, prior.FIXTURE_SHA),
                                ("exclusion_index", args.exclusion_index, None)):
        path = continual.permitted_path(path)
        if expected and continual.sha(path) != expected:
            raise ValueError(f"Pinned {key} bytes differ.")
        inputs[key] = {"path": str(path), "sha256": continual.sha(path)}
    # Rebuild expected pools in memory and compare rows, without changing static inputs.
    pools = [synthetic.build_curriculum(continual.read_json(ROOT / "evaluation/datasets" / prior.RESOURCES[k][0])) for k in ("current", "revised")]
    assessment_rows = synthetic.build_assessment(continual.read_json(ROOT / "evaluation/datasets" / prior.RESOURCES["assessment"][0]), pools)
    development = prior.pinned_jsonl(args.dataset, continual.DEVELOPMENT_SHA)
    if len(development) != 502:
        raise ValueError("Expected 502 development rows.")
    fixture = prior.pinned_jsonl(args.fixture, prior.FIXTURE_SHA)
    if len(fixture) != 48 or sum(row["ambiguous"] for row in fixture) != 7:
        raise ValueError("Expected 48 fixtures including seven ambiguous.")
    for pool in pools:
        synthetic.verify_exclusions(pool, continual.read_json(args.exclusion_index), development)
    synthetic.verify_exclusions({"assessment": assessment_rows}, continual.read_json(args.exclusion_index), development)
    for pool_index, key in enumerate(("current", "revised")):
        parent = Path(inputs[key]["manifest"]).parent
        for name, commitment in inputs[key]["files"].items():
            if continual.sha(continual.permitted_path(parent / name)) != commitment:
                raise ValueError("Prepared pool file changed.")
        if continual.jsonl(parent / "assessment.jsonl") != assessment_rows:
            raise ValueError("Prepared assessment differs from validated shared assessment.")
        for split, expected_rows in pools[pool_index].items():
            if continual.jsonl(parent / (split + ".jsonl")) != expected_rows:
                raise ValueError("Prepared curriculum differs from reviewed resource rendering.")
    if any(inputs["current"]["files"][name] != inputs["revised"]["files"][name] for name in ("heldout.jsonl", "replay.jsonl", "assessment.jsonl")):
        raise ValueError("Both arms require identical guard/replay/assessment bytes.")
    protocol = {"schema_version": "accelerated-semantic-v1", "evaluation_layers": ["semantic"],
        "research_id": "AS-20261010", "original_user_message_at": None,
        "user_objective": "Can you now simulate an accelerated Fuzzer training period so that we can see whether the changes we made had measurable impacts on the LLM layer? This will inform whether we do more iteration on improvement or we can move to discussion and wrap up the paper.",
        "study_id": args.study_id, "created_at": prior.now(), "source_revision": revision,
        "source_files": inventory, "images": images, "image_source_attestation": attestation,
        "inputs": inputs, "cells": matrix(args.study_id), "live": BUDGET, "decision": DECISION,
        "analysis": {"bootstrap_iterations": 2000, "bootstrap_seed": 10102026,
                     "seed_spread": "three revised realizations conditional on one shared deterministic control per profile",
                     "intervals": "paired source-group/family bootstrap describes scenario sampling, not independent training-seed uncertainty"},
        "limitations": ["Normal-size requests with hourly waits compressed; no wall-clock aging or evolving production corpus.",
                        "5376 presentations per trajectory, only 5% above historical 5120; cycle/batch schedule is the principal change.",
                        "Curriculum package changes wording, category and visibility exposure plus allocation; effects are not separately attributed.",
                        "Assistant-provisional contextual targets and overlapping archetypes; annotation presence is a separate task.",
                        "No prompt-backend attribution, final input access, automatic promotion, or result-dependent stopping."]}
    output.mkdir(parents=True, exist_ok=False)
    continual.write_json(output / "protocol.json", protocol)
    continual.write_json(output / "supervisor.json", {"status": "prepared", "protocol_sha256": continual.sha(output / "protocol.json"), "cells": {}})
    return protocol


def verify_freeze(output):
    protocol, state = (continual.read_json(output / name) for name in ("protocol.json", "supervisor.json"))
    if protocol.get("schema_version") != "accelerated-semantic-v1" or protocol.get("evaluation_layers") != ["semantic"]:
        raise ValueError("Only the distinct accelerated semantic protocol is executable.")
    if protocol["live"] != BUDGET or protocol["decision"] != DECISION or protocol["cells"] != matrix(protocol["study_id"]):
        raise ValueError("Frozen budget, matrix or decision rules differ.")
    if state["protocol_sha256"] != continual.sha(output / "protocol.json") or protocol["source_files"] != source_inventory():
        raise ValueError("Frozen protocol or computation source changed.")
    if prior.require_committed_sources(protocol["source_files"]) != protocol["source_revision"]:
        raise ValueError("Execution revision changed after freeze.")
    for key, item in protocol["inputs"].items():
        if key in ("current", "revised"):
            path = continual.permitted_path(item["manifest"])
            if continual.sha(path) != item["manifest_sha256"] or any(continual.sha(continual.permitted_path(path.parent / name)) != value for name, value in item["files"].items()):
                raise ValueError("Frozen curriculum changed.")
        elif continual.sha(continual.permitted_path(item["path"])) != item["sha256"]:
            raise ValueError("Frozen endpoint/exclusion input changed.")
    return protocol, state


def checkpoint_callback(protocol, cell, directory):
    def collect(client, model_id, snapshot, cycle):
        if cycle not in CHECKPOINTS:
            raise ValueError("Unexpected checkpoint.")
        prior.endpoints(client, protocol, cell, snapshot["identity"], directory, cycle, development=False)
    return collect


def controller_args(protocol, cell, directory):
    values = ["--model-id", "privoke-" + cell["profile"], "--cycles", "168", "--prompt-count", "32",
              "--checkpoints", "0,24,72,168", "--no-mining", "--gate-diagnostics", "--seed", "1337",
              "--curriculum-sampler-policy", cell["policy"], "--curriculum-sampler-seed", str(cell["sampler_seed"]),
              "--dataset-file", protocol["inputs"]["dataset"]["path"], "--curriculum-manifest", protocol["inputs"][cell["curriculum"]]["manifest"],
              "--output", str(directory / "controller"), "--operational-manifest", str(directory / "operations.json")]
    if (directory / "controller/run-manifest.json").exists():
        values.append("--resume")
    return continual.parser().parse_args(values)


def execute(args):
    output = continual.permitted_path(args.output)
    protocol, state = verify_freeze(output)
    cells = [c for c in protocol["cells"] if not args.cell or c["id"] == args.cell]
    if not cells:
        raise ValueError("Unknown trajectory.")
    for cell in cells:
        verify_freeze(output)
        saved = state["cells"].get(cell["id"])
        directory, compose, env = prior.compose_configuration(output, protocol, cell)
        log = directory / "execution.log"
        if saved and saved["status"] == "complete":
            prior.verify_archive(directory, saved["archive_sha256"])
            continue
        if saved and saved.get("blocked_collision"):
            raise ValueError("Resource collision requires ownership repair.")
        record = saved or {"status": "reserved", "project": cell["project"], "started_at": prior.now()}
        state["cells"][cell["id"]] = record
        state.update(status="running", current_cell=cell["id"])
        continual.write_json(output / "supervisor.json", state)
        owns = bool(saved)
        try:
            if not saved:
                occupied = prior.command(["docker", "ps", "-a", "--format", "{{.Names}}"] ).splitlines()
                volumes = prior.command(["docker", "volume", "ls", "--format", "{{.Name}}"] ).splitlines()
                networks = prior.command(["docker", "network", "ls", "--format", "{{.Name}}"] ).splitlines()
                if any(name.startswith(cell["project"] + "-") for name in occupied + volumes) or cell["project"] + "_default" in networks:
                    record["blocked_collision"] = True
                    raise ValueError("Fresh trajectory resources already exist.")
            owns = True
            prior.command(compose + ["config", "--services"], env=env, log=log)
            prior.command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", *prior.SERVICES], env=env, log=log)
            operations = prior.operations(cell["project"])
            prior.validate_operations(operations, cell, protocol)
            path = directory / "operations.json"
            if path.exists() and continual.read_json(path) != operations:
                raise ValueError("Operational commitment changed on resume.")
            continual.write_json(path, operations)
            with_client = continual.RpcClient("127.0.0.1:50053", "127.0.0.1:50054", "127.0.0.1:50051")
            try:
                model_id = "privoke-" + cell["profile"]
                if record["status"] == "reserved":
                    prior.assert_baseline(with_client.snapshot(model_id), load_artifact(ROOT / "models" / f"{model_id}.json"))
                    prior.command(["docker", "cp", f"{cell['project']}-updater:/models/{model_id}.json", directory / "initial-artifact.json"], log=log)
                    if continual.sha(directory / "initial-artifact.json") != continual.sha(ROOT / "models" / f"{model_id}.json"):
                        raise ValueError("Fresh baseline artifact bytes differ.")
                    record["status"] = "training"
                    continual.write_json(output / "supervisor.json", state)
                manifest = directory / "controller/run-manifest.json"
                if not manifest.exists() or continual.read_json(manifest)["status"] != "complete":
                    continual.run(controller_args(protocol, cell, directory), client=with_client,
                                  checkpoint_callback=checkpoint_callback(protocol, cell, directory))
                prior.verify_baseline_endpoints(output, cell["profile"], directory, directory / "controller" / model_id)
            finally:
                with_client.close()
            for source, destination in ((f"updater:/models/{model_id}.json", "published-artifact.json"),
                    ("updater:/data", "parameter-update-data"),
                    ("fuzzer:/workspace/dumps/privoke-fuzzer/curriculum.sqlite3", "curriculum.sqlite3"),
                    ("fuzzer:/workspace/dumps/privoke-fuzzer/gate-diagnostics", "gate-diagnostics")):
                prior.command(["docker", "cp", f"{cell['project']}-{source}", directory / destination], log=log)
            record.update(status="complete", finished_at=prior.now(), archive_sha256=prior.archive_cell(directory))
        except BaseException as exc:
            record.update(last_error=str(exc), interrupted_at=prior.now())
            state["status"] = "interrupted"
            raise
        finally:
            continual.write_json(output / "supervisor.json", state)
            if owns:
                prior.command(compose + ["stop", *prior.SERVICES], env=env, log=log)
    state["status"] = "complete" if len(state["cells"]) == 12 and all(c["status"] == "complete" for c in state["cells"].values()) else "partial"
    continual.write_json(output / "supervisor.json", state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "execute", "audit"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--study-id")
    parser.add_argument("--images", type=Path)
    parser.add_argument("--cell")
    parser.add_argument("--current", type=Path)
    parser.add_argument("--revised", type=Path)
    parser.add_argument("--dataset", type=Path, default=ROOT / "evaluation/results/locked-public/development.jsonl")
    parser.add_argument("--fixture", type=Path, default=ROOT / "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl")
    parser.add_argument("--exclusion-index", type=Path, default=ROOT / "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json")
    args = parser.parse_args(argv)
    if args.phase == "prepare":
        if not all((args.study_id, args.images, args.current, args.revised)):
            parser.error("prepare requires --study-id, --images, --current, --revised")
        prepare(args)
    elif args.phase == "execute":
        execute(args)
    else:
        from privoke_eval.accelerated_fuzzer_report import audit
        audit(continual.permitted_path(args.output))
    return 0
