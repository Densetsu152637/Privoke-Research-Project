"""TW01: frozen semantic-only architecture/window package comparison.

Host Python drives dataset and RPC work; Docker runs server services only.
Numerical operations require an explicit root release
bound to exact protocol and source bytes. Existing production training implements
both loops; this module never implements an optimizer or chooses a checkpoint.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
STUDY_ID = "privoke-tw01-20261012"
WEIGHTS_ROOT = ROOT / "models/experiments/task_query_window_20261012"
SOURCE_MODEL = "models/privoke-balanced.json"
SOURCE_MODEL_SHA = "dcacb490bf19cf771fe4084e7f3484d83daee040609c496c1aef04f0da779b51"
INITIAL_V2_SHA = "1fca4eff13ac6892395c07b13158761612e7a95cfa6659ba712fcf6e70392ffc"
INITIAL_V2_SOURCE_REVISION = "250780ae13fd2687c7deae1b99a4c065d6d6ae64"
OBJECTIVE = "class_balanced_contextual_sum_category_decision_margin_v1"
LEGACY = "full_projected_adam64_v1"
WINDOW = "full_projected_adam64_window_checkpoint_v1"
SEEDS = (42, 43, 44)
SOURCE_ROOTS = ("shared/python", "shared/proto", "extension/client-runtime/src",
                "services/privoke-fuzzer/src", "services/param-update-service/app",
                "services/model-streaming-service", "evaluation/privoke_eval")
SOURCE_FILES = (SOURCE_MODEL, "models/generate_baseline.py",
                "extension/client-runtime/Dockerfile", "services/privoke-fuzzer/Dockerfile",
                "services/param-update-service/Dockerfile", "services/model-streaming-service/Dockerfile",
                "evaluation/Dockerfile.task-query-window-study", "evaluation/run-task-query-window-study.py",
                "evaluation/prepare-component-retention.py", "evaluation/tests/test_task_query_window_study.py", ".dockerignore")


def loopback_target(target):
    host, separator, port = target.rpartition(":")
    require(separator and host == "127.0.0.1" and port.isdecimal() and 0 < int(port) <= 65535,
            "Study clients require an explicit IPv4 loopback target")
    return target


def available_ports():
    """Reserve distinct loopback ports during allocation; recheck before startup."""
    sockets = []
    try:
        for _ in range(3):
            handle = socket.socket()
            handle.bind(("127.0.0.1", 0))
            sockets.append(handle)
        return dict(zip(("model", "runtime", "fuzzer"), (s.getsockname()[1] for s in sockets)))
    finally:
        for handle in sockets:
            handle.close()


def frozen_path_resolver(fuzzer_directory, release_directory):
    """Resolve recorded Linux filenames without changing retained evidence bytes."""
    roots = {}
    for prefix, supplied in (("/data", fuzzer_directory), ("/training-window", release_directory)):
        path = Path(supplied).absolute()
        require(path.is_dir(), "Retained root must exist")
        require(not any(parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction())
                        for parent in (path, *path.parents)), "Symlinked retained root refused")
        roots[prefix] = path.resolve()
    def resolve(raw):
        require(isinstance(raw, str) and "\\" not in raw and "\x00" not in raw, "Invalid retained filename")
        value = PurePosixPath(raw)
        require(value.is_absolute() and ".." not in value.parts, "Retained path traversal refused")
        for prefix, root in roots.items():
            base = PurePosixPath(prefix)
            if value.is_relative_to(base):
                candidate = root.joinpath(*value.relative_to(base).parts)
                current = root
                require(not current.is_symlink(), "Symlinked retained root refused")
                for part in value.relative_to(base).parts:
                    current = current / part
                    require(not current.is_symlink() and not (hasattr(current, "is_junction") and current.is_junction()),
                            "Symlinked retained path refused")
                require(candidate.resolve().is_relative_to(root), "Retained path escaped frozen root")
                return candidate
        raise ValueError("Retained path prefix is not allowlisted")
    return resolve


def retained_catalog(cell_id):
    require(cell_id in {cell["id"] for cell in matrix()} | {"initial-v1", "initial-v2"}, "Unknown retained model identity")
    return WEIGHTS_ROOT / "cells" / cell_id


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_bytes())


def exclusive(path, value):
    """Durably create immutable evidence, refusing replacement even if equal."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())


def permitted_input(path):
    """Allow only explicit repository inputs; reject protected final paths."""
    resolved = Path(path).resolve()
    require(resolved.is_relative_to(ROOT.resolve()), "Input is outside the assigned repository")
    parts = resolved.relative_to(ROOT.resolve()).parts
    require(not any("final" in p.casefold() for p in parts), "Protected final inputs are excluded")
    require(resolved.is_file() and not Path(path).is_symlink(), "Input must be an existing regular file")
    return resolved


def verify_inputs(inputs):
    required = {"taxonomy", "benign_pool", "benign_manifest", "benign_proof", "bank",
                "context64", "context320", "binary502", "hazard48"}
    require(set(inputs) == required, "Explicit complete frozen input map required")
    for name, item in inputs.items():
        require(set(item) >= {"path", "sha256"}, "Input path and accepted SHA required: " + name)
        require(sha(permitted_input(ROOT / item["path"])) == item["sha256"], "Input hash differs: " + name)


def matrix():
    """Paired fixed seeds; first planned fit is also the timing canary."""
    return [{"id": f"{architecture}-{loop}-{seed}", "architecture": architecture,
             "loop": loop, "seed": seed, "policy": LEGACY if loop == "legacy" else WINDOW,
             "project": f"{STUDY_ID}-{architecture}-{loop}-{seed}",
             "request_id": f"tw01-{architecture}-{loop}-{seed}-full"}
            for seed in SEEDS for architecture in ("v1", "v2") for loop in ("legacy", "window")]


def source_inventory():
    paths = set()
    for prefix in SOURCE_ROOTS:
        for path in (ROOT / prefix).rglob("*"):
            if path.is_file() and path.suffix in {".py", ".go", ".proto", ".mod", ".sum"}:
                if "__pycache__" not in path.parts and "gen" not in path.relative_to(ROOT / prefix).parts:
                    paths.add(path)
    paths.update(ROOT / name for name in SOURCE_FILES if (ROOT / name).exists())
    for prefix in ("extension/client-runtime", "services/privoke-fuzzer", "services/param-update-service"):
        paths.update((ROOT / prefix).glob("requirements*.txt"))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def git_read(*arguments):
    result = subprocess.run(["git", "-C", str(ROOT), *arguments], check=True, capture_output=True)
    return result.stdout.decode("utf-8")


def draft(output, inputs):
    """No dependency imports, model construction, services or numerical work."""
    verify_inputs(inputs)
    require(sha(ROOT / SOURCE_MODEL) == SOURCE_MODEL_SHA, "Source-current baseline changed")
    model = read(ROOT / SOURCE_MODEL)
    require(model["config"]["max_tokens"] == 96, "Balanced context must remain96")
    initials = prepare_initials(output)
    inventory = source_inventory()
    exclusive(output / "source-attestation.draft.json", {
        "head": git_read("rev-parse", "HEAD").strip(), "branch": git_read("branch", "--show-current").strip(),
        "status": git_read("status", "--short"), "files": inventory,
        "inventory_sha256": digest(inventory), "dirty_source_is_explicit": True})
    diff = git_read("diff", "--", *SOURCE_ROOTS, *SOURCE_FILES)
    with (output / "pre-study-source.diff").open("xb") as stream:
        stream.write(diff.encode("utf-8"))
    protocol = {"schema": 1, "id": "TW01", "status": "draft_not_released",
        "authorization": "Prior resumed goal authorizes this controlled semantic-only genuine study; synthetic reply only overrode the earlier implementation test restriction and is not study authorization",
        "source_model": {"path": SOURCE_MODEL, "sha256": SOURCE_MODEL_SHA},
        "source_inventory_sha256": digest(inventory), "inputs": inputs, "cells": matrix(),
        "model_id": "privoke-balanced", "context": 96, "seeds": list(SEEDS),
        "objective": OBJECTIVE, "scope": "full_encoder", "layers": [4],
        "learning_rate": .003, "radius": .05, "cpu_threads": 1, "main_directions": 64,
        "main_presentations": 4096, "minimum_train_packed_exact_floor": 0.0,
        "floor_comparison": "strict_greater", "floor_authority": "services/privoke-fuzzer/src/config.py:84-88",
        "teachers": "two independently pinned current96 v1/v2 ORIGINALs; no historical refs", "initial_teachers": initials,
        "contrast": "architecture plus native sampling/auxiliary/checkpoint package; not pure optimizer",
        "window_selection": "TRAIN+ORIGINAL TRAIN only; BASE+steps8,16,24,32,40,48,56,64",
        "endpoint_access": "fit workers have no endpoint mounts; score only after all candidate identities frozen",
        "unknown_outcome": "halt without another physical fit; receipt lookup only",
        "improvement": {"primary": "sensitive action-inclusive joint", "paired_seed_count": 3,
            "v2window_vs_v1legacy": "positive mean, no seed lower, at least one strict gain",
            "also_vs_unchanged_v1": "same nonregression and at least one strict sensitive joint gain",
            "per_seed_nonregression": ["all_joint", "sensitive_recall", "clean_specificity", "severity",
                                         "category", "visibility", "action"],
            "casewise_harm": "no worsened assessment/fixture action harm"},
        "uncertainty": "report all paired seed counts and denominators; no independent row pooling",
        "native_binary_overlength": {"rows": 11, "positive": 9, "negative": 2, "maximum_tokens": 295,
            "policy": "evaluate all502, preserve native errors, total and successful subset denominators; any error prevents qualification"},
        "context320_truth": "asserted_personal_disclosure_v1; assistant provisional; not human adjudicated or independent untouched confirmation",
        "expected_window_sha256": {"42": "2f0d61ffa5996a1bb1a922f311027ea3ceb52ab8beced0e07428cac2400b9a70",
            "43": "48abe5854f868bdfe10a10034c6dd142aab6f9f100f459aaa6bf808ba7f7f936",
            "44": "e7034e993c5a0be3e97633cd157611d45bd4e3aabdecdb1a72f40cb90f5a8c74"},
        "no_final": True, "promotion": False, "fit_release": False}
    exclusive(output / "protocol.draft.json", protocol)
    return protocol


def prepare_initials(output):
    """Pure contract migration; no Tiny/model/encoder construction."""
    sys.path.insert(0, str(ROOT / "shared/python"))
    from privoke_model.contextual_training import prepare_task_query_artifact, FULL_ENCODER_STRATEGY
    source = read(ROOT / SOURCE_MODEL)
    v2 = prepare_task_query_artifact(source, version="tw01-v2-initial", generated_at_unix=1791763200,
        source_revision=INITIAL_V2_SOURCE_REVISION, strategy=FULL_ENCODER_STRATEGY)
    require(digest(v2) == INITIAL_V2_SHA, "Current migration does not reproduce pinned v2 ORIGINAL")
    result = {}
    for name, artifact in (("v1", source), ("v2", v2)):
        path = WEIGHTS_ROOT / "initials" / name / "original.json"
        if name == "v1":
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                with path.open("xb") as stream:
                    stream.write((ROOT / SOURCE_MODEL).read_bytes())
            require(sha(path) == SOURCE_MODEL_SHA, "Retained v1 ORIGINAL differs")
        else:
            if not path.exists():
                exclusive(path, artifact)
            require(sha(path) == INITIAL_V2_SHA and read(path) == artifact
                    and artifact["metadata"]["preparation_source_revision"] == INITIAL_V2_SOURCE_REVISION,
                    "Retained v2 ORIGINAL differs from independently pinned migration")
        result[name] = {"path": str(path.resolve()), "sha256": sha(path),
                        "config": artifact["config"], "version": artifact["version"], "checksum": artifact["checksum"]}
    require(all(v == v2["parameters"][n] or (v["shape"] == v2["parameters"][n]["shape"] and
            v["values"] == v2["parameters"][n]["values"]) for n, v in source["parameters"].items()),
            "Task-query preparation changed common backbone/head coordinates")
    return result


def validate_release(output, path, phase):
    release = read(path)
    require(set(release) >= {"phase", "protocol_sha256", "source_inventory_sha256", "accepted"}, "Incomplete root release")
    require(release["accepted"] is True and release["phase"] == phase, "Wrong/unaccepted root release")
    protocol_path = output / release.get("protocol_file", "protocol.draft.json" if phase == "teachers" else "protocol.json")
    require(protocol_path.resolve().parent == output.resolve(), "Release protocol must be a local immutable study record")
    require(release["protocol_sha256"] == sha(protocol_path), "Root release protocol differs")
    attestation_path = output / release.get("source_attestation_file", "source-attestation.draft.json")
    require(attestation_path.resolve().parent == output.resolve(), "Release attestation must be a local immutable study record")
    attestation = read(attestation_path)
    require(release["source_inventory_sha256"] == digest(attestation["files"]), "Root release source differs")
    for name, expected in attestation["files"].items():
        require(sha(ROOT / name) == expected, "Attested source changed: " + name)
    return read(protocol_path)


def images_for_release(output, release_path):
    """Use a release-bound local image map, retaining the historical default."""
    release = read(release_path)
    filename = release.get("images_file")
    expected = release.get("images_sha256")
    require((filename is None) == (expected is None), "Image map filename and SHA must be bound together")
    if filename is None:
        return read(output / "images.json")
    require(isinstance(filename, str) and filename and Path(filename).name == filename
            and "/" not in filename and "\\" not in filename, "Image map must be a local filename")
    path = output / filename
    require(path.resolve().parent == output.resolve(), "Image map escaped local study output")
    require(isinstance(expected, str) and len(expected) == 64 and sha(path) == expected,
            "Release image map SHA differs")
    return read(path)


def install_host_imports():
    for path in (ROOT / "shared/python", ROOT / "extension/client-runtime",
                 ROOT / "extension/client-runtime/generated", ROOT / "services/privoke-fuzzer/src",
                 ROOT / "services/privoke-fuzzer/generated", ROOT / "services/param-update-service/app"):
        sys.path.insert(0, str(path))


def assert_semantic(response, identity):
    require(not response.error and len(response.layers) == 1 and response.layers[0].layer == 4
            and response.layers[0].status == "ok" and not response.layers[0].error,
            "Actual sole successful semantic execution required")
    for field, suffix in (("model_id", "model_id"), ("version", "model_version"),
            ("checksum", "artifact_checksum"), ("parameter_fingerprint", "parameter_fingerprint")):
        require(response.metadata.get("privoke.semantic." + suffix) == identity[field], "Semantic identity differs: " + suffix)


def collect_teacher(target, bank_path, teacher_path, teacher_sha256, capture_directory, output):
    """Host network requests; same-prediction logits are captured by the server."""
    install_host_imports()
    import grpc
    from privoke_model import window_training as contract, sensitive_retention as legacy
    from privoke.v1 import runtime_pb2 as rp, runtime_pb2_grpc as rg
    loopback_target(target)
    bank = legacy.validate_bank(Path(bank_path).read_bytes())
    teacher = contract.teacher_identity(teacher_path, "balanced", teacher_sha256)
    rows = []
    with grpc.insecure_channel(target) as channel:
        stub = rg.PrivokeRuntimeServiceStub(channel)
        for source in bank:
            row_directory = output / "rows" / source["id"]
            request = rp.AnalyzePromptRequest(request_id="tw01-teacher-" + teacher_sha256[:12] + "-" + source["id"],
                text=source["text"], semantic_model_id=teacher["model_id"], layers=[4])
            raw_request = request.SerializeToString(deterministic=True)
            exclusive(row_directory / "attempted.json", {"dispatch": "host_network_AnalyzePrompt", "layers": [4],
                "teacher": teacher, "request_base64": base64.b64encode(raw_request).decode()})
            try:
                response = stub.AnalyzePrompt(request, timeout=60)
            except grpc.RpcError as exc:
                exclusive(row_directory / "transport-error.json", {"code": exc.code().name, "details": exc.details()})
                raise ValueError("Teacher network outcome unknown; no hidden retry") from exc
            raw_response = response.SerializeToString(deterministic=True)
            exclusive(row_directory / "response.json", {"response_base64": base64.b64encode(raw_response).decode()})
            assert_semantic(response, teacher)
            observed = read(capture_directory / hashlib.sha256(request.request_id.encode()).hexdigest() / "observed.json")
            require(observed["teacher"] == teacher and observed["request_id"] == request.request_id
                    and observed["request_sha256"] == hashlib.sha256(raw_request).hexdigest()
                    and observed["response_sha256"] == hashlib.sha256(raw_response).hexdigest()
                    and len(observed["predictions"]) == 1, "Server observer differs from actual same-prediction RPC")
            row = {"id": source["id"], "gold": source["packed_classification"], **observed["predictions"][0]}
            exclusive(row_directory / "completed.json", row)
            rows.append(row)
    result = {"schema": 2, "teacher": teacher, "bank_sha256": legacy.BANK_SHA256, "rows": rows}
    exclusive(output / "task-logits.json", result)
    exclusive(output / "collection.json", {"attempted": len(bank), "completed": len(rows),
        "dispatch": "host_network_AnalyzePrompt", "request_layers": [4], "teacher": teacher,
        "task_logits_sha256": sha(output / "task-logits.json")})
    return result


def training_inputs(input_map, output):
    """Prepare actual native samplers and prove paired guards before fitting."""
    install_host_imports()
    from prompt_generation.taxonomy_coverage import load_dataset
    from prompt_generation import benign_coverage as benign, train_window
    from training.types import BatchTrainingConfig
    from training.trainer import iter_training_examples
    from privoke_model import window_training as contract
    dataset = load_dataset(input_map["taxonomy"]["path"])
    release = benign.load_release(*(input_map[n]["path"] for n in ("benign_pool", "benign_manifest", "benign_proof")), dataset)
    result = {}
    for seed in SEEDS:
        window = train_window.prepare_window(dataset, release, seed)
        originals, guard = benign.generate_partition(dataset, release, seed)
        config = BatchTrainingConfig(learning_rate=.003, max_gradient=.05, transformations_per_example=1, seed=seed)
        expanded = list(iter_training_examples(originals, (), config))
        audit = benign.audit_expanded(dataset, release, originals, expanded, guard, config)
        require(contract.row_wire(window["guard"]) == [{"text": r.text, "packed": r.expected_packed_classification,
                    "weight": float(r.weight)} for r in guard], "Paired native guards differ")
        exclusive(output / str(seed) / "window.json", window)
        wire = lambda rows: [base64.b64encode(r.SerializeToString(deterministic=True)).decode() for r in rows]
        exclusive(output / str(seed) / "legacy.json", {"main_protobuf_base64": wire(benign.training_wire_rows(expanded)),
                  "guard_protobuf_base64": wire(benign.guard_wire_rows(guard)), "audit": audit})
        result[str(seed)] = {"window_sha256": sha(output / str(seed) / "window.json"),
            "legacy_sha256": sha(output / str(seed) / "legacy.json"), "guard_sha256": audit["sampling_guard_wire_sha256"],
            "window_provenance": window["provenance"]}
    exclusive(output / "manifest.json", result)
    return result


def bind(source, target, writable=False):
    return {"type": "bind", "source": str(Path(source).resolve()), "target": target,
            "read_only": not writable, "bind": {"create_host_path": False}}


def compose_cell(cell, directory, images, releases, input_map):
    """Standalone private servers with loopback RPC ports and no shared catalogs."""
    require(set(images) == {"model", "runtime", "updater", "fuzzer"}, "Four explicit immutable image IDs required")
    require(all(v.startswith("sha256:") and len(v) == 71 for v in images.values()), "Images must be immutable SHA IDs")
    prefix = cell["id"]
    names = {role: prefix + "-" + role for role in images}
    security = {"init": True, "restart": "no", "read_only": True, "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"], "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=128m"],
                "cpus": 1.0, "mem_limit": "4g", "pids_limit": 128}
    def service(role):
        return {**security, "image": images[role], "pull_policy": "never",
                "container_name": cell["project"] + "-" + role}
    model = service("model")
    model.update(environment={"MODEL_STREAMING_PORT": "50051", "MODEL_LATEST_ID": "privoke-balanced",
                              "MODEL_ARTIFACT_DIR": "/models"},
                 volumes=[bind(retained_catalog(cell["id"]) / "models", "/models")],
                 ports=[f"127.0.0.1:{cell['ports']['model']}:50051"],
                 healthcheck={"test": ["CMD", "/model-streaming-service", "healthcheck"], "interval": "2s", "timeout": "2s", "retries": 30})
    updater = service("updater")
    updater["tmpfs"] = [*security["tmpfs"], "/var/lib/privoke:rw,noexec,nosuid,nodev,size=16m"]
    updater.update(working_dir="/workspace/services/param-update-service", entrypoint=["python", "app/server.py"],
        environment={"FUZZER_PROMPT_COUNT": "0", "MODEL_ID": "privoke-balanced", "MODEL_ARTIFACT_PATH": "/models/privoke-balanced.json",
                     "PARAM_UPDATE_STORAGE_PATH": "/data/updates.jsonl", "PARAM_UPDATE_PORT": "50052"},
        volumes=[bind(retained_catalog(cell["id"]) / "models", "/models", True), bind(directory / "updater", "/data", True)])
    runtime = service("runtime")
    # Mask the parent image VOLUME explicitly: no anonymous volume is allocated.
    runtime["tmpfs"] = [*runtime["tmpfs"], "/var/lib/privoke:rw,noexec,nosuid,nodev,size=16m"]
    runtime.update(working_dir="/workspace/extension/client-runtime",
        entrypoint=["python", "-B", "/workspace/evaluation/privoke_eval/task_query_window_server.py"],
        environment={"MODEL_ID": "privoke-balanced", "MODEL_STREAMING_TARGET": names["model"] + ":50051",
            "MODEL_STREAMING_CACHE_TTL_SECONDS": "1", "PRIVOKE_MODEL_DEVICE": "cpu", "PRIVOKE_LLM_CHOICE": "streamed",
            "PRIVOKE_STACK_MODE": "internal", "PRIVOKE_ENV_FILE": "/dev/null", "PRIVOKE_GRPC_HOST": "0.0.0.0",
            "PRIVOKE_GRPC_PORT": "50054", "PRIVOKE_REQUIRE_TRAINING_CPU": "true", "TELEMETRY_ENABLED": "false",
            "OMP_NUM_THREADS": "1", "MKL_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1"},
        ports=[f"127.0.0.1:{cell['ports']['runtime']}:50054"], volumes=[])
    fuzzer = service("fuzzer")
    fuzzer.update(working_dir="/workspace/services/privoke-fuzzer", entrypoint=["python", "src/main.py"],
        environment={"MODEL_ID": "privoke-balanced", "PRIVOKE_RUNTIME_TARGET": names["runtime"] + ":50054",
            "PARAM_UPDATE_TARGET": names["updater"] + ":50052", "FUZZER_PORT": "50053", "FUZZ_TIMEOUT_SECONDS": "780",
            "FUZZER_ID": cell["project"] + "-fuzzer",
            "PRIVOKE_FUZZER_DUMP_DIR": "/data", "FUZZ_CURRICULUM_STATE_PATH": "/data/curriculum.sqlite3",
            "FUZZ_MIN_EXACT_MATCH_RATE": "0.0", "FUZZ_MAX_CONCURRENT_CYCLES": "1", "FUZZ_MAX_PROMPT_COUNT": "256",
            "FUZZ_TRAINING_LEARNING_RATE": "0.003", "FUZZ_UNDERLYING_TRAINING_LEARNING_RATE": "0.003",
            "FUZZ_TRAINING_MAX_GRADIENT": "0.05", "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE": "1",
            "FUZZ_HELDOUT_PROMPT_COUNT": "16", "FUZZ_PROMPT_DATASET_PATH": "/inputs/taxonomy",
            "FUZZ_BENIGN_POOL_PATH": "/inputs/benign_pool", "FUZZ_BENIGN_MANIFEST_PATH": "/inputs/benign_manifest",
            "FUZZ_BENIGN_EXCLUSION_PROOF_PATH": "/inputs/benign_proof", "PYTHONDONTWRITEBYTECODE": "1"},
        ports=[f"127.0.0.1:{cell['ports']['fuzzer']}:50053"],
        volumes=[bind(directory / "fuzzer", "/data", True)] +
                [bind(ROOT / input_map[n]["path"], "/inputs/" + n) for n in ("taxonomy", "benign_pool", "benign_manifest", "benign_proof")])
    if cell["loop"] == "window":
        require(set(releases) == {"directory", "window_sha256", "component_sha256", "teacher_sha256"}, "Accepted window release pins required")
        for role, item in (("PRIVOKE", runtime), ("FUZZ", fuzzer)):
            item["volumes"].append(bind(releases["directory"], "/training-window"))
            item["environment"].update({role + "_WINDOW_PATH": "/training-window/window.json",
                role + "_WINDOW_MANIFEST_SHA256": releases["window_sha256"],
                role + "_COMPONENT_BANK_PATH": "/training-window/bank.json",
                role + "_COMPONENT_REFERENCE_PATH": "/training-window/references-v2.json",
                role + "_COMPONENT_MANIFEST_PATH": "/training-window/component-manifest-v2.json",
                role + "_COMPONENT_MANIFEST_SHA256": releases["component_sha256"],
                role + "_COMPONENT_TEACHER_PATH": "/training-window/original.json",
                role + "_COMPONENT_TEACHER_SHA256": releases["teacher_sha256"]})
    services = {names["model"]: model, names["runtime"]: runtime, names["updater"]: updater, names["fuzzer"]: fuzzer}
    for role in ("runtime", "updater", "fuzzer"):
        package, port = {"runtime": ("extension/client-runtime", 50054), "updater": ("services/param-update-service", 50052),
                         "fuzzer": ("services/privoke-fuzzer", 50053)}[role]
        services[names[role]]["healthcheck"] = {"test": ["CMD", "python", "/workspace/shared/python/grpc_healthcheck.py",
            {"runtime": "client-runtime", "updater": "param-update-service", "fuzzer": "privoke-fuzzer"}[role],
            "127.0.0.1:" + str(port), "/workspace/" + package + "/generated"], "interval": "2s", "timeout": "3s", "retries": 40}
    services[names["runtime"]]["depends_on"] = {names["model"]: {"condition": "service_healthy"}}
    services[names["fuzzer"]]["depends_on"] = {names["runtime"]: {"condition": "service_healthy"},
                                                names["updater"]: {"condition": "service_healthy"}}
    # Docker Desktop does not publish loopback ports from an internal network.
    # The named bridge keeps service DNS while published ports remain loopback-only.
    return {"name": cell["project"], "services": services,
            "networks": {"default": {"driver": "bridge", "internal": False,
                                     "name": cell["project"] + "-network"}}}


def network_snapshot(target, output):
    install_host_imports()
    import grpc
    from privoke.v1 import parameters_pb2 as pp, parameters_pb2_grpc as pg
    from privoke_model.fingerprint import parameter_fingerprint
    request = pp.ModelParametersRequest(model_id="privoke-balanced", consumer_id="tw01-auditor")
    with grpc.insecure_channel(target, options=[("grpc.max_receive_message_length", 268435456)]) as channel:
        response = pg.ModelStreamingServiceStub(channel).GetModelParameters(request, timeout=60)
    parameters = {p.name: {"shape": list(p.shape), "values": list(p.values)} for p in response.parameters}
    require(parameters and len(parameters) == len(response.parameters), "Incomplete/duplicate streamed tensors")
    identity = {"model_id": response.model_id, "version": response.version, "checksum": response.metadata.get("artifact_checksum"),
        "parameter_fingerprint": parameter_fingerprint({n: t["values"] for n, t in parameters.items()},
                                                       {n: t["shape"] for n, t in parameters.items()})}
    require(all(identity.values()), "Streamed model identity incomplete")
    result = {"identity": identity, "metadata": dict(response.metadata), "parameters": parameters,
              "request_base64": base64.b64encode(request.SerializeToString(deterministic=True)).decode(),
              "response_base64": base64.b64encode(response.SerializeToString(deterministic=True)).decode()}
    exclusive(output, result)
    return result


def fit_metadata(cell, protocol, accepted):
    from privoke_model import full_adam as adam, window_training as window
    metadata = {"study_gate_diagnostics": "v1", "expected_contextual_training_optimizer": cell["policy"],
                "expected_contextual_training_objective": OBJECTIVE, "expected_contextual_training_scope": "full_encoder"}
    if cell["loop"] == "window":
        metadata.update(contextual_sampling_strategy=window.SAMPLER, expected_contextual_candidate_eligibility=window.ELIGIBILITY)
        metadata.update({"expected_" + window.CONFIG_KEY: window.canonical(window.CONFIG),
                         "expected_" + window.WINDOW_KEY: accepted["window_sha256"],
                         "expected_" + window.REFERENCE_KEY: accepted["component_sha256"]})
        window.expectations(metadata)
    else:
        metadata.update(contextual_sampling_strategy="taxonomy_benign_coverage_v1",
            taxonomy_dataset_sha256=protocol["inputs"]["taxonomy"]["sha256"],
            benign_pool_sha256=protocol["inputs"]["benign_pool"]["sha256"],
            benign_manifest_sha256=protocol["inputs"]["benign_manifest"]["sha256"],
            benign_exclusion_proof_sha256=protocol["inputs"]["benign_proof"]["sha256"],
            expected_contextual_candidate_eligibility=adam.ELIGIBILITY,
            expected_full_projected_adam_config_v1=adam.canonical(adam.CONFIG))
        adam.expectations(metadata)
    return metadata


def network_fit(target, cell, protocol, accepted, output):
    """Exactly one physical outer RPC. Transport failure never retries this fit."""
    install_host_imports()
    import grpc
    import time
    from privoke.v1 import parameters_pb2 as pp, parameters_pb2_grpc as pg
    request = pp.FuzzerTrainingRequest(request_id=cell["request_id"], model_id="privoke-balanced",
        source_id="tw01-" + cell["id"], prompt_count=256 if cell["loop"] == "window" else 32,
        seed=cell["seed"], metadata=fit_metadata(cell, protocol, accepted))
    wire = request.SerializeToString(deterministic=True)
    exclusive(output / "fit-reservation.json", {"request_id": request.request_id, "sha256": hashlib.sha256(wire).hexdigest(),
        "request_base64": base64.b64encode(wire).decode(), "status": "physical_outcome_unknown_until_audit"})
    started = time.monotonic()
    try:
        with grpc.insecure_channel(target, options=[("grpc.max_receive_message_length", 268435456)]) as channel:
            response = pg.FuzzerServiceStub(channel).RunUnderlyingTrainingCycle(request, timeout=1800)
        exclusive(output / "fit-response.json", {"response_base64": base64.b64encode(response.SerializeToString(deterministic=True)).decode(),
            "accepted": response.accepted, "base_version": response.base_version, "applied_version": response.applied_version,
            "metadata": dict(response.metadata), "message": response.message,
            "dispatch_elapsed_seconds": time.monotonic() - started})
    except grpc.RpcError as exc:
        exclusive(output / "fit-transport.json", {"code": exc.code().name, "details": exc.details(),
            "dispatch_elapsed_seconds": time.monotonic() - started, "outcome": "unknown_pending_retained_audit_no_retry"})


def endpoint_target(row, kind):
    """Frozen historical eligibility, with severity/action-only hazard scoring."""
    if kind == "hazard48":
        eligible = not row["ambiguous"] and row.get("action_accuracy_eligible", True) and row.get("context_truth_eligible", True)
        action = row.get("minimum_action") or row.get("expected_action")
        allowed = row.get("allowed_actions") or ([action] if action else ["ALLOW", "WARN", "BLOCK"])
        if not row.get("allowed_actions") and row.get("minimum_action"):
            allowed = [a for a in ("ALLOW", "WARN", "BLOCK") if ("ALLOW", "WARN", "BLOCK").index(a) >=
                       ("ALLOW", "WARN", "BLOCK").index(action)]
        return {"id": row["case_id"], "group_id": row["family_id"], "quantitative": eligible,
                "target": {"sensitivity": row.get("expected_sensitivity")}, "allowed_actions": allowed}
    if kind == "binary502":
        return {"id": row["id"], "group_id": row["group_id"], "quantitative": True,
                "expected_sensitive": row["expected_has_pii"]}
    return {"id": row["id"], "group_id": row["group_id"], "quantitative": True,
            "target": row["classification"], "allowed_actions": row["allowed_actions"]}


def endpoint_request_fields(row, kind, identity, record_id):
    """Preserve historical fixture stimulus; rendered contextual cues stay in text."""
    return {"request_id": "tw01-score-" + digest([identity, kind, record_id])[:40],
        "text": row["text"], "semantic_model_id": "privoke-balanced", "layers": [4],
        "visibility_hint": row.get("visibility_hint", "") if kind == "hazard48" else ""}


def network_score(target, input_path, kind, identity, output):
    install_host_imports()
    import grpc
    from privoke.v1 import runtime_pb2 as rp, runtime_pb2_grpc as rg
    from privoke_contracts.classification import Classification
    predictions = []
    with grpc.insecure_channel(target) as channel:
        stub = rg.PrivokeRuntimeServiceStub(channel)
        for index, line in enumerate(Path(input_path).read_text(encoding="utf-8").splitlines()):
            row = json.loads(line)
            record = endpoint_target(row, kind)
            request = rp.AnalyzePromptRequest(**endpoint_request_fields(row, kind, identity, record["id"]))
            directory = output / "rows" / f"{index:04d}"
            exclusive(directory / "request.json", {"request_base64": base64.b64encode(request.SerializeToString(deterministic=True)).decode()})
            try:
                response = stub.AnalyzePrompt(request, timeout=60)
                exclusive(directory / "response.json", {"response_base64": base64.b64encode(response.SerializeToString(deterministic=True)).decode()})
            except grpc.RpcError as exc:
                exclusive(directory / "transport-error.json", {"code": exc.code().name, "details": exc.details()})
                raise ValueError("Endpoint network outcome unknown; scoring halted") from exc
            require(len(response.layers) == 1 and response.layers[0].layer == 4,
                    "Endpoint isolation violation; scoring halted")
            if response.error or response.layers[0].error or response.layers[0].status != "ok":
                require(response.layers[0].status == "error" and bool(response.error or response.layers[0].error),
                        "Endpoint execution evidence inconsistent; scoring halted")
                # Errors must still identify this model if the runtime supplied identity.
                for field, suffix in (("model_id", "model_id"), ("version", "model_version"),
                        ("checksum", "artifact_checksum"), ("parameter_fingerprint", "parameter_fingerprint")):
                    actual = response.metadata.get("privoke.semantic." + suffix)
                    require(actual is None or actual == identity[field], "Failed semantic response identifies another model")
                record.update(status="error", error=response.error or response.layers[0].error,
                              actual_layer=4, actual_status="error", classification=None, action=None)
            else:
                assert_semantic(response, identity)
                record.update(status="ok", classification=Classification(response.classification.packed).to_dict(),
                              action=response.action, elapsed_ms=response.elapsed_ms)
            exclusive(directory / "prediction.json", record)
            predictions.append(record)
    exclusive(output / "predictions.json", predictions)
    return predictions


def terminal_audit(cell, before, after, output, resolve_path, directory, pins=None):
    """Admit raw production traces and prove publication or immutable BASE."""
    install_host_imports()
    import sqlite3
    from privoke.v1 import runtime_pb2 as rp
    from training.types import BatchTrainingUpdate
    from privoke_model import full_adam, window_training
    from receipts import receipt_key
    records = [read(p) for p in (directory / "fuzzer/training-cycles").rglob("*.json")]
    records = [r for r in records if r.get("request_id") == cell["request_id"]]
    require(len(records) == 1, "No unique complete retained cycle; physical outcome remains unknown")
    record = records[0]
    evidence = record["execution_evidence"]
    request = rp.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"], validate=True))
    response = rp.ComputeSemanticGradientsResponse.FromString(base64.b64decode(evidence["response_protobuf_base64"], validate=True))
    require(list(request.layers) == [4] and request.request_id == cell["request_id"], "Actual fit semantic selection/identity differs")
    update = BatchTrainingUpdate(model_id=record["model_id"], base_version=record["base_version"],
        gradients={p.name: tuple(p.values) for p in response.gradients}, parameter_shapes={p.name: tuple(p.shape) for p in response.gradients},
        metrics=record["metrics"], metadata=record["metadata"], execution_evidence=evidence)
    if cell["loop"] == "window":
        from training.window_evidence import validate_update
        require(pins is not None, "Accepted window pins required for host validation")
        names = {"FUZZ_WINDOW_MANIFEST_SHA256": pins["window_sha256"],
                 "FUZZ_COMPONENT_MANIFEST_SHA256": pins["component_sha256"],
                 "FUZZ_COMPONENT_TEACHER_SHA256": pins["teacher_sha256"]}
        previous = {name: os.environ.get(name) for name in names}
        try:
            os.environ.update(names)
            trace = validate_update(update, resolve_path=resolve_path)
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
    else:
        from training.full_adam_evidence import validate_candidate_route
        require(validate_candidate_route(update, resolve_path=resolve_path), "Legacy actual fit failed production trace admission")
        trace = json.loads(record["metadata"][full_adam.TRACE_KEY])
    scoped_source = hashlib.sha256(("underlying-v1:tw01-" + cell["id"]).encode()).hexdigest()
    key = receipt_key(cell["project"] + "-fuzzer", cell["request_id"], scoped_source)
    db = directory / "updater/updates.jsonl.receipts.sqlite3"
    receipt, database_sha = None, None
    if db.exists():
        database_sha = sha(db)
        with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as connection:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute("SELECT receipt FROM update_receipts WHERE key=?", (key,)).fetchone()
            receipt = json.loads(row[0]) if row else None
        require(sha(db) == database_sha, "Read-only receipt audit changed database")
    artifact = read(retained_catalog(cell["id"]) / "models/privoke-balanced.json")
    latest = json.loads(artifact["metadata"].get("last_update_receipt", "null"))
    if latest and latest.get("key") == key:
        require(receipt is None or receipt == latest, "Committed artifact/receipt disagree")
        receipt = latest
    changed = before["identity"] != after["identity"]
    if changed:
        require(record["gate_passed"] and receipt and receipt["applied_version"] == after["identity"]["version"],
                "Changed model lacks actual acknowledged selected publication")
        outcome = "selected"
    else:
        require(receipt is None and not record.get("ack"), "BASE outcome has unexpected publication/receipt")
        require(not record["gate_passed"] or (cell["loop"] == "window" and trace["status"] == "no_update"),
                "Unchanged model with publication pending is unknown")
        outcome = "known_no_update"
    result = {"cell": {k: v for k, v in cell.items() if k != "ports"}, "outcome": outcome,
        "before_identity": before["identity"], "effective_identity": after["identity"],
        "actual_fit_request_layers": list(request.layers), "actual_executions": [{"phase": e.phase, "layer": e.layer,
            "status": e.status, "examples": e.examples} for e in response.executions],
        "trace": trace, "cycle_metadata": record["metadata"], "metrics": record["metrics"],
        "cycle_sha256": digest(record), "physical_attempt": evidence["physical_attempt"], "receipt": receipt,
        "receipt_database_sha256": database_sha, "guard_protobuf_sha256": hashlib.sha256(b"".join(
            e.SerializeToString(deterministic=True) for e in request.heldout_examples)).hexdigest()}
    exclusive(output, result)
    return result


def command(arguments, output):
    """Retain exact argv/native status; never infer completion from a launched job."""
    directory = output / "commands"
    directory.mkdir(parents=True, exist_ok=True)
    index = len(list(directory.glob("*.json")))
    result = subprocess.run([str(a) for a in arguments], cwd=ROOT, capture_output=True)
    record = {"argv": [str(a) for a in arguments], "returncode": result.returncode,
              "stdout": result.stdout.decode("utf-8", errors="replace"), "stderr": result.stderr.decode("utf-8", errors="replace")}
    exclusive(directory / f"{index:04d}.json", record)
    require(result.returncode == 0, "Command failed; inspect " + str(directory / f"{index:04d}.json"))
    return record["stdout"]


def image_preflight(output):
    """No model construction: inspect effective imports and generated descriptors."""
    install_host_imports()
    from privoke.v1 import runtime_pb2, parameters_pb2
    require(runtime_pb2.ComputeSemanticGradientsRequest.DESCRIPTOR.fields_by_name["layers"].number == 7,
            "Generated semantic training selection differs")
    require("executions" in runtime_pb2.ComputeSemanticGradientsResponse.DESCRIPTOR.fields_by_name,
            "Generated training evidence absent")
    require("RunUnderlyingTrainingCycle" in parameters_pb2.DESCRIPTOR.services_by_name["FuzzerService"].methods_by_name,
            "Generated FULL endpoint absent")
    modules = {"runtime": runtime_pb2, "parameters": parameters_pb2}
    exclusive(output / "generated-attestation.json", {name: {"file": module.__file__, "file_sha256": sha(module.__file__),
        "descriptor_sha256": hashlib.sha256(module.DESCRIPTOR.serialized_pb).hexdigest()} for name, module in modules.items()})
    files = {}
    for prefix in ("shared/python", "extension/client-runtime/src", "services/privoke-fuzzer/src", "services/param-update-service/app", "evaluation/privoke_eval"):
        if (ROOT / prefix).exists():
            files.update({p.relative_to(ROOT).as_posix(): sha(p) for p in (ROOT / prefix).rglob("*.py") if "__pycache__" not in p.parts})
    exclusive(output / "source-import-paths.json", files)


def bind_build_parents(output, parents):
    """Docker FROM needs local tags; inspected image IDs remain authoritative."""
    aliases = {role: STUDY_ID + "-" + role + "-parent" for role in parents}
    for role, identity in parents.items():
        alias = aliases[role]
        existing = command(["docker", "image", "ls", "--no-trunc", "--filter", "reference=" + alias, "--format", "{{.ID}}"], output).splitlines()
        require(not existing or existing == [identity], "Build alias collision with another image")
        command(["docker", "tag", identity, alias], output)
        require(json.loads(command(["docker", "image", "inspect", alias], output))[0]["Id"] == identity,
                "Build alias differs from inspected immutable parent")
    exclusive(output / "build-parent-aliases.json", {role: {"alias": aliases[role], "identity": identity} for role, identity in parents.items()})
    return aliases


def build_images(output, release_path, parents_path):
    validate_release(output, release_path, "teachers")
    parents = read(parents_path)
    require(set(parents) == {"runtime", "fuzzer", "updater", "proto"}, "Four inspected immutable parent images required")
    require(all(v.startswith("sha256:") and len(v) == 71 for v in parents.values()), "Parent IDs must be immutable")
    for role, image in parents.items():
        exclusive(output / "image-build" / (role + "-parent.json"), json.loads(command(["docker", "image", "inspect", image], output)))
    aliases = bind_build_parents(output, parents)
    common = ["docker", "build", "--pull=false", "-f", ROOT / "evaluation/Dockerfile.task-query-window-study"]
    for role, alias in aliases.items():
        common += ["--build-arg", role.upper() + "_IMAGE=" + alias]
    images = {}
    for role in ("runtime", "fuzzer", "updater", "model"):
        tag = STUDY_ID + "-" + role
        if role == "model":
            argv = ["docker", "build", "--pull=false", "-f", ROOT / "services/model-streaming-service/Dockerfile", "--target", "runtime", "-t", tag, ROOT]
        else:
            argv = [*common, "--target", "study-" + role, "-t", tag, ROOT]
        for parent_role, alias in aliases.items():
            require(json.loads(command(["docker", "image", "inspect", alias], output))[0]["Id"] == parents[parent_role], "Parent alias changed before build")
        command(argv, output)
        for parent_role, alias in aliases.items():
            require(json.loads(command(["docker", "image", "inspect", alias], output))[0]["Id"] == parents[parent_role], "Parent alias changed during build")
        inspected = json.loads(command(["docker", "image", "inspect", tag], output))[0]
        images[role] = inspected["Id"]
        exclusive(output / "image-build" / (role + "-image.json"), inspected)
    exclusive(output / "images.json", images)
    exclusive(output / "image-resources.json", {"owned_tags": [STUDY_ID + "-" + role for role in images],
        "immutable_ids": images, "parents_preserved": parents, "owned_parent_alias_tags": list(aliases.values()),
        "cleanup_owner": "ST-I1", "buildkit_cleanup": False})
    image_preflight(output / "host-preflight")
    # Extract only the task image's executable; never execute it for this attestation.
    name = STUDY_ID + "-binary-attestation"
    command(["docker", "create", "--name", name, images["model"]], output)
    try:
        destination = output / "image-build/model-streaming-service.binary"
        command(["docker", "cp", name + ":/model-streaming-service", destination], output)
        exclusive(output / "image-build/model-executable.json", {"image": images["model"], "sha256": sha(destination),
            "recipe": "services/model-streaming-service/Dockerfile", "current_source_inventory_sha256": digest(source_inventory())})
    finally:
        command(["docker", "rm", name], output)
    return images


def artifact_identity(artifact):
    sys.path.insert(0, str(ROOT / "shared/python"))
    from privoke_model.sensitive_retention import original_effective_parameters
    from privoke_model.fingerprint import parameter_fingerprint
    return {"model_id": artifact["model_id"], "version": artifact["version"], "checksum": artifact["checksum"],
        "parameter_fingerprint": parameter_fingerprint(original_effective_parameters(artifact),
            {n: t["shape"] for n, t in artifact["parameters"].items()})}


def prepare_cells(output, release_path):
    """Pure artifact policy binding after independently accepted teacher pins."""
    protocol = validate_release(output, release_path, "fits")
    sys.path.insert(0, str(ROOT / "shared/python"))
    from privoke_model import full_adam as adam, window_training as window
    from privoke_model.contextual_training import prepare_contextual_training_artifact, FULL_ENCODER_STRATEGY
    accepted, manifest = read(output / "accepted-releases.json"), {}
    for cell in protocol["cells"]:
        original = read(protocol["initial_teachers"][cell["architecture"]]["path"])
        require(sha(protocol["initial_teachers"][cell["architecture"]]["path"]) ==
                protocol["initial_teachers"][cell["architecture"]]["sha256"], "ORIGINAL teacher bytes changed")
        prepared = prepare_contextual_training_artifact(original, FULL_ENCODER_STRATEGY, objective=OBJECTIVE)
        if cell["loop"] == "legacy":
            prepared = adam.prepare_artifact(prepared)
        else:
            pins = accepted[cell["id"]]
            prepared = window.prepare_artifact(prepared, pins["window_sha256"], pins["component_sha256"])
        directory = output / "cells" / cell["id"]
        (directory / "updater").mkdir(parents=True, exist_ok=True)
        (directory / "fuzzer").mkdir(parents=True, exist_ok=True)
        model_directory = retained_catalog(cell["id"]) / "models"
        model_directory.mkdir(parents=True, exist_ok=True)
        require(not list(model_directory.iterdir()), "Fresh private cell catalog required")
        exclusive(model_directory / "privoke-balanced.json", prepared)
        manifest[cell["id"]] = {"artifact_sha256": sha(model_directory / "privoke-balanced.json"),
                                 "identity": artifact_identity(prepared)}
    exclusive(output / "cell-preparation.json", manifest)
    return manifest


def execute_cells(output, release_path, only_cell=None):
    """Run fixed physical cells serially; any unknown audit halts progression."""
    protocol = validate_release(output, release_path, "fits")
    images, releases = images_for_release(output, release_path), read(output / "accepted-releases.json")
    frozen = read(output / "cell-preparation.json")
    candidates = [c for c in protocol["cells"] if only_cell is None or c["id"] == only_cell]
    require(candidates, "Unknown cell selection")
    for cell in candidates:
        directory = output / "cells" / cell["id"]
        if (directory / "effective-artifact-pin.json").exists():
            require(read(directory / "terminal-audit.json")["outcome"] in ("selected", "known_no_update"), "Existing cell lacks known audit")
            require(sha(retained_catalog(cell["id"]) / "effective-artifact.json") == read(directory / "effective-artifact-pin.json")["sha256"], "Completed artifact changed")
            continue
        require(not (directory / "fit-reservation.json").exists(), "Physical cell already attempted; no replay")
        require(sha(retained_catalog(cell["id"]) / "models/privoke-balanced.json") == frozen[cell["id"]]["artifact_sha256"], "Private initial catalog changed")
        cell = {**cell, "ports": available_ports()}
        compose_path = directory / "compose.json"
        compose_model = compose_cell(cell, directory, images, releases[cell["id"]], protocol["inputs"])
        exclusive(compose_path, compose_model)
        compose = ["docker", "compose", "--project-name", cell["project"], "-f", compose_path]
        services = list(compose_model["services"])
        require(set(command(compose + ["config", "--services"], output).splitlines()) == set(services), "Resolved services differ")
        occupied = command(["docker", "ps", "-a", "--format", "{{.Names}}"], output).splitlines()
        require(not any(s["container_name"] in occupied for s in compose_model["services"].values()), "Fresh cell container collision")
        exclusive(directory / "owned-resources.json", {"project": cell["project"], "containers": [s["container_name"] for s in compose_model["services"].values()],
            "network": cell["project"] + "-network", "cleanup_owner": "ST-I1", "volumes": []})
        try:
            command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", *services], output)
            inspect = command(["docker", "inspect", *[s["container_name"] for s in compose_model["services"].values()]], output)
            exclusive(directory / "operations.json", json.loads(inspect))
            before = network_snapshot(loopback_target(f"127.0.0.1:{cell['ports']['model']}"), directory / "before.json")
            require(before["identity"] == frozen[cell["id"]]["identity"], "Streamed initial catalog identity differs")
            network_fit(loopback_target(f"127.0.0.1:{cell['ports']['fuzzer']}"), cell, protocol, releases[cell["id"]], directory)
            after = network_snapshot(loopback_target(f"127.0.0.1:{cell['ports']['model']}"), directory / "after.json")
            terminal_audit(cell, before, after, directory / "terminal-audit.json",
                           frozen_path_resolver(directory / "fuzzer", releases[cell["id"]].get("directory", directory / "fuzzer")),
                           directory, releases[cell["id"]])
            audit = read(directory / "terminal-audit.json")
            require(audit["outcome"] in ("selected", "known_no_update"), "Unknown cell halts study")
            effective = retained_catalog(cell["id"]) / "effective-artifact.json"
            with effective.open("xb") as stream:
                stream.write((retained_catalog(cell["id"]) / "models/privoke-balanced.json").read_bytes())
            exclusive(directory / "effective-artifact-pin.json", {"path": str(effective.resolve()), "sha256": sha(effective), "identity": audit["effective_identity"]})
        except BaseException as exc:
            exclusive(directory / "halted.json", {"error_type": type(exc).__name__, "error": str(exc), "physical_retry_permitted": False})
            raise
        finally:
            cleanup_stack(compose, services, cell["project"], directory, output)


def scoring_catalog(name, candidate):
    """Reuse frozen trained weights; materialize only independent initial controls."""
    model_directory = retained_catalog(name) / "models"
    artifact = model_directory / "privoke-balanced.json"
    source = Path(candidate["path"])
    require(sha(source) == candidate["sha256"], "Candidate weight bytes changed")
    if name.startswith("initial-"):
        model_directory.mkdir(parents=True, exist_ok=True)
        if not artifact.exists():
            with artifact.open("xb") as stream:
                stream.write(source.read_bytes())
    else:
        require(artifact.is_file(), "Trained cell catalog missing")
    require(sha(artifact) == candidate["sha256"], "Scoring catalog differs from effective candidate")
    return model_directory


def score_models(output, release_path):
    """Require all twelve known cells before freezing or mounting endpoints."""
    protocol = validate_release(output, release_path, "endpoints")
    images, candidates = images_for_release(output, release_path), {}
    require(protocol["cells"] == matrix(), "Endpoint scoring requires the exact twelve planned cells")
    for cell in protocol["cells"]:
        directory = output / "cells" / cell["id"]
        require(not (directory / "halted.json").exists(), "Halted cell prevents endpoint scoring")
        required = ("fit-reservation.json", "terminal-audit.json", "effective-artifact-pin.json")
        require(all((directory / name).is_file() for name in required), "Incomplete cell prevents endpoint scoring")
        audit, item = read(directory / "terminal-audit.json"), read(directory / "effective-artifact-pin.json")
        require(audit["cell"] == cell and audit["outcome"] in ("selected", "known_no_update"), "Unknown or mismatched terminal cell prevents endpoint scoring")
        require(read(directory / "fit-reservation.json")["request_id"] == cell["request_id"], "Terminal fit request differs")
        path = retained_catalog(cell["id"]) / "effective-artifact.json"
        require(sha(path) == item["sha256"], "Effective candidate artifact changed")
        require(artifact_identity(read(path)) == item["identity"] == audit["effective_identity"], "Effective artifact identity differs from terminal audit")
        candidates[cell["id"]] = {**item, "path": str(path.resolve())}
    for architecture, item in protocol["initial_teachers"].items():
        path = Path(item["path"])
        require(sha(path) == item["sha256"], "Initial endpoint artifact changed")
        candidates["initial-" + architecture] = {"path": str(path.resolve()), "sha256": sha(path), "identity": artifact_identity(read(path))}
    exclusive(output / "endpoint-candidates.json", candidates)
    for name, candidate in candidates.items():
        directory = output / "endpoints" / name
        scoring_catalog(name, candidate)
        cell = {"id": name, "project": STUDY_ID + "-score-" + name, "loop": "legacy", "ports": available_ports()}
        compose_model = compose_cell(cell, directory, images, {}, protocol["inputs"])
        compose_model["services"] = {k: v for k, v in compose_model["services"].items() if k.endswith(("-model", "-runtime"))}
        compose_path = directory / "compose.json"
        exclusive(compose_path, compose_model)
        compose = ["docker", "compose", "--project-name", cell["project"], "-f", compose_path]
        services = list(compose_model["services"])
        exclusive(directory / "identity.json", candidate["identity"])
        try:
            command(compose + ["config", "--services"], output)
            command(compose + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "180", *services], output)
            before = network_snapshot(loopback_target(f"127.0.0.1:{cell['ports']['model']}"), directory / "before.json")
            require(before["identity"] == candidate["identity"], "Scoring model identity differs")
            for kind in ("context64", "context320", "binary502", "hazard48"):
                item = protocol["inputs"][kind]
                path = permitted_input(ROOT / item["path"])
                require(sha(path) == item["sha256"], "Frozen endpoint changed")
                network_score(loopback_target(f"127.0.0.1:{cell['ports']['runtime']}"), path, kind,
                              candidate["identity"], directory / kind)
            after = network_snapshot(loopback_target(f"127.0.0.1:{cell['ports']['model']}"), directory / "after.json")
            require(after["identity"] == candidate["identity"], "Model changed during endpoint scoring")
        finally:
            cleanup_stack(compose, services, cell["project"], directory, output)


def cleanup_stack(compose, services, project, directory, output):
    """Attempt teardown even when collecting service logs fails."""
    try:
        command(compose + ["logs", "--no-color", "--tail", "200", *services], output)
    finally:
        command(compose + ["down", "--remove-orphans"], output)
    containers = command(["docker", "ps", "-a", "--filter", "label=com.docker.compose.project=" + project, "--format", "{{.Names}}"], output).strip()
    networks = command(["docker", "network", "ls", "--filter", "label=com.docker.compose.project=" + project, "--format", "{{.ID}}"], output).strip()
    require(not containers and not networks, "Owned containers/network remain after cleanup")
    exclusive(directory / "cleanup.json", {"containers_remaining": [], "networks_remaining": []})


def sensitive(classification):
    return classification["sensitivity"] != "S0" or bool(classification.get("categories"))


def summarize_counts(rows, kind):
    eligible = [r for r in rows if r["quantitative"]]
    good = [r for r in eligible if r["status"] == "ok"]
    result = {"requested": len(rows), "quantitative": len(eligible), "successful": len(good), "errors": len(eligible) - len(good)}
    if kind == "binary502":
        for label, wanted in (("positive", True), ("negative", False)):
            subset = [r for r in eligible if r["expected_sensitive"] == wanted]
            successes = [r for r in subset if r["status"] == "ok"]
            result[label] = {"correct": sum(sensitive(r["classification"]) == wanted for r in successes),
                             "denominator": len(subset), "successful_denominator": len(successes)}
        return result
    metrics = {name: {"correct": 0, "denominator": len(eligible)} for name in ("severity", "action")}
    if kind != "hazard48":
        metrics.update({name: {"correct": 0, "denominator": len(eligible)} for name in ("category", "visibility", "all_joint", "packed_exact")})
        for name, wanted in (("sensitive_joint", True), ("sensitive_recall", True), ("clean_specificity", False)):
            metrics[name] = {"correct": 0, "denominator": sum(sensitive(r["target"]) == wanted for r in eligible)}
    for row in good:
        prediction, target = row["classification"], row["target"]
        severity = prediction["sensitivity"] == target["sensitivity"]
        action = row["action"] in row["allowed_actions"]
        metrics["severity"]["correct"] += severity
        metrics["action"]["correct"] += action
        if kind == "hazard48":
            continue
        category = set(prediction["categories"]) == set(target["categories"])
        visibility = prediction["visibility"] == target["visibility"]
        binary = sensitive(prediction) == sensitive(target)
        packed = severity and category and visibility
        joint = binary and packed and action
        for key, correct in (("category", category), ("visibility", visibility), ("packed_exact", packed), ("all_joint", joint)):
            metrics[key]["correct"] += correct
        if sensitive(target):
            metrics["sensitive_joint"]["correct"] += joint
            metrics["sensitive_recall"]["correct"] += sensitive(prediction)
        else:
            metrics["clean_specificity"]["correct"] += not sensitive(prediction)
    result.update(metrics)
    return result


def analyze(output):
    from .curriculum_improvement_evidence import restriction_harms
    protocol, candidates = read(output / "protocol.json"), read(output / "endpoint-candidates.json")
    counts, raw = {}, {}
    for name in candidates:
        raw[name] = {kind: read(output / "endpoints" / name / kind / "predictions.json")
                     for kind in ("context64", "context320", "binary502", "hazard48")}
        counts[name] = {kind: summarize_counts(rows, kind) for kind, rows in raw[name].items()}
    nonregression = ("all_joint", "sensitive_recall", "clean_specificity", "severity", "category", "visibility", "action")
    comparisons, factorial = [], []
    complete = all(c["id"] in counts for c in protocol["cells"])
    if complete:
        for seed in SEEDS:
            treatment = f"v2-window-{seed}"
            for control in (f"v1-legacy-{seed}", "initial-v1"):
                a, b = counts[control]["context64"], counts[treatment]["context64"]
                require(all(a[k]["denominator"] == b[k]["denominator"] for k in nonregression), "Paired endpoint denominators differ")
                harms = {kind: restriction_harms(raw[control][kind], raw[treatment][kind]) for kind in ("context64", "context320", "hazard48")}
                comparisons.append({"seed": seed, "treatment": treatment, "control": control,
                    "sensitive_joint_change": b["sensitive_joint"]["correct"] - a["sensitive_joint"]["correct"],
                    "nonregression": all(b[k]["correct"] >= a[k]["correct"] for k in nonregression),
                    "harms": harms, "zero_new_harm": all(h["passed"] for h in harms.values())})
            value = lambda architecture, loop: counts[f"{architecture}-{loop}-{seed}"]["context64"]["sensitive_joint"]["correct"]
            factorial.append({"seed": seed, "architecture_on_legacy": value("v2", "legacy") - value("v1", "legacy"),
                "window_on_v1": value("v1", "window") - value("v1", "legacy"),
                "architecture_on_window": value("v2", "window") - value("v1", "window"),
                "window_on_v2": value("v2", "window") - value("v2", "legacy"),
                "interaction": value("v2", "window") - value("v1", "window") - value("v2", "legacy") + value("v1", "legacy")})
    passed = complete
    for control_type in ("legacy", "baseline"):
        rows = [r for r in comparisons if (r["control"] == "initial-v1") == (control_type == "baseline")]
        passed &= len(rows) == 3 and all(r["nonregression"] and r["zero_new_harm"] and r["sensitive_joint_change"] >= 0 for r in rows) and any(r["sensitive_joint_change"] > 0 for r in rows)
    discrepancy = []
    for a, b in zip(raw["initial-v1"]["context64"], raw["initial-v2"]["context64"]):
        require(a["id"] == b["id"], "Initial baseline endpoint order differs")
        if a["classification"] != b["classification"] or a["action"] != b["action"]:
            discrepancy.append({"id": a["id"], "v1": {k: a[k] for k in ("classification", "action")},
                                "v2": {k: b[k] for k in ("classification", "action")}})
    qualification = {}
    baseline_binary = counts["initial-v1"]["binary502"]
    for name, value in counts.items():
        if name.startswith("initial-"):
            continue
        binary, contextual = value["binary502"], value["context64"]
        harms = {kind: restriction_harms(raw["initial-v1"][kind], raw[name][kind]) for kind in ("context64", "context320", "hazard48")}
        requirements = {"no_native_errors": binary["errors"] == 0,
            "annotation_recall_at_least90percent": binary["positive"]["correct"] >= .9 * binary["positive"]["denominator"],
            "strict_annotation_specificity_gain": binary["negative"]["correct"] > baseline_binary["negative"]["correct"],
            "context_joint_nonregression": contextual["all_joint"]["correct"] >= counts["initial-v1"]["context64"]["all_joint"]["correct"],
            "zero_new_harm": all(h["passed"] for h in harms.values())}
        qualification[name] = {"passed": all(requirements.values()), "requirements": requirements}
    result = {"id": "TW01", "complete_known_cells": sum(c["id"] in counts for c in protocol["cells"]),
        "planned_cells": 12, "bounded_contextual_improvement": bool(passed), "counts": counts,
        "paired_comparisons": comparisons, "secondary_exploratory_factorial": factorial,
        "initial_v1_v2_context64_discrepancies": discrepancy,
        "historical_qualification": qualification,
        "scope": "reused/provisional development, three paired seeds; package contrast; no protected final or promotion",
        "uncertainty": "counts and paired seed dispersion only; no independent pooled-row claim or bootstrap"}
    exclusive(output / "results.json", result)
    report = f"# TW01 task-query/window study\n\nKnown cells: {result['complete_known_cells']}/12. Bounded contextual improvement: {bool(passed)}.\n\n"
    report += "This contrasts the architecture and native training package. Window coverage, component auxiliary work and TRAIN checkpoint selection change together. These reused/provisional development endpoints do not establish independent generalization.\n\n"
    report += "| Seed | Comparison | Sensitive joint count change | Nonregression | Zero new harm |\n|---|---|---:|---|---|\n"
    for row in comparisons:
        report += f"| {row['seed']} | v2-window vs {row['control']} | {row['sensitive_joint_change']} | {row['nonregression']} | {row['zero_new_harm']} |\n"
    report += "\nAll count numerators/denominators, native failures, coverage, factorial contrasts and initial-readout discrepancies are retained in results.json. Binary annotation presence is a distinct target; native overlength failures prevent qualification. No model was promoted.\n"
    with (output / "report.md").open("x", encoding="utf-8") as stream:
        stream.write(report)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("draft", "teacher", "freeze-training", "build-images", "image-preflight",
        "snapshot", "score", "prepare-cells", "execute", "score-models", "analyze"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--release", type=Path)
    parser.add_argument("--bank", type=Path)
    parser.add_argument("--teacher", type=Path)
    parser.add_argument("--teacher-sha256")
    parser.add_argument("--capture-directory", type=Path)
    parser.add_argument("--architecture", choices=("v1", "v2"))
    parser.add_argument("--worker-output", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--kind", choices=("context64", "context320", "binary502", "hazard48"))
    parser.add_argument("--cell")
    parser.add_argument("--parents", type=Path)
    args = parser.parse_args()
    if args.phase == "draft":
        require(args.inputs is not None, "Explicit accepted inputs file required")
        draft(args.output, read(args.inputs))
    elif args.phase == "image-preflight":
        image_preflight(args.output)
    elif args.phase == "snapshot":
        require(args.target and args.worker_output, "Snapshot target/output required")
        network_snapshot(args.target, args.worker_output)
    elif args.phase == "score":
        require(args.target and args.inputs and args.kind and args.identity and args.worker_output, "Frozen endpoint worker inputs required")
        network_score(args.target, args.inputs, args.kind, read(args.identity), args.worker_output)
    elif args.phase in ("prepare-cells", "execute", "score-models", "build-images"):
        require(args.release is not None, "Exact root phase release required")
        if args.phase == "prepare-cells":
            prepare_cells(args.output, args.release)
        elif args.phase == "execute":
            execute_cells(args.output, args.release, args.cell)
        elif args.phase == "score-models":
            score_models(args.output, args.release)
        else:
            require(args.parents is not None, "Inspected immutable parent image map required")
            build_images(args.output, args.release, args.parents)
    elif args.phase == "analyze":
        analyze(args.output)
    else:
        require(args.release is not None, "Numerical/preparation operation requires root release")
        protocol = validate_release(args.output, args.release, "teachers")
        if args.phase == "teacher":
            require(args.bank and args.teacher and args.teacher_sha256 and args.architecture and args.worker_output
                    and args.target and args.capture_directory, "Teacher inputs and loopback target required")
            require(args.teacher_sha256 == protocol["initial_teachers"][args.architecture]["sha256"], "Teacher is outside independently frozen ORIGINAL pin")
            require(sha(args.bank) == protocol["inputs"]["bank"]["sha256"], "Approved TRAIN bank differs")
            collect_teacher(loopback_target(args.target), args.bank, args.teacher, args.teacher_sha256,
                            args.capture_directory, args.worker_output)
        else:
            require(args.worker_output, "Prepared training output required")
            input_map = {name: {**item, "path": str(permitted_input(ROOT / item["path"]))}
                         for name, item in protocol["inputs"].items()}
            manifest = training_inputs(input_map, args.worker_output)
            require({seed: item["window_sha256"] for seed, item in manifest.items()} == protocol["expected_window_sha256"],
                    "Reproduced windows differ from independently accepted hashes")


if __name__ == "__main__":
    main()
