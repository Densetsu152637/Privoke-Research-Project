"""Prospective frozen-encoder comparison with explicit preparation and fit barriers."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np
from host_environment import ROOT, configure_imports

configure_imports()
sys.path.insert(0, str(ROOT / "extension/client-runtime"))
from privoke_contracts.classification import Category, Sensitivity, Visibility
from privoke_model.artifact import artifact_checksum, float32, load_artifact, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.pretrained_context import build_head_artifact, BACKBONE_SHA256, TOKENIZER_SHA256
from . import pretrained_context_resource as resource_tools
from .synthetic_curriculum import build_curriculum, build_assessment, canonical_json, sha256
from src.detection.preprocessing import normalize_text
from src.model import TinyTransformerModel
from src.pretrained_context import FrozenPretrainedEncoder, PretrainedContextModel
from src.transformer_encoder import TOKEN_PATTERN

DEFAULT_OUTPUT = ROOT / "evaluation/results/semantic_pretrained_20261010/prepared-v3"
ASSETS = ROOT / "evaluation/results/semantic_improvement_20261010_assets"
RESOURCE = ROOT / "evaluation/datasets/contextual-head-study-20261010.json"
FIXTURE = ROOT / "evaluation/results/contextual_fixtures_20261004_v1/support/fixture.jsonl"
FIXTURE_SHA = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"
TASKS = {"sensitivity": tuple(Sensitivity.__members__), "visibility": tuple(Visibility.__members__),
         "category": tuple(Category.__members__)}
ARMS = ("random", "pretrained")
SEEDS = (42, 43, 44)
CHECKPOINTS = (25, 50, 75, 100)
SETTINGS = {"seeds": list(SEEDS), "arms": list(ARMS), "epochs": 100, "batch_size": 32,
    "checkpoints": list(CHECKPOINTS), "learning_rate": .01, "weight_decay": .0001,
    "gradient_norm_clip": 1., "adam_betas": [.9, .999], "adam_epsilon": 1e-8,
    "optimizer": "numpy_float64_adam_coupled_l2_after_global_clip_v1",
    "loss": "mean_sensitivity_CE+mean_visibility_CE+mean_all_row_category_BCE",
    "initialization": "PCG64(seed); sensitivity,visibility,category; each C-order Normal(0,0.02) weight then zero bias",
    "feature_contract": {"random": "exact_Tiny.encode(detector_normalize_text_v1); no extra normalization",
                         "pretrained": "official_masked_mean_l2_v1; detector_normalize_text_v1"},
    "category_threshold": .5, "target_convention": resource_tools.CONVENTION,
    "checkpoint_selection": "nonS0 exact sensitivity+visibility+categoryset joint; overall joint; earlier epoch",
    "evaluation_layers": ["DETECTION_LAYER_SEMANTIC"], "semantic_presence_gate": "absent",
    "probability_parity_atol": 1e-5, "rpc_rounded_category_atol": .00005001,
    "runtime_device": "cpu", "encoder_threads": 1,
    "qualification": {"same_paired_seeds_with_both_10pp_gains": 2,
        "nonS0_denominator": 100, "serious_denominator": 80, "S0_denominator": 60,
        "all_seed_recall_specificity_max_loss_pp": 2,
        "all_seed_casewise_capped_action_harm": 0,
        "runtime_errors_skips_identity_parity_mismatches": 0,
        "maximum_RSS_bytes": 1073741824, "warm_single_prompt_p95_ms": 500,
        "operational_inputs": 200},
    "limitations": ["assistant provisional synthetic family transfer, no independent human annotation",
        "representation package contrast changes scale, dimensions, tokenizer and pooling",
        "explicit actual/fiction/private frames and ordinary non-identifying mild phrasing create a shared easy lexical envelope",
        "assessment family siblings are correlated; no protected-final access or automatic promotion"]}


def permitted(value):
    path = Path(value).resolve()
    if any("final" in part.casefold() for part in path.parts):
        raise ValueError("Protected final paths forbidden before access.")
    return path


def read(path):
    return json.loads(permitted(path).read_text(encoding="utf-8"))


def sha(path):
    return sha256(permitted(path).read_bytes())


def write(path, value):
    path = permitted(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8", newline="\n")
    temp.replace(path)


def rows(path):
    return [json.loads(line) for line in permitted(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def git(*args, binary=False):
    result = subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True)
    return result.stdout if binary else result.stdout.decode().strip()


def source_inventory():
    prefixes = ("evaluation/privoke_eval/", "shared/python/", "shared/proto/", "extension/client-runtime/src/",
                "services/model-streaming-service/")
    exact = {"evaluation/run-pretrained-context-study.py", "evaluation/host_environment.py",
             "evaluation/datasets/contextual-head-study-20261010.json", "models/privoke-balanced.json",
             "evaluation/tests/test_pretrained_context_resource.py", "evaluation/tests/test_pretrained_context_study.py",
             "evaluation/README.md", "docs/semantic-pretrained-context-study-20261010.md",
             "extension/client-runtime/requirements.txt", "evaluation/requirements-host.txt", "evaluation/requirements.txt"}
    names = git("ls-files").splitlines()
    selected = [n for n in names if n in exact or (n.startswith(prefixes) and n.endswith((".py", ".go", ".proto", "go.mod", "go.sum")))]
    if not exact.issubset(selected):
        raise ValueError("Study sources/resource/docs must be tracked and committed before freezing.")
    # Git's clean check applies the repository's text filters. Windows checkouts
    # can have CRLF while the committed source is LF; retain actual served bytes
    # separately rather than rejecting an otherwise unchanged checkout.
    changed = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", *selected])
    if changed.returncode != 0:
        raise ValueError("Study/runtime source contents differ from committed HEAD.")
    result = {}
    for name in selected:
        raw = (ROOT / name).read_bytes()
        if name == "evaluation/datasets/contextual-head-study-20261010.json" and raw != git("show", "HEAD:" + name, binary=True):
            raise ValueError("Authored resource bytes differ from committed blob; preserve its explicit byte pin.")
        result[name] = sha256(raw)
    return result


def load_prior(development):
    # Only named public/provisional resources; never glob results or open final data.
    provenance, prior, curricula = [], [], []
    for name in ("synthetic-teacher-templates.json", "synthetic-teacher-templates-v2.json"):
        path = ROOT / "evaluation/datasets" / name
        pools = build_curriculum(read(path))
        curricula.append(pools)
        prior.extend(r for group in pools.values() for r in group)
        provenance.append({"path": str(path), "sha256": sha(path)})
    path = ROOT / "evaluation/datasets/contextual-assessment-20261009.json"
    prior.extend(build_assessment(read(path), curricula))
    provenance.append({"path": str(path), "sha256": sha(path)})
    development = permitted(development)
    if development.name != "development.jsonl" or sha(development) != "65bf02af1f9f7167a5aa5eaaa8aeac54111c90d009585ed36570d3ce0a635095":
        raise ValueError("Expected byte-pinned public development endpoint.")
    dev = rows(development)
    if len(dev) != 502:
        raise ValueError("Expected 502 development rows.")
    prior.extend(dev)
    provenance.append({"path": str(development), "sha256": sha(development)})
    if sha(FIXTURE) != FIXTURE_SHA or len(rows(FIXTURE)) != 48:
        raise ValueError("Expected pinned 48-row historical fixture.")
    prior.extend({"id": r["case_id"], "text": r["text"], "metadata": {"group_id": r["family_id"]}} for r in rows(FIXTURE))
    provenance.append({"path": str(FIXTURE), "sha256": FIXTURE_SHA})
    return prior, provenance


def encoder_pair(assets, baseline):
    if os.environ.get("PRIVOKE_MODEL_DEVICE") != "cpu":
        raise ValueError("Explicit PRIVOKE_MODEL_DEVICE=cpu required.")
    return {"random": TinyTransformerModel.from_artifact(baseline),
            "pretrained": FrozenPretrainedEncoder(assets)}


def prepare(args):
    output, resource_path = permitted(args.output), permitted(args.resource)
    if output.exists():
        raise ValueError("Prepare requires a fresh output directory.")
    resource = read(resource_path)
    pools = resource_tools.render(resource)
    prior, prior_inputs = load_prior(args.development)
    index = read(args.exclusion_index)
    resource_tools.check_exclusions(pools, index, prior)
    baseline = load_artifact(ROOT / "models/privoke-balanced.json")
    encoders = encoder_pair(args.assets, baseline)
    capacity = {"random_maximum_tokens_including_CLS": 0, "pretrained_maximum_tokens_including_specials": 0}
    for group in pools.values():
        for row in group:
            normalized = normalize_text(row["text"])
            count = len(TOKEN_PATTERN.findall(normalized.lower())) + 1
            if count > baseline["config"]["max_tokens"]:
                raise ValueError("Random encoder would silently truncate a study row.")
            # Tokenizer admission only; never compute assessment features prefit.
            count_pretrained = len(encoders["pretrained"]._tokenizer.encode(normalized, add_special_tokens=True).ids)
            if count_pretrained > 256:
                raise ValueError("Pretrained encoder would exceed admitted context.")
            capacity["random_maximum_tokens_including_CLS"] = max(capacity["random_maximum_tokens_including_CLS"], count)
            capacity["pretrained_maximum_tokens_including_specials"] = max(capacity["pretrained_maximum_tokens_including_specials"], count_pretrained)
    output.mkdir(parents=True)
    for split, group in pools.items():
        (output / (split + ".jsonl")).write_text("".join(canonical_json(row) + "\n" for row in group), encoding="utf-8", newline="\n")
    write(output / "protocol.json", SETTINGS)
    import onnxruntime, tokenizers
    record = {"schema_version": 1, "status": "eligible_pending_independent_resource_protocol_review",
        "resource": {"path": str(resource_path), "sha256": sha(resource_path)},
        "splits": {split: {"file": split + ".jsonl", "sha256": sha(output / (split + ".jsonl"))} for split in pools},
        "exclusion_index": {"path": str(permitted(args.exclusion_index)), "sha256": sha(args.exclusion_index),
                            "union_digest": index["all_exclusion_key_sets_sha256"]},
        "prior_public_inputs": prior_inputs, "inventory": resource_tools.inventory(pools), "capacity": capacity,
        "baseline": {"path": str(ROOT / "models/privoke-balanced.json"), "sha256": sha(ROOT / "models/privoke-balanced.json")},
        "assets": {"directory": str(permitted(args.assets)), "backbone_sha256": sha(Path(args.assets) / "model.onnx"),
                   "tokenizer_sha256": sha(Path(args.assets) / "tokenizer.json")},
        "dependencies": {"python": sys.version, "numpy": np.__version__, "onnxruntime": onnxruntime.__version__, "tokenizers": tokenizers.__version__},
        "protocol_sha256": sha(output / "protocol.json"), "assessment_predictions": 0, "fit_started": False}
    write(output / "eligibility.json", record)
    print(json.dumps({"output": str(output), "eligibility_sha256": sha(output / "eligibility.json"), "inventory": record["inventory"]}))


def freeze(args):
    output = permitted(args.output)
    if (output / "freeze.json").exists():
        raise ValueError("Freeze already exists; never replace a prospective commitment.")
    eligibility = read(output / "eligibility.json")
    inventory = source_inventory()
    review = read(args.review_receipt)
    expected = {"status": "accepted", "resource_sha256": eligibility["resource"]["sha256"],
                "protocol_sha256": sha(output / "protocol.json"), "eligibility_sha256": sha(output / "eligibility.json")}
    if (any(review.get(key) != value for key, value in expected.items()) or not review.get("reviewer")
            or review.get("all_60_families_reviewed") is not True):
        raise ValueError("Independent concrete resource/protocol acceptance receipt required before freeze.")
    verify_prepared(output, eligibility)
    write(output / "freeze.json", {"source_revision": git("rev-parse", "HEAD"), "sources": inventory,
        "eligibility_sha256": sha(output / "eligibility.json"), "protocol_sha256": sha(output / "protocol.json"),
        "review_receipt": review, "review_receipt_sha256": sha(args.review_receipt), "timestamp_unix": int(time.time())})


def verify_prepared(output, eligibility, *, include_assessment=True):
    for entry in [eligibility["resource"], eligibility["exclusion_index"], eligibility["baseline"], *eligibility["prior_public_inputs"]]:
        if sha(entry["path"]) != entry["sha256"]:
            raise ValueError("Prepared input commitment changed.")
    for split, entry in eligibility["splits"].items():
        if split == "assessment" and not include_assessment:
            continue
        if sha(output / entry["file"]) != entry["sha256"]:
            raise ValueError("Prepared row bytes changed.")
    if sha(output / "protocol.json") != eligibility["protocol_sha256"] or read(output / "protocol.json") != SETTINGS:
        raise ValueError("Frozen settings changed.")


def verify_freeze(output, *, include_assessment=True):
    frozen, eligibility = read(output / "freeze.json"), read(output / "eligibility.json")
    if sha(output / "eligibility.json") != frozen["eligibility_sha256"] or source_inventory() != frozen["sources"]:
        raise ValueError("Source/eligibility freeze changed.")
    verify_prepared(output, eligibility, include_assessment=include_assessment)
    for name, key in (("model.onnx", "backbone_sha256"), ("tokenizer.json", "tokenizer_sha256")):
        if sha(Path(eligibility["assets"]["directory"]) / name) != eligibility["assets"][key]:
            raise ValueError("Encoder asset bytes changed.")
    return frozen, eligibility


def initialize(hidden, seed):
    rng = np.random.default_rng(seed)
    parameters = {}
    for task, labels in TASKS.items():
        parameters[f"head.{task}.weight"] = rng.normal(0, .02, (hidden, len(labels))).astype(np.float64)
        parameters[f"head.{task}.bias"] = np.zeros(len(labels), dtype=np.float64)
    return parameters


def targets(data):
    result = {task: [] for task in TASKS}
    for row in data:
        target = row["classification"]
        result["sensitivity"].append(TASKS["sensitivity"].index(target["sensitivity"]))
        result["visibility"].append(TASKS["visibility"].index(target["visibility"]))
        result["category"].append([int(c in target["categories"]) for c in TASKS["category"]])
    return {task: np.asarray(value) for task, value in result.items()}


def probabilities(features, parameters):
    result = {}
    for task in TASKS:
        logits = features @ parameters[f"head.{task}.weight"] + parameters[f"head.{task}.bias"]
        if task == "category":
            result[task] = np.exp(-np.logaddexp(0, -logits))
        else:
            exp = np.exp(logits - logits.max(axis=-1, keepdims=True))
            result[task] = exp / exp.sum(axis=-1, keepdims=True)
    return result


def loss_gradients(features, truth, parameters):
    gradients, loss = {}, 0.
    for task in TASKS:
        logits = features @ parameters[f"head.{task}.weight"] + parameters[f"head.{task}.bias"]
        if task == "category":
            loss += float(np.mean(np.logaddexp(0, logits) - truth[task] * logits))
            delta = (np.exp(-np.logaddexp(0, -logits)) - truth[task]) / logits.size
        else:
            shifted = logits - logits.max(axis=1, keepdims=True)
            exp = np.exp(shifted)
            probs = exp / exp.sum(axis=1, keepdims=True)
            loss += float(np.mean(np.log(exp.sum(axis=1)) - shifted[np.arange(len(features)), truth[task]]))
            delta = probs
            delta[np.arange(len(features)), truth[task]] -= 1
            delta /= len(features)
        gradients[f"head.{task}.weight"] = features.T @ delta
        gradients[f"head.{task}.bias"] = delta.sum(axis=0)
    if not np.isfinite(loss) or any(not np.isfinite(value).all() for value in gradients.values()):
        raise ValueError("Nonfinite optimizer loss/gradient.")
    return loss, gradients


class Adam:
    """Clip data gradients globally, then coupled L2, then bias-corrected Adam."""
    def __init__(self, parameters):
        self.m = {name: np.zeros_like(value) for name, value in parameters.items()}
        self.v = {name: np.zeros_like(value) for name, value in parameters.items()}
        self.step_count = 0

    def step(self, parameters, gradients):
        norm = float(np.sqrt(sum(np.sum(value * value) for value in gradients.values())))
        scale = min(1., SETTINGS["gradient_norm_clip"] / (norm + 1e-12))
        self.step_count += 1
        b1, b2 = SETTINGS["adam_betas"]
        for name, parameter in parameters.items():
            gradient = gradients[name] * scale + SETTINGS["weight_decay"] * parameter
            self.m[name] = b1 * self.m[name] + (1 - b1) * gradient
            self.v[name] = b2 * self.v[name] + (1 - b2) * gradient * gradient
            parameter -= SETTINGS["learning_rate"] * (self.m[name] / (1 - b1 ** self.step_count)) / (
                np.sqrt(self.v[name] / (1 - b2 ** self.step_count)) + SETTINGS["adam_epsilon"])
        return norm


def classifications(probs):
    return [{"sensitivity": TASKS["sensitivity"][int(np.argmax(s))],
             "visibility": TASKS["visibility"][int(np.argmax(v))],
             "categories": [c for c, p in zip(TASKS["category"], cat) if p >= .5]}
            for s, v, cat in zip(probs["sensitivity"], probs["visibility"], probs["category"])]


def joint_counts(data, predictions):
    correct = [row["classification"] == prediction for row, prediction in zip(data, predictions)]
    return {"nonS0_joint_correct": sum(ok for row, ok in zip(data, correct) if row["classification"]["sensitivity"] != "S0"),
            "overall_joint_correct": sum(correct), "rows": len(data)}


def checkpoint_key(record):
    return record["nonS0_joint_correct"], record["overall_joint_correct"], -record["epoch"]


def export_artifact(arm, parameters, baseline, seed, epoch, timestamp):
    metadata = {"label_status": "assistant_provisional", "target_convention": resource_tools.CONVENTION,
                "study": "semantic_pretrained_20261010", "seed": str(seed), "epoch": str(epoch),
                "publication_scope": "isolated research only"}
    flat = {name: value.astype(np.float32).ravel().tolist() for name, value in parameters.items()}
    version = f"head-study-{arm}-{seed}-epoch{epoch}"
    if arm == "pretrained":
        return build_head_artifact(flat, version=version, generated_at_unix=timestamp, metadata=metadata)
    result = copy.deepcopy(baseline)
    for name, values in flat.items():
        result["parameters"][name]["values"] = values
    result["version"], result["generated_at_unix"] = version, timestamp
    result.setdefault("metadata", {}).update(metadata)
    result["config"]["category_threshold"] = .5
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def reconstructed(artifact, pretrained_encoder):
    if artifact["architecture"] == "privoke_pretrained_context_v1":
        return PretrainedContextModel(artifact["config"], {n: t["values"] for n, t in artifact["parameters"].items()},
                                      {n: t["shape"] for n, t in artifact["parameters"].items()}, pretrained_encoder)
    return TinyTransformerModel.from_artifact(artifact)


def parity(data, features, artifact, pretrained_encoder):
    model = reconstructed(artifact, pretrained_encoder)
    heads = {n: np.asarray(t["values"], dtype=np.float32).reshape(t["shape"]) for n, t in artifact["parameters"].items() if n.startswith("head.")}
    expected = probabilities(features, heads)
    maximum = 0.
    for i, row in enumerate(data):
        actual = model.predict(normalize_text(row["text"]))
        for task in TASKS:
            values = getattr(actual, "category_probabilities" if task == "category" else task + "_probabilities")
            error = float(np.max(np.abs(expected[task][i] - values)))
            maximum = max(maximum, error)
            if error > 1e-5:
                raise ValueError("Serialized same-encoder probability parity failed.")
    return maximum


def fit(args):
    output = permitted(args.output)
    frozen, eligibility = verify_freeze(output, include_assessment=False)
    fit_directory = output / "fit"
    if fit_directory.exists():
        raise ValueError("Fit must be fresh; preserve failed runs and selections.")
    train, validation = rows(output / "train.jsonl"), rows(output / "validation.jsonl")
    baseline = load_artifact(eligibility["baseline"]["path"])
    encoders = encoder_pair(eligibility["assets"]["directory"], baseline)
    fit_directory.mkdir()
    features = {}
    for arm, encoder in encoders.items():
        features[arm] = {}
        for split, data in (("train", train), ("validation", validation)):
            values = (encoder.features([r["text"] for r in data]) if arm == "pretrained" else
                      np.stack([encoder.encode(normalize_text(r["text"])) for r in data]))
            if not np.isfinite(values).all():
                raise ValueError("Nonfinite features.")
            features[arm][split] = values
            np.save(fit_directory / f"{arm}-{split}-features.npy", values, allow_pickle=False)
    truth = targets(train)
    selections = []
    for seed in SEEDS:
        order_rng = np.random.default_rng(seed)
        orders = [order_rng.permutation(len(train)) for _ in range(100)]
        order_sha = sha256(np.asarray(orders, dtype="<i8").tobytes())
        np.save(fit_directory / f"orders-{seed}.npy", np.asarray(orders), allow_pickle=False)
        for arm in ARMS:
            directory = fit_directory / f"{arm}-{seed}"
            directory.mkdir()
            parameters = initialize(features[arm]["train"].shape[1], seed)
            optimizer = Adam(parameters)
            records, losses = [], []
            np.savez(directory / "initial-heads.npz", **parameters)
            for epoch, order in enumerate(orders, 1):
                epoch_losses = []
                for start in range(0, len(train), 32):
                    indices = order[start:start + 32]
                    loss, gradients = loss_gradients(features[arm]["train"][indices].astype(np.float64),
                        {task: target[indices] for task, target in truth.items()}, parameters)
                    norm = optimizer.step(parameters, gradients)
                    epoch_losses.append({"loss": loss, "gradient_norm_before_clip": norm})
                losses.append({"epoch": epoch, "batches": epoch_losses})
                if epoch in CHECKPOINTS:
                    artifact = export_artifact(arm, parameters, baseline, seed, epoch, frozen["timestamp_unix"])
                    path = directory / f"checkpoint-{epoch}.json"
                    write(path, artifact)
                    # Select using exported float32 heads, matching runtime arithmetic.
                    loaded = read(path)
                    heads = {n: np.asarray(t["values"], dtype=np.float32).reshape(t["shape"]) for n, t in loaded["parameters"].items() if n.startswith("head.")}
                    predicted = classifications(probabilities(features[arm]["validation"], heads))
                    record = {"epoch": epoch, **joint_counts(validation, predicted), "artifact": path.name,
                              "artifact_sha256": sha(path), "probability_parity_max_error": parity(validation, features[arm]["validation"], loaded, encoders["pretrained"])}
                    write(directory / f"validation-{epoch}.json", {"record": record, "predictions": predicted})
                    records.append(record)
            selected = max(records, key=checkpoint_key)
            np.savez(directory / "optimizer-state.npz", **{"m_" + n: v for n, v in optimizer.m.items()}, **{"v_" + n: v for n, v in optimizer.v.items()})
            write(directory / "training.json", {"steps": optimizer.step_count, "orders_sha256": order_sha, "epochs": losses,
                "initial_heads_sha256": sha(directory / "initial-heads.npz"), "checkpoint_records": records})
            receipt = {"arm": arm, "seed": seed, "selected": selected, "steps": optimizer.step_count, "orders_sha256": order_sha,
                       "freeze_sha256": sha(output / "freeze.json"), "selection_rule": SETTINGS["checkpoint_selection"]}
            write(directory / "selection.json", receipt)
            selections.append({"file": str((directory / "selection.json").relative_to(output)), "sha256": sha(directory / "selection.json")})
    write(output / "selection-commitment.json", {"freeze_sha256": sha(output / "freeze.json"), "selections": selections,
                                               "assessment_opened_by_fitter": False, "assessment_predictions": 0})


def selection_barrier(output):
    verify_freeze(output, include_assessment=False)
    commitment = read(output / "selection-commitment.json")
    if commitment["freeze_sha256"] != sha(output / "freeze.json") or len(commitment["selections"]) != 6:
        raise ValueError("All six selection receipts must precede assessment access.")
    seen = set()
    for item in commitment["selections"]:
        path = permitted(output / item["file"])
        path.relative_to(output)
        receipt = read(path)
        key = receipt["arm"], receipt["seed"]
        if sha(path) != item["sha256"] or key in seen or receipt["steps"] != 2000:
            raise ValueError("Invalid or changed selection receipt.")
        selected = receipt["selected"]
        if sha(path.parent / selected["artifact"]) != selected["artifact_sha256"]:
            raise ValueError("Selected artifact changed.")
        seen.add(key)
    if seen != {(arm, seed) for arm in ARMS for seed in SEEDS}:
        raise ValueError("Incomplete paired selections.")
    return commitment


def artifact_identity(artifact):
    # Parameters use repeated float on both unary and streaming RPCs. Original
    # JSON decimals can carry more precision; bind the actually served float32
    # values independently of the unchanged exact artifact checksum/version.
    return {"model_id": artifact["model_id"], "model_version": artifact["version"], "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint({n: [float32(value) for value in t["values"]]
                                                            for n, t in artifact["parameters"].items()},
                                                          {n: t["shape"] for n, t in artifact["parameters"].items()})}


def validate_response(response, request_id, expected, pretrained):
    from privoke.v1 import runtime_pb2 as RP
    if response.request_id != request_id or response.error or len(response.layers) != 1:
        raise ValueError("Request identity, runtime error or layer-count violation.")
    execution = response.layers[0]
    if execution.layer != RP.DETECTION_LAYER_SEMANTIC or execution.status != "ok" or execution.error or execution.HasField("semantic_presence_gate"):
        raise ValueError("Exactly one successful semantic layer without presence gate required.")
    if response.action not in {"ALLOW", "WARN", "BLOCK"}:
        raise ValueError("Unknown runtime action.")
    actual = response.classification
    if (actual.sensitivity not in TASKS["sensitivity"] or actual.visibility not in TASKS["visibility"]
            or len(set(actual.categories)) != len(actual.categories)
            or any(category not in TASKS["category"] for category in actual.categories)):
        raise ValueError("Unknown or duplicate runtime classification label.")
    for finding in execution.results:
        if any(finding.metadata.get(k) != v for k, v in expected.items()):
            raise ValueError("Finding identity differs.")
    if pretrained:
        trace = {**expected, "backbone_sha256": BACKBONE_SHA256, "tokenizer_sha256": TOKENIZER_SHA256}
        if any(response.metadata.get("privoke.pretrained_context." + k) != v for k, v in trace.items()):
            raise ValueError("Response-used pretrained identity differs, including empty results.")


def evaluate(args):
    output = permitted(args.output)
    selection_barrier(output)  # Before any assessment read.
    _, eligibility = verify_freeze(output)
    server = server_manifest(args, output)
    server_sha = sha(args.server_manifest)
    directory = output / "fit" / f"{args.arm}-{args.seed}"
    selected = read(directory / "selection.json")["selected"]
    artifact = load_artifact(directory / selected["artifact"])
    identity = artifact_identity(artifact)
    destination = output / f"assessment-{args.arm}-{args.seed}.json"
    if destination.exists():
        raise ValueError("Assessment score-once receipt already exists.")
    # Record a started receipt before reading assessment. A failed attempt stays visible.
    write(destination, {"status": "started", "selection_commitment_sha256": sha(output / "selection-commitment.json")})
    from .continual_fuzzer_study import RpcClient
    from privoke.v1 import runtime_pb2 as RP
    from google.protobuf.json_format import MessageToDict
    from src.LLM.privoke.parameter_stream import ParameterSnapshot
    from src.LLM.privoke.streamed_model import StreamedTransformerPrivacyModel
    from src.LLM.privoke.pretrained_context_model import StreamedPretrainedContextModel
    from src.pipeline import strongest_result
    # Exact action parity uses the runtime wrapper's clipped/rounded confidence.
    snapshot = ParameterSnapshot(artifact["model_id"], artifact["version"], artifact["generated_at_unix"],
        {n: tuple(t["values"]) for n, t in artifact["parameters"].items()},
        {n: tuple(t["shape"]) for n, t in artifact["parameters"].items()},
        {"architecture": artifact["architecture"], "artifact_checksum": artifact["checksum"], "trainable_parameters": "",
         "model_config": canonical_json(artifact["config"])})
    encoder = FrozenPretrainedEncoder(eligibility["assets"]["directory"])
    wrapper = StreamedPretrainedContextModel(snapshot, encoder) if args.arm == "pretrained" else StreamedTransformerPrivacyModel(snapshot)
    data = rows(output / "assessment.jsonl")
    client = RpcClient(args.fuzzer_target, args.runtime_target, args.model_target)
    predictions = []
    try:
        for row in data:
            if client.snapshot(artifact["model_id"])["identity"] != identity:
                raise ValueError("Before-request model identity differs from selected artifact.")
            request_id = "pretrained-study-" + sha256(f"{args.arm}:{args.seed}:{row['id']}".encode())[:40]
            request = RP.AnalyzePromptRequest(text=row["text"], source="pretrained-context-study", request_id=request_id,
                semantic_model_id=artifact["model_id"], layers=[RP.DETECTION_LAYER_SEMANTIC])
            start = time.perf_counter()
            response = client.runtime.AnalyzePrompt(request, timeout=120)
            elapsed = (time.perf_counter() - start) * 1000
            validate_response(response, request_id, identity, args.arm == "pretrained")
            if client.snapshot(artifact["model_id"])["identity"] != identity:
                raise ValueError("After-request model identity differs, including empty results.")
            findings = wrapper.classify(normalize_text(row["text"]))
            primary, action = strongest_result(findings)
            offline = primary.classification.to_dict() if primary else {"sensitivity": "S0", "visibility": "PU", "categories": []}
            actual = {"sensitivity": response.classification.sensitivity, "visibility": response.classification.visibility,
                      "categories": list(response.classification.categories)}
            if actual != offline or response.action != action.name:
                raise ValueError("Offline/runtime classification or confidence-aware action differs.")
            offline_prediction = wrapper.model.predict(normalize_text(row["text"]))
            for finding in response.layers[0].results:
                if "category_probabilities" in finding.metadata:
                    rounded = json.loads(finding.metadata["category_probabilities"])
                    for label, probability in zip(TASKS["category"], offline_prediction.category_probabilities):
                        if label not in rounded or abs(rounded[label] - probability) > .00005001:
                            raise ValueError("Rounded RPC category probability metadata differs.")
            predictions.append({"id": row["id"], "family_id": row["metadata"]["family_id"], "target": row["classification"],
                "classification": actual, "required_action": row["allowed_actions"][0], "action": response.action,
                "runtime_ms": elapsed, "identity": identity, "raw": MessageToDict(response, preserving_proto_field_name=True)})
            write(destination, {"status": "running", "predictions": predictions, "server_manifest_sha256": sha(args.server_manifest)})
        if sha(args.server_manifest) != server_sha:
            raise ValueError("Server attestation changed during endpoint.")
        write(destination, {"status": "complete", "predictions": predictions, "runtime_errors": 0,
            "selection_commitment_sha256": sha(output / "selection-commitment.json"), "identity": identity,
            "server_manifest_sha256": server_sha})
    except Exception as exc:
        write(destination, {"status": "failed", "error": str(exc), "completed_rows": len(predictions), "predictions": predictions})
        raise
    finally:
        client.close()


def server_manifest(args, output):
    record = read(args.server_manifest)
    expected = {"source_revision": read(output / "freeze.json")["source_revision"], "runtime_device": "cpu",
                "encoder_threads": 1, "concurrent_publication": False, "automatic_training": False,
                "catalog_isolated": True, "runtime_target": args.runtime_target, "model_target": args.model_target}
    if any(record.get(k) != v for k, v in expected.items()) or not record.get("runtime_pid") or not record.get("cpu_name"):
        raise ValueError("Exact isolated, CPU-only, no-background-training server attestation required.")
    if not args.runtime_target.startswith(("127.0.0.1:", "localhost:")):
        raise ValueError("Study runtime must use the attested loopback process.")
    if os.name == "nt":
        port = int(args.runtime_target.rsplit(":", 1)[1])
        command = f"Get-NetTCPConnection -State Listen -LocalPort {port} | Select-Object -ExpandProperty OwningProcess | ConvertTo-Json -Compress"
        response = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, check=True)
        owners = json.loads(response.stdout)
        owners = owners if isinstance(owners, list) else [owners]
        if record["runtime_pid"] not in owners:
            raise ValueError("Attested runtime PID does not own the measured gRPC listener.")
    return record


def endpoint_metrics(predictions):
    result = {}
    for name, predicate in (("nonS0", lambda t: t["sensitivity"] != "S0"),
                            ("serious", lambda t: t["sensitivity"] in {"S2", "S3"}),
                            ("S0", lambda t: t["sensitivity"] == "S0")):
        subset = [p for p in predictions if predicate(p["target"])]
        detected = lambda p: p["classification"]["sensitivity"] != "S0" or bool(p["classification"]["categories"])
        result[name] = {"denominator": len(subset), "joint_correct": sum(p["classification"] == p["target"] for p in subset),
            "union_detected": sum(detected(p) for p in subset),
            "sensitivity_detected": sum(p["classification"]["sensitivity"] != "S0" for p in subset),
            "union_clean": sum(not detected(p) for p in subset),
            "action_correct": sum(p["action"] == p["required_action"] for p in subset)}
    result["categories"] = {c: {"TP": sum(c in p["target"]["categories"] and c in p["classification"]["categories"] for p in predictions),
        "FP": sum(c not in p["target"]["categories"] and c in p["classification"]["categories"] for p in predictions),
        "FN": sum(c in p["target"]["categories"] and c not in p["classification"]["categories"] for p in predictions)} for c in TASKS["category"]}
    result["cardinality"] = {str(k): {"denominator": sum(len(p["target"]["categories"]) == k for p in predictions),
        "categoryset_exact": sum(set(p["target"]["categories"]) == set(p["classification"]["categories"]) for p in predictions if len(p["target"]["categories"]) == k)} for k in (0, 1, 2)}
    return result


def secondary(args):
    """Reused public presence and historical sensitivity/action guards, kept separate."""
    output = permitted(args.output)
    selection_barrier(output)
    _, eligibility = verify_freeze(output)
    server_manifest(args, output)
    server_sha = sha(args.server_manifest)
    if args.arm == "baseline":
        artifact = load_artifact(eligibility["baseline"]["path"])
        tag = "baseline"
    else:
        directory = output / "fit" / f"{args.arm}-{args.seed}"
        selected = read(directory / "selection.json")["selected"]
        artifact = load_artifact(directory / selected["artifact"])
        tag = f"{args.arm}-{args.seed}"
    identity = artifact_identity(artifact)
    destination = output / f"secondary-{tag}.json"
    if destination.exists():
        raise ValueError("Secondary endpoint already attempted; preserve its result.")
    from .continual_fuzzer_study import RpcClient, metrics
    from privoke.v1 import runtime_pb2 as RP
    from google.protobuf.json_format import MessageToDict
    client = RpcClient(args.fuzzer_target, args.runtime_target, args.model_target)
    endpoints = {}
    write(destination, {"status": "started", "identity": identity})
    try:
        development_path = next(item["path"] for item in eligibility["prior_public_inputs"] if Path(item["path"]).name == "development.jsonl")
        for name, data in (("development_presence", rows(development_path)), ("historical_fixture", rows(FIXTURE))):
            predictions = []
            for row in data:
                key = row.get("id", row.get("case_id"))
                if client.snapshot(artifact["model_id"])["identity"] != identity:
                    raise ValueError("Secondary before-request identity changed.")
                request_id = "secondary-" + sha256(f"{tag}:{name}:{key}".encode())[:40]
                request = RP.AnalyzePromptRequest(text=row["text"], source="pretrained-secondary", request_id=request_id,
                    semantic_model_id=artifact["model_id"], layers=[RP.DETECTION_LAYER_SEMANTIC])
                response = client.runtime.AnalyzePrompt(request, timeout=120)
                if client.snapshot(artifact["model_id"])["identity"] != identity:
                    raise ValueError("Secondary after-request identity changed.")
                raw = MessageToDict(response, preserving_proto_field_name=True)
                if response.request_id != request_id or len(response.layers) != 1 or response.layers[0].layer != RP.DETECTION_LAYER_SEMANTIC or response.layers[0].HasField("semantic_presence_gate"):
                    raise ValueError("Secondary semantic-only execution violated.")
                if response.error or response.layers[0].status != "ok" or response.layers[0].error:
                    predictions.append({"id": key, "status": "error", "error": response.error or response.layers[0].error, "raw": raw})
                    continue
                validate_response(response, request_id, identity, args.arm == "pretrained")
                predicted = {"sensitivity": response.classification.sensitivity, "visibility": response.classification.visibility,
                             "categories": list(response.classification.categories)}
                record = {"id": key, "status": "ok", "classification": predicted, "action": response.action, "raw": raw}
                if name == "development_presence":
                    record.update(expected_has_pii=row["expected_has_pii"], group_id=row["group_id"],
                                  detected_sensitive=predicted["sensitivity"] != "S0" or bool(predicted["categories"]))
                else:
                    record.update(quantitative=not row["ambiguous"], expected_sensitivity=row["expected_sensitivity"],
                        sensitivity_correct=predicted["sensitivity"] == row["expected_sensitivity"],
                        action_eligible=not row["ambiguous"] and row.get("action_accuracy_eligible", True),
                        allowed_actions=row["allowed_actions"], action_correct=response.action in row["allowed_actions"],
                        minimum_action=row.get("minimum_action"), visibility=row["expected_visibility"])
                predictions.append(record)
            if name == "development_presence":
                # Error rows retain a denominator and never become successful clean predictions.
                by_id = {r["id"]: r for r in data}
                metric_rows = [{**p, "expected_has_pii": by_id[p["id"]]["expected_has_pii"]} for p in predictions]
                summary = metrics(metric_rows)
            else:
                eligible = [p for p in predictions if p["status"] == "ok" and p["quantitative"]]
                action_rows = [p for p in eligible if p["action_eligible"]]
                summary = {"loaded_rows": len(data), "runtime_errors": sum(p["status"] != "ok" for p in predictions),
                    "sensitivity_denominator": len(eligible), "sensitivity_correct": sum(p["sensitivity_correct"] for p in eligible),
                    "action_denominator": len(action_rows), "action_correct": sum(p["action_correct"] for p in action_rows),
                    "category_exact_comparison": "excluded: historical topic-tag convention differs",
                    "private_action_failures": [p["id"] for p in action_rows if not p["action_correct"] and p["visibility"] in {"P2", "P3", "P4"}]}
            endpoints[name] = {"summary": summary, "predictions": predictions}
            write(destination, {"status": "running", "identity": identity, "endpoints": endpoints})
        if sha(args.server_manifest) != server_sha:
            raise ValueError("Secondary server attestation changed.")
        write(destination, {"status": "complete", "identity": identity, "endpoints": endpoints,
            "scope": "reused secondary endpoints; no fresh TEST claim", "server_manifest_sha256": server_sha})
    except Exception as exc:
        write(destination, {"status": "failed", "error": str(exc), "identity": identity, "endpoints": endpoints})
        raise
    finally:
        client.close()


def paired_qualification(before, after):
    left, right = {p["id"]: p for p in before}, {p["id"]: p for p in after}
    if len(left) != 160 or len(right) != 160 or left.keys() != right.keys():
        raise ValueError("Paired assessment IDs/denominators differ.")
    if any(left[key]["target"] != right[key]["target"] for key in left):
        raise ValueError("Paired assessment target mismatch.")
    baseline, candidate = endpoint_metrics(before), endpoint_metrics(after)
    if [baseline[k]["denominator"] for k in ("nonS0", "serious", "S0")] != [100, 80, 60]:
        raise ValueError("Unexpected qualification denominators.")
    gains = {k: candidate[k]["joint_correct"] - baseline[k]["joint_correct"] for k in ("nonS0", "serious")}
    losses = {"nonS0_union_recall": baseline["nonS0"]["union_detected"] - candidate["nonS0"]["union_detected"],
              "serious_union_recall": baseline["serious"]["union_detected"] - candidate["serious"]["union_detected"],
              "S0_union_specificity": baseline["S0"]["union_clean"] - candidate["S0"]["union_clean"]}
    actions = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}
    harms = []
    for key, prior in left.items():
        current = right[key]
        if prior["target"]["sensitivity"] not in {"S2", "S3"}:
            continue
        required = actions[prior["required_action"]]
        if min(actions[current["action"]], required) < min(actions[prior["action"]], required):
            harms.append({"id": key, "visibility": prior["target"]["visibility"], "required_action": prior["required_action"],
                          "before_action": prior["action"], "after_action": current["action"]})
    private_harms = [h for h in harms if h["visibility"] in {"P2", "P3", "P4"}]
    return {"baseline": baseline, "candidate": candidate, "joint_gains_cases": gains,
        "both_primary_gains": gains["nonS0"] >= 10 and gains["serious"] >= 8,
        "union_metric_losses_cases": losses,
        "veto_clear": losses["nonS0_union_recall"] <= 2 and losses["serious_union_recall"] <= 1 and
                      losses["S0_union_specificity"] <= 1 and not harms,
        "serious_action_harms": harms, "private_serious_action_harms": private_harms}


def process_memory(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle:
            raise OSError(ctypes.get_last_error(), "Cannot inspect runtime process memory.")
        try:
            counters = Counters(); counters.cb = ctypes.sizeof(counters)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                raise OSError(ctypes.get_last_error(), "Cannot measure runtime RSS.")
            return {"rss_bytes": counters.WorkingSetSize, "peak_rss_bytes": counters.PeakWorkingSetSize}
        finally:
            kernel.CloseHandle(handle)
    status = Path(f"/proc/{pid}/status").read_text()
    values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line}
    return {"rss_bytes": int(values["VmRSS"].split()[0]) * 1024, "peak_rss_bytes": int(values["VmHWM"].split()[0]) * 1024}


def operational(args):
    """Measure actual loopback RPC transport, with RSS from the named runtime PID."""
    import platform
    output = permitted(args.output)
    selection_barrier(output)
    _, eligibility = verify_freeze(output)
    server = server_manifest(args, output)
    directory = output / "fit" / f"{args.arm}-{args.seed}"
    selection = read(directory / "selection.json")["selected"]
    artifact = load_artifact(directory / selection["artifact"])
    identity = artifact_identity(artifact)
    if not args.runtime_target.startswith(("127.0.0.1:", "localhost:")):
        raise ValueError("Operational PID/RSS evidence requires the loopback runtime on this host.")
    if args.runtime_pid <= 0 or not args.cpu_name.strip():
        raise ValueError("Named CPU and actual runtime PID required.")
    if args.runtime_pid != server["runtime_pid"] or args.cpu_name != server["cpu_name"]:
        raise ValueError("Operational process/CPU differs from serving attestation.")
    destination = output / f"operational-{args.arm}-{args.seed}.json"
    if destination.exists():
        raise ValueError("Operational evidence is immutable; use a newly authorized attempt after failure.")
    from .continual_fuzzer_study import RpcClient
    from privoke.v1 import runtime_pb2 as RP
    # Cold model construction is explicitly separate from network timing.
    start = time.perf_counter()
    encoder = FrozenPretrainedEncoder(eligibility["assets"]["directory"]) if args.arm == "pretrained" else None
    model = reconstructed(artifact, encoder)
    cold_load_ms = (time.perf_counter() - start) * 1000
    del model, encoder
    workload = rows(output / "train.jsonl")[:200]
    client = RpcClient(args.fuzzer_target, args.runtime_target, args.model_target)
    elapsed, memory = [], []
    write(destination, {"status": "started", "runtime_pid": args.runtime_pid})
    try:
        for i, row in enumerate([workload[0], *workload]):
            if client.snapshot(artifact["model_id"])["identity"] != identity:
                raise ValueError("Operational model identity changed before request.")
            request_id = f"operational-{args.arm}-{args.seed}-{i}"
            request = RP.AnalyzePromptRequest(text=row["text"], source="pretrained-operational", request_id=request_id,
                semantic_model_id=artifact["model_id"], layers=[RP.DETECTION_LAYER_SEMANTIC])
            start = time.perf_counter()
            response = client.runtime.AnalyzePrompt(request, timeout=120)
            duration = (time.perf_counter() - start) * 1000
            validate_response(response, request_id, identity, args.arm == "pretrained")
            if client.snapshot(artifact["model_id"])["identity"] != identity:
                raise ValueError("Operational model identity changed after request.")
            memory.append(process_memory(args.runtime_pid))
            if i:
                elapsed.append(duration)
        record = {"status": "complete", "identity": identity, "runtime_pid": args.runtime_pid,
            "cpu_name": args.cpu_name, "platform": platform.platform(), "encoder_threads": 1,
            "workload_sha256": sha256(canonical_json([r["id"] for r in workload]).encode()),
            "transport": "actual loopback gRPC; snapshot requests excluded from latency", "measured_requests": len(elapsed),
            "warmup_requests": 1, "latency_ms": elapsed, "warm_p95_ms": float(np.percentile(elapsed, 95)),
            "maximum_observed_RSS_bytes": max(m["rss_bytes"] for m in memory),
            "peak_runtime_RSS_bytes": max(m["peak_rss_bytes"] for m in memory),
            "offline_cold_model_construction_ms": cold_load_ms,
            "cold_load_scope": "separate local model construction; does not measure server startup or cold RPC",
            "selection_commitment_sha256": sha(output / "selection-commitment.json")}
        record["operational_gate_pass"] = record["warm_p95_ms"] <= 500 and record["peak_runtime_RSS_bytes"] <= 1073741824
        write(destination, record)
    except Exception as exc:
        write(destination, {"status": "failed", "error": str(exc), "completed_requests": len(elapsed)})
        raise
    finally:
        client.close()


def report(args):
    output = permitted(args.output)
    selection_barrier(output)
    pairs, files = {}, {}
    for seed in SEEDS:
        endpoints = {}
        for arm in ARMS:
            path = output / f"assessment-{arm}-{seed}.json"
            endpoint = read(path)
            if endpoint.get("status") != "complete" or endpoint.get("runtime_errors") != 0 or len(endpoint["predictions"]) != 160:
                raise ValueError("All six complete error-free endpoints required; retain failures.")
            if endpoint["selection_commitment_sha256"] != sha(output / "selection-commitment.json"):
                raise ValueError("Endpoint selection commitment changed.")
            endpoints[arm] = endpoint["predictions"]
            files[path.name] = sha(path)
        pairs[str(seed)] = paired_qualification(endpoints["random"], endpoints["pretrained"])
    operational_records = []
    for arm in ARMS:
        for seed in SEEDS:
            path = output / f"operational-{arm}-{seed}.json"
            if path.exists():
                record = read(path)
                if record.get("status") == "complete":
                    operational_records.append(record)
                    files[path.name] = sha(path)
    operational_clear = len(operational_records) == 6 and all(r.get("operational_gate_pass") for r in operational_records)
    primary = sum(p["both_primary_gains"] for p in pairs.values()) >= 2
    vetoes = all(p["veto_clear"] for p in pairs.values())
    secondary_records = {}
    for tag in ("baseline", *(f"{arm}-{seed}" for arm in ARMS for seed in SEEDS)):
        path = output / f"secondary-{tag}.json"
        if path.exists():
            record = read(path)
            secondary_records[tag] = {"status": record["status"], "endpoints": {name: data["summary"] for name, data in record.get("endpoints", {}).items()}}
            files[path.name] = sha(path)
    write(output / "summary.json", {"source_revision": read(output / "freeze.json")["source_revision"],
        "paired_seeds": pairs, "same_seed_primary_gate_pass": primary, "all_seed_vetoes_clear": vetoes,
        "operational_gate_pass": operational_clear, "engineering_qualified": primary and vetoes and operational_clear,
        "automatic_promotion": False, "files": files, "limitations": SETTINGS["limitations"],
        "secondary_regression": secondary_records, "secondary_complete": len(secondary_records) == 7 and all(r["status"] == "complete" for r in secondary_records.values()),
        "scope": "prospective assistant-provisional synthetic family transfer; historical fixture category semantics differ"})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    sub = parser.add_subparsers(dest="phase", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--resource", type=Path, default=RESOURCE)
    prep.add_argument("--assets", type=Path, default=ASSETS)
    prep.add_argument("--development", type=Path, default=ROOT / "evaluation/results/locked-public/development.jsonl")
    prep.add_argument("--exclusion-index", type=Path, default=ROOT / "evaluation/results/external_pii_20261004_prepared_v3/exclusion-index.json")
    locked = sub.add_parser("freeze")
    locked.add_argument("--review-receipt", type=Path, required=True)
    sub.add_parser("fit")
    evaluation = sub.add_parser("evaluate")
    evaluation.add_argument("--arm", choices=ARMS, required=True)
    evaluation.add_argument("--seed", type=int, choices=SEEDS, required=True)
    evaluation.add_argument("--runtime-target", default="127.0.0.1:50054")
    evaluation.add_argument("--model-target", default="127.0.0.1:50051")
    evaluation.add_argument("--fuzzer-target", default="127.0.0.1:50053")
    evaluation.add_argument("--server-manifest", type=Path, required=True)
    operation = sub.add_parser("operational")
    operation.add_argument("--arm", choices=ARMS, required=True)
    operation.add_argument("--seed", type=int, choices=SEEDS, required=True)
    operation.add_argument("--runtime-target", default="127.0.0.1:50054")
    operation.add_argument("--model-target", default="127.0.0.1:50051")
    operation.add_argument("--fuzzer-target", default="127.0.0.1:50053")
    operation.add_argument("--runtime-pid", type=int, required=True)
    operation.add_argument("--cpu-name", required=True)
    operation.add_argument("--server-manifest", type=Path, required=True)
    sub.add_parser("report")
    guard = sub.add_parser("secondary")
    guard.add_argument("--arm", choices=("baseline", *ARMS), required=True)
    guard.add_argument("--seed", type=int, choices=SEEDS, default=42)
    guard.add_argument("--runtime-target", default="127.0.0.1:50054")
    guard.add_argument("--model-target", default="127.0.0.1:50051")
    guard.add_argument("--fuzzer-target", default="127.0.0.1:50053")
    guard.add_argument("--server-manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    os.environ.setdefault("TEMP", str(ASSETS / "tmp")); os.environ.setdefault("TMP", str(ASSETS / "tmp"))
    {"prepare": prepare, "freeze": freeze, "fit": fit, "evaluate": evaluate, "operational": operational,
     "secondary": secondary, "report": report}[args.phase](args)
    return 0
