"""Train-only accelerated offline cells; fixed final checkpoints, never selection.

The caller freezes TRAIN and settings before calling ``fit_cell``. Tiny inputs
must already have 256 positions. Scratch preserves its native batch of 16 and
64/96/128 contexts, rejecting overlength rows. Sparse full fitting has a native
solver budget, not a minibatch-equivalent dose. Completed cells resume only when
all commitments and output hashes match; interrupted cells require a fresh
output directory. No assessment data, checkpoint ranking or threshold search.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import random
from typing import Mapping

SCHEMA = "accelerated-offline-fit-v1"
SURFACES = {"tiny", "sparse_presence", "scratch_presence", "minilm", "random_control"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _path(value):
    original = Path(value).absolute()
    if any(parent.is_symlink() for parent in (original, *original.parents)):
        raise ValueError("Input symlinks are forbidden.")
    path = original.resolve()
    if any(any(term in part.casefold() for term in ("assessment", "protected", "final")) for part in path.parts):
        raise ValueError("Assessment/protected-final input paths are forbidden before access.")
    if path.is_symlink():
        raise ValueError("Input symlinks are forbidden.")
    return path


def _read_ref(ref):
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
        raise ValueError("Input references require exactly path and sha256.")
    path = _path(ref["path"])
    raw = path.read_bytes()
    if _digest(raw) != ref["sha256"]:
        raise ValueError("Input hash commitment changed.")
    return raw


def _write(path, value):
    raw = _canonical(value) + b"\n"
    with path.open("xb") as handle:
        handle.write(raw)
    return {"path": str(path.resolve()), "sha256": _digest(raw)}


def _reference(path):
    return {"path": str(path.resolve()), "sha256": _digest(path.read_bytes())}


def _validate(cell, inputs):
    if cell.get("kind") != "offline" or cell.get("surface") not in SURFACES:
        raise ValueError("Explicit supported offline surface required.")
    if cell.get("scope") not in {"heads", "full_encoder"}:
        raise ValueError("Explicit heads/full_encoder scope required.")
    if type(cell.get("seed")) is not int or cell["seed"] not in {42, 43, 44}:
        raise ValueError("Frozen study seeds are 42,43,44.")
    if not isinstance(cell.get("id"), str) or not cell["id"]:
        raise ValueError("Explicit cell id required.")
    if not {"train", "assets", "source_revision"} <= set(inputs) or set(inputs) - {"train", "base_artifact", "assets", "source_revision"}:
        raise ValueError("Only explicit TRAIN, base artifact, assets and source revision are allowed.")
    if not isinstance(inputs["assets"], dict) or not isinstance(inputs["source_revision"], str):
        raise ValueError("Invalid assets or source revision.")
    if cell["surface"] in {"scratch_presence", "sparse_presence", "minilm"} and "base_artifact" in inputs:
        raise ValueError("Generated-initializer surfaces do not accept unrelated base artifacts.")
    if not isinstance(cell.get("profile"), str):
        raise ValueError("Explicit profile required.")
    if cell["surface"] != "sparse_presence":
        native_batch = 16 if cell["surface"] == "scratch_presence" else 32
        if cell.get("optimizer_steps") != 96 or cell.get("batch_size") != native_batch:
            raise ValueError("Neural cell must use frozen96-step native batch dose.")
    if cell["surface"] in {"minilm", "random_control", "sparse_presence"} and cell["scope"] != "heads":
        raise ValueError("This surface does not support full_encoder fitting.")
    objective = "binary_presence" if cell["surface"] in {"sparse_presence", "scratch_presence"} else "contextual"
    if cell.get("objective") != objective:
        raise ValueError("Binary and contextual targets must be explicit and separate.")


def _rows(raw, objective):
    rows = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if not rows or len({r["id"] for r in rows}) != len(rows):
        raise ValueError("TRAIN requires nonempty unique row ids.")
    for row in rows:
        if type(row.get("text")) is not str:
            raise ValueError("TRAIN text requires strings.")
        if objective == "binary_presence":
            if type(row.get("present")) is not bool:
                raise ValueError("Binary TRAIN requires explicit bool present; no contextual conversion.")
        elif not isinstance(row.get("classification"), dict):
            raise ValueError("Contextual TRAIN requires explicit classification.")
    return rows


def _schedule(rows, seed, steps, batch):
    rng, stream = random.Random(seed), []
    while len(stream) < steps * batch:
        order = list(range(len(rows)))
        rng.shuffle(order)
        stream.extend(order)
    return [stream[i * batch:(i + 1) * batch] for i in range(steps)]


def _admit(texts, maximum):
    from src.detection.preprocessing import normalize_text
    from src.transformer_encoder import TOKEN_PATTERN
    counts = [len(TOKEN_PATTERN.findall(normalize_text(t).lower())) + 1 for t in texts]
    if max(counts) > maximum:
        raise ValueError(f"TRAIN exceeds native {maximum}-token context; truncation is forbidden.")
    return max(counts)


def _arrays(artifact):
    import numpy as np
    return {n: np.asarray(t["values"], dtype=np.float32).reshape(t["shape"]).copy()
            for n, t in artifact["parameters"].items()}


def _audit(before, after, allowed, scope):
    import numpy as np
    changed = sorted(n for n in before if not np.array_equal(before[n], after[n]))
    if set(changed) - set(allowed):
        raise ValueError("Fit changed tensors outside declared scope.")
    encoder_changed = any(not n.startswith("head.") for n in changed)
    if scope == "full_encoder" and not encoder_changed:
        raise ValueError("Full encoder fit did not change encoder tensors.")
    return {"allowed_names": sorted(allowed), "changed_names": changed,
            "encoder_unchanged": not encoder_changed}


def _replace_artifact(base, arrays, cell):
    from privoke_model.artifact import artifact_checksum, validate_artifact
    result = copy.deepcopy(base)
    for name, value in arrays.items():
        result["parameters"][name]["values"] = value.ravel().tolist()
        result["parameters"][name]["trainable"] = cell["scope"] == "full_encoder" or name.startswith("head.")
    from privoke_model.contextual_training import STRATEGY_KEY, FULL_ENCODER_STRATEGY, OPTIMIZER_KEY, OBJECTIVE_KEY
    metadata = result.setdefault("metadata", {})
    for key in (STRATEGY_KEY, OPTIMIZER_KEY, OBJECTIVE_KEY):
        metadata.pop(key, None)
    if cell["scope"] == "full_encoder":
        metadata[STRATEGY_KEY] = FULL_ENCODER_STRATEGY
    metadata["offline_optimizer"] = "Adam"
    result["version"] = "accelerated-offline-" + str(cell["seed"])
    result.setdefault("metadata", {}).update({"accelerated_cell": cell["id"], "checkpoint_selection": "fixed_final_only"})
    result["checksum"] = artifact_checksum({k: v for k, v in result.items() if k != "checksum"})
    validate_artifact(result)
    return result


def _torch_fit(cell, rows, base, output, commitment):
    import numpy as np
    import torch
    from privoke_eval.in_house_transformer_training import ContextualTarget, InHouseTransformerTrainer, TrainingOptions
    from src.model import ModelConfig, TinyTransformerModel
    from src.detection.preprocessing import normalize_text
    mode = "head_only" if cell["scope"] == "heads" else "end_to_end"
    if cell["optimizer"] != "Adam":
        raise ValueError("Torch fitters require explicit Adam.")
    if cell["surface"] == "tiny":
        if base["model_id"] != cell["model_id"] or base["config"]["max_tokens"] != 256:
            raise ValueError("Tiny requires exact model id and prepared256-capacity baseline.")
        before = _arrays(base)
        trainer = InHouseTransformerTrainer(ModelConfig.from_mapping(base["config"]), before, TrainingOptions(mode=mode))
        target = lambda r: ContextualTarget(r["classification"]["sensitivity"], r["classification"]["visibility"], tuple(r["classification"]["categories"]))
    else:
        from privoke_eval.in_house_presence_training import create_paired_trainers
        pair = create_paired_trainers(cell["profile"])
        trainer = pair[0 if mode == "head_only" else 1]
        if trainer.model_id != cell["model_id"]:
            raise ValueError("Scratch profile/mode and model id differ.")
        before = trainer.export_parameters()
        target = lambda r: r["present"]
    maximum = trainer.config.max_tokens if cell["surface"] == "tiny" else trainer.config["max_tokens"]
    admission = _admit([r["text"] for r in rows], maximum)
    schedule = _schedule(rows, cell["seed"], 96, cell["batch_size"])
    allowed = [n for n, p in trainer.parameters.items() if p.requires_grad]
    if cell["surface"] == "tiny":
        baseline = _replace_artifact(base, before, cell)
    else:
        # Release artifacts reject zero steps; preserve an honest offline-only
        # initialization snapshot without inventing release provenance.
        baseline = {"schema_version": "accelerated-initialization-v1", "model_id": trainer.model_id, "config": dict(trainer.config), "initialization_sha256": trainer.initialization_sha256, "training_steps": 0, "parameters": {n: {"shape": list(a.shape), "values": a.ravel().tolist(), "trainable": n in allowed} for n, a in before.items()}}
    baseline_ref = _write(output / "baseline-artifact.json", baseline)
    losses = []
    for indices in schedule:
        batch = [rows[i] for i in indices]
        result = trainer.step([r["text"] for r in batch], [target(r) for r in batch])
        losses.append(float(result["loss"] if isinstance(result, Mapping) else result.loss))
    after = trainer.export_parameters()
    if cell["surface"] == "tiny":
        final = _replace_artifact(base, after, cell)
        runtime = TinyTransformerModel.from_artifact(final)
        error = 0.
        for text in ("", "Synthetic alpha", rows[0]["text"]):
            ids, mask = trainer.tensor_batch([text])
            logits, pred = trainer.logits(ids, mask), runtime.predict(normalize_text(text))
            for task, expected in (("sensitivity", pred.sensitivity_probabilities), ("visibility", pred.visibility_probabilities), ("category", pred.category_probabilities)):
                actual = (torch.sigmoid(logits[task]) if task == "category" else torch.softmax(logits[task], -1))[0].detach().numpy()
                error = max(error, float(np.max(np.abs(actual - expected))))
                if not np.allclose(actual, expected, atol=2e-5, rtol=2e-5):
                    raise ValueError("Tiny exported inference parity failed.")
    else:
        from privoke_eval.in_house_study_fit import _check_scratch_export
        final = trainer.build_artifact(source_revision=commitment["source_revision"], study_plan_sha256=commitment["sha256"], prepared_manifest_sha256=commitment["sha256"], trainer_contract_sha256=commitment["sha256"], checkpoint_epoch=1, generated_at_unix=1)
        from privoke_model.artifact import artifact_checksum
        final["checksum"] = artifact_checksum({k: v for k, v in final.items() if k != "checksum"})
        error = _check_scratch_export(trainer, final)["parity_max_abs_logit_error"]
    optimizer_state = trainer.optimizer_state()
    if any(int(state["step"].item()) != 96 for state in optimizer_state["state"].values()):
        raise ValueError("Actual optimizer state does not prove96 completed steps.")
    torch.save(optimizer_state, output / "optimizer-state.pt")
    evidence = _write(output / "step-order.json", {"indices": schedule, "row_ids": [[rows[i]["id"] for i in b] for b in schedule], "losses": losses})
    return baseline, final, {"optimizer_steps": 96, "presentations": 96 * cell["batch_size"], "unique_rows": len(set(i for b in schedule for i in b)), "solver_budget": None}, _audit(before, after, allowed, cell["scope"]), {"step_order": evidence, "optimizer_state": _reference(output / "optimizer-state.pt"), "maximum_training_tokens": admission, "maximum_parity_error": error, "learning_rate": .001, "weight_decay": .0001, "gradient_norm_clip": 1.}


def _sparse_fit(cell, rows, output):
    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from privoke_eval.presence_training import make_vectorizer, build_artifact, serialized_runtime_model, runtime_probabilities
    from src.detection.preprocessing import normalize_text
    budget = cell.get("solver_budget")
    if not isinstance(budget, dict) or budget != {"solver": "lbfgs", "max_iter": 1000, "tol": 1e-4, "C": 1.0, "class_weight": "balanced"}:
        raise ValueError("Sparse full fit requires maintained frozen lbfgs1000/tol1e-4/C1/balanced solver budget.")
    if cell["optimizer"] != "lbfgs" or cell.get("optimizer_steps") is not None:
        raise ValueError("Sparse solver budget must not be reported as96 minibatch steps.")
    vectorizer = make_vectorizer(cell["profile"])
    texts = [normalize_text(r["text"]) for r in rows]
    features = vectorizer.fit_transform(texts)
    labels = np.asarray([int(r["present"]) for r in rows])
    estimator = LogisticRegression(random_state=cell["seed"], **budget)
    estimator.classes_ = np.asarray([0, 1])
    estimator.coef_ = np.zeros((1, features.shape[1]))
    estimator.intercept_ = np.zeros(1)
    baseline = build_artifact(vectorizer, estimator, cell["profile"], .5, {"baseline": "zero_head_on_train_fitted_feature_space"})
    _write(output / "baseline-artifact.json", baseline)
    import warnings
    from sklearn.exceptions import ConvergenceWarning
    with warnings.catch_warnings(record=True) as observed_warnings:
        warnings.simplefilter("always", ConvergenceWarning)
        estimator.fit(features, labels)
    solver_warnings = [str(w.message) for w in observed_warnings]
    if any(issubclass(w.category, ConvergenceWarning) for w in observed_warnings):
        _write(output / "solver-failure.json", {"status": "failed_convergence", "solver_budget": budget, "n_iter": [int(n) for n in estimator.n_iter_], "warnings": solver_warnings})
        raise ValueError("Sparse solver did not converge within frozen budget; no budget extension permitted.")
    final = build_artifact(vectorizer, estimator, cell["profile"], .5, {"checkpoint_selection": "fixed_final_only"})
    if final["model_id"] != cell["model_id"]:
        raise ValueError("Sparse profile and model id differ.")
    actual = np.asarray(runtime_probabilities(serialized_runtime_model(final), [{"text": t} for t in texts]))
    expected = estimator.predict_proba(features)[:, 1]
    if not np.allclose(actual, expected, atol=2e-5, rtol=2e-5):
        raise ValueError("Sparse exported inference parity failed.")
    names = sorted(n for n in final["parameters"] if n.startswith("head."))
    evidence = _write(output / "solver-state.json", {"solver_budget": budget, "n_iter": [int(n) for n in estimator.n_iter_], "feature_rows": len(rows), "feature_columns": features.shape[1], "warnings": solver_warnings, "converged": True})
    return baseline, final, {"optimizer_steps": None, "presentations": None, "unique_rows": len(rows), "solver_budget": budget}, {"allowed_names": names, "changed_names": [n for n in names if baseline["parameters"][n]["values"] != final["parameters"][n]["values"]], "encoder_unchanged": True}, {"solver_state": evidence, "feature_fit_scope": "TRAIN_only", "maximum_parity_error": float(np.max(np.abs(actual - expected)))}


def _resume_receipt(receipt, *, cell, inputs, sources, commitment, output):
    """Validate completed identity and every required output reference, fail closed."""
    expected_identity = {"schema_version": SCHEMA, "status": "complete", "cell_id": cell["id"], "settings": cell, "seed": cell["seed"], "source_revision": inputs["source_revision"], "sources": sources, "input_commitment_sha256": commitment, "adapter_source_sha256": _digest(Path(__file__).read_bytes())}
    if not isinstance(receipt, dict) or any(receipt.get(k) != v for k, v in expected_identity.items()):
        raise ValueError("Completed cell schema or identity mismatch.")
    names = {"baseline_artifact": "baseline-artifact.json", "final_artifact": "final-artifact.json"}
    surface = cell["surface"]
    evidence_names = ({"solver_state": "solver-state.json"} if surface == "sparse_presence" else
                      {"step_order": "step-order.json", "optimizer_state": "optimizer-state.pt"} if surface in {"tiny", "scratch_presence"} else
                      {"step_order": "step-order.json", "optimizer_state": "optimizer-state.json", "feature_construction": "feature-construction.json", "baseline_generated_before_fit": "baseline-artifact.json"})
    evidence = receipt.get("evidence")
    metrics = receipt.get("evidence_metrics")
    if not isinstance(evidence, dict) or set(evidence) != set(evidence_names) or not isinstance(metrics, dict):
        raise ValueError("Completed cell required evidence references or separate metrics missing.")
    refs = [(receipt.get(key), name) for key, name in names.items()]
    refs.extend((evidence[key], name) for key, name in evidence_names.items())
    for ref, name in refs:
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or type(ref["path"]) is not str or type(ref["sha256"]) is not str:
            raise ValueError("Completed cell output reference is malformed.")
        expected = output / name
        actual = Path(ref["path"])
        if (not actual.is_absolute() or actual.is_symlink() or actual.resolve() != expected
                or len(ref["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in ref["sha256"])):
            raise ValueError("Completed cell output reference escapes expected cell path or hash format.")
        if not expected.is_file() or _digest(expected.read_bytes()) != ref["sha256"]:
            raise ValueError("Completed cell output hash changed or file missing.")
    step = None if surface == "sparse_presence" else 96
    if receipt.get("checkpoints") != [{"step": step, "artifact": receipt["final_artifact"]}]:
        raise ValueError("Completed fixed-final checkpoint reference mismatch.")
    return receipt


def fit_cell(cell: dict, inputs: dict, output: Path) -> dict:
    """Fit one frozen TRAIN-only cell into an exclusive directory, or verify resume.

    Binary rows use ``present: bool``. Contextual rows require ``classification``.
    No partial-run optimizer resume is allowed: a failed cell remains inspectable
    and must be rerun into a new exclusive directory. No files are overwritten.
    """
    _validate(cell, inputs)
    root = Path(__file__).resolve().parents[2]
    source_paths = [Path(__file__), *(Path(__file__).parent / name for name in ("in_house_transformer_training.py", "in_house_presence_training.py", "presence_training.py", "pretrained_context_study.py", "in_house_study_fit.py")), *(root / name for name in ("models/generate_baseline.py", "extension/client-runtime/src/model.py", "extension/client-runtime/src/transformer_encoder.py", "extension/client-runtime/src/pretrained_context.py", "extension/client-runtime/src/detection/preprocessing.py", "shared/python/privoke_model/artifact.py", "shared/python/privoke_model/contextual_training.py", "shared/python/privoke_model/scratch_presence.py", "shared/python/privoke_model/presence.py", "shared/python/privoke_model/pretrained_context.py"))]
    sources = {str(p): _digest(p.read_bytes()) for p in source_paths}
    commitment = _digest(_canonical({"cell": cell, "inputs": inputs, "sources": sources}))
    raw = _read_ref(inputs["train"])
    base = json.loads(_read_ref(inputs["base_artifact"])) if "base_artifact" in inputs else None
    if cell["surface"] in {"tiny", "random_control"} and base is None:
        raise ValueError("This representation requires an explicit prepared baseline.")
    for ref in inputs["assets"].values():
        _read_ref(ref)
    rows = _rows(raw, cell["objective"])
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    lock = output / ".fit.lock"
    with lock.open("x", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    try:
        receipt_path = output / "fit-receipt.json"
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_bytes())
            return _resume_receipt(receipt, cell=cell, inputs=inputs, sources=sources, commitment=commitment, output=output)
        if any(p != lock for p in output.iterdir()):
            raise ValueError("Interrupted/nonempty output requires a fresh cell directory.")
        import torch
        import numpy as np
        torch.set_num_threads(1)
        torch.use_deterministic_algorithms(True)
        torch.manual_seed(cell["seed"])
        if cell["surface"] == "sparse_presence":
            result = _sparse_fit(cell, rows, output)
        elif cell["surface"] in {"tiny", "scratch_presence"}:
            result = _torch_fit(cell, rows, base, output, {"sha256": commitment, "source_revision": inputs["source_revision"]})
        else:
            result = _frozen_fit(cell, rows, base, inputs, output)
        baseline, final, dose, audit, evidence = result
        evidence_metrics = {k: v for k, v in evidence.items() if not isinstance(v, dict)}
        evidence = {k: v for k, v in evidence.items() if isinstance(v, dict)}
        before_ref = _reference(output / "baseline-artifact.json")
        final_ref = _write(output / "final-artifact.json", final)
        receipt = {"schema_version": SCHEMA, "status": "complete", "cell_id": cell["id"], "input_commitment_sha256": commitment, "source_revision": inputs["source_revision"], "baseline_artifact": before_ref, "final_artifact": final_ref, "checkpoints": [{"step": dose["optimizer_steps"], "artifact": final_ref}], "dose": dose, "tensor_audit": audit, "seed": cell["seed"], "settings": cell, "evidence": evidence, "evidence_metrics": evidence_metrics, "dependencies": {"numpy": np.__version__, "torch": torch.__version__}, "adapter_source_sha256": _digest(Path(__file__).read_bytes()), "sources": sources}
        _write(receipt_path, receipt)
        return receipt
    finally:
        lock.unlink()


def _frozen_fit(cell, rows, base, inputs, output):
    import numpy as np
    from privoke_eval.pretrained_context_study import initialize, targets, probabilities, loss_gradients, Adam
    from privoke_model.pretrained_context import build_head_artifact, BACKBONE_SHA256, TOKENIZER_SHA256
    from src.pretrained_context import FrozenPretrainedEncoder, PretrainedContextModel
    from src.model import TinyTransformerModel
    from src.detection.preprocessing import normalize_text
    if cell["optimizer"] != "numpy_float64_adam_coupled_l2_after_global_clip_v1":
        raise ValueError("Frozen heads require explicit source-native NumPy Adam.")
    texts = [r["text"] for r in rows]
    projection = None
    if cell["surface"] == "minilm":
        assets = inputs["assets"]
        if set(assets) != {"model.onnx", "tokenizer.json"} or assets["model.onnx"]["sha256"] != BACKBONE_SHA256 or assets["tokenizer.json"]["sha256"] != TOKENIZER_SHA256:
            raise ValueError("Official pinned MiniLM assets required.")
        directory = Path(assets["model.onnx"]["path"]).resolve().parent
        if Path(assets["tokenizer.json"]["path"]).resolve().parent != directory:
            raise ValueError("Encoder assets must share directory.")
        encoder = FrozenPretrainedEncoder(directory, max_tokens=256)
        counts = [len(encoder._tokenizer.encode(normalize_text(t), add_special_tokens=True).ids) for t in texts]
        if max(counts) > 256:
            raise ValueError("MiniLM TRAIN exceeds256 tokens; truncation forbidden.")
        features = encoder.features(texts).astype(np.float64)
        feature_spec = {"representation": "official_masked_mean_l2_v1", "hidden_size": 384, "max_tokens": 256, "backbone_sha256": BACKBONE_SHA256, "tokenizer_sha256": TOKENIZER_SHA256}
        def artifact(parameters, training_steps):
            return build_head_artifact({n: a.astype(np.float32).ravel().tolist() for n, a in parameters.items()}, version="accelerated-frozen-heads", generated_at_unix=1, metadata={"checkpoint_selection": "fixed_final_only", "seed": str(cell["seed"])}, max_tokens=256)
    else:
        if base is None or base["config"]["max_tokens"] != 256:
            raise ValueError("Random representation control requires prepared256 Tiny baseline.")
        _admit(texts, 256)
        encoder = TinyTransformerModel.from_artifact(base)
        hidden = base["config"]["hidden_size"]
        # Projection belongs to the frozen representation, never the replicate
        # seed or labels. Both arms share384-dimensional head bytes and order.
        projection = np.random.default_rng(12102026).normal(0, 1 / np.sqrt(hidden), (hidden, 384)).astype(np.float32)
        features = np.stack([encoder.encode(normalize_text(t)) @ projection for t in texts]).astype(np.float32)
        norms = np.linalg.norm(features, axis=1, keepdims=True)
        if np.any(norms <= 0) or not np.isfinite(features).all():
            raise ValueError("Random representation cannot be L2-normalized.")
        features = (features / norms).astype(np.float64)
        feature_spec = {"representation": "frozen_Tiny_fixed_Gaussian_projection_l2_v1", "hidden_size": 384, "projection_seed": 12102026, "projection_dimensions": [hidden, 384], "projection_sha256": _digest(projection.tobytes()), "causal_scope": "representation_package_control"}
        def artifact(parameters, training_steps):
            return {"schema_version": "accelerated-random-control-v1", "version": f"accelerated-control-seed{cell['seed']}-step{training_steps}", "training_steps": training_steps, "seed": cell["seed"], "model_id": cell["model_id"], "base_artifact": inputs["base_artifact"], "feature_spec": feature_spec, "projection": projection.tolist(), "parameters": {n: {"shape": list(a.shape), "values": a.astype(np.float32).ravel().tolist(), "trainable": True} for n, a in parameters.items()}}
    parameters = initialize(384, cell["seed"])
    before = {n: a.copy() for n, a in parameters.items()}
    baseline = artifact(before, 0)
    baseline_ref = _write(output / "baseline-artifact.json", baseline)
    feature_ref = _write(output / "feature-construction.json", feature_spec)
    truth, optimizer = targets(rows), Adam(parameters)
    schedule = _schedule(rows, cell["seed"], 96, 32)
    losses = []
    for indices in schedule:
        batch_truth = {task: values[indices] for task, values in truth.items()}
        loss, gradients = loss_gradients(features[indices], batch_truth, parameters)
        optimizer.step(parameters, gradients)
        losses.append(loss)
    final = artifact(parameters, 96)
    # Independent float32 reconstruction from transported head values, using
    # the already frozen features. MiniLM additionally checks serving predict.
    reloaded = _arrays(final)
    expected = probabilities(features, parameters)
    actual = probabilities(features.astype(np.float32), reloaded)
    error = max(float(np.max(np.abs(expected[t] - actual[t]))) for t in expected)
    if error > 2e-5:
        raise ValueError("Frozen head artifact float32 inference parity failed.")
    if cell["surface"] == "minilm":
        runtime = PretrainedContextModel(final["config"], {n: t["values"] for n, t in final["parameters"].items()}, {n: t["shape"] for n, t in final["parameters"].items()}, encoder)
        pred = runtime.predict(normalize_text(texts[0]))
        for task, runtime_probs in (("sensitivity", pred.sensitivity_probabilities), ("visibility", pred.visibility_probabilities), ("category", pred.category_probabilities)):
            if not np.allclose(runtime_probs, expected[task][0], atol=2e-5, rtol=2e-5):
                raise ValueError("MiniLM exported runtime inference parity failed.")
        for ref in inputs["assets"].values():
            _read_ref(ref)
    order = _write(output / "step-order.json", {"indices": schedule, "row_ids": [[rows[i]["id"] for i in b] for b in schedule], "losses": losses})
    state = _write(output / "optimizer-state.json", {"step_count": optimizer.step_count, "m": {n: a.tolist() for n, a in optimizer.m.items()}, "v": {n: a.tolist() for n, a in optimizer.v.items()}})
    return baseline, final, {"optimizer_steps": 96, "presentations": 3072, "unique_rows": len(set(i for b in schedule for i in b)), "solver_budget": None}, _audit(before, parameters, parameters, "heads"), {"step_order": order, "optimizer_state": state, "feature_construction": feature_ref, "baseline_generated_before_fit": baseline_ref, "maximum_parity_error": error, "head_initialization_sha256": _digest(_canonical({n: a.tolist() for n, a in before.items()})), "learning_rate": .01, "weight_decay": .0001, "gradient_norm_clip": 1.}


def evaluate_cell_snapshot(snapshot_path: Path, rows: list[dict], layers: list[str], *, assets=None) -> list[dict]:
    """Evaluate only the semantic forward pass, preserving errors in denominator.

    This is an offline execution trace, not a protobuf transport assertion.
    ``assets`` uses the same pinned filename-to-reference mapping as fit inputs.
    """
    if layers != ["DETECTION_LAYER_SEMANTIC"]:
        raise ValueError("Exact nonempty semantic-only selection required before access.")
    import numpy as np
    from privoke_model.artifact import validate_artifact
    from privoke_model.fingerprint import parameter_fingerprint
    from src.detection.preprocessing import normalize_text
    from src.model import TinyTransformerModel
    from src.transformer_encoder import NumpyTransformerEncoder, EncoderConfig
    from src.pretrained_context import FrozenPretrainedEncoder, PretrainedContextModel
    from privoke_eval.pretrained_context_study import probabilities, classifications
    path = Path(snapshot_path).resolve()
    raw = path.read_bytes()
    snapshot = json.loads(raw)
    arrays = _arrays(snapshot)
    fingerprint = parameter_fingerprint({n: a.ravel().tolist() for n, a in arrays.items()}, {n: a.shape for n, a in arrays.items()})
    schema, architecture = snapshot["schema_version"], snapshot.get("architecture")
    if schema == "accelerated-initialization-v1":
        if type(snapshot.get("training_steps")) is not int or snapshot["training_steps"] != 0:
            raise ValueError("Initialization snapshot must honestly declare zero training steps.")
        version, training_steps = "initialization-zero-step", 0
    elif schema == "accelerated-random-control-v1":
        training_steps = snapshot.get("training_steps")
        if type(training_steps) is not int or training_steps not in {0, 96}:
            raise ValueError("Random control snapshot requires actual zero/96 training state.")
        version = snapshot.get("version")
        if snapshot.get("seed") not in {42, 43, 44} or version != f"accelerated-control-seed{snapshot['seed']}-step{training_steps}":
            raise ValueError("Random control version and training state disagree.")
    else:
        version = snapshot.get("version")
        if type(version) is not str or not version:
            raise ValueError("Snapshot requires explicit non-initialization version.")
        training_steps = snapshot.get("metadata", {}).get("training_steps")
    identity = {"requested_model_id": snapshot["model_id"], "used_model_id": snapshot["model_id"], "requested_version": version, "used_version": version, "snapshot_sha256": _digest(raw), "snapshot_checksum": snapshot.get("checksum"), "parameter_fingerprint": fingerprint, "snapshot_schema": snapshot["schema_version"], "training_steps": training_steps}
    schema, architecture = snapshot["schema_version"], snapshot.get("architecture")
    if schema == "accelerated-initialization-v1" or architecture == "privoke_scratch_presence_transformer_v1":
        if architecture:
            validate_artifact(snapshot)
        config = snapshot["config"]
        encoder = NumpyTransformerEncoder(EncoderConfig.from_mapping(config), {n: a for n, a in arrays.items() if not n.startswith("head.")})
        def predict(text):
            _admit([text], config["max_tokens"])
            pooled = encoder.encode(normalize_text(text))
            value = (pooled @ arrays["head.presence.weight"] + arrays["head.presence.bias"]).item()
            probability = float(1 / (1 + np.exp(-np.clip(np.float32(value), -30., 30.))))
            return {"present_probability": probability, "present": probability >= config["threshold"]}
    elif schema == "accelerated-random-control-v1":
        base = json.loads(_read_ref(snapshot["base_artifact"]))
        encoder = TinyTransformerModel.from_artifact(base)
        projection = np.asarray(snapshot["projection"], dtype=np.float32)
        if _digest(projection.tobytes()) != snapshot["feature_spec"]["projection_sha256"]:
            raise ValueError("Control projection commitment changed.")
        def predict(text):
            _admit([text], 256)
            pooled = encoder.encode(normalize_text(text)) @ projection
            pooled = pooled / np.linalg.norm(pooled)
            probs = probabilities(pooled[None, :], arrays)
            return {"classification": classifications(probs)[0], "probabilities": {k: v[0].tolist() for k, v in probs.items()}}
    elif architecture == "privoke_sparse_presence_v1":
        from privoke_eval.presence_training import serialized_runtime_model
        runtime = serialized_runtime_model(snapshot)
        def predict(text):
            probability = float(runtime.predict_probability(text))
            return {"present_probability": probability, "present": probability >= snapshot["config"]["threshold"]}
    else:
        validate_artifact(snapshot)
        if architecture == "privoke_pretrained_context_v1":
            if not assets:
                raise ValueError("MiniLM evaluation requires explicit pinned assets.")
            for ref in assets.values():
                _read_ref(ref)
            encoder = FrozenPretrainedEncoder(Path(assets["model.onnx"]["path"]).parent, max_tokens=256)
            runtime = PretrainedContextModel(snapshot["config"], {n: t["values"] for n, t in snapshot["parameters"].items()}, {n: t["shape"] for n, t in snapshot["parameters"].items()}, encoder)
        else:
            runtime = TinyTransformerModel.from_artifact(snapshot)
        def predict(text):
            if architecture != "privoke_pretrained_context_v1":
                _admit([text], snapshot["config"]["max_tokens"])
            pred = runtime.predict(normalize_text(text))
            return {"classification": {"sensitivity": pred.sensitivity, "visibility": pred.visibility, "categories": list(pred.categories)}, "probabilities": {"sensitivity": list(pred.sensitivity_probabilities), "visibility": list(pred.visibility_probabilities), "category": list(pred.category_probabilities)}}
    records = []
    for row in rows:
        try:
            prediction = predict(row["text"])
            records.append({"id": row["id"], **identity, **prediction, "status": "complete", "executed_layers": layers, "executions": [{"layer": layers[0], "status": "complete", "forward_count": 1}], "execution_mode": "offline_learned_forward_v1"})
        except Exception as exc:
            records.append({"id": row["id"], **identity, "status": "error", "error": str(exc), "executed_layers": [], "executions": [], "execution_mode": "offline_learned_forward_v1"})
    return records
