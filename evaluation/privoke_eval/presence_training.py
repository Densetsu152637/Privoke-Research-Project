"""Train and serialize bounded sparse annotation-presence profiles."""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from typing import Mapping, Sequence

import numpy as np
from sklearn.exceptions import ConvergenceWarning
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion

from privoke_model.artifact import artifact_checksum, float32, validate_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.presence import (
    ARITHMETIC,
    BLOCK_SIZE,
    NORMALIZATION,
    PRESENCE_ARCHITECTURE,
    PRESENCE_TASK,
    PROFILE_MAX_FEATURES,
    TOKEN_PATTERN,
    SparsePresenceModel,
    presence_tensor_shapes,
)
from privoke_model.training_data import training_text_key

C_VALUES = (0.1, 1.0, 10.0)
SEED = 7102026
RECALL_FLOOR = 0.90


def make_vectorizer(profile: str) -> FeatureUnion:
    """Build the protocol-fixed word/character TF-IDF branches for a profile."""
    if profile not in PROFILE_MAX_FEATURES:
        raise ValueError(f"Unknown sparse presence profile: {profile!r}.")
    common = {"min_df": 2, "max_features": PROFILE_MAX_FEATURES[profile],
              "lowercase": False, "sublinear_tf": True, "use_idf": True,
              "smooth_idf": True, "norm": "l2", "dtype": np.float64}
    word = TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                           token_pattern=TOKEN_PATTERN, **common)
    char = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), **common)
    return FeatureUnion([("word", word), ("char", char)], n_jobs=1)


def _config(vectorizer: FeatureUnion, profile: str, threshold: float) -> dict:
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("Presence threshold must be finite and within [0, 1].")
    branches = {}
    for name, branch in vectorizer.transformer_list:
        features = [str(feature) for feature in branch.get_feature_names_out()]
        entry = {"analyzer": name, "ngram_range": [1, 2] if name == "word" else [3, 5],
                 "max_features": PROFILE_MAX_FEATURES[profile], "features": features,
                 "sublinear_tf": True, "use_idf": True, "smooth_idf": True,
                 "norm": "l2", "lowercase": False}
        if name == "word":
            entry["token_pattern"] = TOKEN_PATTERN
        branches[name] = entry
    return {"task": PRESENCE_TASK, "profile": profile, "threshold": float(threshold),
            "normalization": NORMALIZATION, "column_order": ["word", "char"],
            "coefficient_block_size": BLOCK_SIZE, "branches": branches}


def build_artifact(vectorizer: FeatureUnion, estimator: LogisticRegression, profile: str,
                   threshold: float, metadata: Mapping[str, str]) -> dict:
    """Export a sklearn fit as a validated, float32 runtime artifact."""
    if list(estimator.classes_) != [0, 1]:
        raise ValueError("Presence estimator must have ABSENT/PRESENT classes [0, 1].")
    config = _config(vectorizer, profile, threshold)
    idf = {}
    feature_count = 0
    for name, branch in vectorizer.transformer_list:
        values = [float32(value) for value in branch.idf_]
        features = config["branches"][name]["features"]
        if len(values) != len(features):
            raise ValueError(f"{name} vocabulary and IDF sizes differ.")
        idf[f"features.{name}.idf"] = values
        feature_count += len(values)
    coefficients = [float32(value) for value in estimator.coef_.ravel()]
    if len(coefficients) != feature_count:
        raise ValueError("Coefficient count differs from ordered word/char columns.")
    values = dict(idf)
    for start in range(0, feature_count, BLOCK_SIZE):
        block = coefficients[start:start + BLOCK_SIZE]
        values[f"head.presence.weight.{start // BLOCK_SIZE:03d}"] = block
    values["head.presence.bias"] = [float32(estimator.intercept_.ravel()[0])]
    shapes = presence_tensor_shapes(config)
    parameters = {name: {"shape": list(shapes[name]), "values": values[name],
                         "trainable": name.startswith("head.presence.")}
                  for name in shapes}
    record = {
        "schema_version": 1,
        "model_id": f"privoke-presence-{profile}",
        "version": "v1.0.0",
        "generated_at_unix": int(time.time()),
        "architecture": PRESENCE_ARCHITECTURE,
        "config": config,
        "parameters": parameters,
        "metadata": {str(key): str(value) for key, value in metadata.items()},
    }
    record["checksum"] = artifact_checksum(record)
    validate_artifact(record)
    return record


def serialized_runtime_model(artifact: Mapping) -> SparsePresenceModel:
    """Round-trip the artifact JSON before using the shared runtime implementation."""
    payload = json.loads(json.dumps(artifact, ensure_ascii=False, allow_nan=False))
    return SparsePresenceModel.from_artifact(payload)


def runtime_probabilities(model: SparsePresenceModel, rows: Sequence[Mapping]) -> list[float]:
    result = [model.predict_probability(row["text"]) for row in rows]
    if not all(math.isfinite(value) and 0.0 <= value <= 1.0 for value in result):
        raise ValueError("Shared presence inference returned a non-finite/out-of-range probability.")
    return result


def binary_metrics(labels: Sequence[bool], probabilities: Sequence[float], threshold: float) -> dict:
    if len(labels) != len(probabilities) or not labels:
        raise ValueError("Presence metrics require aligned, nonempty labels and probabilities.")
    if any(type(label) is not bool for label in labels):
        raise ValueError("Presence ground-truth labels must be strict booleans.")
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("Presence threshold must be finite and in [0, 1].")
    tp = tn = fp = fn = 0
    for label, probability in zip(labels, probabilities):
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("Presence probabilities must be finite and in [0, 1].")
        prediction = probability >= threshold
        if label and prediction:
            tp += 1
        elif label:
            fn += 1
        elif prediction:
            fp += 1
        else:
            tn += 1
    positives, negatives = tp + fn, tn + fp
    recall = tp / positives if positives else None
    specificity = tn / negatives if negatives else None
    balanced = ((recall + specificity) / 2 if recall is not None and specificity is not None else None)
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "positive_examples": positives, "absent_examples": negatives,
            "recall": recall, "specificity": specificity, "balanced_accuracy": balanced}


def select_threshold(labels: Sequence[bool], probabilities: Sequence[float],
                     recall_floor: float = RECALL_FLOOR) -> tuple[float, dict]:
    """Maximize specificity at the recall floor using runtime probabilities."""
    if not 0.0 < recall_floor <= 1.0:
        raise ValueError("Recall floor must be in (0, 1].")
    candidates = sorted({0.0, 1.0, *probabilities})
    eligible = []
    for threshold in candidates:
        metrics = binary_metrics(labels, probabilities, threshold)
        if metrics["recall"] is not None and metrics["recall"] >= recall_floor:
            eligible.append((metrics["specificity"], metrics["recall"], threshold, metrics))
    if not eligible:
        raise ValueError("No threshold meets the validation recall floor.")
    specificity, recall, threshold, metrics = max(eligible, key=lambda item: item[:3])
    return float(threshold), metrics


def source_family(group_id: str) -> str:
    family = group_id.split(":", 1)[0]
    if not family:
        raise ValueError("Source group has no family prefix.")
    return family


def metrics_by_family(rows: Sequence[Mapping], probabilities: Sequence[float], threshold: float) -> dict:
    if len(rows) != len(probabilities):
        raise ValueError("Source-family rows and probabilities are not aligned.")
    grouped = defaultdict(lambda: {"labels": [], "probabilities": []})
    for row, probability in zip(rows, probabilities):
        family = source_family(row["group_id"])
        grouped[family]["labels"].append(row["expected_has_pii"])
        grouped[family]["probabilities"].append(probability)
    return {family: {"rows": len(item["labels"]), **binary_metrics(item["labels"], item["probabilities"], threshold)}
            for family, item in sorted(grouped.items())}


def artifact_identity(artifact: Mapping) -> dict:
    parameters = {name: tensor["values"] for name, tensor in artifact["parameters"].items()}
    shapes = {name: tensor["shape"] for name, tensor in artifact["parameters"].items()}
    return {"model_id": artifact["model_id"], "model_version": artifact["version"],
            "artifact_checksum": artifact["checksum"],
            "parameter_fingerprint": parameter_fingerprint(parameters, shapes),
            "threshold": artifact["config"]["threshold"]}
