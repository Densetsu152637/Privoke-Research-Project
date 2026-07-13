from __future__ import annotations

import random
from math import sqrt
from statistics import NormalDist

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    fbeta_score,
    f1_score,
    precision_score,
    recall_score,
)


MetricValue = float | None


def _round(value: MetricValue, digits: int = 4) -> MetricValue:
    return None if value is None else round(float(value), digits)


SCORE_NAMES = (
    "accuracy",
    "balanced_accuracy",
    "recall",
    "false_negative_rate",
    "specificity",
    "false_positive_rate",
    "precision",
    "negative_predictive_value",
    "f1",
    "f2",
)


def _classification_scores(y_true: list[int], y_pred: list[int]) -> dict[str, MetricValue]:
    if not y_true:
        return {name: None for name in SCORE_NAMES}

    positives = sum(y_true)
    negatives = len(y_true) - positives
    predicted_positives = sum(y_pred)
    tn, fp, fn, tp = (
        int(value) for value in confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    )
    precision = (
        float(precision_score(y_true, y_pred, pos_label=1, zero_division=0))
        if predicted_positives
        else None
    )
    recall = (
        float(recall_score(y_true, y_pred, pos_label=1, zero_division=0))
        if positives
        else None
    )
    specificity = (
        float(recall_score(y_true, y_pred, pos_label=0, zero_division=0))
        if negatives
        else None
    )
    f1 = (
        float(f1_score(y_true, y_pred, pos_label=1, zero_division=0))
        if positives or predicted_positives
        else None
    )
    f2 = (
        float(fbeta_score(y_true, y_pred, beta=2, pos_label=1, zero_division=0))
        if positives or predicted_positives
        else None
    )
    balanced = (
        float(balanced_accuracy_score(y_true, y_pred))
        if positives and negatives
        else None
    )
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": balanced,
        "precision": precision,
        "recall": recall,
        "false_negative_rate": (fn / (fn + tp)) if (fn + tp) else None,
        "f1": f1,
        "f2": f2,
        "specificity": specificity,
        "false_positive_rate": (fp / (fp + tn)) if (fp + tn) else None,
        "negative_predictive_value": (tn / (tn + fn)) if (tn + fn) else None,
    }


def _percentile_interval(values: list[float], confidence: float = 0.95) -> dict[str, float] | None:
    if not values:
        return None
    alpha = (1.0 - confidence) / 2.0
    low, high = np.quantile(np.asarray(values, dtype=float), [alpha, 1.0 - alpha])
    return {"low": round(float(low), 4), "high": round(float(high), 4)}


def _wilson_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> dict[str, float] | None:
    """Wilson score interval for a binomial proportion, including 0%/100% results."""
    if total <= 0:
        return None
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    proportion = successes / total
    denominator = 1.0 + (z * z / total)
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * sqrt(proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total))
        / denominator
    )
    return {
        "low": round(max(0.0, center - margin), 4),
        "high": round(min(1.0, center + margin), 4),
    }


def _complement_interval(interval: dict[str, float] | None) -> dict[str, float] | None:
    if interval is None:
        return None
    return {
        "low": round(1.0 - interval["high"], 4),
        "high": round(1.0 - interval["low"], 4),
    }


def bootstrap_confidence_intervals(
    y_true: list[int],
    y_pred: list[int],
    *,
    iterations: int = 2000,
    seed: int = 42,
    group_ids: list[str] | None = None,
) -> dict[str, dict[str, float] | None]:
    """Return percentile CIs using cluster or class-stratified resampling."""
    metric_names = SCORE_NAMES
    if not y_true or iterations <= 0:
        return {name: None for name in metric_names}

    rng = random.Random(seed)
    samples: dict[str, list[float]] = {name: [] for name in metric_names}
    use_cluster_bootstrap = (
        group_ids is not None
        and len(group_ids) == len(y_true)
        and len(set(group_ids)) < len(group_ids)
    )

    if use_cluster_bootstrap:
        clusters: dict[str, list[int]] = {}
        for index, group_id in enumerate(group_ids or []):
            clusters.setdefault(group_id, []).append(index)
        cluster_ids = list(clusters)
    else:
        indices = {
            0: [index for index, truth in enumerate(y_true) if truth == 0],
            1: [index for index, truth in enumerate(y_true) if truth == 1],
        }

    for _ in range(iterations):
        if use_cluster_bootstrap:
            selected_clusters = (rng.choice(cluster_ids) for _ in cluster_ids)
            sampled_indices = [
                index
                for cluster_id in selected_clusters
                for index in clusters[cluster_id]
            ]
        else:
            sampled_indices = []
            for label in (0, 1):
                class_indices = indices[label]
                sampled_indices.extend(rng.choice(class_indices) for _ in class_indices)
        sampled_true = [y_true[index] for index in sampled_indices]
        sampled_pred = [y_pred[index] for index in sampled_indices]
        scores = _classification_scores(sampled_true, sampled_pred)
        for name, value in scores.items():
            if value is not None:
                samples[name].append(value)

    return {name: _percentile_interval(values) for name, values in samples.items()}


def compute_metrics(
    y_true: list[int],
    y_pred: list[int],
    *,
    errors: int = 0,
    loaded_samples: int | None = None,
    bootstrap_iterations: int = 2000,
    seed: int = 42,
    group_ids: list[str] | None = None,
    error_truths: list[int] | None = None,
) -> dict[str, object]:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must contain the same number of samples.")

    loaded_samples = loaded_samples if loaded_samples is not None else len(y_true) + errors
    if y_true:
        tn, fp, fn, tp = (int(value) for value in confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel())
    else:
        tn = fp = fn = tp = 0

    scores = _classification_scores(y_true, y_pred)
    confidence_intervals = bootstrap_confidence_intervals(
        y_true,
        y_pred,
        iterations=bootstrap_iterations,
        seed=seed,
        group_ids=group_ids,
    )
    repeated_groups = (
        group_ids is not None
        and len(group_ids) == len(y_true)
        and len(set(group_ids)) < len(group_ids)
    )
    if bootstrap_iterations > 0 and not repeated_groups:
        recall_interval = _wilson_interval(tp, tp + fn)
        specificity_interval = _wilson_interval(tn, tn + fp)
        confidence_intervals.update(
            {
                "accuracy": _wilson_interval(tp + tn, len(y_true)),
                "recall": recall_interval,
                "false_negative_rate": _complement_interval(recall_interval),
                "specificity": specificity_interval,
                "false_positive_rate": _complement_interval(specificity_interval),
                "precision": _wilson_interval(tp, tp + fp),
                "negative_predictive_value": _wilson_interval(tn, tn + fn),
            }
        )
    error_truths = error_truths or []
    sensitive_errors = sum(error_truths)
    non_sensitive_errors = len(error_truths) - sensitive_errors
    coverage = len(y_true) / loaded_samples if loaded_samples else 0.0

    return {
        "evaluated_samples": len(y_true),
        "ground_truth_sensitive_rate": round(sum(y_true) / len(y_true), 4) if y_true else None,
        "predicted_sensitive_rate": round(sum(y_pred) / len(y_pred), 4) if y_pred else None,
        "accuracy": _round(scores["accuracy"]),
        "balanced_accuracy": _round(scores["balanced_accuracy"]),
        "recall": _round(scores["recall"]),
        "false_negative_rate": _round(scores["false_negative_rate"]),
        "specificity": _round(scores["specificity"]),
        "false_positive_rate": _round(scores["false_positive_rate"]),
        "precision": _round(scores["precision"]),
        "negative_predictive_value": _round(scores["negative_predictive_value"]),
        "f1": _round(scores["f1"]),
        "f2": _round(scores["f2"]),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "confidence_intervals_95": confidence_intervals,
        "runtime_errors": errors,
        "sensitive_runtime_errors": sensitive_errors,
        "non_sensitive_runtime_errors": non_sensitive_errors,
        "coverage": round(coverage, 4),
        "error_rate": round(errors / loaded_samples, 4) if loaded_samples else 0.0,
        "paper_result_valid": errors == 0,
    }
