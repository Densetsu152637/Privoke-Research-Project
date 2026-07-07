from __future__ import annotations

from statistics import mean


def _safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def compute_metrics(y_true: list[int], y_pred: list[int], latencies_ms: list[float]) -> dict[str, float | int]:
    if not y_true:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "accuracy": 0.0,
            "specificity": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "avg_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "min_latency_ms": 0.0,
            "max_latency_ms": 0.0,
            "true_positives": 0,
            "true_negatives": 0,
            "false_positives": 0,
            "false_negatives": 0,
        }

    true_positives = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 1)
    true_negatives = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 0)
    false_positives = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 0 and pred == 1)
    false_negatives = sum(1 for truth, pred in zip(y_true, y_pred) if truth == 1 and pred == 0)

    precision = _safe_divide(true_positives, true_positives + false_positives)
    recall = _safe_divide(true_positives, true_positives + false_negatives)
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    accuracy = _safe_divide(true_positives + true_negatives, len(y_true))
    specificity = _safe_divide(true_negatives, true_negatives + false_positives)
    false_positive_rate = _safe_divide(false_positives, false_positives + true_negatives)
    false_negative_rate = _safe_divide(false_negatives, false_negatives + true_positives)

    if latencies_ms:
        ordered = sorted(latencies_ms)
        p95_index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
        avg_latency_ms = mean(ordered)
        p95_latency_ms = ordered[p95_index]
        min_latency_ms = ordered[0]
        max_latency_ms = ordered[-1]
    else:
        avg_latency_ms = 0.0
        p95_latency_ms = 0.0
        min_latency_ms = 0.0
        max_latency_ms = 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "specificity": round(specificity, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "avg_latency_ms": round(avg_latency_ms, 3),
        "p95_latency_ms": round(p95_latency_ms, 3),
        "min_latency_ms": round(min_latency_ms, 3),
        "max_latency_ms": round(max_latency_ms, 3),
        "true_positives": true_positives,
        "true_negatives": true_negatives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }
