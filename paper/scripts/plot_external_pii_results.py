#!/usr/bin/env python3
"""Render the verified external-PII validation comparison from aggregate data only.

Example (from the repository root):
    python paper/scripts/plot_external_pii_results.py \
      --summary evaluation/results/external_pii_summary_20261004_v1.json \
      --study-manifest evaluation/results/external_pii_rpc_20261004_v2/run-manifest.json \
      --output-dir evaluation/results/external_pii_figure_20261004_v1

The fixed digests intentionally bind this figure to the reviewed, completed
study. The script does not read predictions, examples, model artifacts, or
positive-only heldout metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


SUMMARY_SHA256 = "e5e138d42f0930390702fb56a745ae0b8e7f7772791d8ed473ab56d51b250c2d"
STUDY_MANIFEST_SHA256 = "62b28e0f6c2e8006915e9bdc8498462d636e44d5bb397f8704a95d96d2ab8671"
VALIDATION_SHA256 = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
PROTOCOL_SHA256 = "962198b384aaed7fd5fb98e10c778b295ac6403c0dd1ba5ea376c28ec786eafe"
PREPARED_MANIFEST_SHA256 = "2b8a63b168d72510ce4e61e03748bf5f7858bdc33b41d15f0095780164658e1c"
PROFILES = ("efficient", "balanced", "quality")
EXPECTED_CONFUSIONS = {
    "efficient": {
        "baseline": {"tp": 429, "tn": 378, "fp": 115, "fn": 46},
        "expanded": {"tp": 428, "tn": 330, "fp": 163, "fn": 47},
    },
    "balanced": {
        "baseline": {"tp": 428, "tn": 392, "fp": 101, "fn": 47},
        "expanded": {"tp": 428, "tn": 396, "fp": 97, "fn": 47},
    },
    "quality": {
        "baseline": {"tp": 428, "tn": 394, "fp": 99, "fn": 47},
        "expanded": {"tp": 430, "tn": 384, "fp": 109, "fn": 45},
    },
}
SOURCE_COLORS = {"recall": "#2166ac", "specificity": "#b2182b"}


def _fail(message: str) -> None:
    raise ValueError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        value = json.load(source, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        _fail(f"expected a JSON object in {path}")
    return value


def _exact_int(record: dict[str, Any], field: str) -> int:
    value = record.get(field)
    if type(value) is not int:
        _fail(f"{field} must be an integer")
    return value


def _validate_confusion(
    record: dict[str, Any], expected: dict[str, int], label: str
) -> dict[str, int]:
    counts = {key: _exact_int(record, key) for key in ("tp", "tn", "fp", "fn")}
    if counts != expected:
        _fail(f"{label} confusion counts do not match the reviewed summary")
    if counts["tp"] + counts["fn"] != 475:
        _fail(f"{label} positive denominator differs from the fixed validation set")
    if counts["tn"] + counts["fp"] != 493:
        _fail(f"{label} negative denominator differs from the fixed validation set")
    if _exact_int(record, "examples") != 968:
        _fail(f"{label} row count differs from the fixed validation set")

    recall = counts["tp"] / (counts["tp"] + counts["fn"])
    specificity = counts["tn"] / (counts["tn"] + counts["fp"])
    for metric, derived in (("recall", recall), ("specificity", specificity)):
        stored = record.get(metric)
        if isinstance(stored, bool) or not isinstance(stored, (int, float)):
            _fail(f"{label} {metric} must be finite numeric data")
        if not math.isfinite(float(stored)) or not math.isclose(
            float(stored), derived, rel_tol=0.0, abs_tol=1e-12
        ):
            _fail(f"{label} {metric} is inconsistent with its confusion counts")
    return counts


def _validate_inputs(
    summary_path: Path, manifest_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if _sha256(summary_path) != SUMMARY_SHA256:
        _fail("summary SHA-256 is not the reviewed aggregate summary")
    if _sha256(manifest_path) != STUDY_MANIFEST_SHA256:
        _fail("study-manifest SHA-256 is not the reviewed completed run")

    summary = _read_json(summary_path)
    manifest = _read_json(manifest_path)
    if summary.get("schema_version") != 1 or summary.get("status") != "verified":
        _fail("aggregate summary is not schema-1 verified evidence")
    if summary.get("study_manifest_sha256") != STUDY_MANIFEST_SHA256:
        _fail("summary is not bound to the reviewed runtime study manifest")
    if manifest.get("schema_version") != 1 or manifest.get("status") != "complete":
        _fail("runtime study manifest is not complete schema-1 evidence")
    if manifest.get("errors") != [] or manifest.get("restoration_verified") is not True:
        _fail("runtime study has errors or failed restoration verification")
    if manifest.get("admin_mutation_outcome_unknown") is not False:
        _fail("runtime study mutation outcome is not verified")
    if manifest.get("contextual_unchanged_or_restored") is not True:
        _fail("contextual artifact restoration was not verified")
    scores = manifest.get("scores")
    if not isinstance(scores, list) or len(scores) != 18:
        _fail("runtime study does not contain all 18 planned scores")
    if any(
        score.get("status") != "complete"
        or score.get("failure_reason") is not None
        or score.get("successful_rows") != score.get("rows")
        for score in scores
        if isinstance(score, dict)
    ) or any(not isinstance(score, dict) for score in scores):
        _fail("runtime study contains an incomplete or failed score")

    provenance = summary.get("provenance")
    if not isinstance(provenance, dict):
        _fail("summary provenance is missing")
    expected_bindings = {
        "protocol_sha256": PROTOCOL_SHA256,
        "prepared_manifest_sha256": PREPARED_MANIFEST_SHA256,
    }
    for key, expected in expected_bindings.items():
        if provenance.get(key) != expected or manifest.get(key) != expected:
            _fail(f"{key} does not match the reviewed study")
    if provenance.get("partition_sha256", {}).get("validation") != VALIDATION_SHA256:
        _fail("summary is not bound to the fixed validation partition")
    if manifest.get("partition_sha256", {}).get("validation") != VALIDATION_SHA256:
        _fail("run manifest is not bound to the fixed validation partition")
    for key in ("execution_source_revision", "fit_source_revision", "partition_sha256"):
        if provenance.get(key) != manifest.get(key):
            _fail(f"summary and run manifest disagree on {key}")

    bootstrap = summary.get("bootstrap")
    if bootstrap != {
        "iterations": 2000,
        "method": "paired_source_group_resampling",
        "minimum_groups": 20,
        "seed": 10102026,
    }:
        _fail("summary bootstrap configuration differs from the reviewed protocol")
    if set(summary.get("profiles", {})) != set(PROFILES):
        _fail("summary must contain exactly the three reviewed profiles")

    validation_scores: dict[tuple[str, str], dict[str, Any]] = {}
    for score in scores:
        if score.get("partition") == "validation":
            identity = (score.get("profile"), score.get("control"))
            if identity in validation_scores:
                _fail("duplicate profile/control validation score in run manifest")
            validation_scores[identity] = score
    expected_scores = {
        (profile, partition, control)
        for profile in PROFILES
        for partition in ("validation", "nemotron_heldout", "meddies_heldout")
        for control in ("baseline", "expanded")
    }
    actual_scores = {
        (score.get("profile"), score.get("partition"), score.get("control"))
        for score in scores
    }
    if actual_scores != expected_scores:
        _fail("run manifest does not contain the exact 18 planned profile/control/partition scores")
    if set(validation_scores) != {
        (profile, control)
        for profile in PROFILES
        for control in ("baseline", "expanded")
    }:
        _fail("run manifest is missing a validation profile/control result")

    verified: dict[str, Any] = {}
    for profile in PROFILES:
        entry = summary["profiles"][profile]
        if entry.get("partition_examples", {}).get("validation") != 968:
            _fail(f"{profile} validation sample count is incorrect")
        if entry.get("partition_examples", {}).get("nemotron_heldout") != 1000:
            _fail(f"{profile} Nemotron diagnostic count is inconsistent")
        if entry.get("partition_examples", {}).get("meddies_heldout") != 999:
            _fail(f"{profile} Meddies diagnostic count is inconsistent")
        matched = entry.get("matched_validation")
        if not isinstance(matched, dict):
            _fail(f"{profile} matched validation metrics are missing")
        profile_data: dict[str, Any] = {}
        for control in ("baseline", "expanded"):
            record = matched.get(control)
            if not isinstance(record, dict):
                _fail(f"{profile} {control} summary metrics are missing")
            counts = _validate_confusion(
                record, EXPECTED_CONFUSIONS[profile][control], f"{profile}/{control}"
            )
            run_record = validation_scores[(profile, control)]
            if run_record.get("rows") != 968 or run_record.get("successful_rows") != 968:
                _fail(f"{profile}/{control} run-manifest row counts are invalid")
            overall = run_record.get("metrics", {}).get("overall")
            if not isinstance(overall, dict):
                _fail(f"{profile}/{control} run-manifest metrics are missing")
            run_counts = {
                "tp": overall.get("true_positives"),
                "tn": overall.get("true_negatives"),
                "fp": overall.get("false_positives"),
                "fn": overall.get("false_negatives"),
            }
            if run_counts != counts or overall.get("group_count") != 714:
                _fail(f"{profile}/{control} summary disagrees with the run manifest")
            profile_data[control] = {
                **counts,
                "recall": counts["tp"] / 475,
                "specificity": counts["tn"] / 493,
            }

        paired = matched.get("paired_delta_expanded_minus_baseline")
        if not isinstance(paired, dict):
            _fail(f"{profile} paired validation interval is missing")
        if (
            paired.get("method") != "paired_source_group_bootstrap"
            or paired.get("group_count") != 714
            or paired.get("iterations") != 2000
            or paired.get("seed") != 10102026
            or paired.get("interval_status") != "complete"
        ):
            _fail(f"{profile} paired source-group bootstrap metadata is invalid")
        ci = paired.get("confidence_intervals_95", {}).get("specificity")
        if not isinstance(ci, dict) or ci.get("valid_replicates") != 2000:
            _fail(f"{profile} specificity interval is incomplete")
        lower, upper = ci.get("lower"), ci.get("upper")
        if (
            isinstance(lower, bool)
            or isinstance(upper, bool)
            or not isinstance(lower, (int, float))
            or not isinstance(upper, (int, float))
            or not math.isfinite(float(lower))
            or not math.isfinite(float(upper))
            or lower > upper
        ):
            _fail(f"{profile} specificity interval bounds are invalid")
        profile_data["specificity_delta_ci"] = [float(lower), float(upper)]
        profile_data["specificity_delta"] = (
            profile_data["expanded"]["specificity"]
            - profile_data["baseline"]["specificity"]
        )
        point_delta = paired.get("point_delta", {}).get("specificity")
        if (
            isinstance(point_delta, bool)
            or not isinstance(point_delta, (int, float))
            or not math.isfinite(float(point_delta))
            or not math.isclose(
                float(point_delta), profile_data["specificity_delta"], rel_tol=0.0, abs_tol=1e-12
            )
        ):
            _fail(f"{profile} specificity point delta disagrees with validation counts")
        verified[profile] = profile_data
    return summary, manifest, verified


def _make_figure(data: dict[str, Any]):
    matplotlib.rcParams["svg.hashsalt"] = "external-pii-validation-v1"
    fig, (metric_ax, interval_ax) = plt.subplots(
        1, 2, figsize=(12.2, 5.6), gridspec_kw={"width_ratios": [1.45, 1]}
    )
    x = list(range(len(PROFILES)))
    offsets = {
        ("recall", "baseline"): -0.18,
        ("recall", "expanded"): -0.06,
        ("specificity", "baseline"): 0.06,
        ("specificity", "expanded"): 0.18,
    }
    markers = {"baseline": "o", "expanded": "^"}
    for profile_index, profile in enumerate(PROFILES):
        for metric in ("recall", "specificity"):
            for condition in ("baseline", "expanded"):
                value = data[profile][condition][metric]
                metric_ax.scatter(
                    profile_index + offsets[(metric, condition)],
                    value * 100,
                    s=58,
                    color=SOURCE_COLORS[metric],
                    marker=markers[condition],
                    edgecolor="white",
                    linewidth=0.7,
                    zorder=3,
                )
    metric_ax.set_title("Validation operating metrics", loc="left", weight="bold")
    metric_ax.set_ylabel("Percent")
    metric_ax.set_xticks(x, [name.title() for name in PROFILES])
    metric_ax.set_ylim(60, 96)
    metric_ax.set_yticks([60, 70, 80, 90, 95])
    metric_ax.grid(axis="y", color="#d9dde3", linewidth=0.8)
    metric_ax.set_axisbelow(True)
    metric_ax.spines[["top", "right"]].set_visible(False)
    metric_handles = [
        Line2D([0], [0], color=SOURCE_COLORS["recall"], marker="o", lw=0, label="Recall · baseline"),
        Line2D([0], [0], color=SOURCE_COLORS["recall"], marker="^", lw=0, label="Recall · expanded"),
        Line2D([0], [0], color=SOURCE_COLORS["specificity"], marker="o", lw=0, label="Specificity · baseline"),
        Line2D([0], [0], color=SOURCE_COLORS["specificity"], marker="^", lw=0, label="Specificity · expanded"),
    ]
    metric_ax.legend(handles=metric_handles, frameon=False, ncol=2, loc="lower left", fontsize=8)

    deltas = [data[p]["specificity_delta"] * 100 for p in PROFILES]
    intervals = [data[p]["specificity_delta_ci"] for p in PROFILES]
    lower_errors = [delta - ci[0] * 100 for delta, ci in zip(deltas, intervals)]
    upper_errors = [ci[1] * 100 - delta for delta, ci in zip(deltas, intervals)]
    interval_ax.errorbar(
        deltas,
        x,
        xerr=[lower_errors, upper_errors],
        fmt="o",
        color="#252525",
        ecolor="#555555",
        capsize=4,
        markersize=6,
        linewidth=1.6,
    )
    interval_ax.axvline(0, color="#8c8c8c", linestyle="--", linewidth=1)
    interval_ax.set_title("Specificity change", loc="left", weight="bold")
    interval_ax.set_xlabel("Expanded − baseline (percentage points)")
    interval_ax.set_yticks(x, [name.title() for name in PROFILES])
    interval_ax.invert_yaxis()
    interval_ax.grid(axis="x", color="#d9dde3", linewidth=0.8)
    interval_ax.set_axisbelow(True)
    interval_ax.spines[["top", "right", "left"]].set_visible(False)
    interval_ax.tick_params(axis="y", length=0)
    interval_ax.set_xlim(-15, 5)
    interval_ax.set_xticks([-15, -10, -5, 0, 5])

    fig.suptitle(
        "External-source training profiles · validation only",
        x=0.06,
        y=0.99,
        ha="left",
        fontsize=14,
        weight="bold",
    )
    fig.text(
        0.06,
        0.015,
        "Binary annotation-presence task · n=968 (475 positive, 493 negative) · "
        "validation-selected operating points; descriptive, not final-set results.\n"
        "Intervals: paired source-group bootstrap, 2,000 replicates, 714 groups, seed 10102026.",
        fontsize=8.5,
        color="#333333",
    )
    fig.tight_layout(rect=(0.02, 0.095, 0.99, 0.94), w_pad=2.2)
    return fig


def _write_fresh(output_dir: Path, summary_path: Path, manifest_path: Path, data: dict[str, Any]) -> None:
    if output_dir.exists():
        _fail(f"output directory already exists; choose a fresh path: {output_dir}")
    else:
        output_dir.mkdir(parents=True)

    figure = _make_figure(data)
    png = output_dir / "external-pii-validation.png"
    svg = output_dir / "external-pii-validation.svg"
    figure.savefig(png, dpi=220, bbox_inches="tight", metadata={"Software": "matplotlib"})
    figure.savefig(
        svg,
        bbox_inches="tight",
        metadata={"Creator": "plot_external_pii_results.py", "Date": None},
    )
    plt.close(figure)

    report = {
        "schema_version": 1,
        "status": "complete",
        "figure_scope": "matched validation metrics only; no heldout partition scores plotted",
        "input_sha256": {
            "summary": _sha256(summary_path),
            "study_manifest": _sha256(manifest_path),
        },
        "source_provenance": {
            "study_manifest_sha256": STUDY_MANIFEST_SHA256,
            "protocol_sha256": PROTOCOL_SHA256,
            "prepared_manifest_sha256": PREPARED_MANIFEST_SHA256,
            "validation_partition_sha256": VALIDATION_SHA256,
            "fit_source_revision": "85c7f475fb8ebd1529254e4135b774d98505ddb1",
            "execution_source_revision": "083ee0c5fb38efdfb63ade634b185eba0c67432d",
        },
        "fixed_validation": {
            "rows": 968,
            "positive_rows": 475,
            "negative_rows": 493,
            "group_count": 714,
            "partition_sha256": VALIDATION_SHA256,
        },
        "bootstrap": {
            "method": "paired source-group bootstrap",
            "iterations": 2000,
            "seed": 10102026,
            "interval": "95%",
        },
        "data": data,
        "caption": (
            "Validation-only results for the binary annotated-PII-presence task. "
            "Each profile was selected using this validation set, so comparisons are "
            "selection-conditioned and descriptive rather than independent confirmation. "
            "Specificity-difference intervals use a paired source-group bootstrap over "
            "714 groups (2,000 replicates; seed 10102026). No final partition was scored."
        ),
        "reproduction": {
            "command_argv": [sys.executable, *sys.argv],
            "python": platform.python_version(),
            "matplotlib": matplotlib.__version__,
            "backend": matplotlib.get_backend(),
            "script_sha256": _sha256(Path(__file__).resolve()),
        },
        "artifacts": {
            png.name: _sha256(png),
            svg.name: _sha256(svg),
        },
    }
    with (output_dir / "figure-manifest.json").open("x", encoding="utf-8", newline="\n") as target:
        json.dump(report, target, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        target.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True, help="verified aggregate summary JSON")
    parser.add_argument("--study-manifest", type=Path, required=True, help="verified completed runtime manifest")
    parser.add_argument("--output-dir", type=Path, required=True, help="fresh directory for PNG, SVG, and manifest")
    args = parser.parse_args(argv)
    try:
        _, _, data = _validate_inputs(args.summary, args.study_manifest)
        _write_fresh(args.output_dir, args.summary, args.study_manifest, data)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"figure generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote verified validation figure to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
