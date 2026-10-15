#!/usr/bin/env python3
"""Plot sustained fuzzer development trajectories from tracked aggregates only.

From the repository root:
    python paper/scripts/plot_long_fuzzer_trajectories.py --validate-only
    python paper/scripts/plot_long_fuzzer_trajectories.py --overwrite

No row-level predictions, source dataset, training prompts, or model weights are
read. Actual checkpoint times come from the safe provenance sidecar.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = REPO_ROOT / "docs" / "evidence" / "long-fuzzer-20261009"
OUTPUT_DIR = REPO_ROOT / "paper" / "figures"
OUTPUT_STEM = "results-long-fuzzer-trajectories"
PROFILES = ("efficient", "balanced", "quality")
LAYERS = ("semantic", "pipeline")
METRICS = ("recall", "specificity")
COLORS = {"efficient": "#0072B2", "balanced": "#D55E00", "quality": "#009E73"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_sources() -> tuple[dict, dict, dict]:
    summary_path = EVIDENCE / "summary.json"
    provenance_path = EVIDENCE / "provenance.json"
    audit_path = EVIDENCE / "independent-audit.json"
    protocol_path = EVIDENCE / "protocol.json"
    summary, provenance = read_json(summary_path), read_json(provenance_path)
    audit, protocol = read_json(audit_path), read_json(protocol_path)

    if audit.get("status") != "passed" or audit.get("minimum_hours") != 6:
        raise ValueError("A passed six-hour independent audit is required.")
    hashes = provenance.get("source_hashes", {})
    expected = {
        "summary_sha256": sha256(summary_path),
        "independent_audit_sha256": sha256(audit_path),
        "protocol_sha256": sha256(protocol_path),
    }
    for key, actual in expected.items():
        if hashes.get(key) != actual:
            raise ValueError(f"Provenance commitment differs for {key}.")
    if summary.get("protocol_sha256") != expected["protocol_sha256"]:
        raise ValueError("Summary protocol commitment differs.")
    if audit.get("summary_sha256") != expected["summary_sha256"]:
        raise ValueError("Independent audit summary commitment differs.")
    if provenance.get("supervisor_status") != "complete":
        raise ValueError("Supervisor has not recorded completion.")
    if summary.get("profiles", {}).keys() != set(PROFILES):
        raise ValueError("Summary profile set differs from the three-profile study.")
    if summary.get("endpoint_rows") != 502 or summary.get("endpoint_positive") != 264 \
            or summary.get("endpoint_negative") != 238 or summary.get("source_groups") != 465:
        raise ValueError("Endpoint denominators differ from the pinned evaluation.")
    if protocol.get("duration_seconds_per_profile") != 7200:
        raise ValueError("Protocol does not prescribe two hours per profile.")
    if len(provenance.get("serving_image_ids", {})) != 5:
        raise ValueError("Frozen serving image identities are incomplete.")
    allocation = provenance.get("allocation_reconciliation", {})
    if (allocation.get("attempts") != summary.get("rounds")
            or allocation.get("train_ids_per_allocation") != 192
            or allocation.get("replay_ids_per_allocation") != 64
            or allocation.get("distinct_train_ids_each_allocation") is not True
            or allocation.get("distinct_replay_ids_each_allocation") is not True
            or allocation.get("train_replay_disjoint_each_allocation") is not True
            or allocation.get("split_membership_verified") is not True):
        raise ValueError("Per-allocation curriculum audit does not meet the protocol.")
    guard = provenance.get("publication_guard", {})
    if guard != {"rows": 16, "sensitive_rows": 8, "clean_rows": 8, "same_gate_hash_all_profiles": True}:
        raise ValueError("Fixed publication guard metadata differs from the protocol.")
    gate_hashes = set()

    for profile in PROFILES:
        profile_data = summary["profiles"][profile]
        timing = provenance["profiles"][profile]
        audit_profile = audit["profiles"][profile]
        if profile_data["attempts"] != audit_profile["attempts_verified"]:
            raise ValueError(f"Audited attempt count differs for {profile}.")
        if profile_data["accepted_updates"] + profile_data["rejected_attempts"] != profile_data["attempts"]:
            raise ValueError(f"Attempt outcome counts do not reconcile for {profile}.")
        if profile_data["unique_train_rows"] != 672 or profile_data["unique_replay_rows"] != 64:
            raise ValueError(f"Curriculum pool coverage differs for {profile}.")
        if allocation.get("profiles", {}).get(profile) != {
                "attempts": profile_data["attempts"],
                "allocations_checked": profile_data["attempts"],
                "invalid_allocations": 0}:
            raise ValueError(f"Allocation reconciliation count differs for {profile}.")
        last_guard = timing.get("last_accepted_guard", {})
        if (last_guard.get("total_examples") != 16
                or last_guard.get("sensitive_examples") != 8
                or last_guard.get("clean_examples") != 8
                or not 0 <= last_guard.get("sensitive_true_positives", -1) <= 8
                or not 0 <= last_guard.get("clean_true_negatives", -1) <= 8):
            raise ValueError(f"Last accepted publication guard counts differ for {profile}.")
        gate_hashes.add(last_guard.get("gate_ids_sha256"))
        start, end = timing["window_started_unix"], timing["window_finished_unix"]
        if not (math.isfinite(start) and math.isfinite(end) and end - start >= 7200):
            raise ValueError(f"Elapsed window is shorter than two hours for {profile}.")
        if timing["timed_training_seconds"] < 7200 or audit_profile["window_seconds"] < 7200:
            raise ValueError(f"Recorded training duration is short for {profile}.")
        checkpoints = timing["checkpoints"]
        if list(checkpoints) != list(profile_data["checkpoints"]):
            raise ValueError(f"Checkpoint set differs for {profile}.")
        times = [datetime.fromisoformat(checkpoints[cycle]["measured_at"]) for cycle in checkpoints]
        if not all(a < b for a, b in zip(times, times[1:])):
            raise ValueError(f"Checkpoint times are not strictly increasing for {profile}.")
        window_start = datetime.fromtimestamp(start, times[0].tzinfo)
        window_end = datetime.fromtimestamp(end, times[0].tzinfo)
        if times[0] > window_start or times[-1] < window_end:
            raise ValueError(f"Baseline/final checkpoint timing differs from the elapsed window for {profile}.")
        elapsed_minutes = (times[-1] - times[0]).total_seconds() / 60
        if elapsed_minutes <= 120:
            raise ValueError(f"Final measured checkpoint should appear after 120 minutes for {profile}.")
        if audit_profile["paired_metrics_verified"] != 72:
            raise ValueError(f"Paired metric audit coverage differs for {profile}.")
        for checkpoint in profile_data["checkpoints"].values():
            for layer in LAYERS:
                metrics = checkpoint[layer]["metrics"]
                tp, tn, fp, fn = (metrics[k] for k in ("true_positives", "true_negatives", "false_positives", "false_negatives"))
                if tp + fn != 264 or tn + fp != 238:
                    raise ValueError(f"Confusion counts do not reconcile for {profile}/{layer}.")
                recall = tp / (tp + fn)
                specificity = tn / (tn + fp)
                if abs(metrics["recall"] - recall) > 1e-12 or abs(metrics["specificity"] - specificity) > 1e-12:
                    raise ValueError(f"Reported rates differ from counts for {profile}/{layer}.")
    if len(gate_hashes) != 1 or None in gate_hashes:
        raise ValueError("Publication guard identity differs across profiles.")
    return summary, provenance, protocol


def make_figure(summary: dict, provenance: dict):
    plt.rcParams.update({
        "font.family": "DejaVu Serif",
        "font.size": 9,
        "axes.labelsize": 9,
        "axes.titlesize": 11,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "svg.fonttype": "none",
        "svg.hashsalt": "privoke-long-fuzzer-20261009",
    })
    fig, axes = plt.subplots(2, 2, figsize=(7.1, 5.0), sharex=True, sharey=True)
    panel_specs = (("semantic", "recall"), ("semantic", "specificity"),
                   ("pipeline", "recall"), ("pipeline", "specificity"))
    for ax, (layer, metric) in zip(axes.flat, panel_specs):
        ax.set_title(f"{layer.title()} {metric}")
        for profile in PROFILES:
            checkpoints = summary["profiles"][profile]["checkpoints"]
            checkpoint_times = provenance["profiles"][profile]["checkpoints"]
            cycles = list(checkpoints)
            baseline = datetime.fromisoformat(checkpoint_times[cycles[0]]["measured_at"])
            minutes = [(datetime.fromisoformat(checkpoint_times[cycle]["measured_at"]) - baseline).total_seconds() / 60 for cycle in cycles]
            values = [checkpoints[cycle][layer]["metrics"][metric] * 100 for cycle in cycles]
            ax.plot(minutes, values, marker="o", markersize=3.2, linewidth=1.4,
                    color=COLORS[profile], label=profile.title())
        ax.set_ylim(0, 100)
        ax.set_yticks(range(0, 101, 20))
        ax.grid(axis="y", color="#d9d9d9", linewidth=0.6)
        ax.axvline(120, color="#777777", linestyle=(0, (3, 2)), linewidth=0.8, zorder=0)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.set_ylabel("Rate (%)")
    axes[1, 0].set_xlabel("Elapsed time since baseline checkpoint (minutes)")
    axes[1, 1].set_xlabel("Elapsed time since baseline checkpoint (minutes)")
    axes[0, 0].legend(frameon=False, loc="best")
    axes[0, 1].legend(frameon=False, loc="best")
    axes[1, 0].legend(frameon=False, loc="best")
    axes[1, 1].legend(frameon=False, loc="best")
    fig.tight_layout(pad=1.0)
    return fig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--overwrite", action="store_true", help="replace only this plot's named outputs")
    parser.add_argument("--validate-only", action="store_true", help="check aggregate sources without writing figures")
    args = parser.parse_args()
    summary, provenance, protocol = validate_sources()
    if args.validate_only:
        print("Validated six-hour audit, aggregate counts/rates, checkpoint times, and source hash commitments.")
        return 0

    output = args.output_dir.resolve()
    targets = [output / f"{OUTPUT_STEM}.{ext}" for ext in ("png", "svg")]
    manifest_path = output / f"{OUTPUT_STEM}-manifest.json"
    if not args.overwrite and any(path.exists() for path in [*targets, manifest_path]):
        parser.error("Named trajectory outputs already exist; use --overwrite to regenerate them")
    output.mkdir(parents=True, exist_ok=True)
    figure = make_figure(summary, provenance)
    figure.savefig(targets[0], dpi=450, metadata={"Software": "Matplotlib"})
    figure.savefig(targets[1], metadata={"Date": None})
    svg_bytes = targets[1].read_bytes()
    normalized_lines = []
    for line in svg_bytes.splitlines(keepends=True):
        if line.endswith(b"\r\n"):
            body, ending = line[:-2], b"\r\n"
        elif line.endswith((b"\n", b"\r")):
            body, ending = line[:-1], line[-1:]
        else:
            body, ending = line, b""
        normalized_lines.append(body.rstrip(b" \t") + ending)
    targets[1].write_bytes(b"".join(normalized_lines))
    plt.close(figure)
    manifest = {
        "schema_version": 1,
        "scope": "Exploratory annotation-presence development trajectories; no row-level inputs accessed",
        "sources": {
            "summary_sha256": sha256(EVIDENCE / "summary.json"),
            "independent_audit_sha256": sha256(EVIDENCE / "independent-audit.json"),
            "protocol_sha256": sha256(EVIDENCE / "protocol.json"),
            "provenance_sha256": sha256(EVIDENCE / "provenance.json"),
        },
        "plotted_data": {
            profile: {
                layer: {
                    metric: [
                        {
                            "cycle": cycle,
                            "measured_at": provenance["profiles"][profile]["checkpoints"][cycle]["measured_at"],
                            "elapsed_minutes_since_baseline": (datetime.fromisoformat(provenance["profiles"][profile]["checkpoints"][cycle]["measured_at"]) - datetime.fromisoformat(provenance["profiles"][profile]["checkpoints"][next(iter(summary["profiles"][profile]["checkpoints"]))]["measured_at"])).total_seconds() / 60,
                            "rate_percent": summary["profiles"][profile]["checkpoints"][cycle][layer]["metrics"][metric] * 100,
                        }
                        for cycle in summary["profiles"][profile]["checkpoints"]
                    ]
                    for metric in METRICS
                }
                for layer in LAYERS
            }
            for profile in PROFILES
        },
        "reproduction": {
            "command": "python paper/scripts/plot_long_fuzzer_trajectories.py --overwrite",
            "matplotlib": matplotlib.__version__,
            "script_sha256": sha256(Path(__file__).resolve()),
            "checkpoint_axis": "actual measured_at UTC, relative to each profile's baseline checkpoint",
        },
        "outputs": {path.name: sha256(path) for path in targets},
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Wrote PNG/SVG trajectory figure and manifest to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
