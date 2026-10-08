#!/usr/bin/env python3
"""Generate manuscript plots from tracked aggregate reports, never raw examples.

From the repository root:
    python paper/scripts/plot_paper_results.py

Outputs default to paper/figures. Use --overwrite to regenerate these named
outputs. Counts and reported intervals are parsed from the source documents;
rates are recomputed, and every plotted input is saved in a provenance manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


REPO_ROOT = Path(__file__).resolve().parents[2]
FIGURE_NAMES = (
    "results-layer-ablation",
    "results-update-outcomes",
    "results-cascade-errors",
    "results-external-specificity",
)
BLUE = "#0072B2"
ORANGE = "#D55E00"
GREY = "#777777"
NUMBER_WORDS = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
                "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}
NUMBER_PATTERN = r"(?:\d+|zero|one|two|three|four|five|six|seven|eight|nine)"


def read_report(relative_path: str, sources: dict) -> str:
    """Read one named aggregate document and record its normalized content hash."""
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8-sig")
    text = text.replace("\r\n", "\n")
    sources[relative_path] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return text


def markdown_table(text: str, first_column: str, required_header: str | None = None) -> list[list[str]]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines)
              if line.startswith("|") and line.split("|")[1].strip() == first_column
              and (required_header is None or required_header in line)]
    if len(starts) != 1:
        raise ValueError(f"Expected one table headed {first_column!r}")
    rows = []
    columns = len(lines[starts[0]].strip().strip("|").split("|"))
    for line in lines[starts[0] + 2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != columns:
            raise ValueError(f"Inconsistent columns in {first_column!r} table")
        rows.append(cells)
    if not rows:
        raise ValueError(f"Empty table: {first_column}")
    return rows


def confusion(value: str, positive: int, negative: int) -> dict:
    parts = re.split(r"\s*/\s*", value.strip())
    if len(parts) != 4 or any(not part.isdigit() for part in parts):
        raise ValueError(f"Invalid TP/TN/FP/FN: {value}")
    counts = dict(zip(("tp", "tn", "fp", "fn"), map(int, parts)))
    if counts["tp"] + counts["fn"] != positive or counts["tn"] + counts["fp"] != negative:
        raise ValueError(f"Class denominators differ from {positive}/{negative}: {value}")
    return counts


def percent(value: str) -> float:
    return float(value.strip().removesuffix("%"))


def check_rate(stored: str, derived: float) -> None:
    if not math.isclose(percent(stored), derived, rel_tol=0, abs_tol=0.0051):
        raise ValueError(f"Reported rate {stored} is inconsistent with counts: {derived}")


def number(value: str) -> int:
    return int(value) if value.isdigit() else NUMBER_WORDS[value.lower()]


def load_data() -> tuple[dict, dict]:
    sources: dict[str, str] = {}
    development = read_report("paper/research/development-results.md", sources)
    layer_labels = {
        "regex": "Regex", "ner": "NER", "regex-ner": "Regex + NER",
        "semantic": "Semantic", "pipeline": "Full pipeline",
        "Independent Presidio (small English NLP model)": "Presidio",
    }
    layer_rows = markdown_table(development, "Layer")
    by_layer = {row[0]: row for row in layer_rows}
    if len(layer_rows) != len(layer_labels) or set(by_layer) != set(layer_labels):
        raise ValueError("Layer table differs from the declared six-layer comparison")
    layers = []
    for key, label in layer_labels.items():
        row = by_layer[key]
        counts = confusion("/".join(row[1:5]), 264, 238)
        recall, specificity = 100 * counts["tp"] / 264, 100 * counts["tn"] / 238
        check_rate(row[5], recall)
        check_rate(row[6], specificity)
        layers.append({"label": label, **counts, "recall": recall, "specificity": specificity})

    index = read_report("docs/model-quality-study-index-20261006.md", sources)
    index_rows = markdown_table(index, "Study")
    study_names = ["Initial grid", "Class-balanced", "Mean-category", "Role-quota",
                   "Local SGD", "Decision-margin"]
    expected_studies = (
        "Initial contextual fuzzer grid", "Class-balanced objective", "Mean-category objective",
        "Role-quota sampling", "Local SGD", "Decision-margin auxiliary objective",
    )
    if tuple(row[0] for row in index_rows) != expected_studies:
        raise ValueError("Study index differs from the six declared contextual grids")
    studies = []
    for label, row in zip(study_names, index_rows):
        attempts = int(row[1])
        if label == "Initial grid":
            initial = read_report("docs/fuzzer-model-results-20261006.md", sources)
            match = re.search(r"(\d+) accepted, (\d+) rejected, and (\d+) validation-eligible", initial)
            if not match:
                raise ValueError("Initial grid acceptance/eligibility counts missing")
            accepted, rejected, eligible = map(int, match.groups())
        else:
            outcome = row[2].lower()
            accepted_match = re.search(rf"({NUMBER_PATTERN}) accepted", outcome)
            if not accepted_match or "zero eligible" not in outcome:
                raise ValueError(f"Missing acceptance or zero-eligibility record for {label}")
            accepted, eligible = number(accepted_match.group(1)), 0
            rejected_match = re.search(rf"({NUMBER_PATTERN}) rejected", outcome)
            # The margin study explicitly states six accepted out of six attempts.
            rejected = number(rejected_match.group(1)) if rejected_match else attempts - accepted
        if accepted + rejected != attempts or not 0 <= eligible <= accepted:
            raise ValueError(f"Inconsistent nested outcome counts for {label}")
        studies.append({"label": label, "attempts": attempts, "accepted": accepted,
                        "rejected": rejected, "eligible": eligible,
                        "accepted_ineligible": accepted - eligible, "retained": 0})
    totals = {key: sum(row[key] for row in studies)
              for key in ("attempts", "accepted", "rejected", "eligible")}
    if totals != {"attempts": 126, "accepted": 59, "rejected": 67, "eligible": 15}:
        raise ValueError("This figure is scoped to the completed 126-attempt checkpoint")
    if "no research artifact is promoted" not in index.lower():
        raise ValueError("Study restoration/no-promotion scope is missing")
    if "failed development and fixture retention" not in index_rows[0][2].lower() or "no retained model" not in index_rows[0][2].lower():
        raise ValueError("Initial validation winner's retention failure is missing")

    cascade_text = read_report("docs/contextual-cascade-results.md", sources)
    cascade_rows = markdown_table(cascade_text, "Profile", "Positive detections lost vs ordinary control")
    ordinary_match = re.search(r"ordinary original-control development pipeline was TP/TN/FP/FN `([^`]+)`", cascade_text)
    if not ordinary_match or [row[0] for row in cascade_rows] != ["Efficient", "Balanced", "Quality"]:
        raise ValueError("Original-control cascade counts missing or changed")
    cascade = [{"label": "Ordinary control", **confusion(ordinary_match.group(1), 264, 238)}]
    for row in cascade_rows:
        counts = confusion(row[1], 264, 238)
        check_rate(row[2], 100 * counts["tp"] / 264)
        check_rate(row[3], 100 * counts["tn"] / 238)
        if cascade[0]["fp"] - counts["fp"] != int(row[5]) or counts["fn"] - cascade[0]["fn"] != int(row[4]):
            raise ValueError("Cascade lost-positive/removed-negative columns disagree")
        cascade.append({"label": f"{row[0]} gate", **counts})

    external = read_report("docs/PII-dataset-analysis.md", sources)
    external_rows = markdown_table(external, "Profile")
    interval_text = external.replace("\u2212", "-")
    intervals = []
    for row in external_rows:
        profile = row[0].lower()
        expanded, base = confusion(row[1], 475, 493), confusion(row[4], 475, 493)
        check_rate(row[2], 100 * expanded["tp"] / 475)
        check_rate(row[3], 100 * expanded["tn"] / 493)
        match = re.search(rf"{profile} ([+-]?\d+\.\d+)(?: percentage points)? \[([+-]?\d+\.\d+), ([+-]?\d+\.\d+)\]", interval_text)
        if not match:
            raise ValueError(f"Reported paired specificity interval missing for {profile}")
        reported, lower, upper = map(float, match.groups())
        delta = 100 * (expanded["tn"] - base["tn"]) / 493
        if abs(delta - reported) > 0.0051 or not lower <= delta <= upper:
            raise ValueError(f"Specificity delta/interval inconsistent for {profile}")
        intervals.append({"label": row[0], "base": base, "expanded": expanded,
                          "delta_pp": delta, "lower_pp": lower, "upper_pp": upper})
    if [row["label"] for row in intervals] != ["Efficient", "Balanced", "Quality"]:
        raise ValueError("External comparison must contain the three declared profiles")
    return {"layers": layers, "studies": studies, "study_totals": totals,
            "cascade": cascade, "external": intervals}, sources


def style_axes(ax, *, grid_axis: str = "x") -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis=grid_axis, color="0.9", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.tick_params(length=2.5, width=0.6)


def layer_figure(rows: list[dict]):
    fig, ax = plt.subplots(figsize=(3.5, 3.0))
    y = np.arange(len(rows))
    for offset, metric, marker, color, label in (
        (-0.12, "recall", "o", BLUE, "Recall"),
        (0.12, "specificity", "s", ORANGE, "Specificity"),
    ):
        values = [row[metric] for row in rows]
        ax.scatter(values, y + offset, marker=marker, color=color, s=24, label=label, zorder=3)
        for value, yy in zip(values, y + offset):
            ax.annotate(f"{value:.1f}", (value, yy), xytext=(-6 if value > 90 else 6, 0),
                        textcoords="offset points", ha="right" if value > 90 else "left",
                        va="center", fontsize=7, color=color)
    ax.set_yticks(y, [row["label"] for row in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xticks(range(0, 101, 20))
    ax.set_xlabel("Annotation-presence rate (%)")
    ax.set_ylim(len(rows) - 0.5, -0.8)
    ax.legend(loc="lower left", bbox_to_anchor=(-0.03, 1.01), ncol=2, frameon=False)
    style_axes(ax)
    fig.tight_layout(pad=0.6)
    return fig


def update_figure(rows: list[dict]):
    fig, ax = plt.subplots(figsize=(3.5, 3.3))
    y, left = np.arange(len(rows)), np.zeros(len(rows))
    for key, color, hatch, label in (
        ("rejected", GREY, "///", "Rejected before publication"),
        ("accepted_ineligible", BLUE, "", "Published, validation-ineligible"),
        ("eligible", ORANGE, "...", "Validation-eligible; not retained"),
    ):
        values = np.array([row[key] for row in rows])
        ax.barh(y, values, left=left, color=color, hatch=hatch, edgecolor="white",
                linewidth=0.5, height=0.65, label=label)
        for i, value in enumerate(values):
            if value:
                ax.text(left[i] + value / 2, i, str(value), color="white", va="center", ha="center", fontsize=7,
                        bbox={"facecolor": color, "edgecolor": "none", "pad": 0.3})
        left += values
    for i, row in enumerate(rows):
        ax.text(row["attempts"] + 1.2, i, str(row["attempts"]), va="center", fontsize=7)
    ax.set_yticks(y, [row["label"] for row in rows])
    ax.invert_yaxis()
    ax.set_xlim(0, 60)
    ax.set_xticks(range(0, 61, 10))
    ax.set_xlabel("Training attempts (total at bar end)")
    ax.legend(loc="upper left", bbox_to_anchor=(-0.4, -0.22), fontsize=7, frameon=False)
    style_axes(ax)
    fig.subplots_adjust(left=0.3, right=0.98, top=0.97, bottom=0.32)
    return fig


def cascade_figure(rows: list[dict]):
    fig, axes = plt.subplots(1, 2, figsize=(7.1, 2.65), sharey=True)
    y = np.arange(len(rows))
    for ax, metric, color, title, upper, ticks in (
        (axes[0], "fp", ORANGE, "False positives (238 negative prompts)", 200, range(0, 201, 50)),
        (axes[1], "fn", BLUE, "False negatives (264 positive prompts)", 30, range(0, 31, 5)),
    ):
        values = [row[metric] for row in rows]
        ax.barh(y, values, color=color, height=0.6)
        for yy, value in zip(y, values):
            ax.text(value + upper * 0.025, yy, str(value), va="center", fontsize=8)
        ax.set_xlim(0, upper)
        ax.set_xticks(list(ticks))
        ax.set_xlabel("Prompt count")
        ax.set_title(title, fontsize=8.5)
        style_axes(ax)
    axes[0].set_yticks(y, [row["label"] for row in rows])
    axes[0].invert_yaxis()
    fig.tight_layout(pad=0.8, w_pad=2)
    return fig


def external_figure(rows: list[dict]):
    fig, ax = plt.subplots(figsize=(3.5, 2.5))
    y = np.arange(len(rows))
    delta = np.array([row["delta_pp"] for row in rows])
    lower = np.array([row["lower_pp"] for row in rows])
    upper = np.array([row["upper_pp"] for row in rows])
    ax.axvline(0, color=GREY, linestyle="--", linewidth=0.8)
    ax.errorbar(delta, y, xerr=[delta - lower, upper - delta], fmt="o", color=BLUE,
                capsize=3, markersize=4, linewidth=1, zorder=3)
    for yy, point, lo, hi in zip(y, delta, lower, upper):
        ax.text(-14.5, yy + 0.28, f"{point:+.2f}  [{lo:+.2f}, {hi:+.2f}]", fontsize=7, va="center")
    ax.set_yticks(y, [row["label"] for row in rows])
    ax.set_ylim(len(rows) - 0.45, -0.45)
    ax.set_xlim(-15, 5)
    ax.set_xticks([-15, -10, -5, 0, 5])
    ax.set_xlabel("Specificity change (percentage points)\nExpanded minus matched fitted control")
    style_axes(ax)
    fig.tight_layout(pad=0.6)
    return fig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "paper" / "figures")
    parser.add_argument("--overwrite", action="store_true", help="replace only this script's named outputs")
    parser.add_argument("--validate-only", action="store_true", help="check sources without writing figures")
    args = parser.parse_args()
    data, sources = load_data()
    if args.validate_only:
        print("Validated aggregate counts, rates, nested study outcomes and reported intervals.")
        return 0
    output = args.output_dir.resolve()
    targets = [output / f"{name}.{ext}" for name in FIGURE_NAMES for ext in ("png", "svg")]
    manifest_path = output / "results-figure-manifest.json"
    if not args.overwrite and any(path.exists() for path in [*targets, manifest_path]):
        parser.error("Named figure outputs already exist; use --overwrite to regenerate them")
    output.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 8,
                         "axes.labelsize": 8, "xtick.labelsize": 7, "ytick.labelsize": 8,
                         "svg.fonttype": "none", "svg.hashsalt": "privoke-results-20261008"})
    makers = (layer_figure, update_figure, cascade_figure, external_figure)
    groups = (data["layers"], data["studies"], data["cascade"], data["external"])
    for name, make, rows in zip(FIGURE_NAMES, makers, groups):
        figure = make(rows)
        figure.savefig(output / f"{name}.png", dpi=450, metadata={"Software": "Matplotlib"})
        figure.savefig(output / f"{name}.svg", metadata={"Date": None})
        plt.close(figure)
    manifest = {"schema_version": 1, "scope": "Exploratory aggregate evidence; no raw/final examples accessed",
                "source_hash_algorithm": "SHA-256 of UTF-8 text with LF line endings",
                "sources": sources, "plotted_data": data,
                "uncertainty": {"layers": "not plotted", "cascade": "paired intervals uncomputed",
                                "external": "reported descriptive 95% paired source-group intervals; 2000 resamples, 714 groups, seed 10102026"},
                "reproduction": {"command": "python paper/scripts/plot_paper_results.py --overwrite",
                                 "matplotlib": matplotlib.__version__,
                                 "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                "outputs": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in targets}}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(FIGURE_NAMES)} PNG/SVG figure pairs and provenance manifest to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
