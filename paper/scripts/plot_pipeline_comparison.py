"""Reproduce PAPER14 figures from the tracked, non-text-bearing PIPE3 aggregate.

No prompts, weights, services or protected data are read. See the adjacent README.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "paper/research/pipeline-comparison-20261014.json"
OUTPUT = ROOT / "paper/figures"
TIERS = ("efficient", "balanced", "quality")
COLORS = {"v1": "#0072B2", "v3": "#D55E00"}
MARKERS = {"v1": "o", "v3": "^"}
STEMS = ("results-pipeline-v1-v3", "results-pipeline-v1-v3-cost")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(data: dict) -> dict:
    assert data["schema_version"] == 1
    w = data["workload"]
    assert (w["n"], w["sensitive"], w["clean"], w["repeats"]) == (1560, 810, 750, 3)
    assert w["accuracy_requests"] == w["n"] * w["repeats"] * 6
    assert w["layers"] == [2, 3, 4] and w["regex_order"] == "FIRST"
    assert data["provenance"]["analysis"]["sha256"] == "2d9190cc26003e9916719c96127791b6b348e1a0683a30b11891a058a96a302f"
    assert data["provenance"]["independent_review"]["sha256"] == "7739f7f2e6d9ad907775606353e84cad42556c8915820f420f3d5302717790f0"
    models = {m["name"]: m for m in data["models"]}
    assert len(models) == 6
    for tier in TIERS:
        old, new = (models[g + "-" + tier] for g in ("v1", "v3"))
        for m in (old, new):
            assert m["denominator"] == w["n"] and m["errors"] == 0
            assert m["sensitive_tp"] + m["sensitive_fn"] == w["sensitive"]
            assert m["clean_tn"] + m["clean_fp"] == w["clean"]
            assert m["semantic_executed"] + m["regex_early_block"] == w["n"]
            assert m["semantic_executed"] == 1271 and m["regex_early_block"] == 289
            assert m["action"] + m["under_cases"] + m["over_cases"] == w["n"]
            assert 0 <= m["joint"] <= min(m[k] for k in ("action", "sensitivity", "visibility", "category_exact"))
            assert 0 < m["host_rpc_median_ms"] <= m["host_rpc_p95_ms"]
            assert m["peak_rss_mib"] > 0
        for metric in ("joint", "action"):
            p = data["paired"][tier][metric]
            assert p["denominator"] == w["n"]
            assert p["net_correct"] == p["improved"] - p["regressed"] == new[metric] - old[metric]
    baseline = data.get("presidio_contextual_reference")
    if baseline:
        assert baseline["status"] == "accepted" and baseline["errors"] == 0
        assert baseline["tp"] + baseline["fn"] == w["sensitive"]
        assert baseline["tn"] + baseline["fp"] == w["clean"]
        assert baseline["n"] == w["n"]
        assert baseline["threshold"] == .5
        for name, m in models.items():
            p = baseline["paired"][name]
            assert p["denominator"] == w["n"]
            assert p["improved"] + p["regressed"] + p["both_correct"] + p["both_incorrect"] == w["n"]
            assert p["net_correct"] == p["improved"] - p["regressed"]
            assert p["net_correct"] == m["sensitive_tp"] + m["clean_tn"] - baseline["tp"] - baseline["tn"]
    return models


def style():
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 8,
        "axes.titlesize": 9, "axes.labelsize": 8,
        "xtick.labelsize": 7.5, "ytick.labelsize": 8,
        "legend.fontsize": 8, "axes.spines.top": False,
        "axes.spines.right": False, "axes.spines.left": False,
        "axes.axisbelow": True, "svg.fonttype": "none", "svg.hashsalt": "privoke-paper14",
        "pdf.fonttype": 42, "figure.facecolor": "white",
    })


def axis(ax, title, xlabel, xmax, labels):
    ax.set_title(title, loc="left", fontweight="bold", pad=9)
    ax.set_xlabel(xlabel)
    ax.set_xlim(0, xmax)
    ax.set_yticks(range(len(labels)), labels)
    ax.invert_yaxis()
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color="#D9D9D9", linewidth=.5)
    ax.set_ylim(len(labels) - .45, -.55)


def save(fig, stem, overwrite, outputs):
    for ext in ("png", "svg", "pdf"):
        path = OUTPUT / (stem + "." + ext)
        if path.exists() and not overwrite:
            raise FileExistsError(f"Use --overwrite to replace {path}")
        metadata = {"Title": stem}
        if ext == "pdf":
            metadata.update(CreationDate=None, ModDate=None)
        elif ext == "svg":
            metadata.update(Date=None)
        fig.savefig(path, dpi=450, facecolor="white", metadata=metadata)
        if ext == "svg":
            clean = "\n".join(line.rstrip() for line in path.read_text(encoding="utf8").splitlines()) + "\n"
            path.write_text(clean, encoding="utf8", newline="\n")
        outputs[path.name] = digest(path)
    plt.close(fig)


def paired_points(ax, models, field, denominator, xmax, title, xlabel):
    axis(ax, title, xlabel, xmax, [t.title() for t in TIERS])
    ax.set_ylim(2.80, -.65)
    ax.tick_params(axis="y", pad=7)
    for y, tier in enumerate(TIERS):
        values = [models[g + "-" + tier][field] for g in ("v1", "v3")]
        xs = [v / denominator * 100 if denominator else v for v in values]
        ax.plot(xs, [y, y], color="#A6A6A6", linewidth=1, zorder=1)
        for g, x, value in zip(("v1", "v3"), xs, values):
            ax.scatter(x, y, c=COLORS[g], marker=MARKERS[g], s=34, zorder=3, clip_on=False,
                       label=g.upper() if y == 0 else None)
            text = f"{value:,}" if not denominator else f"{value:,} ({x:.1f}%)"
            offset = 8 if g == "v1" else -8
            alignment = "right" if denominator and x > 80 else "center"
            ax.annotate(text, (x, y), xytext=(0, offset), textcoords="offset points",
                        ha=alignment, va="center", fontsize=7, color=COLORS[g])


def internal(data, models, overwrite, outputs):
    fig, axes = plt.subplots(2, 2, figsize=(7.16, 4.55))
    fig.subplots_adjust(left=.10, right=.97, bottom=.11, top=.88, hspace=.76, wspace=.38)
    paired_points(axes[0, 0], models, "joint", 1560, 100, "(a) Full joint correctness", "Correct cases / 1,560 (%)")
    paired_points(axes[0, 1], models, "action", 1560, 100, "(b) Allowed-action correctness", "Correct cases / 1,560 (%)")
    paired_points(axes[1, 0], models, "under_cases", None, 270, "(c) Under-enforced cases", "Cases (less restrictive than allowed)")
    paired_points(axes[1, 1], models, "over_cases", None, 450, "(d) Over-enforced cases", "Cases (more restrictive than allowed)")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(.54, .995))
    save(fig, STEMS[0], overwrite, outputs)

    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.80))
    fig.subplots_adjust(left=.13, right=.97, top=.87, bottom=.19, wspace=.50)
    labels = [f"{g.upper()} {t.title()}" for t in TIERS for g in ("v1", "v3")]
    ordered = [models[g + "-" + t] for t in TIERS for g in ("v1", "v3")]
    for ax, title, xlabel, xmax in ((axes[0], "(a) Host RPC latency", "Milliseconds (median; line to p95)", 110),
                                    (axes[1], "(b) Peak process RSS", "MiB (server process)", 570)):
        axis(ax, title, xlabel, xmax, labels)
    for y, m in enumerate(ordered):
        color, marker = COLORS[m["generation"]], MARKERS[m["generation"]]
        x = m["host_rpc_median_ms"]
        axes[0].plot([x, m["host_rpc_p95_ms"]], [y, y], color=color, linewidth=1.7)
        axes[0].scatter(x, y, color=color, marker=marker, s=25, zorder=3)
        axes[0].annotate(f"{x:.1f} / {m['host_rpc_p95_ms']:.1f}", (m["host_rpc_p95_ms"], y),
                         xytext=(4, 0), textcoords="offset points", va="center", fontsize=7)
        axes[1].barh(y, m["peak_rss_mib"], height=.50, color=color, alpha=.85)
        axes[1].text(m["peak_rss_mib"] + 8, y, f"{m['peak_rss_mib']:.1f}", va="center", fontsize=7)
    save(fig, STEMS[1], overwrite, outputs)


def reference(data, models, overwrite, outputs):
    baseline = data.get("presidio_contextual_reference")
    if not baseline:
        return
    ordered = [models[g + "-" + t] for t in TIERS for g in ("v1", "v3")]
    labels = [f"{m['generation'].upper()} {m['tier'].title()}" for m in ordered] + ["Presidio (small English)"]
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 3.00))
    fig.subplots_adjust(left=.20, right=.97, top=.88, bottom=.17, wspace=.25)
    for ax, title, field, bfield, n in ((axes[0], "(a) Contextually sensitive recall", "sensitive_tp", "tp", 810),
                                        (axes[1], "(b) Contextually clean specificity", "clean_tn", "tn", 750)):
        axis(ax, title, f"Correct decisions / {n:,} (%)", 112, labels)
        ax.set_xticks([0, 25, 50, 75, 100])
        for y, m in enumerate(ordered):
            x = 100 * m[field] / n
            ax.scatter(x, y, color=COLORS[m["generation"]], marker=MARKERS[m["generation"]], s=27)
            # Left-aligned labels fit even near 100%; the right margin is reserved for them.
            ax.annotate(f"{m[field]}/{n}", (x, y), xytext=(-5, 0), textcoords="offset points",
                        ha="right", va="center", fontsize=7)
        x = 100 * baseline[bfield] / n
        ax.scatter(x, 6, color="#333333", marker="D", s=27)
        ax.annotate(f"{baseline[bfield]}/{n}", (x, 6), xytext=(-5, 0), textcoords="offset points",
                    ha="right", va="center", fontsize=7)
    save(fig, "results-pipeline-presidio-reference", overwrite, outputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    data = json.loads(DATA.read_text(encoding="utf8"))
    models = validate(data)
    if args.validate_only:
        print("PIPE3 aggregate validated: six packages, counts, pairing, errors and execution scope.")
        return
    style()
    OUTPUT.mkdir(exist_ok=True)
    outputs = {}
    internal(data, models, args.overwrite, outputs)
    reference(data, models, args.overwrite, outputs)
    manifest = {"schema_version": 1, "data_path": str(DATA.relative_to(ROOT)).replace("\\", "/"),
                "data_sha256": digest(DATA), "generator_sha256": digest(Path(__file__)),
                "matplotlib_version": matplotlib.__version__, "numpy_version": np.__version__,
                "command": "python paper/scripts/plot_pipeline_comparison.py --overwrite",
                "scope": data["scope"], "outputs": outputs,
                "presidio_reference_present": bool(data.get("presidio_contextual_reference"))}
    (OUTPUT / "results-pipeline-comparison-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    print(f"Generated {len(outputs)} outputs from the tracked PIPE3 aggregate.")


if __name__ == "__main__":
    main()
