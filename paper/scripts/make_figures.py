#!/usr/bin/env python3
"""Regenerate the CSV data behind the pgfplots figures of main.tex.

Every number is read from an aggregate already recorded under paper/research/:

* agreement.csv   <- pipeline-comparison-20261014.json   (models[*].joint/action)
* presence.csv    <- final-semantic-evidence-20261014.json (metrics[*] confusion)
* continuation.csv<- controlled-studies-20261014.json     (adaptation.full_minus_heads, effective_outcomes)
* latency.csv     <- v3-standard-installed-evidence-20261017.md (resident cost table)

The script uses only the standard library. Re-run it after a record changes:
    python paper/scripts/make_figures.py
The plots themselves are typeset by pgfplots inside main.tex (no matplotlib is
available in the maintained evaluation environments).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "research"
OUT = ROOT / "figures" / "data"


def load(name: str):
    return json.loads((RESEARCH / name).read_text(encoding="utf-8"))


def write(name: str, header: list[str], rows: list[list]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    lines = [",".join(header)] + [",".join(str(v) for v in row) for row in rows]
    (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote figures/data/{name} ({len(rows)} rows)")


def agreement() -> None:
    models = {m["name"]: m for m in load("pipeline-comparison-20261014.json")["models"]}
    rows = []
    for tier in ("efficient", "balanced", "quality"):
        old, new = models[f"v1-{tier}"], models[f"v3-{tier}"]
        assert old["denominator"] == new["denominator"] == 1560
        rows.append([tier, old["joint"], new["joint"], old["action"], new["action"]])
    write("agreement.csv", ["tier", "joint_hist", "joint_upd", "action_hist", "action_upd"], rows)


def presence() -> None:
    metrics = load("final-semantic-evidence-20261014.json")["metrics"]
    rows = []
    for tier in ("efficient", "balanced", "quality"):
        vals = []
        for gen in ("v1", "v3"):
            c = metrics[f"{gen}-{tier}"]["successful_confusion"]
            recall = 100.0 * c["tp"] / (c["tp"] + c["fn"])
            spec = 100.0 * c["tn"] / (c["tn"] + c["fp"])
            vals += [round(recall, 2), round(spec, 2)]
        rows.append([tier] + vals)
    write("presence.csv", ["tier", "recall_hist", "spec_hist", "recall_upd", "spec_upd"], rows)


def continuation() -> None:
    adaptation = load("controlled-studies-20261014.json")["adaptation"]
    rows = []
    for seed in ("42", "43", "44"):
        m = adaptation["full_minus_heads"][seed]["metrics"]
        guard = adaptation["effective_outcomes"][f"steps64-full_encoder-{seed}"]["guard_mapping"]["guard_pass"]
        rows.append([
            seed,
            m["joint"]["improved"], -m["joint"]["regressed"],
            m["action"]["improved"], -m["action"]["regressed"],
            int(bool(guard)),
        ])
    write("continuation.csv",
          ["seed", "joint_gain", "joint_loss", "action_gain", "action_loss", "full_guard_pass"], rows)


def latency() -> None:
    text = (RESEARCH / "v3-standard-installed-evidence-20261017.md").read_text(encoding="utf-8")
    section = text.split("## Resident request-to-receiver cost", 1)[1].split("Per-profile median", 1)[0]
    names = {"Detectors off": "Off", "Regex + NER": "Rules/NER", "Semantic": "Semantic", "Full product": "Full"}
    rows = []
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 6 and cells[0] in ("fetch", "XHR") and cells[2].isdigit():
            arm = next(v for k, v in names.items() if cells[1].startswith(k))
            rows.append([f"{cells[0]}-{arm}", cells[0], arm, cells[3], cells[4], cells[5]])
    assert len(rows) == 8, rows
    write("latency.csv", ["cell", "transport", "arm", "p50", "p95", "max"], rows)


if __name__ == "__main__":
    agreement()
    presence()
    continuation()
    latency()
