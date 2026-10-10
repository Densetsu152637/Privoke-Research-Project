"""Verify published aggregates; optionally regenerate the allowlisted local projection.

No model inference, fitting, network access, or protected-final input is used.
Default verification requires only Python's standard library and this directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STUDY = ROOT / "evaluation/results/semantic_pretrained_20261010"
RAW = STUDY / "prepared-v3"
ASSETS = ROOT / "evaluation/results/semantic_improvement_20261010_assets"
SEEDS = (42, 43, 44)
RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")


def pick(value, keys):
    return {key: value[key] for key in keys}


def publish():
    sources = {}

    def source(path):
        sources[path.relative_to(ROOT).as_posix()] = digest(path)
        return read(path)

    summary = source(RAW / "summary.json")
    assert sources[(RAW / "summary.json").relative_to(ROOT).as_posix()] == "2d673c73234b9d96a126847f3aa29fb971fae17c110ecf4a77f2d0126a1b7668"
    fit_handoff = source(RAW / "sg6-fit-handoff.json")
    rows, operations, selections = {}, {}, {}
    for arm in ("random", "pretrained"):
        for seed in SEEDS:
            tag = f"{arm}-{seed}"
            endpoint = source(RAW / f"assessment-{tag}.json")
            assert endpoint["status"] == "complete" and endpoint["runtime_errors"] == 0
            rows[tag] = {
                "identity": endpoint["identity"],
                "selection_commitment_sha256": endpoint["selection_commitment_sha256"],
                "rows": [pick(row, ("id", "family_id", "target", "classification", "required_action", "action"))
                         for row in endpoint["predictions"]],
            }
            op = source(RAW / f"operational-{tag}.json")
            operations[tag] = pick(op, ("identity", "cpu_name", "platform", "encoder_threads", "workload_sha256",
                "transport", "measured_requests", "warmup_requests", "warm_p95_ms", "peak_runtime_RSS_bytes",
                "offline_cold_model_construction_ms", "cold_load_scope", "operational_gate_pass"))
            selection = source(RAW / "fit" / tag / "selection.json")
            selections[tag] = pick(selection, ("arm", "seed", "selected", "steps", "orders_sha256", "freeze_sha256", "selection_rule"))
    write("primary.json", {"source_revision": summary["source_revision"], "paired_seeds": summary["paired_seeds"],
        "same_seed_primary_gate_pass": summary["same_seed_primary_gate_pass"], "all_seed_vetoes_clear": summary["all_seed_vetoes_clear"],
        "engineering_qualified": summary["engineering_qualified"], "operational_gate_pass": summary["operational_gate_pass"],
        "automatic_promotion": False, "fit_phase_elapsed_seconds": fit_handoff["fit_elapsed_seconds"], "synthetic_predictions": rows, "operations": operations, "selections": selections})
    secondary = source(ASSETS / "sg10/aggregate.json")
    audit = source(STUDY / "secondary-audit/audit.json")
    cells = []
    for cell in secondary["cells"]:
        audited = audit["cells"][cell["tag"]]["endpoints"]
        cells.append({"tag": cell["tag"], "identity": cell["identity"], "receipt_sha256": cell["receipt_sha256"],
            "development_reused": cell["development_reused"],
            "development": pick(audited["development_presence"], ("counts", "ok", "errors", "error_positive_labels", "error_negative_labels", "recall_successful_only", "specificity_successful_only", "coverage")),
            "historical_fixture": pick(audited["historical_fixture"], ("ok", "errors", "ambiguous_null_actions", "sensitivity_correct", "action_correct", "denominator"))})
    write("secondary.json", {"controller_revision": secondary["controller_revision"], "runtime_revision": secondary["frozen_runtime_source_revision"],
        "amendment_sha256": secondary["amendment_sha256"], "counts": audit["counts"], "cells": cells,
        "hint_scope": audit["hint_scope"], "fixture_casewise_regressions": audit["fixture_casewise_regressions"],
        "failed_input_lengths": secondary["failed_input_lengths"], "passed_archive_audit": audit["passed_archive_audit"],
        "secondary_error_free": audit["secondary_error_free"], "original_failed_receipt_sha256": secondary["original_failed_receipt_sha256"],
        "original_primary_summary_sha256": secondary["original_primary_summary_sha256"]})
    extension = source(ASSETS / "token-limit-512-20261010/aggregate.json")
    write("context512.json", pick(extension, ("source_revision", "actual_requests", "successful_semantic_requests", "expected_semantic_errors", "records", "short_train_parity", "previous_error_coverage", "quality_claim", "latency_qualification", "training", "promotion")))
    for path in (RAW / "freeze.json", RAW / "protocol.json", RAW / "eligibility.json", RAW / "resource-review.json",
                 RAW / "selection-commitment.json", RAW / "secondary-amendment-fixture-action-v1.json",
                 STUDY / "primary-audit/audit.json", ASSETS / "config.json", ASSETS / "sentence_bert_config.json",
                 ASSETS / "sg10/evidence-hashes.json",
                 ASSETS / "token-limit-512-20261010/evidence-hashes.json", ASSETS / "token-limit-512-20261010/final-cleanup.json",
                 ASSETS / "token-limit-512-20261010/harness-amendment.json", ASSETS / "token-limit-512-20261010/utf8-recovery.json"):
        if not path.is_file():
            raise ValueError(f"Missing committed source evidence locator: {path.name}")
        sources[path.relative_to(ROOT).as_posix()] = digest(path)
    write("provenance.json", {"research_id": "RQ-SEM-PRETRAINED-CONTEXT-20261010", "raw_sources": sources,
        "projection": "Explicit key allowlist: synthetic labels/actions, aggregate counts, model identities, hashes and functional token counts; no prompt text, raw responses, logits or public-development labels per row.",
        "scope": "Public arithmetic reproduction, not independent rerun of models or verification of unavailable raw evidence.",
        "raw_evidence_modified": False, "protected_final_opened": False})
    names = ("primary.json", "secondary.json", "context512.json", "provenance.json", "reproduce.py")
    write("publication-hashes.json", {"schema_version": 1, "files": {name: digest(HERE / name) for name in names}})


def metrics(rows, predicate):
    group = [row for row in rows if predicate(row["target"])]
    return {"denominator": len(group),
        "joint_correct": sum(row["target"] == row["classification"] for row in group),
        "union_detected": sum(row["classification"]["sensitivity"] != "S0" or bool(row["classification"]["categories"]) for row in group),
        "sensitivity_detected": sum(row["classification"]["sensitivity"] != "S0" for row in group),
        "union_clean": sum(row["classification"]["sensitivity"] == "S0" and not row["classification"]["categories"] for row in group),
        "action_correct": sum(row["action"] == row["required_action"] for row in group)}


def verify():
    manifest = read(HERE / "publication-hashes.json")
    for name, expected in manifest["files"].items():
        assert Path(name).name == name and digest(HERE / name) == expected, name
    primary = read(HERE / "primary.json")
    predicates = {"nonS0": lambda t: t["sensitivity"] != "S0", "serious": lambda t: t["sensitivity"] in ("S2", "S3"), "S0": lambda t: t["sensitivity"] == "S0"}
    gains, vetoes = [], []
    for seed in SEEDS:
        pair = primary["paired_seeds"][str(seed)]
        arms = [primary["synthetic_predictions"][f"{arm}-{seed}"]["rows"] for arm in ("random", "pretrained")]
        assert len(arms[0]) == len(arms[1]) == 160
        for rows, role in zip(arms, ("baseline", "candidate")):
            assert len({row["id"] for row in rows}) == 160 and len({row["family_id"] for row in rows}) == 10
            for row in rows:
                assert set(row) == {"id", "family_id", "target", "classification", "required_action", "action"}
                assert row["id"].startswith("contextual-head-20261010/")
                for field in ("target", "classification"):
                    assert set(row[field]) == {"sensitivity", "visibility", "categories"}
                assert row["action"] in RANK and row["required_action"] in RANK
            for group, predicate in predicates.items():
                assert metrics(rows, predicate) == pair[role][group], (seed, role, group)
            for category, expected in pair[role]["categories"].items():
                values = {"TP": 0, "FP": 0, "FN": 0}
                for row in rows:
                    target, predicted = category in row["target"]["categories"], category in row["classification"]["categories"]
                    if target and predicted: values["TP"] += 1
                    if predicted and not target: values["FP"] += 1
                    if target and not predicted: values["FN"] += 1
                assert values == expected
            for cardinality, expected in pair[role]["cardinality"].items():
                group = [r for r in rows if len(r["target"]["categories"]) == int(cardinality)]
                assert {"denominator": len(group), "categoryset_exact": sum(r["target"]["categories"] == r["classification"]["categories"] for r in group)} == expected
        baseline = {r["id"]: r for r in arms[0]}
        harms = []
        for row in arms[1]:
            old = baseline[row["id"]]
            assert old["target"] == row["target"] and old["required_action"] == row["required_action"]
            if predicates["serious"](row["target"]) and min(RANK[row["action"]], RANK[row["required_action"]]) < min(RANK[old["action"]], RANK[row["required_action"]]):
                harms.append({"id": row["id"], "visibility": row["target"]["visibility"], "required_action": row["required_action"], "before_action": old["action"], "after_action": row["action"]})
        assert harms == pair["serious_action_harms"]
        assert [h for h in harms if h["visibility"] in ("P2", "P3", "P4")] == pair["private_serious_action_harms"]
        b, c = pair["baseline"], pair["candidate"]
        gain = c["nonS0"]["joint_correct"] - b["nonS0"]["joint_correct"] >= 10 and c["serious"]["joint_correct"] - b["serious"]["joint_correct"] >= 8
        limits = b["nonS0"]["union_detected"] - c["nonS0"]["union_detected"] <= 2 and b["serious"]["union_detected"] - c["serious"]["union_detected"] <= 1 and b["S0"]["union_clean"] - c["S0"]["union_clean"] <= 1
        assert gain == pair["both_primary_gains"] and (limits and not harms) == pair["veto_clear"]
        gains.append(gain); vetoes.append(limits and not harms)
    ops = all(o["warm_p95_ms"] <= 500 and o["peak_runtime_RSS_bytes"] <= 1024**3 for o in primary["operations"].values())
    assert ops == primary["operational_gate_pass"]
    assert (sum(gains) >= 2 and all(vetoes) and ops) == primary["engineering_qualified"] == False
    secondary = read(HERE / "secondary.json")
    assert len(secondary["cells"]) == 7
    for cell in secondary["cells"]:
        d = cell["development"]; c = d["counts"]
        assert sum(c.values()) == d["ok"] and d["ok"] + d["errors"] == 502
        assert abs(c["true_positives"] / (c["true_positives"] + c["false_negatives"]) - d["recall_successful_only"]) < 1e-12
        assert abs(c["true_negatives"] / (c["true_negatives"] + c["false_positives"]) - d["specificity_successful_only"]) < 1e-12
        assert c["true_positives"] + c["false_negatives"] + d["error_positive_labels"] == 264
        assert c["true_negatives"] + c["false_positives"] + d["error_negative_labels"] == 238
        assert cell["historical_fixture"]["denominator"] == 41 and cell["historical_fixture"]["ambiguous_null_actions"] == 7
    assert sum(c["development"]["errors"] for c in secondary["cells"]) == secondary["counts"]["errors"] == 6
    witnesses = secondary["fixture_casewise_regressions"]
    assert len(witnesses) == 6
    for name, harms in witnesses.items():
        assert len(harms) == 1
        h = harms[0]
        assert h["id"] == "cc-credentials-03" and h["required"] == "BLOCK" and h["after"] == "ALLOW"
        assert h["before"] == ("WARN" if name.endswith("baseline") else "BLOCK")
        assert h["expected_visibility"] == "PU" and not h["has_unforwarded_hint"]
    extension = read(HERE / "context512.json")
    assert len(extension["records"]) == extension["actual_requests"] == 9
    assert sum(r["status"] == "ok" for r in extension["records"]) == extension["successful_semantic_requests"] == 7
    for row in extension["records"]:
        assert (row["tokens"] > row["profile"]) == row["expected_error"] == (row["status"] == "error")
    assert extension["short_train_parity"] and not extension["quality_claim"] and not extension["latency_qualification"]
    print("PASS: publication hashes; 960 synthetic predictions; paired gates and harms; secondary counts/coverage; nine context-limit outcomes. Qualification remains false.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish-local", action="store_true", help="Regenerate only public projections from existing ignored local receipts; never executes models")
    args = parser.parse_args()
    if args.publish_local:
        publish()
    verify()
