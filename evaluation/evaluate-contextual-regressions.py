"""Score provisional contextual regression fixtures against a frozen cascade."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("contextual_cascade", ROOT / "evaluation/evaluate-contextual-cascade.py")
CASCADE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CASCADE)
from privoke_contracts.classification import Category

RANK = {"ALLOW": 0, "WARN": 1, "BLOCK": 2}


def load_cases(path, expected_counts=None):
    rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line]
    seen = set()
    categories = {item.name for item in Category}
    for row in rows:
        if (not isinstance(row.get("case_id"), str) or not row["case_id"] or row["case_id"] in seen
                or not isinstance(row.get("family_id"), str) or not row["family_id"]
                or not isinstance(row.get("text"), str) or not row["text"].strip()
                or type(row.get("ambiguous")) is not bool
                or type(row.get("required_sensitive")) not in (bool, type(None))
                or not isinstance(row.get("label_status"), str) or not row["label_status"]
                or not isinstance(row.get("provisional_annotation_rationale"), str) or not row["provisional_annotation_rationale"]):
            raise ValueError("Invalid contextual fixture identity/truth/provenance.")
        if row.get("expected_sensitivity") not in (None, "S0", "S1", "S2", "S3") or row.get("expected_visibility") not in (None, "P0", "P1", "P2", "P3", "P4", "PU"):
            raise ValueError("Invalid contextual sensitivity or visibility label.")
        expected_categories = row.get("expected_categories")
        if expected_categories is not None and (not isinstance(expected_categories, list) or any(x not in categories for x in expected_categories) or len(expected_categories) != len(set(expected_categories))):
            raise ValueError("Invalid contextual category labels.")
        if row.get("expected_action") not in (None, *RANK) or row.get("minimum_action") not in (None, *RANK):
            raise ValueError("Invalid contextual action label.")
        allowed = row.get("allowed_actions")
        if allowed is not None and (not isinstance(allowed, list) or not allowed or any(x not in RANK for x in allowed) or len(allowed) != len(set(allowed))):
            raise ValueError("Invalid allowed contextual actions.")
        for flag in ("context_truth_eligible", "action_accuracy_eligible"):
            if flag in row and type(row[flag]) is not bool:
                raise ValueError("Invalid contextual metric eligibility flag.")
        if row["ambiguous"] and (row.get("required_sensitive") is not None or allowed is not None
                                 or any(row.get(flag, False) for flag in ("context_truth_eligible", "action_accuracy_eligible"))):
            raise ValueError("Ambiguous cases must have unknown contextual truth and no quantitative eligibility.")
        if row.get("visibility_hint") not in (None, "P0", "P1", "P2", "P3", "P4", "PU"):
            raise ValueError("Invalid supplied visibility hint.")
        seen.add(row["case_id"])
    counts = {"control": sum(not r["ambiguous"] and r["required_sensitive"] is False for r in rows),
              "disclosure": sum(not r["ambiguous"] and r["required_sensitive"] is True for r in rows),
              "ambiguous_excluded": sum(r["ambiguous"] for r in rows)}
    expected_counts = expected_counts or {"control": 24, "disclosure": 17, "ambiguous_excluded": 7}
    receipt_counts = expected_counts
    if "controls" in expected_counts:
        expected_counts = {"control": expected_counts["controls"], "disclosure": expected_counts["disclosure_candidates"],
                           "ambiguous_excluded": expected_counts["ambiguous_excluded"]}
    if len(rows) != 48 or counts != expected_counts:
        raise ValueError("Fixture counts differ from the frozen reviewed composition.")
    actual_extra = {"total": len(rows), "families": len({r["family_id"] for r in rows}),
                    "context_truth_eligible": sum(r.get("context_truth_eligible", not r["ambiguous"]) for r in rows),
                    "action_accuracy_eligible": sum(r.get("action_accuracy_eligible", not r["ambiguous"]) for r in rows),
                    "visibility_hints": sum(r.get("visibility_hint") is not None for r in rows)}
    if any(receipt_counts[key] != value for key, value in actual_extra.items() if key in receipt_counts):
        raise ValueError("Fixture family/eligibility/hint counts differ from review receipt.")
    return rows


def action_requirement(case):
    return case.get("minimum_action") or case.get("expected_action")


def provisional_metrics(rows, key):
    primary = [r for r in rows if not r["case"]["ambiguous"]]
    confusion = Counter()
    agreements = {name: {"correct": 0, "labelled": 0} for name in ("sensitivity", "visibility", "categories")}
    minimum_pass = minimum_total = clean_interventions = clean_total = 0
    private_action_pass = private_action_total = 0
    allowed_pass = allowed_total = 0
    for row in primary:
        case, output = row["case"], row[key]
        action_eligible = case.get("action_accuracy_eligible", True)
        context_eligible = case.get("context_truth_eligible", True)
        if action_eligible and case.get("expected_action") is not None:
            confusion[f"{case['expected_action']}->{output['action']}"] += 1
        allowed = case.get("allowed_actions")
        if action_eligible and (allowed is not None or case.get("expected_action") is not None):
            allowed_total += 1
            permitted = allowed if allowed is not None else [case["expected_action"]]
            allowed_pass += output["action"] in permitted
        requirement = action_requirement(case)
        if action_eligible and requirement in ("WARN", "BLOCK"):
            minimum_total += 1
            minimum_pass += RANK[output["action"]] >= RANK[requirement]
        if action_eligible and case["required_sensitive"] is True and requirement in ("WARN", "BLOCK"):
            private_action_total += 1
            private_action_pass += RANK[output["action"]] >= RANK[requirement]
        if action_eligible and case["required_sensitive"] is False and (allowed == ["ALLOW"] or allowed is None and case.get("expected_action") == "ALLOW"):
            clean_total += 1
            clean_interventions += output["action"] != "ALLOW"
        for name in agreements:
            expected = case.get("expected_" + name)
            if context_eligible and expected is not None:
                agreements[name]["labelled"] += 1
                actual = output["classification"][name]
                agreements[name]["correct"] += sorted(actual) == sorted(expected) if name == "categories" else actual == expected
    for value in agreements.values():
        value["agreement"] = value["correct"] / value["labelled"] if value["labelled"] else None
    return {"primary_cases": len(primary), "ambiguous_excluded": len(rows) - len(primary),
            "action_confusion": dict(confusion), "classification_agreement": agreements,
            "allowed_or_exact_action": {"passed": allowed_pass, "labelled": allowed_total},
            "minimum_action": {"passed": minimum_pass, "labelled": minimum_total},
            "provisional_private_action_requirement": {"passed": private_action_pass, "labelled": private_action_total},
            "provisional_clean_interventions": {"intervened": clean_interventions, "labelled": clean_total}}


def paired_metrics(rows):
    private_losses, downgrades = [], []
    transitions = Counter()
    families = defaultdict(list)
    for row in rows:
        case = row["case"]
        families[case["family_id"]].append(row)
        if case["ambiguous"]:
            continue
        before, after = row["ordinary"]["action"], row["gated"]["action"]
        transitions[f"{before}->{after}"] += 1
        if RANK[after] < RANK[before]:
            downgrades.append(case["case_id"])
        required = action_requirement(case)
        if case["required_sensitive"] is True and required in ("WARN", "BLOCK") and RANK[before] >= RANK[required] > RANK[after]:
            private_losses.append(case["case_id"])
    return {"ordinary": provisional_metrics(rows, "ordinary"), "gated": provisional_metrics(rows, "gated"),
            "action_transitions": dict(transitions), "action_downgrade_case_ids": downgrades,
            "private_action_loss_case_ids": private_losses,
            "ambiguous_qualitative_case_ids": [r["case"]["case_id"] for r in rows if r["case"]["ambiguous"]],
            "per_family": {family: {"ordinary": provisional_metrics(values, "ordinary"),
                                     "gated": provisional_metrics(values, "gated")} for family, values in sorted(families.items())},
            "label_limitation": "Authored provisional regression requirements; not independent human contextual annotation or deployment approval."}


def frozen_study(study_root, validation_file):
    study_root = CASCADE.inside_results(study_root)
    manifest = CASCADE.read(study_root / "study-manifest.json")
    binding = manifest["binding"]
    reference = CASCADE.dataset(validation_file, "validation")
    if (set(binding.get("controls", {})) != set(CASCADE.CONTROLS)
            or set(binding.get("presence", {})) != set(CASCADE.PROFILES)
            or binding.get("datasets") != {k: list(v) for k, v in CASCADE.DATA.items()}):
        raise ValueError("Study does not bind the prescribed controls, profiles and data.")
    for control in CASCADE.CONTROLS:
        identity = binding["controls"][control]["identity"]
        if identity.get("model_id") != "privoke-balanced" or identity.get("artifact_checksum") != CASCADE.CHECKSUMS[control] or not re.fullmatch(r"[0-9a-f]{64}", identity.get("parameter_fingerprint", "")):
            raise ValueError("Frozen contextual control identity mismatch.")
    for profile in CASCADE.PROFILES:
        identity = binding["presence"][profile]["identity"]
        if identity.get("model_id") != "privoke-presence-" + profile or any(not re.fullmatch(r"[0-9a-f]{64}", identity.get(k, "")) for k in ("artifact_checksum", "parameter_fingerprint")):
            raise ValueError("Frozen presence profile identity mismatch.")
    selection_path = study_root / "calibration/selection.json"
    selection = CASCADE.read(selection_path)
    if selection.get("status") != "frozen" or selection.get("binding") != binding or set(selection.get("choices", {})) != set(CASCADE.PAIRS) or selection.get("frozen_before_development") is not True:
        raise ValueError("Regression caller requires all six frozen choices.")
    for pair in CASCADE.PAIRS:
        collection = study_root / "collect-validation" / pair
        rows = CASCADE.verified_rows(collection, reference, binding, pair)
        chosen = selection["choices"][pair]
        reconstructed = CASCADE.calibrate(rows)
        if (chosen.get("chosen") != reconstructed["chosen"] or chosen.get("status") != reconstructed["status"]
                or chosen.get("collection_report_sha256") != CASCADE.sha(collection / "report.json")):
            raise ValueError("Frozen calibration selection/report mismatch.")
        validation = study_root / "evaluate-validation" / pair
        if chosen["status"] == "ineligible":
            if CASCADE.read(validation / "skipped.json") != {"status": "skipped_ineligible", "pair": pair, "binding": binding,
                                                            "selection_sha256": CASCADE.sha(selection_path)}:
                raise ValueError("Ineligible pair lacks frozen skip evidence.")
            continue
        live = CASCADE.verified_rows(validation, reference, binding, pair)
        proof = validation / "selection-binding.json"
        expected = {"selection_sha256": CASCADE.sha(selection_path), "decision_threshold": chosen["chosen"]["threshold"]}
        if CASCADE.read(proof) != expected or CASCADE.sha(proof) != CASCADE.read(validation / "report.json").get("selection_binding_sha256"):
            raise ValueError("Validation parity is not bound to frozen selection.")
        if any(CASCADE.summary(x["gated"]) != CASCADE.summary(CASCADE.project(y, expected["decision_threshold"])) for x, y in zip(live, rows)):
            raise ValueError("Selected validation did not match frozen projection.")
    return binding, selection, CASCADE.sha(selection_path)


def run(args, client_factory=CASCADE.RuntimeClient):
    output = CASCADE.inside_results(args.output_dir)
    if output.exists():
        raise FileExistsError("Refusing reused contextual regression evidence.")
    binding, selection, selection_sha = frozen_study(args.study_root, args.validation_file)
    if args.runtime_image_id != binding["runtime_image_id"]:
        raise ValueError("Runtime image differs from the frozen cascade study.")
    fixture_sha, rubric_sha = CASCADE.sha(args.case_file), CASCADE.sha(args.rubric_file)
    review = CASCADE.read(args.fixture_review_file)
    if review.get("status") != "reviewed" or review.get("case_file_sha256") != fixture_sha or review.get("rubric_sha256") != rubric_sha:
        raise ValueError("Fixture/rubric must have a digest-bound review before scoring.")
    cases = load_cases(args.case_file, review.get("case_counts") or review.get("expected_counts") or review.get("reviewed_counts"))
    pair = f"{args.control}-{args.profile}"
    choice = selection["choices"][pair]
    output.mkdir(parents=True, exist_ok=False)
    record = {"status": "started", "source_revision": args.source_revision, "study_binding": binding,
              "selection_sha256": selection_sha, "pair": pair, "case_file_sha256": fixture_sha,
              "rubric_sha256": rubric_sha, "fixture_review_sha256": CASCADE.sha(args.fixture_review_file),
              "caller_sha256": CASCADE.sha(Path(__file__)), "cascade_helper_sha256": CASCADE.sha(ROOT / "evaluation/evaluate-contextual-cascade.py"),
              "runtime_image_id": args.runtime_image_id, "evaluator_image_id": args.evaluator_image_id}
    record["validation_file_sha256"] = CASCADE.sha(args.validation_file)
    CASCADE.write(output / "binding.json", record)
    if choice["status"] == "ineligible":
        CASCADE.write(output / "skipped.json", {**record, "status": "skipped_ineligible"})
        return
    identities = {"semantic": binding["controls"][args.control]["identity"],
                  "presence": binding["presence"][args.profile]["identity"]}
    threshold = choice["chosen"]["threshold"]
    client, rows = None, []
    try:
        client = client_factory(args.target or binding["target"])
        for case in cases:
            row = {"id": case["case_id"], "text": case["text"]}
            kwargs = {"visibility_hint": case["visibility_hint"]} if case.get("visibility_hint") is not None else {}
            ordinary = CASCADE.record_rpc(client, row, output, "ordinary", identities["semantic"]["model_id"], **kwargs)
            gated = CASCADE.record_rpc(client, row, output, "gated", identities["semantic"]["model_id"],
                                       presence_id=identities["presence"]["model_id"], threshold=threshold, **kwargs)
            trace = CASCADE.verify_live(ordinary, gated, identities, threshold)
            result = {"case": case, "ordinary": ordinary, "gated": gated, "trace": trace,
                      "ordinary_binary_proxy": CASCADE.detection(ordinary), "gated_binary_proxy": CASCADE.detection(gated)}
            rows.append(result)
            CASCADE.write(output / "rows" / (hashlib.sha256(case["case_id"].encode()).hexdigest() + ".json"), result)
        if (CASCADE.sha(args.case_file) != fixture_sha or CASCADE.sha(args.rubric_file) != rubric_sha
                or CASCADE.sha(args.fixture_review_file) != record["fixture_review_sha256"]
                or CASCADE.sha(Path(args.study_root) / "calibration/selection.json") != selection_sha):
            raise ValueError("Frozen fixtures/rubric/selection changed during scoring.")
        CASCADE.dataset(args.validation_file, "validation")
        CASCADE.write(output / "predictions.json", rows)
        CASCADE.write(output / "report.json", {**record, "status": "complete", "errors": [], "decision_threshold": threshold,
                                              "rows": len(rows), **paired_metrics(rows),
                                              "predictions_sha256": CASCADE.sha(output / "predictions.json"),
                                              "raw_rpc_sha256": {p.name: CASCADE.sha(p) for p in sorted((output / "raw").glob("*.json"))}})
    except Exception as exc:
        CASCADE.write(output / "failure.json", {**record, "status": "failed", "error": str(exc), "completed_rows": len(rows)})
        raise
    finally:
        if client:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("study-root", "validation-file", "case-file", "rubric-file", "fixture-review-file", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--control", choices=CASCADE.CONTROLS, required=True)
    parser.add_argument("--profile", choices=CASCADE.PROFILES, required=True)
    for name in ("source-revision", "runtime-image-id", "evaluator-image-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--target")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision) or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in (args.runtime_image_id, args.evaluator_image_id)):
        parser.error("Require execution revision and actual inspected Docker Image digests.")
    run(args)


if __name__ == "__main__":
    main()
