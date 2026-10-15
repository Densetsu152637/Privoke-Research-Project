"""Read-only quality reporting for the prospectively fixed 24-attempt study."""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "evaluation" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module("balanced_study", "run-class-balanced-fuzzer-study.py")
Q = module("balanced_quality_helpers", "report-contextual-fuzzer-study.py")
AUDIT_FIELDS = ("training_clean_examples", "training_sensitive_examples", "raw_clean_weight",
                "raw_sensitive_weight", "raw_total_weight", "effective_clean_weight",
                "effective_sensitive_weight", "clean_objective_mass", "sensitive_objective_mass")


def objective_audit(response, record):
    P.require(record["objective"] in P.OBJECTIVES, "Unknown objective in quality evidence.")
    metadata = response.get("metadata", {})
    if record["objective"] == "uniform":
        P.require(not any(key in metadata for key in (*AUDIT_FIELDS, "contextual_training_objective", "objective_strata")),
                  "Control unexpectedly reports a class-balanced objective.")
        return {"objective": "original example weighting", "class_balance_applied": False,
                "scope": "Original row weights preserved; no class-balance audit fields are emitted."}
    P.require(metadata.get("contextual_training_objective") == "class_balanced_contextual_v1"
              and metadata.get("objective_strata") == "classification_is_sensitive", "Objective identity missing or changed.")
    values = {key: float(metadata[key]) for key in AUDIT_FIELDS}
    P.require(all(math.isfinite(value) and value > 0 for value in values.values()), "Invalid objective audit values.")
    P.require(all(values[key].is_integer() for key in AUDIT_FIELDS[:2])
              and sum(values[key] for key in AUDIT_FIELDS[:2]) == 256, "Objective class supports differ from training budget.")
    total = values["raw_total_weight"]
    close = lambda left, right: math.isclose(left, right, rel_tol=1e-9, abs_tol=1e-9)
    P.require(close(values["raw_clean_weight"] + values["raw_sensitive_weight"], total)
              and close(values["effective_clean_weight"] + values["effective_sensitive_weight"], total)
              and close(float(metadata["total_weight"]), total), "Objective did not preserve total training weight.")
    for label in ("clean", "sensitive"):
        P.require(close(values[label + "_objective_mass"], .5)
                  and close(values["effective_" + label + "_weight"] / total, .5), "Objective is not half weight per class.")
    return {"objective": record["objective"], "class_balance_applied": True, **values,
            "heldout_scope": "Original held-out row weights and publication guards remain unchanged."}


def quality_report(directory, *, partial=False):
    directory = Path(directory).resolve()
    state = Q.read(directory / "state.json")
    P.require(state.get("phase") == "class-balanced-objective-representation"
              and state["planned_attempts"] == list(P.attempts()), "Not the fixed phase-two grid.")
    for binding in state["source_freeze"].values():
        Q.read_bytes(binding["path"], binding["sha256"])
    for relative, commitment in state["computation_source_sha256"].items():
        Q.read_bytes(directory / "source-freeze/tree" / relative, commitment)
    preparation = Q.read(Path(state["prepared"]) / "manifest.json", state["preparation_manifest_sha256"])
    Q.read_bytes(Path(state["prepared"]) / "prompts.jsonl", preparation["curriculum_sha256"])
    reference = Q.endpoint(state["validation"], Q.VALIDATION_SHA, 968, 475)
    for binding in state.get("catalog_backups", {}).values():
        Q.read_bytes(binding["path"], binding["sha256"])
    original = P.C.load_artifact(state["catalog_backups"]["privoke-balanced"]["path"])
    observed = {record["index"]: record for record in state["records"]}
    P.require(len(observed) == len(state["records"]) and set(observed).issubset(range(24)), "Duplicate or undeclared attempt.")
    complete = (state.get("baseline_complete") is True and len(observed) == 24 and bool(state.get("selection"))
                and bool(state.get("finalized")) and state.get("restoration_verified") is True
                and not state.get("failure") and not state.get("unknown_outcome"))
    P.require(partial or complete, "Incomplete study requires --partial; no completion is certified.")
    baseline, baseline_rows = None, None
    binding = state.get("baselines", {}).get("balanced")
    if binding:
        model, identity = Q.model_summary(binding["artifact"], binding["sha256"])
        baseline, baseline_rows = Q.measurements(binding, model, identity, reference)
    reference_development = None
    if state.get("reference_endpoint"):
        endpoint = state["reference_endpoint"]
        model, identity = Q.model_summary(state["catalog_backups"]["privoke-balanced"]["path"],
                                         state["catalog_backups"]["privoke-balanced"]["sha256"])
        development_rows = Q.endpoint(state["development"], Q.DEVELOPMENT_SHA, 502, 264)
        reference_development, _ = Q.measurements({"reports": endpoint["reports"], "validation": endpoint["counts"]},
                                                 model, identity, development_rows, endpoint_name="development")
        Q.read_bytes(endpoint["fixture"]["path"], endpoint["fixture"]["sha256"])
    items = []
    for plan in state["planned_attempts"]:
        record = observed.get(plan["index"])
        if record is None:
            response_path = directory / f"attempt-{plan['index']:02d}" / "response.json"
            item = {**plan, "status": "not committed to state; no quality score claimed", "quality": None}
            if response_path.exists():
                response_bytes = Q.read_bytes(response_path)
                response = json.loads(response_bytes)
                item.update(observed_response={"path": str(response_path), "sha256": Q.digest(response_bytes),
                                              "accepted": response.get("accepted"), "scope": "Uncommitted response; not a completed attempt."})
            items.append(item)
            continue
        P.require(all(record.get(key) == value for key, value in plan.items()), "Attempt settings changed.")
        response = Q.read(record["response_path"], record["response_sha256"])
        base = P.C.load_artifact(record["base_artifact"])
        Q.read_bytes(record["base_artifact"], record["base_artifact_sha256"])
        P.require(base == P.prepare_base(original, plan), "Attempt did not start from the exact independent live base.")
        P.validate_response(response, plan, base)
        P.verify_pair(state, plan, response)
        P.objective_audit(plan, response)
        item = {**plan, "accepted": record["accepted"], "wall_seconds": record.get("wall_seconds"),
                "training": Q.training_quality(response, plan), "partition_inventory": response["partition_inventory"],
                "response_evidence": {"path": record["response_path"], "sha256": record["response_sha256"]}}
        P.require(response["accepted"] == record["accepted"], "Saved outcome differs from response.")
        if record["accepted"]:
            P.require(baseline is not None, "Scored candidate without baseline.")
            candidate = P.C.load_artifact(record["artifact"])
            P.C.verify_guarded_publication(base, candidate, response)
            P.require(all(candidate.get("metadata", {}).get(key) == base.get("metadata", {}).get(key)
                          for key in ("contextual_training_objective", "contextual_training_strategy")),
                      "Published training objective or strategy changed.")
            P.require(candidate["version"] == response["applied_version"], "Published version differs from receipt.")
            model, identity = Q.model_summary(record["artifact"], record["artifact_sha256"])
            P.require(identity == record["identity"], "Saved model identity differs.")
            item["quality"], candidate_rows = Q.measurements(record, model, identity, reference)
            item["parameter_changes"] = P.parameter_changes(base, candidate)
            item["objective_audit"] = objective_audit(response, plan)
            item["paired_original_validation"] = {layer: Q.paired_quality(baseline_rows[layer], candidate_rows[layer])
                                                   for layer in ("semantic", "pipeline")}
            eligible = P.candidate_key(record, binding["validation"]["pipeline"]) is not None
            P.require(record["eligible"] == eligible, "Eligibility differs from frozen criteria.")
            item.update(status="accepted/scored", eligible=eligible)
        else:
            item.update(status="rejected; no scored model quality", quality=None,
                        rejection_reason=response.get("error") or response.get("message"))
        items.append(item)
    pairs = {}
    for item in items:
        if "accepted" not in item:
            continue
        key = f"{item['strategy']}:{item['rate']}:{item['seed']}"
        partner = pairs.setdefault(key, {})
        partner[item["objective"]] = item["partition_inventory"]
        if len(partner) == 2:
            P.require(partner["uniform"] == partner["class_balanced_contextual_v1"], "Objective pair changed sampled rows/groups.")
    selection = None
    if state.get("selection"):
        selection = Q.read(state["selection"]["path"], state["selection"]["sha256"])
        P.require(len(observed) == 24 and selection["candidate_count"] == 24
                  and selection["development_access_for_selection"] is False, "Selection not frozen over complete grid.")
        eligible = [record for record in state["records"] if record["accepted"] and P.candidate_key(record, binding["validation"]["pipeline"]) is not None]
        expected = max(eligible, key=lambda record: P.candidate_key(record, binding["validation"]["pipeline"])) if eligible else None
        P.require(selection["winner"] == expected, "Frozen winner differs from prospective ranking.")
    endpoint_state = {**state, "live_backups": {"balanced": state["catalog_backups"]["privoke-balanced"]}}
    retention = Q.retention_summary(endpoint_state, directory, selection) if state.get("finalized") else None
    return {"report_status": "complete reconciled study" if complete else "PARTIAL; no completed outcome certified",
            "study": str(directory), "state_sha256": Q.digest(Q.read_bytes(directory / "state.json")),
            "source_revision": state["source_revision"], "source_freeze": state["source_freeze"],
            "computation_source_sha256": state["computation_source_sha256"], "study_images": state.get("study_images"),
            "baseline": baseline, "reference_development": reference_development,
            "attempts": items, "selection": selection, "contextual_retention": retention,
            "paired_inventory_checks": {key: {"members": len(value), "identical_when_complete": len(value) == 2} for key, value in pairs.items()},
            "restoration_verified": state.get("restoration_verified"), "failure": state.get("failure"),
            "reporter_sha256": Q.digest(Q.read_bytes(__file__)),
            "limitations": ["Profile names and tensor counts do not establish model quality.",
                            "The exact live balanced model includes prior training; encoders originate in repository-owned seeded initialization.",
                            "Authored contextual targets and public negatives are provisional, without independent human action truth.",
                            "Reused validation/development are exploratory; no final generalization, statistical superiority or deployment-safety claim follows.",
                            "Annotation presence does not establish sensitivity, visibility, complete span recovery or contextual action correctness.",
                            "Original weighting and class-balanced objective losses use different class mass; loss values are not interchangeable quality scores.",
                            "Confidence calibration and representative production latency remain unestablished.",
                            "The initial 54-attempt study remains separate failed evidence. No protected final examples or labels are opened."]}


def markdown(report):
    percent = Q.percent
    lines = ["# Class-balanced fuzzer model quality", "", report["report_status"], "",
             "All 24 attempts start independently from the same exact live balanced train.2 model. Original weighting retains the original example weights; it does not mean every row has weight one.", "",
             "| Attempt | Strategy / objective | Rate / seed | Outcome | Pipeline recall / specificity / balanced accuracy |",
             "| ---: | --- | --- | --- | ---: |"]
    measured = [("live balanced baseline", report["baseline"])] if report["baseline"] else []
    for item in report["attempts"]:
        quality = item.get("quality")
        metrics = quality["validation"]["pipeline"]["metrics"] if quality else {}
        lines.append(f"| {item['index']} | {item['strategy']} / {item['objective']} | {item['rate']} / {item['seed']} | {item['status']}{'; eligible' if item.get('eligible') else ''} | {percent(metrics.get('recall'))} / {percent(metrics.get('specificity'))} / {percent(metrics.get('balanced_accuracy'))} |")
        if quality:
            measured.append((f"attempt {item['index']}", quality))
    lines += ["", "Validation contains 475 positive and 493 negative rows. Undefined class rates remain unavailable.", "",
              "| Model / source | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 | Balanced accuracy |",
              "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
    for label, quality in measured:
        for layer, detail in quality["validation"].items():
            for source, metrics in {"pooled": detail["metrics"], **detail["source_strata"]}.items():
                lines.append(f"| {label} / {source} | {layer} | {metrics['positive_support']} / {metrics['negative_support']} | {metrics['tp']} / {metrics['tn']} / {metrics['fp']} / {metrics['fn']} | {percent(metrics['recall'])} | {percent(metrics['specificity'])} | {percent(metrics['precision'])} | {percent(metrics['f1'])} | {percent(metrics['balanced_accuracy'])} |")
    lines += ["", "| Model | Version | Parameters / trainable | Hidden / FF / layers / heads / context / vocabulary | Scope |",
              "| --- | --- | ---: | --- | --- |"]
    for label, quality in measured:
        model = quality["model"]
        dimensions = " / ".join(str(model["config"].get(key, "—")) for key in
                                ("hidden_size", "intermediate_size", "num_layers", "num_attention_heads", "max_tokens", "vocab_size"))
        lines.append(f"| {label} | {model['model_version']} | {model['parameters']} / {model['trainable_parameters']} | {dimensions} | {model['training_scope']} |")
    lines += ["", "| Attempt | Row-based held-out exact before → after | Sensitive recall before → after | Clean specificity before → after | Severity/action regression | Diagnostic loss | Supervised objective |",
              "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        training = item.get("training")
        if not training:
            continue
        values, guards = training["recorded_metrics"], training["heldout_checks"]
        pairs = [percent(guards[key]["before"]) + " → " + percent(guards[key]["after"])
                 for key in ("exact_match_rate", "sensitive_recall", "clean_specificity")]
        lines.append(f"| {item['index']} | {' | '.join(pairs)} | {percent(values.get('candidate_heldout_safety_regression_rate'))} | {values.get('average_loss', '—')} | {values.get('supervised_objective_loss', '—')} |")
    lines += ["", "Legacy average_loss measures weighted classification distance. Last-block supervised_objective_loss uses sensitivity CE + visibility CE + summed category BCE. Original and balanced objectives assign different class weight, so their losses are not interchangeable quality scores."]
    lines += ["", "| Accepted attempt | Actual training class rows | Raw class weights | Effective class weights | Clean / sensitive objective mass |",
              "| ---: | --- | --- | --- | --- |"]
    for item in report["attempts"]:
        audit = item.get("objective_audit")
        if not audit:
            continue
        if not audit["class_balance_applied"]:
            lines.append(f"| {item['index']} | see paired inventory in JSON | original weights | unchanged | no additional balancing |")
        else:
            lines.append(f"| {item['index']} | {int(audit['training_clean_examples'])} / {int(audit['training_sensitive_examples'])} | {audit['raw_clean_weight']} / {audit['raw_sensitive_weight']} | {audit['effective_clean_weight']} / {audit['effective_sensitive_weight']} | {audit['clean_objective_mass']} / {audit['sensitive_objective_mass']} |")
    retention = report["contextual_retention"]
    if retention and retention.get("development_measured"):
        lines += ["", "| Development model / source | Layer | Positive / negative support | TP / TN / FP / FN | Recall | Specificity | Precision | F1 | Balanced accuracy |",
                  "| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
        for label, evidence in (("live", retention["live_balanced_development"]), ("winner", retention["winner_development"])):
            for layer, detail in evidence["development"].items():
                for source, metrics in {"pooled": detail["metrics"], **detail["source_strata"]}.items():
                    lines.append(f"| {label} / {source} | {layer} | {metrics['positive_support']} / {metrics['negative_support']} | {metrics['tp']} / {metrics['tn']} / {metrics['fp']} / {metrics['fn']} | {percent(metrics['recall'])} | {percent(metrics['specificity'])} | {percent(metrics['precision'])} | {percent(metrics['f1'])} | {percent(metrics['balanced_accuracy'])} |")
        fixture = retention["fixture"]
        failures = fixture["existing_and_remaining_private_failures"]
        controls = [case for case in fixture["per_case_actions"] if case["quantitative_eligible"] and case["required_sensitive"] is False]
        allowed = {label: sum(case[label + "_action"] == "ALLOW" for case in controls) for label in ("live", "winner")}
        lines += ["", f"Retained research artifact: {retention['assessment']['retained']}. Newly introduced private failures: {fixture['new_private_action_losses']}; newly introduced clean interventions: {fixture['new_clean_interventions']}.",
                  f"Minimum-action disclosures: live {17 - len(failures['live'])}/17, winner {17 - len(failures['winner'])}/17. Clean controls receiving ALLOW: live {allowed['live']}/24, winner {allowed['winner']}/24. Seven ambiguous cases excluded.", "", fixture["identity_scope"]]
    elif retention:
        lines += ["", f"No eligible frozen winner; no candidate development/fixture score claimed. Retained: {retention['assessment']['retained']}."]
    lines += ["", "Model and training identities, parameter dimensions/counts, trainable/frozen tensors, publication changes, held-out guards, loss definitions, paired predictions, sampling inventories and immutable source/report commitments are retained in the JSON evidence. Service timings exclude browser overhead and do not establish production latency.", "", *[f"- {text}" for text in report["limitations"]]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args()
    report = quality_report(args.study, partial=args.partial)
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, allow_nan=False), end="\n")


if __name__ == "__main__":
    main()
