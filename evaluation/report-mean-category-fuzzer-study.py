"""Read-only model-quality reconciliation for the fixed mean-category study."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "evaluation" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module("mean_category_study", "run-mean-category-fuzzer-study.py")
R = module("mean_category_report_helpers", "report-class-balanced-fuzzer-study.py")
Q = R.Q


def historical_quality(state, reference):
    """Read prior validation controls only; never open prior candidate endpoints."""
    prior = state["prior_study"]
    P.validate_prior_binding(prior)
    previous = Q.read(Path(prior["directory"]) / "state.json", prior["state_sha256"])
    result = {}
    for binding in prior["controls"]:
        record = next(value for value in previous["records"] if value["index"] == binding["index"])
        key = (record["strategy"], record["rate"], record["seed"])
        response = Q.read(record["response_path"], record["response_sha256"])
        base = P.C.load_artifact(record["base_artifact"])
        Q.read_bytes(record["base_artifact"], record["base_artifact_sha256"])
        R.P.validate_response(response, R.P.record_subset(record), base)
        R.P.objective_audit(record, response)
        item = {"index": record["index"], "accepted": record["accepted"],
                "response_sha256": record["response_sha256"], "quality": None,
                "comparison_scope": "Archived phase02 control, not contemporaneously refitted or randomized."}
        if record["accepted"]:
            R.objective_audit(response, record)
            candidate = P.C.load_artifact(record["artifact"])
            P.C.verify_guarded_publication(base, candidate, response)
            model, identity = Q.model_summary(record["artifact"], record["artifact_sha256"])
            item["quality"], item["rows"] = Q.measurements(record, model, identity, reference)
        result[key] = item
    return result


def quality_report(directory, *, partial=False):
    directory = Path(directory).resolve()
    state = Q.read(directory / "state.json")
    P.require(state["phase"] == "mean-category-objective-representation"
              and state["planned_attempts"] == list(P.attempts()), "Not the fixed mean-category grid.")
    for binding in state["source_freeze"].values():
        Q.read_bytes(binding["path"], binding["sha256"])
    for relative, commitment in state["computation_source_sha256"].items():
        Q.read_bytes(directory / "source-freeze/tree" / relative, commitment)
    preparation = Q.read(Path(state["prepared"]) / "manifest.json", state["preparation_manifest_sha256"])
    Q.read_bytes(Path(state["prepared"]) / "prompts.jsonl", preparation["curriculum_sha256"])
    reference = Q.endpoint(state["validation"], Q.VALIDATION_SHA, 968, 475)
    for binding in state["catalog_backups"].values():
        Q.read_bytes(binding["path"], binding["sha256"])
    original_binding = state["catalog_backups"]["privoke-balanced"]
    original = P.C.load_artifact(original_binding["path"])
    observed = {record["index"]: record for record in state["records"]}
    P.require(len(observed) == len(state["records"]) and set(observed).issubset(range(12)), "Duplicate or undeclared attempt.")
    complete = (state.get("baseline_complete") is True and len(observed) == 12 and bool(state.get("selection"))
                and bool(state.get("finalized")) and state.get("restoration_verified") is True
                and not state.get("failure") and not state.get("unknown_outcome"))
    P.require(partial or complete, "Incomplete study requires --partial.")
    baseline, baseline_rows = None, None
    baseline_binding = state.get("baselines", {}).get("balanced")
    if baseline_binding:
        model, identity = Q.model_summary(baseline_binding["artifact"], baseline_binding["sha256"])
        baseline, baseline_rows = Q.measurements(baseline_binding, model, identity, reference)
    reference_development = None
    if state.get("reference_endpoint"):
        endpoint = state["reference_endpoint"]
        model, identity = Q.model_summary(original_binding["path"], original_binding["sha256"])
        reference_development, _ = Q.measurements({"reports": endpoint["reports"], "validation": endpoint["counts"]},
            model, identity, Q.endpoint(state["development"], Q.DEVELOPMENT_SHA, 502, 264), endpoint_name="development")
        Q.read_bytes(endpoint["fixture"]["path"], endpoint["fixture"]["sha256"])
    controls = historical_quality(state, reference)
    items = []
    for plan in state["planned_attempts"]:
        record = observed.get(plan["index"])
        if record is None:
            item = {**plan, "status": "not committed to state; no quality score claimed", "quality": None}
            path = directory / f"attempt-{plan['index']:02d}" / "response.json"
            if path.exists():
                raw = Q.read_bytes(path)
                response = json.loads(raw)
                item["observed_response"] = {"path": str(path), "sha256": Q.digest(raw),
                                             "accepted": response.get("accepted"), "scope": "Uncommitted response."}
            items.append(item)
            continue
        P.require(all(record.get(key) == value for key, value in plan.items()), "Attempt settings changed.")
        response = Q.read(record["response_path"], record["response_sha256"])
        base = P.C.load_artifact(record["base_artifact"])
        Q.read_bytes(record["base_artifact"], record["base_artifact_sha256"])
        P.require(base == P.prepare_base(original, plan), "Attempt did not start from the independent exact base.")
        P.validate_response(response, plan, base)
        P.verify_pair(state, plan, response)
        audit = P.objective_audit(plan, response)
        P.require(response["accepted"] == record["accepted"], "Saved outcome differs from response.")
        training = Q.training_quality(response, plan)
        training["loss_scope"]["supervised_objective_loss"] = (
            "Global weighted sensitivity CE + visibility CE + category BCE averaged over labels, for both strategies. "
            "Historical summed-category controls use a different objective scale.")
        item = {**plan, "accepted": record["accepted"], "wall_seconds": record.get("wall_seconds"),
                "training": training, "partition_inventory": response["partition_inventory"],
                "response_evidence": {"path": record["response_path"], "sha256": record["response_sha256"]}}
        control = controls[(plan["strategy"], plan["rate"], plan["seed"])]
        item["historical_control"] = {key: value for key, value in control.items() if key != "rows"}
        if record["accepted"]:
            P.require(baseline is not None, "Scored candidate without baseline.")
            candidate = P.C.load_artifact(record["artifact"])
            P.C.verify_guarded_publication(base, candidate, response)
            P.require(all(candidate.get("metadata", {}).get(key) == base.get("metadata", {}).get(key)
                          for key in ("contextual_training_objective", "contextual_training_strategy")),
                      "Published objective or strategy changed.")
            P.require(candidate["version"] == response["applied_version"], "Published version differs from receipt.")
            model, identity = Q.model_summary(record["artifact"], record["artifact_sha256"])
            P.require(identity == record["identity"], "Saved model identity differs.")
            item["quality"], rows = Q.measurements(record, model, identity, reference)
            item["parameter_changes"] = P.parameter_changes(base, candidate)
            item["objective_audit"] = {"class_balance_applied": True, **audit}
            item["loss_audit"] = P.loss_audit(response, base)
            P.require(record["loss_audit"] == item["loss_audit"], "Saved loss audit differs from response.")
            item["paired_original_validation"] = {layer: Q.paired_quality(baseline_rows[layer], rows[layer])
                                                   for layer in ("semantic", "pipeline")}
            if control["accepted"]:
                item["paired_historical_validation"] = {layer: Q.paired_quality(control["rows"][layer], rows[layer])
                                                         for layer in ("semantic", "pipeline")}
            eligible = P.candidate_key(record, baseline_binding["validation"]["pipeline"]) is not None
            P.require(record["eligible"] == eligible, "Eligibility differs from fixed criteria.")
            item.update(status="accepted/scored", eligible=eligible)
        else:
            item.update(status="rejected; no scored model quality", quality=None,
                        rejection_reason=response.get("error") or response.get("message"))
        items.append(item)
    selection = None
    if state.get("selection"):
        selection = Q.read(state["selection"]["path"], state["selection"]["sha256"])
        P.require(len(observed) == 12 and selection["candidate_count"] == 12
                  and selection["development_access_for_selection"] is False, "Selection not frozen over the full grid.")
        eligible = [record for record in state["records"] if record["accepted"]
                    and P.candidate_key(record, baseline_binding["validation"]["pipeline"]) is not None]
        expected = max(eligible, key=lambda record: P.candidate_key(record, baseline_binding["validation"]["pipeline"])) if eligible else None
        P.require(selection["winner"] == expected, "Frozen winner differs from prospective ranking.")
    endpoint_state = {**state, "live_backups": {"balanced": original_binding}}
    retention = Q.retention_summary(endpoint_state, directory, selection) if state.get("finalized") else None
    return {"report_status": "complete reconciled study" if complete else "PARTIAL; no completed outcome certified",
            "study": str(directory), "state_sha256": Q.digest(Q.read_bytes(directory / "state.json")),
            "source_revision": state["source_revision"], "source_freeze": state["source_freeze"],
            "computation_source_sha256": state["computation_source_sha256"], "study_images": state.get("study_images"),
            "baseline": baseline, "reference_development": reference_development, "attempts": items,
            "selection": selection, "contextual_retention": retention, "prior_study": state["prior_study"],
            "restoration_verified": state.get("restoration_verified"), "failure": state.get("failure"),
            "reporter_sha256": Q.digest(Q.read_bytes(__file__)), "limitations": [
                "Historical controls were archived, not refitted or randomized contemporaneously; comparisons are exploratory.",
                "Category-gradient dominance is an unmeasured hypothesis; task loss magnitudes are not gradient norm measurements.",
                "Model names and parameter counts are not quality rankings; the seeded encoder and live base include authored supervision and prior training.",
                "Training samples contain only 6, 8 or 9 sensitivity-positive rows; class balancing amplifies sparse provisional targets.",
                "Presence annotations do not establish contextual severity, visibility, complete span recovery or action correctness.",
                "Validation and development are reused; untouched generalization and statistical superiority remain unestablished.",
                "Diagnostic distance, summed-category objective and mean-category objective have different scales and meanings.",
                "Confidence calibration and representative production latency remain unestablished.",
                "Prior failed studies remain separate evidence; no protected final examples or labels are opened."]}


def markdown(report):
    text = R.markdown(report).replace("# Class-balanced fuzzer model quality", "# Mean-category fuzzer model quality")
    text = text.replace("All 24 attempts start independently", "All 12 mean-category attempts start independently")
    text = text.replace("Original weighting retains the original example weights; it does not mean every row has weight one.",
                        "Each target class receives half the original total training weight, preserving within-class relative weights.")
    text = text.replace("Last-block supervised_objective_loss uses sensitivity CE + visibility CE + summed category BCE.",
                        "The new objective uses sensitivity CE + visibility CE + category BCE averaged over labels for both training strategies.")
    text = text.replace("Original and balanced objectives assign different class weight, so their losses are not interchangeable quality scores.",
                        "Historical summed-category controls and new mean-category treatments optimize differently scaled losses; losses are not interchangeable quality scores.")
    lines = [text, "| Attempt | Sensitivity CE | Visibility CE | Mean category BCE | True objective |",
             "| ---: | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        if not item.get("loss_audit"):
            continue
        values = item["training"]["metadata"]
        lines.append(f"| {item['index']} | {values['supervised_sensitivity_ce_loss']} | {values['supervised_visibility_ce_loss']} | {values['supervised_category_bce_loss']} | {values['supervised_objective_loss']} |")
    lines += ["", "| New attempt | Historical summed-category control | Control outcome | Pipeline recall / specificity |",
              "| ---: | ---: | --- | ---: |"]
    for item in report["attempts"]:
        control = item.get("historical_control")
        if control is None:
            continue
        metrics = control["quality"]["validation"]["pipeline"]["metrics"] if control["quality"] else {}
        lines.append(f"| {item['index']} | {control['index']} | {'accepted/scored' if control['accepted'] else 'rejected/unscored'} | {Q.percent(metrics.get('recall'))} / {Q.percent(metrics.get('specificity'))} |")
    lines += ["", "Historical controls use identical ordered original training and held-out inputs, but were run earlier. They do not select the new winner. Paired prediction changes and source-specific metrics remain in JSON.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", type=Path, required=True)
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args()
    report = quality_report(args.study, partial=args.partial)
    print(markdown(report) if args.format == "markdown" else json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
