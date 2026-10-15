"""Read-only quality reconciliation for the fresh local-SGD optimizer study."""
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


P = module("local_sgd_study", "run-local-sgd-fuzzer-study.py")
R = module("mean_category_report_helpers", "report-class-balanced-fuzzer-study.py")
Q = R.Q



def quality_report(directory, *, partial=False):
    directory = Path(directory).resolve()
    state = Q.read(directory / "state.json")
    P.require(state["phase"] == "local-sgd-optimizer-representation"
              and state["planned_attempts"] == list(P.attempts()), "Not the fixed local-SGD optimizer grid.")
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
    P.require(len(observed) == len(state["records"]) and set(observed).issubset(range(18)), "Duplicate or undeclared attempt.")
    complete = (state.get("baseline_complete") is True and state.get("preflight_complete") is True and len(observed) == 18 and bool(state.get("selection"))
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
    P.validate_prior_binding(state["prior_study"])
    preflight = P.frozen_preflight(state) if state.get("preflight_complete") else None
    paired_models = {}
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
        P.require(preflight is not None and record["base_artifact_sha256"] == preflight["prepared_bases"][str(plan["index"])]["sha256"], "Attempt base differs from the before-fit optimizer commitment.")
        P.require(base == P.prepare_base(original, plan), "Attempt did not start from the independent exact base.")
        P.validate_response(response, plan, base)
        P.verify_pair(state, plan, response)
        audit = P.objective_audit(plan, response)
        sampler_audit = P.sampling_audit(plan, response)
        P.require(sampler_audit == record["sampling_audit"], "Saved sampler audit differs from actual response/inventory.")
        P.require(audit == record["objective_audit"], "Saved objective audit differs from response.")
        P.require(P.optimizer_audit(plan, response, base) == record["optimizer_audit"], "Saved optimizer trace differs from response/base.")
        P.require(response["accepted"] == record["accepted"], "Saved outcome differs from response.")
        training = Q.training_quality(response, plan)
        training["loss_scope"]["supervised_objective_loss"] = (
            "Global weighted sensitivity CE + visibility CE + category BCE averaged over labels, for both strategies. "
            "All optimizer treatments use the same objective and identical selected rows; local steps/rate differ.")
        item = {**plan, "accepted": record["accepted"], "wall_seconds": record.get("wall_seconds"),
                "training": training, "partition_inventory": response["partition_inventory"],
                "sampling_audit": sampler_audit, "optimizer_audit": P.optimizer_audit(plan, response, base), "response_evidence": {"path": record["response_path"], "sha256": record["response_sha256"]}}
        if record["accepted"]:
            P.require(baseline is not None, "Scored candidate without baseline.")
            candidate = P.C.load_artifact(record["artifact"])
            P.C.verify_guarded_publication(base, candidate, response)
            P.require(all(candidate.get("metadata", {}).get(key) == base.get("metadata", {}).get(key)
                          for key in ("contextual_training_objective", "contextual_training_strategy", P.OPTIMIZER_KEY)),
                      "Published objective or strategy changed.")
            P.require(candidate["version"] == response["applied_version"], "Published version differs from receipt.")
            model, identity = Q.model_summary(record["artifact"], record["artifact_sha256"])
            P.require(identity == record["identity"], "Saved model identity differs.")
            item["quality"], rows = Q.measurements(record, model, identity, reference)
            item["parameter_changes"] = P.parameter_changes(base, candidate)
            P.bind_optimizer_publication(item["optimizer_audit"], item["parameter_changes"], candidate)
            P.require(item["parameter_changes"] == record["parameter_change_audit"], "Saved tensor-change audit differs from model bytes.")
            item["objective_audit"] = {"class_balance_applied": True, **audit}
            item["loss_audit"] = P.loss_audit(response, base)
            P.require(record["loss_audit"] == item["loss_audit"], "Saved loss audit differs from response.")
            item["paired_original_validation"] = {layer: Q.paired_quality(baseline_rows[layer], rows[layer])
                                                   for layer in ("semantic", "pipeline")}
            paired_models[(plan["strategy"], plan["seed"], plan["treatment"])] = (item["quality"], rows)
            eligible = P.candidate_key(record, baseline_binding["validation"]["pipeline"]) is not None
            P.require(record["eligible"] == eligible, "Eligibility differs from fixed criteria.")
            item.update(status="accepted/scored", eligible=eligible)
        else:
            item.update(status="rejected; no scored model quality", quality=None,
                        rejection_reason=response.get("error") or response.get("message"))
        items.append(item)
    pairs = paired_comparisons(items, paired_models, preflight)
    selection = None
    if state.get("selection"):
        selection = Q.read(state["selection"]["path"], state["selection"]["sha256"])
        P.require(len(observed) == 18 and selection["candidate_count"] == 18
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
            "sampling_preflight": preflight, "optimizer_pairs": pairs,
            "restoration_verified": state.get("restoration_verified"), "failure": state.get("failure"),
            "reporter_sha256": Q.digest(Q.read_bytes(__file__)), "limitations": [
                "All 18 optimizer attempts are freshly fitted; matched representation/seed treatments use identical training and held-out targets and original weights.",
                "Quota roles use provisional existing contextual targets, not independent human contextual labels or external annotation-presence truth.",
                "Sparse authored families can receive increased row exposure and half the class objective mass; this supplies no new supervision or broad coverage guarantee.",
                "All attempts start from the same seeded encoder/live train.2 base; parameter counts and profile names do not rank measured quality.",
                "Validation and development are reused exploratory evidence; untouched generalization and statistical superiority remain unestablished.",
                "The optimized CE/mean-BCE objective and legacy weighted classification-distance diagnostic have different meanings/scales.",
                "Optimizer trajectory losses and intermediate shape-aware state fingerprints are runtime-recorded; raw scalar trace does not independently reconstruct intermediate states.",
                "The .012 one-step control matches nominal total rate, not realized displacement under changing directions, clipping and float32 addition.",
                "Severity/visibility/action privacy truth cannot be inferred from validation annotation presence; fixture gates are separately provisional.",
                "Confidence calibration and representative production latency remain unmeasured; timings describe only observed service calls.",
                "Previous studies remain separate archived evidence; no prior candidate endpoint or protected final rows/labels are opened."]}



def paired_comparisons(items, models, preflight):
    result = []
    for strategy in P.STRATEGIES:
        for seed in P.SEEDS:
            for before_name, after_name in (("one_step_003", "four_steps_003"), ("one_step_003", "one_step_012"), ("one_step_012", "four_steps_003")):
                pair = [next(item for item in items if item["strategy"] == strategy and item["seed"] == seed and item["treatment"] == name) for name in (before_name, after_name)]
                item = {"strategy": strategy, "seed": seed, "before_treatment": before_name, "after_treatment": after_name, "before_index": pair[0]["index"], "after_index": pair[1]["index"], "outcomes": [value.get("status") for value in pair], "prediction_changes": None, "metric_differences_after_minus_before": None}
                if preflight:
                    before, after = (preflight["inventories"][str(value["index"])] for value in pair)
                    P.require(before == after, "Optimizer treatments differ in selected inputs.")
                    item["identical_ordered_samples_sha256"] = {partition: before[partition]["ordered_samples_sha256"] for partition in ("train", "heldout")}
                keys = [(strategy, seed, name) for name in (before_name, after_name)]
                if all(key in models for key in keys):
                    before, after = (models[key] for key in keys)
                    item["prediction_changes"] = {layer: Q.paired_quality(before[1][layer], after[1][layer]) for layer in ("semantic", "pipeline")}
                    item["metric_differences_after_minus_before"] = {layer: {name: after[0]["validation"][layer]["metrics"][name] - before[0]["validation"][layer]["metrics"][name] if after[0]["validation"][layer]["metrics"][name] is not None and before[0]["validation"][layer]["metrics"][name] is not None else None for name in ("tp", "tn", "fp", "fn", "recall", "specificity", "precision", "f1", "balanced_accuracy")} for layer in ("semantic", "pipeline")}
                result.append(item)
    return result


def markdown(report):
    text = R.markdown(report).replace("# Class-balanced fuzzer model quality", "# Local-SGD fuzzer model quality")
    text = text.replace("All 24 attempts start independently from the same exact live balanced train.2 model. Original weighting retains the original example weights; it does not mean every row has weight one.", "All 18 attempts start independently from exact live balanced train.2. They retain the same quota rows/objective while changing local step count or rate.")
    text = text.replace("Last-block supervised_objective_loss uses sensitivity CE + visibility CE + summed category BCE. Original and balanced objectives assign different class weight, so their losses are not interchangeable quality scores.", "The optimized objective uses sensitivity CE + visibility CE + category BCE averaged across labels, preserving class balance and original total weight. The classification-distance diagnostic measures a different quantity.")
    lines = [text]
    if report.get("reference_development"):
        lines += ["| Fresh original development | TP / TN / FP / FN | Recall | Specificity | Precision | F1 |",
                  "| --- | --- | ---: | ---: | ---: | ---: |"]
        for layer, details in report["reference_development"]["development"].items():
            values = details["metrics"]
            lines.append(f"| {layer} | {values['tp']} / {values['tn']} / {values['fp']} / {values['fn']} | {Q.percent(values['recall'])} | {Q.percent(values['specificity'])} | {Q.percent(values['precision'])} | {Q.percent(values['f1'])} |")
        lines += ["", "Fresh original development is a reference measurement before the grid; it supplies no candidate selection evidence.", ""]
    lines += ["| Attempt | Sampling mode | Actual authored sensitive / clean | Public / bootstrap | Unique train rows | Authored families |",
             "| ---: | --- | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        audit = item.get("sampling_audit", {})
        lines.append(f"| {item['index']} | role quota | {audit.get('sampling_authored_sensitive_rows', '-')} / {audit.get('sampling_authored_clean_rows', '-')} | {audit.get('sampling_public_negative_rows', '-')} / {audit.get('sampling_bootstrap_replay_rows', '-')} | {audit.get('sampling_training_unique_texts', '-')} | {audit.get('sampling_authored_groups', '-')} |")
    lines += ["", "Quota preflight inventories describe the exact source-bound selection before RPC. Accepted response audits must match; rejected updates receive no invented model score.", "",
              "| Attempt | Initial sensitivity CE | Initial visibility CE | Initial mean category BCE | Initial optimized objective |", "| ---: | ---: | ---: | ---: | ---: |"]
    for item in report["attempts"]:
        values = item.get("loss_audit")
        if values:
            lines.append(f"| {item['index']} | {values['supervised_sensitivity_ce_loss']} | {values['supervised_visibility_ce_loss']} | {values['supervised_category_bce_loss']} | {values['supervised_objective_loss']} |")
    lines += ["", "| Attempt | Optimizer treatment | Steps × rate | Runtime-recorded objective before / after | Clipped coordinates per step | Final transported maximum |", "| ---: | --- | --- | --- | --- | --- |"]
    for item in report["attempts"]:
        trace = item.get("optimizer_audit", {}).get("trace")
        objective = f"{trace['loss'][0][3]} / {trace['loss'][-1][3]}" if trace else "unmeasured"
        clips = str([values[2] for values in trace["updates"]]) if trace else "unmeasured"
        maximum = str(trace["updates"][-1][3]) if trace else "unmeasured"
        lines.append(f"| {item['index']} | {item['treatment']} | {item['local_steps']} × {item['rate']} | {objective} | {clips} | {maximum} |")
    lines += ["", "Trace losses are runtime-recorded on the same training batch; intermediate fingerprints do not independently reconstruct states. The .012 control matches nominal total rate, not realized displacement. Transported deltas and rounded parameter displacement can differ.", "", "Fresh optimizer paired prediction changes, metric differences, immutable inventories, raw/report/response/model identities and service latency summaries remain in JSON. Archived phase04 quota inventories prove selected-input continuity and do not rank this study.", ""]
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
