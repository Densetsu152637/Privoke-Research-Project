"""Read-only sustained-study reconciliation and fixed-final-checkpoint decisions."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from privoke_eval import continual_fuzzer_study as continual
from privoke_eval import curriculum_improvement_study as prior
from privoke_eval import accelerated_fuzzer_study as study
from privoke_eval.curriculum_improvement_evidence import (
    CONTEXT_METRICS, accepted_metadata, audit_allocations, contextual_metrics, matched, restriction_harms,
)
from privoke_eval.curriculum_improvement_report import round_chain, durable_publications, compare_layers
from privoke_model.artifact import load_artifact
from privoke_model.fingerprint import parameter_fingerprint


def prediction_changes(before, after):
    pairs = matched(before, after)
    def prediction(row):
        return (row.get("classification", row.get("raw", {}).get("classification")),
                row.get("action", row.get("raw", {}).get("action")), row.get("detected_sensitive"))
    ids = [a["id"] for a, b in pairs if prediction(a) != prediction(b)]
    return {"changed_rows": len(ids), "changed_ids": ids}


def context_subgroups(rows):
    groups = {"controls": [r for r in rows if r["target"]["sensitivity"] == "S0"],
              "disclosures": [r for r in rows if r["target"]["sensitivity"] != "S0"],
              "hard_positives": [r for r in rows if r["hard_positive"]]}
    if [len(groups[key]) for key in groups] != [32, 32, 4]:
        raise ValueError("Expected 32 contextual controls, 32 disclosures and four hard positives.")
    return {key: contextual_metrics(value) for key, value in groups.items()}


def gate_predicates(record):
    """Independently reconstruct the guard's diagnostic predicates."""
    metrics, minimum = record["metrics"], record["minimum_exact_match_rate"]
    required = ("exact_match_rate", "heldout_exact_match_rate", "candidate_heldout_exact_match_rate",
                "heldout_sensitive_recall", "candidate_heldout_sensitive_recall",
                "heldout_clean_specificity", "candidate_heldout_clean_specificity",
                "candidate_heldout_safety_regression_rate")
    import math
    if type(minimum) not in (int, float) or not math.isfinite(minimum) or not 0 <= minimum <= 1:
        raise ValueError("Invalid numeric gate minimum.")
    invalid = any(type(metrics.get(key)) not in (int, float) or not math.isfinite(metrics[key]) or not 0 <= metrics[key] <= 1 for key in required)
    invalid |= any(type(metrics.get(key)) not in (int, float) or not math.isfinite(metrics[key]) or metrics[key] < 1 or metrics[key] != int(metrics[key]) for key in ("heldout_sensitive_examples", "heldout_clean_examples"))
    if invalid:
        raise ValueError("Incomplete/invalid numeric gate diagnostics.")
    failed = []
    if metrics["exact_match_rate"] <= minimum:
        failed.append("training_exact_above_minimum")
    for name, suffix in (("heldout_exact_no_decline", "exact_match_rate"),
                         ("heldout_recall_no_decline", "sensitive_recall"),
                         ("heldout_specificity_no_decline", "clean_specificity")):
        if metrics["candidate_heldout_" + suffix] < metrics["heldout_" + suffix]:
            failed.append(name)
    if metrics["candidate_heldout_safety_regression_rate"] > 0:
        failed.append("no_safety_regression")
    return failed


def audit_gate_diagnostics(directory, rounds, raw, durable_metadata):
    files = list((directory / "gate-diagnostics").glob("*.json"))
    if len(files) != len(rounds):
        raise ValueError("Exactly one durable gate diagnostic per attempted request required.")
    counts = Counter()
    numeric = []
    for index, attempt in enumerate(rounds, 1):
        request = attempt["request"]
        path = directory / "gate-diagnostics" / (attempt["request_fingerprint"] + ".json")
        if not path.exists():
            raise ValueError("Missing attempt-linked gate diagnostics.")
        diagnostic = continual.read_json(path)
        if diagnostic.get("schema_version") != 1 or diagnostic.get("minimum_exact_match_rate") != 0.0:
            raise ValueError("Diagnostic schema or frozen gate floor differs.")
        if any(diagnostic.get(key) != request[key] for key in ("request_id", "source_id", "model_id")) or diagnostic["request_sha256"] != attempt["request_fingerprint"]:
            raise ValueError("Diagnostic request commitment differs.")
        before = continual.read_json(raw / f"snapshot-{index-1:03d}.json")
        base = parameter_fingerprint({n: p["values"] for n, p in before["parameters"].items()})
        if diagnostic["base_version"] != before["identity"]["model_version"] or diagnostic["base_parameter_fingerprint"] != base:
            raise ValueError("Diagnostic base differs from actual serving parameters.")
        candidate = diagnostic["updated_parameter_fingerprint"]
        if not isinstance(candidate, str) or len(candidate) != 64 or any(c not in "0123456789abcdef" for c in candidate):
            raise ValueError("Missing canonical candidate parameter fingerprint.")
        failed = gate_predicates(diagnostic)
        declared = [row["predicate"] for row in diagnostic["failed_predicates"] if row["predicate"] != "validation"]
        if declared != failed or diagnostic["gate_passed"] != (not failed):
            raise ValueError("Numeric guard results differ from diagnostic predicates.")
        response = attempt["response"]
        if response["accepted"]:
            metadata = accepted_metadata(attempt, durable_metadata)
            if failed or any(diagnostic[key] != metadata[key] for key in ("base_parameter_fingerprint", "updated_parameter_fingerprint")):
                raise ValueError("Published candidate differs from guarded candidate.")
            counts["accepted"] += 1
        else:
            if not failed or response.get("rejection_code") != "FAILED_PRECONDITION":
                raise ValueError("Unexplained rejection; numeric gate evidence required.")
            counts["rejected"] += 1
        counts.update(failed)
        numeric.append({"cycle": index, "published": response["accepted"], "gate_passed": diagnostic["gate_passed"],
                        "metrics": diagnostic["metrics"], "failed_predicates": failed,
                        "base_version": diagnostic["base_version"],
                        "base_parameter_fingerprint": diagnostic["base_parameter_fingerprint"],
                        "candidate_parameter_fingerprint": candidate})
    return {"counts": dict(counts), "attempts": numeric,
            "candidate_evidence_limit": "Fingerprint commitment and service metrics; rejected tensors and independent metric recomputation are not retained."}


def verify_endpoint_truth(endpoint, source_rows, identity, *, fixture=False):
    """Reconstruct targets/eligibility from pinned inputs without issuing RPCs."""
    predictions = endpoint["semantic"]["predictions"]
    keyed = {row["id"]: row for row in predictions}
    if len(keyed) != len(predictions):
        raise ValueError("Duplicate contextual endpoint IDs.")
    class ReplayClient:
        def snapshot(self, model_id):
            return {"identity": identity}
        def analyze(self, row, model_id, layer, request_id):
            key = row["case_id"] if fixture else row["id"]
            saved = keyed[key]
            return {"raw": saved["raw"], "identities": saved["identities"]}
    reconstructed = prior.contextual_rows(ReplayClient(), source_rows, identity["model_id"], identity, "audit-replay", fixture)
    if reconstructed != endpoint:
        raise ValueError("Archived contextual targets, groups, eligibility or metrics differ from pinned truth.")


def load_cell(output, protocol, cell, state):
    directory = output / "cells" / cell["id"]
    prior.verify_archive(directory, state["archive_sha256"])
    model_id = "privoke-" + cell["profile"]
    manifest = continual.read_json(directory / "controller/run-manifest.json")
    config, model = manifest["config"], manifest["models"][model_id]
    expected = {"models": [model_id], "cycles": 168, "prompt_count": 32, "seed": 1337,
                "checkpoints": study.CHECKPOINTS, "mining": False, "evaluation_layers": ["semantic"],
                "gate_diagnostics": True, "curriculum_sampler_policy": cell["policy"],
                "curriculum_sampler_seed": cell["sampler_seed"], "duration_seconds": 0,
                "round_pause_seconds": 0, "checkpoint_only_snapshots": False}
    if manifest["status"] != "complete" or any(config.get(k) != value for k, value in expected.items()):
        raise ValueError("Controller differs from fixed prospective protocol.")
    raw = directory / "controller" / model_id
    initial, published = (load_artifact(directory / name) for name in ("initial-artifact.json", "published-artifact.json"))
    if continual.sha(directory / "initial-artifact.json") != protocol["source_files"][f"models/{model_id}.json"]:
        raise ValueError("Initial artifact differs from frozen checked-in bytes.")
    prior.assert_baseline(continual.read_json(raw / "snapshot-000.json"), initial)
    operations = continual.read_json(directory / "operations.json")
    prior.validate_operations(operations, cell, protocol)
    rows = [json.loads(line) for line in (directory / "parameter-update-data/updates.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    durable_metadata = {(r["metadata"]["request_source_id"], r["metadata"]["request_id"]): r["metadata"] for r in rows}
    rounds = round_chain(raw, model_id, model, durable_metadata, attempts=168, prompt_count=32)
    publication = durable_publications(directory, rounds, published,
                    operations["containers"][cell["project"] + "-fuzzer"]["environment"]["FUZZER_ID"], prompt_count=32)
    if prior.artifact_identity(published) != model["current_identity"]:
        raise ValueError("Final artifact differs from final served identity.")
    lookup = {}
    parent = Path(protocol["inputs"][cell["curriculum"]]["manifest"]).parent
    for split in ("train", "heldout", "replay"):
        for row in continual.jsonl(parent / (split + ".jsonl")):
            lookup[row["id"]] = (split, row)
    exposure = audit_allocations(directory / "curriculum.sqlite3", rounds, lookup, cell["policy"], cell["sampler_seed"], .35,
                                 durable_metadata, new_count=24, replay_count=8)
    gate = audit_gate_diagnostics(directory, rounds, raw, durable_metadata)
    checkpoints = {}
    development_truth = continual.jsonl(protocol["inputs"]["dataset"]["path"])
    assessment_truth = continual.jsonl(Path(protocol["inputs"]["revised"]["manifest"]).parent / "assessment.jsonl")
    fixture_truth = prior.pinned_jsonl(protocol["inputs"]["fixture"]["path"], prior.FIXTURE_SHA)
    for cycle in study.CHECKPOINTS:
        saved_checkpoint = model["checkpoints"][str(cycle)]
        if saved_checkpoint["path"] != f"checkpoint-{cycle:03d}.json" or saved_checkpoint["snapshot_path"] != f"snapshot-{cycle:03d}.json":
            raise ValueError("Unexpected checkpoint path.")
        if continual.sha(raw / saved_checkpoint["path"]) != saved_checkpoint["sha256"] or continual.sha(raw / saved_checkpoint["snapshot_path"]) != saved_checkpoint["snapshot_sha256"]:
            raise ValueError("Controller checkpoint hash changed.")
        development = continual.read_json(raw / f"checkpoint-{cycle:03d}.json")
        context, fixture = (continual.read_json(directory / f"{name}-{cycle:03d}.json") for name in ("context", "fixture"))
        identity = continual.read_json(raw / f"snapshot-{cycle:03d}.json")["identity"]
        if context["identity"] != identity or fixture["identity"] != identity or set(development) != {"semantic"} or development["semantic"]["identity"] != identity:
            raise ValueError("Checkpoint identity/layer contract differs.")
        for endpoint in (development, context["layers"], fixture["layers"]):
            if set(endpoint) != {"semantic"}:
                raise ValueError("Additional endpoint layers are forbidden.")
            for row in endpoint["semantic"]["predictions"]:
                continual.require_semantic_execution(row["raw"])
                if any(observed != identity for observed in row["identities"]):
                    raise ValueError("Endpoint returned an unexpected identity.")
        contextual = context["layers"]["semantic"]["predictions"]
        fixtures = fixture["layers"]["semantic"]["predictions"]
        verify_endpoint_truth(context["layers"], assessment_truth, identity)
        verify_endpoint_truth(fixture["layers"], fixture_truth, identity, fixture=True)
        predictions = development["semantic"]["predictions"]
        truth = {row["id"]: row for row in development_truth}
        if len(predictions) != 502 or {row["id"] for row in predictions} != set(truth):
            raise ValueError("Development endpoint coverage differs.")
        for row in predictions:
            source = truth[row["id"]]
            if row["group_id"] != source["group_id"] or row["expected_has_pii"] != source["expected_has_pii"]:
                raise ValueError("Development annotation truth changed.")
        if development["semantic"]["metrics"] != continual.metrics(predictions) or continual.metrics(predictions)["runtime_errors"]:
            raise ValueError("Development metrics or complete coverage differ.")
        if len(fixtures) != 48 or sum(row["quantitative"] for row in fixtures) != 41:
            raise ValueError("Expected 41 quantitative and seven descriptive fixtures.")
        checkpoints[str(cycle)] = {"development": development, "contextual": context["layers"],
                                   "fixtures": fixture["layers"], "subgroups": context_subgroups(contextual),
                                   "attempts": cycle, "accepted_updates": sum(r["response"]["accepted"] for r in rounds[:cycle]),
                                   "rejected_attempts": sum(not r["response"]["accepted"] for r in rounds[:cycle])}
    prior.verify_baseline_endpoints(output, cell["profile"], directory, raw)
    return {"cell": cell, "attempts": len(rounds), "accepted_updates": model["accepted_updates"],
            "rejected_attempts": len(rounds) - model["accepted_updates"], "publication": publication,
            "exposure": exposure, "gate_diagnostics": gate, "checkpoints": checkpoints,
            "final_24_attempts_accepted": sum(r["response"]["accepted"] for r in rounds[-24:])}


def promising_seed(record, control):
    baseline, final, reference = (record["checkpoints"]["0"], record["checkpoints"]["168"], control["checkpoints"]["168"])
    joint = final["contextual"]["semantic"]["metrics"]["joint_accuracy"]
    failures = []
    for label, other in (("baseline", baseline), ("control", reference)):
        if joint <= other["contextual"]["semantic"]["metrics"]["joint_accuracy"]:
            failures.append("context_joint_not_strictly_better_" + label)
        if final["development"]["semantic"]["metrics"]["recall"] < other["development"]["semantic"]["metrics"]["recall"]:
            failures.append("annotation_recall_declined_" + label)
        for metric in ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy"):
            if final["subgroups"]["disclosures"][metric] < other["subgroups"]["disclosures"][metric]:
                failures.append("disclosure_" + metric + "_declined_" + label)
        if not restriction_harms(other["fixtures"]["semantic"]["predictions"], final["fixtures"]["semantic"]["predictions"])["passed"]:
            failures.append("fixture_harm_" + label)
    return {"promising": not failures, "failed_criteria": failures}


def profile_decision(revised, control):
    decisions = {r["cell"]["id"]: promising_seed(r, control) for r in revised}
    if len(decisions) != 3:
        raise ValueError("Exactly three revised realizations required.")
    harm_veto = any(not restriction_harms(r["checkpoints"]["0"]["fixtures"]["semantic"]["predictions"], r["checkpoints"]["168"]["fixtures"]["semantic"]["predictions"])["passed"] for r in revised)
    count = sum(d["promising"] for d in decisions.values())
    return {"shared_control": control["cell"]["id"], "revised_seed_decisions": decisions,
            "promising_seeds": count, "any_seed_fixture_harm_veto": harm_veto,
            "promising_package": count >= 2 and not harm_veto,
            "decision": "promising" if count >= 2 and not harm_veto else "seed-sensitive/tradeoff-or-plateau",
            "seed_spread_interpretation": "conditional on the same shared deterministic control; no independent control-seed variance"}


def final_outcome_flags(baseline, final, final_24_attempts_accepted):
    """Name the two measured gain dimensions without implying all benefits vanished."""
    gain = (final["development"]["metrics"]["specificity"] > baseline["development"]["metrics"]["specificity"]
            or final["contextual"]["metrics"]["joint_accuracy"] > baseline["contextual"]["metrics"]["joint_accuracy"])
    loss = (final["development"]["metrics"]["recall"] < baseline["development"]["metrics"]["recall"]
            or any(final["subgroups"]["disclosures"][k] < baseline["subgroups"]["disclosures"][k] for k in ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy"))
            or not final["fixtures"]["casewise_harms"]["passed"])
    return {"tradeoff_only": gain and loss, "no_specificity_or_context_joint_gain": not gain,
            "continuing_rejections_final24": final_24_attempts_accepted == 0}


def controlled_effect(record, control, iterations=2000):
    """Paired final effects conditional on one shared control, with baseline checks."""
    baseline, control_baseline = record["checkpoints"]["0"], control["checkpoints"]["0"]
    final, reference = record["checkpoints"]["168"], control["checkpoints"]["168"]
    for name in ("development", "contextual", "fixtures"):
        left, right = (endpoint[name]["semantic"] for endpoint in (baseline, control_baseline))
        if prediction_changes(left["predictions"], right["predictions"])["changed_rows"] or left.get("metrics") != right.get("metrics"):
            raise ValueError("Controlled contrasts require identical baseline predictions and metrics.")
        if any(a.get("identities") != b.get("identities") for a, b in matched(left["predictions"], right["predictions"])):
            raise ValueError("Controlled contrasts require identical baseline model identities.")
    def effects(own_before, own_after, control_before, control_after, keys):
        result = {}
        for key in keys:
            own_change = own_after[key] - own_before[key]
            control_change = control_after[key] - control_before[key]
            contrast = own_after[key] - control_after[key]
            difference = own_change - control_change
            if abs(contrast - difference) > 1e-12:
                raise ValueError("Identical baselines must make final contrast equal difference in changes.")
            result[key] = {"revised_final_minus_shared_control_final": contrast,
                           "revised_change_from_baseline": own_change, "shared_control_change_from_baseline": control_change,
                           "difference_in_changes": difference}
        return result
    result = {"shared_control_id": control["cell"]["id"], "baseline_predictions_and_identities_identical": True,
              "difference_in_changes_equivalent_to_final_contrast": True,
              "interpretation": "one revised realization conditional on the same shared control; descriptive paired scenario sampling intervals, not independent control replicas"}
    for name, keys in (("development", ("recall", "specificity")), ("contextual", CONTEXT_METRICS)):
        result[name] = effects(*(endpoint[name]["semantic"]["metrics"] for endpoint in (baseline, final, control_baseline, reference)), keys)
    result["disclosures"] = effects(*(endpoint["subgroups"]["disclosures"] for endpoint in (baseline, final, control_baseline, reference)),
        ("joint_accuracy", "sensitivity_accuracy", "visibility_accuracy", "category_exact_accuracy", "action_accuracy"))
    result["fixture_harms_vs_shared_control"] = restriction_harms(reference["fixtures"]["semantic"]["predictions"], final["fixtures"]["semantic"]["predictions"])
    result["exact_prediction_changes_vs_shared_control"] = {
        name: prediction_changes(reference[name]["semantic"]["predictions"], final[name]["semantic"]["predictions"])
        for name in ("development", "contextual", "fixtures")}
    result["paired_development_vs_shared_control"] = compare_layers(reference["development"], final["development"], iterations=iterations)
    result["paired_contextual_vs_shared_control"] = compare_layers(reference["contextual"], final["contextual"], contextual=True, iterations=iterations)
    return result


def summarize(records, iterations=2000):
    cells, profiles = [], {}
    for record in records:
        base = record["checkpoints"]["0"]
        checkpoints = {}
        for cycle, endpoint in record["checkpoints"].items():
            checkpoints[cycle] = {key: endpoint[key] for key in ("subgroups", "attempts", "accepted_updates", "rejected_attempts")}
            for name in ("development", "contextual", "fixtures"):
                before, after = base[name]["semantic"]["predictions"], endpoint[name]["semantic"]["predictions"]
                checkpoints[cycle][name] = {"metrics": endpoint[name]["semantic"].get("metrics", contextual_metrics(after) if name != "development" else continual.metrics(after)),
                                          "prediction_changes": prediction_changes(before, after)}
                if name != "development":
                    checkpoints[cycle][name]["casewise_harms"] = restriction_harms(before, after)
            if cycle == "168":
                checkpoints[cycle]["paired_development"] = compare_layers(base["development"], endpoint["development"], iterations=iterations)
                checkpoints[cycle]["paired_contextual"] = compare_layers(base["contextual"], endpoint["contextual"], contextual=True, iterations=iterations)
        final = checkpoints["168"]
        qualified = (final["development"]["metrics"]["recall"] >= .9
                     and final["development"]["metrics"]["specificity"] > checkpoints["0"]["development"]["metrics"]["specificity"]
                     and final["contextual"]["metrics"]["joint_accuracy"] >= checkpoints["0"]["contextual"]["metrics"]["joint_accuracy"]
                     and final["fixtures"]["casewise_harms"]["passed"])
        cells.append({**{k: v for k, v in record.items() if k != "checkpoints"}, "checkpoints": checkpoints, "qualified": qualified,
                      **final_outcome_flags(checkpoints["0"], final, record["final_24_attempts_accepted"])})
    for profile in prior.PROFILES:
        selected = [r for r in records if r["cell"]["profile"] == profile]
        control = next(r for r in selected if r["cell"]["shared_control"])
        revised = [r for r in selected if not r["cell"]["shared_control"]]
        profiles[profile] = profile_decision(revised, control)
        profiles[profile]["revised_final_effects_vs_shared_control"] = {r["cell"]["id"]: controlled_effect(r, control, iterations) for r in revised}
    return {"schema_version": "accelerated-semantic-v1", "evaluation_layers": ["semantic"], "cells": cells, "profiles": profiles,
            "attempts": sum(r["attempts"] for r in records), "allocated_presentations": sum(r["exposure"]["presentations"] for r in records)}


def audit(output):
    protocol, state = study.verify_freeze(output)
    if state["status"] != "complete" or set(state["cells"]) != {cell["id"] for cell in protocol["cells"]}:
        raise ValueError("All twelve trajectories must be complete before final audit.")
    records = [load_cell(output, protocol, cell, state["cells"][cell["id"]]) for cell in protocol["cells"]]
    summary = summarize(records, protocol["analysis"]["bootstrap_iterations"])
    if summary["attempts"] != 2016 or summary["allocated_presentations"] != 64512:
        raise ValueError("Study totals differ from fixed prospective budget.")
    summary.update(source_revision=protocol["source_revision"], protocol_sha256=state["protocol_sha256"], decision_rules=protocol["decision"])
    continual.write_json(output / "summary.json", summary)
    continual.write_json(output / "audit.json", {"passed": True, "protocol_sha256": state["protocol_sha256"],
        "summary_sha256": continual.sha(output / "summary.json"),
        "archives": {key: value["archive_sha256"] for key, value in state["cells"].items()},
        "checks": ["fresh base bytes/float32 identity/predictions", "all attempts/snapshots/encoder immutability",
                   "numeric accepted/rejected gate diagnostics", "reservation/cursor reconstruction", "publication payloads/receipts",
                   "semantic returned execution and endpoint identity", "fixed final decision with disclosure and casewise harm vetoes"]})
    return summary
