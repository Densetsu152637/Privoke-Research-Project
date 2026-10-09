"""Read-only raw-evidence reconciliation and safe aggregate study reporting."""
from __future__ import annotations

from collections import defaultdict
from contextlib import closing
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import struct

from privoke.v1 import parameters_pb2 as PP
from privoke_model.artifact import float32, load_artifact
from privoke_model.fingerprint import parameter_fingerprint
from privoke_eval import continual_fuzzer_study as continual
from privoke_eval.curriculum_improvement_evidence import (
    accepted_metadata, audit_allocations, binary_counts, contextual_changes, contextual_metrics, digest,
    matched, restriction_harms, seed_statistics,
)
from privoke_eval.curriculum_improvement_imports import semantic_view, verify_import_manifest
from privoke_eval.curriculum_improvement_study import (
    ARMS, PROFILES, SEEDS, artifact_identity, assert_baseline, validate_operations, verify_archive,
)


def compare_layers(before, after, contextual=False, iterations=2000):
    result = {}
    for layer in ("semantic",):
        a, b = before[layer]["predictions"], after[layer]["predictions"]
        matched(a, b)
        if contextual:
            result[layer] = {"before": contextual_metrics(a), "after": contextual_metrics(b),
                             "paired": contextual_changes(a, b, iterations=iterations), "casewise_action_harms": restriction_harms(a, b)}
        else:
            result[layer] = {"before": binary_counts(a), "after": binary_counts(b),
                             "paired": continual.paired_changes(a, b, iterations=iterations, seed=10102026)}
    return result


def outcome_statistics(records, *, deltas=False):
    result = {}
    for endpoint in ("development", "contextual", "fixture_classification"):
        if endpoint not in records[0]:
            continue
        result[endpoint] = {}
        for layer in ("semantic",):
            result[endpoint][layer] = {}
            for metric, value in records[0][endpoint][layer]["after"].items():
                if type(value) not in (int, float):
                    continue
                values = [row[endpoint][layer]["after"][metric] - (row[endpoint][layer]["before"][metric] if deltas else 0) for row in records]
                result[endpoint][layer][metric] = seed_statistics(values)
    return result


def round_chain(directory, model_id, model, durable_metadata=None):
    baseline = continual.read_json(directory / "snapshot-000.json")
    current = baseline["identity"]
    rounds = model["rounds"]
    if len(rounds) != 20 or model.get("pending") or model["accepted_updates"] != sum(r["response"]["accepted"] for r in rounds):
        raise ValueError("Exactly 20 resolved attempts, including rejections, required.")
    for index, row in enumerate(rounds, 1):
        request, response = row["request"], row["response"]
        if row["cycle"] != index or request["seed"] != 1337 + index - 1 or request["prompt_count"] != 256 or request["model_id"] != model_id:
            raise ValueError("Training request budget/identity differs.")
        import hashlib
        fingerprint = hashlib.sha256(PP.FuzzerTrainingRequest(**request).SerializeToString(deterministic=True)).hexdigest()
        if row["request_fingerprint"] != fingerprint or continual.read_json(directory / f"round-{index:03d}.json") != row:
            raise ValueError("Attempt bytes or request fingerprint changed.")
        response_path = directory / row["response_path"]
        if continual.sha(response_path) != row["response_sha256"] or continual.read_json(response_path) != response:
            raise ValueError("Response archive differs.")
        snapshot = continual.read_json(directory / f"snapshot-{index:03d}.json")
        if any(tensor != baseline["parameters"].get(name) for name, tensor in snapshot["parameters"].items() if not name.startswith("head.")):
            raise ValueError("Live head-only training changed an encoder tensor.")
        if snapshot["identity"] != row["identity"]:
            raise ValueError("Round snapshot differs from observed identity.")
        shape_fingerprint = parameter_fingerprint({n: p["values"] for n, p in snapshot["parameters"].items()}, {n: p["shape"] for n, p in snapshot["parameters"].items()})
        if shape_fingerprint != row["identity"]["parameter_fingerprint"]:
            raise ValueError("Archived published tensors do not match serving fingerprint.")
        if response["accepted"]:
            if response["base_version"] != current["model_version"] or response["applied_version"] != row["identity"]["model_version"] or response["applied_version"] == response["base_version"]:
                raise ValueError("Accepted publication version chain differs.")
            value_fingerprint = parameter_fingerprint({n: p["values"] for n, p in snapshot["parameters"].items()})
            previous_snapshot = continual.read_json(directory / f"snapshot-{index-1:03d}.json")
            before_fingerprint = parameter_fingerprint({n: p["values"] for n, p in previous_snapshot["parameters"].items()})
            meta = accepted_metadata(row, durable_metadata)
            if (meta.get("updated_parameter_fingerprint") != value_fingerprint
                    or meta.get("base_parameter_fingerprint") != before_fingerprint):
                raise ValueError("Published values differ from exact guarded candidate/base.")
        elif row["identity"] != current:
            raise ValueError("Rejected attempt changed published model.")
        current = row["identity"]
    return rounds


def durable_publications(directory, rounds, published, fuzzer_id):
    audit_path = directory / "parameter-update-data/updates.jsonl"
    receipt_path = audit_path.with_name(audit_path.name + ".receipts.sqlite3")
    rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    with closing(sqlite3.connect(receipt_path.resolve().as_uri() + "?mode=ro", uri=True)) as database:
        receipts = {key: json.loads(raw) for key, raw in database.execute("SELECT key, receipt FROM update_receipts")}
    accepted = [r for r in rounds if r["response"]["accepted"]]
    if len(rows) != len(accepted) or len(receipts) != len(accepted):
        raise ValueError("Durable publication rows/receipts differ from accepted attempts.")
    last = None
    for row, attempt in zip(rows, accepted):
        request, response = attempt["request"], attempt["response"]
        key = digest([fuzzer_id, request["source_id"], request["request_id"]])
        receipt = receipts.get(key)
        if not receipt:
            raise ValueError("Missing durable accepted receipt.")
        metadata = row["metadata"]
        if (row["source_id"] != fuzzer_id or row["model_id"] != request["model_id"]
                or row["base_version"] != response["base_version"] or row["applied_version"] != response["applied_version"]
                or row["artifact_checksum"] != attempt["identity"]["artifact_checksum"]
                or metadata.get("request_id") != request["request_id"] or metadata.get("request_source_id") != request["source_id"]):
            raise ValueError("Durable publication identity differs from attempt.")
        update = PP.ParameterUpdateRequest(source_id=row["source_id"], model_id=row["model_id"], base_version=row["base_version"],
                                           gradients=row["gradients"], metadata=metadata)
        expected = {"key": key, "payload_digest": hashlib.sha256(update.SerializeToString(deterministic=True)).hexdigest(),
                    "request_fingerprint": metadata["training_request_fingerprint"], "model_id": request["model_id"],
                    "base_version": response["base_version"], "applied_version": response["applied_version"], "prompts_generated": 256}
        if receipt != expected:
            raise ValueError("Durable receipt differs from exact transported publication payload.")
        last = receipt
    if last is not None and json.loads(published["metadata"]["last_update_receipt"]) != last:
        raise ValueError("Final artifact does not retain the latest accepted receipt.")
    return {"durable_publications": len(rows), "durable_receipts": len(receipts),
            "replayed_acknowledgments_reconciled_from_durable_metadata": sum(r["response"]["metadata"].get("replayed") == "true" for r in accepted)}


def offline_tensor_changes(initial, published):
    def f32(value):
        return struct.unpack("!f", struct.pack("!f", value))[0]
    if initial["parameters"].keys() != published["parameters"].keys():
        raise ValueError("Offline exported tensor names differ.")
    result = {}
    for name, before in initial["parameters"].items():
        after = published["parameters"][name]
        if before["shape"] != after["shape"]:
            raise ValueError("Offline exported tensor shape differs.")
        a, b = [f32(v) for v in before["values"]], [f32(v) for v in after["values"]]
        result[name] = {"changed_values": sum(x != y for x, y in zip(a, b)),
                        "maximum_absolute_delta": max(abs(f32(y - x)) for x, y in zip(a, b))}
    return result


def semantic_eligibility(outcomes):
    before, after = (outcomes["development"]["semantic"][key] for key in ("before", "after"))
    contextual = outcomes["contextual"]["semantic"]
    return (after["recall"] >= .9 and after["specificity"] > before["specificity"]
            and contextual["after"]["joint_accuracy"] >= contextual["before"]["joint_accuracy"]
            and outcomes["fixtures"]["semantic"]["passed"])


def load_cell(output, protocol, cell, state):
    imported = bool(state.get("imported"))
    analysis_protocol = protocol
    if imported:
        entry = protocol["imports"]["cells"][cell["id"]]
        protocol = verify_import_manifest(analysis_protocol["imports"])
        directory = Path(entry["directory"])
        cell, state = entry["cell"], entry["state"]
    else:
        directory = output / "cells" / cell["id"]
    verify_archive(directory, state["archive_sha256"])
    validate_operations(continual.read_json(directory / "operations.json"), cell, protocol)
    model_id = f"privoke-{cell['profile']}"
    initial = load_artifact(directory / "initial-artifact.json")
    published = load_artifact(directory / "published-artifact.json")
    if continual.sha(directory / "initial-artifact.json") != protocol["source_files"][f"models/{model_id}.json"]:
        raise ValueError("Initial artifact is not committed baseline bytes.")
    context = [continual.read_json(directory / f"context-{cycle:03d}.json") for cycle in (0, 20)]
    fixture = [continual.read_json(directory / f"fixture-{cycle:03d}.json") for cycle in (0, 20)]
    if context[0]["identity"] != artifact_identity(initial) or context[1]["identity"] != artifact_identity(published):
        raise ValueError("Contextual endpoints differ from archived baseline/final artifact identities.")
    if any(f["identity"] != c["identity"] for f, c in zip(fixture, context)):
        raise ValueError("Fixture/contextual endpoint identities differ.")
    for endpoint in (*context, *fixture):
        endpoint["layers"] = semantic_view(endpoint["layers"], imported=imported)
    exposure = None
    if cell["kind"] == "live":
        controller = directory / "controller"
        manifest = continual.read_json(controller / "run-manifest.json")
        config = manifest["config"]
        if manifest["status"] != "complete" or config["mining"] or config["cycles"] != 20 or config["seed"] != 1337 or config["checkpoints"] != [0, 20]:
            raise ValueError("Controller did not execute frozen fixed-attempt protocol.")
        if config["curriculum_sampler_policy"] != cell["policy"] or config["curriculum_sampler_seed"] != cell["sampler_seed"]:
            raise ValueError("Controller sampler differs from frozen cell.")
        model = manifest["models"][model_id]
        raw = controller / model_id
        assert_baseline(continual.read_json(raw / "snapshot-000.json"), initial)
        audit_path = directory / "parameter-update-data/updates.jsonl"
        audit_rows = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        durable_metadata = {(r["metadata"]["request_source_id"], r["metadata"]["request_id"]): r["metadata"] for r in audit_rows}
        rounds = round_chain(raw, model_id, model, durable_metadata)
        operations = continual.read_json(directory / "operations.json")
        publication_counts = durable_publications(directory, rounds, published, operations["containers"][f"{cell['project']}-fuzzer"]["environment"]["FUZZER_ID"])
        curriculum = continual.read_json(protocol["inputs"][cell["curriculum"]]["manifest"])
        parent = Path(protocol["inputs"][cell["curriculum"]]["manifest"]).parent
        lookup = {}
        for split, entry in curriculum["splits"].items():
            for line in (parent / entry["path"]).read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                lookup[row["id"]] = (split, row)
        exposure = audit_allocations(directory / "curriculum.sqlite3", rounds, lookup, cell["policy"], cell["sampler_seed"], cell["replay_weight"], durable_metadata)
        exposure.update(publication_counts)
        development = [continual.read_json(raw / f"checkpoint-{cycle:03d}.json") for cycle in (0, 20)]
        if not imported and config.get("evaluation_layers") != ["semantic"]:
            raise ValueError("Controller did not bind semantic-only measurement.")
        for cycle, checkpoint in zip((0, 20), development):
            saved = model["checkpoints"][str(cycle)]
            if continual.sha(raw / saved["path"]) != saved["sha256"] or continual.sha(raw / saved["snapshot_path"]) != saved["snapshot_sha256"]:
                raise ValueError("Controller checkpoint commitment differs.")
            if any(value["identity"] != context[cycle // 20]["identity"] for value in checkpoint.values()):
                raise ValueError("Development checkpoint identity differs.")
        attempts, accepted = len(rounds), model["accepted_updates"]
    else:
        development = [continual.read_json(directory / f"development-{cycle:03d}.json") for cycle in (0, 20)]
        fit = continual.read_json(directory / "offline/fit-receipt.json")
        changes = offline_tensor_changes(initial, published)
        if fit["changed_tensors"] != changes or fit["optimizer_state_sha256"] != continual.sha(directory / "offline/optimizer-state.pt"):
            raise ValueError("Offline tensor-change or optimizer-state audit differs.")
        encoder_changed = any(item["changed_values"] for name, item in changes.items() if not name.startswith("head."))
        if encoder_changed != (cell["mode"] == "end_to_end"):
            raise ValueError("Offline encoder behavior differs from selected mode.")
        if (fit["mode"] != cell["mode"] or fit["seed"] != cell["replicate_seed"] or fit["steps"] != 20 or fit["presentations"] != 640
                or fit["artifact_sha256"] != continual.sha(directory / "offline/artifact.json") or artifact_identity(published) != artifact_identity(load_artifact(directory / "offline/artifact.json"))
                or fit["baseline_sha256"] != continual.sha(directory / "initial-artifact.json")
                or fit["train_sha256"] != protocol["inputs"]["revised"]["files"]["train.jsonl"]
                or (fit["learning_rate"], fit["weight_decay"], fit["max_gradient_norm"]) != (.001, .0001, 1.0)):
            raise ValueError("Offline fitting contract/export differs.")
        ids = []
        for index in range(1, 21):
            step = continual.read_json(directory / f"offline/step-{index:03d}.json")
            if step["step"] != index or len(step["row_ids"]) != 32:
                raise ValueError("Offline step budget differs.")
            ids.extend(step["row_ids"])
        rows = [json.loads(line) for line in (Path(protocol["inputs"]["revised"]["manifest"]).parent / "train.jsonl").read_text(encoding="utf-8").splitlines()]
        indexes = list(range(len(rows)))
        random.Random(cell["replicate_seed"]).shuffle(indexes)
        expected_ids = [rows[i]["id"] for i in indexes[:640]]
        if ids != expected_ids or fit["schedule_sha256"] != digest(ids) or fit["unique_rows"] != 640:
            raise ValueError("Offline matched schedule differs.")
        exposure = {k: fit[k] for k in ("steps", "presentations", "unique_rows", "unique_families", "partial_epoch", "maximum_inference_parity_error", "changed_tensors")}
        attempts, accepted = None, None
    development = [semantic_view(endpoint, imported=imported) for endpoint in development]
    outcomes = {"development": compare_layers(*development), "contextual": compare_layers(context[0]["layers"], context[1]["layers"], True),
                "fixtures": {layer: restriction_harms(fixture[0]["layers"][layer]["predictions"], fixture[1]["layers"][layer]["predictions"]) for layer in ("semantic",)}}
    outcomes["fixture_classification"] = compare_layers(fixture[0]["layers"], fixture[1]["layers"], True)
    outcomes["hard_positive_contextual"] = compare_layers(
        *[{layer: {"predictions": [row for row in endpoint["layers"][layer]["predictions"] if row.get("hard_positive")]} for layer in ("semantic",)} for endpoint in context], contextual=True)
    before, after = (outcomes["development"]["semantic"][key] for key in ("before", "after"))
    eligible = semantic_eligibility(outcomes)
    baseline_signature = {"development": development[0], "contextual": context[0]["layers"], "fixtures": fixture[0]["layers"]}
    return {"id": cell["id"], "kind": cell["kind"],
            "measurement_origin": "imported_v1_semantic" if imported else "prospective_v2_semantic",
            "execution_source_revision": protocol["source_revision"], "profile": cell["profile"], "arm": cell.get("arm"), "mode": cell.get("mode"),
            "seed": cell["replicate_seed"], "attempts": attempts, "accepted_updates": accepted,
            "rejected_attempts": attempts - accepted if attempts is not None else None, "eligible": eligible,
            "baseline_recall_gate_passed": before["recall"] >= .9, "outcomes": outcomes, "exposure": exposure}, {
            "baseline": baseline_signature, "development": development[1], "contextual": context[1]["layers"], "fixtures": fixture[1]["layers"]}


def audit(output):
    """Audit archived data only; never issues RPCs or reads protected examples."""
    protocol = continual.read_json(output / "protocol.json")
    state = continual.read_json(output / "supervisor.json")
    if protocol.get("schema_version") != 2 or protocol.get("evaluation_layers") != ["semantic"]:
        raise ValueError("Only amended semantic-only v2 analysis is supported; historical v1 remains unchanged.")
    verify_import_manifest(protocol["imports"])
    if continual.sha(output / "semantic-imports.json") != protocol["import_manifest_sha256"]:
        raise ValueError("Semantic import manifest commitment changed.")
    if continual.sha(output / "protocol.json") != state["protocol_sha256"] or state["status"] != "complete":
        raise ValueError("Complete frozen matrix required before aggregate conclusions.")
    if len(protocol["cells"]) != 63 or set(state["cells"]) != {c["id"] for c in protocol["cells"]}:
        raise ValueError("Incomplete prescribed 45 live +18 offline cells.")
    records, raw, baseline = [], {}, {}
    for cell in protocol["cells"]:
        if state["cells"][cell["id"]]["status"] != "complete":
            raise ValueError("Unresolved cell outcome.")
        record, evidence = load_cell(output, protocol, cell, state["cells"][cell["id"]])
        records.append(record)
        raw[cell["id"]] = evidence
        # Request IDs/timing vary. Compare exact contextual/actions and matched truth.
        current = evidence["baseline"]
        reference = baseline.setdefault(cell["profile"], current)
        for endpoint in reference:
            for layer in ("semantic",):
                pairs = matched(reference[endpoint][layer]["predictions"], current[endpoint][layer]["predictions"])
                if any((a.get("classification", a.get("raw", {}).get("classification")), a.get("action", a.get("raw", {}).get("action")), a.get("detected_sensitive")) !=
                       (b.get("classification", b.get("raw", {}).get("classification")), b.get("action", b.get("raw", {}).get("action")), b.get("detected_sensitive")) for a, b in pairs):
                    raise ValueError("Same-profile baseline predictions changed across cells.")
    by_id = {record["id"]: record for record in records}
    contrasts = []
    for profile in PROFILES:
        for label, left, right in (("curriculum deterministic", "A", "B"), ("curriculum seeded", "C", "D"),
                                   ("sampler current", "A", "C"), ("sampler revised", "B", "D"),
                                   ("package", "A", "D"), ("replay", "D", "E")):
            seed_records = []
            for seed in SEEDS:
                a, b = (raw[f"{profile}-{arm.lower()}-{seed}"] for arm in (left, right))
                seed_records.append({"seed": seed, "development": compare_layers(a["development"], b["development"]),
                                     "contextual": compare_layers(a["contextual"], b["contextual"], True),
                                     "fixtures": {layer: restriction_harms(a["fixtures"][layer]["predictions"], b["fixtures"][layer]["predictions"]) for layer in ("semantic",)}})
            contrasts.append({"profile": profile, "comparison": f"{right}-{left}", "meaning": label, "seeds": seed_records,
                              "endpoint_delta_statistics": outcome_statistics(seed_records, deltas=True),
                              "semantic_specificity_delta": seed_statistics([row["development"]["semantic"]["after"]["specificity"] - row["development"]["semantic"]["before"]["specificity"] for row in seed_records]),
                              "semantic_contextual_joint_delta": seed_statistics([row["contextual"]["semantic"]["after"]["joint_accuracy"] - row["contextual"]["semantic"]["before"]["joint_accuracy"] for row in seed_records])})
        interaction = {}
        for endpoint in ("development", "contextual"):
            interaction[endpoint] = {}
            for layer in ("semantic",):
                interaction[endpoint][layer] = {}
                sample = by_id[f"{profile}-a-42"]["outcomes"][endpoint][layer]["after"]
                for metric, point in sample.items():
                    if type(point) not in (int, float):
                        continue
                    values = []
                    for seed in SEEDS:
                        value = lambda arm: by_id[f"{profile}-{arm.lower()}-{seed}"]["outcomes"][endpoint][layer]["after"][metric]
                        values.append((value("D") - value("C")) - (value("B") - value("A")))
                    interaction[endpoint][layer][metric] = seed_statistics(values)
        contrasts.append({"profile": profile, "comparison": "(D-C)-(B-A)", "meaning": "curriculum/sampler interaction",
                          "endpoint_delta_statistics": interaction})
        offline = []
        for seed in SEEDS:
            a, b = (raw[f"{profile}-{mode}-{seed}"] for mode in ("head-only", "end-to-end"))
            offline.append({"seed": seed, "development": compare_layers(a["development"], b["development"]),
                            "contextual": compare_layers(a["contextual"], b["contextual"], True)})
        contrasts.append({"profile": profile, "comparison": "offline end_to_end-head_only", "seeds": offline,
                          "endpoint_delta_statistics": outcome_statistics(offline, deltas=True)})
    group_summaries = []
    for profile in PROFILES:
        for key in list(ARMS) + ["head_only", "end_to_end"]:
            selected = [r for r in records if r["profile"] == profile and (r["arm"] or r["mode"]) == key]
            group_summaries.append({"profile": profile, "arm_or_mode": key, "deterministic_replicas_not_independent": key in {"A", "B"},
                                    "all_endpoint_statistics": outcome_statistics([r["outcomes"] for r in selected]),
                                    "eligible_cells": sum(r["eligible"] for r in selected),
                                    "semantic_recall": seed_statistics([r["outcomes"]["development"]["semantic"]["after"]["recall"] for r in selected]),
                                    "semantic_specificity": seed_statistics([r["outcomes"]["development"]["semantic"]["after"]["specificity"] for r in selected]),
                                    "semantic_contextual_joint": seed_statistics([r["outcomes"]["contextual"]["semantic"]["after"]["joint_accuracy"] for r in selected])})
    summary = {"schema_version": 2, "evaluation_layers": ["semantic"], "amendment": protocol["amendment"], "protocol_sha256": state["protocol_sha256"], "source_revision": protocol["source_revision"],
               "imported_semantic_cells": sum(r["measurement_origin"] == "imported_v1_semantic" for r in records),
               "prospective_semantic_cells": sum(r["measurement_origin"] == "prospective_v2_semantic" for r in records),
               "status": "audited", "live_cells": 45, "offline_cells": 18, "live_attempts": sum(r["attempts"] or 0 for r in records),
               "accepted_updates": sum(r["accepted_updates"] or 0 for r in records), "offline_steps": 360,
               "cells": records, "groups": group_summaries, "contrasts": contrasts, "limitations": protocol["limitations"],
               "inference": "All bootstrap intervals descriptive; no pooled profile quality or three-seed confidence interval. No promotion."}
    if summary["live_attempts"] != 900:
        raise ValueError("Live attempt total differs from 900.")
    continual.write_json(output / "summary.json", summary)
    continual.write_json(output / "audit.json", {"passed": True, "protocol_sha256": state["protocol_sha256"], "summary_sha256": continual.sha(output / "summary.json"),
                         "execution_protocols": {key: protocol["imports"]["protocol_sha256"] if value.get("imported") else state["protocol_sha256"] for key, value in state["cells"].items()},
                         "archives": {key: value["archive_sha256"] for key, value in state["cells"].items()}, "checks": ["baseline bytes/float32 identities/predictions", "attempt/response/publication chains", "SQLite allocations/cursor reconstruction", "matched truth/group endpoints", "offline exposure/export contracts"]})
    return summary
