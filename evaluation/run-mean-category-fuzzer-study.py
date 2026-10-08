"""Prospective mean-category objective study with frozen historical controls."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import itertools
import json
import math
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("contextual_phase01_helpers", ROOT / "evaluation/run-contextual-fuzzer-study.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
prior_spec = importlib.util.spec_from_file_location("class_balanced_phase02_helpers", ROOT / "evaluation/run-class-balanced-fuzzer-study.py")
P = importlib.util.module_from_spec(prior_spec)
prior_spec.loader.exec_module(P)
OBJECTIVE = "class_balanced_contextual_mean_category_v1"
OBJECTIVES = (OBJECTIVE,)
STRATEGIES = ("heads", "last_block")
SEEDS = (42, 1337, 2026)
RATES = (.003, .01)
PREFIX = "meanfuzz20261006v1"
MODEL_IDS = ("privoke-baseline", "privoke-efficient", "privoke-balanced", "privoke-quality", "privoke-presence-efficient", "privoke-presence-balanced", "privoke-presence-quality")
SERVICES = (*C.SERVICES, "telemetry-service")
LIVE_BASE_SHA = "87065d573970eec9b753102599789ebcb199b9b9d75e787b3b06e914137cdd92"
PARITY_SHAS = {"semantic": "6fda10af4810d1045dc977473391e13360ed00d70abfa4c8811db2009652d1a7", "pipeline": "f931cc651116ffea9d89d8a73bc52efe9af2f42504a25b041266710a36bcf1e8"}
OBJECTIVE_AUDITS = ("training_clean_examples", "training_sensitive_examples", "raw_clean_weight", "raw_sensitive_weight", "raw_total_weight", "effective_clean_weight", "effective_sensitive_weight", "clean_objective_mass", "sensitive_objective_mass")
LOSS_AUDITS = ("supervised_sensitivity_ce_loss", "supervised_visibility_ce_loss", "supervised_category_bce_loss", "supervised_objective_loss")
sha, read, write = C.sha, C.read, C.write


def require(condition, message):
    if not condition:
        raise ValueError(message)


def attempts(prefix=PREFIX):
    for index, (strategy, rate, seed, objective) in enumerate(itertools.product(STRATEGIES, RATES, SEEDS, OBJECTIVES)):
        yield {"index": index, "profile": "balanced", "strategy": strategy, "objective": objective, "rate": rate, "seed": seed, "request_id": f"{prefix}-{index:02d}", "source_id": "mean-category-study-20261006", "prompt_count": 256, "heldout_count": 16, "max_gradient": .05, "transforms": 0}


def prepare_base(artifact, record):
    require(record["objective"] in OBJECTIVES and record["strategy"] in STRATEGIES, "Unknown objective/representation.")
    from privoke_model.contextual_training import prepare_contextual_training_artifact, prepare_training_objective_artifact
    result = artifact
    if record["strategy"] == "last_block":
        result = prepare_contextual_training_artifact(result, strategy="contextual_last_block_sgd_v1")
    result = prepare_training_objective_artifact(result, objective=record["objective"])
    require(result["model_id"] == artifact["model_id"] and result["version"] == artifact["version"] and result["config"] == artifact["config"] and {k: (v["shape"], v["values"]) for k, v in result["parameters"].items()} == {k: (v["shape"], v["values"]) for k, v in artifact["parameters"].items()}, "Objective preparation changed base weights/config/identity.")
    return result


def candidate_key(record, original):
    if not record["accepted"]:
        return None
    counts = record["validation"]["pipeline"]
    if counts["tp"] < 428 or counts["tn"] <= original["tn"]:
        return None
    return (counts["tn"], counts["tp"], -record["rate"], -record["seed"], -STRATEGIES.index(record["strategy"]))


def validate_response(response, record, base):
    require(type(response.get("accepted")) is bool and response.get("request") == record, "Training response request/outcome mismatch.")
    receipt = response.get("receipt", {})
    if response["accepted"]:
        if not receipt.get("found") or not receipt.get("accepted") or any(receipt.get(k) != response.get(k) for k in ("model_id", "applied_version", "base_version", "prompts_generated")):
            raise C.UnknownUpdateOutcome("Accepted outcome lacks its exact durable receipt; never retry.")
        require(response.get("base_version") == base["version"] and response.get("model_id") == base["model_id"] and response.get("prompts_generated") == 256, "Training used a different base or sample budget.")
    elif receipt.get("found") or response.get("error_code") not in (None, "FAILED_PRECONDITION", "INVALID_ARGUMENT"):
        raise C.UnknownUpdateOutcome("Rejected/ambiguous outcome conflicts with durable receipt; never retry.")


def inventory_pair(record):
    return (record["strategy"], record["rate"], record["seed"])


def verify_pair(state, record, response):
    inventory = response.get("partition_inventory")
    require(isinstance(inventory, dict) and inventory.get("group_overlap") == 0, "Sampling inventory missing/overlapping.")
    for partition, rows in (("train", 256), ("heldout", 16)):
        value = inventory[partition]
        require(value["rows"] == rows and sum(value["sensitivity_counts"].values()) == rows and value["groups"] == len(value["opaque_group_labels"]), "Sampling inventory supports/groups invalid.")
        commitment = value.get("ordered_samples_sha256", "")
        require(isinstance(commitment, str) and len(commitment) == 64
                and all(character in "0123456789abcdef" for character in commitment),
                "Ordered text/group/target/original-weight commitment missing.")
    require(inventory["heldout"]["groups"] == 16 and not (set(inventory["train"]["opaque_group_labels"]) & set(inventory["heldout"]["opaque_group_labels"])), "Whole-group held-out split invalid.")
    controls = state["prior_study"]["controls"]
    control = next(value for value in controls if (value["strategy"], value["rate"], value["seed"]) == inventory_pair(record))
    require(sha(control["response_path"]) == control["response_sha256"], "Historical control response bytes changed.")
    before = read(control["response_path"])["partition_inventory"]
    require(inventory == before, "Historical control/new objective ordered text/group/target/original-weight commitments differ.")


def objective_audit(record, response):
    """Validate emitted optimization weights; rejected RPCs may lack training metadata."""
    metadata = response.get("metadata", {})
    require(record["objective"] == OBJECTIVE, "Unknown phase03 objective.")
    if not response["accepted"]:
        return {"objective": record["objective"], "accepted": False, "class_balanced_audit_emitted": bool(set(OBJECTIVE_AUDITS) & set(metadata))}
    require(metadata.get("contextual_training_objective") == record["objective"] and metadata.get("objective_strata") == "classification_is_sensitive", "Accepted weighted fit has wrong objective/strata.")
    values = {key: float(metadata[key]) for key in OBJECTIVE_AUDITS}
    require(all(math.isfinite(value) and value > 0 for value in values.values()), "Objective audit must be finite and positive with both classes present.")
    clean, sensitive = values["training_clean_examples"], values["training_sensitive_examples"]
    require(clean.is_integer() and sensitive.is_integer() and clean + sensitive == 256, "Objective class supports do not match the training budget.")
    close = lambda a, b: math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)
    total = values["raw_total_weight"]
    optimization_total = float(metadata["total_weight"])
    require(math.isfinite(optimization_total) and close(optimization_total, total),
            "Optimization denominator differs from preserved original total weight.")
    require(close(values["raw_clean_weight"] + values["raw_sensitive_weight"], total) and all(close(values[f"effective_{label}_weight"], total * .5) and close(values[f"{label}_objective_mass"], .5) for label in ("clean", "sensitive")), "Class-balanced objective masses are not exactly half within numeric tolerance.")
    inventory = response["partition_inventory"]["train"]["sensitivity_counts"]
    # This frozen curriculum has only S0, S2, S3; never infer this mapping for S1 controls.
    require(set(inventory) <= {"S0", "S2", "S3"} and clean == inventory.get("S0", 0) and sensitive == inventory.get("S2", 0) + inventory.get("S3", 0), "Objective supports differ from the frozen curriculum's actual selected class coverage.")
    return {"objective": record["objective"], "strata": metadata["objective_strata"], **values}


def loss_audit(response, base):
    if not response["accepted"]:
        return {"accepted": False, "loss_diagnostics_emitted": all(key in response.get("metadata", {}) for key in LOSS_AUDITS)}
    metadata = response["metadata"]
    values = {key: float(metadata[key]) for key in LOSS_AUDITS}
    require(all(math.isfinite(value) and value >= 0 for value in values.values()), "Mean-category loss components must be finite and nonnegative.")
    require(math.isclose(sum(values[key] for key in LOSS_AUDITS[:3]), values["supervised_objective_loss"], rel_tol=1e-5, abs_tol=1e-6), "Mean-category loss components do not sum to the actual objective.")
    require(metadata.get("category_normalization") == "mean_per_label"
            and metadata.get("diagnostic_loss") == "weighted_classification_distance"
            and metadata.get("category_count") == str(len(base["config"]["category_labels"])),
            "Mean-category reduction/count or legacy diagnostic contract changed.")
    return {**values, "category_count": len(base["config"]["category_labels"]), "category_normalization": "mean_per_label", "diagnostic_loss": "weighted_classification_distance"}


def parity(rows_before, rows_after):
    fields = ("expected_has_pii", "group_id", "detected_sensitive", "sensitivity", "visibility", "categories", "action")
    before = {row["example_id"]: tuple(row.get(key) for key in fields) for row in rows_before}
    after = {row["example_id"]: tuple(row.get(key) for key in fields) for row in rows_after}
    require(len(before) == len(rows_before) == len(after) == len(rows_after) and before == after, "Original balanced prediction parity failed; no fit may proceed.")
    return {"rows": len(before), "classification_action_presence_mismatches": 0, "confidence_and_latency_not_compared": True}


def verify_measurement(counts, reports, reference, artifact):
    require(set(counts) == set(reports) == {"semantic", "pipeline"}, "Both inference layers must be measured.")
    for layer, binding in reports.items():
        require(sha(binding["path"]) == binding["sha256"], "Report bytes changed.")
        report = read(binding["path"])
        require(C.verified_report(report, reference, artifact) == counts[layer], "Raw rows and bound counts disagree.")
        predictions = report["metadata"]["predictions"]
        require(report["metrics"].get("runtime_errors") == 0 and report["metrics"].get("evaluated_samples") == len(reference), "Scored report has runtime errors or missing support.")
        require(all(entry.get("status") in {"ok", "skipped"} and not (entry.get("error") and entry["status"] != "skipped") for row in predictions for entry in row.get("layers", [])), "Scored runtime layer failed.")


def parameter_changes(base, candidate):
    require(set(base["parameters"]) == set(candidate["parameters"]) and base["config"] == candidate["config"], "Parameter/config manifest changed.")
    maximum, changed = 0.0, []
    for name, before in base["parameters"].items():
        after = candidate["parameters"][name]
        require(before["shape"] == after["shape"] and before["trainable"] == after["trainable"] and len(before["values"]) == len(after["values"]), "Tensor shape/trainability changed.")
        differences = [abs(C.float32(old) - C.float32(new)) for old, new in zip(before["values"], after["values"])]
        require(before["trainable"] or not any(differences), "Frozen encoder tensor changed.")
        maximum = max(maximum, *differences)
        if any(differences):
            changed.append(name)
    require(maximum <= .050001, "Published delta exceeds the declared float32-bounded update.")
    return {"maximum_absolute_float32_delta": maximum, "changed_tensors": changed, "frozen_tensors_unchanged": True}


class Driver(C.Driver):
    """Reuse the fixed inference/training protocol; extend exact restoration scope."""
    def images(self):
        result = super().images()
        container = self.command(self.base_compose + ["ps", "-q", "telemetry-service"]).decode().strip()
        require(container and "\n" not in container, "One telemetry container required.")
        result["telemetry-service"] = self.command(["docker", "inspect", "--format", "{{.Image}}", container]).decode().strip()
        return result

    def model_bytes(self, model_id):
        require(model_id in MODEL_IDS, "Unexpected model scope.")
        return self.command(self.base_compose + ["exec", "-T", "param-update-service", "python", "-c", "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())", f"/models/{model_id}.json"])

    def install_model(self, model_id, content):
        require(model_id in MODEL_IDS, "Unexpected model scope.")
        self.command(self.base_compose + ["exec", "-T", "param-update-service", "python", "-c", C.RAW_PUBLICATION_CODE, f"/models/{model_id}.json"], content=content)

    def configure_images(self, images):
        super().configure_images(images)
        self.state["study_images"]["telemetry-service"] = images["telemetry-service"]

    def restore_services(self):
        path = Path(self.args.output) / "restore-images.json"
        expected = {"services": {service: {"image": image} for service, image in self.state["images"].items()}}
        if path.exists():
            require(read(path) == expected, "Restoration image override changed.")
        else:
            write(path, expected)
        self.command(self.base_compose + ["-f", str(path), "up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "120", *C.SERVICES])

    def measure(self, artifact_path, dataset_path, reference, run_name):
        require(not (ROOT / "evaluation/results" / run_name).exists(), "Measurement output already exists; preserve evidence without rerun.")
        return super().measure(artifact_path, dataset_path, reference, run_name)

    def call(self, args, **kwargs):
        # The frozen parent computes a read-only inventory before opening its fit RPC.
        # Verify that result before letting the subsequent RunTrainingCycle command run.
        code = args[-1] if args and isinstance(args[-1], str) else ""
        active = getattr(self, "_active_record", None)
        if active and "RunTrainingCycle(req" in code:
            require(self._inventory_verified, "No historical inventory check before the training RPC.")
        result = super().call(args, **kwargs)
        if active and "from prompt_generation.generator import generate_training_partition" in code:
            verify_pair(self.state, active, {"partition_inventory": json.loads(result)})
            self._inventory_verified = True
        return result

    def train(self, record):
        self._active_record, self._inventory_verified = record, False
        try:
            result = super().train(record)
            require(self._inventory_verified, "Frozen generator inventory hook was not observed.")
            return result
        finally:
            self._active_record = None


def backup_bytes(state):
    result = {}
    require(set(state["catalog_backups"]) == set(MODEL_IDS) and set(state["images"]) == set(SERVICES), "Original seven-model/five-image snapshot incomplete.")
    for model_id, binding in state["catalog_backups"].items():
        require(sha(binding["path"]) == binding["sha256"], "Original backup bytes changed.")
        result[model_id] = Path(binding["path"]).read_bytes()
    return result


def assert_originals(driver, state, backups):
    require(driver.images() == state["images"] and all(driver.model_bytes(model_id) == raw for model_id, raw in backups.items()), "Original catalog bytes or immutable images changed.")


@contextmanager
def restored_catalog(args, state, driver):
    backups = backup_bytes(state)
    assert_originals(driver, state, backups)
    state["restoration_verified"] = False
    write(args.output / "state.json", state)
    try:
        driver.stop_jobs()
        yield
    finally:
        try:
            driver.stop_jobs()
            for model_id, content in backups.items():
                if driver.model_bytes(model_id) != content:
                    driver.install_model(model_id, content)
            driver.restore_services()
            assert_originals(driver, state, backups)
            state["restoration_verified"] = True
        except BaseException as error:
            state["restoration_failure"] = {"type": type(error).__name__, "message": str(error)}
            raise
        finally:
            write(args.output / "state.json", state)


def baseline(args, state, driver):
    require(not state.get("baseline_started") and not state.get("baseline_complete"), "Baseline already started; preserve evidence rather than rerun.")
    state["baseline_started"] = True
    write(args.output / "state.json", state)
    validation = C.bound_inputs(state)
    development = C.bound_rows(state["development"], C.DEVELOPMENT_SHA, 502, 264)
    cases = C.bound_rows(state["fixture"], C.FIXTURE_SHA, 48)
    original_path = Path(state["catalog_backups"]["privoke-balanced"]["path"])
    original = C.load_artifact(original_path)
    driver.configure_images(state["images"])
    with restored_catalog(args, state, driver):
        driver.refresh()
        state["resources"] = driver.resources()
        counts, reports = driver.measure(original_path, state["validation"], validation, f"{state['prefix']}-base-validation")
        verify_measurement(counts, reports, validation, original)
        checks = {}
        for layer in ("semantic", "pipeline"):
            old = state["parity_reports"][layer]
            require(sha(old["path"]) == old["sha256"], "Prior live validation parity proof changed.")
            previous = read(old["path"])
            C.verified_report(previous, validation, original)
            checks[layer] = parity(previous["metadata"]["predictions"], read(reports[layer]["path"])["metadata"]["predictions"])
        state["baselines"] = {"balanced": {"artifact": str(original_path), "sha256": sha(original_path), "identity": C.artifact_identity(original), "validation": counts, "reports": reports, "parity": checks}}
        write(args.output / "state.json", state)
        reference_counts, reference_reports = driver.measure(original_path, state["development"], development, f"{state['prefix']}-base-development")
        verify_measurement(reference_counts, reference_reports, development, original)
        live_fixture = driver.fixture(original_path, cases, args.output / "fixture-live.json")
        state["reference_endpoint"] = {"counts": reference_counts, "reports": reference_reports, "fixture": {"path": str((args.output / 'fixture-live.json').resolve()), "sha256": sha(args.output / "fixture-live.json")}, "case_ids": list(live_fixture), "source_strata": {layer: C.by_dataset(read(binding["path"])) for layer, binding in reference_reports.items()}}
        write(args.output / "state.json", state)
    state["baseline_complete"] = True
    write(args.output / "state.json", state)


def candidates(args, state, driver):
    require(state.get("baseline_complete") and not state.get("selection") and not state.get("failure") and not state.get("unknown_outcome"), "Candidate stage requires fresh complete baseline and unfrozen clean state.")
    validation = C.bound_inputs(state)
    completed = {record["index"] for record in state["records"]}
    remaining = [record for record in state["planned_attempts"] if record["index"] not in completed][:args.limit]
    driver.configure_images(state["images"])
    with restored_catalog(args, state, driver):
        for record in remaining:
            target = args.output / f"attempt-{record['index']:02d}"
            target.mkdir()  # Durable fit request IDs cannot be reused after partial failure.
            write(target / "request.json", record)
            source = state["catalog_backups"]["privoke-balanced"]
            require(sha(source["path"]) == LIVE_BASE_SHA, "Exact live balanced train.2 base changed.")
            base = prepare_base(C.load_artifact(source["path"]), record)
            base_path = target / "base.json"
            write(base_path, base)
            driver.install_raw("balanced", base_path.read_bytes())
            driver.refresh()
            started = time.monotonic()
            try:
                response = driver.train(record)
                write(target / "response.json", response)
                validate_response(response, record, base)
            except C.UnknownUpdateOutcome as error:
                state["unknown_outcome"] = {"attempt": record["index"], "message": str(error), "request_reuse_forbidden": True}
                write(args.output / "state.json", state)
                raise
            verify_pair(state, record, response)
            audit = objective_audit(record, response)
            losses = loss_audit(response, base)
            if response["accepted"]:
                require(float(response["metadata"].get("learning_rate", "nan")) == record["rate"] and float(response["metadata"].get("max_gradient", "nan")) == .05, "Actual training hyperparameters differ from the declaration.")
            result = {**record, "accepted": response["accepted"], "base_artifact": str(base_path.resolve()), "base_artifact_sha256": sha(base_path), "response_path": str((target / "response.json").resolve()), "response_sha256": sha(target / "response.json"), "partition_inventory": response["partition_inventory"], "training_metadata": response.get("metadata", {}), "objective_audit": audit, "loss_audit": losses}
            driver.stop_jobs()
            if response["accepted"]:
                artifact_path = target / "candidate.json"
                artifact_path.write_bytes(driver.live("balanced"))
                artifact = C.load_artifact(artifact_path)
                require(artifact["version"] == response["applied_version"], "Published artifact/version mismatch.")
                require(all(artifact.get("metadata", {}).get(key) == base.get("metadata", {}).get(key) for key in ("contextual_training_objective", "contextual_training_strategy")), "Published objective/representation metadata changed.")
                C.verify_guarded_publication(base, artifact, response)
                result["parameter_change_audit"] = parameter_changes(base, artifact)
                driver.refresh()
                counts, reports = driver.measure(artifact_path, state["validation"], validation, f"{state['prefix']}-v-{record['index']:02d}")
                verify_measurement(counts, reports, validation, artifact)
                result.update(artifact=str(artifact_path.resolve()), artifact_sha256=sha(artifact_path), identity=C.artifact_identity(artifact), validation=counts, reports=reports, source_strata={layer: C.by_dataset(read(binding["path"])) for layer, binding in reports.items()})
                result["eligible"] = candidate_key(result, state["baselines"]["balanced"]["validation"]["pipeline"]) is not None
            result["wall_seconds"] = time.monotonic() - started
            state["records"].append(result)
            write(args.output / "state.json", state)


def freeze(args, state):
    require(len(state["records"]) == 12 and {record["index"] for record in state["records"]} == set(range(12)) and not state.get("failure") and not state.get("unknown_outcome") and state.get("restoration_verified"), "All 12 terminal attempts and exact restoration required before selection.")
    require(not state.get("selection") and not (args.output / "selection.json").exists(), "Selection already frozen.")
    validation = C.bound_inputs(state)
    baseline_binding = state["baselines"]["balanced"]
    require(sha(baseline_binding["artifact"]) == baseline_binding["sha256"] == LIVE_BASE_SHA, "Fresh original baseline artifact changed.")
    verify_measurement(baseline_binding["validation"], baseline_binding["reports"], validation, C.load_artifact(baseline_binding["artifact"]))
    eligible = []
    for record in state["records"]:
        require(all(record.get(key) == value for key, value in state["planned_attempts"][record["index"]].items()), "Terminal settings changed.")
        require(sha(record["response_path"]) == record["response_sha256"], "Response bytes changed.")
        require(sha(record["base_artifact"]) == record["base_artifact_sha256"], "Prepared base bytes changed.")
        response = read(record["response_path"])
        validate_response(response, record_subset(record), C.load_artifact(record["base_artifact"]))
        verify_pair(state, record, response)
        objective_audit(record, response)
        loss_audit(response, C.load_artifact(record["base_artifact"]))
        if record["accepted"]:
            require(sha(record["artifact"]) == record["artifact_sha256"], "Candidate bytes changed.")
            artifact = C.load_artifact(record["artifact"])
            verify_measurement(record["validation"], record["reports"], validation, artifact)
            key = candidate_key(record, state["baselines"]["balanced"]["validation"]["pipeline"])
            if key is not None:
                eligible.append((key, record))
    selection = {"winner": max(eligible, key=lambda item: item[0])[1] if eligible else None, "candidate_count": 12, "rule": "TP>=428/475; TN strictly above fresh exact-base baseline; TN,TP,lower rate,seed,heads tie order", "development_access_for_selection": False, "prior_candidate_endpoints_used": False, "historical_controls_select": False}
    write(args.output / "selection.json", selection)
    state["selection"] = {"path": str((args.output / "selection.json").resolve()), "sha256": sha(args.output / "selection.json")}
    write(args.output / "state.json", state)


def finalize(args, state, driver):
    require(state.get("selection") and not state.get("finalized") and not state.get("failure") and not state.get("unknown_outcome"), "Missing frozen selection or endpoint already started/failed.")
    require(sha(state["selection"]["path"]) == state["selection"]["sha256"], "Frozen selection changed.")
    marker = args.output / "endpoint-started.json"
    require(not marker.exists(), "Endpoint already started; preserve partial evidence without rerun.")
    selection = read(state["selection"]["path"])
    require(selection["candidate_count"] == 12, "Selection grid changed.")
    winner = selection["winner"]
    require(len(state["records"]) == 12 and {record["index"] for record in state["records"]} == set(range(12)) and state.get("restoration_verified"), "Incomplete terminal grid or restoration.")
    if winner is None:
        assert_originals(driver, state, backup_bytes(state))
        state["finalized"] = {"retained": False, "reason": "No eligible validation candidate; no candidate endpoint inference."}
        write(args.output / "state.json", state)
        return
    require(winner == next(record for record in state["records"] if record["index"] == winner["index"]), "Frozen winner differs from its terminal record.")
    write(marker, {"selection_sha256": state["selection"]["sha256"], "winner": winner["index"]})
    development = C.bound_rows(state["development"], C.DEVELOPMENT_SHA, 502, 264)
    cases = C.bound_rows(state["fixture"], C.FIXTURE_SHA, 48)
    reference = state["reference_endpoint"]
    for binding in [*reference["reports"].values(), reference["fixture"]]:
        require(sha(binding["path"]) == binding["sha256"], "Pre-grid reference endpoint evidence changed.")
    before = read(reference["fixture"]["path"])
    verify_measurement(reference["counts"], reference["reports"], development, C.load_artifact(state["catalog_backups"]["privoke-balanced"]["path"]))
    artifact_path = Path(winner["artifact"])
    require(sha(artifact_path) == winner["artifact_sha256"], "Frozen winner bytes changed.")
    driver.configure_images(state["images"])
    with restored_catalog(args, state, driver):
        driver.install_raw("balanced", artifact_path.read_bytes())
        driver.refresh()
        counts, reports = driver.measure(artifact_path, state["development"], development, f"{state['prefix']}-d-winner")
        verify_measurement(counts, reports, development, C.load_artifact(artifact_path))
        after = driver.fixture(artifact_path, cases, args.output / "fixture-winner.json")
        contextual = C.fixture_gate(cases, before, after)
        retained = counts["pipeline"]["tp"] >= 238 and counts["pipeline"]["tn"] > reference["counts"]["pipeline"]["tn"] and contextual["passed"]
        assessment = {"retained": retained, "reference": reference["counts"], "candidate": counts, "reference_reports": reference["reports"], "candidate_reports": reports, "contextual_gate": contextual, "retained_research_artifact": winner["artifact"] if retained else None, "catalog_policy": "Exact original seven-model catalog/five images restored; research artifact only; no default promotion.", "final_access": False, "source_strata": {layer: C.by_dataset(read(binding["path"])) for layer, binding in reports.items()}}
        write(args.output / "final-assessment.json", assessment)
    state["finalized"] = assessment
    write(args.output / "state.json", state)


def record_subset(record):
    return {key: record[key] for key in next(attempts())}


def bind_prior_study(directory):
    """Bind historical training evidence only; never open prior candidate endpoints."""
    directory = Path(directory).resolve()
    state_path = directory / "state.json"
    prior = read(state_path)
    require(prior.get("phase") == "class-balanced-objective-representation"
            and prior["planned_attempts"] == list(P.attempts())
            and len(prior["records"]) == 24
            and {record["index"] for record in prior["records"]} == set(range(24))
            and prior.get("restoration_verified") is True
            and isinstance(prior.get("finalized"), dict) and prior["finalized"].get("retained") is False
            and not prior.get("failure") and not prior.get("unknown_outcome"),
            "Prior study must be the completed, unretained, restored 24-attempt phase02 grid.")
    require(prior["catalog_backups"]["privoke-balanced"]["sha256"] == LIVE_BASE_SHA,
            "Historical control base was not exact live balanced train.2.")
    require(set(prior["catalog_backups"]) == set(MODEL_IDS) and set(prior["images"]) == set(SERVICES), "Historical restoration scope was incomplete.")
    original_binding = prior["catalog_backups"]["privoke-balanced"]
    require(sha(original_binding["path"]) == LIVE_BASE_SHA, "Historical original bytes changed.")
    original = C.load_artifact(original_binding["path"])
    bindings = {"state.json": {"path": str(state_path), "sha256": sha(state_path)}}
    bindings["original-balanced.json"] = original_binding
    selection_binding = prior["selection"]
    require(sha(selection_binding["path"]) == selection_binding["sha256"]
            and read(selection_binding["path"])["candidate_count"] == 24,
            "Prior frozen selection changed.")
    bindings["selection.json"] = selection_binding
    controls = []
    for record in sorted(prior["records"], key=lambda item: item["index"]):
        require(all(record.get(key) == value for key, value in prior["planned_attempts"][record["index"]].items())
                and type(record.get("accepted")) is bool, "Historical terminal settings/outcome changed.")
        require(sha(record["response_path"]) == record["response_sha256"], "Historical response changed.")
        bindings[f"attempt-{record['index']:02d}/response.json"] = {"path": record["response_path"], "sha256": record["response_sha256"]}
        if record["objective"] != "class_balanced_contextual_v1":
            continue
        require(record["index"] % 2 == 1 and sha(record["response_path"]) == record["response_sha256"]
                and sha(record["base_artifact"]) == record["base_artifact_sha256"],
                "Historical weighted response/base commitment changed.")
        response = read(record["response_path"])
        base = C.load_artifact(record["base_artifact"])
        require(base == P.prepare_base(original, record), "Historical weighted control did not start from its exact opt-in original base.")
        P.validate_response(response, P.record_subset(record), base)
        P.verify_pair(prior, record, response)
        P.objective_audit(record, response)
        require(response["accepted"] == record["accepted"]
                and base["model_id"] == "privoke-balanced" and base["version"] == "v0.3.0+train.2"
                and base.get("metadata", {}).get("contextual_training_objective") == "class_balanced_contextual_v1"
                and record["partition_inventory"] == response["partition_inventory"],
                "Historical weighted training identity/objective/inventory mismatch.")
        control = {key: record[key] for key in ("index", "strategy", "rate", "seed", "accepted", "response_path", "response_sha256", "base_artifact", "base_artifact_sha256")}
        if record["accepted"]:
            require(sha(record["artifact"]) == record["artifact_sha256"]
                    and set(record["reports"]) == {"semantic", "pipeline"}, "Historical accepted model/validation binding changed.")
            bindings[f"control-{record['index']:02d}/candidate.json"] = {"path": record["artifact"], "sha256": record["artifact_sha256"]}
            for layer, binding in record["reports"].items():
                require(sha(binding["path"]) == binding["sha256"]
                        and Path(binding["path"]).parent.name == f"{prior['prefix']}-v-{record['index']:02d}",
                        "Historical comparison must bind validation reports, never candidate endpoints.")
                bindings[f"control-{record['index']:02d}/validation-{layer}.json"] = binding
            control.update({key: record[key] for key in ("artifact", "artifact_sha256", "identity", "validation", "reports")})
        controls.append(control)
        bindings[f"control-{record['index']:02d}/response.json"] = {"path": record["response_path"], "sha256": record["response_sha256"]}
        bindings[f"control-{record['index']:02d}/base.json"] = {"path": record["base_artifact"], "sha256": record["base_artifact_sha256"]}
    require(len(controls) == 12 and {inventory_pair(value) for value in controls} == {inventory_pair(value) for value in attempts()}, "Historical matching grid incomplete.")
    return {"directory": str(directory), "state_sha256": sha(state_path), "controls": controls,
            "bindings": bindings, "prepared_manifest_sha256": prior["preparation_manifest_sha256"],
            "scope": {key: prior[key] for key in ("project_name", "runtime_target", "base_overrides", "base_override_sha256", "source_revision")},
            "comparison_design": "archived historical sum-category controls; not contemporaneously refitted or randomized",
            "candidate_endpoints_opened": False, "historical_performance_selects": False}


def validate_prior_binding(prior):
    for binding in prior["bindings"].values():
        require(sha(binding["path"]) == binding["sha256"], "Frozen historical evidence changed.")
    require(bind_prior_study(prior["directory"]) == prior, "Historical prior scope/settings/commitments changed.")


def sources():
    return sorted(set(C.computation_sources()) | {Path(__file__).resolve(), ROOT / "evaluation/run-class-balanced-fuzzer-study.py", ROOT / "evaluation/run-contextual-fuzzer-study.py", ROOT / "evaluation/report-contextual-fuzzer-study.py", ROOT / "evaluation/report-class-balanced-fuzzer-study.py", ROOT / "evaluation/report-mean-category-fuzzer-study.py", ROOT / "evaluation/prepare-contextual-fuzzer-study.py", ROOT / "evaluation/compose.contextual-fuzzer-study.yml", ROOT / "docs/class-balanced-fuzzer-study-20261006.md", ROOT / "docs/mean-category-fuzzer-study-20261006.md", ROOT / "evaluation/tests/test_mean_category_fuzzer_study.py", ROOT / "evaluation/tests/test_class_balanced_fuzzer_study.py"})


def state_plan(args):
    results = args.source_results
    parity_dir = results / "ctxfuzz20261006v2-live-parity"
    parity_reports = {}
    for layer, commitment in PARITY_SHAS.items():
        files = list(parity_dir.glob(f"local-jsonl_{layer}_*_results.json"))
        require(len(files) == 1 and sha(files[0]) == commitment, "Old live-balanced validation parity proof missing/changed.")
        parity_reports[layer] = {"path": str(files[0].resolve()), "sha256": commitment}
    parity_proof = results / "contextual_fuzzer_20261006_preflight/parity.json"
    state = {"schema_version": 1, "phase": "mean-category-objective-representation", "prefix": PREFIX, "prepared": str(args.prepared.resolve()), "preparation_manifest_sha256": sha(args.prepared / "manifest.json"), "validation": str((results / "representation_20261004_v3/prepared/validation.jsonl").resolve()), "development": str((results / "locked-public/development.jsonl").resolve()), "fixture": str((results / "contextual_fixtures_20261004_v1/support/fixture.jsonl").resolve()), "planned_attempts": list(attempts()), "records": [], "restoration_verified": False, "source_revision": C.subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "parity_reports": parity_reports, "parity_proof": {"path": str(parity_proof.resolve()), "sha256": sha(parity_proof)}, "project_name": args.project_name, "runtime_target": args.runtime_target, "base_overrides": args.base_override, "base_override_sha256": {path: sha(ROOT / path) for path in args.base_override}, "computation_source_sha256": {path.relative_to(ROOT).as_posix(): sha(path) for path in sources()}}
    state["prior_study"] = bind_prior_study(args.prior_study)
    require(state["prior_study"]["prepared_manifest_sha256"] == state["preparation_manifest_sha256"] and state["prior_study"]["scope"] == {key: state[key] for key in ("project_name", "runtime_target", "base_overrides", "base_override_sha256", "source_revision")}, "Prior curriculum or execution scope differs.")
    C.bound_inputs(state)
    return state


def initialize(args, state):
    require(not args.output.exists(), "Refuse existing study output.")
    require(args.runtime_image and args.streamer_image and args.updater_image and args.fuzzer_image, "Root-built feature runtime/streamer/updater/fuzzer images required.")
    args.output.mkdir(parents=True)
    frozen = args.output / "source-freeze"
    frozen.mkdir()
    state["source_freeze"] = {}
    for relative, commitment in state["computation_source_sha256"].items():
        path = frozen / "tree" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / relative).read_bytes())
        state["source_freeze"][relative] = {"path": str(path.resolve()), "sha256": commitment}
    for label, source in (("preparation-manifest.json", args.prepared / "manifest.json"), ("prompts.jsonl", args.prepared / "prompts.jsonl"), ("parity.json", Path(state["parity_proof"]["path"])), *((f"parity-{layer}.json", Path(binding["path"])) for layer, binding in state["parity_reports"].items())):
        target = frozen / label
        target.write_bytes(source.read_bytes())
        state["source_freeze"][label] = {"path": str(target.resolve()), "sha256": sha(target)}
    for label, binding in state["prior_study"]["bindings"].items():
        target = frozen / "historical-controls" / label
        target.parent.mkdir(parents=True, exist_ok=True)
        require(sha(binding["path"]) == binding["sha256"], "Historical evidence changed before freeze.")
        target.write_bytes(Path(binding["path"]).read_bytes())
        state["source_freeze"]["historical-controls/" + label] = {"path": str(target.resolve()), "sha256": sha(target)}
    write(args.output / "state.json", state)
    driver = Driver(args, state)
    state["images"] = driver.images()
    require(driver.command(driver.base_compose + ["exec", "-T", "param-update-service", "python", "-c", "import os;print(os.environ['FUZZER_PROMPT_COUNT'])"]).decode().strip() == "0", "Original automatic startup training must be disabled.")
    state["catalog_backups"] = {}
    original = args.output / "original-live"
    original.mkdir()
    for model_id in MODEL_IDS:
        path = original / f"{model_id}.json"
        path.write_bytes(driver.model_bytes(model_id))
        artifact = C.load_artifact(path)
        state["catalog_backups"][model_id] = {"path": str(path.resolve()), "sha256": sha(path), "model_id": artifact["model_id"], "version": artifact["version"], "checksum": artifact["checksum"]}
    balanced = state["catalog_backups"]["privoke-balanced"]
    require(balanced["sha256"] == LIVE_BASE_SHA and balanced["version"] == "v0.3.0+train.2", "Initial base must be exact live balanced train.2 bytes.")
    driver.configure_images(state["images"])
    assert_originals(driver, state, backup_bytes(state))
    state["restoration_verified"] = True
    write(args.output / "state.json", state)


def validate_scope(args, state):
    require(state["planned_attempts"] == list(attempts()) and state["prefix"] == PREFIX, "Grid/prefix changed.")
    require(args.project_name == state["project_name"] and args.runtime_target == state["runtime_target"] and (not args.base_override or args.base_override == state["base_overrides"]), "Project/target/ordered overlays changed.")
    require(C.subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == state["source_revision"] and {path.relative_to(ROOT).as_posix(): sha(path) for path in sources()} == state["computation_source_sha256"], "Frozen source revision/computation changed.")
    for binding in state["source_freeze"].values():
        require(sha(binding["path"]) == binding["sha256"], "Frozen source/proof bytes changed.")
    for path, commitment in state["base_override_sha256"].items():
        require(sha(ROOT / path) == commitment, "Serving override changed.")
    require(not state.get("failure") and not state.get("unknown_outcome"), "Failed/unknown stage requires preserved evidence and fresh reviewed recovery, never blind retry.")
    require(not getattr(args, "prior_study", None) or Path(args.prior_study).resolve() == Path(state["prior_study"]["directory"]).resolve(), "Historical study scope changed.")
    validate_prior_binding(state["prior_study"])
    C.bound_inputs(state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "initialize", "baseline", "candidates", "freeze", "finalize"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepared", type=Path)
    parser.add_argument("--source-results", type=Path)
    parser.add_argument("--prior-study", type=Path)
    parser.add_argument("--project-name", default="privoke-research-project")
    parser.add_argument("--runtime-target", default="127.0.0.1:50054")
    parser.add_argument("--base-override", action="append", default=[])
    parser.add_argument("--limit", type=int, default=1)
    for name in ("runtime", "streamer", "updater", "fuzzer"):
        parser.add_argument(f"--{name}-image")
    args = parser.parse_args()
    args.output = args.output.resolve()
    require(args.output.parent == (ROOT / "evaluation/results").resolve() and 1 <= args.limit <= 12, "Fresh direct-child output and limit1..12 required.")
    if args.mode in ("plan", "initialize"):
        require(args.prepared is not None and args.source_results is not None and args.prior_study is not None, "Prepared/source results and --prior-study required.")
        state = state_plan(args)
        if args.mode == "plan":
            print(json.dumps(state, indent=2))
        else:
            initialize(args, state)
        return
    state = read(args.output / "state.json")
    validate_scope(args, state)
    if args.mode == "freeze":
        freeze(args, state)
        return
    driver = Driver(args, state)
    try:
        with (args.output / "study.log").open("a", encoding="utf-8") as log:
            driver.log = log
            try:
                {"baseline": baseline, "candidates": candidates, "finalize": finalize}[args.mode](args, state, driver)
            finally:
                driver.log = None
    except BaseException as error:
        state["failure"] = {"phase": args.mode, "type": type(error).__name__, "message": str(error), "request_reuse_forbidden": True}
        write(args.output / "state.json", state)
        raise


if __name__ == "__main__":
    main()
