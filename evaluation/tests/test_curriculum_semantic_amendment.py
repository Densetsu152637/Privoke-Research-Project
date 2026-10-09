"""Semantic-only amendment admission, isolation and cross-origin contracts."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from privoke_eval import continual_fuzzer_study as continual
from privoke_eval import curriculum_improvement_imports as imports
from privoke_eval import curriculum_improvement_study as study
from privoke_eval import curriculum_improvement_report as report


def observation(key="row"):
    return {"id": key, "group_id": key, "status": "ok", "expected_has_pii": False,
            "detected_sensitive": False, "quantitative": True, "allowed_actions": ["ALLOW"],
            "target": {"sensitivity": "S0", "visibility": "PU", "categories": []},
            "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []}, "action": "ALLOW",
            "raw": {"layers": [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}],
                    "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []}, "action": "ALLOW"}}


class AmendmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="semantic-amendment-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_import_selects_semantic_before_any_metric_and_fresh_rejects_other_keys(self):
        semantic = {"predictions": [observation()]}
        historical = {"semantic": semantic, "pipeline": {"predictions": "intentionally unusable historical layer"}}
        self.assertEqual(imports.semantic_view(historical, imported=True), {"semantic": semantic})
        with self.assertRaises(ValueError):
            imports.semantic_view(historical)
        for layers in ({}, {"pipeline": semantic}, {"semantic": {"predictions": []}}):
            with self.assertRaises(ValueError):
                imports.semantic_view(layers, imported=True)

    def test_missing_mixed_failed_and_regex_execution_are_rejected(self):
        for layers in ([], [{"layer": "DETECTION_LAYER_REGEX", "status": "ok"}],
                       [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "error"}],
                       [{"layer": "DETECTION_LAYER_SEMANTIC", "status": "ok"}, {"layer": "DETECTION_LAYER_NER", "status": "ok"}]):
            row = observation()
            row["raw"]["layers"] = layers
            with self.subTest(layers=layers), self.assertRaises(continual.LayerIsolationError):
                imports.semantic_view({"semantic": {"predictions": [row]}}, imported=True)

    def test_measure_and_context_issue_only_semantic_and_abort_isolation_violation(self):
        calls = []
        identity = {"model_id": "synthetic"}
        class Client:
            def analyze(self, row, model_id, layer, request_id):
                calls.append(layer)
                return {"identities": [identity], "detected_sensitive": False, "raw": observation()["raw"]}
            def snapshot(self, model_id):
                return {"identity": identity}
        row = {"id": "test", "group_id": "test", "expected_has_pii": False, "text": "Synthetic",
               "classification": observation()["target"], "allowed_actions": ["ALLOW"]}
        client = Client()
        self.assertEqual(set(continual.measure(client, [row], "synthetic", identity, "test")), {"semantic"})
        self.assertEqual(set(study.contextual_rows(client, [row], "synthetic", identity, "test")), {"semantic"})
        self.assertEqual(calls, ["semantic", "semantic"])
        with patch.object(client, "analyze", return_value={"identities": [identity], "raw": {"layers": []}}):
            with self.assertRaises(continual.LayerIsolationError):
                continual.measure(client, [row], "synthetic", identity, "test")

    def test_baseline_match_ignores_origin_but_rejects_changed_semantic_predictions(self):
        layers = {"semantic": {"predictions": [observation()]}}
        study.baseline_equivalence(self.root, "efficient", {"development": {**layers, "pipeline": {}}}, imported=True)
        study.baseline_equivalence(self.root, "efficient", {"development": layers})
        changed = copy.deepcopy(layers)
        changed["semantic"]["predictions"][0]["action"] = "WARN"
        with self.assertRaises(ValueError):
            study.baseline_equivalence(self.root, "efficient", {"development": changed})
        self.assertNotIn("pipeline", continual.read_json(self.root / "baseline-efficient.json")["development"])

    def test_casewise_semantic_gate_cannot_be_rescued_by_pipeline(self):
        outcomes = {"development": {"semantic": {"before": {"recall": .9, "specificity": .2}, "after": {"recall": .91, "specificity": .3}},
                                    "pipeline": {"after": {"recall": 1., "specificity": 1.}}},
                    "contextual": {"semantic": {"before": {"joint_accuracy": .5}, "after": {"joint_accuracy": .5}}},
                    "fixtures": {"semantic": {"passed": True}}}
        self.assertTrue(report.semantic_eligibility(outcomes))
        for poison in ("recall", "specificity", "contextual", "harm"):
            changed = copy.deepcopy(outcomes)
            if poison == "recall":
                changed["development"]["semantic"]["after"]["recall"] = .89
            elif poison == "specificity":
                changed["development"]["semantic"]["after"]["specificity"] = .2
            elif poison == "contextual":
                changed["contextual"]["semantic"]["after"]["joint_accuracy"] = .49
            else:
                changed["fixtures"]["semantic"]["passed"] = False
            with self.subTest(poison=poison):
                self.assertFalse(report.semantic_eligibility(changed))

    def test_comparison_and_seed_statistics_have_no_pipeline_aggregate(self):
        layers = {"semantic": {"predictions": [observation()]}}
        comparison = report.compare_layers(layers, layers, iterations=5)
        self.assertEqual(set(comparison), {"semantic"})
        self.assertEqual(set(report.outcome_statistics([{"development": comparison}])["development"]), {"semantic"})

    def test_old_protocol_execution_is_refused_before_source_or_resource_action(self):
        continual.write_json(self.root / "protocol.json", {"schema_version": 1})
        continual.write_json(self.root / "supervisor.json", {})
        with patch.object(study, "command") as command, self.assertRaisesRegex(ValueError, "Historical v1"):
            study.verify_freeze(self.root)
        command.assert_not_called()

    def test_import_audit_uses_original_project_and_images(self):
        old_cell = {"id": "efficient-a-42", "project": "original-project", "profile": "efficient"}
        old_protocol = {"images": {"client-runtime": "original-image"}}
        old_state = {"status": "complete", "archive_sha256": "original-archive"}
        new_protocol = {"images": {"client-runtime": "new-image"}, "imports": {"cells": {
            "efficient-a-42": {"cell": old_cell, "state": old_state, "directory": str(self.root)}}}}
        continual.write_json(self.root / "operations.json", {"marker": "old-operations"})
        with patch.object(report, "verify_import_manifest", return_value=old_protocol), \
             patch.object(report, "verify_archive") as archive, patch.object(report, "validate_operations") as operations, \
             patch.object(report, "load_artifact", side_effect=RuntimeError("stop after provenance check")):
            with self.assertRaisesRegex(RuntimeError, "provenance"):
                report.load_cell(self.root, new_protocol, {"id": "efficient-a-42", "project": "new-project"}, {"imported": True})
        archive.assert_called_once_with(self.root, "original-archive")
        operations.assert_called_once_with({"marker": "old-operations"}, old_cell, old_protocol)

    def test_import_commitment_rejects_changed_missing_or_unresolved_archive(self):
        key = "efficient-a-42"
        directory = self.root / "cells" / key
        raw = directory / "controller/privoke-efficient"
        raw.mkdir(parents=True)
        for cycle in (0, 20):
            continual.write_json(raw / f"checkpoint-{cycle:03d}.json", {"semantic": {"predictions": [observation(str(i)) for i in range(502)]}})
            for name, count in (("context", 64), ("fixture", 48)):
                continual.write_json(directory / f"{name}-{cycle:03d}.json", {"layers": {"semantic": {"predictions": [observation(str(i)) for i in range(count)]}}})
        commitment = study.archive_cell(directory)
        continual.write_json(self.root / "protocol.json", {"source_revision": imports.V1_SOURCE, "cells": [{"id": key}]})
        protocol_sha = continual.sha(self.root / "protocol.json")
        state = {"protocol_sha256": protocol_sha, "cells": {key: {"status": "complete", "archive_sha256": commitment}}}
        continual.write_json(self.root / "supervisor.json", state)
        continual.write_json(self.root / "semantic-only-pause-checkpoint.json", {"status": "deliberately_stopped_for_semantic_only_amendment", "complete_cells": 15, "pending": None, "verified_at": "synthetic"})
        with patch.object(imports, "V1_PROTOCOL_SHA", protocol_sha), patch.object(imports, "IMPORT_IDS", {key}):
            manifest = imports.build_import_manifest(self.root)
            self.assertEqual(manifest["semantic_observations"], 1228)
            imports.verify_import_manifest(manifest)
            state["cells"][key]["status"] = "training"
            continual.write_json(self.root / "supervisor.json", state)
            with self.assertRaises(ValueError):
                imports.build_import_manifest(self.root)
            state["cells"][key]["status"] = "complete"
            continual.write_json(self.root / "supervisor.json", state)
            endpoint = directory / "context-000.json"
            endpoint.write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                imports.build_import_manifest(self.root)
            endpoint.unlink()
            with self.assertRaises(FileNotFoundError):
                imports.build_import_manifest(self.root)


if __name__ == "__main__":
    unittest.main()
