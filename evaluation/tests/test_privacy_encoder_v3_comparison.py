"""Synthetic EN3 comparison gates and imported BEFORE pairing contracts."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_eval import privacy_encoder_v3 as en
from privoke_eval import privacy_encoder_v3_comparison as compare


class ComparisonContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        en.ph.configure_repository(Path(__file__).resolve().parents[2])

    def test_payload_not_opened_without_complete_registry_gate(self):
        with patch.object(compare, "validate_registry", side_effect=ValueError("unsealed")), \
                patch.object(en.ph, "load_partition") as loader:
            with self.assertRaises(ValueError):
                compare.development_rows("unused")
            loader.assert_not_called()

    def test_controller_failure_access_status_is_action_aware(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1]/"run-privacy-encoder-v3.py"
        spec = importlib.util.spec_from_file_location("en3_failure_controller", path)
        controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controller)
        for action, target, extra, expected in (
                ("evaluate-development", compare, ["--tier", "balanced", "--ready-file", "unused.json"], None),
                ("audit-development", compare, [], None),
                ("prepare", en, [], False)):
            function = {"evaluate-development": "evaluate", "audit-development": "audit", "prepare": "prepare"}[action]
            with self.subTest(action=action), patch.object(target, function, side_effect=ValueError("mocked phase failure")), \
                    patch.object(en, "retain") as retained:
                with self.assertRaisesRegex(ValueError, "mocked phase failure"):
                    controller.main([action, "--results", "unused-results", *extra])
                record = retained.call_args.args[1]
                self.assertIs(record["development_access"], expected)
                self.assertEqual(record["development_access_status"],
                                 "unknown_may_have_accessed" if expected is None else "not_accessed")

    def test_case_pairing_errors_are_incorrect_and_harm_denominator_is_explicit(self):
        target = {"sensitivity": "S3", "visibility": "P0", "categories": ["HEALTH"]}
        before = [{"id": "case", "status": "ok", "target": target, "allowed_actions": ["WARN", "BLOCK"],
                   "classification": target, "action": "WARN"}]
        after = [dict(before[0], status="transport_error", classification=None, action=None)]
        result = compare.raw.paired(before, after)
        self.assertEqual(result["all"]["joint"], {"improved": 0, "regressed": 1, "net_correct": -1, "denominator": 1})
        self.assertEqual(result["action_harms"]["comparable"], 0)
        self.assertEqual(result["action_harms"]["error_pairs"], 1)
        for field, value in (("id", "different"), ("target", dict(target, sensitivity="S0")), ("allowed_actions", ["ALLOW"])):
            with self.assertRaises(ValueError):
                compare.raw.paired(before, [dict(after[0], **{field: value})])

    def test_native_request_explicit_semantic_empty_hints_and_unique_run_ids(self):
        row = {"id": "case", "text": "Synthetic test."}
        entry = {"name": "en3-quality", "family": "v3", "manifest_sha256": "a"*64,
                 "identity": {"model_id": "privoke-v3-quality"}}
        request = compare.raw.request_for(entry, row, compare.request_id(entry["name"], row, 0))
        self.assertEqual(list(request.layers), [4])
        self.assertFalse(request.visibility_hint)
        self.assertEqual(request.metadata["v3_checkpoint"], "a"*64)
        self.assertNotEqual(compare.request_id(entry["name"], row, 0), compare.request_id("v3-quality", row, 0, before=True))

    def test_native_response_rejects_wrong_layer_and_identity(self):
        from privoke.v1 import runtime_pb2
        row = {"id": "case", "text": "Synthetic test."}
        entry = {"name": "en3-quality", "family": "v3", "manifest_sha256": "a"*64,
                 "identity": {"model_id": "privoke-v3-quality"}}
        request = compare.raw.request_for(entry, row, "test")
        response = runtime_pb2.AnalyzePromptResponse(request_id="test")
        response.layers.add(layer=1, status="ok")
        with self.assertRaises(ValueError):
            compare.raw.response_record(response, entry, request)
        response.layers[0].layer = 4
        with self.assertRaises(ValueError):
            compare.raw.response_record(response, entry, request)

    def test_export_history_tampering_rejected(self):
        manifest = {"blob": "b"*64, "evidence": "e"*64}
        item = {"epoch": 3, **manifest}
        evidence = {"schema": 1, "study_id": en.STUDY_ID, "scope": "full_encoder", "tier": "balanced", "kind": "selected",
                    "epoch": 3, "layers": [4], "policy": en.POLICY, "protocol_sha256": "p", "fit_summary_sha256": "s",
                    "checkpoint": "c", "source_closure": "x", "candidate_blob": manifest["blob"], "changes": {},
                    "publication": "local_research_only_no_legacy_guard_pass"}
        kwargs = dict(tier="balanced", kind="selected", epoch=3, checkpoint="c", protocol_sha="p", summary_sha="s", source_closure="x")
        en.assert_export_bindings(item, manifest, evidence, **kwargs)
        for key, value in (("epoch", 4), ("kind", "terminal"), ("study_id", "PH3"), ("scope", "heads"),
                           ("candidate_blob", "z"), ("fit_summary_sha256", "other"), ("source_closure", "other"),
                           ("policy", {})):
            with self.assertRaises(ValueError):
                en.assert_export_bindings(item, manifest, dict(evidence, **{key: value}), **kwargs)
        with self.assertRaises(ValueError):
            en.assert_export_bindings(dict(item, epoch=4), manifest, evidence, **kwargs)


if __name__ == "__main__":
    unittest.main()
