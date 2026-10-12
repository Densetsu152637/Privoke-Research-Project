"""Host-only contract tests; no physical inference, training or study mutations."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_eval import v123_comparison as c


class ComparisonTests(unittest.TestCase):
    def entry(self, family="tiny"):
        identity = {"model_id": "model", "model_version": "version", "artifact_checksum": "checksum", "parameter_fingerprint": "fingerprint"}
        if family == "v3":
            identity.update(parameter_count="10", backbone_sha256="backbone", tokenizer_sha256="tokens", architecture="architecture")
        return {"identity": identity, "server_family": family, "native_window": {"cap": 4, "reject_overlength": True}}

    def response(self, entry, *, error="", layers=(4,), status="ok"):
        value = c.runtime_pb2.AnalyzePromptResponse(request_id="case", error=error, action="ALLOW",
            metadata={"privoke.semantic." + k: v for k, v in entry["identity"].items()})
        for layer in layers:
            value.layers.add(layer=layer, status=status)
        packed = c.Classification()
        value.classification.CopyFrom(c.runtime_pb2.RuntimeClassification(**packed.to_dict(), packed=packed.pack()))
        return value

    def test_same_original_wire_and_explicit_semantic_request(self):
        row = {"text": " A\u00a0B ", "source": "source", "target_app": "app", "visibility_hint": "PR", "purpose": "development"}
        for family in ("tiny", "v3"):
            request = c.request_for(self.entry(family), row, "case")
            self.assertEqual(request.text, row["text"])
            self.assertEqual((request.source, request.target_app, request.visibility_hint), ("source", "app", "PR"))
            self.assertEqual(list(request.layers), [4])
            self.assertFalse(request.HasField("semantic_presence_gate"))
            self.assertEqual(request.metadata["purpose"], "development")
            self.assertEqual("v3_checkpoint" in request.metadata, family == "v3")

    def test_null_absent_and_nonempty_hint_preserved(self):
        for row, expected in (({"text": "x"}, ""), ({"text": "x", "visibility_hint": None}, ""), ({"text": "x", "visibility_hint": "PR"}, "PR")):
            self.assertEqual(c.request_for(self.entry(), row, "case").visibility_hint, expected)

    def test_family_native_success_identity(self):
        for family in ("tiny", "v3"):
            entry = self.entry(family)
            request = c.request_for(entry, {"text": "x"}, "case")
            response = self.response(entry)
            self.assertEqual(c.response_record(response, entry, request)["status"], "ok")
            del response.metadata["privoke.semantic.model_version"]
            with self.assertRaisesRegex(ValueError, "identity"):
                c.response_record(response, entry, request)

    def test_success_requires_actual_sole_semantic_and_consistent_packed(self):
        entry = self.entry()
        request = c.request_for(entry, {"text": "x"}, "case")
        for layers in ((), (1, 4), (1,)):
            with self.assertRaises(ValueError):
                c.response_record(self.response(entry, layers=layers), entry, request)
        response = self.response(entry)
        response.classification.sensitivity = "S3"
        with self.assertRaisesRegex(ValueError, "Packed/named"):
            c.response_record(response, entry, request)

    def test_preexecution_error_without_fabricated_identity_or_execution(self):
        entry = self.entry()
        request = c.request_for(entry, {"text": "x"}, "case")
        response = c.runtime_pb2.AnalyzePromptResponse(request_id="case", error="too long", action="BLOCK")
        result = c.response_record(response, entry, request)
        self.assertEqual((result["failure_stage"], result["actual_layers"], result["metadata"]), ("pre_execution", [], {}))
        self.assertIsNone(result["action"])
        response.metadata["privoke.semantic.model_id"] = "impostor"
        with self.assertRaisesRegex(ValueError, "identity"):
            c.response_record(response, entry, request)

    def test_layer_error_even_status_ok_is_failed(self):
        entry = self.entry()
        request = c.request_for(entry, {"text": "x"}, "case")
        response = self.response(entry)
        response.layers[0].error = "failed internally"
        record = c.response_record(response, entry, c.request_for(entry, {"text": "x"}, "case"))
        self.assertEqual((record["status"], record["error"]), ("error", "failed internally"))
        self.assertIsNone(record["classification"])
        response.ClearField("metadata")
        response.layers.add(layer=1, status="error")
        with self.assertRaisesRegex(ValueError, "isolation"):
            c.response_record(response, entry, request)

    def test_all_four_truth_schemata_and_error_denominators(self):
        context = {"id": "a", "group_id": "g", "classification": {"sensitivity": "S1", "categories": ["PII"], "visibility": "PR"}, "allowed_actions": ["WARN", "BLOCK"]}
        binary = {"id": "b", "group_id": "g", "expected_has_pii": True}
        hazard = {"case_id": "h", "family_id": "g", "expected_sensitivity": "S1", "ambiguous": False, "allowed_actions": ["WARN", "BLOCK"]}
        for kind, row in (("context320", context), ("context64", context), ("binary502", binary), ("hazard48", hazard)):
            record = dict(c.scoring.truth_record(row, kind), status="error", action="BLOCK", classification=None, failure_stage="runtime")
            summary = c.endpoint_summary([record], kind)
            self.assertEqual((summary["requested"], summary["eligible"], summary["all_requested_errors"]), (1, 1, 1))
            self.assertTrue(all(not value for value in c.scoring.case_metrics(record, kind).values()))
        hazard["ambiguous"] = True
        record = dict(c.scoring.truth_record(hazard, "hazard48"), status="transport_error", failure_stage="transport")
        summary = c.endpoint_summary([record], "hazard48")
        self.assertEqual((summary["requested"], summary["eligible"], summary["errors"], summary["all_requested_errors"]), (1, 0, 0, 1))

    def test_allowed_action_set_and_paired_harms(self):
        target = {"id": "a", "group_id": "g", "eligible": True, "target": {"sensitivity": "S1"}, "allowed_actions": ["WARN", "BLOCK"], "status": "ok", "classification": {"sensitivity": "S1"}, "action": "WARN"}
        block = dict(target, action="BLOCK")
        self.assertTrue(c.scoring.case_metrics(block, "hazard48")["action"])
        pair = c.scoring.paired_difference([target], [dict(target, action="ALLOW")], "hazard48")
        self.assertEqual(pair["action_harms"]["under"], 1)

    def test_native_tiny_pretruncation_length(self):
        entry = self.entry()
        self.assertEqual(c.native_length(entry, "One, two 123!"), 6)
        self.assertGreater(c.native_length(entry, "One, two 123!"), entry["native_window"]["cap"])

    def test_case_reservation_transport_error_and_unknown_no_blind_replay(self):
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.calls += 1
                raise TimeoutError("synthetic transport error")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            stub = Stub()
            result = c.invoke(stub, self.entry(), {"text": "x"}, output / "known", "case")
            self.assertEqual(result["failure_stage"], "transport")
            c.invoke(stub, self.entry(), {"text": "x"}, output / "known", "case")
            self.assertEqual(stub.calls, 1)
            c.retain(output / "unknown/request.pb", b"reserved")
            with self.assertRaisesRegex(ValueError, "Unknown reserved"):
                c.invoke(stub, self.entry(), {"text": "x"}, output / "unknown", "case")
            self.assertEqual(stub.calls, 1)

    def test_successful_latency_excludes_errors_but_throughput_pays_error_cost(self):
        values = [{"status": "ok", "host_elapsed_ns": 1000000}, {"status": "ok", "host_elapsed_ns": 3000000}, {"status": "error", "host_elapsed_ns": 1000000000}]
        summary = c.performance_summary(values)
        self.assertEqual((summary["p50_ms_successful"], summary["failed"]), (2, 1))
        self.assertAlmostEqual(summary["rpc_active_successful_requests_per_second"], 2/1.004)

    def test_retained_call_audit_rejects_record_request_timing_or_response_mutation(self):
        entry = self.entry()
        response = self.response(entry)
        class Stub:
            def AnalyzePrompt(self, request, timeout):
                return response
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            row = {"text": "original wire"}
            c.invoke(Stub(), entry, row, base, "case")
            c.audit_call(entry, row, base, "case")
            changed_response = self.response(entry)
            changed_response.metadata["privoke.semantic.model_id"] = "impostor"
            for filename, changed in (("record.json", c.canonical({})), ("timing.json", c.canonical({"started_perf_counter_ns": 5, "ended_perf_counter_ns": 4})), ("response.pb", changed_response.SerializeToString())):
                original = (base / filename).read_bytes()
                (base / filename).write_bytes(changed)
                with self.assertRaises(ValueError):
                    c.audit_call(entry, row, base, "case")
                (base / filename).write_bytes(original)
            with self.assertRaisesRegex(ValueError, "request"):
                c.audit_call(entry, {"text": "changed"}, base, "case")
            (base / "extra.txt").write_text("extra")
            with self.assertRaisesRegex(ValueError, "extraneous"):
                c.audit_call(entry, row, base, "case")

    def test_all_failed_cost_replicates_remain_reportable(self):
        failed = c.performance_summary([{"status": "error", "host_elapsed_ns": 100}])
        result = c.performance_ranges([failed, failed, failed])
        self.assertEqual(result["successful_replicates"], 0)
        self.assertEqual(result["p50_ms_successful_range"], [None, None])
        self.assertEqual(result["status"], "no_successful_timed_calls")

    def test_external_process_rss_units_and_missing_metric(self):
        self.assertEqual(c.proc_memory("VmRSS:\t100 kB\nVmHWM:\t120 kB\n"), {"VmRSS_bytes": 102400, "VmHWM_bytes": 122880})
        with self.assertRaises(ValueError):
            c.proc_memory("VmRSS: 100 kB")

    def test_immutable_artifact_and_distinct_catalog_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "asset.json"
            path.write_bytes(b"different")
            with self.assertRaisesRegex(ValueError, "Artifact bytes"):
                c.tiny_entry("v2-original", path, "not-the-hash")
            c.retain(path, b"different")
            with self.assertRaises(ValueError):
                c.retain(path, b"changed")
        self.assertEqual(len(c.TINY_HASHES) + len(c.V3_PINS), 14)
        self.assertNotEqual(c.V3_PINS["quality"], c.V3_PINS["quality-original"])
        self.assertNotIn("v2-efficient", c.TINY_HASHES)

    def test_fixture_pin_refuses_changed_map_without_opening_payload(self):
        item = dict(c.scoring.ENDPOINTS["binary502"], sha256="tampered")
        with self.assertRaisesRegex(ValueError, "fixed v3 DEVELOPMENT"):
            c.scoring.endpoint_rows("binary502", item)


if __name__ == "__main__":
    unittest.main()
