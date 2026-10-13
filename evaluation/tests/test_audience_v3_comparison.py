"""AU3 test-opening, error-inclusive audience pairing and actual native proof gates."""
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_eval import audience_v3 as au
from privoke_eval import audience_v3_comparison as comparison


def cases():
    result, rows = [], []
    for i, visibility in enumerate(("P4", "P4", "P3", "P3")):
        target = {"sensitivity": "S3", "visibility": visibility, "categories": ["HEALTH"]}
        result.append({"id": str(i), "group_id": "f" + str(i // 2), "family_id": "f" + str(i // 2),
                       "status": "ok", "target": target, "allowed_actions": ["ALLOW", "WARN"],
                       "classification": target, "action": "ALLOW", "host_elapsed_ns": 1000})
        rows.append({"id": str(i), "classification": target, "family_id": "f" + str(i // 2),
                     "metadata": {"audience_expression_group_id": "e" + str(i % 2)}})
    return result, rows


def captures():
    from privoke.v1 import runtime_pb2
    from privoke_contracts.classification import Classification
    identity = {"model_id": "privoke-v3-efficient", "model_version": "a" * 64}
    entry = {"name": "after-efficient", "family": "v3", "manifest_sha256": "a" * 64, "identity": identity}
    value = Classification()
    rows = []
    for i in range(16):
        request = comparison.raw.request_for(entry, {"text": str(i)}, "val-" + str(i))
        response = runtime_pb2.AnalyzePromptResponse(request_id=request.request_id, action="ALLOW",
            classification=runtime_pb2.RuntimeClassification(packed=value.pack(), **value.to_dict()),
            metadata={"privoke.semantic." + k: v for k, v in identity.items()})
        response.layers.add(layer=4, status="ok")
        rows.append({"id": str(i), "text_sha256": au.digest(str(i).encode()),
                     "request_hex": request.SerializeToString(deterministic=True).hex(),
                     "response_hex": response.SerializeToString(deterministic=True).hex(),
                     "logits": {k: [0.] * len(v) for k, v in au.en.ph.LABELS.items()},
                     "values": {"packed": value.pack(), "named": value.to_dict(), "confidence": .5, "action": "ALLOW"},
                     "native_classification": value.to_dict(), "native_action": "ALLOW"})
    a = {"identity": {"study_id": au.STUDY_ID}, "native_identity": identity, "kind": "selected", "manifest_sha256": "a" * 64,
         "blob": "b" * 64, "rows": rows, "fresh_access": False,
         "environment": {"packages": {"torch": "2.12.0+cu130", "numpy": "1.26.4"}, "torch_threads": 4, "deterministic": True}}
    b = copy.deepcopy(a)
    b["environment"]["packages"]["torch"] = "2.11.0+cpu"
    return a, b


class AudienceComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        au.en.ph.configure_repository(ROOT)
        cls.scratch = ROOT / "evaluation/results/audience_v3_20261013/tests/tmp"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def test_invalid_native_wires_are_terminal_incorrect_and_never_replayed(self):
        from privoke.v1 import runtime_pb2
        a, _ = captures()
        entry = {"name": "after-efficient", "family": "v3", "manifest_sha256": a["manifest_sha256"], "identity": a["native_identity"]}
        row = {"id": "bad", "group_id": "g", "family_id": "f", "text": "Synthetic",
               "classification": a["rows"][0]["native_classification"], "allowed_actions": ["ALLOW"]}
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.calls += 1
                response = runtime_pb2.AnalyzePromptResponse.FromString(bytes.fromhex(a["rows"][0]["response_hex"]))
                response.request_id = request.request_id
                if variant == "missing": response.ClearField("layers")
                if variant == "extra": response.layers.add(layer=1, status="ok")
                if variant == "identity": response.metadata["privoke.semantic.model_version"] = "wrong"
                return response
        for variant in ("missing", "extra", "identity"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(dir=self.scratch) as directory:
                stub = Stub()
                result = comparison.invoke(stub, entry, row, directory, "bad-" + variant)
                self.assertEqual(result["status"], "invalid_response")
                self.assertIsNone(result["classification"])
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {"request.pb", "response.pb", "timing.json", "record.json"})
                self.assertEqual(comparison.audit_call(entry, row, directory, "bad-" + variant), result)
                self.assertEqual(comparison.invoke(stub, entry, row, directory, "bad-" + variant), result)
                self.assertEqual(stub.calls, 1)
                summary = comparison.summarize([result])
                self.assertEqual(summary["slices"]["all"]["joint"], {"correct": 0, "denominator": 1})
                self.assertEqual(summary["slices"]["all"]["errors"], 1)
                # A crash after durable outcome/timing but before terminal record
                # can be reconciled independently, without another RPC.
                (Path(directory) / "record.json").unlink()
                self.assertEqual(comparison.invoke(stub, entry, row, directory, "bad-" + variant), result)
                self.assertEqual(stub.calls, 1)
                (Path(directory) / "record.json").unlink()
                (Path(directory) / "timing.json").unlink()
                with self.assertRaisesRegex(ValueError, "reconcile without replay"):
                    comparison.invoke(stub, entry, row, directory, "bad-" + variant)
                self.assertEqual(stub.calls, 1)

    def test_action_distance_and_affected_case_counts_are_distinct(self):
        before, rows = cases()
        one = copy.deepcopy(before[:1])
        one[0]["allowed_actions"] = ["ALLOW"]
        one[0]["action"] = "BLOCK"
        two = copy.deepcopy(before[:2])
        for row in two:
            row["allowed_actions"], row["action"] = ["ALLOW"], "WARN"
        a, b = comparison.summarize(one), comparison.summarize(two)
        self.assertEqual(a["action_distance"]["over"], b["action_distance"]["over"])
        self.assertEqual((a["action_distance"]["over_cases"], b["action_distance"]["over_cases"]), (1, 2))
        self.assertNotIn("independent_groups", a)
        self.assertEqual(a["observed_families"], 1)
        before[0]["allowed_actions"] = ["ALLOW"]
        after = copy.deepcopy(before)
        after[0]["action"] = "BLOCK"
        after[1].update(status="invalid_response", classification=None, action=None)
        paired = comparison.paired(before, after, rows)["action_harms"]
        self.assertEqual(paired["over"], 1)  # worsened cases
        self.assertEqual(paired["over_distance_delta"], 2)
        self.assertEqual(paired["over_cases_delta"], 1)
        self.assertEqual((paired["comparable"], paired["error_pairs"]), (3, 1))

    def test_fresh_loader_not_called_when_all_model_seal_or_gate_missing(self):
        with patch.object(comparison, "validate_registry", side_effect=ValueError("unsealed")), patch.object(au.data, "load_partition") as loader:
            with self.assertRaises(ValueError):
                comparison.evaluation_rows("unused")
            loader.assert_not_called()
        with patch.object(comparison, "validate_registry", return_value=({}, {})), \
                patch.object(au, "approval", side_effect=ValueError("not accepted")), patch.object(au.data, "load_partition") as loader:
            with self.assertRaises(ValueError):
                comparison.evaluation_rows("unused")
            loader.assert_not_called()

    def test_exact_six_current_before_and_new_after_entries(self):
        self.assertEqual(comparison.expected_names(), ["before-efficient", "before-balanced", "before-quality",
                                                       "after-efficient", "after-balanced", "after-quality"])

    def test_p4_p3_errors_keep_audience_and_action_denominators(self):
        before, rows = cases()
        after = copy.deepcopy(before)
        after[0].update(status="transport_error", classification=None, action=None)
        after[2]["classification"] = dict(after[2]["classification"], visibility="P4")
        result = comparison.summarize(after)
        self.assertEqual(result["audience_recall"]["P4"]["recall"], .5)
        self.assertEqual(result["audience_recall"]["P3"]["recall"], .5)
        self.assertEqual(result["confusion"]["visibility"]["P4"]["ERROR"], 1)
        self.assertIsNone(result["audience_recall"]["P0"]["recall"])
        pair = comparison.paired(before, after, rows)
        self.assertEqual(pair["by_true_visibility"]["P4"]["all"]["visibility"],
                         {"improved": 0, "regressed": 1, "net_correct": -1, "denominator": 2})
        self.assertEqual(pair["action_harms"]["error_pairs"], 1)

    def test_both_cluster_sensitivities_reproducible_and_crossed(self):
        before, rows = cases()
        after = copy.deepcopy(before)
        after[0].update(status="error", classification=None, action=None)
        family = comparison.cluster_interval(before, after, rows, "family_id")
        expression = comparison.cluster_interval(before, after, rows, "audience_expression_group_id")
        self.assertEqual(family, comparison.cluster_interval(before, after, rows, "family_id"))
        self.assertEqual((family["clusters"], expression["clusters"]), (2, 2))
        self.assertEqual(family["intervals"]["visibility"]["after_minus_before"], -.25)
        self.assertEqual(expression["intervals"]["visibility"]["after_minus_before"], -.25)
        unavailable = comparison.cluster_interval(before[:2], after[:2], rows[:2], "family_id")
        self.assertIsNone(unavailable["intervals"])
        with self.assertRaises(ValueError):
            comparison.cluster_interval(before, after, list(reversed(rows)), "family_id")

    def test_native_raw_cross_version_proof_and_tamper_failures(self):
        a, b = captures()
        self.assertEqual(au.compare_captures(a, b)["rows"], 16)
        for mutation in ("threads", "version", "logits", "sample", "wire", "action", "identity"):
            bad = copy.deepcopy(b)
            if mutation == "threads": bad["environment"]["torch_threads"] = 16
            if mutation == "version": bad["environment"]["packages"]["torch"] = "2.12.0+cu130"
            if mutation == "logits": bad["rows"][0]["logits"]["visibility"][0] = .1
            if mutation == "sample": bad["rows"][0]["id"] = "other"
            if mutation == "wire": bad["rows"][0]["response_hex"] = ""
            if mutation == "action": bad["rows"][0]["native_action"] = "BLOCK"
            if mutation == "identity": bad["manifest_sha256"] = "c" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                au.compare_captures(a, bad)

    def test_rpc_requests_semantic_only_no_hints_unique_model_and_run(self):
        entry = {"name": "before-quality", "family": "v3", "manifest_sha256": "a" * 64,
                 "identity": {"model_id": "privoke-v3-quality"}}
        row = {"id": "case", "text": "Synthetic."}
        request = comparison.raw.request_for(entry, row, comparison.request_id("r1", entry["name"], row, 0))
        self.assertEqual(list(request.layers), [4])
        self.assertFalse(request.visibility_hint)
        self.assertFalse(request.HasField("semantic_presence_gate"))
        self.assertEqual(request.metadata["v3_checkpoint"], "a" * 64)
        self.assertNotEqual(comparison.request_id("r1", entry["name"], row, 0), comparison.request_id("r2", entry["name"], row, 0))


if __name__ == "__main__":
    unittest.main()
