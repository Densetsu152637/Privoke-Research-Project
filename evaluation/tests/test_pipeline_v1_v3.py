"""PIPE3 behavioral contracts; synthetic wires, no benchmark scoring or fitting."""
import base64
import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_eval import pipeline_v1_v3 as core
core.configure(ROOT)
from privoke.v1 import runtime_pb2 as pb
from privoke_contracts.classification import Classification


def entry():
    return {"name": "v3-efficient", "family": "v3", "identity": {
        "model_id": "privoke-v3-efficient", "model_version": "a" * 64,
        "artifact_checksum": "a" * 64, "parameter_fingerprint": "b" * 64}}


def row():
    return {"id": "case", "text": "Synthetic original input.", "group_id": "g", "family_id": "f",
            "classification": {"sensitivity": "S0", "visibility": "PU", "categories": []},
            "allowed_actions": ["ALLOW"], "source": "source", "target_app": "app",
            "visibility_hint": "P4", "metadata": {"truth": "must not be forwarded"}}


def value(packed=28):
    named = Classification(packed).to_dict()
    return pb.RuntimeClassification(packed=packed, **named)


def response(request, *, skipped=False):
    result = pb.AnalyzePromptResponse(request_id=request.request_id, action="ALLOW", allowed=True,
        classification=value(), elapsed_ms=.01)
    if skipped:
        result.action, result.allowed = "BLOCK", False
        result.classification.CopyFrom(value(39))
        regex = result.layers.add(layer=2, status="ok")
        regex.results.add(classification=value(39), action="BLOCK", section_of_text=request.text,
                          has_span=True, span_start=0, span_end=len(request.text))
        for layer in (3, 4):
            result.layers.add(layer=layer, status="skipped", error="Skipped after regex returned BLOCK.")
    else:
        for layer in core.LAYERS:
            result.layers.add(layer=layer, status="ok")
        result.metadata.update({"privoke.semantic." + k: v for k, v in entry()["identity"].items()})
    return result


class PipelineContracts(unittest.TestCase):
    def setUp(self):
        self.scratch = ROOT / "evaluation/results/pipeline_v1_v3_20261014/tests/tmp"
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.request = core.request_for(entry(), row(), "request")

    def outcome(self, result):
        return core.response_outcome(result.SerializeToString(deterministic=True), entry(), self.request)

    def test_original_text_explicit_three_layers_first_and_truth_isolation(self):
        self.assertEqual(self.request.text, row()["text"])
        self.assertEqual(list(self.request.layers), [2, 3, 4])
        self.assertEqual(self.request.regex_execution_order, 1)
        self.assertEqual((self.request.source, self.request.target_app), ("source", "app"))
        self.assertEqual(self.request.visibility_hint, "")
        self.assertFalse(self.request.HasField("semantic_presence_gate"))
        self.assertNotIn("truth", self.request.metadata)

    def test_actual_all_layers_and_legitimate_early_block_are_distinct(self):
        ordinary, skipped = self.outcome(response(self.request)), self.outcome(response(self.request, skipped=True))
        self.assertEqual(ordinary["status"], "ok")
        self.assertEqual(skipped["status"], "ok")
        self.assertEqual([t["status"] for t in skipped["traces"]], ["ok", "skipped", "skipped"])
        self.assertEqual(skipped["metadata"], {})

    def test_missing_duplicate_order_and_unknown_status_are_invalid(self):
        for variant in ("missing", "duplicate", "order", "status"):
            result = response(self.request)
            if variant == "missing":
                del result.layers[-1]
            elif variant == "duplicate":
                result.layers.add(layer=4, status="ok")
            elif variant == "order":
                result.layers[0].layer, result.layers[1].layer = 3, 2
            else:
                result.layers[1].status = "pretend"
            self.assertEqual(self.outcome(result)["status"], "invalid_response", variant)

    def test_skips_require_actual_regex_block_and_no_semantic_impersonation(self):
        for variant in ("no_block", "one_skip", "bad_reason", "identity"):
            result = response(self.request, skipped=True)
            if variant == "no_block":
                result.layers[0].results[0].action = "WARN"
            elif variant == "one_skip":
                result.layers[1].status = "ok"
            elif variant == "bad_reason":
                result.layers[2].error = "unexpected"
            else:
                result.metadata["privoke.semantic.model_id"] = "not executed"
            self.assertEqual(self.outcome(result)["status"], "invalid_response", variant)

    def test_executed_semantic_requires_every_native_identity_field(self):
        for key in entry()["identity"]:
            result = response(self.request)
            result.metadata["privoke.semantic." + key] = "wrong"
            self.assertEqual(self.outcome(result)["status"], "invalid_response", key)

    def test_fail_closed_runtime_error_does_not_earn_correctness(self):
        result = response(self.request)
        result.error, result.action, result.allowed = "NER failed", "BLOCK", False
        result.layers[1].status, result.layers[1].error = "error", "missing backend"
        outcome = self.outcome(result)
        self.assertEqual(outcome["status"], "runtime_error")
        record = dict(outcome, id="case", group_id="g", family_id="f", target=row()["classification"],
                      allowed_actions=["BLOCK"], host_elapsed_ns=100)
        summary = core.summarize([record])
        self.assertEqual(summary["slices"]["all"]["joint"], {"correct": 0, "denominator": 1})
        self.assertEqual(summary["action_distance"]["errors"], 1)
        self.assertEqual(summary["layer_status_counts"]["3:error"], 1)

    def test_named_packed_action_and_span_mask_contracts(self):
        result = response(self.request)
        result.classification.sensitivity = "S3"
        self.assertEqual(self.outcome(result)["status"], "invalid_response")
        result = response(self.request)
        result.allowed = False
        self.assertEqual(self.outcome(result)["status"], "invalid_response")
        result = response(self.request)
        result.action = "WARN"
        result.evidence.CopyFrom(pb.RuntimeDetectionResult(classification=value(30), action="WARN", has_span=True,
            section_of_text=self.request.text[:9], span_start=0, span_end=9))
        result.masked_text = "[PRIVOKE_MASKED]" + self.request.text[9:]
        self.assertEqual(self.outcome(result)["status"], "ok")
        result.evidence.span_end = 500
        self.assertEqual(self.outcome(result)["status"], "invalid_response")

    def test_terminal_wires_reconstruct_and_resume_without_another_rpc(self):
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.calls += 1
                return response(request)
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path = Path(directory) / "raw.jsonl"
            journal, stub = core.Journal(path), Stub()
            first = core.invoke(stub, journal, entry(), row(), "request", repeat=0, index=0)
            reopened = core.Journal(path)
            second = core.invoke(stub, reopened, entry(), row(), "request", repeat=0, index=0)
            self.assertEqual(first, second)
            self.assertEqual(stub.calls, 1)
            self.assertEqual(len(reopened.events), 2)
            changed = row()
            changed["text"] += " changed"
            with self.assertRaisesRegex(ValueError, "stimulus"):
                core.invoke(stub, reopened, entry(), changed, "request", repeat=0, index=0)
            self.assertEqual(stub.calls, 1)

    def test_reserved_unknown_outcome_partial_and_tampered_journals_stop(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path = Path(directory) / "raw.jsonl"
            journal = core.Journal(path)
            wire = self.request.SerializeToString(deterministic=True)
            journal.append("reserve", "request", request_pb=base64.b64encode(wire).decode(), request_sha256=core.digest(wire))
            with self.assertRaisesRegex(ValueError, "Unknown reserved"):
                core.Journal(path)
            data = path.read_bytes()
            path.write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError, "Partial journal"):
                core.Journal(path)
            path.write_bytes(data.replace(b'"sequence":0', b'"sequence":9'))
            with self.assertRaisesRegex(ValueError, "chain/sequence/hash"):
                core.Journal(path)

    def test_transport_error_is_terminal_and_not_retried(self):
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.calls += 1
                raise RuntimeError("deliberate unavailable")
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            path, stub = Path(directory) / "raw.jsonl", Stub()
            result = core.invoke(stub, core.Journal(path), entry(), row(), "request", repeat=0, index=0)
            self.assertEqual(result["status"], "transport_error")
            again = core.invoke(stub, core.Journal(path), entry(), row(), "request", repeat=0, index=0)
            self.assertEqual(result, again)
            self.assertEqual(stub.calls, 1)

    def test_invalid_wire_is_terminal_incorrect_not_retried(self):
        class Stub:
            calls = 0
            def AnalyzePrompt(self, request, timeout):
                self.calls += 1
                result = response(request)
                result.ClearField("layers")
                return result
        with tempfile.TemporaryDirectory(dir=self.scratch) as directory:
            journal, stub = core.Journal(Path(directory) / "raw.jsonl"), Stub()
            result = core.invoke(stub, journal, entry(), row(), "request", repeat=0, index=0)
            self.assertEqual(result["status"], "invalid_response")
            self.assertEqual(core.summarize([result])["slices"]["all"]["errors"], 1)
            self.assertEqual(core.invoke(stub, journal, entry(), row(), "request", repeat=0, index=0), result)
            self.assertEqual(stub.calls, 1)

    def test_repeats_expose_classification_and_mask_disagreement_without_pooling(self):
        record = {"id": "case", "status": "ok", "classification": row()["classification"], "action": "ALLOW",
                  "masked_text": "", "traces": [], "evidence": None}
        passes = [[copy.deepcopy(record)] for _ in range(3)]
        self.assertTrue(core.repeat_agreement(passes)["all_fields_identical"])
        passes[2][0]["action"], passes[1][0]["masked_text"] = "WARN", "changed"
        result = core.repeat_agreement(passes)
        self.assertEqual(result["accuracy_denominator"], 1)
        self.assertEqual(result["disagreements"]["action"], ["case"])
        self.assertEqual(result["disagreements"]["masked_text"], ["case"])

    def test_v3_adapter_calls_actual_native_findings_without_postprocessing(self):
        from privoke_eval.pipeline_v1_v3_serving import V3SemanticAdapter
        calls, output = [], [object()]
        class Model:
            def findings(self, text, identity):
                calls.append((text, identity))
                return output
        adapter = V3SemanticAdapter(Model(), entry()["identity"])
        self.assertIs(adapter.classify("Original"), output)
        self.assertEqual(calls, [("Original", entry()["identity"])])
        self.assertEqual(adapter.snapshot.fingerprint, entry()["identity"]["parameter_fingerprint"])

    def test_actual_runtime_service_rejects_training_and_invalid_product_selection(self):
        from privoke_eval.pipeline_v1_v3_serving import service, V3SemanticAdapter
        import os
        # Native imports occur after explicitly pinned configuration.
        for key, val in core.PRODUCT_ENV.items():
            os.environ[key] = val
        from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE
        GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds = 604800
        from src.config import GLOBAL_CONFIG
        GLOBAL_CONFIG.wait_for_regex = True
        adapter = V3SemanticAdapter(None, entry()["identity"])
        native = service(entry(), adapter)
        class Rejected(Exception):
            pass
        class Context:
            def abort(self, code, message):
                raise Rejected(message)
        with self.assertRaisesRegex(Rejected, "inference-only"):
            native.ComputeUnderlyingModelGradients(None, Context())
        bad = copy.deepcopy(self.request)
        bad.ClearField("layers")
        with self.assertRaisesRegex(Rejected, "explicit product"):
            native.AnalyzePrompt(bad, Context())
        GLOBAL_STREAMED_MODEL_CACHE.clear()
        with self.assertRaisesRegex(Rejected, "remote fallback prohibited"):
            native.AnalyzePrompt(self.request, Context())

    def test_real_regex_ner_native_cascade_and_remapping_with_synthetic_semantic(self):
        import os
        from privoke_eval.pipeline_v1_v3_serving import service, V3SemanticAdapter
        for key, val in core.PRODUCT_ENV.items():
            os.environ[key] = val
        from src.LLM.privoke.streamed_model import GLOBAL_STREAMED_MODEL_CACHE
        from src.classification import ClassificationResult, initialise_unpacked, Sensitivity, Visibility, Category
        from src.config import GLOBAL_CONFIG
        GLOBAL_STREAMED_MODEL_CACHE.refresh_interval_seconds = 604800
        GLOBAL_CONFIG.wait_for_regex = True
        class Model:
            def findings(self, text, identity):
                return [ClassificationResult(classification=initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
                    section_of_text=text, span=(0, len(text)), confidence=.9, reasoning="Synthetic semantic fixture", metadata=identity)]
        native = service(entry(), V3SemanticAdapter(Model(), entry()["identity"]))
        for index, (text, statuses) in enumerate((
            ("My credit card number is 4111 1111 1111 1111.", ["ok", "skipped", "skipped"]),
            ("  The blue teapot rests beside the window.  ", ["ok", "ok", "ok"]))):
            request = core.request_for(entry(), dict(row(), text=text), "native-" + str(index))
            result = native.AnalyzePrompt(request, None)
            record = core.response_outcome(result.SerializeToString(deterministic=True), entry(), request)
            self.assertEqual(record["status"], "ok", record.get("error"))
            self.assertEqual([t["status"] for t in record["traces"]], statuses)
            if index == 1:
                self.assertEqual(record["action"], "WARN")
                self.assertEqual(record["masked_text"], "  [PRIVOKE_MASKED]  ")
        GLOBAL_STREAMED_MODEL_CACHE.clear()

    def test_serve_serializes_measured_readiness_and_stops_owned_server_on_write_failure(self):
        from privoke_eval import pipeline_v1_v3_serving as serving
        model_entry = dict(entry(), family="v1")
        protocol = {"entries": [model_entry], "environment": {"fixture": "cpu"}, "source_closure": "s" * 64}
        regex = SimpleNamespace(rules=[SimpleNamespace(name="fixture", pattern=SimpleNamespace(pattern="fixture", flags=2),
            signal="fixture", classification=SimpleNamespace(pack=lambda: 28))])
        protocol["effective_regex_rules"] = core.rules_inventory(regex)
        protocol["effective_regex_rules_sha256"] = core.digest(core.canonical(protocol["effective_regex_rules"]))
        ner = SimpleNamespace(backend_name="spacy", model_name="en_core_web_sm",
            nlp=SimpleNamespace(pipe_names=["ner"], meta={"name": "synthetic_backend_metadata"}))
        class Server:
            def __init__(self):
                self.started = self.stopped = self.waited = False
            def add_generic_rpc_handlers(self, handlers):
                self.handlers = handlers
            def add_insecure_port(self, target):
                return 53771
            def start(self):
                self.started = True
            def wait_for_termination(self):
                self.waited = True
            def stop(self, grace):
                self.stopped = True
                return SimpleNamespace(wait=lambda: None)
        for reject_ready in (False, True):
            with self.subTest(reject_ready=reject_ready), tempfile.TemporaryDirectory(dir=self.scratch) as directory:
                server, ready = Server(), Path(directory) / "ready.json"
                retained = core.retain
                def write(path, value):
                    if Path(path) == ready and reject_ready:
                        raise OSError("deliberate readiness write failure")
                    return retained(path, value)
                with patch.object(core, "validate", return_value=protocol), patch.object(core, "configure_numeric"), \
                     patch.object(core, "environment", return_value=protocol["environment"]), \
                     patch.object(core, "file_hash", return_value="p" * 64), patch.object(core, "retain", side_effect=write), \
                     patch("spacy.require_cpu"), patch("src.NER.ner_detector.EntityNERDetector", return_value=ner), \
                     patch("src.regex.rule_detector.RuleDetector", return_value=regex), \
                     patch.object(serving, "load_semantic", return_value=object()), \
                     patch.object(serving, "adapter_parity", return_value={"status": "not_applicable"}), \
                     patch.object(serving, "service", return_value=object()), \
                     patch("grpc.server", return_value=server), \
                     patch("privoke.v1.runtime_pb2_grpc.add_PrivokeRuntimeServiceServicer_to_server"):
                    if reject_ready:
                        with self.assertRaisesRegex(OSError, "deliberate readiness"):
                            serving.serve(Path(directory), model_entry["name"], 53771, ready)
                    else:
                        serving.serve(Path(directory), model_entry["name"], 53771, ready)
                        receipt = core.read(ready)
                        self.assertEqual(set(receipt["resources"]), {"before_load", "after_load"})
                        self.assertIsInstance(receipt["resources"]["before_load"]["pid"], int)
                        self.assertTrue(server.waited)
                self.assertTrue(server.started)
                self.assertTrue(server.stopped)
                self.assertTrue(ready.with_suffix(".shutdown.json").is_file())

    def test_readiness_rejects_effective_rule_tampering_and_package_rule_drift(self):
        rules = [{"name": "rule", "pattern": "x", "flags": 2, "signal": "x", "packed": 28}]
        protocol = {"source_closure": "source", "environment": {"cpu": 4}, "effective_regex_rules": rules,
                    "effective_regex_rules_sha256": core.digest(core.canonical(rules))}
        ready = {"protocol_sha256": "protocol", "identity": entry()["identity"], "source_closure": "source",
                 "training_disabled": True, "native_product_pipeline": True, "name": entry()["name"],
                 "environment": {"cpu": 4}, "regex_rule_count": 1, "effective_regex_rules": copy.deepcopy(rules),
                 "effective_regex_rules_sha256": protocol["effective_regex_rules_sha256"]}
        core.validate_ready(protocol, "protocol", entry(), ready)
        ready["effective_regex_rules"][0]["pattern"] = "changed"
        with self.assertRaisesRegex(ValueError, "effective regex"):
            core.validate_ready(protocol, "protocol", entry(), ready)
        ready["effective_regex_rules_sha256"] = core.digest(core.canonical(ready["effective_regex_rules"]))
        with self.assertRaisesRegex(ValueError, "effective regex"):
            core.validate_ready(protocol, "protocol", entry(), ready)


if __name__ == "__main__":
    unittest.main()
