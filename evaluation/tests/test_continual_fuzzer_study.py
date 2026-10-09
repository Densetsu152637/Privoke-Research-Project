"""Behavior and real loopback RPC checks using wholly synthetic fixture rows."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from privoke_eval import continual_fuzzer_study as study
from privoke.v1 import parameters_pb2 as PP, parameters_pb2_grpc as PA
from privoke.v1 import runtime_pb2 as RP, runtime_pb2_grpc as RA


class FixtureClient:
    def __init__(self, rejected=(), interrupt=None):
        self.version = 0
        self.requests = []
        self.rejected = rejected
        self.interrupt = interrupt
        self.identity = {"model_id": "privoke-efficient", "model_version": "v0", "artifact_checksum": "synthetic-checksum", "parameter_fingerprint": "synthetic-fingerprint"}

    def snapshot(self, model_id):
        return {"identity": dict(self.identity), "parameters": {"head": {"values": [float(self.version)], "shape": [1]}}, "metadata": {}}

    def analyze(self, row, model_id, layer, request_id):
        if self.interrupt == "checkpoint" and self.version:
            self.interrupt = None
            raise RuntimeError("synthetic interrupted checkpoint")
        expected = row.get("expected_has_pii", row.get("classification", {}).get("sensitivity") == "S2")
        return {"identities": [dict(self.identity)], "raw": {"request_id": request_id}, "detected_sensitive": expected if self.version else False}

    def train(self, request):
        self.requests.append(copy.deepcopy(request))
        if self.interrupt == "train":
            self.interrupt = None
            raise RuntimeError("synthetic transport unknown")
        base = self.identity["model_version"]
        accepted = len(self.requests) not in self.rejected
        if accepted:
            self.version += 1
            self.identity["model_version"] = f"v{self.version}"
        return {"accepted": accepted, "model_id": request["model_id"], "base_version": base,
                "applied_version": self.identity["model_version"], "prompts_generated": request["prompt_count"],
                "metadata": {key: request["metadata"][key] for key in ("curriculum_id", "curriculum_manifest_sha256")}, "message": "synthetic"}


class StudyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continual-fixture-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.dataset = self.root / "development.jsonl"
        self.rows = [{"id": f"eval-{i}", "text": f"Synthetic development content {i}", "group_id": f"eval-group-{i}", "expected_has_pii": bool(i % 2)} for i in range(4)]
        self.write_rows(self.dataset, self.rows)
        splits = {}
        for role in ("train", "heldout", "replay"):
            rows = [{"id": f"{role}-{i}", "text": f"Synthetic {role} target {i}",
                     "classification": {"sensitivity": "S2" if i % 2 else "S0", "visibility": "P2", "categories": []},
                     "metadata": {"group_id": f"{role}-group-{i}", "generator": "synthetic-fixture", "parent_id": "synthetic-parent",
                                  "label_status": "assistant_provisional", "curriculum_role": "grammar"}} for i in range(4)]
            path = self.root / f"{role}.jsonl"
            self.write_rows(path, rows)
            splits[role] = {"path": path.name, "sha256": study.sha(path)}
        self.manifest = self.root / "curriculum-manifest.json"
        study.write_json(self.manifest, {"schema_version": 1, "curriculum_id": "synthetic-test", "splits": splits})
        self.args = study.parser().parse_args(["--model-id", "privoke-efficient", "--cycles", "2", "--checkpoints", "0,1,2",
                                               "--cache-wait-seconds", "0", "--bootstrap-iterations", "20", "--dataset-file", str(self.dataset),
                                               "--dataset-sha256", study.sha(self.dataset), "--curriculum-manifest", str(self.manifest), "--output", str(self.root / "output")])

    def write_rows(self, path, rows):
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    def predictions(self, guesses):
        return [{"id": f"row-{i}", "group_id": f"family-{i//2}", "expected_has_pii": bool(i % 2), "status": "ok", "detected_sensitive": bool(value)} for i, value in enumerate(guesses)]

    def test_metric_confusion_and_error_denominators(self):
        rows = self.predictions([0, 1, 1, 0])
        rows.append({"expected_has_pii": True, "status": "error"})
        metric = study.metrics(rows)
        self.assertEqual([metric[name] for name in ("true_positives", "true_negatives", "false_positives", "false_negatives")], [1, 1, 1, 1])
        for name in study.METRICS:
            self.assertEqual(metric[name], .5)
        self.assertEqual(metric["coverage"], .8)
        self.assertFalse(metric["paper_result_valid"])
        self.assertIsNone(study.metrics([])["recall"])

    def test_frozen_live_operations_reject_image_and_setting_drift(self):
        path = self.root / "operations.json"
        study.write_json(path, {"containers": {"fixture": {"image_id": "sha256:expected", "environment": {"MODEL_ID": "privoke-efficient"}}}})
        row = {"Name": "/fixture", "Image": "sha256:expected", "State": {"Running": True},
               "Config": {"Env": ["MODEL_ID=privoke-efficient"]}}
        with patch.object(study.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps([row]))):
            self.assertEqual(study.verify_operations(path)["sha256"], study.sha(path))
        for field in ("image", "environment"):
            changed = copy.deepcopy(row)
            if field == "image":
                changed["Image"] = "sha256:other"
            else:
                changed["Config"]["Env"] = ["MODEL_ID=privoke-quality"]
            with patch.object(study.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps([changed]))):
                with self.assertRaisesRegex(ValueError, "settings differ"):
                    study.verify_operations(path)

    def test_paired_group_arithmetic_alignment_and_errors(self):
        before, after = self.predictions([0, 0, 0, 0]), self.predictions([0, 1, 0, 1])
        report = study.paired_changes(before, list(reversed(after)), iterations=30)
        self.assertEqual(report["improved"], 2)
        self.assertEqual(report["changes"]["recall"]["estimate"], 1)
        self.assertEqual(report["changes"]["specificity"]["interval_95"], [0, 0])
        self.assertEqual(report["changes"]["balanced_accuracy"]["estimate"], .5)
        with self.assertRaises(ValueError):
            study.paired_changes(before, after[:-1])
        after[0]["group_id"] = "wrong"
        with self.assertRaises(ValueError):
            study.paired_changes(before, after)
        after = self.predictions([0, 1, 0, 1])
        after[0]["status"] = "error"
        self.assertFalse(study.paired_changes(before, after)["valid"])

    def test_final_refused_before_content_access(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("read forbidden")):
            with self.assertRaisesRegex(ValueError, "final"):
                study.load_inputs(self.root / "final.jsonl", "unused", self.manifest)

    def test_pinned_input_and_split_leakage_checks(self):
        with self.assertRaisesRegex(ValueError, "byte-pinned"):
            study.load_inputs(self.dataset, "wrong", self.manifest)
        manifest = study.read_json(self.manifest)
        path = self.root / "train.jsonl"
        train = study.jsonl(path)
        train[0]["text"] = self.rows[0]["text"]
        self.write_rows(path, train)
        manifest["splits"]["train"]["sha256"] = study.sha(path)
        study.write_json(self.manifest, manifest)
        with self.assertRaisesRegex(ValueError, "overlap"):
            study.load_inputs(self.dataset, study.sha(self.dataset), self.manifest)

    def test_rejections_preserved_and_actual_acceptance_count(self):
        client = FixtureClient(rejected={1})
        state = study.run(self.args, client)
        model = state["models"]["privoke-efficient"]
        self.assertEqual(state["status"], "complete")
        self.assertEqual(model["accepted_updates"], 1)
        self.assertEqual([r["response"]["accepted"] for r in model["rounds"]], [False, True])
        self.assertEqual([r["seed"] for r in client.requests], [1337, 1338])
        self.assertEqual(set(model["checkpoints"]), {"0", "1", "2"})
        self.assertEqual(study.read_json(self.args.output / "privoke-efficient/checkpoint-002.json")["semantic"]["paired_vs_baseline"]["improved"], 2)
        with self.assertRaises(FileExistsError):
            study.run(self.args, client)

    def test_duration_runs_until_deadline_and_saves_final_checkpoint(self):
        self.args.cycles = 100
        self.args.checkpoints = [0]
        self.args.duration_seconds = 30
        self.args.round_pause_seconds = 10
        self.args.checkpoint_interval_seconds = 15
        self.args.checkpoint_only_snapshots = True
        clock = [100.0]
        with patch.object(study.time, "time", side_effect=lambda: clock[0]), patch.object(study.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            state = study.run(self.args, FixtureClient())
        model = state["models"]["privoke-efficient"]
        self.assertEqual(len(model["rounds"]), 3)
        self.assertEqual(model["timed_training_seconds"], 30)
        self.assertEqual(model["final_cycle"], 3)
        self.assertEqual(set(model["checkpoints"]), {"0", "3"})
        self.assertFalse((self.args.output / "privoke-efficient/snapshot-001.json").exists())

    def test_duration_rejects_early_cycle_cap(self):
        self.args.duration_seconds = 100
        with patch.object(study.time, "time", return_value=100):
            with self.assertRaisesRegex(ValueError, "Cycle cap"):
                study.run(self.args, FixtureClient())
        self.assertEqual(study.read_json(self.args.output / "run-manifest.json")["status"], "interrupted")

    def test_expired_duration_resume_resolves_exact_pending_request(self):
        self.args.duration_seconds = 30
        client = FixtureClient(interrupt="train")
        with patch.object(study.time, "time", return_value=100):
            with self.assertRaisesRegex(RuntimeError, "unknown"):
                study.run(self.args, client)
        pending = copy.deepcopy(client.requests[0])
        self.args.resume = True
        with patch.object(study.time, "time", return_value=140):
            state = study.run(self.args, client)
        self.assertEqual(client.requests[1], pending)
        self.assertEqual(len(client.requests), 2)
        self.assertEqual(state["models"]["privoke-efficient"]["training_deadline_unix"], 130)

    def test_resume_reuses_pending_request_and_does_not_reissue_completed_rounds(self):
        client = FixtureClient(interrupt="train")
        with self.assertRaisesRegex(RuntimeError, "unknown"):
            study.run(self.args, client)
        pending = copy.deepcopy(client.requests[0])
        self.args.resume = True
        state = study.run(self.args, client)
        self.assertEqual(client.requests[1], pending)
        self.assertEqual(len(state["models"]["privoke-efficient"]["rounds"]), 2)

    def test_resume_repairs_interrupted_checkpoint_before_next_round(self):
        client = FixtureClient(interrupt="checkpoint")
        with self.assertRaisesRegex(RuntimeError, "checkpoint"):
            study.run(self.args, client)
        self.args.resume = True
        state = study.run(self.args, client)
        self.assertEqual(len(client.requests), 2)
        self.assertIn("1", state["models"]["privoke-efficient"]["checkpoints"])

    def test_resume_refuses_modified_snapshot_before_rpc(self):
        client = FixtureClient(interrupt="checkpoint")
        with self.assertRaises(RuntimeError):
            study.run(self.args, client)
        path = self.args.output / "privoke-efficient/snapshot-000.json"
        path.write_text("{}")
        self.args.resume = True
        with self.assertRaisesRegex(ValueError, "changed"):
            study.run(self.args, client)
        self.assertEqual(len(client.requests), 1)

    def test_mining_is_train_only_bounded_and_provenance_preserved(self):
        _, splits, _ = study.load_inputs(self.dataset, study.sha(self.dataset), self.manifest)
        client = FixtureClient()
        hard, rows = study.mine_training(client, splits["train"], "privoke-efficient", client.identity, "synthetic")
        self.assertEqual(hard, ["train-1", "train-3"])
        self.assertEqual({row["label_status"] for row in rows}, {"assistant_provisional"})
        self.assertTrue(all(row["id"].startswith("train-") for row in rows))

    def test_measure_retains_rpc_errors_and_rejects_wrong_pinned_identity(self):
        client = FixtureClient()
        original = client.analyze
        def analyze(row, model_id, layer, request_id):
            if row["id"] == "eval-0":
                result = original(row, model_id, layer, request_id)
                result["identities"][0]["model_version"] = "wrong-version"
                return result
            return original(row, model_id, layer, request_id)
        client.analyze = analyze
        report = study.measure(client, self.rows, "privoke-efficient", client.identity, "synthetic")
        self.assertEqual(report["semantic"]["metrics"]["runtime_errors"], 1)
        self.assertEqual(report["pipeline"]["metrics"]["coverage"], .75)
        self.assertEqual(report["semantic"]["predictions"][0]["status"], "error")

    def test_resume_rejects_changed_inputs_or_model(self):
        client = FixtureClient(interrupt="checkpoint")
        with self.assertRaises(RuntimeError):
            study.run(self.args, client)
        self.args.resume = True
        self.args.prompt_count += 1
        with self.assertRaisesRegex(ValueError, "configuration"):
            study.run(self.args, client)
        self.args.prompt_count -= 1
        client.identity["model_version"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "exact identity"):
            study.run(self.args, client)


class LoopbackRpcTests(unittest.TestCase):
    def test_actual_rpc_requests_timeouts_selection_and_snapshot_identity(self):
        requests = []
        identity = {"model_id": "privoke-efficient", "model_version": "synthetic-v1", "artifact_checksum": "synthetic-checksum",
                    "parameter_fingerprint": study.parameter_fingerprint({"head": [1.0]}, {"head": [1]})}
        class Models(PA.ModelStreamingServiceServicer):
            def GetModelParameters(self, request, context):
                requests.append(("snapshot", request, context.time_remaining()))
                return PP.ModelParametersResponse(model_id=request.model_id, version="synthetic-v1", parameters=[PP.Parameter(name="head", values=[1], shape=[1])], metadata={"artifact_checksum": "synthetic-checksum"})
        class Runtime(RA.PrivokeRuntimeServiceServicer):
            def AnalyzePrompt(self, request, context):
                requests.append(("analyze", request, context.time_remaining()))
                return RP.AnalyzePromptResponse(request_id=request.request_id, action="ALLOW", classification=RP.RuntimeClassification(sensitivity="S0", visibility="PU"),
                    layers=[RP.RuntimeLayerExecution(layer=RP.DETECTION_LAYER_SEMANTIC, status="ok", results=[RP.RuntimeDetectionResult(metadata=identity)])])
        class Fuzzer(PA.FuzzerServiceServicer):
            def RunTrainingCycle(self, request, context):
                requests.append(("train", request, context.time_remaining()))
                if request.request_id == "synthetic-guard-rejection":
                    context.abort(study.grpc.StatusCode.FAILED_PRECONDITION, "synthetic safety gate")
                if request.request_id == "synthetic-unknown":
                    context.abort(study.grpc.StatusCode.UNAVAILABLE, "synthetic unknown update outcome")
                return PP.FuzzerTrainingResponse(accepted=False, model_id=request.model_id, base_version="synthetic-v1", applied_version="synthetic-v1", prompts_generated=request.prompt_count, message="synthetic rejection")
        with ThreadPoolExecutor(max_workers=3) as pool:
            server = study.grpc.server(pool)
            PA.add_ModelStreamingServiceServicer_to_server(Models(), server)
            PA.add_FuzzerServiceServicer_to_server(Fuzzer(), server)
            RA.add_PrivokeRuntimeServiceServicer_to_server(Runtime(), server)
            port = server.add_insecure_port("127.0.0.1:0")
            server.start()
            self.addCleanup(lambda: server.stop(0).wait())
            target = f"127.0.0.1:{port}"
            client = study.RpcClient(target, target, target)
            self.addCleanup(client.close)
            self.assertEqual(client.snapshot("privoke-efficient")["identity"], identity)
            result = client.analyze({"text": "Synthetic fixture"}, "privoke-efficient", "pipeline", "synthetic-request")
            self.assertEqual(result["identities"], [identity])
            self.assertFalse(result["detected_sensitive"])
            outcome = client.train({"request_id": "synthetic-round", "source_id": "synthetic", "model_id": "privoke-efficient", "prompt_count": 256, "seed": 1337, "metadata": {"curriculum_stage": "all"}})
            self.assertFalse(outcome["accepted"])
            self.assertEqual(requests[1][1].semantic_model_id, "privoke-efficient")
            self.assertEqual(list(requests[1][1].layers), [RP.DETECTION_LAYER_RUNTIME])
            self.assertGreater(requests[2][2], 290)
            self.assertGreater(requests[1][2], 110)
            request = {"request_id": "synthetic-guard-rejection", "source_id": "synthetic", "model_id": "privoke-efficient", "prompt_count": 256, "seed": 1337}
            rejection = client.train(request)
            self.assertEqual(rejection["rejection_code"], "FAILED_PRECONDITION")
            self.assertFalse(rejection["accepted"])
            request["request_id"] = "synthetic-unknown"
            with self.assertRaises(study.grpc.RpcError):
                client.train(request)


if __name__ == "__main__":
    unittest.main()
