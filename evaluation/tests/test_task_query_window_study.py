"""Synthetic admission/isolation checks; no model or service execution."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_eval import task_query_window_study as study


class StudyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = study.ROOT / "evaluation/results/task_query_window_20261012/tmp"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def test_matrix_is_exact_paired_twelve_without_replacement_requests(self):
        rows = study.matrix()
        self.assertEqual(len(rows), 12)
        self.assertEqual(len({r["request_id"] for r in rows}), 12)
        for seed in (42, 43, 44):
            self.assertEqual({(r["architecture"], r["loop"]) for r in rows if r["seed"] == seed},
                             {(a, b) for a in ("v1", "v2") for b in ("legacy", "window")})

    def test_existing_initials_are_pinned_across_current_head(self):
        with patch.object(study, "git_read", side_effect=AssertionError("current HEAD must not define the frozen teacher")):
            result = study.prepare_initials(self.scratch)
        self.assertEqual(result["v1"]["sha256"], study.SOURCE_MODEL_SHA)
        self.assertEqual(result["v2"]["sha256"], study.INITIAL_V2_SHA)
        self.assertEqual(study.read(result["v2"]["path"])["metadata"]["preparation_source_revision"],
                         study.INITIAL_V2_SOURCE_REVISION)

    def test_scoring_catalog_reuses_trained_cell_and_checks_bytes(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp, patch.object(study, "WEIGHTS_ROOT", Path(temp)):
            cell_id = study.matrix()[0]["id"]
            catalog = study.retained_catalog(cell_id) / "models"
            catalog.mkdir(parents=True)
            artifact = catalog / "privoke-balanced.json"
            artifact.write_bytes(b"effective")
            effective = Path(temp) / "effective.json"
            effective.write_bytes(b"effective")
            candidate = {"path": str(effective), "sha256": study.sha(effective)}
            self.assertEqual(study.scoring_catalog(cell_id, candidate), catalog)
            self.assertEqual(artifact.read_bytes(), b"effective")
            artifact.write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "catalog differs"):
                study.scoring_catalog(cell_id, candidate)
            initial = study.scoring_catalog("initial-v1", candidate)
            self.assertEqual((initial / "privoke-balanced.json").read_bytes(), b"effective")

    def test_incomplete_cells_refuse_before_endpoint_freeze_command_or_mount(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            output = Path(temp)
            study.exclusive(output / "images.json", {})
            protocol = {"cells": study.matrix(), "initial_teachers": {}}
            with patch.object(study, "validate_release", return_value=protocol), patch.object(study, "command") as command, patch.object(study, "bind") as bind:
                with self.assertRaisesRegex(ValueError, "Incomplete cell"):
                    study.score_models(output, output / "unused-release.json")
                command.assert_not_called()
                bind.assert_not_called()
                self.assertFalse((output / "endpoint-candidates.json").exists())
                self.assertFalse((output / "endpoints").exists())

    def test_fixture_stimulus_preserves_only_historical_visibility_hint(self):
        for hint in ("P0", "P3", "P4", "PU", ""):
            row = {"text": "Frozen text", "visibility_hint": hint, "audience_hint": "P4"}
            fields = study.endpoint_request_fields(row, "hazard48", {}, "fixture")
            self.assertEqual(fields["visibility_hint"], hint)
            self.assertEqual(fields["layers"], [4])
            self.assertEqual(fields["text"], row["text"])
            for kind in ("context64", "context320", "binary502"):
                self.assertEqual(study.endpoint_request_fields(row, kind, {}, "row")["visibility_hint"], "")

    def test_build_alias_must_resolve_to_authoritative_parent(self):
        identity = "sha256:" + "a" * 64
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            with patch.object(study, "command", side_effect=["", "", '[{"Id":"' + identity + '"}]']) as command:
                aliases = study.bind_build_parents(Path(temp), {"runtime": identity})
                self.assertFalse(aliases["runtime"].startswith("sha256:"))
                self.assertEqual(command.call_args_list[1].args[0], ["docker", "tag", identity, aliases["runtime"]])
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            with patch.object(study, "command", side_effect=["", "", '[{"Id":"wrong"}]']):
                with self.assertRaisesRegex(ValueError, "differs from inspected"):
                    study.bind_build_parents(Path(temp), {"runtime": identity})

    def response(self):
        identity = {"model_id": "privoke-balanced", "version": "test", "checksum": "checksum", "parameter_fingerprint": "fp"}
        response = SimpleNamespace(error="", layers=[SimpleNamespace(layer=4, status="ok", error="")],
            metadata={"privoke.semantic.model_id": "privoke-balanced", "privoke.semantic.model_version": "test",
                      "privoke.semantic.artifact_checksum": "checksum", "privoke.semantic.parameter_fingerprint": "fp"})
        return response, identity

    def test_semantic_assertion_accepts_complete_execution_and_identity(self):
        study.assert_semantic(*self.response())

    def test_semantic_assertion_refuses_omitted_mixed_failed_and_stale(self):
        for change in ("omitted", "mixed", "failed", "stale"):
            response, identity = self.response()
            if change == "omitted":
                response.layers = []
            elif change == "mixed":
                response.layers.append(SimpleNamespace(layer=1, status="ok", error=""))
            elif change == "failed":
                response.layers[0].status = "error"
            else:
                response.metadata["privoke.semantic.parameter_fingerprint"] = "different"
            with self.subTest(change=change), self.assertRaises(ValueError):
                study.assert_semantic(response, identity)

    def test_host_generated_protobuf_request_has_explicit_semantic_layer(self):
        study.install_host_imports()
        from privoke.v1 import runtime_pb2
        request = runtime_pb2.AnalyzePromptRequest(request_id="tw01-synthetic",
            text="synthetic", semantic_model_id="privoke-balanced", layers=[4])
        restored = runtime_pb2.AnalyzePromptRequest.FromString(request.SerializeToString(deterministic=True))
        self.assertEqual(list(restored.layers), [runtime_pb2.DETECTION_LAYER_SEMANTIC])
        self.assertEqual(restored.request_id, "tw01-synthetic")

    def test_evidence_is_exclusive_and_nonfinite_refused(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            path = Path(temp) / "out.json"
            study.exclusive(path, {"status": "attempted"})
            with self.assertRaises(FileExistsError):
                study.exclusive(path, {"status": "completed"})
            self.assertEqual(study.read(path), {"status": "attempted"})
            with self.assertRaises(ValueError):
                study.canonical({"loss": float("nan")})

    def test_protected_final_rejected_before_read(self):
        with self.assertRaisesRegex(ValueError, "Protected final"):
            study.permitted_input(study.ROOT / "evaluation/results/locked-public/final.jsonl")

    def test_retained_path_mapping_and_catalog_scope(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            root = Path(temp)
            data, release = root / "data", root / "release"
            data.mkdir(); release.mkdir()
            (data / "attempt.json").write_text("{}")
            resolve = study.frozen_path_resolver(data, release)
            self.assertEqual(resolve("/data/attempt.json"), data / "attempt.json")
            self.assertEqual(resolve("/training-window/original.json"), release / "original.json")
            for bad in ("/data/../outside", "/unknown/file", "C:\\outside", "/data\\file"):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    resolve(bad)
            try:
                (data / "link").symlink_to(root)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(ValueError, "Symlinked"):
                    resolve("/data/link/file")
            try:
                (root / "root-link").symlink_to(data, target_is_directory=True)
            except OSError:
                pass
            else:
                with self.assertRaisesRegex(ValueError, "Symlinked retained root"):
                    study.frozen_path_resolver(root / "root-link", release)
            for bad in ("initial-../outside", "initial-other", "../outside"):
                with self.assertRaisesRegex(ValueError, "Unknown retained"):
                    study.retained_catalog(bad)

    def test_compose_is_four_service_private_no_bootstrap_ports_endpoints(self):
        cell = {**study.matrix()[0], "ports": {"model": 55051, "runtime": 55054, "fuzzer": 55053}}
        images = {role: "sha256:" + "a" * 64 for role in ("model", "runtime", "updater", "fuzzer")}
        inputs = {n: {"path": "synthetic/" + n} for n in ("taxonomy", "benign_pool", "benign_manifest", "benign_proof")}
        compose = study.compose_cell(cell, Path("synthetic/cell"), images, {}, inputs)
        self.assertEqual(len(compose["services"]), 4)
        self.assertFalse(compose["networks"]["default"]["internal"])
        self.assertEqual(compose["networks"]["default"]["driver"], "bridge")
        serialized = study.canonical(compose).decode()
        self.assertNotIn("bootstrap", serialized)
        self.assertNotIn("context64", serialized)
        self.assertNotIn("locked-public", serialized)
        for role, port, inner in (("model", 55051, 50051), ("runtime", 55054, 50054), ("fuzzer", 55053, 50053)):
            self.assertEqual(compose["services"][cell["id"] + "-" + role]["ports"],
                             [f"127.0.0.1:{port}:{inner}"])
        self.assertNotIn("ports", compose["services"][cell["id"] + "-updater"])
        for service in compose["services"].values():
            self.assertFalse(any(m["source"] == str(study.ROOT) for m in service.get("volumes", [])))
        updater = compose["services"][cell["id"] + "-updater"]
        self.assertEqual(updater["environment"]["FUZZER_PROMPT_COUNT"], "0")
        for role in ("runtime", "updater"):
            self.assertTrue(any(m.startswith("/var/lib/privoke:") for m in compose["services"][cell["id"] + "-" + role]["tmpfs"]))

    def test_window_pins_are_independently_wired_on_both_sides(self):
        cell = {**study.matrix()[1], "ports": {"model": 55051, "runtime": 55054, "fuzzer": 55053}}
        images = {role: "sha256:" + "a" * 64 for role in ("model", "runtime", "updater", "fuzzer")}
        releases = {"directory": "synthetic/release", "window_sha256": "w", "component_sha256": "c", "teacher_sha256": "t"}
        inputs = {n: {"path": "synthetic/" + n} for n in ("taxonomy", "benign_pool", "benign_manifest", "benign_proof")}
        compose = study.compose_cell(cell, Path("synthetic/cell"), images, releases, inputs)
        for role, prefix in (("runtime", "PRIVOKE"), ("fuzzer", "FUZZ")):
            env = compose["services"][cell["id"] + "-" + role]["environment"]
            self.assertEqual(env[prefix + "_WINDOW_MANIFEST_SHA256"], "w")
            self.assertEqual(env[prefix + "_COMPONENT_MANIFEST_SHA256"], "c")
            self.assertEqual(env[prefix + "_COMPONENT_TEACHER_SHA256"], "t")

    def test_numerical_phase_requires_root_release(self):
        with tempfile.TemporaryDirectory(dir=self.scratch) as temp:
            path = Path(temp) / "release.json"
            study.exclusive(path, {"phase": "teachers", "accepted": False, "protocol_sha256": "x", "source_inventory_sha256": "x"})
            with self.assertRaisesRegex(ValueError, "Wrong/unaccepted"):
                study.validate_release(Path(temp), path, "teachers")


if __name__ == "__main__":
    unittest.main()
