"""Private frozen TW01 precompute readiness; requires host Python 3.11 and NumPy."""
import base64
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from privoke_eval import task_query_window_study as study


class FrozenWindowPrecomputeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = study.ROOT / "evaluation/results/task_query_window_20261012/tmp"
        cls.scratch.mkdir(parents=True, exist_ok=True)

    def test_frozen_window_precompute_reaches_reservation_without_physical_calls(self):
        """Exercise production admission and all six pinned releases on the host."""
        output = study.ROOT / "evaluation/results/task_query_window_20261012/host-v2"
        if not (output / "protocol.fit-r2.json").is_file():
            self.skipTest("Private frozen study releases are unavailable")
        study.install_host_imports()
        fuzzer_source = str(study.ROOT / "services/privoke-fuzzer/src")
        if fuzzer_source in sys.path:
            sys.path.remove(fuzzer_source)
        sys.path.insert(0, fuzzer_source)
        # The updater also exports a top-level ``config`` module; load the
        # fuzzer module from its exact source path for this isolated test.
        import importlib.util
        spec = importlib.util.spec_from_file_location("tw01_fuzzer_config", Path(fuzzer_source) / "config.py")
        config_module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"config": config_module, "tw01_fuzzer_config": config_module}):
            spec.loader.exec_module(config_module)
            from fuzzer_service import FuzzerTrainingService, validate_training_request
        FuzzerConfig = config_module.FuzzerConfig
        from training import window_cycle
        from privoke.v1 import parameters_pb2 as pp

        class ReachedReservation(BaseException):
            pass

        class NoRpcContext:
            def abort(self, code, details):
                raise AssertionError(f"Precompute rejected: {code} {details}")

        protocol = study.read(output / "protocol.fit-r2.json")
        accepted = study.read(output / "accepted-releases.json")
        images = study.read(output / "images.fit-r2.json")
        windows = [cell for cell in protocol["cells"] if cell["loop"] == "window"]
        self.assertEqual(len(windows), 6)
        for name, item in protocol["inputs"].items():
            self.assertEqual(study.sha(study.ROOT / item["path"]), item["sha256"], name)
        for cell in windows:
            with self.subTest(cell=cell["id"]), tempfile.TemporaryDirectory(dir=self.scratch) as temp:
                request = pp.FuzzerTrainingRequest(
                    request_id=cell["request_id"], model_id="privoke-balanced",
                    source_id="tw01-" + cell["id"], prompt_count=256, seed=cell["seed"],
                    metadata=study.fit_metadata(cell, protocol, accepted[cell["id"]]))
                if cell["id"] == "v1-window-42":
                    retained = study.read(output / "attempts/v1-window-42/precompute-missing-numpy-r2/fit-reservation.json")
                    self.assertEqual(retained["sha256"], "858e3c7acf0d40249454a13ae2e2e1229f495db37bc56803323116508dc37641")
                    self.assertEqual(request.SerializeToString(deterministic=True),
                                     base64.b64decode(retained["request_base64"]))
                synthetic_cell = {**cell, "ports": {"model": 55051, "runtime": 55054, "fuzzer": 55053}}
                compose = study.compose_cell(synthetic_cell, output / "cells" / cell["id"],
                                             images, accepted[cell["id"]], protocol["inputs"])
                fuzzer = compose["services"][cell["id"] + "-fuzzer"]
                env = dict(fuzzer["environment"])
                for key, value in tuple(env.items()):
                    for mount in fuzzer["volumes"]:
                        target = mount["target"]
                        if value == target or value.startswith(target + "/"):
                            suffix = value[len(target):].lstrip("/")
                            env[key] = str(Path(mount["source"]) / suffix)
                            break
                env["PRIVOKE_FUZZER_DUMP_DIR"] = temp
                with patch.dict(os.environ, env, clear=True):
                    config = FuzzerConfig.from_env()
                    service = FuzzerTrainingService(config)
                    validate_training_request(request, config.model_id)
                    scoped = pp.FuzzerTrainingRequest(
                        request_id=request.request_id, model_id=request.model_id,
                        source_id=hashlib.sha256(("underlying-v1:" + request.source_id).encode()).hexdigest(),
                        prompt_count=request.prompt_count, seed=request.seed,
                        metadata={**dict(request.metadata), "original_request_source_id": request.source_id})
                    def reached(*args):
                        self.assertEqual(args[0].request_id, request.request_id)
                        raise ReachedReservation
                    with patch.object(window_cycle, "reserve_training_request", side_effect=reached) as reserve, \
                         patch.object(window_cycle, "PrivokeRuntimeClient", side_effect=AssertionError("runtime called")), \
                         patch.object(window_cycle, "train_parameter_batch", side_effect=AssertionError("physical trainer called")), \
                         patch.object(service, "_previous_update_for_fingerprint", side_effect=AssertionError("updater called")):
                        with self.assertRaises(ReachedReservation):
                            window_cycle.run(service, scoped, NoRpcContext(), training_scope="full_encoder")
                        reserve.assert_called_once()
                self.assertEqual(list(Path(temp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
