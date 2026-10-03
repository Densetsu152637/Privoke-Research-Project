from __future__ import annotations

import unittest
from unittest.mock import patch, MagicMock

from privoke_eval.runners import run_pipeline, _bridge_process


class RunnerTests(unittest.TestCase):
    def test_container_mode_uses_local_bridge_without_nested_docker(self):
        process = MagicMock()
        with patch("privoke_eval.runners._bridge", None), patch.dict(
            "os.environ", {"PRIVOKE_EVAL_IN_CONTAINER": "true"}
        ), patch("privoke_eval.runners.subprocess.Popen", return_value=process) as start:
            self.assertIs(_bridge_process(), process)
        command = start.call_args.args[0]
        self.assertNotIn("docker", command)
        self.assertTrue(command[-1].endswith("grpc_runtime_client.py"))

    def setUp(self) -> None:
        patcher = patch("privoke_eval.runners.configure_backend")
        self.addCleanup(patcher.stop)
        patcher.start()

    def test_uses_returned_classification_even_when_action_is_allow(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {
                "sensitivity": "S1",
                "visibility": "PU",
                "categories": ["IDENTITY"],
            },
            "confidence": 0.8,
            "elapsed_ms": 1.0,
        }
        with patch("privoke_eval.runners._request_grpc", return_value=response):
            outcome = run_pipeline("example", "streamed")

        self.assertTrue(outcome.detected_sensitive)
        self.assertFalse(outcome.intervened)

    def test_rejects_invalid_classification_instead_of_scoring_it(self) -> None:
        response = {
            "action": "ALLOW",
            "classification": {"sensitivity": "unknown", "categories": []},
        }
        with patch("privoke_eval.runners._request_grpc", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "invalid classification sensitivity"):
                run_pipeline("example", "streamed")


if __name__ == "__main__":
    unittest.main()
