"""Opt-in actual CPU image smoke test using synthetic mechanics-only TRAIN rows."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("PRIVOKE_OFFLINE_TEST_IMAGE"), "Explicit CPU training image required")
class OfflineImageTests(unittest.TestCase):
    def test_matched_modes_export_valid_parity_checked_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="offline-contract-") as temporary:
            directory = Path(temporary)
            train = directory / "train.jsonl"
            rows = [{"id": f"synthetic-{i}", "text": f"Synthetic mechanics test {i} " + ("private medical record" if i % 2 else "generic public guidance"),
                     "classification": {"sensitivity": "S2" if i % 2 else "S0", "visibility": "P2" if i % 2 else "PU", "categories": ["HEALTH"] if i % 2 else []},
                     "metadata": {"label_status": "assistant_provisional", "group_id": f"synthetic-family-{i//4}"}} for i in range(672)]
            train.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            receipts = []
            for mode in ("head_only", "end_to_end"):
                mounts = [(ROOT / "evaluation/privoke_eval", "/workspace/evaluation/privoke_eval"),
                          (ROOT / "evaluation/host_environment.py", "/workspace/evaluation/host_environment.py"),
                          (ROOT / "evaluation/fit-contextual-representation-arm.py", "/workspace/evaluation/fit-contextual-representation-arm.py"),
                          (ROOT / "shared/python", "/workspace/shared/python"),
                          (ROOT / "extension/client-runtime/src", "/workspace/extension/client-runtime/src"),
                          (ROOT / "models/privoke-efficient.json", "/baseline.json"), (train, "/input/train.jsonl")]
                command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m"]
                for source, target in mounts:
                    command.extend(["--mount", f"type=bind,source={source},target={target},readonly"])
                command += ["--mount", f"type=bind,source={directory},target=/output", "-e", "PYTHONPATH=/workspace/evaluation:/workspace/shared/python:/workspace/extension/client-runtime",
                            os.environ["PRIVOKE_OFFLINE_TEST_IMAGE"], "python", "-B", "/workspace/evaluation/fit-contextual-representation-arm.py",
                            "--baseline", "/baseline.json", "--train", "/input/train.jsonl", "--output", "/output/" + mode, "--mode", mode, "--seed", "42"]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                receipt = json.loads((directory / mode / "fit-receipt.json").read_text(encoding="utf-8"))
                self.assertEqual((receipt["steps"], receipt["presentations"], receipt["unique_rows"]), (20, 640, 640))
                self.assertLessEqual(receipt["maximum_inference_parity_error"], 2e-5)
                encoder = [r["changed_values"] for name, r in receipt["changed_tensors"].items() if not name.startswith("head.")]
                self.assertEqual(any(encoder), mode == "end_to_end")
                receipts.append(receipt)
            self.assertEqual(receipts[0]["schedule_sha256"], receipts[1]["schedule_sha256"])


if __name__ == "__main__":
    unittest.main()
