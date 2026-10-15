"""Publication privacy, aggregate preservation and accepted-input commitments."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "docs/evidence/accelerated-fuzzer-20261010"
SPEC = importlib.util.spec_from_file_location("accelerated_publication", PUBLIC / "reproduce.py")
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)


def private_summary():
    """Reconstruct omitted fields using canaries, without any local raw dataset."""
    summary = json.loads((PUBLIC / "summary.json").read_text(encoding="utf-8"))
    def restore(node):
        if isinstance(node, dict):
            if "changed_rows" in node:
                node["changed_ids"] = ["PRIVATE-EXAMPLE-CANARY"] * node["changed_rows"]
            for value in list(node.values()):
                restore(value)
        elif isinstance(node, list):
            for value in node:
                restore(value)
    restore(summary)
    for cell in summary["cells"]:
        cell["cell"]["project"] = "PRIVATE-LOCAL-PROJECT"
        for attempt in cell["gate_diagnostics"]["attempts"]:
            attempt.update(base_version="PRIVATE-VERSION", base_parameter_fingerprint="a" * 64,
                           candidate_parameter_fingerprint="b" * 64)
    return summary


class PublicationTests(unittest.TestCase):
    def test_nested_ids_and_candidate_identities_are_omitted_with_all_aggregates_preserved(self):
        raw = private_summary()
        projected = publication.summary_projection(raw)
        expected = json.loads((PUBLIC / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(projected, expected)
        encoded = publication.encoded(projected).decode()
        self.assertNotIn("PRIVATE-", encoded)
        self.assertNotIn('"changed_ids"', encoded)
        for profile in projected["profiles"].values():
            for effect in profile["revised_final_effects_vs_shared_control"].values():
                for endpoint in effect["exact_prediction_changes_vs_shared_control"].values():
                    self.assertEqual(set(endpoint), {"changed_rows"})

    def test_unknown_nested_fields_and_missing_metrics_fail_closed(self):
        for mutation in ("extra", "missing"):
            raw = private_summary()
            metric = raw["cells"][0]["checkpoints"]["168"]["development"]["metrics"]
            if mutation == "extra":
                metric["new_example_text"] = "PRIVATE-CANARY"
            else:
                del metric["recall"]
            with self.assertRaises(ValueError):
                publication.summary_projection(raw)

    def test_metric_strings_booleans_and_nonfinite_values_fail_closed(self):
        for invalid in ("PRIVATE-CANARY", True, float("nan"), float("inf"), None):
            raw = private_summary()
            raw["cells"][0]["checkpoints"]["168"]["development"]["metrics"]["recall"] = invalid
            with self.assertRaises(ValueError):
                publication.summary_projection(raw)

    def test_numeric_gate_metrics_and_predicates_remain_exact(self):
        raw = private_summary()
        projected = publication.summary_projection(raw)
        for before, after in zip(raw["cells"], projected["cells"]):
            self.assertEqual(before["gate_diagnostics"]["counts"], after["gate_diagnostics"]["counts"])
            for a, b in zip(before["gate_diagnostics"]["attempts"], after["gate_diagnostics"]["attempts"]):
                self.assertEqual(a["metrics"], b["metrics"])
                self.assertEqual(a["failed_predicates"], b["failed_predicates"])

    def test_small_contrast_and_interval_values_are_not_rounded(self):
        raw = private_summary()
        effect = raw["profiles"]["efficient"]["revised_final_effects_vs_shared_control"]["efficient-revised-42"]
        effect["development"]["recall"]["difference_in_changes"] = 0.000000000123456789
        interval = effect["paired_development_vs_shared_control"]["semantic"]["paired"]["changes"]["recall"]
        interval["interval_95"] = [-0.000000000123456789, 0.000000000987654321]
        projected = publication.summary_projection(raw)["profiles"]["efficient"]["revised_final_effects_vs_shared_control"]["efficient-revised-42"]
        self.assertEqual(projected["development"]["recall"]["difference_in_changes"], 0.000000000123456789)
        self.assertEqual(projected["paired_development_vs_shared_control"]["semantic"]["paired"]["changes"]["recall"], interval)

    def test_hash_mismatch_rejects_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "raw").mkdir()
            (root / "raw/protocol.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Accepted input hash differs"):
                publication.publish(root / "raw", root / "build", root / "public")
            self.assertFalse((root / "public").exists())

    def test_raw_destination_is_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for destination in (root / "raw", root / "raw/nested", root / "build"):
                with self.assertRaisesRegex(ValueError, "separate"):
                    publication.publish(root / "raw", root / "build", destination)
            self.assertFalse((root / "raw").exists())

    def test_publication_manifest_binds_public_bytes_and_script(self):
        manifest = json.loads((PUBLIC / "publication-hashes.json").read_text(encoding="utf-8"))
        self.assertEqual(publication.sha(PUBLIC / "reproduce.py"), manifest["reproduction_script_sha256"])
        for name, expected in manifest["published_sha256"].items():
            self.assertEqual(publication.sha(PUBLIC / name), expected)
        self.assertNotEqual(manifest["raw_to_published"]["summary.json"]["raw_sha256"],
                            manifest["raw_to_published"]["summary.json"]["published_sha256"])
        self.assertTrue(manifest["raw_to_published"]["audit.json"]["identical_bytes"])


if __name__ == "__main__":
    unittest.main()
