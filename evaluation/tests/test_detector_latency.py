import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import detector_latency as dl  # noqa: E402


class DetectorLatencyHelpers(unittest.TestCase):
    def test_percentile_interpolates(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        self.assertEqual(dl.percentile(values, 0.5), 3.0)
        self.assertAlmostEqual(dl.percentile(values, 0.95), 4.8)
        self.assertEqual(dl.percentile([7.0], 0.99), 7.0)

    def test_summarise(self):
        stats = dl.summarise([1.0, 2.0, 3.0])
        self.assertEqual((stats["n"], stats["median_ms"], stats["mean_ms"], stats["max_ms"]), (3, 2.0, 2.0, 3.0))

    def test_configs_match_frozen_table(self):
        self.assertEqual(set(dl.CONFIGS), {"O", "N", "N+strip", "N+digits", "N+email", "N+caseless", "N+all", "N+lg", "N+trf"})
        self.assertEqual(dl.CONFIGS["N+trf"]["env"], {"PRIVOKE_NER_MODEL": "en_core_web_trf"})
        self.assertEqual(dl.CONFIGS["N+trf"]["venv"], "trf")
        self.assertEqual(len(dl.CONFIGS["N+all"]["env"]), 4)
        self.assertEqual(dl.CONFIGS["O"]["env"], {})

    def test_aggregate_deltas(self):
        def run(config, base, cold, rss):
            part = {"median_ms": base, "p95_ms": base * 2, "p99_ms": base * 3, "mean_ms": base}
            return {"config": config, "cold_start_s": cold, "peak_rss_mb": rss, "combined": part, "regex": part, "ner": part}
        out = dl.aggregate([run("O", 10, 4, 300), run("N", 12, 5, 310), run("N+lg", 20, 9, 700)])
        self.assertEqual(out["N"]["delta_vs_O"]["combined"]["median_ms"], 2)
        self.assertEqual(out["N+lg"]["delta_vs_N"]["combined"]["median_ms"], 8)
        self.assertEqual(out["N+lg"]["delta_vs_N"]["peak_rss_mb"], 390)
        self.assertNotIn("delta_vs_O", out["N+lg"])


if __name__ == "__main__":
    unittest.main()
