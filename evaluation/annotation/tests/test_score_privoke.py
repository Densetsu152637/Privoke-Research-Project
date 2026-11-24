"""Scorer gates and metrics on invented fixtures; no model is loaded."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agreement as ag  # noqa: E402
import annotation_schema as schema  # noqa: E402
import score_privoke as sp  # noqa: E402


def git(repo, *args):
    result = subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                             "-c", "commit.gpgsign=false", *args], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def ref(sensitive, action, audience="P1", categories=("HEALTH",)):
    return {"sensitive": sensitive, "action": action, "audience": audience, "categories": list(categories), "subject": "SELF"}


# item: (reference, prediction) with TP=2 FP=1 FN=1 TN=2, under=2 (i2, i3), over=1 (i5)
CASES = {
    "it-1": (ref("yes", "BLOCK"), "BLOCK"),
    "it-2": (ref("yes", "WARN"), "ALLOW"),
    "it-3": (ref("yes", "BLOCK", "P2", ("IDENTITY",)), "WARN"),
    "it-4": (ref("no", "ALLOW", "P1", ()), "ALLOW"),
    "it-5": (ref("no", "ALLOW", "P2", ()), "WARN"),
    "it-6": (ref("no", "ALLOW", "P2", ()), "ALLOW"),
}


def response(action, names, statuses=None):
    statuses = statuses or {n: "ok" for n in names}
    return {"action": action, "metadata": {}, "layers": [{"layer": n, "status": statuses[n]} for n in names]}


class LayerRuleTests(unittest.TestCase):
    def test_empty_and_unknown_layer_lists_are_refused_before_sending(self):
        with self.assertRaises(ValueError):
            sp.require_layers([])
        with self.assertRaises(ValueError):
            sp.require_layers([1])
        self.assertEqual(sp.require_layers([4]), [4])

    def test_arm_definitions(self):
        self.assertEqual(sp.ARMS["product"]["layers"], [2, 3, 4])
        self.assertEqual(sp.ARMS["semantic_only"]["layers"], [4])
        self.assertEqual(sp.ARMS["product"]["scope_label"], "product pipeline (in-process)")
        self.assertEqual(sp.ARMS["semantic_only"]["scope_label"], "LLM-only (semantic)")

    def test_executed_layers_must_equal_the_requested_set(self):
        sp.assert_layers(response("ALLOW", ["semantic"])["layers"], [4])
        sp.assert_layers(response("ALLOW", ["regex", "ner", "semantic"])["layers"], [2, 3, 4])
        for names, requested in ((["regex", "semantic"], [4]), (["semantic"], [2, 3, 4]), (["regex", "ner", "semantic"], [4]),
                                 (["ner", "regex", "semantic"], [2, 3, 4]), ([], [4])):
            with self.assertRaises(sp.LayerAssertionError, msg=(names, requested)):
                sp.assert_layers(response("ALLOW", names)["layers"], requested)

    def test_regex_first_skip_only_when_regex_was_requested(self):
        skipped = {"regex": "ok", "ner": "skipped", "semantic": "skipped"}
        sp.assert_layers(response("BLOCK", ["regex", "ner", "semantic"], skipped)["layers"], [2, 3, 4])
        with self.assertRaises(sp.LayerAssertionError):
            sp.assert_layers(response("BLOCK", ["regex", "ner", "semantic"], {"regex": "ok", "ner": "skipped", "semantic": "ok"})["layers"], [2, 3, 4])
        with self.assertRaises(sp.LayerAssertionError):
            sp.assert_layers(response("ALLOW", ["semantic"], {"semantic": "skipped"})["layers"], [4])

    def test_semantic_identity_is_checked_when_the_layer_ran(self):
        layers = response("ALLOW", ["semantic"])["layers"]
        sp.assert_layers(layers, [4], "abc", {"privoke.semantic.artifact_checksum": "abc"})
        with self.assertRaises(sp.LayerAssertionError):
            sp.assert_layers(layers, [4], "abc", {"privoke.semantic.artifact_checksum": "zzz"})

    def test_score_items_sends_the_arms_explicit_layers_and_aborts_on_a_mismatch(self):
        seen = []

        def analyse(text, request_id, layers):
            seen.append(list(layers))
            return response("ALLOW", [sp.LAYER_NAMES[v] for v in layers])

        items = [{"item_id": "it-1", "text": "invented"}]
        sp.score_items(items, "semantic_only", analyse)
        sp.score_items(items, "product", analyse)
        self.assertEqual(seen, [[4], [2, 3, 4]])
        with self.assertRaises(sp.LayerAssertionError):
            sp.score_items(items, "semantic_only", lambda t, r, l: response("ALLOW", ["regex", "ner", "semantic"]))
        self.assertTrue(all(layers for layers in seen))


class MetricTests(unittest.TestCase):
    def test_hand_computed_metrics_and_intervals(self):
        reference = {k: v[0] for k, v in CASES.items()}
        predictions = {k: v[1] for k, v in CASES.items()}
        clusters = {k: "cell-a" if int(k[-1]) % 2 else "cell-b" for k in CASES}
        report = sp.arm_report("semantic_only", predictions, reference, clusters, n_boot=50)
        m = report["metrics"]
        self.assertEqual((m["precision"]["num"], m["precision"]["den"]), (2, 3))
        self.assertEqual((m["recall"]["num"], m["recall"]["den"]), (2, 3))
        self.assertEqual((m["specificity"]["num"], m["specificity"]["den"]), (2, 3))
        self.assertEqual((m["f1"]["num"], m["f1"]["den"]), (4, 6))
        self.assertAlmostEqual(m["f1"]["value"], 2 / 3)
        self.assertEqual((m["under_enforcement"]["num"], m["under_enforcement"]["den"]), (2, 6))
        self.assertEqual((m["over_enforcement"]["num"], m["over_enforcement"]["den"]), (1, 6))
        self.assertEqual(m["recall"]["ci95"], list(ag.wilson_interval(2, 3)))
        self.assertEqual(report["layers_requested"], [4])
        self.assertEqual(report["scope_label"], "LLM-only (semantic)")
        self.assertEqual(report["per_audience"]["P2"]["n"], 3)
        self.assertEqual(report["per_category"]["IDENTITY"]["recall"]["num"], 1)
        self.assertEqual(report, json.loads(json.dumps(report)))

    def test_missing_predictions_are_an_error(self):
        reference = {k: v[0] for k, v in CASES.items()}
        with self.assertRaises(ValueError):
            sp.arm_report("product", {"it-1": "ALLOW"}, reference, {k: "c" for k in CASES}, n_boot=5)


class FreezeGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        git(self.repo, "init", "-q", "-b", "main")
        self.dir = self.repo / "docs" / "research" / "s13a"
        (self.dir / "labels").mkdir(parents=True)
        self.packet = self.repo / "packet"
        (self.packet / "sheets").mkdir(parents=True)
        (self.packet / "key").mkdir()
        (self.packet / "sheets" / "main_A.csv").write_text("item_id,text\nit-1,invented\n")
        (self.packet / "key" / "sampling_key.jsonl").write_text("{}\n")

    def commit(self, message, *paths):
        git(self.repo, "add", *paths)
        git(self.repo, "commit", "-q", "-m", message)

    def write_manifests(self):
        (self.dir / "set_manifest.json").write_text("{}")
        self.commit("set", "docs/research/s13a/set_manifest.json")
        files = {"sheets/main_A.csv": sha256(self.packet / "sheets" / "main_A.csv"),
                 "key/sampling_key.jsonl": sha256(self.packet / "key" / "sampling_key.jsonl")}
        (self.dir / "packet_manifest.json").write_text(json.dumps({"files": files}))
        self.commit("packet", "docs/research/s13a/packet_manifest.json")

    def write_labels(self):
        rows = [{"item_id": k, **{c: ("|".join(v[0]["categories"]) or "NONE") if c == "categories" else v[0][c]
                                  for c in schema.COMMITTED_LABEL_COLUMNS_V2[1:]}} for k, v in CASES.items()]
        schema.write_csv(self.dir / "labels" / "adjudicated.csv", schema.COMMITTED_LABEL_COLUMNS_V2, rows)

    def freeze_record(self, **override):
        path = self.dir / "labels" / "adjudicated.csv"
        record = {"files": {"labels/adjudicated.csv": sha256(path)}}
        record.update(override)
        (self.dir / "iaa.json").write_text(json.dumps(record))

    def frozen(self):
        self.write_manifests()
        self.write_labels()
        self.freeze_record()
        self.commit("freeze", "docs/research/s13a/labels", "docs/research/s13a/iaa.json")

    def gate(self, **kw):
        return sp.verify_freeze(self.dir, kw.get("sheet", self.packet / "sheets" / "main_A.csv"),
                                kw.get("key", self.packet / "key" / "sampling_key.jsonl"))

    def test_a_complete_freeze_passes(self):
        self.frozen()
        self.assertIn("files", self.gate())

    def test_refuses_without_a_freeze_record(self):
        self.write_manifests()
        self.write_labels()
        with self.assertRaises(sp.FreezeError):
            self.gate()

    def test_refuses_when_not_committed_or_changed_or_unlisted(self):
        self.write_manifests()
        self.write_labels()
        self.freeze_record()
        with self.assertRaises(sp.FreezeError):  # present and hash-correct, but never committed
            self.gate()
        self.commit("freeze", "docs/research/s13a/labels", "docs/research/s13a/iaa.json")
        self.assertIn("files", self.gate())
        path = self.dir / "labels" / "adjudicated.csv"
        path.write_text(path.read_text().replace("BLOCK", "ALLOW", 1))
        with self.assertRaises(sp.FreezeError):  # hash differs from the record
            self.gate()

    def test_refuses_a_record_that_does_not_list_the_adjudicated_file(self):
        self.write_manifests()
        self.write_labels()
        (self.dir / "iaa.json").write_text(json.dumps({"files": {}}))
        self.commit("freeze", "docs/research/s13a")
        with self.assertRaises(sp.FreezeError):
            self.gate()

    def test_refuses_an_unlisted_annotator_label_file(self):
        self.frozen()
        shutil_copy = (self.dir / "labels" / "adjudicated.csv").read_text()
        (self.dir / "labels" / "A.csv").write_text(shutil_copy)
        self.commit("late annotator", "docs/research/s13a/labels")
        with self.assertRaises(sp.FreezeError) as ctx:
            self.gate()
        self.assertIn("not listed", str(ctx.exception))

    def test_refuses_an_uncommitted_change_to_the_freeze_record(self):
        self.frozen()
        record = json.loads((self.dir / "iaa.json").read_text())
        (self.dir / "iaa.json").write_text(json.dumps({**record, "x": 1}))
        with self.assertRaises(sp.FreezeError) as ctx:
            self.gate()
        self.assertIn("uncommitted", str(ctx.exception))

    def test_sheet_and_key_must_match_the_packet_manifest(self):
        self.frozen()
        other = self.repo / "other.csv"
        other.write_text("item_id,text\nit-1,changed\n")
        with self.assertRaises(sp.FreezeError):
            sp.verify_freeze(self.dir, other, self.packet / "key" / "sampling_key.jsonl")
        (self.packet / "key" / "sampling_key.jsonl").write_text("{\"x\": 1}\n")
        with self.assertRaises(sp.FreezeError):
            self.gate()

    def test_the_commit_order_is_checked_before_scoring(self):
        (self.dir / "set_manifest.json").write_text("{}")
        self.write_labels()
        self.freeze_record()
        self.commit("labels first", "docs/research/s13a")
        files = {"sheets/main_A.csv": sha256(self.packet / "sheets" / "main_A.csv"),
                 "key/sampling_key.jsonl": sha256(self.packet / "key" / "sampling_key.jsonl")}
        (self.dir / "packet_manifest.json").write_text(json.dumps({"files": files}))
        self.commit("packet late", "docs/research/s13a/packet_manifest.json")
        with self.assertRaises(sp.FreezeError) as ctx:
            self.gate()
        self.assertIn("commit order", str(ctx.exception))

    def test_main_refuses_before_loading_any_model_or_taking_the_lock(self):
        self.write_labels()
        lock = Path(self.tmp.name) / "host.lock"
        os.environ["S13_HOST_LOCK"] = str(lock)
        self.addCleanup(os.environ.pop, "S13_HOST_LOCK", None)
        sheet = self.repo / "sheet.csv"
        schema.write_csv(sheet, schema.SHEET_COLUMNS_V2, [])
        with self.assertRaises(sp.FreezeError):
            sp.main(["--freeze-dir", str(self.dir), "--sheet", str(sheet), "--key", str(sheet), "--out", str(self.repo / "out")])
        self.assertFalse(lock.exists())
        self.assertFalse((self.repo / "out").exists())


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ErrorAndSmokeTests(unittest.TestCase):
    def test_a_layer_error_or_a_response_error_aborts_the_arm(self):
        items = [{"item_id": "it-1", "text": "invented"}]
        errored = response("ALLOW", ["semantic"], {"semantic": "error"})
        with self.assertRaises(sp.LayerAssertionError):
            sp.score_items(items, "semantic_only", lambda t, r, l: errored)
        with self.assertRaises(sp.LayerAssertionError):
            sp.score_items(items, "product", lambda t, r, l: response("ALLOW", ["regex", "ner", "semantic"], {"regex": "ok", "ner": "error", "semantic": "ok"}))
        with self.assertRaises(sp.LayerAssertionError):
            sp.score_items(items, "semantic_only", lambda t, r, l: {**response("ALLOW", ["semantic"]), "error": "boom"})
        records = sp.score_items(items, "semantic_only", lambda t, r, l: response("WARN", ["semantic"]))
        self.assertEqual(records, [{"item_id": "it-1", "action": "WARN", "layers_ok": True}])

    def test_layers_executed_ok_is_computed_not_hard_coded(self):
        reference = {k: v[0] for k, v in CASES.items()}
        predictions = {k: v[1] for k, v in CASES.items()}
        clusters = {k: "c" for k in CASES}
        self.assertFalse(sp.arm_report("product", predictions, reference, clusters, n_boot=5)["layers_executed_ok"])
        self.assertTrue(sp.arm_report("product", predictions, reference, clusters, n_boot=5, executed_ok=True)["layers_executed_ok"])

    def test_conditional_enforcement_rates_have_their_own_denominators(self):
        reference = {k: v[0] for k, v in CASES.items()}
        predictions = {k: v[1] for k, v in CASES.items()}
        m = sp.arm_report("product", predictions, reference, {k: "c" for k in CASES}, n_boot=5)["metrics"]
        # reference WARN/BLOCK items: it-1, it-2, it-3 (two under-enforced); reference ALLOW items: it-4..it-6 (one over-enforced)
        self.assertEqual((m["under_enforcement_conditional"]["num"], m["under_enforcement_conditional"]["den"]), (2, 3))
        self.assertEqual((m["over_enforcement_conditional"]["num"], m["over_enforcement_conditional"]["den"]), (1, 3))
        self.assertEqual(m["under_enforcement"]["den"], 6)

    def test_smoke_runs_one_invented_sentence_per_arm_under_the_lock_without_labels(self):
        from unittest import mock
        seen = []

        class Runtime:
            def analyse_layers(self, text, request_id, layers):
                seen.append((text, list(layers)))
                return response("ALLOW", [sp.LAYER_NAMES[v] for v in layers])

        with tempfile.TemporaryDirectory() as tmp:
            os.environ["S13_HOST_LOCK"] = str(Path(tmp) / "host.lock")
            self.addCleanup(os.environ.pop, "S13_HOST_LOCK", None)
            with mock.patch.object(sp, "make_runtime", lambda release, generated: (Runtime(), None)):
                sp.main(["--smoke"])
            self.assertFalse((Path(tmp) / "host.lock").exists())
        self.assertEqual([layers for _, layers in seen], [[2, 3, 4], [4]])
        self.assertTrue(all(text == sp.SMOKE_TEXT for text, _ in seen))


class HostLockTests(unittest.TestCase):
    def test_a_held_lock_refuses_and_a_release_removes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["S13_HOST_LOCK"] = str(Path(tmp) / "host.lock")
            self.addCleanup(os.environ.pop, "S13_HOST_LOCK", None)
            with sp.HostLock():
                self.assertEqual(json.loads((Path(tmp) / "host.lock").read_text())["stage"], "13a-5")
                with self.assertRaises(SystemExit):
                    sp.HostLock().__enter__()
            self.assertFalse((Path(tmp) / "host.lock").exists())


if __name__ == "__main__":
    unittest.main()
