"""Tests that the E2EEVADE record re-derives from its rows and that ``--check`` rejects tampering (synthetic data only)."""

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation")]

import e2e_evasion as e2e  # noqa: E402
import e2e_evasion_report as rep  # noqa: E402
from test_e2e_evasion import FULL, row_with, stage3_fixture  # noqa: E402


DETECTOR_META = {"identity": {"artifact_checksum": "good"}}


def make_plan(rows):
    seeds = sorted({r["seed_id"] for r in rows})
    return {"seed_ids": seeds, "seed_group": {s: f"g{int(s[1:]) // 2}" for s in seeds},
            "seed_source": {s: "synthetic/a" for s in seeds}, "frozen_set_sha256": e2e.FROZEN_SET_SHA256,
            "f4_source_sha256": e2e.F4_SOURCE_SHA256, "stage3_transform_module_sha256": e2e.STAGE3_TRANSFORMS_SHA256,
            "template_sha256": "1" * 64, "run_set_sha256": "2" * 64, "sample_seed": e2e.SAMPLE_SEED, "n_seed": len(seeds),
            "rows_by_source": {"synthetic/a": len(seeds)}, "excluded_ids": 0,
            "variants": {"v1": {"family": "unicode", "value_removing": False}},
            "applicable_by_variant": {"v1": len(seeds), "v2": len(seeds)},
            "e2e_generator_revision": "e2e-evasion-transforms-1", "stage3_generator_revision": e2e.STAGE3_GENERATOR_REVISION}


def make_meta(status_edge="not_run", reason_edge="browser not installed on this host"):
    return {"layers": list(FULL), "commands": ["e2e_evasion.py run ..."], "host": {"platform": "synthetic"},
            "started_utc": "2026-12-01T08:00:00Z", "finished_utc": "2026-12-01T09:00:00Z",
            "branch": "feat/asiaccs-s13b", "revision": "a" * 40, "worktree_dirty": False,
            "extension_build": None, "expected_checksum": "good", "settings": {"warn_masking": False},
            "stack": {"target": "127.0.0.1:50051", "model_id": "privoke-v3-balanced", "artifact_checksum": "good"},
            "browsers": [{"key": "chrome", "browser": "Google Chrome", "status": "run", "browser_version": "1", "headless": True,
                          "attended": False, "rows_written": 24},
                         {"key": "edge", "browser": "Microsoft Edge", "status": status_edge, "reason": reason_edge,
                          "headless": True, "attended": False},
                         {"key": "firefox", "browser": "Mozilla Firefox", "status": "not_run",
                          "reason": "extension could not be loaded: synthetic", "headless": True, "attended": False}],
            "host_guard": {"fixture_hosts": ["chatgpt.com"], "foreign_host_requests": [], "driver_foreign_requests": [],
                           "outbound_non_loopback_connections": [], "outside_lookups": 0}}


def make_record(extra_rows=()):
    rows, _, _ = stage3_fixture()
    rows = [dict(r) for r in rows] + [dict(r) for r in extra_rows]
    detector = {}
    for row in rows:
        if row["detector_level"] is not None and not row["attended"]:
            detector[f"{row['seed_id']}::{row['variant']}"] = {
                "action": row["detector_level"]["action"], "failed_closed": False,
                "layer_status": {n: "ok" for n in FULL}}
    return rep.build_record(rows, detector, make_plan(rows), make_meta(), "20261201",
                            detector_meta=DETECTOR_META), rows


class RecordTests(unittest.TestCase):
    def test_a_built_record_passes_its_own_check_in_memory_and_after_a_round_trip(self):
        record, _ = make_record()
        self.assertEqual(rep.check_record(record, rep.render_markdown(record)), [])
        round_trip = json.loads(rep.dumps_record(record))
        self.assertEqual(round_trip, json.loads(json.dumps(record)))
        self.assertEqual(rep.check_record(round_trip, rep.render_markdown(round_trip)), [])

    def test_the_header_scope_labels_and_row_shape(self):
        record, _ = make_record()
        for field in rep.HEADER_FIELDS:
            self.assertIn(field, record)
        self.assertEqual(record["study_id"], "E2EEVADE-20261201")
        self.assertEqual(record["chain"]["evidence"], "E2EEVADE-20261201")
        self.assertEqual(record["scope_label"], e2e.SCOPE_LABEL)
        self.assertEqual(record["arms"]["detector_level"]["scope_label"], e2e.DETECTOR_SCOPE_LABEL)
        self.assertEqual(record["build"], {"branch": "feat/asiaccs-s13b", "sha": "a" * 40, "clean": True})
        self.assertEqual(record["run_dates"], ["20261201"])
        self.assertTrue(all(r["scope_label"] == e2e.SCOPE_LABEL for r in record["rows"]))
        self.assertTrue(all(set(e2e.EXPECTED_ROW_FIELDS) <= set(r) for r in record["rows"]))

    def test_every_aggregate_re_derives_and_a_changed_count_is_caught(self):
        record, _ = make_record()
        key = "chrome|headless"
        tampered = copy.deepcopy(record)
        tampered["results"][key]["arms"]["end_to_end"]["action_level"]["overall"]["evaded"] += 1
        problems = rep.check_record(tampered)
        self.assertTrue(any("do not re-derive" in p for p in problems), problems)
        tampered = copy.deepcopy(record)
        tampered["results"][key]["paired_conditional"]["all_families"]["exact_mcnemar_p"] = 0.5
        self.assertTrue(rep.check_record(tampered))

    def test_a_changed_row_is_caught_through_the_outcome_and_the_results(self):
        record, _ = make_record()
        tampered = copy.deepcopy(record)
        row = next(r for r in tampered["rows"] if r["e2e_outcome"] == "evaded")
        row["e2e_outcome"] = "protected"
        self.assertTrue(any("e2e_outcome" in p for p in rep.check_record(tampered)))
        tampered = copy.deepcopy(record)
        victim = next(r for r in tampered["rows"] if r["variant"] == "v1" and r["decision"] == "BLOCK")
        victim.update(receiver_got=True, payload_intact=True, decision="ALLOW")
        self.assertTrue(rep.check_record(tampered))

    def test_the_markdown_must_equal_the_rendering_of_the_json(self):
        record, _ = make_record()
        markdown = rep.render_markdown(record)
        self.assertIn("E2EEVADE-20261201", markdown)
        self.assertEqual(rep.check_record(record, markdown), [])
        changed = markdown.replace("Conditional ASR", "Conditional  ASR", 1)
        self.assertTrue(any("Markdown" in p for p in rep.check_record(record, changed)))

    def test_the_markdown_reports_both_denominators_and_the_value_removing_split(self):
        record, _ = make_record()
        markdown = rep.render_markdown(record)
        result = record["results"]["chrome|headless"]
        self.assertIn(f"end to end {result['arms']['end_to_end']['protected_baselines']} seeds", markdown)
        self.assertIn(f"detector level {result['arms']['detector_level']['protected_baselines']} seeds", markdown)
        self.assertIn("without value-removing", markdown)
        self.assertIn("Fail-closed", markdown)
        self.assertIn("McNemar", markdown)
        self.assertIn("## Not established", markdown)

    def test_building_does_not_mutate_the_input_rows(self):
        rows, _, _ = stage3_fixture()
        before = copy.deepcopy(rows)
        rep.build_record(rows, {}, make_plan(rows), make_meta(), "20261201", detector_meta=DETECTOR_META)
        self.assertEqual(rows, before)

    def test_the_json_is_valid_with_one_row_per_line_and_no_prompt_keys(self):
        record, _ = make_record()
        text = rep.dumps_record(record)
        parsed = json.loads(text)
        self.assertEqual(len(parsed["rows"]), len(record["rows"]))
        self.assertGreaterEqual(text.count("\n"), len(record["rows"]))
        for key in ('"text"', '"prompt"', '"body"', '"notes"'):
            self.assertNotIn(key, text)


class CheckRulesTests(unittest.TestCase):
    def setUp(self):
        self.record, self.rows = make_record()

    def problems(self, mutate):
        record = copy.deepcopy(self.record)
        mutate(record)
        return rep.check_record(record)

    def test_a_browser_that_is_neither_run_nor_listed_fails(self):
        problems = self.problems(lambda r: r.__setitem__("browsers", [b for b in r["browsers"] if b["key"] != "edge"]))
        self.assertTrue(any("edge" in p and "neither run nor listed" in p for p in problems), problems)

    def test_a_browser_not_run_needs_a_reason(self):
        def drop_reason(record):
            next(b for b in record["browsers"] if b["key"] == "edge").pop("reason")
        self.assertTrue(any("without a reason" in p for p in self.problems(drop_reason)))

    def test_a_run_browser_needs_rows_and_rows_need_a_run_browser(self):
        def mark_firefox_run(record):
            next(b for b in record["browsers"] if b["key"] == "firefox")["status"] = "run"
        self.assertTrue(any("no rows" in p for p in self.problems(mark_firefox_run)))

        def rename(record):
            for row in record["rows"]:
                row["browser"] = "edge"
        self.assertTrue(any("not marked run" in p for p in self.problems(rename)))

    def test_outside_lookups_must_be_zero_and_consistent(self):
        def one_lookup(record):
            record["host_guard"]["outside_lookups"] = 1
        problems = self.problems(one_lookup)
        self.assertTrue(any("differs from its recorded lists" in p for p in problems))

        def foreign(record):
            record["host_guard"]["foreign_host_requests"] = ["real.example"]
            record["host_guard"]["outside_lookups"] = 1
        problems = self.problems(foreign)
        self.assertTrue(any("not 0" in p for p in problems), problems)

    def test_rows_need_explicit_layers_equal_to_the_configured_set(self):
        def empty(record):
            record["rows"][0]["layers_requested"] = []
        self.assertTrue(any("layers_requested" in p for p in self.problems(empty)))

        def short(record):
            record["rows"][0]["layers_requested"] = ["regex", "ner"]
        self.assertTrue(any("layers_requested" in p for p in self.problems(short)))

        def executed(record):
            record["rows"][0]["layers_executed"] = {"regex": "ok", "ner": "ok"}
        self.assertTrue(any("layers_executed" in p for p in self.problems(executed)))

        def empty_config(record):
            record["layers"] = []
        self.assertTrue(any("layers:" in p for p in self.problems(empty_config)))

    def test_header_scope_and_forbidden_keys(self):
        self.assertTrue(any("missing header field" in p for p in self.problems(lambda r: r.pop("not_established"))))
        self.assertTrue(any("vocabulary" in p for p in self.problems(lambda r: r.__setitem__("scope_label", "LLM-only"))))
        self.assertTrue(any("scope_label" in p for p in self.problems(lambda r: r["rows"][0].__setitem__("scope_label", "x"))))
        self.assertTrue(any("forbidden prompt-bearing key" in p for p in self.problems(lambda r: r["rows"][0].__setitem__("text", "x"))))

    def test_both_arms_must_be_checked_against_one_semantic_artifact(self):
        def differ(record):
            record["semantic_model"]["detector_artifact_checksum"] = "other"
        self.assertTrue(any("semantic_model" in p for p in self.problems(differ)))

        def missing(record):
            record["semantic_model"]["e2e_artifact_checksum"] = None
            record["semantic_model"]["detector_artifact_checksum"] = None
        self.assertTrue(any("semantic_model" in p for p in self.problems(missing)))

    def test_warn_masking_must_be_recorded_off(self):
        def on(record):
            record["settings"]["warn_masking"] = True
        self.assertTrue(any("warn_masking" in p for p in self.problems(on)))

    def test_warn_masking_is_derived_from_the_observed_dispositions(self):
        self.assertEqual(self.record["settings"]["warn_masking"], False)
        self.assertEqual(self.record["settings"]["masked_request_handed_off_rows"], 0)
        rows = [dict(r) for r in self.rows]
        rows[0]["request_disposition"] = "MASKED_REQUEST_HANDED_OFF"
        masked = rep.build_record(rows, {}, make_plan(rows), make_meta(), "20261201", detector_meta=DETECTOR_META)
        self.assertTrue(masked["settings"]["warn_masking"])
        self.assertTrue(any("masked hand-off" in p for p in rep.check_record(masked)))

        def forged(record):
            record["rows"][0]["request_disposition"] = "MASKED_REQUEST_HANDED_OFF"
        self.assertTrue(any("do not re-derive" in p for p in self.problems(forged)))

    def test_a_prompt_key_in_a_late_row_is_found(self):
        def late(record):
            record["rows"][-1]["text"] = "x"
        self.assertTrue(any("forbidden prompt-bearing key" in p for p in self.problems(late)))

    def test_rows_with_missing_fields_are_reported(self):
        self.assertTrue(any("missing fields" in p for p in self.problems(lambda r: r["rows"][0].pop("payload_intact"))))

    def test_attended_rows_are_required_and_disagreements_are_reported(self):
        self.assertTrue(any("no attended rows" in p for p in self._attended(self.record)))
        extra = [row_with("s0", "baseline", "BLOCK", detector="BLOCK", attended=True),
                 row_with("s0", "v1", "BLOCK", "unicode", detector="BLOCK", attended=True),
                 row_with("s9", "v1", "ALLOW", "unicode", attended=True)]
        record, rows = make_record(extra)
        self.assertEqual(self._attended(record), [])
        report = rep.attended_report(record["rows"])
        self.assertEqual(report["attended_rows"], 3)
        kinds = {(d["seed_id"], d["variant"]): d["kind"] for d in report["disagreements"]}
        self.assertEqual(kinds, {("s0", "v1"): "different_action", ("s9", "v1"): "no_headless_row"})

    @staticmethod
    def _attended(record):
        return rep.check_record(record, None, require_attended=True)


class CommandLineTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rep.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_check_exits_zero_on_a_good_record_and_one_on_a_bad_one(self):
        record, _ = make_record()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "e2e-evasion-20261201.json"
            path.write_text(rep.dumps_record(record), encoding="utf-8", newline="\n")
            path.with_suffix(".md").write_text(rep.render_markdown(record), encoding="utf-8", newline="\n")
            code, out, _ = self.run_main(["--check", str(path)])
            self.assertEqual(code, 0, out)
            code, _, _ = self.run_main(["--check", str(path), "--require-attended"])
            self.assertEqual(code, 1)
            bad = copy.deepcopy(record)
            bad["host_guard"]["outside_lookups"] = 3
            path.write_text(rep.dumps_record(bad), encoding="utf-8", newline="\n")
            code, _, err = self.run_main(["--check", str(path)])
            self.assertEqual(code, 1)
            self.assertIn("outside_lookups", err)

    def test_build_writes_a_record_that_checks(self):
        rows, _, _ = stage3_fixture()
        detector = {f"{r['seed_id']}::{r['variant']}": {"action": r["detector_level"]["action"], "failed_closed": False,
                                                        "layer_status": {n: "ok" for n in FULL}} for r in rows}
        for r in rows:
            r["detector_level"] = None
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "rows.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            (tmp / "det.jsonl").write_text("\n".join(json.dumps(dict(v, vid=k)) for k, v in detector.items()) + "\n", encoding="utf-8")
            (tmp / "plan.json").write_text(json.dumps(make_plan(rows)), encoding="utf-8")
            (tmp / "meta.json").write_text(json.dumps(make_meta()), encoding="utf-8")
            (tmp / "dm.json").write_text(json.dumps(DETECTOR_META), encoding="utf-8")
            code, _, _ = self.run_main(["--build", "--rows", str(tmp / "rows.jsonl"), "--detector", str(tmp / "det.jsonl"),
                                        "--plan", str(tmp / "plan.json"), "--run-meta", str(tmp / "meta.json"), "--date", "20261201",
                                        "--detector-meta", str(tmp / "dm.json"), "--out-json", str(tmp / "r.json"), "--out-md", str(tmp / "r.md"),
                                        "--out-summary", str(tmp / "s.md")])
            self.assertEqual(code, 0)
            code, out, err = self.run_main(["--check", str(tmp / "r.json")])
            self.assertEqual(code, 0, err)
            self.assertIn("E2EEVADE-20261201", (tmp / "s.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
