"""Unit tests of ``evaluation/v3_update_attacks_report.py`` (stage 13c-1).

The committed row manifest is checked as it is. Records and rows are built here from synthetic states, so no weights, keys or text
are needed.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import v3_update_attacks_report as report  # noqa: E402

SHA = "a" * 64
OTHER = "b" * 64


def state(current: str = SHA, *, served: str | None = None, publications: int = 1, sequence: int = 1, mark=None) -> dict:
    return {
        "store_current": current,
        "versions_count": 2,
        "publications_count": publications,
        "max_sequence": sequence,
        "served_manifest": current if served is None else served,
        "client_mark": mark,
    }


def row_of(entry: dict, leg: str = "ci", **changes) -> dict:
    expected = entry["expected"]
    before = state()
    after = state() if expected in ("rejected_unchanged", "noop_unchanged") else state(OTHER, publications=2, sequence=2)
    row = {
        "id": entry["id"],
        "attack_class": entry["attack_class"],
        "variant": "a variant",
        "combined": False,
        "chain": entry["chain"],
        "leg": leg,
        "surface": "client" if entry["surface"] == "client" else "commit",
        "identity": "trainer-s13c (trainer)",
        "scope_label": report.SCOPE_LABEL,
        "attempted": {"request_id": "r", "model_id": "privoke-v3-efficient", "expected_base": SHA, "candidate_sha": OTHER, "mutation": "m"},
        "expected": expected,
        "observed": {"grpc_code": "OK", "receipt_status": "rejected", "receipt_reason": "stale_base", "message": ""},
        "rejecting_check": {"file": "store.rs", "symbol": "commit", "reason": "stale_base"},
        "active_before": before,
        "active_after": after,
        "orphan_blobs": 1,
        "property_met": True,
        "not_run_reason": None,
    }
    if expected in ("noop_unchanged", "accepted_by_design"):
        row["observed"] = {"grpc_code": "OK", "receipt_status": "applied", "receipt_reason": "", "message": ""}
    row.update(changes)
    return row


class ManifestTest(unittest.TestCase):
    def test_the_committed_manifest_is_sound(self):
        manifest = report.load_manifest()
        self.assertEqual(report.check_manifest(manifest), [])
        self.assertEqual(len(manifest), 50)
        wire_false = {row["id"] for row in manifest if not row["wire_path"]}
        self.assertEqual(
            wire_false,
            {"C10a", "C10b", "C10c", "C10d", "C10e", "C9e", "C9f-serve", "C9f-client", "C2c", "C2d", "C4f", "CS1", "CS2", "CS3", "CS4"},
        )
        ci_only_wire = {row["id"] for row in manifest if row["wire_path"] and row["legs"] == ["ci"]}
        self.assertEqual(ci_only_wire, {"C1b", "C1d"})
        by_id = {row["id"]: row for row in manifest}
        self.assertEqual(by_id["C1d"]["chain"], "no_publisher")
        self.assertEqual(by_id["C2a"]["expected"], "noop_unchanged")
        self.assertEqual({by_id[k]["expected"] for k in ("C10c", "C10d", "C10e")}, {"applied_recovered"})
        self.assertEqual({by_id[k]["expected"] for k in ("C10a", "C10b")}, {"rejected_unchanged"})
        self.assertEqual(by_id["C11g"]["expected"], "accepted_by_design")
        self.assertEqual({row["surface"] for row in manifest if row["id"] in ("CS2", "CS3", "CS4", "C2c", "C2d", "C4f", "C9f-client")}, {"client"})
        self.assertEqual(by_id["CS1"]["surface"], "model-streaming")

    def test_a_malformed_manifest_is_refused(self):
        manifest = report.load_manifest()
        broken = copy.deepcopy(manifest)
        broken[0]["legs"] = ["ci", "container"]
        broken[0]["ci_only_reason"] = "a reason without being CI-only"
        self.assertTrue(any("ci_only_reason" in error for error in report.check_manifest(broken)))
        broken = copy.deepcopy(manifest)
        broken[1]["extra"] = 1
        self.assertTrue(report.check_manifest(broken))
        broken = copy.deepcopy(manifest)
        broken.append(copy.deepcopy(broken[0]))
        self.assertTrue(any("twice" in error for error in report.check_manifest(broken)))
        broken = [row for row in manifest if row["attack_class"] != 7]
        self.assertTrue(any("attack class 7" in error for error in report.check_manifest(broken)))
        broken = copy.deepcopy(manifest)
        next(row for row in broken if row["id"] == "C10a")["legs"] = ["ci", "container"]
        self.assertTrue(report.check_manifest(broken))


class AllocationTest(unittest.TestCase):
    def item(self, **changes) -> dict:
        item = {
            "request_id": "s13c-r1",
            "cycle": 0,
            "model_id": "privoke-v3-efficient",
            "stage": "heads",
            "attempt": 0,
            "sampler": report.SAMPLERS[0],
            "seed": 20261124,
            "expected_base": SHA,
            "source_commitment": OTHER,
            "state": "allocated",
        }
        item.update(changes)
        return item

    def test_a_well_formed_allocation_passes(self):
        self.assertEqual(report.check_allocations([self.item(), self.item(request_id="r2", stage="full_encoder", attempt=1)]), [])

    def test_unknown_and_missing_fields_and_bad_values_are_refused(self):
        self.assertTrue(report.check_allocations({}))
        self.assertTrue(report.check_allocations([self.item(candidate=None)]))
        missing = self.item()
        del missing["seed"]
        self.assertTrue(report.check_allocations([missing]))
        for bad in (
            {"state": "accepted"},
            {"stage": "everything"},
            {"sampler": "another_release"},
            {"model_id": "privoke-v3-unknown"},
            {"seed": 2**32},
            {"seed": -1},
            {"seed": True},
            {"expected_base": "ABC"},
            {"source_commitment": 7},
            {"request_id": ""},
            {"request_id": "x" * 201},
            {"cycle": -1},
        ):
            self.assertTrue(report.check_allocations([self.item(**bad)]), bad)

    def test_the_command_line_validates_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            good, bad = Path(directory, "good.json"), Path(directory, "bad.json")
            good.write_text(json.dumps([self.item()]), encoding="utf-8")
            bad.write_text(json.dumps([self.item(state="accepted")]), encoding="utf-8")
            self.assertEqual(report.main(["--validate-allocations", str(good)]), 0)
            self.assertEqual(report.main(["--validate-allocations", str(bad)]), 1)


class PropertyTest(unittest.TestCase):
    def setUp(self):
        self.manifest = report.load_manifest()
        self.by_id = {row["id"]: row for row in self.manifest}

    def row(self, ident: str, **changes) -> dict:
        return row_of(self.by_id[ident], **changes)

    def test_unchanged_is_the_authority_and_not_the_blob_directory(self):
        row = self.row("C1a")
        self.assertIs(report.derive_property(row), True)
        for key, value in (("store_current", OTHER), ("versions_count", 3), ("publications_count", 2), ("max_sequence", 2), ("served_manifest", OTHER)):
            changed = copy.deepcopy(row)
            changed["active_after"][key] = value
            self.assertIs(report.derive_property(changed), False, key)
        # Orphan blobs are reported and never counted as a change.
        row["orphan_blobs"] = 9
        self.assertEqual(report.check_row(row, self.by_id), [])

    def test_the_client_mark_is_part_of_unchanged(self):
        row = self.row("C2c")
        row["active_before"]["client_mark"] = {"sequence": 2, "manifest_sha": SHA}
        row["active_after"]["client_mark"] = {"sequence": 2, "manifest_sha": SHA}
        self.assertIs(report.derive_property(row), True)
        row["active_after"]["client_mark"] = {"sequence": 1, "manifest_sha": SHA}
        self.assertIs(report.derive_property(row), False)

    def test_an_at_rest_fault_may_fail_closed(self):
        row = self.row("C9f-serve")
        row["active_after"]["served_manifest"] = "refused:DATA_LOSS"
        self.assertIs(report.derive_property(row), True)
        row["active_after"]["served_manifest"] = "refused:UNAVAILABLE"
        self.assertIs(report.derive_property(row), False)
        other = self.row("C1a")
        other["active_after"]["served_manifest"] = "refused:DATA_LOSS"
        self.assertIs(report.derive_property(other), False)

    def test_applied_rows_need_the_authority_and_the_served_version_to_agree(self):
        for ident in ("C10c", "C11g"):
            row = self.row(ident)
            self.assertIs(report.derive_property(row), True, ident)
            row["active_after"]["served_manifest"] = SHA
            self.assertIs(report.derive_property(row), False, ident)

    def test_a_race_loser_leaves_one_application_and_no_publication(self):
        row = self.row("C1b")
        row["race"] = {"winner_request": "x", "loser_request": "y", "applied": 1}
        row["active_after"] = state(OTHER, publications=2, sequence=2)
        self.assertIs(report.derive_property(row), True)
        row["race"]["applied"] = 2
        self.assertIs(report.derive_property(row), False)

    def test_a_row_names_its_check_and_both_states(self):
        row = self.row("C1a")
        row["rejecting_check"]["symbol"] = ""
        self.assertTrue(report.check_row(row, self.by_id))
        row = self.row("C1a")
        del row["active_before"]["store_current"]
        self.assertTrue(report.check_row(row, self.by_id))
        row = self.row("C1a", property_met=False)
        self.assertTrue(any("property_met" in error for error in report.check_row(row, self.by_id)))
        row = self.row("C1a", expected="noop_unchanged")
        self.assertTrue(any("expected" in error for error in report.check_row(row, self.by_id)))
        stray = self.row("C1a", id="NOPE")
        self.assertTrue(any("no manifest id" in error for error in report.check_row(stray, self.by_id)))

    def test_observed_is_tied_to_expected(self):
        def errors(ident: str, **observed) -> list[str]:
            row = self.row(ident)
            row["observed"] = {**row["observed"], **observed}
            return report.check_observed(row)

        self.assertEqual(errors("C1a"), [])
        self.assertTrue(errors("C1a", receipt_status="applied"))
        self.assertEqual(errors("C2a"), [])
        self.assertTrue(errors("C2a", receipt_status="rejected"))
        self.assertTrue(errors("C11g", receipt_status="rejected"))
        self.assertTrue(errors("C11g", receipt_status=""))
        # A staging row that is a no-op has no receipt, and must be an OK call.
        stage = self.row("C3b", surface="stage", observed={"grpc_code": "OK", "receipt_status": "", "receipt_reason": "", "message": ""})
        self.assertEqual(report.check_observed(stage), [])
        stage["observed"]["grpc_code"] = "INVALID_ARGUMENT"
        self.assertTrue(report.check_observed(stage))
        # The receipt reason must be the one the row names as its rejecting check.
        self.assertTrue(errors("C1a", receipt_reason="guard_rejected"))
        self.assertEqual(errors("C1a", receipt_reason=""), [])
        mismatched = self.row("C1a", observed={"grpc_code": "OK", "receipt_status": "rejected", "receipt_reason": "drift_exceeded", "message": ""})
        self.assertTrue(any("rejecting check" in error for error in report.check_row(mismatched, self.by_id)))

    def test_a_row_that_did_not_run_gives_its_reason(self):
        row = self.row("C8b", leg="container", not_run_reason="synthetic only", property_met=None)
        self.assertEqual(report.check_row(row, self.by_id), [])
        self.assertTrue(report.check_row(self.row("C8b", not_run_reason="", property_met=None), self.by_id))


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.manifest = report.load_manifest()

    def record(self, rows: list[dict]) -> dict:
        return {
            "schema": report.SCHEMA,
            "study_id": "V3UPDATK-test",
            "chain": {},
            "build": {},
            "host": {},
            "run_dates": [],
            "commands": [],
            "scope_label": report.SCOPE_LABEL,
            "not_established": [],
            "user_actions": [],
            "rows": rows,
            "aggregates": report.aggregates(rows),
        }

    def complete_rows(self) -> list[dict]:
        rows = []
        for entry in self.manifest:
            rows.append(row_of(entry))
            if entry["wire_path"] and entry["legs"] != ["ci"]:
                rows.append(row_of(entry, leg="container"))
        return rows

    def test_a_complete_record_passes(self):
        rows = self.complete_rows()
        self.assertEqual(report.check_record(self.record(rows), self.manifest), [])

    def test_a_manifest_id_without_a_row_and_a_row_without_a_manifest_id_fail(self):
        rows = [row for row in self.complete_rows() if row["id"] != "C3a"]
        self.assertTrue(any("C3a: the manifest id has no row" in error for error in report.check_record(self.record(rows), self.manifest)))
        stray = row_of(self.manifest[0])
        stray["id"] = "C99"
        errors = report.check_record(self.record([*self.complete_rows(), stray]), self.manifest)
        self.assertTrue(any("C99" in error and "no manifest id" in error for error in errors))

    def test_a_wire_variant_needs_a_container_row_or_a_reason(self):
        entry = next(row for row in self.manifest if row["id"] == "C8a")
        rows = [row for row in self.complete_rows() if not (row["id"] == "C8a" and row["leg"] == "container")]
        errors = report.check_record(self.record(rows), self.manifest)
        self.assertTrue(any("C8a" in error and "container row or a not_run_reason" in error for error in errors), errors)
        # A not_run_reason (on any leg) answers it.
        rows.append(row_of(entry, leg="container", not_run_reason="the real leg builds no such candidate", property_met=None))
        self.assertEqual(report.check_record(self.record(rows), self.manifest), [])

    def test_a_container_row_records_the_served_version_or_a_reason(self):
        rows = self.complete_rows()
        container = next(row for row in rows if row["id"] == "C8a" and row["leg"] == "container")
        container["active_after"]["served_manifest"] = None
        container["active_before"]["served_manifest"] = None
        errors = report.check_record(self.record(rows), self.manifest)
        self.assertTrue(any("no served version" in error for error in errors), errors)

    def test_ci_only_rows_need_no_container_row(self):
        rows = [row for row in self.complete_rows() if row["id"] not in ("C1b", "C1d") or row["leg"] == "ci"]
        self.assertEqual(report.check_record(self.record(rows), self.manifest), [])

    def test_a_class_without_a_row_fails(self):
        rows = [row for row in self.complete_rows() if row["attack_class"] != 5]
        errors = report.check_record(self.record(rows), self.manifest)
        self.assertTrue(any("attack class 5: no row" in error for error in errors), errors)

    def test_an_aggregate_that_differs_from_the_rows_fails(self):
        record = self.record(self.complete_rows())
        record["aggregates"]["property_met"] += 1
        self.assertTrue(any("aggregates differ" in error for error in report.check_record(record, self.manifest)))
        record = self.record(self.complete_rows())
        del record["host"]
        self.assertTrue(any("host" in error for error in report.check_record(record, self.manifest)))

    def test_the_aggregates_are_recomputed_from_the_rows(self):
        rows = self.complete_rows()
        totals = report.aggregates(rows)
        self.assertEqual(totals["rows"], len(rows))
        self.assertEqual(totals["rows_not_run"], 0)
        self.assertEqual(totals["property_met"], len(rows))
        self.assertEqual(totals["by_leg"]["ci"], len(self.manifest))
        self.assertEqual(sum(totals["by_attack_class"].values()), len(rows))
        self.assertEqual(totals["orphan_blobs"], len(rows))

    def test_the_command_line_checks_a_record_and_the_ci_rows(self):
        rows = [row_of(entry) for entry in self.manifest]
        with tempfile.TemporaryDirectory() as directory:
            ci = Path(directory, "ci.json")
            ci.write_text(json.dumps(rows), encoding="utf-8")
            self.assertEqual(report.main(["--ci-rows", str(ci)]), 0)
            ci.write_text(json.dumps(rows[:-1]), encoding="utf-8")
            self.assertEqual(report.main(["--ci-rows", str(ci)]), 1)
            ci.write_text(json.dumps([*rows, rows[0]]), encoding="utf-8")
            self.assertEqual(report.main(["--ci-rows", str(ci)]), 1)
            record = Path(directory, "record.json")
            record.write_text(json.dumps(self.record(self.complete_rows())), encoding="utf-8")
            self.assertEqual(report.main(["--check", str(record)]), 0)
            broken = self.record(self.complete_rows())
            broken["rows"][0]["property_met"] = False
            record.write_text(json.dumps(broken), encoding="utf-8")
            self.assertEqual(report.main(["--check", str(record)]), 1)
        self.assertEqual(report.main(["--check-manifest"]), 0)


class AssembleTest(unittest.TestCase):
    """Stage 13c-2: the record is assembled from a header and the rows of the legs, and its Markdown is rendered from it."""

    def setUp(self):
        self.manifest = report.load_manifest()

    def header(self) -> dict:
        return {
            "schema": report.SCHEMA,
            "study_id": "V3UPDATK-test",
            "chain": {"threat": "t", "defense": "d", "experiment": "e", "metric": "m", "evidence": "v"},
            "build": {"branch": "b", "sha": "0" * 40, "clean": True, "update_path": "Rust only"},
            "host": {"os": "test"},
            "run_dates": ["2026-11-26"],
            "commands": ["a command"],
            "scope_label": report.SCOPE_LABEL,
            "not_established": ["n"],
            "user_actions": [],
            "fit_timings": [{"request_id": "r1", "tier": "efficient", "scope": "heads", "wall_seconds": 50.0, "cpus": "8", "outcome": "applied"}],
        }

    def legs(self) -> tuple[list[dict], list[dict]]:
        ci = [row_of(entry) for entry in self.manifest]
        container = [row_of(entry, leg="container") for entry in self.manifest if entry["wire_path"] and entry["legs"] != ["ci"]]
        container[0] = row_of(
            next(entry for entry in self.manifest if entry["id"] == container[0]["id"]), leg="container", not_run_reason="a reason", property_met=None
        )
        return ci, container

    def test_the_observed_label_names_what_happened(self):
        entry = self.manifest[0]
        self.assertEqual(report.observed_label(row_of(entry)), "rejected:stale_base")
        refused = row_of(entry, observed={"grpc_code": "INVALID_ARGUMENT", "receipt_status": "", "receipt_reason": "", "message": "m"})
        self.assertEqual(report.observed_label(refused), "refused:INVALID_ARGUMENT")
        self.assertEqual(report.observed_label(row_of(entry, not_run_reason="r")), "not_run")

    def test_a_record_is_assembled_checked_and_rendered(self):
        ci, container = self.legs()
        with tempfile.TemporaryDirectory() as directory:
            paths = {name: Path(directory, f"{name}.json") for name in ("header", "ci", "container", "record")}
            paths["header"].write_text(json.dumps(self.header()), encoding="utf-8")
            paths["ci"].write_text(json.dumps(ci), encoding="utf-8")
            paths["container"].write_text(json.dumps(container[::-1]), encoding="utf-8")
            markdown = Path(directory, "record.md")
            arguments = ["--assemble", str(paths["header"]), "--rows", str(paths["ci"]), str(paths["container"]), "--out", str(paths["record"])]
            self.assertEqual(report.main([*arguments, "--markdown", str(markdown)]), 0)
            record = json.loads(paths["record"].read_text(encoding="utf-8"))
            self.assertEqual(report.check_record(record, self.manifest), [])
            self.assertEqual(report.main(["--check", str(paths["record"])]), 0)
            self.assertEqual(record["aggregates"]["by_leg"], {"ci": len(ci), "container": len(container)})
            self.assertEqual(record["aggregates"]["property_by_leg"]["container"]["not_run"], 1)
            ids = [row["id"] for row in record["rows"]]
            self.assertEqual(ids[:2], [self.manifest[0]["id"], self.manifest[0]["id"]], "manifest order, then the legs")
            text = markdown.read_text(encoding="utf-8")
            self.assertIn(f"| rows | {len(ci) + len(container)} |", text)
            self.assertIn("## Fit timings", text)
            self.assertIn("| r1 | efficient | heads | 50.0 | 8 | applied |", text)
            # A record that fails the check is not written.
            paths["record"].unlink()
            paths["ci"].write_text(json.dumps(ci[:-1]), encoding="utf-8")
            self.assertEqual(report.main(arguments), 1)
            self.assertFalse(paths["record"].exists())


if __name__ == "__main__":
    unittest.main()
