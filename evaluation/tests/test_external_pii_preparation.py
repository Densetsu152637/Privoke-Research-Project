"""Preparation integrity tests use only synthetic rows; no source downloads."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "prepare-external-pii-study.py"
spec = importlib.util.spec_from_file_location("external_preparation", PATH)
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


def nemotron(n=1, text="Alice record", spans=None):
    return {"uid": f"{n:032x}", "text": text, "locale": "us",
            "spans": [{"start": 0, "end": 5, "label": "PERSON", "text": text[:5]}] if spans is None else spans,
            "domain": "test", "document_type": "note", "document_format": "text", "document_description": "test note"}


def meddies(n=1, text="Alice clinic", label=None):
    return {"raw": text, "language": "english", "label": {"PERSON": [text[:5]]} if label is None else label,
            "document_type": "note", "document_label": str(n), "text_format": "text", "edge_case": False}


def nemotron_pair(n=1, text="Alice record"):
    us = nemotron(n, text)
    intl = nemotron(n, text + " international")
    intl["locale"] = "intl"
    return [us, intl]


def audit():
    sources = []
    for source, (repo, revision, config, count) in PREP.PINS.items():
        path = ("data" if source == "nemotron-pii" else "english") + "/train-00000-of-00001.parquet"
        fields = ["schema", "uid", "text", "spans", "locale"] if source == "nemotron-pii" else [
            "schema", "language", "document_type", "document_label", "text_format", "edge_case", "raw", "label"]
        sources.append({"repo_id": repo, "revision": revision, "config": config, "split": "train",
                        "license": "cc-by-4.0" if source == "nemotron-pii" else "cc-by-nc-4.0",
                        **{k: "a" * 64 for k in ("card_sha256", "license_source_sha256", "revision_metadata_sha256", "file_tree_metadata_sha256")},
                        "file": {"path": path, "parquet_url": f"https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}",
                                 "row_count": count, "schema_fields": fields, "parquet_size_bytes": 123, "lfs_sha256": "b" * 64}})
    return {"schema_version": 1, "status": "audited", "audit_script_sha256": "a" * 64, "sources": sources}


class ExternalPreparationTests(unittest.TestCase):
    def test_parent_alias_excludes_whole_document(self):
        uid = f"{17:032x}"
        protected = PREP.row_keys("piimb:nemotron-pii:" + uid + "_s15", "nemotron-pii:" + uid, "different sentence")
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", nemotron_pair(17), protected, expected_count=2)
                pool.eliminate_conflicts()
                self.assertEqual(pool.counts["nemotron-pii"]["protected_overlap"], 2)
                self.assertEqual(pool.db.execute("SELECT SUM(eligible) FROM rows").fetchone()[0], 0)
            finally:
                pool.close()

    def test_all_spans_bounds_and_exact_matches(self):
        for span in ({"start": True, "end": 5, "label": "PERSON"},
                     {"start": 0, "end": 999, "label": "PERSON"},
                     {"start": 0, "end": 5, "label": "PERSON", "text": "Wrong"},
                     {"start": 0, "end": 5}, {"start": 0, "end": 5, "label": "PERSON", "type": "OTHER"}):
            with self.subTest(span=span), self.assertRaises(PREP.ExcludeRow):
                PREP.nemotron_annotations(nemotron(spans=[span]))
        spans, categories = PREP.nemotron_annotations(nemotron())
        self.assertEqual(categories, ["PERSON"])
        self.assertEqual(spans[0]["text"], "Alice")

    def test_meddies_mapping_all_entities_must_match(self):
        for labels in ({"PERSON": ["Alice", "Absent"]}, {"PERSON": [7]}, {"PERSON": {"value": "Alice"}}, "invalid"):
            with self.subTest(labels=labels), self.assertRaises(PREP.ExcludeRow):
                PREP.meddies_annotations(meddies(label=labels))
        self.assertEqual(PREP.meddies_annotations(meddies(label='{"PERSON":"Alice"}'))[1], ["PERSON"])
        self.assertEqual(PREP.meddies_annotations(meddies(label="{'PERSON':['Alice']}"))[1], ["PERSON"])

    def test_empty_annotations_are_unknown_not_negatives(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", [nemotron(spans=[])], PREP.empty_keys(), expected_count=1)
                self.assertEqual(pool.db.execute("SELECT state,eligible,payload FROM rows").fetchone(), ("unknown", 0, None))
                self.assertEqual(pool.counts["nemotron-pii"]["unknown_empty_annotation"], 1)
            finally:
                pool.close()

    def test_late_ambiguous_uid_and_conflicting_duplicate_exclude_all(self):
        rows = [nemotron(1, "Alice first"), nemotron(2, "Alice clean"), *nemotron_pair(3, "Alice late")]
        rows += [nemotron(1, "Alice other"), nemotron(2, "Alice clean", spans=[])]
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", iter(rows), PREP.empty_keys(), expected_count=6)
                pool.eliminate_conflicts()
                self.assertEqual(pool.db.execute("SELECT COUNT(*) FROM rows WHERE eligible=1").fetchone()[0], 2)
                self.assertEqual(pool.counts["nemotron-pii"]["verified_variant_parents"], 1)
                self.assertEqual(pool.counts["nemotron-pii"]["excluded_variant_parents"], 2)
                self.assertEqual(pool.counts["nemotron-pii"]["unverified_native_variant_parent_rows"], 3)
            finally:
                pool.close()

    def test_generated_meddies_id_not_group_ordinal(self):
        row = meddies()
        first = PREP.source_identity("meddies-pii", row, 1)
        second = PREP.source_identity("meddies-pii", row, 2)
        self.assertNotEqual(first[0], second[0])
        self.assertEqual(first[1], second[1])
        self.assertEqual(first, PREP.source_identity("meddies-pii", row, 1))
        with self.assertRaises(PREP.ExcludeRow):
            PREP.source_identity("meddies-pii", {k: v for k, v in row.items() if k != "edge_case"}, 1)

    def test_nemotron_geographic_locale_preserved_not_used_as_language(self):
        for locale in ("us", "intl", None, "unknown-region"):
            row = nemotron()
            row["locale"] = locale
            identity = PREP.source_identity("nemotron-pii", row, 0)
            candidate = PREP.serialize_candidate("nemotron-pii", row, 0, identity)
            self.assertEqual(candidate["language"], "en")
            self.assertEqual(candidate["language_provenance"], "pinned_source_card_english")
            self.assertEqual(candidate["locale"], locale)

    def test_verified_locale_variants_unique_ids_same_parent_and_no_split(self):
        rows = nemotron_pair(12)
        identities = [PREP.source_identity("nemotron-pii", row, ordinal) for ordinal, row in enumerate(rows)]
        self.assertNotEqual(identities[0][0], identities[1][0])
        self.assertEqual(identities[0][1], f"nemotron-pii:{12:032x}")
        self.assertEqual(identities[0][1], identities[1][1])
        self.assertEqual(identities[0], PREP.source_identity("nemotron-pii", rows[0], 999))
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", rows, PREP.empty_keys(), expected_count=2)
                pool.eliminate_conflicts()
                self.assertEqual(pool.counts["nemotron-pii"]["verified_variant_parents"], 1)
                pool.assign_groups(heldout_cap=2)
                parts = pool.dedupe_and_sample(caps={"nemotron-pii": 2, "meddies-pii": 1}, heldout_cap=2)
                self.assertEqual(len(parts["nemotron-pii_heldout"]), 2)
                self.assertEqual(parts["train"], [])
                PREP.recheck_partitions(parts, PREP.empty_keys())
            finally:
                pool.close()

    def test_unverified_parent_shapes_or_annotations_exclude_all_variants(self):
        cases = {}
        cases["single"] = nemotron_pair()[:1]
        cases["third_variant"] = nemotron_pair() + [nemotron(1, "Alice third")]
        cases["duplicate_locale"] = nemotron_pair()
        cases["duplicate_locale"][1]["locale"] = "us"
        cases["unknown_locale"] = nemotron_pair()
        cases["unknown_locale"][1]["locale"] = "other"
        cases["unknown_annotation"] = nemotron_pair()
        cases["unknown_annotation"][1]["spans"] = []
        cases["invalid_annotation"] = nemotron_pair()
        cases["invalid_annotation"][1]["spans"][0]["text"] = "Mismatch"
        for field in ("domain", "document_type", "document_format", "document_description"):
            cases[field + "_mismatch"] = nemotron_pair()
            cases[field + "_mismatch"][1][field] = "Other"
            cases[field + "_missing"] = nemotron_pair()
            for row in cases[field + "_missing"]:
                row.pop(field)
        for name, rows in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
                try:
                    pool.scan("nemotron-pii", rows, PREP.empty_keys(), expected_count=len(rows))
                    pool.eliminate_conflicts()
                    self.assertEqual(pool.counts["nemotron-pii"]["excluded_variant_parents"], 1)
                    self.assertEqual(pool.db.execute("SELECT SUM(eligible) FROM rows").fetchone()[0], 0)
                finally:
                    pool.close()

    def test_same_normalized_text_conflicting_category_annotations_still_excluded(self):
        rows = nemotron_pair()
        rows[1]["text"] = rows[0]["text"]
        rows[1]["spans"][0]["label"] = "OTHER"
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", rows, PREP.empty_keys(), expected_count=2)
                pool.eliminate_conflicts()
                self.assertEqual(pool.db.execute("SELECT SUM(eligible) FROM rows").fetchone()[0], 0)
                self.assertEqual(pool.counts["nemotron-pii"]["conflicting_annotation_variants"], 2)
            finally:
                pool.close()

    def test_group_assignment_caps_and_global_crosssource_dedupe(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("nemotron-pii", nemotron_pair(1, "Alice duplicate") + nemotron_pair(2, "Alice two") + nemotron_pair(3, "Alice three"), PREP.empty_keys(), expected_count=6)
                pool.scan("meddies-pii", [meddies(1, "Alice duplicate"), meddies(2, "Alice med two"), meddies(3, "Alice med three")], PREP.empty_keys(), expected_count=3)
                pool.eliminate_conflicts()
                pool.assign_groups(heldout_cap=2)
                partitions = pool.dedupe_and_sample(caps={"nemotron-pii": 2, "meddies-pii": 2}, heldout_cap=2)
                PREP.recheck_partitions(partitions, PREP.empty_keys())
                selected = [r for rows in partitions.values() for r in rows]
                self.assertEqual(len({r["text_key"] for r in selected}), len(selected))
                self.assertLessEqual(len(partitions["train"]), 4)
                self.assertEqual(sum(c["global_normalized_text_duplicate"] for c in pool.counts.values()), 1)
                self.assertTrue(all(r["expected_has_pii"] is True for r in selected))
            finally:
                pool.close()

    def test_whole_group_too_large_never_splits(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                pool.scan("meddies-pii", [meddies(1, "Alice one"), meddies(1, "Alice two")], PREP.empty_keys(), expected_count=2)
                pool.eliminate_conflicts()
                assignment = pool.assign_groups(heldout_cap=1)
                parts = pool.dedupe_and_sample(caps={"nemotron-pii": 1, "meddies-pii": 1}, heldout_cap=1)
                self.assertEqual(assignment["meddies-pii"]["heldout_assigned_groups"], 0)
                self.assertEqual(parts["meddies-pii_heldout"], [])
                self.assertEqual(parts["train"], [])
            finally:
                pool.close()

    def test_actual_fullscan_count_and_schema_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            pool = PREP.CandidatePool(Path(directory) / "pool.sqlite")
            try:
                with self.assertRaises(ValueError):
                    pool.scan("nemotron-pii", [nemotron()], PREP.empty_keys(), expected_count=2)
                with self.assertRaises(ValueError):
                    pool.scan("nemotron-pii", [nemotron()], PREP.empty_keys(), expected_count=1, schema_fields=["schema", "uid", "text", "spans"])
            finally:
                pool.close()

    def test_audit_exact_pins_split_paths_schema_and_license(self):
        self.assertEqual(set(PREP.validate_audit(audit())), set(PREP.PINS))
        for field, wrong in (("revision", "c" * 40), ("config", "mixed"), ("split", "test"), ("license", "unknown")):
            value = audit()
            value["sources"][0][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                PREP.validate_audit(value)
        for field, wrong in (("row_count", 1), ("path", "data/test.parquet"), ("lfs_sha256", ""), ("schema_fields", ["raw"])):
            value = audit()
            value["sources"][1]["file"][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                PREP.validate_audit(value)

    def test_protocol_mismatch_and_existing_output_refused_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            protocol = directory / "protocol.md"
            protocol.write_text("prospective", encoding="utf-8")
            receipt = directory / "audit.json"
            receipt.write_text(json.dumps(audit()), encoding="utf-8")
            args = SimpleNamespace(output=directory / "new", source_revision="a" * 40,
                                   protocol_file=protocol, protocol_sha256="b" * 64, source_audit=receipt)
            with patch.object(PREP, "source_rows", side_effect=AssertionError("no data reads")):
                with self.assertRaisesRegex(ValueError, "protocol"):
                    PREP.prepare(args)
                args.output.mkdir()
                with self.assertRaisesRegex(ValueError, "existing"):
                    PREP.prepare(args)

    def test_references_read_only_named_train_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            expected = {}
            for part in ("train", "validation"):
                row = {"id": part, "group_id": part, "text": part, "text_key": part, "expected_has_pii": part == "train"}
                data = (json.dumps(row) + "\n").encode()
                (directory / (part + ".jsonl")).write_bytes(data)
                expected[part] = (1, PREP.hashlib.sha256(data).hexdigest())
            # Traps are intentionally malformed; preparation never attempts to parse them.
            (directory / "development.jsonl").write_text("DO NOT READ")
            (directory / "final.jsonl").write_text("DO NOT READ")
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            with patch.object(PREP, "REFERENCE", expected):
                rows, raw = PREP.read_references(directory)
                self.assertEqual(set(rows), {"train", "validation"})
                self.assertEqual(raw["train"], before["train.jsonl"])
            self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
            with self.assertRaisesRegex(ValueError, "digest"):
                PREP.read_references(directory)

    def test_final_overlap_recheck_is_fail_closed(self):
        item = PREP.serialize_candidate("nemotron-pii", nemotron(), 0, PREP.source_identity("nemotron-pii", nemotron(), 0))
        for parts, excluded in (({"train": [item]}, PREP.row_keys(item["id"], item["group_id"], "other")),
                                ({"train": [item], "heldout": [item]}, PREP.empty_keys())):
            with self.assertRaises(ValueError):
                PREP.recheck_partitions(parts, excluded)

    def test_original_selection_opaque_and_exact_aggregate_pins(self):
        examples = [SimpleNamespace(text=f"Protected unique text {n}", metadata={
            "example_id": f"piimb:test:{n}", "group_id": f"test:group:{n % 929}"}) for n in range(1000)]
        loaded = SimpleNamespace(examples=examples, population_scan_complete=True, rows_seen=150022,
                                 eligible_rows=107488, duplicate_rows=15354,
                                 population_label_counts={"pii": 60418, "clean": 47070},
                                 selected_label_counts={"pii": 500, "clean": 500}, sampling_seed=3102026,
                                 sampling_strategy="balanced", exclusions={"conflicting_duplicate_label_rows": 598,
                                                                            "non_english_language_rows": 27180})
        source = SimpleNamespace(revision=PREP.PIIMB_PIN)
        result, keys = PREP.protected_index(source, loaded)
        encoded = PREP.canonical(result)
        self.assertNotIn("Protected unique text", encoded)
        self.assertNotIn("piimb:test:", encoded)
        self.assertEqual(len(result["records"]), 1000)
        self.assertEqual(len(keys["groups"]), 929)
        self.assertTrue(all(set(r) == {"id_sha256", "canonical_group_sha256", "normalized_text_sha256", "text_sha256"} for r in result["records"]))
        loaded.duplicate_rows -= 1
        with self.assertRaisesRegex(ValueError, "aggregates"):
            PREP.protected_index(source, loaded)
        with patch.object(PREP, "LOADER_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "loader code"):
                PREP.reproduce_protection()

    def test_full_preparation_preserves_reference_bytes_and_manifest_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            references = directory / "reference"
            references.mkdir()
            original, expected = {}, {}
            for part in ("train", "validation"):
                row = {"id": part, "group_id": part, "text": part, "text_key": part, "expected_has_pii": part == "train"}
                original[part] = (json.dumps(row, indent=None) + "\n").encode()
                (references / (part + ".jsonl")).write_bytes(original[part])
                expected[part] = (1, PREP.hashlib.sha256(original[part]).hexdigest())
            (references / "development.jsonl").write_text("forbidden malformed file")
            (references / "final.jsonl").write_text("forbidden malformed file")
            protocol = directory / "protocol.md"
            protocol.write_bytes(b"fixed prospective protocol\n")
            bootstrap = directory / "bootstrap.py"
            bootstrap.write_text("def training_samples():\n    return [(f'anchor {i}', None) for i in range(43)]\n")
            pins = {source: (repo, revision, config, 6 if source == "nemotron-pii" else 3) for source, (repo, revision, config, _) in PREP.PINS.items()}
            with patch.object(PREP, "PINS", pins):
                receipt = audit()
                source_audit = directory / "audit.json"
                source_audit.write_text(json.dumps(receipt, indent=2) + "\n")
                output = directory / "evaluation/results/new"
                args = SimpleNamespace(output=output, source_revision="c" * 40, protocol_file=protocol,
                                       protocol_sha256=PREP.sha(protocol), source_audit=source_audit,
                                       prepared_reference=references, bootstrap_source=bootstrap)
                supplied = {"nvidia/Nemotron-PII": [row for n in (1, 2, 3) for row in nemotron_pair(n, f"Alice nem {n}")],
                            "Meddies/meddies-pii": [meddies(n, f"Alice med {n}") for n in (1, 2, 3)]}
                # The immutable audit schema is checked against these synthetic complete schemas.
                for entry in receipt["sources"]:
                    entry["file"]["schema_fields"] = ["schema", *supplied[entry["repo_id"]][0].keys()]
                source_audit.write_text(json.dumps(receipt, indent=2) + "\n")
                with patch.object(PREP, "ROOT", directory), patch.object(PREP, "REFERENCE", expected), \
                     patch.object(PREP, "HELDOUT_CAP", 2), patch.object(PREP, "CAPS", {"nemotron-pii": 4, "meddies-pii": 2}), \
                     patch.object(PREP, "reproduce_protection", return_value=({"aggregate": {"selected": 1000}, "sorted_records_sha256": "a" * 64}, PREP.empty_keys())), \
                     patch.object(PREP, "source_rows", side_effect=lambda entry: iter(supplied[entry["repo_id"]])), \
                     patch.object(PREP, "sha", side_effect=lambda path: "a" * 64 if str(path).endswith("training_data.py") else PREP.hashlib.sha256(Path(path).read_bytes()).hexdigest()):
                    manifest = PREP.prepare(args)
                self.assertEqual(manifest["status"], "prepared")
                self.assertEqual(manifest["rows"], {"train": 6, "validation": 1, "nemotron_heldout": 2, "meddies_heldout": 2})
                self.assertEqual((output / "validation.jsonl").read_bytes(), original["validation"])
                self.assertTrue((output / "train.jsonl").read_bytes().startswith(original["train"]))
                self.assertEqual(manifest["prepared_reference"]["train_bytes"], len(original["train"]))
                self.assertEqual((output / "source-audit.json").read_bytes(), source_audit.read_bytes())
                for part, filename in manifest["partition_files"].items():
                    self.assertEqual(manifest["partition_sha256"][part], PREP.sha(output / filename))
                self.assertEqual((references / "train.jsonl").read_bytes(), original["train"])


if __name__ == "__main__":
    unittest.main()
