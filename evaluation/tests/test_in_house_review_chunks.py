"""Synthetic confinement, authenticated assembly and exclusive-file checks."""
from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "evaluation"), str(ROOT / "shared/python")]
from privoke_eval import in_house_review_chunks as chunks  # noqa: E402
from test_in_house_dual_review import _pool, _response  # noqa: E402


def fixture(size=1):
    pool = _pool()
    packages = b"".join(chunks.canonical({
        "review_id": p.review_id, "text": p.text, "text_sha256": p.text_sha256,
        "rubric_sha256": p.rubric_sha256,
        "native_spans": [{"entity_type": s.entity_type, "start": s.start, "end": s.end} for s in p.native_spans],
    }) + b"\n" for p in pool.core.packages)
    rubric = (ROOT / "paper/research/clean-augmentation-rubric.json").read_bytes()
    assignments = {
        "schema_version": 1, "kind": "privoke-in-house-review-assignments-v1",
        "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256,
        "chunk_size": size,
        "sets": {s: {"ensemble_id": "ensemble-" + s,
                     "chunks": [{"index": i, "actor_id": f"actor-{s}-{i}", "producer_id": f"producer-{s}-{i}"}
                                for i in range((pool.core.pool_size + size - 1) // size)]} for s in ("A", "B")},
    }
    assignment_bytes = chunks.canonical(assignments)
    manifest = {key: "a" * 64 for key in chunks._MANIFEST_FIELDS}
    manifest.update(schema_version=1, kind="privoke-in-house-blind-review-preparation-v1",
        status="complete", scope="review_preparation_only", source_revision=pool.core.bindings.source_revision,
        preparation_identity=pool.preparation_identity, review_pool_sha256=pool.review_pool_sha256,
        legacy_pool_sha256=pool.core.pool_sha256, bindings=pool.bindings.to_dict(),
        counts={"pool_size": pool.core.pool_size}, no_allocation=True, no_model_scoring=True,
        not_authorized_for_fitting=True, review_packages_file="review-packages.jsonl",
        review_packages_sha256=chunks.digest(packages), private_review_map_file="private-review-map.jsonl",
        rubric_sha256=chunks.RUBRIC_SHA256, private_directory_mode="0700", private_file_mode="0600", platform="posix",
        parquet_sha256=pool.core.bindings.source_sha256, protocol_sha256=pool.core.bindings.protocol_sha256)
    manifest_bytes = chunks.canonical(manifest)
    trust = chunks.ExportTrust(chunks.digest(manifest_bytes), chunks.digest(packages), chunks.digest(rubric),
        chunks.digest(chunks.canonical(pool.bindings.to_dict())), pool.preparation_identity,
        pool.review_pool_sha256, pool.core.pool_sha256, chunks.digest(assignment_bytes),
        pool.core.bindings.source_revision, pool.core.pool_size)
    exports = chunks.export_review_chunks(manifest_bytes, packages, rubric, assignment_bytes, trust=trust)
    return pool, (manifest_bytes, packages, rubric, assignment_bytes), trust, exports


def submissions(pool, exports, *, ordinary_b_present=False):
    result, claims = {}, {}
    package_map = {p.review_id: p for p in pool.core.packages}
    for export in exports:
        assignment = json.loads(export.assignment)
        responses = []
        for line in export.packages.splitlines():
            package = package_map[json.loads(line)["review_id"]]
            if package.native_spans:
                span = package.native_spans[0]
                response = _response(pool, package, assignment["ensemble_id"], "present", ("IDENTITY",),
                                     (("IDENTITY", span.start, span.end),))
            elif ordinary_b_present and assignment["set_id"] == "B":
                response = _response(pool, package, assignment["ensemble_id"], "present", ("FINANCIAL",),
                                     (("FINANCIAL", 32, 35),))
            else:
                response = _response(pool, package, assignment["ensemble_id"], "absent")
            responses.append(response)
        body = {"schema_version": 1, "kind": "privoke-in-house-review-chunk-responses-v1",
                "assignment_sha256": chunks.digest(export.assignment),
                **{k: assignment[k] for k in ("set_id", "ensemble_id", "actor_id", "producer_id")},
                "blinding": {"no_private_map": True, "no_peer_judgments": True}, "responses": responses}
        body_bytes = chunks.canonical(body)
        receipt = {"schema_version": 1, "kind": "privoke-in-house-review-producer-receipt-v1",
                   **{k: assignment[k] for k in ("actor_id", "producer_id")},
                   "assignment_sha256": chunks.digest(export.assignment), "response_sha256": chunks.digest(body_bytes)}
        receipt_bytes = chunks.canonical(receipt)
        result[export.name] = chunks.ChunkSubmission(export.assignment, body_bytes, receipt_bytes)
        claims[export.name] = {"assignment_sha256": chunks.digest(export.assignment),
                              "response_sha256": chunks.digest(body_bytes), "producer_receipt_sha256": chunks.digest(receipt_bytes)}
    commitment = chunks.canonical({"schema_version": 1, "kind": "privoke-in-house-review-producer-commitments-v1",
        "preparation_identity": pool.preparation_identity, "review_pool_sha256": pool.review_pool_sha256, "chunks": claims})
    return result, commitment


class ChunkTests(unittest.TestCase):
    def assemble(self, pool, exports, submitted, commitment):
        return chunks.assemble_review_chunks(pool, exports, submitted, commitment,
            commitments_sha256=chunks.digest(commitment), trusted_bindings=pool.bindings)

    def test_two_complete_role_blind_sets_and_genuine_dual_validation(self):
        pool, _, _, exports = fixture()
        self.assertEqual(len(exports), 4)
        for export in exports:
            self.assertEqual(set(json.loads(export.packages)), chunks._PACKAGE_FIELDS)
            self.assertNotIn("native_category", json.loads(export.assignment))
            self.assertNotIn("component_id", json.loads(export.assignment))
        submitted, commitment = submissions(pool, exports)
        result = self.assemble(pool, exports, submitted, commitment)
        self.assertEqual(result.consensus.counts["present"], 1)
        self.assertEqual(result.consensus.counts["absent"], 1)
        self.assertFalse(result.consensus.human_agreement_claimed)
        self.assertEqual(result.first_raw_sha256, chunks.digest(result.first_envelope_bytes))
        self.assertEqual(json.loads(result.first_envelope_bytes)["responses"][0]["reviewer_id"], "ensemble-A")

    def test_valid_disagreement_stays_unknown(self):
        pool, _, _, exports = fixture()
        submitted, commitment = submissions(pool, exports, ordinary_b_present=True)
        self.assertEqual(self.assemble(pool, exports, submitted, commitment).consensus.counts["uncertain"], 1)

    def test_hash_before_decode_and_strict_json(self):
        with patch.object(chunks.json, "loads", side_effect=AssertionError("must not parse")) as mocked:
            with self.assertRaisesRegex(ValueError, "^Review chunk boundary failed validation\\.$"):
                chunks.decode_pinned(b"secret malformed", "0" * 64)
            mocked.assert_not_called()
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'"\xff"'):
            with self.assertRaises(ValueError):
                chunks.decode_pinned(raw, chunks.digest(raw))

    def test_package_contamination_and_duplicate_membership_refuse(self):
        _, raws, trust, _ = fixture()
        package = json.loads(raws[1].splitlines()[0])
        for change in ({"source_uid": 123}, {"native_category": "positive"}, {"component_id": "secret"}):
            bad = chunks.canonical({**package, **change}) + b"\n" + raws[1].splitlines(keepends=True)[1]
            manifest = json.loads(raws[0])
            manifest["review_packages_sha256"] = chunks.digest(bad)
            manifest_raw = chunks.canonical(manifest)
            with self.assertRaises(ValueError):
                chunks.export_review_chunks(manifest_raw, bad, raws[2], raws[3],
                    trust=replace(trust, packages_sha256=chunks.digest(bad), manifest_sha256=chunks.digest(manifest_raw)))
        duplicate = chunks.canonical(package) + b"\n"
        duplicate *= 2
        with self.assertRaises(ValueError):
            chunks._packages(duplicate, replace(trust, packages_sha256=chunks.digest(duplicate)))

    def test_assignment_shared_actor_cross_set_refuses(self):
        _, raws, trust, _ = fixture()
        assignments = json.loads(raws[3])
        assignments["sets"]["B"]["chunks"][0]["actor_id"] = assignments["sets"]["A"]["chunks"][0]["actor_id"]
        raw = chunks.canonical(assignments)
        with self.assertRaises(ValueError):
            chunks.export_review_chunks(*raws[:3], raw, trust=replace(trust, assignments_sha256=chunks.digest(raw)))

    def test_manifest_plan_source_and_count_binding_refuses(self):
        _, raws, trust, _ = fixture()
        for key, replacement in (("parquet_sha256", "0" * 64), ("counts", {"pool_size": True}),
                                 ("scope", "allocation"), ("no_allocation", False)):
            manifest = json.loads(raws[0])
            manifest[key] = replacement
            raw = chunks.canonical(manifest)
            with self.assertRaises(ValueError):
                chunks.export_review_chunks(raw, *raws[1:], trust=replace(trust, manifest_sha256=chunks.digest(raw)))

    def test_missing_extra_duplicate_cross_set_and_changed_response_refuse(self):
        pool, _, _, exports = fixture()
        submitted, commitment = submissions(pool, exports)
        bad_cases = [dict(submitted), dict(submitted), dict(submitted)]
        bad_cases[0].pop(exports[0].name)
        bad_cases[1]["unexpected"] = submitted[exports[0].name]
        bad_cases[2][exports[0].name] = submitted[exports[-1].name]
        for bad in bad_cases:
            with self.assertRaises(ValueError):
                self.assemble(pool, exports, bad, commitment)
        changed = dict(submitted)
        changed[exports[0].name] = replace(changed[exports[0].name], response_bytes=b"[]")
        with self.assertRaises(ValueError):
            self.assemble(pool, exports, changed, commitment)
        with self.assertRaises(ValueError):
            self.assemble(pool, exports + (exports[0],), submitted, commitment)

    def test_actual_response_validator_rejects_bad_offsets_and_blinding(self):
        pool, _, _, exports = fixture(size=2)
        submitted, commitment = submissions(pool, exports)
        for field in ("offset", "blinding", "extra", "duplicate", "owner"):
            bad = dict(submitted)
            claims = json.loads(commitment)
            name = exports[0].name
            body = json.loads(bad[name].response_bytes)
            if field == "offset":
                next(r for r in body["responses"] if r["evidence"])["evidence"][0]["end"] = 99999
            elif field == "blinding":
                body["blinding"]["no_peer_judgments"] = False
            elif field == "extra":
                body["responses"][0]["source_uid"] = 1
            elif field == "duplicate":
                body["responses"][1] = body["responses"][0]
            else:
                body["actor_id"] = "unassigned-actor"
            raw = chunks.canonical(body)
            receipt = json.loads(bad[name].producer_receipt_bytes)
            receipt["response_sha256"] = chunks.digest(raw)
            receipt_raw = chunks.canonical(receipt)
            claims["chunks"][name]["response_sha256"] = chunks.digest(raw)
            claims["chunks"][name]["producer_receipt_sha256"] = chunks.digest(receipt_raw)
            bad[name] = replace(bad[name], response_bytes=raw, producer_receipt_bytes=receipt_raw)
            with self.assertRaises(ValueError):
                self.assemble(pool, exports, bad, chunks.canonical(claims))

    def test_nonposix_io_fails_before_write(self):
        unavailable = Path("unavailable")
        with patch.object(chunks.os, "name", "nt"):
            with self.assertRaises(ValueError):
                chunks.publish_review_chunks(unavailable, ())

    def test_closed_names_cover_all_allowed_chunk_indices(self):
        names = [chunks._chunk_name("A", index) for index in range(chunks.MAX_REVIEW_POOL)]
        self.assertEqual(len(set(names)), chunks.MAX_REVIEW_POOL)
        self.assertEqual(names[9999], "A-09999")
        self.assertEqual(names[10000], "A-10000")
        self.assertEqual(names[-1], "A-12095")
        for index in (-1, chunks.MAX_REVIEW_POOL, True):
            with self.assertRaises(ValueError):
                chunks._chunk_name("A", index)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor checks require Linux")
    def test_fsync_root_permission_and_owner_mutation_refuses_success(self):
        _, _, _, exports = fixture()
        original_fsync = os.fsync
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for mutation in ("mode", "owner"):
                if mutation == "owner" and os.geteuid() != 0:
                    continue  # Actual chown requires privilege; mode case always runs.
                output = base / mutation
                changed = []
                def hook(fd):
                    if output.exists() and chunks._identity(os.fstat(fd)) == chunks._identity(os.lstat(output)):
                        if not changed:
                            if mutation == "mode":
                                os.chmod(output, 0o755)
                            else:
                                os.chown(output, 65534, -1)
                            changed.append(True)
                    return original_fsync(fd)
                try:
                    with patch.object(chunks.os, "fsync", side_effect=hook):
                        with self.assertRaisesRegex(ValueError, "^Review chunk boundary failed validation\\.$"):
                            chunks.publish_review_chunks(output, exports)
                    self.assertTrue(changed)
                finally:
                    if output.exists():
                        if os.geteuid() == 0:
                            os.chown(output, os.geteuid(), -1)
                        os.chmod(output, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor checks require Linux")
    def test_private_leaf_mode_rechecked_after_read_and_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            raw = b"synthetic private bytes"
            for operation in ("read", "write"):
                directory = base / operation
                directory.mkdir(mode=0o700)
                response = directory / "responses.json"
                if operation == "read":
                    chunks.write_exclusive_response(directory, raw)
                changed = []
                original = os.read if operation == "read" else os.fsync
                def hook(*args):
                    result = original(*args)
                    if not changed:
                        os.chmod(directory, 0o755)
                        changed.append(True)
                    return result
                tool = "read" if operation == "read" else "fsync"
                try:
                    with patch.object(chunks.os, tool, side_effect=hook):
                        with self.assertRaises(ValueError):
                            if operation == "read":
                                chunks.read_pinned_file(response, chunks.digest(raw))
                            else:
                                chunks.write_exclusive_response(directory, raw)
                    self.assertTrue(changed)
                finally:
                    os.chmod(directory, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor checks require Linux")
    def test_largest_index_name_publishes(self):
        _, _, _, exports = fixture()
        maximum = replace(exports[0], name=chunks._chunk_name("A", chunks.MAX_REVIEW_POOL - 1))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "maximum-index"
            chunks.publish_review_chunks(output, (maximum,))
            self.assertTrue((output / "A-12095" / "assignment.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor checks require Linux")
    def test_private_output_no_overwrite_symlink_hardlink_and_substitution(self):
        _, _, _, exports = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
            output = base / "export"
            chunks.publish_review_chunks(output, exports)
            with self.assertRaises(ValueError):
                chunks.publish_review_chunks(output, exports)
            actor_output = base / "actor-output"
            actor_output.mkdir(mode=0o700)
            raw = b'{"private":"synthetic"}'
            chunks.write_exclusive_response(actor_output, raw)
            with self.assertRaises(ValueError):
                chunks.write_exclusive_response(actor_output, raw)
            response = actor_output / "responses.json"
            os.link(response, actor_output / "hardlink")
            with self.assertRaises(ValueError):
                chunks.read_pinned_file(response, chunks.digest(raw))
            (actor_output / "hardlink").unlink()
            with chunks._HeldDirectory(actor_output) as held:
                actor_output.rename(base / "renamed")
                actor_output.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    held.verify()
            (base / "link").symlink_to(base / "renamed", target_is_directory=True)
            with self.assertRaises(ValueError):
                chunks.read_pinned_file(base / "link" / "responses.json", chunks.digest(raw))


if __name__ == "__main__":
    unittest.main()
