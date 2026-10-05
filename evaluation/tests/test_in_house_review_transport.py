"""Synthetic semantic checks and actual POSIX assigned-volume boundaries."""
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
from privoke_eval import in_house_review_transport as transport  # noqa: E402
from test_in_house_review_chunks import fixture, submissions  # noqa: E402


def semantic_request(export, submission):
    body = json.loads(submission.response_bytes)
    return chunks.canonical({"schema_version": 1, "kind": "privoke-in-house-review-semantic-request-v1",
        "assignment_sha256": chunks.digest(export.assignment), "full_prompt_reviewed": True,
        "blinding_attestation": {k: True for k in transport.BLIND_FIELDS},
        "responses": [{k: r[k] for k in transport.SEMANTIC_FIELDS} for r in body["responses"]]})


class SemanticTests(unittest.TestCase):
    def test_local_native_validation_and_original_unicode_offsets(self):
        _, _, _, exports = fixture(size=2)
        packages = [json.loads(line) for line in exports[0].packages.splitlines()]
        positive = next(p for p in packages if p["native_spans"])
        native = positive["native_spans"][0]
        item = {"review_id": positive["review_id"], "decision": "present", "categories": ["IDENTITY"],
                "evidence": [{"category": "IDENTITY", "start": native["start"], "end": native["end"]}],
                "uncertainty_reason": None}
        self.assertEqual(transport._semantic_response(item, positive), item)
        self.assertIn("Zoë", positive["text"])
        for decision in ("absent", "uncertain"):
            other = {**item, "decision": decision, "categories": [], "evidence": [], "uncertainty_reason": None}
            with self.assertRaises(ValueError):
                transport._semantic_response(other, positive)
        uncertain = {**item, "decision": "uncertain", "categories": [], "evidence": [], "uncertainty_reason": "unresolved synthetic context"}
        self.assertEqual(transport._semantic_response(uncertain, positive), uncertain)

    def test_missing_category_evidence_bad_offsets_and_auto_metadata_refuse(self):
        pool, _, _, exports = fixture(size=2)
        submitted, _ = submissions(pool, exports)
        request = json.loads(semantic_request(exports[0], submitted[exports[0].name]))
        package_map = {json.loads(line)["review_id"]: json.loads(line) for line in exports[0].packages.splitlines()}
        item = next(r for r in request["responses"] if r["evidence"])
        for changed in ({**item, "reviewer_id": "forged"}, {**item, "categories": []},
                        {**item, "evidence": [{"category": "IDENTITY", "start": True, "end": 9}]},
                        {**item, "evidence": [{"category": "IDENTITY", "start": 0, "end": 999999}]}):
            with self.assertRaises(ValueError):
                transport._semantic_response(changed, package_map[item["review_id"]])

    def test_nonposix_transport_refuses_without_path_factory_error(self):
        path = Path("/chunk")
        with patch.object(chunks.os, "name", "nt"):
            with self.assertRaisesRegex(ValueError, "^Assigned review transport failed validation\\.$"):
                transport.read_chunk_page(path, assignment_sha256="0" * 64)


@unittest.skipUnless(os.name == "posix", "POSIX assigned transport checks require Linux")
class PosixTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.pool, _, _, self.exports = fixture(size=2)
        self.export_root = self.base / "exports"
        chunks.publish_review_chunks(self.export_root, self.exports)
        self.export = self.exports[0]
        self.input = self.export_root / self.export.name
        self.output = self.base / "response"
        self.output.mkdir(mode=0o700)
        self.submitted, _ = submissions(self.pool, self.exports)
        self.request = semantic_request(self.export, self.submitted[self.export.name])
        self.assignment_sha = chunks.digest(self.export.assignment)

    def write(self, request=None):
        return transport.write_chunk_response(self.input, self.output, self.request if request is None else request,
                                               assignment_sha256=self.assignment_sha)

    def test_pages_preserve_complete_text_and_no_split_or_unknown_page(self):
        pages = [json.loads(transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha,
                                                    start=i, count=1)) for i in range(2)]
        original = [json.loads(line) for line in self.export.packages.splitlines()]
        self.assertEqual([p["packages"][0] for p in pages], original)
        self.assertEqual(pages[0]["next_start"], 1)
        self.assertIsNone(pages[1]["next_start"])
        with patch.object(transport, "MAX_PAGE_BYTES", 1):
            with self.assertRaises(ValueError):
                transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha)
        for start in (-1, 2, True):
            with self.assertRaises(ValueError):
                transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha, start=start)

    def test_explicit_request_preserved_closed_receipt_and_exclusive_write(self):
        result = self.write()
        self.assertEqual(set(os.listdir(self.output)), transport.RESPONSE_FILES)
        self.assertEqual((self.output / "semantic-request.json").read_bytes(), self.request)
        self.assertEqual(result["semantic_request_sha256"], chunks.digest(self.request))
        body = json.loads((self.output / "responses.json").read_bytes())
        self.assertEqual(body["ensemble_id"], json.loads(self.export.assignment)["ensemble_id"])
        self.assertTrue(all(r["full_prompt_reviewed"] is True for r in body["responses"]))
        self.assertNotIn("responses", result)
        with self.assertRaises(ValueError):
            self.write()

    def test_writer_return_same_byte_response_inode_replacement_refuses(self):
        original = transport._exclusive
        replaced = []
        def hook(directory, filename, raw):
            identity = original(directory, filename, raw)
            if filename == "responses.json" and not replaced:
                replacement = self.base / "same-byte-response-replacement"
                replacement.write_bytes(raw)
                os.chmod(replacement, 0o600)
                os.replace(replacement, Path(directory) / filename)
                self.assertNotEqual(chunks._identity(os.lstat(Path(directory) / filename)), identity)
                self.assertEqual(chunks.digest((Path(directory) / filename).read_bytes()), chunks.digest(raw))
                replaced.append(True)
            return identity
        with patch.object(transport, "_exclusive", side_effect=hook):
            with self.assertRaisesRegex(ValueError, "^Assigned review transport failed validation\\.$"):
                self.write()
        self.assertTrue(replaced)

    def test_false_missing_attestation_missing_duplicate_unknown_ids_reject_before_write(self):
        for change in ("false", "missing", "duplicate", "unknown", "short"):
            request = json.loads(self.request)
            if change == "false":
                request["full_prompt_reviewed"] = False
            elif change == "missing":
                request["blinding_attestation"].pop("no_peer_judgments")
            elif change == "duplicate":
                request["responses"][1] = request["responses"][0]
            elif change == "unknown":
                request["responses"][0]["review_id"] = "0" * 64
            else:
                request["responses"].pop()
            with self.assertRaises(ValueError):
                self.write(chunks.canonical(request))
            self.assertEqual(os.listdir(self.output), [])

    def test_unknown_files_wrong_assignment_and_tampered_packages_reject(self):
        for extra in ("private-review-map.jsonl", "peer-responses.json", "reserved-test.jsonl"):
            (self.input / extra).write_bytes(b"synthetic forbidden file")
            with self.assertRaises(ValueError):
                transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha)
            (self.input / extra).unlink()
        with self.assertRaises(ValueError):
            transport.read_chunk_page(self.input, assignment_sha256="0" * 64)
        path = self.input / "packages.jsonl"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            self.write()

    def test_symlink_hardlink_and_output_permission_mutation_refuse(self):
        link = self.base / "chunk-link"
        link.symlink_to(self.input, target_is_directory=True)
        with self.assertRaises(ValueError):
            transport.read_chunk_page(link, assignment_sha256=self.assignment_sha)
        hardlink = self.base / "package-link"
        os.link(self.input / "packages.jsonl", hardlink)
        with self.assertRaises(ValueError):
            self.write()
        hardlink.unlink()
        original_fsync = os.fsync
        changed = []
        def hook(fd):
            result = original_fsync(fd)
            if not changed:
                os.chmod(self.output, 0o755)
                changed.append(True)
            return result
        try:
            with patch.object(transport.os, "fsync", side_effect=hook):
                with self.assertRaises(ValueError):
                    self.write()
            self.assertTrue(changed)
        finally:
            os.chmod(self.output, 0o700)

    def test_same_byte_inode_replacement_during_read_and_permission_mutation_reject(self):
        original_read = chunks.read_pinned_file
        mutated = []
        def hook(path, *args, **kwargs):
            raw = original_read(path, *args, **kwargs)
            if not mutated:
                target = self.input / "packages.jsonl"
                replacement = self.base / "replacement"
                replacement.write_bytes(target.read_bytes())
                os.chmod(replacement, 0o600)
                os.replace(replacement, target)
                mutated.append(True)
            return raw
        with patch.object(chunks, "read_pinned_file", side_effect=hook):
            with self.assertRaises(ValueError):
                transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha)
        self.assertTrue(mutated)
        os.chmod(self.input, 0o755)
        with self.assertRaises(ValueError):
            transport.read_chunk_page(self.input, assignment_sha256=self.assignment_sha)
        os.chmod(self.input, 0o700)

    def test_genuine_dual_assembly_of_actual_written_synthetic_files(self):
        actual, claims = {}, {}
        for export in self.exports:
            directory = self.base / ("response-" + export.name)
            directory.mkdir(mode=0o700)
            request = semantic_request(export, self.submitted[export.name])
            result = transport.write_chunk_response(self.export_root / export.name, directory, request,
                                                     assignment_sha256=chunks.digest(export.assignment))
            actual[export.name] = chunks.ChunkSubmission(export.assignment,
                (directory / "responses.json").read_bytes(), (directory / "producer-receipt.json").read_bytes())
            claims[export.name] = {"assignment_sha256": result["assignment_sha256"],
                "response_sha256": result["response_sha256"], "producer_receipt_sha256": result["producer_receipt_sha256"]}
        raw = chunks.canonical({"schema_version": 1, "kind": "privoke-in-house-review-producer-commitments-v1",
            "preparation_identity": self.pool.preparation_identity, "review_pool_sha256": self.pool.review_pool_sha256,
            "chunks": claims})
        result = chunks.assemble_review_chunks(self.pool, self.exports, actual, raw,
            commitments_sha256=chunks.digest(raw), trusted_bindings=self.pool.bindings)
        self.assertEqual(result.consensus.counts["present"], 1)
        self.assertEqual(result.consensus.counts["absent"], 1)
        self.assertFalse(result.consensus.label_truth_authenticated)


if __name__ == "__main__":
    unittest.main()
