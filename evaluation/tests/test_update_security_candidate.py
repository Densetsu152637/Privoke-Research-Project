"""Tests for stage 13d-1b: CK8, the three positive controls and TL1-candidate on the genuine 13c-2 candidate.

No test here starts a container. They cover the parts the live run depends on: the reading and checking of the 13c-2 export, the
allocation format handed to `s13c_journal_seed`, the row logic against a fake store that follows the product's commit rules, the
TL1-candidate verdict and the proxy that holds a request back (against a Python TLS server), the Compose override and the RUSTDOCK
helper calls, the run options, and the exit status. The live run hosts the stack.
"""
import contextlib
import hashlib
import io
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_security as harness  # noqa: E402
import update_security_pki as pki_tools  # noqa: E402
import update_security_report as report  # noqa: E402
from test_update_security_authz import EchoServer, client_exchange, layer_row, map_rows, record_of, tls_fixture  # noqa: E402

ROOT = harness.ROOT
REAL_TEST = ROOT / "rust/services/param-update/tests/s13c_update_attacks_real.rs"
PIN, ORIGINAL = "1" * 64, "2" * 64


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allocation(request_id: str, base: str = PIN) -> dict:
    return {"request_id": request_id, "cycle": 0, "model_id": harness.S13C_MODEL, "stage": "heads", "attempt": 0,
            "sampler": "existing_taxonomy_benign_common_frozen_stream_v1", "seed": 7, "expected_base": base, "source_commitment": "3" * 64,
            "state": "allocated"}


def write_export(directory: Path, *, allocate_c11e: bool = False, drop: str | None = None, model: str = harness.S13C_MODEL) -> tuple[Path, Path]:
    """A 13c-2 export in the layout `s13c_real_leg` writes: the genuine candidate (allocated on the pin) and C11e (not allocated)."""
    candidates, evidence = directory / "candidates", directory / "evidence"
    for folder in (candidates / "manifests", candidates / "blobs", evidence):
        folder.mkdir(parents=True)
    entries, allocations = [], []
    for role, request_id in (("genuine", "v3r-c0-efficient-heads-a0-test"), ("C11e", "s13c2-c11e")):
        blob, manifest, proof = b"blob-of-the-genuine-candidate", f"manifest {role}".encode(), f"evidence naming {request_id}".encode()
        (candidates / "blobs" / f"{sha(blob)}.safetensors").write_bytes(blob)
        (candidates / "manifests" / f"{sha(manifest)}.json").write_bytes(manifest)
        (evidence / f"{sha(proof)}.json").write_bytes(proof)
        entries.append({"role": role, "request_id": request_id, "allocated": role == "genuine" or allocate_c11e, "manifest_sha": sha(manifest),
                        "blob_sha": sha(blob), "evidence_sha": sha(proof), "scope": "heads", "parent": PIN, "note": role})
        if role == "genuine" or allocate_c11e:
            allocations.append(allocation(request_id))
    (candidates / "index.json").write_text(json.dumps({"pin": PIN, "original": ORIGINAL, "model_id": model, "candidates": entries}), encoding="utf-8")
    (candidates / "allocations.json").write_text(json.dumps(allocations), encoding="utf-8")
    if drop:
        entry = next(item for item in entries if item["role"] == drop)
        (evidence / f"{entry['evidence_sha']}.json").unlink()
    return candidates, evidence


class FakeRpcError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class FakeStack:
    """The authority of a store on the pin, following the commit rules the rows rely on: a request id answers its stored receipt; an
    unallocated request is rejected (request_not_allocated); a commit whose expected base is not current is rejected (stale_base); otherwise
    it is applied with a new publication. A rollback is applied with reason `rollback`. The knobs model the failures the rows must catch."""

    def __init__(self, export, *, allows_unallocated=False, replay_reaches_store=False, proxy_leaks=False, refuse_runtime_stage=False):
        self.export, self.name = export, "s13d-test"
        self.current, self.versions, self.publications, self.sequence = export.pin, {export.pin, export.original}, 0, 0
        self.receipts, self.staged = {}, set()
        self.allows_unallocated, self.replay_reaches_store, self.proxy_leaks = allows_unallocated, replay_reaches_store, proxy_leaks
        self.refuse_runtime_stage = refuse_runtime_stage
        self.allocated = {row["request_id"] for row in export.allocations}

    def observe(self, served=None):
        return {"current": self.current, "versions": len(self.versions), "publications": self.publications, "max_sequence": self.sequence,
                "served": self.current}

    def status(self, request_id):
        return self.receipts[request_id].status if request_id in self.receipts else "unknown"

    def publish(self, manifest):
        self.current = manifest
        self.versions.add(manifest)
        self.publications += 1
        self.sequence += 1

    def commit(self, commit):
        stored = self.receipts.get(commit["request_id"])
        if stored is not None:
            return stored
        if commit["request_id"] not in self.allocated and not self.allows_unallocated:
            receipt = SimpleNamespace(status="rejected", reason="request_not_allocated")
        elif self.current != commit["expected_base"]:
            receipt = SimpleNamespace(status="rejected", reason="stale_base")
        else:
            self.publish(commit["candidate"])
            receipt = SimpleNamespace(status="applied", reason="")
        self.receipts[commit["request_id"]] = receipt
        return receipt

    def call(self, identity, fn):
        stack = self

        class Client:
            def stage(self, data, manifest=b""):
                if identity == "runtime" and stack.refuse_runtime_stage:
                    raise FakeRpcError("PERMISSION_DENIED", "role may not call this method")
                stack.staged.add(sha(data))
                return sha(data)

            def commit(self, commit):
                return stack.commit(commit)

            def rollback(self, request_id, manifest):
                stack.publish(manifest)
                stack.receipts[request_id] = SimpleNamespace(status="applied", reason="rollback")
                return stack.receipts[request_id]

        try:
            value = fn(Client())
        except FakeRpcError as error:
            return {"observed": "rejected", "code": error.code, "message": error.message}
        return harness.receipt_result(value) if hasattr(value, "status") else {"observed": "accepted", "code": "OK", "message": str(value)}

    def withheld_commit(self, identity, commit):
        if self.proxy_leaks:
            self.commit(commit)
        self.pending = commit
        return {"observed": "rejected", "code": "DEADLINE_EXCEEDED", "message": "Deadline Exceeded", "server_records_after_flight": 2}, 3, b"recorded"

    def replay(self, sent):
        if self.replay_reaches_store:
            self.commit(self.pending)
            return {"stats": {"first_record_type": 22, "records": 9, "last_record_bytes": 300, "application_bytes": 9000}, "closed": False}
        return {"stats": {"first_record_type": 22, "records": 4, "last_record_bytes": 24, "application_bytes": 3000}, "closed": True}


class CandidateRowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.export = harness.CandidateExport(*write_export(Path(self.directory.name)))

    def tearDown(self):
        self.directory.cleanup()

    def rows(self, **knobs):
        rows = harness.candidate_rows(FakeStack(self.export, **knobs), [])
        return {row["id"]: row for row in harness.finalize_authz_rows(rows, harness.StackIssuers())}

    def test_the_rows_are_the_pending_ones_and_every_property_holds_on_a_sound_store(self):
        rows = self.rows()
        self.assertEqual(sorted(rows), sorted(report.PENDING_13D_1B))
        for row in rows.values():
            self.assertTrue(row["property_met"], row)
            self.assertEqual(row["credential_issuer"], "privoke-pki")
            self.assertEqual(row["service"], "param-update")
        self.assertEqual((rows["CK8"]["code"], rows["CK8"]["message"], rows["CK8"]["denied_by"]), ("RECEIPT_REJECTED", "request_not_allocated", "application"))
        self.assertEqual((rows["TL1-candidate"]["code"], rows["TL1-candidate"]["denied_by"]), ("CONNECTION_ABORTED", "tls_handshake"))
        self.assertEqual(rows["TL1-candidate"]["scope_label"], "transport (Rust)")
        self.assertEqual(rows["CK8"]["scope_label"], "update path (Rust V3)")
        self.assertTrue(rows["CK8"]["model_unchanged"] and rows["TL1-candidate"]["model_unchanged"])
        for control in ("CK-positive-publisher-commit", "CK-positive-publisher-rollback", "CK-positive-runtime-stage"):
            self.assertEqual((rows[control]["observed"], rows[control]["denied_by"]), ("accepted", "not_denied"), control)
        self.assertEqual(rows["CK-positive-publisher-commit"]["identity"], "s13c2-publisher (publisher)")
        self.assertEqual(rows["CK-positive-runtime-stage"]["identity"], "v3-runtime (runtime)")
        self.assertEqual(rows["CK8"]["identity"], "s13c2-trainer (trainer)")
        for row in rows.values():
            self.assertEqual(report.denied_by_problems(row), [], row["id"])

    def test_the_rows_cover_cross_identity_misuse_and_nothing_is_pending(self):
        rows = [row for row in map_rows() if row["id"] not in report.PENDING_13D_1B] + list(self.rows().values())
        coverage = report.s13d_coverage(record_of(rows))
        self.assertTrue(coverage["ok"], coverage["problems"])
        self.assertEqual(coverage["pending_13d_1b"], [])
        misuse = next(item for item in coverage["attacks"] if item["attack"] == "Cross-identity misuse")
        self.assertIn("CK8", misuse["counted"])
        self.assertIn("application", misuse["denied_by"])

    def test_an_admitted_unallocated_commit_is_an_unmet_ck8(self):
        rows = self.rows(allows_unallocated=True)
        self.assertFalse(rows["CK8"]["property_met"])
        self.assertEqual(rows["CK8"]["denied_by"], "not_denied")

    def test_a_replay_that_reaches_the_store_is_an_unmet_tl1_candidate(self):
        rows = self.rows(replay_reaches_store=True)
        self.assertEqual(rows["TL1-candidate"]["observed"], "accepted")
        self.assertFalse(rows["TL1-candidate"]["property_met"])
        self.assertFalse(rows["TL1-candidate"]["model_unchanged"])

    def test_a_proxy_that_let_the_request_through_makes_tl1_candidate_a_harness_error(self):
        rows = self.rows(proxy_leaks=True)
        self.assertEqual((rows["TL1-candidate"]["observed"], rows["TL1-candidate"]["code"]), ("not_run", "HARNESS_ERROR"))
        self.assertIsNone(rows["TL1-candidate"]["property_met"])
        self.assertFalse(rows["CK-positive-publisher-commit"]["property_met"])  # the stored receipt is no new publication

    def test_a_refused_runtime_stage_is_an_unmet_control(self):
        rows = self.rows(refuse_runtime_stage=True)
        self.assertFalse(rows["CK-positive-runtime-stage"]["property_met"])
        self.assertEqual(rows["CK-positive-runtime-stage"]["code"], "PERMISSION_DENIED")


class Tl1CandidateVerdictTests(unittest.TestCase):
    refused = {"stats": {"first_record_type": 22, "records": 4, "last_record_bytes": 24}, "closed": True}
    deadline = {"observed": "rejected", "code": "DEADLINE_EXCEEDED", "message": "x"}

    def test_refused_only_with_a_tls_abort_an_unchanged_store_and_an_applied_control(self):
        verdict = harness.tl1_candidate_verdict
        self.assertEqual(verdict(self.deadline, 3, self.refused, True, True, True)["code"], "CONNECTION_ABORTED")
        # A replay that left a trace reached the store, even when the control then fails (it finds the replay's receipt).
        self.assertEqual(verdict(self.deadline, 3, self.refused, True, False, False)["observed"], "accepted")
        self.assertEqual(verdict(self.deadline, 3, self.refused, False, True, True)["code"], "HARNESS_ERROR")  # the proxy let it through
        self.assertEqual(verdict(self.deadline, 3, self.refused, True, True, False)["code"], "HARNESS_ERROR")
        self.assertEqual(verdict(self.deadline, 0, self.refused, True, True, True)["code"], "HARNESS_ERROR")
        answered = {**self.deadline, "code": "OK"}
        self.assertEqual(verdict(answered, 3, self.refused, True, True, True)["code"], "HARNESS_ERROR")
        silent = {"stats": {"first_record_type": None, "records": 0, "last_record_bytes": 0}, "closed": False}
        self.assertEqual(verdict(self.deadline, 3, silent, True, True, True)["code"], "HARNESS_ERROR")

    def test_the_abort_shape_needs_a_handshake_a_close_and_an_alert_sized_end(self):
        self.assertTrue(pki_tools.replay_aborted({"first_record_type": 22, "records": 3, "last_record_bytes": 24}, True))
        self.assertFalse(pki_tools.replay_aborted({"first_record_type": 22, "records": 3, "last_record_bytes": 24}, False))
        self.assertFalse(pki_tools.replay_aborted({"first_record_type": 22, "records": 3, "last_record_bytes": 400}, True))
        self.assertFalse(pki_tools.replay_aborted({"first_record_type": 22, "records": 1, "last_record_bytes": 24}, True))
        self.assertFalse(pki_tools.replay_aborted({"first_record_type": 23, "records": 3, "last_record_bytes": 24}, True))

    def test_server_records_after_the_flight_show_a_completed_handshake(self):
        events = [(0, "c2s", 22, 500), (1, "s2c", 22, 90), (2, "s2c", 23, 2000), (3, "c2s", 23, 600), (4, "s2c", 23, 250), (5, "s2c", 23, 40)]
        self.assertEqual(pki_tools.server_records_after_flight(events), 2)
        self.assertEqual(pki_tools.server_records_after_flight(events[:3]), 0)

    def test_receipts_map_to_outcomes_and_the_layer(self):
        rejected = harness.receipt_result(SimpleNamespace(status="rejected", reason="request_not_allocated"))
        self.assertEqual((rejected["observed"], rejected["code"], rejected["message"]), ("rejected", "RECEIPT_REJECTED", "request_not_allocated"))
        self.assertEqual(harness.observed_layer(rejected), "application")
        applied = harness.receipt_result(SimpleNamespace(status="applied", reason="rollback"))
        self.assertEqual((applied["observed"], applied["code"], applied["reason"]), ("accepted", "OK", "rollback"))
        self.assertEqual(harness.claimed_layer("CK8"), "application")
        self.assertEqual(harness.claimed_layer("TL1-candidate"), "tls_handshake")
        row = layer_row("CK8", "application", code="RECEIPT_REJECTED", message="request_not_allocated")
        self.assertEqual(report.denied_by_problems(row), [])


class WithholdingProxyTests(unittest.TestCase):
    """The proxy that holds a request back, against a Python TLS 1.3 server that answers b"ping" with b"pong"."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.work = Path(self.directory.name)
        try:
            self.authority, self.server, self.client = tls_fixture(self.work)
        except RuntimeError as error:  # no OpenSSL on this host
            self.directory.cleanup()
            self.skipTest(str(error))
        self.echo = EchoServer(self.work, self.authority, self.server)

    def tearDown(self):
        self.echo.close()
        self.directory.cleanup()

    def test_a_held_back_request_never_reaches_the_server_and_its_replay_is_aborted(self):
        proxy = pki_tools.RecordingProxy(self.echo.port, withhold_after=1)
        try:
            reply = client_exchange(self.work, self.authority, self.client, proxy.port)
            time.sleep(0.3)
            sent, _ = proxy.captured()
            withheld = proxy.withheld
        finally:
            proxy.close()
        self.assertEqual(reply, b"")
        self.assertGreaterEqual(withheld, 1)
        time.sleep(0.3)
        self.assertEqual(self.echo.served, 0)
        replay = pki_tools.replay_bytes(self.echo.port, sent, wait=3.0)
        self.assertTrue(pki_tools.replay_aborted(replay["stats"], replay["closed"]), replay["stats"])
        self.assertEqual(self.echo.served, 0)
        # The same request, sent cleanly, is answered: what was held back and replayed was an admissible request.
        self.assertEqual(client_exchange(self.work, self.authority, self.client, self.echo.port), b"pong")
        self.assertEqual(self.echo.served, 1)

    def test_a_held_back_exchange_takes_one_connection_only(self):
        proxy = pki_tools.RecordingProxy(self.echo.port, withhold_after=1)
        try:
            client_exchange(self.work, self.authority, self.client, proxy.port)
            self.assertEqual(client_exchange(self.work, self.authority, self.client, proxy.port), b"")
        finally:
            proxy.close()
        self.assertEqual(self.echo.served, 0)


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.work = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_a_sound_export_has_no_problem_and_its_files_hash_to_their_names(self):
        export = harness.CandidateExport(*write_export(self.work))
        self.assertEqual(export.problems(), [])
        genuine = export.candidates["genuine"]
        self.assertEqual(sha(genuine.read("blob")), genuine.blob_sha)
        self.assertEqual(genuine.commit(PIN), {"request_id": genuine.request_id, "model_id": "privoke-v3-efficient", "expected_base": PIN,
                                               "candidate": genuine.manifest_sha, "evidence": genuine.evidence_sha})
        genuine.paths["blob"].write_bytes(b"other bytes")
        with self.assertRaisesRegex(RuntimeError, "does not hash"):
            genuine.read("blob")

    def test_an_allocated_ck8_request_a_missing_file_or_another_tier_is_a_problem(self):
        self.assertIn("is allocated", "; ".join(harness.CandidateExport(*write_export(self.work / "a", allocate_c11e=True)).problems()))
        self.assertIn("missing file: C11e evidence", harness.CandidateExport(*write_export(self.work / "b", drop="C11e")).problems())
        self.assertIn("not privoke-v3-efficient", "; ".join(harness.CandidateExport(*write_export(self.work / "c", model="privoke-v3-balanced")).problems()))

    def test_the_allocation_handed_to_the_seed_is_the_13c1_format(self):
        rust = (ROOT / "rust/services/param-update/tests/s13c_allocations/mod.rs").read_text(encoding="utf-8")
        keys = re.search(r"ALLOCATION_KEYS: \[&str; 10\] =\s*\[([^\]]+)\]", rust).group(1)
        self.assertEqual(tuple(re.findall(r'"([a-z_]+)"', keys)), harness.S13C_ALLOCATION_KEYS)
        text = harness.allocation_json([allocation("r1")])
        self.assertEqual(list(json.loads(text)[0]), list(harness.S13C_ALLOCATION_KEYS))
        with self.assertRaisesRegex(ValueError, "exactly"):
            harness.allocation_json([{**allocation("r1"), "candidate": "x"}])
        with self.assertRaisesRegex(ValueError, "not in state"):
            harness.allocation_json([{**allocation("r1"), "state": "settled"}])

    def test_inputs_are_checked_before_anything_is_hosted(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz"])
        self.assertIn("no 13c-2 export was named", harness.candidate_inputs_problem(args))
        candidates, evidence = write_export(self.work)
        named = ["--s13c-candidates", str(candidates), "--s13c-evidence", str(evidence), "--s13c-originals", str(self.work),
                 "--s13c-retention-bank-dir", str(self.work), "--release-dir", str(self.work)]
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", *named])
        self.assertIsNone(harness.candidate_inputs_problem(args))
        args.s13c_originals = self.work / "absent"
        self.assertIn("not found: --s13c-originals", harness.candidate_inputs_problem(args))

    def test_without_an_export_the_rows_are_not_run_with_the_reason_and_nothing_is_started(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz"])
        with mock.patch.object(harness.subprocess, "run") as run:
            rows, commands = harness.run_candidate_rows(args, self.work)
            run.assert_not_called()
        self.assertEqual([row["id"] for row in rows], list(report.PENDING_13D_1B))
        self.assertTrue(all(row["observed"] == "not_run" and "no 13c-2 export was named" in row["message"] for row in rows))
        self.assertEqual(commands, [])

    def test_a_stack_that_fails_records_the_rows_that_did_not_run_as_harness_errors_and_is_torn_down(self):
        candidates, evidence = write_export(self.work)
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--s13c-candidates", str(candidates),
                                                  "--s13c-evidence", str(evidence), "--s13c-originals", str(self.work),
                                                  "--s13c-retention-bank-dir", str(self.work), "--release-dir", str(self.work)])
        with mock.patch.object(harness.CandidateStack, "start", side_effect=RuntimeError("compose up failed")), \
                mock.patch.object(harness.CandidateStack, "stop") as stop:
            rows, _ = harness.run_candidate_rows(args, self.work)
        stop.assert_called_once()
        self.assertEqual([row["id"] for row in rows], list(report.PENDING_13D_1B))
        self.assertTrue(all(row["code"] == "HARNESS_ERROR" and "compose up failed" in row["message"] for row in rows))


class StackTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.work = Path(self.directory.name)
        candidates, evidence = write_export(self.work)
        self.args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--s13c-candidates", str(candidates),
                                                       "--s13c-evidence", str(evidence), "--s13c-originals", str(self.work),
                                                       "--s13c-retention-bank-dir", str(self.work), "--release-dir", str(self.work),
                                                       "--stack-name", "s13d1b", "--stack-cpus", "6"])
        self.stack = harness.CandidateStack(self.args, self.work, harness.CandidateExport(candidates, evidence))
        self.stack.work.mkdir(parents=True)

    def tearDown(self):
        self.directory.cleanup()

    def test_the_override_renames_the_containers_and_publishes_on_loopback_only(self):
        self.stack.write_override()
        services = json.loads(self.stack.override.read_text(encoding="utf-8"))["services"]
        self.assertEqual(services["param-update-service"]["container_name"], "s13d1b-param-update")
        self.assertEqual(services["model-streaming-service"]["container_name"], "s13d1b-model-streaming")
        self.assertEqual(services["param-update-service"]["ports"], [f"127.0.0.1:{self.stack.port}:50052"])
        self.assertEqual(services["param-update-service"]["cpus"], 6.0)
        for service in services.values():
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["volumes"][0]["target"], "/model-releases")
            self.assertTrue(service["volumes"][0]["read_only"])
        environment = self.stack.environment()
        self.assertEqual(environment["FUZZER_PROMPT_COUNT"], "0")
        self.assertEqual(environment["MODEL_PUBLISH"], f"127.0.0.1:{self.stack.model_port}")
        self.assertNotIn(".privoke", environment["PRIVOKE_PKI_DIR"])  # the disposable test PKI, never the production key's directory

    def test_the_compose_file_has_the_services_and_variables_the_override_relies_on(self):
        compose = harness.STACK_COMPOSE_FILE.read_text(encoding="utf-8")
        for name in ("param-update-service:", "model-streaming-service:", "profiles: [v3-training]", "target: /model-releases", "${V3_SOURCE_DIR",
                     "${V3_ORIGINAL_DIR", "${V3_RETENTION_BANK_DIR", "${MODEL_PUBLISH", "FUZZER_PROMPT_COUNT: ${FUZZER_PROMPT_COUNT",
                     "${PRIVOKE_PARAM_UPDATE_IMAGE", "${PRIVOKE_MODEL_STREAMING_IMAGE", "${PRIVOKE_PKI_DIR}/v3-publication.key"):
            self.assertIn(name, compose)

    def test_a_rustdock_helper_runs_one_exact_test_under_the_stack_name_and_needs_its_own_success_line(self):
        output = SimpleNamespace(returncode=0, stdout="running 1 test\nPKI written to /s13d/pki\nok")
        with mock.patch.object(harness.subprocess, "run", return_value=output) as run:
            self.stack.rustdock("s13c_compose_pki", {"S13C_PKI_DIR": "/s13d/pki"}, [("w", "/s13d")], "PKI written to")
        command = run.call_args[0][0]
        self.assertTrue(command[command.index("--name") + 1].startswith("s13d1b-rustdock-"))
        self.assertIn("--cpus=6", command)
        self.assertEqual(command[command.index("--test") + 1:], ["s13c_update_attacks_real", "s13c_compose_pki", "--", "--exact", "--nocapture"])
        self.assertIn("rust:1.99.1-bookworm", command)
        self.assertIn("S13C_PKI_DIR=/s13d/pki", command)
        with mock.patch.object(harness.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="PENDING: set S13C_PKI_DIR")):
            with self.assertRaisesRegex(RuntimeError, "s13c_compose_pki failed"):
                self.stack.rustdock("s13c_compose_pki", {}, [], "PKI written to")

    def test_the_helpers_and_the_principals_are_the_13c2_seams(self):
        source = REAL_TEST.read_text(encoding="utf-8")
        for helper in ("fn s13c_compose_pki()", "fn s13c_source_root()", "fn s13c_journal_seed()"):
            self.assertIn(helper, source)
        self.assertIn('"S13C_WRITE_SOURCE_ROOT"', source)
        self.assertIn('say(&format!("SEEDED {} allocations into {}"', source)
        self.assertIn('say(&format!("SOURCE ROOT written to {}"', source)
        self.assertIn('say(&format!("PKI written to {}', source)
        for name, role, folder in (("s13c2-publisher", "publisher", "test"), ("s13c2-trainer", "trainer", "test"), ("v3-runtime", "runtime", "svc")):
            self.assertIn(f'("{name}", "{role}", "{folder}")', source)
        for identity, (certificate, key, _) in harness.STACK_IDENTITIES.items():
            if identity != "installation":
                self.assertRegex(certificate, r"^(test|svc)/[a-z0-9-]+\.crt$")
                self.assertEqual(certificate[:-4], key[:-4])
        self.assertIn('installation.join("client.crt")', source)
        self.assertIn('installation.id', source)


class ExitAndOptionTests(unittest.TestCase):
    def record(self, rows, *, unchanged=True):
        coverage = report.s13d_coverage({"attacks": rows})
        return {"summary": harness.summarize(rows), "coverage": coverage, "attacks": rows, "standard_release_store_unchanged": unchanged}

    def test_a_candidate_run_passes_only_when_every_13d1b_row_ran_and_held(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        export = harness.CandidateExport(*write_export(Path(directory.name)))
        rows = harness.finalize_authz_rows(harness.candidate_rows(FakeStack(export), []), harness.StackIssuers())
        self.assertEqual(harness.authz_exit_status(self.record(rows), candidate_only=True), 0)
        self.assertEqual(harness.authz_exit_status(self.record(rows, unchanged=False), candidate_only=True), 1)
        self.assertEqual(harness.authz_exit_status(self.record(harness.pending_rows()), candidate_only=True), 1)
        broken = harness.finalize_authz_rows(harness.candidate_rows(FakeStack(export, allows_unallocated=True), []), harness.StackIssuers())
        self.assertEqual(harness.authz_exit_status(self.record(broken), candidate_only=True), 1)

    def test_a_full_run_without_an_export_still_passes_but_a_failed_stack_does_not(self):
        rows = map_rows()
        self.assertEqual(harness.authz_exit_status(self.record(rows), candidate_only=False), 0)
        failed = [{**row, "code": "HARNESS_ERROR"} if row["id"] == "CK8" else row for row in rows]
        self.assertEqual(harness.authz_exit_status(self.record(failed), candidate_only=False), 1)

    def test_the_candidate_options_parse_and_a_candidate_run_needs_no_privoke_pki_build(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--authz-families", "candidate", "--s13c-candidates", "c",
                                                  "--stack-name", "s13d1b", "--stack-cpus", "4"])
        self.assertEqual((args.authz_families, args.s13c_candidates, args.stack_name, args.stack_cpus), ("candidate", Path("c"), "s13d1b", "4"))
        self.assertEqual(harness.build_parser().parse_args([]).authz_families, "all")
        with tempfile.TemporaryDirectory() as directory:
            args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--authz-families", "candidate", "--release-dir", directory])
            with mock.patch.object(harness.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(harness.run_authz_target(args), 2)
                run.assert_not_called()
            self.assertIn("13d-1b rows cannot run: no 13c-2 export was named", errors.getvalue())
            self.assertNotIn("privoke-pki build", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
