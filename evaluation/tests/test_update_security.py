"""Tests for the guarded-update and authentication security harness (UPDSEC-20261116).

The live-service checks start the real param-update-service servicer in-process on an
ephemeral loopback port with a private copy of the tracked legacy artifact. The full
harness (Go streaming service, hard kills, mutual-TLS stand-in) is run by
`evaluation/update_security.py`; these tests cover its contracts and the recorded JSON.
"""
from concurrent import futures
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import update_security as harness  # noqa: E402
import update_security_report as report  # noqa: E402

ROOT = harness.ROOT
RECORD = ROOT / "paper/research/update-security-20261116.json"
DOCUMENT = ROOT / "paper/research/update-security-20261116.md"
SERVICE_APP = ROOT / "services/param-update-service/app"


class WireHelperTests(unittest.TestCase):
    def test_raw_update_round_trips_through_the_protocol_message(self):
        from privoke.v1 import parameters_pb2 as pb

        payload = harness.raw_update("m", "v1", [harness.raw_gradient(b"g", struct.pack("<2f", 1.0, 2.0), (2,))])
        message = pb.ParameterUpdateRequest.FromString(payload)
        self.assertEqual((message.model_id, message.base_version, message.gradients[0].name), ("m", "v1", "g"))
        self.assertEqual(list(message.gradients[0].values), [1.0, 2.0])
        self.assertEqual(list(message.gradients[0].shape), [2])

    def test_misaligned_packed_floats_do_not_decode(self):
        from google.protobuf.message import DecodeError
        from privoke.v1 import parameters_pb2 as pb

        payload = harness.raw_update("m", "v1", [harness.raw_gradient(b"g", b"\x00\x00\x80", (1,))])
        with self.assertRaises(DecodeError):
            pb.ParameterUpdateRequest.FromString(payload)


class SummaryTests(unittest.TestCase):
    def test_summary_counts_outcomes_and_unmet_properties(self):
        rows = [{"id": "a", "class": "stale", "observed": "rejected", "property_met": True},
                {"id": "b", "class": "stale", "observed": "accepted", "property_met": False},
                {"id": "c", "class": "interrupted", "observed": "applied_once", "property_met": True},
                {"id": "d", "class": "interrupted", "observed": "not_applicable", "property_met": None, "gap": "GAP-X"}]
        summary = harness.summarize(rows)
        self.assertEqual(summary["total_rows"], 4)
        self.assertEqual(summary["by_class"]["stale"]["rejected"], 1)
        self.assertEqual(summary["by_class"]["stale"]["accepted"], 1)
        self.assertEqual(summary["by_class"]["interrupted"]["property_na"], 1)
        self.assertEqual(summary["property_unmet_ids"], ["b"])
        self.assertEqual(summary["gap_ids_exercised"], ["GAP-X"])


class StaticEvidenceTests(unittest.TestCase):
    def test_every_static_claim_holds_in_this_revision(self):
        for item in harness.static_evidence():
            self.assertTrue(item["holds"], item)

    def test_gap_evidence_references_existing_static_checks(self):
        ids = {item["id"] for item in harness.static_evidence()}
        for gap in harness.GAPS:
            self.assertTrue(set(gap["evidence"]) <= ids, gap)


@unittest.skipUnless(shutil.which("openssl") or Path(r"C:\Program Files\Git\usr\bin\openssl.exe").exists(), "OpenSSL unavailable")
class PkiTests(unittest.TestCase):
    def test_backdated_certificate_is_expired_and_current_one_verifies(self):
        import datetime as dt
        import update_security_pki as pki

        with tempfile.TemporaryDirectory() as directory:
            authority = pki.TestAuthority(Path(directory), "ca")
            now = dt.datetime.now(dt.timezone.utc)
            authority.issue("good", cn="good", usage="clientAuth")
            authority.issue("old", cn="old", usage="clientAuth", start=now - dt.timedelta(hours=10), end=now - dt.timedelta(hours=5))

            def verify(name):
                return subprocess.run([authority.openssl, "verify", "-CAfile", "ca.crt", f"{name}.crt"], cwd=authority.dir,
                                      text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(verify("good").returncode, 0)
            expired = verify("old")
            self.assertNotEqual(expired.returncode, 0)
            self.assertIn("expired", expired.stderr)


@unittest.skipUnless(list((ROOT / "services/param-update-service").glob("generated/privoke/v1/parameters_pb2.py")),
                     "run evaluation/setup-host.py first")
class LiveUpdaterTests(unittest.TestCase):
    """The real SubmitParameterUpdate servicer over a real gRPC channel (legacy update path)."""

    @classmethod
    def setUpClass(cls):
        import grpc
        from privoke_model import load_artifact
        # An earlier test may have left another service's top-level modules (the fuzzer's
        # ``config``) in sys.modules; import the updater's modules in isolation, then restore.
        names = {path.stem for path in SERVICE_APP.glob("*.py")} | {"server", "config"}
        saved = {name: sys.modules.pop(name) for name in names if name in sys.modules}
        sys.path.insert(0, str(SERVICE_APP))
        try:
            import server as updater
        finally:
            sys.path.remove(str(SERVICE_APP))
            for name in names:
                sys.modules.pop(name, None)
            sys.modules.update(saved)

        cls.grpc, cls.load_artifact = grpc, staticmethod(load_artifact)
        cls.directory = tempfile.TemporaryDirectory()
        base = Path(cls.directory.name)
        cls.artifact = base / "privoke-balanced.json"
        shutil.copyfile(ROOT / "models/privoke-balanced.json", cls.artifact)
        servicer = updater.ParamUpdateService(base / "updates.jsonl", expected_model_id="privoke-balanced", max_abs_gradient=1.0,
                                              model_artifact_path=cls.artifact)
        cls.server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        updater.parameters_pb2_grpc.add_ParamUpdateServiceServicer_to_server(servicer, cls.server)
        port = cls.server.add_insecure_port("127.0.0.1:0")
        cls.server.start()
        cls.channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        cls.pb = updater.parameters_pb2
        cls.stub = updater.parameters_pb2_grpc.ParamUpdateServiceStub(cls.channel)

    @classmethod
    def tearDownClass(cls):
        cls.channel.close()
        cls.server.stop(0).wait(2)
        cls.directory.cleanup()

    def request(self, values, *, shape=(4,), name="head.sensitivity.bias", base=None, metadata=None, source="tester"):
        message = self.pb.ParameterUpdateRequest(source_id=source, model_id="privoke-balanced", metadata=metadata or {},
                                                 base_version=base or self.version())
        message.gradients.add(name=name, shape=list(shape), values=list(values))
        return message

    def version(self):
        return json.loads(self.artifact.read_text())["version"]

    def digest(self):
        return hashlib.sha256(self.artifact.read_bytes()).hexdigest()

    def submit(self, message):
        try:
            return self.stub.SubmitParameterUpdate(message, timeout=20)
        except self.grpc.RpcError as error:
            return error

    def assertRejectedUnchanged(self, message, code):
        before = self.digest()
        result = self.submit(message)
        self.assertIsInstance(result, self.grpc.RpcError)
        self.assertEqual(result.code(), code, result.details())
        self.assertEqual(self.digest(), before)

    def test_non_finite_wrong_shape_and_excessive_values_leave_the_model_unchanged(self):
        invalid = self.grpc.StatusCode.INVALID_ARGUMENT
        for values in ([float("nan")] * 4, [float("inf")] + [0.0] * 3, [-float("inf")] + [0.0] * 3, [1.0000001] + [0.0] * 3, [-2.0] + [0.0] * 3):
            with self.subTest(values=values):
                self.assertRejectedUnchanged(self.request(values), invalid)
        self.assertRejectedUnchanged(self.request([1e-4] * 128, shape=(4, 32), name="head.sensitivity.weight"), invalid)
        self.assertRejectedUnchanged(self.request([1e-4] * 5, shape=(5,)), invalid)

    def test_stale_and_replayed_updates_apply_exactly_once(self):
        first = self.request([1e-4] * 4, metadata={"request_id": "unit-1"})
        base = first.base_version
        ack = self.submit(first)
        self.assertTrue(ack.accepted)
        after_first = self.digest()
        replay = self.submit(first)
        self.assertEqual(replay.applied_version, ack.applied_version)
        self.assertEqual(self.digest(), after_first)
        self.assertRejectedUnchanged(self.request([1e-4] * 4, base=base), self.grpc.StatusCode.FAILED_PRECONDITION)
        conflicting = self.request([2e-4] * 4, base=base, metadata={"request_id": "unit-1"})
        self.assertRejectedUnchanged(conflicting, self.grpc.StatusCode.INVALID_ARGUMENT)

    def test_concurrent_duplicates_apply_once(self):
        request = self.request([1e-4] * 4, metadata={"request_id": "unit-dup"})
        before = int(json.loads(self.artifact.read_text())["metadata"]["training_revision"])
        with futures.ThreadPoolExecutor(8) as pool:
            results = list(pool.map(lambda _: self.submit(request), range(8)))
        self.assertTrue(all(not isinstance(r, self.grpc.RpcError) for r in results))
        self.assertEqual(len({r.applied_version for r in results}), 1)
        self.assertEqual(int(json.loads(self.artifact.read_text())["metadata"]["training_revision"]) - before, 1)
        self.load_artifact(self.artifact)  # still a valid, checksummed artifact

    def test_truncated_wire_message_is_rejected_without_change(self):
        before = self.digest()
        method = self.channel.unary_unary("/privoke.v1.ParamUpdateService/SubmitParameterUpdate",
                                          request_serializer=lambda v: v, response_deserializer=lambda v: v)
        payload = harness.raw_update("privoke-balanced", self.version(), [harness.raw_gradient(b"g", b"\x00\x00\x80", (1,))])
        with self.assertRaises(self.grpc.RpcError) as caught:
            method(payload, timeout=10)
        self.assertNotEqual(caught.exception.code(), self.grpc.StatusCode.OK)
        self.assertEqual(self.digest(), before)

    def test_gap_any_peer_with_any_source_id_can_publish(self):
        """Documents GAP-NO-PUBLISHER-AUTH: a valid update is accepted with no credential and a forged source_id."""
        ack = self.submit(self.request([1e-4] * 4, source="server-fuzzer"))
        self.assertTrue(ack.accepted)
        self.assertEqual(json.loads(self.artifact.read_text())["metadata"]["last_update_source"], "server-fuzzer")


class RecordedResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RECORD.exists():
            raise unittest.SkipTest("record not generated yet")
        cls.record = json.loads(RECORD.read_text(encoding="utf-8"))

    def test_summary_re_derives_from_the_attack_rows(self):
        self.assertEqual(harness.summarize(self.record["attacks"]), self.record["summary"])

    def test_every_g7_and_g8_class_has_an_observed_row(self):
        ids = {row["id"]: row for row in self.record["attacks"]}
        for goal, names in (("G7", harness.G7_CLASSES), ("G8", harness.G8_CLASSES)):
            for name in names:
                members = self.record["goal_coverage"][goal][name]
                self.assertTrue(members, (goal, name))
                self.assertTrue(any(ids[i]["observed"] != "not_run" for i in members), (goal, name))

    def test_rows_use_declared_outcomes_and_known_gaps(self):
        gaps = {gap["id"] for gap in self.record["gaps"]}
        for row in self.record["attacks"]:
            self.assertIn(row["observed"], harness.OUTCOMES, row["id"])
            self.assertNotEqual(row.get("code"), "HARNESS_ERROR", row["id"])
            if row.get("gap"):
                self.assertIn(row["gap"], gaps)
        self.assertEqual(len({row["id"] for row in self.record["attacks"]}), len(self.record["attacks"]))

    def test_every_unmet_property_is_a_declared_gap(self):
        for row in self.record["attacks"]:
            if row["property_met"] is False:
                self.assertTrue(row.get("gap"), f"{row['id']} failed its property without a declared gap")

    def test_standard_release_store_and_rejections_left_models_unchanged(self):
        self.assertTrue(self.record["standard_release_store_unchanged"])
        for row in self.record["attacks"]:
            if row["expected"] == "rejected_unchanged" and row["observed"] == "rejected" and row["path"] != "transport-standin":
                self.assertTrue(row["model_unchanged"], row["id"])

    def test_record_contains_no_key_material(self):
        text = RECORD.read_text(encoding="utf-8")
        for marker in ("PRIVATE KEY", "BEGIN CERTIFICATE"):
            self.assertNotIn(marker, text)

    def test_markdown_tables_match_the_record(self):
        document = DOCUMENT.read_text(encoding="utf-8")
        generated = document.split(report.BEGIN, 1)[1].split(report.END, 1)[0].strip("\n")
        self.assertEqual(generated + "\n", report.render_tables(self.record))


if __name__ == "__main__":
    unittest.main()
