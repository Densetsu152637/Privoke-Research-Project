"""Tests for the guarded-update and authentication security harness (UPDSEC-20261116).

The live-service checks start the real param-update-service servicer in-process on an
ephemeral loopback port with a private copy of the tracked legacy artifact. The full
harness (Go streaming service, hard kills, mutual-TLS stand-in) is run by
`evaluation/update_security.py`; these tests cover its contracts and the recorded JSON.
"""
from concurrent import futures
import hashlib
import json
import os
import re
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


OPENSSL_AVAILABLE = bool(shutil.which("openssl") or Path(r"C:\Program Files\Git\usr\bin\openssl.exe").exists())
RUST_BINARY = os.environ.get("PRIVOKE_RUST_MODEL_STREAMING_BINARY")
RUST_UPDATE_BINARY = os.environ.get("PRIVOKE_RUST_PARAM_UPDATE_BINARY")
RELEASE_STORE = Path(os.environ.get("PRIVOKE_STANDARD_RELEASES") or ROOT / "models/standard-releases")


class RustTargetOptionTests(unittest.TestCase):
    """`--target rust` is additive: the default target, its defaults and its exit codes are those of the recorded harness."""

    def test_default_target_and_options_are_the_recorded_harness(self):
        args = harness.build_parser().parse_args([])
        self.assertEqual(args.target, "go")
        self.assertIsNone(args.output)  # main() fills in the recorded record path for the go target
        self.assertEqual(args.image, "privoke-updsec-model-dev:20261116")
        self.assertEqual(args.release_dir, ROOT / "models/standard-releases")
        self.assertFalse(args.skip_docker)

    def test_rust_options_parse(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-image", "x:1", "--rust-binary", "bin", "--output", "out.json"])
        self.assertEqual((args.target, args.rust_image, args.rust_binary, args.output), ("rust", "x:1", Path("bin"), Path("out.json")))
        with self.assertRaises(SystemExit):
            harness.build_parser().parse_args(["--target", "python"])

    def test_both_targets_refuse_a_missing_release_store_before_hosting_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "absent")
            self.assertEqual(harness.main(["--release-dir", missing]), 2)
            self.assertEqual(harness.main(["--target", "rust", "--release-dir", missing]), 2)

    def test_rust_record_never_defaults_to_the_recorded_research_files(self):
        source = Path(harness.__file__).read_text(encoding="utf-8")
        self.assertIn('args.output or ROOT / ".tmp/update-security-rust-s03.json"', source)

    def test_registry_toml_has_the_transport_format(self):
        text = harness.registry_toml(["123e4567-e89b-42d3-a456-426614174000"], [("client-runtime", "runtime")], reporter=False)
        self.assertEqual(text.splitlines()[:2], ["version = 1", "reporter = false"])
        self.assertIn('[[installation]]\nid = "123e4567-e89b-42d3-a456-426614174000"', text)
        self.assertIn('[[service]]\nname = "client-runtime"\nrole = "runtime"', text)
        try:
            import tomllib
        except ImportError:  # Python 3.10
            return
        parsed = tomllib.loads(text)
        self.assertEqual(parsed["installation"][0]["id"], "123e4567-e89b-42d3-a456-426614174000")
        self.assertEqual(parsed["service"][0], {"name": "client-runtime", "role": "runtime"})

    def test_property_rule_needs_the_allowed_status_and_an_unchanged_store(self):
        rule = harness.evaluate_rust_row
        denied = ("PERMISSION_DENIED",)
        self.assertTrue(rule("rejected_unchanged", "rejected", "PERMISSION_DENIED", denied, True))
        self.assertFalse(rule("rejected_unchanged", "rejected", "NOT_FOUND", denied, True), "a refusal with the wrong status is not the expected control")
        self.assertFalse(rule("rejected_unchanged", "rejected", "PERMISSION_DENIED", denied, False))
        self.assertFalse(rule("rejected_unchanged", "accepted", "OK", denied, True))
        self.assertFalse(rule("rejected_unchanged", "not_run", "HARNESS_ERROR", None, True))
        self.assertTrue(rule("rejected_unchanged", "rejected", "UNAVAILABLE", None, True))
        self.assertTrue(rule("positive_control", "accepted", "OK", None, True))
        self.assertFalse(rule("positive_control", "rejected", "PERMISSION_DENIED", None, True))
        self.assertIsNone(rule("not_applicable", "not_applicable", None, None, None))

    def test_the_stage_3_row_families_are_declared(self):
        self.assertEqual(set(harness.RUST_ROW_IDS), {f"T{n}" for n in range(1, 13)} | {"R3", "R4", "R7", "R8", "R9", "X8"})
        self.assertEqual(harness.rust_row_family("R7-no-cert"), "R7")
        self.assertEqual(harness.rust_row_family("T12"), "T12")

    def test_stage_5_options_are_additive_and_default_to_the_stage_3_rows(self):
        args = harness.build_parser().parse_args(["--target", "rust"])
        self.assertEqual((args.rust_service, args.rust_update_image), ("model-streaming", harness.RUST_UPDATE_DEFAULT_IMAGE))
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "param-update", "--rust-update-image", "u:1", "--rust-binary", "bin"])
        self.assertEqual((args.rust_service, args.rust_update_image, args.rust_binary), ("param-update", "u:1", Path("bin")))
        with self.assertRaises(SystemExit):
            harness.build_parser().parse_args(["--target", "rust", "--rust-service", "telemetry"])

    def test_the_stage_5_row_families_are_declared_and_the_record_has_its_own_default_path(self):
        self.assertEqual(set(harness.RUST_UPDATE_ROW_IDS), {"A1", "A2", "A3", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "T14", "R1", "R2", "R5"})
        self.assertEqual(harness.rust_row_family("R5-replay"), "R5")
        source = Path(harness.__file__).read_text(encoding="utf-8")
        self.assertIn('args.output or ROOT / ".tmp/update-security-rust-s05.json"', source)
        self.assertNotEqual(harness.RUST_UPDATE_RECORD_ID, harness.RUST_RECORD_ID)

    def test_the_budgets_of_the_drift_rows_sit_below_what_the_rows_send(self):
        # E6 sends 25 updates of norm 2.0 (50 in total) and needs a budget under that to see a refusal.
        self.assertLess(harness.RUST_UPDATE_E6_BUDGET, 25 * 2.0)
        self.assertEqual(harness.RUST_UPDATE_E6_BUDGET % 2, 0)
        self.assertEqual(harness.RUST_UPDATE_R5_BUDGET % 1, 0)


@unittest.skipUnless(OPENSSL_AVAILABLE, "OpenSSL unavailable")
class RustPkiTests(unittest.TestCase):
    """The disposable PKI carries the identity profile the Rust server enforces."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.pki = harness.RustPki(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def describe(self, pem: bytes) -> str:
        import update_security_pki as pki

        return subprocess.run([pki.find_openssl(), "x509", "-noout", "-text"], input=pem, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()

    def test_every_identity_is_a_single_privoke_uri_san(self):
        for name in ("registered", "second", "expired", "future", "no-eku", "server-only", "foreign"):
            text = self.describe(self.pki.certs[name][0])
            self.assertIn(f"URI:{harness.URN_INSTALLATION}{self.pki.ids[name]}", text, name)
        self.assertIn(f"URI:{harness.URN_SERVICE}client-runtime", self.describe(self.pki.certs["runtime"][0]))
        self.assertIn(f"URI:{harness.URN_REPORTER}", self.describe(self.pki.certs["reporter"][0]))

    def test_extended_key_usage_profiles_match_the_r3_rows(self):
        self.assertIn("TLS Web Client Authentication", self.describe(self.pki.certs["registered"][0]))
        self.assertIn("TLS Web Server Authentication", self.describe(self.pki.certs["server-only"][0]))
        self.assertNotIn("TLS Web Client Authentication", self.describe(self.pki.certs["server-only"][0]))
        self.assertNotIn("Extended Key Usage", self.describe(self.pki.certs["no-eku"][0]))

    def test_validity_windows_make_the_expired_and_future_certificates(self):
        import datetime as dt

        def moment(text, label):
            found = re.search(label + r"\s*:\s*(.+?) GMT", text).group(1)
            return dt.datetime.strptime(" ".join(found.split()), "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)

        def window(name):
            text = self.describe(self.pki.certs[name][0])
            return moment(text, "Not Before"), moment(text, "Not After")

        now = dt.datetime.now(dt.timezone.utc)
        self.assertLess(window("expired")[1], now)
        self.assertGreater(window("future")[0], now)
        start, end = window("registered")
        self.assertLess(start, now)
        self.assertGreater(end, now)

    def test_crl_is_version_2_signed_and_not_stale(self):
        import update_security_pki as pki

        text = subprocess.run([pki.find_openssl(), "crl", "-noout", "-text"], input=self.pki.crl, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode()
        self.assertIn("Version 2", text)
        self.assertIn("Next Update", text)
        self.assertIn("X509v3 CRL Number", text)

    def test_published_files_name_only_registered_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            published = self.pki.publish(Path(directory))
            registry = (published / "registry.toml").read_text(encoding="utf-8")
            for name in ("registered", "second-registered", "expired", "future", "no-eku", "server-only", "foreign"):
                self.assertIn(self.pki.ids[name], registry)
            self.assertNotIn(self.pki.ids["second"], registry, "the unregistered control identity must not be in the registry")
            self.assertEqual({path.name for path in published.iterdir()}, {"server.crt", "server.key", "client-ca.pem", "crl.pem", "registry.toml"})


@unittest.skipUnless(RUST_BINARY and Path(RUST_BINARY).exists() and RELEASE_STORE.is_dir(),
                     "set PRIVOKE_RUST_MODEL_STREAMING_BINARY (and prepare models/standard-releases or set PRIVOKE_STANDARD_RELEASES) "
                     "to run the rows against a host binary")
class RustTargetRowsTests(unittest.TestCase):
    def test_every_stage_3_row_passes_against_a_host_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "record.json"
            code = harness.main(["--target", "rust", "--rust-binary", RUST_BINARY, "--release-dir", str(RELEASE_STORE), "--output", str(output)])
            record = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(record["summary"]["property_unmet_ids"], [])
        self.assertEqual(record["missing_row_families"], [])
        self.assertTrue(record["standard_release_store_unchanged"])
        self.assertEqual(code, 0)
        self.assertNotIn("PRIVATE KEY", json.dumps(record))


@unittest.skipUnless(OPENSSL_AVAILABLE, "OpenSSL unavailable")
class RustUpdatePkiTests(unittest.TestCase):
    """The stage 5 PKI registers the fuzzer's publisher identity, a second publisher and a trainer, and leaves one service unregistered."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.pki = harness.RustUpdatePki(Path(cls.directory.name))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_registry_names_the_publishers_and_the_trainer_but_not_the_stranger(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = (self.pki.publish(Path(directory)) / "registry.toml").read_text(encoding="utf-8")
        for name, role in (("server-fuzzer", "publisher"), ("test-trainer", "publisher"), ("trainer", "trainer")):
            self.assertIn(f'name = "{name}"' + chr(10) + f'role = "{role}"', registry)
        self.assertNotIn("stranger", registry)
        self.assertIn(self.pki.ids["registered"], registry)

    def test_every_stage_5_identity_is_a_single_service_urn(self):
        for identity, name in (("publisher", "server-fuzzer"), ("impostor", "test-trainer"), ("trainer", "trainer"), ("stranger", "stranger")):
            certificate, _ = self.pki.certs[identity]
            text = subprocess.run([__import__("update_security_pki").find_openssl(), "x509", "-noout", "-text"], input=certificate, stdout=subprocess.PIPE,
                                  check=True).stdout.decode()
            self.assertEqual(text.count("urn:privoke:"), 1, identity)
            self.assertIn(f"urn:privoke:service:{name}", text)
            self.assertIn("TLS Web Client Authentication", text)


@unittest.skipUnless(RUST_UPDATE_BINARY and Path(RUST_UPDATE_BINARY).exists() and OPENSSL_AVAILABLE,
                     "set PRIVOKE_RUST_PARAM_UPDATE_BINARY to run the stage 5 rows against a host binary")
class RustUpdateRowsTests(unittest.TestCase):
    def test_every_stage_5_row_passes_against_a_host_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "record.json"
            code = harness.main(["--target", "rust", "--rust-service", "param-update", "--rust-binary", RUST_UPDATE_BINARY, "--output", str(output)])
            record = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(record["summary"]["property_unmet_ids"], [])
        self.assertEqual(record["missing_row_families"], [])
        self.assertEqual(code, 0)
        self.assertNotIn("PRIVATE KEY", json.dumps(record))


if __name__ == "__main__":
    unittest.main()
