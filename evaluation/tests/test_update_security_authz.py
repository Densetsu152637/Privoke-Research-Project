"""Tests for stage 13d-1a: the authentication and authorisation rows against the Rust stack.

No test here starts a Rust container. They cover the contracts the run depends on: the `privoke-pki` spellings, the `denied_by`
vocabulary and the way the denying layer is derived, the coverage check of the attack map, the TLS record tools of the TL rows (against
a Python TLS server, so the observable they rely on is checked on a second implementation), the record shape, and the options.
The run itself (13d-2) hosts the containers.
"""
import contextlib
import datetime as dt
import io
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import update_security as harness  # noqa: E402
import update_security_pki as pki_tools  # noqa: E402
import update_security_report as report  # noqa: E402

ROOT = harness.ROOT
LEGACY_RECORDS = ("update-security-20261116", "update-security-20261117")
PLAN_VOCABULARY = ("tls_handshake", "revocation", "registry", "role_policy", "rpc_surface", "application", "client_admission", "not_denied")


def layer_row(row_id: str, layer: str, **overrides) -> dict:
    """A row that ran and was refused (or admitted) by `layer`, with the code and message that layer produces."""
    code, message = {"tls_handshake": ("UNAVAILABLE", "failed to connect"), "revocation": ("UNAVAILABLE", "failed to connect"),
                     "registry": ("PERMISSION_DENIED", "identity is not registered"), "role_policy": ("PERMISSION_DENIED", "role may not call this method"),
                     "rpc_surface": ("UNIMPLEMENTED", "method is not served on this listener"), "application": ("NOT_FOUND", "no such model"),
                     "client_admission": ("FAILED_PRECONDITION", "not admitted"), "not_denied": ("OK", "served")}[layer]
    row = {"id": row_id, "class": "unauthorized_retrieval", "path": "rust-public", "description": row_id, "expected": "rejected_unchanged",
           "observed": "accepted" if layer == "not_denied" else "rejected", "code": code, "message": message, "model_unchanged": True,
           "expected_codes": None, "identity": "registered", "property_met": layer != "not_denied", "gap": None, "evidence": [], "duration_s": 0.0,
           "scope_label": "transport (Rust)", "credential_issuer": "privoke-pki", "denied_by": layer}
    row.update(overrides)
    return row


def map_rows(layer: str = "tls_handshake") -> list[dict]:
    """One row for every matcher of the attack map (a pattern is instantiated), plus the pending rows as the harness records them."""
    ids = []
    for _, matchers, _ in report.S13D_ATTACKS:
        for matcher in matchers:
            ids.append(matcher.replace("*", "x"))
    rows = [layer_row(row_id, layer) for row_id in dict.fromkeys(ids) if row_id not in report.PENDING_13D_1B]
    return rows + harness.pending_rows()


def record_of(rows: list[dict]) -> dict:
    return {"attacks": rows}


class FakePki:
    issuers = {"registered": "privoke-pki", "expired": "openssl-helper", "trainer": "privoke-pki"}

    def credential_issuer(self, identity):
        return self.issuers.get(identity or "", "none")


class PkiToolTests(unittest.TestCase):
    def test_the_subcommands_are_the_ones_the_rust_cli_declares(self):
        source = (ROOT / "rust/tools/privoke-pki/src/main.rs").read_text(encoding="utf-8")
        enum = source[source.index("enum Command {"):source.index("fn validity")]
        variants = re.findall(r"^    ([A-Z][A-Za-z]+) \{", enum, re.M)
        kebab = {re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower() for name in variants}
        self.assertEqual(kebab, set(pki_tools.PKI_SUBCOMMANDS))

    def test_one_binary_and_only_known_subcommands(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                pki_tools.PkiTool(Path(directory))
            with self.assertRaises(ValueError):
                pki_tools.PkiTool(Path(directory), binary=Path("a"), linux_binary=Path("b"))
            tool = pki_tools.PkiTool(Path(directory), binary=Path("privoke-pki"))
            with self.assertRaises(ValueError):
                tool.run("sign-everything")

    def test_a_container_batch_mounts_the_work_directory_and_names_paths_inside_it(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()
            tool = pki_tools.PkiTool(work, linux_binary=work / "bin" / "privoke-pki")
            seen = {}

            def fake_run(argv, **_):
                seen["argv"] = argv
                return subprocess.CompletedProcess(argv, 0, stdout=f"{pki_tools.BATCH_MARK}\nfirst\n{pki_tools.BATCH_MARK}\nsecond\n", stderr="")

            with mock.patch.object(pki_tools.subprocess, "run", fake_run):
                outputs = tool.batch([["init-ca", "--dir", work / "ca", "--name", "n"], ["crl", "--ca-dir", work / "ca", "--out", work / "crl.pem", "--days", 2]])
            self.assertEqual(outputs, ["first\n", "second\n"])
            argv = seen["argv"]
            self.assertEqual(argv[:3], ["docker", "run", "--rm"])
            self.assertIn("--network", argv)
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            self.assertIn(f"{work}:/pki", argv)
            script = argv[-1]
            self.assertIn("--dir /pki/ca", script)
            self.assertIn("--out /pki/crl.pem", script)
            self.assertNotIn(str(work), script)
            self.assertEqual(tool.commands, ["privoke-pki init-ca --dir ca --name n", "privoke-pki crl --ca-dir ca --out crl.pem --days 2"])

    def test_a_failing_command_is_an_error_with_the_tool_message(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = pki_tools.PkiTool(Path(directory), binary=Path("privoke-pki"))
            failed = subprocess.CompletedProcess([], 1, stdout="", stderr="CA refused")
            with mock.patch.object(pki_tools.subprocess, "run", return_value=failed), self.assertRaisesRegex(RuntimeError, "CA refused"):
                tool.run("status", "--dir", "x")

    def test_registered_invalid_identities_are_appended_to_the_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.toml"
            path.write_text("version = 1\nreporter = true\n", encoding="utf-8")
            pki_tools.append_registry_installations(path, ["11111111-1111-4111-8111-111111111111"])
            text = path.read_text(encoding="utf-8")
            self.assertIn('[[installation]]\nid = "11111111-1111-4111-8111-111111111111"', text)
            self.assertTrue(text.startswith("version = 1"))


@unittest.skipUnless(os.environ.get("S13D_PKI_LINUX_BINARY"), "set S13D_PKI_LINUX_BINARY to a Linux privoke-pki build to run the container PKI test")
class PrivokePkiLiveTests(unittest.TestCase):
    def test_principals_come_from_privoke_pki_and_invalid_ones_from_openssl(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("S13D_PKI_WORK")) as directory:
            work = Path(directory).resolve()
            tool = pki_tools.PkiTool(work, linux_binary=Path(os.environ["S13D_PKI_LINUX_BINARY"]))
            pki = pki_tools.PrivokePki(work, tool)
            for name in (*pki.INSTALLATIONS, *pki.SERVICES, "reporter"):
                self.assertEqual(pki.issuers[name], "privoke-pki", name)
            for name in pki.INVALID:
                self.assertEqual(pki.issuers[name], "openssl-helper", name)
            registry = (work / "registry.toml").read_text(encoding="utf-8")
            for name in (*pki.INVALID,):
                self.assertIn(pki.ids[name], registry, name)
            self.assertNotIn(pki.ids["second"], registry)  # signed, never registered
            self.assertIn("reporter = true", registry)
            before = pki.crl_path.read_bytes()
            self.assertNotEqual(pki.revoke("x13-revoked"), before)
            self.assertIn("revoke --ca-dir client-ca --installation", " ".join(tool.commands))
            self.assertIn("privoke-pki crl --ca-dir client-ca", " ".join(tool.commands))


class DeniedByTests(unittest.TestCase):
    def test_the_vocabulary_is_the_plans(self):
        self.assertEqual(report.DENIED_BY, PLAN_VOCABULARY)

    def test_the_layer_comes_from_the_status_and_the_message(self):
        cases = [({"observed": "rejected", "code": "UNAVAILABLE", "message": "x"}, "tls_handshake"),
                 ({"observed": "rejected", "code": "PERMISSION_DENIED", "message": "role may not call this method"}, "role_policy"),
                 ({"observed": "rejected", "code": "PERMISSION_DENIED", "message": "identity is not registered"}, "registry"),
                 ({"observed": "rejected", "code": "PERMISSION_DENIED", "message": "identity is revoked"}, "registry"),
                 ({"observed": "rejected", "code": "PERMISSION_DENIED", "message": "claimed identity differs from the client certificate"}, "application"),
                 ({"observed": "rejected", "code": "UNIMPLEMENTED", "message": "method is not served on this listener"}, "rpc_surface"),
                 ({"observed": "rejected", "code": "NOT_FOUND", "message": "x"}, "application"),
                 ({"observed": "rejected", "code": "INVALID_ARGUMENT", "message": "x"}, "application"),
                 ({"observed": "accepted", "code": "OK", "message": "x"}, "not_denied"),
                 ({"observed": "not_run", "code": "NOT_RUN", "message": "x"}, None)]
        for row, layer in cases:
            self.assertEqual(harness.observed_layer(row), layer, row)

    def test_r9_submit_update_is_denied_by_the_rpc_surface(self):
        row = layer_row("R9-submit-update", "rpc_surface", denied_by=None)
        harness.finalize_authz_rows([row], FakePki())
        self.assertEqual(row["denied_by"], "rpc_surface")
        self.assertIs(row["property_met"], True)

    def test_a_tls_refusal_of_a_revocation_row_is_revocation(self):
        for row_id in ("CK6", "X13-revoked", "X13-corrupt-crl-keeps-revocation"):
            row = layer_row(row_id, "tls_handshake", denied_by=None)
            harness.finalize_authz_rows([row], FakePki())
            self.assertEqual(row["denied_by"], "revocation", row_id)
        row = layer_row("CK5", "tls_handshake", denied_by=None)
        harness.finalize_authz_rows([row], FakePki())
        self.assertEqual(row["denied_by"], "tls_handshake")

    def test_a_layer_that_contradicts_the_claim_is_recorded_as_observed_and_unmet(self):
        row = layer_row("CK3", "registry", denied_by=None)  # a registered installation must be refused by the role policy, not the registry
        harness.finalize_authz_rows([row], FakePki())
        self.assertEqual(row["denied_by"], "registry")
        self.assertIs(row["property_met"], False)
        self.assertIn("not the claimed role_policy", row["message"])

    def test_every_plaintext_row_expects_the_tls_layer(self):
        self.assertEqual(harness.claimed_layer("R6-checkpoint"), "tls_handshake")
        self.assertEqual(harness.claimed_layer("R6-telemetry-public"), "tls_handshake")

    def test_positive_controls_and_property_rows_get_no_denial(self):
        control = {**layer_row("CK0-trainer-health", "not_denied", denied_by=None), "expected": "positive_control", "property_met": True}
        property_row = {**layer_row("X13-no-restart", "not_denied", denied_by=None), "expected": "same_process"}
        harness.finalize_authz_rows([control, property_row], FakePki())
        self.assertEqual(control["denied_by"], "not_denied")
        self.assertIsNone(property_row["denied_by"])

    def test_the_claims_cover_the_attack_map(self):
        claimed = set(harness.CLAIMED_LAYER)
        for attack, matchers, _ in report.S13D_ATTACKS:
            for matcher in matchers:
                if matcher in report.PENDING_13D_1B:
                    continue
                if "*" in matcher:
                    self.assertTrue(any(re.fullmatch(matcher.replace("*", ".*"), name) for name in claimed), f"{attack}: {matcher}")
                else:
                    self.assertIn(matcher, claimed, f"{attack}: {matcher}")

    def test_every_claim_uses_a_layer_of_the_vocabulary(self):
        self.assertTrue(set(harness.CLAIMED_LAYER.values()) <= set(report.DENIED_BY))

    def test_issuers_follow_the_credential_and_agree_across_several_identities(self):
        pki = FakePki()
        self.assertEqual(harness.credential_issuer_of("registered", pki), "privoke-pki")
        self.assertEqual(harness.credential_issuer_of("expired", pki), "openssl-helper")
        self.assertEqual(harness.credential_issuer_of("no client certificate", pki), "none")
        self.assertEqual(harness.credential_issuer_of("registered, trainer", pki), "privoke-pki")
        self.assertEqual(harness.credential_issuer_of("registered, expired", pki), "none")


class CoverageTests(unittest.TestCase):
    def test_a_complete_record_covers_every_attack(self):
        coverage = report.s13d_coverage(record_of(map_rows()))
        self.assertTrue(coverage["ok"], coverage["problems"])
        self.assertTrue(all(attack["covered"] for attack in coverage["attacks"]))
        self.assertEqual(coverage["unmet_properties"], [])
        self.assertEqual(sorted(coverage["pending_13d_1b"]), sorted(report.PENDING_13D_1B))

    def test_an_attack_with_no_row_that_ran_fails(self):
        rows = [row for row in map_rows() if row["id"] not in ("TL1",)]
        coverage = report.s13d_coverage(record_of(rows))
        self.assertFalse(coverage["ok"])
        self.assertTrue(any("Replayed authenticated request" in problem for problem in coverage["problems"]))
        not_run = [{**row, "observed": "not_run", "code": "NOT_RUN", "denied_by": None} if row["id"] == "TL1" else row for row in map_rows()]
        self.assertFalse(report.s13d_coverage(record_of(not_run))["ok"])

    def test_one_row_is_enough_when_an_attack_has_several(self):
        rows = [row for row in map_rows() if row["id"] not in ("CK4", "CK8", "R7-reporter", "R10-installation")]
        self.assertTrue(report.s13d_coverage(record_of(rows))["ok"])  # Cross-identity misuse keeps CK2

    def test_a_not_denied_row_counts_and_is_reported_as_unmet(self):
        rows = [layer_row("TL1", "not_denied") if row["id"] == "TL1" else row for row in map_rows()]
        coverage = report.s13d_coverage(record_of(rows))
        self.assertTrue(coverage["ok"], coverage["problems"])
        self.assertEqual(coverage["unmet_properties"], ["TL1"])
        attack = next(item for item in coverage["attacks"] if item["attack"] == "Replayed authenticated request")
        self.assertTrue(attack["covered"])
        self.assertEqual(attack["denied_by"], ["not_denied"])

    def test_a_row_that_ran_without_a_denied_by_fails(self):
        rows = map_rows()
        del next(row for row in rows if row["id"] == "CK1")["denied_by"]
        problems = report.s13d_coverage(record_of(rows))["problems"]
        self.assertIn("CK1: no denied_by field", problems)

    def test_a_layer_outside_the_vocabulary_or_inconsistent_with_the_code_fails(self):
        rows = map_rows()
        next(row for row in rows if row["id"] == "CK1")["denied_by"] = "firewall"
        next(row for row in rows if row["id"] == "CK2")["denied_by"] = "rpc_surface"  # the code is PERMISSION_DENIED
        problems = "\n".join(report.s13d_coverage(record_of(rows))["problems"])
        self.assertIn("CK1: denied_by 'firewall' is not in the vocabulary", problems)
        self.assertIn("CK2: denied_by rpc_surface is inconsistent", problems)

    def test_a_pending_row_is_listed_and_never_a_failure(self):
        coverage = report.s13d_coverage(record_of(map_rows()))
        self.assertTrue(coverage["ok"])
        self.assertIn("CK8", coverage["pending_13d_1b"])
        self.assertTrue(all(row["denied_by"] is None for row in harness.pending_rows()))

    def test_the_flag_exits_zero_or_one_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            good, bad = Path(directory) / "good.json", Path(directory) / "bad.json"
            good.write_text(json.dumps(record_of(map_rows())), encoding="utf-8")
            bad.write_text(json.dumps(record_of([row for row in map_rows() if row["id"] != "CK5" and row["id"] != "R7-no-cert" and row["id"] != "R8-no-cert"
                                                  and row["id"] != "R10-no-cert"])), encoding="utf-8")
            legacy = ROOT / "paper/research/update-security-20261116.md"
            before = legacy.read_bytes()
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(report.main(["--record", str(good), "--check-s13d-coverage"]), 0)
                self.assertEqual(report.main(["--record", str(bad), "--check-s13d-coverage"]), 1)
            self.assertIn("pending 13d-1b: CK8", output.getvalue())
            self.assertIn("FAIL Missing credentials", output.getvalue())
            self.assertEqual(legacy.read_bytes(), before)

    def test_the_attack_map_is_the_plans(self):
        names = [attack for attack, _, _ in report.S13D_ATTACKS]
        self.assertEqual(names, ["Invalid credentials", "Expired certificate", "Missing credentials", "Wrong client identity", "Unauthorised model retrieval",
                                 "Unauthorised update submission", "Unauthorised publication", "Replayed authenticated request", "Tampered request",
                                 "Cross-identity misuse"])
        cross = {attack: references for attack, _, references in report.S13D_ATTACKS if references}
        self.assertEqual(cross, {"Replayed authenticated request": ("13c C2a", "13c C2b"), "Tampered request": ("13c C9",)})


class RecordTests(unittest.TestCase):
    def args(self, **overrides):
        values = dict(rust_image="privoke-model-streaming-rust:dev", rust_update_image="privoke-param-update-rust:dev",
                      rust_telemetry_image="privoke-telemetry-rust:dev", no_v3=False)
        values.update(overrides)
        return SimpleNamespace(**values)

    def record(self) -> dict:
        rows = harness.finalize_authz_rows(map_rows(), FakePki())
        for row in rows:
            row["denied_by"] = row["denied_by"]  # the helper rows already carry theirs
        static = [{"id": "ST1", "claim": "x", "holds": True, "detail": ["ok"]}]
        pki = SimpleNamespace(issuers=FakePki.issuers)
        return harness.authz_record(self.args(), rows, pki, static, ["privoke-pki init-ca --dir client-ca"], ["CK8 pending"], "log")

    def test_the_record_has_the_shared_header_and_passes_its_own_check(self):
        record = self.record()
        for name in report.RECORD_HEADER:
            self.assertIn(name, record)
        self.assertEqual(set(record["chain"]), {"threat", "defense", "experiment", "metric", "evidence"})
        self.assertEqual(set(record["build"]), {"branch", "sha", "clean"})
        self.assertEqual(record["schema"], report.AUTHZ_SCHEMA)
        self.assertTrue(set(record["scope_label"]) <= set(report.SCOPE_LABELS))
        self.assertEqual(report.check_authz_record(record), [])

    def test_the_gap_table_cites_both_earlier_records(self):
        ids = {gap["id"] for gap in self.record()["gaps"]}
        self.assertTrue({"UPDSEC-20261116", "UPDSEC-20261117"} <= ids)
        record = self.record()
        record["gaps"] = [gap for gap in record["gaps"] if gap["id"] != "UPDSEC-20261117"]
        self.assertIn("the gap table does not cite UPDSEC-20261117", report.check_authz_record(record))

    def test_the_check_reports_a_missing_header_a_bad_label_and_wrong_totals(self):
        record = self.record()
        del record["chain"]
        record["attacks"][0]["scope_label"] = "somewhere"
        record["attacks"][1]["credential_issuer"] = "gpg"
        record["summary"]["total_rows"] += 1
        problems = "\n".join(report.check_authz_record(record))
        self.assertIn("header field chain is missing", problems)
        self.assertIn("scope_label 'somewhere'", problems)
        self.assertIn("credential_issuer 'gpg'", problems)
        self.assertIn("summary counts", problems)

    def test_the_generated_tables_come_from_the_record_and_splice_idempotently(self):
        record = self.record()
        tables = report.render_authz_tables(record)
        self.assertIn("### Attack coverage", tables)
        self.assertIn("| Replayed authenticated request | TL1 |", tables)
        self.assertIn("13c C2a, 13c C2b", tables)
        self.assertIn("### Pending rows (13d-1b)", tables)
        self.assertIn("CK8", tables)
        self.assertEqual(report.render_tables(record), tables)
        document = f"head\n{report.BEGIN}\nold\n{report.END}\ntail\n"
        once = report.splice(document, tables)
        self.assertEqual(report.splice(once, tables), once)

    def test_every_pending_row_names_its_reason_and_is_not_a_pass(self):
        for row in harness.pending_rows():
            self.assertEqual(row["observed"], "not_run")
            self.assertIsNone(row["property_met"])
            self.assertIn("13d-1b", row["message"])
        self.assertEqual([row["id"] for row in harness.pending_rows()], list(report.PENDING_13D_1B))


class LegacyRecordTests(unittest.TestCase):
    def test_the_recorded_updsec_tables_reproduce_unchanged(self):
        for stem in LEGACY_RECORDS:
            record = json.loads((ROOT / f"paper/research/{stem}.json").read_text(encoding="utf-8"))
            document = (ROOT / f"paper/research/{stem}.md").read_text(encoding="utf-8")
            self.assertEqual(report.splice(document, report.render_tables(record)), document, stem)

    def test_a_legacy_record_is_not_rendered_as_an_authz_record(self):
        record = json.loads((ROOT / "paper/research/update-security-20261117.json").read_text(encoding="utf-8"))
        self.assertNotEqual(record.get("schema"), report.AUTHZ_SCHEMA)


class OptionTests(unittest.TestCase):
    def test_the_authz_service_and_the_pki_options_parse(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--pki-linux-binary", "p", "--pki-runner-image", "img"])
        self.assertEqual((args.rust_service, args.pki_linux_binary, args.pki_runner_image), ("authz", Path("p"), "img"))
        self.assertIsNone(harness.build_parser().parse_args([]).pki_binary)

    def test_the_run_refuses_without_a_privoke_pki_build_before_hosting_anything(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz"])
        with mock.patch.object(harness.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(harness.run_authz_target(args), 2)
            run.assert_not_called()
        self.assertIn("--pki-linux-binary", errors.getvalue())

    def test_the_run_refuses_a_missing_release_store_before_hosting_anything(self):
        args = harness.build_parser().parse_args(["--target", "rust", "--rust-service", "authz", "--pki-binary", "p", "--release-dir", "no-such-directory"])
        with mock.patch.object(harness.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(harness.run_authz_target(args), 2)
            run.assert_not_called()
        self.assertIn("standard release store not found", errors.getvalue())

    def test_existing_families_keep_their_signatures_and_the_legacy_pki_revokes_through_openssl(self):
        import inspect

        self.assertIs(inspect.signature(harness.run_x13_rows).parameters["no_v3"].default, True)
        self.assertTrue(callable(harness.RustPki.revoke))
        self.assertTrue(callable(pki_tools.PrivokePki.revoke))


class CheckpointServiceTests(unittest.TestCase):
    def test_the_service_enables_the_store_over_an_empty_directory_and_polls_for_reloads(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            pki = SimpleNamespace(publish=lambda target: (target.mkdir(parents=True, exist_ok=True), target)[1], certs={}, server_ca=SimpleNamespace(cert=b""))
            service = harness.RustCheckpointService(work, pki, "checkpoint", image="img")
            settings = service._settings("/models", "/data")
            self.assertEqual(settings["V3_STORE"], "/v3-store")
            self.assertEqual(settings["V3_DRIFT_BOUNDS"], "/config/v3-drift-bounds.toml")
            self.assertNotIn("V3_INITIAL", settings)
            self.assertNotIn("V3_PINNED", settings)
            self.assertEqual(settings["FUZZER_PROMPT_COUNT"], "0")
            self.assertEqual(service.command_arguments("/pki")[-2:], ["--reload-poll-secs", "1"])
            self.assertIsNone(service.binary)

    def test_the_drift_bounds_and_source_root_the_container_names_exist_in_the_image_inputs(self):
        self.assertTrue((ROOT / "rust/services/param-update/config/v3-drift-bounds.toml").is_file())

    def test_the_policy_the_rows_assume_is_the_servers(self):
        source = (ROOT / "rust/services/param-update/src/server.rs").read_text(encoding="utf-8")
        policy = source[source.index("pub fn policy()"):source.index("/// A running server")]
        self.assertRegex(policy, r"CHECKPOINT_COMMIT, &\[Role::Publisher, Role::Trainer\]")
        self.assertRegex(policy, r"CHECKPOINT_ROLLBACK, &\[Role::Publisher\]")
        self.assertRegex(policy, r"CHECKPOINT_STAGE, &\[Role::Publisher, Role::Trainer, Role::Runtime\]")
        self.assertNotIn("TrainingService", policy)  # CK9 relies on an RPC the policy does not list
        self.assertNotIn("SubmitParameterUpdate", policy)


def tls_fixture(directory: Path):
    """A CA, a server certificate for 127.0.0.1 and a client certificate, issued by the OpenSSL helper."""
    authority = pki_tools.TestAuthority(directory, "tls-ca")
    server = authority.issue("server", cn="server", usage="serverAuth", san="DNS:localhost,IP:127.0.0.1")
    client = authority.issue("client", cn="client", usage="clientAuth")
    return authority, server, client


class EchoServer:
    """A TLS 1.3 server that requires a client certificate and answers b"ping" with b"pong"."""

    def __init__(self, directory: Path, authority, server):
        (directory / "server.crt").write_bytes(server[0])
        (directory / "server.key").write_bytes(server[1])
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(str(directory / "server.crt"), str(directory / "server.key"))
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cadata=authority.cert.decode())
        self.served, self.failed = 0, 0
        self._stop = threading.Event()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw):
        raw.settimeout(3)
        try:
            with self.context.wrap_socket(raw, server_side=True) as connection:
                if connection.recv(16) == b"ping":
                    connection.sendall(b"pong")
                    self.served += 1
        except (ssl.SSLError, OSError):
            self.failed += 1

    def close(self):
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=2)


def client_exchange(directory: Path, authority, client, port: int) -> bytes:
    """One authenticated request; returns the reply, or b"" when the connection was refused or aborted."""
    (directory / "client.crt").write_bytes(client[0])
    (directory / "client.key").write_bytes(client[1])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata=authority.cert.decode())
    context.load_cert_chain(str(directory / "client.crt"), str(directory / "client.key"))
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw, context.wrap_socket(raw, server_hostname="127.0.0.1") as connection:
            connection.settimeout(3)
            connection.sendall(b"ping")
            return connection.recv(16)
    except (ssl.SSLError, OSError):
        return b""


class TlsRecordToolTests(unittest.TestCase):
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

    def record_exchange(self, **proxy_options):
        proxy = pki_tools.RecordingProxy(self.echo.port, **proxy_options)
        try:
            reply = client_exchange(self.work, self.authority, self.client, proxy.port)
            depends_on = proxy.client_application_records_before_response()
            time.sleep(0.3)
        finally:
            proxy.close()
        return reply, proxy, depends_on

    def test_the_proxy_forwards_and_records_a_tls_exchange_as_records(self):
        reply, proxy, depends_on = self.record_exchange()
        self.assertEqual(reply, b"pong")
        sent, answered = proxy.captured()
        self.assertTrue(pki_tools.tls_records(sent) and pki_tools.tls_records(answered))
        self.assertEqual(pki_tools.tls_records(sent)[0][0], 22)  # the ClientHello
        self.assertGreaterEqual(depends_on, 1)
        self.assertGreater(pki_tools.stream_stats(answered)["application_bytes"], 0)

    def test_a_bit_flipped_in_a_record_the_request_depends_on_aborts_the_exchange(self):
        _, _, depends_on = self.record_exchange()
        self.assertGreaterEqual(depends_on, 1)
        for record in range(1, depends_on + 1):
            before = self.echo.served
            reply, proxy, _ = self.record_exchange(flip_record=record)
            self.assertTrue(proxy.flipped, record)
            self.assertEqual(reply, b"", record)
            self.assertEqual(self.echo.served, before, record)

    def test_replaying_the_recorded_bytes_gets_an_alert_and_no_reply(self):
        reply, proxy, _ = self.record_exchange()
        self.assertEqual(reply, b"pong")
        sent, answered = proxy.captured()
        served = self.echo.served
        replay = pki_tools.replay_bytes(self.echo.port, sent, wait=3.0)
        original, refused = pki_tools.stream_stats(answered), replay["stats"]
        self.assertTrue(pki_tools.replay_refused(original, refused, replay["closed"]), (original, refused, replay["closed"]))
        self.assertEqual(self.echo.served, served)
        # The same test refuses to call a live answer a refusal: the original exchange, judged against itself, is not one.
        self.assertFalse(pki_tools.replay_refused(original, original, True))

    def test_a_certificate_from_another_ca_is_refused_before_any_request_is_sent(self):
        foreign = pki_tools.TestAuthority(self.work, "foreign-ca")
        mitm_certificate = foreign.issue("mitm", cn="mitm", usage="serverAuth", san="DNS:localhost,IP:127.0.0.1")
        mitm = pki_tools.MitmListener(mitm_certificate[0], mitm_certificate[1], self.work / "mitm")
        try:
            self.assertEqual(client_exchange(self.work, self.authority, self.client, mitm.port), b"")
            time.sleep(0.3)
            seen = mitm.stats()
            self.assertEqual((seen["handshakes_completed"], seen["application_bytes"]), (0, 0))
            # Trusting the foreign CA, the same listener completes a handshake: the refusal above is about the CA.
            self.assertNotEqual(client_exchange(self.work, foreign, self.client, mitm.port), b"pong")
            time.sleep(0.3)
            self.assertEqual(mitm.stats()["handshakes_completed"], 1)
        finally:
            mitm.close()


class TlsPureFunctionTests(unittest.TestCase):
    def test_records_stop_at_garbage_and_at_a_truncated_record(self):
        record = bytes([23, 3, 3, 0, 4]) + b"abcd"
        self.assertEqual(pki_tools.tls_records(record + record), [(23, 0, 9), (23, 9, 9)])
        self.assertEqual(pki_tools.tls_records(record + b"\x99\x03\x03\x00\x01x"), [(23, 0, 9)])
        self.assertEqual(pki_tools.tls_records(record + record[:7]), [(23, 0, 9)])
        self.assertEqual(pki_tools.tls_records(b""), [])

    def test_flipping_a_bit_changes_one_bit_of_the_body_and_keeps_the_header(self):
        record = bytes([23, 3, 3, 0, 8]) + bytes(range(8))
        flipped = pki_tools.flip_bit(record)
        self.assertEqual(flipped[:5], record[:5])
        differences = [(a ^ b) for a, b in zip(record, flipped) if a != b]
        self.assertEqual(len(differences), 1)
        self.assertEqual(bin(differences[0]).count("1"), 1)
        self.assertEqual(len(pki_tools.tls_records(flipped)), 1)

    def test_a_replay_is_refused_only_when_closed_alert_sized_and_smaller(self):
        original = {"application_bytes": 900, "last_record_bytes": 24}
        alert = {"application_bytes": 700, "last_record_bytes": 24}
        self.assertTrue(pki_tools.replay_refused(original, alert, True))
        self.assertFalse(pki_tools.replay_refused(original, alert, False))
        self.assertFalse(pki_tools.replay_refused(original, {**alert, "last_record_bytes": 300}, True))
        self.assertFalse(pki_tools.replay_refused(original, {**alert, "application_bytes": 900}, True))

    def test_a_stream_that_is_not_tls_has_no_records(self):
        self.assertEqual(pki_tools.stream_stats(b"plain text, no record")["records"], 0)


class AdoptedAuthorityTests(unittest.TestCase):
    def test_the_helper_signs_with_an_adopted_ca_so_invalid_credentials_chain_to_the_real_one(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            try:
                original = pki_tools.TestAuthority(work, "operator-ca")
            except RuntimeError as error:
                self.skipTest(str(error))
            adopted = pki_tools.TestAuthority.adopt(work, "adopted", original.cert, (original.dir / "ca.key").read_bytes())
            now = dt.datetime.now(dt.timezone.utc)
            expired = adopted.issue("expired", cn="x", usage="clientAuth", start=now - dt.timedelta(hours=10), end=now - dt.timedelta(hours=5))
            plain = adopted.issue_extensions("plain", cn="y", extensions=["subjectAltName=URI:urn:privoke:installation:x"],
                                                                  start=now - dt.timedelta(hours=1), end=now + dt.timedelta(hours=1))
            for name, certificate in (("expired", expired[0]), ("plain", plain[0])):
                (work / f"{name}.pem").write_bytes(certificate)
            openssl = pki_tools.find_openssl()
            check = lambda name, *extra: subprocess.run([openssl, "verify", "-CAfile", str(work / "operator-ca" / "ca.crt"), *extra, str(work / f"{name}.pem")],  # noqa: E731
                                                         text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "MSYS2_ARG_CONV_EXCL": "*"})
            self.assertIn("expired", (check("expired").stdout + check("expired").stderr).lower())
            self.assertEqual(check("plain").returncode, 0, check("plain").stderr)
            self.assertNotIn("extendedKeyUsage", subprocess.run([openssl, "x509", "-in", str(work / "plain.pem"), "-noout", "-text"], text=True,
                                                                 stdout=subprocess.PIPE, env={**os.environ, "MSYS2_ARG_CONV_EXCL": "*"}).stdout)


if __name__ == "__main__":
    unittest.main()
