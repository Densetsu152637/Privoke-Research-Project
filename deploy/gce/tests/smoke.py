#!/usr/bin/env python3
"""Smoke test for the Rust cloud topology (stages 8a and 8b of docs/plans/rust-server-rewrite.md).

It talks to the two public listeners as a host client, so it runs unchanged against loopback ports (staging, CI) and
against the public endpoints (external smoke). It starts no stack and runs no test inside a container; the optional
start-up checks only run images with `docker run` and expect them to refuse to start.

What it asserts, in order:

* mutual TLS is required on both listeners: no client certificate, an untrusted server, and (when supplied) a certificate
  from another CA all fail;
* authorisation: an installation is served by the model listener and refused by the telemetry listener, the reporter
  credential the other way round, and an unregistered installation (when supplied) is refused;
* private RPCs are denied (R9): the internal and service RPCs answer UNIMPLEMENTED on both public listeners;
* the standard V3 package is fetched over `GetModelPackage` and `StreamModelAsset` and its pin is verified (G8);
* a locally randomised telemetry report is accepted with the reporter credential;
* with `--images`, every cloud image started without its CA, CRL or client CA exits non-zero without serving (a container
  that cannot authenticate its callers must not start).

Credential directory (`--creds`): `server-ca.pem`, `installation.crt`, `installation.key`, `reporter.crt`,
`reporter.key`; optional `unregistered.crt` and `unregistered.key` (signed by the client CA, not in the registry) and
`foreign.crt` and `foreign.key` (signed by another CA). Nothing in this file is a credential.

Requires Python with `grpcio`, `grpcio-tools` and `protobuf`. Exit status 0 only if every check passed; any unexpected
accept is a failure.

    python deploy/gce/tests/smoke.py --creds DIR --model-target 127.0.0.1:50443 --telemetry-target 127.0.0.1:58443 \\
        --server-name stack.example.com [--images PREFIX:TAG --pki-dir DIR --live-dir DIR]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

import grpc

ROOT = Path(__file__).resolve().parents[3]
PRIVACY_PATH = ROOT / "extension/client-runtime/src/telemetry/privacy.py"
PINS_PATH = ROOT / "shared/python/privoke_model/standard_v3.py"
PROTO_DIR = ROOT / "shared/proto"
CHANNEL_OPTIONS = (("grpc.enable_http_proxy", 0), ("grpc.max_receive_message_length", 8 * 1024 * 1024))

# Rust images take the five TLS flags and must refuse to start without them.
RUST_IMAGES = ("model-streaming-service", "telemetry-service", "param-update-service", "analysis-service")
PRIVATE_RPCS = (
    "/privoke.v1.ModelStreamingService/GetModelParameters",
    "/privoke.v1.ParamUpdateService/SubmitParameterUpdate",
    "/privoke.v1.ParamUpdateService/GetParameterUpdateStatus",
    "/privoke.v1.PrivokeRuntimeService/AnalyzePrompt",
    "/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients",
    "/privoke.v1.FuzzerService/RunTrainingCycle",
    "/privoke.v1.TelemetryService/GetTelemetrySummary",
)


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def run(self, name: str, check: Callable[[], None]) -> None:
        try:
            check()
        except AssertionError as error:
            self.rows.append((name, False, str(error) or "assertion failed"))
        except Exception as error:  # noqa: BLE001 - a crashed check is a failed check
            self.rows.append((name, False, f"{type(error).__name__}: {error}"))
        else:
            self.rows.append((name, True, ""))
        status = "PASS" if self.rows[-1][1] else "FAIL"
        print(f"{status}  {name}" + (f"  ({self.rows[-1][2]})" if not self.rows[-1][1] else ""), flush=True)

    @property
    def failed(self) -> list[str]:
        return [name for name, ok, _ in self.rows if not ok]


def load_stubs(directory: Path):
    from grpc_tools import protoc

    args = ["protoc", f"-I{PROTO_DIR}", f"--python_out={directory}", f"--grpc_python_out={directory}"]
    args += [str(PROTO_DIR / "privoke/v1" / name) for name in ("parameters.proto", "telemetry.proto")]
    if protoc.main(args) != 0:
        raise RuntimeError("could not generate protobuf stubs")
    sys.path.insert(0, str(directory))
    from privoke.v1 import parameters_pb2, parameters_pb2_grpc, telemetry_pb2, telemetry_pb2_grpc

    return parameters_pb2, parameters_pb2_grpc, telemetry_pb2, telemetry_pb2_grpc


def channel(target: str, server_name: str, trust: bytes | None, identity: tuple[Path, Path] | None) -> grpc.Channel:
    credentials = grpc.ssl_channel_credentials(
        root_certificates=trust,
        private_key=identity[1].read_bytes() if identity else None,
        certificate_chain=identity[0].read_bytes() if identity else None,
    )
    options = CHANNEL_OPTIONS + ((("grpc.ssl_target_name_override", server_name),) if server_name else ())
    return grpc.secure_channel(target, credentials, options=options)


def expect_code(code: grpc.StatusCode, call: Callable[[], object], what: str) -> None:
    try:
        call()
    except grpc.RpcError as error:
        assert error.code() == code, f"{what}: expected {code.name}, got {error.code().name}: {error.details()}"
    else:
        raise AssertionError(f"{what}: accepted, expected {code.name}")


def pin_for(model_id: str, override: str | None) -> str:
    if override:
        return override
    text = PINS_PATH.read_text(encoding="utf-8") if PINS_PATH.is_file() else ""
    match = re.search(rf'"{re.escape(model_id)}"\s*:\s*"([0-9a-f]{{64}})"', text)
    if not match:
        raise AssertionError(f"no pin for {model_id}: pass --pin or provide {PINS_PATH.relative_to(ROOT)}")
    return match.group(1)


def fetch_v3_package(models, pb, model_id: str, pin: str) -> int:
    """Fetch the package and every asset over mutual TLS and verify the pin, sizes and digests. Returns the byte count."""
    package = models.GetModelPackage(pb.ModelParametersRequest(consumer_id="", model_id=model_id), timeout=30)
    assert package.model_id == model_id, f"package is for {package.model_id!r}"
    manifest_digest = hashlib.sha256(package.manifest_json).hexdigest()
    assert manifest_digest == package.manifest_sha256, "manifest bytes do not match the advertised digest"
    assert manifest_digest == pin, "manifest digest is not the pinned release"
    assert package.assets, "package declares no assets"
    total = 0
    for asset in package.assets:
        digest, offset = hashlib.sha256(), 0
        request = pb.ModelAssetRequest(consumer_id="", model_id=model_id, manifest_sha256=pin, asset_name=asset.name)
        for chunk in models.StreamModelAsset(request, timeout=300):
            assert chunk.asset_name == asset.name and chunk.offset == offset, f"{asset.name}: out-of-order chunk"
            assert chunk.total_bytes == asset.size_bytes, f"{asset.name}: size differs from the declaration"
            digest.update(chunk.data)
            offset += len(chunk.data)
        assert offset == asset.size_bytes, f"{asset.name}: {offset} bytes, declared {asset.size_bytes}"
        assert digest.hexdigest() == asset.sha256, f"{asset.name}: digest differs from the declaration"
        total += offset
    return total


def load_privacy():
    spec = importlib.util.spec_from_file_location("privoke_smoke_privacy", PRIVACY_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {PRIVACY_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def telemetry_packet(pb):
    privacy = load_privacy()
    epsilon = 1.0
    truth = {"action": "ALLOW", "risk_bucket": "0.0-0.2", "primary_category": "NONE", "model_version": "v0.3.0",
             "time_bucket": "08-12_UTC"}
    values = privacy.randomize_report(truth, epsilon, rng=random.Random(20261117))
    return pb.TelemetryPacket(**values, privacy_mechanism=privacy.MECHANISM, privacy_epsilon=epsilon)


def docker_run(image: str, arguments: list[str], mounts: list[str], timeout: float) -> tuple[int | None, str]:
    """Run an image once. Returns (exit code, output); the code is None if it was still running at the timeout."""
    name = f"privoke-smoke-{int(time.time() * 1000) % 10**9}"
    command = ["docker", "run", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--group-add", "10010", *mounts, image, *arguments]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        return process.returncode, output[-400:]
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return None, "still running"
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def startup_checks(results: Results, images: str, pki_dir: Path, live_dir: Path) -> None:
    prefix, _, tag = images.rpartition(":")
    assert prefix and tag, "--images must be PREFIX:TAG"
    mounts = ["-v", f"{pki_dir.resolve()}:/pki:ro", "-v", f"{live_dir.resolve()}:/live:ro"]
    full = ["--cert=/pki/server/server.crt", "--key=/pki/server/server.key", "--client-ca=/pki/client-ca.pem",
            "--crl=/live/crl.pem", "--registry=/live/registry.toml"]
    variants = {
        "no arguments": [],
        "no CRL": [a for a in full if not a.startswith("--crl")],
        "missing CRL file": [a if not a.startswith("--crl") else "--crl=/live/absent-crl.pem" for a in full],
        "no client CA": [a for a in full if not a.startswith("--client-ca")],
        "missing client CA file": [a if not a.startswith("--client-ca") else "--client-ca=/pki/absent-ca.pem" for a in full],
    }
    for service in RUST_IMAGES:
        for label, arguments in variants.items():
            def check(service=service, arguments=arguments) -> None:
                code, output = docker_run(f"{prefix}/{service}:{tag}", arguments, mounts, 60)
                assert code not in (None, 0), f"started or exited 0 ({output.strip()[-120:]})"
            results.run(f"{service} refuses to start: {label}", check)

    def fuzzer_check() -> None:
        code, output = docker_run(f"{prefix}/privoke-fuzzer:{tag}", [], [], 90)
        assert code not in (None, 0), f"served plaintext or exited 0 ({output.strip()[-120:]})"
    results.run("privoke-fuzzer refuses to serve without TLS", fuzzer_check)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--creds", type=Path, required=True, help="credential directory (see above)")
    parser.add_argument("--model-target", required=True, help="host:port of the public model listener")
    parser.add_argument("--telemetry-target", required=True, help="host:port of the public telemetry listener")
    parser.add_argument("--server-name", default="", help="name in the server certificate (needed for loopback targets)")
    parser.add_argument("--model-id", default="privoke-v3-balanced")
    parser.add_argument("--pin", default=None, help="expected manifest SHA-256 (default: shared/python/privoke_model/standard_v3.py)")
    parser.add_argument("--images", default=None, help="PREFIX:TAG of the cloud images, to run the start-up refusal checks")
    parser.add_argument("--pki-dir", type=Path, default=None, help="with --images: the PKI directory the stack uses")
    parser.add_argument("--live-dir", type=Path, default=None, help="with --images: directory holding crl.pem and registry.toml")
    args = parser.parse_args()
    if args.images and not (args.pki_dir and args.live_dir):
        parser.error("--images needs --pki-dir and --live-dir")

    creds = args.creds
    ca = (creds / "server-ca.pem").read_bytes()
    installation = (creds / "installation.crt", creds / "installation.key")
    reporter = (creds / "reporter.crt", creds / "reporter.key")
    unregistered = (creds / "unregistered.crt", creds / "unregistered.key")
    foreign = (creds / "foreign.crt", creds / "foreign.key")
    name = args.server_name
    results = Results()

    with tempfile.TemporaryDirectory(prefix="privoke-smoke-") as scratch:
        pb, pb_rpc, tel, tel_rpc = load_stubs(Path(scratch))

        def model_health(identity, trust=ca):
            with channel(args.model_target, name, trust, identity) as ch:
                return pb_rpc.ModelStreamingServiceStub(ch).Health(pb.HealthRequest(), timeout=10)

        def telemetry_record(identity, trust=ca):
            with channel(args.telemetry_target, name, trust, identity) as ch:
                return tel_rpc.TelemetryServiceStub(ch).RecordTelemetry(telemetry_packet(tel), timeout=10)

        # Mutual TLS is required on both listeners.
        for label, call in (("model", model_health), ("telemetry", telemetry_record)):
            results.run(f"{label}: a client without a certificate is refused",
                        lambda call=call: expect_code(grpc.StatusCode.UNAVAILABLE, lambda: call(None), "no client certificate"))
            results.run(f"{label}: a server that is not trusted is refused",
                        lambda call=call: expect_code(grpc.StatusCode.UNAVAILABLE, lambda: call(installation, None), "untrusted server"))
            if foreign[0].is_file():
                results.run(f"{label}: a certificate from another CA is refused",
                            lambda call=call: expect_code(grpc.StatusCode.UNAVAILABLE, lambda: call(foreign), "foreign CA"))

        # Authorisation by role.
        def installation_health() -> None:
            response = model_health(installation)
            assert response.service and response.status == "SERVING", f"{response.service!r} {response.status!r}"
        results.run("model: a registered installation is served", installation_health)
        results.run("model: the reporter credential is refused",
                    lambda: expect_code(grpc.StatusCode.PERMISSION_DENIED, lambda: model_health(reporter), "reporter on model"))
        results.run("telemetry: an installation certificate is refused",
                    lambda: expect_code(grpc.StatusCode.PERMISSION_DENIED, lambda: telemetry_record(installation), "installation on telemetry"))
        if unregistered[0].is_file():
            results.run("model: an unregistered installation is refused",
                        lambda: expect_code(grpc.StatusCode.PERMISSION_DENIED, lambda: model_health(unregistered), "unregistered"))

        # R9: private RPCs are not served on the public listeners.
        for label, target, identity in (("model", args.model_target, installation), ("telemetry", args.telemetry_target, reporter)):
            def private(target=target, identity=identity) -> None:
                with channel(target, name, ca, identity) as ch:
                    for path in PRIVATE_RPCS:
                        expect_code(grpc.StatusCode.UNIMPLEMENTED,
                                    lambda path=path: ch.unary_unary(path)(b"", timeout=10), path)
            results.run(f"{label}: private RPCs are denied (R9)", private)

        # G8: the default V3 package is fetchable and verified against its pin.
        def v3() -> None:
            pin = pin_for(args.model_id, args.pin)
            with channel(args.model_target, name, ca, installation) as ch:
                size = fetch_v3_package(pb_rpc.ModelStreamingServiceStub(ch), pb, args.model_id, pin)
            print(f"      {args.model_id}: {size} asset bytes verified against pin {pin[:12]}", flush=True)
        results.run(f"model: {args.model_id} fetched and its pin verified (G8)", v3)

        # Telemetry is accepted with the reporter credential.
        def accepted() -> None:
            response = telemetry_record(reporter)
            assert response.accepted, response.message
        results.run("telemetry: a randomised report is accepted with the reporter credential", accepted)

    if args.images:
        startup_checks(results, args.images, args.pki_dir, args.live_dir)

    failed = results.failed
    print(f"{len(results.rows) - len(failed)} passed, {len(failed)} failed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
