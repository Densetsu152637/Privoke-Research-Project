"""Exercise the cloud Compose deployment with disposable volumes and TLS identities.

Run after `docker compose build`, using Python with grpcio and grpcio-tools.
Only resources belonging to the unique smoke-test project are removed.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import random
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import grpc

ROOT = Path(__file__).resolve().parents[3]
_PRIVACY_SPEC = importlib.util.spec_from_file_location(
    "privoke_smoke_privacy", ROOT / "extension/client-runtime/src/telemetry/privacy.py"
)
if _PRIVACY_SPEC is None or _PRIVACY_SPEC.loader is None:
    raise RuntimeError("Could not load the client telemetry privacy mechanism.")
_PRIVACY_MODULE = importlib.util.module_from_spec(_PRIVACY_SPEC)
_PRIVACY_SPEC.loader.exec_module(_PRIVACY_MODULE)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    project = "privoke-smoke-" + uuid.uuid4().hex[:10]
    source_project = os.getenv("COMPOSE_PROJECT_NAME", ROOT.name.lower())
    openssl = shutil.which("openssl")
    if not openssl and os.name == "nt":
        openssl = r"C:\Program Files\Git\usr\bin\openssl.exe"
    if not openssl:
        raise RuntimeError("OpenSSL is required for disposable test certificates.")
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gce-smoke-", dir=ROOT / ".tmp") as directory:
        temporary = Path(directory)
        secrets = temporary / "secrets"
        secrets.mkdir()
        clients = temporary / "clients"
        clients.mkdir()
        def ssl(*args):
            try:
                run(openssl, *args, cwd=clients, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(error.stderr) from error

        (clients / "ca.cnf").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Smoke CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n", encoding="utf-8")
        ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", "ca.cnf", "-keyout", "ca.key", "-out", "client-ca.crt")
        for name, purpose in (("server", "serverAuth"), ("client", "clientAuth")):
            ssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", f"{name}.key", "-out", f"{name}.csr")
            (clients / f"{name}.ext").write_text(f"subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage={purpose}\nbasicConstraints=CA:FALSE\n", encoding="utf-8")
            ssl("x509", "-req", "-in", f"{name}.csr", "-CA", "client-ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-extfile", f"{name}.ext", "-out", f"{name}.crt")
        ssl("verify", "-CAfile", "client-ca.crt", "server.crt", "client.crt")
        for name in ("server.key", "server.crt", "client-ca.crt"):
            shutil.copyfile(clients / name, secrets / name)

        for service in ("model-streaming-service", "param-update-service", "telemetry-service", "privoke-fuzzer", "client-runtime"):
            run("docker", "tag", f"{source_project}-{service}:latest", f"{project}/{service}:test")
        environment = {**os.environ, "IMAGE_PREFIX": project, "IMAGE_TAG": "test", "SECRETS_DIR": str(secrets), "FUZZER_PROMPT_COUNT": "0"}
        rendered = run("docker", "compose", "-f", str(ROOT / "deploy/gce/compose.yml"), "config", "--format", "json", env=environment, capture_output=True)
        config = json.loads(rendered.stdout)
        config["name"] = project
        # Keep the production routing/security, but reserve a random loopback port.
        config["services"]["ingress"]["ports"] = [{"target": 443, "published": "0", "host_ip": "127.0.0.1", "protocol": "tcp"}]
        for key, volume in config["volumes"].items():
            volume["name"] = f"{project}_{key}"
        for key, network in config.get("networks", {}).items():
            network["name"] = f"{project}_{key}"
        compose_file = temporary / "compose.json"
        compose_file.write_text(json.dumps(config), encoding="utf-8")
        compose = ["docker", "compose", "--project-name", project, "-f", str(compose_file)]
        root_owned_secrets = None
        try:
            root_owned_secrets = ingress_secret_permissions_restore_token(secrets, temporary)
            prepare_ingress_secret_permissions(root_owned_secrets)
            run(*compose, "up", "-d", "--wait", "--wait-timeout", "240")
            # Run the existing internal end-to-end checks against the cloud topology.
            run(*compose, "exec", "-T", "client-runtime", "python", "test/stack_smoke.py")
            endpoint = run(*compose, "port", "ingress", "443", capture_output=True).stdout.strip()
            port = endpoint.rsplit(":", 1)[1]
            generated = temporary / "generated"
            generated.mkdir()
            run(sys.executable, "-m", "grpc_tools.protoc", "-I", str(ROOT / "shared/proto"), f"--python_out={generated}", f"--grpc_python_out={generated}", str(ROOT / "shared/proto/privoke/v1/parameters.proto"), str(ROOT / "shared/proto/privoke/v1/telemetry.proto"))
            sys.path.insert(0, str(generated))
            from privoke.v1 import parameters_pb2 as parameters, parameters_pb2_grpc as parameter_rpc, telemetry_pb2 as telemetry, telemetry_pb2_grpc as telemetry_rpc

            credentials = grpc.ssl_channel_credentials((clients / "client-ca.crt").read_bytes(), (clients / "client.key").read_bytes(), (clients / "client.crt").read_bytes())
            # The test binds IPv4 loopback only; never route it through a host proxy.
            with grpc.secure_channel(f"127.0.0.1:{port}", credentials, options=(("grpc.enable_http_proxy", 0),)) as channel:
                models = parameter_rpc.ModelStreamingServiceStub(channel)
                assert models.Health(parameters.HealthRequest(), timeout=10).status == "SERVING"
                chunks = list(models.StreamModelParameters(parameters.ModelParametersRequest(consumer_id="cloud-smoke", model_id="latest"), timeout=20))
                assert chunks and chunks[0].model_id
                summary_before = read_telemetry_summary(compose)
                epsilon = 1.0
                synthetic_values = {
                    "action": "ALLOW",
                    "risk_bucket": "0.0-0.2",
                    "primary_category": "NONE",
                    "model_version": "v0.3.0",
                    "time_bucket": "08-12_UTC",
                }
                protected_values = _PRIVACY_MODULE.randomize_report(
                    synthetic_values, epsilon, rng=random.Random(2026)
                )
                packet = telemetry.TelemetryPacket(
                    **protected_values,
                    privacy_mechanism=_PRIVACY_MODULE.MECHANISM,
                    privacy_epsilon=epsilon,
                )
                response = telemetry_rpc.TelemetryServiceStub(channel).RecordTelemetry(packet, timeout=10)
                assert response.accepted, response.message
                summary_after = read_telemetry_summary(compose)
                validate_aggregate_summary(summary_before, summary_after, protected_values)
                for path in ("ParamUpdateService/SubmitParameterUpdate", "ParamUpdateService/GetParameterUpdateStatus", "PrivokeRuntimeService/AnalyzePrompt", "FuzzerService/RunTrainingCycle"):
                    try:
                        channel.unary_unary(f"/privoke.v1.{path}")(b"", timeout=5)
                    except grpc.RpcError as error:
                        assert error.code() == grpc.StatusCode.UNIMPLEMENTED, (path, error)
                    else:
                        raise AssertionError(f"Private RPC was exposed: {path}")

            for credentials in (
                grpc.ssl_channel_credentials((clients / "client-ca.crt").read_bytes()),
                grpc.ssl_channel_credentials(),  # Does not trust the private test CA.
            ):
                with grpc.secure_channel(f"127.0.0.1:{port}", credentials, options=(("grpc.enable_http_proxy", 0),)) as channel:
                    try:
                        parameter_rpc.ModelStreamingServiceStub(channel).Health(parameters.HealthRequest(), timeout=3)
                    except grpc.RpcError:
                        pass
                    else:
                        raise AssertionError("TLS accepted an untrusted server or missing client identity.")
            # A recreation must retain seeded models and application data.
            run(*compose, "exec", "-T", "param-update-service", "python", "-c", "from pathlib import Path; Path('/models/.smoke-persisted').write_text('retained')")
            run(*compose, "up", "-d", "--force-recreate", "--wait", "--wait-timeout", "240")
            run(*compose, "exec", "-T", "param-update-service", "python", "-c", "from pathlib import Path; assert Path('/models/.smoke-persisted').read_text() == 'retained'")
            summary_recreated = read_telemetry_summary(compose)
            assert summary_recreated["sample_count"] >= summary_after["sample_count"], "aggregate telemetry count decreased after recreation"
            run(*compose, "exec", "-T", "client-runtime", "python", "test/stack_smoke.py", "--skip-training")
            print("Cloud smoke passed: services, TLS identity, download, aggregate telemetry API, private RPC denial, and recreation.", flush=True)
        except BaseException:
            subprocess.run([*compose, "logs", "--tail", "80", "--no-color"], check=False)
            raise
        finally:
            try:
                run(*compose, "down", "--volumes", "--remove-orphans", "--timeout", "20")
            finally:
                try:
                    restore_ingress_secret_directory_owner(root_owned_secrets)
                finally:
                    for service in ("model-streaming-service", "param-update-service", "telemetry-service", "privoke-fuzzer", "client-runtime"):
                        run("docker", "image", "rm", "--no-prune", f"{project}/{service}:test", stdout=subprocess.DEVNULL)


def ingress_secret_permissions_restore_token(secrets: Path, temporary: Path):
    """Capture the exact temporary secret directory and its original owner before mutation."""
    if os.name == "nt":
        # Docker Desktop translates bind-mount ownership from Windows filesystems.
        return None
    directory = secrets.resolve(strict=True)
    temporary_root = temporary.resolve(strict=True)
    server_key = (directory / "server.key").resolve(strict=True)
    if directory.parent != temporary_root or server_key.parent != directory:
        raise RuntimeError("TLS smoke secret paths must remain inside the temporary fixture directory.")
    return (directory, (os.getuid(), os.getgid()))


def prepare_ingress_secret_permissions(ownership):
    """Match deploy.sh's root-only, non-recursive TLS key permissions on Linux."""
    if ownership is None:
        return
    directory, _owner = ownership
    server_key = directory / "server.key"
    os.chmod(directory, 0o700)
    os.chmod(server_key, 0o600)
    os.chmod(directory / "server.crt", 0o644)
    os.chmod(directory / "client-ca.crt", 0o644)
    _run_as_root("chown", "0:0", str(server_key))
    _run_as_root("chown", "0:0", str(directory))


def restore_ingress_secret_directory_owner(ownership):
    if ownership is None:
        return
    directory, (uid, gid) = ownership
    _run_as_root("chown", f"{uid}:{gid}", str(directory))


def _run_as_root(*args):
    if os.name == "nt":
        return
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        command = list(args)
    else:
        sudo = shutil.which("sudo")
        if sudo is None:
            raise RuntimeError("TLS smoke requires root or non-interactive sudo to model the production-owned server key.")
        command = [sudo, "-n", *args]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        detail = result.stderr.strip()
        raise RuntimeError(f"Could not prepare restrictive TLS smoke permissions with {' '.join(command[:3])}: {detail}")


def read_telemetry_summary(compose):
    code = (
        "import json, grpc, sys; "
        "sys.path.insert(0, '/workspace/services/telemetry-service/generated'); "
        "from privoke.v1 import telemetry_pb2 as pb, telemetry_pb2_grpc as rpc; "
        "channel = grpc.insecure_channel('127.0.0.1:50055'); "
        "response = rpc.TelemetryServiceStub(channel).GetTelemetrySummary(pb.GetTelemetrySummaryRequest(), timeout=10); "
        "print(json.dumps({'sample_count': response.sample_count, 'dimensions': "
        "{dimension.dimension: {value.value: {'observed_noisy_count': value.observed_noisy_count, "
        "'estimated_count': value.estimated_count} for value in dimension.values} "
        "for dimension in response.dimensions}})); channel.close()"
    )
    result = run(
        *compose, "exec", "-T", "telemetry-service", "python", "-c", code,
        capture_output=True,
    )
    return json.loads(result.stdout.strip().splitlines()[-1])


def validate_aggregate_summary(before, after, protected_values):
    domains = _PRIVACY_MODULE.DOMAINS
    dimensions = _PRIVACY_MODULE.DIMENSIONS
    assert after["sample_count"] >= before["sample_count"] + 1, "synthetic report did not increase aggregate count"
    assert set(after["dimensions"]) == set(dimensions), "aggregate API returned unexpected dimensions"
    for dimension in dimensions:
        assert set(after["dimensions"][dimension]) == set(domains[dimension]), f"wrong aggregate domain for {dimension}"
        previous = before["dimensions"].get(dimension, {}).get(protected_values[dimension], {}).get("observed_noisy_count", 0)
        current = after["dimensions"][dimension][protected_values[dimension]]["observed_noisy_count"]
        assert current >= previous + 1, f"synthetic noisy {dimension} value missing from aggregate"
        for value in after["dimensions"][dimension].values():
            estimate = value["estimated_count"]
            assert math.isfinite(estimate) and 0 <= estimate <= after["sample_count"], f"invalid estimate for {dimension}"


if __name__ == "__main__":
    main()
