"""Exercise the cloud Compose deployment with disposable volumes and TLS identities.

Run after `docker compose build`, using Python with grpcio and grpcio-tools.
Only resources belonging to the unique smoke-test project are removed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import grpc

ROOT = Path(__file__).resolve().parents[3]


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
        def ssl(*args):
            try:
                run(openssl, *args, cwd=secrets, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(error.stderr) from error

        (secrets / "ca.cnf").write_text("[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Smoke CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n", encoding="utf-8")
        ssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", "ca.cnf", "-keyout", "ca.key", "-out", "client-ca.crt")
        for name, purpose in (("server", "serverAuth"), ("client", "clientAuth")):
            ssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={name}", "-keyout", f"{name}.key", "-out", f"{name}.csr")
            (secrets / f"{name}.ext").write_text(f"subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage={purpose}\nbasicConstraints=CA:FALSE\n", encoding="utf-8")
            ssl("x509", "-req", "-in", f"{name}.csr", "-CA", "client-ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-extfile", f"{name}.ext", "-out", f"{name}.crt")
        ssl("verify", "-CAfile", "client-ca.crt", "server.crt", "client.crt")

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
        try:
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

            credentials = grpc.ssl_channel_credentials((secrets / "client-ca.crt").read_bytes(), (secrets / "client.key").read_bytes(), (secrets / "client.crt").read_bytes())
            # The test binds IPv4 loopback only; never route it through a host proxy.
            with grpc.secure_channel(f"127.0.0.1:{port}", credentials, options=(("grpc.enable_http_proxy", 0),)) as channel:
                models = parameter_rpc.ModelStreamingServiceStub(channel)
                assert models.Health(parameters.HealthRequest(), timeout=10).status == "SERVING"
                chunks = list(models.StreamModelParameters(parameters.ModelParametersRequest(consumer_id="cloud-smoke", model_id="latest"), timeout=20))
                assert chunks and chunks[0].model_id
                now = datetime.now(timezone.utc)
                event_id = str(uuid.uuid4())
                response = telemetry_rpc.TelemetryServiceStub(channel).RecordTelemetry(telemetry.TelemetryPacket(
                    event_id=event_id, occurred_at_unix_ms=int(now.timestamp() * 1000),
                    time_bucket=now.strftime("%Y-%m-%dT%H:00:00Z"), source_id="cloud-smoke",
                    action="ALLOW", sensitivity="S0", visibility="PU", risk_bucket="0.0-0.2", detector_version="smoke",
                ), timeout=10)
                assert response.accepted, response.message
                for path in ("TelemetryService/ListTelemetry", "ParamUpdateService/SubmitParameterUpdate", "PrivokeRuntimeService/AnalyzePrompt", "FuzzerService/RunTrainingCycle"):
                    try:
                        channel.unary_unary(f"/privoke.v1.{path}")(b"", timeout=5)
                    except grpc.RpcError as error:
                        assert error.code() == grpc.StatusCode.UNIMPLEMENTED, (path, error)
                    else:
                        raise AssertionError(f"Private RPC was exposed: {path}")

            for credentials in (
                grpc.ssl_channel_credentials((secrets / "client-ca.crt").read_bytes()),
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
            run(*compose, "exec", "-T", "telemetry-service", "python", "-c", "import sqlite3, sys; db=sqlite3.connect('/data/telemetry.db'); assert db.execute('SELECT COUNT(*) FROM telemetry_events WHERE event_id = ?', (sys.argv[1],)).fetchone()[0] == 1", event_id)
            run(*compose, "exec", "-T", "client-runtime", "python", "test/stack_smoke.py", "--skip-training")
            print("Cloud smoke passed: services, TLS identity, download, telemetry, private RPC denial, and recreation.", flush=True)
        except BaseException:
            subprocess.run([*compose, "logs", "--tail", "80", "--no-color"], check=False)
            raise
        finally:
            run(*compose, "down", "--volumes", "--remove-orphans", "--timeout", "20")
            for service in ("model-streaming-service", "param-update-service", "telemetry-service", "privoke-fuzzer", "client-runtime"):
                run("docker", "image", "rm", "--no-prune", f"{project}/{service}:test", stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
