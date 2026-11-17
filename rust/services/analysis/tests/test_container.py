"""Stage W3 checks against the hosted containers (host Python test client, no `docker compose run`).

The stack is hosted with Docker Compose, from `docker-compose.prod.yml` and `docker-compose.analysis-test.yml` with the
`legacy-training` profile (the analysis services belong to the production file since stage 8a). Every certificate is
issued at test time by the real `privoke-pki` into a temporary directory that is mounted read-only into the containers
and deleted afterwards; none is committed. The test client reaches the services through the loopback ports of the
test-only gateway (TCP only, TLS stays end to end).

Run from the repository root with a host Python that has grpcio, protobuf and the generated clients (the interpreter
`evaluation/setup-host.py` prepares):

    python -m unittest rust/services/analysis/tests/test_container.py -v

Requires Docker, the images built by the Compose files (the first run builds them), and a built `privoke-pki`
(`cargo build -p privoke-pki`). `PRIVOKE_W3_KEEP=1` leaves the stack running for inspection.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path[:0] = [str(ROOT / "shared/python"), str(ROOT / "shared/python/tests"), str(ROOT / "extension/client-runtime/generated"),
                str(ROOT / "services/privoke-fuzzer/generated"), str(ROOT / "services/privoke-fuzzer/src")]

import grpc  # noqa: E402
from mtls_pki import PkiFixture, locate_pki_tool  # noqa: E402
from privoke.v1 import parameters_pb2, parameters_pb2_grpc, runtime_pb2, runtime_pb2_grpc  # noqa: E402

PROJECT = "privoke-w3-analysis"
COMPOSE_FILES = ("docker-compose.prod.yml", "docker-compose.analysis-test.yml")
SERVICES = ("analysis-service", "analysis-model-streaming", "analysis-test-gateway", "privoke-fuzzer", "param-update-service")
PORTS = {"analysis": 50754, "fuzzer": 50753, "models": 50752}
SEMANTIC = [runtime_pb2.DETECTION_LAYER_SEMANTIC]
CAPTURE = ROOT / "tests/conformance/worker-frames"

STATE: dict = {}


def run(*arguments, check=True, env=None, timeout=1800, capture=True):
    result = subprocess.run([str(item) for item in arguments], cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace", capture_output=capture, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(map(str, arguments))[:200]} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")
    return result


def compose(*arguments, check=True, timeout=1800):
    command = ["docker", "compose", "-p", PROJECT]
    for name in COMPOSE_FILES:
        command += ["-f", name]
    command += ["--profile", "legacy-training"]
    return run(*command, *arguments, check=check, env=STATE["environment"], timeout=timeout)


def build_pki(tool: Path) -> tuple[PkiFixture, Path]:
    names = ("localhost", "127.0.0.1", "analysis-service", "analysis-model-streaming", "privoke-fuzzer", "param-update-service")
    pki = PkiFixture(tool, server_names=names)
    for name, role in (("fuzzer", "publisher"), ("analysis", "runtime"), ("w3-driver", "publisher"), ("param-update", "publisher"), ("probe", "runtime")):
        pki.service(name, role)
    pki._run("crl", "--ca-dir", pki.client_ca, "--out", pki.root / "crl.pem")
    # An installation identity (role consumer) for the negative checks.
    enrolment = pki.root / "installation"
    enrolment.mkdir()
    output = run(pki.tool, "enrol", "--dir", enrolment).stdout
    installation = re.search(r"installation (\S+)", output).group(1)
    csr = next(enrolment.glob("*.csr*"), None) or Path(re.search(r"CSR: (.+)", output).group(1).strip())
    bundle = pki.root / "installation-signed"
    run(pki.tool, "sign", "--ca-dir", pki.client_ca, "--csr", csr, "--installation", installation, "--out-dir", bundle,
        "--registry", pki.registry, "--server-ca", pki.server_ca_pem)
    # The mounted tree: the PRIVOKE_PKI_DIR layout of docker-compose.prod.yml (live/ holds the hot-reloaded files).
    mount = pki.root / "mount"
    (mount / "svc").mkdir(parents=True)
    (mount / "server").mkdir()
    (mount / "live").mkdir()
    shutil.copy(pki.server_ca_pem, mount / "server-ca.pem")
    shutil.copy(pki.client_ca_pem, mount / "client-ca.pem")
    shutil.copy(pki.root / "crl.pem", mount / "live/crl.pem")
    shutil.copy(pki.registry, mount / "live/registry.toml")
    shutil.copy(pki.server_cert, mount / "server/server.crt")
    shutil.copy(pki.server_key, mount / "server/server.key")
    for name in ("fuzzer", "analysis", "w3-driver", "param-update", "probe"):
        certificate, key = pki.root / "service" / name / f"{name}.crt", pki.root / "service" / name / f"{name}.key"
        shutil.copy(certificate, mount / "svc" / f"{name}.crt")
        shutil.copy(key, mount / "svc" / f"{name}.key")
    if os.name != "nt":
        # The keys are synthetic and the containers run as other users; make the tree readable (and traversable) for them.
        for path in (mount, *mount.rglob("*")):
            path.chmod(0o755 if path.is_dir() else 0o644)
    STATE["installation"] = (bundle / "client.crt", enrolment / "client.key")
    return pki, mount


def channel(port: int, identity: tuple[Path, Path] | None, server_name: str, trust: Path | None = None):
    trust = trust or STATE["mount"] / "server-ca.pem"
    credentials = grpc.ssl_channel_credentials(
        root_certificates=trust.read_bytes(),
        private_key=identity[1].read_bytes() if identity else None,
        certificate_chain=identity[0].read_bytes() if identity else None,
    )
    options = (("grpc.ssl_target_name_override", server_name), ("grpc.enable_http_proxy", 0),
               ("grpc.max_receive_message_length", 8 * 1024 * 1024))
    return grpc.secure_channel(f"127.0.0.1:{port}", credentials, options=options)


def service_identity(name: str) -> tuple[Path, Path]:
    return STATE["mount"] / "svc" / f"{name}.crt", STATE["mount"] / "svc" / f"{name}.key"


def analysis_channel(identity=None):
    return channel(PORTS["analysis"], identity or service_identity("fuzzer"), "analysis-service")


def exec_in(container: str, *command, check=True):
    return run("docker", "exec", container, *command, check=check)


def semantic_request(text="My doctor prescribed medication for my diagnosis.", **fields):
    return runtime_pb2.AnalyzePromptRequest(request_id="w3", text=text, layers=SEMANTIC, semantic_model_id="privoke-balanced", **fields)


def setUpModule():
    tool = locate_pki_tool()
    if tool is None or shutil.which("docker") is None:
        raise unittest.SkipTest("privoke-pki or docker is unavailable")
    pki, mount = build_pki(tool)
    STATE.update(pki=pki, mount=mount)
    STATE["environment"] = {**os.environ, "PRIVOKE_PKI_DIR": str(mount), "COMPOSE_PROJECT_NAME": PROJECT,
                            "FUZZER_PROMPT_COUNT": "32"}
    compose("down", "-v", "--remove-orphans", check=False)
    started = time.monotonic()
    # Name the services: the plaintext client-runtime, Go model service and telemetry service of the production file
    # have no profile and would otherwise start too; nothing here depends on them.
    compose("up", "-d", "--build", "--wait", "--wait-timeout", "900", *SERVICES)
    STATE["started_in"] = time.monotonic() - started
    print(f"\nstack healthy after {STATE['started_in']:.0f} s", flush=True)


def tearDownModule():
    if os.environ.get("PRIVOKE_W3_KEEP") == "1":
        print("PRIVOKE_W3_KEEP=1: the stack is left running", flush=True)
        return
    compose("down", "-v", "--remove-orphans", check=False)
    if "pki" in STATE:
        STATE["pki"].close()


class QuarantineTests(unittest.TestCase):
    """The container is the quarantine: nothing it can do reaches the network, and nothing it can write outlives it."""

    @classmethod
    def setUpClass(cls):
        cls.inspect = json.loads(run("docker", "inspect", "analysis-service").stdout)[0]

    def test_hardening_is_what_the_compose_file_says(self):
        config, host = self.inspect["Config"], self.inspect["HostConfig"]
        self.assertEqual(config["User"], "10001:10001")
        self.assertTrue(host["ReadonlyRootfs"])
        self.assertEqual(host["CapDrop"], ["ALL"])
        self.assertFalse(host["CapAdd"])
        self.assertIn("no-new-privileges:true", host["SecurityOpt"])
        self.assertFalse([item for item in host["SecurityOpt"] if item.startswith("seccomp")], "the default seccomp profile must apply")
        self.assertFalse(host["Privileged"])
        self.assertEqual(host["Memory"], 3 * 1024 ** 3)
        self.assertEqual(host["NanoCpus"], 2_000_000_000)
        self.assertEqual(host["PidsLimit"], 256)
        self.assertIn("/tmp", host["Tmpfs"])
        self.assertFalse(host["PortBindings"], "no published port")

    def test_only_internal_networks_are_attached(self):
        names = list(self.inspect["NetworkSettings"]["Networks"])
        self.assertEqual(sorted(name.removeprefix(f"{PROJECT}_") for name in names), ["analysis-fuzzer", "analysis-models"])
        for name in names:
            network = json.loads(run("docker", "network", "inspect", name).stdout)[0]
            self.assertTrue(network["Internal"], name)
            members = sorted(item["Name"] for item in network["Containers"].values())
            if name.endswith("analysis-fuzzer"):
                # The fuzzer, and the test-only TCP gateway that lets this host reach it.
                self.assertEqual(members, ["analysis-service", "analysis-test-gateway", "privoke-fuzzer"])
            else:
                self.assertEqual(members, ["analysis-model-streaming", "analysis-service", "analysis-test-gateway"])

    def test_outbound_connections_fail_from_inside(self):
        script = (
            "import socket, sys\n"
            "failures = []\n"
            "for host, port in (('1.1.1.1', 443), ('8.8.8.8', 53), ('host.docker.internal', 80), ('example.com', 443)):\n"
            "    try:\n"
            "        socket.create_connection((host, port), timeout=4).close()\n"
            "        print('CONNECTED', host, port); sys.exit(1)\n"
            "    except OSError as error:\n"
            "        failures.append((host, type(error).__name__))\n"
            "print('OUTBOUND-BLOCKED', failures)\n"
        )
        result = exec_in("analysis-service", "/opt/venv/bin/python", "-c", script)
        self.assertIn("OUTBOUND-BLOCKED", result.stdout)
        self.assertNotIn("CONNECTED", result.stdout)

    def test_root_filesystem_is_read_only_and_only_scratch_and_the_cache_are_writable(self):
        script = (
            "import os, sys\n"
            "def writable(path):\n"
            "    try:\n"
            "        with open(os.path.join(path, '.w3-probe'), 'w') as handle: handle.write('x')\n"
            "        os.remove(os.path.join(path, '.w3-probe')); return True\n"
            "    except OSError: return False\n"
            "print({p: writable(p) for p in ('/', '/etc', '/usr/local/bin', '/workspace/extension/client-runtime/src', '/opt/venv', '/tmp', '/var/cache/privoke-models')})\n"
        )
        result = exec_in("analysis-service", "/opt/venv/bin/python", "-c", script)
        state = eval(result.stdout.strip())  # noqa: S307 - our own output
        self.assertEqual({path for path, ok in state.items() if ok}, {"/tmp", "/var/cache/privoke-models"}, state)

    def test_worker_started_sandboxed_without_telemetry(self):
        logs = run("docker", "logs", "analysis-service").stderr + run("docker", "logs", "analysis-service").stdout
        ready = re.search(r"worker ready: (\{.*\})", logs)
        self.assertIsNotNone(ready, logs[-2000:])
        info = json.loads(ready.group(1))
        self.assertEqual(info["sandbox_self_check"], "passed", "the worker proved it could not open a socket")
        self.assertEqual(info["telemetry"], "disabled")
        self.assertEqual(info["loaded"], ["semantic:privoke-balanced"])

    def test_models_load_with_the_root_read_only(self):
        # The service is healthy with a read-only root, and the models it serves came through the cache volume.
        listing = exec_in("analysis-service", "ls", "/var/cache/privoke-models").stdout.split()
        self.assertIn("privoke-balanced.snapshot.pb", listing)
        response = runtime_pb2_grpc.PrivokeRuntimeServiceStub(analysis_channel()).AnalyzePrompt(semantic_request(), timeout=60)
        self.assertEqual(response.error, "")
        self.assertEqual([layer.layer for layer in response.layers], SEMANTIC)
        self.assertEqual(response.layers[0].status, "ok")


class AccessTests(unittest.TestCase):
    def stub(self, identity=None, trust=None):
        return runtime_pb2_grpc.PrivokeRuntimeServiceStub(channel(PORTS["analysis"], identity, "analysis-service", trust))

    def code(self, call):
        try:
            call()
        except grpc.RpcError as error:
            return error.code()
        return grpc.StatusCode.OK

    def test_the_fuzzer_is_served(self):
        stub = self.stub(service_identity("fuzzer"))
        health = stub.Health(runtime_pb2.RuntimeHealthRequest(), timeout=10)
        self.assertEqual((health.service, health.status), ("privoke-analysis-service", "SERVING"))
        self.assertEqual(self.code(lambda: stub.AnalyzePrompt(semantic_request(), timeout=60)), grpc.StatusCode.OK)

    def test_other_identities_get_permission_denied(self):
        for label, identity in (("a registered publisher that is not the fuzzer", service_identity("param-update")),
                                ("the service's own model credential", service_identity("analysis")),
                                ("the test driver", service_identity("w3-driver")),
                                ("an installation", STATE["installation"])):
            with self.subTest(label):
                stub = self.stub(identity)
                for call in (lambda: stub.AnalyzePrompt(semantic_request(), timeout=30),
                             lambda: stub.ComputeSemanticGradients(runtime_pb2.ComputeSemanticGradientsRequest(model_id="privoke-balanced", layers=SEMANTIC), timeout=30),
                             lambda: stub.DetectAnnotationPresence(runtime_pb2.DetectAnnotationPresenceRequest(text="x", layers=SEMANTIC), timeout=30)):
                    self.assertEqual(self.code(call), grpc.StatusCode.PERMISSION_DENIED)

    def test_publisher_and_model_rpcs_are_unimplemented(self):
        connection = analysis_channel()
        update = parameters_pb2.ParameterUpdateRequest(source_id="fuzzer", model_id="privoke-balanced", base_version="v1")
        self.assertEqual(self.code(lambda: parameters_pb2_grpc.ParamUpdateServiceStub(connection).SubmitParameterUpdate(update, timeout=10)), grpc.StatusCode.UNIMPLEMENTED)
        self.assertEqual(self.code(lambda: parameters_pb2_grpc.ParamUpdateServiceStub(connection).GetParameterUpdateStatus(parameters_pb2.ParameterUpdateStatusRequest(), timeout=10)), grpc.StatusCode.UNIMPLEMENTED)
        request = parameters_pb2.ModelParametersRequest(consumer_id="fuzzer", model_id="privoke-balanced")
        self.assertEqual(self.code(lambda: parameters_pb2_grpc.ModelStreamingServiceStub(connection).GetModelParameters(request, timeout=10)), grpc.StatusCode.UNIMPLEMENTED)
        self.assertEqual(self.code(lambda: parameters_pb2_grpc.FuzzerServiceStub(connection).RunTrainingCycle(parameters_pb2.FuzzerTrainingRequest(), timeout=10)), grpc.StatusCode.UNIMPLEMENTED)

    def test_no_certificate_or_an_untrusted_one_cannot_connect(self):
        self.assertEqual(self.code(lambda: self.stub(None).Health(runtime_pb2.RuntimeHealthRequest(), timeout=10)), grpc.StatusCode.UNAVAILABLE)
        # A trusted client certificate from a CA the server does not know.
        foreign = PkiFixture(locate_pki_tool())
        try:
            identity = foreign.service("fuzzer", "publisher")
            self.assertEqual(self.code(lambda: self.stub(identity).Health(runtime_pb2.RuntimeHealthRequest(), timeout=10)), grpc.StatusCode.UNAVAILABLE)
        finally:
            foreign.close()


class SemanticOnlyTests(unittest.TestCase):
    def test_non_semantic_layer_requests_are_rejected(self):
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(analysis_channel())
        for layers in ([], [runtime_pb2.DETECTION_LAYER_REGEX], [runtime_pb2.DETECTION_LAYER_NER], [runtime_pb2.DETECTION_LAYER_RUNTIME],
                       [runtime_pb2.DETECTION_LAYER_SEMANTIC, runtime_pb2.DETECTION_LAYER_NER]):
            with self.subTest(layers=layers), self.assertRaises(grpc.RpcError) as caught:
                stub.AnalyzePrompt(runtime_pb2.AnalyzePromptRequest(text="Email bob@example.com", layers=layers, semantic_model_id="privoke-balanced"), timeout=30)
            self.assertEqual(caught.exception.code(), grpc.StatusCode.INVALID_ARGUMENT)
        with self.assertRaises(grpc.RpcError) as caught:
            stub.ComputeUnderlyingModelGradients(runtime_pb2.ComputeSemanticGradientsRequest(model_id="privoke-balanced", layers=[runtime_pb2.DETECTION_LAYER_REGEX]), timeout=30)
        self.assertEqual(caught.exception.code(), grpc.StatusCode.INVALID_ARGUMENT)

    def test_the_fuzzers_own_runtime_client_assertion_holds_through_the_service(self):
        from runtime_client import PrivokeRuntimeClient, RuntimeAnalysisError

        environment = {"PRIVOKE_TLS_CERT_FILE": str(service_identity("fuzzer")[0]), "PRIVOKE_TLS_KEY_FILE": str(service_identity("fuzzer")[1]),
                       "PRIVOKE_TLS_CA_FILE": str(STATE["mount"] / "server-ca.pem")}
        previous = {key: os.environ.get(key) for key in environment}
        os.environ.update(environment)
        try:
            client = PrivokeRuntimeClient(f"127.0.0.1:{PORTS['analysis']}", timeout_seconds=60)
            result = client.analyze({"text": "My doctor prescribed medication for my diagnosis.", "semantic_model_id": "privoke-balanced"}, layers=["semantic"])
            self.assertEqual([layer["layer"] for layer in result["layers"]], ["semantic"])
            self.assertEqual(result["layers"][0]["status"], "ok")
            for layers in (["regex"], ["ner"], ["regex", "ner", "semantic"], ["runtime"]):
                with self.subTest(layers=layers), self.assertRaises((grpc.RpcError, RuntimeAnalysisError)):
                    client.analyze({"text": "Email bob@example.com"}, layers=layers)
        except grpc.RpcError as error:
            if error.code() == grpc.StatusCode.UNAVAILABLE and "ssl" in (error.details() or "").lower():
                self.skipTest(f"the fuzzer client cannot verify 127.0.0.1 against the test certificate: {error.details()}")
            raise
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def strip_wall_clock(data: bytes, elapsed_field: int, metadata_field: int | None) -> bytes:
    """Drops `elapsed_ms` (a double field) and the `elapsed_ms` metadata entry from a serialized response, byte for byte."""
    def varint(offset):
        value, shift = 0, 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, offset
            shift += 7

    out, offset = bytearray(), 0
    while offset < len(data):
        start = offset
        key, offset = varint(offset)
        field, wire = key >> 3, key & 7
        drop = False
        if wire == 0:
            _, offset = varint(offset)
        elif wire == 1:
            offset += 8
            drop = field == elapsed_field
        elif wire == 2:
            length, offset = varint(offset)
            if field == metadata_field:
                drop = data[offset + 2: offset + 2 + 10] == b"elapsed_ms" and data[offset] == 0x0A and data[offset + 1] == 10
            offset += length
        elif wire == 5:
            offset += 4
        else:
            raise ValueError(wire)
        if not drop:
            out += data[start:offset]
    return bytes(out)


class ParityTests(unittest.TestCase):
    """Analysis and gradients through the service against the recorded W1 pipe responses and against themselves."""

    def raw(self, path: str, payload: bytes, metadata=()):
        method = analysis_channel().unary_unary(path, request_serializer=lambda value: value, response_deserializer=lambda value: value)
        return method(payload, timeout=120, metadata=tuple(metadata))

    def test_semantic_analysis_equals_the_recorded_w1_pipe_responses(self):
        manifest = json.loads((CAPTURE / "manifest.json").read_text())
        torch_build = exec_in("analysis-service", "/opt/venv/bin/python", "-c", "import torch; print(torch.__version__)").stdout.strip()
        if torch_build != manifest["environment"]["torch"]:
            self.skipTest(f"recorded with torch {manifest['environment']['torch']}, the container has {torch_build}")
        compared = 0
        for case in json.loads((CAPTURE / "analysis.json").read_text())["cases"]:
            if case["scope"] != "llm_only" or case["method"] != "AnalyzePrompt" or "v3" in case["label"]:
                continue
            frame = bytes.fromhex(case["request_frame_hex"])
            answer = self.raw("/privoke.v1.PrivokeRuntimeService/AnalyzePrompt", frame[20:])
            digest = hashlib.sha256(strip_wall_clock(answer, 11, 8)).hexdigest()
            self.assertEqual(digest, case["response_payload_sha256"], case["label"])
            compared += 1
        self.assertGreaterEqual(compared, 20)
        print(f"\n{compared} recorded W1 semantic-only responses reproduced through the container", flush=True)

    def test_gradients_are_deterministic_and_finite_through_the_service(self):
        # The recorded gradient digests need the W1 training models; the Rust test replays them. Here the tracked
        # privoke-balanced model serves the same RPCs in the hosted container: two identical calls must agree byte for
        # byte, so a worker that holds state between calls would show here.
        from privoke_contracts.classification import Category, Sensitivity, Visibility, initialise_unpacked

        clean = initialise_unpacked(Sensitivity.S0, Visibility.PU, []).pack()
        private = initialise_unpacked(Sensitivity.S3, Visibility.P4, [Category.HEALTH]).pack()
        examples = [runtime_pb2.RuntimeTrainingExample(text=text, has_target=True, weight=1.0,
                                                       target=runtime_pb2.RuntimeClassification(packed=packed))
                    for text, packed in (("Synthetic public weather", clean), ("My private diagnosis is cancer", private))]
        heldout = [runtime_pb2.RuntimeTrainingExample(text=text, has_target=True, weight=1.0,
                                                      target=runtime_pb2.RuntimeClassification(packed=packed))
                   for text, packed in (("Anonymous public forecast", clean), ("My doctor prescribed medication", private))]
        request = runtime_pb2.ComputeSemanticGradientsRequest(
            request_id="w3-grad", model_id="privoke-balanced", examples=examples, heldout_examples=heldout,
            learning_rate=0.003, max_gradient=0.0001, layers=SEMANTIC).SerializeToString()
        first = self.raw("/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients", request)
        second = self.raw("/privoke.v1.PrivokeRuntimeService/ComputeSemanticGradients", request)
        self.assertEqual(first, second)
        response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(first)
        self.assertEqual(response.error, "")
        self.assertTrue(response.gradients)
        self.assertTrue(all(abs(value) < 1e6 and value == value for item in response.gradients for value in item.values))
        self.assertEqual([item.layer for item in response.executions], [runtime_pb2.DETECTION_LAYER_SEMANTIC] * len(response.executions))


class TrainingCycleTests(unittest.TestCase):
    """The fuzzer's training cycle, end to end in the legacy-training profile, with the analysis service as its runtime."""

    @staticmethod
    def snapshot_version():
        identity = service_identity("analysis")
        stub = parameters_pb2_grpc.ModelStreamingServiceStub(channel(PORTS["models"], identity, "analysis-model-streaming"))
        reply = stub.GetModelParameters(parameters_pb2.ModelParametersRequest(consumer_id="w3-test", model_id="privoke-balanced"), timeout=30)
        return reply.version, [list(item.values) for item in reply.parameters]

    def test_a_cycle_trains_through_the_analysis_service_and_the_service_follows_the_update(self):
        containers = run("docker", "ps", "--format", "{{.Names}}").stdout.split()
        self.assertNotIn("client-runtime", containers, "the Python runtime is not part of this stack")
        for name in ("analysis-service", "privoke-fuzzer", "param-update-service", "analysis-model-streaming"):
            self.assertIn(name, containers)

        before, before_values = self.snapshot_version()
        request = parameters_pb2.FuzzerTrainingRequest(request_id=f"w3-{uuid.uuid4().hex}", source_id="w3-driver",
                                                       model_id="privoke-balanced", prompt_count=32, seed=1,
                                                       metadata={"purpose": "stage-w3"})
        stub = parameters_pb2_grpc.FuzzerServiceStub(channel(PORTS["fuzzer"], service_identity("w3-driver"), "privoke-fuzzer"))
        deadline = time.monotonic() + 180
        while True:
            try:
                response = stub.RunTrainingCycle(request, timeout=600)
                break
            except grpc.RpcError as error:
                if error.code() == grpc.StatusCode.RESOURCE_EXHAUSTED and time.monotonic() < deadline:
                    time.sleep(1)
                    continue
                logs = run("docker", "logs", "--tail", "60", "privoke-fuzzer", check=False)
                raise AssertionError(f"{error.code()}: {error.details()}\n{logs.stdout}{logs.stderr}") from error
        self.assertTrue(response.accepted, response.message)
        self.assertEqual(response.model_id, "privoke-balanced")
        self.assertEqual(response.prompts_generated, 32)
        self.assertEqual(response.base_version, before)
        self.assertTrue(response.applied_version)
        after, after_values = self.snapshot_version()
        self.assertEqual(after, response.applied_version, "the Rust model service streams the published version")
        self.assertNotEqual(before_values, after_values, "training changed the weights")

        # The analysis service follows the update without a restart: its cache holds the new version after the next call.
        stub = runtime_pb2_grpc.PrivokeRuntimeServiceStub(analysis_channel())
        script = ("import sys; sys.path.insert(0, '/workspace/extension/client-runtime/generated')\n"
                  "from privoke.v1 import parameters_pb2\n"
                  "print(parameters_pb2.ModelParametersResponse.FromString(open('/var/cache/privoke-models/privoke-balanced.snapshot.pb','rb').read()).version)\n")
        cached = None
        for _ in range(30):
            stub.AnalyzePrompt(semantic_request(), timeout=60)
            cached = exec_in("analysis-service", "/opt/venv/bin/python", "-c", script).stdout.strip()
            if cached == after:
                break
            time.sleep(1)
        self.assertEqual(cached, after)


if __name__ == "__main__":
    unittest.main()
