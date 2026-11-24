"""Disposable test PKI and a mutual-TLS gRPC stand-in for the authentication negative tests.

Everything here is generated per run in a temporary directory and holds synthetic
identities only. The stand-in terminator is a grpcio server that requires a client
certificate; it is NOT the production nginx ingress (see the record's limitations).
"""
from __future__ import annotations

import datetime as dt
import os
import shlex
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid
from concurrent import futures
from pathlib import Path
from types import SimpleNamespace

CA_CONFIG = """[ca]
default_ca=CA_default
[CA_default]
dir=.
database=index.txt
new_certs_dir=.
serial=serial
default_md=sha256
policy=policy_any
unique_subject=no
copy_extensions=none
[policy_any]
commonName=supplied
"""


def find_openssl() -> str:
    found = shutil.which("openssl")
    if not found and os.name == "nt":
        found = r"C:\Program Files\Git\usr\bin\openssl.exe"
    if not found or not Path(found).exists():
        raise RuntimeError("OpenSSL is required to generate disposable test certificates.")
    return found


def _stamp(moment: dt.datetime) -> str:
    return moment.strftime("%Y%m%d%H%M%SZ")


class TestAuthority:
    """One private CA able to issue certificates with an explicit validity window."""

    def __init__(self, directory: Path, name: str):
        self.dir = directory / name
        self.dir.mkdir(parents=True)
        self.name = name
        self.openssl = find_openssl()
        (self.dir / "ca.cnf").write_text(CA_CONFIG, encoding="utf-8")
        (self.dir / "index.txt").write_text("", encoding="utf-8")
        (self.dir / "serial").write_text("1000\n", encoding="utf-8")
        # The CA validity starts well in the past so that back-dated leaf windows (expired
        # certificates) still chain to a currently valid CA.
        now = dt.datetime.now(dt.timezone.utc)
        (self.dir / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n", encoding="utf-8")
        self._run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={name}",
                  "-keyout", "ca.key", "-out", "ca.csr")
        self._run("ca", "-config", "ca.cnf", "-batch", "-notext", "-selfsign", "-in", "ca.csr", "-out", "ca.crt",
                  "-keyfile", "ca.key", "-startdate", _stamp(now - dt.timedelta(days=30)),
                  "-enddate", _stamp(now + dt.timedelta(days=2)), "-extfile", "ca.ext")
        self.cert = (self.dir / "ca.crt").read_bytes()

    @classmethod
    def adopt(cls, directory: Path, name: str, cert: bytes, key: bytes) -> "TestAuthority":
        """Wrap an existing CA (for the 13d rows: the client CA that `privoke-pki init-ca` created) so that OpenSSL can sign
        the deliberately invalid credentials `privoke-pki` refuses to mint. The adopted CA keeps its own certificate and key."""
        authority = cls.__new__(cls)
        authority.dir = directory / name
        authority.dir.mkdir(parents=True)
        authority.name = name
        authority.openssl = find_openssl()
        (authority.dir / "ca.cnf").write_text(CA_CONFIG, encoding="utf-8")
        (authority.dir / "index.txt").write_text("", encoding="utf-8")
        (authority.dir / "serial").write_text("1000\n", encoding="utf-8")
        (authority.dir / "ca.crt").write_bytes(cert)
        (authority.dir / "ca.key").write_bytes(key)
        authority.cert = cert
        return authority

    def issue_extensions(self, label: str, *, cn: str, extensions: list[str], start: dt.datetime, end: dt.datetime) -> tuple[bytes, bytes]:
        """Issue a leaf whose extension block is written verbatim (a profile `issue` cannot express, such as no extended key usage)."""
        key, csr, crt, ext = (f"{label}.key", f"{label}.csr", f"{label}.crt", f"{label}.ext")
        self._run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", f"/CN={cn}", "-keyout", key, "-out", csr)
        (self.dir / ext).write_text("\n".join(["basicConstraints=CA:FALSE", *extensions]) + "\n", encoding="utf-8")
        self._run("ca", "-config", "ca.cnf", "-batch", "-notext", "-in", csr, "-out", crt, "-cert", "ca.crt", "-keyfile", "ca.key",
                  "-startdate", _stamp(start), "-enddate", _stamp(end), "-extfile", ext)
        return (self.dir / crt).read_bytes(), (self.dir / key).read_bytes()

    def _run(self, *args):
        env = {**os.environ, "MSYS2_ARG_CONV_EXCL": "*"}
        result = subprocess.run([self.openssl, *args], cwd=self.dir, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError(f"openssl {args[0]} failed: {result.stderr.strip()[:300]}")

    def issue(self, label: str, *, cn: str, usage: str, san: str = "", start: dt.datetime | None = None,
              end: dt.datetime | None = None) -> tuple[bytes, bytes]:
        """Return (certificate_pem, private_key_pem). Default window: valid for the next hour."""
        now = dt.datetime.now(dt.timezone.utc)
        start = start or now - dt.timedelta(minutes=5)
        end = end or now + dt.timedelta(hours=1)
        key, csr, crt, ext = (f"{label}.key", f"{label}.csr", f"{label}.crt", f"{label}.ext")
        self._run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                  "-subj", f"/CN={cn}", "-keyout", key, "-out", csr)
        lines = ["basicConstraints=CA:FALSE", f"extendedKeyUsage={usage}"]
        if san:
            lines.append(f"subjectAltName={san}")
        (self.dir / ext).write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._run("ca", "-config", "ca.cnf", "-batch", "-notext", "-in", csr, "-out", crt, "-cert", "ca.crt",
                  "-keyfile", "ca.key", "-startdate", _stamp(start), "-enddate", _stamp(end), "-extfile", ext)
        return (self.dir / crt).read_bytes(), (self.dir / key).read_bytes()

    def self_signed(self, label: str, *, cn: str, usage: str, san: str = "") -> tuple[bytes, bytes]:
        """A certificate not issued by any CA (the subject signs itself)."""
        args = ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1",
                "-subj", f"/CN={cn}", "-keyout", f"{label}.key", "-out", f"{label}.crt",
                "-addext", f"extendedKeyUsage={usage}", "-addext", "basicConstraints=CA:FALSE"]
        if san:
            args += ["-addext", f"subjectAltName={san}"]
        self._run(*args)
        return (self.dir / f"{label}.crt").read_bytes(), (self.dir / f"{label}.key").read_bytes()


class MutualTlsStandIn:
    """grpcio server that demands a client certificate and counts handler invocations."""

    def __init__(self, servicer_registrar, server_cert: bytes, server_key: bytes, client_ca: bytes):
        import grpc

        self.calls = 0
        self._lock = threading.Lock()
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=4),
                                  interceptors=(_CountingInterceptor(self),))
        servicer_registrar(self.server)
        credentials = grpc.ssl_server_credentials([(server_key, server_cert)], root_certificates=client_ca,
                                                  require_client_auth=True)
        self.port = self.server.add_secure_port("0.0.0.0:0", credentials)
        self.server.start()

    def count(self) -> int:
        with self._lock:
            return self.calls

    def stop(self):
        self.server.stop(0).wait(2)


def _CountingInterceptor(owner):
    import grpc

    class Interceptor(grpc.ServerInterceptor):
        def intercept_service(self, continuation, handler_call_details):
            with owner._lock:
                owner.calls += 1
            return continuation(handler_call_details)

    return Interceptor()


# --------------------------------------------------------------------------------------
# Stage 13d: legitimate principals from `privoke-pki`, deliberately invalid ones from OpenSSL
# --------------------------------------------------------------------------------------

PKI_RUNNER_IMAGE = "rust:1.99.1-bookworm"
URN_INSTALLATION = "urn:privoke:installation:"
URN_SERVICE = "urn:privoke:service:"
URN_REPORTER = "urn:privoke:reporter"
ISSUER_PKI, ISSUER_OPENSSL, ISSUER_NONE = "privoke-pki", "openssl-helper", "none"
PKI_SUBCOMMANDS = ("init-ca", "issue-server", "issue-reporter", "sign", "sign-service", "revoke", "crl", "enrol", "renew", "install-cert", "status")
BATCH_MARK = "@@privoke-pki-command@@"


class PkiTool:
    """Runs `privoke-pki`. Either a host executable (`binary`) or a Linux build run inside a container (`linux_binary`, mounted read-only
    next to a bind mount of the working directory). Every command is kept, with paths relative to the working directory, for the record."""

    def __init__(self, work: Path, *, binary: Path | None = None, linux_binary: Path | None = None, runner_image: str = PKI_RUNNER_IMAGE):
        if (binary is None) == (linux_binary is None):
            raise ValueError("name exactly one of a host binary and a Linux binary")
        self.work = work.resolve()
        self.binary = binary
        self.linux_binary = linux_binary.resolve() if linux_binary else None
        self.runner_image = runner_image
        self.commands: list[str] = []
        self._counter = 0

    def arg(self, value) -> str:
        """A path argument as the tool sees it; anything else is passed as text."""
        if isinstance(value, Path):
            if self.linux_binary:
                return "/pki/" + value.resolve().relative_to(self.work).as_posix()
            return str(value)
        return str(value)

    def _spelled(self, args) -> str:
        shown = []
        for value in args:
            shown.append(value.resolve().relative_to(self.work).as_posix() if isinstance(value, Path) else str(value))
        return "privoke-pki " + " ".join(shown)

    def _docker(self, entrypoint: str, arguments: list[str]) -> list[str]:
        self._counter += 1
        command = ["docker", "run", "--rm", "--name", f"s13d-pki-{os.getpid()}-{self._counter}", "--network", "none",
                   "-v", f"{self.work}:/pki", "-v", f"{self.linux_binary.parent}:/opt/pki-tool:ro"]
        if hasattr(os, "getuid"):
            command += ["--user", f"{os.getuid()}:{os.getgid()}"]
        return [*command, "--entrypoint", entrypoint, self.runner_image, *arguments]

    def run(self, *args) -> str:
        return self.batch([list(args)])[0]

    def batch(self, commands: list[list]) -> list[str]:
        """Run several commands in order, stopping at the first failure. A container run starts once for the whole batch."""
        for command in commands:
            if command[0] not in PKI_SUBCOMMANDS:
                raise ValueError(f"not a privoke-pki subcommand: {command[0]}")
        outputs: list[str] = []
        if self.linux_binary:
            tool = f"/opt/pki-tool/{self.linux_binary.name}"
            lines = ["set -e"]
            for command in commands:
                lines.append(f"echo {shlex.quote(BATCH_MARK)}")
                lines.append(shlex.quote(tool) + " " + " ".join(shlex.quote(self.arg(value)) for value in command))
            result = subprocess.run(self._docker("sh", ["-c", "\n".join(lines)]), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                raise RuntimeError(f"privoke-pki failed: {result.stderr.strip()[-400:]}")
            outputs = result.stdout.split(BATCH_MARK + "\n")[1:]
        else:
            for command in commands:
                result = subprocess.run([str(self.binary), *[self.arg(value) for value in command]], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode:
                    raise RuntimeError(f"privoke-pki {command[0]} failed: {result.stderr.strip()[-400:]}")
                outputs.append(result.stdout)
        self.commands.extend(self._spelled(command) for command in commands)
        return outputs


def append_registry_installations(path: Path, ids: list[str]) -> None:
    """Register installations whose certificates a CA tool did not sign (the deliberately invalid ones), so that a refusal can only
    come from the TLS verifier and never from an unregistered subject."""
    text = path.read_text(encoding="utf-8")
    for installation in ids:
        text += f'\n[[installation]]\nid = "{installation}"\n'
    path.write_text(text, encoding="utf-8", newline="\n")


class PrivokePki:
    """The disposable PKI of the 13d rows. Legitimate principals (both CAs, the server certificate, the reporter, installations,
    service roles, the CRL and every revocation) come from `privoke-pki`. Deliberately invalid credentials (expired, not yet valid, no
    client-auth usage, server-auth only, a foreign CA, self-signed) come from OpenSSL, which signs with the adopted client CA, because
    `privoke-pki` refuses to mint them. `issuers` records the tool behind every credential label."""

    INSTALLATIONS = ("registered", "second", "second-registered", "x13-revoked", "x13-denied", "x13-bystander")
    UNREGISTERED_INSTALLATIONS = ("second",)
    SERVICES = {"publisher": ("server-fuzzer", "publisher"), "trainer": ("trainer", "trainer"), "runtime": ("client-runtime", "runtime"),
                "ck-revoked-trainer": ("ck-revoked-trainer", "trainer"), "ck-denied-trainer": ("ck-denied-trainer", "trainer"),
                "stranger": ("stranger", None)}
    INVALID = ("expired", "future", "no-eku", "server-only", "foreign", "self-signed")
    CERT_DAYS = 1

    def __init__(self, work: Path, tool: PkiTool):
        self.work, self.tool = work.resolve(), tool
        w = self.work
        self.client_dir, self.server_dir = w / "client-ca", w / "server-ca"
        self.registry_path, self.crl_path = w / "registry.toml", w / "crl.pem"
        self.registry_path.write_text("version = 1\nreporter = true\n", encoding="utf-8", newline="\n")
        for name in self.INSTALLATIONS:
            (w / "installations" / name).mkdir(parents=True)
            (w / "installations" / name / "bundle").mkdir()
        (w / "services").mkdir()
        tool.batch([["init-ca", "--dir", self.client_dir, "--name", "privoke-s13d-client-ca", "--days", 2],
                    ["init-ca", "--dir", self.server_dir, "--name", "privoke-s13d-server-ca", "--days", 2],
                    ["issue-server", "--ca-dir", self.server_dir, "--dns", "localhost", "--dns", "127.0.0.1", "--out-dir", w / "server", "--days", 2],
                    ["issue-reporter", "--ca-dir", self.client_dir, "--days", 2],
                    *[["enrol", "--dir", w / "installations" / name] for name in self.INSTALLATIONS]])
        self.ids: dict[str, str] = {name: (w / "installations" / name / "installation.id").read_text(encoding="utf-8").strip()
                                    for name in self.INSTALLATIONS}
        sign: list[list] = []
        for name in self.INSTALLATIONS:
            directory = w / "installations" / name
            command = ["sign", "--ca-dir", self.client_dir, "--csr", directory / "client.csr", "--installation", self.ids[name], "--days", self.CERT_DAYS,
                       "--out-dir", directory / "bundle", "--server-ca", self.server_dir / "ca.crt", "--label", name]
            if name not in self.UNREGISTERED_INSTALLATIONS:
                command += ["--registry", self.registry_path]
            sign.append(command)
            sign.append(["install-cert", "--dir", directory, "--cert", directory / "bundle" / "client.crt", "--server-ca", self.server_dir / "ca.crt"])
        for service, role in self.SERVICES.values():
            command = ["sign-service", "--ca-dir", self.client_dir, "--name", service, "--role", role or "runtime", "--days", self.CERT_DAYS,
                       "--out-dir", w / "services"]
            if role:  # a service with no registered role is signed by the client CA and never registered
                command += ["--registry", self.registry_path]
            sign.append(command)
        sign.append(["crl", "--ca-dir", self.client_dir, "--out", self.crl_path, "--days", 2])
        tool.batch(sign)
        self.certs: dict[str, tuple[bytes, bytes]] = {}
        self.issuers: dict[str, str] = {}
        for name in self.INSTALLATIONS:
            directory = w / "installations" / name
            self.certs[name] = ((directory / "client.crt").read_bytes(), (directory / "client.key").read_bytes())
            self.issuers[name] = ISSUER_PKI
        for label, (service, _) in self.SERVICES.items():
            self.certs[label] = ((w / "services" / f"{service}.crt").read_bytes(), (w / "services" / f"{service}.key").read_bytes())
            self.issuers[label] = ISSUER_PKI
        self.certs["reporter"] = ((self.client_dir / "reporter/reporter.crt").read_bytes(), (self.client_dir / "reporter/reporter.key").read_bytes())
        self.issuers["reporter"] = ISSUER_PKI
        self.server = ((w / "server" / "server.crt").read_bytes(), (w / "server" / "server.key").read_bytes())
        self.server_ca = SimpleNamespace(cert=(self.server_dir / "ca.crt").read_bytes())
        self.client_ca = SimpleNamespace(cert=(self.client_dir / "ca.crt").read_bytes())
        self.service_names = {label: service for label, (service, _) in self.SERVICES.items()}
        self._issue_invalid()
        self.crl = self.crl_path.read_bytes()

    def _issue_invalid(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        hour = dt.timedelta(hours=1)
        w = self.work
        adopted = TestAuthority.adopt(w / "openssl", "client-ca-adopted", (self.client_dir / "ca.crt").read_bytes(), (self.client_dir / "ca.key").read_bytes())
        self.foreign_ca = TestAuthority(w / "openssl", "foreign-ca")
        for name in self.INVALID:
            self.ids[name] = str(uuid.uuid4())
        urn = lambda name: f"URI:{URN_INSTALLATION}{self.ids[name]}"  # noqa: E731
        self.certs["expired"] = adopted.issue("expired", cn="installation-expired", usage="clientAuth", san=urn("expired"), start=now - 10 * hour, end=now - 5 * hour)
        self.certs["future"] = adopted.issue("future", cn="installation-future", usage="clientAuth", san=urn("future"), start=now + 5 * hour, end=now + 10 * hour)
        self.certs["server-only"] = adopted.issue("server-only", cn="installation-server-only", usage="serverAuth", san=urn("server-only"))
        self.certs["no-eku"] = adopted.issue_extensions("no-eku", cn="installation-no-eku", extensions=[f"subjectAltName={urn('no-eku')}"],
                                                        start=now - hour, end=now + hour)
        self.certs["foreign"] = self.foreign_ca.issue("foreign", cn="installation-foreign", usage="clientAuth", san=urn("foreign"))
        self.certs["self-signed"] = self.foreign_ca.self_signed("self-signed", cn="installation-self-signed", usage="clientAuth", san=urn("self-signed"))
        for name in self.INVALID:
            self.issuers[name] = ISSUER_OPENSSL
        # The man in the middle of TL3: a server certificate for the right names from a CA the client does not trust.
        self.mitm = self.foreign_ca.issue("mitm-server", cn="mitm-server", usage="serverAuth", san="DNS:localhost,IP:127.0.0.1")
        self.issuers["mitm-server"] = ISSUER_OPENSSL
        append_registry_installations(self.registry_path, [self.ids[name] for name in self.INVALID])

    @property
    def registered_ids(self) -> list[str]:
        return [self.ids[name] for name in self.INSTALLATIONS if name not in self.UNREGISTERED_INSTALLATIONS] + [self.ids[name] for name in self.INVALID]

    def publish(self, directory: Path) -> Path:
        """Write the files a server reads. Keys are synthetic, so they are world-readable for the container's user."""
        directory.mkdir(parents=True, exist_ok=True)
        files = {"server.crt": self.server[0], "server.key": self.server[1], "client-ca.pem": self.client_ca.cert, "crl.pem": self.crl_path.read_bytes(),
                 "registry.toml": self.registry_path.read_bytes()}
        for name, content in files.items():
            path = directory / name
            path.write_bytes(content)
            path.chmod(0o644)
        return directory

    def revoke(self, label: str) -> bytes:
        """Revoke one identity in the CA ledger (no registry edit, so only the CRL changes) and return the new signed CRL."""
        if label in self.INSTALLATIONS:
            who = ["--installation", self.ids[label]]
        elif label in self.SERVICES and self.SERVICES[label][1]:
            who = ["--service", self.service_names[label]]
        else:
            raise KeyError(label)
        self.tool.batch([["revoke", "--ca-dir", self.client_dir, *who], ["crl", "--ca-dir", self.client_dir, "--out", self.crl_path, "--days", 2]])
        return self.crl_path.read_bytes()

    def credential_issuer(self, identity: str | None) -> str:
        """The tool behind the credential a row presented (`none` when it presented no certificate)."""
        return self.issuers.get(identity or "", ISSUER_NONE)


# --------------------------------------------------------------------------------------
# TLS record tools for the TL rows: a recording and tampering loopback proxy, a raw replay, a man in the middle
# --------------------------------------------------------------------------------------

TLS_HANDSHAKE, TLS_APPLICATION = 22, 23
TLS_CONTENT_TYPES = (20, 21, 22, 23)
ALERT_RECORD_MAX = 32  # an encrypted TLS 1.3 alert is 24 bytes (5 header, 2 alert, 1 inner type, 16 tag)


def tls_records(data: bytes) -> list[tuple[int, int, int]]:
    """(content type, offset, length including the 5-byte header) of every complete record at the start of `data`. Parsing stops at the
    first byte that does not begin a plausible record or at a truncated record."""
    records, position = [], 0
    while position + 5 <= len(data):
        content_type, length = data[position], int.from_bytes(data[position + 3:position + 5], "big")
        if content_type not in TLS_CONTENT_TYPES or length > 16645 or position + 5 + length > len(data):
            break
        records.append((content_type, position, 5 + length))
        position += 5 + length
    return records


def stream_stats(data: bytes) -> dict:
    """What can be said about one direction of a TLS 1.3 stream without any key: record count, application-data records (which
    carry every encrypted handshake message and every HTTP/2 byte), their total size and the size of the last record."""
    records = tls_records(data)
    application = [length for content_type, _, length in records if content_type == TLS_APPLICATION]
    return {"bytes": len(data), "records": len(records), "application_records": len(application), "application_bytes": sum(application),
            "last_record_bytes": records[-1][2] if records else 0, "first_record_type": records[0][0] if records else None}


def replay_refused(original: dict, replay: dict, closed: bool) -> bool:
    """A replayed ClientHello gets a fresh server random, so the recorded Finished cannot verify and the server aborts with an alert. The
    replay is refused when the server answered at all (the stream starts with a handshake record and holds at least two records, so a
    silent or empty stream is not a refusal), closed the connection, ended with an alert-sized record, and sent less protected data
    than it did for the original exchange (no post-handshake tickets and no HTTP/2 response, so no receipt)."""
    if replay.get("first_record_type") != TLS_HANDSHAKE or replay.get("records", 0) < 2:
        return False
    return bool(closed and replay["last_record_bytes"] <= ALERT_RECORD_MAX and replay["application_bytes"] < original["application_bytes"])


def flip_bit(record: bytes) -> bytes:
    """One bit of the ciphertext of a TLS record (the middle byte of its body; the header stays intact so the record still parses)."""
    mutated = bytearray(record)
    mutated[5 + (len(record) - 5) // 2] ^= 0x01
    return bytes(mutated)


class RecordingProxy:
    """A loopback TCP proxy in front of a TLS listener. It forwards both directions and keeps what crossed it, in order, as TLS
    records. With `flip_record=k` it flips one bit of the ciphertext of the k-th client application-data record (1-based). It never
    sees a key: it can record, replay and corrupt bytes, which is the attacker model of the TL rows."""

    def __init__(self, upstream_port: int, *, flip_record: int | None = None):
        self.upstream_port, self.flip_record = upstream_port, flip_record
        self._lock = threading.Lock()
        self.events: list[tuple[int, str, int]] = []  # (sequence, direction, content type), appended before each record is forwarded
        self.client_bytes = bytearray()
        self.server_bytes = bytearray()
        self.flipped = False
        self._sockets: list[socket.socket] = []
        self._stop = threading.Event()
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self._threads = [threading.Thread(target=self._accept, daemon=True)]
        self._threads[0].start()

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            try:
                upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
            except OSError:
                client.close()
                continue
            self._sockets += [client, upstream]
            for source, sink, direction in ((client, upstream, "c2s"), (upstream, client, "s2c")):
                thread = threading.Thread(target=self._pump, args=(source, sink, direction), daemon=True)
                self._threads.append(thread)
                thread.start()

    def _log(self, direction: str, content_type: int) -> None:
        with self._lock:
            self.events.append((len(self.events), direction, content_type))

    def _pump(self, source: socket.socket, sink: socket.socket, direction: str) -> None:
        pending, application = b"", 0
        store = self.client_bytes if direction == "c2s" else self.server_bytes
        try:
            while not self._stop.is_set():
                try:
                    chunk = source.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                with self._lock:
                    store += chunk
                pending += chunk
                consumed = 0
                for content_type, offset, length in tls_records(pending):
                    record = pending[offset:offset + length]
                    self._log(direction, content_type)
                    if direction == "c2s" and content_type == TLS_APPLICATION:
                        application += 1
                        if self.flip_record == application and not self.flipped:
                            record, self.flipped = flip_bit(record), True
                    sink.sendall(record)
                    consumed = offset + length
                pending = pending[consumed:]
                if len(pending) >= 5 and pending[0] not in TLS_CONTENT_TYPES:
                    sink.sendall(pending)  # not TLS at all: forward untouched
                    pending = b""
        except OSError:
            pass
        finally:
            for end in (source, sink):
                try:
                    end.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def client_application_records_before_response(self) -> int:
        """Client application-data records the server had to receive before it sent its last application record: the records a
        request depends on. Records the client sent after the response (window updates, the close alert) are not counted."""
        with self._lock:
            events = list(self.events)
        last_server = max((sequence for sequence, direction, kind in events if direction == "s2c" and kind == TLS_APPLICATION), default=-1)
        return sum(1 for sequence, direction, kind in events if direction == "c2s" and kind == TLS_APPLICATION and sequence < last_server)

    def captured(self) -> tuple[bytes, bytes]:
        with self._lock:
            return bytes(self.client_bytes), bytes(self.server_bytes)

    def close(self) -> None:
        self._stop.set()
        for end in [self._listener, *self._sockets]:
            try:
                end.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=2)


def replay_bytes(port: int, data: bytes, *, wait: float = 4.0) -> dict:
    """Send recorded client bytes to a TLS listener on a new connection and keep what comes back, until the server closes or `wait` passes."""
    received, closed = b"", False
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(data)
        connection.settimeout(0.5)
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                chunk = connection.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                closed = True
                break
            if not chunk:
                closed = True
                break
            received += chunk
    return {"received": received, "closed": closed, "stats": stream_stats(received)}


class MitmListener:
    """A TLS server presenting a certificate chain the client may or may not trust. It counts completed handshakes and the application
    bytes it receives, which is what a man in the middle would need to read or alter a request."""

    def __init__(self, certificate: bytes, key: bytes, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "mitm.crt").write_bytes(certificate)
        (directory / "mitm.key").write_bytes(key)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(str(directory / "mitm.crt"), str(directory / "mitm.key"))
        self.context.set_alpn_protocols(["h2"])
        self.completed = 0
        self.failed = 0
        self.application_bytes = 0
        self._lock = threading.Lock()
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

    def _handle(self, raw: socket.socket) -> None:
        raw.settimeout(5)
        try:
            with self.context.wrap_socket(raw, server_side=True) as connection:
                with self._lock:
                    self.completed += 1
                connection.settimeout(1.0)
                try:
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            break
                        with self._lock:
                            self.application_bytes += len(data)
                except (socket.timeout, OSError, ssl.SSLError):
                    pass
        except (ssl.SSLError, OSError):
            with self._lock:
                self.failed += 1
            try:
                raw.close()
            except OSError:
                pass

    def stats(self) -> dict:
        with self._lock:
            return {"handshakes_completed": self.completed, "handshakes_failed": self.failed, "application_bytes": self.application_bytes}

    def close(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=2)
