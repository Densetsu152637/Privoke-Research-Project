"""Disposable test PKI and a mutual-TLS gRPC stand-in for the authentication negative tests.

Everything here is generated per run in a temporary directory and holds synthetic
identities only. The stand-in terminator is a grpcio server that requires a client
certificate; it is NOT the production nginx ingress (see the record's limitations).
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import threading
from concurrent import futures
from pathlib import Path

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
