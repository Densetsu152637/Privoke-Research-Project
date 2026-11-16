"""Synthetic loopback HTTPS receiver for the cross-platform study (XPLAT-20261117).

It plays every supported-provider host (the browser maps those names to
127.0.0.1) so the unmodified extension intercepts the pages, and records the
exact bytes of every POST that actually reaches it. It contains no provider
logic and never contacts the network.
"""

from __future__ import annotations

import http.server
import json
import ssl
import subprocess
import threading
from pathlib import Path

from cross_platform_probes import FIXTURE_HOSTS, Capture, probe_id_from_path

PAGE = b"<!doctype html><title>synthetic receiver</title><body>synthetic</body>"


def generate_certificate(directory: Path, openssl: str = "openssl") -> tuple[Path, Path, str]:
    """Self-signed certificate for the fixture hosts; returns (cert, key, spki-sha256-base64)."""
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / "san.cnf"
    names = ",".join(f"DNS:{host}" for host in FIXTURE_HOSTS)
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        f"[dn]\nCN={FIXTURE_HOSTS[0]}\n[v3]\nsubjectAltName={names}\nbasicConstraints=CA:FALSE\n",
        encoding="ascii",
    )
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "2", "-config", str(config)],
                   check=True, capture_output=True)
    pubkey = subprocess.run([openssl, "x509", "-in", str(cert), "-pubkey", "-noout"],
                            check=True, capture_output=True).stdout
    der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "der"], input=pubkey,
                         check=True, capture_output=True).stdout
    digest = subprocess.run([openssl, "dgst", "-sha256", "-binary"], input=der,
                            check=True, capture_output=True).stdout
    spki = subprocess.run([openssl, "base64"], input=digest, check=True, capture_output=True).stdout
    return cert, key, spki.decode("ascii").strip()


class Receiver:
    def __init__(self, cert: Path, key: Path, port: int = 443) -> None:
        self.captures: list[Capture] = []
        self.gets: list[str] = []
        self.foreign_hosts: list[str] = []
        self.lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _cors(self) -> None:
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

            def _respond(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self._cors()
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                host = (self.headers.get("Host") or "").split(":")[0]
                with outer.lock:
                    outer.gets.append(f"{host}{self.path}")
                    if host not in FIXTURE_HOSTS:
                        outer.foreign_hosts.append(host)
                self._respond(200, "text/html; charset=utf-8", PAGE)

            def do_OPTIONS(self) -> None:  # noqa: N802
                self._respond(204, "text/plain", b"")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                host = self.headers.get("Host") or ""
                with outer.lock:
                    outer.captures.append(Capture(
                        probe=probe_id_from_path(self.path), host=host, method="POST", path=self.path,
                        content_type=self.headers.get("Content-Type"), body=body))
                    if host.split(":")[0] not in FIXTURE_HOSTS:
                        outer.foreign_hosts.append(host)
                self._respond(200, "application/json", json.dumps({"ok": True}).encode())

            def log_message(self, *args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def captures_for(self, probe_id: str) -> list[Capture]:
        with self.lock:
            return [capture for capture in self.captures if capture.probe == probe_id]

    def unattributed(self) -> list[Capture]:
        with self.lock:
            return [capture for capture in self.captures if capture.probe is None]
