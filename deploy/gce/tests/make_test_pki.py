#!/usr/bin/env python3
"""Generate a throwaway test PKI for the container smoke job (stage 23 of docs/plans/rust-server-rewrite.md).

Everything is issued at run time by the real `privoke-pki` tool into directories the caller names; nothing is committed and
nothing here is a credential. It writes:

* `--out DIR`, the layout `docker-compose.prod.yml` mounts as `PRIVOKE_PKI_DIR`:
  `server-ca.pem`, `client-ca.pem`, `server/server.{crt,key}`, `svc/{probe,param-update,fuzzer,analysis}.{crt,key}` and
  `live/{crl.pem,registry.toml}` (the reporter is admitted);
* `--creds DIR`, the credential directory of `smoke.py`: `server-ca.pem`, `installation.{crt,key}` (registered),
  `reporter.{crt,key}`, `unregistered.{crt,key}` (signed by the client CA, not registered) and `foreign.{crt,key}`
  (signed by another CA);
* `--work DIR`, the CA directories, which hold the CA private keys and must never be mounted.

    python deploy/gce/tests/make_test_pki.py --tool rust/target/release/privoke-pki --out "$PRIVOKE_PKI_DIR" \\
        --creds "$RUNNER_TEMP/smoke-creds" --work "$RUNNER_TEMP/pki-work"
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

SERVER_NAMES = ("localhost", "127.0.0.1", "model-streaming-service", "telemetry-service", "param-update-service",
                "privoke-fuzzer", "analysis-service", "analysis-model-streaming")
SERVICES = (("probe", "runtime"), ("param-update", "publisher"), ("fuzzer", "publisher"), ("analysis", "runtime"))


class Tool:
    def __init__(self, binary: Path) -> None:
        self.binary = str(binary)

    def run(self, *arguments: object) -> str:
        result = subprocess.run([self.binary, *map(str, arguments)], capture_output=True, text=True)
        if result.returncode:
            raise SystemExit(f"privoke-pki {arguments[0]} failed: {result.stderr.strip()}")
        return result.stdout


def copy(source: Path, destination: Path, mode: int = 0o640) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def installation(tool: Tool, work: Path, name: str, ca_dir: Path, server_ca: Path, registry: Path | None) -> tuple[Path, Path]:
    """Enrol an installation, have `ca_dir` sign it (and register it when `registry` is given); returns (certificate, key)."""
    directory, bundle = work / name, work / f"{name}-bundle"
    tool.run("enrol", "--dir", directory)
    identifier = (directory / "installation.id").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", identifier):
        raise SystemExit(f"unexpected installation id for {name}")
    arguments: list[object] = ["sign", "--ca-dir", ca_dir, "--csr", directory / "client.csr", "--installation", identifier,
                               "--out-dir", bundle, "--server-ca", server_ca]
    if registry is not None:
        arguments += ["--registry", registry, "--label", name]
    tool.run(*arguments)
    return bundle / "client.crt", directory / "client.key"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--creds", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    tool = Tool(args.tool)
    out, creds, work = args.out, args.creds, args.work
    for directory in (out, creds, work):
        if directory.exists() and any(directory.iterdir()):
            raise SystemExit(f"{directory} is not empty; the test PKI is generated fresh on every run")
        directory.mkdir(parents=True, exist_ok=True)

    client_ca, server_ca, foreign_ca = work / "ca-client", work / "ca-server", work / "ca-foreign"
    tool.run("init-ca", "--dir", client_ca, "--name", "PriVoke CI client CA")
    tool.run("init-ca", "--dir", server_ca, "--name", "PriVoke CI server CA")
    tool.run("init-ca", "--dir", foreign_ca, "--name", "PriVoke CI foreign CA")
    server_arguments: list[object] = ["issue-server", "--ca-dir", server_ca, "--out-dir", work / "server"]
    for name in SERVER_NAMES:
        server_arguments += ["--dns", name]
    tool.run(*server_arguments)
    tool.run("issue-reporter", "--ca-dir", client_ca)

    registry = out / "live" / "registry.toml"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text("version = 1\nreporter = true\n", encoding="utf-8")
    for name, role in SERVICES:
        tool.run("sign-service", "--ca-dir", client_ca, "--name", name, "--role", role, "--out-dir", work / "svc", "--registry", registry)
    smoke_installation = installation(tool, work, "smoke", client_ca, server_ca / "ca.crt", registry)
    unregistered = installation(tool, work, "unregistered", client_ca, server_ca / "ca.crt", None)
    foreign = installation(tool, work, "foreign", foreign_ca, server_ca / "ca.crt", None)
    tool.run("crl", "--ca-dir", client_ca, "--out", out / "live" / "crl.pem", "--days", "7")
    registry.chmod(0o640)
    (out / "live" / "crl.pem").chmod(0o640)

    copy(server_ca / "ca.crt", out / "server-ca.pem")
    copy(client_ca / "ca.crt", out / "client-ca.pem")
    copy(work / "server" / "server.crt", out / "server" / "server.crt")
    copy(work / "server" / "server.key", out / "server" / "server.key")
    for name, _ in SERVICES:
        copy(work / "svc" / f"{name}.crt", out / "svc" / f"{name}.crt")
        copy(work / "svc" / f"{name}.key", out / "svc" / f"{name}.key")

    copy(server_ca / "ca.crt", creds / "server-ca.pem", 0o600)
    for label, (certificate, key) in (("installation", smoke_installation), ("unregistered", unregistered), ("foreign", foreign)):
        copy(certificate, creds / f"{label}.crt", 0o600)
        copy(key, creds / f"{label}.key", 0o600)
    copy(client_ca / "reporter" / "reporter.crt", creds / "reporter.crt", 0o600)
    copy(client_ca / "reporter" / "reporter.key", creds / "reporter.key", 0o600)
    print(f"test PKI written: {out} (stack), {creds} (smoke credentials); CA keys stay in {work}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
