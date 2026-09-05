"""Workstation stack selection and authenticated gRPC transport."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Mapping


def load_runtime_environment(runtime_root: Path) -> None:
    # An explicit path also supports installed packages launched from any cwd.
    from dotenv import load_dotenv

    env_path = Path(os.getenv("PRIVOKE_ENV_FILE", str(runtime_root / ".env"))).resolve()
    load_dotenv(env_path, override=False, interpolate=False)
    for name in ("PRIVOKE_TLS_CA_FILE", "PRIVOKE_TLS_CERT_FILE", "PRIVOKE_TLS_KEY_FILE"):
        value = os.getenv(name, "").strip()
        if value and not Path(value).is_absolute():
            os.environ[name] = str(env_path.parent / value)


def use_local_stack(environment: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environment is None else environment
    value = env.get("PRIVOKE_USE_LOCAL_STACK", "false").strip().lower()
    if value not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("PRIVOKE_USE_LOCAL_STACK must be a boolean.")
    return value in {"true", "1", "yes", "on"}


def stack_target(service: str, environment: Mapping[str, str] | None = None) -> str:
    env = os.environ if environment is None else environment
    ports = {"MODEL_STREAMING": 50051, "TELEMETRY": 50055}
    if service not in ports:
        raise ValueError("Unsupported stack service.")
    if env.get("PRIVOKE_STACK_MODE") == "internal":
        target = env.get(f"{service}_TARGET", "").strip()
        if not target:
            raise ValueError(f"{service}_TARGET is required in internal mode.")
        return target
    if use_local_stack(env):
        return f"127.0.0.1:{ports[service]}"
    return env.get("PRIVOKE_CLOUD_TARGET", "").strip()


def grpc_channel(target: str, *, environment: Mapping[str, str] | None = None, options=()):
    import grpc

    env = os.environ if environment is None else environment
    if not target:
        raise ValueError("Configure PRIVOKE_CLOUD_TARGET in the client runtime .env.")
    # Explicit loopback callers (including evaluation harnesses) need no TLS.
    host = target.rsplit(":", 1)[0].strip("[]")
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if loopback or env.get("PRIVOKE_STACK_MODE") == "internal":
        return grpc.insecure_channel(target, options=options)
    cert = env.get("PRIVOKE_TLS_CERT_FILE", "").strip()
    key = env.get("PRIVOKE_TLS_KEY_FILE", "").strip()
    if not cert or not key:
        raise ValueError("Cloud connections require PRIVOKE_TLS_CERT_FILE and PRIVOKE_TLS_KEY_FILE.")
    ca = env.get("PRIVOKE_TLS_CA_FILE", "").strip()
    credentials = grpc.ssl_channel_credentials(
        root_certificates=Path(ca).read_bytes() if ca else None,
        private_key=Path(key).read_bytes(),
        certificate_chain=Path(cert).read_bytes(),
    )
    return grpc.secure_channel(target, credentials, options=options)
