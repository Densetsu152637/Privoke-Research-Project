"""Workstation stack selection and authenticated gRPC transport.

Client side: ``stack_target`` picks the model and telemetry targets, and ``grpc_channel`` opens a mutually
authenticated channel. Server side: ``build_server`` and ``bind_server`` give the Python servers mutual TLS and a
peer-identity check, and refuse plaintext on any non-loopback address.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import threading
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

LOGGER = logging.getLogger(__name__)

# Credential kinds a client channel can present, and the environment variables that name their key pair.
CREDENTIAL_FILES = {
    "installation": ("PRIVOKE_TLS_CERT_FILE", "PRIVOKE_TLS_KEY_FILE"),
    "reporter": ("PRIVOKE_TELEMETRY_TLS_CERT_FILE", "PRIVOKE_TELEMETRY_TLS_KEY_FILE"),
}
SERVER_TLS_CERT = "PRIVOKE_SERVER_TLS_CERT_FILE"
SERVER_TLS_KEY = "PRIVOKE_SERVER_TLS_KEY_FILE"
SERVER_TLS_CLIENT_CA = "PRIVOKE_SERVER_TLS_CLIENT_CA_FILE"
ALLOWED_IDENTITIES = "PRIVOKE_SERVER_ALLOWED_IDENTITIES"
ALLOWED_ROLES = "PRIVOKE_SERVER_ALLOWED_ROLES"
REGISTRY_FILE = "PRIVOKE_SERVER_REGISTRY_FILE"
# Explicit research-only opt-out of the Compose-network mutual-TLS requirement. Never set it in a deployment.
INSECURE_INTERNAL = "PRIVOKE_ALLOW_INSECURE_INTERNAL_PLAINTEXT"

_FILE_VARIABLES = (
    "PRIVOKE_TLS_CA_FILE",
    "PRIVOKE_TLS_CERT_FILE",
    "PRIVOKE_TLS_KEY_FILE",
    "PRIVOKE_TELEMETRY_TLS_CERT_FILE",
    "PRIVOKE_TELEMETRY_TLS_KEY_FILE",
)


def load_runtime_environment(runtime_root: Path) -> None:
    # An explicit path also supports installed packages launched from any cwd.
    from dotenv import load_dotenv

    env_path = Path(os.getenv("PRIVOKE_ENV_FILE", str(runtime_root / ".env"))).resolve()
    load_dotenv(env_path, override=False, interpolate=False)
    for name in _FILE_VARIABLES:
        value = os.getenv(name, "").strip()
        if value and not Path(value).is_absolute():
            os.environ[name] = str(env_path.parent / value)


def _boolean(env: Mapping[str, str], name: str, default: str = "false") -> bool:
    value = env.get(name, default).strip().lower()
    if value not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError(f"{name} must be a boolean.")
    return value in {"true", "1", "yes", "on"}


def use_local_stack(environment: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environment is None else environment
    return _boolean(env, "PRIVOKE_USE_LOCAL_STACK")


def stack_target(service: str, environment: Mapping[str, str] | None = None) -> str:
    env = os.environ if environment is None else environment
    local_targets = {
        "MODEL_STREAMING": env.get("PRIVOKE_LOCAL_MODEL_STREAMING_TARGET", "127.0.0.1:50051").strip(),
        "TELEMETRY": env.get("PRIVOKE_LOCAL_TELEMETRY_TARGET", "127.0.0.1:50055").strip(),
    }
    if service not in local_targets:
        raise ValueError("Unsupported stack service.")
    if env.get("PRIVOKE_STACK_MODE") == "internal":
        target = env.get(f"{service}_TARGET", "").strip()
        if not target:
            raise ValueError(f"{service}_TARGET is required in internal mode.")
        return target
    if use_local_stack(env):
        return local_targets[service]
    # The model and telemetry servers listen on different public ports. An unset model target falls back to the
    # shared one; telemetry has no fallback because it needs its own port and credential.
    if service == "MODEL_STREAMING":
        return env.get("PRIVOKE_CLOUD_MODEL_TARGET", "").strip() or env.get("PRIVOKE_CLOUD_TARGET", "").strip()
    return env.get("PRIVOKE_CLOUD_TELEMETRY_TARGET", "").strip()


def is_loopback_host(host: str) -> bool:
    host = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def is_loopback_target(target: str) -> bool:
    return is_loopback_host(target.rsplit(":", 1)[0])


def insecure_internal_allowed(env: Mapping[str, str]) -> bool:
    """Only Compose-internal mode may opt out, and only by an explicit setting."""
    return env.get("PRIVOKE_STACK_MODE") == "internal" and _boolean(env, INSECURE_INTERNAL)


def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def grpc_channel(
    target: str,
    *,
    environment: Mapping[str, str] | None = None,
    options=(),
    credential: str = "installation",
    tls: bool | None = None,
):
    """Open a client channel.

    Loopback targets use plaintext (the workstation boundary) unless ``tls`` is True. Every other target, including
    a Compose-internal one, needs mutual TLS with the key pair named by ``credential``: the installation certificate,
    or the shared telemetry reporter credential.
    """
    import grpc

    env = os.environ if environment is None else environment
    if not target:
        raise ValueError(
            "Configure PRIVOKE_CLOUD_TARGET (or PRIVOKE_CLOUD_MODEL_TARGET / PRIVOKE_CLOUD_TELEMETRY_TARGET) "
            "in the client runtime .env."
        )
    if credential not in CREDENTIAL_FILES:
        raise ValueError("Unsupported credential kind.")
    loopback = is_loopback_target(target)
    if tls is None:
        tls = not loopback
    if not tls:
        return grpc.insecure_channel(target, options=options)
    if not loopback and insecure_internal_allowed(env):
        LOGGER.warning("plaintext Compose-network channel allowed by %s", INSECURE_INTERNAL)
        return grpc.insecure_channel(target, options=options)
    cert_name, key_name = CREDENTIAL_FILES[credential]
    cert = env.get(cert_name, "").strip()
    key = env.get(key_name, "").strip()
    if not cert or not key:
        raise ValueError(f"Non-loopback connections require {cert_name} and {key_name}.")
    ca = env.get("PRIVOKE_TLS_CA_FILE", "").strip()
    credentials = grpc.ssl_channel_credentials(
        root_certificates=_read(ca) if ca else None,
        private_key=_read(key),
        certificate_chain=_read(cert),
    )
    return grpc.secure_channel(target, credentials, options=options)


def service_channel(target: str, *, environment: Mapping[str, str] | None = None, options=()):
    """Channel between Python services (fuzzer to runtime or param-update, v3 servers to each other).

    A service with an identity (``PRIVOKE_TLS_CERT_FILE`` and key) always uses mutual TLS. Without one it keeps the
    legacy plaintext channel and says so: the servers refuse plaintext themselves, so a service that lacks its
    certificate fails there rather than silently degrading.
    """
    import grpc

    env = os.environ if environment is None else environment
    cert_name, key_name = CREDENTIAL_FILES["installation"]
    if env.get(cert_name, "").strip() and env.get(key_name, "").strip():
        return grpc_channel(target, environment=env, options=options, tls=True)
    if not is_loopback_target(target):
        LOGGER.warning("no %s configured: using a plaintext channel to %s", cert_name, target)
    return grpc.insecure_channel(target, options=options)


# --- server side -----------------------------------------------------------------------------------------------


def server_credentials_configured(env: Mapping[str, str]) -> bool:
    return any(env.get(name, "").strip() for name in (SERVER_TLS_CERT, SERVER_TLS_KEY, SERVER_TLS_CLIENT_CA))


def server_credentials(environment: Mapping[str, str] | None = None):
    """Mutual-TLS server credentials, or None when no server TLS is configured. A partial setting is an error."""
    import grpc

    env = os.environ if environment is None else environment
    values = {name: env.get(name, "").strip() for name in (SERVER_TLS_CERT, SERVER_TLS_KEY, SERVER_TLS_CLIENT_CA)}
    if not any(values.values()):
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ValueError("Server TLS needs " + ", ".join(missing) + ".")
    return grpc.ssl_server_credentials(
        [(_read(values[SERVER_TLS_KEY]), _read(values[SERVER_TLS_CERT]))],
        root_certificates=_read(values[SERVER_TLS_CLIENT_CA]),
        require_client_auth=True,
    )


@dataclass(frozen=True)
class _Registry:
    denied: frozenset
    expiry: Mapping
    roles: Mapping


def _parse_time(text) -> datetime | None:
    if text is None:
        return None
    return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)


def parse_registry(text: str) -> _Registry:
    """Read the version 1 registry the Rust servers use (see ``privoke-transport``)."""
    data = tomllib.loads(text)
    if data.get("version") != 1:
        raise ValueError("unsupported registry version")
    expiry: dict = {}
    roles: dict = {}
    for entry in data.get("installation", []):
        expiry[f"urn:privoke:installation:{entry['id']}"] = _parse_time(entry.get("expires"))
    for entry in data.get("service", []):
        urn = f"urn:privoke:service:{entry['name']}"
        expiry[urn] = _parse_time(entry.get("expires"))
        roles[urn] = entry["role"]
    return _Registry(frozenset(entry["urn"] for entry in data.get("deny", [])), expiry, roles)


class PeerIdentityGuard:
    """Decides whether a verified peer certificate may call this server.

    The TLS layer has already required a certificate from the client CA. This adds the identity decision: the
    certificate must carry exactly one ``urn:privoke:`` SAN, that identity must be on the allow list (or be a
    registered service with an allowed role), must not be on the registry deny list, and must not be past its
    registry expiry. The registry file is re-read when it changes; a bad edit keeps the previous registry.
    gRPC's Python server cannot load a CRL, so revocation here is the deny list plus short certificate lifetimes.
    """

    def __init__(
        self,
        allowed_identities: Iterable[str] = (),
        allowed_roles: Iterable[str] = (),
        registry_path: str | Path | None = None,
    ):
        self.allowed = frozenset(allowed_identities)
        self.roles = frozenset(allowed_roles)
        self.registry_path = Path(registry_path) if registry_path else None
        if not self.allowed and not (self.registry_path and self.roles):
            raise ValueError(
                f"Mutual TLS needs {ALLOWED_IDENTITIES}, or {REGISTRY_FILE} with {ALLOWED_ROLES}; refusing to start."
            )
        self._lock = threading.Lock()
        self._registry: _Registry | None = None
        self._stamp = None
        if self.registry_path:
            self._refresh(first=True)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "PeerIdentityGuard":
        env = os.environ if environment is None else environment

        def split(name: str) -> list[str]:
            return [part.strip() for part in env.get(name, "").split(",") if part.strip()]

        return cls(split(ALLOWED_IDENTITIES), split(ALLOWED_ROLES), env.get(REGISTRY_FILE, "").strip() or None)

    def _refresh(self, first: bool = False) -> None:
        try:
            stat = self.registry_path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp == self._stamp:
                return
            registry = parse_registry(self.registry_path.read_text(encoding="utf-8"))
        except Exception as exc:
            if first:
                raise ValueError("The server registry is unreadable or invalid.") from exc
            LOGGER.error("registry reload refused, keeping the previous registry (%s)", exc.__class__.__name__)
            return
        with self._lock:
            self._registry, self._stamp = registry, stamp

    @staticmethod
    def identity(auth_context) -> str | None:
        """The single PriVoke URI SAN of the verified peer certificate, or None."""
        if not auth_context or b"ssl" not in (auth_context.get("transport_security_type") or ()):
            return None
        urns = {
            value.decode("utf-8", "replace")
            for value in auth_context.get("x509_subject_alternative_name", ())
            if value.startswith(b"urn:privoke:")
        }
        return next(iter(urns)) if len(urns) == 1 else None

    def check(self, auth_context) -> str | None:
        """None when the peer may call, else a short reason."""
        urn = self.identity(auth_context)
        if urn is None:
            return "peer certificate carries no single PriVoke identity"
        if self.registry_path:
            self._refresh()
            with self._lock:
                registry = self._registry
            if urn in registry.denied:
                return "identity is revoked"
            expires = registry.expiry.get(urn)
            if expires is not None and expires <= datetime.now(timezone.utc):
                return "registration has expired"
            if urn not in self.allowed and registry.roles.get(urn) not in self.roles:
                return "identity is not authorised for this service"
            return None
        return None if urn in self.allowed else "identity is not authorised for this service"


def _guard_interceptor(guard: PeerIdentityGuard):
    import grpc

    def verify(context) -> None:
        reason = guard.check(context.auth_context())
        if reason:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, reason)

    class Interceptor(grpc.ServerInterceptor):
        def intercept_service(self, continuation, handler_call_details):
            handler = continuation(handler_call_details)
            if handler is None:
                return None
            if handler.request_streaming and handler.response_streaming:
                def stream_stream(request, context, _inner=handler.stream_stream):
                    verify(context)
                    yield from _inner(request, context)
                return handler._replace(stream_stream=stream_stream)
            if handler.response_streaming:
                def unary_stream(request, context, _inner=handler.unary_stream):
                    verify(context)
                    yield from _inner(request, context)
                return handler._replace(unary_stream=unary_stream)
            if handler.request_streaming:
                def stream_unary(request, context, _inner=handler.stream_unary):
                    verify(context)
                    return _inner(request, context)
                return handler._replace(stream_unary=stream_unary)

            def unary_unary(request, context, _inner=handler.unary_unary):
                verify(context)
                return _inner(request, context)
            return handler._replace(unary_unary=unary_unary)

    return Interceptor()


def build_server(executor, *, options=(), environment: Mapping[str, str] | None = None):
    """``grpc.server`` that checks peer identities whenever server TLS is configured."""
    import grpc

    env = os.environ if environment is None else environment
    interceptors = ()
    if server_credentials_configured(env):
        interceptors = (_guard_interceptor(PeerIdentityGuard.from_environment(env)),)
    return grpc.server(executor, options=options, interceptors=interceptors)


def bind_server(server, host: str, port: int, *, environment: Mapping[str, str] | None = None) -> int:
    """Bind with mutual TLS when configured. Plaintext is allowed on loopback only (or by the internal opt-out)."""
    env = os.environ if environment is None else environment
    credentials = server_credentials(env)
    address = f"{host}:{port}"
    if credentials is not None:
        bound = server.add_secure_port(address, credentials)
    elif is_loopback_host(host):
        bound = server.add_insecure_port(address)
    elif insecure_internal_allowed(env):
        LOGGER.warning("serving plaintext on %s by %s", address, INSECURE_INTERNAL)
        bound = server.add_insecure_port(address)
    else:
        raise ValueError(
            f"Refusing plaintext on non-loopback address {address}: set {SERVER_TLS_CERT}, {SERVER_TLS_KEY} "
            f"and {SERVER_TLS_CLIENT_CA}."
        )
    if bound == 0:
        raise RuntimeError(f"Cannot bind {address}.")
    return bound
