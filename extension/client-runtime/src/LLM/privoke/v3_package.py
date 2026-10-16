"""Maintained binary package transport and native V3 inference for the product."""
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import threading
import uuid

from privoke.v1 import parameters_pb2
from privoke_model.standard_v3 import STANDARD_PINS, ASSETS, admitted_manifest, digest_file, safe_file, verify_package, is_link
from privoke_model.v3_contract import ARCHITECTURE, MAX_BLOB_BYTES

_LOCK = threading.RLock()
_PACKAGES = {}


@dataclass(frozen=True)
class NativeV3Package:
    model_id: str
    version: str
    directory: Path
    manifest: dict

    @property
    def fingerprint(self):
        return self.manifest["blob"]

    @property
    def parameter_count(self):
        return self.manifest["parameter_count"]

    @property
    def metadata(self):
        return {"architecture": ARCHITECTURE, "artifact_checksum": self.version,
                "backbone_sha256": self.manifest["source"]["weights_sha256"],
                "tokenizer_sha256": self.manifest["vocab"]}

    @property
    def cache_key(self):
        return f"{self.model_id}:{self.version}:{self.fingerprint}"


def cache_root():
    configured = os.getenv("MODEL_PACKAGE_CACHE_DIR", "").strip()
    if configured:
        return Path(configured).absolute()
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "PriVoke/model-packages"
    return Path(os.getenv("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "privoke/model-packages"


def private_directory(path):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if is_link(parent):
            raise ValueError("Model cache must not traverse symlinks")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def receive_asset(chunks, outgoing, *, model_id, pin, name, expected_sha, expected_size):
    """Accept one fully bound ordered binary stream; no partial package is loaded."""
    if name not in ASSETS or not 0 < expected_size <= MAX_BLOB_BYTES:
        raise ValueError("Invalid declared model asset")
    offset, digest = 0, hashlib.sha256()
    for chunk in chunks:
        if (chunk.model_id != model_id or chunk.manifest_sha256 != pin or chunk.asset_name != name
                or chunk.sha256 != expected_sha or chunk.offset != offset or chunk.total_bytes != expected_size
                or not 0 < len(chunk.data) <= 1024 * 1024 or offset + len(chunk.data) > expected_size):
            raise ValueError("Model asset stream changed identity, order or bounds")
        outgoing.write(chunk.data)
        digest.update(chunk.data)
        offset += len(chunk.data)
    if offset != expected_size or digest.hexdigest() != expected_sha:
        raise ValueError("Model asset stream is incomplete or corrupted")


def fetch_package(client, request, *, target, timeout):
    package = client.GetModelPackage(request, timeout=timeout)
    if package.architecture != ARCHITECTURE:
        if request.model_id.startswith("privoke-v3-") or package.manifest_json or package.assets:
            raise ValueError("V3 request returned a different model family")
        return None  # Explicit legacy-only server latest override uses the old float RPCs.
    manifest = admitted_manifest(bytes(package.manifest_json), request.model_id)
    model_id, pin = manifest["model_id"], STANDARD_PINS[manifest["model_id"]]
    if package.model_id != model_id or package.manifest_sha256 != pin:
        raise ValueError("Model package response identity differs from admitted manifest")
    descriptors = {asset.name: asset for asset in package.assets}
    if len(package.assets) != len(ASSETS) or set(descriptors) != set(ASSETS):
        raise ValueError("Model package must contain exactly the declared assets")
    for name, asset in descriptors.items():
        if asset.sha256 != manifest[ASSETS[name]] or not 0 < asset.size_bytes <= MAX_BLOB_BYTES:
            raise ValueError("Model package asset declarations differ")
    with _LOCK:
        directory = private_directory(cache_root() / model_id / pin)
        identity = (target, str(directory), pin)
        if identity in _PACKAGES:
            # Refresh only the small manifest. A reloaded model revalidates all assets.
            if digest_file(safe_file(directory, "manifest.json")) != pin:
                raise ValueError("Cached manifest was corrupted")
            return _PACKAGES[identity]
        download_timeout = float(os.getenv("MODEL_PACKAGE_TIMEOUT_SECONDS", "120"))
        if not math.isfinite(download_timeout) or download_timeout <= 0:
            raise ValueError("MODEL_PACKAGE_TIMEOUT_SECONDS must be finite and positive")
        for name, asset in descriptors.items():
            destination = directory / name
            if destination.exists() or is_link(destination):
                if digest_file(safe_file(directory, name)) != asset.sha256:
                    raise ValueError("Existing model cache asset is corrupted")
                continue
            temporary = directory / (".download-" + uuid.uuid4().hex)
            try:
                with temporary.open("xb") as outgoing:
                    receive_asset(client.StreamModelAsset(parameters_pb2.ModelAssetRequest(
                        consumer_id=request.consumer_id, model_id=model_id, manifest_sha256=pin, asset_name=name),
                        timeout=download_timeout), outgoing, model_id=model_id, pin=pin, name=name,
                        expected_sha=asset.sha256, expected_size=asset.size_bytes)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                if destination.exists() or is_link(destination):
                    raise ValueError("Model cache destination appeared during download")
                temporary.rename(destination)
            finally:
                temporary.unlink(missing_ok=True)
        after = client.GetModelPackage(request, timeout=timeout)
        if after.SerializeToString(deterministic=True) != package.SerializeToString(deterministic=True):
            raise ValueError("Model manifest changed while assets were downloaded")
        manifest_path = directory / "manifest.json"
        if manifest_path.exists() or is_link(manifest_path):
            if digest_file(safe_file(directory, "manifest.json")) != pin:
                raise ValueError("Cached model manifest differs")
        else:
            temporary = directory / (".manifest-" + uuid.uuid4().hex)
            try:
                with temporary.open("xb") as stream:
                    stream.write(package.manifest_json)
                    stream.flush()
                    os.fsync(stream.fileno())
                if manifest_path.exists() or is_link(manifest_path):
                    raise ValueError("Model manifest appeared during cache admission")
                temporary.rename(manifest_path)
            finally:
                temporary.unlink(missing_ok=True)
        verify_package(directory, model_id)
        snapshot = NativeV3Package(model_id, pin, directory, manifest)
        _PACKAGES[identity] = snapshot
        return snapshot


class NativeV3PrivacyModel:
    def __init__(self, snapshot):
        from ...v3.model import PretrainedV3
        if os.getenv("PRIVOKE_MODEL_DEVICE", "cpu").lower() not in ("auto", "cpu"):
            raise ValueError("Standard V3 currently supports the verified CPU inference backend")
        self.snapshot = snapshot
        manifest = verify_package(snapshot.directory, snapshot.model_id)
        self.model = PretrainedV3.load(manifest, snapshot.directory / "model.safetensors",
            snapshot.directory / "config.json", snapshot.directory / "vocab.txt", device="cpu")
        self.model.eval()
        for parameter in self.model.parameters():
            parameter.requires_grad_(False)

    def classify(self, text):
        identity = {"model_id": self.snapshot.model_id, "model_version": self.snapshot.version,
                    "artifact_checksum": self.snapshot.version, "parameter_fingerprint": self.snapshot.fingerprint,
                    "architecture": ARCHITECTURE, "parameter_count": str(self.snapshot.parameter_count),
                    "backbone_sha256": self.snapshot.metadata["backbone_sha256"],
                    "tokenizer_sha256": self.snapshot.metadata["tokenizer_sha256"]}
        return self.model.findings(text, identity)
