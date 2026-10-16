"""Pinned standard AU3 inference releases; legacy Tiny contracts stay separate."""
from pathlib import Path
import hashlib
import stat
from .v3_contract import ARCHITECTURE, MAX_BLOB_BYTES, MAX_MANIFEST_BYTES, parse, validate_manifest

STANDARD_LATEST = "privoke-v3-balanced"
STANDARD_PINS = {
    "privoke-v3-efficient": "1f45a21bd7bd0c931dad215f823008193e7af7359bc68527c1f5dd4e7fbbeffd",
    "privoke-v3-balanced": "99b36171056bb0398584a0b0556d9d7ff2640d0acac4b124a126327451a80589",
    "privoke-v3-quality": "bb17d355fe1ad13c7052e922fb6de607d82cdafb1f4440fee1a47f35d42caf39",
}
ASSETS = {"model.safetensors": "blob", "config.json": "config", "vocab.txt": "vocab", "evidence.json": "evidence"}


def is_link(path):
    """Reject symlinks and Windows junction/reparse points, including broken ones."""
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_file(root, name):
    """Only fixed package names beneath a regular non-symlink directory."""
    root = Path(root).absolute()
    if name not in {"manifest.json", *ASSETS}:
        raise ValueError("Unrecognized model package asset")
    for parent in (root, *root.parents):
        if is_link(parent):
            raise ValueError("Model package directories must not be symlinks")
    path = root / name
    if is_link(path) or not path.is_file():
        raise ValueError("Model asset must be a regular non-symlink file")
    return path


def admitted_manifest(payload, model_id=None):
    manifest = validate_manifest(parse(payload, MAX_MANIFEST_BYTES))
    expected = STANDARD_PINS.get(manifest["model_id"])
    if expected is None or hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError("Model is not a pinned standard AU3 release")
    if model_id and model_id not in ("latest", manifest["model_id"]):
        raise ValueError("Model package identity differs from request")
    return manifest


def verify_package(directory, model_id=None):
    manifest = admitted_manifest(safe_file(directory, "manifest.json").read_bytes(), model_id)
    for name, key in ASSETS.items():
        path = safe_file(directory, name)
        if not 0 < path.stat().st_size <= MAX_BLOB_BYTES or digest_file(path) != manifest[key]:
            raise ValueError("Model package asset size/hash differs from pinned manifest")
    return manifest
