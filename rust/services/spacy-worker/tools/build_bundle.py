"""Build the spaCy bundle: relocatable CPython 3.11, the hash-locked site-packages and the privoke-spacy-worker binary.

    python build_bundle.py --out <dir> --build-python <python 3.11 with headers and libs> --model-installed <site-packages>

The result is a directory that runs with no system Python on PATH:

    <out>/privoke-spacy-worker.exe     the worker (PyO3 links python311.dll beside it)
    <out>/python311.dll, python311.zip, *.pyd, vcruntime*.dll   the python.org embeddable CPython, unchanged
    <out>/python311._pth               makes CPython ignore the user's environment and use only the bundle
    <out>/Lib/site-packages            every package in bundle.lock.txt, installed from hash-checked wheels
    <out>/bundle.lock.txt              the lock the worker compares itself against at every start
    <out>/licenses                     the LICENSE files of spaCy, thinc and the model, and LICENSES_SOURCES

The build fails if a license file is missing, if a download does not match the recorded hash, or if the finished bundle
does not pass its own start-up check. The Linux bundle is not built here (see the stage 11 plan: CI/Linux stage).

The model wheel is not on PyPI (only on the model's GitHub release), and this build fetches from python.org and PyPI only.
`--model-wheel` takes the release wheel and checks its SHA-256 against the lock. `--model-installed` takes the
site-packages of an environment that already has the model installed (read-only) and copies exactly the files listed in
its RECORD after checking every file's hash, so the bundle contains the model's files unchanged.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKER_DIR = HERE.parent
LOCK = WORKER_DIR / "bundle.lock.txt"
RUST_DIR = WORKER_DIR.parent.parent
IMPL = WORKER_DIR / "python" / "privoke_spacy_impl.py"
MODEL = "en_core_web_sm"
REQUIRED_LICENSES = {
    "spacy": ("spacy-3.7.5.dist-info", ["LICENSE"]),
    "thinc": ("thinc-8.2.5.dist-info", ["LICENSE"]),
    "en_core_web_sm": ("en_core_web_sm-3.7.1.dist-info", ["LICENSE", "LICENSES_SOURCES"]),
}


def die(message: str) -> "None":
    raise SystemExit(f"build_bundle: {message}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lock_header(text: str) -> dict[str, str]:
    return dict(re.findall(r"^# privoke-lock: ([a-z0-9._-]+) = (.*)$", text, flags=re.M))


def download(url: str, destination: Path, sha256: str) -> None:
    if destination.exists() and sha256_file(destination) == sha256:
        return
    if not re.match(r"^https://(www\.python\.org|files\.pythonhosted\.org)/", url):
        die(f"refusing to download from {url}: only python.org and PyPI are allowed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=120) as response, open(destination, "wb") as out:
        shutil.copyfileobj(response, out)
    if sha256_file(destination) != sha256:
        destination.unlink()
        die(f"{url} does not match the locked SHA-256 {sha256}")


def pip_requirements(lock_text: str) -> str:
    """The lock without the model's URL requirement (it is installed separately and verified by hash)."""
    blocks = re.split(r"\n(?=\S)", lock_text.strip())
    kept = [b for b in blocks if b.startswith("#") or not re.match(r"^en[-_]core[-_]web[-_]sm\s*@", b)]
    return "\n".join(kept) + "\n"


def record_hash(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def install_model_from_installed(site_packages: Path, target: Path) -> None:
    """Copies the model's files listed in its RECORD, after checking each file's hash."""
    dist_info = next(site_packages.glob(f"{MODEL}-*.dist-info"), None)
    if dist_info is None:
        die(f"{site_packages} has no installed {MODEL}")
    copied = 0
    with open(dist_info / "RECORD", newline="", encoding="utf-8") as handle:
        for name, hash_field, _size in csv.reader(handle):
            if "__pycache__" in name or name.endswith((".pyc", "INSTALLER", "REQUESTED", "direct_url.json", "RECORD")):
                continue
            source = (site_packages / name).resolve()
            if not str(source).startswith(str(site_packages.resolve())):
                die(f"RECORD entry {name} leaves the site-packages directory")
            algorithm, _, expected = hash_field.partition("=")
            if algorithm != "sha256" or record_hash(source) != expected:
                die(f"{name} does not match the model's RECORD hash")
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied += 1
    (target / dist_info.name / "INSTALLER").write_text("privoke-bundle\n")
    print(f"model: copied {copied} files from {dist_info.name}, each checked against its RECORD hash")


def install_model_from_wheel(wheel: Path, target: Path, locked_sha256: str) -> None:
    if sha256_file(wheel) != locked_sha256:
        die(f"{wheel} does not match the locked model wheel hash {locked_sha256}")
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(target)
    print(f"model: extracted {wheel.name} (SHA-256 matches the lock)")


def run(cmd: list[str], **kwargs) -> None:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def bundle_python_probe(out: Path) -> tuple[str, str]:
    """Runs the bundle's own interpreter to read the CPython build identity and the BLIS dispatch target."""
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import privoke_spacy_impl as m; "
        "print(m.cpython_identity()); print(m.blis_target())"
    )
    probe = out / "probe"
    probe.mkdir(exist_ok=True)
    shutil.copy2(IMPL, probe / "privoke_spacy_impl.py")
    result = subprocess.run([str(out / "python.exe"), "-c", code, str(probe)], capture_output=True, text=True, check=True)
    shutil.rmtree(probe)
    lines = result.stdout.strip().splitlines()
    return lines[-2], lines[-1]


def record_identity(identity: str, blis: str) -> None:
    text = LOCK.read_text(encoding="utf-8")
    for key, value in (("cpython-build.windows-x86_64", identity), ("blis-target.windows-x86_64", blis)):
        line = f"# privoke-lock: {key} = {value}"
        if re.search(rf"^# privoke-lock: {re.escape(key)} = ", text, flags=re.M):
            text = re.sub(rf"^# privoke-lock: {re.escape(key)} = .*$", lambda _m: line, text, flags=re.M)
        else:
            text = text.replace("\n\n", f"\n{line}\n\n", 1)
    LOCK.write_text(text, encoding="utf-8", newline="\n")
    print(f"recorded identity in {LOCK.name}: {identity} | blis {blis}")


def self_check(out: Path) -> dict:
    """Starts the worker with no Python on PATH and reads its ready frame."""
    env = {"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"), "PATH": os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")}
    proc = subprocess.Popen([str(out / "privoke-spacy-worker.exe")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    try:
        header = proc.stdout.read(4)
        if len(header) < 4:
            die(f"the worker exited before its first frame (exit code {proc.wait()}); see stderr above")
        payload = proc.stdout.read(struct.unpack("<I", header)[0])
        frame = json.loads(payload)
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    if frame.get("type") != "ready":
        die(f"the worker refused the bundle: {frame.get('reason')}")
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-python", type=Path, required=True, help="CPython 3.11 with headers and libs, used by PyO3 to link")
    parser.add_argument("--model-installed", type=Path, help="site-packages that has the model installed (read-only)")
    parser.add_argument("--model-wheel", type=Path, help="the en_core_web_sm wheel (checked against the lock)")
    parser.add_argument("--cache", type=Path, default=RUST_DIR / "target" / "bundle-cache")
    parser.add_argument("--debug", action="store_true", help="build the worker in debug mode")
    parser.add_argument("--test-hooks", action="store_true", help="build the worker with its test hooks (never ship)")
    parser.add_argument("--record-identity", action="store_true", help="write the bundle's CPython build and BLIS target into the lock")
    args = parser.parse_args()

    if sys.platform != "win32":
        die("only the Windows bundle is built by this script; the Linux bundle belongs to the CI/Linux stage")
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        die(f"{out} is not empty")
    lock_text = LOCK.read_text(encoding="utf-8")
    header = lock_header(lock_text)

    # 1. The CPython runtime, from python.org, by hash.
    archive = args.cache / Path(header["cpython-distribution-url.windows-x86_64"]).name
    download(header["cpython-distribution-url.windows-x86_64"], archive, header["cpython-distribution-sha256.windows-x86_64"])
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zipped:
        zipped.extractall(out)
    stem = f"python{header['cpython-version'].split('.')[0]}{header['cpython-version'].split('.')[1]}"
    (out / f"{stem}._pth").write_text(f"{stem}.zip\n.\nLib\\site-packages\n", encoding="ascii")
    site = out / "Lib" / "site-packages"
    site.mkdir(parents=True)

    # 2. Every locked package, from hash-checked wheels. No dependency resolution: the lock is the complete set.
    requirements = args.cache / "pip-requirements.txt"
    requirements.write_text(pip_requirements(lock_text), encoding="utf-8", newline="\n")
    run(
        [
            sys.executable, "-m", "pip", "install", "--require-hashes", "--no-deps", "--only-binary=:all:", "--no-compile",
            "--disable-pip-version-check", "--target", str(site), "--platform", "win_amd64", "--python-version", "3.11",
            "--implementation", "cp", "--abi", "cp311", "--abi", "abi3", "--abi", "none", "-r", str(requirements),
        ]
    )  # fmt: skip
    shutil.rmtree(site / "bin", ignore_errors=True)

    # 3. The model.
    model_hash = re.search(r"en[-_]core[-_]web[-_]sm\s*@\s*\S+\s*\\?\s*--hash=sha256:([0-9a-f]{64})", lock_text).group(1)
    if args.model_wheel:
        install_model_from_wheel(args.model_wheel, site, model_hash)
    elif args.model_installed:
        install_model_from_installed(args.model_installed, site)
    else:
        die("give --model-wheel or --model-installed: the model is not on PyPI")

    # 4. Licenses: the build fails if any is missing.
    licenses = out / "licenses"
    for package, (dist_info, files) in REQUIRED_LICENSES.items():
        for name in files:
            source = site / dist_info / name
            if not source.is_file():
                die(f"missing license file {source}")
            (licenses / package).mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, licenses / package / name)
    meta = json.loads((site / MODEL / "meta.json").read_text(encoding="utf-8"))
    if meta.get("license") != "MIT":
        die(f"the model's meta.json declares {meta.get('license')!r}, expected MIT")
    shutil.copy2(site / MODEL / "meta.json", licenses / MODEL / "meta.json")

    # 5. The worker. PyO3 links python311.lib from --build-python; at run time it loads python311.dll from the bundle.
    env = dict(os.environ, PYO3_PYTHON=str(args.build_python))
    features = "embed,test-hooks" if args.test_hooks else "embed"
    cargo = ["cargo", "build", "--locked", "-p", "privoke-spacy-worker", "--features", features, "--manifest-path", str(RUST_DIR / "Cargo.toml")]
    if not args.debug:
        cargo.append("--release")
    run(cargo, env=env)
    profile = "debug" if args.debug else "release"
    shutil.copy2(RUST_DIR / "target" / profile / "privoke-spacy-worker.exe", out / "privoke-spacy-worker.exe")

    # 6. The lock, copied byte for byte (the worker hashes this copy).
    if args.record_identity:
        identity, blis = bundle_python_probe(out)
        record_identity(identity, blis)
    shutil.copy2(LOCK, out / "bundle.lock.txt")
    if (out / "bundle.lock.txt").read_bytes() != LOCK.read_bytes():
        die("the lock copy differs from the source")

    # 7. The bundle must pass its own check with no Python on PATH.
    ready = self_check(out)
    print("bundle ready:", json.dumps(ready))


if __name__ == "__main__":
    main()
