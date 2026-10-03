"""Preserve local research evidence without publishing raw benchmark examples."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.name):
        parser.error("Use a 1-64 character artifact identifier starting with a letter or digit.")
    destination = ROOT / "evaluation/artifacts" / (args.name + ".zip")
    if destination.exists() or args.manifest.exists():
        raise SystemExit("Refusing to overwrite an artifact or its external manifest.")
    git = ["git", "-c", f"safe.directory={ROOT.as_posix()}"]
    revision = subprocess.check_output(git + ["rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source = subprocess.check_output(git + ["archive", "--format=tar", revision], cwd=ROOT)
    paths = sorted(path for path in (ROOT / "evaluation/results").rglob("*")
                   if path.is_file() and path.suffix != ".base64")
    paths += sorted((ROOT / "evaluation").glob("*.log"))
    paths += sorted(path for path in (ROOT / "paper/research").glob("*")
                    if path.is_file() and path.resolve() != args.manifest.resolve())
    records = []
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("source.tar", source)
        records.append({"path": "source.tar", "bytes": len(source),
                        "sha256": hashlib.sha256(source).hexdigest()})
        for path in paths:
            if not path.resolve().is_relative_to(ROOT):
                raise SystemExit("Evidence path resolves outside the workspace.")
            content = path.read_bytes()
            name = path.relative_to(ROOT).as_posix()
            archive.writestr(name, content)
            records.append({"path": name, "bytes": len(content),
                            "sha256": hashlib.sha256(content).hexdigest()})
        manifest = {"source_revision": revision,
                    "scope": "Local evidence; no permission to redistribute raw dataset examples implied",
                    "source_overlay": "paper/research files are preserved separately from committed source.tar",
                    "files": records}
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))
    content = archive_bytes.getvalue()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as output:
        output.write(content)
    manifest.update({"archive": destination.relative_to(ROOT).as_posix(),
                     "archive_bytes": len(content), "archive_sha256": hashlib.sha256(content).hexdigest()})
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("x", encoding="utf-8") as output:
        output.write(json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise SystemExit("Archive failed its integrity check.")
        for record in records:
            if hashlib.sha256(archive.read(record["path"])).hexdigest() != record["sha256"]:
                raise SystemExit("Archived file hash differs from its manifest.")
    print(json.dumps({key: manifest[key] for key in
                     ("source_revision", "archive", "archive_bytes", "archive_sha256")}))


if __name__ == "__main__":
    main()
