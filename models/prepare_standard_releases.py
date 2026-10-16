"""Copy existing selected AU3 packages to a verified, ignored distribution store.

No model construction, weight initialization, fitting, dataset reads or publication.
"""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
from privoke_model.standard_v3 import STANDARD_PINS, STANDARD_LATEST, ASSETS, verify_package, digest_file, is_link


def prepare(source_root, destination):
    destination = Path(destination).absolute()
    for parent in (destination, *destination.parents):
        if is_link(parent):
            raise ValueError("Release destination must not traverse symlinks")
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for model_id, pin in STANDARD_PINS.items():
        source = Path(source_root) / model_id.removeprefix("privoke-v3-") / "selected"
        verify_package(source, model_id)
        target = destination / model_id
        if target.exists():
            verify_package(target, model_id)
        else:
            target.mkdir()
            try:
                for name in ("manifest.json", *ASSETS):
                    with (source / name).open("rb") as incoming, (target / name).open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                verify_package(target, model_id)
            except Exception:
                # Preserve an incomplete package for diagnosis; never activate it.
                raise
        records.append({"model_id": model_id, "manifest_sha256": pin,
                        "source": str(source.resolve()), "source_files": {name: digest_file(source / name) for name in ("manifest.json", *ASSETS)}})
    receipt = {"schema": 1, "latest": STANDARD_LATEST, "publication": "local_read_only_inference_distribution",
               "records": records}
    receipt_path = destination / "preparation.json"
    if is_link(receipt_path):
        raise ValueError("Distribution provenance must not be a link")
    if receipt_path.exists():
        if json.loads(receipt_path.read_text()) != receipt:
            raise ValueError("Existing distribution provenance differs; use a fresh destination")
    else:
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT / "models/experiments/audience_v3_20261013/runs/cpu-02/exports")
    parser.add_argument("--destination", type=Path, default=ROOT / "models/standard-releases")
    args = parser.parse_args()
    print(json.dumps(prepare(args.source_root, args.destination), indent=2))
