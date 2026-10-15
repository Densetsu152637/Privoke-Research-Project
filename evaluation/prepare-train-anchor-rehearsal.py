"""Prepare the accepted fixed TRAIN bank without opening any evaluation endpoints."""
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'services/privoke-fuzzer/src', ROOT / 'services/privoke-fuzzer/generated', ROOT / 'shared/python'):
    sys.path.insert(0, str(path))

from prompt_generation.anchor_rehearsal import prepare_manifest, load_snapshot
from prompt_generation.taxonomy_coverage import load_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    dataset = load_dataset(args.dataset)
    payload = prepare_manifest(dataset)
    manifest = load_snapshot(payload, dataset)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never overwrite an already frozen bank, including a conflicting preparation.
    if path.exists():
        if path.read_bytes() != payload:
            raise ValueError('Existing rehearsal manifest differs; refusing overwrite.')
    else:
        with path.open('xb') as stream:
            stream.write(payload)
    print(f'fit_release=false dataset={dataset.sha256} bank={manifest.bank_sha256} manifest={hashlib.sha256(payload).hexdigest()}')


if __name__ == '__main__':
    main()
