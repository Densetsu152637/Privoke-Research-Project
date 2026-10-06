"""Externally committed operator inputs for the two-phase partition publisher."""
from __future__ import annotations
import argparse
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'evaluation'), str(ROOT/'shared/python')]
from privoke_eval import in_house_partition_publication as publication
from privoke_eval import in_house_advpii_review_io as io
from privoke_eval.in_house_review_reconstruction import PublishedPreparationTrust


def committed(path, expected, limit=publication.LIMIT):
    path = Path(path)
    fd, before = io._open_read_nofollow(path)
    try:
        raw = b''
        while len(raw) <= limit:
            chunk = os.read(fd, 1024*1024)
            if not chunk:
                break
            raw += chunk
        if len(raw)>limit or publication.sha(raw)!=expected or publication.identity(before)!=publication.identity(os.fstat(fd)):
            publication.fail()
    finally:
        os.close(fd)
    named = os.lstat(path)
    if publication.identity(named)!=publication.identity(before):
        publication.fail()
    return raw


def run(args):
    value = publication.decode(committed(args.inputs, args.inputs_sha256), args.inputs_sha256)
    publication.closed(value, ('schema_version','phase','cli_raw_sha256','compose_raw_sha256','inputs'))
    if type(value['schema_version']) is not int or value['schema_version']!=1 or value['phase']!=args.phase:
        publication.fail()
    cli_raw = committed(Path(__file__), value['cli_raw_sha256'], io._CODE_LIMIT)
    io._attest_module('publisher_cli', cli_raw, Path(__file__), module_override=sys.modules[__name__])
    committed(ROOT/'evaluation/compose.in-house-publication.yml', value['compose_raw_sha256'], io._CODE_LIMIT)
    inputs = value['inputs']
    if args.phase=='prepare':
        publication.closed(inputs, ('paths','preparation_trust','published_trust','external_trust','output'))
        paths = io.InHouseReviewIOPaths(**{key:Path(path) for key,path in inputs['paths'].items()})
        result = publication.prepare_partitions(paths,
            preparation_trust=io.InHousePreparationTrust(**inputs['preparation_trust']),
            published_trust=PublishedPreparationTrust(**inputs['published_trust']), external_trust=inputs['external_trust'],
            source_root=ROOT, output=Path(inputs['output']))
        return {'phase':'prepare','status':'complete','prepared_manifest_raw_sha256':result['prepared_manifest_raw_sha256']}
    if args.phase=='publish':
        publication.closed(inputs, ('prepared','prepared_manifest_raw_sha256','programme','external_trust',
                                   'destinations','metadata_output','sealed_metadata_output'))
        publication.closed(inputs['programme'], ('file','sha256'))
        programme_raw=committed(inputs['programme']['file'], inputs['programme']['sha256'])
        result=publication.publish_flat_views(Path(inputs['prepared']),
            expected_prepared_raw_sha256=inputs['prepared_manifest_raw_sha256'],programme_input_bytes=programme_raw,
            expected_programme_input_raw_sha256=inputs['programme']['sha256'],external_trust=inputs['external_trust'],
            source_root=ROOT,destinations=inputs['destinations'],metadata_output=inputs['metadata_output'],
            sealed_metadata_output=inputs['sealed_metadata_output'])
        return {'phase':'publish','status':result['status'],'publication_receipt_raw_sha256':publication.sha(publication.canonical(result))}
    publication.closed(inputs, ('train_raw_sha256','training_view_manifest_raw_sha256','source_hashes'))
    publication.attest(ROOT, inputs['source_hashes'])
    return publication.verify_train_reader(Path('/train'),expected_train_sha256=inputs['train_raw_sha256'],
        expected_manifest_sha256=inputs['training_view_manifest_raw_sha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('prepare','publish','verify-train'))
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--inputs-sha256', required=True)
    args=parser.parse_args()
    try:
        print(publication.canonical(run(args)).decode('ascii'))
        return 0
    except Exception:
        print('Partition publication failed validation.',file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
