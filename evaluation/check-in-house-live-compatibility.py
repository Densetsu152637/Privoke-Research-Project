"""Root-operated compatibility CLI; no serving-service lifecycle operations."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT/'evaluation', ROOT/'shared/python', ROOT/'extension/client-runtime',
             ROOT/'extension/client-runtime/generated', ROOT/'models'):
    sys.path.insert(0, str(path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='mode', required=True)
    helper = commands.add_parser('helper')
    helper.add_argument('--request', required=True)
    helper.add_argument('--request-sha256', required=True)
    source = commands.add_parser('source-preflight')
    source.add_argument('--spec', required=True)
    source.add_argument('--spec-sha256', required=True)
    source.add_argument('--output', required=True)
    source_helper = commands.add_parser('source-helper')
    source_helper.add_argument('--request', required=True)
    source_helper.add_argument('--request-sha256', required=True)
    for mode in ('run', 'accept'):
        sub = commands.add_parser(mode)
        sub.add_argument('--commitments', required=True)
        sub.add_argument('--commitments-sha256', required=True)
        sub.add_argument('--output', required=True)
        if mode == 'accept':
            sub.add_argument('--candidate', required=True)
            sub.add_argument('--candidate-sha256', required=True)
            sub.add_argument('--root-acceptance', required=True)
            sub.add_argument('--root-acceptance-sha256', required=True)
    args = parser.parse_args()
    exit_code=0
    try:
        from privoke_eval import in_house_live_compatibility as producer
        from privoke_eval import in_house_study_controller as controller
        if args.mode in ('helper', 'source-helper'):
            if args.request != '/request.json':
                producer.fail()
            request = controller.json_reference({'file': args.request, 'sha256': args.request_sha256})
            result = producer.source_helper(request) if args.mode == 'source-helper' else producer.helper(request)
            producer.verify_source_closure(request['source_files'],root=ROOT)
        elif args.mode == 'source-preflight':
            spec = producer.validate_source_spec(controller.json_reference({'file': args.spec, 'sha256': args.spec_sha256}), root=ROOT)
            output = producer.fresh_metadata_output(args.output)
            backend = producer.CompatibilityBackend(output, spec, root=ROOT)
            ref = producer.produce_source_preflight(spec, backend, output)
            result = {'status': 'source_preflight_candidate', 'source_preflight_sha256': ref['sha256']}
        else:
            reference = {'file': args.commitments, 'sha256': args.commitments_sha256}
            commitments = producer.validate_commitments(controller.json_reference(reference), root=ROOT)
            output = producer.fresh_metadata_output(args.output)
            backend = producer.CompatibilityBackend(output, commitments, root=ROOT)
            if args.mode == 'run':
                ref = producer.run_producer(commitments, backend, output, commitments_reference=reference)
                candidate = controller.json_reference(ref)
                exit_code=0 if candidate['status']=='candidate' else 1
                result = {'status': candidate['status'], 'candidate_sha256': ref['sha256'],
                          'restoration_complete': candidate['restoration']['complete']}
            else:
                ref = producer.accept_candidate({'file': args.candidate, 'sha256': args.candidate_sha256},
                    commitments, backend, {'file': args.root_acceptance, 'sha256': args.root_acceptance_sha256}, output)
                result = {'status': 'root_accepted', 'compatibility_sha256': ref['sha256']}
        print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)
        return exit_code
    except Exception:
        print('{"status":"failed","error_code":"compatibility_rejected"}', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())