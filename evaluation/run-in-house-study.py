"""Root-operated fixed eight-arm study. No implicit inputs or dry-run success."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'shared/python'))
from privoke_eval import in_house_study_controller as controller
from privoke_eval import in_house_study_evidence as evidence


def main(argv=None):
    if '--private-helper' in (sys.argv[1:] if argv is None else argv):
        parser = argparse.ArgumentParser(description='Restricted metadata-only private-volume helper.')
        parser.add_argument('--private-helper', action='store_true', required=True)
        parser.add_argument('--request', required=True, type=Path)
        parser.add_argument('--request-sha256', required=True)
        parser.add_argument('--controller-sha256', required=True)
        parser.add_argument('--cli-sha256', required=True)
        args = parser.parse_args(argv)
        try:
            evidence._attest_module(controller, args.controller_sha256)
            evidence._attest_module(sys.modules[__name__], args.cli_sha256)
            request = controller.json_reference({'file': str(args.request), 'sha256': args.request_sha256})
            result = controller.private_helper(request)
            print(evidence.canonical(result).decode('utf8'))
            return 0
        except Exception:
            print('Private metadata helper failed; restricted evidence retained.', file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--test-release', type=Path, required=True,
                        help='Opaque release-file locator; not opened before authenticated barrier.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = controller.run_study(inputs_file=args.inputs, inputs_sha256=args.inputs_sha256,
                           test_release_file=args.test_release, output=args.output)
    except Exception:
        print('Fixed study preflight or lifecycle failed; no result or test authority conferred.', file=sys.stderr)
        return 1
    print('Fixed study '+result['status']+'; restoration_verified='+str(result['restoration_verified']).lower())
    return 0 if result['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
