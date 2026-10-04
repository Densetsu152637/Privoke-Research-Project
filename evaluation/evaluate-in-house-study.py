"""Evaluation-only collector/offline consumer. No catalogue or training operations.

The controller supplies one externally SHA-pinned closed trust bundle per phase.
All paths are explicit local inputs; earlier bundles cannot contain test inputs.
This CLI never treats a summary report as authenticated raw evidence.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'shared/python'))
generated = Path('/workspace/extension/client-runtime/generated')
if generated.is_dir():
    sys.path.insert(0, str(generated))

from privoke_eval import in_house_study_evidence as evidence
from privoke_eval import in_house_study_analysis as analysis
from privoke_eval import in_house_study_contract as contract

PHASES = (*evidence.PHASES, 'select-validation', 'pretest-barrier', 'analyze-test')


def _input(reference, limit=evidence.MAX_INPUT_BYTES):
    evidence.closed(reference, ('file', 'sha256'))
    return evidence.read_committed(reference['file'], reference['sha256'], limit)


def load_collection(reference):
    evidence.closed(reference, ('binding', 'directory', 'inventory_sha256', 'dataset_file', 'contextual_artifact', 'presence_artifact'))
    binding = evidence.CollectionBinding(**reference['binding'])
    evidence._attest_module(sys.modules[__name__], binding.source_hashes['caller'])
    evidence.attest_sources(binding)
    directory = Path(reference['directory'])
    if directory.is_symlink() or any(p.is_symlink() for p in directory.parents):
        evidence.fail()
    raw = evidence.read_committed(directory / 'inventory.json', reference['inventory_sha256'])
    inventory = evidence.checked_json(raw, reference['inventory_sha256'])
    if type(inventory.get('files')) is not list:
        evidence.fail()
    names = [item['file'] for item in inventory['files']]
    if (len(set(names)) != len(names) or any(type(name) is not str or not name.startswith('rpc-') or '/' in name or '\\' in name for name in names)
            or {p.name for p in directory.iterdir()} != set(names) | {'inventory.json'}):
        evidence.fail()
    frames = {item['file']: evidence.read_committed(directory / item['file'], item['sha256'], evidence.MAX_FRAME_BYTES * 3)
              for item in inventory['files']}
    return evidence.verify_raw_collection(raw, inventory_sha256=reference['inventory_sha256'], trusted_phase_binding=binding,
             captured_dataset=evidence.read_committed(reference['dataset_file'], binding.dataset_sha256),
             captured_artifacts={'contextual': evidence.read_committed(reference['contextual_artifact'], binding.contextual_identity['artifact_sha256'], evidence.MAX_FRAME_BYTES),
                                 'presence': evidence.read_committed(reference['presence_artifact'], binding.presence_identity['artifact_sha256'], evidence.MAX_FRAME_BYTES)},
             raw_files=frames)


def _load_set(references, phase):
    if type(references) is not list:
        evidence.fail()
    # Check declared phase BEFORE opening any referenced dataset (test isolation).
    if any(reference.get('binding', {}).get('phase') != phase for reference in references):
        evidence.fail()
    return [load_collection(reference) for reference in references]


def barrier_inputs(value):
    evidence.closed(value, ('programme', 'checkpoints', 'live', 'fixtures', 'selection', 'fit_inventory'))
    programme = contract.freeze_programme(evidence.checked_json(_input(value['programme']), value['programme']['sha256']))
    checkpoints = _load_set(value['checkpoints'], 'collect-validation')
    live = _load_set(value['live'], 'rerun-validation')
    fixtures = _load_set(value['fixtures'], 'collect-fixtures')
    selection_raw = _input(value['selection'])
    if any(c.binding.selection_sha256 != value['selection']['sha256'] for c in (*live, *fixtures)):
        evidence.fail()
    return evidence.derive_barrier_records(programme, checkpoints, selection_raw, live, fixtures,
             _input(value['fit_inventory']), trusted_fit_inventory_sha256=value['fit_inventory']['sha256'],
             trusted_selection_sha256=value['selection']['sha256'])


def run(args):
    # Only an operator-supplied digest can authorize decoding a trust bundle.
    raw = evidence.read_committed(args.trust_bundle, args.trust_bundle_sha256)
    trust = evidence.checked_json(raw, args.trust_bundle_sha256)
    evidence.closed(trust, ('schema_version', 'phase', 'inputs'))
    if type(trust['schema_version']) is not int or trust['schema_version'] != 1 or trust['phase'] != args.phase:
        evidence.fail()
    value = trust['inputs']
    output = Path(args.output)
    try:
        output.resolve().relative_to((ROOT / 'evaluation/results').resolve())
    except ValueError:
        evidence.fail()
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        evidence.fail()
    result = None
    if args.phase in evidence.PHASES:
        keys = {'binding', 'dataset_file', 'contextual_artifact', 'presence_artifact'}
        if args.phase != 'collect-validation':
            keys.add('selection')
        if args.phase == 'collect-test':
            keys.update(('barrier_inputs', 'barrier_receipt'))
        evidence.closed(value, keys)
        binding = evidence.CollectionBinding(**value['binding'])
        if binding.phase != args.phase:
            evidence.fail()
        evidence._attest_module(sys.modules[__name__], binding.source_hashes['caller'])
        evidence.attest_sources(binding)
        if args.phase != 'collect-validation':
            evidence.require_selected(binding, _input(value['selection']))
            if value['selection']['sha256'] != binding.selection_sha256:
                evidence.fail()
        if args.phase == 'collect-test':
            _, _, recomputed = barrier_inputs(value['barrier_inputs'])
            receipt_raw = _input(value['barrier_receipt'])
            if (value['barrier_receipt']['sha256'] != binding.barrier_sha256
                    or evidence.checked_json(receipt_raw, binding.barrier_sha256) != recomputed
                    or recomputed['programme_sha256'] != binding.programme_sha256):
                evidence.fail()
            evidence.require_test_binding(binding, pretest_receipt=recomputed,
                                          selection_raw_sha256=value['selection']['sha256'])
        # Test data is opened only AFTER the full authenticated barrier above.
        dataset = evidence.read_committed(value['dataset_file'], binding.dataset_sha256)
        rows = evidence.dataset_rows(dataset, binding)
        artifacts = {'contextual': evidence.read_committed(value['contextual_artifact'], binding.contextual_identity['artifact_sha256'], evidence.MAX_FRAME_BYTES),
                     'presence': evidence.read_committed(value['presence_artifact'], binding.presence_identity['artifact_sha256'], evidence.MAX_FRAME_BYTES)}
        evidence.artifact_identity(artifacts['contextual'], binding.contextual_identity)
        presence = evidence.artifact_identity(artifacts['presence'], binding.presence_identity)
        if presence['config']['threshold'] != binding.model_threshold:
            evidence.fail()
        writer = evidence.PrivateWriter(args.output)
        client = None
        try:
            client = evidence.RuntimeClient(args.target)
            evidence.collect_rows(client, binding, rows, writer)
        finally:
            if client is not None:
                client.close()
            writer.close()
        return
    if args.phase == 'select-validation':
        evidence.closed(value, ('checkpoints',))
        result = analysis.select_joint_validation(evidence.make_joint_validation_input(_load_set(value['checkpoints'], 'collect-validation')))
    elif args.phase == 'pretest-barrier':
        records, references, receipt = barrier_inputs(value)
        result = {'records': records, 'trusted_claim_references': references, 'receipt': receipt, 'test_authorized': False}
    elif args.phase == 'analyze-test':
        evidence.closed(value, ('barrier_inputs', 'barrier_receipt', 'test', 'selection'))
        _, _, receipt = barrier_inputs(value['barrier_inputs'])
        if evidence.checked_json(_input(value['barrier_receipt']), value['barrier_receipt']['sha256']) != receipt:
            evidence.fail()
        if type(value['test']) is not list:
            evidence.fail()
        selection_raw = _input(value['selection'])
        # Check every declared test binding before any test raw collection/data is opened.
        for reference in value['test']:
            binding = evidence.CollectionBinding(**reference['binding'])
            if binding.barrier_sha256 != value['barrier_receipt']['sha256']:
                evidence.fail()
            evidence.require_test_binding(binding, pretest_receipt=receipt,
                                          selection_raw_sha256=value['selection']['sha256'])
            evidence.require_selected(binding, selection_raw)
        collections = _load_set(value['test'], 'collect-test')
        for collection in collections:
            if collection.binding.barrier_sha256 != value['barrier_receipt']['sha256']:
                evidence.fail()
            evidence.require_selected(collection.binding, _input(value['selection']))
        result = analysis.analyze_paired_endpoint(evidence.endpoint_input(collections))
    else:
        evidence.fail()
    writer = evidence.PrivateWriter(args.output)
    try:
        if args.phase == 'pretest-barrier':
            writer.write('receipt.json', evidence.canonical(result['receipt']))
            writer.write('records.json', evidence.canonical(result['records']))
            writer.write('claim-references.json', evidence.canonical(result['trusted_claim_references']))
        writer.write('result.json', evidence.canonical(result))
    finally:
        writer.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--trust-bundle', type=Path, required=True)
    parser.add_argument('--trust-bundle-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', default='client-runtime:50054')
    args = parser.parse_args(argv)
    try:
        run(args)
    except Exception:
        print('In-house evidence phase failed; no test authority or publication conferred.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
