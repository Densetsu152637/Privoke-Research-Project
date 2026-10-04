"""Synthetic boundaries; generated-wire tests are mandatory in the Linux image."""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
from types import FunctionType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'evaluation'))
sys.path.insert(0, str(ROOT / 'shared/python'))
sys.path.insert(0, str(Path(__file__).parent))
from privoke_eval import in_house_study_evidence as e
from privoke_eval import in_house_study_analysis as a
from privoke_eval import in_house_study_contract as c
import test_in_house_study_analysis as analysis_fixtures
import test_in_house_study_contract as contract_fixtures


def binding(arm='S0', epoch=0, phase='collect-validation', rows=None, **changes):
    context = contract_fixtures.programme_input()['original_contextual']
    identity = analysis_fixtures.identity(arm if arm in c.ARM_KEYS else 'S0', epoch)
    row_values = rows or [{'id': str(i), 'group_id': str(i), 'text': 'synthetic', 'expected_has_pii': i < 1000} for i in range(2000)]
    raw = b'\n'.join(e.canonical(row) for row in row_values) + b'\n'
    keys = [{'row_id_sha256': e.opaque('row', row['id']), 'group_id_sha256': e.opaque('group', row['group_id']), 'truth': row['expected_has_pii']} for row in row_values]
    value = dict(programme_sha256='a' * 64, control_binding_sha256='b' * 64, phase=phase, arm=arm, epoch=epoch,
                 contextual_identity=context, presence_identity=identity, decision_threshold=0.0, model_threshold=.5,
                 dataset_sha256=e.sha(raw), dataset_rows=48 if phase == 'collect-fixtures' else 2000,
                 dataset_keys_sha256=e.digest(keys), source_revision='a' * 40,
                 source_hashes={key: 'c' * 64 for key in e.SOURCE_ROLES},
                 operational_hashes={key: 'd' * 64 for key in ('runtime_image', 'evaluator_image', 'effective_configuration', 'protocol', 'fixture_rubric', 'fixture_review')},
                 run_nonce='synthetic-run-0001', selection_sha256=None if phase == 'collect-validation' else 'e' * 64,
                 barrier_sha256='f' * 64 if phase == 'collect-test' else None)
    value['operational_hashes']['protocol'] = dict(c.PIN_ITEMS)['protocol']
    value.update(changes)
    return e.CollectionBinding(**value), raw


def response(gated=False, block=False):
    result = {'request_id': 'synthetic', 'action': 'BLOCK' if block else 'ALLOW', 'allowed': not block,
              'masked_text': 'synthetic', 'classification': {'sensitivity': 'S0', 'visibility': 'PU', 'categories': []},
              'error': '', 'layers': []}
    for name in ('REGEX', 'NER', 'SEMANTIC'):
        skipped = block and name != 'REGEX'
        result['layers'].append({'layer': 'DETECTION_LAYER_' + name, 'status': 'skipped' if skipped else 'ok',
                                 'error': a.REGEX_BLOCK_REASON if skipped else '', 'results': []})
    if gated:
        b, _ = binding()
        gate = {'status': 'SEMANTIC_PRESENCE_GATE_STATUS_NOT_RUN' if block else 'SEMANTIC_PRESENCE_GATE_STATUS_APPLIED',
                'model_id': b.presence_identity['model_id'], 'decision_threshold': 0.0,
                'predicted_label': 'ANNOTATION_PRESENCE_UNSPECIFIED' if block else 'ANNOTATION_PRESENCE_PRESENT',
                'error': a.REGEX_BLOCK_REASON if block else '', 'semantic_results': []}
        if not block:
            gate.update(probability=0.0, model_threshold=.5)
            for prefix, identity in (('', b.presence_identity), ('contextual_', b.contextual_identity)):
                for field, key in (('model_id', 'model_id'), ('model_version', 'version'), ('artifact_checksum', 'artifact_checksum'), ('parameter_fingerprint', 'parameter_fingerprint')):
                    gate[prefix + field] = identity[key]
        result['layers'][-1]['semantic_presence_gate'] = gate
    return result


def synthetic_authenticated(b, rows):
    """Test-only construction, never a provenance substitute in production."""
    raw, joins = e.canonical(rows), e.canonical([])
    definition = c.ARMS[c.ARM_KEYS.index(b.arm)]
    metadata = {'source_revision': 'a' * 40, 'study_plan_sha256': dict(c.PIN_ITEMS)['plan'],
                'prepared_manifest_sha256': dict(contract_fixtures.programme_input()['external_hashes'])['prepared_manifest'],
                'trainer_contract_sha256': 'b' * 64, 'training_seed': '12102026',
                'initialization_sha256': contract_fixtures.sha(definition.profile) if b.epoch else None,
                'checkpoint_epoch': str(b.epoch), 'training_steps': str(b.epoch * 490),
                'programme_sha256': b.programme_sha256, 'selected_C': '1.0',
                'training_strategy': 'train_only_sparse_tfidf_logistic_c1'}
    provenance = e.canonical(metadata)
    seal = e._collection_seal(b, raw, 'a' * 64, joins, provenance)
    return e.AuthenticatedCollection(b, raw, 'a' * 64, joins, provenance, seal, e._AUTH)


class EvidenceBoundaryTests(unittest.TestCase):
    def test_hash_is_checked_before_json_decoder(self):
        with patch.object(e.json, 'loads', side_effect=AssertionError('decoder called')):
            with self.assertRaises(e.StudyEvidenceError):
                e.checked_json(b'private-invalid', '0' * 64)

    def test_duplicates_nonfinite_and_oversize_fail_closed(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff'):
            with self.assertRaises(e.StudyEvidenceError):
                e.checked_json(raw, e.sha(raw))
        with self.assertRaises(e.StudyEvidenceError):
            e.checked_json(b'1234', e.sha(b'1234'), 3)

    def test_closed_binding_modes_epochs_threshold_types_and_test_prerequisite(self):
        for changes in ({'arm': 'latest'}, {'epoch': True}, {'decision_threshold': 0}, {'decision_threshold': float('nan')},
                        {'decision_threshold': .5}, {'phase': 'collect-test', 'barrier_sha256': None}):
            with self.subTest(changes=changes), self.assertRaises(e.StudyEvidenceError):
                binding(**changes)
        b, _ = binding('B-F', 1)
        with self.assertRaises(TypeError):
            b.presence_identity['model_id'] = 'changed'

    def test_dataset_truth_group_text_order_are_bound_to_captured_bytes(self):
        b, raw = binding()
        self.assertEqual(len(e.dataset_rows(raw, b)), 2000)
        for altered in (raw.replace(b'"synthetic"', b'"changed"', 1), raw.replace(b'"expected_has_pii":true', b'"expected_has_pii":false', 1)):
            with self.assertRaises(e.StudyEvidenceError):
                e.dataset_rows(altered, b)
        with self.assertRaises(e.StudyEvidenceError):
            e.dataset_rows(raw, replace(b, dataset_keys_sha256='0' * 64))
        rows = [json.loads(line) for line in raw.splitlines()]
        rows[0]['expected_has_pii'] = None
        bad, bad_raw = binding(rows=rows)
        with self.assertRaises(e.StudyEvidenceError):
            e.dataset_rows(bad_raw, bad)

    def test_row_and_group_domains_do_not_collide(self):
        self.assertNotEqual(e.opaque('row', 'same'), e.opaque('group', 'same'))
        self.assertNotEqual(e.opaque('row', ' a'), e.opaque('row', 'a'))

    def test_optional_evidence_absence_is_not_fabricated(self):
        absent = e.outcome_claim(response())
        self.assertIsNone(absent['evidence_sha256'])
        present = response()
        present['evidence'] = {'classification': {'sensitivity': 'S0'}}
        self.assertNotEqual(e.outcome_claim(present)['evidence_sha256'], absent['evidence_sha256'])
        missing = response()
        del missing['classification']
        with self.assertRaises(e.StudyEvidenceError):
            e.outcome_claim(missing)

    def test_visible_layer_errors_and_partial_shortcuts_reject(self):
        for field in ('error', 'status'):
            bad = response()
            bad['layers'][1][field] = 'private-marker'
            with self.assertRaises(e.StudyEvidenceError) as raised:
                e.outcome_claim(bad)
            self.assertNotIn('private-marker', str(raised.exception))
        shortcut = response(block=True)
        self.assertEqual(e.outcome_claim(shortcut)['action'], 'BLOCK')
        shortcut['layers'][2]['error'] = 'other reason'
        with self.assertRaises(e.StudyEvidenceError):
            e.outcome_claim(shortcut)

    def test_trace_zero_threshold_and_original_context_identity(self):
        b, _ = binding()
        self.assertEqual(e.trace_claim(response(True), b)['predicted_label'], 'PRESENT')
        for key, value in (('contextual_parameter_fingerprint', '0' * 64), ('decision_threshold', .1), ('probability', True), ('model_threshold', .4)):
            bad = response(True)
            bad['layers'][-1]['semantic_presence_gate'][key] = value
            with self.assertRaises(e.StudyEvidenceError):
                e.trace_claim(bad, b)

    def test_not_run_has_no_fabricated_identity_or_probability(self):
        b, _ = binding()
        self.assertIsNone(e.trace_claim(response(True, True), b)['probability'])
        for key, value in (('probability', 0.0), ('model_version', 'wrong'), ('error', ''), ('model_id', 'wrong')):
            bad = response(True, True)
            bad['layers'][-1]['semantic_presence_gate'][key] = value
            with self.assertRaises(e.StudyEvidenceError):
                e.trace_claim(bad, b)

    def test_authenticated_claims_cannot_be_mutated_or_replaced(self):
        b, _ = binding()
        value = synthetic_authenticated(b, [{'value': 1}])
        returned = value.rows
        returned[0]['value'] = 2
        self.assertEqual(value.rows[0]['value'], 1)
        with self.assertRaises(e.StudyEvidenceError):
            replace(value, _claims_raw=e.canonical([{'value': 2}]))
        with self.assertRaises(e.StudyEvidenceError):
            e.AuthenticatedCollection(b, b'[]', 'a' * 64, b'[]', b'{}')

    def test_partial_checkpoint_survivors_are_not_analysis_inputs(self):
        b, _ = binding()
        with self.assertRaises(e.StudyEvidenceError):
            e.make_joint_validation_input([synthetic_authenticated(b, [])])
        with self.assertRaises(e.StudyEvidenceError):
            e.make_live_input([])

    def test_selected_choice_requires_external_raw_digest_and_exact_identity(self):
        b, _ = binding(phase='rerun-validation')
        value = {'status': 'eligible', 'control_binding_sha256': b.control_binding_sha256,
                 'selections': {key: {'epoch': 0, 'identity': dict(b.presence_identity), 'threshold': 0.0} for key in c.ARM_KEYS}}
        raw = e.canonical(value)
        b = replace(b, selection_sha256=e.sha(raw))
        e.require_selected(b, raw)
        value['selections']['S0']['threshold'] = .5
        with self.assertRaises(e.StudyEvidenceError):
            e.require_selected(b, e.canonical(value))

    def test_float32_fingerprint_is_not_raw_float64_fingerprint(self):
        from privoke_model.fingerprint import parameter_fingerprint
        from privoke_model.artifact import float32
        value = .1
        independently_cast = struct.unpack('<f', struct.pack('<f', value))[0]
        self.assertEqual(float32(value), independently_cast)
        self.assertNotEqual(parameter_fingerprint({'x': [value]}, {'x': [1]}),
                            parameter_fingerprint({'x': [float32(value)]}, {'x': [1]}))

    def test_actual_public_all_arm_selector_and_live_consumer(self):
        original = analysis_fixtures.validation_input(2000, 1000)
        collections = []
        for arm in original['arms']:
            for cp in arm['checkpoints']:
                b, _ = binding(arm['arm'], cp['epoch'], control_binding_sha256=original['control_binding_sha256'])
                collections.append(synthetic_authenticated(b, cp['rows']))
        joint = e.make_joint_validation_input(collections)
        selection = a.select_joint_validation(joint)
        self.assertEqual(selection['status'], 'eligible')
        live_input = analysis_fixtures.live_input(joint, selection)
        live = []
        for item in live_input['arms']:
            b, _ = binding(item['arm'], item['epoch'], phase='rerun-validation',
                           control_binding_sha256=original['control_binding_sha256'], decision_threshold=item['threshold'])
            live.append(synthetic_authenticated(b, item['rows']))
        receipt = a.verify_selected_live_validation(joint, selection, e.make_live_input(live))
        self.assertFalse(receipt['test_authorized'])
        with self.assertRaises(e.StudyEvidenceError):
            e.make_live_input(live[:-1])

    def test_cli_wrong_external_trust_hash_fails_before_decoding_or_rpc(self):
        spec = importlib.util.spec_from_file_location('study_evidence_cli_test', ROOT / 'evaluation/evaluate-in-house-study.py')
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trust.json'
            path.write_bytes(b'{"phase":"collect-test"}')
            args = type('Arguments', (), {'trust_bundle': path, 'trust_bundle_sha256': '0' * 64})()
            with patch.object(e, 'RuntimeClient', side_effect=AssertionError('RPC')), patch.object(e, 'checked_json', side_effect=AssertionError('JSON decode')):
                with self.assertRaises(e.StudyEvidenceError):
                    cli.run(args)

    def test_actual_source_attestation_rejects_foreign_function_and_method(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic_attested_module.py'
            raw = b'def outer():\n    def nested():\n        return 1\n    return nested()\nclass Wrapper:\n    def call(self):\n        return outer()\n'
            path.write_bytes(raw)
            spec = importlib.util.spec_from_file_location('synthetic_attested_module', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            e._attest_module(module, e.sha(raw))
            with patch.object(module, 'outer', lambda: 2):
                with self.assertRaises(e.StudyEvidenceError):
                    e._attest_module(module, e.sha(raw))
            with patch.object(module.Wrapper, 'call', lambda self: 2):
                with self.assertRaises(e.StudyEvidenceError):
                    e._attest_module(module, e.sha(raw))
            clone = FunctionType(module.outer.__code__, dict(vars(module)), module.outer.__name__, module.outer.__defaults__)
            clone.__module__ = module.__name__
            clone.__qualname__ = module.outer.__qualname__
            with patch.object(module, 'outer', clone):
                with self.assertRaises(e.StudyEvidenceError):
                    e._attest_module(module, e.sha(raw))
            method_clone = FunctionType(module.Wrapper.call.__code__, dict(vars(module)), module.Wrapper.call.__name__)
            method_clone.__module__ = module.__name__
            with patch.object(module.Wrapper, 'call', method_clone):
                with self.assertRaises(e.StudyEvidenceError):
                    e._attest_module(module, e.sha(raw))

    @unittest.skipUnless(sys.platform != 'win32', 'POSIX descriptor/permissions gate mandatory in Linux.')
    def test_private_writer_exclusive_no_reuse_and_replaced_output_path(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'fresh'
            writer = e.PrivateWriter(output)
            try:
                writer.write('rpc-one.json', b'{}')
                self.assertEqual((output / 'rpc-one.json').stat().st_mode & 0o777, 0o600)
                with self.assertRaises(e.StudyEvidenceError):
                    writer.write('rpc-one.json', b'changed')
                retained = Path(directory) / 'retained'
                output.rename(retained)
                output.mkdir()
                with self.assertRaises(e.StudyEvidenceError):
                    writer.write('rpc-two.json', b'{}')
                self.assertFalse((output / 'rpc-two.json').exists())
            finally:
                writer.close()

    def test_actual_public_barrier_joins_claims_not_raw_file_hashes(self):
        source = analysis_fixtures.validation_input(2000, 1000)
        programme_input = contract_fixtures.programme_input()
        programme_input['s0'] = analysis_fixtures.identity('S0', 0)
        programme = c.freeze_programme(programme_input)
        operational = {key: dict(programme.external_hashes)[key] for key in ('runtime_image', 'evaluator_image', 'effective_configuration', 'fixture_rubric', 'fixture_review')}
        operational['protocol'] = dict(c.PIN_ITEMS)['protocol']
        checkpoints, fit_entries = [], []
        for arm in source['arms']:
            definition = c.ARMS[c.ARM_KEYS.index(arm['arm'])]
            for cp in arm['checkpoints']:
                b, _ = binding(arm['arm'], cp['epoch'], control_binding_sha256=source['control_binding_sha256'],
                               programme_sha256=programme.sha256, operational_hashes=operational)
                checkpoints.append(synthetic_authenticated(b, cp['rows']))
                fit_entries.append({'arm': arm['arm'], 'epoch': cp['epoch'], 'identity': cp['identity'], 'steps': cp['epoch'] * 490,
                    'initialization_sha256': dict(programme.initialization_fingerprints)[definition.profile] if cp['epoch'] else None,
                    'permutation_sha256': c.permutation_sha256(definition.profile, cp['epoch'], 7832) if cp['epoch'] else None,
                    'job_receipt_sha256': 'a' * 64})
        joint = e.make_joint_validation_input(checkpoints)
        selection = a.select_joint_validation(joint)
        selection_raw = e.canonical(selection)
        live, fixtures = [], []
        fixture_views = []
        for i, case in enumerate(contract_fixtures.fixtures()):
            fixture_views.append({'id': str(i), 'group_id': str(i), 'text': 'synthetic', 'expected_has_pii': case['required_sensitive'],
                                 **{key: case[key] for key in ('ambiguous', 'required_sensitive', 'required_action', 'visibility_hint')}})
        for item in analysis_fixtures.live_input(joint, selection)['arms']:
            common = dict(control_binding_sha256=source['control_binding_sha256'], programme_sha256=programme.sha256,
                          operational_hashes=operational, decision_threshold=item['threshold'], selection_sha256=e.sha(selection_raw))
            b, _ = binding(item['arm'], item['epoch'], phase='rerun-validation', **common)
            live.append(synthetic_authenticated(b, item['rows']))
            fb, _ = binding(item['arm'], item['epoch'], phase='collect-fixtures', rows=fixture_views, **common)
            rows = [{'row_id_sha256': case['case_sha256'], 'group_id_sha256': case['case_sha256'], 'truth': case['required_sensitive'],
                     **{key: case[key] for key in ('ambiguous', 'required_sensitive', 'required_action', 'visibility_hint')},
                     'ordinary': {'action': case['ordinary_action']}, 'outcome': {'action': case['action']}} for case in contract_fixtures.fixtures()]
            fixtures.append(synthetic_authenticated(fb, rows))
        fit_raw = e.canonical({'schema_version': 1, 'programme_sha256': programme.sha256, 'checkpoints': fit_entries,
                             'trainer_contract_sha256': 'b' * 64, 'source_revision': 'a' * 40,
                             'prepared_manifest_sha256': dict(programme.external_hashes)['prepared_manifest']})
        records, refs, receipt = e.derive_barrier_records(programme, checkpoints, selection_raw, live, fixtures, fit_raw,
            trusted_fit_inventory_sha256=e.sha(fit_raw), trusted_selection_sha256=e.sha(selection_raw))
        self.assertEqual(len(records), 8)
        self.assertEqual(len(receipt['authenticated_collections']), 48)
        self.assertFalse(receipt['test_authorized'])
        self.assertNotEqual(refs['S0/checkpoint/0'], checkpoints[0].inventory_sha256)
        with self.assertRaises(c.StudyContractError):
            bad = copy.deepcopy(records)
            bad[1]['fixtures'][24]['action'] = 'ALLOW'
            c.validate_pretest_barrier(programme, bad, refs)


try:
    from privoke.v1 import runtime_pb2
    from google.protobuf.json_format import ParseDict
    HAS_WIRE = True
except ImportError:
    HAS_WIRE = False


@unittest.skipUnless(HAS_WIRE, 'Actual generated protobuf unavailable; Linux generated-wire gate mandatory.')
class GeneratedWireTests(unittest.TestCase):
    def test_collector_retains_malformed_response_before_failure_marker(self):
        class Writer:
            def __init__(self):
                self.files = {}
            def write(self, name, raw):
                self.files[name] = raw
                return e.sha(raw)
        class Client:
            def analyze(self, request):
                return b'\xff'
        b, _ = binding()
        writer = Writer()
        with self.assertRaises(e.StudyEvidenceError):
            e.collect_rows(Client(), b, ({'id': 'one', 'text': 'fake'},), writer, e.WireCodec())
        self.assertIn('rpc-0000-ordinary.json', writer.files)
        self.assertIn('failure.json', writer.files)
        self.assertNotIn('inventory.json', writer.files)
        frame = json.loads(writer.files['rpc-0000-ordinary.json'])
        self.assertEqual(base64.b64decode(frame['response_b64']), b'\xff')

    def test_actual_optional_message_and_zero_override_roundtrip(self):
        codec = e.WireCodec()
        b, _ = binding()
        row = {'id': 'one', 'text': 'fake unicode \u00e9', 'visibility_hint': 'P0'}
        request = codec.request(b, row, 'gated')
        self.assertTrue(request.semantic_presence_gate.HasField('threshold'))
        self.assertEqual(request.semantic_presence_gate.threshold, 0.0)
        self.assertEqual(request.visibility_hint, 'P0')
        raw = ParseDict(response(True), runtime_pb2.AnalyzePromptResponse()).SerializeToString(deterministic=True)
        _, parsed = codec.parse_response(raw)
        self.assertIsNone(e.outcome_claim(parsed)['evidence_sha256'])
        self.assertEqual(e.trace_claim(parsed, b)['probability'], 0.0)

    def test_actual_unknown_wire_fields_and_missing_classification_reject(self):
        codec = e.WireCodec()
        raw = ParseDict(response(), runtime_pb2.AnalyzePromptResponse()).SerializeToString(deterministic=True)
        with self.assertRaises(e.StudyEvidenceError):
            codec.parse_response(raw + b'\xf8\x07\x01')
        with self.assertRaises(e.StudyEvidenceError):
            codec.parse_response(runtime_pb2.AnalyzePromptResponse(request_id='one').SerializeToString())

    def test_requests_distinguish_models_text_layers_ids_and_hints(self):
        codec = e.WireCodec()
        b, _ = binding()
        row = {'id': 'one', 'text': 'fake', 'visibility_hint': None}
        first = codec.request(b, row, 'gated').SerializeToString(deterministic=True)
        for altered in ({**row, 'text': 'different'}, {**row, 'id': 'two'}, {**row, 'visibility_hint': 'PU'}):
            self.assertNotEqual(first, codec.request(b, altered, 'gated').SerializeToString(deterministic=True))
        self.assertNotEqual(first, codec.request(b, row, 'nonsemantic').SerializeToString(deterministic=True))

    def test_actual_raw_consumer_inventory_and_request_response_tampering(self):
        codec = e.WireCodec()
        b, dataset = binding()
        rows = e.dataset_rows(dataset, b)
        files, entries = {}, []
        for index, row in enumerate(rows):
            for purpose in ('ordinary', 'gated', 'nonsemantic'):
                req = codec.request(b, row, purpose)
                payload = response(purpose == 'gated')
                payload['request_id'] = req.request_id
                if purpose == 'nonsemantic':
                    payload['layers'][-1].update(status='not_requested', error=a.NOT_REQUESTED_REASON)
                raw = ParseDict(payload, runtime_pb2.AnalyzePromptResponse()).SerializeToString(deterministic=True)
                request_raw = req.SerializeToString(deterministic=True)
                frame = {'schema_version': 1, 'binding_sha256': b.sha256, 'row_index': index, 'purpose': purpose,
                         'request_b64': base64.b64encode(request_raw).decode(), 'response_b64': base64.b64encode(raw).decode(),
                         'request_sha256': e.sha(request_raw), 'response_sha256': e.sha(raw), 'elapsed_ns': 1}
                name = f'rpc-{index:04d}-{purpose}.json'
                files[name] = e.canonical(frame)
                entries.append({'file': name, 'sha256': e.sha(files[name])})
        inventory = {'schema_version': 1, 'status': 'complete', 'binding_sha256': b.sha256, 'files': entries}
        raw_inventory = e.canonical(inventory)
        kwargs = dict(inventory_sha256=e.sha(raw_inventory), trusted_phase_binding=b, captured_dataset=dataset,
                      captured_artifacts={'contextual': b'public-synthetic', 'presence': b'public-synthetic'}, raw_files=files, codec=codec)
        # Synthetic artifact/source seams only; actual generated requests, decoding,
        # raw inventories and public claim derivation execute unchanged.
        with patch.object(e, 'attest_sources'), patch.object(e, 'artifact_identity', return_value={'config': {'threshold': .5}}):
            result = e.verify_raw_collection(raw_inventory, **kwargs)
            self.assertEqual(len(result.rows), 2000)
            for extra in (True, False):
                altered = dict(files)
                if extra:
                    altered['rpc-extra.json'] = b'{}'
                else:
                    altered.pop(next(iter(altered)))
                with self.assertRaises(e.StudyEvidenceError):
                    e.verify_raw_collection(raw_inventory, **{**kwargs, 'raw_files': altered})
            first_name = entries[0]['file']
            frame = json.loads(files[first_name])
            request = runtime_pb2.AnalyzePromptRequest.FromString(base64.b64decode(frame['request_b64']))
            request.text = 'tampered-private-marker'
            raw = request.SerializeToString(deterministic=True)
            frame.update(request_b64=base64.b64encode(raw).decode(), request_sha256=e.sha(raw))
            altered_files = {**files, first_name: e.canonical(frame)}
            altered_inventory = copy.deepcopy(inventory)
            altered_inventory['files'][0]['sha256'] = e.sha(altered_files[first_name])
            altered_raw = e.canonical(altered_inventory)
            with self.assertRaises(e.StudyEvidenceError) as raised:
                e.verify_raw_collection(altered_raw, **{**kwargs, 'inventory_sha256': e.sha(altered_raw), 'raw_files': altered_files})
            self.assertNotIn('tampered-private-marker', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
