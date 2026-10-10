"""Synthetic-only adapter mechanics; never reads study TRAIN or assessment."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / 'evaluation', ROOT / 'shared/python', ROOT / 'extension/client-runtime', ROOT / 'models'):
    sys.path.insert(0, str(p))
import numpy as np
from generate_baseline import initial_parameters, SENSITIVITIES, VISIBILITIES, CATEGORIES
from src.model import ModelConfig
from privoke_model.artifact import artifact_checksum
from privoke_eval.accelerated_training_surfaces_offline import fit_cell, evaluate_cell_snapshot, _schedule, _admit, _validate, _read_ref


def ref(path):
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def fixture(directory):
    config = ModelConfig(32, 8, 16, 256, SENSITIVITIES, VISIBILITIES, CATEGORIES, num_attention_heads=2)
    arrays = initial_parameters(config, np.random.default_rng(7))
    artifact = {'schema_version': 1, 'model_id': 'privoke-baseline', 'version': 'synthetic-v1', 'generated_at_unix': 1, 'architecture': 'privoke_tiny_transformer_v1', 'config': asdict(config), 'parameters': {n: {'shape': list(a.shape), 'values': a.ravel().tolist(), 'trainable': n.startswith('head.')} for n, a in arrays.items()}, 'metadata': {}}
    artifact['checksum'] = artifact_checksum(artifact)
    base = directory / 'base.json'
    base.write_text(json.dumps(artifact))
    train = directory / 'train.jsonl'
    train.write_text('\n'.join(json.dumps({'id': str(i), 'text': f'Synthetic alpha {i}', 'classification': {'sensitivity': 'S0' if i % 2 else 'S2', 'visibility': 'PU' if i % 2 else 'P3', 'categories': [] if i % 2 else ['FINANCIAL']}}) for i in range(4)))
    cell = {'id': 'mechanics', 'kind': 'offline', 'surface': 'tiny', 'model_id': 'privoke-baseline', 'profile': 'synthetic', 'scope': 'heads', 'seed': 42, 'optimizer_steps': 96, 'batch_size': 32, 'objective': 'contextual', 'optimizer': 'Adam'}
    return cell, {'train': ref(train), 'base_artifact': ref(base), 'assets': {}, 'source_revision': 'a' * 40}


class OfflineAdapterTests(unittest.TestCase):
    def test_layer_boundary_rejects_before_access(self):
        for layers in ([], ['DETECTION_LAYER_REGEX'], ['DETECTION_LAYER_SEMANTIC', 'DETECTION_LAYER_NER']):
            with self.assertRaises(ValueError):
                evaluate_cell_snapshot(Path('missing'), [], layers)

    def test_schedule_dose_repetition_pairing(self):
        rows = [{'id': str(i)} for i in range(7)]
        schedule = _schedule(rows, 42, 96, 32)
        self.assertEqual(schedule, _schedule(rows, 42, 96, 32))
        self.assertNotEqual(schedule, _schedule(rows, 43, 96, 32))
        self.assertEqual(sum(map(len, schedule)), 3072)
        self.assertEqual(set(i for b in schedule for i in b), set(range(7)))

    def test_context_rejects_without_truncation(self):
        self.assertEqual(_admit(['alpha beta'], 3), 3)
        with self.assertRaises(ValueError):
            _admit(['alpha beta gamma'], 3)

    def test_native_scratch_dose_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            cell, inputs = fixture(Path(d))
            cell.update(surface='scratch_presence', objective='binary_presence')
            del inputs['base_artifact']
            with self.assertRaises(ValueError):
                _validate(cell, inputs)
            cell['batch_size'] = 16
            _validate(cell, inputs)

    def test_forbidden_path_and_hash(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'assessment.jsonl'
            path.write_text('never read')
            with self.assertRaises(ValueError):
                _read_ref(ref(path))
            path = Path(d) / 'train.jsonl'
            path.write_text('ok')
            with self.assertRaises(ValueError):
                _read_ref({'path': str(path), 'sha256': '0' * 64})

    def test_tiny_fixed_final_scope_resume_and_forward_errors(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            output = directory / 'cell'
            receipt = fit_cell(cell, inputs, output)
            self.assertEqual(receipt['dose']['optimizer_steps'], 96)
            self.assertEqual(receipt['dose']['presentations'], 3072)
            self.assertTrue(receipt['tensor_audit']['encoder_unchanged'])
            self.assertTrue(receipt['tensor_audit']['changed_names'])
            self.assertEqual(receipt, fit_cell(cell, inputs, output))
            records = evaluate_cell_snapshot(Path(receipt['final_artifact']['path']), [{'id': 'ok', 'text': 'synthetic'}, {'id': 'long', 'text': 'word ' * 256}], ['DETECTION_LAYER_SEMANTIC'])
            self.assertEqual([r['status'] for r in records], ['complete', 'error'])
            self.assertEqual(records[0]['executions'][0]['forward_count'], 1)
            self.assertEqual(records[1]['executions'], [])
            Path(receipt['final_artifact']['path']).write_text('{}')
            with self.assertRaises(ValueError):
                fit_cell(cell, inputs, output)

    def test_scratch_generated_baseline_native_dose_and_parity(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell.update(id='scratch-mechanics', surface='scratch_presence', profile='efficient', model_id='privoke-scratch-presence-efficient-head-only', batch_size=16, objective='binary_presence')
            del inputs['base_artifact']
            train = directory / 'binary-train.jsonl'
            train.write_text('\n'.join(json.dumps({'id': str(i), 'text': f'Synthetic binary alpha {i}', 'present': bool(i % 2)}) for i in range(4)))
            inputs['train'] = ref(train)
            receipt = fit_cell(cell, inputs, directory / 'scratch')
            self.assertEqual(receipt['dose']['presentations'], 1536)
            self.assertTrue(receipt['tensor_audit']['encoder_unchanged'])
            baseline = json.loads(Path(receipt['baseline_artifact']['path']).read_bytes())
            self.assertEqual(baseline['training_steps'], 0)
            for key in ('baseline_artifact', 'final_artifact'):
                records = evaluate_cell_snapshot(Path(receipt[key]['path']), [{'id': 'probe', 'text': 'Synthetic binary'}], ['DETECTION_LAYER_SEMANTIC'])
                self.assertEqual(records[0]['status'], 'complete')

    def test_sparse_native_solver_and_zero_head_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell.update(id='sparse-mechanics', surface='sparse_presence', profile='efficient', model_id='privoke-presence-efficient', objective='binary_presence', optimizer='lbfgs', optimizer_steps=None, solver_budget={'solver': 'lbfgs', 'max_iter': 1000, 'tol': 1e-4, 'C': 1.0, 'class_weight': 'balanced'})
            del inputs['base_artifact']
            train = directory / 'binary-train.jsonl'
            train.write_text('\n'.join(json.dumps({'id': str(i), 'text': 'Synthetic private account' if i % 2 else 'Synthetic public weather', 'present': bool(i % 2)}) for i in range(8)))
            inputs['train'] = ref(train)
            receipt = fit_cell(cell, inputs, directory / 'sparse')
            self.assertIsNone(receipt['dose']['optimizer_steps'])
            self.assertIsNone(receipt['dose']['presentations'])
            baseline = json.loads(Path(receipt['baseline_artifact']['path']).read_bytes())
            final = json.loads(Path(receipt['final_artifact']['path']).read_bytes())
            self.assertEqual(baseline['config'], final['config'])
            records = evaluate_cell_snapshot(Path(receipt['baseline_artifact']['path']), [{'id': 'probe', 'text': 'Synthetic binary'}], ['DETECTION_LAYER_SEMANTIC'])
            self.assertEqual(records[0]['present_probability'], .5)
            self.assertEqual(receipt, fit_cell(cell, inputs, directory / 'sparse'))
            damaged = json.loads(json.dumps(receipt))
            del damaged['evidence']['solver_state']
            (directory / 'sparse' / 'fit-receipt.json').write_text(json.dumps(damaged))
            with self.assertRaises(ValueError):
                fit_cell(cell, inputs, directory / 'sparse')

    def test_random_control_shared384_head_initialization(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell.update(id='control-mechanics', surface='random_control', optimizer='numpy_float64_adam_coupled_l2_after_global_clip_v1')
            receipt = fit_cell(cell, inputs, directory / 'control')
            self.assertEqual(receipt, fit_cell(cell, inputs, directory / 'control'))
            import copy
            from unittest.mock import patch
            for key in ('feature_construction', 'baseline_generated_before_fit', 'step_order', 'optimizer_state'):
                damaged = copy.deepcopy(receipt)
                del damaged['evidence'][key]
                (directory / 'control' / 'fit-receipt.json').write_text(json.dumps(damaged))
                with patch('privoke_eval.accelerated_training_surfaces_offline._frozen_fit', side_effect=AssertionError('resume must not fit')), self.assertRaises(ValueError):
                    fit_cell(cell, inputs, directory / 'control')
            (directory / 'control' / 'fit-receipt.json').write_text(json.dumps(receipt))
            baseline = json.loads(Path(receipt['baseline_artifact']['path']).read_bytes())
            self.assertEqual(baseline['feature_spec']['projection_dimensions'], [8, 384])
            self.assertEqual(baseline['feature_spec']['projection_seed'], 12102026)
            from src.model import TinyTransformerModel
            from src.detection.preprocessing import normalize_text
            encoder = TinyTransformerModel.from_artifact(json.loads(Path(inputs['base_artifact']['path']).read_bytes()))
            pooled = encoder.encode(normalize_text('Synthetic control')) @ np.asarray(baseline['projection'], dtype=np.float32)
            pooled /= np.linalg.norm(pooled)
            traces = []
            for key, steps in (('baseline_artifact', 0), ('final_artifact', 96)):
                snapshot_path = Path(receipt[key]['path'])
                snapshot_raw = snapshot_path.read_bytes()
                snapshot = json.loads(snapshot_raw)
                record = evaluate_cell_snapshot(snapshot_path, [{'id': 'probe', 'text': 'Synthetic control'}], ['DETECTION_LAYER_SEMANTIC'])[0]
                traces.append(record)
                self.assertEqual(record['status'], 'complete')
                self.assertEqual(record['training_steps'], steps)
                self.assertEqual(record['requested_version'], f'accelerated-control-seed42-step{steps}')
                self.assertEqual(record['used_version'], record['requested_version'])
                self.assertEqual(record['snapshot_sha256'], ref(snapshot_path)['sha256'])
                for task in ('sensitivity', 'visibility', 'category'):
                    weight = snapshot['parameters'][f'head.{task}.weight']
                    bias = snapshot['parameters'][f'head.{task}.bias']
                    logits = pooled @ np.asarray(weight['values'], dtype=np.float32).reshape(weight['shape']) + np.asarray(bias['values'], dtype=np.float32)
                    if task == 'category':
                        expected = 1 / (1 + np.exp(-logits))
                    else:
                        exponent = np.exp(logits - logits.max())
                        expected = exponent / exponent.sum()
                    np.testing.assert_allclose(record['probabilities'][task], expected, atol=2e-6)
                damaged = dict(snapshot)
                damaged.pop('version')
                snapshot_path.write_text(json.dumps(damaged))
                with self.assertRaises(ValueError):
                    evaluate_cell_snapshot(snapshot_path, [], ['DETECTION_LAYER_SEMANTIC'])
                snapshot_path.write_bytes(snapshot_raw)
            self.assertNotEqual(traces[0]['used_version'], traces[1]['used_version'])
            self.assertNotEqual(traces[0]['snapshot_sha256'], traces[1]['snapshot_sha256'])
            self.assertNotEqual(traces[0]['parameter_fingerprint'], traces[1]['parameter_fingerprint'])

    def test_full_tiny_changes_encoder_with_same_initial_tensors(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell['scope'] = 'full_encoder'
            receipt = fit_cell(cell, inputs, directory / 'full')
            self.assertFalse(receipt['tensor_audit']['encoder_unchanged'])
            self.assertIn('token_embedding', receipt['tensor_audit']['allowed_names'])

    def test_scratch_full_encoder_changes_with_canonical_pair(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell.update(id='scratch-full-mechanics', surface='scratch_presence', profile='efficient', scope='full_encoder', model_id='privoke-scratch-presence-efficient-full-encoder', batch_size=16, objective='binary_presence')
            del inputs['base_artifact']
            train = directory / 'binary-train.jsonl'
            train.write_text('\n'.join(json.dumps({'id': str(i), 'text': f'Synthetic binary alpha {i}', 'present': bool(i % 2)}) for i in range(4)))
            inputs['train'] = ref(train)
            receipt = fit_cell(cell, inputs, directory / 'scratch-full')
            self.assertFalse(receipt['tensor_audit']['encoder_unchanged'])
            from privoke_eval.in_house_presence_training import create_paired_trainers
            pair = create_paired_trainers('efficient')
            baseline = json.loads(Path(receipt['baseline_artifact']['path']).read_bytes())
            self.assertEqual(baseline['initialization_sha256'], pair[0].initialization_sha256)
            self.assertEqual(pair[0].initialization_sha256, pair[1].initialization_sha256)

    def test_sparse_convergence_failure_never_extends_budget(self):
        import warnings
        from unittest.mock import patch
        from sklearn.exceptions import ConvergenceWarning
        from sklearn.linear_model import LogisticRegression
        native_fit = LogisticRegression.fit
        calls = []
        def warned_fit(estimator, features, labels):
            calls.append(estimator.max_iter)
            result = native_fit(estimator, features, labels)
            warnings.warn('synthetic convergence failure', ConvergenceWarning)
            return result
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            cell.update(id='sparse-failure', surface='sparse_presence', profile='efficient', model_id='privoke-presence-efficient', objective='binary_presence', optimizer='lbfgs', optimizer_steps=None, solver_budget={'solver': 'lbfgs', 'max_iter': 1000, 'tol': 1e-4, 'C': 1.0, 'class_weight': 'balanced'})
            del inputs['base_artifact']
            train = directory / 'binary-train.jsonl'
            train.write_text('\n'.join(json.dumps({'id': str(i), 'text': 'Synthetic private account' if i % 2 else 'Synthetic public weather', 'present': bool(i % 2)}) for i in range(8)))
            inputs['train'] = ref(train)
            with patch.object(LogisticRegression, 'fit', warned_fit), self.assertRaises(ValueError):
                fit_cell(cell, inputs, directory / 'failure')
            self.assertEqual(calls, [1000])
            failure = json.loads((directory / 'failure' / 'solver-failure.json').read_bytes())
            self.assertEqual(failure['status'], 'failed_convergence')
            self.assertFalse((directory / 'failure' / 'fit-receipt.json').exists())

    def test_completed_resume_rejects_malformed_references_and_identity(self):
        import copy
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            output = directory / 'cell'
            receipt = fit_cell(cell, inputs, output)
            damaged_receipts = []
            for key in ('baseline_artifact', 'final_artifact'):
                for value in (None, {}, {**receipt[key], 'extra': True}):
                    damaged = copy.deepcopy(receipt)
                    damaged[key] = value
                    damaged_receipts.append(damaged)
                damaged = copy.deepcopy(receipt)
                damaged[key]['path'] = str(directory / 'outside.json')
                damaged_receipts.append(damaged)
            for key in ('step_order', 'optimizer_state'):
                for value in (None, {}, {**receipt['evidence'][key], 'extra': True}):
                    damaged = copy.deepcopy(receipt)
                    damaged['evidence'][key] = value
                    damaged_receipts.append(damaged)
                damaged = copy.deepcopy(receipt)
                del damaged['evidence'][key]
                damaged_receipts.append(damaged)
            for key, value in (('schema_version', 'wrong'), ('status', 'failed'), ('cell_id', 'wrong'), ('settings', {}), ('source_revision', 'b' * 40), ('sources', {}), ('evidence_metrics', None), ('checkpoints', [])):
                damaged = copy.deepcopy(receipt)
                damaged[key] = value
                damaged_receipts.append(damaged)
            with patch('privoke_eval.accelerated_training_surfaces_offline._torch_fit', side_effect=AssertionError('resume must not fit')):
                for damaged in damaged_receipts:
                    with self.subTest(damaged=damaged):
                        (output / 'fit-receipt.json').write_text(json.dumps(damaged))
                        with self.assertRaises(ValueError):
                            fit_cell(cell, inputs, output)
                (output / 'fit-receipt.json').write_text(json.dumps(receipt))
                self.assertEqual(receipt, fit_cell(cell, inputs, output))

    def test_exclusive_and_partial_output(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            cell, inputs = fixture(directory)
            output = directory / 'cell'
            output.mkdir()
            (output / '.fit.lock').write_text('another process')
            with self.assertRaises(FileExistsError):
                fit_cell(cell, inputs, output)
            (output / '.fit.lock').unlink()
            (output / 'partial').write_text('incomplete')
            with self.assertRaises(ValueError):
                fit_cell(cell, inputs, output)


if __name__ == '__main__':
    unittest.main()
