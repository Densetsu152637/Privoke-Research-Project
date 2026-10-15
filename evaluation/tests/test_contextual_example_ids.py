"""Source-declared evaluator IDs must match exactly without alternate-ID retries."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


STUDY = module('id_study', 'evaluation/run-contextual-fuzzer-study.py')
QUALITY = module('id_quality', 'evaluation/report-contextual-fuzzer-study.py')


class DeclaredExampleIdTests(unittest.TestCase):
    def test_explicit_native_id_overrides_generated_namespace(self):
        self.check_ids({'id': 'x', 'example_id': 'piimb:native', 'group_id': 'source:x', 'expected_has_pii': True}, 'piimb:native', 'local-jsonl:x')

    def test_absent_explicit_id_uses_local_namespace(self):
        self.check_ids({'id': 'x', 'group_id': 'source:x', 'expected_has_pii': True}, 'local-jsonl:x', 'x')

    def check_ids(self, source, correct, wrong):
        artifact = {'model_id': 'synthetic', 'version': 'test', 'checksum': 'frozen', 'parameters': {'head': {'shape': [1], 'values': [0.]}}}
        identity = STUDY.artifact_identity(artifact)
        row = {'example_id': correct, 'expected_has_pii': True, 'group_id': source['group_id'], 'detected_sensitive': True, 'status': 'ok', 'elapsed_ms': 1., 'layers': [{'layer': 'DETECTION_LAYER_SEMANTIC', 'status': 'ok', 'results': [{'metadata': identity}]}]}
        report = {'errors': [], 'metadata': {'predictions': [row]}, 'metrics': {'evaluated_samples': 1, 'runtime_errors': 0, 'true_positives': 1, 'true_negatives': 0, 'false_positives': 0, 'false_negatives': 0}}
        counts = {'tp': 1, 'tn': 0, 'fp': 0, 'fn': 0}
        with patch.object(QUALITY, 'read_bytes', return_value=(json.dumps(source) + '\n').encode()):
            reference = QUALITY.endpoint(Path('synthetic.jsonl'), 'mock', 1, 1)
        self.assertEqual(reference, {correct: (True, source['group_id'])})
        self.assertEqual(STUDY.verified_report(report, [source], artifact), counts)
        with patch.object(QUALITY, 'read', return_value=report):
            self.assertEqual(QUALITY.verify_report({'path': 'synthetic-report', 'sha256': 'mock'}, reference, identity, counts)[0]['metrics']['tp'], 1)
        row['example_id'] = wrong
        with self.assertRaises(ValueError):
            STUDY.verified_report(report, [source], artifact)
        with patch.object(QUALITY, 'read', return_value=report), self.assertRaises(ValueError):
            QUALITY.verify_report({'path': 'synthetic-report', 'sha256': 'mock'}, reference, identity, counts)


if __name__ == '__main__':
    unittest.main()
