"""Behavior checks for capsule integrity and actual module-origin controls."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('capsule', Path(__file__).resolve().parents[1] / 'local_reproduction_capsule.py')
capsule = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capsule)


class CapsuleIntegrityTests(unittest.TestCase):
    def fixture(self, root):
        capsule.retain(root / 'source/module.py', b'original\n')
        pins = {'source/module.py': {'sha256': capsule.sha(root / 'source/module.py')}}
        capsule.retain(root / 'manifest.json', {'synthetic_only': True, 'synthetic_texts': list(capsule.SYNTHETIC),
            'pins': pins, 'full_source_sha256': capsule.hashlib.sha256(capsule.canonical({k: v['sha256'] for k, v in pins.items()})).hexdigest()})

    def test_tampered_source_fails_before_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            capsule.verify(root)
            (root / 'source/module.py').write_bytes(b'tampered\n')
            with self.assertRaisesRegex(ValueError, 'Capsule pin differs'):
                capsule.verify(root)

    def test_pin_cannot_escape_capsule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            manifest = capsule.read(root / 'manifest.json')
            manifest['pins']['../outside.py'] = {'sha256': 'not-read'}
            (root / 'manifest.json').write_bytes(capsule.canonical(manifest))
            with self.assertRaisesRegex(ValueError, 'Pin escapes'):
                capsule.verify(root)

    def test_non_synthetic_manifest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            manifest = capsule.read(root / 'manifest.json')
            manifest['synthetic_texts'][0] = 'another text'
            (root / 'manifest.json').write_bytes(capsule.canonical(manifest))
            with self.assertRaisesRegex(ValueError, 'Wrong capsule purpose'):
                capsule.verify(root)

    def test_torch_virtual_filename_allowlist_is_exact(self):
        class VirtualTorchModule(ModuleType):
            pass
        VirtualTorchModule.__module__ = 'torch._classes'
        module = VirtualTorchModule('torch.classes')
        module.__file__ = '_classes.py'
        module.__spec__ = None
        self.assertEqual(capsule.module_file_origin('torch.classes', module), (None, '_classes.py'))
        with self.assertRaisesRegex(ValueError, 'Unexpected nonexistent module origin'):
            capsule.module_file_origin('untrusted.module', module)

    def test_real_module_file_is_resolved_for_boundary_check(self):
        module = ModuleType('known')
        module.__file__ = __file__
        origin, virtual = capsule.module_file_origin('known', module)
        self.assertEqual(origin, Path(__file__).resolve())
        self.assertIsNone(virtual)

    def test_rejected_response_keeps_received_wire(self):
        class Response:
            def SerializeToString(self, deterministic):
                return b'received-wire'
        class Stub:
            def AnalyzePrompt(self, request, timeout):
                return Response()
        with patch.object(capsule, 'normalize', side_effect=ValueError('wrong layer')):
            terminal = capsule.capture_terminal(Stub(), object(), {}, object())
        self.assertFalse(terminal['valid'])
        self.assertEqual(capsule.base64.b64decode(terminal['response_pb']), b'received-wire')
        self.assertIn('wrong layer', terminal['error'])

    def test_transport_failure_has_terminal_error(self):
        class Stub:
            def AnalyzePrompt(self, request, timeout):
                raise TimeoutError('RPC timed out')
        terminal = capsule.capture_terminal(Stub(), object(), {}, object())
        self.assertFalse(terminal['valid'])
        self.assertIn('TimeoutError', terminal['error'])
        self.assertNotIn('response_pb', terminal)

    def test_retained_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'receipt.json'
            capsule.retain(target, {'first': True})
            with self.assertRaises(FileExistsError):
                capsule.retain(target, {'first': False})


if __name__ == '__main__':
    unittest.main()
