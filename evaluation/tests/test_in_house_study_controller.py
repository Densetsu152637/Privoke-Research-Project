"""Synthetic sequence/lifecycle tests. No Docker, RPC or research inputs."""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

EVALUATION = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EVALUATION))
sys.path.insert(0, str(EVALUATION.parent/'shared/python'))
from privoke_eval import in_house_study_controller as c
from privoke_eval import in_house_study_evidence as e
from privoke_eval import in_house_study_contract as k

H = 'a'*64
REV = 'b'*40


def identity(raw):
    value = json.loads(raw)
    return value['identity'], {'config': {'threshold': .5}}


def artifact(model_id, version='v1.0.0', label='base'):
    fp = e.digest({'id': model_id, 'version': version, 'label': label})
    # Synthetic identity reader seam has a nonrecursive RAW commitment.
    data = {'identity': {'model_id': model_id, 'version': version,
              'artifact_sha256': H, 'artifact_checksum': fp, 'parameter_fingerprint': fp}, 'label': label}
    return e.canonical(data)


class FakeBackend:
    def __init__(self, inputs, output, *, failure=None):
        self.inputs, self.output, self.failure = inputs, output, failure
        self.jobs, self.unresolved, self.calls = [], set(), []
        self.catalog = {mid: artifact(mid) for mid in c.LEGACY_IDS} | {mid: None for mid in c.SCRATCH_IDS}
        self.initial = dict(self.catalog)
        self.counter = 0

    def safe(self):
        if self.unresolved:
            raise c.RemoteUnknown('synthetic unknown')

    def quiescent(self):
        self.safe()
        self.calls.append(('quiescent',))
        return True

    def controls(self):
        self.safe()
        self.calls.append(('controls',))
        return {'frozen': H}

    def read_catalog(self, model_id):
        self.safe()
        self.calls.append(('read', model_id))
        return self.catalog[model_id]

    def mutate(self, model_id, raw, *, expected_raw_sha256):
        self.safe()
        self.calls.append(('mutate', model_id, raw is None))
        actual = self.catalog[model_id]
        if (None if actual is None else c.raw_hash(actual)) != expected_raw_sha256:
            c.fail()
        if self.failure == 'restore-unknown' and raw == self.initial[model_id] and self.counter:
            self.unresolved.add('restore-job')
            raise c.RemoteUnknown('synthetic unknown')
        self.catalog[model_id] = raw

    def probe(self, contextual, presence):
        self.safe()
        self.calls.append(('probe', presence['model_id']))
        if self.failure == 'probe' and self.counter:
            raise c.ControllerError('synthetic probe failure')

    def probe_absence(self, model_id):
        self.safe()
        self.calls.append(('absence', model_id))
        if self.failure == 'absence':
            c.fail()
        if self.catalog[model_id] is not None:
            c.fail()

    def capture_metadata(self, reference, name):
        self.safe()
        self.calls.append(('metadata', name))
        return {'file': str(c.PRIVATE_ROOT/name), 'sha256': reference['sha256']}

    def capture_dataset(self, descriptor, *, role):
        self.safe()
        self.calls.append(('dataset-volume', role, descriptor['volume']))
        return {'file': str(c.PRIVATE_ROOT/'datasets'/descriptor['file']), 'sha256': descriptor['sha256']}

    def fit(self, arm, refs, output):
        self.safe()
        self.calls.append(('fit', arm))
        if self.failure == 'fit-unknown':
            self.unresolved.add('fit-job')
            raise c.RemoteUnknown('synthetic unknown')
        self.counter += 1
        output.mkdir(parents=True)
        expected = c.json_reference(refs['expected'])
        definition = k.ARMS[k.ARM_KEYS.index(arm)]
        records = []
        for epoch in ((0,) if arm == 'S1' else (1, 2, 3, 4, 5)):
            if self.failure == 'incomplete' and arm == 'Q-F' and epoch == 5:
                continue
            raw = artifact(definition.model_id, 'v1.0.0' if epoch == 0 else f'v1.0.0+epoch.{epoch}', arm)
            name = f'checkpoint-epoch-{epoch:02d}.json'
            c.exclusive(output/name, raw)
            records.append({'epoch': epoch, 'steps': epoch*490, 'artifact_file': name,
                'artifact_sha256': c.raw_hash(raw), 'identity': identity(raw)[0],
                'initialization_sha256': None if not epoch else H,
                'permutation_sha256': None if not epoch else k.permutation_sha256(definition.profile, epoch, 7832)})
        manifest = {'status': 'complete', 'arm_key': arm, 'checkpoint_count': len(records), 'checkpoint_records': records,
            'actual_training_image_id': expected['actual_training_image_id'], 'test_scored': False, 'validation_read': False,
            'inputs_sha256': {'expected_inputs_raw': refs['expected']['sha256']}}
        manifest['private_manifest_raw_sha256'] = e.digest(manifest)
        c.save(output/'manifest.json', manifest)
        return manifest, H

    def phase(self, phase, trust, output, evidence_root):
        self.safe()
        self.calls.append(('phase', phase))
        if self.failure == phase:
            raise c.ControllerError('synthetic primary failure')
        output.mkdir()
        if phase in e.PHASES:
            c.save(output/'inventory.json', {'synthetic': True})
        elif phase == 'select-validation':
            selections = {}
            for arm in k.ARM_KEYS:
                item = next(x for x in trust['checkpoints'] if x['binding']['arm'] == arm)
                selections[arm] = {'epoch': item['binding']['epoch'], 'threshold': .5,
                                   'identity': item['binding']['presence_identity']}
            c.save(output/'result.json', {'status': 'ineligible' if self.failure == 'ineligible' else 'eligible',
                                         'selections': selections})
        elif phase == 'pretest-barrier':
            if self.failure == 'fixture-loss':
                c.fail()
            all_refs = trust['checkpoints']+trust['live']+trust['fixtures']
            binding = e.CollectionBinding(**all_refs[0]['binding'])
            receipt = {'schema_version': 1, 'programme_sha256': binding.programme_sha256,
                'record_sha256': H, 'claim_references': {}, 'raw_to_claim_joins': [],
                'authenticated_collections': [{'binding': r['binding'], 'binding_sha256': e.CollectionBinding(**r['binding']).sha256, 'inventory_sha256': r['inventory_sha256']} for r in all_refs],
                'pretest_binding': e._phase_scope(binding), 'selection_raw_sha256': trust['selection']['sha256'], 'test_authorized': False}
            c.save(output/'receipt.json', receipt)
        else:
            c.save(output/'result.json', {'status': 'complete', 'rows': 2000, 'positive_examples': 1000,
                'absent_examples': 1000, 'arm_metrics': {arm: {} for arm in k.ARM_KEYS},
                'test_authorized': False, 'retention_decision': None})
        self.jobs.append({'name': f'fake-{len(self.jobs)}', 'terminal': True})
        name = 'inventory.json' if phase in e.PHASES else 'receipt.json' if phase == 'pretest-barrier' else 'result.json'
        raw = (output/name).read_bytes()
        metadata = None if phase in e.PHASES else json.loads(raw)
        if phase == 'pretest-barrier':
            metadata = {k: metadata[k] for k in ('programme_sha256','record_sha256','pretest_binding','selection_raw_sha256')} | {'bindings': metadata['authenticated_collections']}
        return {'raw_sha256': c.raw_hash(raw), 'metadata': metadata, 'private_directory': str(c.PRIVATE_ROOT/output.name)}


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.out = self.root/'study-synthetic-0001'
        external = {key: H for key in k.EXTERNAL_HASH_KEYS}
        self.programme = SimpleNamespace(sha256=H, external_hashes=tuple(external.items()),
            original_contextual=SimpleNamespace(**{'model_id': 'privoke-balanced', 'version': 'v0.3.0',
            'artifact_sha256': H, 'artifact_checksum': '8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c', 'parameter_fingerprint': H}),
            s0=SimpleNamespace(**identity(artifact('privoke-presence-balanced'))[0]),
            initialization_fingerprints=tuple((p, H) for p in ('efficient', 'balanced', 'quality')))
        def ref(name, raw):
            return c.exclusive(self.root/name, raw)
        self.inputs = {'source_revision': REV, 'images': {role: H for role in c.IMAGE_ROLES},
            'source_hashes': {role: H for role in e.SOURCE_ROLES}, 'control_binding_sha256': H,
            'trainer_contract_sha256': c.TRAINER_DIGEST, 's0_job_receipt': H,
            'programme': ref('programme.json', b'{}'), 'original': ref('original.json', artifact('privoke-balanced')),
            's0': ref('s0.json', artifact('privoke-presence-balanced')), 'compatibility': {},
            'datasets': {'validation': {'volume': 'synthetic-validation', 'file': 'validation.jsonl', 'sha256': H, 'keys_sha256': H, 'rows': 2000},
                         'fixtures': {'volume': 'synthetic-fixtures', 'file': 'fixtures.jsonl', 'sha256': H, 'keys_sha256': H, 'rows': 48}},
            'test_metadata': {'sha256': H, 'keys_sha256': H, 'rows': 2000, 'kind': 'new-prospective-reserved-test-v1'}, 'fits': {}}
        for key, filename in (('validation', 'val'), ('fixtures', 'fx')):
            r = ref(filename, b'synthetic scoring view')
            self.inputs['datasets'][key]['sha256'] = r['sha256']
        test = ref('test-data', b'new synthetic reserved test')
        self.inputs['test_metadata']['sha256'] = test['sha256']
        release = {'schema_version': 1, 'kind': 'new-prospective-reserved-test-release-v1', 'programme_sha256': H,
                   'test_metadata': self.inputs['test_metadata'], 'dataset': {'volume': 'synthetic-test', 'file': 'reserved-test.jsonl', 'sha256': test['sha256']}}
        self.release = ref('release.json', e.canonical(release))
        self.inputs['test_release_sha256'] = self.release['sha256']
        self.backend = FakeBackend(self.inputs, self.out)
        self.inputs['prior_catalog'] = {mid: identity(raw)[0] for mid, raw in self.backend.initial.items() if raw is not None}
        for arm in k.ARM_KEYS[1:]:
            train = ref(arm+'-train', b'explicit synthetic training only')
            manifest = ref(arm+'-manifest', b'{}')
            expected = {'arm_key': arm, 'programme_sha256': H, 'programme_input_raw_sha256': self.inputs['programme']['sha256'],
                'trainer_contract_sha256': c.TRAINER_DIGEST, 'source_revision': REV, 'train_raw_sha256': train['sha256'],
                'training_view_manifest_raw_sha256': manifest['sha256'], 'actual_training_image_id': 'sha256:'+H,
                'prepared_manifest_raw_sha256': H, 'initialization_fingerprints': dict(self.programme.initialization_fingerprints)}
            self.inputs['fits'][arm] = {'train': {'volume':'synthetic-train','file':'train.jsonl','sha256':train['sha256']}, 'manifest': {'volume':'synthetic-train','file':'training-manifest.json','sha256':manifest['sha256']}, 'expected': ref(arm+'-expected', e.canonical(expected))}
        self.identity_patch = patch.object(c, 'artifact_identity', identity)
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
        self.compatibility_patch = patch.object(c, 'validate_compatibility', return_value=H)
        self.compatibility_patch.start()
        self.addCleanup(self.compatibility_patch.stop)
        self.attestation_patch = patch.object(c, 'attest_controller')
        self.attestation_patch.start()
        self.addCleanup(self.attestation_patch.stop)

    def run_sequence(self, failure=None):
        self.backend.failure = failure
        return c.Controller(self.inputs, self.programme, self.out, self.backend,
                            test_release_file=self.release['file']).run()

    def test_full_actual_sequence_restores_raw_four_removes_six_and_test_order(self):
        with patch.object(c, 'read_reference', wraps=c.read_reference) as reads:
            result = self.run_sequence()
        self.assertEqual(result['status'], 'completed')
        self.assertTrue(result['restoration_verified'])
        self.assertEqual(self.backend.catalog, self.backend.initial)
        phases = [x[1] for x in self.backend.calls if x[0] == 'phase']
        self.assertEqual(phases.count('collect-validation'), 32)
        self.assertEqual(phases.count('rerun-validation'), 8)
        self.assertEqual(phases.count('collect-fixtures'), 8)
        self.assertEqual(phases.count('collect-test'), 8)
        captures = [x for x in self.backend.calls if x[0] == 'dataset-volume']
        self.assertEqual(captures, [('dataset-volume','validation','synthetic-validation'), ('dataset-volume','fixtures','synthetic-fixtures'), ('dataset-volume','test','synthetic-test')])
        self.assertFalse(any(call.args[0].get('file') in ('train.jsonl','validation.jsonl','fixtures.jsonl','reserved-test.jsonl') for call in reads.call_args_list))
        self.assertLess(phases.index('pretest-barrier'), phases.index('collect-test'))
        self.assertEqual({x[1] for x in self.backend.calls if x[0] == 'mutate' and x[2]}, set(c.SCRATCH_IDS))
        # S0/S1 switch at each of validation/rerun/fixture/test, then prior restore.
        self.assertEqual(sum(x[0:2] == ('mutate', 'privoke-presence-balanced') for x in self.backend.calls), 9)
        self.assertEqual(sum(call.args[0].get('file') == self.release['file'] for call in reads.call_args_list), 1)

    def test_incomplete_ineligible_fixture_failure_never_opens_release(self):
        for failure in ('incomplete', 'ineligible', 'fixture-loss'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                self.out = pathlib.Path(tmp)/'synthetic-sequence-0001'
                self.backend = FakeBackend(self.inputs, self.out)
                with patch.object(c, 'read_reference', wraps=c.read_reference) as reads:
                    result = self.run_sequence(failure)
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(result['test_released'])
                self.assertFalse(any(call.args[0].get('file') == self.release['file'] for call in reads.call_args_list))
                self.assertEqual(self.backend.catalog, self.backend.initial)

    def test_malformed_or_missing_barrier_binding_never_opens_release(self):
        for mutation in ('missing', 'malformed'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                self.out = pathlib.Path(tmp)/'synthetic-binding-0001'
                self.backend = FakeBackend(self.inputs, self.out)
                original_phase = self.backend.phase
                def phase(name, *args, **kwargs):
                    produced = original_phase(name, *args, **kwargs)
                    if name == 'pretest-barrier':
                        if mutation == 'missing':
                            produced['metadata']['bindings'].pop()
                        else:
                            produced['metadata']['bindings'][0]['binding_sha256'] = 'd'*64
                    return produced
                self.backend.phase = phase
                with patch.object(c, 'read_reference', wraps=c.read_reference) as reads:
                    result = self.run_sequence()
                self.assertEqual(result['status'], 'failed')
                self.assertFalse(result['test_released'])
                self.assertFalse(any(call.args[0].get('file') == self.release['file'] for call in reads.call_args_list))
                self.assertFalse(any(call[:2] == ('dataset-volume', 'test') for call in self.backend.calls))
                self.assertEqual(self.backend.catalog, self.backend.initial)

    def test_unknown_fit_stops_restore_and_all_subsequent_writes(self):
        result = self.run_sequence('fit-unknown')
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['restoration_verified'])
        self.assertEqual(result['unresolved_jobs'], ['fit-job'])
        self.assertFalse(any(x[0] == 'mutate' for x in self.backend.calls))

    def test_unknown_admin_publication_blocks_every_following_write(self):
        original_mutate = self.backend.mutate
        def mutate(model_id, raw, *, expected_raw_sha256):
            original_mutate(model_id, raw, expected_raw_sha256=expected_raw_sha256)
            self.backend.unresolved.add('admin-job')
            raise c.RemoteUnknown('publication observation unknown')
        self.backend.mutate = mutate
        result = self.run_sequence()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['restoration_verified'])
        self.assertEqual(result['unresolved_jobs'], ['admin-job'])
        self.assertEqual(sum(x[0] == 'mutate' for x in self.backend.calls), 1)
        self.assertFalse(any(x == ('phase', 'collect-validation') for x in self.backend.calls))

    def test_unknown_model_id_cannot_be_installed(self):
        controller = c.Controller(self.inputs, self.programme, self.out, self.backend,
                                  test_release_file=self.release['file'])
        controller.backups = dict(self.backend.initial)
        with self.assertRaises(c.ControllerError):
            controller.install(artifact('latest'))
        self.assertFalse(any(x[0] == 'mutate' for x in self.backend.calls))

    def test_primary_scoring_failure_preserved_and_known_safe_restore(self):
        result = self.run_sequence('rerun-validation')
        self.assertEqual(result['primary_failure']['error_type'], 'ControllerError')
        self.assertTrue(result['restoration_verified'])
        self.assertFalse(result['test_released'])
        self.assertEqual(self.backend.catalog, self.backend.initial)

    def test_unknown_restore_halts_remaining_mutations(self):
        original_phase = self.backend.phase
        def phase(*args, **kwargs):
            if args[0] == 'rerun-validation':
                self.backend.failure = 'restore-unknown'
                raise c.ControllerError('synthetic primary')
            return original_phase(*args, **kwargs)
        self.backend.phase = phase
        result = self.run_sequence()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['primary_failure']['error_type'], 'ControllerError')
        self.assertFalse(result['restoration_verified'])
        self.assertEqual(result['unresolved_jobs'], ['restore-job'])

    def test_absence_probe_failure_is_overall_failed(self):
        result = self.run_sequence('absence')
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['restoration_verified'])
        self.assertTrue(result['restoration_failures'])

    def test_foreign_collision_never_deleted(self):
        original_phase = self.backend.phase
        def phase(*args, **kwargs):
            if args[0] == 'select-validation':
                self.backend.catalog[c.SCRATCH_IDS[-1]] = b'foreign-write'
                raise c.ControllerError('synthetic primary')
            return original_phase(*args, **kwargs)
        self.backend.phase = phase
        result = self.run_sequence()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.backend.catalog[c.SCRATCH_IDS[-1]], b'foreign-write')
        self.assertFalse(any(x == ('mutate', c.SCRATCH_IDS[-1], True) for x in self.backend.calls))

    def test_existing_scratch_entry_stops_before_fit(self):
        self.backend.catalog[c.SCRATCH_IDS[0]] = b'foreign-present'
        result = self.run_sequence()
        self.assertFalse(any(x[0] == 'fit' for x in self.backend.calls))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.backend.catalog[c.SCRATCH_IDS[0]], b'foreign-present')

    def test_output_reuse_refused_and_old_bytes_preserved(self):
        self.out.mkdir()
        (self.out/'prior').write_bytes(b'preserve')
        with self.assertRaises(c.ControllerError):
            self.run_sequence()
        self.assertEqual((self.out/'prior').read_bytes(), b'preserve')
        self.assertEqual(self.backend.calls, [])

    def test_wrong_reserved_test_release_stops_before_data_capture(self):
        changed = json.loads(pathlib.Path(self.release['file']).read_bytes())
        changed['kind'] = 'original-locked-final'
        raw = e.canonical(changed)
        pathlib.Path(self.release['file']).write_bytes(raw)
        self.inputs['test_release_sha256'] = c.raw_hash(raw)
        result = self.run_sequence()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['test_released'])
        self.assertFalse((self.out/'evidence/reserved-test.jsonl').exists())
        self.assertFalse(any(x == ('phase', 'collect-test') for x in self.backend.calls))

    def test_frozen_controls_change_blocks_test_release(self):
        original = self.backend.controls
        def controls():
            # Preflight and pre-validation pass, actual pretest check fails.
            previous = sum(x[0] == 'controls' for x in self.backend.calls)
            result = original()
            return result if previous < 2 else {'changed': H}
        self.backend.controls = controls
        with patch.object(c, 'read_reference', wraps=c.read_reference) as reads:
            result = self.run_sequence()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['test_released'])
        self.assertFalse(any(call.args[0].get('file') == self.release['file'] for call in reads.call_args_list))


class PrivateVolumeTests(unittest.TestCase):
    def test_actual_fit_backend_uses_train_only_volume_and_bounded_initializer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            backend = c.DockerBackend(root, {'images':{r:H for r in c.IMAGE_ROLES},'source_revision':REV})
            backend.create_volume = lambda role: 'private-fit-output'
            expected = c.exclusive(root/'expected.json', b'{}')
            refs = {'train':{'volume':'private-training','file':'train.jsonl','sha256':H},
                'manifest':{'volume':'private-training','file':'training-manifest.json','sha256':H}, 'expected':expected}
            calls = []
            def job(service, args, **kwargs):
                calls.append((service,args,kwargs))
                if service == 'in-house-fit-job':
                    return e.canonical({'manifest_sha256':H}), H
                return b'',H
            backend.job = job
            backend.helper = lambda request, **kwargs: {'kind':'private-fit-export-v1','private_manifest_raw_sha256':H,
                'manifest':{'checkpoint_records':[]},'artifacts':{}}
            backend.fit('E-H',refs,root/'export')
            self.assertEqual([x[0] for x in calls],['in-house-data-permissions','in-house-fit-job'])
            init = calls[0]
            compile(init[1][2],'<permissions>','exec')
            self.assertEqual(json.loads(init[1][3]),{'train.jsonl':H,'training-manifest.json':H})
            fit = calls[1]
            compile(fit[1][2],'<fit-wrapper>','exec')
            self.assertIn('/fit-output/arm/run-manifest.json', fit[1][2])
            self.assertEqual(fit[2]['mounts'][0],('volume:private-training','/train',True))
            self.assertEqual(fit[2]['mounts'][1],('volume:private-fit-output','/fit-output',False))
            self.assertEqual(fit[2]['timeout'],7200)
            self.assertFalse(any('test' in str(v) or 'validation' in str(v) for v in fit[2]['mounts']))

    def test_fit_reader_uses_same_uid_service_and_only_readonly_fit_and_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = c.DockerBackend(pathlib.Path(tmp), {'images': {r:H for r in c.IMAGE_ROLES},
                'controller_sha256': H, 'cli_sha256': H})
            calls = []
            backend.private_store = lambda: self.fail('Fit reader must not mount/write evidence volume.')
            def job(service, args, **kwargs):
                calls.append((service, args, kwargs))
                request_file = pathlib.Path(kwargs['mounts'][0][0])
                self.assertEqual(request_file.stat().st_mode & 0o777, 0o444)
                return e.canonical({'kind': 'synthetic-reader-result'}), H
            backend.job = job
            backend.helper({'mode':'read-fit', 'manifest_sha256':H, 'arm':'S1'},
                           mounts=(('volume:synthetic-private-fit', str(c.FIT_ROOT), True),))
            service, args, options = calls[0]
            self.assertEqual(service, 'in-house-fit-reader')
            self.assertEqual(options['mounts'][1:], (('volume:synthetic-private-fit', str(c.FIT_ROOT), True),))
            self.assertEqual(options['mounts'][0][1:], ('/request.json', True))
            with self.assertRaises(c.ControllerError):
                backend.helper({'mode':'read-fit', 'manifest_sha256':H, 'arm':'S1'},
                               mounts=(('volume:synthetic-private-fit', str(c.FIT_ROOT), False),))

    def test_actual_phase_backend_keeps_raw_evidence_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            backend = c.DockerBackend(root, {'images':{r:H for r in c.IMAGE_ROLES}})
            backend.private_store = lambda:'private-raw-evidence'
            calls = []
            def job(service,args,**kwargs):
                calls.append((service,args,kwargs)); return e.canonical({'raw_sha256':H}),H
            backend.job = job
            backend.helper = lambda request, **kwargs: {'kind':'private-phase-v1','phase':'collect-validation','raw_sha256':H,'metadata':None}
            result = backend.phase('collect-validation',{'synthetic':'metadata only'},root/'collect-validation-S0-0',root/'evidence')
            compile(calls[0][1][2],'<evidence-wrapper>','exec')
            self.assertEqual(calls[0][2]['mounts'][1],('volume:private-raw-evidence',str(c.PRIVATE_ROOT),False))
            self.assertEqual(result['private_directory'],str(c.PRIVATE_ROOT/'collect-validation-S0-0'))
            self.assertFalse((root/'collect-validation-S0-0').exists())

    def test_actual_backend_capture_mounts_only_named_phase_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = c.DockerBackend(pathlib.Path(tmp), {'images': {r: H for r in c.IMAGE_ROLES}})
            seen = []
            def helper(request, *, mounts):
                seen.append((request, mounts))
                return {'kind':'private-capture-v1', 'file':str(c.PRIVATE_ROOT/'datasets'/'validation.jsonl'), 'sha256':H}
            backend.helper = helper
            result = backend.capture_dataset({'volume':'private-validation-01','file':'validation.jsonl','sha256':H}, role='validation')
            self.assertEqual(seen[0][1], (('volume:private-validation-01', '/phase-data', True),))
            self.assertEqual(seen[0][0]['inventory'], {'validation.jsonl':H})
            self.assertEqual(result['file'], str(c.PRIVATE_ROOT/'datasets'/'validation.jsonl'))
            with self.assertRaises((c.ControllerError,e.StudyEvidenceError)):
                backend.capture_dataset({'volume':'private-validation-01','file':'reserved-test.jsonl','sha256':H}, role='validation')

    def test_exact_inventory_before_any_decoder_and_foreign_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            raw = b'opaque synthetic rows; never decoded'
            (root/'validation.jsonl').write_bytes(raw)
            self.assertEqual(c.verify_volume_inventory({'validation.jsonl':c.raw_hash(raw)}, root=root), {'validation.jsonl':raw})
            (root/'reserved-test.jsonl').write_bytes(b'forbidden earlier mount')
            with self.assertRaises((c.ControllerError,e.StudyEvidenceError)):
                c.verify_volume_inventory({'validation.jsonl':c.raw_hash(raw)}, root=root)

    def test_metadata_reader_cannot_export_row_fields_or_unrecognized_phases(self):
        with self.assertRaises((c.ControllerError,e.StudyEvidenceError)):
            c.phase_metadata('collect-test', b'{}', c.raw_hash(b'{}'))
        value = {'schema_version':1,'status':'complete','rows':2000,'positive_examples':1000,'absent_examples':1000,
            'component_count':400,'positive_components':200,'negative_components':200,'mixed_label_components':0,
            'arm_metrics':{'S0':{'text':'PRIVATE_MARKER'}},'paired_component_bootstrap':{},'test_authorized':False,'retention_decision':None}
        raw = e.canonical(value)
        with self.assertRaises((c.ControllerError,e.StudyEvidenceError)) as error:
            c.phase_metadata('analyze-test', raw, c.raw_hash(raw))
        self.assertNotIn('PRIVATE_MARKER', str(error.exception))

    def test_unknown_reader_blocks_real_helper_and_every_later_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = c.DockerBackend(pathlib.Path(tmp), {'images':{r:H for r in c.IMAGE_ROLES},'controller_sha256':H,'cli_sha256':H})
            backend.private_store = lambda: 'private-evidence'
            calls = []
            def job(*args, **kwargs):
                calls.append((args,kwargs)); backend.unresolved.add('unknown-reader'); raise c.RemoteUnknown('unknown')
            backend.job = job
            with self.assertRaises(c.RemoteUnknown):
                backend.helper({'mode':'read-phase','phase':'select-validation','directory':'selection','expected_sha256':H})
            with self.assertRaises(c.RemoteUnknown):
                backend.safe()
            self.assertEqual(len(calls),1)
            self.assertIn(('volume:private-evidence',str(c.PRIVATE_ROOT),False), calls[0][1]['mounts'])



@unittest.skipUnless(sys.platform == 'linux' and getattr(os, 'geteuid', lambda: -1)() == 0,
                     'requires Linux root for synthetic ownership and capability-drop checks')
class FitReaderPermissionTests(unittest.TestCase):
    def test_actual_private_helper_reads_fitter_filename_without_relaxing_permissions(self):
        inputs = {key:H for key in ('expected_inputs_raw', 'training_view_manifest_raw', 'train_raw',
            'original_train_prefix_raw', 'prepared_manifest_raw', 'programme_input_raw', 'programme',
            'allocation_receipt', 'reviewed_labels_receipt', 'trainer_contract', 'dependency_lock')}
        value = {'status':'complete', 'arm_key':'S1', 'checkpoint_count':0, 'checkpoint_records':[],
            'actual_training_image_id':'sha256:'+H, 'test_scored':False, 'validation_read':False,
            'inputs_sha256':inputs, 'private_training_marker':'DO_NOT_EXPORT_SYNTHETIC_MARKER'}
        script = """
import ctypes,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from privoke_eval import in_house_study_controller as c
root=Path(sys.argv[2]);mode=sys.argv[4]
if mode=='legacy-root':
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 data=(Data*2)();header=Header(0x20080522,0)
 if ctypes.CDLL(None,use_errno=True).capset(ctypes.byref(header),data)!=0:raise RuntimeError('Synthetic capability drop failed.')
 try:(root/'arm'/'run-manifest.json').read_bytes()
 except PermissionError:print('legacy-root-denied');raise SystemExit(0)
 raise RuntimeError('Capability-free root unexpectedly traversed private UID65534 output.')
os.setgroups([]);os.setgid(65534);os.setuid(65534)
c.FIT_ROOT=root;os.environ['PRIVOKE_EVAL_IN_CONTAINER']='true'
try:result=c.private_helper({'mode':'read-fit','manifest_sha256':sys.argv[3],'arm':'S1'})
except Exception:result=None
if result is not None:
 assert result['manifest']['status']=='complete'
 assert 'private_training_marker' not in result['manifest']
permissions=[(p.lstat().st_uid,p.lstat().st_mode&0o777) for p in (root,root/'arm',root/'arm'/'run-manifest.json')]
print(json.dumps({'kind':'reader-rejected' if result is None else result['kind'],'uid':os.geteuid(),'permissions':permissions}))
raise SystemExit(2 if result is None else 0)
"""
        for mutation in (None, 'mode', 'owner', 'schema'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                base = pathlib.Path(tmp)
                root = base/'fit-output'
                arm = root/'arm'
                arm.mkdir(parents=True, mode=0o700)
                root.chmod(0o700)
                manifest = arm/'run-manifest.json'
                payload = dict(value)
                if mutation == 'schema':
                    payload['status'] = 'failed'
                raw = e.canonical(payload)
                manifest.write_bytes(raw)
                manifest.chmod(0o600)
                if mutation == 'mode':
                    manifest.chmod(0o644)
                # Deepest first keeps setup possible without DAC capabilities.
                for path in (manifest, arm, root, base):
                    os.chown(path, 0 if mutation == 'owner' and path == manifest else 65534, 65534)
                expected_permissions = [[65534,0o700],[65534,0o700],
                    [0 if mutation == 'owner' else 65534,0o644 if mutation == 'mode' else 0o600]]
                try:
                    arguments = [sys.executable, '-B', '-c', script, str(EVALUATION), str(root), c.raw_hash(raw)]
                    if mutation is None:
                        negative = subprocess.run([*arguments, 'legacy-root'], capture_output=True, text=True)
                        self.assertEqual(negative.returncode, 0, negative.stderr)
                        self.assertEqual(negative.stdout.strip(), 'legacy-root-denied')
                    result = subprocess.run([*arguments, 'same-uid'], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0 if mutation is None else 2, result.stderr)
                    self.assertNotIn('DO_NOT_EXPORT_SYNTHETIC_MARKER', result.stdout+result.stderr)
                    self.assertEqual(json.loads(result.stdout), {'kind':'private-fit-export-v1' if mutation is None else 'reader-rejected',
                        'uid':65534,'permissions':expected_permissions})
                finally:
                    # Reclaim only these synthetic fixture objects for TempDirectory cleanup.
                    for path in (base, root, arm, manifest):
                        os.chown(path, 0, 0)


class CompatibilityTests(unittest.TestCase):
    def test_external_raw_and_named_terminal_proofs_required_for_all_six(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            inputs = {'source_revision': REV, 'images': {r: H for r in c.IMAGE_ROLES},
                      'effective_configuration': H, 'source_hashes': {r: H for r in e.SOURCE_ROLES},
                      'prior_catalog': {mid: {'artifact_sha256': H} for mid in c.LEGACY_IDS}}
            request = c.exclusive(root/'request.json', b'bounded synthetic probe operation')
            record = {'name': 'synthetic-terminal-job', 'container_id': 'c'*64, 'image_id': 'sha256:'+H,
                      'exit_code': 0, 'terminal': True, 'request_sha256': request['sha256']}
            job = c.save(root/'job.json', record)
            catalog = {mid: H for mid in c.LEGACY_IDS} | {mid: None for mid in c.SCRATCH_IDS}
            receipt = {'schema_version': 1, 'kind': 'root-accepted-scratch-live-compatibility-v1',
                'source_revision': REV, 'images': {r: H for r in c.IMAGE_ROLES[:2]}, 'effective_configuration_sha256': H,
                'source_hashes': inputs['source_hashes'], 'protocol_sha256': dict(k.PIN_ITEMS)['protocol'],
                'before_catalog': catalog, 'after_catalog': catalog, 'scratch': {}}
            for mid in c.SCRATCH_IDS:
                i = identity(artifact(mid))[0]
                receipt['scratch'][mid] = {'identity': i, 'streaming_identity': i, 'runtime_identity': i,
                    'absent_after_removal': True, 'jobs': {op: {**{key: record[key] for key in ('name', 'container_id', 'image_id', 'exit_code')},
                        'operation': op, 'request': request, 'receipt': job} for op in ('install', 'probe', 'remove', 'absence')}}
            backend = SimpleNamespace(verify_external_job=lambda proof: None)
            # Public validator, genuine hash-before-parse references, no fabricated
            # fixture identities escape this synthetic compatibility test.
            for number, mutation in enumerate((None, 'missing-id', 'config', 'job', 'raw-request', 'stream-identity')):
                value = json.loads(e.canonical(receipt))
                if mutation == 'missing-id':
                    value['scratch'].pop(c.SCRATCH_IDS[-1])
                elif mutation == 'config':
                    value['effective_configuration_sha256'] = 'd'*64
                elif mutation == 'job':
                    value['scratch'][c.SCRATCH_IDS[0]]['jobs']['install']['exit_code'] = 1
                elif mutation == 'raw-request':
                    value['scratch'][c.SCRATCH_IDS[0]]['jobs']['install']['request']['sha256'] = 'd'*64
                elif mutation == 'stream-identity':
                    value['scratch'][c.SCRATCH_IDS[0]]['streaming_identity']['version'] = 'v9.0.0'
                ref = c.save(root/f'compat-{number}.json', value)
                if mutation is None:
                    self.assertEqual(c.validate_compatibility(ref, inputs, backend), ref['sha256'])
                else:
                    with self.assertRaises((c.ControllerError, e.StudyEvidenceError)):
                        c.validate_compatibility(ref, inputs, backend)


class DockerJobTests(unittest.TestCase):
    def job(self, *, wait_timeout=False, running=False, launch_timeout=False, exit_code=0):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        output = pathlib.Path(tmp.name)
        calls = []
        cid = 'c'*64
        def runner(args, **kwargs):
            calls.append(args)
            if 'run' in args:
                if launch_timeout:
                    raise subprocess.TimeoutExpired(args, 120)
                raw = cid.encode()
            elif args[1] == 'inspect':
                raw = e.canonical([{'Id': cid, 'Image': 'sha256:'+H,
                    'Config': {'Cmd': ['python', 'synthetic.py'], 'Labels': {'com.docker.compose.service': 'in-house-evidence-job'}},
                    'HostConfig': {'ReadonlyRootfs': True, 'Memory': 4*1024**3, 'NanoCpus': 4_000_000_000}, 'Mounts': [],
                    'State': {'Running': running, 'Status': 'running' if running else 'exited', 'ExitCode': exit_code}}])
            elif args[1] == 'wait':
                if wait_timeout:
                    raise subprocess.TimeoutExpired(args, 7200)
                raw = str(exit_code).encode()
            else:
                raw = b'synthetic terminal logs'
            return SimpleNamespace(returncode=0, stdout=raw, stderr=b'')
        backend = c.DockerBackend(output, {'images': {r: H for r in c.IMAGE_ROLES}}, runner=runner)
        return backend, calls

    def test_actual_fit_jobs_reject_user_or_security_drift(self):
        for service, drift in itertools.product(('in-house-fit-reader', 'in-house-fit-job'),
                (None, 'user', 'cap-add', 'cap-drop', 'security', 'network')):
            with self.subTest(service=service, drift=drift):
                backend, _ = self.job()
                original = backend.runner
                def runner(args, **kwargs):
                    result = original(args, **kwargs)
                    if args[1] == 'inspect':
                        state = json.loads(result.stdout)
                        item = state[0]
                        item['Config'].update(User='0:0' if drift == 'user' else '65534:65534',
                            Labels={'com.docker.compose.service':service})
                        item['HostConfig'].update(NetworkMode='default' if drift == 'network' else 'none',
                            CapDrop=[] if drift == 'cap-drop' else ['ALL'],
                            CapAdd=['DAC_OVERRIDE'] if drift == 'cap-add' else None,
                            SecurityOpt=[] if drift == 'security' else ['no-new-privileges:true'])
                        result.stdout = e.canonical(state)
                    return result
                backend.runner = runner
                if drift is None:
                    backend.job(service, ['python','synthetic.py'], request_sha256=H)
                else:
                    with self.assertRaises(c.ControllerError):
                        backend.job(service, ['python','synthetic.py'], request_sha256=H)
                self.assertFalse(backend.unresolved)

    def test_actual_job_rejects_wrong_named_volume_despite_matching_destination(self):
        for actual_name in ('private-validation','foreign-volume'):
            backend, calls = self.job()
            original = backend.runner
            def runner(args, **kwargs):
                result = original(args, **kwargs)
                if args[1] == 'inspect':
                    state = json.loads(result.stdout)
                    state[0]['Mounts'] = [{'Type':'volume','Name':actual_name,'Destination':'/phase-data','RW':False}]
                    result.stdout = e.canonical(state)
                return result
            backend.runner = runner
            if actual_name == 'private-validation':
                backend.job('in-house-evidence-job',['python','synthetic.py'],mounts=(('volume:private-validation','/phase-data',True),),request_sha256=H)
                self.assertTrue(any('private-validation:/phase-data:ro' in argv for argv in calls))
            else:
                with self.assertRaises(c.ControllerError):
                    backend.job('in-house-evidence-job',['python','synthetic.py'],mounts=(('volume:private-validation','/phase-data',True),),request_sha256=H)
                self.assertFalse(backend.unresolved)

    def test_external_compatibility_job_is_rechecked_before_later_mutation(self):
        backend, _ = self.job()
        state = {'Id':'c'*64,'Image':'sha256:'+H,'State':{'Running':False,'Status':'exited','ExitCode':0}}
        backend.inspect = lambda name: state
        proof = {'name':'external-compatibility','container_id':'c'*64,'image_id':'sha256:'+H,'exit_code':0,
            'request':{'file':'opaque-operation','sha256':H},'receipt':{'file':'opaque-receipt','sha256':H}}
        backend.verify_external_job(proof)
        self.assertEqual(len(backend.jobs),1)
        state['State']['Running'] = True
        with self.assertRaises(c.RemoteUnknown):
            backend.quiescent()
        with self.assertRaises(c.RemoteUnknown):
            backend.safe()

    def test_real_job_method_inspects_image_terminal_and_logs(self):
        backend, calls = self.job()
        raw, receipt = backend.job('in-house-evidence-job', ['python', 'synthetic.py'], request_sha256=H)
        self.assertEqual(raw, b'synthetic terminal logs')
        self.assertEqual(len(receipt), 64)
        self.assertFalse(backend.unresolved)
        self.assertTrue(backend.jobs[0]['terminal'])
        self.assertFalse(any('rm' in argv or 'restart' in argv for argv in calls))

    def test_launch_and_wait_timeout_running_never_removes_or_relaunches(self):
        for options in ({'wait_timeout': True, 'running': True}, {'launch_timeout': True, 'running': True}):
            with self.subTest(options=options):
                backend, calls = self.job(**options)
                with self.assertRaises(c.RemoteUnknown):
                    backend.job('in-house-evidence-job', ['python', 'synthetic.py'], request_sha256=H)
                with self.assertRaises(c.RemoteUnknown):
                    backend.safe()
                self.assertEqual(sum('run' in argv for argv in calls), 1)
                self.assertFalse(any('rm' in argv or 'restart' in argv for argv in calls))

    def test_timeout_with_fresh_known_terminal_is_failure_but_safe_restore(self):
        backend, _ = self.job(wait_timeout=True)
        with self.assertRaises(c.ControllerError):
            backend.job('in-house-evidence-job', ['python', 'synthetic.py'], request_sha256=H)
        self.assertFalse(backend.unresolved)
        backend.safe()
        self.assertTrue(backend.jobs[0]['terminal'])


if __name__ == '__main__':
    unittest.main()
