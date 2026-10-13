"""Nonmodel rehearsal contracts, fail-closed replay and bounded wire publication."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_taxonomy_coverage import fixture, Context, Aborted
from config import FuzzerConfig
from fuzzer_service import FuzzerTrainingService
from prompt_generation import anchor_rehearsal as rehearsal, taxonomy_coverage as legacy
from prompt_generation.generator import generate_training_partition
from training.trainer import iter_training_examples, train_parameter_batch
from training.types import BatchTrainingConfig, BatchTrainingUpdate
from training.evidence import persist_cycle_evidence
from training.parameter_updates import emit_training_update
from training.full_adam_evidence import REHEARSAL_KEY, REHEARSAL_FIELDS, WEIGHT_FIELDS, GATE_KEY
from privoke_model.full_adam import POLICY, ELIGIBILITY, OBJECTIVE, CONFIG, canonical, TRACE_KEY
from privoke.v1 import parameters_pb2 as pb, runtime_pb2


def admission():
    return {'expected_contextual_training_objective': OBJECTIVE, 'expected_contextual_training_optimizer': POLICY,
        'expected_contextual_candidate_eligibility': ELIGIBILITY, 'expected_full_projected_adam_config_v1': canonical(CONFIG),
        'expected_contextual_training_scope': 'full_encoder'}


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        self.payload = legacy.canonical_bytes(fixture())
        self.dataset = legacy.load_snapshot(self.payload)
        pin = patch.object(rehearsal, 'DATASET_SHA256', self.dataset.sha256)
        pin.start(); self.addCleanup(pin.stop)
        self.manifest = rehearsal.load_snapshot(rehearsal.prepare_manifest(self.dataset), self.dataset)
        self.config = BatchTrainingConfig(seed=42, learning_rate=.003)
        self.originals, self.guard = rehearsal.generate_partition(self.dataset, self.manifest, 42)

    def test_exact_fixed_table_counts_all_families_and_unchanged_guard(self):
        ids = {r.metadata['taxonomy_row_id'] for r in self.originals}
        for seed in (0, 1, 42, 1337, 2026):
            rows, guard = rehearsal.generate_partition(self.dataset, self.manifest, seed)
            self.assertEqual(ids, {r.metadata['taxonomy_row_id'] for r in rows})
            self.assertEqual(guard, legacy.generate_partition(self.dataset, seed)[1])
            self.assertEqual((rows, guard), rehearsal.generate_partition(self.dataset, self.manifest, seed))
            self.assertEqual(len({r.metadata['group_id'] for r in rows}), 20)
            for role, family in (('anchor', 0), ('complement', 1)):
                half = [r for r in rows if r.metadata['rehearsal_role'] == role]
                self.assertEqual(legacy._counts(half)[:2], ({'S0': 4, 'S1': 2, 'S2': 3, 'S3': 7}, {v: 2 for v in legacy.Visibility.__members__}))
                actual = {r.metadata['primary_category']: r.expected_classification.visibility().name for r in half if r.metadata['control'] == 'actual'}
                self.assertEqual(actual, {c: vs[family] for c, vs in rehearsal.ACTUAL.items()})
                self.assertTrue(all(r.metadata['group_id'].endswith(str(family)) for r in half))
        expanded = list(iter_training_examples(self.originals, (), self.config))
        audit = rehearsal.audit_expanded(self.dataset, self.manifest, self.originals, expanded, self.guard, self.config)
        self.assertEqual(audit['sampling_expanded_rows'], '64')
        self.assertEqual(int(audit['sampling_expanded_unique_texts']), len({r.text for r in expanded}))
        self.assertLess(int(audit['sampling_expanded_unique_texts']), 64)
        self.assertEqual(audit['sampling_expanded_wire_sha256'], rehearsal.wire_commitment(rehearsal.training_wire_rows(expanded)))

    def test_manifest_rejects_noncanonical_membership_targets_partition_counts_and_weights(self):
        value = json.loads(self.manifest.payload)
        for mutate in (lambda v: v.update(schema=2), lambda v: v.update(originals=31),
                       lambda v: v['bank'][0].update(partition='guard'), lambda v: v['bank'][0].update(weight=.35),
                       lambda v: v['bank'][0].update(packed=0), lambda v: v['bank'][0].update(id=self.guard[0].metadata['taxonomy_row_id']),
                       lambda v: v['weights'].update(anchor=2), lambda v: v.update(fit_release=True)):
            altered = copy.deepcopy(value); mutate(altered)
            with self.assertRaises(ValueError): rehearsal.load_snapshot(legacy.canonical_bytes(altered), self.dataset)
        with self.assertRaises(ValueError): rehearsal.load_snapshot(self.manifest.payload + b' ', self.dataset)
        with self.assertRaises(ValueError): rehearsal.prepare_manifest(replace(self.dataset, sha256='0'*64))

    def test_cross_original_transform_collision_is_rejected_even_with_equal_labels(self):
        source = rehearsal.bank(self.dataset)
        clean = [r for r in source if r.metadata['control'] == 'fiction' and r.expected_classification.visibility().name == 'P0']
        for first, second in ((source[0], source[1]), (clean[0], clean[1])):
            changed = list(self.dataset.rows)
            index = next(i for i, r in enumerate(changed) if r.metadata['taxonomy_row_id'] == second.metadata['taxonomy_row_id'])
            changed[index] = replace(changed[index], text='Please review this prompt: ' + first.text)
            with self.assertRaisesRegex(ValueError, 'collision'):
                rehearsal.bank(replace(self.dataset, rows=tuple(changed)))

    def test_dispatch_and_direct_trainer_reject_fallback_head_extra_replay_and_tampering(self):
        with self.assertRaises(ValueError): generate_training_partition(32,16,42,sampling_strategy=rehearsal.STRATEGY,taxonomy_dataset=self.dataset)
        runtime = type('Runtime', (), {'compute_underlying_gradients': lambda *a, **kw: self.fail('no model RPC')})()
        kwargs = dict(model_id='privoke-balanced', new_examples=self.originals, heldout_examples=self.guard,
            config=self.config, runtime_client=runtime, taxonomy_dataset=self.dataset, rehearsal_manifest=self.manifest,
            training_scope='full_encoder', expected_objective=OBJECTIVE, expected_optimizer=POLICY,
            expected_candidate_eligibility=ELIGIBILITY, expected_optimizer_config=canonical(CONFIG), expected_training_scope='full_encoder')
        for changed in ({'training_scope': 'heads'}, {'rehearsal_manifest': None}, {'golden_examples': self.originals[:1]},
                        {'expected_optimizer': None}, {'config': replace(self.config, new_example_weight=.5)},
                        {'config': replace(self.config, transformations_per_example=0)},
                        {'new_examples': [replace(self.originals[0], weight=2), *self.originals[1:]]}):
            with self.assertRaises(ValueError): train_parameter_batch(**{**kwargs, **changed})
        with patch('training.trainer.random_pii_transform',return_value='invented out of superset'), self.assertRaisesRegex(ValueError,'superset'):
            train_parameter_batch(**kwargs)

    def test_actual_publication_constructor_restores_exact_strings_and_enforces_limits(self):
        expanded = list(iter_training_examples(self.originals, (), self.config))
        audit = rehearsal.audit_expanded(self.dataset,self.manifest,self.originals,expanded,self.guard,self.config)
        wire = runtime_pb2.ComputeSemanticGradientsRequest(request_id='req',model_id='privoke-balanced',
            layers=[runtime_pb2.DETECTION_LAYER_SEMANTIC], examples=rehearsal.training_wire_rows(expanded),
            heldout_examples=[runtime_pb2.RuntimeTrainingExample(text=r.text,has_target=True,weight=r.weight,
                target=runtime_pb2.RuntimeClassification(packed=r.expected_packed_classification)) for r in self.guard])
        gate = {'minimum_exact_match_rate': 0}
        meta = {**audit, 'contextual_training_optimizer':POLICY, 'training_scope':'full_encoder',
            'base_parameter_fingerprint':'b'*64, TRACE_KEY:'immutable detailed mock trace', GATE_KEY:canonical(gate)}
        metrics = {k: .000000123 for k in WEIGHT_FIELDS}
        evidence = {'request_protobuf_base64':base64.b64encode(wire.SerializeToString(deterministic=True)).decode()}
        update = BatchTrainingUpdate('privoke-balanced','v1',{}, {}, metrics,meta,evidence)
        request = pb.FuzzerTrainingRequest(request_id='req',source_id='test')
        extra = {'request_source_id':'test','request_id':'req','training_request_fingerprint':'d'*64}
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,{'PRIVOKE_FUZZER_DUMP_DIR':directory}), \
             patch('training.full_adam_evidence.validate_candidate_route',return_value=True), \
             patch('training.full_adam_evidence.gate_summary',return_value=gate), \
             patch('fuzzer_service.validate_training_update'), patch('training.parameter_updates.emit_parameter_update') as emit:
            evidence['rehearsal_audit'] = rehearsal.persist_audit(self.manifest,audit)
            persist_cycle_evidence(request,update,'full_encoder',gate_passed=True)
            emit_training_update('mock','fuzzer',update,extra)
            actual = emit.call_args.args[1].metadata
            self.assertLessEqual(len(actual),64)
            self.assertTrue(all(len(v.encode()) <= 2048 for v in actual.values()))
            restored = json.loads(actual[REHEARSAL_KEY])['fields']
            self.assertEqual(restored,{k:audit[k] for k in REHEARSAL_FIELDS})
            self.assertEqual(actual[rehearsal.BANK_KEY],self.manifest.bank_sha256)
            self.assertEqual(actual[rehearsal.MANIFEST_KEY],self.manifest.sha256)
            self.assertIn(TRACE_KEY,update.metadata)
            emit.reset_mock()
            wire.examples[0].weight=2
            bad = replace(update,execution_evidence={**evidence,'request_protobuf_base64':base64.b64encode(wire.SerializeToString(deterministic=True)).decode()})
            persist_cycle_evidence(request,bad,'full_encoder',gate_passed=True)
            with self.assertRaises(ValueError): emit_training_update('mock','fuzzer',bad,extra)
            emit.assert_not_called()


class RehearsalReplayTests(unittest.TestCase):
    def setUp(self):
        RehearsalTests.setUp(self)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.dataset_path = root/'dataset.json'; self.dataset_path.write_bytes(self.payload)
        self.manifest_path = root/'manifest.json'; self.manifest_path.write_bytes(self.manifest.payload)
        env = patch.dict(os.environ,{'PRIVOKE_FUZZER_DUMP_DIR':str(root/'durable')})
        env.start(); self.addCleanup(env.stop)
        self.service_config = replace(FuzzerConfig.from_env(),model_id='privoke-balanced', prompt_dataset_path=str(self.dataset_path),
            rehearsal_manifest_path=str(self.manifest_path), underlying_training_learning_rate=.003)
        self.request = pb.FuzzerTrainingRequest(request_id='same',source_id='test',prompt_count=32,seed=42,model_id='privoke-balanced',
            metadata={**admission(),'contextual_sampling_strategy':rehearsal.STRATEGY,'taxonomy_dataset_sha256':self.dataset.sha256,
                rehearsal.BANK_KEY:self.manifest.bank_sha256,rehearsal.MANIFEST_KEY:self.manifest.sha256})
        self.previous = pb.ParameterUpdateStatus(found=True,base_version='v1',prompts_generated=32,
            ack=pb.ParameterUpdateAck(accepted=True,model_id='privoke-balanced',applied_version='v2'))

    def test_replay_and_conflicts_are_validated_before_lookup_or_compute(self):
        service=FuzzerTrainingService(self.service_config)
        with patch.object(service,'_previous_update_for_fingerprint',return_value=self.previous) as lookup, patch.object(service,'_train') as train:
            self.assertTrue(service.RunUnderlyingTrainingCycle(self.request,Context()).accepted)
            fingerprint=lookup.call_args.args[3]
            self.assertTrue(service.RunUnderlyingTrainingCycle(self.request,Context()).accepted)
            self.assertEqual(fingerprint,lookup.call_args.args[3]); train.assert_not_called()
        for changed in (replace(self.service_config,minimum_exact_match_rate=.1),replace(self.service_config,seed=2026)):
            # Explicit request seed wins; changing a dormant default is compatible.
            if changed.seed != self.service_config.seed: continue
            service=FuzzerTrainingService(changed)
            with patch.object(service,'_previous_update_for_fingerprint') as lookup,self.assertRaisesRegex(Aborted,'different effective'):
                service.RunUnderlyingTrainingCycle(self.request,Context())
            lookup.assert_not_called()
        for key in rehearsal.PIN_KEYS | {'expected_contextual_training_optimizer'}:
            bad=pb.FuzzerTrainingRequest(); bad.CopyFrom(self.request); del bad.metadata[key]
            service=FuzzerTrainingService(self.service_config)
            with patch('fuzzer_service.reserve_training_request') as reserve, patch.object(service,'_previous_update_for_fingerprint') as lookup, self.assertRaises(Aborted):
                service.RunUnderlyingTrainingCycle(bad,Context())
            reserve.assert_not_called(); lookup.assert_not_called()
        self.manifest_path.write_bytes(self.manifest.payload+b' ')
        with patch('fuzzer_service.reserve_training_request') as reserve,patch.object(service,'_previous_update_for_fingerprint') as lookup,self.assertRaises(Aborted):
            service.RunUnderlyingTrainingCycle(self.request,Context())
        reserve.assert_not_called(); lookup.assert_not_called()

    def test_head_orphan_curriculum_and_missing_path_reject_before_reservation(self):
        for mode in ('head','orphan','curriculum','missing_path','pin_mismatch'):
            request=pb.FuzzerTrainingRequest();request.CopyFrom(self.request)
            config=self.service_config
            if mode=='orphan':request.metadata['contextual_sampling_strategy']=legacy.STRATEGY
            if mode=='curriculum':config=replace(config,curriculum_manifest_path='forbidden')
            if mode=='missing_path':config=replace(config,rehearsal_manifest_path=None)
            if mode=='pin_mismatch':request.metadata[rehearsal.BANK_KEY]='a'*64
            service=FuzzerTrainingService(config)
            with patch('fuzzer_service.reserve_training_request') as reserve,patch.object(service,'_previous_update_for_fingerprint') as lookup,self.assertRaises(Aborted):
                (service.RunTrainingCycle if mode=='head' else service.RunUnderlyingTrainingCycle)(request,Context())
            reserve.assert_not_called();lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
