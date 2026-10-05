"""Synthetic genuine dual allocation and strict partition publication boundaries."""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from pathlib import Path
import copy
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'evaluation'), str(ROOT/'shared/python'), str(Path(__file__).parent)]
from privoke_eval import in_house_partition_publication as p
from privoke_eval.in_house_advpii_review import build_in_house_review_pool
from privoke_eval.clean_augmentation_grouping import ProtectedKeys, build_components
from test_advpii_review import _parsed
from test_in_house_dual_review import _bindings, _envelope, _raw
from test_in_house_dual_allocation import run, baseline
import test_in_house_review_reconstruction as reconstruction_tests
from test_in_house_study_contract import fixtures, programme_input


def authored_fixtures():
    return p.jsonl([{'case_id':'case-'+str(i),'family_id':'family-'+str(i//4),'text':'Authored fixture text '+str(i),
                     'ambiguous':r['ambiguous'],'required_sensitive':r['required_sensitive'],
                     'minimum_action':r['required_action'],'expected_action':None,'visibility_hint':r['visibility_hint']}
                    for i,r in enumerate(fixtures())])


def original_train():
    return p.jsonl([{'id':'original-'+str(i),'group_id':'old-'+str(i),'text':'Original training row '+str(i),
                     'text_key':p.training_data.training_text_key('Original training row '+str(i)),
                     'expected_has_pii':bool(i)} for i in range(2)])


def synthetic_contracts(stack, original):
    for name,value in {'SOURCE_ROWS':9000,'ORIGINAL_ROWS':2,'ORIGINAL_BYTES':len(original),'ORIGINAL_SHA256':p.sha(original)}.items():
        stack.enter_context(patch.object(p,name,value))


class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Actual full graph, genuine opaque pool, complete two envelopes and frozen allocator.
        rows, spans, uid = [], {}, 1
        for component in range(1000):
            for category,copies in (('positive',4),('negative',4),('hard_negative',1)):
                for _ in range(copies):
                    parsed,native = _parsed(uid,category)
                    rows.append(replace(parsed,grouping_row=replace(parsed.grouping_row,input_id=component+1)))
                    spans[uid]=native
                    uid+=1
        keys=ProtectedKeys()
        cls.pool=build_in_house_review_pool(rows,build_components([r.grouping_row for r in rows],keys),_bindings(keys),keys,spans)
        cls.first=_envelope(cls.pool,'reviewer-one',baseline(cls.pool))
        cls.second=_envelope(cls.pool,'reviewer-two',baseline(cls.pool))
        cls.allocation,cls.reviews=run(cls.pool,cls.first,cls.second)
        cls.original=original_train()
        with ExitStack() as stack:
            synthetic_contracts(stack,cls.original)
            cls.payloads,cls.provenance=p._assemble(cls.pool,cls.allocation,cls.reviews,cls.original,authored_fixtures())

    def test_exact_prefix_fixed_quotas_and_full_component_reservations(self):
        self.assertTrue(self.payloads['train.jsonl'].startswith(self.original))
        self.assertEqual(len(self.payloads['train.jsonl'].splitlines()),4002)
        self.assertEqual(len(self.provenance),8000)
        for name in ('validation.jsonl','reserved-test.jsonl'):
            metadata=p.dataset_metadata(self.payloads[name])
            self.assertEqual(metadata['rows'],2000)
            rows=[p.decode(line,p.sha(line)) for line in self.payloads[name].splitlines()]
            self.assertEqual(sum(row['expected_has_pii'] for row in rows),1000)
            for label in (False,True):
                self.assertGreaterEqual(len({row['group_id'] for row in rows if row['expected_has_pii'] is label}),200)
        self.assertEqual(len(set(r['id'] for r in self.provenance)),8000)
        self.assertTrue(any(record.first_evidence and record.second_evidence for record in self.reviews.records.values()))
        self.assertFalse(self.reviews.human_agreement_claimed)
        self.assertFalse(self.reviews.label_truth_authenticated)

    def test_changed_original_prefix_incomplete_source_and_failed_allocation_reject(self):
        with ExitStack() as stack:
            synthetic_contracts(stack,self.original)
            for pool,result,original in ((self.pool,self.allocation,self.original.replace(b'Original',b'Altered',1)),
                (replace(self.pool,_source_rows=self.pool._source_rows[:-1]),self.allocation,self.original),
                (self.pool,replace(self.allocation,status='failed'),self.original)):
                with self.assertRaises(p.PublicationError):
                    p._assemble(pool,result,self.reviews,original,authored_fixtures())

    def test_genuine_reconstruction_and_actual_dual_shortage_cannot_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            stack,paths,trust,captures,expected=reconstruction_tests.ReconstructionTests().fixture(Path(temp))
            with stack:
                rebuilt,*_=p.reconstruction._rebuild(paths,captures,trust,dict(expected.bindings.execution_code_raw_sha256),
                    expected.bindings.protection,expected._combined_keys,lambda:None)
            result,reviews=run(rebuilt,_envelope(rebuilt,'reviewer-one',baseline(rebuilt)),_envelope(rebuilt,'reviewer-two',baseline(rebuilt)))
            self.assertEqual(result.status,'failed')
            with self.assertRaises(p.PublicationError):
                p._assemble(rebuilt,result,reviews,self.original,authored_fixtures())

    def test_complete_actual_envelope_commitments_and_reviewers_cannot_be_substituted(self):
        wrong=copy.deepcopy(self.second)
        wrong['responses'][0]['reviewer_id']='reviewer-one'
        with self.assertRaises(ValueError):
            run(self.pool,self.first,wrong)
        with self.assertRaises(ValueError):
            p.dual.consume_dual_reviews(self.pool,_raw(self.first),_raw(self.second),trusted_bindings=self.pool.bindings,
                expected_preparation_identity=self.pool.preparation_identity,expected_first_reviewer_id='reviewer-one',
                expected_second_reviewer_id='reviewer-two',expected_first_raw_sha256='0'*64,expected_second_raw_sha256=p.sha(_raw(self.second)))


    def _prepared_snapshot(self, original):
        with ExitStack() as stack:
            synthetic_contracts(stack,original)
            stack.enter_context(patch.object(p,'ORIGINAL_ROWS',len(original.splitlines())))
            payloads,provenance=p._assemble(self.pool,self.allocation,self.reviews,original,authored_fixtures())
        payloads.update({'first-envelope.json':_raw(self.first),'second-envelope.json':_raw(self.second),
            'dual-review.json':p.canonical({'consensus_sha256':self.reviews.consensus_sha256,
                'records':{k:p.asdict(v) for k,v in self.reviews.records.items()}}),
            'allocation.json':p.canonical({k:p.plain(getattr(self.allocation,k)) for k in ('status','partitions','assigned_component_ids','capacities','represented_components','streams')}),
            'provenance.json':p.canonical(provenance)})
        sources={k:'a'*64 for k in p.SOURCE_MODULES}
        inputs={k:'b'*64 for k in p.io._INPUT_ROLES}
        manifest=dict(schema_version=1,kind=p.KIND,source_revision='a'*40,source_rows=9000,
            preparation_identity=self.pool.preparation_identity,review_pool_sha256=self.pool.review_pool_sha256,
            published_preparation={'output_raw_sha256':{name:'a'*64 for name in p.reconstruction._FILES},
                'expected_counts':{'source_rows':9000,'pool_size':self.pool.core.pool_size,'graph_components':1000,'assignable_rows':9000}},
            source_hashes=sources,preparation_input_hashes=inputs,
            preparation_code_hashes=dict(self.pool.bindings.execution_code_raw_sha256),
            protection_bindings=p.plain(vars(self.pool.bindings.protection)),
            original={'sha256':p.sha(original),'bytes':len(original),'rows':len(original.splitlines())},
            files={k:p.sha(v) for k,v in payloads.items()},
            datasets={k:p.dataset_metadata(payloads[k],fixture=k=='fixtures.jsonl') for k in p.DATA_FILES[1:]},
            quotas=p.plain(p.allocator._QUOTAS),component_floors=200,
            consensus_sha256=self.reviews.consensus_sha256,consensus_rule_raw_sha256=self.reviews.consensus_rule_raw_sha256,
            reviewers={'first':'reviewer-one','second':'reviewer-two'},human_agreement_claimed=False,label_truth_authenticated=False)
        return payloads,manifest,sources

    def test_prepared_manifest_closure_prefix_and_dataset_pins_fail_closed(self):
        payloads,manifest,sources=self._prepared_snapshot(self.original)
        with ExitStack() as stack:
            synthetic_contracts(stack,self.original)
            p.validate_prepared(manifest,payloads,sources)
            variants=[]
            for key,value in (('human_agreement_claimed',True),('source_rows',8999),('component_floors',199),('kind','other')):
                bad=copy.deepcopy(manifest);bad[key]=value;variants.append(bad)
            bad=copy.deepcopy(manifest);bad['extra']=True;variants.append(bad)
            bad=copy.deepcopy(manifest);bad['published_preparation']['expected_counts']['source_rows']=8999;variants.append(bad)
            bad=copy.deepcopy(manifest);bad['reviewers']['second']='reviewer-one';variants.append(bad)
            bad=copy.deepcopy(manifest);bad['datasets']['validation.jsonl']['keys_sha256']='0'*64;variants.append(bad)
            for bad in variants:
                with self.assertRaises(p.PublicationError):p.validate_prepared(bad,payloads,sources)
            changed={**payloads,'train.jsonl':payloads['train.jsonl'].replace(b'Original',b'Altered',1)}
            rebound=copy.deepcopy(manifest);rebound['files']['train.jsonl']=p.sha(changed['train.jsonl'])
            with self.assertRaises(p.PublicationError):p.validate_prepared(rebound,changed,sources)
            with self.assertRaises(p.PublicationError):p.validate_prepared(manifest,{**payloads,'extra.json':b'{}'},sources)

    @contextmanager
    def _flat_case(self):
        payloads,manifest,sources=self._prepared_snapshot(self.original)
        raw=p.canonical(manifest)
        operator=programme_input()
        external=operator['external_hashes']
        external.update(prepared_manifest=p.sha(raw),training_image='d'*64,dependency_lock='e'*64,
            combined_protected_keys=manifest['protection_bindings']['combined_protection_sha256'],
            helper_sources=p.sha(p.canonical({'preparation':manifest['preparation_code_hashes'],'publication':sources})))
        for role,key in (('fixture','fixture'),('fixture_rubric','fixture_rubric'),('fixture_review','fixture_review'),
            ('historical_protection_artifact','protected_union'),('historical_protection_receipt','protection_receipt'),
            ('fixture_addon_artifact','addon_artifact'),('fixture_addon_receipt','addon_receipt')):
            external[role]=manifest['preparation_input_hashes'][key]
        programme_raw=p.canonical(operator)
        trust={'source_hashes':sources,'trainer_contract_sha256':'c'*64,'training_image_id':'d'*64,
            'dependency_lock_sha256':'e'*64,'volumes':{k:'synthetic-'+k for k in ('train','validation','fixtures','test')}}
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            synthetic_contracts(stack,self.original)
            base=Path(temp)
            with p.HeldDirectory(base/'prepared',create=True) as held:
                for name,content in {**payloads,'prepared-manifest.json':raw}.items():held.write(name,content)
            destinations={role:base/role for role in trust['volumes']}
            for path in destinations.values():path.mkdir(mode=0o700)
            kwargs=dict(expected_prepared_raw_sha256=p.sha(raw),programme_input_bytes=programme_raw,
                expected_programme_input_raw_sha256=p.sha(programme_raw),external_trust=trust,source_root=ROOT,
                destinations=destinations,metadata_output=base/'metadata',sealed_metadata_output=base/'sealed')
            try:
                with patch.object(p,'attest'):
                    yield base,kwargs
            finally:
                train=destinations['train']
                if train.stat().st_uid==65534:
                    # Reclaim only the exact synthetic train pair for cleanup.
                    os.chown(train,0,0)
                    for name in ('train.jsonl','training-manifest.json'):os.chown(train/name,0,0)

    @unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:None)()==0,
                         'Real late-role output mutation regression mandatory in ROOT Linux harness.')
    def test_later_role_or_metadata_write_cannot_mutate_an_earlier_role(self):
        for trigger,victim in (('fixtures.jsonl','validation/validation.jsonl'),
            ('fit-S1.json','fixtures/fixtures.jsonl'),('publication-receipt.json','test/reserved-test.jsonl')):
            with self.subTest(trigger=trigger),self._flat_case() as (base,kwargs):
                original_write=p.HeldDirectory.write
                triggered=[]
                def write(held,name,raw):
                    original_write(held,name,raw)
                    if name==trigger and not triggered:
                        path=base/victim;data=path.read_bytes()
                        path.write_bytes(bytes([data[0]^1])+data[1:])
                        triggered.append(name)
                with patch.object(p.HeldDirectory,'write',write),self.assertRaises(p.PublicationError):
                    p.publish_flat_views(base/'prepared',**kwargs)
                self.assertEqual(triggered,[trigger])

    @unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:None)()==0,
                         'Real post-CHOWN global mutation regression mandatory in ROOT Linux harness.')
    def test_post_handoff_fsync_and_later_role_read_cannot_mutate_root_owned_outputs(self):
        for attack in ('fsync','later-read'):
            with self.subTest(attack=attack),self._flat_case() as (base,kwargs):
                captured={}
                original_write=p.HeldDirectory.write
                original_read=p.os.read
                original_fsync=p.os.fsync
                triggered=[]
                def write(held,name,raw):
                    original_write(held,name,raw)
                    if name=='publication-receipt.json':captured['meta']=held.fd
                    if name=='sealed-test-release.json':captured['sealed']=held.files[name][0]
                def mutate():
                    path=base/'validation/validation.jsonl';data=path.read_bytes()
                    path.write_bytes(bytes([data[0]^1])+data[1:])
                    triggered.append(attack)
                def read(fd,size):
                    if (attack=='later-read' and fd==captured.get('sealed') and not triggered
                            and (base/'train').stat().st_uid==65534):mutate()
                    return original_read(fd,size)
                def fsync(fd):
                    original_fsync(fd)
                    if (attack=='fsync' and fd==captured.get('meta') and not triggered
                            and (base/'train').stat().st_uid==65534):mutate()
                with patch.object(p.HeldDirectory,'write',write),patch.object(p.os,'read',read), \
                     patch.object(p.os,'fsync',fsync),self.assertRaises(p.PublicationError):
                    p.publish_flat_views(base/'prepared',**kwargs)
                self.assertEqual(triggered,[attack])

    @unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:None)()==0,
                         'Actual CHOWN/private publication plus fitter compatibility mandatory in ROOT Linux harness.')
    def test_actual_flat_publication_chown_and_closed_fitter_consumer(self):
        # No fit/source data: synthetic full-count original rows and genuine dual allocation.
        original=p.jsonl([{'id':'original-'+str(i),'group_id':'old-'+str(i),'text':'Original training row '+str(i),
            'text_key':p.training_data.training_text_key('Original training row '+str(i)),
            'expected_has_pii':i%2==0} for i in range(3832)])
        payloads,manifest,sources=self._prepared_snapshot(original)
        raw=p.canonical(manifest)
        operator=programme_input()
        external=operator['external_hashes']
        external.update(prepared_manifest=p.sha(raw),training_image='d'*64,dependency_lock='e'*64,
            combined_protected_keys=manifest['protection_bindings']['combined_protection_sha256'],
            helper_sources=p.sha(p.canonical({'preparation':manifest['preparation_code_hashes'],'publication':sources})))
        for role,key in (('fixture','fixture'),('fixture_rubric','fixture_rubric'),('fixture_review','fixture_review'),
            ('historical_protection_artifact','protected_union'),('historical_protection_receipt','protection_receipt'),
            ('fixture_addon_artifact','addon_artifact'),('fixture_addon_receipt','addon_receipt')):
            external[role]=manifest['preparation_input_hashes'][key]
        programme_raw=p.canonical(operator)
        trust={'source_hashes':sources,'trainer_contract_sha256':'c'*64,'training_image_id':'d'*64,
               'dependency_lock_sha256':'e'*64,'volumes':{k:'synthetic-'+k for k in ('train','validation','fixtures','test')}}
        captured={}
        original_write=p.HeldDirectory.write
        def write(held,name,content):
            captured[name]=content
            return original_write(held,name,content)
        with tempfile.TemporaryDirectory() as temp,ExitStack() as stack:
            synthetic_contracts(stack,original);stack.enter_context(patch.object(p,'ORIGINAL_ROWS',3832))
            base=Path(temp)
            with p.HeldDirectory(base/'prepared',create=True) as held:
                for name,content in {**payloads,'prepared-manifest.json':raw}.items():held.write(name,content)
            destinations={role:base/role for role in trust['volumes']}
            for path in destinations.values():path.mkdir(mode=0o700)
            kwargs=dict(expected_prepared_raw_sha256=p.sha(raw),programme_input_bytes=programme_raw,
                expected_programme_input_raw_sha256=p.sha(programme_raw),external_trust=trust,source_root=ROOT,
                destinations=destinations,metadata_output=base/'metadata',sealed_metadata_output=base/'sealed')
            # Only live source-attestation is a synthetic seam. Real held files,
            # programme parser, schemas, projection, exclusive writes and CHOWN execute.
            with patch.object(p,'attest'),patch.object(p.HeldDirectory,'write',write):
                with self.assertRaises(p.PublicationError):
                    p.publish_flat_views(base/'prepared',**{**kwargs,'expected_prepared_raw_sha256':'0'*64})
                self.assertTrue(all(not list(path.iterdir()) for path in destinations.values()))
                receipt=p.publish_flat_views(base/'prepared',**kwargs)
            self.assertEqual(receipt['status'],'awaiting_train_reader')
            self.assertEqual(destinations['train'].stat().st_uid,65534)
            self.assertEqual(destinations['train'].stat().st_mode&0o777,0o700)
            self.assertEqual(set((base/'sealed').iterdir()),{base/'sealed/sealed-test-release.json'})
            self.assertNotIn('sealed-test-release.json',{file.name for file in (base/'metadata').iterdir()})
            for role,name in (('validation','validation.jsonl'),('fixtures','fixtures.jsonl'),('test','reserved-test.jsonl')):
                self.assertEqual({file.name for file in destinations[role].iterdir()},{name})
                self.assertEqual((destinations[role]/name).read_bytes(),payloads[name])
            sys.path.insert(0,str(ROOT/'extension/client-runtime'))
            from privoke_eval import in_house_study_fit as fitter
            for arm in p.contract.ARM_KEYS[1:]:
                expected_raw=(base/'metadata'/('fit-'+arm+'.json')).read_bytes()
                expected=fitter.parse_expected_inputs(expected_raw,pinned_sha256=p.sha(expected_raw),expected_arm=arm,expected_revision='a'*40)
                with patch.object(fitter,'_verify_source'):
                    verified=fitter.load_verified_training(payloads['train.jsonl'],captured['training-manifest.json'],expected)
                self.assertEqual(len(verified.rows),7832)
                self.assertEqual(verified.original_count,3832)
            # ROOT's separate real UID65534/drop-ALL reader still gates acceptance.
            # CHOWN back only synthetic artifacts for TemporaryDirectory cleanup.
            os.chown(destinations['train'],0,0)
            for name in ('train.jsonl','training-manifest.json'):os.chown(destinations['train']/name,0,0)


class FixtureProjectionTests(unittest.TestCase):
    def test_null_presence_authored_action_precedence_and_visibility_preserved(self):
        raw=authored_fixtures()
        rows=[p.decode(line,p.sha(line)) for line in raw.splitlines()]
        rows[24]['expected_action']='ALLOW'
        projected=[p.decode(line,p.sha(line)) for line in p.fixture_view(p.jsonl(rows)).splitlines()]
        self.assertEqual(projected[24]['required_action'],'WARN')
        self.assertTrue(all(row['expected_has_pii'] is None for row in projected))
        self.assertEqual(sum(row['ambiguous'] for row in projected),7)
        self.assertEqual(sum(row['required_sensitive'] is True for row in projected),17)
        self.assertEqual(sum(row['required_sensitive'] is False for row in projected),24)
        self.assertEqual(sorted(row['visibility_hint'] for row in projected if row['visibility_hint']),['P0','P3','P4','PU'])
        rows[24]['minimum_action']=None
        rows[24]['expected_action']='BLOCK'
        projected=[p.decode(line,p.sha(line)) for line in p.fixture_view(p.jsonl(rows)).splitlines()]
        self.assertEqual(projected[24]['required_action'],'BLOCK')

    def test_invalid_fixture_action_sensitivity_ambiguity_and_counts_reject(self):
        base=[p.decode(line,p.sha(line)) for line in authored_fixtures().splitlines()]
        for index,key,value in ((0,'required_sensitive',None),(0,'minimum_action','INVALID'),
            (0,'expected_action','INVALID'),(47,'required_sensitive',False),(47,'minimum_action','ALLOW')):
            rows=copy.deepcopy(base); rows[index][key]=value
            with self.subTest(key=key,index=index),self.assertRaises(p.PublicationError):
                p.fixture_view(p.jsonl(rows))
        with self.assertRaises((p.PublicationError,p.evidence.StudyEvidenceError)):
            p.fixture_view(p.jsonl(base[:-1]))

    def test_boolean_dataset_contract_still_rejects_null_truth(self):
        raw=p.jsonl([{'id':str(i),'group_id':str(i),'text':'Synthetic '+str(i),'expected_has_pii':None if i==0 else i<1000} for i in range(2000)])
        with self.assertRaises(p.PublicationError):
            p.dataset_metadata(raw)


class SourceAttestationTests(unittest.TestCase):
    def test_actual_module_pins_and_foreign_live_function_reject(self):
        pins={role:p.sha((ROOT/relative).read_bytes()) for role,(_,relative) in p.SOURCE_MODULES.items()}
        def opening(path):
            fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0))
            return fd,os.fstat(fd)
        # Host substitutes only unavailable POSIX open; genuine byte pins and
        # live function/global attestation execute on the actual source tree.
        with patch.object(p.io,'_open_read_nofollow',opening):
            p.attest(ROOT,pins)
            with patch.object(p,'canonical',lambda _:b'changed'),self.assertRaises(ValueError):
                p.attest(ROOT,pins)
            with self.assertRaises(p.PublicationError):
                p.attest(ROOT,{**pins,'publisher':'0'*64})


class StorageBoundaryTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','Held no-follow publication mandatory in Linux.')
    def test_private_exclusive_bytes_modes_and_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fresh'
            with p.HeldDirectory(target,create=True) as held:
                held.write('a.json',b'{}')
                held.verify(('a.json',))
                self.assertEqual(target.stat().st_mode&0o777,0o700)
                self.assertEqual((target/'a.json').stat().st_mode&0o777,0o600)
                with self.assertRaises(FileExistsError):
                    held.write('a.json',b'changed')
                (target/'unexpected').write_bytes(b'no')
                with self.assertRaises(p.PublicationError):
                    held.verify(('a.json',))
            with self.assertRaises(p.PublicationError):
                with p.HeldDirectory(target,create=True):
                    pass

    @unittest.skipUnless(os.name=='posix','Held no-follow publication mandatory in Linux.')
    def test_same_inode_content_mode_hardlink_symlink_and_ancestor_replacement_reject(self):
        for attack in ('bytes','mode','hardlink','symlink','directory'):
            with tempfile.TemporaryDirectory() as temp:
                target=Path(temp)/'fresh'
                with p.HeldDirectory(target,create=True) as held:
                    held.write('a.json',b'{}')
                    path=target/'a.json'
                    if attack=='bytes': path.write_bytes(b'[]')
                    elif attack=='mode': path.chmod(0o644)
                    elif attack=='hardlink': os.link(path,target/'linked')
                    elif attack=='symlink':
                        path.unlink(); path.symlink_to('outside')
                    else:
                        target.rename(Path(temp)/'retained'); target.mkdir(mode=0o700)
                    with self.subTest(attack=attack),self.assertRaises(p.PublicationError): held.verify(('a.json',))

    @unittest.skipUnless(os.name=='posix','Real final fsync mutation regression mandatory in Linux.')
    def test_final_directory_fsync_mutation_is_rejected_by_phase_a_seal(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fresh'
            with p.HeldDirectory(target,create=True) as held:
                held.write('a.json',b'{}')
                original_fsync=p.os.fsync
                triggered=[]
                def fsync(fd):
                    original_fsync(fd)
                    if fd==held.fd:
                        (target/'a.json').write_bytes(b'[]')
                        triggered.append(fd)
                with patch.object(p.os,'fsync',fsync),self.assertRaises(p.PublicationError):
                    p.seal_directory(held,('a.json',))
                self.assertEqual(triggered,[held.fd])

    @unittest.skipUnless(os.name=='posix','Real sequential held read mutation regression mandatory in Linux.')
    def test_later_file_read_cannot_mutate_same_inode_same_size_earlier_member(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'fresh'
            with p.HeldDirectory(target,create=True) as held:
                held.write('a.json',b'{}')
                held.write('b.json',b'{}')
                original_read=p.os.read
                initial=(target/'a.json').stat()
                triggered=[]
                def read(fd,size):
                    if fd==held.files['b.json'][0] and not triggered:
                        (target/'a.json').write_bytes(b'[]')
                        # Restore mtime deliberately: ctime still binds mutation.
                        os.utime(target/'a.json',ns=(initial.st_atime_ns,initial.st_mtime_ns))
                        triggered.append(fd)
                    return original_read(fd,size)
                with patch.object(p.os,'read',read),self.assertRaises(p.PublicationError):
                    held.verify(('a.json','b.json'))
                final=(target/'a.json').stat()
                self.assertEqual(initial.st_ino,final.st_ino)
                self.assertEqual(initial.st_size,final.st_size)
                self.assertEqual(triggered,[held.files['b.json'][0]])

    def test_unsupported_platform_fails_before_creating_outputs(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(p.io,'_platform_supported',return_value=False):
            target=Path(temp)/'must-not-exist'
            with self.assertRaises(p.PublicationError):
                with p.HeldDirectory(target,create=True): pass
            self.assertFalse(target.exists())

    def test_reader_requires_real_uid_and_gid_65534(self):
        with patch.object(p.os,'geteuid',return_value=0,create=True),self.assertRaises(p.PublicationError):
            p.verify_train_reader(Path('/not-opened'),expected_train_sha256='a'*64,expected_manifest_sha256='b'*64)


if __name__=='__main__':
    unittest.main()
