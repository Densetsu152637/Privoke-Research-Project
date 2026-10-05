"""Fixed eight-arm host controller. Actual execution requires external RAW pins.

Training, evidence and catalogue operations are named, inspected one-off jobs.
An unresolved remote handle blocks every later mutation, including restoration.
The test release locator is consumed only after the raw-authenticated barrier.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

from . import in_house_study_contract as contract
from . import in_house_study_evidence as evidence

LEGACY_IDS = ('privoke-balanced', 'privoke-presence-efficient',
              'privoke-presence-balanced', 'privoke-presence-quality')
SCRATCH_IDS = tuple(arm.model_id for arm in contract.ARMS[2:])
CATALOG_IDS = LEGACY_IDS + SCRATCH_IDS
IMAGE_ROLES = ('client-runtime', 'model-streaming-service', 'param-update-service',
               'evaluator', 'training')
CHECKPOINT_KEYS = tuple((arm, epoch) for arm in contract.ARM_KEYS
                        for epoch in ((0,) if arm.startswith('S') else range(1, 6)))
TRAINER_DIGEST = '2e5ddc5d5f13098a5d95ff98bf116421263de0472b7eb729156066b5c2a67806'
ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILES = ('docker-compose.yml', 'evaluation/compose.tests.yml',
                 'evaluation/compose.public-negatives.yml', 'evaluation/compose.presence.yml',
                 'evaluation/compose.in-house-fit.yml', 'evaluation/compose.in-house-study.yml')
FIT_ROOT = Path('/private-fit-root')


class ControllerError(ValueError):
    """No private input or remote exception text is exposed."""


class RemoteUnknown(ControllerError):
    """A named job may still act. No subsequent writes or cleanup are safe."""


def fail():
    raise ControllerError('Fixed programme inputs, evidence or lifecycle are invalid.')


def raw_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def read_reference(reference, limit=evidence.MAX_INPUT_BYTES):
    evidence.closed(reference, ('file', 'sha256'))
    path = Path(reference['file'])
    if any(p.is_symlink() or getattr(p.lstat(), 'st_file_attributes', 0) & 0x400
           for p in (path, *path.parents) if p.exists()):
        fail()
    return evidence.read_committed(path, reference['sha256'], limit)


def json_reference(reference):
    raw = read_reference(reference)
    return evidence.checked_json(raw, reference['sha256'])


def volume_reference(value):
    evidence.closed(value, ('volume', 'file', 'sha256'))
    if (type(value['volume']) is not str or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}', value['volume'])
            or value['file'] not in ('train.jsonl', 'training-manifest.json', 'validation.jsonl', 'fixtures.jsonl', 'reserved-test.jsonl')):
        fail()
    evidence.checked_hash(value['sha256'])
    return value


def exclusive(path, raw):
    """No replacement of prior evidence; caller owns and rechecks its root."""
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {'file': str(path), 'sha256': raw_hash(raw)}


def save(path, value):
    return exclusive(path, evidence.canonical(value))


def artifact_identity(raw):
    """Independent RAW, canonical artifact checksum, transported f32 identity."""
    from privoke_model.artifact import float32, validate_artifact
    from privoke_model.fingerprint import parameter_fingerprint
    value = evidence.checked_json(raw, raw_hash(raw), evidence.MAX_FRAME_BYTES)
    validate_artifact(value)
    parameters = {key: [float32(v) for v in item['values']] for key, item in value['parameters'].items()}
    shapes = {key: item['shape'] for key, item in value['parameters'].items()}
    return {'model_id': value['model_id'], 'version': value['version'],
            'artifact_sha256': raw_hash(raw), 'artifact_checksum': value['checksum'],
            'parameter_fingerprint': parameter_fingerprint(parameters, shapes)}, value


def validate_inputs(value):
    """Closed operator commitments. No test release path or data read here."""
    evidence.closed(value, ('schema_version', 'programme', 'source_revision', 'controller_sha256', 'cli_sha256', 'compose_sha256',
        'images', 'effective_configuration', 'source_hashes', 'control_binding_sha256',
        'original', 's0', 's0_job_receipt', 'prior_catalog', 'fits', 'datasets',
        'test_metadata', 'test_release_sha256', 'trainer_contract_sha256', 'compatibility'))
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        fail()
    if not re.fullmatch('[0-9a-f]{40}', value['source_revision']):
        fail()
    for key in ('controller_sha256', 'cli_sha256', 'compose_sha256', 'effective_configuration', 'control_binding_sha256',
                'test_release_sha256', 'trainer_contract_sha256', 's0_job_receipt'):
        evidence.checked_hash(value[key])
    if value['trainer_contract_sha256'] != TRAINER_DIGEST:
        fail()
    evidence.closed(value['images'], IMAGE_ROLES)
    for image in value['images'].values():
        evidence.checked_hash(image)
    evidence.closed(value['source_hashes'], evidence.SOURCE_ROLES)
    for digest in value['source_hashes'].values():
        evidence.checked_hash(digest)
    evidence.closed(value['prior_catalog'], LEGACY_IDS)
    for identity in value['prior_catalog'].values():
        evidence._identity(identity)
    evidence.closed(value['fits'], contract.ARM_KEYS[1:])
    for ref in value['fits'].values():
        evidence.closed(ref, ('train', 'manifest', 'expected'))
        for role in ('train', 'manifest'):
            volume_reference(ref[role])
        if (ref['train']['file'] != 'train.jsonl' or ref['manifest']['file'] != 'training-manifest.json'
                or ref['train']['volume'] != ref['manifest']['volume']):
            fail()
        evidence.closed(ref['expected'], ('file', 'sha256'))
        evidence.checked_hash(ref['expected']['sha256'])
    evidence.closed(value['datasets'], ('validation', 'fixtures'))
    for key in ('validation', 'fixtures'):
        evidence.closed(value['datasets'][key], ('volume', 'file', 'sha256', 'keys_sha256', 'rows'))
        volume_reference({k: value['datasets'][key][k] for k in ('volume', 'file', 'sha256')})
        if value['datasets'][key]['file'] != ('fixtures.jsonl' if key == 'fixtures' else 'validation.jsonl'):
            fail()
        evidence.checked_hash(value['datasets'][key]['sha256'])
        evidence.checked_hash(value['datasets'][key]['keys_sha256'])
        if type(value['datasets'][key]['rows']) is not int or value['datasets'][key]['rows'] != (48 if key == 'fixtures' else 2000):
            fail()
    train_volumes = {ref['train']['volume'] for ref in value['fits'].values()}
    if len(train_volumes) != 1 or len(train_volumes | {v['volume'] for v in value['datasets'].values()}) != 3:
        fail()
    evidence.closed(value['test_metadata'], ('sha256', 'keys_sha256', 'rows', 'kind'))
    if value['test_metadata']['kind'] != 'new-prospective-reserved-test-v1' or type(value['test_metadata']['rows']) is not int or value['test_metadata']['rows'] != 2000:
        fail()
    for key in ('sha256', 'keys_sha256'):
        evidence.checked_hash(value['test_metadata'][key])
    programme = contract.freeze_programme(json_reference(value['programme']))
    external = dict(programme.external_hashes)
    if (programme.source_revision != value['source_revision'] or external['effective_configuration'] != value['effective_configuration']
            or any(external[f'{role}_image'] != value['images'][role] for role in ('evaluator', 'training'))
            or external['runtime_image'] != value['images']['client-runtime']):
        fail()
    for name, expected in (('original', vars(programme.original_contextual)), ('s0', vars(programme.s0))):
        identity, _ = artifact_identity(read_reference(value[name], evidence.MAX_FRAME_BYTES))
        if identity != expected:
            fail()
    return programme


def attest_controller(inputs):
    evidence._attest_module(sys.modules[__name__], inputs['controller_sha256'])
    for path, digest in ((ROOT/'evaluation/run-in-house-study.py', inputs['cli_sha256']),
                         (ROOT/'evaluation/compose.in-house-study.yml', inputs['compose_sha256'])):
        evidence.read_committed(path, digest)


def validate_compatibility(reference, inputs, backend):
    """Consume root-accepted RAW/job commitments; never a bool-only waiver.

    Root independently authenticates the underlying typed probe raw bytes before
    freezing this reference. This consumer joins that external authority to the
    current programme controls and inspects all actual named terminal handles.
    """
    receipt = json_reference(reference)
    evidence.closed(receipt, ('schema_version', 'kind', 'source_revision', 'images',
        'effective_configuration_sha256', 'source_hashes', 'protocol_sha256',
        'before_catalog', 'after_catalog', 'scratch'))
    if (type(receipt['schema_version']) is not int or receipt['schema_version'] != 1
            or receipt['kind'] != 'root-accepted-scratch-live-compatibility-v1'
            or receipt['source_revision'] != inputs['source_revision']
            or receipt['images'] != {k: inputs['images'][k] for k in IMAGE_ROLES[:2]}
            or receipt['effective_configuration_sha256'] != inputs['effective_configuration']
            or receipt['source_hashes'] != inputs['source_hashes']
            or receipt['protocol_sha256'] != dict(contract.PIN_ITEMS)['protocol']):
        fail()
    expected_catalog = {k: inputs['prior_catalog'][k]['artifact_sha256'] for k in LEGACY_IDS} | {k: None for k in SCRATCH_IDS}
    if receipt['before_catalog'] != expected_catalog or receipt['after_catalog'] != expected_catalog:
        fail()
    evidence.closed(receipt['scratch'], SCRATCH_IDS)
    for model_id, item in receipt['scratch'].items():
        evidence.closed(item, ('identity', 'streaming_identity', 'runtime_identity', 'absent_after_removal', 'jobs'))
        identity = dict(evidence._identity(item['identity']))
        if (identity['model_id'] != model_id or item['streaming_identity'] != identity
                or item['runtime_identity'] != identity or item['absent_after_removal'] is not True):
            fail()
        evidence.closed(item['jobs'], ('install', 'probe', 'remove', 'absence'))
        for operation, proof in item['jobs'].items():
            evidence.closed(proof, ('name', 'container_id', 'image_id', 'exit_code', 'operation', 'request', 'receipt'))
            if proof['operation'] != operation or type(proof['exit_code']) is not int or proof['exit_code'] != 0:
                fail()
            if not re.fullmatch('[a-zA-Z0-9_-]{1,128}', proof['name']) or not re.fullmatch('[0-9a-f]{64}', proof['container_id']):
                fail()
            if proof['image_id'] != 'sha256:'+inputs['images']['evaluator']:
                fail()
            read_reference(proof['request'])
            job = json_reference(proof['receipt'])
            for key in ('name', 'container_id', 'image_id', 'exit_code'):
                if job.get(key) != proof[key]:
                    fail()
            if job.get('terminal') is not True or job.get('request_sha256') != proof['request']['sha256']:
                fail()
            backend.verify_external_job(proof)
    return reference['sha256']


@dataclass(frozen=True)
class JobResult:
    name: str
    container_id: str
    image_id: str
    request_sha256: str
    exit_code: int
    logs_sha256: str
    terminal: bool


# Executed only inside the isolated named admin job. No file is selected by a
# caller path: the fixed model ID maps to exactly one catalogue filename.
ADMIN = r'''
import base64, fcntl, hashlib, json, os, stat, sys, uuid
from pathlib import Path
from privoke_model.artifact import validate_artifact, float32
from privoke_model.fingerprint import parameter_fingerprint
IDS = %s
def sha(b): return hashlib.sha256(b).hexdigest()
def fail(): raise ValueError('Catalogue operation rejected.')
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d: fail()
  d[k]=v
 return d
request_raw=Path(sys.argv[1]).read_bytes()
if sha(request_raw)!=sys.argv[2]: fail()
r=json.loads(request_raw,object_pairs_hook=unique)
if set(r)!={'operation','model_id','expected_raw_sha256','raw_b64','identity'}: fail()
if r['model_id'] not in IDS or r['operation'] not in ('read','write','delete'): fail()
d=os.open('/models',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
fcntl.flock(d,fcntl.LOCK_EX)
name=r['model_id']+'.json'
def read():
 try: f=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)
 except FileNotFoundError: return None
 with os.fdopen(f,'rb') as h:
  if not stat.S_ISREG(os.fstat(h.fileno()).st_mode): fail()
  b=h.read(8*1024*1024+1)
  if len(b)>8*1024*1024: fail()
  return b
old=read()
if r['operation']=='read':
 if any(r[k] is not None for k in ('expected_raw_sha256','raw_b64','identity')): fail()
 result={'exists':old is not None,'raw_b64':None if old is None else base64.b64encode(old).decode(),'raw_sha256':None if old is None else sha(old)}
else:
 if (None if old is None else sha(old))!=r['expected_raw_sha256']: fail()
 if r['operation']=='delete':
  if r['model_id'] not in IDS[4:] or old is None or r['raw_b64'] is not None or r['identity'] is not None: fail()
  os.unlink(name,dir_fd=d);os.fsync(d);result={'exists':False,'raw_sha256':None}
 else:
  b=base64.b64decode(r['raw_b64'],validate=True)
  if len(b)>8*1024*1024: fail()
  v=json.loads(b,object_pairs_hook=unique);validate_artifact(v)
  identity={'model_id':v['model_id'],'version':v['version'],'artifact_sha256':sha(b),'artifact_checksum':v['checksum'],'parameter_fingerprint':parameter_fingerprint({k:[float32(x) for x in t['values']] for k,t in v['parameters'].items()},{k:t['shape'] for k,t in v['parameters'].items()})}
  if identity!=r['identity'] or identity['model_id']!=r['model_id']: fail()
  temp='.'+name+'.'+uuid.uuid4().hex
  fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=d)
  with os.fdopen(fd,'wb') as h:h.write(b);h.flush();os.fsync(h.fileno())
  if (None if read() is None else sha(read()))!=r['expected_raw_sha256']: fail()
  os.rename(temp,name,src_dir_fd=d,dst_dir_fd=d);os.fsync(d)
  if read()!=b: fail()
  result={'exists':True,'raw_sha256':sha(b)}
print(json.dumps(result,sort_keys=True))
os.close(d)
''' % repr(CATALOG_IDS)

PROBE = r'''
import hashlib,json,sys,time,grpc
from privoke.v1 import parameters_pb2 as p,parameters_pb2_grpc as pg,runtime_pb2 as r,runtime_pb2_grpc as rg
from privoke_model.fingerprint import parameter_fingerprint
expected=json.load(open(sys.argv[1]));deadline=time.monotonic()+65
def check(i):
 with grpc.insecure_channel('model-streaming-service:50051') as c:
  v=pg.ModelStreamingServiceStub(c).GetModelParameters(p.ModelParametersRequest(model_id=i['model_id'],consumer_id='in-house-study-controller'),timeout=10)
  tensors={x.name:list(x.values) for x in v.parameters};shapes={x.name:list(x.shape) for x in v.parameters}
  if v.model_id!=i['model_id'] or v.version!=i['version'] or v.metadata.get('artifact_checksum')!=i['artifact_checksum'] or parameter_fingerprint(tensors,shapes)!=i['parameter_fingerprint']: raise ValueError()
while True:
 try:
  check(expected['contextual']);check(expected['presence'])
  with grpc.insecure_channel('client-runtime:50054') as c:
   stub=rg.PrivokeRuntimeServiceStub(c)
   x=stub.DetectAnnotationPresence(r.DetectAnnotationPresenceRequest(request_id='in-house-controller-identity-probe',text='synthetic identity probe',model_id=expected['presence']['model_id']),timeout=15)
   i=expected['presence']
   if x.error or (x.model_id,x.model_version,x.artifact_checksum,x.parameter_fingerprint)!=(i['model_id'],i['version'],i['artifact_checksum'],i['parameter_fingerprint']):raise ValueError()
   q=r.AnalyzePromptRequest(request_id='in-house-controller-context-probe',text='synthetic identity probe',source='in-house-study-evaluation',semantic_model_id=expected['contextual']['model_id'],regex_execution_order=r.REGEX_EXECUTION_ORDER_FIRST,layers=[r.DETECTION_LAYER_REGEX,r.DETECTION_LAYER_NER,r.DETECTION_LAYER_SEMANTIC])
   q.semantic_presence_gate.model_id=i['model_id'];q.semantic_presence_gate.threshold=0.0
   y=stub.AnalyzePrompt(q,timeout=15);g=next(z.semantic_presence_gate for z in y.layers if z.layer==r.DETECTION_LAYER_SEMANTIC)
   i=expected['contextual']
   if g.status!=r.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED or g.error or (g.contextual_model_id,g.contextual_model_version,g.contextual_artifact_checksum,g.contextual_parameter_fingerprint)!=(i['model_id'],i['version'],i['artifact_checksum'],i['parameter_fingerprint']):raise ValueError()
  print(json.dumps({'verified':True,'identities':expected},sort_keys=True));break
 except Exception:
  if time.monotonic()>=deadline:raise RuntimeError('Live identity probe failed.') from None
  time.sleep(.25)
'''


PRIVATE_ROOT = Path('/workspace/evaluation/results/study')


def private_path(value, root=PRIVATE_ROOT):
    """Closed local paths; no caller-selected host export or alternate roots."""
    path = Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        fail()
    target = root/path
    if any(p.is_symlink() for p in (target, *target.parents)):
        fail()
    return target


def verify_volume_inventory(inventory, *, root=Path('/phase-data')):
    """Full flat file closure and hashes BEFORE data bytes are decoded."""
    if type(inventory) is not dict or not inventory:
        fail()
    names = set(inventory)
    if names not in ({'train.jsonl', 'training-manifest.json'}, {'validation.jsonl'}, {'fixtures.jsonl'}, {'reserved-test.jsonl'}):
        fail()
    if {p.name for p in root.iterdir()} != names:
        fail()
    return {name: evidence.read_committed(root/name, digest) for name, digest in inventory.items()}


def phase_metadata(phase, raw, expected_sha256):
    """Whitelist aggregates/identities only. Never rows, labels, frames or maps."""
    value = evidence.checked_json(raw, expected_sha256)
    if phase == 'select-validation':
        allowed = ('schema_version', 'status', 'control_binding_sha256', 'validation_rows',
            'validation_positive_examples', 'validation_absent_examples', 'validation_components',
            'validation_positive_components', 'validation_negative_components', 'validation_mixed_label_components',
            'recall_floor', 'candidate_tables', 'selections', 'selection_sha256', 'test_authorized')
        evidence.closed(value, allowed)
        selections = value['selections']
        if selections is not None:
            evidence.closed(selections, contract.ARM_KEYS)
            for choice in selections.values():
                evidence.closed(choice, ('epoch', 'threshold', 'identity', 'metrics', 'eligible', 'reason', 'candidate_sha256'))
                evidence._identity(choice['identity'])
                evidence.closed(choice['metrics'], ('tp', 'tn', 'fp', 'fn', 'recall', 'specificity', 'positive_examples', 'absent_examples', 'balanced_accuracy'))
        return {'status': value['status'], 'selections': selections}
    if phase == 'pretest-barrier':
        evidence.closed(value, ('schema_version', 'programme_sha256', 'record_sha256', 'claim_references',
            'raw_to_claim_joins', 'authenticated_collections', 'pretest_binding', 'selection_raw_sha256', 'test_authorized'))
        # The original full receipt remains private and is reauthenticated by B
        # before each test collection. Host consumes only complete binding metadata.
        bindings = []
        for item in value['authenticated_collections']:
            evidence.closed(item, ('binding', 'binding_sha256', 'inventory_sha256', 'raw_frames'))
            bound = evidence.CollectionBinding(**item['binding'])
            if bound.sha256 != item['binding_sha256']:
                fail()
            bindings.append({k: item[k] for k in ('binding', 'binding_sha256', 'inventory_sha256')})
        return {k: value[k] for k in ('programme_sha256', 'record_sha256', 'pretest_binding', 'selection_raw_sha256')} | {'bindings': bindings}
    if phase == 'analyze-test':
        evidence.closed(value, ('schema_version', 'status', 'rows', 'positive_examples', 'absent_examples',
            'component_count', 'positive_components', 'negative_components', 'mixed_label_components',
            'arm_metrics', 'paired_component_bootstrap', 'test_authorized', 'retention_decision'))
        # Returned analysis is an aggregate-only closed public producer; recursively
        # prohibit private row/content fields even if a future producer adds them.
        def safe_tree(item):
            if isinstance(item, dict):
                if any(k in ('text', 'rows_data', 'row_id', 'group_id', 'truth', 'labels', 'raw_frames', 'request_b64', 'response_b64') for k in item):
                    fail()
                for v in item.values():
                    safe_tree(v)
            elif isinstance(item, list):
                for v in item:
                    safe_tree(v)
        safe_tree(value)
        return value
    fail()


def verify_barrier_metadata(binding, receipt, selection_sha256):
    """Controller scope check only; B reconstructs full private RAW before reads."""
    evidence.closed(receipt, ('programme_sha256', 'record_sha256', 'pretest_binding', 'selection_raw_sha256', 'bindings'))
    scope = evidence._phase_scope(binding)
    if receipt['pretest_binding'] != scope or receipt['programme_sha256'] != binding.programme_sha256 or receipt['selection_raw_sha256'] != selection_sha256:
        fail()
    seen = set()
    for record in receipt['bindings']:
        evidence.closed(record, ('binding', 'binding_sha256', 'inventory_sha256'))
        captured = evidence.CollectionBinding(**record['binding'])
        evidence.checked_hash(record['inventory_sha256'])
        if captured.sha256 != record['binding_sha256'] or evidence._phase_scope(captured) != scope:
            fail()
        key = (captured.phase, captured.arm, captured.epoch if captured.phase == 'collect-validation' else None)
        if key in seen or (captured.phase != 'collect-validation' and captured.selection_sha256 != selection_sha256):
            fail()
        seen.add(key)
    expected = {('collect-validation', arm, epoch) for arm, epoch in CHECKPOINT_KEYS}
    expected |= {(phase, arm, None) for phase in ('rerun-validation', 'collect-fixtures') for arm in contract.ARM_KEYS}
    if seen != expected:
        fail()


def private_helper(request):
    """Source-attested in-container producer/reader. No arbitrary cat/copy mode."""
    if os.name != 'posix' or os.environ.get('PRIVOKE_EVAL_IN_CONTAINER') != 'true':
        fail()
    mode = request.get('mode')
    if mode != 'read-fit':
        fd = os.open(PRIVATE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    if mode == 'capture-data':
        evidence.closed(request, ('mode', 'inventory', 'source', 'target'))
        data = verify_volume_inventory(request['inventory'])
        if request['source'] not in data or request['target'] not in ('validation.jsonl', 'fixtures.jsonl', 'reserved-test.jsonl'):
            fail()
        directory = PRIVATE_ROOT/'datasets'
        directory.mkdir(mode=0o700, exist_ok=True)
        ref = exclusive(directory/request['target'], data[request['source']])
        return {'kind': 'private-capture-v1', 'file': str(directory/request['target']), 'sha256': ref['sha256']}
    if mode == 'capture-metadata':
        evidence.closed(request, ('mode', 'source_sha256', 'target'))
        if not re.fullmatch(r'(?:original|s0|programme|fit-inventory|S1-0|[EBQ]-[HF]-[1-5])\.json', request['target']):
            fail()
        raw = evidence.read_committed('/metadata-input.json', request['source_sha256'])
        target = PRIVATE_ROOT/request['target']
        ref = exclusive(target, raw)
        return {'kind': 'private-capture-v1', 'file': str(target), 'sha256': ref['sha256']}
    if mode == 'read-phase':
        evidence.closed(request, ('mode', 'phase', 'directory', 'expected_sha256'))
        directory = private_path(request['directory'])
        phase = request['phase']
        name = 'inventory.json' if phase in evidence.PHASES else 'receipt.json' if phase == 'pretest-barrier' else 'result.json'
        raw = evidence.read_committed(directory/name, request['expected_sha256'])
        if phase in evidence.PHASES:
            inventory = evidence.checked_json(raw, request['expected_sha256'])
            evidence.closed(inventory, ('schema_version', 'status', 'binding_sha256', 'files'))
            if inventory['status'] != 'complete':
                fail()
            return {'kind': 'private-phase-v1', 'phase': phase, 'raw_sha256': request['expected_sha256'], 'metadata': None}
        return {'kind': 'private-phase-v1', 'phase': phase, 'raw_sha256': request['expected_sha256'],
                'metadata': phase_metadata(phase, raw, request['expected_sha256'])}
    if mode == 'read-fit':
        evidence.closed(request, ('mode', 'manifest_sha256', 'arm'))
        if os.geteuid() != 65534 or request['arm'] not in contract.ARM_KEYS[1:]:
            fail()
        root = FIT_ROOT/'arm'
        for directory in (FIT_ROOT, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 65534 or stat.S_IMODE(info.st_mode) != 0o700:
                fail()
        def read_fit_file(name, digest, limit=evidence.MAX_INPUT_BYTES):
            path = root/name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 65534
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                fail()
            return evidence.read_committed(path, digest, limit)
        raw = read_fit_file('run-manifest.json', request['manifest_sha256'])
        value = evidence.checked_json(raw, request['manifest_sha256'])
        if value.get('arm_key') != request['arm'] or value.get('status') != 'complete':
            fail()
        records = value['checkpoint_records']
        allowed = ('epoch', 'steps', 'identity', 'artifact_file', 'artifact_sha256', 'initialization_sha256', 'permutation_sha256')
        sanitized, artifacts = [], {}
        for record in records:
            if not re.fullmatch(r'checkpoint-epoch-0[0-5]\.json', record['artifact_file']):
                fail()
            artifact_raw = read_fit_file(record['artifact_file'], record['artifact_sha256'], evidence.MAX_FRAME_BYTES)
            if artifact_identity(artifact_raw)[0] != record['identity']:
                fail()
            sanitized.append({k: record[k] for k in allowed})
            artifacts[record['artifact_file']] = base64.b64encode(artifact_raw).decode()
        evidence.closed(value['inputs_sha256'], ('expected_inputs_raw', 'training_view_manifest_raw', 'train_raw', 'original_train_prefix_raw', 'prepared_manifest_raw', 'programme_input_raw', 'programme', 'allocation_receipt', 'reviewed_labels_receipt', 'trainer_contract', 'dependency_lock'))
        for digest in value['inputs_sha256'].values():
            evidence.checked_hash(digest)
        manifest = {k: value[k] for k in ('status', 'arm_key', 'checkpoint_count', 'actual_training_image_id', 'test_scored', 'validation_read', 'inputs_sha256')}
        manifest['checkpoint_records'] = sanitized
        return {'kind': 'private-fit-export-v1', 'private_manifest_raw_sha256': request['manifest_sha256'],
                'manifest': manifest, 'artifacts': artifacts}
    fail()


class DockerBackend:
    """Real fixed Compose backend; never starts or rebuilds serving services."""
    def __init__(self, output, inputs, *, root=ROOT, runner=subprocess.run):
        self.output, self.inputs, self.root = Path(output), inputs, Path(root)
        self.runner = runner
        self.jobs = []
        self.unresolved = set()
        self.counter = 0
        self.evidence_volume = None
        self.created_volumes = []
        self.env = dict(os.environ)
        self.env.update(IN_HOUSE_EVALUATOR_IMAGE='sha256:'+inputs['images']['evaluator'],
                        IN_HOUSE_TRAINING_IMAGE='sha256:'+inputs['images']['training'])
        self.compose = ['docker', 'compose', '--project-directory', str(self.root)]
        for file in COMPOSE_FILES:
            self.compose += ['-f', str(self.root / file)]

    def create_volume(self, role):
        self.safe()
        name = f'in-house-{self.output.name}-{role}-{uuid.uuid4().hex[:8]}'
        # Creation is only of a fresh task-owned private volume; never deleted here.
        self.call(['docker', 'volume', 'create', '--label', 'privoke.in-house-study='+self.output.name, name])
        data = json.loads(self.call(['docker', 'volume', 'inspect', name]))
        if len(data) != 1 or data[0]['Name'] != name or data[0].get('Labels', {}).get('privoke.in-house-study') != self.output.name:
            fail()
        self.created_volumes.append(name)
        return name

    def private_store(self):
        if self.evidence_volume is None:
            self.evidence_volume = self.create_volume('evidence')
        return self.evidence_volume

    def helper(self, request, *, mounts=()):
        ref = save(self.output/f'private-request-{uuid.uuid4().hex}.json', request)
        fit_reader = request.get('mode') == 'read-fit'
        if fit_reader:
            if len(mounts) != 1 or mounts[0][1:] != (str(FIT_ROOT), True) or not mounts[0][0].startswith('volume:'):
                fail()
            os.chmod(ref['file'], 0o444)
        job_mounts = ((ref['file'], '/request.json', True), *mounts) if fit_reader else (
            (ref['file'], '/request.json', True), ('volume:'+self.private_store(), str(PRIVATE_ROOT), False), *mounts)
        raw, receipt = self.job('in-house-fit-reader' if fit_reader else 'in-house-evidence-job', ['python', '/workspace/evaluation/run-in-house-study.py',
            '--private-helper', '--request', '/request.json', '--request-sha256', ref['sha256'],
            '--controller-sha256', self.inputs['controller_sha256'], '--cli-sha256', self.inputs['cli_sha256']],
            mounts=job_mounts,
            timeout=120, request_sha256=ref['sha256'])
        value = evidence.checked_json(raw, raw_hash(raw))
        save(self.output/f'private-export-{uuid.uuid4().hex}.json', {'job_receipt_sha256': receipt, 'metadata': value})
        return value

    def capture_metadata(self, reference, name):
        result = self.helper({'mode': 'capture-metadata', 'source_sha256': reference['sha256'], 'target': name},
                             mounts=((reference['file'], '/metadata-input.json', True),))
        evidence.closed(result, ('kind', 'file', 'sha256'))
        if result != {'kind': 'private-capture-v1', 'file': str(PRIVATE_ROOT/name), 'sha256': reference['sha256']}:
            fail()
        return {k: result[k] for k in ('file', 'sha256')}

    def capture_dataset(self, descriptor, *, role):
        volume_reference({k: descriptor[k] for k in ('volume', 'file', 'sha256')})
        expected_file = {'validation': 'validation.jsonl', 'fixtures': 'fixtures.jsonl', 'test': 'reserved-test.jsonl'}[role]
        if descriptor['file'] != expected_file:
            fail()
        result = self.helper({'mode': 'capture-data', 'inventory': {expected_file: descriptor['sha256']},
            'source': expected_file, 'target': expected_file}, mounts=(('volume:'+descriptor['volume'], '/phase-data', True),))
        evidence.closed(result, ('kind', 'file', 'sha256'))
        if result != {'kind': 'private-capture-v1', 'file': str(PRIVATE_ROOT/'datasets'/expected_file), 'sha256': descriptor['sha256']}:
            fail()
        return {k: result[k] for k in ('file', 'sha256')}

    def call(self, argv, *, timeout=30):
        try:
            result = self.runner(argv, cwd=self.root, env=self.env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=timeout)
        except Exception:
            raise ControllerError('Container command observation failed.') from None
        if result.returncode:
            raise ControllerError('Container command exited unsuccessfully.')
        return result.stdout

    def safe(self):
        if self.unresolved:
            raise RemoteUnknown('Named remote operation remains unresolved; writes stopped.')

    def inspect(self, name):
        value = json.loads(self.call(['docker', 'inspect', name]))
        if type(value) is not list or len(value) != 1:
            fail()
        return value[0]

    def job(self, service, args, *, mounts=(), timeout=7200, request_sha256):
        self.safe()
        self.counter += 1
        name = f'in-house-{self.output.name}-{self.counter:04d}-{uuid.uuid4().hex[:8]}'
        self.unresolved.add(name)  # BEFORE launch; CLI timeout is not proof of no container.
        argv = self.compose + ['run', '-d', '--no-deps', '-T', '--name', name]
        for source, destination, readonly in mounts:
            if ',' in str(source) or any(c in str(source) for c in '\r\n'):
                fail()
            mounted_source = source.removeprefix('volume:') if str(source).startswith('volume:') else str(Path(source).resolve())
            argv += ['--volume', f'{mounted_source}:{destination}'+(':ro' if readonly else '')]
        argv += [service, *args]
        primary = None
        record = {'name': name, 'container_id': None, 'image_id': None,
                  'request_sha256': request_sha256, 'exit_code': None,
                  'terminal': False, 'logs_sha256': None}
        try:
            returned = self.call(argv, timeout=120).decode().strip()
            observed = self.inspect(name)
            if not re.fullmatch('[0-9a-f]{12,64}', returned) or not observed['Id'].startswith(returned):
                fail()
            role = 'training' if service == 'in-house-fit-job' else 'evaluator'
            record.update(container_id=observed['Id'], image_id=observed['Image'])
            if observed['Image'] != 'sha256:'+self.inputs['images'][role]:
                fail()
            config, host = observed['Config'], observed['HostConfig']
            if service in ('in-house-fit-reader', 'in-house-fit-job') and (
                    config.get('User') != '65534:65534' or host.get('CapDrop') != ['ALL']
                    or host.get('CapAdd') or host.get('SecurityOpt') != ['no-new-privileges:true']):
                fail()
            if (config['Cmd'] != list(args) or config.get('Labels', {}).get('com.docker.compose.service') != service
                    or host['ReadonlyRootfs'] is not True or host['Memory'] != 4*1024**3
                    or host['NanoCpus'] != 4_000_000_000
                    or service != 'in-house-evidence-job' and host['NetworkMode'] != 'none'):
                fail()
            expected_mounts = {target: readonly for _, target, readonly in mounts}
            if service == 'in-house-catalog-admin':
                expected_mounts['/models'] = False
            actual_mounts = {item['Destination']: not item['RW'] for item in observed['Mounts'] if item['Type'] in ('bind', 'volume')}
            if actual_mounts != expected_mounts:
                fail()
            for source, target, _ in mounts:
                observed_mount = next(item for item in observed['Mounts'] if item['Destination'] == target)
                if str(source).startswith('volume:'):
                    if observed_mount.get('Type') != 'volume' or observed_mount.get('Name') != str(source).removeprefix('volume:'):
                        fail()
                elif observed_mount.get('Type') != 'bind':
                    fail()
            self.call(['docker', 'wait', observed['Id']], timeout=timeout)
        except Exception as exc:
            primary = exc
        # A fresh state check, including after launch/wait timeout. Never force-remove
        # or retry an unknown/running job, and never infer terminal from CLI exit.
        try:
            observed = self.inspect(name)
            if record['container_id'] is not None and observed['Id'] != record['container_id']:
                fail()
            if observed['State']['Running'] or observed['State']['Status'] not in ('exited', 'dead'):
                raise RemoteUnknown('Named job is not proven terminal.')
            record.update(container_id=observed['Id'], image_id=observed['Image'],
                          exit_code=observed['State']['ExitCode'], terminal=True)
            logs = self.call(['docker', 'logs', observed['Id']])
            record['logs_sha256'] = raw_hash(logs)
            exclusive(self.output / f'job-{self.counter:04d}.log', logs)
            self.unresolved.remove(name)
        except Exception:
            primary = RemoteUnknown('Named job terminal state is unresolved; writes stopped.')
        receipt = save(self.output / f'job-{self.counter:04d}.json', record)
        self.jobs.append({**record, 'receipt_sha256': receipt['sha256']})
        if self.unresolved:
            raise RemoteUnknown('Named job outcome is unresolved; writes stopped.')
        if primary:
            raise primary
        if record['exit_code'] != 0 or record['image_id'] != 'sha256:'+self.inputs['images'][role]:
            fail()
        return logs, receipt['sha256']

    def quiescent(self):
        self.safe()
        for record in self.jobs:
            state = self.inspect(record['name'])
            if state['Id'] != record['container_id'] or state['Image'] != record['image_id'] or state['State']['Running'] or state['State']['Status'] not in ('exited', 'dead'):
                self.unresolved.add(record['name'])
                self.safe()
        return True

    def verify_external_job(self, proof):
        state = self.inspect(proof['name'])
        if (state['Id'] != proof['container_id'] or state['Image'] != proof['image_id']
                or state['State']['Running'] or state['State']['Status'] not in ('exited', 'dead')
                or state['State']['ExitCode'] != proof['exit_code']):
            fail()
        if not any(record['name'] == proof['name'] for record in self.jobs):
            self.jobs.append({'name': proof['name'], 'container_id': proof['container_id'],
                'image_id': proof['image_id'], 'exit_code': proof['exit_code'], 'terminal': True,
                'request_sha256': proof['request']['sha256'], 'receipt_sha256': proof['receipt']['sha256'], 'external_compatibility': True})

    def controls(self):
        self.safe()
        observed = {}
        configs = {}
        for service in IMAGE_ROLES[:3]:
            ids = self.call(self.compose + ['ps', '--status', 'running', '--quiet', service]).decode().splitlines()
            if len(ids) != 1:
                fail()
            item = self.inspect(ids[0])
            if (not item['State']['Running'] or item['State'].get('Health', {}).get('Status', 'healthy') != 'healthy'
                    or item['Image'] != 'sha256:'+self.inputs['images'][service]):
                fail()
            configs[service] = item['Config']
            observed[service] = {'container_id': item['Id'], 'image_id': item['Image']}
        if evidence.digest(configs) != self.inputs['effective_configuration']:
            fail()
        if 'FUZZER_PROMPT_COUNT=0' not in configs['param-update-service']['Env']:
            fail()
        if 'MODEL_LATEST_ID=privoke-balanced' not in configs['model-streaming-service']['Env']:
            fail()
        ttl_value = next((item.split('=', 1)[1] for item in configs['client-runtime']['Env']
                          if item.startswith('MODEL_STREAMING_CACHE_TTL_SECONDS=')), '1.0')
        try:
            ttl = float(ttl_value)
        except (TypeError, ValueError):
            fail()
        if not 0 <= ttl <= 60:
            fail()
        for service in ('privoke-fuzzer', 'presence-fuzzer', 'presence-update-service'):
            if self.call(self.compose + ['ps', '--status', 'running', '--quiet', service]).strip():
                fail()
        return observed

    def _admin(self, request):
        self.safe()
        ref = save(self.output / f'admin-request-{uuid.uuid4().hex}.json', request)
        # Host ancestor remains0700; this one explicit read-only file mount is
        # readable by the catalogue's existing10001 UID inside the isolated job.
        os.chmod(ref['file'], 0o444)
        raw, _ = self.job('in-house-catalog-admin', ['python', '-c', ADMIN, '/request.json', ref['sha256']],
                         mounts=((ref['file'], '/request.json', True),), timeout=120,
                         request_sha256=ref['sha256'])
        return json.loads(raw)

    def read_catalog(self, model_id):
        if model_id not in CATALOG_IDS:
            fail()
        result = self._admin({'operation': 'read', 'model_id': model_id,
                            'expected_raw_sha256': None, 'raw_b64': None, 'identity': None})
        evidence.closed(result, ('exists', 'raw_b64', 'raw_sha256'))
        if result['exists'] is False:
            if result['raw_b64'] is not None or result['raw_sha256'] is not None:
                fail()
            return None
        if result['exists'] is not True:
            fail()
        raw = base64.b64decode(result['raw_b64'], validate=True)
        if raw_hash(raw) != result['raw_sha256']:
            fail()
        return raw

    def mutate(self, model_id, raw, *, expected_raw_sha256):
        if model_id not in CATALOG_IDS or raw is None and model_id not in SCRATCH_IDS:
            fail()
        identity = None if raw is None else artifact_identity(raw)[0]
        result = self._admin({'operation': 'delete' if raw is None else 'write', 'model_id': model_id,
            'expected_raw_sha256': expected_raw_sha256, 'raw_b64': None if raw is None else base64.b64encode(raw).decode(),
            'identity': identity})
        expected = {'exists': raw is not None, 'raw_sha256': None if raw is None else raw_hash(raw)}
        if result != expected or self.read_catalog(model_id) != raw:
            fail()

    def probe(self, contextual, presence):
        ref = save(self.output / f'probe-{uuid.uuid4().hex}.json', {'contextual': contextual, 'presence': presence})
        raw, _ = self.job('in-house-evidence-job', ['python', '-c', PROBE, '/probe.json'],
                         mounts=((ref['file'], '/probe.json', True),), timeout=120, request_sha256=ref['sha256'])
        if json.loads(raw) != {'verified': True, 'identities': {'contextual': contextual, 'presence': presence}}:
            fail()

    def probe_absence(self, model_id):
        # Live Go unary lookup must fail for a removed prior-absent destination.
        script = "import grpc,sys,time;from privoke.v1 import parameters_pb2 as p,parameters_pb2_grpc as g,runtime_pb2 as r,runtime_pb2_grpc as rg\nwith grpc.insecure_channel('model-streaming-service:50051') as c:\n try:g.ModelStreamingServiceStub(c).GetModelParameters(p.ModelParametersRequest(model_id=sys.argv[1],consumer_id='in-house-study-controller'),timeout=10)\n except grpc.RpcError as e:\n  if e.code()!=grpc.StatusCode.NOT_FOUND:raise\n else:raise RuntimeError('Removed model remains available.')\ndeadline=time.monotonic()+65\nwith grpc.insecure_channel('client-runtime:50054') as c:\n while True:\n  x=rg.PrivokeRuntimeServiceStub(c).DetectAnnotationPresence(r.DetectAnnotationPresenceRequest(request_id='in-house-absence-probe',text='synthetic identity probe',model_id=sys.argv[1]),timeout=15)\n  if x.error and x.predicted_label==r.ANNOTATION_PRESENCE_UNSPECIFIED and not x.model_version and not x.artifact_checksum and not x.parameter_fingerprint:break\n  if time.monotonic()>=deadline:raise RuntimeError('Removed model remains cached.')\n  time.sleep(.25)\n"
        self.job('in-house-evidence-job', ['python', '-c', script, model_id], timeout=120,
                 request_sha256=evidence.digest({'absence': model_id}))
        if self.read_catalog(model_id) is not None:
            fail()

    def fit(self, arm, refs, output):
        output.mkdir(parents=True, mode=0o700)
        fit_volume = self.create_volume('fit-'+arm.lower())
        inventory = {refs[k]['file']: refs[k]['sha256'] for k in ('train', 'manifest')}
        permission_script = "import os,stat,json,hashlib,sys\ni=json.loads(sys.argv[1]);d=os.open('/phase-data',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\nif set(os.listdir(d))!=set(i):raise ValueError('Invalid train inventory.')\nfor n,h in i.items():\n f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=d)\n if not stat.S_ISREG(os.fstat(f).st_mode):raise ValueError('Invalid train input.')\n with os.fdopen(os.dup(f),'rb') as s:b=s.read(64*1024*1024+1)\n if len(b)>64*1024*1024 or hashlib.sha256(b).hexdigest()!=h:raise ValueError('Invalid train hash.')\n if os.fstat(f).st_uid!=65534:os.fchmod(f,0o600);os.fchown(f,65534,65534)\n elif stat.S_IMODE(os.fstat(f).st_mode)!=0o600:raise ValueError('Invalid train permissions.')\n os.close(f)\nif os.fstat(d).st_uid!=65534:os.fchmod(d,0o700);os.fchown(d,65534,65534)\nelif stat.S_IMODE(os.fstat(d).st_mode)!=0o700:raise ValueError('Invalid private directory permissions.')\nos.close(d)\nd=os.open('/fit-output',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\nif os.listdir(d):raise ValueError('Reused fit output.')\nif os.fstat(d).st_uid!=65534:os.fchmod(d,0o700);os.fchown(d,65534,65534)\nelif stat.S_IMODE(os.fstat(d).st_mode)!=0o700:raise ValueError('Invalid private directory permissions.')\nos.close(d)\n"
        self.job('in-house-data-permissions', ['python', '-c', permission_script, evidence.canonical(inventory).decode()],
            mounts=(('volume:'+refs['train']['volume'], '/phase-data', False), ('volume:'+fit_volume, '/fit-output', False)),
            timeout=120, request_sha256=evidence.digest({'arm': arm, 'operation': 'train-only-permissions', 'script_sha256': raw_hash(permission_script.encode())}))
        # Fixed training source CLI, captured privately. Only its actual manifest
        # RAW hash is emitted; no train labels/rows or untrusted stdout reaches host.
        script = "import subprocess,sys,json,hashlib;from pathlib import Path\nr=subprocess.run(['python','-B','/workspace/evaluation/fit-in-house-study-arm.py',*sys.argv[1:]],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\nif r.returncode:raise SystemExit(1)\nwith open('/fit-output/arm/run-manifest.json','rb') as f:b=f.read(256*1024+1)\nif len(b)>256*1024:raise SystemExit(1)\nprint(json.dumps({'manifest_sha256':hashlib.sha256(b).hexdigest()}))\n"
        args = ['python', '-c', script, '--arm', arm, '--train-file', '/train/train.jsonl',
            '--training-manifest', '/train/training-manifest.json', '--expected-inputs', '/expected.json',
            '--expected-inputs-sha256', refs['expected']['sha256'], '--output', '/fit-output/arm',
            '--source-revision', self.inputs['source_revision']]
        os.chmod(refs['expected']['file'], 0o444)
        raw, receipt = self.job('in-house-fit-job', args, mounts=(
            ('volume:'+refs['train']['volume'], '/train', True), ('volume:'+fit_volume, '/fit-output', False),
            (refs['expected']['file'], '/expected.json', True)), timeout=7200,
            request_sha256=evidence.digest({'arm': arm, 'inputs': refs, 'inventory': inventory}))
        produced = evidence.checked_json(raw, raw_hash(raw))
        evidence.closed(produced, ('manifest_sha256',))
        exported = self.helper({'mode': 'read-fit', 'manifest_sha256': produced['manifest_sha256'], 'arm': arm},
                               mounts=(('volume:'+fit_volume, '/private-fit-root', True),))
        evidence.closed(exported, ('kind', 'private_manifest_raw_sha256', 'manifest', 'artifacts'))
        if exported['kind'] != 'private-fit-export-v1' or exported['private_manifest_raw_sha256'] != produced['manifest_sha256']:
            fail()
        manifest = exported['manifest']
        expected_names = {item['artifact_file'] for item in manifest['checkpoint_records']}
        if set(exported['artifacts']) != expected_names:
            fail()
        for name, encoded in exported['artifacts'].items():
            if not re.fullmatch(r'checkpoint-epoch-0[0-5]\.json', name):
                fail()
            exclusive(output/name, base64.b64decode(encoded, validate=True))
        manifest['private_manifest_raw_sha256'] = produced['manifest_sha256']
        save(output/'manifest.json', manifest)
        return manifest, receipt

    def phase(self, phase, trust, output, evidence_root):
        ref = save(self.output / f'trust-{uuid.uuid4().hex}.json', {'schema_version': 1, 'phase': phase, 'inputs': trust})
        name = output.name
        if not re.fullmatch('[a-zA-Z0-9_-]{1,128}', name):
            fail()
        script = "import subprocess,sys,json,hashlib;from pathlib import Path\nr=subprocess.run(['python','/workspace/evaluation/evaluate-in-house-study.py',*sys.argv[1:]],stdout=subprocess.PIPE,stderr=subprocess.PIPE)\nif r.returncode:raise SystemExit(1)\nphase=sys.argv[sys.argv.index('--phase')+1];directory=Path(sys.argv[sys.argv.index('--output')+1]);name='inventory.json' if phase in ('collect-validation','rerun-validation','collect-fixtures','collect-test') else 'receipt.json' if phase=='pretest-barrier' else 'result.json'\nwith open(directory/name,'rb') as h:b=h.read(64*1024*1024+1)\nif len(b)>64*1024*1024:raise SystemExit(1)\nprint(json.dumps({'raw_sha256':hashlib.sha256(b).hexdigest()}))\n"
        raw, receipt = self.job('in-house-evidence-job', ['python', '-c', script,
             '--phase', phase, '--trust-bundle', '/trust.json', '--trust-bundle-sha256', ref['sha256'],
             '--output', str(PRIVATE_ROOT/name)], mounts=((ref['file'], '/trust.json', True),
                 ('volume:'+self.private_store(), str(PRIVATE_ROOT), False)), timeout=14400, request_sha256=ref['sha256'])
        produced = evidence.checked_json(raw, raw_hash(raw))
        evidence.closed(produced, ('raw_sha256',))
        metadata = self.helper({'mode': 'read-phase', 'phase': phase, 'directory': name, 'expected_sha256': produced['raw_sha256']})
        evidence.closed(metadata, ('kind', 'phase', 'raw_sha256', 'metadata'))
        if metadata['kind'] != 'private-phase-v1' or metadata['phase'] != phase or metadata['raw_sha256'] != produced['raw_sha256']:
            fail()
        return metadata | {'job_receipt_sha256': receipt, 'private_directory': str(PRIVATE_ROOT/name)}


class Controller:
    """One actual sequence, shared by real Docker and behavior-test backends."""
    def __init__(self, inputs, programme, output, backend, *, test_release_file):
        self.inputs, self.programme = inputs, programme
        self.output, self.backend = Path(output), backend
        self.test_release_file = test_release_file  # opaque locator; never inspected before barrier
        self.evidence_root = self.output/'evidence'
        self.state = {'schema_version': 1, 'status': 'running', 'phase': 'preflight',
            'test_released': False, 'test_scored': False, 'restoration_verified': False,
            'primary_failure': None, 'restoration_failures': [],
            'professor_confirmation': 'pending', 'fixture_labels': 'assistant-provisional',
            'programme_sha256': programme.sha256, 'jobs': [], 'events': []}
        self.backups, self.owned = {}, {}
        self.checkpoints = {}
        self.collections, self.live, self.fixtures, self.test = [], [], [], []
        self.event_number = 0
        self.output_identity = None

    def verify_output(self):
        current = self.output.stat()
        if self.output.is_symlink() or (current.st_dev, current.st_ino) != self.output_identity:
            fail()

    def record(self, phase):
        self.verify_output()
        self.event_number += 1
        self.state['phase'] = phase
        self.state['jobs'] = list(self.backend.jobs)
        self.state['retained_private_volumes'] = list(getattr(self.backend, 'created_volumes', ()))
        self.state['events'].append(phase)
        save(self.output/f'state-{self.event_number:04d}.json', self.state)

    def capture(self, reference, name):
        self.verify_output()
        return exclusive(self.evidence_root/name, read_reference(reference))

    def install(self, raw):
        self.backend.safe()
        identity, _ = artifact_identity(raw)
        model_id = identity['model_id']
        if model_id not in CATALOG_IDS or model_id not in self.backups:
            fail()
        expected = self.owned.get(model_id, None if self.backups[model_id] is None else raw_hash(self.backups[model_id]))
        # Mark mutation intent BEFORE remote launch. If terminal failure happened
        # after publication, restoration determines ownership by exact intended RAW.
        intended = raw_hash(raw)
        self.owned[model_id] = intended
        try:
            self.backend.mutate(model_id, raw, expected_raw_sha256=expected)
        except Exception:
            if not self.backend.unresolved:
                observed = self.backend.read_catalog(model_id)
                actual = None if observed is None else raw_hash(observed)
                if actual == expected:
                    if expected is None:
                        self.owned.pop(model_id, None)
                    else:
                        self.owned[model_id] = expected
                elif actual != intended:
                    # Collision is neither ours nor permission to overwrite.
                    self.owned[model_id] = intended
            raise
        return identity

    def backup(self):
        self.controls = self.backend.controls()
        validate_compatibility(self.inputs['compatibility'], self.inputs, self.backend)
        snapshots = {}
        for model_id in CATALOG_IDS:
            raw = self.backend.read_catalog(model_id)
            if model_id in LEGACY_IDS:
                if raw is None or artifact_identity(raw)[0] != self.inputs['prior_catalog'][model_id]:
                    fail()
                reference = exclusive(self.output/(model_id+'-prior.json'), raw)
                snapshots[model_id] = {'prior_exists': True, 'raw_reference': reference,
                                       'identity': self.inputs['prior_catalog'][model_id]}
            else:
                if raw is not None:
                    fail()
                snapshots[model_id] = {'prior_exists': False, 'raw_reference': None, 'identity': None}
            self.backups[model_id] = raw
        save(self.output/'catalog-backups.json', snapshots)
        self.record('ten-backups-verified')

    def controls_unchanged(self):
        attest_controller(self.inputs)
        self.backend.quiescent()
        if self.backend.controls() != self.controls:
            fail()
        self.verify_output()
        # Ensure all copied immutable inputs still match their exact reference.
        for path, digest in self.captured_hashes.items():
            evidence.read_committed(path, digest)

    def fit_all(self):
        self.record('fits')
        self.original = self.capture(self.inputs['original'], 'original.json')
        self.s0 = self.capture(self.inputs['s0'], 's0.json')
        self.programme_ref = self.capture(self.inputs['programme'], 'programme.json')
        self.validation = self.backend.capture_dataset(self.inputs['datasets']['validation'], role='validation')
        self.fixture_data = self.backend.capture_dataset(self.inputs['datasets']['fixtures'], role='fixtures')
        self.private_original = self.backend.capture_metadata(self.original, 'original.json')
        self.private_s0 = self.backend.capture_metadata(self.s0, 's0.json')
        self.private_programme = self.backend.capture_metadata(self.programme_ref, 'programme.json')
        self.checkpoints[('S0', 0)] = {'reference': self.s0, 'private_reference': self.private_s0, 'identity': vars(self.programme.s0),
            'threshold': artifact_identity(read_reference(self.s0))[1]['config']['threshold'], 'steps': 0,
            'initialization_sha256': None, 'permutation_sha256': None,
            'job_receipt_sha256': self.inputs['s0_job_receipt']}
        for arm in contract.ARM_KEYS[1:]:
            refs = self.inputs['fits'][arm]
            expected = json_reference(refs['expected'])
            # Actual A also checks the whole closed FitInputs schema and training
            # view. This joins root supplied commitments before launching a job.
            checks = {'arm_key': arm, 'programme_sha256': self.programme.sha256,
                      'programme_input_raw_sha256': self.inputs['programme']['sha256'],
                      'trainer_contract_sha256': self.inputs['trainer_contract_sha256'],
                      'source_revision': self.inputs['source_revision'],
                      'train_raw_sha256': refs['train']['sha256'],
                      'training_view_manifest_raw_sha256': refs['manifest']['sha256'],
                      'actual_training_image_id': 'sha256:'+self.inputs['images']['training'],
                      'prepared_manifest_raw_sha256': dict(self.programme.external_hashes)['prepared_manifest'],
                      'initialization_fingerprints': dict(self.programme.initialization_fingerprints)}
            if any(expected.get(k) != v for k, v in checks.items()):
                fail()
            # Snapshot only train inputs. Fit job never receives evidence_root.
            train_dir = self.output/'train-inputs'/arm
            train_dir.mkdir(parents=True, mode=0o700)
            captured = dict(refs)
            captured['expected'] = exclusive(train_dir/'expected.json', read_reference(refs['expected']))
            manifest, job_receipt = self.backend.fit(arm, captured, self.output/'fits'/arm)
            epochs = (0,) if arm == 'S1' else (1, 2, 3, 4, 5)
            if (manifest.get('status') != 'complete' or manifest.get('arm_key') != arm
                    or manifest.get('checkpoint_count') != len(epochs)
                    or [c['epoch'] for c in manifest.get('checkpoint_records', [])] != list(epochs)
                    or manifest.get('test_scored') is not False or manifest.get('validation_read') is not False
                    or manifest.get('actual_training_image_id') != checks['actual_training_image_id']
                    or manifest.get('inputs_sha256', {}).get('expected_inputs_raw') != captured['expected']['sha256']):
                fail()
            manifest_raw = (self.output/'fits'/arm/'manifest.json').read_bytes()
            if evidence.checked_json(manifest_raw, raw_hash(manifest_raw)) != manifest:
                fail()
            save(self.output/(arm+'-fit-verified.json'), {'export_manifest_sha256': raw_hash(manifest_raw),
                                                         'private_manifest_raw_sha256': manifest['private_manifest_raw_sha256'],
                                                         'manifest_claim_sha256': evidence.digest(manifest),
                                                         'job_receipt_sha256': job_receipt})
            for item in manifest['checkpoint_records']:
                epoch = item['epoch']
                if item['artifact_file'] != f'checkpoint-epoch-{epoch:02d}.json':
                    fail()
                raw = read_reference({'file': str(self.output/'fits'/arm/item['artifact_file']), 'sha256': item['artifact_sha256']}, evidence.MAX_FRAME_BYTES)
                identity, payload = artifact_identity(raw)
                if (identity != item['identity'] or identity['model_id'] != contract.ARMS[contract.ARM_KEYS.index(arm)].model_id
                        or identity['version'] != ('v1.0.0' if not epoch else f'v1.0.0+epoch.{epoch}')):
                    fail()
                if epoch and (item['steps'] != epoch*490 or item['initialization_sha256'] != dict(self.programme.initialization_fingerprints)[contract.ARMS[contract.ARM_KEYS.index(arm)].profile]
                        or item['permutation_sha256'] != contract.permutation_sha256(contract.ARMS[contract.ARM_KEYS.index(arm)].profile, epoch, 7832)):
                    fail()
                reference = exclusive(self.evidence_root/f'{arm}-{epoch}.json', raw)
                self.checkpoints[(arm, epoch)] = {'reference': reference, 'private_reference': self.backend.capture_metadata(reference, f'{arm}-{epoch}.json'), 'identity': identity,
                    'threshold': float(payload['config']['threshold']), 'steps': 0 if not epoch else epoch*490,
                    'initialization_sha256': item['initialization_sha256'],
                    'permutation_sha256': item['permutation_sha256'], 'job_receipt_sha256': job_receipt}
        if set(self.checkpoints) != set(CHECKPOINT_KEYS):
            fail()
        inventory = {'schema_version': 1, 'programme_sha256': self.programme.sha256,
            'trainer_contract_sha256': self.inputs['trainer_contract_sha256'], 'source_revision': self.inputs['source_revision'],
            'prepared_manifest_sha256': dict(self.programme.external_hashes)['prepared_manifest'], 'checkpoints': [
                {'arm': arm, 'epoch': epoch, **{k: self.checkpoints[(arm, epoch)][k] for k in
                  ('identity', 'steps', 'initialization_sha256', 'permutation_sha256', 'job_receipt_sha256')}} for arm, epoch in CHECKPOINT_KEYS]}
        self.fit_inventory = self.backend.capture_metadata(save(self.evidence_root/'fit-inventory.json', inventory), 'fit-inventory.json')
        self.captured_hashes = {str(path): raw_hash(path.read_bytes()) for path in self.evidence_root.iterdir() if path.is_file()}
        self.record('32-checkpoints-complete')

    def binding(self, phase, arm, epoch, threshold, selection=None, barrier=None):
        cp = self.checkpoints[(arm, epoch)]
        dataset = self.inputs['test_metadata'] if phase == 'collect-test' else self.inputs['datasets']['fixtures' if phase == 'collect-fixtures' else 'validation']
        external = dict(self.programme.external_hashes)
        return evidence.CollectionBinding(programme_sha256=self.programme.sha256,
            control_binding_sha256=self.inputs['control_binding_sha256'], phase=phase, arm=arm, epoch=epoch,
            contextual_identity=vars(self.programme.original_contextual), presence_identity=cp['identity'],
            decision_threshold=float(threshold), model_threshold=float(cp['threshold']),
            dataset_sha256=dataset['sha256'], dataset_rows=dataset['rows'], dataset_keys_sha256=dataset['keys_sha256'],
            source_revision=self.inputs['source_revision'], source_hashes=self.inputs['source_hashes'],
            operational_hashes={k: external[k] for k in ('runtime_image', 'evaluator_image', 'effective_configuration', 'fixture_rubric', 'fixture_review')} | {'protocol': dict(contract.PIN_ITEMS)['protocol']},
            run_nonce=self.output.name, selection_sha256=selection, barrier_sha256=barrier)

    def collect(self, phase, arm, epoch, threshold):
        cp = self.checkpoints[(arm, epoch)]
        self.install(read_reference(cp['reference'], evidence.MAX_FRAME_BYTES))
        self.backend.probe(vars(self.programme.original_contextual), cp['identity'])
        selection = None if phase == 'collect-validation' else self.selection
        barrier = self.barrier_receipt if phase == 'collect-test' else None
        binding = self.binding(phase, arm, epoch, threshold,
                               None if selection is None else selection['sha256'], None if barrier is None else barrier['sha256'])
        dataset = self.test_data if phase == 'collect-test' else self.fixture_data if phase == 'collect-fixtures' else self.validation
        inputs = {'binding': binding.as_dict(), 'dataset_file': dataset['file'],
                  'contextual_artifact': self.private_original['file'], 'presence_artifact': cp['private_reference']['file']}
        if selection is not None:
            inputs['selection'] = selection
        if barrier is not None:
            inputs.update(barrier_inputs=self.barrier_inputs, barrier_receipt=barrier)
        output = self.evidence_root/f'{phase}-{arm}-{epoch}'
        produced = self.backend.phase(phase, inputs, output, self.evidence_root)
        inventory = {'file': produced['private_directory']+'/inventory.json', 'sha256': produced['raw_sha256']}
        return {'binding': binding.as_dict(), 'directory': produced['private_directory'], 'inventory_sha256': inventory['sha256'],
                'dataset_file': dataset['file'], 'contextual_artifact': self.private_original['file'], 'presence_artifact': cp['private_reference']['file']}

    def phases(self):
        self.install(read_reference(self.original, evidence.MAX_FRAME_BYTES))
        for arm, epoch in CHECKPOINT_KEYS:
            self.collections.append(self.collect('collect-validation', arm, epoch, 0.0))
        self.record('32-validation-complete')
        selection_dir = self.evidence_root/'selection'
        produced = self.backend.phase('select-validation', {'checkpoints': self.collections}, selection_dir, self.evidence_root)
        self.selection = {'file': produced['private_directory']+'/result.json', 'sha256': produced['raw_sha256']}
        selected = produced['metadata']
        if selected.get('status') != 'eligible' or set(selected.get('selections') or ()) != set(contract.ARM_KEYS):
            fail()
        self.record('all8-choices-frozen')
        for arm in contract.ARM_KEYS:
            item = selected['selections'][arm]
            if item['identity'] != self.checkpoints[(arm, item['epoch'])]['identity']:
                fail()
            self.live.append(self.collect('rerun-validation', arm, item['epoch'], item['threshold']))
        for arm in contract.ARM_KEYS:
            item = selected['selections'][arm]
            self.fixtures.append(self.collect('collect-fixtures', arm, item['epoch'], item['threshold']))
        self.barrier_inputs = {'programme': self.private_programme, 'checkpoints': self.collections,
            'live': self.live, 'fixtures': self.fixtures, 'selection': self.selection, 'fit_inventory': self.fit_inventory}
        barrier_dir = self.evidence_root/'barrier'
        produced = self.backend.phase('pretest-barrier', self.barrier_inputs, barrier_dir, self.evidence_root)
        self.barrier_receipt = {'file': produced['private_directory']+'/receipt.json', 'sha256': produced['raw_sha256']}
        receipt = produced['metadata']
        if receipt.get('programme_sha256') != self.programme.sha256 or receipt.get('selection_raw_sha256') != self.selection['sha256']:
            fail()
        for arm in contract.ARM_KEYS:
            item = selected['selections'][arm]
            verify_barrier_metadata(self.binding('collect-test', arm, item['epoch'], item['threshold'], self.selection['sha256'], self.barrier_receipt['sha256']), receipt, self.selection['sha256'])
        # Pure receipt is insufficient: source/catalog and actual named jobs are
        # checked BEFORE opening the separately pinned release locator.
        self.controls_unchanged()
        self.record('authenticated-barrier-and-quiescence')
        release = json_reference({'file': self.test_release_file, 'sha256': self.inputs['test_release_sha256']})
        evidence.closed(release, ('schema_version', 'kind', 'programme_sha256', 'test_metadata', 'dataset'))
        if (type(release['schema_version']) is not int or release['schema_version'] != 1
                or release['kind'] != 'new-prospective-reserved-test-release-v1'
                or release['programme_sha256'] != self.programme.sha256 or release['test_metadata'] != self.inputs['test_metadata']):
            fail()
        volume_reference(release['dataset'])
        if release['dataset']['file'] != 'reserved-test.jsonl':
            fail()
        if release['dataset']['volume'] in {self.inputs['fits']['S1']['train']['volume'], *(v['volume'] for v in self.inputs['datasets'].values())}:
            fail()
        if release['dataset']['sha256'] != self.inputs['test_metadata']['sha256']:
            fail()
        self.test_data = self.backend.capture_dataset(release['dataset'], role='test')
        self.state['test_released'] = True
        self.record('test-released')
        for arm in contract.ARM_KEYS:
            item = selected['selections'][arm]
            self.test.append(self.collect('collect-test', arm, item['epoch'], item['threshold']))
        produced = self.backend.phase('analyze-test', {'barrier_inputs': self.barrier_inputs, 'barrier_receipt': self.barrier_receipt,
            'test': self.test, 'selection': self.selection}, self.evidence_root/'endpoint', self.evidence_root)
        result = produced['metadata']
        if (result.get('status') != 'complete' or result.get('rows') != 2000
                or result.get('positive_examples') != 1000 or result.get('absent_examples') != 1000
                or set(result.get('arm_metrics', {})) != set(contract.ARM_KEYS)
                or result.get('test_authorized') is not False or result.get('retention_decision') is not None):
            fail()
        self.state['endpoint_raw_sha256'] = produced['raw_sha256']
        self.state['test_scored'] = True
        self.record('all8-endpoint-complete')

    def restore(self):
        self.backend.safe()
        self.backend.quiescent()
        for model_id in CATALOG_IDS:
            if model_id not in self.backups:
                continue
            prior = self.backups[model_id]
            observed = self.backend.read_catalog(model_id)
            if observed == prior:
                if prior is None:
                    try:
                        self.backend.probe_absence(model_id)
                    except Exception as exc:
                        self.state['restoration_failures'].append({'model_id': model_id, 'error_type': type(exc).__name__})
                        if self.backend.unresolved:
                            break
                continue
            actual = None if observed is None else raw_hash(observed)
            if model_id not in self.owned or actual != self.owned[model_id]:
                self.state['restoration_failures'].append({'model_id': model_id, 'error_type': 'CASCollision'})
                continue
            try:
                self.backend.mutate(model_id, prior, expected_raw_sha256=actual)
                if prior is None:
                    self.backend.probe_absence(model_id)
            except Exception as exc:
                self.state['restoration_failures'].append({'model_id': model_id, 'error_type': type(exc).__name__})
                if isinstance(exc, RemoteUnknown) or self.backend.unresolved:
                    break
        if self.backend.unresolved:
            raise RemoteUnknown('Restoration operation remains unresolved.')
        for model_id, prior in self.backups.items():
            if self.backend.read_catalog(model_id) != prior:
                self.state['restoration_failures'].append({'model_id': model_id, 'error_type': 'RestoreMismatch'})
        # Typed restored prior pair, plus exact RAW of all four legacy files.
        if not self.state['restoration_failures'] and len(self.backups) == 10:
            for model_id in LEGACY_IDS[1:]:
                self.backend.probe(self.inputs['prior_catalog']['privoke-balanced'], self.inputs['prior_catalog'][model_id])
            self.controls_unchanged()
            self.state['restoration_verified'] = True

    def run(self):
        if self.output.exists() or any(p.is_symlink() for p in self.output.parents):
            fail()
        if not re.fullmatch('[a-zA-Z0-9_-]{16,64}', self.output.name):
            fail()
        self.output.mkdir(mode=0o700)
        current = self.output.stat()
        self.output_identity = current.st_dev, current.st_ino
        self.evidence_root.mkdir(mode=0o700)
        self.captured_hashes = {}
        try:
            self.record('preflight')
            self.backup()
            self.fit_all()
            self.controls_unchanged()
            self.phases()
        except Exception as exc:
            self.state['primary_failure'] = {'error_type': type(exc).__name__}
        finally:
            try:
                self.restore()
            except Exception as exc:
                self.state['restoration_failures'].append({'error_type': type(exc).__name__})
            self.state['status'] = ('completed' if self.state['primary_failure'] is None
                and self.state['restoration_verified'] and self.state['test_scored'] else 'failed')
            self.state['unresolved_jobs'] = sorted(self.backend.unresolved)
            self.record('terminal')
            save(self.output/'manifest.json', self.state)
        return self.state


def run_study(*, inputs_file, inputs_sha256, test_release_file, output, backend_factory=DockerBackend):
    inputs = json_reference({'file': str(inputs_file), 'sha256': inputs_sha256})
    programme = validate_inputs(inputs)
    attest_controller(inputs)
    output = Path(output)
    try:
        output.resolve().relative_to((ROOT/'evaluation/results').resolve())
    except ValueError:
        fail()
    return Controller(inputs, programme, output, backend_factory(output, inputs), test_release_file=str(test_release_file)).run()
