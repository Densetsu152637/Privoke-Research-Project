"""Raw evidence boundary. Never trains, writes a catalogue, or authorizes test access."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import importlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from types import MappingProxyType
from collections.abc import Mapping

from . import in_house_study_analysis as analysis
from . import in_house_study_contract as contract

MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
PHASES = ('collect-validation', 'rerun-validation', 'collect-fixtures', 'collect-test')
IDENTITY_KEYS = frozenset(('model_id', 'version', 'artifact_sha256', 'artifact_checksum', 'parameter_fingerprint'))
SOURCE_ROLES = frozenset(('caller', 'evidence', 'analysis', 'contract', 'artifact', 'fingerprint', 'presence', 'scratch', 'runtime_pb2', 'runtime_pb2_grpc'))
_HEX = re.compile(r'^[0-9a-f]{64}$')
_AUTH = object()
_SEAL_KEY = os.urandom(32)


class StudyEvidenceError(ValueError):
    """Sanitized failure; input paths, identifiers and prompts never appear."""


def fail():
    raise StudyEvidenceError('Study raw evidence is invalid, incomplete or unauthenticated.')


def sha(raw):
    if type(raw) is not bytes:
        fail()
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, OverflowError):
        fail()


def digest(value):
    return sha(canonical(value))


def checked_hash(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        fail()
    return value


def closed(value, keys):
    if not isinstance(value, Mapping) or set(value) != set(keys):
        fail()
    return value


def checked_json(raw, expected_sha256, limit=MAX_INPUT_BYTES):
    """Hash captured bytes BEFORE decoding; reject duplicate and nonfinite JSON."""
    if type(raw) is not bytes or len(raw) > limit or sha(raw) != checked_hash(expected_sha256):
        fail()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail()
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=lambda _: fail())
    except (UnicodeError, ValueError, RecursionError):
        fail()


def read_committed(path, expected_sha256, limit=MAX_INPUT_BYTES):
    """Read a nonlink regular file once and verify the exact consumed bytes."""
    try:
        if Path(path).is_symlink():
            fail()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                fail()
            raw = handle.read(limit + 1)
    except OSError:
        fail()
    if len(raw) > limit or sha(raw) != checked_hash(expected_sha256):
        fail()
    return raw


def _identity(value):
    closed(value, IDENTITY_KEYS)
    if any(type(value[k]) is not str or not value[k] for k in ('model_id', 'version')):
        fail()
    for key in ('artifact_sha256', 'artifact_checksum', 'parameter_fingerprint'):
        checked_hash(value[key])
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class CollectionBinding:
    """Externally pinned metadata; dataset and selection hashes mean RAW bytes."""
    programme_sha256: str
    control_binding_sha256: str
    phase: str
    arm: str
    epoch: int
    contextual_identity: Mapping
    presence_identity: Mapping
    decision_threshold: float
    model_threshold: float
    dataset_sha256: str
    dataset_rows: int
    dataset_keys_sha256: str
    source_revision: str
    source_hashes: Mapping
    operational_hashes: Mapping
    run_nonce: str
    selection_sha256: str | None = None
    barrier_sha256: str | None = None

    def __post_init__(self):
        for name in ('programme_sha256', 'control_binding_sha256', 'dataset_sha256', 'dataset_keys_sha256'):
            checked_hash(getattr(self, name))
        if self.phase not in PHASES or self.arm not in contract.ARM_KEYS:
            fail()
        definition = contract.ARMS[contract.ARM_KEYS.index(self.arm)]
        if type(self.epoch) is not int or self.epoch not in ((0,) if self.arm.startswith('S') else (1, 2, 3, 4, 5)):
            fail()
        context, presence = _identity(self.contextual_identity), _identity(self.presence_identity)
        if (context['model_id'] != 'privoke-balanced' or context['version'] != 'v0.3.0'
                or context['artifact_checksum'] != '8390b96871c6edd00916e3a6126da1b09c19f9fdbdda8214ebe667a893e5ee2c'
                or presence['model_id'] != definition.model_id
                or presence['version'] != ('v1.0.0' if not self.epoch else f'v1.0.0+epoch.{self.epoch}')):
            fail()
        for value in (self.decision_threshold, self.model_threshold):
            if type(value) is not float or not math.isfinite(value) or not 0 <= value <= 1:
                fail()
        if self.phase == 'collect-validation' and self.decision_threshold != 0.0:
            fail()
        if not self.arm.startswith('S') and self.model_threshold != .5:
            fail()
        if type(self.dataset_rows) is not int or self.dataset_rows != (48 if self.phase == 'collect-fixtures' else 2000):
            fail()
        if type(self.source_revision) is not str or re.fullmatch(r'[0-9a-f]{40}', self.source_revision) is None:
            fail()
        if type(self.run_nonce) is not str or re.fullmatch(r'[a-zA-Z0-9_-]{16,64}', self.run_nonce) is None:
            fail()
        closed(self.source_hashes, SOURCE_ROLES)
        closed(self.operational_hashes, ('runtime_image', 'evaluator_image', 'effective_configuration', 'protocol', 'fixture_rubric', 'fixture_review'))
        for value in (*self.source_hashes.values(), *self.operational_hashes.values()):
            checked_hash(value)
        if self.operational_hashes['protocol'] != dict(contract.PIN_ITEMS)['protocol']:
            fail()
        if self.phase != 'collect-validation':
            checked_hash(self.selection_sha256)
        elif self.selection_sha256 is not None:
            fail()
        if self.phase == 'collect-test':
            checked_hash(self.barrier_sha256)
        elif self.barrier_sha256 is not None:
            fail()
        for name, value in (('contextual_identity', context), ('presence_identity', presence),
                            ('source_hashes', MappingProxyType(dict(self.source_hashes))),
                            ('operational_hashes', MappingProxyType(dict(self.operational_hashes)))):
            object.__setattr__(self, name, value)

    def as_dict(self):
        return {key: dict(value) if isinstance(value, Mapping) else value for key, value in vars(self).items()}

    @property
    def sha256(self):
        return digest(self.as_dict())


def attest_sources(binding):
    """Verify actual imported module origins, loader code and live public functions."""
    names = {'evidence': __name__, 'analysis': analysis.__name__, 'contract': contract.__name__,
             'artifact': 'privoke_model.artifact', 'fingerprint': 'privoke_model.fingerprint',
             'presence': 'privoke_model.presence', 'scratch': 'privoke_model.scratch_presence',
             'runtime_pb2': 'privoke.v1.runtime_pb2', 'runtime_pb2_grpc': 'privoke.v1.runtime_pb2_grpc'}
    read_committed(Path(__file__).resolve().parents[1] / 'evaluate-in-house-study.py', binding.source_hashes['caller'], MAX_FRAME_BYTES)
    for role, name in names.items():
        _attest_module(importlib.import_module(name), binding.source_hashes[role])
    return dict(binding.source_hashes)


def _attest_module(module, expected_sha256):
    """Check defining source code including nested function/method constants."""
    try:
        origin = Path(module.__file__).resolve()
        spec_origin = module.__spec__.origin if module.__spec__ is not None else module.__file__ if module.__name__ == '__main__' else None
        if spec_origin is None or origin != Path(spec_origin).resolve() or origin.suffix != '.py':
            fail()
        raw = read_committed(origin, expected_sha256, MAX_FRAME_BYTES)
        expected = compile(raw, str(origin), 'exec', dont_inherit=True)
        if expected != module.__loader__.get_code(module.__name__):
            fail()
        codes = {item.co_name: item for item in expected.co_consts if inspect.iscode(item) and item.co_name.isidentifier()}
        for name, code in codes.items():
            value = vars(module).get(name)
            if code.co_flags & inspect.CO_NEWLOCALS and not inspect.isfunction(value):
                fail()
            if inspect.isfunction(value) and (value.__module__ != module.__name__ or value.__code__ != code
                                              or value.__globals__ is not vars(module)):
                fail()
            if not code.co_flags & inspect.CO_NEWLOCALS and not inspect.isclass(value):
                fail()
            if inspect.isclass(value):
                if value.__module__ != module.__name__:
                    fail()
                methods = {item.co_name: item for item in code.co_consts if inspect.iscode(item) and item.co_name.isidentifier()}
                for method_name, method_code in methods.items():
                    method = vars(value).get(method_name)
                    if isinstance(method, (staticmethod, classmethod)):
                        method = method.__func__
                    if isinstance(method, property):
                        method = method.fget
                    if (not inspect.isfunction(method) or method.__code__ != method_code
                            or method.__globals__ is not vars(module)):
                        fail()
    except (OSError, AttributeError, TypeError, SyntaxError, ValueError, ImportError):
        fail()


def opaque(kind, value):
    if kind not in ('row', 'group') or type(value) is not str:
        fail()
    return sha(('privoke-in-house-' + kind + '-v1\0' + value).encode('utf-8'))


def dataset_rows(raw, binding):
    if sha(raw) != binding.dataset_sha256 or len(raw) > MAX_INPUT_BYTES:
        fail()
    rows = []
    for line in raw.splitlines():
        item = checked_json(line, sha(line), MAX_FRAME_BYTES)
        base = {'id', 'group_id', 'text', 'expected_has_pii'}
        fixture = {'ambiguous', 'required_sensitive', 'required_action', 'visibility_hint'}
        closed(item, base | fixture if binding.phase == 'collect-fixtures' else base)
        if any(type(item[k]) is not str or not item[k] for k in ('id', 'group_id', 'text')):
            fail()
        if len(item['text']) > 100000 or any(0xD800 <= ord(ch) <= 0xDFFF for ch in item['text']):
            fail()
        if binding.phase == 'collect-fixtures':
            if type(item['ambiguous']) is not bool or item['visibility_hint'] not in (None, 'P0', 'P1', 'P2', 'P3', 'P4', 'PU'):
                fail()
            if item['ambiguous']:
                if any(item[k] is not None for k in ('expected_has_pii', 'required_sensitive', 'required_action')):
                    fail()
            elif (type(item['required_sensitive']) is not bool or type(item['expected_has_pii']) is not bool
                  or item['required_action'] not in ('ALLOW', 'WARN', 'BLOCK')):
                fail()
        elif type(item['expected_has_pii']) is not bool:
            fail()
        rows.append(item)
    if len(rows) != binding.dataset_rows or len({r['id'] for r in rows}) != len(rows):
        fail()
    keys = [{'row_id_sha256': opaque('row', r['id']), 'group_id_sha256': opaque('group', r['group_id']), 'truth': r['expected_has_pii']} for r in rows]
    if digest(keys) != binding.dataset_keys_sha256:
        fail()
    if binding.phase != 'collect-fixtures':
        if sum(r['expected_has_pii'] for r in rows) != 1000 or any(len({r['group_id'] for r in rows if r['expected_has_pii'] is truth}) < 200 for truth in (False, True)):
            fail()
    else:
        if (sum(r['ambiguous'] for r in rows) != 7
                or sum(r['required_sensitive'] is True for r in rows) != 17
                or sum(r['required_sensitive'] is False for r in rows) != 24
                or sorted(r['visibility_hint'] for r in rows if r['visibility_hint'] is not None) != ['P0', 'P3', 'P4', 'PU']):
            fail()
    return tuple(rows)


def artifact_identity(raw, expected):
    from privoke_model.artifact import validate_artifact, float32
    from privoke_model.fingerprint import parameter_fingerprint
    payload = checked_json(raw, expected['artifact_sha256'], MAX_FRAME_BYTES)
    try:
        validate_artifact(payload)
        parameters = {name: [float32(x) for x in tensor['values']] for name, tensor in payload['parameters'].items()}
        shapes = {name: tensor['shape'] for name, tensor in payload['parameters'].items()}
        observed = {'model_id': payload['model_id'], 'version': payload['version'], 'artifact_sha256': sha(raw),
                    'artifact_checksum': payload['checksum'], 'parameter_fingerprint': parameter_fingerprint(parameters, shapes)}
    except (ValueError, TypeError, KeyError, OverflowError):
        fail()
    if observed != dict(expected):
        fail()
    return payload


class WireCodec:
    """Actual generated protobuf codec; no runtime implementation import."""
    def __init__(self):
        from privoke.v1 import runtime_pb2
        from google.protobuf.json_format import MessageToDict
        self.pb = runtime_pb2
        self.convert = MessageToDict

    def request(self, binding, row, purpose):
        request_id = 'in-house-' + digest({'binding': binding.sha256, 'row': opaque('row', row['id']), 'purpose': purpose})
        pb = self.pb
        kwargs = dict(text=row['text'], source='in-house-study-evaluation', request_id=request_id,
                      semantic_model_id=binding.contextual_identity['model_id'],
                      layers=[pb.DETECTION_LAYER_REGEX, pb.DETECTION_LAYER_NER],
                      regex_execution_order=pb.REGEX_EXECUTION_ORDER_FIRST)
        if purpose != 'nonsemantic':
            kwargs['layers'].append(pb.DETECTION_LAYER_SEMANTIC)
        if row.get('visibility_hint') is not None:
            kwargs['visibility_hint'] = row['visibility_hint']
        if purpose == 'gated':
            kwargs['semantic_presence_gate'] = pb.SemanticPresenceGate(
                model_id=binding.presence_identity['model_id'], threshold=binding.decision_threshold)
        elif purpose not in ('ordinary', 'nonsemantic'):
            fail()
        return pb.AnalyzePromptRequest(**kwargs)

    def parse_response(self, raw):
        if type(raw) is not bytes or len(raw) > MAX_FRAME_BYTES:
            fail()
        try:
            response = self.pb.AnalyzePromptResponse.FromString(raw)
            clean = self.pb.AnalyzePromptResponse()
            clean.CopyFrom(response)
            clean.DiscardUnknownFields()
            if clean.SerializeToString(deterministic=True) != response.SerializeToString(deterministic=True):
                fail()
            if not response.HasField('classification'):
                fail()
            try:
                result = self.convert(response, preserving_proto_field_name=True, always_print_fields_with_no_presence=True)
            except TypeError:
                result = self.convert(response, preserving_proto_field_name=True, including_default_value_fields=True)
            return response, result
        except Exception:
            raise StudyEvidenceError('Invalid protobuf response.') from None


class RuntimeClient:
    """Receive original gRPC response frames, not reserialized message bytes."""
    def __init__(self, target):
        import grpc
        self.channel = grpc.insecure_channel(target)
        self.call = self.channel.unary_unary('/privoke.v1.PrivokeRuntimeService/AnalyzePrompt',
                    request_serializer=lambda request: request.SerializeToString(deterministic=True),
                    response_deserializer=lambda raw: raw)

    def analyze(self, request):
        return self.call(request, timeout=120)

    def close(self):
        self.channel.close()


def _layers(response):
    if response.get('error') or type(response.get('layers')) is not list or len(response['layers']) != 3:
        fail()
    names = {'DETECTION_LAYER_REGEX': 'regex', 'DETECTION_LAYER_NER': 'ner', 'DETECTION_LAYER_SEMANTIC': 'semantic'}
    result = {}
    for layer in response['layers']:
        name = names.get(layer.get('layer'))
        if name is None or name in result or layer.get('status') not in ('ok', 'skipped', 'not_requested'):
            fail()
        if layer['status'] == 'ok' and layer.get('error'):
            fail()
        if layer['status'] != 'ok' and layer.get('results'):
            fail()
        result[name] = layer
    return result


def outcome_claim(response):
    layers = _layers(response)
    classification = response.get('classification')
    if not isinstance(classification, dict) or type(response.get('masked_text')) is not str:
        fail()
    result = {'status': 'complete', 'error_count': 0,
        'classification': {key: classification.get(key) for key in ('sensitivity', 'visibility', 'categories')},
        'action': response.get('action'), 'allowed': response.get('allowed'),
        'masked_text_sha256': sha(response['masked_text'].encode('utf-8')),
        'evidence_sha256': digest(response['evidence']) if 'evidence' in response else None,
        'layers': {name: {'status': item['status'], 'results_sha256': digest(item.get('results', [])) if item['status'] == 'ok' else None,
                         'skip_reason': None if item['status'] == 'ok' else item.get('error')} for name, item in layers.items()}}
    classification = result['classification']
    categories = classification['categories']
    if (type(classification['sensitivity']) is not str or classification['sensitivity'] not in ('S0', 'S1', 'S2', 'S3')
            or type(classification['visibility']) is not str or classification['visibility'] not in ('P0', 'P1', 'P2', 'P3', 'P4', 'PU')
            or type(categories) is not list or any(type(x) is not str for x in categories)
            or len(set(categories)) != len(categories)
            or any(x not in ('HEALTH', 'POLITICS', 'RELIGION', 'CRIMINAL', 'FINANCIAL', 'SEXUAL', 'CHILD', 'LOCATION', 'IDENTITY', 'THIRD_PARTY') for x in categories)
            or result['action'] not in ('ALLOW', 'WARN', 'BLOCK') or type(result['allowed']) is not bool
            or result['allowed'] is not (result['action'] != 'BLOCK') or layers['regex']['status'] != 'ok'):
        fail()
    nonsemantic = layers['semantic']['status'] == 'not_requested'
    shortcut = result['action'] == 'BLOCK' and layers['ner']['status'] == 'skipped'
    for name in ('ner', 'semantic'):
        layer = layers[name]
        if name == 'semantic' and nonsemantic:
            if layer.get('error') != analysis.NOT_REQUESTED_REASON:
                fail()
        elif shortcut:
            if layer['status'] != 'skipped' or layer.get('error') != analysis.REGEX_BLOCK_REASON:
                fail()
        elif layer['status'] != 'ok':
            fail()
    return result


def trace_claim(response, binding):
    semantic = _layers(response)['semantic']
    gate = semantic.get('semantic_presence_gate')
    if not isinstance(gate, dict) or gate.get('model_id') != binding.presence_identity['model_id']:
        fail()
    if type(gate.get('decision_threshold')) is not float or gate['decision_threshold'] != binding.decision_threshold:
        fail()
    status = gate.get('status')
    if status == 'SEMANTIC_PRESENCE_GATE_STATUS_NOT_RUN':
        if (semantic['status'] != 'skipped' or gate.get('error') != analysis.REGEX_BLOCK_REASON
                or semantic.get('error') != analysis.REGEX_BLOCK_REASON
                or any(key in gate for key in ('probability', 'model_threshold'))
                or any(gate.get(key) for key in ('model_version', 'artifact_checksum', 'parameter_fingerprint',
                       'contextual_model_id', 'contextual_model_version', 'contextual_artifact_checksum', 'contextual_parameter_fingerprint', 'semantic_results'))
                or gate.get('predicted_label') != 'ANNOTATION_PRESENCE_UNSPECIFIED'):
            fail()
        return {'status': 'NOT_RUN', 'model_id': gate['model_id'], 'identity': None, 'probability': None,
                'model_threshold': None, 'decision_threshold': binding.decision_threshold,
                'predicted_label': None, 'semantic_results_sha256': None}
    if status != 'SEMANTIC_PRESENCE_GATE_STATUS_APPLIED' or gate.get('error') or semantic['status'] != 'ok':
        fail()
    for prefix, identity in (('', binding.presence_identity), ('contextual_', binding.contextual_identity)):
        for field, key in (('model_id', 'model_id'), ('model_version', 'version'), ('artifact_checksum', 'artifact_checksum'), ('parameter_fingerprint', 'parameter_fingerprint')):
            if gate.get(prefix + field) != identity[key]:
                fail()
    probability = gate.get('probability')
    if (type(probability) is not float or not math.isfinite(probability) or not 0 <= probability <= 1
            or type(gate.get('model_threshold')) is not float or gate['model_threshold'] != binding.model_threshold):
        fail()
    label = 'PRESENT' if probability >= binding.decision_threshold else 'ABSENT'
    if gate.get('predicted_label') != 'ANNOTATION_PRESENCE_' + label:
        fail()
    return {'status': 'APPLIED', 'model_id': gate['model_id'],
            'identity': {'model_id': gate['model_id'], 'model_version': gate['model_version'],
                         'artifact_checksum': gate['artifact_checksum'], 'parameter_fingerprint': gate['parameter_fingerprint']},
            'probability': probability, 'model_threshold': float(gate['model_threshold']),
            'decision_threshold': binding.decision_threshold, 'predicted_label': label,
            'semantic_results_sha256': digest(gate.get('semantic_results', []))}


def verify_gate_retention(outcome, trace):
    """Check the producer's decision/result relationship before sealing a row."""
    layers = outcome['layers']
    if trace['status'] == 'APPLIED':
        if trace['predicted_label'] not in ('PRESENT', 'ABSENT'):
            fail()
        expected = trace['semantic_results_sha256'] if trace['predicted_label'] == 'PRESENT' else digest([])
        if (layers['semantic']['status'] != 'ok'
                or layers['semantic']['results_sha256'] != expected
                or any(layers[name]['status'] != 'ok' for name in ('regex', 'ner'))):
            fail()
    elif trace['status'] == 'NOT_RUN':
        if (outcome['action'] != 'BLOCK' or layers['regex']['status'] != 'ok'
                or any(layers[name]['status'] != 'skipped'
                       or layers[name]['skip_reason'] != analysis.REGEX_BLOCK_REASON
                       or layers[name]['results_sha256'] is not None for name in ('ner', 'semantic'))):
            fail()
    else:
        fail()


class PrivateWriter:
    """Fresh POSIX directory held by FD; relative exclusive writes, no cleanup."""
    def __init__(self, output):
        if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW'):
            fail()
        self.path = Path(output)
        if any(p.is_symlink() for p in (self.path, *self.path.parents)):
            fail()
        try:
            self.path.mkdir(mode=0o700, parents=False, exist_ok=False)
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.inode = os.fstat(self.fd)
        except OSError:
            fail()

    def write(self, name, raw):
        if type(name) is not str or re.fullmatch(r'[a-zA-Z0-9_-]+[.]json', name) is None or type(raw) is not bytes:
            fail()
        try:
            current = self.path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (self.inode.st_dev, self.inode.st_ino):
                fail()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(self.fd)
            current = self.path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (self.inode.st_dev, self.inode.st_ino):
                fail()
        except OSError:
            fail()
        return sha(raw)

    def close(self):
        os.close(self.fd)


@dataclass(frozen=True)
class AuthenticatedCollection:
    binding: CollectionBinding
    _claims_raw: bytes = field(repr=False)
    inventory_sha256: str
    _joins_raw: bytes = field(repr=False)
    _provenance_raw: bytes = field(repr=False)
    _seal: str = field(repr=False, default='')
    _authority: object = field(repr=False, default=None)

    def __post_init__(self):
        if self._authority is not _AUTH or not hmac.compare_digest(self._seal, _collection_seal(self.binding, self._claims_raw, self.inventory_sha256, self._joins_raw, self._provenance_raw)):
            fail()

    @property
    def rows(self):
        # Each access returns copies; caller mutation cannot change authenticated data.
        return tuple(checked_json(self._claims_raw, sha(self._claims_raw)))

    @property
    def raw_joins(self):
        return tuple(checked_json(self._joins_raw, sha(self._joins_raw)))

    @property
    def artifact_provenance(self):
        return checked_json(self._provenance_raw, sha(self._provenance_raw))


def _collection_seal(binding, claims_raw, inventory_sha256, joins, provenance):
    return hmac.new(_SEAL_KEY, canonical({'binding': binding.sha256, 'claims': sha(claims_raw),
                    'inventory': inventory_sha256, 'joins': sha(joins), 'provenance': sha(provenance)}), hashlib.sha256).hexdigest()


def _purposes(binding):
    if binding.phase in ('collect-validation', 'collect-fixtures'):
        return ('ordinary', 'gated', 'nonsemantic')
    return ('gated',)


def collect_rows(client, binding, rows, writer, codec=None):
    """Capture frames before parsing; retain partial evidence on failure."""
    codec = codec or WireCodec()
    if type(codec) is not WireCodec:
        fail()
    entries = []
    try:
        for index, row in enumerate(rows):
            for purpose in _purposes(binding):
                request = codec.request(binding, row, purpose)
                request_raw = request.SerializeToString(deterministic=True)
                start = time.monotonic_ns()
                response_raw = client.analyze(request)
                elapsed = time.monotonic_ns() - start
                if type(response_raw) is not bytes or len(response_raw) > MAX_FRAME_BYTES:
                    fail()
                frame = {'schema_version': 1, 'binding_sha256': binding.sha256, 'row_index': index,
                         'purpose': purpose, 'request_b64': base64.b64encode(request_raw).decode('ascii'),
                         'response_b64': base64.b64encode(response_raw).decode('ascii'),
                         'request_sha256': sha(request_raw), 'response_sha256': sha(response_raw), 'elapsed_ns': elapsed}
                name = f'rpc-{index:04d}-{purpose}.json'
                frame_sha = writer.write(name, canonical(frame))
                entries.append({'file': name, 'sha256': frame_sha})
                response, parsed = codec.parse_response(response_raw)
                if response.request_id != request.request_id:
                    fail()
                outcome_claim(parsed)
                if purpose == 'gated':
                    verify_gate_retention(outcome_claim(parsed), trace_claim(parsed, binding))
        inventory = {'schema_version': 1, 'status': 'complete', 'binding_sha256': binding.sha256, 'files': entries}
        writer.write('inventory.json', canonical(inventory))
        return inventory
    except Exception:
        writer.write('failure.json', canonical({'schema_version': 1, 'status': 'failed', 'completed_rpcs': len(entries)}))
        raise StudyEvidenceError('Study collection failed; restricted partial evidence retained.') from None


def verify_raw_collection(raw_inventory, *, inventory_sha256, trusted_phase_binding,
                          captured_dataset, captured_artifacts, raw_files, codec=None):
    """Reconstruct every request and derive observations from trusted raw bytes."""
    binding = trusted_phase_binding
    if type(binding) is not CollectionBinding:
        fail()
    attest_sources(binding)
    inventory = checked_json(raw_inventory, inventory_sha256)
    closed(inventory, ('schema_version', 'status', 'binding_sha256', 'files'))
    if type(inventory['schema_version']) is not int or inventory['schema_version'] != 1 or inventory['status'] != 'complete' or inventory['binding_sha256'] != binding.sha256:
        fail()
    rows = dataset_rows(captured_dataset, binding)
    closed(captured_artifacts, ('contextual', 'presence'))
    artifact_identity(captured_artifacts['contextual'], binding.contextual_identity)
    payload = artifact_identity(captured_artifacts['presence'], binding.presence_identity)
    if payload['config']['threshold'] != binding.model_threshold:
        fail()
    codec = codec or WireCodec()
    if type(codec) is not WireCodec:
        fail()
    expected_names = [f'rpc-{index:04d}-{purpose}.json' for index in range(len(rows)) for purpose in _purposes(binding)]
    if type(inventory['files']) is not list or len(inventory['files']) != len(expected_names) or set(raw_files) != set(expected_names):
        fail()
    claims, joins = [], []
    for index, row in enumerate(rows):
        responses = {}
        for purpose in _purposes(binding):
            name = f'rpc-{index:04d}-{purpose}.json'
            entry = inventory['files'][len(joins)]
            closed(entry, ('file', 'sha256'))
            if entry['file'] != name:
                fail()
            frame = checked_json(raw_files[name], entry['sha256'], MAX_FRAME_BYTES * 3)
            closed(frame, ('schema_version', 'binding_sha256', 'row_index', 'purpose', 'request_b64', 'response_b64', 'request_sha256', 'response_sha256', 'elapsed_ns'))
            if (type(frame['schema_version']) is not int or frame['schema_version'] != 1 or frame['binding_sha256'] != binding.sha256
                    or type(frame['row_index']) is not int or frame['row_index'] != index or frame['purpose'] != purpose
                    or type(frame['elapsed_ns']) is not int or frame['elapsed_ns'] < 0):
                fail()
            try:
                request_raw = base64.b64decode(frame['request_b64'], validate=True)
                response_raw = base64.b64decode(frame['response_b64'], validate=True)
            except (ValueError, TypeError):
                fail()
            if any(len(raw) > MAX_FRAME_BYTES for raw in (request_raw, response_raw)) or sha(request_raw) != frame['request_sha256'] or sha(response_raw) != frame['response_sha256']:
                fail()
            expected_request = codec.request(binding, row, purpose)
            if request_raw != expected_request.SerializeToString(deterministic=True):
                fail()
            response, parsed = codec.parse_response(response_raw)
            if response.request_id != expected_request.request_id:
                fail()
            responses[purpose] = parsed
            joins.append({'file': name, 'raw_sha256': entry['sha256'], 'request_sha256': sha(request_raw), 'response_sha256': sha(response_raw)})
        key = {'row_id_sha256': opaque('row', row['id']), 'group_id_sha256': opaque('group', row['group_id']), 'truth': row['expected_has_pii']}
        gated, trace = outcome_claim(responses['gated']), trace_claim(responses['gated'], binding)
        verify_gate_retention(gated, trace)
        if binding.phase == 'collect-validation':
            claim = {**key, 'ordinary': outcome_claim(responses['ordinary']), 'gate_zero': gated,
                     'nonsemantic': outcome_claim(responses['nonsemantic']), 'gate': trace}
        elif binding.phase == 'collect-fixtures':
            claim = {**key, 'ordinary': outcome_claim(responses['ordinary']), 'outcome': gated, 'gate': trace,
                     'ambiguous': row['ambiguous'], 'required_sensitive': row['required_sensitive'],
                     'required_action': row['required_action'], 'visibility_hint': row['visibility_hint']}
            for layer in ('regex', 'ner'):
                if claim['ordinary']['layers'][layer] != gated['layers'][layer]:
                    fail()
            nonsemantic = outcome_claim(responses['nonsemantic'])
            if nonsemantic['layers']['semantic']['status'] != 'not_requested':
                fail()
            for layer in ('regex', 'ner'):
                if nonsemantic['layers'][layer] != gated['layers'][layer]:
                    fail()
            comparison = claim['ordinary'] if trace['status'] == 'NOT_RUN' or trace['predicted_label'] == 'PRESENT' else nonsemantic
            if any(comparison[k] != gated[k] for k in ('classification', 'action', 'allowed', 'masked_text_sha256', 'evidence_sha256')):
                fail()
            if trace['status'] == 'APPLIED':
                if trace['semantic_results_sha256'] != claim['ordinary']['layers']['semantic']['results_sha256']:
                    fail()
                retained = trace['semantic_results_sha256'] if trace['predicted_label'] == 'PRESENT' else digest([])
                if gated['layers']['semantic']['results_sha256'] != retained:
                    fail()
        else:
            claim = {**key, 'gate': trace, 'outcome': gated}
        claims.append(claim)
    claims_raw = canonical(claims)
    joins_raw = canonical(joins)
    provenance_raw = canonical(payload.get('metadata', {}))
    seal = _collection_seal(binding, claims_raw, inventory_sha256, joins_raw, provenance_raw)
    return AuthenticatedCollection(binding, claims_raw, inventory_sha256, joins_raw, provenance_raw, seal, _AUTH)


def _collections(values, phase, all_checkpoints=False):
    expected = {(arm, epoch) for arm in contract.ARM_KEYS for epoch in ((0,) if arm.startswith('S') else range(1, 6))} if all_checkpoints else set(contract.ARM_KEYS)
    result, first = {}, None
    for value in values:
        if type(value) is not AuthenticatedCollection or value._authority is not _AUTH or value.binding.phase != phase:
            fail()
        value.__post_init__()
        binding = value.binding
        key = (binding.arm, binding.epoch) if all_checkpoints else binding.arm
        common = (binding.programme_sha256, binding.control_binding_sha256, binding.dataset_sha256,
                  binding.dataset_keys_sha256, dict(binding.contextual_identity), dict(binding.source_hashes),
                  dict(binding.operational_hashes), binding.selection_sha256, binding.barrier_sha256)
        if key in result or (first is not None and common != first):
            fail()
        first = common
        result[key] = value
    if set(result) != expected:
        fail()
    return result


def make_joint_validation_input(collections):
    verified = _collections(collections, 'collect-validation', True)
    control_sha = next(iter(verified.values())).binding.control_binding_sha256
    return {'schema_version': 1, 'control_binding_sha256': control_sha,
            'arms': [{'arm': arm, 'control_binding_sha256': control_sha,
                      'checkpoints': [{'epoch': epoch, 'identity': dict(verified[(arm, epoch)].binding.presence_identity),
                                       'rows': list(verified[(arm, epoch)].rows)} for epoch in ((0,) if arm.startswith('S') else range(1, 6))]}
                     for arm in contract.ARM_KEYS]}


def make_live_input(collections):
    verified = _collections(collections, 'rerun-validation')
    return {'schema_version': 1, 'control_binding_sha256': next(iter(verified.values())).binding.control_binding_sha256,
            'arms': [{'arm': arm, 'status': 'complete', 'error_count': 0, 'epoch': verified[arm].binding.epoch,
                      'threshold': verified[arm].binding.decision_threshold, 'identity': dict(verified[arm].binding.presence_identity),
                      'rows': list(verified[arm].rows)} for arm in contract.ARM_KEYS]}


def endpoint_input(collections):
    verified = _collections(collections, 'collect-test')
    return {'schema_version': 1, 'arms': [{'arm': arm, 'status': 'complete', 'error_count': 0,
             'rows': [{k: row[k] for k in ('row_id_sha256', 'group_id_sha256', 'truth', 'outcome')} for row in verified[arm].rows]} for arm in contract.ARM_KEYS]}


def require_selected(binding, selection_raw):
    """Validate frozen choice BEFORE any rerun/fixture/test dataset is read."""
    selection = checked_json(selection_raw, binding.selection_sha256)
    if (selection.get('status') != 'eligible' or selection.get('control_binding_sha256') != binding.control_binding_sha256
            or type(selection.get('selections')) is not dict or set(selection['selections']) != set(contract.ARM_KEYS)):
        fail()
    choice = selection['selections'][binding.arm]
    if (choice['epoch'] != binding.epoch or choice['identity'] != dict(binding.presence_identity)
            or type(choice['threshold']) is not float or choice['threshold'] != binding.decision_threshold):
        fail()
    return selection


def _phase_scope(binding):
    """Scientific execution scope shared across validation, fixtures and test."""
    return {key: binding.as_dict()[key] for key in (
        'programme_sha256', 'control_binding_sha256', 'contextual_identity',
        'source_revision', 'source_hashes', 'operational_hashes')}


def require_test_binding(binding, *, pretest_receipt, selection_raw_sha256):
    """Join test to a REBUILT authenticated pretest receipt before dataset reads.

    The caller must reconstruct this receipt from raw collections, not load an
    unchecked summary. Dataset/order/class/group commitments remain phase-specific.
    """
    if type(binding) is not CollectionBinding or binding.phase != 'collect-test':
        fail()
    checked_hash(selection_raw_sha256)
    closed(pretest_receipt, ('schema_version', 'programme_sha256', 'record_sha256', 'claim_references',
                            'raw_to_claim_joins', 'authenticated_collections', 'pretest_binding',
                            'selection_raw_sha256', 'test_authorized'))
    expected_scope = pretest_receipt['pretest_binding']
    if (type(pretest_receipt['schema_version']) is not int or pretest_receipt['schema_version'] != 1
            or _phase_scope(binding) != expected_scope
            or binding.programme_sha256 != pretest_receipt['programme_sha256']
            or binding.selection_sha256 != selection_raw_sha256
            or binding.selection_sha256 != pretest_receipt['selection_raw_sha256']
            or pretest_receipt['test_authorized'] is not False):
        fail()
    expected = {('collect-validation', arm, epoch) for arm in contract.ARM_KEYS
                for epoch in ((0,) if arm.startswith('S') else range(1, 6))}
    # Selected phases have one checkpoint per arm, whose epoch may be any frozen choice.
    seen_checkpoints, seen_selected = set(), set()
    for record in pretest_receipt['authenticated_collections']:
        captured = CollectionBinding(**record['binding'])
        if record['binding_sha256'] != captured.sha256 or _phase_scope(captured) != expected_scope:
            fail()
        if captured.phase == 'collect-validation':
            key = captured.phase, captured.arm, captured.epoch
            if key in seen_checkpoints:
                fail()
            seen_checkpoints.add(key)
        elif captured.phase in ('rerun-validation', 'collect-fixtures'):
            key = captured.phase, captured.arm
            if key in seen_selected or captured.selection_sha256 != selection_raw_sha256:
                fail()
            seen_selected.add(key)
        else:
            fail()
    if (seen_checkpoints != expected
            or seen_selected != {(phase, arm) for phase in ('rerun-validation', 'collect-fixtures') for arm in contract.ARM_KEYS}):
        fail()


def derive_barrier_records(programme, checkpoint_collections, selection_raw, live_collections, fixture_collections,
                           verified_fit_inventory, *, trusted_fit_inventory_sha256, trusted_selection_sha256):
    """Join externally RAW-pinned fitter evidence to actual artifact identities.

    Terminal job/resource attestation is controller-owned. This function does not
    convert self-reported job status into proof or authorize a test mount.
    """
    fits = checked_json(verified_fit_inventory, trusted_fit_inventory_sha256)
    closed(fits, ('schema_version', 'programme_sha256', 'trainer_contract_sha256', 'source_revision', 'prepared_manifest_sha256', 'checkpoints'))
    if type(fits['schema_version']) is not int or fits['schema_version'] != 1 or fits['programme_sha256'] != programme.sha256:
        fail()
    checked_hash(fits['trainer_contract_sha256'])
    if (type(fits['source_revision']) is not str or re.fullmatch(r'[0-9a-f]{40}', fits['source_revision']) is None
            or fits['prepared_manifest_sha256'] != dict(programme.external_hashes)['prepared_manifest']):
        fail()
    checkpoints = _collections(checkpoint_collections, 'collect-validation', True)
    live = _collections(live_collections, 'rerun-validation')
    fixtures = _collections(fixture_collections, 'collect-fixtures')
    selection = checked_json(selection_raw, trusted_selection_sha256)
    if any(value.binding.selection_sha256 != trusted_selection_sha256 for value in (*live.values(), *fixtures.values())):
        fail()
    analysis.verify_selected_live_validation(make_joint_validation_input(checkpoint_collections), selection, make_live_input(live_collections))
    if selection['status'] != 'eligible' or any(value.binding.programme_sha256 != programme.sha256 for value in (*checkpoints.values(), *live.values(), *fixtures.values())):
        fail()
    external = dict(programme.external_hashes)
    pretest_scope = _phase_scope(next(iter(checkpoints.values())).binding)
    for value in (*checkpoints.values(), *live.values(), *fixtures.values()):
        binding = value.binding
        if _phase_scope(binding) != pretest_scope:
            fail()
        if dict(binding.contextual_identity) != vars(programme.original_contextual):
            fail()
        for key in ('runtime_image', 'evaluator_image', 'effective_configuration', 'fixture_rubric', 'fixture_review'):
            if binding.operational_hashes[key] != external[key]:
                fail()
        if binding.arm == 'S0' and dict(binding.presence_identity) != vars(programme.s0):
            fail()
    observed = {}
    for item in fits['checkpoints']:
        closed(item, ('arm', 'epoch', 'identity', 'steps', 'initialization_sha256', 'permutation_sha256', 'job_receipt_sha256'))
        checked_hash(item['job_receipt_sha256'])
        key = item['arm'], item['epoch']
        if key in observed or key not in checkpoints or item['identity'] != dict(checkpoints[key].binding.presence_identity):
            fail()
        observed[key] = item
        if item['arm'] != 'S0':
            metadata = checkpoints[key].artifact_provenance
            if any(metadata.get(field) != expected for field, expected in (
                    ('source_revision', fits['source_revision']), ('study_plan_sha256', dict(contract.PIN_ITEMS)['plan']),
                    ('prepared_manifest_sha256', fits['prepared_manifest_sha256']),
                    ('trainer_contract_sha256', fits['trainer_contract_sha256']), ('training_seed', '12102026'))):
                fail()
            if item['epoch']:
                if any(metadata.get(field) != expected for field, expected in (
                        ('initialization_sha256', item['initialization_sha256']), ('checkpoint_epoch', str(item['epoch'])),
                        ('training_steps', str(item['steps'])))):
                    fail()
            elif (metadata.get('programme_sha256') != programme.sha256 or metadata.get('selected_C') != '1.0'
                  or metadata.get('training_strategy') != 'train_only_sparse_tfidf_logistic_c1'):
                fail()
    if set(observed) != set(checkpoints):
        fail()
    references = {f'global/{key}': value for key, value in programme.external_hashes}
    references.update({'global/original-contextual': programme.original_contextual.artifact_sha256, 'global/s0': programme.s0.artifact_sha256})
    records, joins = [], []
    for arm in contract.ARM_KEYS:
        choice, selected, fixture = selection['selections'][arm], live[arm], fixtures[arm]
        if (dict(selected.binding.presence_identity) != choice['identity'] or selected.binding.epoch != choice['epoch']
                or selected.binding.decision_threshold != choice['threshold']
                or dict(fixture.binding.presence_identity) != choice['identity'] or fixture.binding.decision_threshold != choice['threshold']
                or fixture.binding.epoch != choice['epoch'] or fixture.binding.selection_sha256 != selected.binding.selection_sha256):
            fail()
        fixture_rows = [{'case_sha256': row['row_id_sha256'], 'ambiguous': row['ambiguous'], 'required_sensitive': row['required_sensitive'],
                         'required_action': row['required_action'], 'visibility_hint': row['visibility_hint'],
                         'ordinary_action': row['ordinary']['action'], 'action': row['outcome']['action']} for row in fixture.rows]
        record = {'arm': arm, 'status': 'complete', 'contract_sha256': programme.sha256, 'checkpoints': [],
                  'selected_epoch': choice['epoch'], 'selected_identity': choice['identity'], 'threshold': choice['threshold'],
                  'validation_rows': 2000, 'validation_errors': 0, 'parity_matched_rows': 2000,
                  'validation_recall': choice['metrics']['recall'], 'fixture_errors': 0, 'fixtures': fixture_rows}
        for epoch in ((0,) if arm.startswith('S') else range(1, 6)):
            fit = observed[(arm, epoch)]
            cp = {key: fit[key] for key in ('epoch', 'steps', 'identity', 'initialization_sha256', 'permutation_sha256')}
            cp.update(validation_rows=2000, validation_errors=0, gate_zero_parity_matched_rows=2000)
            purpose = f'{arm}/checkpoint/{epoch}'
            references[purpose] = digest({'arm': arm, 'contract_sha256': programme.sha256, **cp})
            cp['evidence_ref'] = {'purpose': purpose, 'sha256': references[purpose]}
            record['checkpoints'].append(cp)
            joins.append({'purpose': purpose, 'claim_sha256': references[purpose], 'inventory_sha256': checkpoints[(arm, epoch)].inventory_sha256,
                          'fit_inventory_sha256': trusted_fit_inventory_sha256, 'job_receipt_sha256': fit['job_receipt_sha256']})
        fields = {'choice': ('arm', 'contract_sha256', 'selected_epoch', 'selected_identity', 'threshold'),
                  'validation-rerun': ('arm', 'contract_sha256', 'selected_identity', 'threshold', 'validation_rows', 'validation_errors', 'parity_matched_rows', 'validation_recall'),
                  'fixtures': ('arm', 'contract_sha256', 'selected_identity', 'threshold', 'fixture_errors', 'fixtures')}
        for suffix, keys in fields.items():
            purpose = f'{arm}/{suffix}'
            references[purpose] = digest({key: record[key] for key in keys})
            record[{'choice': 'choice_ref', 'validation-rerun': 'rerun_ref', 'fixtures': 'fixture_ref'}[suffix]] = {'purpose': purpose, 'sha256': references[purpose]}
            joins.append({'purpose': purpose, 'claim_sha256': references[purpose],
                          'inventory_sha256': fixture.inventory_sha256 if suffix == 'fixtures' else selected.inventory_sha256,
                          'selection_raw_sha256': trusted_selection_sha256,
                          'checkpoint_inventory_sha256': [checkpoints[(arm, epoch)].inventory_sha256 for epoch in ((0,) if arm.startswith('S') else range(1, 6))]})
        records.append(record)
    contract.validate_pretest_barrier(programme, records, references)
    authenticated = [{'binding': value.binding.as_dict(), 'binding_sha256': value.binding.sha256,
                      'inventory_sha256': value.inventory_sha256, 'raw_frames': list(value.raw_joins)}
                     for value in (*checkpoints.values(), *live.values(), *fixtures.values())]
    return records, references, {'schema_version': 1, 'programme_sha256': programme.sha256, 'record_sha256': digest(records),
                                'claim_references': references, 'raw_to_claim_joins': joins,
                                'authenticated_collections': authenticated, 'pretest_binding': pretest_scope,
                                'selection_raw_sha256': trusted_selection_sha256, 'test_authorized': False}
