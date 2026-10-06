"""Root-operated synthetic scratch compatibility; no study data or fitting gate waiver.

Run produces a candidate and retained private RAW evidence. Only accept_candidate,
with a separately RAW-pinned root acceptance, emits the controller's accepted kind.
Unknown named jobs block every later catalogue mutation, including restoration.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
import time

from . import in_house_study_controller as controller
from . import in_house_study_evidence as evidence

MAX_RAW = 8 * 1024 * 1024
MAX_PACKET = 32 * 1024 * 1024
MAX_CHUNKS = 256
STORE = Path('/compatibility')
CONSUMER = 'in-house-live-compatibility'
PROBE_TEXT = 'synthetic compatibility identity probe'
CANDIDATE_KIND = 'scratch-live-compatibility-candidate-v1'
ACCEPTED_KIND = 'root-accepted-scratch-live-compatibility-v1'
SOURCE_FILES = (
    'evaluation/check-in-house-live-compatibility.py',
    'evaluation/evaluate-in-house-study.py',
    'evaluation/privoke_eval/__init__.py',
    'evaluation/privoke_eval/in_house_live_compatibility.py',
    'evaluation/privoke_eval/in_house_study_controller.py',
    'evaluation/privoke_eval/in_house_study_evidence.py',
    'evaluation/privoke_eval/in_house_study_analysis.py',
    'evaluation/privoke_eval/in_house_study_contract.py',
    'evaluation/privoke_eval/in_house_presence_training.py',
    'shared/python/privoke_model/__init__.py',
    'shared/python/privoke_model/artifact.py',
    'shared/python/privoke_model/fingerprint.py',
    'shared/python/privoke_model/presence.py',
    'shared/python/privoke_model/scratch_presence.py',
    'shared/python/privoke_model/training_data.py',
    'shared/python/privoke_contracts/__init__.py',
    'shared/python/privoke_contracts/classification.py',
    'models/generate_baseline.py',
    'extension/client-runtime/src/model.py',
    'extension/client-runtime/src/transformer_encoder.py',
    'extension/client-runtime/src/detection/preprocessing.py',
    'extension/client-runtime/src/hosting/grpc_server.py',
    'extension/client-runtime/src/pipeline.py',
    'extension/client-runtime/src/LLM/privoke/streamed_model.py',
    'extension/client-runtime/src/LLM/privoke/parameter_stream.py',
    'extension/client-runtime/src/LLM/privoke/scratch_presence_model.py',
    'extension/client-runtime/generated/privoke/v1/runtime_pb2.py',
    'extension/client-runtime/generated/privoke/v1/runtime_pb2_grpc.py',
    'extension/client-runtime/generated/privoke/v1/parameters_pb2.py',
    'extension/client-runtime/generated/privoke/v1/parameters_pb2_grpc.py',
    'shared/proto/privoke/v1/runtime.proto',
    'shared/proto/privoke/v1/parameters.proto',
    'services/model-streaming-service/cmd/server/catalog.go',
    'services/model-streaming-service/cmd/server/artifact.go',
    'services/model-streaming-service/cmd/server/scratch_presence.go',
    'services/model-streaming-service/cmd/server/streaming_server.go',
)


class CompatibilityError(ValueError):
    """Sanitized boundary error; never contains artifacts, requests or replies."""


def fail():
    raise CompatibilityError('Live compatibility evidence or lifecycle rejected.')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_signature(info):
    # Reading can update atime; identity and all mutation-relevant metadata stay fixed.
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def synthetic_manifest():
    texts = ('synthetic mechanics zero', 'synthetic mechanics one')
    return {'schema_version': 1, 'kind': 'compatibility-synthetic-minibatch-v1',
            'purpose': 'transport-mechanics-only', 'text_sha256': [sha(t.encode()) for t in texts],
            'targets': [False, True], 'rows': 2, 'seed': 12102026, 'steps_per_model': 1}


def validate_commitments(value, *, root):
    evidence.closed(value, ('schema_version', 'kind', 'source_revision', 'images',
        'effective_configuration_sha256', 'source_hashes', 'source_files',
        'image_source_attestation', 'prior_catalog', 'plan_sha256', 'protocol_sha256',
        'trainer_contract_sha256', 'synthetic_manifest_sha256'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'scratch-live-compatibility-commitments-v1'
            or not re.fullmatch('[0-9a-f]{40}', value['source_revision'])):
        fail()
    evidence.closed(value['images'], controller.IMAGE_ROLES)
    evidence.closed(value['source_hashes'], evidence.SOURCE_ROLES)
    evidence.closed(value['source_files'], SOURCE_FILES)
    for mapping in ('images', 'source_hashes', 'source_files'):
        for digest in value[mapping].values():
            evidence.checked_hash(digest)
    for key in ('effective_configuration_sha256', 'plan_sha256', 'protocol_sha256',
                'trainer_contract_sha256', 'synthetic_manifest_sha256'):
        evidence.checked_hash(value[key])
    if (value['plan_sha256'] != dict(controller.contract.PIN_ITEMS)['plan']
            or value['protocol_sha256'] != dict(controller.contract.PIN_ITEMS)['protocol']
            or value['trainer_contract_sha256'] != controller.TRAINER_DIGEST
            or value['synthetic_manifest_sha256'] != evidence.digest(synthetic_manifest())):
        fail()
    evidence.closed(value['prior_catalog'], controller.LEGACY_IDS)
    for model_id, identity in value['prior_catalog'].items():
        if dict(evidence._identity(identity))['model_id'] != model_id:
            fail()
    verify_source_closure(value['source_files'],root=root)
    # The externally RAW-pinned attestation distinguishes helper bindings from
    # bounded serving-image source subsets; observation is checked by the backend.
    attestation = controller.json_reference(value['image_source_attestation'])
    validate_source_attestation(attestation, value)
    role_paths = {'caller': 'evaluation/evaluate-in-house-study.py',
        'evidence': 'evaluation/privoke_eval/in_house_study_evidence.py',
        'analysis': 'evaluation/privoke_eval/in_house_study_analysis.py',
        'contract': 'evaluation/privoke_eval/in_house_study_contract.py',
        'artifact': 'shared/python/privoke_model/artifact.py',
        'fingerprint': 'shared/python/privoke_model/fingerprint.py',
        'presence': 'shared/python/privoke_model/presence.py',
        'scratch': 'shared/python/privoke_model/scratch_presence.py',
        'runtime_pb2': 'extension/client-runtime/generated/privoke/v1/runtime_pb2.py',
        'runtime_pb2_grpc': 'extension/client-runtime/generated/privoke/v1/runtime_pb2_grpc.py'}
    # The study caller commitment remains its real evaluation caller.
    for role, path in role_paths.items():
        if value['source_hashes'][role] != value['source_files'][path]:
            fail()
    return value


class PrivateDirectory:
    """Held private leaf; refuses link, owner, mode, inode or content substitution."""
    def __init__(self, path, *, mode=0o700):
        if os.name != 'posix':
            fail()
        self.path, self.mode = Path(path), mode
        self.fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        self.identity = os.fstat(self.fd)
        self.verify()

    def verify(self):
        opened = os.fstat(self.fd)
        named = os.stat(self.path, follow_symlinks=False)
        for item in (opened, named):
            if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.geteuid()
                    or stat.S_IMODE(item.st_mode) != self.mode
                    or (item.st_dev, item.st_ino) != (self.identity.st_dev, self.identity.st_ino)):
                fail()

    def read(self, name, digest, limit=MAX_RAW):
        self.verify()
        if not re.fullmatch('[A-Za-z0-9_.-]{1,128}', name):
            fail()
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            first = os.fstat(fd)
            if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
                    or first.st_uid != os.geteuid() or stat.S_IMODE(first.st_mode) != 0o600):
                fail()
            raw = bytearray()
            while len(raw) <= limit:
                part = os.read(fd, min(65536, limit+1-len(raw)))
                if not part:
                    break
                raw.extend(part)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            after = os.fstat(fd)
            if (file_signature(first) != file_signature(after) or (named.st_dev, named.st_ino) != (first.st_dev, first.st_ino)
                    or named.st_uid != os.geteuid() or stat.S_IMODE(named.st_mode) != 0o600
                    or named.st_nlink != 1 or len(raw) > limit or sha(raw) != digest):
                fail()
            self.verify()
            return bytes(raw)
        finally:
            os.close(fd)

    def write(self, name, raw):
        self.verify()
        if not re.fullmatch('[A-Za-z0-9_.-]{1,128}', name) or len(raw) > MAX_PACKET:
            fail()
        fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            identity = os.fstat(fd)
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    fail()
                offset += count
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            after = os.fstat(fd)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            for item in (after, named):
                if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1
                        or item.st_uid != os.geteuid() or stat.S_IMODE(item.st_mode) != 0o600
                        or (item.st_dev, item.st_ino) != (identity.st_dev, identity.st_ino)):
                    fail()
            os.fsync(self.fd)
            self.verify()
        finally:
            os.close(fd)
        digest = sha(raw)
        if self.read(name, digest, MAX_PACKET) != raw:
            fail()
        return {'file': name, 'sha256': digest}

    def close(self):
        os.close(self.fd)


def frame(message):
    return raw_frame(message.SerializeToString(deterministic=True))


def raw_frame(raw):
    if type(raw) is not bytes:
        fail()
    if len(raw) > MAX_RAW:
        fail()
    return {'raw_b64': base64.b64encode(raw).decode('ascii'), 'sha256': sha(raw)}


def decode_frame(value, message_type):
    evidence.closed(value, ('raw_b64', 'sha256'))
    if type(value['raw_b64']) is not str or len(value['raw_b64']) > (MAX_RAW+2)//3*4:
        fail()
    try:
        raw = base64.b64decode(value['raw_b64'], validate=True)
    except (ValueError, TypeError):
        fail()
    if len(raw) > MAX_RAW or sha(raw) != evidence.checked_hash(value['sha256']):
        fail()
    message = message_type()
    message.ParseFromString(raw)
    return message


def _protobufs():
    from privoke.v1 import parameters_pb2 as p, runtime_pb2 as r
    return p, r


def _identity_matches(message, identity, *, gate=False, contextual=False):
    prefix = 'contextual_' if contextual else ''
    names = ('model_id', 'model_version', 'artifact_checksum', 'parameter_fingerprint')
    values = tuple(getattr(message, prefix+k) for k in names)
    expected = tuple(identity[k] for k in ('model_id', 'version', 'artifact_checksum', 'parameter_fingerprint'))
    if values != expected:
        fail()


def verify_probe(packet_raw, packet_sha256, scratch_raw, contextual_raw):
    """Reconstruct actual typed RAW replies; no boolean verification shortcut."""
    p, r = _protobufs()
    from privoke_model.scratch_presence import validate_scratch_presence_stream_metadata
    from privoke_model.fingerprint import parameter_fingerprint
    scratch, artifact = controller.artifact_identity(scratch_raw)
    contextual, _ = controller.artifact_identity(contextual_raw)
    packet = evidence.checked_json(packet_raw, packet_sha256, MAX_PACKET)
    evidence.closed(packet, ('schema_version', 'kind', 'stream', 'presence', 'gate'))
    if (type(packet['schema_version']) is not int or packet['schema_version'] != 1
            or packet['kind'] != 'scratch-compatibility-raw-probe-v1'):
        fail()
    stream = packet['stream']
    evidence.closed(stream, ('request', 'chunks'))
    request = decode_frame(stream['request'], p.ModelParametersRequest)
    if request.model_id != scratch['model_id'] or request.consumer_id != CONSUMER:
        fail()
    if type(stream['chunks']) is not list or not 0 < len(stream['chunks']) <= MAX_CHUNKS:
        fail()
    expected = artifact['parameters']
    expected_chunks = []
    for name in sorted(expected):
        tensor = expected[name]
        for offset in range(0, len(tensor['values']), 1024):
            expected_chunks.append((name, tensor, offset))
    if len(stream['chunks']) != len(expected_chunks):
        fail()
    parameters, shapes, total_bytes = {}, {}, 0
    for index, (captured, (name, tensor, offset)) in enumerate(zip(stream['chunks'], expected_chunks)):
        chunk = decode_frame(captured, p.ModelParameterChunk)
        total_bytes += chunk.ByteSize()
        if (total_bytes > MAX_RAW or chunk.model_id != scratch['model_id']
                or chunk.version != scratch['version'] or chunk.generated_at_unix != artifact['generated_at_unix']
                or chunk.chunk_index != index or chunk.total_chunks != len(expected_chunks)
                or chunk.parameter.name != name or list(chunk.parameter.shape) != tensor['shape']
                or chunk.parameter.value_offset != offset):
            fail()
        values = list(chunk.parameter.values)
        expected_values = [struct.unpack('<f', struct.pack('<f', x))[0]
                           for x in tensor['values'][offset:offset+1024]]
        if values != expected_values or any(not math.isfinite(x) for x in values):
            fail()
        if index == 0:
            metadata = dict(chunk.metadata)
            config = validate_scratch_presence_stream_metadata(chunk.model_id, chunk.version, metadata)
            if (config != artifact['config'] or metadata['artifact_checksum'] != scratch['artifact_checksum']
                    or metadata['artifact_file_checksum'] != scratch['artifact_sha256']
                    or metadata['consumer_id'] != CONSUMER
                    or any(metadata[k] != v for k, v in artifact['metadata'].items())):
                fail()
        elif chunk.metadata:
            fail()
        parameters.setdefault(name, []).extend(values)
        shapes[name] = tensor['shape']
    if parameter_fingerprint(parameters, shapes) != scratch['parameter_fingerprint']:
        fail()
    for key, request_type, response_type in (
        ('presence', r.DetectAnnotationPresenceRequest, r.DetectAnnotationPresenceResponse),
        ('gate', r.AnalyzePromptRequest, r.AnalyzePromptResponse)):
        evidence.closed(packet[key], ('request', 'response'))
        req = decode_frame(packet[key]['request'], request_type)
        response = decode_frame(packet[key]['response'], response_type)
        if req.text != PROBE_TEXT or req.request_id != CONSUMER+'-'+key or response.request_id != req.request_id:
            fail()
        if key == 'presence':
            if req.model_id != scratch['model_id'] or response.error:
                fail()
            _identity_matches(response, scratch)
            if (not math.isfinite(response.probability) or not 0 <= response.probability <= 1
                    or response.threshold != artifact['config']['threshold']
                    or response.predicted_label != (r.ANNOTATION_PRESENCE_PRESENT if response.probability >= response.threshold else r.ANNOTATION_PRESENCE_ABSENT)):
                fail()
        else:
            if (req.semantic_model_id != contextual['model_id'] or contextual['model_id'] != 'privoke-balanced'
                    or list(req.layers) != [r.DETECTION_LAYER_SEMANTIC]
                    or not req.HasField('semantic_presence_gate')
                    or req.semantic_presence_gate.model_id != scratch['model_id']
                    or not req.semantic_presence_gate.HasField('threshold')
                    or req.semantic_presence_gate.threshold != 0.0):
                fail()
            if len(response.layers) != 1 or response.layers[0].layer != r.DETECTION_LAYER_SEMANTIC:
                fail()
            layer = response.layers[0]
            gate = layer.semantic_presence_gate
            if (not layer.HasField('semantic_presence_gate') or gate.status != r.SEMANTIC_PRESENCE_GATE_STATUS_APPLIED
                    or gate.error or layer.error or layer.status != 'ok' or response.error):
                fail()
            _identity_matches(gate, scratch)
            _identity_matches(gate, contextual, contextual=True)
            if (not all(gate.HasField(k) for k in ('probability', 'model_threshold', 'decision_threshold'))
                    or not math.isfinite(gate.probability) or not 0 <= gate.probability <= 1
                    or gate.model_threshold != artifact['config']['threshold'] or gate.decision_threshold != 0.0
                    or gate.predicted_label != r.ANNOTATION_PRESENCE_PRESENT):
                fail()
    return {'streaming_identity': scratch, 'runtime_identity': scratch,
            'contextual_identity': contextual, 'raw_sha256': packet_sha256,
            'chunks': len(expected_chunks)}

def verify_absence(packet_raw, packet_sha256, model_id, *, contextual_identity=None):
    p, r = _protobufs()
    packet = evidence.checked_json(packet_raw, packet_sha256, MAX_PACKET)
    evidence.closed(packet, ('schema_version', 'kind', 'stream_request', 'stream_status',
                            'stream_chunks', 'presence', 'gate'))
    if (type(packet['schema_version']) is not int or packet['schema_version'] != 1
            or packet['kind'] != 'scratch-compatibility-raw-absence-v1'
            or model_id not in controller.SCRATCH_IDS or packet['stream_status'] != 'NOT_FOUND'
            or packet['stream_chunks'] != []):
        fail()
    req = decode_frame(packet['stream_request'], p.ModelParametersRequest)
    if req.model_id != model_id or req.consumer_id != CONSUMER:
        fail()
    for key, request_type, response_type in (
        ('presence', r.DetectAnnotationPresenceRequest, r.DetectAnnotationPresenceResponse),
        ('gate', r.AnalyzePromptRequest, r.AnalyzePromptResponse)):
        evidence.closed(packet[key], ('request', 'response'))
        req = decode_frame(packet[key]['request'], request_type)
        response = decode_frame(packet[key]['response'], response_type)
        if req.text != PROBE_TEXT or req.request_id != CONSUMER+'-'+key or response.request_id != req.request_id:
            fail()
        if key == 'presence':
            if req.model_id != model_id or not response.error or response.predicted_label != r.ANNOTATION_PRESENCE_UNSPECIFIED:
                fail()
        else:
            if (req.semantic_model_id != 'privoke-balanced' or list(req.layers) != [r.DETECTION_LAYER_SEMANTIC]
                    or req.semantic_presence_gate.model_id != model_id or len(response.layers) != 1):
                fail()
            layer = response.layers[0]
            gate = layer.semantic_presence_gate
            if (layer.layer != r.DETECTION_LAYER_SEMANTIC or layer.status != 'error' or not layer.error
                    or not gate.error or gate.status != r.SEMANTIC_PRESENCE_GATE_STATUS_ERROR):
                fail()
            if contextual_identity is not None:
                _identity_matches(gate,contextual_identity,contextual=True)
    return {'absent_after_removal': True, 'raw_sha256': packet_sha256}


def capture_probe(model_id, *, absence=False, ttl=1.0, clock=time.monotonic, sleep=time.sleep, record=None):
    """Actual fixed local RPCs; retain the original serialized reply bytes."""
    import grpc
    p, r = _protobufs()
    if model_id not in controller.SCRATCH_IDS or not math.isfinite(ttl) or not 0 <= ttl <= 60:
        fail()
    stream_request = p.ModelParametersRequest(consumer_id=CONSUMER, model_id=model_id)
    presence_request = r.DetectAnnotationPresenceRequest(request_id=CONSUMER+'-presence', text=PROBE_TEXT, model_id=model_id)
    gate_request = r.AnalyzePromptRequest(request_id=CONSUMER+'-gate', text=PROBE_TEXT,
        source=CONSUMER, semantic_model_id='privoke-balanced', layers=[r.DETECTION_LAYER_SEMANTIC])
    gate_request.semantic_presence_gate.model_id = model_id
    gate_request.semantic_presence_gate.threshold = 0.0
    # No deadline extension or cache resets. A stale cached success cannot pass.
    deadline = clock()+60.0
    while True:
        try:
            with grpc.insecure_channel('model-streaming-service:50051') as channel:
                chunks = []
                status = 'OK'
                try:
                    for chunk_raw in channel.unary_stream('/privoke.v1.ModelStreamingService/StreamModelParameters', request_serializer=lambda x:x.SerializeToString(deterministic=True), response_deserializer=lambda raw:raw)(stream_request, timeout=min(10,max(0.1,deadline-clock()))):
                        if len(chunks) >= MAX_CHUNKS:
                            fail()
                        chunks.append(raw_frame(chunk_raw))
                except grpc.RpcError as exc:
                    if record is not None:
                        record(evidence.canonical({'kind':'compatibility-partial-stream-status-v1','request':frame(stream_request),'chunks':chunks,'status':exc.code().name,'details':raw_frame((exc.details() or '').encode('utf-8'))}))
                    if not absence or exc.code() != grpc.StatusCode.NOT_FOUND:
                        raise
                    status = 'NOT_FOUND'
            with grpc.insecure_channel('client-runtime:50054') as channel:
                presence = channel.unary_unary('/privoke.v1.PrivokeRuntimeService/DetectAnnotationPresence',request_serializer=lambda x:x.SerializeToString(deterministic=True),response_deserializer=lambda raw:raw)(presence_request,timeout=min(10,max(0.1,deadline-clock())))
                gate = channel.unary_unary('/privoke.v1.PrivokeRuntimeService/AnalyzePrompt',request_serializer=lambda x:x.SerializeToString(deterministic=True),response_deserializer=lambda raw:raw)(gate_request,timeout=min(10,max(0.1,deadline-clock())))
            packet = {'schema_version': 1,
                'kind': 'scratch-compatibility-raw-absence-v1' if absence else 'scratch-compatibility-raw-probe-v1',
                'presence': {'request': frame(presence_request), 'response': raw_frame(presence)},
                'gate': {'request': frame(gate_request), 'response': raw_frame(gate)}}
            if absence:
                packet.update(stream_request=frame(stream_request), stream_status=status, stream_chunks=chunks)
                raw = evidence.canonical(packet)
                if record is not None:
                    record(raw)
                verify_absence(raw, sha(raw), model_id)
            else:
                if status != 'OK':
                    fail()
                packet['stream'] = {'request': frame(stream_request), 'chunks': chunks}
                if record is not None:
                    record(evidence.canonical(packet))
            if clock() > deadline:
                fail()
            return packet
        except Exception:
            if clock() >= deadline:
                raise CompatibilityError('Fixed live identity or absence deadline failed.') from None
            sleep(min(0.25, max(0.0, deadline-clock())))


def _read_artifact(directory, name, *, expected=None, held_fd=None):
    """Read only one canonical artifact through a held directory descriptor."""
    fd = os.dup(held_fd) if held_fd is not None else os.open(directory, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parent = os.fstat(fd)
        named_parent = os.stat(directory, follow_symlinks=False)
        if (parent.st_dev,parent.st_ino)!=(named_parent.st_dev,named_parent.st_ino):
            fail()
        f = os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=fd)
        try:
            first = os.fstat(f)
            if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > MAX_RAW:
                fail()
            raw = bytearray()
            while len(raw) <= MAX_RAW:
                part = os.read(f, min(65536, MAX_RAW+1-len(raw)))
                if not part:
                    break
                raw.extend(part)
            last = os.fstat(f)
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if file_signature(first) != file_signature(last) or (first.st_dev, first.st_ino) != (named.st_dev, named.st_ino):
                fail()
            if len(raw) > MAX_RAW or expected is not None and sha(raw) != expected:
                fail()
        finally:
            os.close(f)
        after = os.stat(directory, follow_symlinks=False)
        if (parent.st_dev, parent.st_ino) != (after.st_dev, after.st_ino):
            fail()
        return bytes(raw)
    finally:
        os.close(fd)


def initialize_store():
    if os.name != 'posix' or os.geteuid() != 0:
        fail()
    fd = os.open(STORE, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        if initial.st_uid != 0 or os.listdir(fd):
            fail()
        os.fchmod(fd, 0o711)
        for name in ('backups', 'artifacts', 'frames', 'contextual'):
            os.mkdir(name, 0o700, dir_fd=fd)
            child = os.open(name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=fd)
            try:
                if name in ('backups', 'contextual'):
                    os.fchown(child, 10001, 10001)
                os.fchmod(child, 0o700)
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(fd)
        named = os.stat(STORE, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (initial.st_dev, initial.st_ino) or stat.S_IMODE(named.st_mode) != 0o711:
            fail()
    finally:
        os.close(fd)
    return {'status': 'private_store_initialized'}


def generate_synthetic_artifacts(request):
    from .in_house_presence_training import create_paired_trainers
    synthetic = synthetic_manifest()
    if evidence.digest(synthetic) != request['synthetic_manifest_sha256']:
        fail()
    directory = PrivateDirectory(STORE/'artifacts')
    records = {}
    try:
        if os.listdir(directory.fd):
            fail()
        for profile in ('efficient', 'balanced', 'quality'):
            for trainer in create_paired_trainers(profile):
                metrics = trainer.step(('synthetic mechanics zero', 'synthetic mechanics one'), (False, True))
                if metrics.step != 1 or not math.isfinite(metrics.loss):
                    fail()
                artifact = trainer.build_artifact(source_revision=request['source_revision'],
                    study_plan_sha256=request['plan_sha256'],
                    prepared_manifest_sha256=request['synthetic_manifest_sha256'],
                    trainer_contract_sha256=request['trainer_contract_sha256'],
                    checkpoint_epoch=1, generated_at_unix=int(time.time()))
                raw = evidence.canonical(artifact)
                identity, _ = controller.artifact_identity(raw)
                reference = directory.write(trainer.model_id+'.json', raw)
                records[trainer.model_id] = {'identity': identity, 'file': reference,
                    'loss': metrics.loss, 'optimizer_steps': trainer.successful_steps,
                    'seed': synthetic['seed'], 'rows': synthetic['rows']}
        # Only synthetic artifacts become readable by the dedicated catalogue UID.
        # No study data, backups or typed frames are published through this leaf.
        for name in os.listdir(directory.fd):
            fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=directory.fd)
            try:
                os.fchmod(fd, 0o444)
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fchmod(directory.fd, 0o711)
        os.fsync(directory.fd)
    finally:
        directory.close()
    return {'status': 'synthetic_mechanics_only', 'manifest': synthetic,
            'manifest_sha256': request['synthetic_manifest_sha256'], 'scratch': records}



def _read_held_file(fd):
    os.lseek(fd,0,os.SEEK_SET)
    raw=bytearray()
    while len(raw)<=MAX_RAW:
        part=os.read(fd,min(65536,MAX_RAW+1-len(raw)))
        if not part:
            break
        raw.extend(part)
    if len(raw)>MAX_RAW:
        fail()
    return bytes(raw)


def _verify_bound_file(directory_fd,name,fd,signature,expected_raw):
    opened=os.fstat(fd)
    named=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
    if (file_signature(opened)!=signature or file_signature(named)!=signature
            or not stat.S_ISREG(opened.st_mode) or opened.st_uid!=os.geteuid()
            or stat.S_IMODE(opened.st_mode)!=0o600 or opened.st_nlink!=1):
        fail()
    if _read_held_file(fd)!=expected_raw:
        fail()
    # Do not permit replacement during the content re-read either.
    if (file_signature(os.fstat(fd))!=signature
            or file_signature(os.stat(name,dir_fd=directory_fd,follow_symlinks=False))!=signature):
        fail()


def remove_committed(directory_fd,name,expected_sha256):
    """Held inode and RAW recheck immediately before unlink under catalogue flock.

    POSIX unlink cannot conditionally compare an inode. The directory flock and
    ROOT's writer quiescence therefore remain mandatory cooperative-writer scope;
    these checks reject observed replacements without deleting the foreign entry.
    """
    if os.name!='posix':
        fail()
    expected_sha256=evidence.checked_hash(expected_sha256)
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
    try:
        signature=file_signature(os.fstat(fd))
        raw=_read_held_file(fd)
        if sha(raw)!=expected_sha256:
            fail()
        _verify_bound_file(directory_fd,name,fd,signature,raw)
        # Last named-entry comparison before the cooperative, locked mutation.
        if file_signature(os.stat(name,dir_fd=directory_fd,follow_symlinks=False))!=signature:
            fail()
        os.unlink(name,dir_fd=directory_fd)
        os.fsync(directory_fd)
        if os.fstat(fd).st_nlink!=0:
            fail()
        try:
            os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
        except FileNotFoundError:
            return
        fail()
    finally:
        os.close(fd)


def publish_no_replace(directory_fd,temp,name,fd,raw):
    """Atomically link a fresh owned inode; preserve collision and temp evidence."""
    if os.name!='posix':
        fail()
    signature=file_signature(os.fstat(fd))
    _verify_bound_file(directory_fd,temp,fd,signature,raw)
    # link() fails atomically if name already exists, including foreign symlinks.
    # Never rename-overwrite or clean up a failed artifact/collision here.
    os.link(temp,name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd,follow_symlinks=False)
    opened=os.fstat(fd)
    for entry in (temp,name):
        named=os.stat(entry,dir_fd=directory_fd,follow_symlinks=False)
        if (not stat.S_ISREG(named.st_mode) or named.st_nlink!=2
                or named.st_uid!=os.geteuid() or stat.S_IMODE(named.st_mode)!=0o600
                or (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino)):
            fail()
    if _read_held_file(fd)!=raw:
        fail()
    os.unlink(temp,dir_fd=directory_fd)
    os.fsync(directory_fd)
    final=file_signature(os.fstat(fd))
    _verify_bound_file(directory_fd,name,fd,final,raw)


def restoration_barrier(backend,captured):
    backend.safe()
    backend.quiescent()
    if backend.controls()!=captured:
        fail()

def catalogue_operation(request):
    """10001 catalogue job; full RAW backups stay in its private volume leaf."""
    import fcntl
    if os.name != 'posix' or os.geteuid() != 10001:
        fail()
    operation, model_id = request['operation'], request['model_id']
    if operation not in ('backup', 'install', 'remove', 'catalogue-final'):
        fail()
    models = os.open('/models', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    fcntl.flock(models, fcntl.LOCK_EX)
    try:
        def read(mid):
            try:
                return _read_artifact('/models', mid+'.json', held_fd=models)
            except FileNotFoundError:
                return None
        def inventory():
            result = {}
            for mid in controller.CATALOG_IDS:
                raw = read(mid)
                result[mid] = None if raw is None else sha(raw)
            return result
        if operation == 'backup':
            prior = inventory()
            expected = {mid: request['prior_catalog'][mid]['artifact_sha256'] for mid in controller.LEGACY_IDS} | {mid: None for mid in controller.SCRATCH_IDS}
            if prior != expected:
                fail()
            backups = PrivateDirectory(STORE/'backups')
            try:
                if os.listdir(backups.fd):
                    fail()
                for mid in controller.LEGACY_IDS:
                    raw = read(mid)
                    if controller.artifact_identity(raw)[0] != request['prior_catalog'][mid]:
                        fail()
                    backups.write(mid+'.json', raw)
                    if mid == 'privoke-balanced':
                        contextual = PrivateDirectory(STORE/'contextual')
                        try:
                            contextual.write(mid+'.json', raw)
                            f = os.open(mid+'.json', os.O_RDONLY|os.O_NOFOLLOW, dir_fd=contextual.fd)
                            try:
                                os.fchmod(f, 0o444);os.fsync(f)
                            finally:
                                os.close(f)
                            os.fchmod(contextual.fd, 0o711);os.fsync(contextual.fd)
                        finally:
                            contextual.close()
            finally:
                backups.close()
            return {'status': 'four_raw_backups_verified', 'catalog': prior}
        if operation == 'catalogue-final':
            current = inventory()
            expected = {mid: request['prior_catalog'][mid]['artifact_sha256'] for mid in controller.LEGACY_IDS} | {mid: None for mid in controller.SCRATCH_IDS}
            if current != expected:
                fail()
            backups = PrivateDirectory(STORE/'backups')
            try:
                for mid in controller.LEGACY_IDS:
                    raw = backups.read(mid+'.json', expected[mid])
                    if read(mid) != raw:
                        fail()
            finally:
                backups.close()
            return {'status': 'exact_raw_baseline_restored', 'catalog': current}
        if model_id not in controller.SCRATCH_IDS:
            fail()
        name = model_id+'.json'
        if operation == 'remove':
            remove_committed(models,name,request['expected_sha256'])
            return {'status': 'removed', 'model_id': model_id, 'artifact_sha256': None}
        old = read(model_id)
        observed = None if old is None else sha(old)
        if observed != request['expected_sha256']:
            fail()
        if old is not None:
            fail()
        raw = _read_artifact(STORE/'artifacts', name,expected=evidence.checked_hash(request['artifact_sha256']))
        identity, _ = controller.artifact_identity(raw)
        if identity['model_id'] != model_id:
            fail()
        temp = '.'+name+'.'+os.urandom(8).hex()
        f = os.open(temp, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=models)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(f, raw[offset:])
                if count <= 0:
                    fail()
                offset += count
            os.fchmod(f, 0o600)
            os.fsync(f)
            publish_no_replace(models,temp,name,f,raw)
        finally:
            os.close(f)
        if read(model_id) != raw:
            fail()
        return {'status': 'installed', 'identity': identity}
    finally:
        os.close(models)


def helper(request):
    """In-container fixed operations. No caller-selected data/body paths."""
    evidence.closed(request, ('schema_version', 'operation', 'model_id', 'expected_sha256', 'artifact_sha256',
        'source_files', 'source_revision', 'plan_sha256', 'trainer_contract_sha256',
        'synthetic_manifest_sha256', 'cache_ttl_seconds', 'prior_catalog'))
    if (os.name != 'posix' or os.environ.get('PRIVOKE_EVAL_IN_CONTAINER') != 'true'
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or request['operation'] not in ('initialize', 'generate', 'backup', 'install', 'probe', 'remove', 'absence', 'catalogue-final')):
        fail()
    evidence.closed(request['source_files'], SOURCE_FILES)
    verify_source_closure(request['source_files'],root=Path('/workspace'))
    if request['operation'] == 'initialize':
        return initialize_store()
    if request['operation'] == 'generate':
        return generate_synthetic_artifacts(request)
    if request['operation'] in ('backup', 'install', 'remove', 'catalogue-final'):
        return catalogue_operation(request)
    if os.geteuid() != 0 or request['model_id'] not in controller.SCRATCH_IDS:
        fail()
    absence = request['operation'] == 'absence'
    attempts = []
    def retain_attempt(raw):
        leaf=PrivateDirectory(STORE/'frames')
        try:
            attempts.append(leaf.write(request['model_id']+'-'+request['operation']+'-attempt-'+str(len(attempts))+'.json',raw))
        finally:
            leaf.close()
    packet = capture_probe(request['model_id'], absence=absence, ttl=request['cache_ttl_seconds'], record=retain_attempt)
    raw = evidence.canonical(packet)
    # Store captured RAW before semantic validation, preserving failed evidence.
    frames = PrivateDirectory(STORE/'frames')
    try:
        reference = frames.write(request['model_id']+'-'+request['operation']+'.json', raw)
    finally:
        frames.close()
    if absence:
        result = verify_absence(raw, reference['sha256'], request['model_id'],contextual_identity=request['prior_catalog']['privoke-balanced'])
    else:
        scratch = _read_artifact(STORE/'artifacts', request['model_id']+'.json',expected=evidence.checked_hash(request['artifact_sha256']))
        contextual = _read_artifact(STORE/'contextual', 'privoke-balanced.json', expected=request['prior_catalog']['privoke-balanced']['artifact_sha256'])
        result = verify_probe(raw, reference['sha256'], scratch, contextual)
    return {'status': 'raw_'+request['operation']+'_validated', 'evidence': reference, 'result': result}

class CompatibilityBackend(controller.DockerBackend):
    """Existing inspected job backend plus fixed compatibility operation roles."""
    def __init__(self, output, commitments, *, root=controller.ROOT, runner=None):
        inputs = {'images': commitments['images'],
                  'effective_configuration': commitments['effective_configuration_sha256']}
        kwargs = {'root': root}
        if runner is not None:
            kwargs['runner'] = runner
        super().__init__(output, inputs, **kwargs)
        self.commitments = commitments
        self.volume = None
        self.model_volume = None
        self.cache_ttl = None

    def verify_source_observations(self):
        verify_source_observations(self.commitments, self)

    def prepare(self):
        observed = self.controls()
        model = self.inspect(observed['model-streaming-service']['container_id'])
        selected = [m for m in model['Mounts'] if m['Destination'] == '/models']
        if len(selected) != 1 or selected[0]['Type'] != 'volume' or selected[0]['RW']:
            fail()
        self.model_volume = selected[0]['Name']
        runtime = self.inspect(observed['client-runtime']['container_id'])
        values = [v.split('=', 1)[1] for v in runtime['Config']['Env'] if v.startswith('MODEL_STREAMING_CACHE_TTL_SECONDS=')]
        if len(values) > 1:
            fail()
        self.cache_ttl = float(values[0] if values else '1.0')
        if not math.isfinite(self.cache_ttl) or not 0 <= self.cache_ttl <= 60:
            fail()
        self.volume = self.create_volume('compatibility')
        return observed

    def perform(self, operation, *, model_id=None, expected_sha256=None, artifact_sha256=None):
        self.safe()
        if self.volume is None or self.model_volume is None:
            fail()
        r = self.commitments
        request = {'schema_version': 1, 'operation': operation, 'model_id': model_id,
            'expected_sha256': expected_sha256, 'artifact_sha256':artifact_sha256, 'source_files': r['source_files'],
            'source_revision': r['source_revision'], 'plan_sha256': r['plan_sha256'],
            'trainer_contract_sha256': r['trainer_contract_sha256'],
            'synthetic_manifest_sha256': r['synthetic_manifest_sha256'],
            'cache_ttl_seconds': self.cache_ttl, 'prior_catalog': r['prior_catalog']}
        reference = controller.save(self.output/('request-'+os.urandom(8).hex()+'.json'), request)
        os.chmod(reference['file'], 0o444)
        service = ('in-house-data-permissions' if operation == 'initialize' else
                   'in-house-catalog-admin' if operation in ('backup', 'install', 'remove', 'catalogue-final')
                   else 'in-house-evidence-job')
        mounts = [(reference['file'], '/request.json', True), ('volume:'+self.volume, '/compatibility', False)]
        # Every imported source is an individually pinned RO file. No repository,
        # datasets, results, model-training volumes or private review maps mounted.
        mounts.extend((str(self.root/path), '/workspace/'+path, True) for path in SOURCE_FILES)
        argv = ['python', '-B', '/workspace/evaluation/check-in-house-live-compatibility.py',
                'helper', '--request', '/request.json', '--request-sha256', reference['sha256']]
        raw, receipt_sha = self.job(service, argv, mounts=tuple(mounts), timeout=180,
                                   request_sha256=reference['sha256'])
        record = self.jobs[-1]
        actual = self.inspect(record['container_id'])
        config,host=actual['Config'],actual['HostConfig']
        expected_user='10001:10001' if service=='in-house-catalog-admin' else '0:0'
        expected_caps={'CHOWN','DAC_OVERRIDE'} if operation=='initialize' else set()
        if (config.get('User')!=expected_user or host.get('CapDrop')!=['ALL']
                or compatibility_caps(host.get('CapAdd'))!=expected_caps
                or host.get('SecurityOpt')!=['no-new-privileges:true']
                or host.get('PidsLimit')!=128):
            fail()
        if operation in ('backup', 'install', 'remove', 'catalogue-final'):
            mounted = [m for m in actual['Mounts'] if m['Destination'] == '/models']
            if (len(mounted) != 1 or mounted[0].get('Type') != 'volume'
                    or mounted[0].get('Name') != self.model_volume
                    or mounted[0]['RW'] != (operation != 'probe')):
                fail()
        receipt = {'file': str(self.output/f'job-{self.counter:04d}.json'), 'sha256': receipt_sha}
        proof = {k: record[k] for k in ('name', 'container_id', 'image_id', 'exit_code')}
        proof.update(operation=operation, request=reference, receipt=receipt)
        metadata = evidence.checked_json(raw, sha(raw), MAX_PACKET)
        return metadata, proof, {'file': str(self.output/f'job-{self.counter:04d}.log'), 'sha256': sha(raw)}


def expected_catalog(commitments):
    return {mid: commitments['prior_catalog'][mid]['artifact_sha256'] for mid in controller.LEGACY_IDS} | {mid: None for mid in controller.SCRATCH_IDS}


def run_producer(commitments, backend, output, *, commitments_reference):
    """Produce a candidate; never automatically accepts it or changes service state."""
    output = Path(output)
    validate_commitments(commitments, root=backend.root)
    backend.verify_source_observations()
    captured = backend.prepare()
    owned = {}
    auxiliary, proofs, metadata_refs, raw_inventory = [], {}, {}, {}
    restoration = {'complete': False, 'failure': None}
    failure = None
    try:
        for operation in ('initialize', 'backup', 'generate'):
            result, proof, log = backend.perform(operation)
            auxiliary.append(proof)
            metadata_refs[proof['name']] = log
            if operation == 'backup' and result != {'status': 'four_raw_backups_verified', 'catalog': expected_catalog(commitments)}:
                fail()
            if operation == 'generate':
                evidence.closed(result, ('status', 'manifest', 'manifest_sha256', 'scratch'))
                if (result['status'] != 'synthetic_mechanics_only' or result['manifest'] != synthetic_manifest()
                        or result['manifest_sha256'] != commitments['synthetic_manifest_sha256']):
                    fail()
                evidence.closed(result['scratch'], controller.SCRATCH_IDS)
                generated = result
        for mid in controller.SCRATCH_IDS:
            identity = dict(evidence._identity(generated['scratch'][mid]['identity']))
            item = generated['scratch'][mid]
            evidence.closed(item,('identity','file','loss','optimizer_steps','seed','rows'))
            evidence.closed(item['file'],('file','sha256'))
            if (identity['model_id'] != mid or type(item['optimizer_steps']) is not int or item['optimizer_steps'] != 1
                    or type(item['seed']) is not int or item['seed'] != 12102026 or type(item['rows']) is not int or item['rows'] != 2
                    or type(item['loss']) not in (int,float) or not math.isfinite(item['loss']) or item['file']['sha256'] != identity['artifact_sha256']):
                fail()
            entries = {}
            for operation in ('install', 'probe', 'remove', 'absence'):
                backend.safe()
                backend.quiescent()
                if backend.controls() != captured:
                    fail()
                if operation == 'install':
                    owned[mid] = identity['artifact_sha256']
                result, proof, log = backend.perform(operation, model_id=mid,
                    expected_sha256=identity['artifact_sha256'] if operation == 'remove' else None,
                    artifact_sha256=identity['artifact_sha256'] if operation in ('install','probe') else None)
                entries[operation] = proof
                metadata_refs[proof['name']] = log
                if operation == 'install':
                    if result != {'status': 'installed', 'identity': identity}:
                        fail()
                    owned[mid] = identity['artifact_sha256']
                elif operation == 'remove':
                    if result != {'status': 'removed', 'model_id': mid, 'artifact_sha256': None}:
                        fail()
                    owned.pop(mid, None)
                else:
                    evidence.closed(result, ('status', 'evidence', 'result'))
                    if result['status'] != 'raw_'+operation+'_validated':
                        fail()
                    evidence.closed(result['evidence'], ('file', 'sha256'))
                    evidence.checked_hash(result['evidence']['sha256'])
                    raw_inventory[mid+'-'+operation] = result['evidence']
                    if operation == 'probe':
                        if (result['result']['streaming_identity'] != identity
                                or result['result']['runtime_identity'] != identity
                                or result['result']['contextual_identity'] != commitments['prior_catalog']['privoke-balanced']
                                or result['result']['raw_sha256'] != result['evidence']['sha256']):
                            fail()
                    elif result['result'] != {'absent_after_removal': True, 'raw_sha256': result['evidence']['sha256']}:
                        fail()
            proofs[mid] = {'identity': identity, 'streaming_identity': identity,
                'runtime_identity': identity, 'absent_after_removal': True, 'jobs': entries}
    except Exception:
        failure = 'compatibility_operation_failed'
    # An unknown named handle bars even rollback. Retain everything for ROOT.
    try:
        backend.safe()
        backend.quiescent()
        for mid, digest in tuple(owned.items()):
            restoration_barrier(backend,captured)
            result, proof, log = backend.perform('remove', model_id=mid, expected_sha256=digest)
            auxiliary.append(proof)
            metadata_refs[proof['name']] = log
            if result != {'status': 'removed', 'model_id': mid, 'artifact_sha256': None}:
                fail()
            owned.pop(mid)
        restoration_barrier(backend,captured)
        result, proof, log = backend.perform('catalogue-final')
        auxiliary.append(proof)
        metadata_refs[proof['name']] = log
        if result != {'status': 'exact_raw_baseline_restored', 'catalog': expected_catalog(commitments)}:
            fail()
        backend.quiescent()
        if backend.controls() != captured:
            fail()
        restoration['complete'] = True
    except Exception:
        restoration['failure'] = 'restoration_unproven_or_remote_unknown'
    receipt = {'schema_version': 1, 'kind': CANDIDATE_KIND,
        'source_revision': commitments['source_revision'],
        'images': {k: commitments['images'][k] for k in controller.IMAGE_ROLES[:2]},
        'effective_configuration_sha256': commitments['effective_configuration_sha256'],
        'source_hashes': commitments['source_hashes'], 'protocol_sha256': commitments['protocol_sha256'],
        'before_catalog': expected_catalog(commitments), 'after_catalog': expected_catalog(commitments), 'scratch': proofs}
    candidate = {'schema_version': 1, 'kind': CANDIDATE_KIND,
        'commitments': commitments_reference, 'status': 'candidate' if failure is None and restoration['complete'] and len(proofs) == 6 else 'failed',
        'failure': failure, 'restoration': restoration, 'receipt': receipt,
        'synthetic_receipt': generated if 'generated' in locals() else None,
        'raw_inventory': raw_inventory, 'auxiliary_jobs': auxiliary, 'metadata_references': metadata_refs}
    # Candidate embeds the receipt shape only; it is not accepted authority.
    return controller.save(output/'compatibility-candidate.json', candidate)


def accept_candidate(candidate_reference, commitments, backend, root_acceptance_reference, output):
    """External root RAW authority plus real terminal handles and metadata joins."""
    validate_commitments(commitments, root=backend.root)
    backend.verify_source_observations()
    candidate = controller.json_reference(candidate_reference)
    if controller.json_reference(candidate['commitments']) != commitments:
        fail()
    evidence.closed(candidate, ('schema_version', 'kind', 'commitments', 'status', 'failure',
        'restoration', 'receipt', 'synthetic_receipt', 'raw_inventory', 'auxiliary_jobs', 'metadata_references'))
    if (candidate['schema_version'] != 1 or candidate['kind'] != CANDIDATE_KIND
            or candidate['status'] != 'candidate' or candidate['failure'] is not None
            or candidate['restoration'] != {'complete': True, 'failure': None}):
        fail()
    acceptance = controller.json_reference(root_acceptance_reference)
    evidence.closed(acceptance, ('schema_version', 'kind', 'candidate_sha256',
        'raw_inventory_sha256', 'image_source_attestation_sha256', 'job_proofs_sha256'))
    jobs = [proof for item in candidate['receipt']['scratch'].values() for proof in item['jobs'].values()]
    all_jobs = jobs+candidate['auxiliary_jobs']
    if (type(acceptance['schema_version']) is not int or acceptance['schema_version'] != 1
            or acceptance['kind'] != 'root-authenticated-scratch-compatibility-raw-v1'
            or acceptance['candidate_sha256'] != candidate_reference['sha256']
            or acceptance['raw_inventory_sha256'] != evidence.digest(candidate['raw_inventory'])
            or acceptance['job_proofs_sha256'] != evidence.digest(all_jobs)
            or acceptance['image_source_attestation_sha256'] != commitments['image_source_attestation']['sha256']):
        fail()
    if len(jobs) != 24 or len({x['name'] for x in all_jobs}) != len(all_jobs) or len({x['container_id'] for x in all_jobs}) != len(all_jobs):
        fail()
    expected_raw = {mid+'-'+op for mid in controller.SCRATCH_IDS for op in ('probe', 'absence')}
    if set(candidate['raw_inventory']) != expected_raw:
        fail()
    for proof in all_jobs:
        backend.verify_external_job(proof)
        request = controller.json_reference(proof['request'])
        if request['operation'] != proof['operation'] or request['source_files'] != commitments['source_files']:
            fail()
        record = controller.json_reference(proof['receipt'])
        log = candidate['metadata_references'][proof['name']]
        if (record.get('terminal') is not True or record.get('logs_sha256') != log['sha256']
                or record.get('request_sha256') != proof['request']['sha256']
                or any(record.get(k) != proof[k] for k in ('name', 'container_id', 'image_id', 'exit_code'))
                or proof['image_id'] != 'sha256:'+commitments['images']['evaluator'] or type(proof['exit_code']) is not int or proof['exit_code'] != 0):
            fail()
        controller.json_reference(log)  # Metadata-only log RAW hash, never typed bodies.
    backend.quiescent()
    backend.controls()
    receipt = dict(candidate['receipt'],kind=ACCEPTED_KIND)
    inputs = {'source_revision': commitments['source_revision'], 'images': commitments['images'],
        'effective_configuration': commitments['effective_configuration_sha256'],
        'source_hashes': commitments['source_hashes'], 'prior_catalog': commitments['prior_catalog']}
    ref = controller.save(Path(output)/'compatibility.json', receipt)
    controller.validate_compatibility(ref, inputs, backend)
    return ref

def verify_source_closure(pins, *, root):
    evidence.closed(pins,SOURCE_FILES)
    origins={}
    for relative,digest in pins.items():
        path=(Path(root)/relative).resolve()
        evidence.read_committed(path,digest)
        origins[str(path)]=digest
    for module in tuple(sys.modules.values()):
        origin=getattr(module,'__file__',None)
        if origin is not None and str(Path(origin).resolve()) in origins:
            evidence._attest_module(module,origins[str(Path(origin).resolve())])


SOURCE_SCOPES = {
    'operator': SOURCE_FILES[:8],
    'evaluator_helper': SOURCE_FILES,
    'client_runtime_image': tuple(path for path in SOURCE_FILES if path.startswith(('shared/', 'extension/'))),
    'model_streaming_image': tuple(path for path in SOURCE_FILES if path.startswith('services/')) +
        ('shared/proto/privoke/v1/parameters.proto',),
}
SOURCE_PREFLIGHT_KIND = 'compatibility-source-preflight-v1'


def source_scopes(pins):
    return {role: {path: pins[path] for path in paths} for role, paths in SOURCE_SCOPES.items()}


def fresh_metadata_output(path):
    """Host aggregate metadata only; Windows chmod is not a private ACL claim."""
    path = Path(path)
    if not path.is_absolute():
        fail()
    for ancestor in (path, *path.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            fail()
    if path.exists():
        fail()
    path.mkdir(mode=0o700)
    return path


def validate_source_spec(value, *, root):
    evidence.closed(value, ('schema_version', 'kind', 'source_revision', 'images',
        'effective_configuration_sha256', 'source_files', 'source_scopes'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['kind'] != 'compatibility-source-spec-v1'
            or not re.fullmatch('[0-9a-f]{40}', value['source_revision'])):
        fail()
    evidence.closed(value['images'], controller.IMAGE_ROLES)
    for digest in (*value['images'].values(), value['effective_configuration_sha256']):
        evidence.checked_hash(digest)
    verify_source_closure(value['source_files'], root=root)
    if value['source_scopes'] != source_scopes(value['source_files']):
        fail()
    return value


def source_helper(request):
    evidence.closed(request, ('schema_version', 'kind', 'source_files'))
    if (os.name != 'posix' or os.environ.get('PRIVOKE_EVAL_IN_CONTAINER') != 'true'
            or type(request['schema_version']) is not int or request['schema_version'] != 1
            or request['kind'] != SOURCE_PREFLIGHT_KIND):
        fail()
    verify_source_closure(request['source_files'], root=Path('/workspace'))
    return {'schema_version': 1, 'kind': SOURCE_PREFLIGHT_KIND,
            'source_files': request['source_files']}


def source_job_command(role, scope, request=None):
    if role == 'evaluator_helper':
        return ['python', '-B', '/workspace/evaluation/check-in-house-live-compatibility.py',
                'source-helper', '--request', '/request.json', '--request-sha256', request['sha256']]
    # Fixed filenames only. No shell, semantic payload, artifact or data access.
    return ['sha256sum', *('/workspace/'+path for path in sorted(scope))]


def validate_source_attestation(value, commitments):
    evidence.closed(value, ('schema_version', 'kind', 'source_revision', 'images',
        'effective_configuration_sha256', 'source_files', 'source_scopes',
        'helper_bindings', 'image_source_receipts'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 2
            or value['kind'] != 'root-authenticated-compatibility-image-source-v2'
            or any(value[k] != commitments[k] for k in ('source_revision', 'images',
                'effective_configuration_sha256', 'source_files'))
            or value['source_scopes'] != source_scopes(commitments['source_files'])):
        fail()
    evidence.closed(value['image_source_receipts'], ('client-runtime', 'model-streaming-service'))
    evidence.closed(value['helper_bindings'], ('proof', 'request', 'bindings'))
    bindings = value['helper_bindings']['bindings']
    if type(bindings) is not list or len(bindings) != len(SOURCE_FILES):
        fail()
    if len({item.get('destination') for item in bindings if type(item) is dict}) != len(SOURCE_FILES):
        fail()
    by_destination = {}
    for item in bindings:
        evidence.closed(item, ('source', 'host_source', 'destination', 'sha256', 'readonly'))
        if (type(item['source']) is not str or not item['source'].startswith('/')
                or type(item['host_source']) is not str or item['readonly'] is not True):
            fail()
        by_destination[item['destination']] = item
    for path in SOURCE_FILES:
        item = by_destination.get('/workspace/'+path)
        if item is None or item['sha256'] != commitments['source_files'][path]:
            fail()
    return value


def verify_source_observations(commitments, backend):
    """Re-inspect externally pinned terminal source-only jobs before mutation."""
    value = controller.json_reference(commitments['image_source_attestation'])
    validate_source_attestation(value, commitments)
    seen_names, seen_ids = set(), set()
    entries = [('evaluator_helper', value['helper_bindings']['proof'])] + list(value['image_source_receipts'].items())
    for role, proof in entries:
        evidence.closed(proof, ('name', 'container_id', 'image_id', 'exit_code', 'receipt', 'log', 'request_sha256', 'serving_container_id'))
        if (type(proof['name']) is not str or not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}', proof['name'])
                or not re.fullmatch('[0-9a-f]{64}', proof['container_id'])
                or proof['name'] in seen_names or proof['container_id'] in seen_ids
                or type(proof['exit_code']) is not int or proof['exit_code'] != 0):
            fail()
        seen_names.add(proof['name']);seen_ids.add(proof['container_id'])
        image_role = 'evaluator' if role == 'evaluator_helper' else role
        if proof['image_id'] != 'sha256:'+commitments['images'][image_role]:
            fail()
        record = controller.json_reference(proof['receipt'])
        if (record.get('terminal') is not True or record.get('logs_sha256') != proof['log']['sha256']
                or any(record.get(k) != proof[k] for k in ('name', 'container_id', 'image_id', 'exit_code', 'request_sha256'))):
            fail()
        raw = controller.read_reference(proof['log'])
        observed = backend.inspect(proof['name'])
        if (observed['Id'] != proof['container_id'] or observed['Image'] != proof['image_id']
                or observed['State']['Running'] or observed['State']['Status'] not in ('exited', 'dead')
                or observed['State']['ExitCode'] != 0):
            fail()
        host, config = observed['HostConfig'], observed['Config']
        if (host.get('ReadonlyRootfs') is not True or host.get('NetworkMode') != 'none'
                or host.get('CapDrop') != ['ALL'] or host.get('CapAdd')
                or host.get('SecurityOpt') != ['no-new-privileges:true']
                or config.get('User') != '65534:65534' or host.get('Memory') != 4*1024**3
                or host.get('NanoCpus') != 4_000_000_000 or host.get('PidsLimit') != 128):
            fail()
        mounts = [m for m in observed['Mounts'] if m['Type'] in ('bind', 'volume')]
        if role == 'evaluator_helper':
            if proof['serving_container_id'] is not None:
                fail()
            request = value['helper_bindings']['request']
            request_value = controller.json_reference(request)
            if request_value != {'schema_version': 1, 'kind': SOURCE_PREFLIGHT_KIND, 'source_files': commitments['source_files']}:
                fail()
            for binding in value['helper_bindings']['bindings']:
                relative = binding['destination'].removeprefix('/workspace/')
                if binding['host_source'] != str((backend.root/relative).resolve()):
                    fail()
            expected = {b['destination']: b['source'] for b in value['helper_bindings']['bindings']}
            request_mounts = [m for m in mounts if m['Destination'] == '/request.json']
            if len(request_mounts) != 1 or request_mounts[0]['Type'] != 'bind' or request_mounts[0]['RW']:
                fail()
            expected['/request.json'] = request_mounts[0]['Source']
            if (len(mounts) != len(expected) or {m['Destination']: m.get('Source') for m in mounts} != expected
                    or any(m['Type'] != 'bind' or m['RW'] for m in mounts)
                    or evidence.checked_json(raw, proof['log']['sha256']) != {'schema_version': 1, 'kind': SOURCE_PREFLIGHT_KIND, 'source_files': commitments['source_files']}
                    or proof['request_sha256'] != request['sha256']):
                fail()
            scope = value['source_scopes']['evaluator_helper']
        else:
            if mounts:
                fail()
            serving = backend.inspect(proof['serving_container_id'])
            if (not re.fullmatch('[0-9a-f]{64}', proof['serving_container_id'])
                    or serving['Id'] != proof['serving_container_id'] or serving['Image'] != proof['image_id']
                    or not serving['State']['Running']):
                fail()
            scope = value['source_scopes'][{'client-runtime': 'client_runtime_image', 'model-streaming-service': 'model_streaming_image'}[role]]
            reject_source_overlays(serving, scope)
            lines = raw.decode('ascii', errors='strict').splitlines()
            expected_lines = [digest+'  /workspace/'+path for path, digest in sorted(scope.items())]
            if lines != expected_lines or proof['request_sha256'] != evidence.digest({'role': role, 'scope': scope}):
                fail()
            request = None
        if config.get('Cmd') != source_job_command(role, scope, request):
            fail()
    backend.safe()


def produce_source_preflight(spec, backend, output):
    """No compatibility/catalogue/data prerequisite and no model/data mounts."""
    validate_source_spec(spec, root=backend.root)
    original_images = backend.inputs['images']
    helper_request = controller.save(Path(output)/'source-request.json',
        {'schema_version': 1, 'kind': SOURCE_PREFLIGHT_KIND, 'source_files': spec['source_files']})
    os.chmod(helper_request['file'], 0o444)
    bindings = [{'host_source': str((backend.root/path).resolve()), 'source': '/unobserved', 'destination': '/workspace/'+path,
        'sha256': spec['source_files'][path], 'readonly': True} for path in SOURCE_FILES]
    proofs = {}
    try:
        for role in ('client-runtime', 'model-streaming-service', 'evaluator_helper'):
            backend.safe()
            image_role = 'evaluator' if role == 'evaluator_helper' else role
            backend.inputs = dict(backend.inputs, images=dict(original_images, evaluator=original_images[image_role]))
            backend.env['IN_HOUSE_EVALUATOR_IMAGE'] = 'sha256:'+original_images[image_role]
            scope = spec['source_scopes']['evaluator_helper' if role == 'evaluator_helper' else {'client-runtime': 'client_runtime_image', 'model-streaming-service': 'model_streaming_image'}[role]]
            request = helper_request if role == 'evaluator_helper' else None
            mounts = ((helper_request['file'], '/request.json', True), *[(b['host_source'], b['destination'], True) for b in bindings]) if request else ()
            serving_id = None
            if role != 'evaluator_helper':
                ids = backend.call(backend.compose+['ps', '--status', 'running', '--quiet', role]).decode().splitlines()
                if len(ids) != 1:
                    fail()
                serving = backend.inspect(ids[0])
                if serving['Image'] != 'sha256:'+original_images[role] or not serving['State']['Running']:
                    fail()
                serving_id = serving['Id']
            request_hash = request['sha256'] if request else evidence.digest({'role': role, 'scope': scope})
            raw, receipt_sha = backend.job('in-house-fit-reader', source_job_command(role, scope, request),
                mounts=mounts, timeout=120, request_sha256=request_hash)
            record = backend.jobs[-1]
            if role == 'evaluator_helper':
                actual = backend.inspect(record['container_id'])
                for binding in bindings:
                    entries = [m for m in actual['Mounts'] if m['Destination'] == binding['destination']]
                    if len(entries) != 1 or entries[0]['Type'] != 'bind' or entries[0]['RW']:
                        fail()
                    binding['source'] = entries[0]['Source']
            proofs[role] = {k: record[k] for k in ('name', 'container_id', 'image_id', 'exit_code', 'request_sha256')}
            proofs[role].update(receipt={'file': str(Path(output)/f'job-{backend.counter:04d}.json'), 'sha256': receipt_sha},
                log={'file': str(Path(output)/f'job-{backend.counter:04d}.log'), 'sha256': sha(raw)}, serving_container_id=serving_id)
    finally:
        backend.inputs = dict(backend.inputs, images=original_images)
        backend.env['IN_HOUSE_EVALUATOR_IMAGE'] = 'sha256:'+original_images['evaluator']
    att = {k: spec[k] for k in ('source_revision', 'images', 'effective_configuration_sha256', 'source_files', 'source_scopes')}
    att.update(schema_version=2, kind='root-authenticated-compatibility-image-source-v2',
        helper_bindings={'proof': proofs['evaluator_helper'], 'request': helper_request, 'bindings': bindings},
        image_source_receipts={role: proofs[role] for role in ('client-runtime', 'model-streaming-service')})
    # This output is a proposed attestation, never self-authenticating ROOT authority.
    ref = controller.save(Path(output)/'source-preflight.json', att)
    verify_source_observations(dict(spec, image_source_attestation=ref), backend)
    return ref



def reject_source_overlays(serving, scope):
    """Image-byte receipts cannot vouch for source hidden by a live mount."""
    destinations = [item['Destination'] for item in serving['Mounts']]
    destinations.extend(serving.get('HostConfig', {}).get('Tmpfs', {}).keys())
    for destination in destinations:
        if type(destination) is not str or not destination.startswith('/'):
            fail()
        prefix = destination.rstrip('/')+'/'
        for path in scope:
            pinned = '/workspace/'+path
            if pinned == destination or pinned.startswith(prefix):
                fail()



def compatibility_caps(value):
    """Only the two explicitly permitted initialization capabilities."""
    if value is None:
        return set()
    if type(value) is not list:
        fail()
    names=[]
    for name in value:
        if type(name) is not str:
            fail()
        normalized=name.removeprefix('CAP_')
        if normalized not in ('CHOWN','DAC_OVERRIDE') or name not in (normalized,'CAP_'+normalized):
            fail()
        names.append(normalized)
    if len(set(names))!=len(names):
        fail()
    return set(names)
