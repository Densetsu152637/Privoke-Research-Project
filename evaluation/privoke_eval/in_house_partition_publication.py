"""Authenticated two-phase publication; never fits, scores or authorizes a study.

Phase A replays complete source and dual review before privately freezing bytes.
Phase B joins an independently committed programme to those exact bytes. Source
and review commitments are external claims, not proof of human annotation truth.
"""
from __future__ import annotations
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
from collections.abc import Mapping

from privoke_eval import in_house_advpii_review_io as io
from privoke_eval import in_house_review_reconstruction as reconstruction
from privoke_eval import in_house_dual_allocation as allocator
from privoke_eval import in_house_dual_review as dual
from privoke_eval import in_house_study_contract as contract
from privoke_eval import in_house_study_evidence as evidence
from privoke_model import training_data
from privoke_eval.in_house_advpii_review import InHouseProtectionBindings

SOURCE_ROWS = 104728
ORIGINAL_ROWS = 3832
ORIGINAL_BYTES = 1257228
ORIGINAL_SHA256 = 'da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d'
LIMIT = 128 * 1024 * 1024
KIND = 'privoke-in-house-partitions-prepared-v1'
RELEASE_KIND = 'new-prospective-reserved-test-release-v1'
DATA_FILES = ('train.jsonl', 'validation.jsonl', 'fixtures.jsonl', 'reserved-test.jsonl')
RECEIPT_FILES = ('first-envelope.json', 'second-envelope.json', 'dual-review.json', 'allocation.json', 'provenance.json')
PREPARED_FILES = DATA_FILES + RECEIPT_FILES + ('prepared-manifest.json',)
SOURCE_MODULES = {
    'publisher': ('privoke_eval.in_house_partition_publication', 'evaluation/privoke_eval/in_house_partition_publication.py'),
    'reconstruction': (reconstruction.__name__, 'evaluation/privoke_eval/in_house_review_reconstruction.py'),
    'allocator': (allocator.__name__, 'evaluation/privoke_eval/in_house_dual_allocation.py'),
    'consumer': (dual.__name__, 'evaluation/privoke_eval/in_house_dual_review.py'),
    'evidence': (evidence.__name__, 'evaluation/privoke_eval/in_house_study_evidence.py'),
    'programme': (contract.__name__, 'evaluation/privoke_eval/in_house_study_contract.py'),
    'normalizer': (training_data.__name__, 'shared/python/privoke_model/training_data.py'),
    'cli': (None, 'evaluation/publish-in-house-partitions.py'),
    'compose': (None, 'evaluation/compose.in-house-publication.yml'),
}
MANIFEST_KEYS = ('schema_version', 'kind', 'source_revision', 'source_rows', 'preparation_identity',
    'review_pool_sha256', 'published_preparation', 'source_hashes', 'preparation_input_hashes', 'preparation_code_hashes',
    'protection_bindings', 'original', 'files', 'datasets', 'quotas', 'component_floors',
    'consensus_sha256', 'consensus_rule_raw_sha256', 'reviewers', 'human_agreement_claimed',
    'label_truth_authenticated')


class PublicationError(ValueError):
    """Sanitized failure with no prompt, label or private path in diagnostics."""


def fail():
    raise PublicationError('Partition publication failed validation.') from None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def plain(value):
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


def decode(raw, expected):
    try:
        return evidence.checked_json(raw, expected, LIMIT)
    except Exception:
        fail()


def closed(value, fields):
    if not isinstance(value, Mapping) or set(value) != set(fields):
        fail()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def directory_identity(info):
    # Creating legitimate children changes directory times/link counts. Names,
    # inode, ownership and mode still remain anchored to held ancestors.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def file_signature(info):
    return identity(info) + (info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class HeldDirectory:
    """Hold no-follow ancestors and authenticate private names on every edge."""
    def __init__(self, path, *, create=False, empty=False, owner=None, private=True):
        self.path = Path(path)
        self.create, self.empty = create, empty
        self.private = private
        self.owner = (os.geteuid() if hasattr(os, "geteuid") else None) if owner is None else owner
        self.ancestors = []
        self.files = {}

    def __enter__(self):
        try:
            if (not io._platform_supported() or not self.path.is_absolute()
                    or '..' in self.path.parts or str(self.path) != str(self.path.absolute())):
                fail()
            parts = self.path.parts
            fd = None
            for index, part in enumerate(parts):
                if index == len(parts)-1 and self.create:
                    os.mkdir(part, 0o700, dir_fd=fd)
                before = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(before.st_mode):
                    fail()
                opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                self.ancestors.append((part, fd, opened, directory_identity(before)))
                if directory_identity(os.fstat(opened)) != directory_identity(before):
                    fail()
                fd = opened
            self.fd = fd
            info = os.fstat(fd)
            if self.private and info.st_uid != self.owner:
                fail()
            if self.empty:
                if os.listdir(fd):
                    fail()
                os.fchmod(fd, 0o700)
                part, parent, opened, _ = self.ancestors[-1]
                self.ancestors[-1] = (part, parent, opened, directory_identity(os.fstat(fd)))
            if self.private and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                fail()
            self.verify()
            return self
        except Exception:
            self.__exit__(None, None, None)
            fail()

    def verify(self, expected_names=None):
        def directories():
            for name, parent, fd, expected in self.ancestors:
                if (directory_identity(os.fstat(fd)) != expected
                        or directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected):
                    fail()
        def members():
            if expected_names is not None and set(os.listdir(self.fd)) != set(expected_names):
                fail()
        def signature(name, fd, expected, size):
            before = os.fstat(fd)
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (file_signature(before) != expected or file_signature(named) != expected
                    or not stat.S_ISREG(before.st_mode) or (self.private and before.st_uid != self.owner)
                    or stat.S_IMODE(before.st_mode) not in ((0o600,) if self.private else (0o444,0o644))
                    or before.st_nlink != 1 or before.st_size != size):
                fail()
        directories()
        members()
        for name, (fd, expected, digest, size) in self.files.items():
            signature(name, fd, expected, size)
            os.lseek(fd, 0, os.SEEK_SET)
            raw = b''
            while len(raw) <= size:
                chunk = os.read(fd, min(1024 * 1024, size + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if len(raw) != size or sha(raw) != digest:
                fail()
            signature(name, fd, expected, size)
        # A later read can race a previously hashed member. Sweep every held
        # and named signature plus exact membership after all content reads.
        for name, (fd, expected, _, size) in self.files.items():
            signature(name, fd, expected, size)
        members()
        directories()

    def verify_state(self, expected_names):
        """Read-free final sweep, including members hashed by an earlier role."""
        for name, parent, fd, expected in self.ancestors:
            if (directory_identity(os.fstat(fd)) != expected
                    or directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected):
                fail()
        for name, (fd, expected, _, _) in self.files.items():
            if (file_signature(os.fstat(fd)) != expected
                    or file_signature(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != expected):
                fail()
        if set(os.listdir(self.fd)) != set(expected_names):
            fail()

    def read(self, name, digest):
        if Path(name).name != name or not io._valid_sha(digest):
            fail()
        self.verify()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        self.files[name] = (fd, file_signature(os.fstat(fd)), digest, os.fstat(fd).st_size)
        if self.files[name][-1] > LIMIT:
            fail()
        self.verify()
        os.lseek(fd, 0, os.SEEK_SET)
        raw = b''
        while chunk := os.read(fd, 1024 * 1024):
            raw += chunk
        self.verify()
        return raw

    def write(self, name, raw):
        if Path(name).name != name or type(raw) is not bytes or len(raw) > LIMIT:
            fail()
        self.verify()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        self.files[name] = (fd, file_signature(os.fstat(fd)), sha(raw), len(raw))
        os.fchmod(fd, 0o600)
        cursor = 0
        while cursor < len(raw):
            written = os.write(fd, raw[cursor:])
            if written <= 0:
                fail()
            cursor += written
        os.fsync(fd)
        self.files[name] = (fd, file_signature(os.fstat(fd)), sha(raw), len(raw))
        self.verify()

    def __exit__(self, *_):
        for fd, *_ in self.files.values():
            os.close(fd)
        self.files.clear()
        for _, _, fd, _ in reversed(self.ancestors):
            os.close(fd)
        self.ancestors.clear()



def seal_directory(directory, names):
    """Finish durability before the final held byte/state verification."""
    os.fsync(directory.fd)
    directory.verify(names)


def verify_output_set(outputs, inventories, meta, metadata_names, sealed, *, include_train):
    """Hash all selected roles, then sweep ALL signatures without later reads."""
    selected = {role: output for role,output in outputs.items() if include_train or role != 'train'}
    for role, output in selected.items():
        output.verify(inventories[role])
    meta.verify(metadata_names)
    sealed.verify(('sealed-test-release.json',))
    for role, output in selected.items():
        output.verify_state(inventories[role])
    meta.verify_state(metadata_names)
    sealed.verify_state(('sealed-test-release.json',))


def read_reference(stack, ref):
    closed(ref, ('file', 'sha256'))
    path = Path(ref['file'])
    held = stack.enter_context(HeldDirectory(path.parent))
    return held.read(path.name, ref['sha256']), held


def attest(source_root, pins, preparation_code=None):
    closed(pins, SOURCE_MODULES)
    root = Path(source_root)
    if preparation_code is not None:
        io._attest_code(root, SimpleNamespace(execution_code_raw_sha256=preparation_code))
    for role, (name, relative) in SOURCE_MODULES.items():
        path = root / relative
        if not root.is_absolute() or path.resolve(strict=True) != path or not io._valid_sha(pins[role]):
            fail()
        fd, before = io._open_read_nofollow(path)
        try:
            raw = b''
            while len(raw) <= io._CODE_LIMIT:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                raw += chunk
            if len(raw) > io._CODE_LIMIT or sha(raw) != pins[role] or identity(before) != identity(os.fstat(fd)):
                fail()
        finally:
            os.close(fd)
        if name is None:
            continue
        module = sys.modules[name]
        if Path(module.__file__).resolve(strict=True) != path:
            fail()
        if role == 'evidence':
            evidence._attest_module(module, pins[role])
        else:
            io._attest_module(role, raw, path, module_override=module)


def parse_rows(raw, count, *, training=False):
    if not raw or not raw.endswith(b'\n') or len(raw) > LIMIT:
        fail()
    rows = []
    fields = {'id', 'group_id', 'text', 'expected_has_pii'} | ({'text_key'} if training else set())
    for line in raw.splitlines():
        row = decode(line, sha(line))
        closed(row, fields)
        if (any(type(row[k]) is not str or not row[k] for k in ('id', 'group_id', 'text'))
                or type(row['expected_has_pii']) is not bool):
            fail()
        key = training_data.training_text_key(row['text'])
        if not key or (training and row['text_key'] != key):
            fail()
        rows.append(row)
    if len(rows) != count or len({r['id'] for r in rows}) != count or len({training_data.training_text_key(r['text']) for r in rows}) != count:
        fail()
    return rows


def dataset_metadata(raw, *, fixture=False):
    rows = [decode(line, sha(line)) for line in raw.splitlines()]
    keys = [{'row_id_sha256': evidence.opaque('row', r['id']), 'group_id_sha256': evidence.opaque('group', r['group_id']),
             'truth': r['expected_has_pii']} for r in rows]
    result = {'sha256': sha(raw), 'keys_sha256': evidence.digest(keys), 'rows': len(rows)}
    captured = SimpleNamespace(phase='collect-fixtures' if fixture else 'collect-validation',
                               dataset_sha256=result['sha256'], dataset_keys_sha256=result['keys_sha256'], dataset_rows=result['rows'])
    try:
        evidence.dataset_rows(raw, captured)
    except evidence.StudyEvidenceError:
        fail()
    if not fixture and len(rows) != 2000:
        fail()
    return result


def jsonl(rows):
    return b''.join(canonical(row) + b'\n' for row in rows)


def fixture_view(raw):
    """Preserve authored action/sensitivity requirements; do not infer PII truth."""
    rows = []
    for line in raw.splitlines():
        source = decode(line, sha(line))
        ambiguous = source.get('ambiguous')
        if any(source.get(k) not in (None, 'ALLOW', 'WARN', 'BLOCK') for k in ('minimum_action','expected_action')):
            fail()
        if type(ambiguous) is not bool:
            fail()
        row = {'id': source.get('case_id'), 'group_id': source.get('family_id'), 'text': source.get('text'),
               'expected_has_pii': None, 'ambiguous': ambiguous,
               'required_sensitive': source.get('required_sensitive'),
               'required_action': None if ambiguous else source.get('minimum_action') or source.get('expected_action'),
               'visibility_hint': source.get('visibility_hint')}
        if ambiguous and (source.get('required_sensitive') is not None
                          or source.get('expected_action') is not None or source.get('minimum_action') is not None):
            fail()
        rows.append(row)
    result = jsonl(rows)
    dataset_metadata(result, fixture=True)
    return result


def _assemble(pool, allocation, consensus, original_raw, fixture_raw):
    """Pure projection of authenticated allocation; production callers cannot supply a pool."""
    original = parse_rows(original_raw, ORIGINAL_ROWS, training=True)
    if len(original_raw) != ORIGINAL_BYTES or sha(original_raw) != ORIGINAL_SHA256:
        fail()
    if len(pool._source_rows) != SOURCE_ROWS or allocation.status != 'complete':
        fail()
    by_uid = {r.grouping_row.uid: r for r in pool._source_rows}
    member_by_uid = {m.uid: m for m in pool.core._members}
    groups = {uid: c.component_id for c in pool._graph.components for uid in c.member_uids}
    payloads, provenance, partition_groups = {}, [], {}
    for partition, count in (('train', 4000), ('validation', 2000), ('test', 2000)):
        if len(allocation.partitions[partition]) != count:
            fail()
        rows, counts = [], {'positive': 0, 'ordinary': 0, 'hard': 0}
        selected = set()
        for uid in allocation.partitions[partition]:
            member, parsed = member_by_uid.get(uid), by_uid.get(uid)
            if member is None or parsed is None:
                fail()
            record = consensus.records[member.review_id]
            if type(record.has_pii) is not bool:
                fail()
            stratum = 'positive' if record.has_pii else 'hard' if member.native_category == 'hard_negative' else 'ordinary'
            counts[stratum] += 1
            group = groups[uid]
            if group not in allocation.assigned_component_ids[partition]:
                fail()
            selected.add(group)
            row = {'id': 'in-house-advpii-' + str(uid), 'group_id': 'in-house-component-' + group,
                   'text': parsed.grouping_row.text, 'expected_has_pii': record.has_pii}
            if partition == 'train':
                row['text_key'] = training_data.training_text_key(row['text'])
            rows.append(row)
            provenance.append({'partition': partition, 'id': row['id'], 'source_uid': uid, 'component_id': group,
                               'review_id': member.review_id, 'text_sha256': sha(row['text'].encode()),
                               'text_key': training_data.training_text_key(row['text']), 'expected_has_pii': record.has_pii,
                               'first_response_sha256': record.first_response_sha256,
                               'second_response_sha256': record.second_response_sha256})
        if counts != allocator._QUOTAS[partition]:
            fail()
        partition_groups[partition] = set(allocation.assigned_component_ids[partition])
        if partition != 'train' and any(allocation.represented_components[partition][label] < 200 for label in ('positive', 'absent')):
            fail()
        filename = 'reserved-test.jsonl' if partition == 'test' else partition + '.jsonl'
        payloads[filename] = (original_raw if partition == 'train' else b'') + jsonl(rows)
    sets = list(partition_groups.values())
    if any(sets[i] & sets[j] for i in range(3) for j in range(i)):
        fail()
    combined = parse_rows(payloads['train.jsonl'], ORIGINAL_ROWS + 4000, training=True)
    additions = combined[ORIGINAL_ROWS:]
    if {r['group_id'] for r in original} & {r['group_id'] for r in additions}:
        fail()
    all_keys = [{training_data.training_text_key(r['text']) for r in parse_rows(payloads[name], count, training=name=='train.jsonl')}
                for name, count in (('train.jsonl', ORIGINAL_ROWS + 4000), ('validation.jsonl', 2000), ('reserved-test.jsonl', 2000))]
    if any(all_keys[i] & all_keys[j] for i in range(3) for j in range(i)):
        fail()
    payloads['fixtures.jsonl'] = fixture_view(fixture_raw)
    fixture_keys = {training_data.training_text_key(r['text']) for r in [decode(line, sha(line)) for line in payloads['fixtures.jsonl'].splitlines()]}
    new_train_keys = {training_data.training_text_key(r['text']) for r in additions}
    if any(keys & fixture_keys for keys in (new_train_keys, *all_keys[1:])):
        fail()
    return payloads, provenance


def prepare_partitions(paths, *, preparation_trust, published_trust, external_trust, source_root, output):
    """Replay source plus two actual complete envelopes into a fresh private result."""
    try:
        closed(external_trust, ('source_hashes', 'preparation_identity', 'first_reviewer_id', 'second_reviewer_id',
                              'first_envelope', 'second_envelope', 'original_train'))
        with ExitStack() as stack:
            attest(source_root, external_trust['source_hashes'])
            first, first_held = read_reference(stack, external_trust['first_envelope'])
            second, second_held = read_reference(stack, external_trust['second_envelope'])
            original, original_held = read_reference(stack, external_trust['original_train'])
            pool = reconstruction.reconstruct_in_house_review_pool(paths, trust=preparation_trust,
                published_trust=published_trust, source_root=Path(source_root))
            if len(pool._source_rows) != SOURCE_ROWS:
                fail()
            result, reviews = allocator.allocate_dual_reviewed_components(pool, first, second,
                source_root=Path(source_root), preparation_trust=preparation_trust,
                expected_adapter_raw_sha256=external_trust['source_hashes']['allocator'],
                expected_consumer_raw_sha256=external_trust['source_hashes']['consumer'],
                trusted_bindings=pool.bindings, expected_preparation_identity=external_trust['preparation_identity'],
                expected_first_reviewer_id=external_trust['first_reviewer_id'], expected_second_reviewer_id=external_trust['second_reviewer_id'],
                expected_first_raw_sha256=external_trust['first_envelope']['sha256'], expected_second_raw_sha256=external_trust['second_envelope']['sha256'])
            fixture_held = stack.enter_context(HeldDirectory(Path(paths.fixture).parent, private=False))
            fixture_raw = fixture_held.read(Path(paths.fixture).name, preparation_trust.input_raw_sha256['fixture'])
            if len(fixture_raw) > io._INPUT_LIMITS['fixture']:
                fail()
            payloads, provenance = _assemble(pool, result, reviews, original, fixture_raw)
            payloads.update({'first-envelope.json': first, 'second-envelope.json': second,
                'dual-review.json': canonical({'preparation_identity': reviews.preparation_identity,
                    'review_pool_sha256': reviews.review_pool_sha256, 'first_reviewer_id': reviews.first.reviewer_id,
                    'second_reviewer_id': reviews.second.reviewer_id, 'first_responses_sha256': reviews.first.responses_sha256,
                    'second_responses_sha256': reviews.second.responses_sha256, 'counts': plain(reviews.counts),
                    'consensus_rule_raw_sha256': reviews.consensus_rule_raw_sha256, 'consensus_sha256': reviews.consensus_sha256,
                    'records': {k: asdict(v) for k, v in reviews.records.items()},
                    'human_agreement_claimed': False, 'label_truth_authenticated': False}),
                'allocation.json': canonical({k: plain(getattr(result, k)) for k in ('status','reason','partitions',
                    'assigned_component_ids','capacities','represented_components','assigned_components_by_class','shortages','floor_shortages','streams')}),
                'provenance.json': canonical(provenance)})
            manifest = {'schema_version': 1, 'kind': KIND, 'source_revision': preparation_trust.source_revision,
                'source_rows': SOURCE_ROWS, 'preparation_identity': pool.preparation_identity,
                'review_pool_sha256': pool.review_pool_sha256,
                'published_preparation': {'output_raw_sha256': plain(published_trust.output_raw_sha256),
                    'expected_counts': plain(published_trust.expected_counts)}, 'source_hashes': plain(external_trust['source_hashes']),
                'preparation_input_hashes': plain(preparation_trust.input_raw_sha256),
                'preparation_code_hashes': plain(preparation_trust.execution_code_raw_sha256),
                'protection_bindings': plain(vars(pool.bindings.protection)),
                'original': {'sha256': ORIGINAL_SHA256, 'bytes': ORIGINAL_BYTES, 'rows': ORIGINAL_ROWS},
                'files': {name: sha(raw) for name, raw in payloads.items()},
                'datasets': {name: dataset_metadata(payloads[name], fixture=name=='fixtures.jsonl') for name in DATA_FILES[1:]},
                'quotas': plain(allocator._QUOTAS), 'component_floors': 200,
                'consensus_sha256': reviews.consensus_sha256, 'consensus_rule_raw_sha256': reviews.consensus_rule_raw_sha256,
                'reviewers': {'first': reviews.first.reviewer_id, 'second': reviews.second.reviewer_id},
                'human_agreement_claimed': False, 'label_truth_authenticated': False}
            payloads['prepared-manifest.json'] = canonical(manifest)
            with HeldDirectory(output, create=True) as destination:
                for name, raw in payloads.items():
                    first_held.verify(); second_held.verify(); original_held.verify(); fixture_held.verify()
                    attest(source_root, external_trust['source_hashes'])
                    destination.write(name, raw)
                destination.verify(PREPARED_FILES)
                first_held.verify(); second_held.verify(); original_held.verify(); fixture_held.verify()
                attest(source_root, external_trust['source_hashes'])
                seal_directory(destination, PREPARED_FILES)
            return {'prepared_manifest_raw_sha256': sha(payloads['prepared-manifest.json']),
                    'files': {name: sha(raw) for name, raw in payloads.items()}}
    except Exception:
        fail()


def validate_prepared(manifest, payloads, expected_sources):
    closed(manifest, MANIFEST_KEYS)
    closed(payloads, DATA_FILES + RECEIPT_FILES)
    closed(manifest['files'], DATA_FILES + RECEIPT_FILES)
    if (type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or manifest['kind'] != KIND
            or manifest['source_rows'] != SOURCE_ROWS or manifest['source_hashes'] != expected_sources
            or manifest['human_agreement_claimed'] is not False or manifest['label_truth_authenticated'] is not False
            or manifest['original'] != {'sha256': ORIGINAL_SHA256, 'bytes': ORIGINAL_BYTES, 'rows': ORIGINAL_ROWS}
            or manifest['quotas'] != plain(allocator._QUOTAS) or manifest['component_floors'] != 200):
        fail()
    closed(manifest['published_preparation'], ('output_raw_sha256','expected_counts'))
    closed(manifest['published_preparation']['output_raw_sha256'], reconstruction._FILES)
    closed(manifest['published_preparation']['expected_counts'], ('source_rows','pool_size','graph_components','assignable_rows'))
    counts = manifest['published_preparation']['expected_counts']
    if (counts['source_rows'] != SOURCE_ROWS or any(type(v) is not int or not 0 <= v <= SOURCE_ROWS for v in counts.values())
            or any(not io._valid_sha(v) for v in manifest['published_preparation']['output_raw_sha256'].values())):
        fail()
    closed(manifest['preparation_input_hashes'], io._INPUT_ROLES)
    closed(manifest['preparation_code_hashes'], io._CODE_PATHS)
    if any(not io._valid_sha(v) for v in (*manifest['preparation_input_hashes'].values(), *manifest['preparation_code_hashes'].values(),
            manifest['preparation_identity'], manifest['review_pool_sha256'], manifest['consensus_sha256'], manifest['consensus_rule_raw_sha256'])):
        fail()
    closed(manifest['reviewers'], ('first','second'))
    if (any(type(v) is not str or not v.strip() or v != v.strip() for v in manifest['reviewers'].values())
            or manifest['reviewers']['first'] == manifest['reviewers']['second']):
        fail()
    try:
        InHouseProtectionBindings(**manifest['protection_bindings'])
    except Exception:
        fail()
    for name, raw in payloads.items():
        if sha(raw) != manifest['files'][name]:
            fail()
    train = payloads['train.jsonl']
    if len(train) <= ORIGINAL_BYTES or sha(train[:ORIGINAL_BYTES]) != ORIGINAL_SHA256 or not train[:ORIGINAL_BYTES].endswith(b'\n'):
        fail()
    parse_rows(train[:ORIGINAL_BYTES], ORIGINAL_ROWS, training=True)
    parse_rows(train, ORIGINAL_ROWS + 4000, training=True)
    closed(manifest['datasets'], DATA_FILES[1:])
    for name in DATA_FILES[1:]:
        if manifest['datasets'][name] != dataset_metadata(payloads[name], fixture=name=='fixtures.jsonl'):
            fail()


def publish_flat_views(prepared, *, expected_prepared_raw_sha256, programme_input_bytes,
                       expected_programme_input_raw_sha256, external_trust, source_root, destinations, metadata_output, sealed_metadata_output):
    """Publish flat phase inventories, never a test locator in train/controller inputs.

Train ownership is handed to 65534 only after owner-side checks. The separate
readonly UID-65534 reader must attest the resulting inventory before use.
"""
    try:
        closed(external_trust, ('source_hashes', 'trainer_contract_sha256', 'training_image_id', 'dependency_lock_sha256', 'volumes'))
        closed(destinations, ('train', 'validation', 'fixtures', 'test'))
        closed(external_trust['volumes'], destinations)
        if (len(set(external_trust['volumes'].values())) != 4
                or len({str(Path(p)) for p in (*destinations.values(), metadata_output, sealed_metadata_output, prepared)}) != 7):
            fail()
        for value in external_trust['volumes'].values():
            if type(value) is not str or not value or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for c in value):
                fail()
        attest(source_root, external_trust['source_hashes'])
        with HeldDirectory(prepared) as held, ExitStack() as stack:
            raw = held.read('prepared-manifest.json', expected_prepared_raw_sha256)
            manifest = decode(raw, expected_prepared_raw_sha256)
            closed(manifest, MANIFEST_KEYS)
            payloads = {name: held.read(name, digest) for name, digest in manifest['files'].items()}
            held.verify(PREPARED_FILES)
            validate_prepared(manifest, payloads, external_trust['source_hashes'])
            attest(source_root, external_trust['source_hashes'], manifest['preparation_code_hashes'])
            programme = contract.freeze_programme(decode(programme_input_bytes, expected_programme_input_raw_sha256))
            external = dict(programme.external_hashes)
            joins = {'prepared_manifest': expected_prepared_raw_sha256, 'training_image': external_trust['training_image_id'],
                     'dependency_lock': external_trust['dependency_lock_sha256'], 'fixture': manifest['preparation_input_hashes']['fixture'],
                     'fixture_rubric': manifest['preparation_input_hashes']['fixture_rubric'],
                     'fixture_review': manifest['preparation_input_hashes']['fixture_review'],
                     'historical_protection_artifact': manifest['preparation_input_hashes']['protected_union'],
                     'historical_protection_receipt': manifest['preparation_input_hashes']['protection_receipt'],
                     'fixture_addon_artifact': manifest['preparation_input_hashes']['addon_artifact'],
                     'fixture_addon_receipt': manifest['preparation_input_hashes']['addon_receipt'],
                     'combined_protected_keys': manifest['protection_bindings']['combined_protection_sha256'],
                     'helper_sources': sha(canonical({'preparation': manifest['preparation_code_hashes'],
                                                      'publication': manifest['source_hashes']}))}
            if programme.source_revision != manifest['source_revision'] or any(external[k] != v for k,v in joins.items()):
                fail()
            if not io._valid_sha(external_trust['trainer_contract_sha256']):
                fail()
            view = {'schema_version': 1, 'kind': 'privoke-in-house-training-view-v1',
                'source_revision': programme.source_revision, 'programme_sha256': programme.sha256,
                'programme_input_raw_sha256': expected_programme_input_raw_sha256,
                'prepared_manifest_raw_sha256': expected_prepared_raw_sha256, 'train_raw_sha256': sha(payloads['train.jsonl']),
                'original_train_raw_sha256': ORIGINAL_SHA256, 'train_prefix_bytes': ORIGINAL_BYTES,
                'trainer_contract_sha256': external_trust['trainer_contract_sha256'],
                'allocation_receipt_sha256': sha(payloads['allocation.json']),
                'reviewed_labels_receipt_sha256': sha(payloads['dual-review.json']),
                'row_count': ORIGINAL_ROWS + 4000, 'original_row_count': ORIGINAL_ROWS, 'addition_row_count': 4000,
                'initialization_fingerprints': dict(programme.initialization_fingerprints)}
            view_raw = canonical(view)
            inventories = {'train': {'train.jsonl': payloads['train.jsonl'], 'training-manifest.json': view_raw},
                           'validation': {'validation.jsonl': payloads['validation.jsonl']},
                           'fixtures': {'fixtures.jsonl': payloads['fixtures.jsonl']},
                           'test': {'reserved-test.jsonl': payloads['reserved-test.jsonl']}}
            outputs = {role: stack.enter_context(HeldDirectory(path, empty=True)) for role,path in destinations.items()}
            meta = stack.enter_context(HeldDirectory(metadata_output, create=True))
            sealed = stack.enter_context(HeldDirectory(sealed_metadata_output, create=True))
            for role, files in inventories.items():
                for name, content in files.items():
                    held.verify(PREPARED_FILES); attest(source_root, external_trust['source_hashes'], manifest['preparation_code_hashes'])
                    outputs[role].write(name, content)
                outputs[role].verify(files)
                os.fsync(outputs[role].fd)
            fit_inputs = {}
            for arm in contract.ARM_KEYS[1:]:
                expected = {k:v for k,v in view.items() if k not in ('row_count','original_row_count','addition_row_count')}
                expected.update(kind='privoke-in-house-fit-inputs-v1', arm_key=arm, training_view_manifest_raw_sha256=sha(view_raw),
                    actual_training_image_id='sha256:' + external_trust['training_image_id'], dependency_lock_sha256=external_trust['dependency_lock_sha256'])
                expected_raw = canonical(expected)
                name = 'fit-' + arm + '.json'
                meta.write(name, expected_raw)
                fit_inputs[arm] = {'train': {'volume': external_trust['volumes']['train'], 'file': 'train.jsonl', 'sha256': sha(payloads['train.jsonl'])},
                    'manifest': {'volume': external_trust['volumes']['train'], 'file': 'training-manifest.json', 'sha256': sha(view_raw)},
                    'expected': {'file': name, 'sha256': sha(expected_raw)}}
            descriptors = {role: {'volume': external_trust['volumes'][role], 'file': role+'.jsonl', **manifest['datasets'][role+'.jsonl']}
                           for role in ('validation', 'fixtures')}
            test_metadata = {'kind': 'new-prospective-reserved-test-v1', **manifest['datasets']['reserved-test.jsonl']}
            release = {'schema_version': 1, 'kind': RELEASE_KIND, 'programme_sha256': programme.sha256,
                       'test_metadata': test_metadata, 'dataset': {'volume': external_trust['volumes']['test'],
                       'file': 'reserved-test.jsonl', 'sha256': test_metadata['sha256']}}
            sealed.write('sealed-test-release.json', canonical(release))
            sealed.verify(('sealed-test-release.json',))
            os.fsync(sealed.fd)
            receipt = {'schema_version':1, 'kind':'privoke-in-house-flat-publication-v1', 'programme_sha256':programme.sha256,
                'prepared_manifest_raw_sha256':expected_prepared_raw_sha256, 'fits':fit_inputs, 'datasets':descriptors,
                'test_metadata':test_metadata, 'sealed_test_release_raw_sha256':sha(canonical(release)),
                'status': 'awaiting_train_reader', 'train_reader_required': True, 'training_view_manifest_raw_sha256':sha(view_raw),
                'train_raw_sha256':sha(payloads['train.jsonl'])}
            meta.write('publication-receipt.json', canonical(receipt))
            metadata_names = tuple('fit-'+arm+'.json' for arm in contract.ARM_KEYS[1:]) + ('publication-receipt.json',)
            held.verify(PREPARED_FILES)
            attest(source_root, external_trust['source_hashes'], manifest['preparation_code_hashes'])
            # Complete durability operations before the global owner-side
            # barrier, so later role/metadata writes cannot bypass an earlier
            # role's check. Fresh volumes have no other authorized writer.
            for output in outputs.values():
                os.fsync(output.fd)
            os.fsync(meta.fd)
            os.fsync(sealed.fd)
            verify_output_set(outputs, inventories, meta, metadata_names, sealed, include_train=True)
            # Only CHOWN is needed; no DAC authority over evidence or other volumes.
            train = outputs['train']
            train.verify(inventories['train'])
            for fd, *_ in train.files.values():
                os.fchown(fd, 65534, 65534)
            os.fchown(train.fd, 65534, 65534)
            directory_info = os.fstat(train.fd)
            if directory_info.st_uid != 65534 or directory_info.st_gid != 65534 or stat.S_IMODE(directory_info.st_mode) != 0o700:
                fail()
            os.fsync(train.fd)
            os.fsync(meta.fd)
            transferred_signatures = {}
            for fd, _, digest, size in train.files.values():
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 65534 or info.st_gid != 65534
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size != size):
                    fail()
                transferred_signatures[fd] = file_signature(info)
                os.lseek(fd,0,os.SEEK_SET)
                content = b''
                while len(content) <= size:
                    chunk = os.read(fd, min(1024*1024, size+1-len(content)))
                    if not chunk:
                        break
                    content += chunk
                if sha(content) != digest or file_signature(os.fstat(fd)) != transferred_signatures[fd]:
                    fail()
            # Root retains search authority over every other output. Verify
            # them after ALL CHOWN/fsync/train reads, with no later mutation
            # operation. Train pathname/readability acceptance remains the
            # dedicated UID65534 reader's responsibility; no DAC is added.
            held.verify(PREPARED_FILES)
            verify_output_set(outputs, inventories, meta, metadata_names, sealed, include_train=False)
            if any(file_signature(os.fstat(fd)) != signature for fd,signature in transferred_signatures.items()):
                fail()
            return receipt
    except Exception:
        fail()


def verify_train_reader(path, *, expected_train_sha256, expected_manifest_sha256):
    """Actual UID65534/no-capabilities flat-view check, before publication acceptance."""
    try:
        if os.geteuid() != 65534 or os.getegid() != 65534:
            fail()
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if any(int(status[k].strip(), 16) != 0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) or status['NoNewPrivs'].strip() != '1':
            fail()
        with HeldDirectory(path, owner=65534) as held:
            held.read('train.jsonl', expected_train_sha256)
            held.read('training-manifest.json', expected_manifest_sha256)
            held.verify(('train.jsonl','training-manifest.json'))
            if os.fstat(held.fd).st_gid != 65534 or any(os.fstat(fd).st_gid != 65534 for fd,*_ in held.files.values()):
                fail()
            return {'schema_version':1, 'kind':'privoke-in-house-train-reader-v1', 'uid':65534,
                    'train_raw_sha256':expected_train_sha256, 'training_view_manifest_raw_sha256':expected_manifest_sha256}
    except Exception:
        fail()
