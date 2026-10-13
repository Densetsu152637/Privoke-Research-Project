"""Fixed gold-target permanent-TRAIN bank; preparation is not measured efficacy."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import random

from privoke_model.training_data import training_text_key
from training.types import BatchTrainingExample
from . import taxonomy_coverage as legacy

STRATEGY = "taxonomy_anchor_rehearsal_v1"
TABLE_VERSION = "pc43_fixed_16_plus_16_v1"
DATASET_SHA256 = "3b777f328a8e08140ee964facbd559c694673336b4c5655320befdd84aef66e0"
BANK_KEY = "rehearsal_bank_sha256"
MANIFEST_KEY = "rehearsal_manifest_sha256"
PIN_KEYS = frozenset(("taxonomy_dataset_sha256", BANK_KEY, MANIFEST_KEY))
ACTUAL = {
    "HEALTH": ("P3", "P0"), "POLITICS": ("P0", "P4"),
    "RELIGION": ("P3", "P1"), "CRIMINAL": ("P4", "P2"),
    "FINANCIAL": ("P0", "P3"), "SEXUAL": ("P4", "P0"),
    "CHILD": ("P1", "P3"), "LOCATION": ("P2", "P4"),
    "IDENTITY": ("PU", "P2"), "THIRD_PARTY": ("P2", "PU"),
}
FICTION = ((('HEALTH', 'P0'), ('POLITICS', 'P1'), ('RELIGION', 'P2'), ('CRIMINAL', 'P3')),
           (('FINANCIAL', 'P4'), ('SEXUAL', 'PU'), ('CHILD', 'P0'), ('LOCATION', 'PU')))
MILD = ((('HEALTH', 'P1'), ('RELIGION', 'PU')), (('POLITICS', 'P1'), ('CRIMINAL', 'PU')))


def digest(value):
    return hashlib.sha256(legacy.canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class RehearsalManifest:
    sha256: str
    bank_sha256: str
    payload: bytes


def bank(dataset):
    """Select only positively validated permanent TRAIN rows, never guard rows."""
    if dataset.sha256 != DATASET_SHA256:
        raise ValueError("Rehearsal requires the exact accepted permanent-TRAIN dataset SHA.")
    result = []
    for family, role in enumerate(("anchor", "complement")):
        groups = {c: sorted({r.metadata['group_id'] for r in dataset.rows
                             if r.metadata['primary_category'] == c
                             and dataset.partitions.get(r.metadata['group_id']) == 'train'})
                  for c in ACTUAL}
        if any(len(g) != 2 for g in groups.values()):
            raise ValueError("Rehearsal needs exactly two positively proven TRAIN families per category.")
        slots = [(c, 'actual', vs[family]) for c, vs in ACTUAL.items()]
        slots += [(c, 'fiction', v) for c, v in FICTION[family]]
        slots += [(c, 'mild', v) for c, v in MILD[family]]
        half = []
        for category, control, audience in slots:
            row = legacy._row(dataset, groups[category][family], control, audience)
            if (row.metadata.get('split') != 'train' or row.metadata.get('taxonomy_partition') != 'train'
                    or row.weight != 1.0):
                raise ValueError("Rehearsal slot is not an original unit-weight permanent TRAIN row.")
            half.append(BatchTrainingExample(row.text, row.expected_classification, row.weight,
                {**row.metadata, 'taxonomy_strategy': STRATEGY, 'rehearsal_role': role}))
        sensitivity, visibility, _ = legacy._counts(half)
        if sensitivity != {'S0': 4, 'S1': 2, 'S2': 3, 'S3': 7} or visibility != {v: 2 for v in legacy.Visibility.__members__}:
            raise ValueError("Rehearsal half differs from the accepted target/visibility table.")
        result.extend(half)
    seen = {}
    for row in result:
        for variant in legacy.transform_variants(row.text):
            key = training_text_key(variant)
            identity = row.metadata['taxonomy_row_id']
            if key in seen and seen[key] != identity:
                raise ValueError("Rehearsal cross-original transformed-text/target collision.")
            seen[key] = identity
    if (len({training_text_key(r.text) for r in result}) != 32
            or len({r.metadata['taxonomy_row_id'] for r in result}) != 32
            or len({r.metadata['group_id'] for r in result}) != 20):
        raise ValueError("Rehearsal originals must be unique and cover all twenty TRAIN families.")
    if any(legacy._counts(result)[2][c] < n for c, n in legacy.CATEGORY_MINIMUMS.items()):
        raise ValueError("Rehearsal lost required source category coverage.")
    return result


def row_commitment(row):
    return {'id': row.metadata['taxonomy_row_id'], 'group': row.metadata['group_id'],
            'role': row.metadata['rehearsal_role'], 'category': row.metadata['primary_category'],
            'control': row.metadata['control'], 'partition': row.metadata['taxonomy_partition'],
            'text_sha256': hashlib.sha256(row.text.encode()).hexdigest(),
            'target': row.expected_classification.to_dict(), 'packed': row.expected_packed_classification,
            'weight': row.weight}


def prepare_manifest(dataset):
    rows = bank(dataset)
    membership = [row_commitment(r) for r in rows]
    return legacy.canonical_bytes({'schema': 1, 'strategy': STRATEGY, 'table_version': TABLE_VERSION,
        'dataset_sha256': dataset.sha256, 'bank_sha256': digest(membership), 'bank': membership,
        'originals': 32, 'anchor_originals': 16, 'complement_originals': 16, 'expanded': 64,
        'sensitivity_counts': legacy.SENSITIVITY_COUNTS, 'sensitive_visibility_counts': {v: 4 for v in legacy.Visibility.__members__},
        'weights': {'anchor': 1, 'complement': 1, 'new_example_weight': 1},
        'expansion': 'unchanged_legacy_seeded_one_invariance_transform_v1',
        'guard': 'unchanged_same_seed_taxonomy_coverage_v1_16_rows',
        'partition_recipe': legacy.PARTITION_RECIPE, 'exclusion_validation': dataset.exclusion_validation,
        'fit_release': False, 'expansion_exclusion_status': 'requires_actual_v2_subset_proof_against_pinned_validated_TC02_superset',
        'coverage_change': 'fixed_both_TRAIN_families_and_PC43_audiences'})


def load_snapshot(payload, dataset):
    expected = prepare_manifest(dataset)
    if payload != expected:
        raise ValueError("Rehearsal manifest bytes/schema/membership/targets/config differ from the accepted contract.")
    value = json.loads(payload)
    return RehearsalManifest(hashlib.sha256(payload).hexdigest(), value['bank_sha256'], payload)


def load_manifest(path, dataset):
    if not path:
        raise ValueError("Rehearsal requires an explicit manifest path.")
    return load_snapshot(Path(path).read_bytes(), dataset)


def validate_pins(metadata, manifest, dataset):
    expected = {'taxonomy_dataset_sha256': dataset.sha256, BANK_KEY: manifest.bank_sha256, MANIFEST_KEY: manifest.sha256}
    if metadata.get('contextual_sampling_strategy') != STRATEGY or any(metadata.get(k) != v for k, v in expected.items()):
        raise ValueError("Rehearsal requires matching explicit strategy/dataset/bank/manifest SHA pins.")
    load_snapshot(manifest.payload, dataset)


def generate_partition(dataset, manifest, seed):
    load_snapshot(manifest.payload, dataset)
    selected = bank(dataset)
    random.Random(seed).shuffle(selected)  # nosec B311
    training = [BatchTrainingExample(r.text, r.expected_classification, r.weight,
                {**r.metadata, 'generation_seed': str(seed), 'generation_index': str(i)}) for i, r in enumerate(selected)]
    _, guard = legacy.generate_partition(dataset, seed)
    audit_originals(dataset, manifest, training, guard, seed)
    return training, guard


def audit_originals(dataset, manifest, originals, guard, seed):
    load_snapshot(manifest.payload, dataset)
    expected = {r.metadata['taxonomy_row_id']: r for r in bank(dataset)}
    if len(originals) != 32 or Counter(r.metadata.get('taxonomy_row_id') for r in originals) != Counter(expected.keys()):
        raise ValueError("Rehearsal original membership differs from the fixed bank.")
    ordered = list(expected)
    random.Random(seed).shuffle(ordered)  # nosec B311
    if [r.metadata['taxonomy_row_id'] for r in originals] != ordered:
        raise ValueError("Rehearsal original order differs from the declared seed.")
    for index, row in enumerate(originals):
        source = expected[row.metadata['taxonomy_row_id']]
        if (row.text != source.text or row.expected_packed_classification != source.expected_packed_classification
                or row.weight != 1.0 or row.metadata != {**source.metadata, 'generation_seed': str(seed), 'generation_index': str(index)}):
            raise ValueError("Rehearsal original target/text/weight/provenance differs.")
    _, expected_guard = legacy.generate_partition(dataset, seed)
    if guard != expected_guard:
        raise ValueError("Rehearsal requires the unchanged same-seed v1 guard.")
    guard_keys = {training_text_key(r.text) for r in guard}
    if guard_keys & {training_text_key(v) for r in originals for v in legacy.transform_variants(r.text)}:
        raise ValueError("Rehearsal transformed training texts overlap the guard.")
    sensitivity, visibility, categories = legacy._counts(originals)
    return {'contextual_sampling_strategy': STRATEGY, 'taxonomy_dataset_sha256': dataset.sha256,
        BANK_KEY: manifest.bank_sha256, MANIFEST_KEY: manifest.sha256,
        'sampling_table_version': TABLE_VERSION, 'sampling_training_rows': '32', 'sampling_training_unique_texts': '32',
        'sampling_training_groups': '20', 'sampling_guard_rows': '16', 'sampling_guard_groups': '16',
        'sampling_anchor_rows': '16', 'sampling_complement_rows': '16',
        'sampling_anchor_clean_rows': '4', 'sampling_anchor_sensitive_rows': '12',
        'sampling_sensitivity_counts': json.dumps(dict(sensitivity), sort_keys=True),
        'sampling_sensitive_visibility_counts': json.dumps(dict(visibility), sort_keys=True),
        'sampling_category_counts': json.dumps(dict(categories), sort_keys=True),
        'sampling_training_ids_sha256': legacy._digest(expected),
        'sampling_training_groups_sha256': legacy._digest({r.metadata['group_id'] for r in bank(dataset)}),
        'sampling_guard_groups_sha256': legacy._digest(r.metadata['group_id'] for r in guard),
        'sampling_original_order_sha256': digest([row_commitment(r) for r in originals]),
        'sampling_seed': str(seed)}


def wire_commitment(rows):
    """Commit exact ordered protobuf training fields, including named targets."""
    return digest([{'text': r.text, 'has_target': r.has_target, 'weight': r.weight,
                    'target': {'packed': r.target.packed, 'sensitivity': r.target.sensitivity,
                               'visibility': r.target.visibility, 'categories': list(r.target.categories)}} for r in rows])


def training_wire_rows(rows):
    from privoke.v1 import runtime_pb2
    return [runtime_pb2.RuntimeTrainingExample(text=r.text, has_target=True, weight=r.weight,
        target=runtime_pb2.RuntimeClassification(packed=r.expected_packed_classification,
            sensitivity=r.expected_classification.sensitivity().name, visibility=r.expected_classification.visibility().name,
            categories=[c.name for c in r.expected_classification.categories()])) for r in rows]


def audit_expanded(dataset, manifest, originals, expanded, guard, config):
    from training.trainer import iter_training_examples
    audit = audit_originals(dataset, manifest, originals, guard, config.seed)
    if (config.transformations_per_example != 1 or config.new_example_weight != 1.0 or len(expanded) != 64
            or expanded != list(iter_training_examples(originals, (), config))):
        raise ValueError("Rehearsal expansion/weight/seed differs from unchanged legacy transforms.")
    for index, original in enumerate(originals):
        if any(row.text not in legacy.transform_variants(original.text) for row in expanded[index * 2:index * 2 + 2]):
            raise ValueError("Rehearsal expansion is outside the pinned validated source transform superset.")
    audit.update(sampling_expanded_rows='64',
        sampling_expanded_unique_texts=str(len({training_text_key(r.text) for r in expanded})),
        sampling_expanded_ids_sha256=legacy._digest(r.metadata['taxonomy_row_id'] for r in expanded),
        sampling_expanded_wire_sha256=wire_commitment(training_wire_rows(expanded)))
    return audit


def persist_audit(manifest, audit):
    """Retain complete immutable sampling evidence before the physical RPC."""
    directory = os.getenv('PRIVOKE_FUZZER_DUMP_DIR')
    if not directory:
        raise ValueError('Rehearsal requires durable complete sampling evidence.')
    payload = legacy.canonical_bytes({'schema': 1, 'manifest_utf8': manifest.payload.decode('utf-8'), 'audit': audit})
    sha = hashlib.sha256(payload).hexdigest()
    path = Path(directory) / 'rehearsal-audits' / (sha + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if path.read_bytes() != payload:
            raise ValueError('Rehearsal immutable sampling evidence conflicts.')
    return {'path': str(path), 'sha256': sha}


def validate_retained_audit(evidence, metadata):
    reference = evidence['rehearsal_audit']
    payload = Path(reference['path']).read_bytes()
    if hashlib.sha256(payload).hexdigest() != reference['sha256']:
        raise ValueError('Rehearsal retained sampling evidence checksum differs.')
    record = json.loads(payload)
    manifest_bytes = record['manifest_utf8'].encode('utf-8')
    manifest = json.loads(manifest_bytes)
    if (record['schema'] != 1 or hashlib.sha256(manifest_bytes).hexdigest() != metadata.get(MANIFEST_KEY)
            or digest(manifest['bank']) != metadata.get(BANK_KEY)
            or manifest['dataset_sha256'] != metadata.get('taxonomy_dataset_sha256')
            or any(metadata.get(k) != v for k, v in record['audit'].items())):
        raise ValueError('Rehearsal full retained audit differs from outgoing publication.')
    return record
