"""Bind opt-in candidate eligibility and trace projection to durable raw RPC evidence."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from privoke_model.full_adam import (POLICY, ELIGIBILITY, ELIGIBILITY_KEY, EXECUTED_KEY,
    TRACE_KEY, SUMMARY_KEY, CONFIG, CONFIG_KEY, canonical, validate_trace)
from privoke_model.fingerprint import parameter_fingerprint
from privoke_model.contextual_training import parse_training_admission_metadata

GATE_KEY = "full_adam_gate_v1"
WEIGHT_KEY = "full_adam_weight_audit_v1"
WEIGHT_FIELDS = frozenset({"training_clean_examples", "training_sensitive_examples", "raw_clean_weight",
    "raw_sensitive_weight", "raw_total_weight", "effective_clean_weight", "effective_sensitive_weight",
    "clean_objective_mass", "sensitive_objective_mass"})
TAXONOMY_KEY = "full_adam_taxonomy_audit_v1"
TAXONOMY_FIELDS = frozenset({"sampling_training_rows", "sampling_training_unique_texts", "sampling_training_groups",
    "sampling_guard_rows", "sampling_guard_groups", "sampling_sensitivity_counts", "sampling_sensitive_visibility_counts",
    "sampling_category_counts", "sampling_training_ids_sha256", "sampling_training_groups_sha256",
    "sampling_guard_groups_sha256", "sampling_expanded_rows", "sampling_expanded_unique_texts", "sampling_expanded_ids_sha256"})
REHEARSAL_KEY = "full_adam_rehearsal_audit_v1"
REHEARSAL_FIELDS = TAXONOMY_FIELDS | frozenset({'sampling_table_version', 'sampling_anchor_rows',
    'sampling_complement_rows', 'sampling_anchor_clean_rows', 'sampling_anchor_sensitive_rows',
    'sampling_original_order_sha256', 'sampling_seed', 'sampling_expanded_wire_sha256'})
BENIGN_KEY = "full_adam_benign_audit_v1"
BENIGN_FIELDS = TAXONOMY_FIELDS | frozenset({'sampling_ordinary_benign_rows', 'sampling_fiction_rows',
    'sampling_original_order_sha256', 'sampling_seed', 'sampling_expanded_wire_sha256', 'sampling_guard_wire_sha256'})


def project_benign_audit(metadata, request):
    """Bind this strategy's exact source and ordered TRAIN/guard wire commitments."""
    from prompt_generation.benign_coverage import DATASET_SHA256, POOL_KEY, MANIFEST_KEY, PROOF_KEY, wire_commitment
    if (BENIGN_KEY in metadata or {k for k in metadata if k.startswith('sampling_')} != BENIGN_FIELDS
            or metadata.get('taxonomy_dataset_sha256') != DATASET_SHA256
            or any(type(metadata.get(k)) is not str or len(metadata[k]) != 64
                   or any(c not in '0123456789abcdef' for c in metadata[k]) for k in (POOL_KEY, MANIFEST_KEY, PROOF_KEY))
            or len(request.examples) != 64 or len(request.heldout_examples) != 16
            or metadata.get('sampling_expanded_wire_sha256') != wire_commitment(request.examples)
            or metadata.get('sampling_guard_wire_sha256') != wire_commitment(request.heldout_examples)):
        raise ValueError("FULL Adam benign audit/pins/actual ordered TRAIN/guard wire differs.")
    projected = dict(metadata)
    fields = {k: projected.pop(k) for k in sorted(BENIGN_FIELDS)}
    projected[BENIGN_KEY] = canonical({'schema': 1, 'fields': fields})
    restored = dict(projected)
    packed = json.loads(restored.pop(BENIGN_KEY))
    if set(packed) != {'schema', 'fields'} or packed['schema'] != 1 or set(packed['fields']) != BENIGN_FIELDS:
        raise ValueError("FULL Adam benign summary schema differs.")
    restored.update(packed['fields'])
    if restored != metadata:
        raise ValueError("FULL Adam benign summary is not lossless.")
    return projected


def project_rehearsal_audit(metadata, request):
    """Pack exact outgoing strings and independently restore them before publication."""
    from prompt_generation.anchor_rehearsal import BANK_KEY, MANIFEST_KEY, DATASET_SHA256, wire_commitment
    if (REHEARSAL_KEY in metadata or {k for k in metadata if k.startswith('sampling_')} != REHEARSAL_FIELDS
            or metadata.get('taxonomy_dataset_sha256') != DATASET_SHA256
            or any(type(metadata.get(k)) is not str or len(metadata[k]) != 64
                   or any(c not in '0123456789abcdef' for c in metadata[k]) for k in (BANK_KEY, MANIFEST_KEY))
            or len(request.examples) != 64 or len(request.heldout_examples) != 16
            or metadata.get('sampling_expanded_wire_sha256') != wire_commitment(request.examples)):
        raise ValueError("FULL Adam rehearsal audit/pins/actual wire commitment differs.")
    projected = dict(metadata)
    fields = {k: projected.pop(k) for k in sorted(REHEARSAL_FIELDS)}
    projected[REHEARSAL_KEY] = canonical({'schema': 1, 'fields': fields})
    restored = dict(projected)
    packed = json.loads(restored.pop(REHEARSAL_KEY))
    if set(packed) != {'schema', 'fields'} or packed['schema'] != 1 or set(packed['fields']) != REHEARSAL_FIELDS:
        raise ValueError("FULL Adam rehearsal summary schema differs.")
    restored.update(packed['fields'])
    if restored != metadata:
        raise ValueError("FULL Adam rehearsal publication summary is not lossless.")
    return projected


def eligibility_metric(update):
    return "candidate_train_exact_match_rate" if validate_candidate_route(update) else "exact_match_rate"


def gate_summary(update, minimum):
    """Authenticated metric choice and exact strict guard contract, with no prompt data."""
    import math
    if not math.isfinite(minimum) or not 0 <= minimum <= 1:
        raise ValueError("Minimum exact match rate must be finite and within [0, 1].")
    metric = eligibility_metric(update)
    from privoke_model import sensitive_retention as retention
    retained = update.metadata.get("contextual_training_optimizer") in retention.POLICIES
    return {"schema": 2 if retained else 1, "policy": retention.ELIGIBILITY if retained else ELIGIBILITY if metric == "candidate_train_exact_match_rate" else "base_train_exact_v1",
        **({"original_train_per_row_predicates": ["sensitive", "severity>=min(gold,original)", "action>=min(gold,original)"],
            "allowed_violations": 0, "manifest_sha256": update.metadata[retention.MANIFEST_KEY]} if retained else {}),
        "selected_metric": metric, "minimum_exact_match_rate": minimum, "training_predicate": ">",
        "heldout_predicates": {"exact": ">=base", "sensitive_recall": ">=base", "clean_specificity": ">=base",
            "safety_regression": "<=0", "sensitive_examples": ">=1_integer", "clean_examples": ">=1_integer"}}


def persist_reservation_rejection(request, header, directory, error):
    """A rejected local reservation is zero RPC work; the original outcome stays unknown."""
    from .evidence import _write_presence_attempt
    wire = request.SerializeToString(deterministic=True)
    identity = hashlib.sha256(wire + canonical(header).encode()).hexdigest()
    return _write_presence_attempt(Path(directory)/"full-adam-runtime"/identity/"reservation-rejections",
        {"schema": 1, "compute_status": "reservation_rejected_no_rpc", "rpc_calls": 0,
         "request_sha256": hashlib.sha256(wire).hexdigest(), "invocation_metadata": header,
         "error_type": type(error).__name__, "prior_attempt_outcome": "unchanged_unknown_no_replay"})


def reserve_physical_attempt(request, header, directory):
    """Fail closed on a repeated physical request, including crash/unknown outcomes."""
    import os
    if not directory:
        raise ValueError("FULL Adam requires durable physical attempt reservation.")
    wire = request.SerializeToString(deterministic=True)
    identity = hashlib.sha256(wire + canonical(header).encode()).hexdigest()
    path = Path(directory)/"full-adam-runtime"/identity/"started.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(canonical({"schema": 1, "request_sha256": hashlib.sha256(wire).hexdigest(),
            "invocation_metadata": header, "status": "reserved_outcome_unknown_until_durable_response"}))
        stream.flush()
        os.fsync(stream.fileno())
    return path


def validate_candidate_route(update, *, resolve_path=None):
    """Metrics alone can never opt a legacy/HEAD update into candidate eligibility."""
    meta = update.metadata
    from privoke_model import sensitive_retention as retention
    retention_mode = meta.get("contextual_training_optimizer") in retention.POLICIES
    opted = meta.get("contextual_training_optimizer") == POLICY or retention_mode
    if not opted:
        if ELIGIBILITY_KEY in meta or EXECUTED_KEY in meta or TRACE_KEY in meta or SUMMARY_KEY in meta or retention.TRACE_KEY in meta or retention.SUMMARY_KEY in meta:
            raise ValueError("Candidate eligibility evidence requires its explicit artifact optimizer.")
        return False
    from privoke.v1 import runtime_pb2
    evidence = update.execution_evidence
    physical = (resolve_path or Path)(evidence["physical_attempt"])
    record = json.loads(physical.read_text(encoding="utf-8"))
    raw_request = base64.b64decode(evidence["request_protobuf_base64"], validate=True)
    raw_response = base64.b64decode(evidence["response_protobuf_base64"], validate=True)
    header = evidence.get("invocation_metadata")
    if (record.get("request_protobuf_base64") != evidence["request_protobuf_base64"]
            or record.get("response_protobuf_base64") != evidence["response_protobuf_base64"]
            or record.get("invocation_metadata") != header
            or record.get("request_protobuf_sha256") != hashlib.sha256(raw_request).hexdigest()):
        raise ValueError("FULL Adam immutable attempt differs from admitted raw evidence/header.")
    request = runtime_pb2.ComputeSemanticGradientsRequest.FromString(raw_request)
    response = runtime_pb2.ComputeSemanticGradientsResponse.FromString(raw_response)
    admission = parse_training_admission_metadata(header or ())
    if (admission is None or admission.get("expected_optimizer") != meta.get("contextual_training_optimizer")
            or admission.get("expected_candidate_eligibility") != (retention.ELIGIBILITY if retention_mode else ELIGIBILITY)
            or admission.get("expected_optimizer_config") != canonical(CONFIG)
            or admission.get("expected_training_scope") != meta.get("training_scope")
            or list(request.layers) != [runtime_pb2.DETECTION_LAYER_SEMANTIC]
            or request.request_id != response.request_id or request.model_id != response.model_id
            or response.model_id != update.model_id or response.base_version != update.base_version or response.error
            or any(meta.get(k) != v for k,v in response.metadata.items())
            or any(update.metrics.get(k) != v for k,v in response.metrics.items())
            or {p.name: tuple(p.values) for p in response.gradients} != dict(update.gradients)
            or {p.name: tuple(p.shape) for p in response.gradients} != dict(update.parameter_shapes)):
        raise ValueError("FULL Adam raw response/request/policy/delta binding differs.")
    scope = meta["training_scope"]
    if evidence.get("rpc") != ("ComputeUnderlyingModelGradients" if scope == "full_encoder" else "ComputeSemanticGradients"):
        raise ValueError("FULL Adam scope differs from executed RPC.")
    phases = [("training", len(request.examples)), ("base_heldout", len(request.heldout_examples)),
              ("candidate_heldout", len(request.heldout_examples))]
    if retention_mode:
        phases.extend(retention.execution_phases(meta))
        if admission.get("expected_retention_manifest_sha256") != meta[retention.MANIFEST_KEY]:
            raise ValueError("Retention raw admission manifest differs.")
        from .sensitive_retention_evidence import retained_release, validate_source_bindings
        validate_source_bindings(meta, retained_release(evidence["retention_release"], update.model_id))
    if len(response.executions) != len(phases) or any(e.phase != phase or e.examples != count or e.status != "ok"
            or e.error or e.layer != runtime_pb2.DETECTION_LAYER_SEMANTIC
            for e,(phase,count) in zip(response.executions, phases)):
        raise ValueError("FULL Adam actual semantic phases differ.")
    validate_trace(meta, scope=scope, examples=len(request.examples), candidate_fingerprint=meta["updated_parameter_fingerprint"],
                   delta_fingerprint=parameter_fingerprint(update.gradients, update.parameter_shapes))
    if scope == "heads":
        return False
    value = update.metrics.get("candidate_train_exact_match_rate")
    if type(value) not in (int, float) or not 0 <= value <= 1 or abs(value * len(request.examples) - round(value * len(request.examples))) > 1e-7:
        raise ValueError("FULL Adam candidate TRAIN exact metric/count differs.")
    return True


def publication_metadata(update, metadata, extra, directory):
    if not validate_candidate_route(update):
        return metadata
    if not directory:
        raise ValueError("FULL Adam publication requires durable complete cycle evidence.")
    identity = hashlib.sha256(canonical(["full_encoder", extra["request_source_id"], extra["request_id"]]).encode()).hexdigest()
    retained = json.loads((Path(directory)/"training-cycles"/identity/(update.metadata["base_parameter_fingerprint"]+".json")).read_text())
    evidence = update.execution_evidence
    from privoke.v1 import runtime_pb2
    request = runtime_pb2.ComputeSemanticGradientsRequest.FromString(base64.b64decode(evidence["request_protobuf_base64"], validate=True))
    summary = json.loads(update.metadata[GATE_KEY])
    if update.metadata[GATE_KEY] != canonical(gate_summary(update, summary["minimum_exact_match_rate"])):
        raise ValueError("FULL Adam retained gate policy/config differs.")
    from fuzzer_service import validate_training_update
    validate_training_update(update, minimum_exact_match_rate=summary["minimum_exact_match_rate"])
    if (retained.get("metadata") != dict(update.metadata) or retained.get("metrics") != dict(update.metrics)
            or retained.get("execution_evidence") != evidence or retained.get("gate_passed") is not True
            or retained.get("request_id") != extra["request_id"] or request.request_id != extra["request_id"]
            or retained.get("source_id") != extra["request_source_id"] or retained.get("model_id") != update.model_id
            or retained.get("base_version") != update.base_version or retained.get("training_stage") != "full_encoder"
            or any(metadata.get(k) != v for k,v in update.metadata.items())):
        raise ValueError("FULL Adam publication differs from retained cycle/gate/identity.")
    projected = dict(metadata)
    from privoke_model import sensitive_retention as retention
    del projected[retention.TRACE_KEY if projected.get("contextual_training_optimizer") in retention.POLICIES else TRACE_KEY]
    # Preserve the exact outgoing string values; no floating point reformatting.
    weights = {key: projected[key] for key in sorted(WEIGHT_FIELDS)}
    if any(weights[key] != str(update.metrics[key]) for key in WEIGHT_FIELDS):
        raise ValueError("FULL Adam weight audit differs from retained metrics.")
    for key in WEIGHT_FIELDS:
        del projected[key]
    projected[WEIGHT_KEY] = canonical({"schema": 1, "fields": weights})
    if projected.get("contextual_sampling_strategy") == "taxonomy_benign_coverage_v1":
        from prompt_generation.benign_coverage import validate_retained_audit
        validate_retained_audit(evidence, projected)
        projected = project_benign_audit(projected, request)
    elif projected.get("contextual_sampling_strategy") == "taxonomy_anchor_rehearsal_v1":
        from prompt_generation.anchor_rehearsal import validate_retained_audit
        validate_retained_audit(evidence, projected)
        projected = project_rehearsal_audit(projected, request)
    elif projected.get("contextual_sampling_strategy") == "taxonomy_coverage_v1":
        if TAXONOMY_KEY in projected:
            raise ValueError("FULL Adam taxonomy summary must not overwrite an existing key.")
        if {key for key in projected if key.startswith("sampling_")} != TAXONOMY_FIELDS:
            raise ValueError("FULL Adam taxonomy audit requires its complete exact field allowlist.")
        dataset = projected.get("taxonomy_dataset_sha256", "")
        if len(dataset) != 64 or any(c not in "0123456789abcdef" for c in dataset):
            raise ValueError("FULL Adam taxonomy audit requires its visible dataset identity.")
        fields = {key: projected.pop(key) for key in sorted(TAXONOMY_FIELDS)}
        projected[TAXONOMY_KEY] = canonical({"schema": 1, "fields": fields})
    projected["training_evidence_sha256"] = hashlib.sha256(canonical({k: retained[k] for k in
        ("metadata", "metrics", "execution_evidence", "gate_passed", "request_id", "source_id", "model_id", "base_version")}).encode()).hexdigest()
    if len(projected) > 64 or any(len(v.encode()) > 2048 for v in projected.values()):
        raise ValueError("FULL Adam publication exceeds unchanged64-entry/2048-byte limits.")
    return projected
