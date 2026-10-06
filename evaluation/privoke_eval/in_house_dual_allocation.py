"""Dual-review allocation preserving the literal frozen single-pass algorithm."""
from __future__ import annotations
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import replace
import hashlib
import random
import os
from pathlib import Path
import sys
import privoke_eval.in_house_advpii_review_io as io
import privoke_eval.in_house_dual_review as dual
from types import MappingProxyType
from privoke_model.training_data import training_text_key
from privoke_eval.advpii_review import (
    AllocationResult, ReviewPool, _PoolMember, _canonical_json, _sha256,
    _membership_digest, _component_caps, _freeze_nested, _QUOTAS, _STRATA,
    _EVALUATION_COMPONENT_FLOOR, SPLIT_SEED, ROW_FILL_SEED, protected_keys_digest,
)
from privoke_eval.clean_augmentation_grouping import Component, GroupingResult, ProtectedKeys, build_components
from privoke_eval.in_house_dual_review import DualReviewRecord, DualReviewResult, consume_dual_reviews
from privoke_eval.in_house_advpii_review import InHouseReviewPool, InHouseReviewBindings


def allocate_dual_reviewed_components(
    pool: InHouseReviewPool, first_envelope_bytes: bytes, second_envelope_bytes: bytes,
    *, source_root: Path, preparation_trust: io.InHousePreparationTrust,
    expected_adapter_raw_sha256: str, expected_consumer_raw_sha256: str,
    trusted_bindings: InHouseReviewBindings, expected_preparation_identity: str,
    expected_first_reviewer_id: str, expected_second_reviewer_id: str,
    expected_first_raw_sha256: str, expected_second_raw_sha256: str,
) -> tuple[AllocationResult, DualReviewResult]:
    """Reconsume committed review bytes before allocating the complete source.

    External reviewer assignments/raw commitments and genuine reconstruction
    are separate trust gates. Both reviewers' evidence remains separate; this
    adapter never manufactures a single-review response or ValidatedReview.
    """
    def edge():
        io._trusted_maps(preparation_trust)
        if io._attest_code(source_root, preparation_trust) != dict(trusted_bindings.execution_code_raw_sha256):
            raise ValueError("Dual allocator execution commitments differ.")
        for module, filename, expected in (
            (sys.modules[__name__], "in_house_dual_allocation.py", expected_adapter_raw_sha256),
            (dual, "in_house_dual_review.py", expected_consumer_raw_sha256),
        ):
            path = source_root / "evaluation/privoke_eval" / filename
            fd, before = io._open_read_nofollow(path)
            try:
                raw = b""
                while len(raw) <= io._CODE_LIMIT:
                    chunk = os.read(fd, min(1024 * 1024, io._CODE_LIMIT + 1 - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                if len(raw) > io._CODE_LIMIT or io._identity(before) != io._identity(os.fstat(fd)):
                    raise ValueError("Dual allocator adapter source changed.")
            finally:
                os.close(fd)
            if not io._valid_sha(expected) or io._sha(raw) != expected:
                raise ValueError("Dual allocator adapter source commitment differs.")
            io._attest_module("dual_adapter", raw, path, module_override=module)
    edge()
    consensus = consume_dual_reviews(
        pool, first_envelope_bytes, second_envelope_bytes,
        trusted_bindings=trusted_bindings,
        expected_preparation_identity=expected_preparation_identity,
        expected_first_reviewer_id=expected_first_reviewer_id,
        expected_second_reviewer_id=expected_second_reviewer_id,
        expected_first_raw_sha256=expected_first_raw_sha256,
        expected_second_raw_sha256=expected_second_raw_sha256,
    )
    edge()
    allocation = _allocate_consensus(pool.core, consensus.records, pool._source_rows,
                                     pool._graph, pool._combined_keys)
    edge()
    return allocation, consensus


def _allocate_consensus(pool: ReviewPool, reviews: Mapping[str, DualReviewRecord],
                        parsed_rows, original_graph: GroupingResult,
                        protected: ProtectedKeys) -> AllocationResult:
    """Private literal frozen continuation; caller must authenticate consensus."""
    if not isinstance(protected, ProtectedKeys) or protected_keys_digest(protected) != pool.bindings.protected_keys_sha256:
        raise ValueError("Allocator protected-key set differs from the frozen key commitment.")
    if _membership_digest(original_graph.components) != pool.graph_membership_sha256:
        raise ValueError("Allocator input graph differs from the frozen full-source graph.")
    by_uid = {item.grouping_row.uid: item for item in parsed_rows}
    if len(by_uid) != len(parsed_rows) or set(by_uid) != {
        uid for component in original_graph.components for uid in component.member_uids
    }:
        raise ValueError("Allocator requires the complete source and unique UIDs.")
    component_for_uid = {uid: component.component_id for component in original_graph.components for uid in component.member_uids}
    if len({member.uid for member in pool._members}) != len(pool._members):
        raise ValueError("Frozen review pool contains duplicate source representatives.")
    for member in pool._members:
        parsed = by_uid.get(member.uid)
        if parsed is None:
            raise ValueError("Frozen review-pool representative is absent from the complete source.")
        text = parsed.grouping_row.text
        if (
            not isinstance(text, str)
            or _sha256(text.encode("utf-8")) != member.exact_text_sha256
            or training_text_key(text) != member.normalized_text_key
            or component_for_uid.get(member.uid) != member.component_id
            or parsed.native_category != member.native_category
            or parsed.grouping_row.eligible is not member.structural_eligible
        ):
            raise ValueError("Frozen review-pool representative does not match its source row.")
    review_by_uid = {item.uid: reviews[item.review_id] for item in pool._members}
    relabeled = []
    for uid, parsed in by_uid.items():
        row = parsed.grouping_row
        reviewed = review_by_uid.get(uid)
        relabeled.append(replace(row, reviewed_has_pii=reviewed.has_pii if reviewed else None))
    graph = build_components(relabeled, protected)
    if _membership_digest(graph.components) != pool.graph_membership_sha256:
        raise ValueError("Reviewed-label graph changed full component membership.")
    members_by_component: dict[str, list[_PoolMember]] = defaultdict(list)
    for member in pool._members:
        members_by_component[member.component_id].append(member)
    component_info = {
        component.component_id: _component_caps(component, members_by_component, reviews)
        for component in graph.components
    }
    component_order = sorted(graph.components, key=lambda component: component.component_id)
    random.Random(SPLIT_SEED).shuffle(component_order)
    chosen: dict[str, list[Component]] = {part: [] for part in ("test", "validation", "train")}
    capacities: dict[str, Counter[str]] = {part: Counter() for part in chosen}
    class_components: dict[str, dict[str, set[str]]] = {
        part: {"positive": set(), "absent": set()} for part in chosen
    }
    assigned: set[str] = set()
    failed_part: str | None = None
    for part in ("test", "validation", "train"):
        floors = part in {"test", "validation"}
        for component in component_order:
            if component.component_id in assigned or component.exclusion_reasons:
                continue
            component_capacity, _ = component_info[component.component_id]
            positive = component_capacity["positive"] > 0
            absent = component_capacity["ordinary"] + component_capacity["hard"] > 0
            row_need = any(capacities[part][stratum] < _QUOTAS[part][stratum] and component_capacity[stratum] > 0 for stratum in _STRATA)
            floor_need = floors and (
                (positive and len(class_components[part]["positive"]) < _EVALUATION_COMPONENT_FLOOR)
                or (absent and len(class_components[part]["absent"]) < _EVALUATION_COMPONENT_FLOOR)
            )
            if not row_need and not floor_need:
                continue
            assigned.add(component.component_id)
            chosen[part].append(component)
            for stratum in _STRATA:
                capacities[part][stratum] += component_capacity[stratum]
            if positive:
                class_components[part]["positive"].add(component.component_id)
            if absent:
                class_components[part]["absent"].add(component.component_id)
            complete = all(capacities[part][s] >= _QUOTAS[part][s] for s in _STRATA)
            if floors:
                complete = complete and all(len(class_components[part][c]) >= _EVALUATION_COMPONENT_FLOOR for c in ("positive", "absent"))
            if complete:
                break
        if not all(capacities[part][s] >= _QUOTAS[part][s] for s in _STRATA):
            failed_part = part
            break
        if floors and any(len(class_components[part][c]) < _EVALUATION_COMPONENT_FLOOR for c in ("positive", "absent")):
            failed_part = part
            break
    if failed_part is None and len(chosen["train"]) == 0:
        failed_part = "train"
    if failed_part is not None:
        shortages = {
            part: {s: max(0, _QUOTAS[part][s] - capacities[part][s]) for s in _STRATA}
            for part in ("test", "validation", "train")
        }
        floor_shortages = {
            part: {
                class_name: max(0, _EVALUATION_COMPONENT_FLOOR - len(class_components[part][class_name]))
                if part in {"test", "validation"} else 0
                for class_name in ("positive", "absent")
            }
            for part in ("test", "validation", "train")
        }
        failed_dimensions = [
            f"rows_{stratum}" for stratum, shortage in shortages[failed_part].items() if shortage
        ] + [
            f"floor_{class_name}" for class_name, shortage in floor_shortages[failed_part].items() if shortage
        ]
        return AllocationResult(
            "failed", f"single_pass_shortage_{failed_part}:{','.join(failed_dimensions)}", {},
            MappingProxyType({part: tuple(c.component_id for c in chosen[part]) for part in chosen}),
            _freeze_nested({part: {s: capacities[part][s] for s in _STRATA} for part in capacities}),
            _freeze_nested({part: {"positive": 0, "absent": 0} for part in chosen}),
            _freeze_nested({part: {k: len(v) for k, v in class_components[part].items()} for part in class_components}),
            _freeze_nested(shortages), _freeze_nested(floor_shortages),
            ("component_order:random.Random(11102026)",), graph,
        )

    selections: dict[str, tuple[int, ...]] = {}
    member_by_uid = {member.uid: member for member in pool._members}
    for part in ("test", "validation", "train"):
        candidates: dict[str, list[int]] = {s: [] for s in _STRATA}
        for component in chosen[part]:
            _, rows = component_info[component.component_id]
            for stratum in _STRATA:
                candidates[stratum].extend(rows[stratum])
        anchors: dict[str, set[int]] = {s: set() for s in _STRATA}
        if part in {"test", "validation"}:
            for component in chosen[part]:
                _, rows = component_info[component.component_id]
                if rows["positive"] and len(anchors["positive"]) < _EVALUATION_COMPONENT_FLOOR:
                    anchors["positive"].add(min(rows["positive"]))
                if len(anchors["ordinary"]) + len(anchors["hard"]) < _EVALUATION_COMPONENT_FLOOR:
                    if rows["ordinary"]:
                        anchors["ordinary"].add(min(rows["ordinary"]))
                    elif rows["hard"]:
                        anchors["hard"].add(min(rows["hard"]))
        selected_by_stratum: dict[str, list[int]] = {}
        for stratum in _STRATA:
            quota = _QUOTAS[part][stratum]
            anchor_rows = sorted(anchors[stratum])
            if len(anchor_rows) > quota:
                raise ValueError("Evaluation class anchors exceed a frozen row quota.")
            remaining = sorted(set(candidates[stratum]) - set(anchor_rows))
            stream_seed = int.from_bytes(
                hashlib.sha256(_canonical_json(["privoke-clean-row-fill-v1", ROW_FILL_SEED, part, stratum])).digest(),
                "big",
            )
            random.Random(stream_seed).shuffle(remaining)
            needed = quota - len(anchor_rows)
            if len(remaining) < needed:
                raise ValueError("Frozen row-fill capacity became inconsistent after allocation.")
            selected_by_stratum[stratum] = sorted(anchor_rows + remaining[:needed])
        combined = tuple(uid for stratum in _STRATA for uid in selected_by_stratum[stratum])
        if len(combined) != sum(_QUOTAS[part].values()) or len(set(combined)) != len(combined):
            raise ValueError("Final deterministic row selection violates frozen quotas or uniqueness.")
        if part in {"test", "validation"}:
            positive_components = {
                member_by_uid[uid].component_id for uid in selected_by_stratum["positive"]
            }
            absent_components = {
                member_by_uid[uid].component_id
                for stratum in ("ordinary", "hard")
                for uid in selected_by_stratum[stratum]
            }
            if (
                len(positive_components) < _EVALUATION_COMPONENT_FLOOR
                or len(absent_components) < _EVALUATION_COMPONENT_FLOOR
            ):
                raise ValueError("Final row selection lost a required evaluation component floor.")
        selections[part] = combined
    selected_component_sets = {
        part: {member_by_uid[uid].component_id for uid in selected}
        for part, selected in selections.items()
    }
    if (
        selected_component_sets["test"] & selected_component_sets["validation"]
        or selected_component_sets["test"] & selected_component_sets["train"]
        or selected_component_sets["validation"] & selected_component_sets["train"]
    ):
        raise ValueError("Final partitions share a full-source component.")
    selected_class_components = {
        part: {
            "positive": len({member_by_uid[uid].component_id for uid in selections[part]
                             if member_by_uid[uid].native_category == "positive"}),
            "absent": len({member_by_uid[uid].component_id for uid in selections[part]
                           if member_by_uid[uid].native_category in {"negative", "hard_negative"}}),
        }
        for part in selections
    }
    return AllocationResult(
        "complete", None, MappingProxyType(selections),
        MappingProxyType({part: tuple(c.component_id for c in chosen[part]) for part in chosen}),
        _freeze_nested({part: {s: capacities[part][s] for s in _STRATA} for part in capacities}),
        _freeze_nested(selected_class_components),
        _freeze_nested({part: {k: len(v) for k, v in class_components[part].items()} for part in class_components}),
        _freeze_nested({part: {s: 0 for s in _STRATA} for part in chosen}),
        _freeze_nested({part: {class_name: 0 for class_name in ("positive", "absent")} for part in chosen}),
        ("component_order:random.Random(11102026)", "row_fill:domain-separated-sha256/13102026"), graph,
    )
