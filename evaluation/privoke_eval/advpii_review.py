"""Pure blind-review pool, response validation, and fixed allocator helpers.

All returned prompt packages and UID/component mappings are restricted in-memory
objects for a later I/O boundary. This module does not open files, sample source
data, emit packages, call a detector, or assign labels from native categories.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
import hashlib
import json
import random
import re
from types import MappingProxyType

from privoke_eval.advpii_native import ParsedNativeRow
from privoke_eval.clean_augmentation_grouping import (
    Component,
    GroupingResult,
    GroupingRow,
    NativeIdentifier,
    ProtectedKeys,
    build_components,
)
from privoke_model.training_data import training_text_key


SOURCE_SHA256 = "e97f6a32132e7fa058919798c030fca54aaad3318c47954d281717a435bfeb69"
PROTOCOL_SHA256 = "3991777aedadc8d50b7395a9ce8ef2aebfec946603229b823f1b6c118a16cbdf"
RUBRIC_SHA256 = "203f37b4c77789a0f9c0838905954b9e1b76acf4f7906ab7717849e94616fcd7"
REFERENCE_TRAIN_SHA256 = "da9a1b095587264714c5ae99c8a0f92329a04f6fc237a8ace7d71e837ede429d"
POOL_SEED = 13102026
SPLIT_SEED = 11102026
ROW_FILL_SEED = 13102026
MAX_REVIEW_POOL = 12096
MAX_ORDINARY_POOL = 6200
MAX_HARD_NEGATIVE_POOL = 1232
MAX_POSITIVE_POOL = 4664
MAX_POSITIVE_PER_COMPONENT = 4
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_CATEGORIES = frozenset({
    "HEALTH", "POLITICS", "RELIGION", "CRIMINAL", "FINANCIAL", "SEXUAL", "CHILD",
    "LOCATION", "IDENTITY", "THIRD_PARTY",
})
_STRATA = ("positive", "ordinary", "hard")
_QUOTAS = {
    "test": {"positive": 1000, "ordinary": 750, "hard": 250},
    "validation": {"positive": 1000, "ordinary": 750, "hard": 250},
    "train": {"positive": 2000, "ordinary": 1600, "hard": 400},
}
_EVALUATION_COMPONENT_FLOOR = 200
_RESPONSE_FIELDS = {
    "review_id", "source_sha256", "pool_sha256", "rubric_sha256", "text_sha256", "reviewer_id",
    "reviewed_at", "full_prompt_reviewed", "blinding_attestation", "decision", "categories", "evidence",
    "uncertainty_reason",
}
_BLIND_FIELDS = {"no_detector_outputs", "no_model_scores_or_vocabularies", "no_partition_roles"}


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _membership_digest(components: Sequence[Component]) -> str:
    ordered = sorted((component.component_id, tuple(sorted(component.member_uids))) for component in components)
    return _sha256(_canonical_json([[component_id, list(members)] for component_id, members in ordered]))


def _pool_member_digest(members: Sequence["_PoolMember"]) -> str:
    rows = sorted((
        item.review_id, item.uid, item.component_id, item.native_category,
        item.exact_text_sha256, item.normalized_text_key, item.structural_eligible,
        [[span.entity_type, span.start, span.end] for span in item.native_spans],
    ) for item in members)
    return _sha256(_canonical_json(rows))


def protected_keys_digest(protected: ProtectedKeys) -> str:
    """Commit to the exact protected key sets used for full-graph closure.

    This digest is a consistency binding only. The future I/O boundary must
    derive both these keys and the protected artifact SHA from the same
    checksum-verified artifact and trusted receipt.
    """
    if not isinstance(protected, ProtectedKeys):
        raise TypeError("Protected-key digest requires a validated ProtectedKeys value.")
    return _sha256(_canonical_json({
        "ids": sorted(protected.ids),
        "groups": sorted(protected.groups),
        "exact_text_sha256": sorted(protected.exact_text_sha256),
        "normalized_texts": sorted(protected.normalized_texts),
    }))


def _domain_rng(domain: str, seed: int) -> random.Random:
    seed_bytes = _sha256(_canonical_json(["privoke-advpii-review-pool-v1", seed, domain])).encode("ascii")
    return random.Random(int(seed_bytes, 16))


@dataclass(frozen=True)
class ReviewBindings:
    source_revision: str
    source_sha256: str
    protocol_sha256: str
    rubric_sha256: str
    parser_sha256: str
    grouping_sha256: str
    normalizer_sha256: str
    protected_union_sha256: str
    protected_keys_sha256: str
    reference_train_sha256: str = REFERENCE_TRAIN_SHA256

    def validate(self) -> None:
        if not isinstance(self.source_revision, str) or _SHA1.fullmatch(self.source_revision) is None:
            raise ValueError("Review binding source revision is invalid.")
        if self.source_sha256 != SOURCE_SHA256:
            raise ValueError("Review binding source digest differs from the pinned source.")
        if self.protocol_sha256 != PROTOCOL_SHA256 or self.rubric_sha256 != RUBRIC_SHA256:
            raise ValueError("Review binding protocol or rubric digest differs from the frozen contract.")
        for name in ("parser_sha256", "grouping_sha256", "normalizer_sha256", "protected_union_sha256", "protected_keys_sha256"):
            if not _is_sha256(getattr(self, name)):
                raise ValueError(f"Review binding {name} is malformed.")
        if self.reference_train_sha256 != REFERENCE_TRAIN_SHA256:
            raise ValueError("Review binding original training commitment differs from the frozen source.")


@dataclass(frozen=True)
class NativeSpanForReview:
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True)
class ValidatedNativeSpanInput:
    """Checksum-bound adapter record; values are validated then discarded."""

    entity_type: str
    start: int
    end: int
    literal: str
    base_value: str | None


@dataclass(frozen=True)
class ReviewPackageItem:
    review_id: str
    text: str = field(repr=False)
    text_sha256: str
    rubric_sha256: str
    native_spans: tuple[NativeSpanForReview, ...]


@dataclass(frozen=True)
class _PoolMember:
    review_id: str
    uid: int
    component_id: str
    native_category: str
    exact_text_sha256: str
    normalized_text_key: str
    text_sha256: str
    structural_eligible: bool
    native_spans: tuple[NativeSpanForReview, ...]


@dataclass(frozen=True)
class ReviewPool:
    packages: tuple[ReviewPackageItem, ...] = field(repr=False)
    _members: tuple[_PoolMember, ...] = field(repr=False)
    pool_sha256: str
    graph_membership_sha256: str
    private_members_sha256: str
    bindings: ReviewBindings
    selection_streams: tuple[str, ...]
    pool_size: int


@dataclass(frozen=True)
class ValidatedReview:
    review_id: str
    decision: str
    has_pii: bool | None
    categories: tuple[str, ...]
    reviewer_id: str = field(repr=False)
    reviewed_at: str
    uncertainty_reason: str | None = field(repr=False)
    response_sha256: str
    evidence: tuple[tuple[str, int, int], ...] = field(repr=False)


@dataclass(frozen=True)
class AllocationResult:
    status: str
    reason: str | None
    partitions: Mapping[str, tuple[int, ...]] = field(repr=False)
    assigned_component_ids: Mapping[str, tuple[str, ...]] = field(repr=False)
    capacities: Mapping[str, Mapping[str, int]]
    represented_components: Mapping[str, Mapping[str, int]]
    shortages: Mapping[str, Mapping[str, int]]
    streams: tuple[str, ...]
    graph: GroupingResult = field(repr=False)


def build_review_pool(
    parsed_rows: Sequence[ParsedNativeRow],
    full_graph: GroupingResult,
    bindings: ReviewBindings,
    protected: ProtectedKeys,
    validated_native_spans_by_uid: Mapping[int, Sequence[ValidatedNativeSpanInput]],
) -> ReviewPool:
    """Freeze a deterministic, masked pool from the already-closed full graph."""
    bindings.validate()
    if not isinstance(protected, ProtectedKeys) or protected_keys_digest(protected) != bindings.protected_keys_sha256:
        raise ValueError("Review pool protected-key set differs from the frozen key commitment.")
    if not isinstance(full_graph, GroupingResult) or full_graph.row_count != len(parsed_rows):
        raise ValueError("Review pool requires the complete graph for every parsed source row.")
    by_uid: dict[int, ParsedNativeRow] = {}
    for parsed in parsed_rows:
        uid = parsed.grouping_row.uid
        if uid in by_uid:
            raise ValueError("Review pool source UIDs must be unique.")
        by_uid[uid] = parsed
    graph_uids = {uid for component in full_graph.components for uid in component.member_uids}
    if graph_uids != set(by_uid) or sum(len(component.member_uids) for component in full_graph.components) != len(by_uid):
        raise ValueError("Review pool graph membership is incomplete or duplicated.")
    expected_graph = build_components([item.grouping_row for item in parsed_rows], protected)
    if expected_graph != full_graph:
        raise ValueError("Review pool full graph does not match the bound protected keys and source rows.")
    component_ids = [component.component_id for component in full_graph.components]
    if len(component_ids) != len(set(component_ids)):
        raise ValueError("Review pool graph has duplicate component identities.")
    component_by_uid: dict[int, Component] = {}
    for component in full_graph.components:
        for uid in component.member_uids:
            component_by_uid[uid] = component
    if not isinstance(validated_native_spans_by_uid, Mapping) or set(validated_native_spans_by_uid) != set(by_uid):
        raise ValueError("Validated native-span input must cover every source UID exactly.")
    spans_by_uid = {
        uid: _validate_native_spans(parsed, validated_native_spans_by_uid[uid])
        for uid, parsed in by_uid.items()
    }

    # Deduplicate before any decisions: one lowest signed UID represents each
    # eligible normalized prompt, while the original graph retains all aliases.
    rows_by_text_key: dict[str, list[ParsedNativeRow]] = defaultdict(list)
    for parsed in parsed_rows:
        row = parsed.grouping_row
        component = component_by_uid[row.uid]
        if (
            not row.eligible
            or parsed.native_category not in {"positive", "negative", "hard_negative"}
            or component.exclusion_reasons
            or not isinstance(row.text, str)
        ):
            continue
        key = training_text_key(row.text)
        if key:
            rows_by_text_key[key].append(parsed)
    representatives = [min(members, key=lambda parsed: parsed.grouping_row.uid) for members in rows_by_text_key.values()]
    hard_rows = sorted(
        (parsed for parsed in representatives if parsed.native_category == "hard_negative"),
        key=lambda parsed: parsed.grouping_row.uid,
    )
    ordinary_rows = sorted(
        (parsed for parsed in representatives if parsed.native_category == "negative"),
        key=lambda parsed: parsed.grouping_row.uid,
    )
    _domain_rng("pool/ordinary", POOL_SEED).shuffle(ordinary_rows)
    ordinary_rows = ordinary_rows[:MAX_ORDINARY_POOL]

    positive_by_component: dict[str, list[ParsedNativeRow]] = defaultdict(list)
    for parsed in representatives:
        if parsed.native_category == "positive":
            positive_by_component[component_by_uid[parsed.grouping_row.uid].component_id].append(parsed)
    positive_rows: list[ParsedNativeRow] = []
    for component_id in sorted(positive_by_component):
        candidates = sorted(positive_by_component[component_id], key=lambda parsed: parsed.grouping_row.uid)
        _domain_rng(f"pool/positive/{component_id}", POOL_SEED).shuffle(candidates)
        positive_rows.extend(candidates[:MAX_POSITIVE_PER_COMPONENT])

    if len(hard_rows) > MAX_HARD_NEGATIVE_POOL or len(positive_rows) > MAX_POSITIVE_POOL:
        raise ValueError("Pinned source pool exceeds its frozen native-stratum ceiling.")
    selected = hard_rows + ordinary_rows + positive_rows
    if len(selected) > MAX_REVIEW_POOL:
        raise ValueError("Frozen review pool exceeds its maximum size.")
    package_pairs = []
    for parsed in selected:
        row = parsed.grouping_row
        component = component_by_uid[row.uid]
        text = row.text
        if not isinstance(text, str):
            raise ValueError("A selected review prompt is missing its complete text.")
        text_sha = _sha256(text.encode("utf-8"))
        review_id = _sha256(_canonical_json(["privoke-advpii-review-id-v1", bindings.source_sha256, row.uid]))
        spans = spans_by_uid[row.uid]
        package = ReviewPackageItem(review_id, text, text_sha, bindings.rubric_sha256, spans)
        member = _PoolMember(
            review_id=review_id,
            uid=row.uid,
            component_id=component.component_id,
            native_category=parsed.native_category or "",
            exact_text_sha256=text_sha,
            normalized_text_key=training_text_key(text),
            text_sha256=text_sha,
            structural_eligible=row.eligible,
            native_spans=spans,
        )
        package_pairs.append((package, member))
    package_pairs.sort(key=lambda pair: pair[0].review_id)
    _domain_rng("pool/package-order", POOL_SEED).shuffle(package_pairs)
    packages = tuple(pair[0] for pair in package_pairs)
    members = tuple(pair[1] for pair in package_pairs)
    if len({item.review_id for item in packages}) != len(packages):
        raise ValueError("Review-pool opaque identifiers collided.")
    if len({item.text_sha256 for item in packages}) != len(packages):
        raise ValueError("Review pool contains a duplicate exact prompt after normalization deduplication.")
    pool_sha = _sha256(_canonical_json([
        {
            "review_id": item.review_id,
            "text": item.text,
            "text_sha256": item.text_sha256,
            "rubric_sha256": item.rubric_sha256,
            "native_spans": [[span.entity_type, span.start, span.end] for span in item.native_spans],
        }
        for item in packages
    ]))
    return ReviewPool(
        packages=packages,
        _members=members,
        pool_sha256=pool_sha,
        graph_membership_sha256=_membership_digest(full_graph.components),
        private_members_sha256=_pool_member_digest(members),
        bindings=bindings,
        selection_streams=("pool/ordinary", "pool/positive/<component-id>", "pool/package-order"),
        pool_size=len(packages),
    )


def _validate_native_spans(
    parsed: ParsedNativeRow, raw_spans: Sequence[ValidatedNativeSpanInput]
) -> tuple[NativeSpanForReview, ...]:
    """Check the checksum-bound I/O adapter's spans without exposing values."""
    row = parsed.grouping_row
    if not isinstance(row.text, str) or not isinstance(raw_spans, (tuple, list)):
        raise ValueError("Validated native spans are malformed.")
    if not isinstance(row.identifiers, (tuple, list)) or any(
        not isinstance(item, NativeIdentifier) for item in row.identifiers
    ):
        raise ValueError("Validated native spans are malformed.")
    identifiers = Counter((item.entity_type, item.native_value) for item in row.identifiers)
    allowed_types = {"credit_card_number", "phone_number", "iban", "email", "ssn"}
    spans: list[NativeSpanForReview] = []
    for span in raw_spans:
        if not isinstance(span, ValidatedNativeSpanInput):
            raise ValueError("Validated native spans are malformed.")
        if (
            span.entity_type not in allowed_types
            or type(span.start) is not int
            or type(span.end) is not int
            or not (0 <= span.start < span.end <= len(row.text))
            or not isinstance(span.literal, str)
            or not span.literal
            or row.text[span.start:span.end] != span.literal
            or (span.base_value is not None and not isinstance(span.base_value, str))
        ):
            raise ValueError("Validated native spans are malformed.")
        if span.base_value is not None and span.base_value.strip():
            if identifiers[(span.entity_type, span.base_value)] <= 0:
                raise ValueError("Validated native-span identifiers differ from the parsed row.")
            identifiers[(span.entity_type, span.base_value)] -= 1
        spans.append(NativeSpanForReview(span.entity_type, span.start, span.end))
    if len(spans) != parsed.valid_span_count:
        raise ValueError("Validated native-span coverage differs from the parsed row.")
    if tuple(sorted(span.entity_type for span in spans)) != parsed.native_span_types:
        raise ValueError("Validated native-span types differ from the parsed row.")
    if any(identifiers.values()):
        raise ValueError("Validated native-span identifiers differ from the parsed row.")
    if parsed.native_category == "positive" and not spans:
        raise ValueError("A native-positive review package requires validated spans.")
    return tuple(sorted(spans, key=lambda span: (span.start, span.end, span.entity_type)))


def validate_review_responses(pool: ReviewPool, responses: Sequence[Mapping[str, object]]) -> Mapping[str, ValidatedReview]:
    """Validate a complete blinded response set; unknown never becomes absent."""
    if not isinstance(pool, ReviewPool) or not isinstance(responses, (tuple, list)):
        raise ValueError("Review response bundle is malformed.")
    pool.bindings.validate()
    package_by_id = {item.review_id: item for item in pool.packages}
    member_by_id = {item.review_id: item for item in pool._members}
    if (
        len(package_by_id) != len(pool.packages)
        or len(member_by_id) != len(pool._members)
        or set(package_by_id) != set(member_by_id)
        or pool.pool_size != len(package_by_id)
    ):
        raise ValueError("Frozen review pool has inconsistent package membership.")
    if _pool_member_digest(pool._members) != pool.private_members_sha256:
        raise ValueError("Frozen review pool private membership commitment is invalid.")
    package_commitment = _sha256(_canonical_json([
        {
            "review_id": item.review_id,
            "text": item.text,
            "text_sha256": item.text_sha256,
            "rubric_sha256": item.rubric_sha256,
            "native_spans": [[span.entity_type, span.start, span.end] for span in item.native_spans],
        }
        for item in pool.packages
    ]))
    if package_commitment != pool.pool_sha256:
        raise ValueError("Frozen review pool package commitment is invalid.")
    for review_id, package in package_by_id.items():
        member = member_by_id[review_id]
        if (
            not isinstance(package.text, str)
            or _sha256(package.text.encode("utf-8")) != package.text_sha256
            or package.rubric_sha256 != pool.bindings.rubric_sha256
            or member.text_sha256 != package.text_sha256
            or member.exact_text_sha256 != package.text_sha256
            or member.review_id != _sha256(_canonical_json([
                "privoke-advpii-review-id-v1", pool.bindings.source_sha256, member.uid
            ]))
        ):
            raise ValueError("Frozen review pool contains inconsistent text or rubric bindings.")
    result: dict[str, ValidatedReview] = {}
    for response in responses:
        if not isinstance(response, Mapping) or set(response) != _RESPONSE_FIELDS:
            raise ValueError("Review response schema is invalid.")
        review_id = response.get("review_id")
        if not isinstance(review_id, str) or review_id not in package_by_id or review_id in result:
            raise ValueError("Review response coverage is invalid.")
        package = package_by_id[review_id]
        if (
            response.get("source_sha256") != pool.bindings.source_sha256
            or response.get("pool_sha256") != pool.pool_sha256
            or response.get("rubric_sha256") != pool.bindings.rubric_sha256
            or response.get("text_sha256") != package.text_sha256
        ):
            raise ValueError("Review response binding does not match the frozen package.")
        if response.get("full_prompt_reviewed") is not True:
            raise ValueError("Review response must attest to complete-prompt review.")
        attestation = response.get("blinding_attestation")
        if not isinstance(attestation, Mapping) or set(attestation) != _BLIND_FIELDS or any(
            attestation.get(field) is not True for field in _BLIND_FIELDS
        ):
            raise ValueError("Review response blinding attestation is incomplete.")
        reviewer = response.get("reviewer_id")
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 256:
            raise ValueError("Review response reviewer identity is invalid.")
        reviewed_at = response.get("reviewed_at")
        if not isinstance(reviewed_at, str) or len(reviewed_at) > 128:
            raise ValueError("Review response timestamp is invalid.")
        try:
            parsed_time = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Review response timestamp is invalid.") from exc
        if parsed_time.tzinfo is None:
            raise ValueError("Review response timestamp must include a timezone.")
        decision = response.get("decision")
        categories = response.get("categories")
        evidence = response.get("evidence")
        reason = response.get("uncertainty_reason")
        if not isinstance(categories, (tuple, list)) or not isinstance(evidence, (tuple, list)):
            raise ValueError("Review response categories or evidence are malformed.")
        if any(not isinstance(category, str) or category not in _CATEGORIES for category in categories):
            raise ValueError("Review response contains an unsupported category.")
        if len(set(categories)) != len(categories):
            raise ValueError("Review response categories contain duplicates.")
        normalized_evidence: list[tuple[str, int, int]] = []
        for item in evidence:
            if not isinstance(item, Mapping) or set(item) != {"category", "start", "end"}:
                raise ValueError("Review response evidence is malformed.")
            category, start, end = item.get("category"), item.get("start"), item.get("end")
            if (
                not isinstance(category, str)
                or category not in _CATEGORIES
                or type(start) is not int
                or type(end) is not int
                or not (0 <= start < end <= len(package.text))
                or not package.text[start:end].strip()
            ):
                raise ValueError("Review response evidence is invalid.")
            normalized_evidence.append((category, start, end))
        if decision == "present":
            if not categories or not evidence or set(categories) != {item[0] for item in normalized_evidence} or reason not in (None, ""):
                raise ValueError("Present review requires category-supported evidence.")
            has_pii: bool | None = True
            reason = None
        elif decision == "absent":
            if categories or evidence or reason not in (None, ""):
                raise ValueError("Absent review cannot include evidence, categories, or uncertainty.")
            has_pii = False
        elif decision == "uncertain":
            if not isinstance(reason, str) or not reason.strip() or categories or evidence:
                raise ValueError("Uncertain review requires a reason and no binary evidence.")
            has_pii = None
        else:
            raise ValueError("Review response decision is invalid.")
        member = member_by_id[review_id]
        if member.native_category == "positive" and has_pii is False:
            raise ValueError("A native-positive row cannot be reviewed absent.")
        response_commitment = {
            "review_id": review_id,
            "source_sha256": pool.bindings.source_sha256,
            "pool_sha256": pool.pool_sha256,
            "rubric_sha256": pool.bindings.rubric_sha256,
            "text_sha256": package.text_sha256,
            "reviewer_id": reviewer,
            "reviewed_at": reviewed_at,
            "full_prompt_reviewed": True,
            "blinding_attestation": {name: True for name in sorted(_BLIND_FIELDS)},
            "decision": decision,
            "categories": list(categories),
            "evidence": [{"category": c, "start": start, "end": end} for c, start, end in normalized_evidence],
            "uncertainty_reason": reason,
        }
        result[review_id] = ValidatedReview(
            review_id=review_id,
            decision=decision,
            has_pii=has_pii,
            categories=tuple(sorted(categories)),
            reviewer_id=reviewer,
            reviewed_at=reviewed_at,
            uncertainty_reason=reason if decision == "uncertain" else None,
            response_sha256=_sha256(_canonical_json(response_commitment)),
            evidence=tuple(sorted(normalized_evidence)),
        )
    if set(result) != set(package_by_id):
        raise ValueError("Review response set does not cover the frozen pool exactly.")
    return MappingProxyType(result)


def _component_caps(component: Component, members_by_component: Mapping[str, Sequence[_PoolMember]], reviews: Mapping[str, ValidatedReview]):
    capacities = Counter()
    row_uids: dict[str, list[int]] = {stratum: [] for stratum in _STRATA}
    for member in members_by_component.get(component.component_id, ()):
        review = reviews[member.review_id]
        if not member.structural_eligible or component.exclusion_reasons or review.has_pii is None:
            continue
        if member.native_category == "positive" and review.has_pii is True:
            stratum = "positive"
        elif member.native_category == "negative" and review.has_pii is False:
            stratum = "ordinary"
        elif member.native_category == "hard_negative" and review.has_pii is False:
            stratum = "hard"
        else:
            continue
        capacities[stratum] += 1
        row_uids[stratum].append(member.uid)
    return capacities, row_uids


def _freeze_nested(values: Mapping[str, Mapping[str, int]]) -> Mapping[str, Mapping[str, int]]:
    return MappingProxyType({name: MappingProxyType(dict(counts)) for name, counts in values.items()})


def allocate_reviewed_components(
    pool: ReviewPool,
    responses: Sequence[Mapping[str, object]],
    parsed_rows: Sequence[ParsedNativeRow],
    original_graph: GroupingResult,
    protected: ProtectedKeys,
) -> AllocationResult:
    """Attach only explicit representative labels, reclose all bridges, and make one greedy pass."""
    reviews = validate_review_responses(pool, responses)
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
        return AllocationResult(
            "failed", f"single_pass_shortage_{failed_part}", {},
            MappingProxyType({part: tuple(c.component_id for c in chosen[part]) for part in chosen}),
            _freeze_nested({part: {s: capacities[part][s] for s in _STRATA} for part in capacities}),
            _freeze_nested({part: {k: len(v) for k, v in class_components[part].items()} for part in class_components}),
            _freeze_nested(shortages), ("component_order:random.Random(11102026)",), graph,
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
    return AllocationResult(
        "complete", None, MappingProxyType(selections),
        MappingProxyType({part: tuple(c.component_id for c in chosen[part]) for part in chosen}),
        _freeze_nested({part: {s: capacities[part][s] for s in _STRATA} for part in capacities}),
        _freeze_nested({part: {k: len(v) for k, v in class_components[part].items()} for part in class_components}),
        _freeze_nested({part: {s: 0 for s in _STRATA} for part in chosen}),
        ("component_order:random.Random(11102026)", "row_fill:domain-separated-sha256/13102026"), graph,
    )
