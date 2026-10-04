"""Pure versioned addon bindings for blind preparation; no I/O or allocation.

External trust must be supplied by the separately reviewed consumer. These
consistency checks do not authenticate raw receipts, source bytes or labels.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
import hashlib
import json
import re
from types import MappingProxyType

from privoke_eval.advpii_review import (
    ReviewBindings, ReviewPool, build_review_pool, protected_keys_digest,
    validate_review_responses,
)
from privoke_eval.advpii_native import ParsedNativeRow
from privoke_eval.clean_augmentation_grouping import GroupingResult, ProtectedKeys
from privoke_eval.contextual_fixture_protection import combined_protection_digest
from privoke_model.training_data import training_text_key

PLAN_SHA256 = "2dcaa5f98e3f8075bc11c7a2025b7e6e853a860819b9123f8fd319851b3dacbd"
PREPARATION_DESIGN_SHA256 = "b482e355f0689b319fd6f3ba2a69e02e0589f149a7483977526a2f45b3f0f3b0"
ALLOCATOR_DESIGN_SHA256 = "a413c922d2f710f1e47e5013d42373bc42e1e695db34ed8844e1509c9402cc63"
EXECUTION_CODE_ROLES = frozenset({
    "parser", "structure", "grouping", "review_helper", "protection_core",
    "protection_io", "fixture_validator", "normalizer", "in_house_review",
    "in_house_review_io", "cli",
})
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REV = re.compile(r"[0-9a-f]{40}\Z")
_STREAMS = ("pool/ordinary", "pool/positive/<component-id>", "pool/package-order")
_NATIVE_TYPES = {"credit_card_number", "iban", "phone_number", "email", "ssn"}


def _fail():
    raise ValueError("In-house blind preparation binding failed validation.")


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail()
    return value


def _digest_map(value, roles):
    if not isinstance(value, Mapping) or set(value) != set(roles):
        _fail()
    return MappingProxyType({name: _sha(value[name]) for name in sorted(roles)})


def _plain(value):
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, (InHouseProtectionBindings, InHouseReviewBindings, ReviewBindings)):
        return {item.name: _plain(getattr(value, item.name)) for item in fields(value)}
    return value


def _hash(value):
    try:
        raw = json.dumps(_plain(value), sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _fail()
    return hashlib.sha256(raw).hexdigest()


def _require_immutable(value):
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) in (tuple, frozenset):
        for item in value:
            _require_immutable(item)
        return
    if type(value) is MappingProxyType:
        for key, item in value.items():
            _require_immutable(key)
            _require_immutable(item)
        return
    if is_dataclass(value) and not isinstance(value, type) and value.__dataclass_params__.frozen:
        for item in fields(value):
            _require_immutable(getattr(value, item.name))
        return
    _fail()


@dataclass(frozen=True)
class InHouseProtectionBindings:
    historical_artifact_raw_sha256: str
    historical_receipt_raw_sha256: str
    historical_union_content_sha256: str
    addon_artifact_raw_sha256: str
    addon_receipt_raw_sha256: str
    addon_content_sha256: str
    combined_protection_sha256: str
    internal_protected_keys_sha256: str
    fixture_input_raw_sha256: Mapping[str, str]
    fixture_input_consumed_sha256: Mapping[str, str]
    addon_producer_revision: str
    addon_helper_raw_sha256: Mapping[str, str]
    schema_version: int = 1
    kind: str = "privoke-in-house-protection-bindings-v1"
    professor_confirmation: str = "pending"
    review_status: str = "reviewed"

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != 1
                or self.kind != "privoke-in-house-protection-bindings-v1"
                or self.professor_confirmation != "pending" or self.review_status != "reviewed"
                or type(self.addon_producer_revision) is not str
                or not _REV.fullmatch(self.addon_producer_revision)):
            _fail()
        for name in ("historical_artifact_raw_sha256", "historical_receipt_raw_sha256",
                     "historical_union_content_sha256", "addon_artifact_raw_sha256",
                     "addon_receipt_raw_sha256", "addon_content_sha256",
                     "combined_protection_sha256", "internal_protected_keys_sha256"):
            _sha(getattr(self, name))
        for name, roles in (("fixture_input_raw_sha256", {"fixture", "rubric", "review"}),
                            ("fixture_input_consumed_sha256", {"fixture", "rubric", "review"}),
                            ("addon_helper_raw_sha256", {"grouping", "normalizer", "fixture_validator"})):
            object.__setattr__(self, name, _digest_map(getattr(self, name), roles))
        if self.fixture_input_raw_sha256["review"] != self.fixture_input_consumed_sha256["review"]:
            _fail()

    def to_dict(self):
        return _plain(self)


@dataclass(frozen=True)
class InHouseReviewBindings:
    legacy: ReviewBindings
    protection: InHouseProtectionBindings
    preparation_pin_manifest_raw_sha256: str
    execution_code_raw_sha256: Mapping[str, str]
    study_plan_lf_sha256: str = PLAN_SHA256
    preparation_design_sha256: str = PREPARATION_DESIGN_SHA256
    allocator_design_sha256: str = ALLOCATOR_DESIGN_SHA256
    schema_version: int = 1
    kind: str = "privoke-in-house-review-bindings-v1"

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != 1
                or self.kind != "privoke-in-house-review-bindings-v1"
                or type(self.legacy) is not ReviewBindings
                or type(self.protection) is not InHouseProtectionBindings
                or self.study_plan_lf_sha256 != PLAN_SHA256
                or self.preparation_design_sha256 != PREPARATION_DESIGN_SHA256
                or self.allocator_design_sha256 != ALLOCATOR_DESIGN_SHA256):
            _fail()
        self.legacy.validate()
        _sha(self.preparation_pin_manifest_raw_sha256)
        object.__setattr__(self, "execution_code_raw_sha256",
                           _digest_map(self.execution_code_raw_sha256, EXECUTION_CODE_ROLES))
        if (self.legacy.protected_union_sha256 != self.protection.historical_union_content_sha256
                or self.legacy.protected_keys_sha256 != self.protection.internal_protected_keys_sha256):
            _fail()
        for role, actual in (("parser", self.legacy.parser_sha256),
                             ("grouping", self.legacy.grouping_sha256),
                             ("normalizer", self.legacy.normalizer_sha256)):
            if self.execution_code_raw_sha256[role] != actual:
                _fail()
        for role, actual in self.protection.addon_helper_raw_sha256.items():
            if self.execution_code_raw_sha256[role] != actual:
                _fail()

    def to_dict(self):
        return _plain(self)


@dataclass(frozen=True)
class InHouseReviewPool:
    core: ReviewPool = field(repr=False)
    bindings: InHouseReviewBindings
    preparation_identity: str
    review_pool_sha256: str
    _graph: GroupingResult = field(repr=False)
    _source_rows: tuple[ParsedNativeRow, ...] = field(repr=False)
    _combined_keys: ProtectedKeys = field(repr=False)
    _native_span_inputs: Mapping = field(repr=False)

    def __post_init__(self):
        if (type(self.core) is not ReviewPool or type(self.bindings) is not InHouseReviewBindings
                or type(self._graph) is not GroupingResult or type(self._source_rows) is not tuple
                or any(type(row) is not ParsedNativeRow for row in self._source_rows)
                or type(self._combined_keys) is not ProtectedKeys
                or type(self.core.packages) is not tuple or type(self.core._members) is not tuple
                or type(self._graph.components) is not tuple
                or not isinstance(self._native_span_inputs, Mapping)):
            _fail()
        from privoke_eval.advpii_review import ValidatedNativeSpanInput
        copied = {}
        for uid, spans in self._native_span_inputs.items():
            if type(uid) is not int or type(spans) not in (tuple, list):
                _fail()
            if any(type(span) is not ValidatedNativeSpanInput for span in spans):
                _fail()
            copied[uid] = tuple(spans)
        object.__setattr__(self, "_native_span_inputs", MappingProxyType(copied))
        for component in self._graph.components:
            if any(type(getattr(component, name)) is not tuple
                   for name in ("member_uids", "assignable_uids", "exclusion_reasons")):
                _fail()
        for row in self._source_rows:
            if type(row.grouping_row.identifiers) is not tuple:
                _fail()
        for value in (self.core, self.bindings, self._graph, self._source_rows,
                      self._combined_keys, self._native_span_inputs):
            _require_immutable(value)


def _identities(core, bindings):
    pool_hash = _hash({
        "schema": "privoke-in-house-review-pool-v1", "bindings": bindings,
        "legacy_pool_sha256": core.pool_sha256,
        "graph_membership_sha256": core.graph_membership_sha256,
        "private_members_sha256": core.private_members_sha256,
        "pool_size": core.pool_size, "selection_streams": core.selection_streams,
    })
    preparation = _hash({"schema": "privoke-in-house-review-preparation-v1",
                         "review_pool_sha256": pool_hash, "bindings": bindings})
    return preparation, pool_hash


def build_in_house_review_pool(parsed_rows, full_graph, bindings, combined_keys,
                               validated_native_spans_by_uid) -> InHouseReviewPool:
    """Build with the actual combined keys, preserving legacy pool selection."""
    if type(bindings) is not InHouseReviewBindings or type(combined_keys) is not ProtectedKeys:
        _fail()
    if (protected_keys_digest(combined_keys) != bindings.protection.internal_protected_keys_sha256
            or combined_protection_digest(combined_keys) != bindings.protection.combined_protection_sha256):
        _fail()
    if any(row.grouping_row.reviewed_has_pii is not None for row in parsed_rows):
        _fail()
    core = build_review_pool(parsed_rows, full_graph, bindings.legacy, combined_keys,
                             validated_native_spans_by_uid)
    preparation, pool_hash = _identities(core, bindings)
    pool = InHouseReviewPool(core, bindings, preparation, pool_hash, full_graph,
                             tuple(parsed_rows), combined_keys, validated_native_spans_by_uid)
    validate_in_house_review_pool(pool, trusted_bindings=bindings)
    return pool


def _validate_core(core, graph):
    if (type(core) is not ReviewPool or type(graph) is not GroupingResult
            or type(core.packages) is not tuple or type(core._members) is not tuple
            or type(core.pool_size) is not int or core.pool_size != len(core.packages)
            or len(core._members) != core.pool_size or core.selection_streams != _STREAMS):
        _fail()
    packages = []
    members = []
    seen_ids, seen_uids, seen_text = set(), set(), set()
    graph_members = {}
    for component in graph.components:
        for uid in component.member_uids:
            if uid in graph_members:
                _fail()
            graph_members[uid] = component
    if len(graph_members) != graph.row_count:
        _fail()
    membership = sorted((item.component_id, tuple(sorted(item.member_uids))) for item in graph.components)
    if _hash([[identity, list(uids)] for identity, uids in membership]) != core.graph_membership_sha256:
        _fail()
    for package, member in zip(core.packages, core._members, strict=True):
        try:
            text_sha = hashlib.sha256(package.text.encode("utf-8")).hexdigest()
        except (AttributeError, UnicodeError):
            _fail()
        if (type(member.uid) is not int or member.uid in seen_uids
                or package.review_id in seen_ids or text_sha in seen_text
                or package.review_id != member.review_id
                or member.uid not in graph_members or graph_members[member.uid].exclusion_reasons
                or member.component_id != graph_members[member.uid].component_id
                or member.native_category not in {"positive", "negative", "hard_negative"}
                or member.structural_eligible is not True
                or package.text_sha256 != text_sha or member.text_sha256 != text_sha
                or member.exact_text_sha256 != text_sha
                or member.normalized_text_key != training_text_key(package.text)
                or package.rubric_sha256 != core.bindings.rubric_sha256
                or package.native_spans != member.native_spans
                or package.review_id != _hash(["privoke-advpii-review-id-v1", core.bindings.source_sha256, member.uid])):
            _fail()
        seen_ids.add(package.review_id)
        seen_uids.add(member.uid)
        seen_text.add(text_sha)
        spans = []
        for span in package.native_spans:
            if (span.entity_type not in _NATIVE_TYPES or type(span.start) is not int
                    or type(span.end) is not int or not 0 <= span.start < span.end <= len(package.text)
                    or not package.text[span.start:span.end].strip()):
                _fail()
            spans.append([span.entity_type, span.start, span.end])
        if member.native_category == "positive" and not spans:
            _fail()
        if member.native_category != "positive" and spans:
            _fail()
        packages.append({"review_id": package.review_id, "text": package.text,
                         "text_sha256": package.text_sha256, "rubric_sha256": package.rubric_sha256,
                         "native_spans": spans})
        members.append((member.review_id, member.uid, member.component_id, member.native_category,
                        member.exact_text_sha256, member.normalized_text_key, member.structural_eligible, spans))
    if (_hash(packages) != core.pool_sha256 or _hash(sorted(members)) != core.private_members_sha256):
        _fail()


def validate_in_house_review_pool(pool: InHouseReviewPool, *,
                                  trusted_bindings: InHouseReviewBindings) -> None:
    """Check actual core commitments plus an independently supplied trust value."""
    if (type(pool) is not InHouseReviewPool or type(trusted_bindings) is not InHouseReviewBindings
            or pool.bindings != trusted_bindings or pool.core.bindings != trusted_bindings.legacy):
        _fail()
    if (protected_keys_digest(pool._combined_keys) != trusted_bindings.protection.internal_protected_keys_sha256
            or combined_protection_digest(pool._combined_keys) != trusted_bindings.protection.combined_protection_sha256):
        _fail()
    rebuilt = build_review_pool(pool._source_rows, pool._graph, trusted_bindings.legacy,
                                pool._combined_keys, pool._native_span_inputs)
    if rebuilt != pool.core:
        _fail()
    _validate_core(pool.core, pool._graph)
    if _identities(pool.core, trusted_bindings) != (pool.preparation_identity, pool.review_pool_sha256):
        _fail()


def validate_in_house_review_responses(pool, envelope, *, trusted_bindings,
                                       expected_preparation_identity):
    """Authenticate the envelope binding before validating supplied decisions."""
    validate_in_house_review_pool(pool, trusted_bindings=trusted_bindings)
    _sha(expected_preparation_identity)
    if (not isinstance(envelope, Mapping)
            or set(envelope) != {"schema_version", "kind", "preparation_identity", "review_pool_sha256", "responses"}
            or type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1
            or envelope["kind"] != "privoke-in-house-blind-review-responses-v1"
            or envelope["preparation_identity"] != expected_preparation_identity
            or expected_preparation_identity != pool.preparation_identity
            or envelope["review_pool_sha256"] != pool.review_pool_sha256):
        _fail()
    return validate_review_responses(pool.core, envelope["responses"])
