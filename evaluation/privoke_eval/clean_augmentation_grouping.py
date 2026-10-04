"""Pure, source-scoped component closure for prospective clean augmentation.

This module accepts already parsed row structures; it performs no I/O, source
loading, annotation review, or label inference. Callers must run it over every
structurally available source row before filtering rows for eligibility or
protected overlap. Raw text and identifier values are used only in local keys
and are never copied into the returned result.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import re
import unicodedata
from typing import Iterable

from privoke_model.training_data import training_text_key


_DOMAIN = "privoke-external-exclusion-v1"
_SOURCE = "advpiibench"
_MAX_INT32 = 2**31 - 1
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def opaque_exclusion_key(kind: str, value: str) -> str:
    """Match the existing preparation key scheme without importing its CLI."""
    if not isinstance(kind, str) or not kind or not isinstance(value, str):
        raise TypeError("Opaque exclusion keys require a nonempty kind and string value.")
    return _digest_text(f"{_DOMAIN}\0{kind}\0{value}")


def canonical_native_value(entity_type: str, native_value: str) -> tuple[str, str] | None:
    """Return the protocol's typed native-value key; never accept fuzzy values."""
    if (
        not isinstance(entity_type, str)
        or not entity_type.strip()
        or not isinstance(native_value, str)
        or not native_value.strip()
    ):
        return None
    value = unicodedata.normalize("NFKC", native_value).casefold()
    value = "".join(character for character in value if not character.isspace())
    if not value:
        return None
    return entity_type, value


@dataclass(frozen=True)
class NativeIdentifier:
    """A valid native span identity used only to join repeated injected values."""

    entity_type: str
    native_value: str


@dataclass(frozen=True)
class GroupingRow:
    """Parsed source row metadata supplied by a later reviewed preparation adapter.

    ``uid`` and ``input_id`` are the source's native integer identities. The
    raw ``text`` is preserved verbatim. ``reviewed_has_pii`` must be an explicit
    rubric-reviewed bool or ``None``; source categories/spans never determine it.
    ``eligible`` records other caller-validated criteria, without removing this
    row's usable graph links. ``content_conflict`` is an explicit review result.
    """

    uid: int
    input_id: object
    text: object
    identifiers: object
    reviewed_has_pii: bool | None
    eligible: bool = True
    content_conflict: bool = False


@dataclass(frozen=True)
class ProtectedKeys:
    """Opaque protected IDs/groups/normalized texts plus direct exact-text hashes."""

    ids: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    exact_text_sha256: frozenset[str] = frozenset()
    normalized_texts: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for field_name in ("ids", "groups", "exact_text_sha256", "normalized_texts"):
            values = getattr(self, field_name)
            if not isinstance(values, (set, frozenset)):
                raise TypeError(f"Protected {field_name} must be a set of SHA-256 hex digests.")
            frozen = frozenset(values)
            if any(not isinstance(value, str) or not _SHA256_RE.fullmatch(value) for value in frozen):
                raise ValueError(f"Protected {field_name} contains a malformed digest.")
            object.__setattr__(self, field_name, frozen)


@dataclass(frozen=True)
class Component:
    """A private grouping result; IDs are source UIDs, never prompt text."""

    component_id: str
    member_uids: tuple[int, ...]
    assignable_uids: tuple[int, ...]
    exclusion_reasons: tuple[str, ...]
    positive_rows: int
    negative_rows: int


@dataclass(frozen=True)
class GroupingResult:
    components: tuple[Component, ...]
    row_reasons: tuple[tuple[int, tuple[str, ...]], ...]
    row_reason_counts: tuple[tuple[str, int], ...]
    component_reason_counts: tuple[tuple[str, int], ...]
    relationship_counts: tuple[tuple[str, int], ...]
    row_count: int
    component_count: int
    assignable_row_count: int
    mixed_label_component_count: int


class _DisjointSet:
    def __init__(self, values: Iterable[int]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: int) -> int:
        parent = self.parent[value]
        while parent != self.parent[parent]:
            self.parent[parent] = self.parent[self.parent[parent]]
            parent = self.parent[parent]
        self.parent[value] = parent
        return parent

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root == right_root:
            return
        # Choosing the smaller native UID gives deterministic roots regardless
        # of input iteration order.
        smaller, larger = sorted((left_root, right_root))
        self.parent[larger] = smaller


def _valid_int32(value: object) -> bool:
    return type(value) is int and -(2**31) <= value <= _MAX_INT32


def _stable_id(uid: int) -> str:
    return f"{_SOURCE}:uid:{uid}"


def _parent_group(input_id: int) -> str:
    return f"{_SOURCE}:input_id:{input_id}"


def _prepare_rows(rows: Iterable[GroupingRow]):
    ordered = list(rows)
    by_uid: dict[int, GroupingRow] = {}
    for row in ordered:
        if not isinstance(row, GroupingRow):
            raise TypeError("Grouping input must contain GroupingRow values.")
        if not _valid_int32(row.uid):
            raise ValueError("Every grouping node needs a valid native int32 UID.")
        if row.uid in by_uid:
            raise ValueError("Duplicate native UID; refusing to overwrite a graph node.")
        if type(row.eligible) is not bool or type(row.content_conflict) is not bool:
            raise TypeError("Eligibility and reviewed content-conflict flags must be strict bools.")
        if row.reviewed_has_pii is not None and type(row.reviewed_has_pii) is not bool:
            raise TypeError("Reviewed presence truth must be strict bool or None; native categories are not truth.")
        by_uid[row.uid] = row
    return by_uid


def build_components(rows: Iterable[GroupingRow], protected: ProtectedKeys | None = None) -> GroupingResult:
    """Build full transitive components, then compute eligibility/exclusions.

    All valid links from all rows are collected first, including links from rows
    that are unreviewed, otherwise ineligible, or protected. Only after closure
    does the function exclude an entire component for protected collisions,
    contradictory reviewed truth on the same normalized text, or a reviewed
    same-content conflict. Missing link fields are counted and make that row
    ineligible, but other valid links from that row are retained.
    """
    protected = ProtectedKeys() if protected is None else protected
    if not isinstance(protected, ProtectedKeys):
        raise TypeError("protected must be a ProtectedKeys value.")
    by_uid = _prepare_rows(rows)
    uid_order = sorted(by_uid)
    dsu = _DisjointSet(uid_order)
    row_reasons: dict[int, set[str]] = {uid: set() for uid in uid_order}
    relationships: dict[tuple[str, str], list[int]] = defaultdict(list)
    relationship_counts: Counter[str] = Counter()
    protected_reasons: dict[int, set[str]] = {uid: set() for uid in uid_order}
    normalized_by_uid: dict[int, str] = {}
    exact_by_uid: dict[int, str] = {}

    # Collect all structurally usable graph links before any eligibility or
    # protected-overlap decisions. No text/value is stored in the result.
    for uid in uid_order:
        row = by_uid[uid]
        if opaque_exclusion_key("id", _stable_id(uid)) in protected.ids:
            protected_reasons[uid].add("protected_id_overlap")
        if not _valid_int32(row.input_id):
            row_reasons[uid].add("missing_or_unusable_input_id")
        else:
            parent_key = opaque_exclusion_key("group", _parent_group(row.input_id))
            relationships[("parent", parent_key)].append(uid)
            relationship_counts["parent_links"] += 1
            if parent_key in protected.groups:
                protected_reasons[uid].add("protected_group_overlap")

        if not isinstance(row.text, str) or not row.text.strip():
            row_reasons[uid].add("missing_or_unusable_text")
        else:
            exact_hash = _digest_text(row.text)
            normalized_text = training_text_key(row.text)
            if not normalized_text:
                row_reasons[uid].add("empty_normalized_text_key")
            else:
                normalized_key = opaque_exclusion_key("text_key", normalized_text)
                exact_by_uid[uid] = exact_hash
                normalized_by_uid[uid] = normalized_key
                relationships[("exact_text", exact_hash)].append(uid)
                relationships[("normalized_text", normalized_key)].append(uid)
                relationship_counts["exact_text_links"] += 1
                relationship_counts["normalized_text_links"] += 1
                if exact_hash in protected.exact_text_sha256:
                    protected_reasons[uid].add("protected_exact_text_overlap")
                if normalized_key in protected.normalized_texts:
                    protected_reasons[uid].add("protected_normalized_text_overlap")

        if not isinstance(row.identifiers, (tuple, list)):
            row_reasons[uid].add("missing_or_unusable_identifier_collection")
            native_identifiers: tuple[object, ...] = ()
        else:
            native_identifiers = tuple(row.identifiers)
        valid_value_count = 0
        for identifier in native_identifiers:
            if not isinstance(identifier, NativeIdentifier):
                row_reasons[uid].add("unusable_native_identifier")
                continue
            canonical = canonical_native_value(identifier.entity_type, identifier.native_value)
            if canonical is None:
                row_reasons[uid].add("unusable_native_identifier")
                continue
            entity_type, canonical_value = canonical
            # Hash the value key immediately so no identifier string escapes
            # this call through relation maps or result objects.
            value_key = opaque_exclusion_key("native_identifier", _canonical_json([entity_type, canonical_value]))
            relationships[("native_identifier", value_key)].append(uid)
            relationship_counts["native_identifier_links"] += 1
            valid_value_count += 1
        if row.reviewed_has_pii is True and valid_value_count == 0:
            row_reasons[uid].add("positive_without_recoverable_native_value")
        if row.reviewed_has_pii is None:
            row_reasons[uid].add("reviewed_label_unknown")
        if not row.eligible:
            row_reasons[uid].add("upstream_ineligible")

    # Union all keys, preserving bridges contributed by rows already marked
    # ineligible above. Sorted keys/members make component output reproducible.
    for _, members in sorted(relationships.items()):
        distinct = sorted(set(members))
        if len(distinct) > 1:
            anchor = distinct[0]
            for member in distinct[1:]:
                dsu.union(anchor, member)

    grouped: dict[int, list[int]] = defaultdict(list)
    for uid in uid_order:
        grouped[dsu.find(uid)].append(uid)
    members_by_root = sorted((tuple(sorted(members)) for members in grouped.values()), key=lambda item: item)

    components: list[Component] = []
    component_reason_counts: Counter[str] = Counter()
    mixed_label_components = 0
    assignable_rows = 0
    row_reason_counts: Counter[str] = Counter()
    for uid, reasons in row_reasons.items():
        row_reason_counts.update(reasons)

    for member_uids in members_by_root:
        exclusions = set()
        labels = set()
        content_keys: dict[str, set[bool]] = defaultdict(set)
        exact_text_labels: dict[str, set[bool]] = defaultdict(set)
        for uid in member_uids:
            row = by_uid[uid]
            exclusions.update(protected_reasons[uid])
            if row.content_conflict:
                exclusions.add("irreconcilable_reviewed_content_conflict")
            if row.reviewed_has_pii is not None:
                labels.add(row.reviewed_has_pii)
                normalized_key = normalized_by_uid.get(uid)
                if normalized_key is not None:
                    content_keys[normalized_key].add(row.reviewed_has_pii)
                    exact_hash = exact_by_uid.get(uid)
                    if exact_hash is not None:
                        exact_text_labels[exact_hash].add(row.reviewed_has_pii)
        if len(labels) > 1:
            mixed_label_components += 1
        for normalized_key, truth_values in content_keys.items():
            if truth_values == {False, True}:
                if any(
                    exact_text_labels.get(exact_hash) == {False, True}
                    for uid in member_uids
                    if normalized_by_uid.get(uid) == normalized_key
                    for exact_hash in (exact_by_uid.get(uid),)
                    if exact_hash is not None
                ):
                    exclusions.add("opposing_reviewed_truth_on_exact_text")
                else:
                    exclusions.add("opposing_reviewed_truth_on_normalized_text")

        for reason in exclusions:
            component_reason_counts[reason] += 1
        has_component_exclusion = bool(exclusions)
        assignable_uids = tuple(
            uid for uid in member_uids if not row_reasons[uid] and not has_component_exclusion
        )
        assignable_rows += len(assignable_uids)
        component_id = _digest_text(
            "privoke-clean-augmentation-component-v1\0" + _canonical_json([_SOURCE, list(member_uids)])
        )
        components.append(
            Component(
                component_id=component_id,
                member_uids=member_uids,
                assignable_uids=assignable_uids,
                exclusion_reasons=tuple(sorted(exclusions)),
                positive_rows=sum(by_uid[uid].reviewed_has_pii is True for uid in member_uids),
                negative_rows=sum(by_uid[uid].reviewed_has_pii is False for uid in member_uids),
            )
        )

    return GroupingResult(
        components=tuple(components),
        row_reasons=tuple((uid, tuple(sorted(row_reasons[uid]))) for uid in uid_order),
        row_reason_counts=tuple(sorted(row_reason_counts.items())),
        component_reason_counts=tuple(sorted(component_reason_counts.items())),
        relationship_counts=tuple(sorted(relationship_counts.items())),
        row_count=len(uid_order),
        component_count=len(components),
        assignable_row_count=assignable_rows,
        mixed_label_component_count=mixed_label_components,
    )
