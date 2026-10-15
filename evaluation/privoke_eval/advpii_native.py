"""Pure parser and Arrow schema guard for the pinned AdvPIIBench release.

The parser preserves usable grouping links while reporting structural problems.
It never maps source categories to the separately reviewed broad-presence label.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from privoke_eval.clean_augmentation_grouping import GroupingRow, NativeIdentifier


_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1
_CATEGORIES = frozenset({"positive", "negative", "hard_negative"})
_SPAN_TYPES = frozenset({"credit_card_number", "phone_number", "iban", "email", "ssn"})
_PII_OPERATIONS = frozenset({
    "homoglyph", "chunking", "emojify", "char_to_word", "invisible_chars", "separators",
})
_CONTEXT_OPERATIONS = frozenset({
    "supportive_context", "affix_redacted", "affix_ignore_pii", "affix_category_prime",
    "pi_ceo_instruct", "pi_few_shot_safe", "pi_hypothetical",
    "pi_educational_framing", "pi_category_prime",
})
_TOP_FIELDS = ("uid", "input_id", "category", "attack_target", "llm_input", "pii_spans")
_SPAN_FIELDS = ("type", "start", "end", "value", "value_fuzzy")
_ATTACK_FIELDS = ("pii", "context")


@dataclass(frozen=True)
class ParsedNativeRow:
    grouping_row: GroupingRow = field(repr=False)
    native_category: str | None
    structural_reasons: tuple[str, ...]
    valid_span_count: int
    recoverable_identifier_count: int
    native_span_types: tuple[str, ...]
    few_shot_excluded: bool


def _is_int32(value: object) -> bool:
    return type(value) is int and _INT32_MIN <= value <= _INT32_MAX


def _fixed_mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def parse_native_row(row: Mapping[str, object]) -> ParsedNativeRow:
    """Parse one already-decoded source row without I/O or broad-label inference.

    Missing or malformed non-UID fields produce fixed reason codes and do not
    erase independently valid parent, text, or sibling-span grouping links.
    Missing/invalid UID is fatal because a full scan cannot safely deduplicate it.
    """
    if not isinstance(row, Mapping):
        raise TypeError("AdvPIIBench row must be a mapping.")
    uid = row.get("uid")
    if not _is_int32(uid):
        raise ValueError("AdvPIIBench row has a missing or invalid signed int32 UID.")

    reasons: set[str] = set()
    input_id = row.get("input_id")
    if not _is_int32(input_id):
        input_id = None
        reasons.add("missing_or_unusable_input_id")

    text = row.get("llm_input")
    if not isinstance(text, str) or not text.strip():
        text = None
        reasons.add("missing_or_unusable_text")

    raw_category = row.get("category")
    category = raw_category if isinstance(raw_category, str) and raw_category in _CATEGORIES else None
    if category is None:
        reasons.add("missing_or_unknown_native_category")

    attack = _fixed_mapping(row.get("attack_target"))
    attack_valid = attack is not None and set(attack.keys()) == set(_ATTACK_FIELDS)
    pii_ops: tuple[object, ...] = ()
    context_ops: tuple[object, ...] = ()
    if attack_valid:
        raw_pii, raw_context = attack.get("pii"), attack.get("context")
        attack_valid = isinstance(raw_pii, list) and isinstance(raw_context, list)
        if attack_valid:
            pii_ops, context_ops = tuple(raw_pii), tuple(raw_context)
            attack_valid = all(isinstance(item, str) and item in _PII_OPERATIONS for item in pii_ops)
            attack_valid = attack_valid and all(
                isinstance(item, str) and item in _CONTEXT_OPERATIONS for item in context_ops
            )
    if not attack_valid:
        reasons.add("missing_or_invalid_attack_target")
    few_shot_excluded = "pi_few_shot_safe" in context_ops
    if few_shot_excluded:
        reasons.add("excluded_pi_few_shot_safe")

    raw_spans = row.get("pii_spans")
    if not isinstance(raw_spans, list):
        raw_spans = []
        reasons.add("missing_or_invalid_pii_spans")
    elif category is None:
        # Keep usable spans for graph closure, but a missing category is itself
        # a structural failure.
        pass
    if text is None:
        # Offset checks require the exact unnormalized source string.
        reasons.add("spans_unverifiable_without_text")

    identifiers: list[NativeIdentifier] = []
    valid_span_types: list[str] = []
    valid_span_count = 0
    if text is not None:
        for raw_span in raw_spans:
            span = _fixed_mapping(raw_span)
            if span is None or set(span.keys()) != set(_SPAN_FIELDS):
                reasons.add("invalid_native_span_structure")
                continue
            span_type = span.get("type")
            start, end = span.get("start"), span.get("end")
            value, value_fuzzy = span.get("value"), span.get("value_fuzzy")
            if not isinstance(span_type, str) or span_type not in _SPAN_TYPES:
                reasons.add("unknown_native_span_type")
                continue
            if not _is_int32(start) or not _is_int32(end) or not (0 <= start < end <= len(text)):
                reasons.add("invalid_native_span_offsets")
                continue
            if value is not None and not isinstance(value, str):
                reasons.add("invalid_native_span_value")
                continue
            if value_fuzzy is not None and not isinstance(value_fuzzy, str):
                reasons.add("invalid_native_span_value")
                continue
            expected = value_fuzzy or value
            if not isinstance(expected, str) or not expected or text[start:end] != expected:
                reasons.add("native_span_literal_mismatch")
                continue
            valid_span_count += 1
            valid_span_types.append(span_type)
            # Fuzzy text is validated against the exact offsets, but only the
            # recoverable native base value may connect repeated identifiers.
            if isinstance(value, str) and value.strip():
                identifiers.append(NativeIdentifier(span_type, value))
    elif raw_spans:
        reasons.add("invalid_native_span_structure")

    recoverable_count = len(identifiers)
    if category == "positive" and recoverable_count == 0:
        reasons.add("positive_without_recoverable_native_value")
    if category in {"negative", "hard_negative"} and raw_spans:
        reasons.add("native_negative_has_spans")
    if category == "positive" and not raw_spans:
        reasons.add("native_positive_has_no_spans")

    grouping_row = GroupingRow(
        uid=uid,
        input_id=input_id,
        text=text,
        identifiers=tuple(identifiers),
        reviewed_has_pii=None,
        eligible=not reasons,
        content_conflict=False,
    )
    return ParsedNativeRow(
        grouping_row=grouping_row,
        native_category=category,
        structural_reasons=tuple(sorted(reasons)),
        valid_span_count=valid_span_count,
        recoverable_identifier_count=recoverable_count,
        native_span_types=tuple(sorted(valid_span_types)),
        few_shot_excluded=few_shot_excluded,
    )


def parse_native_rows(rows: Iterable[Mapping[str, object]]) -> tuple[ParsedNativeRow, ...]:
    """Parse a full iterable and reject duplicate native UIDs without overwrite."""
    parsed: list[ParsedNativeRow] = []
    seen: set[int] = set()
    for row in rows:
        result = parse_native_row(row)
        uid = result.grouping_row.uid
        if uid in seen:
            raise ValueError("AdvPIIBench source contains a duplicate native UID.")
        seen.add(uid)
        parsed.append(result)
    return tuple(parsed)


def validate_arrow_schema(schema: object) -> None:
    """Require the exact pinned six-field Arrow schema; import PyArrow lazily."""
    try:
        import pyarrow as pa
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError("PyArrow is required to validate the AdvPIIBench Arrow schema.") from exc

    if not isinstance(schema, pa.Schema):
        raise TypeError("Expected a PyArrow Schema.")
    if tuple(schema.names) != _TOP_FIELDS:
        raise ValueError("AdvPIIBench Arrow schema has unexpected top-level fields or order.")

    def require_field(field: object, name: str, data_type: object, nullable: bool = True) -> None:
        if field.name != name or field.type != data_type or field.nullable is not nullable:
            raise ValueError(f"AdvPIIBench Arrow field {name!r} has an unexpected type or nullability.")

    require_field(schema.field("uid"), "uid", pa.int32())
    require_field(schema.field("input_id"), "input_id", pa.int32())
    require_field(schema.field("category"), "category", pa.string())
    require_field(schema.field("llm_input"), "llm_input", pa.string())

    attack = schema.field("attack_target")
    if not attack.nullable or not pa.types.is_struct(attack.type) or tuple(attack.type.names) != _ATTACK_FIELDS:
        raise ValueError("AdvPIIBench attack_target has an unexpected nested schema.")
    def require_string_list_field(field: object, name: str) -> None:
        if field.name != name or field.nullable is not True or not pa.types.is_list(field.type):
            raise ValueError(f"AdvPIIBench Arrow field {name!r} has an unexpected list type.")
        child = field.type.value_field
        if child.name not in {"item", "element"} or child.nullable is not True or child.type != pa.string():
            raise ValueError(f"AdvPIIBench Arrow list {name!r} has an unexpected child type.")

    require_string_list_field(attack.type.field("pii"), "pii")
    require_string_list_field(attack.type.field("context"), "context")

    spans = schema.field("pii_spans")
    if not spans.nullable or not pa.types.is_list(spans.type):
        raise ValueError("AdvPIIBench pii_spans must be a standard Arrow list.")
    span_value = spans.type.value_field
    if span_value.name not in {"item", "element"} or not span_value.nullable:
        raise ValueError("AdvPIIBench pii_spans list child has an unexpected name or nullability.")
    if not pa.types.is_struct(span_value.type) or tuple(span_value.type.names) != _SPAN_FIELDS:
        raise ValueError("AdvPIIBench pii_spans has an unexpected nested schema.")
    expected_types = {
        "type": pa.string(),
        "start": pa.int32(),
        "end": pa.int32(),
        "value": pa.string(),
        "value_fuzzy": pa.string(),
    }
    for field_name in _SPAN_FIELDS:
        require_field(span_value.type.field(field_name), field_name, expected_types[field_name])
