"""Pure dual-review consumer for frozen in-house blind-review pools.

This module validates two independently committed review envelopes and makes
conservative per-prompt consensus labels. It does not authenticate who operated
an unrestricted producer: reviewer IDs and raw-byte digests are external
assignment commitments supplied by the caller.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re
from types import MappingProxyType

from privoke_eval.advpii_review import ValidatedReview
from privoke_eval.in_house_advpii_review import (
    InHouseReviewBindings,
    InHouseReviewPool,
    validate_in_house_review_responses,
)

MAX_REVIEW_ENVELOPE_BYTES = 64 * 1024 * 1024
CONSENSUS_RULE_RAW_SHA256 = "50c4cb981ed88f93f275a4cd8459af36b7a9b6434acd1f6b2e2bbe9521587ac2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UNCERTAIN = "review_uncertain_or_disagreement"


def _fail() -> None:
    # Never chain parser/validator messages: they must not echo prompt content.
    raise ValueError("Dual-review bundle failed validation.") from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _valid_sha(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _reject_constant(_value: str):
    _fail()


def _object_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _decode_envelope(raw: object, expected_sha256: object) -> tuple[dict, str]:
    if (type(raw) is not bytes or not raw or len(raw) > MAX_REVIEW_ENVELOPE_BYTES
            or not _valid_sha(expected_sha256)):
        _fail()
    digest = _sha256(raw)
    if digest != expected_sha256:
        _fail()
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_object_no_duplicates,
                           parse_constant=_reject_constant)
    except Exception:
        _fail()
    if type(value) is not dict:
        _fail()
    return value, digest


def _reviewer_id(value: object) -> str:
    if (type(value) is not str or not value.strip() or value != value.strip()
            or len(value) > 256):
        _fail()
    return value


def _copy_review(review: ValidatedReview) -> ValidatedReview:
    """Detach returned immutable records from validator-owned mappings."""
    return ValidatedReview(
        review_id=str(review.review_id),
        decision=str(review.decision),
        has_pii=review.has_pii,
        categories=tuple(str(item) for item in review.categories),
        reviewer_id=str(review.reviewer_id),
        reviewed_at=str(review.reviewed_at),
        uncertainty_reason=(None if review.uncertainty_reason is None
                           else str(review.uncertainty_reason)),
        response_sha256=str(review.response_sha256),
        evidence=tuple((str(category), int(start), int(end))
                       for category, start, end in review.evidence),
    )


@dataclass(frozen=True)
class ReviewSet:
    """One complete, validated response set and its external reviewer claim."""

    reviewer_id: str = field(repr=False)
    envelope_raw_sha256: str
    responses_sha256: str
    reviews: Mapping[str, ValidatedReview] = field(repr=False)


@dataclass(frozen=True)
class DualReviewRecord:
    """Consensus for one opaque review ID; evidence remains separate by reviewer."""

    review_id: str = field(repr=False)
    has_pii: bool | None
    categories: tuple[str, ...]
    reason: str
    first_response_sha256: str
    second_response_sha256: str
    first_evidence: tuple[tuple[str, int, int], ...] = field(repr=False)
    second_evidence: tuple[tuple[str, int, int], ...] = field(repr=False)


@dataclass(frozen=True)
class DualReviewResult:
    """Immutable dual-review result. This is provisional, not ground truth."""

    preparation_identity: str
    review_pool_sha256: str
    first: ReviewSet = field(repr=False)
    second: ReviewSet = field(repr=False)
    records: Mapping[str, DualReviewRecord] = field(repr=False)
    counts: Mapping[str, int]
    consensus_rule_raw_sha256: str
    consensus_sha256: str
    human_agreement_claimed: bool = False
    label_truth_authenticated: bool = False


def _freeze_review_set(validated: Mapping[str, ValidatedReview], reviewer_id: str,
                       envelope_sha256: str) -> ReviewSet:
    copied = {review_id: _copy_review(validated[review_id])
              for review_id in sorted(validated)}
    response_digest = _sha256(json.dumps(
        [[review_id, copied[review_id].response_sha256] for review_id in copied],
        sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii"))
    return ReviewSet(reviewer_id, envelope_sha256, response_digest,
                     MappingProxyType(copied))


def consume_dual_reviews(
    pool: InHouseReviewPool,
    first_envelope_bytes: bytes,
    second_envelope_bytes: bytes,
    *,
    trusted_bindings: InHouseReviewBindings,
    expected_preparation_identity: str,
    expected_first_reviewer_id: str,
    expected_second_reviewer_id: str,
    expected_first_raw_sha256: str,
    expected_second_raw_sha256: str,
) -> DualReviewResult:
    """Validate two full response sets and apply strict agreement-only consensus.

    Exact raw-byte hashes and distinct reviewer assignments are supplied by the
    caller. This function checks those claims but cannot attest to a human or
    to the provenance of a producer process.
    """
    try:
        if (type(pool) is not InHouseReviewPool
                or type(trusted_bindings) is not InHouseReviewBindings
                or type(pool.core.pool_size) is not int or pool.core.pool_size <= 0
                or type(expected_preparation_identity) is not str
                or not _valid_sha(expected_preparation_identity)
                or expected_preparation_identity != pool.preparation_identity):
            _fail()
        first_id = _reviewer_id(expected_first_reviewer_id)
        second_id = _reviewer_id(expected_second_reviewer_id)
        if first_id == second_id:
            _fail()

        first_envelope, first_raw_sha = _decode_envelope(
            first_envelope_bytes, expected_first_raw_sha256)
        second_envelope, second_raw_sha = _decode_envelope(
            second_envelope_bytes, expected_second_raw_sha256)

        first_validated = validate_in_house_review_responses(
            pool, first_envelope, trusted_bindings=trusted_bindings,
            expected_preparation_identity=expected_preparation_identity,
        )
        second_validated = validate_in_house_review_responses(
            pool, second_envelope, trusted_bindings=trusted_bindings,
            expected_preparation_identity=expected_preparation_identity,
        )
        if (set(first_validated) != set(second_validated)
                or len(first_validated) != pool.core.pool_size
                or len(second_validated) != pool.core.pool_size):
            _fail()
        for review_id in first_validated:
            if (first_validated[review_id].reviewer_id != first_id
                    or second_validated[review_id].reviewer_id != second_id):
                _fail()

        first = _freeze_review_set(first_validated, first_id, first_raw_sha)
        second = _freeze_review_set(second_validated, second_id, second_raw_sha)
        records: dict[str, DualReviewRecord] = {}
        counts = {
            "pool_size": len(first.reviews),
            "present": 0,
            "absent": 0,
            "uncertain": 0,
            "decision_matches": 0,
            "present_category_matches": 0,
        }
        for review_id in sorted(first.reviews):
            left = first.reviews[review_id]
            right = second.reviews[review_id]
            if left.decision == right.decision:
                counts["decision_matches"] += 1
            if (left.decision == right.decision == "present"
                    and left.categories == right.categories):
                counts["present_category_matches"] += 1
            if left.decision == "uncertain" or right.decision == "uncertain":
                label, categories, reason = None, (), _UNCERTAIN
            elif left.decision != right.decision:
                label, categories, reason = None, (), _UNCERTAIN
            elif left.decision == "absent":
                label, categories, reason = False, (), "both_reviewers_absent"
            elif left.decision == "present" and left.categories == right.categories:
                label, categories, reason = True, left.categories, "both_reviewers_present_same_categories"
            else:
                label, categories, reason = None, (), _UNCERTAIN
            counts["uncertain" if label is None else "present" if label else "absent"] += 1
            records[review_id] = DualReviewRecord(
                review_id=review_id,
                has_pii=label,
                categories=tuple(categories),
                reason=reason,
                first_response_sha256=left.response_sha256,
                second_response_sha256=right.response_sha256,
                first_evidence=tuple(left.evidence),
                second_evidence=tuple(right.evidence),
            )

        canonical_records = [
            [key, item.has_pii, list(item.categories), item.reason,
             item.first_response_sha256, item.second_response_sha256,
             [list(span) for span in item.first_evidence],
             [list(span) for span in item.second_evidence]]
            for key, item in records.items()
        ]
        consensus = {
            "schema": "privoke-in-house-dual-review-consensus-v1",
            "consensus_rule_raw_sha256": CONSENSUS_RULE_RAW_SHA256,
            "preparation_identity": pool.preparation_identity,
            "review_pool_sha256": pool.review_pool_sha256,
            "first_raw_sha256": first_raw_sha,
            "second_raw_sha256": second_raw_sha,
            "first_responses_sha256": first.responses_sha256,
            "second_responses_sha256": second.responses_sha256,
            "records": canonical_records,
        }
        consensus_sha256 = _sha256(json.dumps(
            consensus, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8"))
        return DualReviewResult(
            preparation_identity=pool.preparation_identity,
            review_pool_sha256=pool.review_pool_sha256,
            first=first,
            second=second,
            records=MappingProxyType(records),
            counts=MappingProxyType(counts),
            consensus_rule_raw_sha256=CONSENSUS_RULE_RAW_SHA256,
            consensus_sha256=consensus_sha256,
        )
    except Exception:
        _fail()
