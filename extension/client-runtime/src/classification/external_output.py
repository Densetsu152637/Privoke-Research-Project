"""Strict validation at external semantic classifier boundaries."""
import math
from typing import Any

from .classification_results import ClassificationResult, build_results
from .classification_types import Category, Sensitivity, Visibility


def build_external_results(content: Any, text: str) -> list[ClassificationResult]:
    """Reject incomplete/malformed responses rather than defaulting them clean.

    The legacy internal parser stays permissive. External APIs must return an
    explicit clean S0 result when no risk exists, rather than an empty response.
    """
    if isinstance(content, dict):
        if 'results' in content:
            raw_results = content['results']
        elif 'classification_results' in content:
            raw_results = content['classification_results']
        else:
            raw_results = [content]
    else:
        raw_results = content
    if not isinstance(raw_results, list) or not raw_results:
        raise RuntimeError('Semantic classifier returned no valid results.')

    for item in raw_results:
        if not isinstance(item, dict):
            _invalid()
        for key, enum in (('sensitivity', Sensitivity), ('visibility', Visibility)):
            value = item.get(key)
            if not isinstance(value, str) or value not in enum.__members__:
                _invalid()
        categories = item.get('categories')
        if (not isinstance(categories, list) or
                any(not isinstance(value, str) or value not in Category.__members__
                    for value in categories)):
            _invalid()
        if any(not isinstance(item.get(key), str)
               for key in ('section_of_text', 'reasoning')):
            _invalid()
        confidence = item.get('confidence')
        if confidence is not None and (type(confidence) not in (int, float) or
                not math.isfinite(confidence) or not 0 <= confidence <= 1):
            _invalid()
        if 'metadata' in item and not isinstance(item['metadata'], dict):
            _invalid()
        span = item.get('span')
        if span is not None:
            if (not isinstance(span, list) or len(span) != 2 or
                    any(type(value) is not int for value in span) or
                    not 0 <= span[0] < span[1] <= len(text) or
                    text[span[0]:span[1]] != item['section_of_text']):
                _invalid()
    return build_results(raw_results)


def _invalid() -> None:
    # Never include raw model content or prompt evidence in an error message.
    raise RuntimeError('Semantic classifier returned malformed classification results.')
