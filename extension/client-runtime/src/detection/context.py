from __future__ import annotations

import re


_CLEAN_DISCUSSION_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:what is|what are|explain|define|definition of|meaning of)\b",
        r"\b(?:example|sample|format|placeholder|template)\b",
        r"\b(?:redact|mask|remove|sanitize|anonymi[sz]e)\b",
        r"\b(?:without|avoid|do not|don't)\s+(?:real|actual|personal|private|sensitive)\b",
        r"\b(?:using|use)\s+(?:xxxx|\[email\]|\[phone\]|\[name\]|\[address\]|placeholder)\b",
        r"\b(?:no|not)\s+(?:real|actual)\s+(?:data|details|information|pii)\b",
    )
)

_DISCLOSURE_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(?:my|his|her|their|our)\s+(?:email|phone|ssn|address|account|password|diagnosis|doctor|medication|salary|child|case|record)\b",
        r"\b(?:i|we|he|she|they)\s+(?:have|has|had|am|was|were|live|work|take|takes|owe|earn|voted|believe)\b",
        r"\b(?:patient|client|student|employee|tenant)\s+(?:has|had|is|was|record|id|number|diagnosis|salary)\b",
    )
)


def is_clean_discussion_context(text: str) -> bool:
    """Return true for prompts discussing sensitive concepts without disclosure."""
    return (
        any(pattern.search(text) for pattern in _CLEAN_DISCUSSION_PATTERNS)
        and not any(pattern.search(text) for pattern in _DISCLOSURE_PATTERNS)
    )
