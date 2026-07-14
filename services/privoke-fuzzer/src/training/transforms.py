from __future__ import annotations

import random
import re


def random_pii_transform(text: str, rng: random.Random | None = None) -> str:
    # Research-data variation only; cryptographic randomness is not required.
    rng = rng or random.Random()  # nosec B311
    transforms = (
        lambda value: value,
        lambda value: f"Please review this prompt: {value}",
        redact_common_name,
        synthetic_common_name,
        redact_email,
        synthetic_phone,
    )
    return rng.choice(transforms)(text)


def redact_common_name(text: str) -> str:
    return re.sub(r"\bJohn Doe\b", "[REDACTED_NAME]", text, flags=re.IGNORECASE)


def synthetic_common_name(text: str) -> str:
    return re.sub(r"\bJohn Doe\b", "Alex Smith", text, flags=re.IGNORECASE)


def redact_email(text: str) -> str:
    return re.sub(
        r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        text,
    )


def synthetic_phone(text: str) -> str:
    return re.sub(
        r"\b(?:\+?\d[\d .()-]{7,}\d)\b",
        "0400 000 000",
        text,
    )
