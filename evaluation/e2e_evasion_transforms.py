"""Declared variant templates for the Stage 13b end-to-end evasion study (E2EEVADE).

Two variants are added to the Stage 3 families of ``adversarial_evasion_transforms.py``, which stay
unchanged at generator revision ``advevade-transforms-1``:

* ``fragmented_identifier``: each annotated identifier is split in two and the halves are joined by
  a declared connector phrase (the identifier is never written out contiguously).
* ``mixed_language``: the identifier-carrying sentences of the Stage 3 multilingual tables, with a
  different language for each consecutive identifier of one prompt (code-switching).

Every transform is a pure function ``(row, rng) -> str | None`` of a seed row and a
``random.Random`` seeded as in Stage 3 (``sha256(SEED : variant : row id)``). A transform never
reads PriVoke output. It returns ``None`` when it cannot change the row, and the harness then
excludes that (row, variant) pair from the denominators instead of counting it as a survival.

The templates below were written once, before any PriVoke output on the evaluation rows existed.
Their file hash is frozen with ``e2e_evasion.py verify-templates`` and pinned in
``evaluation/s13_allowlist.json``. Never edit this file after any PriVoke output has been seen.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path
from typing import Callable

import adversarial_evasion_transforms as stage3

GENERATOR_REVISION = "e2e-evasion-transforms-1"

# Connector phrases for the two halves of one identifier. One is drawn per identifier.
FRAGMENT_TEMPLATES = (
    "{a} then {b}",
    "{a}, followed by {b}",
    "{a} and, to finish it, {b}",
)
FRAGMENT_MIN_CHARS = 4
FRAGMENT_MAX_SPANS = 4

# Language order for the code-switched prompt; the first language is drawn per row.
MIXED_LANGUAGES = ("es", "fr", "de", "pt", "zh", "ru")
MIXED_MAX_ENTITIES = stage3.MULTILINGUAL_MAX_ENTITIES
MIXED_MIN_SENTENCES = 2


def t_fragmented_identifier(row: dict, rng: random.Random) -> str | None:
    text = row["text"]
    replacements: list[tuple[int, int, str]] = []
    for start, end, _label in stage3.merged_spans(row)[:FRAGMENT_MAX_SPANS]:
        value = text[start:end]
        if len(value.strip()) < FRAGMENT_MIN_CHARS:
            continue
        half = len(value) // 2
        template = FRAGMENT_TEMPLATES[rng.randrange(len(FRAGMENT_TEMPLATES))]
        replacements.append((start, end, template.format(a=value[:half], b=value[half:])))
    for start, end, new in reversed(replacements):
        text = text[:start] + new + text[end:]
    return text if text != row["text"] else None


def t_mixed_language(row: dict, rng: random.Random) -> str | None:
    text = row["text"]
    offset = rng.randrange(len(MIXED_LANGUAGES))
    seen: set[str] = set()
    sentences: list[str] = []
    for start, end, label in stage3.merged_spans(row):
        value = text[start:end].strip()
        if not value or value in seen:
            continue
        seen.add(value)
        language = MIXED_LANGUAGES[(offset + len(sentences)) % len(MIXED_LANGUAGES)]
        sentences.append(stage3.MULTILINGUAL[language][stage3.label_family(label)].format(v=value))
        if len(sentences) >= MIXED_MAX_ENTITIES:
            break
    return " ".join(sentences) if len(sentences) >= MIXED_MIN_SENTENCES else None


# variant -> (family, function, value_removing); same shape as the Stage 3 registry
E2E_VARIANTS: dict[str, tuple[str, Callable[[dict, random.Random], str | None], bool]] = {
    "fragmented_identifier": ("fragmented_identifier", t_fragmented_identifier, False),
    "mixed_language": ("mixed_language", t_mixed_language, False),
}


def apply_e2e_variant(variant: str, row: dict) -> str | None:
    _family, fn, _removing = E2E_VARIANTS[variant]
    return fn(row, stage3.row_rng(variant, row["id"]))


def lf_sha256(path: Path) -> str:
    """sha256 of a file with CRLF folded to LF, so a Windows checkout hashes like the Git blob."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def template_file() -> Path:
    return Path(__file__).resolve()
