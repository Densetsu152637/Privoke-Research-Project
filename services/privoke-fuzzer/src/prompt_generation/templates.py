from __future__ import annotations

import random

from . import vocabulary


def render_template(template: str, rng: random.Random) -> str:
    values = {
        "name": rng.choice(vocabulary.NAMES),
        "relative": rng.choice(vocabulary.RELATIVES),
        "condition": rng.choice(vocabulary.CONDITIONS),
        "medication": rng.choice(vocabulary.MEDICATIONS),
        "employer": rng.choice(vocabulary.EMPLOYERS),
        "city": rng.choice(vocabulary.CITIES),
        "bank": rng.choice(vocabulary.BANKS),
        "amount": rng.choice(vocabulary.AMOUNTS),
        "group": rng.choice(vocabulary.GROUPS),
        "public_place": rng.choice(vocabulary.PUBLIC_PLACES),
        "account": rng.choice(vocabulary.ACCOUNTS),
    }
    return template.format(**values)
