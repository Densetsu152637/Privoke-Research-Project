from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from training import BatchTrainingExample


@dataclass(frozen=True)
class PromptSeed:
    template: str
    sensitivity: str
    visibility: str
    categories: Tuple[str, ...] = ()
    metadata: Dict[str, str] = field(default_factory=dict)


def generate_training_prompts(
    count: int,
    seed: int,
    dataset_path: str | Path | None = None,
) -> List[BatchTrainingExample]:
    if count <= 0:
        return []

    rng = random.Random(seed)
    prompt_seeds = load_prompt_dataset(dataset_path)
    generated = []

    for index in range(count):
        prompt_seed = rng.choice(prompt_seeds)
        text = _render_template(prompt_seed.template, rng)
        metadata = dict(prompt_seed.metadata)
        metadata.update(
            {
                "generator": "prompt_generation",
                "generation_index": str(index),
                "generation_seed": str(seed),
            }
        )
        generated.append(
            BatchTrainingExample(
                text=text,
                sensitivity=prompt_seed.sensitivity,
                visibility=prompt_seed.visibility,
                categories=prompt_seed.categories,
                metadata=metadata,
            )
        )

    return generated


def load_prompt_dataset(
    dataset_path: str | Path | None = None,
) -> List[PromptSeed]:
    if dataset_path is None:
        return list(DEFAULT_PROMPT_DATASET)

    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Prompt dataset does not exist: {path}")

    if path.suffix.lower() == ".jsonl":
        items = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, Mapping):
            items = (
                payload.get("prompts")
                or payload.get("examples")
                or payload.get("data")
                or []
            )
        else:
            items = payload

    if not isinstance(items, list):
        raise ValueError("Prompt dataset must be a JSON array or JSONL file.")

    return [_prompt_seed_from_mapping(item) for item in items]


def _prompt_seed_from_mapping(item: Any) -> PromptSeed:
    if not isinstance(item, Mapping):
        raise ValueError("Prompt dataset entries must be objects.")

    template = item.get("template") or item.get("text") or item.get("prompt")
    if not isinstance(template, str) or not template.strip():
        raise ValueError("Prompt dataset entries need template/text/prompt.")

    classification = item.get("classification")
    if not isinstance(classification, Mapping):
        classification = {}

    return PromptSeed(
        template=template,
        sensitivity=_label(
            item.get("sensitivity") or classification.get("sensitivity"),
            "S0",
        ),
        visibility=_label(
            item.get("visibility") or classification.get("visibility"),
            "PU",
        ),
        categories=_categories(
            item.get("categories") or classification.get("categories")
        ),
        metadata={
            str(key): str(value)
            for key, value in item.get("metadata", {}).items()
        }
        if isinstance(item.get("metadata"), Mapping)
        else {},
    )


def _render_template(template: str, rng: random.Random) -> str:
    values = {
        "name": rng.choice(NAMES),
        "relative": rng.choice(RELATIVES),
        "condition": rng.choice(CONDITIONS),
        "medication": rng.choice(MEDICATIONS),
        "employer": rng.choice(EMPLOYERS),
        "city": rng.choice(CITIES),
        "bank": rng.choice(BANKS),
        "amount": rng.choice(AMOUNTS),
        "group": rng.choice(GROUPS),
        "public_place": rng.choice(PUBLIC_PLACES),
        "account": rng.choice(ACCOUNTS),
    }
    return template.format(**values)


def _label(value: Any, default: str) -> str:
    if not isinstance(value, str) or not value.strip():
        return default
    return value.strip().upper()


def _categories(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip().upper() for part in value.split(",") if part.strip())
    if isinstance(value, Sequence):
        return tuple(str(part).strip().upper() for part in value if str(part).strip())
    return ()


NAMES = (
    "John Doe",
    "Alex Smith",
    "Priya Patel",
    "Sam Nguyen",
    "Jordan Lee",
)
RELATIVES = ("wife", "husband", "partner", "coworker", "manager", "child")
CONDITIONS = ("anxiety", "depression", "diabetes", "cancer", "ptsd")
MEDICATIONS = ("insulin", "sertraline", "opioid medication", "adhd medication")
EMPLOYERS = ("Acme Robotics", "Northside Clinic", "Metro Bank", "City University")
CITIES = ("Sydney", "Melbourne", "Brisbane", "Newcastle", "Canberra")
BANKS = ("Metro Bank", "North Credit Union", "Riverline Finance")
AMOUNTS = ("$480", "$2,300", "$7,800", "$18,000")
GROUPS = ("private channel", "group chat", "members only forum", "locked account")
PUBLIC_PLACES = ("public post", "public profile", "conference bio", "news article")
ACCOUNTS = ("bank account", "loan application", "tax return", "credit score")


DEFAULT_PROMPT_DATASET: Tuple[PromptSeed, ...] = (
    PromptSeed(
        template="My {account} at {bank} is behind login and shows a balance of {amount}.",
        sensitivity="S2",
        visibility="P2",
        categories=("FINANCIAL",),
        metadata={"dataset": "default_financial"},
    ),
    PromptSeed(
        template="In a {group}, {name} said their {relative} was diagnosed with {condition}.",
        sensitivity="S3",
        visibility="P3",
        categories=("HEALTH", "THIRD_PARTY"),
        metadata={"dataset": "default_health_third_party"},
    ),
    PromptSeed(
        template="My doctor prescribed {medication} after my {condition} diagnosis.",
        sensitivity="S3",
        visibility="PU",
        categories=("HEALTH",),
        metadata={"dataset": "default_health"},
    ),
    PromptSeed(
        template="I work at {employer} and I am the only person in my role in {city}.",
        sensitivity="S2",
        visibility="PU",
        categories=("IDENTITY", "LOCATION"),
        metadata={"dataset": "default_identity_location"},
    ),
    PromptSeed(
        template="This is a {public_place} about a product launch in {city}.",
        sensitivity="S0",
        visibility="P0",
        categories=(),
        metadata={"dataset": "default_public"},
    ),
    PromptSeed(
        template="My private diary says I voted for a political party and left my religion.",
        sensitivity="S3",
        visibility="P4",
        categories=("POLITICS", "RELIGION"),
        metadata={"dataset": "default_beliefs"},
    ),
    PromptSeed(
        template="My {relative} has a court date after a dui charge.",
        sensitivity="S3",
        visibility="PU",
        categories=("CRIMINAL", "THIRD_PARTY"),
        metadata={"dataset": "default_criminal"},
    ),
    PromptSeed(
        template="The document says my home address is near my office in {city}.",
        sensitivity="S2",
        visibility="PU",
        categories=("LOCATION", "IDENTITY"),
        metadata={"dataset": "default_location"},
    ),
)
