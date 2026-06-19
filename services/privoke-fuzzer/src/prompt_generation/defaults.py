from __future__ import annotations

from typing import Tuple

from training.classifications import classification_from_components, classification_module

from .types import PromptSeed


def default_prompt_dataset() -> Tuple[PromptSeed, ...]:
    client_types = classification_module()
    sensitivity = client_types.Sensitivity
    visibility = client_types.Visibility
    category = client_types.Category

    return (
        PromptSeed(
            template=(
                "My {account} at {bank} is behind login and shows a balance "
                "of {amount}."
            ),
            classification=classification_from_components(
                sensitivity.S2,
                visibility.P2,
                [category.FINANCIAL],
            ),
            metadata={"dataset": "default_financial"},
        ),
        PromptSeed(
            template=(
                "In a {group}, {name} said their {relative} was diagnosed "
                "with {condition}."
            ),
            classification=classification_from_components(
                sensitivity.S3,
                visibility.P3,
                [category.HEALTH, category.THIRD_PARTY],
            ),
            metadata={"dataset": "default_health_third_party"},
        ),
        PromptSeed(
            template="My doctor prescribed {medication} after my {condition} diagnosis.",
            classification=classification_from_components(
                sensitivity.S3,
                visibility.PU,
                [category.HEALTH],
            ),
            metadata={"dataset": "default_health"},
        ),
        PromptSeed(
            template=(
                "I work at {employer} and I am the only person in my role "
                "in {city}."
            ),
            classification=classification_from_components(
                sensitivity.S2,
                visibility.PU,
                [category.IDENTITY, category.LOCATION],
            ),
            metadata={"dataset": "default_identity_location"},
        ),
        PromptSeed(
            template="This is a {public_place} about a product launch in {city}.",
            classification=classification_from_components(
                sensitivity.S0,
                visibility.P0,
                [],
            ),
            metadata={"dataset": "default_public"},
        ),
        PromptSeed(
            template=(
                "My private diary says I voted for a political party and "
                "left my religion."
            ),
            classification=classification_from_components(
                sensitivity.S3,
                visibility.P4,
                [category.POLITICS, category.RELIGION],
            ),
            metadata={"dataset": "default_beliefs"},
        ),
        PromptSeed(
            template="My {relative} has a court date after a dui charge.",
            classification=classification_from_components(
                sensitivity.S3,
                visibility.PU,
                [category.CRIMINAL, category.THIRD_PARTY],
            ),
            metadata={"dataset": "default_criminal"},
        ),
        PromptSeed(
            template="The document says my home address is near my office in {city}.",
            classification=classification_from_components(
                sensitivity.S2,
                visibility.PU,
                [category.LOCATION, category.IDENTITY],
            ),
            metadata={"dataset": "default_location"},
        ),
    )
