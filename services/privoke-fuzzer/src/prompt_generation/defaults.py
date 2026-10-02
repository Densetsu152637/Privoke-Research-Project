from __future__ import annotations

from privoke_contracts.classification import Category, Sensitivity, Visibility
from training.classifications import classification_from_components

from .types import PromptSeed


def default_prompt_dataset() -> tuple[PromptSeed, ...]:
    return (
        PromptSeed(
            template=(
                "My {account} at {bank} is behind login and shows a balance "
                "of {amount}."
            ),
            classification=classification_from_components(
                Sensitivity.S2,
                Visibility.P2,
                [Category.FINANCIAL],
            ),
            metadata={"dataset": "default_financial"},
        ),
        PromptSeed(
            template=(
                "In a {group}, {name} said their {relative} was diagnosed "
                "with {condition}."
            ),
            classification=classification_from_components(
                Sensitivity.S3,
                Visibility.P3,
                [Category.HEALTH, Category.THIRD_PARTY],
            ),
            metadata={"dataset": "default_health_third_party"},
        ),
        PromptSeed(
            template="My doctor prescribed {medication} after my {condition} diagnosis.",
            classification=classification_from_components(
                Sensitivity.S3,
                Visibility.PU,
                [Category.HEALTH],
            ),
            metadata={"dataset": "default_health"},
        ),
        PromptSeed(
            template=(
                "I work at {employer} and I am the only person in my role in {city}."
            ),
            classification=classification_from_components(
                Sensitivity.S2,
                Visibility.PU,
                [Category.IDENTITY, Category.LOCATION],
            ),
            metadata={"dataset": "default_identity_location"},
        ),
        PromptSeed(
            template="This is a {public_place} about a product launch in {city}.",
            classification=classification_from_components(
                Sensitivity.S0,
                Visibility.P0,
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
                Sensitivity.S3,
                Visibility.P4,
                [Category.POLITICS, Category.RELIGION],
            ),
            metadata={"dataset": "default_beliefs"},
        ),
        PromptSeed(
            template="My {relative} has a court date after a dui charge.",
            classification=classification_from_components(
                Sensitivity.S3,
                Visibility.PU,
                [Category.CRIMINAL, Category.THIRD_PARTY],
            ),
            metadata={"dataset": "default_criminal"},
        ),
        PromptSeed(
            template="The document says my home address is near my office in {city}.",
            classification=classification_from_components(
                Sensitivity.S2,
                Visibility.PU,
                [Category.LOCATION, Category.IDENTITY],
            ),
            metadata={"dataset": "default_location"},
        ),
    )
