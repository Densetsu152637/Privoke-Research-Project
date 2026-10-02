from __future__ import annotations

from privoke_contracts.classification import Category, Sensitivity, Visibility
from training.classifications import classification_from_components

from .types import PromptSeed


def default_prompt_dataset() -> tuple[PromptSeed, ...]:
    challenge_seeds = (
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

    # Independently labeled calibration examples also used by bootstrap training.
    # They make mixed easy/challenging adaptive cycles useful; held-out checks
    # establish current-cycle safety, not generalization beyond bootstrap data.
    calibration = (
        ("this was posted publicly for everyone", "S0", "P0", ()),
        ("discussion in a public community forum", "S0", "P1", ()),
        ("the page is restricted behind login", "S0", "P2", ()),
        ("I sent this in a private group chat", "S0", "P3", ()),
        ("this is a private diary for my eyes only", "S0", "P4", ()),
        ("explain privacy using imaginary placeholders", "S0", "PU", ()),
        ("write a friendly email about tomorrow's meeting", "S0", "PU", ()),
        ("summarise this public product documentation", "S0", "P0", ()),
        ("what is the weather forecast", "S0", "PU", ()),
        ("help me format a generic travel checklist", "S0", "PU", ()),
        ("my diagnosis is cancer", "S3", "PU", ("HEALTH",)),
        ("my therapist prescribed medication", "S3", "PU", ("HEALTH",)),
        ("I am pregnant and have anxiety", "S3", "PU", ("HEALTH",)),
        ("my bank account and mortgage debt", "S2", "PU", ("FINANCIAL",)),
        ("my salary and credit score", "S2", "PU", ("FINANCIAL",)),
        ("I filed a tax return", "S2", "PU", ("FINANCIAL",)),
    )
    return challenge_seeds + tuple(
        PromptSeed(
            template=text,
            classification=classification_from_components(
                Sensitivity[sensitivity], Visibility[visibility],
                [Category[name] for name in categories],
            ),
            metadata={"dataset": "bootstrap_calibration"},
        )
        for text, sensitivity, visibility, categories in calibration
    )
