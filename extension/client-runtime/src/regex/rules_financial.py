from typing import List

from .rule_types import Downgrade, RuleDefinition
from .rule_validators import (
    CARD_CONTEXT,
    IBAN_CONTEXT,
    alphanumeric_identifier_shape,
    checksum_validator,
    context_required_validator,
    iban_valid,
    luhn_valid,
    match_shape_validator,
)
from ..classification import Category, Sensitivity, Visibility, initialise_unpacked


def financial_rules() -> List[RuleDefinition]:
    """Financial account, transaction, debt, income, and asset rules."""
    return [
        RuleDefinition(
            "credit_card",
            r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
            initialise_unpacked(
                Sensitivity.S3,
                Visibility.PU,
                [Category.FINANCIAL, Category.IDENTITY],
            ),
            "credit_card",
            validator=checksum_validator(luhn_valid),
            downgrades=(
                # A card number that fails Luhn but is labelled as a card is still the
                # user's card (typos, test and synthetic numbers). Unlabelled digit runs
                # are left to the generic account-number patterns.
                Downgrade(
                    "credit_card_unverified",
                    initialise_unpacked(
                        Sensitivity.S3, Visibility.PU, [Category.FINANCIAL, Category.IDENTITY]
                    ),
                    "credit_card",
                    accept=context_required_validator(CARD_CONTEXT),
                ),
            ),
        ),
        RuleDefinition(
            "iban",
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.FINANCIAL]),
            "iban",
            validator=checksum_validator(iban_valid),
            downgrades=(
                Downgrade(
                    "iban_unverified",
                    initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.FINANCIAL]),
                    "iban",
                    accept=context_required_validator(IBAN_CONTEXT),
                ),
                # Not a valid IBAN, but still a long letter-prefixed number-like token.
                Downgrade(
                    "unverified_number_identifier",
                    initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.IDENTITY]),
                    "number_identifier",
                    accept=match_shape_validator(alphanumeric_identifier_shape),
                ),
            ),
        ),
        RuleDefinition(
            "bank_account",
            r"\b(?:bank\s+account|account\s+number|routing\s+number|sort\s+code)\s*(?:is|number is|[:#=])?\s*(?=[A-Z0-9\- ]{6,24}\b)(?=[A-Z0-9\- ]*\d)[A-Z0-9][A-Z0-9\- ]{5,23}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.FINANCIAL]),
            "bank_account",
        ),
        RuleDefinition(
            "swift_bic",
            r"\b(?:swift|bic|swift/bic)\s*[:#=]?\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "swift_bic",
        ),
        RuleDefinition(
            "crypto_wallet",
            r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "crypto_wallet",
        ),
        RuleDefinition(
            "salary_disclosure",
            r"\b(?:my|his|her|their|salary|income|paycheck|bonus)\s+(?:salary|income|paycheck|bonus|is|was|offer|of|=|:)\s*\$?\d[\d,]*(?:\.\d{2})?\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "salary_disclosure",
        ),
        RuleDefinition(
            "financial_keyword",
            r"\b(?:my|his|her|their)\s+(?:\w+\s+){0,2}(?:salary|income|bonus|loan|mortgage|debt|investment|stock|crypto|bitcoin|ethereum|tax|paycheck|transaction|balance|savings|net\s+worth|credit\s+(?:score|history|report))\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "financial_info",
        ),
        RuleDefinition(
            "money_amount",
            r"\b(?:(?:my|our|his|her|their)\b[^.!?;\n]{0,64}"
            r"|(?:i|we)\s+(?:earn|earned|spent|spend|paid|pay|owe|owed|saved)\b[^.!?;\n]{0,48}"
            r"|(?:salary|income|debt|balance|mortgage|paycheck)\s*[:=]\s*)"
            r"(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\s?(?:usd|aud|eur|gbp)\b)",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "money_amount",
        ),
    ]
