from typing import List

from .rule_types import RuleDefinition
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
        ),
        RuleDefinition(
            "iban",
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.FINANCIAL]),
            "iban",
        ),
        RuleDefinition(
            "bank_account",
            r"\b(?:bank\s+account|account\s+number|routing\s+number|sort\s+code)\s*[:#=]?\s*[A-Z0-9\- ]{6,24}\b",
            initialise_unpacked(Sensitivity.S3, Visibility.PU, [Category.FINANCIAL]),
            "bank_account",
        ),
        RuleDefinition(
            "financial_keyword",
            r"\b(salary|income|bonus|bank|account|credit|loan|mortgage|debt|investment|stock|crypto|bitcoin|ethereum|tax|paycheck|transaction|balance)\b",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "financial_info",
        ),
        RuleDefinition(
            "money_amount",
            r"(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\s?(?:usd|aud|eur|gbp)\b)",
            initialise_unpacked(Sensitivity.S2, Visibility.PU, [Category.FINANCIAL]),
            "money_amount",
        ),
    ]
