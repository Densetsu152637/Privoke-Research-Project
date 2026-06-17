"""
Rule-Based Detector for PriVoke Phase 1.

Fast regex-based pattern matching for common PII and sensitive data. Rules are
defined in terms of classification.py enums and produce Classification objects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Pattern, Sequence, Tuple

from classification import (
    Category,
    Classification,
    Sensitivity,
    Visibility,
    dedupe_categories,
    initialise_unpacked,
    merge_classifications,
)


@dataclass(frozen=True)
class RuleDefinition:
    """A regex rule mapped to a classification category."""

    name: str
    pattern: str
    sensitivity: Sensitivity
    visibility: Visibility
    categories: Sequence[Category]
    signal: str
    flags: int = re.IGNORECASE

    def compile(self) -> "CompiledRule":
        return CompiledRule(
            name=self.name,
            pattern=re.compile(self.pattern, self.flags),
            sensitivity=self.sensitivity,
            visibility=self.visibility,
            categories=tuple(self.categories),
            signal=self.signal,
        )


@dataclass(frozen=True)
class CompiledRule:
    """Compiled version of a rule definition."""

    name: str
    pattern: Pattern[str]
    sensitivity: Sensitivity
    visibility: Visibility
    categories: Sequence[Category]
    signal: str


@dataclass(frozen=True)
class RuleMatch:
    """One rule hit and its enum-backed classification."""

    rule_name: str
    signal: str
    text: str
    span: Tuple[int, int]
    classification: Classification

    def to_dict(self) -> Dict:
        return {
            "rule_name": self.rule_name,
            "signal": self.signal,
            "text": self.text,
            "span": self.span,
            "sensitivity": self.classification.sensitivity().name,
            "visibility": self.classification.visibility().name,
            "categories": [
                category.name for category in self.classification.categories()
            ],
            "packed_classification": self.classification.pack(),
        }


def _classification_for_rule(rule: CompiledRule) -> Classification:
    return initialise_unpacked(
        rule.sensitivity,
        rule.visibility,
        list(rule.categories),
    )


def _signals(matches: Sequence[RuleMatch]) -> List[str]:
    signals = [match.signal for match in matches]
    return list(dict.fromkeys(signals))


def _rule_definitions() -> List[RuleDefinition]:
    """Define rule regexes once, with classification metadata beside them."""
    return [
        # IDENTITY: direct identifiers and account handles.
        RuleDefinition(
            "email",
            r"\b[\w\.-]+@[\w\.-]+\.\w+\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "email",
        ),
        RuleDefinition(
            "phone_us",
            r"(\+?1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "phone",
        ),
        RuleDefinition(
            "phone_intl",
            r"\+\d{1,3}([\s\-]?\d{2,4}){2,3}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "phone",
        ),
        RuleDefinition(
            "ssn_formatted",
            r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "ssn",
        ),
        RuleDefinition(
            "passport",
            r"\b(?:passport|pass(?:port)? no\.?|passport number)\s*[:#=]?\s*[A-Z]{1,2}\d{6,9}\b|\b[A-Z]{1,2}\d{6,9}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "passport",
        ),
        RuleDefinition(
            "driver_license",
            r"\b(?:driver'?s?\s+licen[cs]e|dl)\s*[:#=]?\s*[A-Z0-9\-]{5,15}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "driver_license",
        ),
        RuleDefinition(
            "government_id",
            r"\b(?:national\s+id|tax\s+id|tin|id\s+number|identity\s+number)\s*[:#=]?\s*[A-Z0-9\-]{5,20}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.IDENTITY],
            "government_id",
        ),
        RuleDefinition(
            "social_handle",
            r"(?<![a-zA-Z0-9.])@[\w\-\.]{2,}(?![a-zA-Z0-9_])",
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
            "social_handle",
        ),
        RuleDefinition(
            "structured_identity",
            r"\b(name|username|user|handle|account|login|email|phone|location|address)\s*[:=]\s*[\w\s\.\-@]+",
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
            "structured_field",
        ),
        RuleDefinition(
            "date_field",
            r"\b(birth[\s_]?date|dob|date[\s_]?of[\s_]?birth|birthday|born|age)\s*[:=]?\s*[\d\s\/-]+",
            Sensitivity.S2,
            Visibility.PU,
            [Category.IDENTITY],
            "date_field",
        ),

        # LOCATION: exact places, addresses, and route-like disclosures.
        RuleDefinition(
            "street_address",
            r"\b\d{1,6}\s+[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,4}\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|drive|dr|lane|ln|court|ct|way|terrace|pl|place)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.LOCATION],
            "street_address",
        ),
        RuleDefinition(
            "geo_coordinates",
            r"\b-?\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.LOCATION],
            "geo_coordinates",
        ),
        RuleDefinition(
            "location_keyword",
            r"\b(live|lives|living|located|from|address|hometown|residence|staying|alone tonight)\s*(?:in|at|near)?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?",
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
            "location",
        ),
        RuleDefinition(
            "route_or_commute",
            r"\b(?:commute|route|walk|drive|bus|train)\s+(?:from|to|between)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            Sensitivity.S2,
            Visibility.PU,
            [Category.LOCATION],
            "route_location",
        ),

        # HEALTH: physical and mental health disclosures.
        RuleDefinition(
            "health_keyword",
            r"\b(hospital|doctor|medication|medicine|prescription|disease|cancer|diabetes|depression|anxiety|therapy|psychiatric|diagnosis|prognosis|allergy|symptom|treatment|pregnan(?:t|cy)|hiv|aids|autism|adhd)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.HEALTH],
            "health_info",
        ),
        RuleDefinition(
            "health_statement",
            r"\b(?:i|my|he|she|they)\s+(?:have|has|had|take|takes|was diagnosed with|am diagnosed with|suffer from)\s+(?:medication|medicine|prescription|cancer|diabetes|depression|anxiety|therapy|diagnosis|allergy|symptom|treatment|hiv|aids|autism|adhd|ptsd|bipolar|asthma)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.HEALTH],
            "health_disclosure",
        ),

        # FINANCIAL: accounts, cards, debts, income, and investments.
        RuleDefinition(
            "credit_card",
            r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.FINANCIAL, Category.IDENTITY],
            "credit_card",
        ),
        RuleDefinition(
            "iban",
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.FINANCIAL],
            "iban",
        ),
        RuleDefinition(
            "bank_account",
            r"\b(?:bank\s+account|account\s+number|routing\s+number|sort\s+code)\s*[:#=]?\s*[A-Z0-9\- ]{6,24}\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.FINANCIAL],
            "bank_account",
        ),
        RuleDefinition(
            "financial_keyword",
            r"\b(salary|income|bonus|bank|account|credit|loan|mortgage|debt|investment|stock|crypto|bitcoin|ethereum|tax|paycheck|transaction|balance)\b",
            Sensitivity.S2,
            Visibility.PU,
            [Category.FINANCIAL],
            "financial_info",
        ),
        RuleDefinition(
            "money_amount",
            r"(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\s?(?:usd|aud|eur|gbp)\b)",
            Sensitivity.S2,
            Visibility.PU,
            [Category.FINANCIAL],
            "money_amount",
        ),

        # PDPA and harm-sensitive categories beyond direct identifiers.
        RuleDefinition(
            "politics",
            r"\b(voted?\s+for|political\s+(?:party|view|belief|campaign)|democrat|republican|labor party|liberal party|conservative|socialist|communist|activist|protest(?:ed|ing)?|union member)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.POLITICS],
            "political_info",
        ),
        RuleDefinition(
            "religion",
            r"\b(christian|muslim|islam|jewish|judaism|hindu|buddhist|atheist|agnostic|church|mosque|synagogue|temple|priest|pastor|imam|rabbi|religion|faith|prayer group)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.RELIGION],
            "religious_info",
        ),
        RuleDefinition(
            "criminal",
            r"\b(arrest(?:ed)?|convict(?:ed|ion)|felony|misdemeanor|probation|parole|criminal\s+record|charged\s+with|court\s+case|restraining\s+order)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.CRIMINAL],
            "criminal_info",
        ),
        RuleDefinition(
            "sexual",
            r"\b(sexual\s+(?:orientation|history)|gay|lesbian|bisexual|transgender|queer|lgbtq|dating\s+profile|intimate|pregnancy termination|abortion)\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.SEXUAL],
            "sexual_info",
        ),
        RuleDefinition(
            "child",
            r"\b(?:my\s+)?(?:child|children|kid|kids|son|daughter|minor|underage|schoolchild|student)\b|\b(?:age|aged)\s+(?:[1-9]|1[0-7])\b",
            Sensitivity.S3,
            Visibility.PU,
            [Category.CHILD],
            "child_info",
        ),
        RuleDefinition(
            "third_party_disclosure",
            r"\b(?:my|his|her|their)\s+(?:spouse|husband|wife|partner|boyfriend|girlfriend|child|son|daughter|mother|father|friend|coworker|colleague|boss|employee)\b",
            Sensitivity.S2,
            Visibility.PU,
            [Category.THIRD_PARTY],
            "third_party_info",
        ),

        # Context that can combine with other matches.
        RuleDefinition(
            "family_disclosure",
            r"\b(spouse|husband|wife|partner|boyfriend|girlfriend|children|kids|son|daughter|mother|father|siblings?|family)\b",
            Sensitivity.S2,
            Visibility.PU,
            [Category.THIRD_PARTY],
            "family_info",
        ),
        RuleDefinition(
            "workplace_keyword",
            r"\b(work(?:s|ing)?|employ(?:ee|er|ment)|company|office|boss|colleague|manager|department)\b",
            Sensitivity.S1,
            Visibility.PU,
            [Category.IDENTITY],
            "workplace_info",
        ),
        RuleDefinition(
            "timestamp_field",
            r"\b(timestamp|visited|accessed|logged|created|modified|updated|date|time)\s*[:=]\s*[\d\s\-/:T.Z]+",
            Sensitivity.S1,
            Visibility.PU,
            [Category.IDENTITY],
            "timestamp",
        ),
    ]


class RuleDetector:
    """
    Pattern-based detector using regex rules for common sensitive categories.
    """

    def __init__(self):
        self.rules = [definition.compile() for definition in _rule_definitions()]
        self.patterns = {rule.name: rule.pattern.pattern for rule in self.rules}

    def analyze(self, text: str) -> Dict:
        """
        Analyze text and return structured enum-backed classification details.

        Returns:
            classification: merged Classification object
            packed_classification: 16-bit packed classification
            matches: list[RuleMatch]
            match_details: JSON-friendly match dictionaries
            signals: ordered list of matched rule signal names
        """
        matches = self._collect_matches(text)
        matches.extend(self._heuristic_matches(text, matches))

        matches = self._dedupe_matches(matches)
        classification = merge_classifications(
            match.classification for match in matches
        )

        return {
            "classification": classification,
            "packed_classification": classification.pack(),
            "matches": matches,
            "match_details": [match.to_dict() for match in matches],
            "signals": _signals(matches),
        }

    def _collect_matches(self, text: str) -> List[RuleMatch]:
        matches = []
        for rule in self.rules:
            for regex_match in rule.pattern.finditer(text):
                matches.append(
                    RuleMatch(
                        rule_name=rule.name,
                        signal=rule.signal,
                        text=regex_match.group(0),
                        span=regex_match.span(),
                        classification=_classification_for_rule(rule),
                    )
                )
        return matches

    def _heuristic_matches(
        self,
        text: str,
        matches: Sequence[RuleMatch],
    ) -> List[RuleMatch]:
        heuristic_matches = []
        word_count = len(text.split())

        if word_count > 80:
            heuristic_matches.append(
                self._synthetic_match(
                    "personal_narrative",
                    f"long_personal_narrative({word_count}_words)",
                    "",
                    (0, min(len(text), 1)),
                    Sensitivity.S1,
                    Visibility.PU,
                    [Category.IDENTITY],
                )
            )

        identity_field_count = len(
            re.findall(
                r"\b(name|email|phone|username|location|address)\s*[:=]\s*",
                text,
                re.IGNORECASE,
            )
        )
        if identity_field_count >= 2:
            heuristic_matches.append(
                self._synthetic_match(
                    "multiple_identity_fields",
                    f"multiple_identity_fields({identity_field_count})",
                    "",
                    (0, 0),
                    Sensitivity.S2,
                    Visibility.PU,
                    [Category.IDENTITY],
                )
            )

        high_confidence_matches = [
            match
            for match in matches
            if match.classification.sensitivity() == Sensitivity.S3
        ]
        if word_count < 10 and high_confidence_matches:
            categories = dedupe_categories(
                category
                for match in high_confidence_matches
                for category in match.classification.categories()
            )
            heuristic_matches.append(
                self._synthetic_match(
                    "concentrated_sensitive_data",
                    "concentrated_pii",
                    "",
                    (0, len(text)),
                    Sensitivity.S2,
                    Visibility.PU,
                    categories,
                )
            )

        return heuristic_matches

    def _synthetic_match(
        self,
        rule_name: str,
        signal: str,
        text: str,
        span: Tuple[int, int],
        sensitivity: Sensitivity,
        visibility: Visibility,
        categories: Sequence[Category],
    ) -> RuleMatch:
        return RuleMatch(
            rule_name=rule_name,
            signal=signal,
            text=text,
            span=span,
            classification=initialise_unpacked(
                sensitivity,
                visibility,
                list(categories),
            ),
        )

    def _dedupe_matches(self, matches: Sequence[RuleMatch]) -> List[RuleMatch]:
        seen = set()
        deduped = []
        for match in matches:
            key = (match.rule_name, match.signal, match.span, match.text)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(match)
        return deduped
