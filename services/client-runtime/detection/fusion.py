"""
Fusion Engine for PriVoke Phase 1.

Combines rule, LLM, and NER detector outputs into a single Classification.
Internal decisions use classification.py enums instead of category/severity
strings.
"""

from typing import Dict, List, Tuple

from classification import (
    Category,
    Classification,
    DataType,
    Sensitivity,
    Visibility,
    dedupe_categories,
    describe_categories,
    initialise_unpacked,
    merge_classifications,
    sensitivity_score,
)


DIRECT_RULE_SIGNALS = {
    "email",
    "phone",
    "ssn",
    "credit_card",
    "passport",
    "driver_license",
    "government_id",
    "bank_account",
    "iban",
    "street_address",
    "geo_coordinates",
}

AUTH_RULE_SIGNALS = {
    "structured_field",
    "driver_license",
    "government_id",
    "passport",
}

CONTEXTUAL_RULE_SIGNALS = {
    "health_info",
    "health_disclosure",
    "financial_info",
    "money_amount",
    "political_info",
    "religious_info",
    "criminal_info",
    "sexual_info",
    "child_info",
    "third_party_info",
    "family_info",
    "workplace_info",
    "long_personal_narrative",
}


class FusionEngine:
    """
    Fuses detector outputs into one Classification and risk score.

    Weighting scheme:
    - Rule classification: 50%
    - LLM classification: 30%
    - Entity boost: 20%
    """

    def fuse(
        self,
        rule_result: Dict,
        llm_result: Dict,
        ner_result: Dict | None = None,
    ) -> Dict:
        if ner_result is None:
            ner_result = {}

        rule_classification = self._classification_from_result(rule_result)
        llm_classification = self._classification_from_result(llm_result)
        entity_flags = self._entity_flags(llm_result, ner_result)
        entity_classification = self._classification_from_entities(entity_flags)

        entity_boost = self._entity_boost(entity_flags)
        if self._has_sensitive_disagreement(rule_classification, llm_classification):
            entity_boost = max(entity_boost, 1.5)

        weighted_score = (
            sensitivity_score(rule_classification.sensitivity()) * 0.5
            + sensitivity_score(llm_classification.sensitivity()) * 0.3
            + entity_boost * 0.2
        )
        merged_context = merge_classifications(
            [rule_classification, llm_classification, entity_classification]
        )
        final_sensitivity = max(
            self._score_to_sensitivity(weighted_score),
            merged_context.sensitivity(),
            key=sensitivity_score,
        )
        final_classification = initialise_unpacked(
            final_sensitivity,
            merged_context.visibility(),
            merged_context.categories(),
        )

        data_type, data_type_reason = self._classify_data_type(
            rule_result,
            final_classification,
            entity_flags,
        )

        signals_used = self._signals_used(rule_result, llm_result, entity_flags, entity_boost)

        return {
            "classification": final_classification,
            "packed_classification": final_classification.pack(),
            "data_type": data_type,
            "data_type_explanation": {
                "reason": data_type_reason,
                "signals_used": signals_used,
                "entity_boost_applied": round(entity_boost, 2),
            },
            "raw_score": min(3.0, weighted_score) / 3.0,
            "risk_score_details": {
                "rule_contribution": sensitivity_score(rule_classification.sensitivity()) * 0.5,
                "llm_contribution": sensitivity_score(llm_classification.sensitivity()) * 0.3,
                "entity_contribution": entity_boost * 0.2,
            },
            "rule": rule_result,
            "llm": llm_result,
            "ner": ner_result if ner_result else None,
            "detector_confidence": {
                "rule_classification": rule_classification.to_dict(),
                "llm_classification": llm_classification.to_dict(),
                "entity_classification": entity_classification.to_dict(),
                "entity_boost": round(entity_boost, 2),
            },
        }

    def _classification_from_result(self, result: Dict) -> Classification:
        classification = result.get("classification")
        if isinstance(classification, Classification):
            return classification
        return initialise_unpacked(Sensitivity.S0, Visibility.PU, [])

    def _entity_flags(self, llm_result: Dict, ner_result: Dict) -> Dict[str, bool]:
        llm_entities = llm_result.get("entities", {})
        if not isinstance(llm_entities, dict):
            llm_entities = {}

        ner_summary = ner_result.get("entity_summary", {}) if ner_result else {}

        return {
            "email": bool(llm_entities.get("email") or ner_summary.get("has_email")),
            "phone": bool(llm_entities.get("phone") or ner_summary.get("has_phone")),
            "location": bool(llm_entities.get("location") or ner_summary.get("has_location")),
            "username": bool(llm_entities.get("username") or ner_summary.get("has_username")),
            "name": bool(llm_entities.get("name") or ner_summary.get("has_name")),
            "credit_card": bool(
                llm_entities.get("credit_card") or ner_summary.get("has_credit_card")
            ),
            "ssn": bool(llm_entities.get("ssn") or ner_summary.get("has_ssn")),
            "api_key": bool(llm_entities.get("api_key")),
        }

    def _classification_from_entities(self, entity_flags: Dict[str, bool]) -> Classification:
        categories: List[Category] = []
        sensitivity = Sensitivity.S0

        if entity_flags["credit_card"]:
            categories.extend([Category.FINANCIAL, Category.IDENTITY])
            sensitivity = Sensitivity.S3
        if entity_flags["ssn"] or entity_flags["api_key"]:
            categories.append(Category.IDENTITY)
            sensitivity = Sensitivity.S3
        if entity_flags["email"] or entity_flags["phone"]:
            categories.append(Category.IDENTITY)
            sensitivity = max(sensitivity, Sensitivity.S3, key=sensitivity_score)
        if entity_flags["name"] or entity_flags["username"]:
            categories.append(Category.IDENTITY)
            sensitivity = max(sensitivity, Sensitivity.S2, key=sensitivity_score)
        if entity_flags["location"]:
            categories.append(Category.LOCATION)
            sensitivity = max(sensitivity, Sensitivity.S2, key=sensitivity_score)

        return initialise_unpacked(
            sensitivity,
            Visibility.PU,
            dedupe_categories(categories),
        )

    def _entity_boost(self, entity_flags: Dict[str, bool]) -> float:
        email = entity_flags["email"]
        phone = entity_flags["phone"]
        location = entity_flags["location"]
        username = entity_flags["username"]
        name = entity_flags["name"]
        credit_card = entity_flags["credit_card"]
        ssn = entity_flags["ssn"]
        api_key = entity_flags["api_key"]

        if (credit_card or ssn) and (name or email):
            return 3.0
        if email and phone and name:
            return 3.0
        if name and location and email:
            return 3.0
        if credit_card or ssn or api_key:
            return 2.5
        if (name and location) or (username and location) or (email and phone):
            return 2.0
        if email or phone:
            return 1.8
        if (name and username) or (location and username):
            return 1.5
        if name:
            return 1.3
        if location or username:
            return 1.1
        return 1.0

    def _has_sensitive_disagreement(
        self,
        rule_classification: Classification,
        llm_classification: Classification,
    ) -> bool:
        rule_sensitive = rule_classification.is_sensitive()
        llm_sensitive = llm_classification.is_sensitive()
        if rule_sensitive != llm_sensitive:
            return True
        if not rule_sensitive:
            return False
        rule_categories = set(rule_classification.categories())
        llm_categories = set(llm_classification.categories())
        return bool(rule_categories and llm_categories and not rule_categories & llm_categories)

    def _score_to_sensitivity(self, score: float) -> Sensitivity:
        level = int(min(3.0, max(0.0, score)) + 0.5)
        return Sensitivity(level)

    def _classify_data_type(
        self,
        rule_result: Dict,
        classification: Classification,
        entity_flags: Dict[str, bool],
    ) -> Tuple[DataType, str]:
        rule_signals = set(rule_result.get("signals", []))
        categories = set(classification.categories())

        if self._has_direct_entity(entity_flags) or rule_signals & DIRECT_RULE_SIGNALS:
            return (
                DataType.DIRECT_PII,
                "Direct identifiers or precise location data detected",
            )

        if rule_signals & AUTH_RULE_SIGNALS:
            return (
                DataType.AUTH,
                "Structured identity or credential metadata detected",
            )

        if self._has_quasi_identifier_combination(entity_flags):
            return (
                DataType.QUASI_PII,
                "Combination of quasi-identifiers enables probable identification",
            )

        contextual_categories = {
            Category.HEALTH,
            Category.POLITICS,
            Category.RELIGION,
            Category.CRIMINAL,
            Category.FINANCIAL,
            Category.SEXUAL,
            Category.CHILD,
            Category.THIRD_PARTY,
        }
        if categories & contextual_categories or rule_signals & CONTEXTUAL_RULE_SIGNALS:
            return (
                DataType.CONTEXTUAL,
                f"Contextual sensitive category detected: {describe_categories(categories)}",
            )

        if categories:
            return (
                DataType.QUASI_PII,
                f"Identifier category detected: {describe_categories(categories)}",
            )

        return (DataType.NORMAL, "No strong privacy risk indicators detected")

    def _has_direct_entity(self, entity_flags: Dict[str, bool]) -> bool:
        return any(
            entity_flags[key]
            for key in ["email", "phone", "credit_card", "ssn", "api_key"]
        )

    def _has_quasi_identifier_combination(self, entity_flags: Dict[str, bool]) -> bool:
        return (
            (entity_flags["name"] and entity_flags["location"])
            or (entity_flags["username"] and entity_flags["location"])
            or (entity_flags["name"] and entity_flags["username"])
        )

    def _signals_used(
        self,
        rule_result: Dict,
        llm_result: Dict,
        entity_flags: Dict[str, bool],
        entity_boost: float,
    ) -> List[str]:
        signals = list(rule_result.get("signals", []))
        signals.extend(key for key, value in entity_flags.items() if value)

        if entity_boost >= 2.5:
            signals.append("critical_combination")
        elif entity_boost >= 1.5:
            signals.append("high_combination")

        implicit_risks = llm_result.get("implicit_risks", [])
        if isinstance(implicit_risks, list):
            signals.extend(implicit_risks[:3])

        return list(dict.fromkeys(signals))
