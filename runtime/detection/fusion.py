"""
Fusion Engine for PriVoke Phase 1

Combines outputs from:
- Rule-Based Detector
- LLM Semantic Classifier
- Entity/NER Detector

Produces weighted final risk score and categorization.
Uses domain-aware heuristics for accuracy across all privacy-sensitive datasets.
"""

from typing import Dict, Optional


class FusionEngine:
    """
    Fuses multiple detector outputs into a single authoritative risk decision.
    
    Weighting scheme:
    - Rule (pattern-based): 50% - Fast, reliable, high precision
    - LLM (semantic): 30% - Flexible, contextual, catches implicit risks
    - Entity (NER): 20% - Structural signals, entity combinations
    
    Risk elevation rules apply entity boost for combinations.
    """

    def __init__(self):
        """Initialize severity ranking system."""
        self.severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        self.inv_rank = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}

    def fuse(
        self,
        rule_result: Dict,
        llm_result: Dict,
        ner_result: Optional[Dict] = None
    ) -> Dict:
        """
        Fuse multiple detector outputs into final risk assessment.
        
        Args:
            rule_result: Output from RuleDetector
            llm_result: Output from LLMClassifier (parsed JSON)
            ner_result: Output from EntityNERDetector (optional)
        
        Returns:
            Fused output with final category, severity, data type, and risk score
        """
        
        if ner_result is None:
            ner_result = {}
        
        # ========================================
        # SEVERITY SCORES (1-3 scale)
        # ========================================
        
        rule_sev = self.severity_rank.get(rule_result.get("severity", "LOW"), 1) # Default to LOW if not provided
        llm_sev = self.severity_rank.get(llm_result.get("severity", "LOW"), 1) # Default to LOW if not provided
        
        # ========================================
        # ENTITY EXTRACTION
        # ========================================
        
        entities = llm_result.get("entities", {})
        if not isinstance(entities, dict):
            entities = {}
        
        # Extract entity flags
        email = bool(entities.get("email"))
        phone = bool(entities.get("phone"))
        location = bool(entities.get("location"))
        username = bool(entities.get("username"))
        name = bool(entities.get("name"))
        credit_card = bool(entities.get("credit_card"))
        ssn = bool(entities.get("ssn"))
        api_key = bool(entities.get("api_key"))
        
        # Merge with NER results if available
        ner_summary = ner_result.get("entity_summary", {})
        email = email or ner_summary.get("has_email", False)
        phone = phone or ner_summary.get("has_phone", False)
        location = location or ner_summary.get("has_location", False)
        username = username or ner_summary.get("has_username", False)
        name = name or ner_summary.get("has_name", False)
        credit_card = credit_card or ner_summary.get("has_credit_card", False)
        ssn = ssn or ner_summary.get("has_ssn", False)
        
        # ========================================
        # ENTITY BOOST (Risk elevation for combinations)
        # ========================================
        
        entity_boost = 1.0  # Baseline multiplier
        
        # CRITICAL COMBINATIONS (3.0x boost = HIGH severity)
        if (credit_card or ssn) and (name or email):
            entity_boost = 3.0  # Credential + identity = critical
        elif email and phone and name:
            entity_boost = 3.0  # Full contact profile + name = critical
        elif name and location and email:
            entity_boost = 3.0  # Full identifying profile
        
        # HIGH COMBINATIONS (2.5x boost)
        elif credit_card or ssn or api_key:
            entity_boost = 2.5  # Sensitive credentials alone
        elif (name or email or phone) and (credit_card or ssn):
            entity_boost = 2.5  # Any credential combo
        
        # MEDIUM-HIGH COMBINATIONS (2.0x boost)
        elif (name and location) or (username and location) or (email and phone):
            entity_boost = 2.0  # Two quasi-identifiers
        elif email or phone:
            entity_boost = 1.8  # Direct contact info
        
        # MEDIUM COMBINATIONS (1.5x boost)
        elif (name and username) or (location and username):
            entity_boost = 1.5  # Identity + social identity
        elif name or api_key:
            entity_boost = 1.3  # Single strong identifier
        
        # LOW COMBINATIONS (1.0x - no boost)
        elif location or username:
            entity_boost = 1.1  # Weak quasi-identifiers
        
        # ========================================
        # DISAGREEMENT ADJUSTMENT
        # ========================================
        
        rule_cat = rule_result.get("category", "NORMAL")
        llm_cat = llm_result.get("category", "NORMAL")
        
        # Normalize CREDENTIAL to PII (credential is a type of PII)
        rule_cat_normalized = "PII" if rule_cat == "CREDENTIAL" else rule_cat
        llm_cat_normalized = "PII" if llm_cat == "CREDENTIAL" else llm_cat
        
        # If rule and LLM disagree and one says PII, elevate severity
        # (but treat CREDENTIAL as PII - they're compatible)
        if rule_cat_normalized != llm_cat_normalized and ("PII" in [rule_cat_normalized, llm_cat_normalized]):
            entity_boost = max(entity_boost, 1.5)
        
        # ========================================
        # FINAL RISK SCORE CALCULATION
        # ========================================
        
        # Weighted average: Rule 50% + LLM 30% + Entity Boost 20%
        # Entity boost is treated as an additional severity multiplier
        weighted_score = (rule_sev * 0.5) + (llm_sev * 0.3) + (entity_boost * 0.2)
        
        # Clamp to valid range and normalize
        final_score_clamped = min(3.0, weighted_score)
        normalized_score = final_score_clamped / 3.0  # Normalize to 0-1 for telemetry
        
        # Round to severity level for enforcement decision
        final_severity_level = round(final_score_clamped)
        final_severity_level = max(1, min(final_severity_level, 3))
        
        # ========================================
        # CATEGORY DETERMINATION
        # ========================================
        
        # If any detector says PII or entity boost is high, classify as PII
        final_category = "PII" if (
            rule_cat == "PII" or
            llm_cat == "PII" or
            entity_boost >= 1.8
        ) else "NORMAL"
        
        # LLM-specific categories override for CREDENTIAL/FINANCE/HEALTH
        if llm_cat in ["CREDENTIAL", "FINANCIAL", "HEALTH"] and llm_sev == "HIGH":
            final_category = llm_cat
        
        # ========================================
        # DATA TYPE CLASSIFICATION
        # ========================================
        
        data_type, data_type_reason = self._classify_data_type(
            rule_result, llm_result, entities, entity_boost, ner_result
        )
        
        # ========================================
        # SIGNALS LOG
        # ========================================
        
        signals_used = []
        
        if email:
            signals_used.append("email")
        if phone:
            signals_used.append("phone")
        if name:
            signals_used.append("name")
        if location:
            signals_used.append("location")
        if username:
            signals_used.append("username")
        if credit_card:
            signals_used.append("credit_card")
        if ssn:
            signals_used.append("ssn")
        if api_key:
            signals_used.append("api_key")
        
        if entity_boost > 2.0:
            signals_used.append("critical_combination")
        elif entity_boost > 1.5:
            signals_used.append("high_combination")
        
        if rule_cat != llm_cat and rule_cat != "NORMAL" and llm_cat != "NORMAL":
            signals_used.append("detector_disagreement")
        
        # Add implicit risk signals from LLM
        implicit_risks = llm_result.get("implicit_risks", [])
        signals_used.extend(implicit_risks[:3])  # Top 3 implicit risks
        
        # ========================================
        # RETURN FUSED OUTPUT
        # ========================================
        
        return {
            "category": final_category,
            "severity": self.inv_rank[final_severity_level],
            "data_type": data_type,
            "data_type_explanation": {
                "reason": data_type_reason,
                "signals_used": signals_used,
                "entity_boost_applied": round(entity_boost, 2)
            },
            "raw_score": min(3.0, final_score_clamped) / 3.0,  # Normalize to 0-1
            "risk_score_details": {
                "rule_contribution": rule_sev * 0.5,
                "llm_contribution": llm_sev * 0.3,
                "entity_contribution": entity_boost * 0.2
            },
            "rule": rule_result,
            "llm": llm_result,
            "ner": ner_result if ner_result else None,
            "detector_confidence": {
                "rule_severity": self.inv_rank[rule_sev],
                "llm_severity": self.inv_rank[llm_sev],
                "entity_boost": round(entity_boost, 2)
            }
        }

    def _classify_data_type(
        self,
        rule_result: Dict,
        llm_result: Dict,
        entities: Dict,
        entity_boost: float,
        ner_result: Dict
    ) -> tuple:
        """
        Classify data into finer-grained data type categories.
        
        Returns:
        (data_type, explanation_string)
        """
        
        email = entities.get("email", False)
        phone = entities.get("phone", False)
        location = entities.get("location", False)
        username = entities.get("username", False)
        name = entities.get("name", False)
        credit_card = entities.get("credit_card", False)
        ssn = entities.get("ssn", False)
        api_key = entities.get("api_key", False)
        
        # Check rule detector signals (string)
        rule_signals = rule_result.get("signals", "")
        if not isinstance(rule_signals, str):
            rule_signals = str(rule_signals)
        
        # Check LLM category for implicit risks
        llm_category = llm_result.get("category", "")
        llm_severity = llm_result.get("severity", "")
        
        # DIRECT_PII: Strong identifiers alone or sensitive credentials
        if credit_card or ssn or api_key:
            return (
                "DIRECT_PII",
                "Contains direct sensitive identifiers (credentials/financial data)"
            )
        
        if email or phone:
            return (
                "DIRECT_PII",
                "Contains direct contact identifiers (email/phone)"
            )
        
        # CONTEXTUAL: Health or financial information (without direct identifiers)
        # These are sensitive but contextual, not direct PII
        if llm_category in ["FINANCIAL", "HEALTH"] and llm_severity == "HIGH":
            return (
                "CONTEXTUAL",
                f"Sensitive {llm_category.lower()} information - high risk due to potential profiling"
            )
        
        # Rule detector found financial/health information
        if "financial_info" in rule_signals or "salary" in rule_signals:
            return (
                "CONTEXTUAL",
                "Personal financial context disclosed (salary/income information)"
            )
        
        if "health_info" in rule_signals or "medical" in rule_signals:
            return (
                "CONTEXTUAL",
                "Personal health context disclosed (medical/health information)"
            )
        
        if email and phone and (name or location):
            return (
                "DIRECT_PII",
                "Complete contact profile with location/name enables direct identification"
            )
        
        # QUASI-PII: Combinations of weak identifiers
        if (name and location) or (username and location) or (name and username):
            return (
                "QUASI_PII",
                "Combination of quasi-identifiers enables probable identification"
            )
        
        if entity_boost >= 1.8 and (name or email or phone):
            return (
                "QUASI_PII",
                "Multiple weak identifiers in combination"
            )
        
        # AUTH: Structured identity/credential fields
        if "identity_field" in rule_signals or "structured_field" in rule_signals:
            return (
                "AUTH",
                "Structured identity/credential metadata detected"
            )
        
        # CONTEXTUAL: Behavioral, temporal, or relationship data
        # Health/financial from rule detector = CONTEXTUAL if not HIGH severity
        if "health_info" in rule_signals or "medical" in rule_signals:
            return (
                "CONTEXTUAL",
                "Personal health context disclosed"
            )
        
        if "financial_info" in rule_signals or "salary" in rule_signals:
            return (
                "CONTEXTUAL",
                "Personal financial context disclosed"
            )
        
        if any(keyword in rule_signals for keyword in ["family_info", "workplace_info"]):
            return (
                "CONTEXTUAL",
                "Personal relationship/workplace context disclosed"
            )
        
        if "personal_narrative" in rule_signals and len(rule_signals) > 1:
            return (
                "CONTEXTUAL",
                "Extended personal context that could enable identification"
            )
        
        # NORMAL: No detectable risks
        return (
            "NORMAL",
            "No strong privacy risk indicators detected"
        )
