import re
from typing import Dict, List, Tuple


class EnforcementEngine:
    """
    Final gatekeeper that converts fused risk output into enforcement actions.
    
    Rules:
    - HIGH risk OR DIRECT_PII -> BLOCK ("BLOCK_PROMPT")
    - MEDIUM risk OR QUASI_PII -> WARN + MASK ("WARN_AND_MASK")
    - LOW risk -> ALLOW ("ALLOW")
    """

    def __init__(self):
        self.severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3} # Define severity ranking for comparison

    def enforce(self, fused_output: Dict) -> Dict:
        """
        Takes fused output and decides enforcement action.
        
        Returns:
        {
            "action": "ALLOW" | "WARN_AND_MASK" | "BLOCK_PROMPT",
            "severity": "LOW" | "MEDIUM" | "HIGH",
            "category": "PII" | "NORMAL",
            "data_type": "DIRECT_PII" | "QUASI_PII" | "AUTH" | "CONTEXTUAL" | "NORMAL",
            "reason": "explanation of action",
            "masked_text": "original text with sensitive data masked (if WARN_AND_MASK)",
            "entities_masked": ["list of entity types masked"]
        }
        """
        
        severity = fused_output.get("severity", "LOW") # Default to LOW if not provided
        category = fused_output.get("category", "NORMAL") # Default to NORMAL if not provided
        data_type = fused_output.get("data_type", "NORMAL") # Default to NORMAL if not provided
        
        # Determine action based on rules
        action, reason = self._determine_action(severity, category, data_type)
        
        entities_masked = []
        masked_text = fused_output.get("original_text", "") # Default to empty string if not provided
        
        # If WARN_AND_MASK, perform masking
        if action == "WARN_AND_MASK":
            # Build merged entities from LLM and NER outputs
            merged_entities = self._build_merged_entities(fused_output) # Combine LLM and NER entities for comprehensive masking
            masked_text, entities_masked = self._mask_sensitive_entities( # Mask based on merged entities to ensure all detected sensitive data is masked
                fused_output.get("original_text", ""), # Use original text for masking
                merged_entities
            )
        
        return {
            "action": action,
            "severity": severity,
            "category": category,
            "data_type": data_type,
            "reason": reason,
            "masked_text": masked_text if action == "WARN_AND_MASK" else None,
            "entities_masked": entities_masked,
            "original_risk_score": fused_output.get("raw_score", 0.0)
        }

    def _build_merged_entities(self, fused_output: Dict) -> Dict:
        """
        Build merged entity dict from LLM and NER outputs.
        Combines all detected entities from both sources.
        """
        merged_entities = {}
        
        # Get entities from LLM
        llm_entities = fused_output.get("llm", {}).get("entities", {}) # Safely access LLM entities
        if isinstance(llm_entities, dict): # Ensure we have a dict to merge
            merged_entities.update(llm_entities) # Start with LLM entities as they may have more comprehensive detection
        
        # Get entities from NER and merge
        ner_result = fused_output.get("ner", {})
        if ner_result:
            ner_summary = ner_result.get("entity_summary", {})
            # Convert NER has_* flags to merged format
            if ner_summary.get("has_email"):
                merged_entities["email"] = True
            if ner_summary.get("has_phone"):
                merged_entities["phone"] = True
            if ner_summary.get("has_name"):
                merged_entities["name"] = True
            if ner_summary.get("has_location"):
                merged_entities["location"] = True
            if ner_summary.get("has_username"):
                merged_entities["username"] = True
            if ner_summary.get("has_credit_card"):
                merged_entities["credit_card"] = True
            if ner_summary.get("has_ssn"):
                merged_entities["ssn"] = True
        
        return {"entities": merged_entities}

    def _determine_action(self, severity: str, category: str, data_type: str) -> Tuple[str, str]:
        """Determine enforcement action based on severity and data type."""
        
        # BLOCK rules
        if severity == "HIGH":
            return "BLOCK_PROMPT", f"HIGH severity {category} risk detected ({data_type})"
        
        if data_type == "DIRECT_PII":
            return "BLOCK_PROMPT", f"Direct PII detected ({data_type})"
        
        # WARN_AND_MASK rules
        if severity == "MEDIUM":
            return "WARN_AND_MASK", f"MEDIUM severity {category} risk - masking sensitive entities"
        
        if data_type in ["QUASI_PII", "AUTH"]:
            return "WARN_AND_MASK", f"Quasi-identifier or auth data detected ({data_type}) - masking"
        
        # ALLOW (default)
        return "ALLOW", f"Low risk - {category} content allowed"

    def _mask_sensitive_entities(self, text: str, llm_result: Dict) -> Tuple[str, List[str]]:
        """
        Mask sensitive entities in text.
        
        Returns:
        (masked_text, list_of_masked_entity_types)
        """
        masked_text = text
        entities_masked = []
        
        entities = llm_result.get("entities", {})
        
        # Email masking
        if entities.get("email"):
            masked_text = re.sub(
                r'\b[\w\.-]+@[\w\.-]+\.\w+\b',
                '[EMAIL]',
                masked_text,
                flags=re.IGNORECASE
            )
            entities_masked.append("email")
        
        # Phone masking
        if entities.get("phone"):
            masked_text = re.sub(
                r'\b(\+?\d{1,3}[- ]?)?\d{8,12}\b',
                '[PHONE]',
                masked_text
            )
            entities_masked.append("phone")
        
        # Credit card masking
        if entities.get("credit_card"):
            masked_text = re.sub(
                r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
                '[CREDIT_CARD]',
                masked_text
            )
            entities_masked.append("credit_card")
        
        # SSN masking
        if entities.get("ssn"):
            masked_text = re.sub(
                r'\b\d{3}-\d{2}-\d{4}\b',
                '[SSN]',
                masked_text
            )
            entities_masked.append("ssn")
        
        # LOCATION MASKING FIRST (before name masking to prevent collisions with multi-word locations)
        if entities.get("location"):
            # Known location keywords  and cities (must be done BEFORE name masking)
            locations = ['San Francisco', 'New York', 'Los Angeles', 'San Diego', 'London', 'Paris', 'Tokyo', 'Sydney', 'Toronto', 'Berlin', 'Rome', 'Madrid', 'Moscow', 'Dubai', 'Singapore', 'Hong Kong', 'Bangkok', 'Istanbul', 'Mexico City', 'New Delhi']
            for location in locations:
                masked_text = masked_text.replace(location, '[LOCATION]')
                masked_text = masked_text.replace(location.lower(), '[LOCATION]')
            
            # Also match generic patterns for single-word locations
            masked_text = re.sub(
                r'\b(?:California|Texas|Florida|New York|Paris|London|Tokyo|Sydney|Toronto|Berlin|Rome|Madrid)\b',
                '[LOCATION]',
                masked_text,
                flags=re.IGNORECASE
            )
            
            if "[LOCATION]" in masked_text and "location" not in entities_masked:
                entities_masked.append("location")
        
        # Name masking (after location to avoid collisions like "San Francisco" → "[NAME] [NAME]")
        if entities.get("name"):
            # Match capitalized names but avoid single letters
            masked_text = re.sub(
                r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b',
                '[NAME]',
                masked_text
            )
            entities_masked.append("name")
        
        # Username masking
        if entities.get("username"):
            masked_text = re.sub(
                r'@\w+',
                '[USERNAME]',
                masked_text
            )
            entities_masked.append("username")
        
        # Health information masking (keywords)
        health_keywords = r'\b(anxiety|depression|medication|mental\s+health|psychiatric|therapy|doctor|hospital|disease|condition|symptom|treatment)\b'
        if re.search(health_keywords, masked_text, re.IGNORECASE):
            # Only mask if we have health info
            masked_text = re.sub(
                health_keywords,
                '[HEALTH]',
                masked_text,
                flags=re.IGNORECASE
            )
            if "[HEALTH]" in masked_text and "health" not in entities_masked:
                entities_masked.append("health_info")
        
        # Financial information masking (amounts and keywords)
        financial_pattern = r'\b(?:salary|income|earnings|money|payment|transaction|balance|credit|debit|account|bank|financial|money)\b|\$[\d,]+'
        if re.search(financial_pattern, masked_text, re.IGNORECASE):
            masked_text = re.sub(
                financial_pattern,
                lambda m: '[SALARY]' if m.group().lower() == 'salary' else '[AMOUNT]' if m.group().startswith('$') else '[FINANCIAL]',
                masked_text,
                flags=re.IGNORECASE
            )
            if "[FINANCIAL]" in masked_text or "[AMOUNT]" in masked_text or "[SALARY]" in masked_text:
                if "financial_info" not in entities_masked:
                    entities_masked.append("financial_info")
        
        return masked_text, entities_masked
