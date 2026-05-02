"""
LLM-based Semantic Risk Classifier for PriVoke Phase 1

Uses OpenAI GPT-4o-mini for nuanced, semantic privacy risk detection.
Detects implicit privacy threats and contextual risks missed by rules.
Works with any privacy-sensitive content through generic semantic analysis.
"""

import os
import json
from typing import Dict
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


class LLMClassifier:
    """
    Semantic privacy risk classifier using OpenAI API.
    Detects implicit identifiers, contextual risks, and indirect privacy threats.
    """

    def __init__(self):
        """Initialize OpenAI client with API key from environment."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables. "
                "Please set OPENAI_API_KEY in your .env file."
            )
        self.client = OpenAI(api_key=api_key)

    def classify(self, text: str) -> str:
        """
        Classify text for privacy risks using semantic analysis.
        
        Args:
            text: Normalized text to analyze
        
        Returns:
            JSON string with classification results
        """
        
        system_prompt = """You are a STRICT privacy risk detection system for security auditing.

Your role: Detect IMPLICIT and CONTEXTUAL privacy risks, not just direct identifiers.

Be CONSERVATIVE and PARANOID about privacy:
- Even indirect identifiers that could be combined with other data to identify someone are HIGH risk
- Contextual information (like job, location, hobbies) that narrows identity are MEDIUM risk
- Information that reveals sensitive characteristics (health, financial, political) are MEDIUM-HIGH risk
- Vague or seemingly innocent information in combination with other data is still risky

CATEGORY definitions:
- PII: Personally Identifiable Information (direct or quasi-identifiers)
- CREDENTIAL: Login credentials, passwords, API keys, tokens
- FINANCIAL: Bank accounts, credit cards, transactions, salary, investments
- HEALTH: Medical conditions, medications, doctor visits, mental health
- NORMAL: Generic, non-sensitive information

SEVERITY guidance:
- HIGH: Direct identifiers, financial data, health conditions, combinations of quasi-identifiers
- MEDIUM: Single quasi-identifier, unique occupations/locations, emotional disclosures
- LOW: Public-facing role/title, common hobbies, generic location

ENTITIES to detect:
- email: Email addresses
- phone: Phone numbers
- name: Real or full names
- location: City, country, region, address
- username: Social media handles, usernames, account names
- credit_card: Credit card patterns
- ssn: Social Security Numbers
- api_key: API keys, tokens, secrets
- medical: Medical terms, conditions
- financial: Financial terms

Return a valid JSON object with these exact fields."""

        user_prompt = f"""Analyze this text for privacy risks:

TEXT:
"{text}"

Return ONLY a valid JSON object (no markdown, no extra text):
{{
  "category": "PII" | "CREDENTIAL" | "FINANCIAL" | "HEALTH" | "NORMAL",
  "severity": "LOW" | "MEDIUM" | "HIGH",
  "entities": {{
    "email": false,
    "phone": false,
    "name": false,
    "location": false,
    "username": false,
    "credit_card": false,
    "ssn": false,
    "api_key": false
  }},
  "implicit_risks": [
    "any implicit or contextual privacy risks detected"
  ],
  "reasoning": "Brief explanation of category and severity decision"
}}"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3,  # Lower temperature for consistency
                max_tokens=500
            )
            
            content = response.choices[0].message.content.strip()
            
            # Validate and parse JSON
            try:
                parsed = json.loads(content)
                
                # Ensure all required fields exist
                required_fields = ["category", "severity", "entities", "reasoning"]
                for field in required_fields:
                    if field not in parsed:
                        return self._fallback_response("missing_required_field")
                
                # Validate enum values
                valid_categories = ["PII", "CREDENTIAL", "FINANCIAL", "HEALTH", "NORMAL"]
                valid_severities = ["LOW", "MEDIUM", "HIGH"]
                
                if parsed.get("category") not in valid_categories:
                    parsed["category"] = "NORMAL"
                if parsed.get("severity") not in valid_severities:
                    parsed["severity"] = "LOW"
                
                return json.dumps(parsed)
            except json.JSONDecodeError:
                return self._fallback_response("json_parse_error")
        
        except Exception as e:
            print(f"⚠️ LLM API Error: {e}")
            return self._fallback_response("api_error")

    def _fallback_response(self, reason: str) -> str:
        """
        Return a safe fallback response when LLM fails.
        """
        fallback = {
            "category": "NORMAL",
            "severity": "LOW",
            "entities": {
                "email": False,
                "phone": False,
                "name": False,
                "location": False,
                "username": False,
                "credit_card": False,
                "ssn": False,
                "api_key": False
            },
            "implicit_risks": [],
            "reasoning": f"LLM classifier fallback due to: {reason}"
        }
        return json.dumps(fallback)
