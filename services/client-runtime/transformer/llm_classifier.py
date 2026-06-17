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
from classification import Category, Sensitivity, Visibility, initialise_unpacked

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

    def classify(self, text: str) -> Dict:
        """
        Classify text for privacy risks using semantic analysis.
        
        Args:
            text: Normalized text to analyze
        
        Returns:
            Dict with Classification, entities, implicit risks, and reasoning
        """
        
        system_prompt = """You are a STRICT privacy risk detection system for security auditing.

Your role: Detect IMPLICIT and CONTEXTUAL privacy risks, not just direct identifiers.

Be CONSERVATIVE and PARANOID about privacy:
- Even indirect identifiers that could be combined with other data to identify someone are HIGH risk
- Contextual information (like job, location, hobbies) that narrows identity are MEDIUM risk
- Information that reveals sensitive characteristics (health, financial, political) are MEDIUM-HIGH risk
- Vague or seemingly innocent information in combination with other data is still risky

Classification definitions:
- sensitivity:
  - S0: benign / no privacy risk
  - S1: low, mild personal or non-identifying context
  - S2: medium, personal information that could cause targeting or harm
  - S3: high, sensitive categories or identifiable details
- visibility:
  - Use PU unless the text itself clearly states public/semi-public/restricted/private visibility.
- categories:
  - HEALTH: Medical conditions, medications, doctor visits, mental health
  - POLITICS: Political views, affiliation, campaigns, voting
  - RELIGION: Religious belief, affiliation, worship
  - CRIMINAL: Criminal history, charges, arrests, legal orders
  - FINANCIAL: Bank accounts, credit cards, transactions, salary, investments
  - SEXUAL: Sexual orientation, history, intimate disclosures
  - CHILD: Children or minors
  - LOCATION: Address, precise location, routes, private whereabouts
  - IDENTITY: Names, emails, phones, IDs, usernames, credentials, tokens
  - THIRD_PARTY: Sensitive information about someone other than the speaker

Sensitivity guidance:
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
  "sensitivity": "S0" | "S1" | "S2" | "S3",
  "visibility": "P0" | "P1" | "P2" | "P3" | "PU",
  "categories": [
    "HEALTH" | "POLITICS" | "RELIGION" | "CRIMINAL" | "FINANCIAL" | "SEXUAL" | "CHILD" | "LOCATION" | "IDENTITY" | "THIRD_PARTY"
  ],
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
  "reasoning": "Brief explanation of classification decision"
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
                required_fields = [
                    "sensitivity",
                    "visibility",
                    "categories",
                    "entities",
                    "reasoning",
                ]
                for field in required_fields:
                    if field not in parsed:
                        return self._fallback_response("missing_required_field")
                
                return self._build_result(parsed)
            except json.JSONDecodeError:
                return self._fallback_response("json_parse_error")
        
        except Exception as e:
            print(f"⚠️ LLM API Error: {e}")
            return self._fallback_response("api_error")

    def _build_result(self, parsed: Dict) -> Dict:
        """Convert model JSON into internal enum-backed classification output."""
        try:
            sensitivity = Sensitivity[parsed.get("sensitivity", "S0")]
        except KeyError:
            sensitivity = Sensitivity.S0

        try:
            visibility = Visibility[parsed.get("visibility", "PU")]
        except KeyError:
            visibility = Visibility.PU

        categories = []
        raw_categories = parsed.get("categories", [])
        if isinstance(raw_categories, list):
            for raw_category in raw_categories:
                try:
                    categories.append(Category[raw_category])
                except KeyError:
                    continue

        classification = initialise_unpacked(sensitivity, visibility, categories)

        return {
            "classification": classification,
            "packed_classification": classification.pack(),
            "entities": parsed.get("entities", {}),
            "implicit_risks": parsed.get("implicit_risks", []),
            "reasoning": parsed.get("reasoning", ""),
        }

    def _fallback_response(self, reason: str) -> Dict:
        """
        Return a safe fallback response when LLM fails.
        """
        classification = initialise_unpacked(Sensitivity.S0, Visibility.PU, [])
        fallback = {
            "classification": classification,
            "packed_classification": classification.pack(),
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
        return fallback
