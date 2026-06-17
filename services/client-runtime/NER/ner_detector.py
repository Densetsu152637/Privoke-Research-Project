"""
Entity/NER Detector for PriVoke Phase 1

Extracts named entities (emails, phone numbers, names, locations, usernames) 
using both pattern-based (regex) and ML-based (spaCy) approaches.

Returns structured entity information for fusion engine.
"""

import re
import json
from typing import Dict, List, Tuple


class EntityNERDetector:
    """
    Hybrid entity extraction combining:
    - Regex patterns: email, phone, URLs, credit cards, SSN
    - spaCy NER: PERSON, GPE (location), PRODUCT (usernames/handles)
    """

    def __init__(self):
        """Initialize NER detector with spaCy model."""
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
            self.spacy_available = True
        except Exception as e:
            print(f"⚠️ spaCy model not available: {e}. Falling back to regex-only mode.")
            self.nlp = None
            self.spacy_available = False

    def extract_entities(self, text: str) -> Dict:
        """
        Extract entities from text.
        
        Returns:
        {
            "emails": [{"text": "...", "span": (0, 10), "confidence": 0.95}],
            "phones": [...],
            "names": [...],
            "locations": [...],
            "usernames": [...],
            "credit_cards": [...],
            "ssns": [...],
            "urls": [...],
            "raw_entities": {  # spaCy NER output
                "PERSON": [...],
                "GPE": [...],
                "ORG": [...],
                ...
            },
            "entity_summary": {
                "has_email": bool,
                "has_phone": bool,
                "has_name": bool,
                "has_location": bool,
                "has_username": bool,
                "has_credential": bool,
                "total_entities": int
            }
        }
        """
        
        entities = {
            "emails": [],
            "phones": [],
            "names": [],
            "locations": [],
            "usernames": [],
            "credit_cards": [],
            "ssns": [],
            "urls": [],
            "raw_entities": {},
            "entity_summary": {}
        }
        
        # ========================================
        # REGEX-BASED EXTRACTION
        # ========================================
        
        # Email addresses
        email_pattern = r'\b[\w\.-]+@[\w\.-]+\.\w+\b'
        for match in re.finditer(email_pattern, text, re.IGNORECASE):
            entities["emails"].append({
                "text": match.group(),
                "span": match.span(),
                "confidence": 0.95,
                "type": "DIRECT_PII"
            })
        
        # Phone numbers (multiple formats)
        phone_patterns = [
            r'\+?\d{1,3}[\s\-.]?\d{3}[\s\-.]?\d{3}[\s\-.]?\d{4}',  # International
            r'\(?(\d{3})\)?[\s\-.]?\d{3}[\s\-.]?\d{4}',              # US/CA
            r'\b\d{8,12}\b'                                           # Generic 8-12 digits
        ]
        
        # Track phone spans to prevent overlapping duplicates (keep longest match)
        phone_spans = []
        
        for pattern in phone_patterns:
            for match in re.finditer(pattern, text):
                phone_text = match.group().strip()
                if len(re.sub(r'\D', '', phone_text)) >= 8:  # At least 8 digits
                    # Check if this overlaps with an already-found phone (skip if it does)
                    is_overlap = False
                    for existing_start, existing_end, existing_text in phone_spans:
                        # Check for overlap or near-overlap
                        if not (match.end() <= existing_start or match.start() >= existing_end):
                            # Overlaps - keep the longer one
                            if len(phone_text) > len(existing_text):
                                # Remove old, will add new
                                phone_spans = [(s, e, t) for s, e, t in phone_spans if not (s == existing_start and e == existing_end)]
                            else:
                                # Keep old, skip new
                                is_overlap = True
                                break
                    
                    if not is_overlap:
                        phone_spans.append((match.start(), match.end(), phone_text))
                        entities["phones"].append({
                            "text": phone_text,
                            "span": match.span(),
                            "confidence": 0.90,
                            "type": "DIRECT_PII"
                        })
        
        # Credit card numbers (common formats)
        cc_pattern = r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'
        for match in re.finditer(cc_pattern, text):
            entities["credit_cards"].append({
                "text": match.group(),
                "span": match.span(),
                "confidence": 0.92,
                "type": "DIRECT_PII"
            })
        
        # SSN (XXX-XX-XXXX or XXXXXXXXX)
        ssn_pattern = r'\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b'
        for match in re.finditer(ssn_pattern, text):
            ssn_text = re.sub(r'\s', '', match.group())
            if len(ssn_text) == 9:  # Valid SSN length
                entities["ssns"].append({
                    "text": match.group(),
                    "span": match.span(),
                    "confidence": 0.88,
                    "type": "DIRECT_PII"
                })
        
        # URLs
        url_pattern = r'https?://[^\s]+'
        for match in re.finditer(url_pattern, text, re.IGNORECASE):
            entities["urls"].append({
                "text": match.group(),
                "span": match.span(),
                "confidence": 0.95,
                "type": "CONTEXTUAL"
            })
        
        # Usernames (@ prefix or "username:" format)
        # NOTE: Exclude emails by requiring @ not to be preceded by word chars/dots
        username_patterns = [
            r'(?<![a-zA-Z0-9.])@[\w\-]+',                    # @handle (but not @example.com)
            r'(?:username|user|handle)\s*[:=]\s*[\w\-]+',   # username: value
        ]
        
        for pattern in username_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                entities["usernames"].append({
                    "text": match.group(),
                    "span": match.span(),
                    "confidence": 0.85,
                    "type": "QUASI_PII"
                })
        
        # ========================================
        # SPACY NER EXTRACTION
        # ========================================
        
        if self.spacy_available:
            doc = self.nlp(text)
            
            for ent in doc.ents:
                if ent.label_ == "PERSON":
                    entities["names"].append({
                        "text": ent.text,
                        "span": (ent.start_char, ent.end_char),
                        "confidence": 0.85,
                        "type": "DIRECT_PII",
                        "source": "spacy"
                    })
                
                elif ent.label_ in ["GPE", "LOC"]:  # Geopolitical entity or location
                    entities["locations"].append({
                        "text": ent.text,
                        "span": (ent.start_char, ent.end_char),
                        "confidence": 0.85,
                        "type": "QUASI_PII",
                        "source": "spacy"
                    })
                
                elif ent.label_ == "PRODUCT":  # Can indicate brand/account/username
                    entities["usernames"].append({
                        "text": ent.text,
                        "span": (ent.start_char, ent.end_char),
                        "confidence": 0.75,
                        "type": "QUASI_PII",
                        "source": "spacy"
                    })
            
            # Store raw spaCy output
            entities["raw_entities"] = {
                ent.label_: [
                    {
                        "text": ent.text,
                        "span": (ent.start_char, ent.end_char)
                    }
                    for ent in doc.ents
                    if ent.label_ == label
                ]
                for label in set(ent.label_ for ent in doc.ents)
            }
        
        # ========================================
        # ENTITY SUMMARY
        # ========================================
        
        entities["entity_summary"] = {
            "has_email": len(entities["emails"]) > 0,
            "has_phone": len(entities["phones"]) > 0,
            "has_name": len(entities["names"]) > 0,
            "has_location": len(entities["locations"]) > 0,
            "has_username": len(entities["usernames"]) > 0,
            "has_credit_card": len(entities["credit_cards"]) > 0,
            "has_ssn": len(entities["ssns"]) > 0,
            "has_url": len(entities["urls"]) > 0,
            "total_entities": (
                len(entities["emails"]) + len(entities["phones"]) +
                len(entities["names"]) + len(entities["locations"]) +
                len(entities["usernames"]) + len(entities["credit_cards"]) +
                len(entities["ssns"]) + len(entities["urls"])
            )
        }
        
        return entities

    def get_entity_risk_signals(self, entities: Dict) -> Dict:
        """
        Convert extracted entities into risk signals for fusion engine.
        
        Returns:
        {
            "entity_flags": {
                "email": bool,
                "phone": bool,
                "name": bool,
                "location": bool,
                "username": bool,
                "credential": bool  # credit card or SSN
            },
            "high_risk_combinations": [
                "name_location",
                "username_location",
                "email_phone",
                ...
            ],
            "strongest_entity": "email" | "phone" | "credit_card" | "name" | ...,
            "entity_count": int
        }
        """
        
        summary = entities["entity_summary"]
        
        flags = {
            "email": summary["has_email"],
            "phone": summary["has_phone"],
            "name": summary["has_name"],
            "location": summary["has_location"],
            "username": summary["has_username"],
            "credential": summary["has_credit_card"] or summary["has_ssn"]
        }
        
        # Detect high-risk combinations
        combinations = []
        
        if flags["email"] and flags["phone"]:
            combinations.append("email_phone")
        if flags["name"] and flags["location"]:
            combinations.append("name_location")
        if flags["username"] and flags["location"]:
            combinations.append("username_location")
        if flags["email"] and flags["name"]:
            combinations.append("email_name")
        if flags["credential"] and flags["name"]:
            combinations.append("credential_name")
        if flags["credential"] and (flags["email"] or flags["phone"]):
            combinations.append("credential_contact")
        
        # Determine strongest entity type (for prioritization)
        entity_priority = [
            ("credit_card", summary["has_credit_card"]),
            ("ssn", summary["has_ssn"]),
            ("email", summary["has_email"]),
            ("phone", summary["has_phone"]),
            ("name", summary["has_name"]),
            ("location", summary["has_location"]),
            ("username", summary["has_username"]),
        ]
        
        strongest = None
        for entity_type, present in entity_priority:
            if present:
                strongest = entity_type
                break
        
        return {
            "entity_flags": flags,
            "high_risk_combinations": combinations,
            "strongest_entity": strongest,
            "entity_count": summary["total_entities"]
        }


def initialize_ner_detector() -> EntityNERDetector:
    """
    Factory function to initialize NER detector.
    If spaCy model is not available, provides fallback behavior.
    """
    return EntityNERDetector()
