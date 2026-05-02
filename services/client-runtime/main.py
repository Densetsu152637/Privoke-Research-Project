"""
PriVoke Phase 1: Runtime Privacy Protection Pipeline

Complete end-to-end system for detecting privacy risks in user input.
Works with any privacy-sensitive dataset or domain.

Architecture:
1. User Input Layer (Browser Extension)
2. Preprocessing Layer (Text Normalization)
3. Internal Model Service (Hybrid Detection)
   - Rule-Based Detector
   - Entity/NER Detector
   - Semantic LLM Risk Detector
4. Fusion + Risk Scoring Engine
5. Enforcement Engine (ALLOW/WARN_AND_MASK/BLOCK)
6. Structured Event Emitter (Metadata telemetry)
7. Target Application Output

Dataset: Works with PANORAMA, medical records, financial data, or any privacy-sensitive dataset.
Detector Version: v1 (rules + baseline LLM model)
"""

from preprocessing.normalizer import TextNormalizer
from detection.rule_detector import RuleDetector
from detection.ner_detector import EntityNERDetector, initialize_ner_detector
from detection.llm_classifier import LLMClassifier
from detection.fusion import FusionEngine
from detection.enforcement_engine import EnforcementEngine
from detection.event_emitter import StructuredEventEmitter

import json
from datetime import datetime


def run_full_pipeline():
    """
    Execute complete Phase 1 pipeline with all detector components.
    
    Demonstrates:
    - Text normalization
    - Rule-based detection
    - Entity/NER extraction
    - LLM semantic analysis
    - Fusion + risk scoring
    - Enforcement decision
    - Structured event emission
    """
    
    # ========================================
    # INITIALIZE ALL COMPONENTS
    # ========================================
    
    normalizer = TextNormalizer()
    rule_engine = RuleDetector()
    ner_detector = initialize_ner_detector()
    llm_engine = LLMClassifier()  # Requires OPENAI_API_KEY
    fusion_engine = FusionEngine()
    enforcement_engine = EnforcementEngine()
    event_emitter = StructuredEventEmitter(detector_version="v1")
    
    # ========================================
    # TEST CASES (Privacy-sensitive dataset samples across domains)
    # ========================================
    
    test_cases = [
        "My email is alice@example.com please reset my password",
        "Call me at +1-555-123-4567 for urgent matters",
        "I live in San Francisco and my name is John Smith",
        "Check out my new game: pretty fun to play",
        "My username is @jane_doe and I'm from Paris",
        "My credit card is 4532-1234-5678-9012",
        "I take medication for my anxiety and depression",
        "My salary is $150,000 per year",
    ]
    
    events_batch = []
    
    # ========================================
    # HEADER
    # ========================================
    
    print("\n" + "=" * 90)
    print(" PriVoke PHASE 1: RUNTIME PRIVACY PROTECTION PIPELINE")
    print("=" * 90)
    print(f"Initialized at: {datetime.now().isoformat()}Z")
    print(f"Detector Version: v1 (rules + baseline LLM model)")
    print(f"Dataset: Privacy-sensitive text (cross-domain)")
    print(f"Test Cases: {len(test_cases)}")
    print("=" * 90)
    
    # ========================================
    # PROCESS EACH TEST CASE
    # ========================================
    
    for idx, original_text in enumerate(test_cases, 1):
        print(f"\n{'#' * 90}")
        print(f"TEST CASE {idx}/{len(test_cases)}")
        print(f"{'#' * 90}")
        
        # ========================================
        # LAYER 1: USER INPUT
        # ========================================
        
        print(f"\n[LAYER 1] USER INPUT FROM BROWSER EXTENSION")
        print(f"Original: {original_text}")
        
        # ========================================
        # LAYER 2: PREPROCESSING (NORMALIZATION)
        # ========================================
        
        print(f"\n[LAYER 2] PREPROCESSING - TEXT NORMALIZATION")
        normalized_text = normalizer.normalize(original_text)
        print(f"Normalized: {normalized_text}")
        
        # ========================================
        # LAYER 3A: RULE-BASED DETECTOR
        # ========================================
        
        print(f"\n[LAYER 3A] RULE-BASED DETECTOR (Fast Pattern Matching)")
        rule_category, rule_severity, rule_signals = rule_engine.analyze(normalized_text)
        rule_result = {
            "category": rule_category,
            "severity": rule_severity,
            "signals": rule_signals
        }
        print(f"  Category: {rule_category}")
        print(f"  Severity: {rule_severity}")
        print(f"  Signals: {rule_signals}")
        
        # ========================================
        # LAYER 3B: ENTITY/NER DETECTOR
        # ========================================
        
        print(f"\n[LAYER 3B] ENTITY/NER DETECTOR (Structured Entity Extraction)")
        ner_result = ner_detector.extract_entities(normalized_text)
        entity_summary = ner_result["entity_summary"]
        print(f"  Emails detected: {entity_summary['has_email']}")
        print(f"  Phones detected: {entity_summary['has_phone']}")
        print(f"  Names detected: {entity_summary['has_name']}")
        print(f"  Locations detected: {entity_summary['has_location']}")
        print(f"  Usernames detected: {entity_summary['has_username']}")
        print(f"  Credentials detected: {entity_summary['has_credit_card'] or entity_summary['has_ssn']}")
        print(f"  Total entities: {entity_summary['total_entities']}")
        
        # ========================================
        # LAYER 3C: SEMANTIC LLM RISK DETECTOR
        # ========================================
        
        print(f"\n[LAYER 3C] SEMANTIC LLM RISK DETECTOR (OpenAI GPT-4o-mini)")
        try:
            llm_raw = llm_engine.classify(normalized_text)
            llm_result = json.loads(llm_raw)
        except Exception as e:
            print(f"   LLM Error: {e}")
            llm_result = {
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
                "reasoning": f"LLM error: {str(e)}"
            }
        
        print(f"  Category: {llm_result.get('category')}")
        print(f"  Severity: {llm_result.get('severity')}")
        print(f"  Reasoning: {llm_result.get('reasoning', llm_result.get('reason', 'N/A'))}")
        print(f"  Entities Detected:")
        for entity_type, detected in llm_result.get('entities', {}).items():
            if detected:
                print(f"    - {entity_type}: {detected}")
        
        # ========================================
        # LAYER 4: FUSION + RISK SCORING
        # ========================================
        
        print(f"\n[LAYER 4] FUSION ENGINE - WEIGHTED RISK SCORING")
        print(f"  Weighting: Rule 50% + LLM 30% + Entity 20%")
        
        fused_output = fusion_engine.fuse(rule_result, llm_result, ner_result)
        fused_output["original_text"] = original_text
        
        raw_score = fused_output.get("raw_score", 0.0)
        
        print(f"  Final Category: {fused_output.get('category')}")
        print(f"  Final Severity: {fused_output.get('severity')}")
        print(f"  Risk Score: {raw_score:.3f}")
        print(f"  Data Type: {fused_output.get('data_type')}")
        print(f"  Reason: {fused_output.get('data_type_explanation', {}).get('reason')}")
        
        # Detector agreement/disagreement (normalized - treat CREDENTIAL/HEALTH/FINANCIAL as subtypes of PII)
        rule_cat = rule_result["category"]
        llm_cat = llm_result.get("category")
        
        # Normalize CREDENTIAL/HEALTH/FINANCIAL to PII for comparison
        rule_cat_normalized = "PII" if rule_cat in ["CREDENTIAL", "HEALTH", "FINANCIAL"] else rule_cat
        llm_cat_normalized = "PII" if llm_cat in ["CREDENTIAL", "HEALTH", "FINANCIAL"] else llm_cat
        
        disagreement = rule_cat_normalized != llm_cat_normalized
        if disagreement:
            print(f"  ⚠️ DETECTOR DISAGREEMENT: Rule={rule_cat}, LLM={llm_cat}")
        
        # ========================================
        # LAYER 5: ENFORCEMENT ENGINE
        # ========================================
        
        print(f"\n[LAYER 5] ENFORCEMENT ENGINE - FINAL DECISION")
        enforcement_output = enforcement_engine.enforce(fused_output)
        action = enforcement_output.get("action")
        print(f"  ACTION: {action}")
        print(f"  Reason: {enforcement_output.get('reason')}")
        
        if action == "WARN_AND_MASK":
            print(f"   MASKED OUTPUT:")
            print(f"     {enforcement_output.get('masked_text')}")
            if enforcement_output.get('entities_masked'):
                print(f"   MASKED ENTITIES: {enforcement_output.get('entities_masked')}")
        elif action == "BLOCK_PROMPT":
            print(f"   PROMPT BLOCKED - Not sent to target application")
        else:
            print(f"   PROMPT ALLOWED - Forwarding to target application")
        
        # ========================================
        # LAYER 6: STRUCTURED EVENT EMISSION
        # ========================================
        
        print(f"\n[LAYER 6] STRUCTURED EVENT EMITTER - METADATA TELEMETRY")
        event = event_emitter.emit(original_text, enforcement_output, fused_output)
        
        print(f"  Event ID: {event.get('event_id')}")
        print(f"  Time Bucket: {event.get('time_bucket')}")
        print(f"  Risk Category: {event.get('risk_category')}")
        print(f"  Risk Score: {event.get('risk_score')} (bucket: {event.get('risk_score_bucket')})")
        print(f"  Action Taken: {event.get('action_taken')}")
        print(f"  Detector Version: {event.get('detector_version')}")
        
        events_batch.append(event)
        
        # ========================================
        # LAYER 7: TARGET APPLICATION OUTPUT
        # ========================================
        
        print(f"\n[LAYER 7] TARGET APPLICATION OUTPUT")
        print(f"  Original Text: {original_text}")
        print(f"  Normalized Text: {normalized_text}")
        print(f"  Enforcement Action: {action}")
        
        if action == "WARN_AND_MASK":
            print(f"  Display to User: {enforcement_output.get('masked_text')}")
        elif action == "ALLOW":
            print(f"  Display to User: {original_text}")
        else:
            print(f"  Display to User: [BLOCKED - Input rejected due to privacy risk]")
        
        print()
    
    # ========================================
    # BATCH TELEMETRY OUTPUT (FOR PHASE 3)
    # ========================================
    
    print("\n" + "=" * 90)
    print(" STRUCTURED EVENT BATCH FOR PHASE 3 (SERVER-SIDE TELEMETRY)")
    print("=" * 90)
    print("\nThis batch would be transmitted to the Telemetry Collector.")
    print("Phase 3 performs: validation, aggregation, differential privacy, dashboard\n")
    
    batch_json = event_emitter.batch_serialize(events_batch)
    print(batch_json)
    
    # ========================================
    # FOOTER
    # ========================================
    
    print("\n" + "=" * 90)
    print(" PHASE 1 PIPELINE COMPLETE")
    print("=" * 90)
    print("=" * 90 + "\n")


if __name__ == "__main__":
    run_full_pipeline()
