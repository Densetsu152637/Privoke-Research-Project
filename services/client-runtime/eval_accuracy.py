"""
================================================================================
PriVoke Phase 1 - PANORAMA Dataset Accuracy Evaluation

DESCRIPTION:
  Evaluates the PriVoke privacy detection pipeline on real-world text from the
  PANORAMA dataset. The detector identifies 7 types of privacy risks (NORMAL,
  PII, CREDENTIAL, HEALTH, FINANCIAL, etc.) and determines enforcement actions:
  - ALLOW: No privacy risk
  - WARN_AND_MASK: Medium risk - mask sensitive entities
  - BLOCK_PROMPT: High risk - reject input entirely

HOW TO RUN:
  Basic evaluation on 100 samples:
    python3 eval_accuracy.py --limit 100
  
  Evaluation on first 50 samples:
    python3 eval_accuracy.py --limit 50
  
  Evaluation on ALL samples (can take 10+ minutes):
    python3 eval_accuracy.py --limit 0
  
  Save results to JSON file:
    python3 eval_accuracy.py --limit 100 --output results.json

REQUIREMENTS:
  - datasets library: pip install datasets
  - huggingface_hub: pip install huggingface_hub
  - OpenAI API key in .env file (see README.md)

INTERPRETING THE OUTPUT:
  
  SUMMARY:
    - "Total samples": How many texts were evaluated
    - "Samples with PII detected": Count and percentage of privacy-sensitive content
  
  CATEGORY DISTRIBUTION:
    Shows breakdown of detected privacy categories:
    - NORMAL: Safe text, no privacy risk
    - PII: Directly identifying information (names, emails, phones, etc.)
    - CREDENTIAL: Authentication data (passwords, tokens)
    - HEALTH: Medical/health information
    - FINANCIAL: Salary, account numbers, credit cards
  
  ENFORCEMENT ACTION DISTRIBUTION:
    - ALLOW: Safely passed to target application
    - WARN_AND_MASK: Flagged and sensitive entities masked with [TAGS]
    - BLOCK_PROMPT: Rejected - too sensitive to process
  
  Expected Results:
    - High detection rate (80-95%) on PANORAMA (privacy-rich dataset)
    - Most content → WARN_AND_MASK (medium risk quasi-identifiers)
    - Some → BLOCK_PROMPT (direct identifiers like SSN, full CC)
    - Small % -> ALLOW (genuinely non-sensitive)

SAMPLE PREDICTIONS:
  Shows first 10 evaluated texts with:
    - Original text (truncated)
    - Category detected (PII/NORMAL/etc.)
    - Severity (LOW/MEDIUM/HIGH)
    - Enforcement action (ALLOW/WARN_AND_MASK/BLOCK_PROMPT)
================================================================================
"""

import json
import argparse # this is used for parsing through command line arguments when running the script
from preprocessing.normalizer import TextNormalizer
from detection.rule_detector import RuleDetector
from detection.ner_detector import initialize_ner_detector
from detection.llm_classifier import LLMClassifier
from detection.fusion import FusionEngine


def evaluate_on_panorama(limit=100):
    """
    Evaluate Phase 1 detector on PANORAMA dataset using real OpenAI API.
    
    Args:
        limit: Number of samples to evaluate (None = all)
    """
    
    try:
        from datasets import load_dataset
        dataset = load_dataset("srirxml/PANORAMA")["train"]
        if limit:
            dataset = dataset.select(range(min(limit, len(dataset))))
    except Exception as e:
        print(f" Error loading PANORAMA dataset: {e}")
        print("   Please install: pip install datasets huggingface_hub")
        return None
    
    # Initialize detectors
    normalizer = TextNormalizer()
    rule_engine = RuleDetector()
    ner_detector = initialize_ner_detector()
    
    # Initialize LLM engine
    llm_engine = LLMClassifier()
    
    fusion_engine = FusionEngine()
    from detection.enforcement_engine import EnforcementEngine
    enforcement_engine = EnforcementEngine()
    
    # Track results
    results = {
        "samples": [],
        "categories": {},
        "actions": {},
        "total": len(dataset),
        "total_with_pii": 0
    }
    
    print(f"\n Running Phase 1 Detector on {len(dataset)} PANORAMA Samples")
    print("=" * 80)
    
    for idx, sample in enumerate(dataset):
        text = sample.get("text", "")
        if not text:
            continue
        
        # Normalize
        normalized = normalizer.normalize(text)
        
        # Rule detection
        rule_cat, rule_sev, rule_signals = rule_engine.analyze(normalized)
        
        # NER detection
        ner_result = ner_detector.extract_entities(normalized)
        
        # LLM detection
        try:
            llm_raw = llm_engine.classify(normalized)
            llm_result = json.loads(llm_raw)
        except Exception as e:
            llm_result = {
                "category": "NORMAL",
                "severity": "LOW",
                "entities": {}
            }
        
        # Fusion
        rule_result = {
            "category": rule_cat,
            "severity": rule_sev
        }
        fused = fusion_engine.fuse(rule_result, llm_result, ner_result)
        
        # Enforcement
        enforced = enforcement_engine.enforce(fused)
        action = enforced.get("action", "ALLOW")
        
        # Track results
        pred_category = fused.get("category", "NORMAL")
        
        results["samples"].append({
            "text": text[:80],
            "category": pred_category,
            "severity": fused.get("severity", "LOW"),
            "action": action,
            "entities_count": ner_result.get("total_entities", 0)
        })
        
        # Track by category
        if pred_category not in results["categories"]:
            results["categories"][pred_category] = 0
        results["categories"][pred_category] += 1
        
        # Track by action
        if action not in results["actions"]:
            results["actions"][action] = 0
        results["actions"][action] += 1
        
        # Count PII detections
        if pred_category != "NORMAL":
            results["total_with_pii"] += 1
        
        if (idx + 1) % 20 == 0:
            print(f"   Processed {idx + 1}/{len(dataset)} samples")
    
    return results


def print_results(results):
    """Print evaluation results in a nice format."""
    
    if results is None:
        return
    
    print("\n" + "=" * 80)
    print(" PHASE 1 DETECTOR - PANORAMA DATASET EVALUATION")
    print("=" * 80)
    
    # Summary stats
    total = results["total"]
    with_pii = results["total_with_pii"]
    print(f"\nSUMMARY")
    print(f"  Total samples: {total}")
    print(f"  Samples with PII detected: {with_pii} ({with_pii/total:.1%})")
    
    # Category breakdown
    print(f"\nCATEGORY DISTRIBUTION")
    for cat in sorted(results["categories"].keys()):
        count = results["categories"][cat]
        pct = count / total
        print(f"  {cat:15s}: {count:4d} ({pct:.1%})")
    
    # Action breakdown
    print(f"\nENFORCEMENT ACTION DISTRIBUTION")
    for action in sorted(results["actions"].keys()):
        count = results["actions"][action]
        pct = count / total
        print(f"  {action:20s}: {count:4d} ({pct:.1%})")
    
    # Sample predictions
    print(f"\nSAMPLE PREDICTIONS (first 10)")
    for sample in results["samples"][:10]:
        print(f"  • {sample['text'][:75]}")
        print(f"      Category: {sample['category']}, Severity: {sample['severity']}, Action: {sample['action']}")
    
    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser( # this is used for parsing command line arguments when running the script
        description="Evaluate PriVoke Phase 1 on PANORAMA dataset"
    )
    parser.add_argument( # this adds a command line argument for --limit which specifies how many samples to evaluate, with a default of 100
        "--limit", type=int, default=100,
        help="Number of samples to evaluate (default: 100, 0=all)"
    )
    parser.add_argument( # this adds a command line argument for --output which specifies a JSON file to save the results to
        "--output", type=str,
        help="Save results to JSON file"
    )
    
    args = parser.parse_args() # this parses the command line arguments and stores them in the args variable
    
    results = evaluate_on_panorama(limit=args.limit) # this calls the evaluate_on_panorama function with the specified limit and stores the results in the results variable
    print_results(results) # this calls the print_results function to display the evaluation results in a readable format
    
    if args.output and results:
        # Save results to JSON, excluding non-serializable data (like raw text samples)
        import datetime
        output = {
            k: v for k, v in results.items() # Only include serializable items in the output JSON (e.g., counts and distributions, but not raw text samples which may contain complex objects or be too large)
            if k not in ["samples"] or isinstance(v, (str, int, float, bool, list, dict)) # Only include 'samples' if it's a serializable type (e.g., list of dicts without complex objects)
        }
        with open(args.output, "w") as f: # this opens the specified output file in write mode and assigns it to the variable f
            json.dump(output, f, indent=2, default=str) # this writes the output dictionary to the file in JSON format with indentation for readability, and uses default=str to handle any non-serializable objects by converting them to strings
        print(f"\n Results saved to {args.output}") # this prints a message indicating that the results have been saved to the specified output file


if __name__ == "__main__":
    main()
