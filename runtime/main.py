from datasets import load_dataset  # load dataset from hugging face

from preprocessing.normalizer import TextNormalizer  # text normalisation class
from detection.rule_detector import RuleDetector  # rule-based detection
from detection.llm_classifier import InternalModelService  # LLM-based detection
from detection.fusion import FusionEngine  # fusion class
import random  # for selecting random samples
import json


def run_pipeline(): # privoke detection pipeline 

    normalizer = TextNormalizer()
    rule_engine = RuleDetector()
    llm_engine = InternalModelService()  # API key loaded from .env automatically
    fusion = FusionEngine()

    dataset = load_dataset("srirxml/PANORAMA")

    print("\n=== PriVoke PIPELINE DEMO ===")

    indices = random.sample(range(len(dataset["train"])), 5)
    for i in indices:

        text = dataset["train"][i]["text"]

        print("\n--- ORIGINAL ---")
        print(text)

        # STEP 1: normalize
        cleaned = normalizer.normalize(text)

        print("\n--- NORMALIZED ---")
        print(cleaned)

        # STEP 2: rule detection
        category, severity, reason = rule_engine.analyze(cleaned)

        rule_result = {
            "category": category,
            "severity": severity,
            "signals": reason
        }
        print("\n--- RULE DETECTION ---")
        print(rule_result)

        # STEP 3: LLM semantic detection 
        llm_raw = llm_engine.classify(cleaned)

        try:
            llm_result = json.loads(llm_raw)
        except:
           llm_result = {
            "category": "NORMAL",
            "severity": "LOW",
            "entities": {
                "email": False,
                "phone": False,
                "location": False,
                "username": False,
                "name": False
            },
            "reason": "parse error"
        }

        print("\n--- LLM ANALYSIS ---")
        print(llm_result)

        # STEP 4: fuse
        disagreement = rule_result["category"] != llm_result.get("category")

        final = fusion.fuse(rule_result, llm_result)
        final["disagreement"] = disagreement

        print("DATA TYPE:", final["data_type"])
        print("DATA TYPE EXPLANATION:", final["data_type_explanation"])
        print("DISAGREEMENT:", final["disagreement"])

        print("-" * 60)
        print("\n--- FINAL DECISION ---")
        print(final)

        if rule_result["category"] != llm_result.get("category"):
            print("⚠️ DISAGREEMENT DETECTED")


if __name__ == "__main__":
    run_pipeline()