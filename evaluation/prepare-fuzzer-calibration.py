"""Author a reproducible fictional clean-topic curriculum; never copy benchmark rows."""
import json
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CLEAN = (
    "The public schedule describes maintenance windows and service availability.",
    "The general handbook explains how salary bands and tax brackets work.",
    "The standard contract describes aggregate spending and reporting procedures.",
    "The public product list gives a suggested price of {amount}.",
    "The location guide explains how distance and route planning are calculated.",
    "The blank application template contains no completed personal fields.",
    "The committee reviews general compliance procedures for the next reporting period.",
    "A public health brochure explains {condition} without patient details.",
    "Explain public banking fees and interest calculations using generic examples.",
    "The blank legal form has headings without client details or a case record.",
    "The technical summary describes aggregate accuracy and error rates.",
    "The public instruction manual explains how to format a document and its headings.",
)
CLEAN_ENDINGS = (
    "It is intended for general reference.",
    "It contains no completed identifying information.",
    "The material describes a general process rather than an individual record.",
    "Only general instructions and aggregate descriptions are included.",
    "No person's contact, account or residence details are supplied.",
    "The text explains terminology without disclosing an individual's circumstances.",
)
PRIVATE = (
    ("My {account} at {bank} shows a balance of {amount}.", "S2", "PU", ["FINANCIAL"]),
    ("My salary is {amount} and my mortgage debt is overdue.", "S2", "PU", ["FINANCIAL"]),
    ("My doctor prescribed {medication} after my {condition} diagnosis.", "S3", "PU", ["HEALTH"]),
    ("My diagnosis is {condition} and I am taking {medication}.", "S3", "PU", ["HEALTH"]),
    ("My home address is in {city} near my workplace.", "S2", "PU", ["LOCATION"]),
    ("I work at {employer} and I am the only person in my role in {city}.", "S2", "PU", ["IDENTITY", "LOCATION"]),
    ("My contact email is fictional.person@example.invalid.", "S3", "PU", ["IDENTITY"]),
    ("My phone number is +61 400 000 000.", "S3", "PU", ["IDENTITY"]),
    ("In a {group}, {name} said their {relative} was diagnosed with {condition}.", "S3", "P3", ["HEALTH", "THIRD_PARTY"]),
    ("My private diary says I voted for a political party and left my religion.", "S3", "P4", ["POLITICS", "RELIGION"]),
    ("My {relative} has a court date after a DUI charge.", "S3", "PU", ["CRIMINAL", "THIRD_PARTY"]),
    ("My {relative}'s private medical record describes their {condition} diagnosis.", "S3", "PU", ["HEALTH", "THIRD_PARTY"]),
)
PRIVATE_ENDINGS = (
    "Please help me understand this information.",
    "Please summarize the details accurately.",
    "Please explain the practical implications of these details.",
)
ANCHORS = (
    ("this was posted publicly for everyone", "S0", "P0", []),
    ("discussion in a public community forum", "S0", "P1", []),
    ("the page is restricted behind login", "S0", "P2", []),
    ("I sent this in a private group chat", "S0", "P3", []),
    ("this is a private diary for my eyes only", "S0", "P4", []),
    ("explain privacy using imaginary placeholders", "S0", "PU", []),
    ("write a friendly email about tomorrow's meeting", "S0", "PU", []),
    ("summarise this public product documentation", "S0", "P0", []),
    ("what is the weather forecast", "S0", "PU", []),
    ("help me format a generic travel checklist", "S0", "PU", []),
    ("my diagnosis is cancer", "S3", "PU", ["HEALTH"]),
    ("my therapist prescribed medication", "S3", "PU", ["HEALTH"]),
    ("I am pregnant and have anxiety", "S3", "PU", ["HEALTH"]),
    ("my bank account and mortgage debt", "S2", "PU", ["FINANCIAL"]),
    ("my salary and credit score", "S2", "PU", ["FINANCIAL"]),
    ("I filed a tax return", "S2", "PU", ["FINANCIAL"]),
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evaluation/datasets/fuzzer-calibration.json")
    parser.add_argument("--include-bootstrap-anchors", action="store_true")
    args = parser.parse_args()
    output = args.output
    if output.exists():
        raise SystemExit("Refusing to overwrite a curriculum used in research.")
    rows = []
    for family, text in enumerate(CLEAN):
        for ending in CLEAN_ENDINGS:
            rows.append({"template": text + " " + ending,
                         "classification": {"sensitivity": "S0", "visibility": "P0", "categories": []},
                         "metadata": {"dataset": "agent_authored_fictional_calibration",
                                      "family": f"clean_{family}", "label_status": "provisional"}})
    for family, (text, sensitivity, visibility, categories) in enumerate(PRIVATE):
        for ending in PRIVATE_ENDINGS:
            rows.append({"template": text + " " + ending,
                         "classification": {"sensitivity": sensitivity, "visibility": visibility,
                                            "categories": categories},
                         "metadata": {"dataset": "agent_authored_fictional_calibration",
                                      "family": f"private_{family}", "label_status": "provisional"}})
    if args.include_bootstrap_anchors:
        for text, sensitivity, visibility, categories in ANCHORS:
            rows.append({"template": text, "classification": {
                "sensitivity": sensitivity, "visibility": visibility, "categories": categories},
                "metadata": {"dataset": "existing_bootstrap_calibration_anchor",
                             "label_status": "existing_internal_training_label"}})
    assert len({row["template"] for row in rows}) == len(rows)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(rows, indent=2) + "\n")
    print(json.dumps({"path": str(output), "clean_templates": 72, "sensitive_templates": 36,
                      "bootstrap_anchors": len(ANCHORS) if args.include_bootstrap_anchors else 0,
                      "scope": "Fictional development training; provisional labels, not contextual test ground truth"}))


if __name__ == "__main__":
    main()
