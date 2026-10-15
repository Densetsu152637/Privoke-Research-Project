"""Prepare provisional contextual training without opening locked final examples."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared/python"))
sys.path.insert(0, str(ROOT / "evaluation"))
from privoke_contracts.classification import Category
from privoke_model.training_data import training_text_key
from privoke_eval.clean_augmentation_grouping import opaque_exclusion_key

PUBLIC_SHA = "61b0d5c5f06fe0d948092f86044eb21c64a08c5f6d4f60ec6ecfb1466d42ecda"
VALIDATION_SHA = "d2d0c538e49f5bbc7a8f85887b9b8cfddb188a5ab9aae55c69ce26ae932be6d1"
INDEX_SHA = "c0700613a965e26b85a2511c8a721b2f808536f215b8fe6f18f0d3890634fc2d"
FIXTURE_SHA = "d6c7d5d87235cd6b0f9d24eac43b30c3ace9f0bf4f421ef5d5d812de79827a17"


def digest(content):
    return hashlib.sha256(content).hexdigest()


def read_bound(path, expected):
    content = Path(path).read_bytes()
    if digest(content) != expected:
        raise ValueError(f"Input byte commitment changed: {path}")
    return content


def rows(content):
    return [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]


def strict_target(row):
    target = row.get("classification")
    if not isinstance(target, dict) or set(target) != {"sensitivity", "visibility", "categories"}:
        raise ValueError("Contextual training requires explicit complete classification targets.")
    if target["sensitivity"] not in {"S0", "S1", "S2", "S3"} or target["visibility"] not in {"P0", "P1", "P2", "P3", "P4", "PU"}:
        raise ValueError("Invalid sensitivity or visibility target.")
    categories = target["categories"]
    if not isinstance(categories, list) or any(type(x) is not str or x not in Category.__members__ for x in categories) or len(set(categories)) != len(categories):
        raise ValueError("Invalid explicit category targets.")
    if not isinstance(row.get("template"), str) or not row["template"].strip():
        raise ValueError("Training template must be nonempty text.")
    metadata = row.get("metadata", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("group_id"), str) or not metadata["group_id"].strip() or not metadata.get("label_status"):
        raise ValueError("Every contextual example requires a declared group and label provenance.")


def authored_rows():
    """Whole-family contrast pairs; fictional values carry explicitly asserted roles."""
    families = [
        ("ledger_contrast", "Explain how an empty expense ledger calculates totals without any completed entries.", "My household ledger records an unpaid utility debt of 640 dollars.", "S2", "PU", ["FINANCIAL"]),
        ("treatment_contrast", "Describe the steps in an unfilled treatment-plan template using no patient details.", "My specialist started treatment for my rheumatoid arthritis last Tuesday.", "S3", "PU", ["HEALTH"]),
        ("workplace_contrast", "Outline generic workplace access procedures without employee records.", "My employer Northpine Studio is reviewing my private disciplinary complaint.", "S2", "PU", ["IDENTITY"]),
        ("recovery_contrast", "Explain account recovery with blank fields and no working secrets.", "The recovery password for my account is synthetic-working-secret-841.", "S3", "PU", ["IDENTITY"]),
        ("contact_contrast", "Show blank contact-field headings without filled contact details.", "Reach me at fictional.contact841@example.invalid about my case.", "S3", "PU", ["IDENTITY"]),
        ("residence_contrast", "Explain how a blank moving checklist is organized without identifying a resident.", "I live at 841 Fictional Crescent and will be away this weekend.", "S2", "PU", ["LOCATION"]),
        ("enrolment_contrast", "Describe school enrolment procedures without student details.", "My eight-year-old daughter attends the fictional Elmcrest School and has dyslexia.", "S3", "PU", ["CHILD", "HEALTH", "THIRD_PARTY"]),
        ("legal_contrast", "Explain the headings in an empty legal intake form without client details.", "My brother is awaiting sentencing after his fraud conviction.", "S3", "PU", ["CRIMINAL", "THIRD_PARTY"]),
        ("belief_contrast", "Compare general civic participation concepts without personal affiliations.", "In this private group chat, I describe leaving my religion and joining a political party.", "S3", "P3", ["RELIGION", "POLITICS"]),
        ("journal_contrast", "Explain how to organize a blank journal without personal entries.", "This diary is for my eyes only: I am undergoing fertility treatment.", "S3", "P4", ["HEALTH"]),
        ("credit_contrast", "Define credit-report terminology without anyone's actual credit information.", "My credit report says my loan is delinquent and my score is 510.", "S2", "PU", ["FINANCIAL"]),
        ("coworker_contrast", "Describe anonymous survey design without identifiable respondent details.", "My colleague Fictional Rowan told me privately that they have epilepsy.", "S3", "PU", ["HEALTH", "THIRD_PARTY", "IDENTITY"]),
        ("public_listing_contrast", "Summarize a public list of exhibition opening hours with no visitor records.", "My private visitor record identifies my weekly therapy appointments.", "S3", "PU", ["HEALTH"]),
        ("route_contrast", "Explain route-planning notation without an individual's whereabouts.", "I am staying at Fictional Lodge room 841 until Friday.", "S2", "PU", ["LOCATION"]),
        ("invoice_contrast", "Describe blank invoice headings without customer or account information.", "My bank account at Fictional Harbor Bank contains 2840 dollars.", "S2", "PU", ["FINANCIAL"]),
        ("restricted_contrast", "Explain what login-protected documentation means without a completed private record.", "Behind login, my patient record shows my recent depression diagnosis.", "S3", "P2", ["HEALTH"]),
    ]
    result = []
    endings = ("Please summarize the supplied information.", "Help me write a concise explanation.", "Explain the wording in plain language.", "Please check the text for clarity.")
    for family, clean, private, severity, visibility, categories in families:
        for sensitive, text in ((False, clean), (True, private)):
            for variant, ending in enumerate(endings):
                result.append({"template": f"{text} {ending}", "classification": {"sensitivity": severity if sensitive else "S0", "visibility": visibility if sensitive else "PU", "categories": categories if sensitive else []}, "metadata": {"example_id": f"ctx-fuzzer-{family}-{int(sensitive)}-{variant}", "group_id": f"ctx-fuzzer-family:{family}", "training_role": "authored_contrastive_context", "label_status": "hand_authored_assistant_provisional", "source": "contextual-fuzzer-study-20261006"}})
    return result


def prepare(public, validation, fixture, index, *, enforce_counts=True):
    validation_groups = {r["group_id"] for r in validation}
    validation_ids = {r["id"] for r in validation}
    validation_texts = {training_text_key(r["text"]) for r in validation}
    fixture_texts = {training_text_key(r["text"]) for r in fixture}
    fixture_families = {r["family_id"] for r in fixture}
    protected = index["key_sets"]
    protected_groups, protected_ids, protected_texts = (set(protected[k]) for k in ("groups", "ids", "texts"))
    retained, removed = [], []
    for row in public:
        strict_target(row)
        meta, text = row["metadata"], row["template"]
        # Public source braces were already escaped by its pinned preparer.
        literal = text.replace("{{", "{").replace("}}", "}")
        if meta["group_id"] in validation_groups or meta.get("example_id") in validation_ids or training_text_key(literal) in validation_texts:
            removed.append(row)
            continue
        if opaque_exclusion_key("group", meta["group_id"]) in protected_groups or opaque_exclusion_key("id", meta.get("example_id", "")) in protected_ids or opaque_exclusion_key("text_key", training_text_key(literal)) in protected_texts or training_text_key(literal) in fixture_texts:
            raise ValueError("Pinned public curriculum collides with a protected endpoint.")
        retained.append(row)
    if enforce_counts and (len(public) != 2443 or len(removed) != 271 or len(retained) != 2172 or len({r["metadata"]["group_id"] for r in removed}) != 190):
        raise ValueError("Pinned public/validation exclusion counts changed.")
    novel = authored_rows()
    for row in novel:
        strict_target(row)
        meta, text = row["metadata"], row["template"]
        key = training_text_key(text)
        if meta["group_id"] in validation_groups or meta["group_id"] in fixture_families or key in validation_texts | fixture_texts or opaque_exclusion_key("text_key", key) in protected_texts or opaque_exclusion_key("id", meta["example_id"]) in protected_ids or opaque_exclusion_key("group", meta["group_id"]) in protected_groups:
            raise ValueError("Authored curriculum overlaps protected evidence.")
    combined = retained + novel
    keys = [training_text_key(r["template"].replace("{{", "{").replace("}}", "}")) for r in combined]
    if len(keys) != len(set(keys)):
        raise ValueError("Training normalized texts must be unique.")
    groups = {r["metadata"]["group_id"] for r in combined}
    if len(groups) < 16 or groups & validation_groups:
        raise ValueError("Insufficient disjoint training source groups.")
    return combined, {"retained_public_and_replay": len(retained), "excluded_validation_rows": len(removed), "excluded_validation_groups": len({r["metadata"]["group_id"] for r in removed}), "authored_rows": len(novel), "authored_families": len({r["metadata"]["group_id"] for r in novel}), "rows": len(combined), "groups": len(groups), "sensitivity_counts": dict(Counter(r["classification"]["sensitivity"] for r in combined))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()
    source = args.source_results
    inputs = {"public": (source / "public-negative-curriculum/prompts.jsonl", PUBLIC_SHA), "validation": (source / "representation_20261004_v3/prepared/validation.jsonl", VALIDATION_SHA), "fixture": (source / "contextual_fixtures_20261004_v1/support/fixture.jsonl", FIXTURE_SHA), "index": (source / "external_pii_20261004_prepared_v3/exclusion-index.json", INDEX_SHA)}
    content = {k: read_bound(path, commitment) for k, (path, commitment) in inputs.items()}
    curriculum, counts = prepare(rows(content["public"]), rows(content["validation"]), rows(content["fixture"]), json.loads(content["index"]))
    manifest = {"schema_version": 1, "scope": "Provisional contextual head/last-block training; reused exploratory validation, no final access", "inputs": {k: {"path": str(path.resolve()), "sha256": commitment} for k, (path, commitment) in inputs.items()}, "counts": counts, "label_limitation": "Public negatives are annotation-proxy S0/PU; bootstrap replay and authored contextual labels are provisional, not independently established human truth.", "final_access": "none; only pinned opaque exclusion index used"}
    print(json.dumps(manifest, indent=2))
    if args.inspect_only:
        return
    if args.output.exists():
        raise SystemExit("Refusing existing preparation output.")
    args.output.mkdir(parents=True)
    raw = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in curriculum).encode("utf-8")
    (args.output / "prompts.jsonl").write_bytes(raw)
    manifest["curriculum_sha256"] = digest(raw)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
