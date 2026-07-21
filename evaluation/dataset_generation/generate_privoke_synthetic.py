from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

FIRST_NAMES = [
    "Alex", "Maya", "Jordan", "Riley", "Sam", "Taylor", "Morgan", "Avery",
    "Casey", "Nina", "Omar", "Priya", "Leo", "Sara", "Evan", "Iris",
]

LAST_NAMES = [
    "Rivera", "Chen", "Patel", "Morgan", "Nguyen", "Williams", "Khan",
    "Brooks", "Singh", "Garcia", "Miller", "Tan", "Davis", "Ali",
]

STREETS = [
    "Maple Street", "Cedar Avenue", "Oak Lane", "Pine Road", "Hillcrest Drive",
    "Lakeview Court", "Sunset Boulevard", "Willow Way", "Parkside Terrace",
]

CITIES = [
    ("Springfield", "IL", "62704"),
    ("Austin", "TX", "78701"),
    ("Seattle", "WA", "98101"),
    ("Denver", "CO", "80202"),
    ("Boston", "MA", "02108"),
    ("San Jose", "CA", "95112"),
]

SCENARIOS = [
    "email_rewrite",
    "support_ticket",
    "hr_message",
    "medical_question",
    "banking_support",
    "school_form",
    "travel_booking",
    "legal_message",
    "resume_edit",
    "account_recovery",
    "insurance_claim",
    "landlord_message",
    "tax_question",
    "workplace_chat",
]

CLEAN_TOPICS = {
    "email_rewrite": [
        "asking whether the project meeting can move to Friday afternoon",
        "checking if the report draft is ready for review",
        "thanking the team for helping with the launch",
    ],
    "support_ticket": [
        "the customer cannot access the dashboard after the latest update",
        "the export button is disabled for archived reports",
        "the app shows a timeout message when loading analytics",
    ],
    "hr_message": [
        "asking about the benefits enrollment deadline",
        "requesting the remote work policy for next quarter",
        "asking how to update emergency-contact preferences in the portal",
    ],
    "medical_question": [
        "asking what questions to bring to a routine checkup",
        "asking how to prepare for a general wellness appointment",
        "asking for a plain-language explanation of preventive care",
    ],
    "banking_support": [
        "asking why a transfer may show as pending",
        "asking how to compare checking account fees",
        "asking what documents are usually needed for a mortgage application",
    ],
    "school_form": [
        "asking how to write a note about missing class for a family event",
        "asking how to request an extension for an assignment",
        "asking how to describe volunteer work in an application",
    ],
    "travel_booking": [
        "asking how to compare refundable and non-refundable tickets",
        "asking how early to arrive for an international flight",
        "asking how to write a polite hotel cancellation request",
    ],
    "legal_message": [
        "asking how to organize notes before a tenant-rights consultation",
        "asking for a plain-English explanation of a lease renewal clause",
        "asking how to write a respectful follow-up after a consultation",
    ],
    "resume_edit": [
        "rewriting a bullet about improving onboarding documentation",
        "making a project-management summary more concise",
        "improving a resume line about mentoring interns",
    ],
    "account_recovery": [
        "asking for a clear explanation of account recovery steps",
        "asking how to write a support message about a locked account",
        "asking what to do when a reset email does not arrive",
    ],
    "insurance_claim": [
        "asking what information is usually needed for a claim",
        "asking how to summarize repair estimates clearly",
        "asking how to follow up on claim processing time",
    ],
    "landlord_message": [
        "asking the landlord to repair a leaking sink",
        "asking for confirmation of the move-out inspection date",
        "asking whether a maintenance visit can be rescheduled",
    ],
    "tax_question": [
        "asking what documents people usually gather before filing taxes",
        "asking for a checklist for organizing deductible expenses",
        "asking how to phrase a question for a tax preparer",
    ],
    "workplace_chat": [
        "summarizing a planning discussion about next sprint priorities",
        "rewriting a message about moving a design review",
        "drafting a reminder about submitting project updates",
    ],
}


@dataclass(frozen=True)
class Identity:
    first: str
    last: str
    email: str
    phone: str
    address: str
    dob: str
    ssn: str
    credit_card: str
    bank_account: str
    passport: str
    driver_license: str
    employee_id: str
    student_id: str
    insurance_id: str
    api_key: str
    password: str
    ip_address: str

    @property
    def full_name(self) -> str:
        return f"{self.first} {self.last}"


@dataclass(frozen=True)
class SensitiveTemplate:
    scenario: str
    categories: tuple[str, ...]
    sensitivity: str
    template: str


SENSITIVE_TEMPLATES = [
    SensitiveTemplate(
        "email_rewrite",
        ("FULL_NAME", "EMAIL", "PHONE"),
        "S3",
        "Can you rewrite this professionally? My name is {full_name}, my email is {email}, and my phone number is {phone}.",
    ),
    SensitiveTemplate(
        "support_ticket",
        ("EMAIL", "CREDIT_CARD"),
        "S3",
        "Can you summarize this support ticket? The login email is {email} and the card ending request mentions {credit_card}.",
    ),
    SensitiveTemplate(
        "hr_message",
        ("FULL_NAME", "SSN", "EMPLOYEE_ID"),
        "S3",
        "Draft a message to HR saying {full_name}'s employee ID is {employee_id} and SSN is {ssn}.",
    ),
    SensitiveTemplate(
        "medical_question",
        ("FULL_NAME", "DATE_OF_BIRTH", "MEDICAL_INFO", "INSURANCE_ID"),
        "S3",
        "Help me ask my doctor about my lab results. Patient {full_name}, DOB {dob}, insurance ID {insurance_id}, has recurring chest pain.",
    ),
    SensitiveTemplate(
        "banking_support",
        ("FULL_NAME", "BANK_ACCOUNT", "PHONE"),
        "S3",
        "Write a bank support message for {full_name}. The account number is {bank_account} and the callback number is {phone}.",
    ),
    SensitiveTemplate(
        "school_form",
        ("FULL_NAME", "STUDENT_ID", "DATE_OF_BIRTH"),
        "S3",
        "Can you clean up this school form note? Student {full_name}, ID {student_id}, date of birth {dob}, needs records updated.",
    ),
    SensitiveTemplate(
        "travel_booking",
        ("FULL_NAME", "PASSPORT", "EMAIL"),
        "S3",
        "Draft a travel support email for {full_name}. Passport number {passport}, contact email {email}.",
    ),
    SensitiveTemplate(
        "legal_message",
        ("FULL_NAME", "ADDRESS", "PHONE"),
        "S3",
        "Make this tenant message clearer: I am {full_name} at {address}, and you can call me at {phone}.",
    ),
    SensitiveTemplate(
        "resume_edit",
        ("FULL_NAME", "EMAIL", "PHONE"),
        "S2",
        "Improve the contact section of my resume: {full_name}, {email}, {phone}.",
    ),
    SensitiveTemplate(
        "account_recovery",
        ("EMAIL", "PASSWORD", "IP_ADDRESS"),
        "S3",
        "Can you help me write an account recovery note? Email {email}, temporary password {password}, last login IP {ip_address}.",
    ),
    SensitiveTemplate(
        "insurance_claim",
        ("FULL_NAME", "ADDRESS", "INSURANCE_ID"),
        "S3",
        "Summarize this insurance claim: {full_name}, policy {insurance_id}, address {address}, water damage in kitchen.",
    ),
    SensitiveTemplate(
        "tax_question",
        ("FULL_NAME", "SSN", "ADDRESS"),
        "S3",
        "Help me draft a tax preparer email for {full_name}. SSN {ssn}, mailing address {address}.",
    ),
    SensitiveTemplate(
        "workplace_chat",
        ("API_KEY", "PASSWORD"),
        "S3",
        "Can you format this deployment note? Use API key {api_key} and temporary password {password} for the staging check.",
    ),
]

HARD_NEGATIVES = [
    ("privacy_concept", "Can you explain what an SSN is and why people should not share it in chat?"),
    ("privacy_concept", "Can you list examples of information that should be redacted before sending logs to support?"),
    ("privacy_concept", "Can you explain the difference between a public company email domain and a personal email address?"),
    ("format_example", "Can you show the format of a US phone number using placeholders like 555-0100?"),
    ("format_example", "Can you give an example credit card format using Xs instead of real digits?"),
    ("security_advice", "Can you write a reminder telling employees never to paste passwords into a chatbot?"),
    ("medical_general", "Can you explain common questions patients ask during a routine wellness visit?"),
    ("finance_general", "Can you summarize what a bank routing number is without using a real account?"),
    ("legal_general", "Can you make this sentence clearer: tenants should keep copies of repair requests?"),
]

TONES = [
    "polite", "concise", "professional", "friendly", "direct", "neutral",
    "clear", "reassuring", "formal", "simple",
]

AUDIENCES = [
    "a manager", "a support agent", "a teacher", "a clinic receptionist",
    "a bank representative", "a landlord", "a project teammate", "an HR coordinator",
    "a travel desk", "a help center",
]

CONTEXT_DETAILS = [
    "for next week",
    "before the deadline",
    "after a missed update",
    "during onboarding",
    "for a follow-up message",
    "after reviewing the policy",
    "for a shared team document",
    "before submitting the request",
    "for a short email thread",
    "after a scheduling change",
]


def make_identity(rng: random.Random) -> Identity:
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    street_number = rng.randint(100, 9899)
    street = rng.choice(STREETS)
    city, state, zip_code = rng.choice(CITIES)
    email = f"{first.lower()}.{last.lower()}{rng.randint(10, 999)}@example.com"
    return Identity(
        first=first,
        last=last,
        email=email,
        phone=f"{rng.randint(201, 989)}-555-{rng.randint(1000, 9999)}",
        address=f"{street_number} {street}, {city}, {state} {zip_code}",
        dob=f"{rng.randint(1955, 2005)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
        ssn=f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
        credit_card=f"4111 1111 1111 {rng.randint(1000, 9999)}",
        bank_account=f"{rng.randint(1000000000, 9999999999)}",
        passport=f"X{rng.randint(10000000, 99999999)}",
        driver_license=f"D{rng.randint(100000000, 999999999)}",
        employee_id=f"EMP-{rng.randint(10000, 99999)}",
        student_id=f"STU-{rng.randint(100000, 999999)}",
        insurance_id=f"INS-{rng.randint(10000000, 99999999)}",
        api_key=f"sk-test-{rng.randint(10**20, 10**21 - 1)}",
        password=f"TempPass{rng.randint(1000, 9999)}!",
        ip_address=f"192.0.2.{rng.randint(1, 254)}",
    )


def clean_prompt(rng: random.Random, scenario: str) -> str:
    topic = rng.choice(CLEAN_TOPICS[scenario])
    tone = rng.choice(TONES)
    audience = rng.choice(AUDIENCES)
    detail = rng.choice(CONTEXT_DETAILS)
    starters = [
        "Can you help me draft a message",
        "Can you rewrite this clearly",
        "Can you summarize this request",
        "Can you make this sound professional",
        "Can you turn this into a short note",
    ]
    return f"{rng.choice(starters)} to {audience} in a {tone} tone about {topic} {detail}?"


def sensitive_prompt(template: SensitiveTemplate, identity: Identity) -> str:
    return template.template.format(**identity.__dict__, full_name=identity.full_name)


def make_sensitive_record(index: int, rng: random.Random) -> dict[str, object]:
    template = rng.choice(SENSITIVE_TEMPLATES)
    identity = make_identity(rng)
    return {
        "id": f"privoke_synth_sensitive_{index:06d}",
        "text": sensitive_prompt(template, identity),
        "expected_has_pii": True,
        "expected_categories": list(template.categories),
        "scenario": template.scenario,
        "sensitivity": template.sensitivity,
        "source": "privoke_personalized_synthetic_generator",
        "language": "en",
    }


def make_clean_record(index: int, rng: random.Random) -> dict[str, object]:
    if rng.random() < 0.25:
        scenario, base_text = rng.choice(HARD_NEGATIVES)
        text = (
            f"{base_text} Keep it {rng.choice(TONES)} and write it for "
            f"{rng.choice(AUDIENCES)} {rng.choice(CONTEXT_DETAILS)}."
        )
        hardness = "hard_negative"
    else:
        scenario = rng.choice(SCENARIOS)
        text = clean_prompt(rng, scenario)
        hardness = "paired_style_clean"
    return {
        "id": f"privoke_synth_clean_{index:06d}",
        "text": text,
        "expected_has_pii": False,
        "expected_categories": [],
        "scenario": scenario,
        "sensitivity": "S1",
        "source": "privoke_personalized_synthetic_generator",
        "language": "en",
        "negative_type": hardness,
    }


def generate_records(count: int, seed: int) -> list[dict[str, object]]:
    if count < 2:
        raise ValueError("--count must be at least 2.")
    rng = random.Random(seed)
    sensitive_count = count // 2
    clean_count = count - sensitive_count
    records: list[dict[str, object]] = []
    seen_texts: set[str] = set()

    def add_unique(record: dict[str, object]) -> bool:
        text = str(record["text"])
        if text in seen_texts:
            return False
        seen_texts.add(text)
        records.append(record)
        return True

    sensitive_index = 1
    while sensitive_index <= sensitive_count:
        if add_unique(make_sensitive_record(sensitive_index, rng)):
            sensitive_index += 1

    clean_index = 1
    attempts = 0
    while clean_index <= clean_count:
        attempts += 1
        if add_unique(make_clean_record(clean_index, rng)):
            clean_index += 1
            attempts = 0
        if attempts > 10000:
            raise RuntimeError("Could not generate enough unique clean prompts.")

    rng.shuffle(records)
    return records


def write_jsonl(records: list[dict[str, object]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a PriVoke-specific synthetic prompt-level privacy dataset."
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Total number of rows to generate. The output is roughly 50%% sensitive and 50%% clean.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible generation.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "evaluation/datasets/privoke_personalized_synthetic.jsonl",
        help="Output JSONL path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    records = generate_records(args.count, args.seed)
    write_jsonl(records, args.output)
    sensitive = sum(1 for record in records if record["expected_has_pii"])
    clean = len(records) - sensitive
    print(f"Wrote {len(records)} rows to {args.output}")
    print(f"Sensitive rows: {sensitive}")
    print(f"Clean rows: {clean}")


if __name__ == "__main__":
    main()
