from __future__ import annotations

import argparse
import json
import os
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
API_KEY_RE = re.compile(r"\b(?:sk|pk|ghp|xoxb|AKIA)[-_A-Za-z0-9]{16,}\b")
PASSWORD_RE = re.compile(r"\b(?:password|passwd|pwd|passcode)\s*[:=]\s*\S+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DATE_RE = re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")
LICENSE_PLATE_RE = re.compile(r"\b[A-Z]{3}-\d{4}\b")
CRYPTO_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
TOKEN_URL_RE = re.compile(r"https?://\S+(?:token|key|secret|auth)=\S+", re.IGNORECASE)

SENSITIVE_PATTERNS = [
    EMAIL_RE,
    PHONE_RE,
    SSN_RE,
    CREDIT_CARD_RE,
    API_KEY_RE,
    PASSWORD_RE,
    IP_RE,
    DATE_RE,
    IBAN_RE,
    MAC_RE,
    VIN_RE,
    LICENSE_PLATE_RE,
    CRYPTO_RE,
    TOKEN_URL_RE,
]

FIRST_NAMES = [
    "Alex", "Maya", "Jordan", "Riley", "Sam", "Taylor", "Morgan", "Avery",
    "Casey", "Nina", "Omar", "Priya", "Leo", "Sara", "Evan", "Iris",
]

LAST_NAMES = [
    "Rivera", "Chen", "Patel", "Nguyen", "Williams", "Khan", "Brooks",
    "Singh", "Garcia", "Miller", "Tan", "Davis", "Ali", "Roberts",
]

PERSONAS = [
    "stressed retail customer",
    "senior software engineer",
    "medical billing clerk",
    "impatient student",
    "HR coordinator",
    "small business owner",
    "tenant dealing with repairs",
    "parent filling a school form",
    "banking customer",
    "travel desk employee",
]

CONTEXTS = [
    "chatting with an AI assistant",
    "submitting a website contact form",
    "typing in a customer support portal",
    "pasting into a coding assistant",
    "rewriting an email",
    "summarizing a pasted document",
    "asking for help with a form",
    "drafting a complaint",
]

STYLES = [
    "messy with typos",
    "short and blunt",
    "very formal",
    "rambling and anxious",
    "bullet points",
    "casual text-message style",
    "corporate and polished",
    "fragmented copy-paste style",
]

SCENARIOS = [
    "account_recovery",
    "medical_question",
    "banking_support",
    "hr_message",
    "school_form",
    "travel_booking",
    "legal_or_tenant_message",
    "resume_or_job_application",
    "software_log_or_secret",
    "customer_support",
]

HARD_NEGATIVE_INSTRUCTIONS = [
    "Mention a sensitive concept, such as SSN, password, credit card, or medical records, but do not include an actual value.",
    "Ask for advice about privacy or redaction without including any personal data.",
    "Use placeholders like [email] or XXXX instead of real-looking identifiers.",
    "Discuss a support, HR, banking, school, legal, or medical workflow without any specific personal facts.",
    "Ask how to safely format or remove sensitive data without providing the data itself.",
]


@dataclass(frozen=True)
class SensitiveCase:
    fine_category: str
    description: str
    template: str
    privoke_category: str
    sensitivity: str
    reference_family: str


@dataclass(frozen=True)
class SyntheticValues:
    full_name: str
    email: str
    phone: str
    ssn: str
    credit_card: str
    bank_account: str
    dob: str
    address: str
    password: str
    api_key: str
    ip_address: str
    medical_condition: str
    passport: str
    student_id: str
    employee_id: str
    insurance_id: str
    username: str
    driver_license: str
    medical_license: str
    medicare_id: str
    itin: str
    iban: str
    swift_bic: str
    crypto_wallet: str
    mac_address: str
    url_with_token: str
    vin: str
    license_plate: str
    mother_maiden_name: str
    place_of_birth: str
    precise_location: str
    political_affiliation: str
    religious_affiliation: str
    criminal_record: str
    sexual_orientation: str
    child_info: str
    employment_info: str
    education_record: str
    legal_case_info: str


def make_values(rng: random.Random) -> SyntheticValues:
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    city, state, zip_code = rng.choice(
        [
            ("Austin", "TX", "78701"),
            ("Seattle", "WA", "98101"),
            ("Denver", "CO", "80202"),
            ("Boston", "MA", "02108"),
            ("San Jose", "CA", "95112"),
        ]
    )
    return SyntheticValues(
        full_name=f"{first} {last}",
        email=f"{first.lower()}.{last.lower()}{rng.randint(10, 999)}@example.com",
        phone=f"{rng.randint(201, 989)}-555-{rng.randint(1000, 9999)}",
        ssn=f"{rng.randint(100, 899)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
        credit_card=f"4111 1111 1111 {rng.randint(1000, 9999)}",
        bank_account=f"{rng.randint(1000000000, 9999999999)}",
        dob=f"{rng.randint(1955, 2005)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
        address=f"{rng.randint(100, 9899)} Maple Street, {city}, {state} {zip_code}",
        password=f"TempPass{rng.randint(1000, 9999)}!",
        api_key=f"sk-test-{rng.randint(10**20, 10**21 - 1)}",
        ip_address=f"192.0.2.{rng.randint(1, 254)}",
        medical_condition=rng.choice(
            ["recurring chest pain", "recent diabetes diagnosis", "panic attacks", "positive strep test"]
        ),
        passport=f"X{rng.randint(10000000, 99999999)}",
        student_id=f"STU-{rng.randint(100000, 999999)}",
        employee_id=f"EMP-{rng.randint(10000, 99999)}",
        insurance_id=f"INS-{rng.randint(10000000, 99999999)}",
        username=f"{first.lower()}_{last.lower()}_{rng.randint(10, 99)}",
        driver_license=f"D{rng.randint(100000000, 999999999)}",
        medical_license=f"MD{rng.randint(1000000, 9999999)}",
        medicare_id=f"{rng.choice('123456789')}EG{rng.randint(1000, 9999)}TE{rng.randint(0, 9)}",
        itin=f"9{rng.randint(10, 99)}-7{rng.randint(0, 9)}-{rng.randint(1000, 9999)}",
        iban=f"GB{rng.randint(10, 99)}BARC{rng.randint(1000000000000000, 9999999999999999)}",
        swift_bic=f"BOFAUS3N{rng.randint(100, 999)}",
        crypto_wallet=f"bc1q{rng.randint(10**25, 10**26 - 1)}",
        mac_address=":".join(f"{rng.randint(0, 255):02x}" for _ in range(6)),
        url_with_token=f"https://portal.example.com/reset?token=tok_{rng.randint(10**18, 10**19 - 1)}",
        vin=f"1HGCM82633A{rng.randint(100000, 999999)}",
        license_plate=f"{rng.choice(['KLM', 'RVT', 'QPX', 'NDA'])}-{rng.randint(1000, 9999)}",
        mother_maiden_name=f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}",
        place_of_birth=rng.choice(["Queens, NY", "Austin, TX", "Seattle, WA", "Boston, MA"]),
        precise_location=f"{round(rng.uniform(25.0, 48.0), 6)}, {round(rng.uniform(-122.0, -70.0), 6)}",
        political_affiliation=rng.choice(["local campaign volunteer for the Green Party", "registered party precinct captain"]),
        religious_affiliation=rng.choice(["weekly mosque volunteer", "church small-group leader", "temple youth program coordinator"]),
        criminal_record=rng.choice(["probation hearing for a misdemeanor charge", "sealed arrest record from 2021"]),
        sexual_orientation=rng.choice(["I am bisexual and not out at work", "my partner and I are a same-sex couple"]),
        child_info=rng.choice(["my 8-year-old son's counseling appointment", "my daughter in grade 4 needs an IEP meeting"]),
        employment_info=rng.choice(["performance warning from my manager", "salary offer of $118,500"]),
        education_record=rng.choice(["transcript showing a 2.7 GPA", "disciplinary note from the registrar"]),
        legal_case_info=rng.choice(["protective order case number CIV-2049-18", "tenant dispute hearing on unpaid rent"]),
    )

SENSITIVE_CASES = [
    SensitiveCase("FULL_NAME", "person name", "{full_name}", "IDENTITY", "S2", "NIST/Presidio/Azure"),
    SensitiveCase("EMAIL", "email address", "{email}", "IDENTITY", "S2", "Presidio/Azure"),
    SensitiveCase("PHONE", "phone number", "{phone}", "IDENTITY", "S2", "Presidio/Azure"),
    SensitiveCase("USERNAME", "username", "{username}", "IDENTITY", "S1", "Azure"),
    SensitiveCase("SSN", "US Social Security number", "{ssn}", "IDENTITY", "S3", "NIST/Presidio"),
    SensitiveCase("ITIN", "US Individual Taxpayer Identification Number", "{itin}", "IDENTITY", "S3", "Presidio"),
    SensitiveCase("PASSPORT", "passport number", "{passport}", "IDENTITY", "S2", "Presidio/Azure"),
    SensitiveCase("DRIVER_LICENSE", "driver license number", "{driver_license}", "IDENTITY", "S2", "Presidio/Azure"),
    SensitiveCase("MEDICARE_ID", "Medicare beneficiary identifier", "{medicare_id}", "HEALTH", "S3", "Presidio/Azure"),
    SensitiveCase("MEDICAL_LICENSE", "medical license number", "{medical_license}", "HEALTH", "S3", "Presidio"),
    SensitiveCase("STUDENT_ID", "student ID", "{student_id}", "IDENTITY", "S2", "NIST linked educational info"),
    SensitiveCase("EMPLOYEE_ID", "employee ID", "{employee_id}", "IDENTITY", "S2", "NIST linked employment info"),
    SensitiveCase("INSURANCE_ID", "insurance ID", "{insurance_id}", "HEALTH", "S3", "Azure PHI-style identifier"),
    SensitiveCase("DATE_OF_BIRTH", "date of birth", "{dob}", "IDENTITY", "S2", "NIST/Azure"),
    SensitiveCase("PLACE_OF_BIRTH", "place of birth", "{place_of_birth}", "IDENTITY", "S2", "NIST"),
    SensitiveCase("MOTHER_MAIDEN_NAME", "mother's maiden name", "{mother_maiden_name}", "IDENTITY", "S3", "NIST"),
    SensitiveCase("ADDRESS", "home address", "{address}", "LOCATION", "S3", "Azure"),
    SensitiveCase("PRECISE_LOCATION", "precise geolocation", "{precise_location}", "LOCATION", "S3", "Azure"),
    SensitiveCase("CREDIT_CARD", "credit card number", "{credit_card}", "FINANCIAL", "S3", "Presidio/Azure"),
    SensitiveCase("BANK_ACCOUNT", "bank account number", "{bank_account}", "FINANCIAL", "S3", "Presidio/Azure"),
    SensitiveCase("IBAN", "IBAN", "{iban}", "FINANCIAL", "S3", "Presidio"),
    SensitiveCase("SWIFT_BIC", "SWIFT/BIC code", "{swift_bic}", "FINANCIAL", "S2", "Azure financial entities"),
    SensitiveCase("CRYPTO_WALLET", "crypto wallet address", "{crypto_wallet}", "FINANCIAL", "S2", "Presidio"),
    SensitiveCase("PASSWORD", "password", "password: {password}", "IDENTITY", "S3", "Azure"),
    SensitiveCase("API_KEY", "API key", "{api_key}", "IDENTITY", "S3", "Azure cloud secret style"),
    SensitiveCase("URL_WITH_TOKEN", "URL containing token", "{url_with_token}", "IDENTITY", "S3", "Presidio URL/Azure secret style"),
    SensitiveCase("IP_ADDRESS", "IP address", "{ip_address}", "IDENTITY", "S1", "Presidio"),
    SensitiveCase("MAC_ADDRESS", "MAC address", "{mac_address}", "IDENTITY", "S1", "Presidio"),
    SensitiveCase("VIN", "vehicle identification number", "{vin}", "IDENTITY", "S2", "Azure"),
    SensitiveCase("LICENSE_PLATE", "license plate", "{license_plate}", "LOCATION", "S2", "Azure"),
    SensitiveCase("MEDICAL_INFO", "medical condition", "{medical_condition}", "HEALTH", "S3", "NIST linked medical info/Presidio medical"),
    SensitiveCase("POLITICAL_AFFILIATION", "political affiliation", "{political_affiliation}", "POLITICS", "S3", "Presidio NRP/PriVoke"),
    SensitiveCase("RELIGIOUS_AFFILIATION", "religious affiliation", "{religious_affiliation}", "RELIGION", "S3", "Presidio NRP/PriVoke"),
    SensitiveCase("CRIMINAL_RECORD", "criminal/legal record", "{criminal_record}", "CRIMINAL", "S3", "PriVoke contextual category"),
    SensitiveCase("SEXUAL_ORIENTATION", "sexual orientation", "{sexual_orientation}", "SEXUAL", "S3", "PriVoke contextual category"),
    SensitiveCase("CHILD_INFO", "minor child information", "{child_info}", "CHILD", "S3", "PriVoke contextual category"),
    SensitiveCase("EMPLOYMENT_INFO", "employment information", "{employment_info}", "IDENTITY", "S2", "NIST linked employment info"),
    SensitiveCase("EDUCATION_RECORD", "education record", "{education_record}", "IDENTITY", "S2", "NIST linked educational info"),
    SensitiveCase("LEGAL_CASE_INFO", "legal case information", "{legal_case_info}", "CRIMINAL", "S2", "PriVoke contextual category"),
]


def strongest_sensitivity(cases: list[SensitiveCase]) -> str:
    rank = {"S1": 1, "S2": 2, "S3": 3}
    return max((case.sensitivity for case in cases), key=lambda value: rank[value], default="S1")


def sensitive_markers(
    values: SyntheticValues,
    rng: random.Random,
) -> tuple[list[str], list[str], list[str], str, list[str]]:
    selected = rng.sample(SENSITIVE_CASES, rng.randint(1, 3))
    fine_categories = [case.fine_category for case in selected]
    markers = [case.template.format(**values.__dict__) for case in selected]
    privoke_categories = sorted({case.privoke_category for case in selected})
    source_families = sorted({case.reference_family for case in selected})
    return fine_categories, markers, privoke_categories, strongest_sensitivity(selected), source_families


def contains_sensitive_pattern(text: str) -> bool:
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)


def build_messages(
    *,
    expected_has_pii: bool,
    persona: str,
    context: str,
    style: str,
    scenario: str,
    categories: list[str],
    markers: list[str],
    rng: random.Random,
) -> list[dict[str, str]]:
    if expected_has_pii:
        marker_lines = "\n".join(f"- {marker}" for marker in markers)
        category_text = ", ".join(categories)
        rule = (
            "Write one realistic user prompt that naturally includes every exact "
            "sensitive value below. Do not mask, alter, paraphrase, or omit them. "
            f"The sensitive categories are: {category_text}.\n{marker_lines}"
        )
    else:
        rule = (
            "Write one realistic user prompt that is clean. It may discuss privacy, "
            "support, HR, banking, legal, school, code, or medical workflows, but it "
            "must not contain real-looking names, emails, phone numbers, addresses, "
            "IDs, passwords, API keys, account numbers, dates of birth, or exact "
            f"personal facts. Extra constraint: {rng.choice(HARD_NEGATIVE_INSTRUCTIONS)}"
        )
    system = (
        "You generate synthetic evaluation prompts for a privacy filter. "
        "Output only the final user prompt text. No quotes, no markdown, no labels."
    )
    user = (
        f"Persona: {persona}\n"
        f"Context: {context}\n"
        f"Style: {style}\n"
        f"Scenario: {scenario}\n"
        f"Rule: {rule}\n"
        "Make it sound like a real human request, with varied wording and structure."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def call_openai(client: object, model: str, messages: list[dict[str, str]], temperature: float) -> str:
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
    )
    return response.choices[0].message.content.strip()


def make_record(index: int, expected_has_pii: bool, rng: random.Random) -> dict[str, object]:
    values = make_values(rng)
    if expected_has_pii:
        fine_categories, markers, privoke_categories, sensitivity, source_families = sensitive_markers(values, rng)
    else:
        fine_categories, markers, privoke_categories, sensitivity, source_families = [], [], [], "S1", []
    return {
        "id": f"privoke_openai_synth_{'sensitive' if expected_has_pii else 'clean'}_{index:06d}",
        "expected_has_pii": expected_has_pii,
        "expected_categories": privoke_categories,
        "fine_pii_categories": fine_categories,
        "pii_reference_families": source_families,
        "scenario": rng.choice(SCENARIOS),
        "persona": rng.choice(PERSONAS),
        "context": rng.choice(CONTEXTS),
        "style": rng.choice(STYLES),
        "language": "en",
        "source": "privoke_openai_synthetic_generator",
        "sensitivity": sensitivity,
        "required_markers": markers,
    }


def is_valid_record(record: dict[str, object], text: str) -> bool:
    if not text or len(text) < 25:
        return False
    if record["expected_has_pii"]:
        return all(marker in text for marker in record["required_markers"])
    return not contains_sensitive_pattern(text)


def generate_records(args: argparse.Namespace) -> list[dict[str, object]]:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency: install the OpenAI SDK with "
            "`evaluation/.venv/bin/pip install openai`."
        ) from exc

    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is not set.")

    client = OpenAI()
    rng = random.Random(args.seed)
    target_sensitive = args.count // 2
    target_clean = args.count - target_sensitive
    accepted: list[dict[str, object]] = []
    seen_texts: set[str] = set()
    class_counts = {True: 0, False: 0}
    failures = 0

    while class_counts[True] < target_sensitive or class_counts[False] < target_clean:
        expected_has_pii = (
            class_counts[True] < target_sensitive
            and (class_counts[False] >= target_clean or rng.random() < 0.5)
        )
        class_index = class_counts[expected_has_pii] + 1
        record = make_record(class_index, expected_has_pii, rng)
        messages = build_messages(
            expected_has_pii=expected_has_pii,
            persona=str(record["persona"]),
            context=str(record["context"]),
            style=str(record["style"]),
            scenario=str(record["scenario"]),
            categories=list(record["expected_categories"]),
            markers=list(record["required_markers"]),
            rng=rng,
        )

        text = call_openai(client, args.model, messages, args.temperature)
        normalized = text.strip().strip('"')
        if normalized in seen_texts or not is_valid_record(record, normalized):
            failures += 1
            if failures > args.max_failures:
                raise RuntimeError(
                    f"Stopped after {failures} rejected generations. "
                    "Try a lower count or check the model output."
                )
            continue

        seen_texts.add(normalized)
        record["text"] = normalized
        del record["required_markers"]
        accepted.append(record)
        class_counts[expected_has_pii] += 1
        failures = 0

        if args.sleep:
            time.sleep(args.sleep)
        if len(accepted) % args.progress_every == 0:
            print(f"Generated {len(accepted)}/{args.count} rows")

    rng.shuffle(accepted)
    return accepted


def write_jsonl(records: list[dict[str, object]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a high-diversity PriVoke synthetic dataset with the OpenAI API."
    )
    parser.add_argument("--count", type=int, default=200, help="Total rows to generate.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for row controls.")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model name.")
    parser.add_argument("--temperature", type=float, default=0.9, help="Generation temperature.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Seconds to sleep between API calls.")
    parser.add_argument("--progress-every", type=int, default=25, help="Progress print interval.")
    parser.add_argument("--max-failures", type=int, default=100, help="Rejected rows before stopping.")
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "evaluation/datasets/privoke_openai_synthetic.jsonl",
        help="Output JSONL path.",
    )
    args = parser.parse_args()
    if args.count < 2:
        parser.error("--count must be at least 2.")
    if args.progress_every < 1:
        parser.error("--progress-every must be at least 1.")
    return args


def main() -> None:
    args = parse_args()
    records = generate_records(args)
    write_jsonl(records, args.output)
    sensitive = sum(1 for record in records if record["expected_has_pii"])
    clean = len(records) - sensitive
    print(f"Wrote {len(records)} rows to {args.output}")
    print(f"Sensitive rows: {sensitive}")
    print(f"Clean rows: {clean}")


if __name__ == "__main__":
    main()
