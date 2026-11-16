//! Rule definitions, in the execution order of `rule_registry.all_rule_definitions`.

use crate::classification::{Classification, Sensitivity, category as cat, visibility as vis};
use crate::validators::{
    CARD_CONTEXT, DATE_CONTEXT_WORDS, DRIVER_LICENSE_CONTEXT, IBAN_CONTEXT, MatchView, SSN_CONTEXT, alphanumeric_identifier_shape,
    digits_or_context, has_context, iban_valid, luhn_valid, nhs_number_valid, us_ssn_valid,
};

/// How a hit is checked after the regex matched (`RuleDefinition.validator` and `Downgrade.accept`).
#[derive(Clone, Copy, Debug)]
pub enum Validator {
    /// `checksum_validator(check)`.
    Checksum(fn(&[char]) -> bool),
    /// `match_shape_validator(shape)`.
    Shape(fn(&[char]) -> bool),
    /// `context_required_validator(words)`.
    ContextRequired(&'static [&'static str]),
    /// `digits_or_context_validator(min_digits, words)`.
    DigitsOrContext(usize, &'static [&'static str]),
    /// `has_identifier_shape` over the `value` group.
    IdentifierShape,
}

impl Validator {
    pub(crate) fn check(self, view: &MatchView<'_>, date_value: &crate::pyre::PyRegex) -> bool {
        match self {
            Self::Checksum(check) | Self::Shape(check) => check(&view.text[view.start..view.end]),
            Self::ContextRequired(words) => has_context(view, words),
            Self::DigitsOrContext(min, words) => digits_or_context(view, min, words),
            Self::IdentifierShape => crate::validators::has_identifier_shape(view, date_value),
        }
    }
}

/// What a hit that fails its rule's validator is reported as instead of being dropped.
#[derive(Clone, Debug)]
pub struct Downgrade {
    /// Rule name of the downgraded hit.
    pub name: &'static str,
    /// Classification of the downgraded hit.
    pub classification: Classification,
    /// Signal of the downgraded hit.
    pub signal: &'static str,
    /// Acceptance test; `None` accepts everything.
    pub accept: Option<Validator>,
    /// Confidence of the downgraded hit.
    pub confidence: f64,
}

/// A regex rule with its classification.
#[derive(Clone, Debug)]
pub struct RuleDefinition {
    /// Rule name.
    pub name: String,
    /// Python pattern text.
    pub pattern: String,
    /// Resulting classification.
    pub classification: Classification,
    /// Signal name.
    pub signal: String,
    /// Validator, if any.
    pub validator: Option<Validator>,
    /// Downgrades in priority order.
    pub downgrades: Vec<Downgrade>,
}

/// Validator kinds of the imported Presidio rules.
#[derive(Clone, Copy, Debug)]
pub enum PresidioValidator {
    /// None.
    None,
    /// Luhn checksum.
    Luhn,
    /// IBAN mod 97.
    Iban,
    /// NHS mod 11.
    Nhs,
    /// US SSN ranges.
    UsSsn,
    /// Alphanumeric driver licence: 5 digits or a licence context word.
    DriverLicenseDigitsOrContext,
    /// Short date: needs a date context word.
    DateContext,
}

/// One imported Presidio pattern.
#[derive(Clone, Copy, Debug)]
pub struct PresidioRule {
    /// `presidio_<recogniser>_<pattern>`, lowercased.
    pub name: &'static str,
    /// `presidio_<entity>`.
    pub signal: &'static str,
    /// Packed classification.
    pub packed: u16,
    /// Validator kind.
    pub validator: PresidioValidator,
    /// Regex text from presidio-analyzer.
    pub pattern: &'static str,
}

const IDENTITY: Classification = Classification::new(Sensitivity::S3, vis::PU, cat::IDENTITY);

fn rule(name: &str, pattern: impl Into<String>, classification: Classification, signal: &str) -> RuleDefinition {
    RuleDefinition {
        name: name.to_owned(),
        pattern: pattern.into(),
        classification,
        signal: signal.to_owned(),
        validator: None,
        downgrades: Vec::new(),
    }
}

fn with(mut definition: RuleDefinition, validator: Validator, downgrades: Vec<Downgrade>) -> RuleDefinition {
    definition.validator = Some(validator);
    definition.downgrades = downgrades;
    definition
}

fn downgrade(name: &'static str, classification: Classification, signal: &'static str, accept: Validator) -> Downgrade {
    Downgrade { name, classification, signal, accept: Some(accept), confidence: 0.80 }
}

/// Visibility-only rules.
pub fn visibility_rules() -> Vec<RuleDefinition> {
    let level = |visibility| Classification::new(Sensitivity::S0, visibility, 0);
    vec![
        rule(
            "visibility_public",
            r"\b(public(?:ly)?|public\s+(?:post|profile|page)|visible\s+to\s+anyone|open\s+internet)\b",
            level(vis::P0),
            "visibility_public",
        ),
        rule(
            "visibility_semi_public",
            r"\b(community\s+(?:page|thread|forum)|public\s+thread|members?\s+thread|semi-public)\b",
            level(vis::P1),
            "visibility_semi_public",
        ),
        rule(
            "visibility_restricted",
            r"\b(behind\s+(?:login|authentication)|authenticated|restricted|members?\s+only|logged-in\s+users?)\b",
            level(vis::P2),
            "visibility_restricted",
        ),
        rule(
            "visibility_group_private",
            r"\b(group\s+(?:chat|dm|message)|shared\s+dm|private\s+(?:group|workspace|channel)|team\s+chat)\b",
            level(vis::P3),
            "visibility_group_private",
        ),
        rule(
            "visibility_personal_private",
            r"\b(personal\s+(?:note|diary|journal)|my\s+(?:diary|journal)|diary|journal|only\s+me|not\s+shared|private\s+note|local-only)\b",
            level(vis::P4),
            "visibility_personal_private",
        ),
    ]
}

/// Direct and quasi identity rules.
pub fn identity_rules() -> Vec<RuleDefinition> {
    let s2 = |categories| Classification::new(Sensitivity::S2, vis::PU, categories);
    vec![
        rule("email", r"\b[\w\.-]+@[\w\.-]+\.\w+\b", IDENTITY, "email"),
        rule("phone_us", r"(?<![\w])(?:\+?1[\s\-]?)?\(?[2-9]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b", IDENTITY, "phone"),
        rule("phone_intl", r"\+\d{1,3}([\s\-]?\d{2,4}){2,3}\b", IDENTITY, "phone"),
        with(
            rule("ssn_formatted", r"\b\d{3}[\s\-]?\d{2}[\s\-]?\d{4}\b", IDENTITY, "ssn"),
            Validator::Checksum(us_ssn_valid),
            vec![downgrade("ssn_unverified", IDENTITY, "ssn", Validator::ContextRequired(SSN_CONTEXT))],
        ),
        rule("itin", r"\b9\d{2}[\s\-]?(?:7\d|8[0-8]|9[0-2]|9[4-9])[\s\-]?\d{4}\b", IDENTITY, "itin"),
        rule(
            "passport",
            r"\b(?:passport|pass(?:port)? no\.?|passport number)\s*[:#=]?\s*[A-Z]{1,2}\d{6,9}\b|\b[A-Z]{1,2}\d{6,9}\b",
            IDENTITY,
            "passport",
        ),
        rule("driver_license", r"\b(?:driver'?s?\s+licen[cs]e|dl)\s*[:#=]?\s*[A-Z0-9\-]{5,15}\b", IDENTITY, "driver_license"),
        rule(
            "government_id",
            r"\b(?:national\s+id|tax\s+id|tin|id\s+number|identity\s+number)\s*[:#=]?\s*[A-Z0-9\-]{5,20}\b",
            IDENTITY,
            "government_id",
        ),
        rule(
            "student_id",
            concat!(
                r"\bstudent(?:[\s_-]*(?:id|number|no\.?)\s*[:#=]?|\b[^\n.;:!?]{0,60}?[,(]\s*id\s*[:#=]?)\s*",
                r"(?=[a-z0-9-]*\d)[a-z0-9][a-z0-9-]{3,}\b"
            ),
            IDENTITY,
            "student_id",
        ),
        rule("api_key", r"\b(?:sk|pk|ghp|xoxb|akia)[-_a-z0-9]{16,}\b", IDENTITY, "api_key"),
        rule("url_with_token", r"https?://\S*(?:token|key|secret|auth|session)=\S+", IDENTITY, "url_token"),
        rule(
            "password_assignment",
            r"\b(?:password|passwd|pwd|passcode)\s*[:=]\s*(?!(?:required|optional|none|null|nil|true|false|empty|blank|unknown|hidden|masked|n/?a)\b)\S+",
            IDENTITY,
            "password",
        ),
        rule("mac_address", r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", s2(cat::IDENTITY), "mac_address"),
        rule("vin", r"\b[A-HJ-NPR-Z0-9]{17}\b", s2(cat::IDENTITY), "vin"),
        rule(
            "social_handle",
            r"(?<![a-zA-Z0-9.])@(?!(?:here|everyone|channel|all)\b)[\w\-\.]{2,}(?![a-zA-Z0-9_])",
            s2(cat::IDENTITY),
            "social_handle",
        ),
        rule(
            "structured_identity",
            concat!(
                r"\b(?:(?:name|username|user|handle|account|login|email|location|address)\s*[:=][ \t]*",
                r"|phone\s*[:=][ \t]*(?=[+(\d]))",
                r"[+(]?[\w\.\-@]+\)?(?:[ \t]+[+(]?[\w\.\-@]+\)?){0,4}"
            ),
            Classification::new(Sensitivity::S2, vis::P2, cat::IDENTITY),
            "structured_field",
        ),
        rule(
            "date_field",
            r"\b(birth[\s_]?date|dob|date[\s_]?of[\s_]?birth|birthday|born|age)\s*[:=]?\s*[\d\s\/-]+",
            s2(cat::IDENTITY),
            "date_field",
        ),
    ]
}

// ---- labelled identifiers (`rules_identifiers.py`) -----------------------------------------

const WORD_NOUN: &str = r"(?:id|identifier|numbers?|no|num|nr|code|ref(?:erence)?)\b\.?";
const PAYMENT_CARD: &str = r"(?<!loyalty\s)(?<!library\s)(?<!gift\s)(?<!store\s)(?<!reward\s)(?<!rewards\s)(?<!club\s)card";
const SENSITIVE_QUALIFIERS: &[&str] = &[
    r"passport",
    r"licen[cs]e",
    r"national",
    r"social\s+(?:security|insurance)",
    r"tax(?:\s+(?:file|payer|registration))?",
    r"identity",
    r"identification",
    r"citizen(?:ship)?",
    r"voter",
    r"visa",
    r"residen(?:ce|cy)\s+permit",
    r"immigration",
    r"military",
    r"birth\s+certificate",
    r"patient",
    r"medical(?:\s+record)?",
    r"health(?:\s+plan)?",
    r"(?:health|medical|insurance)(?:\s+plan)?\s+member",
    r"insurance",
    r"medicare",
    r"medicaid",
    r"beneficiary",
    r"bank(?:\s+account)?",
    PAYMENT_CARD,
];
const GENERIC_QUALIFIERS: &[&str] = &[
    r"customer",
    r"client",
    r"account",
    r"member(?:ship)?",
    r"subscriber",
    r"employee",
    r"staff",
    r"personnel",
    r"user",
    r"policy",
    r"claim",
    r"registration",
    r"plate",
    r"(?:loyalty|library|rewards?|club|gift|store)\s+card",
    r"reference",
];
const SENSITIVE_ACRONYMS: &[&str] = &["ssn", "tfn", "nino", "ein", "itin", "mrn", "nric"];
const SELF_LABELLING_DOCUMENTS: &[&str] = &[r"passport", r"id\s+card", r"identity\s+card", r"medicare", r"medicaid"];
const CONNECTOR: &str = r#"[\"'*_]*(?:\s*(?:is|was|are)\b)?\s*[:=#]?[*_\s\"'(\[]*"#;
const TOKEN: &str = r"[A-Z0-9_]+";

fn alternation(parts: &[&str]) -> String {
    format!("(?:{})", parts.join("|"))
}

fn value_pattern() -> String {
    format!(
        r"(?:(?=[A-Z0-9_\-]*\d){TOKEN}(?:-{TOKEN})*|[A-Z]{{1,3}}(?=\s[A-Z0-9_\-]*\d))(?:-{TOKEN}|\s(?=[A-Z0-9_\-]*\d){TOKEN}(?:-{TOKEN})*){{0,5}}"
    )
}

fn labelled_identifier_pattern(qualifiers: &[&str], acronyms: &[&str], self_labelling: &[&str]) -> String {
    let mut shapes = vec![format!(r"{}(?:[\s_-]*{WORD_NOUN}(?:[\s_-]+{WORD_NOUN})?|\s*#)", alternation(qualifiers))];
    if !acronyms.is_empty() {
        shapes.push(format!(r"{}(?:[\s_-]*{WORD_NOUN})?", alternation(acronyms)));
    }
    if !self_labelling.is_empty() {
        shapes.push(format!(r"{}\s*(?=[:=#])", alternation(self_labelling)));
    }
    let shapes: Vec<&str> = shapes.iter().map(String::as_str).collect();
    format!(r"\b{}{CONNECTOR}(?P<value>{})\b", alternation(&shapes), value_pattern())
}

/// General labelled-identifier rules, by identifier class.
pub fn identifier_rules() -> Vec<RuleDefinition> {
    vec![
        with(
            rule(
                "labelled_identifier_sensitive",
                labelled_identifier_pattern(SENSITIVE_QUALIFIERS, SENSITIVE_ACRONYMS, SELF_LABELLING_DOCUMENTS),
                IDENTITY,
                "labelled_identifier",
            ),
            Validator::IdentifierShape,
            Vec::new(),
        ),
        with(
            rule(
                "labelled_identifier_generic",
                labelled_identifier_pattern(GENERIC_QUALIFIERS, &[], &[]),
                Classification::new(Sensitivity::S2, vis::PU, cat::IDENTITY),
                "labelled_identifier",
            ),
            Validator::IdentifierShape,
            Vec::new(),
        ),
    ]
}

// ---- location ----------------------------------------------------------------------------------

const CLOSED_CLASS_WORDS: &[&str] = &[
    "a",
    "an",
    "the",
    "this",
    "that",
    "these",
    "those",
    "some",
    "any",
    "all",
    "each",
    "every",
    "either",
    "neither",
    "both",
    "another",
    "other",
    "such",
    "anything",
    "anyone",
    "something",
    "someone",
    "everything",
    "everyone",
    "nothing",
    "nobody",
    "somewhere",
    "anywhere",
    "everywhere",
    "nowhere",
    "i",
    "me",
    "my",
    "mine",
    "you",
    "your",
    "we",
    "our",
    "us",
    "they",
    "their",
    "them",
    "he",
    "him",
    "his",
    "she",
    "her",
    "it",
    "its",
    "and",
    "or",
    "but",
    "nor",
    "so",
    "if",
    "than",
    "then",
    "as",
    "because",
    "to",
    "of",
    "in",
    "on",
    "at",
    "for",
    "with",
    "without",
    "by",
    "from",
    "about",
    "into",
    "over",
    "after",
    "before",
    "between",
    "through",
    "during",
    "under",
    "again",
    "near",
    "up",
    "out",
    "off",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "am",
    "do",
    "does",
    "did",
    "can",
    "could",
    "will",
    "would",
    "should",
    "may",
    "might",
    "must",
    "not",
    "no",
    "just",
    "only",
    "also",
    "too",
    "very",
    "more",
    "most",
    "what",
    "which",
    "who",
    "whom",
    "whose",
    "how",
    "when",
    "where",
    "why",
    "there",
    "here",
];

/// Precise and quasi-location rules.
pub fn location_rules() -> Vec<RuleDefinition> {
    let location = |sensitivity| Classification::new(sensitivity, vis::PU, cat::LOCATION);
    let location_keyword = format!(
        "{}(?!(?:{})\\b)[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)?",
        concat!(
            r"\b(?:(?:(?:i|we|he|she|they)\s+(?:(?:am|are|is)\s+)?",
            r"|(?:i['’]m|we['’]re|he['’]s|she['’]s|they['’]re)\s+)(?:currently\s+)?",
            r"(?:live|lives|living|located|from|(?:come|comes)\s+from|stay|staying|alone\s+tonight)",
            r"\s+(?:in\s+|on\s+|at\s+|near\s+)?",
            r"|(?:my|our|his|her|their)\s+(?:home\s+)?(?:address|hometown|residence|location)",
            r"\s*(?:is\s+|was\s+|[:=]\s*|(?:in|on|at|near)\s+)",
            r"|(?:home\s+)?(?:address|hometown|residence)\s*[:=]\s*)"
        ),
        CLOSED_CLASS_WORDS.join("|")
    );
    vec![
        rule(
            "street_address",
            r"\b\d{1,6}\s+[A-Z][\w.'-]*(?:\s+[A-Z][\w.'-]*){0,4}\s+(?:st|street|ave|avenue|rd|road|blvd|boulevard|drive|dr|lane|ln|court|ct|way|terrace|pl|place)\b",
            location(Sensitivity::S3),
            "street_address",
        ),
        rule("geo_coordinates", r"\b-?\d{1,2}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b", location(Sensitivity::S3), "geo_coordinates"),
        rule(
            "license_plate",
            r"\b(?:license\s+plate|plate)\s*[:#=]?\s*[A-Z]{2,4}[-\s]?\d{3,4}\b|\b(?!(?:rfc|cve|iso|iec|bcp|std)-)[A-Z]{3}-\d{4}\b",
            location(Sensitivity::S2),
            "license_plate",
        ),
        rule("location_keyword", location_keyword, location(Sensitivity::S2), "location"),
        rule(
            "route_or_commute",
            r"\b(?:commute|route|walk|drive|bus|train)\s+(?:from|to|between)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b",
            location(Sensitivity::S2),
            "route_location",
        ),
    ]
}

/// Physical and mental health disclosure rules.
pub fn health_rules() -> Vec<RuleDefinition> {
    let health = Classification::new(Sensitivity::S3, vis::PU, cat::HEALTH);
    vec![
        rule(
            "health_keyword",
            r"\b(?:my|his|her|their|patient|child|son|daughter|spouse|partner)\s+(?:hospital|doctor|medication|medicine|prescription|disease|cancer|diabetes|depression|anxiety|therapy|psychiatric|diagnosis|prognosis|allergy|symptom|treatment|pregnan(?:t|cy)|hiv|aids|autism|adhd)\b",
            health,
            "health_info",
        ),
        rule(
            "health_statement",
            r"\b(?:i|my|he|she|they|patient|client|child|son|daughter|spouse|partner)\s+(?:have|has|had|take|takes|was diagnosed with|am diagnosed with|is diagnosed with|suffer from|suffers from|tested positive for)\s+(?:medication|medicine|prescription|cancer|diabetes|depression|anxiety|therapy|diagnosis|allergy|symptom|treatment|hiv|aids|autism|adhd|ptsd|bipolar|asthma|strep|chest pain)\b",
            health,
            "health_disclosure",
        ),
        rule(
            "medical_identifier",
            r"\b(?:insurance\s+id|policy\s+id|member\s+id|medical\s+license|medicare\s+(?:id|number))\s*[:#=]?\s*[A-Z0-9\-]{5,24}\b",
            health,
            "medical_identifier",
        ),
    ]
}

/// Financial account, transaction, debt, income and asset rules.
pub fn financial_rules() -> Vec<RuleDefinition> {
    let s3 = |categories| Classification::new(Sensitivity::S3, vis::PU, categories);
    let s2 = |categories| Classification::new(Sensitivity::S2, vis::PU, categories);
    vec![
        with(
            rule("credit_card", r"\b(?:\d{4}[\s\-]?){3}\d{4}\b", s3(cat::FINANCIAL | cat::IDENTITY), "credit_card"),
            Validator::Checksum(luhn_valid),
            vec![downgrade(
                "credit_card_unverified",
                s3(cat::FINANCIAL | cat::IDENTITY),
                "credit_card",
                Validator::ContextRequired(CARD_CONTEXT),
            )],
        ),
        with(
            rule("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b", s3(cat::FINANCIAL), "iban"),
            Validator::Checksum(iban_valid),
            vec![
                downgrade("iban_unverified", s3(cat::FINANCIAL), "iban", Validator::ContextRequired(IBAN_CONTEXT)),
                downgrade(
                    "unverified_number_identifier",
                    s2(cat::IDENTITY),
                    "number_identifier",
                    Validator::Shape(alphanumeric_identifier_shape),
                ),
            ],
        ),
        rule(
            "bank_account",
            r"\b(?:bank\s+account|account\s+number|routing\s+number|sort\s+code)\s*(?:is|number is|[:#=])?\s*(?=[A-Z0-9\- ]{6,24}\b)(?=[A-Z0-9\- ]*\d)[A-Z0-9][A-Z0-9\- ]{5,23}\b",
            s3(cat::FINANCIAL),
            "bank_account",
        ),
        rule(
            "swift_bic",
            r"\b(?:swift|bic|swift/bic)\s*[:#=]?\s*[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
            s2(cat::FINANCIAL),
            "swift_bic",
        ),
        rule("crypto_wallet", r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b", s2(cat::FINANCIAL), "crypto_wallet"),
        rule(
            "salary_disclosure",
            r"\b(?:my|his|her|their|salary|income|paycheck|bonus)\s+(?:salary|income|paycheck|bonus|is|was|offer|of|=|:)\s*\$?\d[\d,]*(?:\.\d{2})?\b",
            s2(cat::FINANCIAL),
            "salary_disclosure",
        ),
        rule(
            "financial_keyword",
            r"\b(?:my|his|her|their)\s+(?:\w+\s+){0,2}(?:salary|income|bonus|loan|mortgage|debt|investment|stock|crypto|bitcoin|ethereum|tax|paycheck|transaction|balance|savings|net\s+worth|credit\s+(?:score|history|report))\b",
            s2(cat::FINANCIAL),
            "financial_info",
        ),
        rule(
            "money_amount",
            concat!(
                r"\b(?:(?:my|our|his|her|their)\b[^.!?;\n]{0,64}",
                r"|(?:i|we)\s+(?:earn|earned|spent|spend|paid|pay|owe|owed|saved)\b[^.!?;\n]{0,48}",
                r"|(?:salary|income|debt|balance|mortgage|paycheck)\s*[:=]\s*)",
                r"(?:\$\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\s?(?:usd|aud|eur|gbp)\b)"
            ),
            s2(cat::FINANCIAL),
            "money_amount",
        ),
    ]
}

/// PDPA-sensitive and harm-sensitive category rules.
pub fn sensitive_category_rules() -> Vec<RuleDefinition> {
    let s3 = |categories| Classification::new(Sensitivity::S3, vis::PU, categories);
    vec![
        rule(
            "politics",
            r"\b(voted?\s+for|political\s+(?:party|view|belief|campaign)|democrat|republican|labor party|liberal party|conservative|socialist|communist|activist|protest(?:ed|ing)?|union member)\b",
            s3(cat::POLITICS),
            "political_info",
        ),
        rule(
            "religion",
            r"\b(christian|muslim|islam|jewish|judaism|hindu|buddhist|atheist|agnostic|church|mosque|synagogue|temple|priest|pastor|imam|rabbi|religion|faith|prayer group)\b",
            s3(cat::RELIGION),
            "religious_info",
        ),
        rule(
            "criminal",
            r"\b(arrest(?:ed)?|convict(?:ed|ion)|felony|misdemeanor|probation|parole|criminal\s+record|charged\s+with|court\s+case|restraining\s+order)\b",
            s3(cat::CRIMINAL),
            "criminal_info",
        ),
        rule(
            "sexual",
            r"\b(sexual\s+(?:orientation|history)|gay|lesbian|bisexual|transgender|queer|lgbtq|dating\s+profile|intimate|pregnancy termination|abortion)\b",
            s3(cat::SEXUAL),
            "sexual_info",
        ),
        rule(
            "child",
            concat!(
                r"\b(?:my|our|his|her|their)\s+(?:[\w-]+[\s-]+){0,2}?(?:child|children|kid|kids|son|daughter)\b",
                r"|\b(?:age|aged)\s+(?:[1-9]|1[0-7])\b",
                r"|\b(?:my|our|his|her|their)\s+(?:[1-9]|1[0-7])[\s-]*(?:year|yr)s?[\s-]*old\b",
                r"|\b(?:[1-9]|1[0-7])[\s-]*(?:year|yr)s?[\s-]*old\s+(?:child|kid|son|daughter|boy|girl|toddler|baby|infant|niece|nephew|grandson|granddaughter|pupil|student)\b"
            ),
            s3(cat::CHILD),
            "child_info",
        ),
        rule(
            "third_party_disclosure",
            r"\b(?:my|his|her|their)\s+(?:spouse|husband|wife|partner|boyfriend|girlfriend|child|son|daughter|mother|father|friend|coworker|colleague|boss|employee)\b",
            Classification::new(Sensitivity::S2, vis::PU, cat::THIRD_PARTY),
            "third_party_info",
        ),
    ]
}

/// Relationship, workplace and temporal context rules.
pub fn contextual_rules() -> Vec<RuleDefinition> {
    vec![
        rule(
            "family_disclosure",
            r"\b(?:my|our|his|her|their)\s+(?:[\w-]+[\s-]+){0,2}?(?:spouse|husband|wife|partner|boyfriend|girlfriend|children|kids|son|daughter|mother|father|siblings?|family)\b",
            Classification::new(Sensitivity::S2, vis::PU, cat::THIRD_PARTY),
            "family_info",
        ),
        rule(
            "workplace_keyword",
            concat!(
                r"\b(?:(?:i|we)\s+(?:work|worked|am\s+employed|are\s+employed)\s+(?:at|for|by)",
                r"|(?:my|our)\s+(?:employer|company|workplace|office|manager|boss)\s*(?:is|are|[:=])",
                r"|(?:employer|company|department)\s*[:=])\s+[a-z][\w&.-]*"
            ),
            Classification::new(Sensitivity::S1, vis::PU, cat::IDENTITY),
            "workplace_info",
        ),
        rule(
            "timestamp_field",
            r"\b(timestamp|visited|accessed|logged|created|modified|updated|date|time)\s*[:=]\s*[\d\s\-/:T.Z]+",
            Classification::new(Sensitivity::S1, vis::PU, cat::IDENTITY),
            "timestamp",
        ),
    ]
}

/// The imported Presidio rules.
pub fn presidio_rules() -> Vec<RuleDefinition> {
    crate::presidio::PRESIDIO_RULES
        .iter()
        .map(|source| {
            let validator = match source.validator {
                PresidioValidator::None => None,
                PresidioValidator::Luhn => Some(Validator::Checksum(luhn_valid)),
                PresidioValidator::Iban => Some(Validator::Checksum(iban_valid)),
                PresidioValidator::Nhs => Some(Validator::Checksum(nhs_number_valid)),
                PresidioValidator::UsSsn => Some(Validator::Checksum(us_ssn_valid)),
                PresidioValidator::DriverLicenseDigitsOrContext => Some(Validator::DigitsOrContext(5, DRIVER_LICENSE_CONTEXT)),
                PresidioValidator::DateContext => Some(Validator::ContextRequired(DATE_CONTEXT_WORDS)),
            };
            RuleDefinition {
                name: source.name.to_owned(),
                pattern: source.pattern.to_owned(),
                classification: packed(source.packed),
                signal: source.signal.to_owned(),
                validator,
                downgrades: Vec::new(),
            }
        })
        .collect()
}

pub(crate) fn packed(value: u16) -> Classification {
    let sensitivity = match value & 0b11 {
        0 => Sensitivity::S0,
        1 => Sensitivity::S1,
        2 => Sensitivity::S2,
        _ => Sensitivity::S3,
    };
    Classification::new(sensitivity, value & 0b11100, value & 0x7FE0)
}
