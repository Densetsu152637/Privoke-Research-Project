//! The regex rule detector (`rule_detector.py`, `rule_heuristics.py`, `detection/context.py`).

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::classification::{Classification, Sensitivity, category, visibility};
use crate::pyre::{FancyReason, Haystack, PatternError, PyRegex};
use crate::pyunicode;
use crate::rules::{self, RuleDefinition};
use crate::validators::MatchView;

/// Which optional rule families are loaded (`PRIVOKE_REGEX_PRESIDIO`, `PRIVOKE_REGEX_GITLEAKS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSetOptions {
    /// Import the Presidio recognisers.
    pub presidio: bool,
    /// Import the Gitleaks catalogue.
    pub gitleaks: bool,
}

impl Default for RuleSetOptions {
    fn default() -> Self {
        Self { presidio: true, gitleaks: true }
    }
}

impl RuleSetOptions {
    /// `_env_enabled` of `rule_registry.py`: on unless the value is `0`, `false`, `no` or `off`.
    pub fn from_env() -> Self {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// The same, reading variables through `lookup`.
    pub fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        let enabled = |name: &str| match lookup(name) {
            Some(value) => !matches!(pyunicode::lower(value.trim_matches(pyunicode::is_space)).as_str(), "0" | "false" | "no" | "off"),
            None => true,
        };
        Self { presidio: enabled("PRIVOKE_REGEX_PRESIDIO"), gitleaks: enabled("PRIVOKE_REGEX_GITLEAKS") }
    }
}

/// Errors from building or running the detector.
#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    /// A rule pattern failed to compile or run.
    #[error("rule {rule:?}: {source}")]
    Rule {
        /// Rule name.
        rule: String,
        /// Underlying failure.
        source: PatternError,
    },
    /// A support pattern failed.
    #[error(transparent)]
    Pattern(#[from] PatternError),
    /// The Gitleaks catalogue did not parse.
    #[error("gitleaks catalogue: {0}")]
    Catalogue(#[from] toml::de::Error),
}

/// One regex or heuristic hit.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleHit {
    /// Rule name.
    pub rule_name: String,
    /// Signal.
    pub signal: String,
    /// Matched text (the whole text for heuristics).
    pub text: String,
    /// Span in code points.
    pub span: (usize, usize),
    /// Classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
}

/// A rule with its compiled pattern.
#[derive(Debug)]
pub struct CompiledRule {
    /// The definition.
    pub definition: RuleDefinition,
    /// The pattern.
    pub regex: PyRegex,
    value_group: Option<usize>,
}

const WEAK_CONTEXT_RULES: &[&str] = &[
    "financial_keyword",
    "money_amount",
    "health_keyword",
    "politics",
    "religion",
    "criminal",
    "sexual",
    "child",
    "family_disclosure",
    "workplace_keyword",
];

struct Support {
    clean: Vec<PyRegex>,
    disclosure: Vec<PyRegex>,
    identity_fields: PyRegex,
    date_value: PyRegex,
}

fn build_support() -> Result<Support, PatternError> {
    let compile = |patterns: &[&str]| patterns.iter().map(|p| PyRegex::new(p, true)).collect::<Result<Vec<_>, _>>();
    Ok(Support {
        clean: compile(&[
            r"\b(?:what is|what are|explain|define|definition of|meaning of)\b",
            r"\b(?:example|sample|format|placeholder|template)\b",
            r"\b(?:redact|mask|remove|sanitize|anonymi[sz]e)\b",
            r"\b(?:without|avoid|do not|don't)\s+(?:real|actual|personal|private|sensitive)\b",
            r"\b(?:using|use)\s+(?:xxxx|\[email\]|\[phone\]|\[name\]|\[address\]|placeholder)\b",
            r"\b(?:no|not)\s+(?:real|actual)\s+(?:data|details|information|pii)\b",
        ])?,
        disclosure: compile(&[
            r"\b(?:my|his|her|their|our)\s+(?:email|phone|ssn|address|account|password|diagnosis|doctor|medication|salary|child|case|record)\b",
            r"\b(?:i|we|he|she|they)\s+(?:have|has|had|am|was|were|live|work|take|takes|owe|earn|voted|believe)\b",
            r"\b(?:patient|client|student|employee|tenant)\s+(?:has|had|is|was|record|id|number|diagnosis|salary)\b",
        ])?,
        identity_fields: PyRegex::new(r"\b(name|email|phone|username|location|address)\s*[:=]\s*", true)?,
        date_value: PyRegex::new(r"\A(?:\d{4}-\d{2}-\d{2}|\d{1,2}-\d{1,2}-\d{2,4})\Z", false)?,
    })
}

static SUPPORT: LazyLock<Result<Support, String>> = LazyLock::new(|| build_support().map_err(|error| error.to_string()));

fn support() -> Result<&'static Support, PatternError> {
    SUPPORT.as_ref().map_err(|message| PatternError::Engine(message.clone()))
}

/// The rule detector.
#[derive(Debug)]
pub struct Detector {
    rules: Vec<CompiledRule>,
}

impl Detector {
    /// Build the detector with every rule family selected by `options`.
    pub fn new(options: RuleSetOptions) -> Result<Self, DetectorError> {
        let mut rules = Vec::new();
        let compile = |definition: RuleDefinition| -> Result<CompiledRule, DetectorError> {
            let regex =
                PyRegex::new(&definition.pattern, true).map_err(|source| DetectorError::Rule { rule: definition.name.clone(), source })?;
            Ok(CompiledRule { value_group: regex.group_index("value"), definition, regex })
        };
        for set in [
            rules::visibility_rules(),
            rules::identity_rules(),
            rules::identifier_rules(),
            rules::location_rules(),
            rules::health_rules(),
            rules::financial_rules(),
            rules::sensitive_category_rules(),
            rules::contextual_rules(),
        ] {
            for definition in set {
                rules.push(compile(definition)?);
            }
        }
        if options.gitleaks {
            for (definition, regex) in crate::gitleaks::gitleaks_rules()? {
                rules.push(CompiledRule { value_group: regex.group_index("value"), definition, regex });
            }
        }
        if options.presidio {
            for definition in rules::presidio_rules() {
                rules.push(compile(definition)?);
            }
        }
        support()?;
        Ok(Self { rules })
    }

    /// The compiled rules, in execution order.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Every rule whose pattern needs `fancy-regex`, with the reasons.
    pub fn fancy_report(&self) -> Vec<(&str, &[FancyReason])> {
        self.rules
            .iter()
            .filter(|rule| !rule.regex.fancy_reasons().is_empty())
            .map(|rule| (rule.definition.name.as_str(), rule.regex.fancy_reasons()))
            .collect()
    }

    /// `RuleDetector.analyze`: one hit per regex or heuristic match.
    pub fn analyze(&self, text: &str) -> Result<Vec<RuleHit>, DetectorError> {
        let support = support()?;
        let hay = Haystack::new(text);
        let mut matches = self.collect_matches(&hay, support)?;
        if is_clean_discussion_context(&hay, support)? {
            matches.retain(|hit| !WEAK_CONTEXT_RULES.contains(&hit.rule_name.as_str()));
        }
        let generated = heuristic_matches(&hay, &matches, support)?;
        matches.extend(generated);
        let mut seen = HashSet::new();
        matches.retain(|hit| seen.insert((hit.rule_name.clone(), hit.signal.clone(), hit.span, hit.text.clone())));
        Ok(matches)
    }

    fn collect_matches(&self, hay: &Haystack, support: &Support) -> Result<Vec<RuleHit>, DetectorError> {
        let mut matches = Vec::new();
        for rule in &self.rules {
            let found = rule.regex.find_iter(hay).map_err(|source| DetectorError::Rule { rule: rule.definition.name.clone(), source })?;
            for hit in found {
                let view = MatchView {
                    text: hay.chars(),
                    start: hit.start,
                    end: hit.end,
                    value: rule.value_group.and_then(|index| hit.group(index)),
                };
                let definition = &rule.definition;
                if let Some(validator) = definition.validator
                    && !validator.check(&view, &support.date_value)
                {
                    for downgrade in &definition.downgrades {
                        if downgrade.accept.is_none_or(|accept| accept.check(&view, &support.date_value)) {
                            matches.push(RuleHit {
                                rule_name: downgrade.name.to_owned(),
                                signal: downgrade.signal.to_owned(),
                                text: hay.slice(hit.start, hit.end),
                                span: (hit.start, hit.end),
                                classification: downgrade.classification,
                                confidence: downgrade.confidence,
                            });
                            break;
                        }
                    }
                    continue;
                }
                matches.push(RuleHit {
                    rule_name: definition.name.clone(),
                    signal: definition.signal.clone(),
                    text: hay.slice(hit.start, hit.end),
                    span: (hit.start, hit.end),
                    classification: definition.classification,
                    confidence: 0.95,
                });
            }
        }
        Ok(matches)
    }
}

fn is_clean_discussion_context(hay: &Haystack, support: &Support) -> Result<bool, PatternError> {
    let mut clean = false;
    for pattern in &support.clean {
        if pattern.search(hay)?.is_some() {
            clean = true;
            break;
        }
    }
    if !clean {
        return Ok(false);
    }
    for pattern in &support.disclosure {
        if pattern.search(hay)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn heuristic_matches(hay: &Haystack, matches: &[RuleHit], support: &Support) -> Result<Vec<RuleHit>, PatternError> {
    let mut generated = Vec::new();
    let word_count = pyunicode::split_count(hay.chars());
    let identity_field_count = support.identity_fields.find_iter(hay)?.len();
    let whole = (0, hay.len());
    if identity_field_count >= 2 {
        generated.push(RuleHit {
            rule_name: "multiple_identity_fields".to_owned(),
            signal: format!("multiple_identity_fields({identity_field_count})"),
            text: hay.slice(0, hay.len()),
            span: whole,
            classification: Classification::new(Sensitivity::S2, visibility::PU, category::IDENTITY),
            confidence: 0.70,
        });
    }
    let mut categories = 0u16;
    let mut any_high = false;
    for hit in matches.iter().filter(|hit| hit.classification.sensitivity() == Sensitivity::S3) {
        any_high = true;
        categories |= hit.classification.categories();
    }
    if word_count < 10 && any_high {
        generated.push(RuleHit {
            rule_name: "concentrated_sensitive_data".to_owned(),
            signal: "concentrated_pii".to_owned(),
            text: hay.slice(0, hay.len()),
            span: whole,
            classification: Classification::new(Sensitivity::S2, visibility::PU, categories),
            confidence: 0.70,
        });
    }
    Ok(generated)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rule_families_follow_the_environment_switches() {
        let env = |pairs: &'static [(&str, &str)]| {
            move |key: &str| pairs.iter().find(|(name, _)| *name == key).map(|(_, value)| (*value).to_owned())
        };
        assert_eq!(RuleSetOptions::from_lookup(&env(&[])), RuleSetOptions { presidio: true, gitleaks: true });
        let off = RuleSetOptions::from_lookup(&env(&[("PRIVOKE_REGEX_PRESIDIO", " Off "), ("PRIVOKE_REGEX_GITLEAKS", "no")]));
        assert_eq!(off, RuleSetOptions { presidio: false, gitleaks: false });
        let odd = RuleSetOptions::from_lookup(&env(&[("PRIVOKE_REGEX_PRESIDIO", "banana"), ("PRIVOKE_REGEX_GITLEAKS", "")]));
        assert_eq!(odd, RuleSetOptions { presidio: true, gitleaks: true });
        let counts: Vec<usize> = [(true, true), (false, true), (true, false), (false, false)]
            .iter()
            .map(|&(presidio, gitleaks)| Detector::new(RuleSetOptions { presidio, gitleaks }).expect("detector builds").rules().len())
            .collect();
        assert_eq!(counts, vec![300, 257, 92, 49]);
    }

    #[test]
    fn detects_common_identifiers() {
        let detector = Detector::new(RuleSetOptions::default()).expect("detector builds");
        let hits = detector.analyze("Contact jane.doe@example.com or call 415-555-2671, card 4111 1111 1111 1111").expect("analyses");
        let names: Vec<&str> = hits.iter().map(|hit| hit.rule_name.as_str()).collect();
        assert!(names.contains(&"email") && names.contains(&"phone_us") && names.contains(&"credit_card"), "{names:?}");
    }

    #[test]
    fn clean_discussion_suppresses_weak_rules_only() {
        let detector = Detector::new(RuleSetOptions { presidio: false, gitleaks: false }).expect("detector builds");
        let hits = detector.analyze("Explain what a conservative political party is").expect("analyses");
        assert!(hits.iter().all(|hit| hit.rule_name != "politics"), "{hits:?}");
    }
}
