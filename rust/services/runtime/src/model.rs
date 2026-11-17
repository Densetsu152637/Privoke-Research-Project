//! Classification values, the action policy and the evidence aggregation of the pipeline.
//!
//! Ports `privoke_contracts/classification.py`, `classification/classification_policy.py`,
//! `classification/classification_results.py` and `pipeline.strongest_result`. A classification is the packed 16-bit
//! word: two sensitivity bits, three visibility bits and ten category bits.

use std::collections::BTreeMap;

use privoke_rules::classification::Classification;

/// A visibility value that is not a member of the Python enum (`Visibility(0)` raises `ValueError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not a valid Visibility")]
pub struct InvalidVisibility(pub u16);

const VISIBILITY_MASK: u16 = 0b1_1100;
const CATEGORY_MASK: u16 = 0x7FE0;

/// The visibility members in definition order, with their names and packed values.
const VISIBILITIES: [(&str, u16); 6] =
    [("P0", 0b00100), ("P1", 0b01000), ("P2", 0b01100), ("P3", 0b10000), ("P4", 0b10100), ("PU", 0b11100)];

/// The category members in definition order, with their names and packed values.
pub const CATEGORIES: [(&str, u16); 10] = [
    ("HEALTH", 0b000_0000_0010_0000),
    ("POLITICS", 0b000_0000_0100_0000),
    ("RELIGION", 0b000_0000_1000_0000),
    ("CRIMINAL", 0b000_0001_0000_0000),
    ("FINANCIAL", 0b000_0010_0000_0000),
    ("SEXUAL", 0b000_0100_0000_0000),
    ("CHILD", 0b000_1000_0000_0000),
    ("LOCATION", 0b001_0000_0000_0000),
    ("IDENTITY", 0b010_0000_0000_0000),
    ("THIRD_PARTY", 0b100_0000_0000_0000),
];

const IDENTIFIER_CATEGORIES: u16 = 0b001_0000_0000_0000 | 0b010_0000_0000_0000;

/// The names the `visibility_hint` request field accepts, in Python's error-message order.
pub fn visibility_names() -> Vec<&'static str> {
    VISIBILITIES.iter().map(|(name, _)| *name).collect()
}

/// The packed value of the visibility called `name` (already upper-cased), if it is one.
pub fn visibility_by_name(name: &str) -> Option<u16> {
    VISIBILITIES.iter().find(|(candidate, _)| *candidate == name).map(|(_, value)| *value)
}

/// `Visibility.PU`.
pub const PU: u16 = 0b11100;

/// The enforcement action, ordered like `PriVokeAction` (`ALLOW` < `WARN` < `BLOCK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Let the prompt through.
    Allow = 0,
    /// Warn the user.
    Warn = 1,
    /// Block the prompt.
    Block = 2,
}

impl Action {
    /// `PriVokeAction.name`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        }
    }
}

/// `Classification.visibility().name`, or Python's `ValueError` text for a value outside the enum.
pub fn visibility_name(packed: u16) -> Result<&'static str, InvalidVisibility> {
    let bits = packed & VISIBILITY_MASK;
    VISIBILITIES.iter().find(|(_, value)| *value == bits).map(|(name, _)| *name).ok_or(InvalidVisibility(bits))
}

/// `visibility_rank`: PU ranks 0, every other member its own value.
fn visibility_rank(bits: u16) -> u16 {
    if bits == PU { 0 } else { bits }
}

/// `strongest_visibility(values)`: the first value with the highest rank, PU for no values.
pub fn strongest_visibility(values: &[u16]) -> u16 {
    let mut best: Option<u16> = None;
    for &value in values {
        if best.is_none_or(|current| visibility_rank(value) > visibility_rank(current)) {
            best = Some(value);
        }
    }
    best.unwrap_or(PU)
}

/// `Classification.categories()` as names, in enum order.
pub fn category_names(packed: u16) -> Vec<&'static str> {
    CATEGORIES.iter().filter(|(_, value)| packed & CATEGORY_MASK & *value != 0).map(|(name, _)| *name).collect()
}

fn is_restricted_or_private(visibility_bits: u16) -> bool {
    visibility_rank(visibility_bits) >= 0b01100
}

/// `action_for_classification_result`: the baseline mapping, moderated for results below 0.5 confidence.
pub fn action_for(classification: Classification, confidence: Option<f64>) -> Result<Action, InvalidVisibility> {
    let packed = classification.pack();
    let sensitivity = packed & 0b11;
    let categories = packed & CATEGORY_MASK;
    if confidence.is_some_and(|value| value < 0.5) {
        return Ok(match sensitivity {
            3 => Action::Warn,
            2 if categories & IDENTIFIER_CATEGORIES != 0 => Action::Warn,
            _ => Action::Allow,
        });
    }
    // Python evaluates `classification.visibility()` before it calls the baseline, so an invalid value raises even for S0.
    visibility_name(packed)?;
    if sensitivity == 0 && categories == 0 {
        return Ok(Action::Allow);
    }
    if sensitivity == 3 {
        return Ok(Action::Block);
    }
    if sensitivity == 2 {
        return Ok(Action::Warn);
    }
    let identifier_count = (categories & IDENTIFIER_CATEGORIES).count_ones();
    if identifier_count > 0 && (identifier_count > 1 || is_restricted_or_private(packed & VISIBILITY_MASK)) {
        return Ok(Action::Warn);
    }
    Ok(Action::Allow)
}

/// `merge_classifications`.
pub fn merge_classifications(values: &[Classification]) -> Result<Classification, InvalidVisibility> {
    if values.is_empty() {
        return Ok(Classification::new(privoke_rules::classification::Sensitivity::S0, PU, 0));
    }
    let mut sensitivity = 0u16;
    let mut visibilities = Vec::with_capacity(values.len());
    let mut categories = 0u16;
    for value in values {
        let packed = value.pack();
        visibility_name(packed)?;
        sensitivity = sensitivity.max(packed & 0b11);
        visibilities.push(packed & VISIBILITY_MASK);
        categories |= packed & CATEGORY_MASK;
    }
    Ok(from_parts(sensitivity, strongest_visibility(&visibilities), categories))
}

/// `initialise_unpacked` from raw parts.
pub fn from_parts(sensitivity: u16, visibility: u16, categories: u16) -> Classification {
    use privoke_rules::classification::Sensitivity;
    let sensitivity = match sensitivity & 0b11 {
        0 => Sensitivity::S0,
        1 => Sensitivity::S1,
        2 => Sensitivity::S2,
        _ => Sensitivity::S3,
    };
    Classification::new(sensitivity, visibility & VISIBILITY_MASK, categories & CATEGORY_MASK)
}

/// One `ClassificationResult`: a finding of a layer, in the coordinates of the original prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The classification.
    pub classification: Classification,
    /// `section_of_text`.
    pub section: String,
    /// `reasoning`.
    pub reasoning: String,
    /// `span`, code point offsets.
    pub span: Option<(usize, usize)>,
    /// `confidence`.
    pub confidence: Option<f64>,
    /// `metadata`, every value already in the text the protobuf map carries (`json.dumps` for non-strings).
    pub metadata: BTreeMap<String, String>,
}

impl Finding {
    /// `ClassificationResult.action()`.
    pub fn action(&self) -> Result<Action, InvalidVisibility> {
        action_for(self.classification, self.confidence)
    }
}

/// `pipeline.strongest_result`: one combined result and the strongest action over all of them.
pub fn strongest_result<'a>(results: impl IntoIterator<Item = &'a Finding>) -> Result<(Option<Finding>, Action), InvalidVisibility> {
    let results: Vec<&Finding> = results.into_iter().collect();
    if results.is_empty() {
        return Ok((None, Action::Allow));
    }
    let mut keys = Vec::with_capacity(results.len());
    for result in &results {
        keys.push((result.action()?, result.classification.pack() & 0b11, (result.classification.pack() & CATEGORY_MASK).count_ones()));
    }
    // `max` keeps the first of equal keys.
    let mut primary = 0usize;
    for (index, key) in keys.iter().enumerate() {
        if *key > keys[primary] {
            primary = index;
        }
    }
    let classifications: Vec<Classification> = results.iter().map(|result| result.classification).collect();
    let merged = merge_classifications(&classifications)?;
    let merged_sensitivity = merged.pack() & 0b11;
    let contributors: Vec<&&Finding> = results.iter().filter(|result| result.classification.pack() & 0b11 == merged_sensitivity).collect();
    let confidence = if contributors.iter().any(|result| result.confidence.is_none()) {
        None
    } else {
        // `max` over floats keeps the first of equal values; NaN does not occur (confidences come from rules and models).
        contributors.iter().filter_map(|result| result.confidence).reduce(|best, value| if value > best { value } else { best })
    };
    let mut combined = Finding {
        classification: merged,
        section: results[primary].section.clone(),
        reasoning: results[primary].reasoning.clone(),
        span: results[primary].span,
        confidence,
        metadata: results[primary].metadata.clone(),
    };
    if results.len() > 1 {
        combined.reasoning = format!("{} Combined {} detector findings.", results[primary].reasoning, results.len());
        combined.metadata.insert("combined_result_count".to_string(), results.len().to_string());
    }
    let mut action = combined.action()?;
    for result in &results {
        action = action.max(result.action()?);
    }
    Ok((Some(combined), action))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use privoke_rules::classification::{Sensitivity, category, visibility};

    use super::*;

    fn finding(sensitivity: Sensitivity, vis: u16, categories: u16, confidence: Option<f64>) -> Finding {
        Finding {
            classification: Classification::new(sensitivity, vis, categories),
            section: "x".into(),
            reasoning: "r".into(),
            span: Some((0, 1)),
            confidence,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn baseline_policy() {
        let act = |c: Classification| action_for(c, Some(0.95)).unwrap();
        assert_eq!(act(Classification::new(Sensitivity::S3, visibility::PU, 0)), Action::Block);
        assert_eq!(act(Classification::new(Sensitivity::S2, visibility::PU, 0)), Action::Warn);
        assert_eq!(act(Classification::new(Sensitivity::S0, visibility::PU, 0)), Action::Allow);
        // One identifier category alone allows, unless the visibility is restricted or private; two warn.
        assert_eq!(act(Classification::new(Sensitivity::S1, visibility::PU, category::LOCATION)), Action::Allow);
        assert_eq!(act(Classification::new(Sensitivity::S1, visibility::P2, category::LOCATION)), Action::Warn);
        assert_eq!(act(Classification::new(Sensitivity::S1, visibility::PU, category::LOCATION | category::IDENTITY)), Action::Warn);
        assert_eq!(act(Classification::new(Sensitivity::S1, visibility::P1, category::IDENTITY)), Action::Allow);
    }

    #[test]
    fn low_confidence_moderates_s3_and_identifier_s2() {
        let low = |c: Classification| action_for(c, Some(0.4)).unwrap();
        assert_eq!(low(Classification::new(Sensitivity::S3, visibility::PU, 0)), Action::Warn);
        assert_eq!(low(Classification::new(Sensitivity::S2, visibility::PU, category::IDENTITY)), Action::Warn);
        assert_eq!(low(Classification::new(Sensitivity::S2, visibility::PU, category::HEALTH)), Action::Allow);
        assert_eq!(action_for(Classification::new(Sensitivity::S3, visibility::PU, 0), None).unwrap(), Action::Block);
    }

    #[test]
    fn strongest_result_combines_and_keeps_the_first_of_equals() {
        let a = finding(Sensitivity::S2, visibility::PU, category::IDENTITY, Some(0.9));
        let mut b = finding(Sensitivity::S2, visibility::P3, category::HEALTH, Some(0.95));
        b.reasoning = "second".into();
        let (combined, action) = strongest_result([&a, &b]).unwrap();
        let combined = combined.unwrap();
        assert_eq!(action, Action::Warn);
        assert_eq!(combined.reasoning, "r Combined 2 detector findings.");
        assert_eq!(combined.metadata.get("combined_result_count").map(String::as_str), Some("2"));
        assert_eq!(combined.confidence, Some(0.95));
        assert_eq!(visibility_name(combined.classification.pack()).unwrap(), "P3");
        assert_eq!(category_names(combined.classification.pack()), vec!["HEALTH", "IDENTITY"]);
        let none: [&Finding; 0] = [];
        assert_eq!(strongest_result(none).unwrap().1, Action::Allow);
    }

    #[test]
    fn missing_confidence_wins_over_numbers() {
        let a = finding(Sensitivity::S1, visibility::PU, 0, None);
        let b = finding(Sensitivity::S1, visibility::PU, 0, Some(0.9));
        assert_eq!(strongest_result([&a, &b]).unwrap().0.unwrap().confidence, None);
    }

    #[test]
    fn an_invalid_visibility_reads_like_the_enum_error() {
        assert_eq!(visibility_name(0b00011).unwrap_err().to_string(), "0 is not a valid Visibility");
        assert_eq!(visibility_name(0b11000).unwrap_err().to_string(), "24 is not a valid Visibility");
    }
}
