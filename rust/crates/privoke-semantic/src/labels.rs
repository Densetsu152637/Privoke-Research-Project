//! Label inventories of the classification heads and the shared prediction rules.

use privoke_rules::classification::{Classification, Sensitivity, category, visibility};

/// Sensitivity labels, in head order (`LABELS["sensitivity"]`).
pub const SENSITIVITY: [(&str, Sensitivity); 4] =
    [("S0", Sensitivity::S0), ("S1", Sensitivity::S1), ("S2", Sensitivity::S2), ("S3", Sensitivity::S3)];

/// Visibility labels, in head order (`LABELS["visibility"]`), with their packed values.
pub const VISIBILITY: [(&str, u16); 6] = [
    ("P0", visibility::P0),
    ("P1", visibility::P1),
    ("P2", visibility::P2),
    ("P3", visibility::P3),
    ("P4", visibility::P4),
    ("PU", visibility::PU),
];

/// Category labels, in head order (`LABELS["category"]`), with their packed bits.
pub const CATEGORY: [(&str, u16); 10] = [
    ("HEALTH", category::HEALTH),
    ("POLITICS", category::POLITICS),
    ("RELIGION", category::RELIGION),
    ("CRIMINAL", category::CRIMINAL),
    ("FINANCIAL", category::FINANCIAL),
    ("SEXUAL", category::SEXUAL),
    ("CHILD", category::CHILD),
    ("LOCATION", category::LOCATION),
    ("IDENTITY", category::IDENTITY),
    ("THIRD_PARTY", category::THIRD_PARTY),
];

/// Number of labels of each head: sensitivity, visibility, category.
pub const HEAD_WIDTHS: [usize; 3] = [SENSITIVITY.len(), VISIBILITY.len(), CATEGORY.len()];

/// A classification head decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    /// The packed classification (`initialise_unpacked`).
    pub classification: Classification,
    /// Sensitivity label.
    pub sensitivity: String,
    /// Visibility label.
    pub visibility: String,
    /// Category labels at or above the threshold, in head order.
    pub categories: Vec<String>,
    /// The largest of the sensitivity and category probabilities, unrounded.
    pub confidence_raw: f64,
    /// `round(min(max(raw, 0), .999), 3)`.
    pub confidence: f64,
}

/// Python's `round(value, 3)`: the nearest multiple of 0.001 of the exact binary value, ties to even.
pub fn round3(value: f64) -> f64 {
    format!("{value:.3}").parse::<f64>().unwrap_or(value)
}

/// The reported confidence of a raw probability.
pub fn reported_confidence(raw: f64) -> f64 {
    round3(raw.clamp(0.0, 0.999))
}

/// The sensitivity of a label name.
pub fn sensitivity_value(name: &str) -> Option<Sensitivity> {
    SENSITIVITY.iter().find(|(label, _)| *label == name).map(|(_, value)| *value)
}

/// The packed visibility of a label name.
pub fn visibility_value(name: &str) -> Option<u16> {
    VISIBILITY.iter().find(|(label, _)| *label == name).map(|(_, value)| *value)
}

/// The category bit of a label name.
pub fn category_bit(name: &str) -> Option<u16> {
    CATEGORY.iter().find(|(label, _)| *label == name).map(|(_, bit)| *bit)
}

/// Index of the first largest value (`argmax`).
pub fn argmax(values: &[f32]) -> usize {
    let mut best = 0;
    for (index, value) in values.iter().enumerate() {
        if *value > values[best] {
            best = index;
        }
    }
    best
}

/// A finding is reported unless the classification is exactly the empty one (`S0`, no categories, `PU`).
pub fn is_empty_classification(sensitivity: Sensitivity, categories: u16, visibility_value: u16) -> bool {
    sensitivity == Sensitivity::S0 && categories == 0 && visibility_value == visibility::PU
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round3_matches_python() {
        // Python: round(0.954321, 3) == 0.954; round(0.0005, 3) == 0.001 and round(0.0015, 3) == 0.002 (the doubles are
        // just above the tie); round(0.0625, 3) == 0.062 (an exact tie goes to the even digit).
        assert_eq!(round3(0.954_321), 0.954);
        assert_eq!(round3(0.0005), 0.001);
        assert_eq!(round3(0.0015), 0.002);
        assert_eq!(round3(0.0625), 0.062);
        assert_eq!(round3(0.999), 0.999);
        assert_eq!(round3(0.0), 0.0);
    }

    #[test]
    fn confidence_is_clamped() {
        assert_eq!(reported_confidence(1.0), 0.999);
        assert_eq!(reported_confidence(-0.5), 0.0);
        assert_eq!(reported_confidence(0.5), 0.5);
    }

    #[test]
    fn argmax_takes_the_first_maximum() {
        assert_eq!(argmax(&[0.1, 0.9, 0.9, 0.2]), 1);
        assert_eq!(argmax(&[3.0]), 0);
    }

    #[test]
    fn empty_classification() {
        assert!(is_empty_classification(Sensitivity::S0, 0, visibility::PU));
        assert!(!is_empty_classification(Sensitivity::S1, 0, visibility::PU));
        assert!(!is_empty_classification(Sensitivity::S0, category::HEALTH, visibility::PU));
        assert!(!is_empty_classification(Sensitivity::S0, 0, visibility::P0));
    }
}
