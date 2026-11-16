//! How a backend NER label maps into PriVoke classification (`NER/use_cases.py`).

use privoke_rules::classification::{Classification, Sensitivity, category, visibility};

/// `EntityUseCase`: entity type, classification and confidence of one label.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EntityUseCase {
    /// `entity_type`.
    pub entity_type: &'static str,
    /// The classification's sensitivity.
    pub sensitivity: Sensitivity,
    /// The classification's visibility bits.
    pub visibility: u16,
    /// The classification's category bits.
    pub categories: u16,
    /// Confidence.
    pub confidence: f64,
}

impl EntityUseCase {
    /// The packed classification of the label.
    pub const fn classification(&self) -> Classification {
        Classification::new(self.sensitivity, self.visibility, self.categories)
    }

    /// `initialise_unpacked(sensitivity, base.visibility(), base.categories())`: the label's classification at another
    /// sensitivity.
    pub const fn with_sensitivity(&self, sensitivity: Sensitivity) -> Classification {
        Classification::new(sensitivity, self.visibility, self.categories)
    }
}

const PERSON: EntityUseCase = EntityUseCase {
    entity_type: "name",
    sensitivity: Sensitivity::S2,
    visibility: visibility::PU,
    categories: category::IDENTITY,
    confidence: 0.85,
};
const GPE: EntityUseCase = EntityUseCase {
    entity_type: "location",
    sensitivity: Sensitivity::S2,
    visibility: visibility::PU,
    categories: category::LOCATION,
    confidence: 0.85,
};
const FAC: EntityUseCase = EntityUseCase { confidence: 0.80, ..GPE };
const ORG: EntityUseCase = EntityUseCase {
    entity_type: "organization",
    sensitivity: Sensitivity::S1,
    visibility: visibility::PU,
    categories: category::IDENTITY,
    confidence: 0.75,
};

/// `NER_LABEL_USE_CASES.get(label)`: PERSON, GPE, LOC, FAC and ORG.
pub fn use_case(label: &str) -> Option<EntityUseCase> {
    match label {
        "PERSON" => Some(PERSON),
        "GPE" | "LOC" => Some(GPE),
        "FAC" => Some(FAC),
        "ORG" => Some(ORG),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_map_like_the_python_table() {
        assert_eq!(use_case("PERSON").map(|u| u.classification().pack()), Some(8222));
        assert_eq!(use_case("GPE").map(|u| u.classification().pack()), Some(4126));
        assert_eq!(use_case("LOC"), use_case("GPE"));
        assert_eq!(use_case("FAC").map(|u| u.confidence), Some(0.80));
        assert_eq!(use_case("ORG").map(|u| u.entity_type), Some("organization"));
        assert_eq!(use_case("DATE"), None);
    }
}
