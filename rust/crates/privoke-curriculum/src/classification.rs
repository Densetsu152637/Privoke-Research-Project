//! `privoke_contracts.classification`: the packed sensitivity, visibility and category word.

use crate::error::{Error, Result, invalid};
use crate::value::{Value, object, string, strings};

/// Sensitivity names and bits, in enum order.
pub const SENSITIVITY: [(&str, u16); 4] = [("S0", 0b00), ("S1", 0b01), ("S2", 0b10), ("S3", 0b11)];
/// Visibility names and bits, in enum order.
pub const VISIBILITY: [(&str, u16); 6] =
    [("P0", 0b00100), ("P1", 0b01000), ("P2", 0b01100), ("P3", 0b10000), ("P4", 0b10100), ("PU", 0b11100)];
/// Category names and bits, in enum order.
pub const CATEGORY: [(&str, u16); 10] = [
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

const SENSITIVITY_MASK: u16 = 0b00011;
const VISIBILITY_MASK: u16 = 0b11100;
const CATEGORY_MASK: u16 = 0x7FE0;

/// Sensitivity names in enum order (`Sensitivity.__members__`).
pub fn sensitivity_names() -> impl Iterator<Item = &'static str> {
    SENSITIVITY.iter().map(|(name, _)| *name)
}

/// Visibility names in enum order (`Visibility.__members__`).
pub fn visibility_names() -> impl Iterator<Item = &'static str> {
    VISIBILITY.iter().map(|(name, _)| *name)
}

/// Category names in enum order (`Category.__members__`).
pub fn category_names() -> impl Iterator<Item = &'static str> {
    CATEGORY.iter().map(|(name, _)| *name)
}

/// `name in Sensitivity.__members__`.
pub fn is_sensitivity(name: &str) -> bool {
    SENSITIVITY.iter().any(|(candidate, _)| *candidate == name)
}

/// `name in Visibility.__members__`.
pub fn is_visibility(name: &str) -> bool {
    VISIBILITY.iter().any(|(candidate, _)| *candidate == name)
}

/// `name in Category.__members__`.
pub fn is_category(name: &str) -> bool {
    CATEGORY.iter().any(|(candidate, _)| *candidate == name)
}

/// `Sensitivity[name].value`.
pub fn sensitivity_value(name: &str) -> Result<u16> {
    SENSITIVITY
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, bits)| *bits)
        .ok_or_else(|| Error::Invalid(format!("unknown sensitivity {name}")))
}

/// A packed classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Classification(pub u16);

impl Classification {
    /// `Classification(packed)`: the value is masked to sixteen bits.
    pub fn from_packed(packed: i64) -> Self {
        Self((packed & 0xFFFF) as u16)
    }

    /// `pack()`.
    pub fn pack(self) -> u16 {
        self.0
    }

    /// `sensitivity().name`.
    pub fn sensitivity(self) -> &'static str {
        let bits = self.0 & SENSITIVITY_MASK;
        SENSITIVITY.iter().find(|(_, value)| *value == bits).map(|(name, _)| *name).unwrap_or("S0")
    }

    /// `visibility().name`; Python raises `ValueError` for a visibility word that names no audience.
    pub fn visibility(self) -> Result<&'static str> {
        let bits = self.0 & VISIBILITY_MASK;
        match VISIBILITY.iter().find(|(_, value)| *value == bits) {
            Some((name, _)) => Ok(name),
            None => invalid(format!("{bits} is not a valid Visibility")),
        }
    }

    /// `[c.name for c in categories()]`, in enum order.
    pub fn categories(self) -> Vec<&'static str> {
        CATEGORY.iter().filter(|(_, bits)| self.0 & CATEGORY_MASK & bits != 0).map(|(name, _)| *name).collect()
    }

    /// `is_sensitive()`.
    pub fn is_sensitive(self) -> bool {
        self.sensitivity() != "S0" || self.0 & CATEGORY_MASK != 0
    }

    /// `to_dict()`.
    pub fn to_value(self) -> Result<Value> {
        Ok(object(vec![
            ("sensitivity", string(self.sensitivity())),
            ("visibility", string(self.visibility()?)),
            ("categories", strings(&self.categories())),
        ]))
    }
}

/// `initialise_unpacked(Sensitivity[s], Visibility[v], categories)`.
pub fn initialise_unpacked(sensitivity: &str, visibility: &str, categories: &[&str]) -> Result<Classification> {
    let sensitivity_bits = sensitivity_value(sensitivity)?;
    let visibility_bits = VISIBILITY
        .iter()
        .find(|(name, _)| *name == visibility)
        .map(|(_, bits)| *bits)
        .ok_or_else(|| Error::Invalid(format!("unknown visibility {visibility}")))?;
    let mut packed = sensitivity_bits | visibility_bits;
    for category in categories {
        let bits = CATEGORY
            .iter()
            .find(|(name, _)| name == category)
            .map(|(_, bits)| *bits)
            .ok_or_else(|| Error::Invalid(format!("unknown category {category}")))?;
        packed |= bits;
    }
    Ok(Classification(packed))
}

/// `privacy_heads_curriculum.target`: explicit complete targets, never inferred.
pub fn target(sensitivity: &str, visibility: &str, categories: &[String]) -> Result<Classification> {
    if !is_sensitivity(sensitivity) || !is_visibility(visibility) {
        return invalid("Unknown privacy classification component.");
    }
    let mut unique: Vec<&str> = categories.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != categories.len() || categories.iter().any(|category| !is_category(category)) {
        return invalid("Categories must be an explicit unique supported list.");
    }
    let ordered: Vec<&str> = category_names().filter(|name| categories.iter().any(|category| category == name)).collect();
    initialise_unpacked(sensitivity, visibility, &ordered)
}

/// `target(**value)` for a `{"sensitivity", "visibility", "categories"}` dict value.
pub fn target_from_value(value: &Value) -> Result<Classification> {
    let sensitivity = crate::value::str_at(value, "sensitivity")?;
    let visibility = crate::value::str_at(value, "visibility")?;
    let categories = crate::value::array_at(value, "categories")?;
    let mut names = Vec::new();
    for item in categories {
        match crate::value::as_str(item) {
            Some(name) => names.push(name.to_string()),
            None => return invalid("Categories must be an explicit unique supported list."),
        }
    }
    target(sensitivity, visibility, &names)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(digits) => digits != "0",
        Value::Float(number) => *number != 0.0,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `bool(value)` for a JSON value.
pub fn is_truthy(value: &Value) -> bool {
    truthy(value)
}

/// `str(value)` for a scalar JSON value as Python prints it; containers use their JSON form.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Int(digits) => digits.clone(),
        Value::Float(number) => privoke_contracts::pyfloat::repr(*number).unwrap_or_default(),
        Value::String(text) => text.clone(),
        other => crate::value::dumps(other).unwrap_or_default(),
    }
}

const PACKED_KEYS: [&str; 4] = ["packed_classification", "expected_packed_classification", "classification_packed", "packed"];
const NESTED_KEYS: [&str; 3] = ["classification", "expected_classification", "target"];

fn packed_value(item: &Value) -> Option<&Value> {
    for key in PACKED_KEYS {
        match crate::value::get(item, key) {
            Some(Value::Null) | None => {}
            Some(found) => return Some(found),
        }
    }
    for key in NESTED_KEYS {
        if let Some(found @ (Value::Int(_) | Value::Bool(_))) = crate::value::get(item, key) {
            return Some(found);
        }
    }
    None
}

fn packed_to_int(value: &Value) -> Result<i64> {
    match value {
        Value::Int(digits) => digits.parse().map_err(|_| Error::Invalid("packed classification out of range".to_string())),
        Value::Bool(flag) => Ok(i64::from(*flag)),
        Value::Float(number) => Ok(*number as i64),
        Value::String(text) => text.trim().parse().map_err(|_| Error::Invalid(format!("invalid literal for int(): {text}"))),
        _ => invalid("packed classification must be an int or numeric string"),
    }
}

fn first_present<'a>(item: &'a Value, payload: Option<&'a Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(found) = crate::value::get(item, key) {
            return Some(found);
        }
        if let Some(found) = payload.and_then(|payload| crate::value::get(payload, key)) {
            return Some(found);
        }
    }
    None
}

fn enum_name(value: Option<&Value>, members: &[(&str, u16)]) -> Option<&'static str> {
    let value = value?;
    if matches!(value, Value::Null) {
        return None;
    }
    let key = py_str(value).trim().to_uppercase();
    members.iter().find(|(name, _)| *name == key).map(|(name, _)| *name)
}

// `str.strip().upper()` over the names, which are ASCII, so Rust's case mapping agrees with Python's.
fn categories_from_value(value: Option<&Value>) -> Vec<&'static str> {
    let raw: Vec<Value> = match value {
        None | Some(Value::Null) => return Vec::new(),
        Some(Value::String(text)) => text.split(',').map(|part| Value::String(part.trim().to_uppercase())).collect(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => return Vec::new(),
    };
    raw.iter().filter_map(|item| enum_name(Some(item), &CATEGORY)).collect()
}

/// `classification_from_mapping(item)`: the explicit or packed target of a dataset row, or `None` when it has none.
pub fn from_mapping(item: &Value) -> Result<Option<Classification>> {
    if let Some(packed) = packed_value(item) {
        return Ok(Some(Classification::from_packed(packed_to_int(packed)?)));
    }
    let payload = NESTED_KEYS.iter().find_map(|key| match crate::value::get(item, key) {
        Some(found @ Value::Object(_)) => Some(found),
        _ => None,
    });
    if let Some(packed) = payload.and_then(packed_value) {
        return Ok(Some(Classification::from_packed(packed_to_int(packed)?)));
    }
    let sensitivity = enum_name(first_present(item, payload, &["sensitivity", "expected_sensitivity"]), &SENSITIVITY);
    let visibility = enum_name(first_present(item, payload, &["visibility", "expected_visibility"]), &VISIBILITY);
    let categories = categories_from_value(first_present(item, payload, &["categories", "expected_categories"]));
    if sensitivity.is_none() && visibility.is_none() && categories.is_empty() {
        return Ok(None);
    }
    Ok(Some(initialise_unpacked(sensitivity.unwrap_or("S0"), visibility.unwrap_or("PU"), &categories)?))
}
