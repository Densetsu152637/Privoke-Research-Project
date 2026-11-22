//! Compact JSON in the form Python's `json.dumps(value, separators=(",", ":"), allow_nan=False)` writes it: object keys
//! stay in insertion order, floats use `float.__repr__` and integers are integers. The training traces (local SGD,
//! backtracking and TRAIN diagnostics) are metadata strings, so their bytes are part of the response.

use privoke_contracts::pyfloat;

use crate::error::TrainingError;

/// A JSON value with ordered object keys.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A finite float.
    Float(f64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Json>),
    /// An object whose keys are written in this order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// A string value.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    /// An integer from a count.
    pub fn count(value: usize) -> Self {
        Self::Int(i64::try_from(value).unwrap_or(i64::MAX))
    }

    /// An array of floats.
    pub fn floats(values: &[f64]) -> Self {
        Self::Array(values.iter().map(|value| Self::Float(*value)).collect())
    }

    /// An array of strings.
    pub fn strings(values: &[&str]) -> Self {
        Self::Array(values.iter().map(|value| Self::text(*value)).collect())
    }

    /// An object from `(key, value)` pairs, in order.
    pub fn object(entries: Vec<(&str, Json)>) -> Self {
        Self::Object(entries.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
    }

    /// `json.dumps(value, separators=(",", ":"), allow_nan=False)`.
    pub fn dump(&self) -> Result<String, TrainingError> {
        let mut out = String::new();
        self.write(&mut out)?;
        Ok(out)
    }

    fn write(&self, out: &mut String) -> Result<(), TrainingError> {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(value) => out.push_str(&value.to_string()),
            Self::Float(value) => {
                let text = pyfloat::repr(*value).map_err(|_| TrainingError::invalid("Out of range float values are not JSON compliant"))?;
                out.push_str(&text);
            }
            Self::Str(value) => out.push_str(&quote(value)?),
            Self::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out)?;
                }
                out.push(']');
            }
            Self::Object(entries) => {
                out.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&quote(key)?);
                    out.push(':');
                    value.write(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
}

fn quote(text: &str) -> Result<String, TrainingError> {
    serde_json::to_string(text).map_err(|error| TrainingError::invalid(error.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn writes_python_compact_json() {
        let value = Json::object(vec![
            ("b", Json::Float(1e-5)),
            ("a", Json::Array(vec![Json::Int(1), Json::Float(1.0), Json::Null, Json::Bool(true), Json::text("x\"y")])),
            ("c", Json::floats(&[0.5, 100.0, 1e16])),
        ]);
        assert_eq!(value.dump().unwrap(), "{\"b\":1e-05,\"a\":[1,1.0,null,true,\"x\\\"y\"],\"c\":[0.5,100.0,1e+16]}");
        assert!(Json::Float(f64::NAN).dump().is_err());
    }
}
