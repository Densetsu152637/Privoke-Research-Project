//! Structurally framed tensor identity: `privoke_model.fingerprint.parameter_fingerprint`.

use std::collections::BTreeMap;

use crate::canonical::{self, CanonicalError, Variant};
use crate::digest::sha256_hex;
use crate::pyfloat;

/// Hash the ordered tensor names, shapes and values without ambiguous joins.
///
/// With `shapes = None` every tensor carries a `null` shape. With `Some`, a tensor missing from the map carries `[]`,
/// as Python's `list(shapes.get(name, ()))` does. Values are the doubles Python obtains from `float(value)`.
pub fn parameter_fingerprint(
    parameters: &BTreeMap<String, Vec<f64>>,
    shapes: Option<&BTreeMap<String, Vec<u64>>>,
) -> Result<String, CanonicalError> {
    let mut out = String::from("[");
    for (index, (name, values)) in parameters.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('[');
        canonical::write_string(&mut out, name, Variant::Utf8);
        out.push(',');
        match shapes {
            None => out.push_str("null"),
            Some(map) => {
                out.push('[');
                if let Some(shape) = map.get(name) {
                    for (position, size) in shape.iter().enumerate() {
                        if position > 0 {
                            out.push(',');
                        }
                        out.push_str(&size.to_string());
                    }
                }
                out.push(']');
            }
        }
        out.push_str(",[");
        for (position, value) in values.iter().enumerate() {
            if position > 0 {
                out.push(',');
            }
            out.push_str(&pyfloat::repr(*value)?);
        }
        out.push_str("]]");
    }
    out.push(']');
    Ok(sha256_hex(out.as_bytes()))
}
