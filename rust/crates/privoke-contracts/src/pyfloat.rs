//! Python `float.__repr__` for finite doubles.
//!
//! Python writes the shortest digit string that round-trips, in positional notation unless the decimal
//! exponent is below -4 or at least 16 (`1e-05`, `1e+16`, `1e-08`). Rust's `{:e}` gives the same shortest digits,
//! so only the layout differs.

/// Error for NaN and infinities, which `json.dumps(..., allow_nan=False)` refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("non-finite floating-point value")]
pub struct NonFinite;

/// Return Python's `repr(value)`.
pub fn repr(value: f64) -> Result<String, NonFinite> {
    if !value.is_finite() {
        return Err(NonFinite);
    }
    if value == 0.0 {
        return Ok(if value.is_sign_negative() { "-0.0" } else { "0.0" }.to_string());
    }
    let scientific = format!("{:e}", value.abs());
    let Some((mantissa, exponent)) = scientific.split_once('e') else {
        return Err(NonFinite);
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let Ok(exponent) = exponent.parse::<i32>() else {
        return Err(NonFinite);
    };
    // The decimal point sits after `point` digits: value = 0.DIGITS * 10^point.
    let point = exponent + 1;
    let count = i32::try_from(digits.len()).map_err(|_| NonFinite)?;
    let mut out = String::with_capacity(digits.len() + 8);
    if value.is_sign_negative() {
        out.push('-');
    }
    if point <= -4 || point > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let shown = point - 1;
        out.push('e');
        out.push(if shown < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", shown.abs()));
    } else if point <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat(usize::try_from(-point).map_err(|_| NonFinite)?));
        out.push_str(&digits);
    } else if point >= count {
        out.push_str(&digits);
        out.push_str(&"0".repeat(usize::try_from(point - count).map_err(|_| NonFinite)?));
        out.push_str(".0");
    } else {
        let split = usize::try_from(point).map_err(|_| NonFinite)?;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::repr;

    #[test]
    fn matches_python_layout_at_the_boundaries() {
        let cases = [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (0.1, "0.1"),
            (1e-8, "1e-08"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.5e300, "1.5e+300"),
            (5e-324, "5e-324"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (-2.5e-7, "-2.5e-07"),
            (0.30000000000000004, "0.30000000000000004"),
        ];
        for (value, expected) in cases {
            assert_eq!(repr(value).as_deref(), Ok(expected), "{value:e}");
        }
    }

    #[test]
    fn refuses_non_finite() {
        assert!(repr(f64::NAN).is_err());
        assert!(repr(f64::INFINITY).is_err());
        assert!(repr(f64::NEG_INFINITY).is_err());
    }
}
