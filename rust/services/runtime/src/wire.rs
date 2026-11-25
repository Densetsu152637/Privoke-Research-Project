//! A small protobuf encoder that writes what the Python runtime (`upb`) writes with `SerializeToString(deterministic=True)`:
//! fields in field-number order, proto3 scalars at their default left out, and every map entry written with both its key
//! and its value (an empty value included), entries in key order.
//!
//! `prost` leaves the value out of a map entry whose value is the default, so its bytes differ from Python's for an
//! empty string value. The responses of this crate are therefore written here, and `prost` only decodes requests.

/// Appends a base-128 varint.
pub fn varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn key(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    varint(out, (u64::from(field) << 3) | u64::from(wire_type));
}

/// A string field; left out when empty.
pub fn string(out: &mut Vec<u8>, field: u32, value: &str) {
    if !value.is_empty() {
        string_always(out, field, value);
    }
}

/// A string field that is written even when empty (repeated elements and map entries).
pub fn string_always(out: &mut Vec<u8>, field: u32, value: &str) {
    key(out, field, 2);
    varint(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// A nested message, written even when it is empty (a message that is set).
pub fn message(out: &mut Vec<u8>, field: u32, body: &[u8]) {
    key(out, field, 2);
    varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

/// A `bool` field; left out when false.
pub fn boolean(out: &mut Vec<u8>, field: u32, value: bool) {
    if value {
        key(out, field, 0);
        out.push(1);
    }
}

/// A `uint32` field; left out when zero.
pub fn uint32(out: &mut Vec<u8>, field: u32, value: u32) {
    if value != 0 {
        key(out, field, 0);
        varint(out, u64::from(value));
    }
}

/// An `int32` field; left out when zero. A negative value takes ten bytes, as protobuf writes it.
pub fn int32(out: &mut Vec<u8>, field: u32, value: i32) {
    if value != 0 {
        key(out, field, 0);
        varint(out, i64::from(value) as u64);
    }
}

/// An enum field; left out when zero.
pub fn enumeration(out: &mut Vec<u8>, field: u32, value: i32) {
    int32(out, field, value);
}

/// A `double` field; left out when its bits are all zero (positive zero), as proto3 implicit presence does.
pub fn double(out: &mut Vec<u8>, field: u32, value: f64) {
    if value.to_bits() != 0 {
        key(out, field, 1);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// A `double` that is written even at zero: a proto3 `optional` field that is set, and a map value.
pub fn double_always(out: &mut Vec<u8>, field: u32, value: f64) {
    key(out, field, 1);
    out.extend_from_slice(&value.to_le_bytes());
}

/// A packed `repeated float` field: one length-delimited run of little-endian floats; left out when empty.
pub fn packed_f32(out: &mut Vec<u8>, field: u32, values: &[f32]) {
    if values.is_empty() {
        return;
    }
    key(out, field, 2);
    varint(out, (values.len() * 4) as u64);
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// A packed `repeated uint32` field: one length-delimited run of varints; left out when empty.
pub fn packed_u32(out: &mut Vec<u8>, field: u32, values: &[u32]) {
    if values.is_empty() {
        return;
    }
    let mut body = Vec::with_capacity(values.len());
    for value in values {
        varint(&mut body, u64::from(*value));
    }
    message(out, field, &body);
}

/// A `map<string, double>` field: one entry per key in byte order, each with its key and its value (zero included).
pub fn double_map<'a>(out: &mut Vec<u8>, field: u32, entries: impl IntoIterator<Item = (&'a String, &'a f64)>) {
    let mut sorted: Vec<(&String, &f64)> = entries.into_iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for (name, value) in sorted {
        let mut entry = Vec::with_capacity(name.len() + 12);
        string_always(&mut entry, 1, name);
        double_always(&mut entry, 2, *value);
        message(out, field, &entry);
    }
}

/// A `map<string, string>` field: one entry per key in byte order, each with its key and its value.
pub fn string_map<'a>(out: &mut Vec<u8>, field: u32, entries: impl IntoIterator<Item = (&'a String, &'a String)>) {
    let mut sorted: Vec<(&String, &String)> = entries.into_iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for (name, value) in sorted {
        let mut entry = Vec::with_capacity(name.len() + value.len() + 4);
        string_always(&mut entry, 1, name);
        string_always(&mut entry, 2, value);
        message(out, field, &entry);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn map_entries_keep_empty_values_and_sort_by_key() {
        let mut map = BTreeMap::new();
        map.insert("b".to_string(), "c".to_string());
        map.insert("a".to_string(), String::new());
        let mut out = Vec::new();
        string(&mut out, 1, "x");
        string_map(&mut out, 8, &map);
        // Verified against `SerializeToString(deterministic=True)` of the Python runtime.
        assert_eq!(out, [0x0a, 0x01, b'x', 0x42, 0x05, 0x0a, 0x01, b'a', 0x12, 0x00, 0x42, 0x06, 0x0a, 0x01, b'b', 0x12, 0x01, b'c']);
    }

    #[test]
    fn packed_fields_and_double_maps_keep_zero_values() {
        let mut out = Vec::new();
        packed_f32(&mut out, 2, &[]);
        packed_u32(&mut out, 3, &[]);
        assert!(out.is_empty());
        packed_f32(&mut out, 2, &[1.0, -2.5]);
        assert_eq!(out, [0x12, 8, 0, 0, 0x80, 0x3f, 0, 0, 0x20, 0xc0]);
        let mut out = Vec::new();
        packed_u32(&mut out, 3, &[8, 300]);
        assert_eq!(out, [0x1a, 3, 8, 0xac, 0x02]);
        let mut map = BTreeMap::new();
        map.insert("z".to_string(), 0.0f64);
        map.insert("a".to_string(), 1.0f64);
        let mut out = Vec::new();
        double_map(&mut out, 5, &map);
        assert_eq!(&out[..2], &[0x2a, 12]);
        assert_eq!(&out[2..7], &[0x0a, 1, b'a', 0x11, 0]);
        assert_eq!(&out[out.len() - 12..], &[0x0a, 1, b'z', 0x11, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn defaults_are_left_out_and_negative_numbers_take_ten_bytes() {
        let mut out = Vec::new();
        boolean(&mut out, 6, false);
        double(&mut out, 7, 0.0);
        uint32(&mut out, 4, 0);
        int32(&mut out, 4, 0);
        assert!(out.is_empty());
        int32(&mut out, 4, -1);
        assert_eq!(out.len(), 11);
        let mut out = Vec::new();
        double(&mut out, 7, 0.95);
        assert_eq!(out[0], 0x39);
        assert_eq!(&out[1..], &0.95f64.to_le_bytes());
    }
}
