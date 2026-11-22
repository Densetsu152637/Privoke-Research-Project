//! Protobuf bytes as Python's `SerializeToString(deterministic=True)` writes them, for the two places where the bytes are
//! hashed or retained.
//!
//! The Python runtime writes every map entry with both its key and its value field, even when the value is the default
//! (an empty string or `0.0`); `prost` leaves a default value out. The two decode to the same message, but a fingerprint
//! over the request and the retained response bytes of the cycle record must be the bytes Python wrote, so these two
//! messages are encoded here: everything but the map fields by `prost`, the map entries by hand, in field order.

use privoke_contracts::proto::v1::{ComputeSemanticGradientsResponse, FuzzerTrainingRequest};
use prost::Message;

/// The order in which Python's deterministic serialization writes the entries of a string-keyed map: bytewise, except that a key
/// that is a prefix of another sorts after it (`contextual_training_diagnostics_policy` before `contextual_training_diagnostics`).
fn python_order(left: &str, right: &str) -> std::cmp::Ordering {
    let (left, right) = (left.as_bytes(), right.as_bytes());
    let shared = left.len().min(right.len());
    left[..shared].cmp(&right[..shared]).then(right.len().cmp(&left.len()))
}

fn sorted<'a, V>(map: impl IntoIterator<Item = (&'a String, &'a V)>) -> Vec<(&'a String, &'a V)>
where
    V: 'a,
{
    let mut entries: Vec<_> = map.into_iter().collect();
    entries.sort_by(|left, right| python_order(left.0, right.0));
    entries
}

fn varint(mut number: usize, out: &mut Vec<u8>) {
    loop {
        let low = (number & 0x7f) as u8;
        number >>= 7;
        if number == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn text_entry(field_tag: u8, key: &str, value: &str, out: &mut Vec<u8>) {
    let mut entry = vec![0x0a];
    varint(key.len(), &mut entry);
    entry.extend_from_slice(key.as_bytes());
    entry.push(0x12);
    varint(value.len(), &mut entry);
    entry.extend_from_slice(value.as_bytes());
    out.push(field_tag);
    varint(entry.len(), out);
    out.extend_from_slice(&entry);
}

fn double_entry(field_tag: u8, key: &str, value: f64, out: &mut Vec<u8>) {
    let mut entry = vec![0x0a];
    varint(key.len(), &mut entry);
    entry.extend_from_slice(key.as_bytes());
    entry.push(0x11);
    entry.extend_from_slice(&value.to_le_bytes());
    out.push(field_tag);
    varint(entry.len(), out);
    out.extend_from_slice(&entry);
}

/// `request.SerializeToString(deterministic=True)` of a [`FuzzerTrainingRequest`] (`metadata` is field 6, the last).
pub fn fuzzer_request_bytes(request: &FuzzerTrainingRequest) -> Vec<u8> {
    let mut scalars = request.clone();
    scalars.metadata.clear();
    let mut out = scalars.encode_to_vec();
    for (key, value) in sorted(&request.metadata) {
        text_entry(0x32, key, value, &mut out);
    }
    out
}

/// `response.SerializeToString(deterministic=True)` of a [`ComputeSemanticGradientsResponse`]: fields 1 to 4, then
/// `metrics` (5) and `metadata` (6) with explicit entries, then `error` (7) and `executions` (8).
pub fn compute_response_bytes(response: &ComputeSemanticGradientsResponse) -> Vec<u8> {
    let mut head = response.clone();
    head.metrics.clear();
    head.metadata.clear();
    head.error.clear();
    head.executions.clear();
    let tail =
        ComputeSemanticGradientsResponse { error: response.error.clone(), executions: response.executions.clone(), ..Default::default() };
    let mut out = head.encode_to_vec();
    for (key, number) in sorted(&response.metrics) {
        double_entry(0x2a, key, *number, &mut out);
    }
    for (key, value) in sorted(&response.metadata) {
        text_entry(0x32, key, value, &mut out);
    }
    out.extend(tail.encode_to_vec());
    out
}

/// `response.SerializeToString(deterministic=True)` of a `ComputePresenceGradientsResponse` (the same layout as the semantic one).
pub fn presence_response_bytes(response: &privoke_contracts::proto::v1::ComputePresenceGradientsResponse) -> Vec<u8> {
    use privoke_contracts::proto::v1::ComputePresenceGradientsResponse as Response;
    let mut head = response.clone();
    head.metrics.clear();
    head.metadata.clear();
    head.error.clear();
    head.executions.clear();
    let tail = Response { error: response.error.clone(), executions: response.executions.clone(), ..Default::default() };
    let mut out = head.encode_to_vec();
    for (key, number) in sorted(&response.metrics) {
        double_entry(0x2a, key, *number, &mut out);
    }
    for (key, value) in sorted(&response.metadata) {
        text_entry(0x32, key, value, &mut out);
    }
    out.extend(tail.encode_to_vec());
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_valued_map_entries_are_written_and_decode_to_the_same_message() {
        let mut response = ComputeSemanticGradientsResponse { request_id: "r".into(), error: "e".into(), ..Default::default() };
        response.metrics.insert("zero".into(), 0.0);
        response.metrics.insert("one".into(), 1.0);
        response.metadata.insert("empty".into(), String::new());
        response.metadata.insert("key".into(), "value".into());
        let python = compute_response_bytes(&response);
        assert!(python.len() > response.encode_to_vec().len(), "the default value fields are present");
        assert_eq!(ComputeSemanticGradientsResponse::decode(python.as_slice()).unwrap(), response);
        // `one` sorts before `zero`; its entry is `0a 03 one 11 <1.0>`.
        let expected: Vec<u8> = [&[0x2a, 0x0e, 0x0a, 0x03][..], b"one", &[0x11], &1.0f64.to_le_bytes()].concat();
        assert!(python.windows(expected.len()).any(|window| window == expected.as_slice()));
    }

    #[test]
    fn a_key_that_is_a_prefix_of_another_sorts_after_it_as_in_python() {
        let mut keys = vec!["a", "b", "ab", "aa", "diagnostics", "diagnostics_policy"];
        keys.sort_by(|left, right| python_order(left, right));
        assert_eq!(keys, ["aa", "ab", "a", "b", "diagnostics_policy", "diagnostics"]);
    }

    #[test]
    fn a_request_with_an_empty_metadata_value_keeps_the_value_field() {
        let mut request = FuzzerTrainingRequest { request_id: "r".into(), prompt_count: 8, ..Default::default() };
        request.metadata.insert("k".into(), String::new());
        let python = fuzzer_request_bytes(&request);
        assert_eq!(python[python.len() - 7..], [0x32, 0x05, 0x0a, 0x01, b'k', 0x12, 0x00]);
        assert_eq!(FuzzerTrainingRequest::decode(python.as_slice()).unwrap(), request);
        request.metadata.clear();
        assert_eq!(fuzzer_request_bytes(&request), request.encode_to_vec());
    }
}
