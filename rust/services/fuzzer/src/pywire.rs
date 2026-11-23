//! Protobuf bytes as Python's `SerializeToString(deterministic=True)` writes them, for the two places where the bytes are
//! hashed or retained.
//!
//! The Python runtime writes every map entry with both its key and its value field, even when the value is the default
//! (an empty string or `0.0`); `prost` leaves a default value out. The two decode to the same message, but a fingerprint
//! over the request and the retained response bytes of the cycle record must be the bytes Python wrote, so these two
//! messages are encoded here: everything but the map fields by `prost`, the map entries by hand, in field order.

use privoke_contracts::proto::v1::ComputeSemanticGradientsResponse;
use privoke_contracts::pywire::{double_entry, sorted, text_entry};
use prost::Message;

/// The request encoder moved to `privoke_contracts::pywire` (shared with the V3 fuzzer).
pub use privoke_contracts::pywire::fuzzer_request_bytes;

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
}
