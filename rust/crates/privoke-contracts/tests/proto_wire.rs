//! The generated bindings must read and re-write the Python-serialised messages of the corpus byte for byte.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use base64::Engine;
use common::{array, get, load, text};
use privoke_contracts::digest::{receipt_key, sha256_hex};
use privoke_contracts::proto::v1::{ParameterUpdateRequest, ParameterUpdateStatusRequest, TelemetryPacket};
use prost::Message;

fn decode(value: &common::Value) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(text(value)).unwrap()
}

#[test]
fn update_requests_round_trip_byte_for_byte() {
    let corpus = load("update_sequence.json");
    let steps = array(get(&corpus, "steps"));
    assert!(steps.len() >= 15);
    for step in steps {
        let label = text(get(step, "label"));
        let bytes = decode(get(step, "request_b64"));
        let request = ParameterUpdateRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(request.encode_to_vec(), bytes, "{label}");
    }
    for lookup in array(get(&corpus, "status_lookups")) {
        let bytes = decode(get(lookup, "request_b64"));
        let request = ParameterUpdateStatusRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(request.encode_to_vec(), bytes, "{}", text(get(lookup, "label")));
    }
}

#[test]
fn recorded_receipts_follow_from_the_recorded_requests() {
    let corpus = load("update_sequence.json");
    let steps = array(get(&corpus, "steps"));
    let receipts = array(get(&corpus, "receipts"));
    assert_eq!(receipts.len(), 3);
    for entry in receipts {
        let receipt = get(entry, "receipt");
        let step = steps
            .iter()
            .find(|step| {
                let request = ParameterUpdateRequest::decode(decode(get(step, "request_b64")).as_slice()).unwrap();
                text(get(step, "label")) != "request-id-reuse-different-payload"
                    && request.metadata.get("request_id").is_some_and(|id| {
                        receipt_key(&request.source_id, id, request.metadata.get("request_source_id").map_or("", String::as_str)).unwrap()
                            == text(get(entry, "key"))
                    })
                    && text(get(step, "status")) == "OK"
            })
            .unwrap_or_else(|| panic!("no request for receipt {}", text(get(entry, "key"))));
        let bytes = decode(get(step, "request_b64"));
        // The receipt's payload digest is the SHA-256 of the deterministic serialisation.
        assert_eq!(sha256_hex(&bytes), text(get(receipt, "payload_digest")));
    }
}

#[test]
fn telemetry_packets_round_trip_byte_for_byte() {
    let corpus = load("telemetry.json");
    let records = array(get(&corpus, "records"));
    assert!(records.len() > 190);
    for record in records {
        let bytes = decode(get(record, "request_b64"));
        let packet = TelemetryPacket::decode(bytes.as_slice()).unwrap();
        assert_eq!(packet.encode_to_vec(), bytes, "{}", text(get(record, "label")));
    }
}

#[test]
fn map_fields_encode_in_key_order() {
    let mut request = ParameterUpdateRequest::default();
    for key in ["zeta", "alpha", "mid"] {
        request.metadata.insert(key.to_string(), "v".to_string());
    }
    let bytes = request.encode_to_vec();
    let positions: Vec<usize> =
        ["alpha", "mid", "zeta"].iter().map(|key| bytes.windows(key.len()).position(|w| w == key.as_bytes()).unwrap()).collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "map entries must be sorted: {positions:?}");
}
