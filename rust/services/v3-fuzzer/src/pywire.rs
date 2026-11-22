//! Protobuf bytes as Python's `SerializeToString(deterministic=True)` writes them, for the two messages whose bytes are hashed
//! or retained: the cycle request (hashed into the fingerprint and written to `cycle-request.pb`) and the response (stored in
//! the `cycles` table).
//!
//! Python writes every protobuf map entry with its value field even when the value is the default; `prost` omits it. The
//! request encoder is the one of the legacy fuzzer ([`privoke_fuzzer::pywire`]); the response encoder is here.

use privoke_contracts::proto::v1::FuzzerTrainingResponse;
use prost::Message;

pub use privoke_fuzzer::pywire::fuzzer_request_bytes;

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

/// `response.SerializeToString(deterministic=True)` of a [`FuzzerTrainingResponse`] (`metadata` is field 7, the last).
pub fn fuzzer_response_bytes(response: &FuzzerTrainingResponse) -> Vec<u8> {
    let mut scalars = response.clone();
    scalars.metadata.clear();
    let mut out = scalars.encode_to_vec();
    for (key, value) in &response.metadata {
        text_entry(0x3a, key, value, &mut out);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_default_valued_metadata_entry_keeps_its_value_field_and_decodes_to_the_same_message() {
        let mut response = FuzzerTrainingResponse { accepted: true, model_id: "m".into(), prompts_generated: 64, ..Default::default() };
        response.metadata.insert("empty".into(), String::new());
        response.metadata.insert("key".into(), "value".into());
        let python = fuzzer_response_bytes(&response);
        assert!(python.len() > response.encode_to_vec().len());
        assert_eq!(FuzzerTrainingResponse::decode(python.as_slice()).unwrap(), response);
        let tail = [0x3a, 0x0c, 0x0a, 0x03, b'k', b'e', b'y', 0x12, 0x05, b'v', b'a', b'l', b'u', b'e'];
        assert_eq!(python[python.len() - tail.len()..], tail[..]);
        response.metadata.clear();
        assert_eq!(fuzzer_response_bytes(&response), response.encode_to_vec());
    }
}
