//! Recorded responses of the external classifier, parsed in Rust and compared with what the Python client returned
//! for the same HTTP answer (stage 16). No network is involved.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod open_support;

use open_support::golden;
use privoke_rules::classification::Sensitivity;
use privoke_semantic::open_response::parse_http_response;
use privoke_semantic::{ExternalResult, SemanticError};
use serde_json::Value;

fn assert_same_result(id: &str, index: usize, ours: &ExternalResult, theirs: &Value) {
    let at = format!("{id}[{index}]");
    assert_eq!(u64::from(ours.classification.pack()), theirs["packed"].as_u64().unwrap(), "{at}: packed");
    assert_eq!(ours.section_of_text, theirs["section_of_text"].as_str().unwrap(), "{at}: section");
    assert_eq!(ours.reasoning, theirs["reasoning"].as_str().unwrap(), "{at}: reasoning");
    let span = ours.span.map_or(Value::Null, |(start, end)| serde_json::json!([start, end]));
    assert_eq!(span, theirs["span"], "{at}: span");
    // Python's confidence is an int, a float or `None`.
    assert_eq!(ours.confidence, theirs["confidence"].as_f64(), "{at}: confidence");
    assert_eq!(Value::Object(ours.metadata.clone()), theirs["metadata"], "{at}: metadata");
}

#[test]
fn recorded_responses_parse_identically() {
    let golden = golden();
    let cases = golden["responses"].as_array().unwrap();
    assert!(cases.len() >= 80);
    let (mut ok, mut errors) = (0, 0);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let status = u16::try_from(case["status"].as_u64().unwrap()).unwrap();
        let outcome = parse_http_response(status, case["http_body"].as_str().unwrap().as_bytes(), case["text"].as_str().unwrap());
        let python = &case["python"];
        match (python["status"].as_str().unwrap(), outcome) {
            ("ok", Ok(results)) => {
                let expected = python["results"].as_array().unwrap();
                assert_eq!(results.len(), expected.len(), "{id}: result count");
                for (index, (ours, theirs)) in results.iter().zip(expected).enumerate() {
                    assert_same_result(id, index, ours, theirs);
                }
                ok += 1;
            }
            ("error", Err(error)) => {
                let (kind, message) = (python["type"].as_str().unwrap(), python["message"].as_str().unwrap());
                match kind {
                    // The classifier's own `RuntimeError`s carry the same text.
                    "RuntimeError" => assert_eq!(error.to_string(), message, "{id}"),
                    // `APIStatusError`: the SDK appends the response body, which this client never echoes.
                    "AuthenticationError" | "RateLimitError" | "InternalServerError" => {
                        assert_eq!(error.to_string(), format!("Error code: {status}"), "{id}");
                    }
                    // The SDK's decoding failure of a body that is not JSON.
                    "JSONDecodeError" => {
                        assert_eq!(error.to_string(), "Semantic classifier returned an invalid HTTP response.", "{id}");
                    }
                    other => panic!("{id}: unexpected Python error {other}"),
                }
                errors += 1;
            }
            (expected, got) => panic!("{id}: Python {expected}, Rust {got:?}"),
        }
    }
    assert!(ok >= 25 && errors >= 40, "ok {ok}, errors {errors}");
}

fn text_error(result: Result<Vec<ExternalResult>, SemanticError>) -> String {
    result.err().map(|error| error.to_string()).unwrap_or_default()
}

fn completion(content: &str) -> String {
    serde_json::json!({"choices": [{"message": {"content": content}}]}).to_string()
}

#[test]
fn no_risk_envelope_is_an_empty_list_and_a_bare_list_is_not() {
    assert!(parse_http_response(200, completion("{\"results\": []}").as_bytes(), "t").unwrap().is_empty());
    assert_eq!(text_error(parse_http_response(200, completion("[]").as_bytes(), "t")), "Semantic classifier returned no valid results.");
}

#[test]
fn sensitivity_is_read_from_the_defined_names() {
    let content = r#"{"results": [{"sensitivity": "S3", "visibility": "P4", "categories": ["HEALTH", "IDENTITY"], "section_of_text": "t", "reasoning": "r", "confidence": 0.5}]}"#;
    let results = parse_http_response(200, completion(content).as_bytes(), "t").unwrap();
    assert_eq!(results[0].classification.sensitivity(), Sensitivity::S3);
}

#[test]
fn a_body_that_is_not_a_completion_is_an_invalid_response() {
    assert_eq!(text_error(parse_http_response(200, &[b' '; 64], "t")), "Semantic classifier returned an invalid HTTP response.");
}
