//! The external classifier's request against the Python SDK's (stage 16): byte-identical bodies for the stage 0 corpus
//! prompts, the same method, URL and protocol headers, and the same configuration resolution. No network is involved.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod open_support;

use open_support::{PLACEHOLDER_KEY, corpus_prompt, env_of, golden, manifest_dir};
use privoke_contracts::digest::sha256_hex;
use privoke_semantic::open_classifier::{build_request, request_body};
use privoke_semantic::{OpenConfig, OpenOptions};
use serde_json::Value;

fn key_env() -> impl Fn(&str) -> Option<String> {
    env_of(vec![("OPENAI_API_KEY".into(), PLACEHOLDER_KEY.into())])
}

/// The configuration a golden request case was captured with.
fn config_for(case: &Value) -> OpenConfig {
    let mut options = OpenOptions::default();
    if let Some(base_url) = case["base_url"].as_str() {
        options.base_url = Some(base_url.to_string());
    }
    if let Some(given) = case.get("options") {
        options.model = given["model"].as_str().map(str::to_string);
        options.temperature = given["temperature"].as_f64();
        options.max_tokens = given["max_tokens"].as_u64();
    }
    OpenConfig::resolve(options, &key_env()).unwrap()
}

#[test]
fn request_bodies_are_byte_identical_to_the_sdk() {
    let golden = golden();
    let cases = golden["requests"].as_array().unwrap();
    assert!(cases.len() >= 23);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let expected = &case["request"];
        let request = build_request(&config_for(case), &corpus_prompt(case["prompt"].as_str().unwrap()));
        assert_eq!(request.method, expected["method"].as_str().unwrap(), "{id}: method");
        assert_eq!(request.url, expected["url"].as_str().unwrap(), "{id}: url");
        assert_eq!(request.body.len() as u64, expected["body_len"].as_u64().unwrap(), "{id}: length");
        assert_eq!(sha256_hex(&request.body), expected["body_sha256"].as_str().unwrap(), "{id}: sha256");
        if let Some(body) = expected["body"].as_str() {
            assert_eq!(request.body, body.as_bytes(), "{id}: body bytes");
        }
    }
}

#[test]
fn protocol_headers_match_and_transport_headers_are_the_clients_own() {
    let golden = golden();
    let mut transport = std::collections::BTreeSet::new();
    for case in golden["requests"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let expected = case["request"]["headers"].as_object().unwrap();
        let request = build_request(&config_for(case), &corpus_prompt(case["prompt"].as_str().unwrap()));
        for (name, value) in &request.headers {
            if *name == "authorization" {
                assert_eq!(expected["authorization"], "Bearer <redacted>", "{id}");
                assert_eq!(value, &format!("Bearer {PLACEHOLDER_KEY}"), "{id}");
            } else {
                assert_eq!(expected[*name].as_str(), Some(value.as_str()), "{id}: {name}");
            }
        }
        for name in expected.keys() {
            if !request.headers.iter().any(|(own, _)| own == name) {
                transport.insert(name.clone());
            }
        }
        assert_eq!(expected["content-length"].as_str().unwrap(), request.body.len().to_string(), "{id}");
    }
    // What Python's httpx adds on its own; reqwest manages the equivalents (host, content-length, connection).
    let transport: Vec<&str> = transport.iter().map(String::as_str).collect();
    assert_eq!(transport, ["accept-encoding", "connection", "content-length", "host"]);
}

#[test]
fn the_fixture_holds_no_credential_shaped_text() {
    let text = std::fs::read_to_string(manifest_dir().join("tests/fixtures/open_classifier_golden.json")).unwrap();
    assert!(!text.contains("AWS_SECRET"));
    assert!(!text.contains("Bearer P"));
    assert!(!text.contains("sk-"));
}

#[test]
fn the_body_stays_valid_json_for_awkward_text() {
    // The corpus holds the unicode prompt; control characters and quotes are covered by the prompt's unit tests. Here the
    // whole body must stay valid JSON that decodes back to the same user content.
    let config = OpenConfig::resolve(OpenOptions::default(), &key_env()).unwrap();
    let text = "tab\t quote\" backslash\\ nul\u{0} del\u{7f} line\u{2028}sep \u{1f600}";
    let body: Value = serde_json::from_slice(&request_body(&config, text)).unwrap();
    let user = body["messages"][1]["content"].as_str().unwrap();
    assert!(user.contains(&serde_json::to_string(text).unwrap()));
}

#[test]
fn configuration_resolution_matches_python() {
    let golden = golden();
    for case in golden["environments"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let pairs: Vec<(String, String)> = case["environment"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_string()))
            .collect();
        let outcome = &case["outcome"];
        let resolved = OpenConfig::resolve(OpenOptions::default(), &env_of(pairs));
        if outcome["status"] == "ok" {
            let config = resolved.unwrap_or_else(|error| panic!("{id}: {error}"));
            assert_eq!(config.model, outcome["model"].as_str().unwrap(), "{id}: model");
            assert_eq!(config.temperature, outcome["temperature"].as_f64().unwrap(), "{id}: temperature");
            assert_eq!(config.max_tokens, outcome["max_tokens"].as_u64().unwrap(), "{id}: max_tokens");
            assert_eq!(config.base_url(), outcome["base_url"].as_str().unwrap(), "{id}: base_url");
            assert_eq!(config.timeout.as_secs_f64(), outcome["timeout"].as_f64().unwrap(), "{id}: timeout");
            assert_eq!(config.max_retries, 2, "{id}: the SDK retries twice");
        } else {
            let error = resolved.err().unwrap_or_else(|| panic!("{id}: expected an error"));
            assert_eq!(error.to_string(), outcome["message"].as_str().unwrap(), "{id}");
        }
    }
}

#[test]
fn without_the_environment_nothing_is_read() {
    let env = env_of(vec![("OPENAI_API_KEY".into(), "PLACEHOLDER".into()), ("OPENAI_MODEL".into(), "other".into())]);
    let options = OpenOptions { use_environment: false, ..OpenOptions::default() };
    assert_eq!(
        OpenConfig::resolve(options, &env).err().unwrap().to_string(),
        "OpenAI API key is not configured. Set OPENAI_API_KEY or provide openai.api_key via /config/llm."
    );
    let options = OpenOptions {
        use_environment: false,
        api_key: Some("PLACEHOLDER".into()),
        model: Some("explicit".into()),
        ..OpenOptions::default()
    };
    let config = OpenConfig::resolve(options, &env).unwrap();
    assert_eq!((config.model.as_str(), config.temperature, config.max_tokens), ("explicit", 0.25, 512));
    assert_eq!(config.base_url(), "https://api.openai.com/v1/");
}

#[test]
fn the_dependency_graph_has_no_openssl() {
    let lock = std::fs::read_to_string(manifest_dir().join("../../Cargo.lock")).unwrap();
    for forbidden in ["openssl", "openssl-sys", "native-tls"] {
        assert!(!lock.contains(&format!("name = \"{forbidden}\"")), "{forbidden} is in the lock file");
    }
    assert!(lock.contains("name = \"rustls\""));
}
