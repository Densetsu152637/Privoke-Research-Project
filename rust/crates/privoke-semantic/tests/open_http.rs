//! The external classifier over a real `reqwest` exchange with an in-process loopback server (stage 16). No live API is
//! called: the server is a thread in this test binary and the key is the literal `PLACEHOLDER`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod open_support;

use std::net::TcpListener;
use std::time::Duration;

use open_support::{MockServer, PLACEHOLDER_KEY, Reply, corpus_prompt, golden};
use privoke_semantic::open_classifier::build_request;
use privoke_semantic::{LayerOutcome, OpenClassifier, OpenConfig, OpenOptions, analyse_semantic_layer};

const NO_RISK: &str = r#"{"choices": [{"message": {"content": "{\"results\": []}"}}]}"#;

fn classifier(base_url: String, edit: impl FnOnce(&mut OpenConfig)) -> OpenClassifier {
    let options = OpenOptions {
        api_key: Some(PLACEHOLDER_KEY.to_string()),
        base_url: Some(base_url),
        use_environment: false,
        model: Some("test-model".to_string()),
        ..OpenOptions::default()
    };
    let mut config = OpenConfig::resolve(options, &|_| None).unwrap();
    config.retry_base_delay = Duration::ZERO;
    edit(&mut config);
    OpenClassifier::new(config).unwrap()
}

fn completion(content: &str) -> String {
    serde_json::json!({"choices": [{"message": {"content": content}}]}).to_string()
}

#[test]
fn the_wire_request_is_the_golden_request() {
    let golden = golden();
    let server = MockServer::start(vec![Reply::json(200, NO_RISK)]);
    for case in golden["requests"].as_array().unwrap().iter().filter(|case| case["config"] == "default") {
        let id = case["id"].as_str().unwrap();
        let prompt = case["prompt"].as_str().unwrap();
        let text = corpus_prompt(prompt);
        // The golden used the default model, so the loopback client takes the same configuration but for the base URL.
        let options =
            OpenOptions { api_key: Some(PLACEHOLDER_KEY.to_string()), base_url: Some(server.base_url()), ..OpenOptions::default() };
        let mut config = OpenConfig::resolve(options, &|_| None).unwrap();
        config.retry_base_delay = Duration::ZERO;
        let before = server.recorded().len();
        let found = OpenClassifier::new(config).unwrap().classify_detailed(&text).unwrap();
        assert!(found.is_empty(), "{id}");
        let seen = &server.recorded()[before];
        assert_eq!(seen.method, "POST", "{id}");
        assert_eq!(seen.path, "/v1/chat/completions", "{id}");
        assert_eq!(seen.header("authorization"), Some("Bearer PLACEHOLDER"), "{id}");
        assert_eq!(seen.header("content-type"), Some("application/json"), "{id}");
        assert_eq!(seen.header("accept"), Some("application/json"), "{id}");
        assert_eq!(seen.header("content-length"), Some(case["request"]["body_len"].to_string().as_str()), "{id}");
        assert_eq!(privoke_contracts::digest::sha256_hex(&seen.body), case["request"]["body_sha256"].as_str().unwrap(), "{id}: wire body");
        if let Some(body) = case["request"]["body"].as_str() {
            assert_eq!(seen.body, body.as_bytes(), "{id}: wire body bytes");
        }
    }
}

#[test]
fn the_built_request_is_what_goes_on_the_wire() {
    let server = MockServer::start(vec![Reply::json(200, NO_RISK)]);
    let client = classifier(server.base_url(), |_| {});
    let text = corpus_prompt("unicode");
    client.classify_detailed(&text).unwrap();
    let built = build_request(client.config(), &text);
    assert_eq!(server.recorded()[0].body, built.body);
}

#[test]
fn findings_become_layer_hits_with_spans_in_the_original_prompt() {
    let prompt = corpus_prompt("health");
    // The layer sends the lower-cased canonical text, so the span is in its characters (ASCII here).
    let start = prompt.to_lowercase().find("metformin").unwrap();
    let content = format!(
        r#"{{"results": [{{"sensitivity": "S2", "visibility": "PU", "categories": ["HEALTH"], "section_of_text": "metformin", "reasoning": "r", "confidence": 0.8, "span": [{start}, {}]}}]}}"#,
        start + 9
    );
    let server = MockServer::start(vec![Reply::json(200, &completion(&content))]);
    let client = classifier(server.base_url(), |_| {});
    match analyse_semantic_layer(&client, &prompt) {
        LayerOutcome::Ok(hits) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].text, "metformin");
            assert_eq!(hits[0].span, Some((start, start + 9)));
            assert_eq!(hits[0].confidence, 0.8);
        }
        LayerOutcome::Error(error) => panic!("{error}"),
    }
}

#[test]
fn a_malformed_answer_is_the_layer_error_with_the_python_text() {
    let server = MockServer::start(vec![Reply::json(200, &completion("not json"))]);
    let client = classifier(server.base_url(), |_| {});
    assert_eq!(analyse_semantic_layer(&client, "hello"), LayerOutcome::Error("Semantic classifier returned invalid JSON.".to_string()));
}

#[test]
fn retryable_statuses_are_retried_and_the_others_are_not() {
    // 500 then success.
    let server = MockServer::start(vec![Reply::json(500, "{}"), Reply::json(200, NO_RISK)]);
    let client = classifier(server.base_url(), |_| {});
    assert!(client.classify_detailed("hello").unwrap().is_empty());
    assert_eq!(server.recorded().len(), 2);

    // 429 forever: the first request and two retries, then the status error.
    let server = MockServer::start(vec![Reply::Respond {
        status: 429,
        headers: vec![("retry-after".into(), "0".into())],
        body: b"{\"error\": {\"message\": \"detail\"}}".to_vec(),
    }]);
    let client = classifier(server.base_url(), |_| {});
    let error = client.classify_detailed("hello").err().unwrap();
    assert_eq!(error.to_string(), "Error code: 429");
    assert_eq!(server.recorded().len(), 3);

    // 401 is final at once, and the body is never echoed.
    let server = MockServer::start(vec![Reply::json(401, "{\"error\": {\"message\": \"leaky detail\"}}")]);
    let client = classifier(server.base_url(), |_| {});
    let error = client.classify_detailed("hello").err().unwrap();
    assert_eq!(error.to_string(), "Error code: 401");
    assert_eq!(server.recorded().len(), 1);

    // Retries can be turned off.
    let server = MockServer::start(vec![Reply::json(500, "{}")]);
    let client = classifier(server.base_url(), |config| config.max_retries = 0);
    assert_eq!(client.classify_detailed("hello").err().unwrap().to_string(), "Error code: 500");
    assert_eq!(server.recorded().len(), 1);
}

#[test]
fn a_silent_server_is_a_timeout() {
    let server = MockServer::start(vec![Reply::Hang]);
    let client = classifier(server.base_url(), |config| {
        config.timeout = Duration::from_millis(300);
        config.max_retries = 0;
    });
    assert_eq!(client.classify_detailed("hello").err().unwrap().to_string(), "Request timed out.");
}

#[test]
fn a_closed_port_is_a_connection_error() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let client = classifier(format!("http://127.0.0.1:{port}/v1"), |config| config.max_retries = 0);
    assert_eq!(client.classify_detailed("hello").err().unwrap().to_string(), "Connection error.");
}

#[test]
fn recorded_http_answers_over_the_wire_match_the_golden_outcome() {
    let golden = golden();
    for case in golden["responses"].as_array().unwrap().iter().filter(|case| {
        // Retried statuses repeat the same answer; the parse of every case is covered by `open_response`.
        case["status"] == 200
            && [
                "results_one",
                "results_empty_envelope",
                "span_valid",
                "content_invalid_json",
                "no_choices",
                "http_200_html",
                "bare_empty_list",
                "confidence_over_one",
            ]
            .contains(&case["id"].as_str().unwrap())
    }) {
        let id = case["id"].as_str().unwrap();
        let server = MockServer::start(vec![Reply::json(200, case["http_body"].as_str().unwrap())]);
        let client = classifier(server.base_url(), |config| config.max_retries = 0);
        let outcome = client.classify_detailed(case["text"].as_str().unwrap());
        let python = &case["python"];
        assert_eq!(outcome.is_ok(), python["status"] == "ok", "{id}");
        if let (Ok(results), Some(expected)) = (&outcome, python["results"].as_array()) {
            assert_eq!(results.len(), expected.len(), "{id}");
        }
    }
}
