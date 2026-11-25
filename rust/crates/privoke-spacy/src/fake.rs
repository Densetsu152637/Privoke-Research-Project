//! A Python-free [`Engine`] for the in-process tests and the runtime host. It produces the same bytes as the fake
//! worker process (`privoke-spacy-fake-worker`), so the two backends can be compared without spaCy.
//!
//! Text triggers: `CRASH` aborts the process from the interpreter thread (a stand-in for an interpreter crash), `HANG`
//! never answers, `SLEEP:<ms>` answers late, `ERR` answers with an error, `PANIC` panics the thread. Anything else is
//! split on spaces into tokens, and `Paris` is a `GPE` entity in the full selection.

use std::time::Duration;

use crate::inprocess::Engine;
use crate::protocol::{Selection, WorkerInfo};

/// The fake engine.
#[derive(Debug, Default)]
pub struct FakeEngine;

/// The ready announcement the fake engine's host sends.
pub fn fake_info() -> WorkerInfo {
    WorkerInfo {
        kind: "ready".to_string(),
        protocol: Some(1),
        spacy: Some("fake".to_string()),
        model: Some("fake".to_string()),
        model_version: Some("0".to_string()),
        ..WorkerInfo::default()
    }
}

fn analysis(text: &str, full: bool) -> serde_json::Value {
    let mut tokens = Vec::new();
    let mut ents = Vec::new();
    let mut offset = 0usize;
    for (i, word) in text.split(' ').enumerate() {
        let len = word.chars().count();
        if !word.is_empty() {
            let lower = word.to_lowercase();
            tokens.push(serde_json::json!([word, offset, " ", true, lower, "NN", "NOUN", lower, "dep", i]));
            if full && word == "Paris" {
                ents.push(serde_json::json!([offset, offset + len, "GPE"]));
            }
        }
        offset += len + 1;
    }
    serde_json::json!({ "tokens": tokens, "ents": ents })
}

impl Engine for FakeEngine {
    fn analyze(&mut self, selection: Selection, text: &str) -> Result<String, String> {
        match text {
            "CRASH" => std::process::abort(),
            "HANG" => loop {
                std::thread::sleep(Duration::from_secs(3600));
            },
            "ERR" => return Err("boom".to_string()),
            "PANIC" => panic!("the fake interpreter panicked"),
            _ => {}
        }
        if let Some(ms) = text.strip_prefix("SLEEP:").and_then(|v| v.parse().ok()) {
            std::thread::sleep(Duration::from_millis(ms));
        }
        Ok(analysis(text, selection == Selection::Full).to_string())
    }

    fn lemma_index(&mut self) -> Result<String, String> {
        Ok(r#"["alpha","beta"]"#.to_string())
    }

    #[cfg(feature = "test-hooks")]
    fn crash(&mut self) -> Result<String, String> {
        std::process::abort()
    }

    #[cfg(feature = "test-hooks")]
    fn test_print(&mut self) -> Result<String, String> {
        eprintln!("PRIVOKE-TEST-PRINT fake engine");
        Ok("null".to_string())
    }
}
