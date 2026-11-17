//! `prompt_generation.defaults`: the built-in challenge seeds and the bootstrap calibration examples.

use std::collections::BTreeMap;

use crate::classification::initialise_unpacked;
use crate::error::Result;
use crate::prompt_seed::PromptSeed;

fn seed(template: &str, sensitivity: &str, visibility: &str, categories: &[&str], dataset: &str) -> Result<PromptSeed> {
    let mut metadata = BTreeMap::new();
    metadata.insert("dataset".to_string(), dataset.to_string());
    Ok(PromptSeed { template: template.to_string(), classification: initialise_unpacked(sensitivity, visibility, categories)?, metadata })
}

/// `default_prompt_dataset()`.
pub fn default_prompt_dataset() -> Result<Vec<PromptSeed>> {
    let mut seeds = vec![
        seed("My {account} at {bank} is behind login and shows a balance of {amount}.", "S2", "P2", &["FINANCIAL"], "default_financial")?,
        seed(
            "In a {group}, {name} said their {relative} was diagnosed with {condition}.",
            "S3",
            "P3",
            &["HEALTH", "THIRD_PARTY"],
            "default_health_third_party",
        )?,
        seed("My doctor prescribed {medication} after my {condition} diagnosis.", "S3", "PU", &["HEALTH"], "default_health")?,
        seed(
            "I work at {employer} and I am the only person in my role in {city}.",
            "S2",
            "PU",
            &["IDENTITY", "LOCATION"],
            "default_identity_location",
        )?,
        seed("This is a {public_place} about a product launch in {city}.", "S0", "P0", &[], "default_public")?,
        seed(
            "My private diary says I voted for a political party and left my religion.",
            "S3",
            "P4",
            &["POLITICS", "RELIGION"],
            "default_beliefs",
        )?,
        seed("My {relative} has a court date after a dui charge.", "S3", "PU", &["CRIMINAL", "THIRD_PARTY"], "default_criminal")?,
        seed("The document says my home address is near my office in {city}.", "S2", "PU", &["LOCATION", "IDENTITY"], "default_location")?,
    ];
    // Independently labeled calibration examples also used by bootstrap training.
    let calibration: [(&str, &str, &str, &[&str]); 16] = [
        ("this was posted publicly for everyone", "S0", "P0", &[]),
        ("discussion in a public community forum", "S0", "P1", &[]),
        ("the page is restricted behind login", "S0", "P2", &[]),
        ("I sent this in a private group chat", "S0", "P3", &[]),
        ("this is a private diary for my eyes only", "S0", "P4", &[]),
        ("explain privacy using imaginary placeholders", "S0", "PU", &[]),
        ("write a friendly email about tomorrow's meeting", "S0", "PU", &[]),
        ("summarise this public product documentation", "S0", "P0", &[]),
        ("what is the weather forecast", "S0", "PU", &[]),
        ("help me format a generic travel checklist", "S0", "PU", &[]),
        ("my diagnosis is cancer", "S3", "PU", &["HEALTH"]),
        ("my therapist prescribed medication", "S3", "PU", &["HEALTH"]),
        ("I am pregnant and have anxiety", "S3", "PU", &["HEALTH"]),
        ("my bank account and mortgage debt", "S2", "PU", &["FINANCIAL"]),
        ("my salary and credit score", "S2", "PU", &["FINANCIAL"]),
        ("I filed a tax return", "S2", "PU", &["FINANCIAL"]),
    ];
    for (text, sensitivity, visibility, categories) in calibration {
        seeds.push(seed(text, sensitivity, visibility, categories, "bootstrap_calibration")?);
    }
    Ok(seeds)
}
