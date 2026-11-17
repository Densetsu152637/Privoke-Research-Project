//! `prompt_generation.vocabulary` and `prompt_generation.templates`: the placeholder vocabulary and its seeded rendering.

use std::collections::BTreeMap;

use crate::error::Result;
use crate::pyrandom::Random;
use crate::text::format_named;

/// Names.
pub const NAMES: [&str; 5] = ["John Doe", "Alex Smith", "Priya Patel", "Sam Nguyen", "Jordan Lee"];
/// Relatives.
pub const RELATIVES: [&str; 6] = ["wife", "husband", "partner", "coworker", "manager", "child"];
/// Conditions.
pub const CONDITIONS: [&str; 5] = ["anxiety", "depression", "diabetes", "cancer", "ptsd"];
/// Medications.
pub const MEDICATIONS: [&str; 4] = ["insulin", "sertraline", "opioid medication", "adhd medication"];
/// Employers.
pub const EMPLOYERS: [&str; 4] = ["Acme Robotics", "Northside Clinic", "Metro Bank", "City University"];
/// Cities.
pub const CITIES: [&str; 5] = ["Sydney", "Melbourne", "Brisbane", "Newcastle", "Canberra"];
/// Banks.
pub const BANKS: [&str; 3] = ["Metro Bank", "North Credit Union", "Riverline Finance"];
/// Amounts.
pub const AMOUNTS: [&str; 4] = ["$480", "$2,300", "$7,800", "$18,000"];
/// Groups.
pub const GROUPS: [&str; 4] = ["private channel", "group chat", "members only forum", "locked account"];
/// Public places.
pub const PUBLIC_PLACES: [&str; 4] = ["public post", "public profile", "conference bio", "news article"];
/// Accounts.
pub const ACCOUNTS: [&str; 4] = ["bank account", "loan application", "tax return", "credit score"];

/// `render_template(template, rng)`: eleven `rng.choice` draws in the fixed field order, then `str.format`.
pub fn render_template(template: &str, rng: &mut Random) -> Result<String> {
    let fields: [(&str, &[&str]); 11] = [
        ("name", &NAMES),
        ("relative", &RELATIVES),
        ("condition", &CONDITIONS),
        ("medication", &MEDICATIONS),
        ("employer", &EMPLOYERS),
        ("city", &CITIES),
        ("bank", &BANKS),
        ("amount", &AMOUNTS),
        ("group", &GROUPS),
        ("public_place", &PUBLIC_PLACES),
        ("account", &ACCOUNTS),
    ];
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, choices) in fields {
        let chosen = rng.choice(choices)?;
        values.insert(name, chosen);
    }
    format_named(template, &values)
}
