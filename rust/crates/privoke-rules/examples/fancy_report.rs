//! Lists the rules that need `fancy-regex`, with the reason, and the rules with a `$` fallback.
//!
//! ```text
//! cargo run -p privoke-rules --example fancy_report
//! ```

use privoke_rules::{Detector, RuleSetOptions};

fn main() {
    let detector = match Detector::new(RuleSetOptions::default()) {
        Ok(detector) => detector,
        Err(error) => {
            eprintln!("detector: {error}");
            std::process::exit(1);
        }
    };
    let total = detector.rules().len();
    let report = detector.fancy_report();
    println!("{} of {total} rules need fancy-regex; the other {} run on the regex crate.", report.len(), total - report.len());
    for (name, reasons) in &report {
        let labels: Vec<&str> = reasons.iter().map(|reason| reason.label()).collect();
        println!("{name}: {}", labels.join(", "));
    }
    let dollar: Vec<&str> =
        detector.rules().iter().filter(|rule| rule.regex.has_dollar_fallback()).map(|rule| rule.definition.name.as_str()).collect();
    println!("\n{} rules use `$` and keep an exact fancy-regex variant for text that ends with a newline.", dollar.len());
}
