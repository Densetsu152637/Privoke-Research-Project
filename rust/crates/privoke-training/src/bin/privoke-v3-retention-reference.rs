//! The generator of the V3 retention reference releases (stage V3-R9).
//!
//! ```text
//! privoke-v3-retention-reference build  --tier <tier> --release <standard-release-dir> --bank <approved-train-bank.json> --out <dir>
//! privoke-v3-retention-reference verify --tier <tier> --release <standard-release-dir> --bank <approved-train-bank.json> --references <dir>
//! ```
//!
//! `build` freezes the pinned standard release of a tier (the routine root; never the untrained `initials/`) into the two files
//! of a reference release, `<out>/references.json` and `<out>/manifest.json`, and prints their digests as one JSON line. `verify`
//! rebuilds the release from the same inputs and requires it to equal the files in `--references` byte for byte and the
//! manifest to hash to the compiled pin (`RELEASE_PINS`), so the pins are reproducible from the standard release and the bank.
//! The bank holds prompt text: it is read from the path given, hash-checked against the approved pin, and never copied.
//!
//! The runs are LLM-only (the semantic model alone, never a detector layer).

use std::path::PathBuf;
use std::process::ExitCode;

use privoke_contracts::digest::sha256_hex;
use privoke_training::retention_v3::{BuiltRelease, build_production_release, production_spec};

struct Arguments {
    command: String,
    tier: String,
    release: PathBuf,
    bank: PathBuf,
    directory: PathBuf,
}

fn parse(arguments: &[String]) -> Result<Arguments, String> {
    let command = arguments.first().cloned().ok_or("a command (build or verify) is required")?;
    let mut tier = None;
    let mut release = None;
    let mut bank = None;
    let mut directory = None;
    let mut rest = arguments[1..].iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match (flag.as_str(), command.as_str()) {
            ("--tier", _) => tier = Some(value.clone()),
            ("--release", _) => release = Some(PathBuf::from(value)),
            ("--bank", _) => bank = Some(PathBuf::from(value)),
            ("--out", "build") | ("--references", "verify") => directory = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    if !["build", "verify"].contains(&command.as_str()) {
        return Err(format!("unknown command {command}"));
    }
    Ok(Arguments {
        command,
        tier: tier.ok_or("--tier is required")?,
        release: release.ok_or("--release is required")?,
        bank: bank.ok_or("--bank is required")?,
        directory: directory.ok_or("--out (build) or --references (verify) is required")?,
    })
}

fn build(arguments: &Arguments) -> Result<BuiltRelease, String> {
    let bank = std::fs::read(&arguments.bank).map_err(|error| format!("{}: {error}", arguments.bank.display()))?;
    let mut done = 0usize;
    let built = build_production_release(&arguments.tier, &arguments.release, &bank, &mut |_row| {
        done += 1;
        if done.is_multiple_of(50) {
            eprintln!("{} rows", done);
        }
    })
    .map_err(|error| error.to_string())?;
    Ok(built)
}

fn summary(tier: &str, built: &BuiltRelease) -> String {
    let eligible = built.rows.iter().filter(|row| row.eligible).count();
    format!(
        "{{\"tier\":\"{tier}\",\"manifest_sha256\":\"{}\",\"references_sha256\":\"{}\",\"rows\":{},\"eligible\":{eligible}}}",
        built.manifest_sha256(),
        built.references_sha256(),
        built.rows.len()
    )
}

fn run(arguments: &Arguments) -> Result<(), String> {
    let spec = production_spec(&arguments.tier).ok_or("the tier must be efficient, balanced or quality")?;
    let built = build(arguments)?;
    match arguments.command.as_str() {
        "build" => {
            std::fs::create_dir_all(&arguments.directory).map_err(|error| error.to_string())?;
            std::fs::write(arguments.directory.join("references.json"), built.references.as_bytes()).map_err(|error| error.to_string())?;
            std::fs::write(arguments.directory.join("manifest.json"), built.manifest.as_bytes()).map_err(|error| error.to_string())?;
            println!("{}", summary(&arguments.tier, &built));
            Ok(())
        }
        _ => {
            let read = |name: &str| std::fs::read(arguments.directory.join(name)).map_err(|error| format!("{name}: {error}"));
            let (references, manifest) = (read("references.json")?, read("manifest.json")?);
            if references != built.references.as_bytes() || manifest != built.manifest.as_bytes() {
                return Err("the files are not what the standard release and the bank build".to_string());
            }
            if sha256_hex(&manifest) != spec.manifest_sha256 {
                return Err(format!("the manifest hashes to {}, not to the compiled pin {}", sha256_hex(&manifest), spec.manifest_sha256));
            }
            println!("{}", summary(&arguments.tier, &built));
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match parse(&arguments).and_then(|parsed| run(&parsed)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("privoke-v3-retention-reference: {message}");
            ExitCode::FAILURE
        }
    }
}
