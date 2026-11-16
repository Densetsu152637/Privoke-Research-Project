//! Environment and file locations: the `.env` loader, the model cache and the credential directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A complete environment, as a map. The process environment is read once and passed around, so tests never touch
/// the real one.
pub type Environment = BTreeMap<String, String>;

/// The variables whose relative paths the client runtime resolves against the `.env` directory.
const FILE_VARIABLES: [&str; 5] = [
    "PRIVOKE_TLS_CA_FILE",
    "PRIVOKE_TLS_CERT_FILE",
    "PRIVOKE_TLS_KEY_FILE",
    "PRIVOKE_TELEMETRY_TLS_CERT_FILE",
    "PRIVOKE_TELEMETRY_TLS_KEY_FILE",
];

/// The process environment.
pub fn process_environment() -> Environment {
    std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?))).collect()
}

/// `load_runtime_environment`: read `PRIVOKE_ENV_FILE` (default `<client runtime>/.env`) without overriding what is
/// already set, then make the file variables absolute against the `.env` directory. A missing file is not an error.
pub fn load_runtime_environment(client_runtime_root: &Path, environment: &mut Environment) {
    let env_path = environment.get("PRIVOKE_ENV_FILE").map_or_else(|| client_runtime_root.join(".env"), PathBuf::from);
    if let Ok(text) = std::fs::read_to_string(&env_path) {
        for (name, value) in parse_dotenv(&text) {
            environment.entry(name).or_insert(value);
        }
    }
    let base = env_path.parent().map(Path::to_path_buf).unwrap_or_default();
    for name in FILE_VARIABLES {
        if let Some(value) = environment.get(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
            && !Path::new(&value).is_absolute()
        {
            environment.insert(name.to_string(), base.join(value).to_string_lossy().into_owned());
        }
    }
}

/// The `KEY=VALUE` subset of dotenv the runtime's `.env` uses: comments, `export`, single and double quotes, no
/// interpolation.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((name, value)) = line.split_once('=') else { continue };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value = value.trim();
        let value = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].find(quote).map_or_else(|| value[1..].to_string(), |end| value[1..=end].to_string()),
            _ => value.split(" #").next().unwrap_or_default().trim().to_string(),
        };
        pairs.push((name.to_string(), value));
    }
    pairs
}

/// A positive integer variable, or its default.
pub fn positive_int(environment: &Environment, name: &str, default: u64) -> Result<u64, String> {
    let value = match environment.get(name) {
        None => default,
        Some(raw) => raw.trim().parse::<u64>().map_err(|_| format!("{name} must be an integer."))?,
    };
    if value == 0 { Err(format!("{name} must be greater than zero.")) } else { Ok(value) }
}

/// A positive, finite number of seconds, or its default.
pub fn positive_seconds(environment: &Environment, name: &str, default: f64) -> Result<Duration, String> {
    let value = match environment.get(name) {
        None => default,
        Some(raw) => raw.trim().parse::<f64>().map_err(|_| format!("{name} must be a number."))?,
    };
    if value.is_finite() && value > 0.0 {
        Duration::try_from_secs_f64(value).map_err(|error| error.to_string())
    } else {
        Err(format!("{name} must be greater than zero."))
    }
}

/// A boolean variable with Python's accepted words.
pub fn boolean(environment: &Environment, name: &str, default: bool) -> Result<bool, String> {
    match environment.get(name).map(|v| v.trim().to_ascii_lowercase()) {
        None => Ok(default),
        Some(value) => match value.as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(format!("{name} must be a boolean value.")),
        },
    }
}

/// The per-user model cache: `MODEL_PACKAGE_CACHE_DIR`, else `%LOCALAPPDATA%\PriVoke\model-packages` on Windows,
/// else `$XDG_CACHE_HOME` or `~/.cache` plus `privoke/model-packages`. The same rule as the Python runtime, so both
/// share one cache.
pub fn cache_root(environment: &Environment) -> PathBuf {
    if let Some(configured) = environment.get("MODEL_PACKAGE_CACHE_DIR").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return std::path::absolute(configured).unwrap_or_else(|_| PathBuf::from(configured));
    }
    if cfg!(windows)
        && let Some(local) = environment.get("LOCALAPPDATA").filter(|v| !v.is_empty())
    {
        return Path::new(local).join("PriVoke").join("model-packages");
    }
    let base =
        environment.get("XDG_CACHE_HOME").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| home(environment).join(".cache"));
    base.join("privoke").join("model-packages")
}

/// The credential directory: `PRIVOKE_CREDENTIAL_DIR`, else `%LOCALAPPDATA%\PriVoke\credentials`, else
/// `$XDG_DATA_HOME` or `~/.local/share` plus `privoke/credentials`.
pub fn credential_dir(environment: &Environment) -> PathBuf {
    if let Some(configured) = environment.get("PRIVOKE_CREDENTIAL_DIR").map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return PathBuf::from(configured);
    }
    if cfg!(windows)
        && let Some(local) = environment.get("LOCALAPPDATA").filter(|v| !v.is_empty())
    {
        return Path::new(local).join("PriVoke").join("credentials");
    }
    let base = environment
        .get("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home(environment).join(".local").join("share"));
    base.join("privoke").join("credentials")
}

fn home(environment: &Environment) -> PathBuf {
    environment.get("HOME").or_else(|| environment.get("USERPROFILE")).map(PathBuf::from).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_subset() {
        let parsed = parse_dotenv("# c\nA=1\nexport B = two # note\nC=\"x # y\"\nD='q'\n\nE=\n");
        assert_eq!(
            parsed,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "two".into()),
                ("C".into(), "x # y".into()),
                ("D".into(), "q".into()),
                ("E".into(), String::new())
            ]
        );
    }

    #[test]
    fn existing_environment_wins_and_files_resolve_to_the_env_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "PRIVOKE_TLS_CERT_FILE=secrets/client.crt\nPRIVOKE_USE_LOCAL_STACK=true\nPRIVOKE_TLS_KEY_FILE=secrets/client.key\n",
        )
        .unwrap();
        let mut environment = Environment::new();
        environment.insert("PRIVOKE_USE_LOCAL_STACK".into(), "false".into());
        load_runtime_environment(dir.path(), &mut environment);
        assert_eq!(environment["PRIVOKE_USE_LOCAL_STACK"], "false");
        assert_eq!(Path::new(&environment["PRIVOKE_TLS_CERT_FILE"]), dir.path().join("secrets/client.crt"));
    }

    #[test]
    fn numeric_variables_reject_zero_and_text() {
        let mut environment = Environment::new();
        assert_eq!(positive_int(&environment, "X", 7), Ok(7));
        environment.insert("X".into(), "0".into());
        assert!(positive_int(&environment, "X", 7).is_err());
        environment.insert("X".into(), "abc".into());
        assert!(positive_int(&environment, "X", 7).is_err());
        environment.insert("Y".into(), "-1".into());
        assert!(positive_seconds(&environment, "Y", 1.0).is_err());
        environment.insert("Y".into(), "NaN".into());
        assert!(positive_seconds(&environment, "Y", 1.0).is_err());
        environment.insert("Z".into(), "maybe".into());
        assert!(boolean(&environment, "Z", true).is_err());
    }
}
