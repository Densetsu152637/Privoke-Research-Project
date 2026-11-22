//! `config.py`: validated configuration of the fuzzer service, read from the environment.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use privoke_curriculum::audience;
use privoke_curriculum::types::BatchTrainingConfig;
use privoke_transport::ClientTlsConfig;

use crate::error::{Error, Result, invalid};
use crate::validate::validate_text;

/// The two training scopes of a cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Heads only (`training_scope="heads"`).
    Heads,
    /// The full Tiny encoder (`training_scope="full_encoder"`).
    FullEncoder,
}

impl Scope {
    /// The scope's name in the evidence and in the response metadata.
    pub fn name(self) -> &'static str {
        match self {
            Self::Heads => "heads",
            Self::FullEncoder => "full_encoder",
        }
    }
}

/// `FuzzerConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct FuzzerConfig {
    /// `param_update_target`.
    pub param_update_target: String,
    /// `privoke_runtime_target`.
    pub privoke_runtime_target: String,
    /// `model_id`.
    pub model_id: String,
    /// `presence_model_id`.
    pub presence_model_id: String,
    /// `fuzzer_id`.
    pub fuzzer_id: String,
    /// `port`.
    pub port: u16,
    /// `timeout_seconds`.
    pub timeout_seconds: f64,
    /// `seed`.
    pub seed: u64,
    /// `max_prompt_count`.
    pub max_prompt_count: i64,
    /// `max_concurrent_cycles`.
    pub max_concurrent_cycles: usize,
    /// `prompt_dataset_path`.
    pub prompt_dataset_path: Option<PathBuf>,
    /// `presence_dataset_path`.
    pub presence_dataset_path: Option<PathBuf>,
    /// `training_learning_rate`.
    pub training_learning_rate: f64,
    /// `training_max_gradient`.
    pub training_max_gradient: f64,
    /// `training_transformations_per_example`.
    pub training_transformations_per_example: i64,
    /// `minimum_exact_match_rate`.
    pub minimum_exact_match_rate: f64,
    /// `heldout_prompt_count`.
    pub heldout_prompt_count: i64,
    /// `curriculum_manifest_path`.
    pub curriculum_manifest_path: Option<PathBuf>,
    /// `curriculum_state_path`.
    pub curriculum_state_path: Option<PathBuf>,
    /// `curriculum_replay_fraction`.
    pub curriculum_replay_fraction: f64,
    /// `training_replay_weight`.
    pub training_replay_weight: f64,
    /// `underlying_training_learning_rate`.
    pub underlying_training_learning_rate: Option<f64>,
    /// `contextual_sampling_strategy`.
    pub contextual_sampling_strategy: String,
    /// `audience_manifest_path`.
    pub audience_manifest_path: Option<PathBuf>,
    /// `audience_manifest_sha256`.
    pub audience_manifest_sha256: Option<String>,
    /// `rehearsal_manifest_path` (`FUZZ_REHEARSAL_MANIFEST_PATH`).
    pub rehearsal_manifest_path: Option<PathBuf>,
    /// `benign_pool_path` (`FUZZ_BENIGN_POOL_PATH`).
    pub benign_pool_path: Option<PathBuf>,
    /// `benign_manifest_path` (`FUZZ_BENIGN_MANIFEST_PATH`).
    pub benign_manifest_path: Option<PathBuf>,
    /// `benign_exclusion_proof_path` (`FUZZ_BENIGN_EXCLUSION_PROOF_PATH`).
    pub benign_exclusion_proof_path: Option<PathBuf>,
    /// `retention_bank_path` (`FUZZ_RETENTION_BANK_PATH`).
    pub retention_bank_path: Option<PathBuf>,
    /// `retention_reference_path` (`FUZZ_RETENTION_REFERENCE_PATH`).
    pub retention_reference_path: Option<PathBuf>,
    /// `retention_manifest_path` (`FUZZ_RETENTION_MANIFEST_PATH`).
    pub retention_manifest_path: Option<PathBuf>,
    /// `retention_teacher_path` (`FUZZ_RETENTION_TEACHER_PATH`).
    pub retention_teacher_path: Option<PathBuf>,
    /// `retention_manifest_sha256` (`FUZZ_RETENTION_MANIFEST_SHA256`): the server's trusted manifest pin.
    pub retention_manifest_sha256: Option<String>,
    /// `window_path` (`FUZZ_WINDOW_PATH`).
    pub window_path: Option<PathBuf>,
    /// `window_manifest_sha256` (`FUZZ_WINDOW_MANIFEST_SHA256`): the server's pin of the frozen window.
    pub window_manifest_sha256: Option<String>,
    /// `component_bank_path` (`FUZZ_COMPONENT_BANK_PATH`).
    pub component_bank_path: Option<PathBuf>,
    /// `component_reference_path` (`FUZZ_COMPONENT_REFERENCE_PATH`).
    pub component_reference_path: Option<PathBuf>,
    /// `component_manifest_path` (`FUZZ_COMPONENT_MANIFEST_PATH`).
    pub component_manifest_path: Option<PathBuf>,
    /// `component_teacher_path` (`FUZZ_COMPONENT_TEACHER_PATH`).
    pub component_teacher_path: Option<PathBuf>,
    /// `component_teacher_sha256` (`FUZZ_COMPONENT_TEACHER_SHA256`): the accepted raw-file pin of the ORIGINAL teacher.
    pub component_teacher_sha256: Option<String>,
    /// `component_manifest_sha256` (`FUZZ_COMPONENT_MANIFEST_SHA256`): the server's trusted component manifest pin.
    pub component_manifest_sha256: Option<String>,
    /// `PRIVOKE_FUZZER_DUMP_DIR`: the durable evidence directory.
    pub dump_dir: Option<PathBuf>,
    /// Where the listener binds (`FUZZER_BIND`).
    pub bind: IpAddr,
    /// The per-RPC deadline of the listener (`FUZZER_REQUEST_TIMEOUT_SECONDS`); a cycle runs inside one RPC.
    pub request_timeout: Duration,
}

/// `os.getenv(name)` as a value: unset and empty are both "absent", as in Python's truthiness tests.
fn present(get: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).filter(|value| !value.is_empty())
}

fn env_string(get: &impl Fn(&str) -> Option<String>, name: &str, default: &str, strip: bool) -> String {
    let value = get(name).unwrap_or_else(|| default.to_string());
    if strip { value.trim().to_string() } else { value }
}

fn env_int(get: &impl Fn(&str) -> Option<String>, name: &str, default: i64) -> Result<i64> {
    match get(name) {
        None => Ok(default),
        Some(raw) => raw.trim().parse::<i64>().map_err(|_| Error(format!("{name} must be an integer."))),
    }
}

fn env_float(get: &impl Fn(&str) -> Option<String>, name: &str, default: f64) -> Result<f64> {
    match get(name) {
        None => Ok(default),
        Some(raw) => raw.trim().parse::<f64>().map_err(|_| Error(format!("{name} must be a number."))),
    }
}

fn positive_int(name: &str, value: i64) -> Result<()> {
    if value <= 0 { invalid(format!("{name} must be positive.")) } else { Ok(()) }
}

fn positive_float(name: &str, value: f64) -> Result<()> {
    if !value.is_finite() || value <= 0.0 { invalid(format!("{name} must be finite and positive.")) } else { Ok(()) }
}

impl FuzzerConfig {
    /// `FuzzerConfig.from_env()` over any lookup, validated.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let legacy_inputs = present(&get, "FUZZ_PROMPT_DATASET_PATH").is_some() || present(&get, "FUZZ_CURRICULUM_MANIFEST_PATH").is_some();
        let default_strategy = if legacy_inputs { audience::LEGACY } else { audience::STRATEGY };
        let path = |name: &str| present(&get, name).map(PathBuf::from);
        let seed = env_int(&get, "FUZZ_SEED", 1337)?;
        let heldout = env_int(&get, "FUZZ_HELDOUT_PROMPT_COUNT", 16)?;
        let port = env_int(&get, "FUZZER_PORT", 50053)?;
        let concurrent = env_int(&get, "FUZZ_MAX_CONCURRENT_CYCLES", 1)?;
        let underlying = if get("FUZZ_UNDERLYING_TRAINING_LEARNING_RATE").is_some() {
            Some(env_float(&get, "FUZZ_UNDERLYING_TRAINING_LEARNING_RATE", 0.03)?)
        } else {
            None
        };
        let bind = env_string(&get, "FUZZER_BIND", "0.0.0.0", true);
        let timeout = env_float(&get, "FUZZER_REQUEST_TIMEOUT_SECONDS", 1800.0)?;
        let config = Self {
            param_update_target: env_string(&get, "PARAM_UPDATE_TARGET", "param-update-service:50052", true),
            privoke_runtime_target: env_string(&get, "PRIVOKE_RUNTIME_TARGET", "client-runtime:50054", true),
            model_id: env_string(&get, "MODEL_ID", "privoke-baseline", true),
            presence_model_id: env_string(&get, "PRESENCE_MODEL_ID", "privoke-presence-balanced", true),
            fuzzer_id: env_string(&get, "FUZZER_ID", "privoke-fuzzer", true),
            contextual_sampling_strategy: env_string(&get, "FUZZ_CONTEXTUAL_SAMPLING_STRATEGY", default_strategy, true),
            audience_manifest_path: path("FUZZ_AUDIENCE_MANIFEST_PATH"),
            audience_manifest_sha256: present(&get, "FUZZ_AUDIENCE_MANIFEST_SHA256"),
            rehearsal_manifest_path: path("FUZZ_REHEARSAL_MANIFEST_PATH"),
            benign_pool_path: path("FUZZ_BENIGN_POOL_PATH"),
            benign_manifest_path: path("FUZZ_BENIGN_MANIFEST_PATH"),
            benign_exclusion_proof_path: path("FUZZ_BENIGN_EXCLUSION_PROOF_PATH"),
            retention_bank_path: path("FUZZ_RETENTION_BANK_PATH"),
            retention_reference_path: path("FUZZ_RETENTION_REFERENCE_PATH"),
            retention_manifest_path: path("FUZZ_RETENTION_MANIFEST_PATH"),
            retention_teacher_path: path("FUZZ_RETENTION_TEACHER_PATH"),
            retention_manifest_sha256: present(&get, "FUZZ_RETENTION_MANIFEST_SHA256"),
            window_path: path("FUZZ_WINDOW_PATH"),
            window_manifest_sha256: present(&get, "FUZZ_WINDOW_MANIFEST_SHA256"),
            component_bank_path: path("FUZZ_COMPONENT_BANK_PATH"),
            component_reference_path: path("FUZZ_COMPONENT_REFERENCE_PATH"),
            component_manifest_path: path("FUZZ_COMPONENT_MANIFEST_PATH"),
            component_teacher_path: path("FUZZ_COMPONENT_TEACHER_PATH"),
            component_teacher_sha256: present(&get, "FUZZ_COMPONENT_TEACHER_SHA256"),
            component_manifest_sha256: present(&get, "FUZZ_COMPONENT_MANIFEST_SHA256"),
            port: u16::try_from(port).map_err(|_| Error("FUZZER_PORT must be between 1 and 65535.".to_string()))?,
            timeout_seconds: env_float(&get, "FUZZ_TIMEOUT_SECONDS", 10.0)?,
            seed: u64::try_from(seed).map_err(|_| Error("FUZZ_SEED must not be negative.".to_string()))?,
            max_prompt_count: env_int(&get, "FUZZ_MAX_PROMPT_COUNT", 256)?,
            max_concurrent_cycles: usize::try_from(concurrent).unwrap_or(0),
            prompt_dataset_path: path("FUZZ_PROMPT_DATASET_PATH"),
            presence_dataset_path: path("FUZZ_PRESENCE_DATASET_PATH"),
            training_learning_rate: env_float(&get, "FUZZ_TRAINING_LEARNING_RATE", 0.03)?,
            training_max_gradient: env_float(&get, "FUZZ_TRAINING_MAX_GRADIENT", 0.05)?,
            training_transformations_per_example: env_int(&get, "FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE", 1)?,
            minimum_exact_match_rate: env_float(&get, "FUZZ_MIN_EXACT_MATCH_RATE", 0.0)?,
            heldout_prompt_count: heldout,
            curriculum_manifest_path: path("FUZZ_CURRICULUM_MANIFEST_PATH"),
            curriculum_state_path: path("FUZZ_CURRICULUM_STATE_PATH"),
            curriculum_replay_fraction: env_float(&get, "FUZZ_CURRICULUM_REPLAY_FRACTION", 0.25)?,
            training_replay_weight: env_float(&get, "FUZZ_TRAINING_REPLAY_WEIGHT", 0.35)?,
            underlying_training_learning_rate: underlying,
            dump_dir: path("PRIVOKE_FUZZER_DUMP_DIR"),
            bind: bind.parse::<IpAddr>().map_err(|_| Error("FUZZER_BIND must be an IP address.".to_string()))?,
            request_timeout: Duration::try_from_secs_f64(timeout)
                .map_err(|_| Error("FUZZER_REQUEST_TIMEOUT_SECONDS must be finite and positive.".to_string()))?,
        };
        config.validated()
    }

    /// `FuzzerConfig.from_env()`.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// `validated()`: the cross-field checks, in the Python order and with its messages.
    pub fn validated(self) -> Result<Self> {
        if self.contextual_sampling_strategy != audience::STRATEGY && self.contextual_sampling_strategy != audience::LEGACY {
            return invalid("Unknown FUZZ_CONTEXTUAL_SAMPLING_STRATEGY.");
        }
        if self.audience_manifest_path.is_some() != self.audience_manifest_sha256.is_some() {
            return invalid("Custom audience manifest requires both path and SHA256 pin.");
        }
        if self.contextual_sampling_strategy == audience::STRATEGY {
            if self.prompt_dataset_path.is_some() || self.curriculum_manifest_path.is_some() {
                return invalid("Default audience mode cannot mix an explicit legacy dataset/curriculum.");
            }
            audience::validate_count(self.max_prompt_count, self.heldout_prompt_count)?;
        } else if self.audience_manifest_path.is_some() || self.audience_manifest_sha256.is_some() {
            return invalid("Audience pins require the audience sampling strategy.");
        }
        if !self.training_replay_weight.is_finite() || !(0.0 < self.training_replay_weight && self.training_replay_weight <= 1.0) {
            return invalid("FUZZ_TRAINING_REPLAY_WEIGHT must be finite and in (0, 1].");
        }
        if !self.curriculum_replay_fraction.is_finite() || !(0.0 < self.curriculum_replay_fraction && self.curriculum_replay_fraction < 1.0)
        {
            return invalid("FUZZ_CURRICULUM_REPLAY_FRACTION must be between zero and one.");
        }
        if self.curriculum_manifest_path.is_some() && self.curriculum_state_path.is_none() {
            return invalid("Curriculum training requires a durable FUZZ_CURRICULUM_STATE_PATH.");
        }
        if self.curriculum_manifest_path.is_some() && self.heldout_prompt_count != 16 {
            return invalid("Curriculum training requires the fixed 16-row gate.");
        }
        positive_int("FUZZ_MAX_PROMPT_COUNT", self.max_prompt_count)?;
        positive_int("FUZZ_MAX_CONCURRENT_CYCLES", i64::try_from(self.max_concurrent_cycles).unwrap_or(0))?;
        if self.training_transformations_per_example < 0 {
            return invalid("FUZZ_TRAINING_TRANSFORMS_PER_EXAMPLE must not be negative.");
        }
        positive_float("FUZZ_TIMEOUT_SECONDS", self.timeout_seconds)?;
        positive_float("FUZZ_TRAINING_LEARNING_RATE", self.training_learning_rate)?;
        positive_float("FUZZ_TRAINING_MAX_GRADIENT", self.training_max_gradient)?;
        if let Some(rate) = self.underlying_training_learning_rate {
            positive_float("FUZZ_UNDERLYING_TRAINING_LEARNING_RATE", rate)?;
        }
        if !self.minimum_exact_match_rate.is_finite() || self.minimum_exact_match_rate < 0.0 {
            return invalid("FUZZ_MIN_EXACT_MATCH_RATE must be finite and non-negative.");
        }
        if self.minimum_exact_match_rate > 1.0 {
            return invalid("FUZZ_MIN_EXACT_MATCH_RATE must not exceed 1.");
        }
        if !(2..=256).contains(&self.heldout_prompt_count) {
            return invalid("FUZZ_HELDOUT_PROMPT_COUNT must be between 2 and 256.");
        }
        let expanded = self
            .max_prompt_count
            .saturating_mul(self.training_transformations_per_example.saturating_add(1))
            .saturating_add(self.heldout_prompt_count);
        if expanded > 1024 {
            return invalid("Expanded training plus held-out examples must not exceed 1024.");
        }
        if self.port == 0 {
            return invalid("FUZZER_PORT must be between 1 and 65535.");
        }
        for (name, value) in [
            ("PARAM_UPDATE_TARGET", &self.param_update_target),
            ("PRIVOKE_RUNTIME_TARGET", &self.privoke_runtime_target),
            ("MODEL_ID", &self.model_id),
            ("PRESENCE_MODEL_ID", &self.presence_model_id),
            ("FUZZER_ID", &self.fuzzer_id),
        ] {
            validate_text(value, name, true, 256)?;
        }
        Ok(self)
    }

    /// `batch_training_config(seed, training_scope=)`: the FULL encoder rate is chosen before the runtime computes.
    pub fn batch_training_config(&self, seed: u64, scope: Scope) -> BatchTrainingConfig {
        let mut learning_rate = self.training_learning_rate;
        if scope == Scope::FullEncoder
            && let Some(rate) = self.underlying_training_learning_rate
        {
            learning_rate = rate;
        }
        BatchTrainingConfig {
            learning_rate,
            max_gradient: self.training_max_gradient,
            transformations_per_example: self.training_transformations_per_example,
            seed,
            golden_example_weight: self.training_replay_weight,
            ..BatchTrainingConfig::default()
        }
    }
}

/// The credentials every outbound channel presents: the service's registered certificate and the server CA
/// (`PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE`). A missing or empty file is an error, so a
/// deployment without credentials fails at startup instead of sending plaintext.
pub fn client_tls_from_lookup(target: &str, server_name_variable: &str, get: impl Fn(&str) -> Option<String>) -> Result<ClientTlsConfig> {
    let file = |variable: &str| -> Result<PathBuf> {
        let path = get(variable)
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| Error(format!("{variable} is required.")))?;
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Ok(path),
            _ => Err(Error(format!("{variable} {} is not a non-empty file.", path.display()))),
        }
    };
    let host = target.rsplit_once(':').map_or(target, |(host, _)| host).trim_matches(['[', ']']).to_string();
    let server_name = get(server_name_variable).filter(|value| !value.trim().is_empty()).unwrap_or(host);
    Ok(ClientTlsConfig {
        server_ca: file("PRIVOKE_TLS_CA_FILE")?,
        identity: Some((file("PRIVOKE_TLS_CERT_FILE")?, file("PRIVOKE_TLS_KEY_FILE")?)),
        server_name,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs.iter().map(|(key, value)| ((*key).to_string(), (*value).to_string())).collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn defaults_select_the_audience_sampler() {
        let config = FuzzerConfig::from_lookup(lookup(&[])).unwrap();
        assert_eq!(config.contextual_sampling_strategy, "audience_coverage_v1");
        assert_eq!(config.port, 50053);
        assert_eq!(config.max_prompt_count, 256);
        assert_eq!(config.heldout_prompt_count, 16);
        assert_eq!(config.fuzzer_id, "privoke-fuzzer");
    }

    #[test]
    fn an_explicit_dataset_selects_the_legacy_sampler() {
        let config = FuzzerConfig::from_lookup(lookup(&[("FUZZ_PROMPT_DATASET_PATH", "data.json")])).unwrap();
        assert_eq!(config.contextual_sampling_strategy, "legacy_random_v1");
    }

    #[test]
    fn invalid_settings_are_refused_with_the_python_messages() {
        let legacy = ("FUZZ_CONTEXTUAL_SAMPLING_STRATEGY", "legacy_random_v1");
        let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (vec![("FUZZ_MAX_PROMPT_COUNT", "x")], "FUZZ_MAX_PROMPT_COUNT must be an integer."),
            (vec![("FUZZ_TIMEOUT_SECONDS", "x")], "FUZZ_TIMEOUT_SECONDS must be a number."),
            (vec![("FUZZ_CONTEXTUAL_SAMPLING_STRATEGY", "other")], "Unknown FUZZ_CONTEXTUAL_SAMPLING_STRATEGY."),
            (vec![legacy, ("FUZZ_MIN_EXACT_MATCH_RATE", "2")], "FUZZ_MIN_EXACT_MATCH_RATE must not exceed 1."),
            (vec![legacy, ("FUZZ_HELDOUT_PROMPT_COUNT", "1")], "FUZZ_HELDOUT_PROMPT_COUNT must be between 2 and 256."),
            (vec![legacy, ("FUZZ_TRAINING_REPLAY_WEIGHT", "0")], "FUZZ_TRAINING_REPLAY_WEIGHT must be finite and in (0, 1]."),
            (
                vec![legacy, ("FUZZ_CURRICULUM_MANIFEST_PATH", "m.json")],
                "Curriculum training requires a durable FUZZ_CURRICULUM_STATE_PATH.",
            ),
            (vec![legacy, ("FUZZ_MAX_PROMPT_COUNT", "1024")], "Expanded training plus held-out examples must not exceed 1024."),
        ];
        for (pairs, message) in cases {
            assert_eq!(FuzzerConfig::from_lookup(lookup(&pairs)).unwrap_err().0, message, "{pairs:?}");
        }
    }

    #[test]
    fn the_full_encoder_rate_applies_only_to_that_scope() {
        let config = FuzzerConfig::from_lookup(lookup(&[("FUZZ_UNDERLYING_TRAINING_LEARNING_RATE", "0.003")])).unwrap();
        assert!((config.batch_training_config(7, Scope::Heads).learning_rate - 0.03).abs() < f64::EPSILON);
        assert!((config.batch_training_config(7, Scope::FullEncoder).learning_rate - 0.003).abs() < f64::EPSILON);
        assert_eq!(config.batch_training_config(7, Scope::Heads).seed, 7);
    }

    #[test]
    fn client_credentials_are_required_files() {
        let directory = std::env::temp_dir().join(format!("privoke-fuzzer-config-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        assert!(client_tls_from_lookup("runtime:50054", "X", |_| None).is_err());
        let file = directory.join("c.pem");
        std::fs::write(&file, b"synthetic").unwrap();
        let path = file.to_string_lossy().to_string();
        let credentials = |key: &str| match key {
            "PRIVOKE_TLS_CA_FILE" | "PRIVOKE_TLS_CERT_FILE" | "PRIVOKE_TLS_KEY_FILE" => Some(path.clone()),
            _ => None,
        };
        let spec = client_tls_from_lookup("runtime:50054", "X", credentials).unwrap();
        assert_eq!(spec.server_name, "runtime");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
