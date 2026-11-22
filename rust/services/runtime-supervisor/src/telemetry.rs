//! The telemetry reporter, owned by the controller (stage 18 wired in, plan "Worker isolation architecture").
//!
//! The inference worker has no reporter and no network. After an `AnalyzePrompt` result has passed through the
//! controller, [`Telemetry::observe`] maps it to the few facts a report may use (an [`AnalysisInput`]: the action name,
//! the sensitivity and category names, the model version string) and hands them to the stage 18 reporter, which
//! reserves budget, randomises locally and delivers over mutual TLS with the reporter credential. No text, span,
//! request id or metadata other than the model version is representable in an `AnalysisInput`, so none can reach a
//! packet.
//!
//! The reporter is off unless `TELEMETRY_ENABLED` is true and a telemetry target is configured, the rule of
//! `grpc_main.py`. A failure of telemetry never fails an analysis: nothing here returns an error to the caller.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use privoke_contracts::proto::v1::AnalyzePromptResponse;
use privoke_telemetry_client::{
    AnalysisInput, AnalysisResult, Classification, GrpcTransport, ReporterEndpoint, ReporterSettings, TelemetryReporter,
};
use prost::Message;

use crate::config::{Environment, positive_int, positive_seconds};

/// How long one analysis waits for the ledger transaction of its report. A report never waits for the network; this
/// bounds a stuck ledger file, and the transaction then finishes in the background.
const REPORT_WAIT: Duration = Duration::from_secs(2);
/// How long shutdown waits for the delivery worker.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// The reporter, shared by every session of the controller.
#[derive(Debug, Clone)]
pub struct Telemetry {
    reporter: Arc<TelemetryReporter>,
}

/// `env_bool` of the Python runtime: only `1`, `true`, `yes` and `on` are true, anything else is false.
fn env_flag(environment: &Environment, name: &str) -> bool {
    environment.get(name).is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

/// `env_positive_float` of the Python runtime.
fn positive_float(environment: &Environment, name: &str, default: f64) -> Result<f64, String> {
    let value = match environment.get(name) {
        None => default,
        Some(raw) => raw.trim().parse::<f64>().map_err(|_| format!("{name} must be a number."))?,
    };
    if value > 0.0 { Ok(value) } else { Err(format!("{name} must be greater than zero.")) }
}

/// `stack_target("TELEMETRY")`: the telemetry target of the stack in `environment`. Telemetry has its own public
/// port and credential, so there is no fallback to `PRIVOKE_CLOUD_TARGET`.
pub fn telemetry_target(environment: &Environment) -> Result<String, String> {
    let get = |name: &str| environment.get(name).map(|value| value.trim().to_string()).unwrap_or_default();
    if get("PRIVOKE_STACK_MODE") == "internal" {
        let target = get("TELEMETRY_TARGET");
        return if target.is_empty() { Err("TELEMETRY_TARGET is required in internal mode.".into()) } else { Ok(target) };
    }
    if crate::runtime::use_local_stack(environment).map_err(|error| error.message)? {
        let local = get("PRIVOKE_LOCAL_TELEMETRY_TARGET");
        return Ok(if local.is_empty() { "127.0.0.1:50055".to_string() } else { local });
    }
    Ok(get("PRIVOKE_CLOUD_TELEMETRY_TARGET"))
}

/// The reporter's numbers and paths from the environment, with the names and defaults of the Python runtime.
pub fn settings_from_environment(environment: &Environment) -> Result<ReporterSettings, String> {
    let defaults = ReporterSettings::default();
    let ledger_path = environment.get("TELEMETRY_PRIVACY_LEDGER_PATH").map(|value| value.trim()).filter(|value| !value.is_empty());
    let queue_size = positive_int(environment, "TELEMETRY_QUEUE_SIZE", defaults.queue_size as u64)?;
    Ok(ReporterSettings {
        event_epsilon: positive_float(environment, "TELEMETRY_LDP_EPSILON", defaults.event_epsilon)?,
        daily_epsilon: positive_float(environment, "TELEMETRY_LDP_DAILY_EPSILON", defaults.daily_epsilon)?,
        ledger_path: ledger_path.map(Into::into),
        timeout: positive_seconds(environment, "TELEMETRY_TIMEOUT_SECONDS", defaults.timeout.as_secs_f64())?,
        queue_size: usize::try_from(queue_size).map_err(|_| "TELEMETRY_QUEUE_SIZE is too large.".to_string())?,
    })
}

/// What a report may take from the response the controller is about to return.
///
/// `None` when there is nothing to report: a response with neither a result nor any layer execution is what the
/// Python servicer returns from its exception path, where it does not report either. The classification and the
/// model version are those of the result (`evidence`), as the Python reporter reads `analysis.result`.
pub fn analysis_input(response: &AnalyzePromptResponse) -> Option<AnalysisInput> {
    if response.evidence.is_none() && response.layers.is_empty() {
        return None;
    }
    let result = response.evidence.as_ref().map(|evidence| AnalysisResult {
        classification: evidence
            .classification
            .as_ref()
            .map(|found| Classification { sensitivity: found.sensitivity.clone(), categories: found.categories.clone() }),
        model_version: evidence.metadata.get("model_version").cloned(),
    });
    Some(AnalysisInput { action: response.action.clone(), result })
}

impl Telemetry {
    /// A telemetry hook over a started reporter.
    pub fn new(reporter: TelemetryReporter) -> Self {
        Self { reporter: Arc::new(reporter) }
    }

    /// The reporter the environment configures, `Ok(None)` when telemetry is off: not enabled, or enabled with no
    /// target (the Python runtime prints a notice and continues without telemetry). An invalid number, a target that
    /// needs a credential that is not configured, or a ledger that cannot be opened is an error: the caller runs
    /// without telemetry and says why, since a controller that cannot report is still a working controller.
    pub fn from_environment(environment: &Environment) -> Result<Option<Self>, String> {
        if !env_flag(environment, "TELEMETRY_ENABLED") {
            return Ok(None);
        }
        let target = telemetry_target(environment)?;
        if target.is_empty() {
            tracing::warn!("Telemetry is enabled but PRIVOKE_CLOUD_TELEMETRY_TARGET is not set; telemetry is off.");
            return Ok(None);
        }
        let settings = settings_from_environment(environment)?;
        let endpoint =
            ReporterEndpoint::from_environment(&target, &|name| environment.get(name).cloned()).map_err(|error| error.to_string())?;
        let transport = GrpcTransport::new(endpoint).map_err(|error| error.to_string())?;
        let reporter = TelemetryReporter::start(settings, Box::new(transport)).map_err(|error| error.to_string())?;
        Ok(Some(Self::new(reporter)))
    }

    /// Reports one analysis. `payload` is the base64 `AnalyzePromptResponse` the controller returns to the extension.
    /// The report runs on a blocking thread (a short SQLite transaction); its outcome is not used.
    pub async fn observe(&self, payload: &str) {
        let Some(input) = STANDARD
            .decode(payload)
            .ok()
            .and_then(|bytes| AnalyzePromptResponse::decode(bytes.as_slice()).ok())
            .and_then(|response| analysis_input(&response))
        else {
            return;
        };
        let reporter = Arc::clone(&self.reporter);
        let task = tokio::task::spawn_blocking(move || {
            reporter.report(&input);
        });
        let _ = tokio::time::timeout(REPORT_WAIT, task).await;
    }

    /// Stops the delivery worker after the packets already queued. Called once when the session ends.
    pub async fn close(&self) {
        let reporter = Arc::clone(&self.reporter);
        let _ = tokio::task::spawn_blocking(move || reporter.close(CLOSE_WAIT)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use privoke_contracts::proto::v1::{RuntimeClassification, RuntimeDetectionResult, RuntimeLayerExecution};

    use super::*;

    fn environment(pairs: &[(&str, &str)]) -> Environment {
        pairs.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())).collect()
    }

    #[test]
    fn telemetry_is_off_unless_enabled_and_targeted() {
        assert!(Telemetry::from_environment(&environment(&[])).unwrap().is_none());
        assert!(Telemetry::from_environment(&environment(&[("TELEMETRY_ENABLED", "false")])).unwrap().is_none());
        // Enabled without a telemetry target: off, as in `grpc_main.py`; the model target is not a fallback.
        let enabled = environment(&[("TELEMETRY_ENABLED", "true"), ("PRIVOKE_CLOUD_TARGET", "cloud.example:443")]);
        assert!(Telemetry::from_environment(&enabled).unwrap().is_none());
    }

    #[test]
    fn the_target_follows_the_stack() {
        let cloud = environment(&[("PRIVOKE_CLOUD_TELEMETRY_TARGET", " t.example:50443 ")]);
        assert_eq!(telemetry_target(&cloud).unwrap(), "t.example:50443");
        assert_eq!(telemetry_target(&environment(&[("PRIVOKE_USE_LOCAL_STACK", "true")])).unwrap(), "127.0.0.1:50055");
        let local = environment(&[("PRIVOKE_USE_LOCAL_STACK", "1"), ("PRIVOKE_LOCAL_TELEMETRY_TARGET", "127.0.0.1:9")]);
        assert_eq!(telemetry_target(&local).unwrap(), "127.0.0.1:9");
        let internal = environment(&[("PRIVOKE_STACK_MODE", "internal"), ("TELEMETRY_TARGET", "telemetry:50055")]);
        assert_eq!(telemetry_target(&internal).unwrap(), "telemetry:50055");
        assert!(telemetry_target(&environment(&[("PRIVOKE_STACK_MODE", "internal")])).is_err());
    }

    #[test]
    fn settings_use_the_python_names_and_defaults() {
        let defaults = settings_from_environment(&environment(&[])).unwrap();
        assert_eq!((defaults.event_epsilon, defaults.daily_epsilon, defaults.queue_size), (1.0, 8.0, 1024));
        assert!(defaults.ledger_path.is_none());
        let set = environment(&[
            ("TELEMETRY_LDP_EPSILON", "0.5"),
            ("TELEMETRY_LDP_DAILY_EPSILON", "4"),
            ("TELEMETRY_PRIVACY_LEDGER_PATH", "ledger.sqlite3"),
            ("TELEMETRY_TIMEOUT_SECONDS", "2.5"),
            ("TELEMETRY_QUEUE_SIZE", "8"),
        ]);
        let settings = settings_from_environment(&set).unwrap();
        assert_eq!((settings.event_epsilon, settings.daily_epsilon, settings.queue_size), (0.5, 4.0, 8));
        assert_eq!(settings.timeout, Duration::from_millis(2500));
        assert_eq!(settings.ledger_path.as_deref(), Some(std::path::Path::new("ledger.sqlite3")));
        for bad in [("TELEMETRY_LDP_EPSILON", "0"), ("TELEMETRY_QUEUE_SIZE", "0"), ("TELEMETRY_TIMEOUT_SECONDS", "x")] {
            assert!(settings_from_environment(&environment(&[bad])).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn only_the_allowed_facts_are_taken_from_a_response() {
        let evidence = RuntimeDetectionResult {
            classification: Some(RuntimeClassification {
                sensitivity: "S2".into(),
                categories: vec!["HEALTH".into(), "FINANCIAL".into()],
                ..Default::default()
            }),
            reasoning: "a reasoning that must not travel".into(),
            metadata: [("model_version".to_string(), "privoke-v3-balanced+train.7".to_string()), ("other".into(), "x".into())].into(),
            ..Default::default()
        };
        let response = AnalyzePromptResponse {
            request_id: "r-1".into(),
            action: "WARN".into(),
            masked_text: "text that must not travel".into(),
            evidence: Some(evidence),
            ..Default::default()
        };
        let input = analysis_input(&response).unwrap();
        assert_eq!(input.action, "WARN");
        let result = input.result.unwrap();
        assert_eq!(result.model_version.as_deref(), Some("privoke-v3-balanced+train.7"));
        let found = result.classification.unwrap();
        assert_eq!(found.sensitivity, "S2");
        assert_eq!(found.categories, vec!["HEALTH".to_string(), "FINANCIAL".to_string()]);
    }

    #[test]
    fn a_response_without_result_or_layers_reports_nothing_and_one_with_layers_only_has_no_result() {
        assert!(analysis_input(&AnalyzePromptResponse { action: "ALLOW".into(), ..Default::default() }).is_none());
        let layered = AnalyzePromptResponse {
            action: "ALLOW".into(),
            layers: vec![RuntimeLayerExecution { status: "ok".into(), ..Default::default() }],
            ..Default::default()
        };
        let input = analysis_input(&layered).unwrap();
        assert_eq!((input.action.as_str(), input.result), ("ALLOW", None));
    }
}
