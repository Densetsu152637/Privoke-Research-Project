//! `cli.py`: the `train` subcommand (one training cycle against a running fuzzer) and the container health probe.
//!
//! The Python CLI opened an insecure channel; this one presents a registered `trainer` or `publisher` certificate over
//! mutual TLS (`PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE`, and `FUZZER_TLS_SERVER_NAME` when the
//! certificate does not carry the target host name). `test-prompts` (`prompt_testing.py`) is a study helper that sends
//! prompts to detector layers; it is not part of this service and is not ported.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use privoke_contracts::proto::v1::fuzzer_service_client::FuzzerServiceClient;
use privoke_contracts::proto::v1::{FuzzerTrainingRequest, FuzzerTrainingResponse, HealthRequest};
use privoke_curriculum::value;
use privoke_transport::ClientTlsConfig;
use privoke_transport::client::connect;
use tonic::Request;

use crate::SERVICE_NAME;
use crate::config::client_tls_from_lookup;
use crate::error::{Error, Result};

const WINDOW_POLICY: &str = "full_projected_adam64_window_checkpoint_v1";

/// Arguments of `train`.
#[derive(Debug, Clone, clap::Args)]
pub struct TrainArgs {
    /// `host:port` of the fuzzer.
    #[arg(long, default_value = "privoke-fuzzer:50053")]
    pub target: String,
    /// The model to train.
    #[arg(long, default_value = "privoke-baseline")]
    pub model_id: String,
    /// The `source_id` of the request.
    #[arg(long, default_value = "privoke-fuzzer-cli")]
    pub source_id: String,
    /// The request identity; generated when absent.
    #[arg(long)]
    pub request_id: Option<String>,
    /// Originals to train on (8; 256 for the window policy).
    #[arg(long)]
    pub prompt_count: Option<u32>,
    /// The window training policy (the frozen TRAIN window with exact checkpoint selection; implies the FULL endpoint).
    #[arg(long, value_parser = [WINDOW_POLICY])]
    pub training_policy: Option<String>,
    /// Use the FULL underlying-model endpoint.
    #[arg(long)]
    pub underlying: bool,
    /// Pin of the prepared window manifest (window policy only).
    #[arg(long)]
    pub window_manifest_sha256: Option<String>,
    /// Pin of the prepared component manifest (window policy only).
    #[arg(long)]
    pub component_manifest_sha256: Option<String>,
    /// The cycle seed.
    #[arg(long, default_value_t = 1337)]
    pub seed: u32,
    /// The call deadline in seconds (60; 1800 for the window policy).
    #[arg(long)]
    pub timeout: Option<f64>,
}

/// Arguments of `healthcheck`.
#[derive(Debug, Clone, clap::Args)]
pub struct HealthcheckArgs {
    /// `host:port` of the listener. Defaults to loopback on `FUZZER_PORT` (50053).
    #[arg(long)]
    pub address: Option<String>,
    /// CA bundle that signed the server certificate (`FUZZER_HEALTHCHECK_SERVER_CA`).
    #[arg(long)]
    pub server_ca: Option<PathBuf>,
    /// Client certificate of a registered service identity (`FUZZER_HEALTHCHECK_CERT`).
    #[arg(long)]
    pub client_cert: Option<PathBuf>,
    /// Its private key (`FUZZER_HEALTHCHECK_KEY`).
    #[arg(long)]
    pub client_key: Option<PathBuf>,
    /// The name the server certificate carries (`FUZZER_HEALTHCHECK_SERVER_NAME`, default `localhost`).
    #[arg(long)]
    pub server_name: Option<String>,
}

/// The request `train` sends.
pub fn build_request(args: &TrainArgs, request_id: String) -> Result<FuzzerTrainingRequest> {
    let mut metadata = BTreeMap::from([("initiator".to_string(), "privoke-fuzzer-cli".to_string())]);
    if args.training_policy.is_some() {
        let (Some(window), Some(component)) = (
            args.window_manifest_sha256.as_ref().filter(|pin| !pin.is_empty()),
            args.component_manifest_sha256.as_ref().filter(|pin| !pin.is_empty()),
        ) else {
            return Err(Error("Window policy requires both explicit prepared manifest pins.".to_string()));
        };
        for (key, text) in [
            ("contextual_sampling_strategy", privoke_curriculum::train_window::SAMPLER),
            ("expected_contextual_training_optimizer", WINDOW_POLICY),
            ("expected_contextual_training_objective", crate::policy::SUM_MARGIN),
            ("expected_contextual_candidate_eligibility", crate::policy::WINDOW_ELIGIBILITY),
            ("expected_contextual_training_scope", "full_encoder"),
            ("expected_train_window_config_v1", privoke_training::admission::WINDOW_CONFIG_CANONICAL),
            ("expected_train_window_manifest_sha256", window),
            ("expected_original_train_component_manifest_sha256", component),
        ] {
            metadata.insert(key.to_string(), text.to_string());
        }
        crate::policy::window_expectations(&metadata)?;
    } else if args.window_manifest_sha256.as_ref().is_some_and(|pin| !pin.is_empty())
        || args.component_manifest_sha256.as_ref().is_some_and(|pin| !pin.is_empty())
    {
        return Err(Error("Manifest pins require an explicit window training policy.".to_string()));
    }
    Ok(FuzzerTrainingRequest {
        request_id,
        source_id: args.source_id.clone(),
        model_id: args.model_id.clone(),
        prompt_count: args.prompt_count.unwrap_or(if args.training_policy.is_some() { 256 } else { 8 }),
        seed: args.seed,
        metadata,
    })
}

fn generated_request_id() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("privoke-cli-{}-{:08x}", now.as_secs(), now.subsec_nanos() ^ std::process::id())
}

/// `json.dumps(record, indent=2, sort_keys=True)` for the flat record `train` prints.
pub fn render_response(response: &FuzzerTrainingResponse) -> Result<String> {
    let text = |item: &str| -> Result<String> { Ok(value::dumps(&value::string(item))?) };
    let mut metadata = String::new();
    if response.metadata.is_empty() {
        metadata.push_str("{}");
    } else {
        let entries: Vec<String> =
            response.metadata.iter().map(|(key, item)| Ok(format!("    {}: {}", text(key)?, text(item)?))).collect::<Result<_>>()?;
        metadata.push_str("{\n");
        metadata.push_str(&entries.join(",\n"));
        metadata.push_str("\n  }");
    }
    Ok(format!(
        "{{\n  \"accepted\": {},\n  \"applied_version\": {},\n  \"base_version\": {},\n  \"message\": {},\n  \"metadata\": {},\n  \"model_id\": {},\n  \"prompts_generated\": {}\n}}",
        response.accepted,
        text(&response.applied_version)?,
        text(&response.base_version)?,
        text(&response.message)?,
        metadata,
        text(&response.model_id)?,
        response.prompts_generated
    ))
}

/// `run_training_cycle`: send one request and print the response. Returns whether it was accepted.
pub async fn run_train(args: TrainArgs) -> Result<bool> {
    let request_id = args.request_id.clone().unwrap_or_else(generated_request_id);
    let request = build_request(&args, request_id)?;
    let tls = client_tls_from_lookup(&args.target, "FUZZER_TLS_SERVER_NAME", |name| std::env::var(name).ok())?;
    let channel = connect(&args.target, &tls).await.map_err(|error| Error(error.to_string()))?;
    let mut message = Request::new(request);
    message.set_timeout(
        Duration::try_from_secs_f64(args.timeout.unwrap_or(if args.training_policy.is_some() { 1800.0 } else { 60.0 }))
            .map_err(|_| Error("--timeout must be positive.".to_string()))?,
    );
    let mut client = FuzzerServiceClient::new(channel);
    let outcome = if args.underlying || args.training_policy.is_some() {
        client.run_underlying_training_cycle(message).await
    } else {
        client.run_training_cycle(message).await
    };
    let response = outcome.map_err(|status| Error(format!("{}: {}", status.code(), status.message())))?.into_inner();
    println!("{}", render_response(&response)?);
    Ok(response.accepted)
}

fn required(flag: &str, value: Option<PathBuf>, variable: &str) -> Result<PathBuf> {
    value
        .or_else(|| std::env::var_os(variable).filter(|text| !text.is_empty()).map(PathBuf::from))
        .ok_or_else(|| Error(format!("missing {flag} (or {variable})")))
}

/// The `healthcheck` subcommand: one mutual-TLS `Health` call; succeeds only for a `SERVING` fuzzer.
pub async fn run_healthcheck(args: HealthcheckArgs, default_port: u16) -> Result<()> {
    let server_ca = required("--server-ca", args.server_ca, "FUZZER_HEALTHCHECK_SERVER_CA")?;
    let cert = required("--client-cert", args.client_cert, "FUZZER_HEALTHCHECK_CERT")?;
    let key = required("--client-key", args.client_key, "FUZZER_HEALTHCHECK_KEY")?;
    let server_name = args
        .server_name
        .or_else(|| std::env::var("FUZZER_HEALTHCHECK_SERVER_NAME").ok().filter(|text| !text.is_empty()))
        .unwrap_or_else(|| "localhost".to_string());
    let address = args.address.unwrap_or_else(|| format!("127.0.0.1:{default_port}"));
    let spec = ClientTlsConfig { server_ca, identity: Some((cert, key)), server_name };
    let probe = async {
        let channel = connect(&address, &spec).await.map_err(|error| Error(error.to_string()))?;
        let response =
            FuzzerServiceClient::new(channel).health(HealthRequest {}).await.map_err(|error| Error(error.to_string()))?.into_inner();
        if response.service != SERVICE_NAME || response.status != "SERVING" {
            return Err(Error(format!("unexpected health response service={:?} status={:?}", response.service, response.status)));
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(5), probe).await.map_err(|_| Error("health probe timed out".to_string()))?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn args() -> TrainArgs {
        TrainArgs {
            target: "privoke-fuzzer:50053".into(),
            model_id: "m".into(),
            source_id: "s".into(),
            request_id: None,
            prompt_count: None,
            training_policy: None,
            underlying: false,
            window_manifest_sha256: None,
            component_manifest_sha256: None,
            seed: 1337,
            timeout: None,
        }
    }

    #[test]
    fn the_request_matches_the_python_defaults() {
        let request = build_request(&args(), "id".into()).unwrap();
        assert_eq!((request.prompt_count, request.seed), (8, 1337));
        assert_eq!(request.metadata["initiator"], "privoke-fuzzer-cli");
    }

    #[test]
    fn the_window_policy_needs_both_pins_and_pins_need_the_policy() {
        let mut policy = args();
        policy.training_policy = Some(WINDOW_POLICY.into());
        assert_eq!(build_request(&policy, "id".into()).unwrap_err().0, "Window policy requires both explicit prepared manifest pins.");
        policy.window_manifest_sha256 = Some("a".repeat(64));
        policy.component_manifest_sha256 = Some("b".repeat(64));
        let request = build_request(&policy, "id".into()).unwrap();
        assert_eq!(request.prompt_count, 256);
        assert_eq!(request.metadata["contextual_sampling_strategy"], "taxonomy_benign_train_window_v1");
        assert_eq!(request.metadata["expected_train_window_manifest_sha256"], "a".repeat(64));
        assert_eq!(request.metadata["expected_original_train_component_manifest_sha256"], "b".repeat(64));
        assert_eq!(request.metadata.len(), 9);
        let mut malformed = policy.clone();
        malformed.window_manifest_sha256 = Some("short".into());
        assert_eq!(
            build_request(&malformed, "id".into()).unwrap_err().0,
            "Window admission requires exact FULL policy/config and independent release pins."
        );
        let mut pins = args();
        pins.window_manifest_sha256 = Some("x".into());
        assert_eq!(build_request(&pins, "id".into()).unwrap_err().0, "Manifest pins require an explicit window training policy.");
    }

    #[test]
    fn the_response_prints_as_python_json_with_two_space_indent_and_sorted_keys() {
        let response = FuzzerTrainingResponse {
            accepted: true,
            model_id: "m".into(),
            base_version: "v1".into(),
            applied_version: "v2".into(),
            prompts_generated: 8,
            message: String::new(),
            metadata: BTreeMap::from([("b".to_string(), "2".to_string()), ("a".to_string(), "1".to_string())]),
        };
        let expected = "{\n  \"accepted\": true,\n  \"applied_version\": \"v2\",\n  \"base_version\": \"v1\",\n  \"message\": \"\",\n  \"metadata\": {\n    \"a\": \"1\",\n    \"b\": \"2\"\n  },\n  \"model_id\": \"m\",\n  \"prompts_generated\": 8\n}";
        assert_eq!(render_response(&response).unwrap(), expected);
    }
}
