//! The external (OpenAI-compatible) classifier client (`LLM/open_classifier.py`, stage 16, decision D10).
//!
//! * [`OpenConfig::resolve`] is the constructor's configuration (explicit options, then the `OPENAI_*` variables).
//! * [`build_request`] is the exact request the Python SDK sends: `POST <base>/chat/completions`, compact JSON with the
//!   keys in the SDK's order, `ensure_ascii=False` text.
//! * [`OpenClassifier`] sends it with `reqwest` (rustls, no OpenSSL) and parses the answer with
//!   [`crate::open_response`]; it implements [`SemanticClassifier`], so [`crate::analyse_semantic_layer`] runs it.
//!
//! The API key comes only from the options or the environment at run time. It is never logged, never part of a `Debug`
//! output, and never recorded in a fixture. The client is blocking, like `classify`: call it from a thread that is not
//! an async runtime worker (for example inside `tokio::task::spawn_blocking`).

use std::fmt;
use std::io::Read;
use std::time::Duration;

use reqwest::blocking::Client;

use crate::error::SemanticError;
use crate::layer::{Finding, SemanticClassifier};
use crate::open_prompt::{SYSTEM_PROMPT, user_prompt};
use crate::open_response::{ExternalResult, MAX_RESPONSE_BYTES, parse_http_response};

/// The SDK's default base URL.
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_MODEL: &str = "gpt-4o-mini";
const DEFAULT_TEMPERATURE: f64 = 0.25;
const DEFAULT_MAX_TOKENS: u64 = 512;
const DEFAULT_TIMEOUT_SECONDS: f64 = 60.0;
/// The SDK retries a failed request twice.
const DEFAULT_MAX_RETRIES: u32 = 2;
const RETRY_BASE_SECONDS: f64 = 0.5;
const RETRY_MAX_SECONDS: f64 = 8.0;
const KEY_MISSING: &str = "OpenAI API key is not configured. Set OPENAI_API_KEY or provide openai.api_key via /config/llm.";

/// Explicit constructor arguments (`OpenClassifier(api_key=..., ...)`). `None` means "not given".
#[derive(Clone)]
pub struct OpenOptions {
    /// `api_key`.
    pub api_key: Option<String>,
    /// `model`.
    pub model: Option<String>,
    /// `base_url`.
    pub base_url: Option<String>,
    /// `timeout_seconds`.
    pub timeout_seconds: Option<f64>,
    /// `temperature`.
    pub temperature: Option<f64>,
    /// `max_tokens`.
    pub max_tokens: Option<u64>,
    /// `use_environment`: read the `OPENAI_*` variables for what is not given (the Python default is `true`).
    pub use_environment: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            api_key: None,
            model: None,
            base_url: None,
            timeout_seconds: None,
            temperature: None,
            max_tokens: None,
            use_environment: true,
        }
    }
}

impl fmt::Debug for OpenOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenOptions")
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("timeout_seconds", &self.timeout_seconds)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("use_environment", &self.use_environment)
            .finish()
    }
}

/// The resolved configuration of one classifier.
#[derive(Clone)]
pub struct OpenConfig {
    api_key: String,
    base_url: String,
    /// `model`.
    pub model: String,
    /// `temperature`.
    pub temperature: f64,
    /// `max_tokens`.
    pub max_tokens: u64,
    /// Connect and response timeout (the SDK's `timeout`).
    pub timeout: Duration,
    /// Retries after a retryable failure (the SDK's `max_retries`, default 2).
    pub max_retries: u32,
    /// The first retry delay; each retry doubles it up to eight seconds.
    pub retry_base_delay: Duration,
}

impl fmt::Debug for OpenConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenConfig")
            .field("api_key", &"<redacted>")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("temperature", &self.temperature)
            .field("max_tokens", &self.max_tokens)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("retry_base_delay", &self.retry_base_delay)
            .finish()
    }
}

fn message(text: impl Into<String>) -> SemanticError {
    SemanticError::Input(text.into())
}

/// `env_float`: Python's `float(raw)` (surrounding whitespace allowed). A non-finite value is refused: it cannot be sent
/// as JSON and Python only accepts it by accident.
fn env_float(env: &dyn Fn(&str) -> Option<String>, name: &str, default: f64) -> Result<f64, SemanticError> {
    let Some(raw) = env(name) else {
        return Ok(default);
    };
    match raw.trim().parse::<f64>() {
        Ok(value) if value.is_finite() => Ok(value),
        _ => Err(message(format!("{name} must be a number."))),
    }
}

/// `env_positive_int`.
fn env_positive_int(env: &dyn Fn(&str) -> Option<String>, name: &str, default: u64) -> Result<u64, SemanticError> {
    let Some(raw) = env(name) else {
        return Ok(default);
    };
    let Ok(value) = raw.trim().parse::<i64>() else {
        return Err(message(format!("{name} must be an integer.")));
    };
    u64::try_from(value).ok().filter(|value| *value > 0).ok_or_else(|| message(format!("{name} must be greater than zero.")))
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

impl OpenConfig {
    /// The constructor of `OpenClassifier`: explicit options first, then (with `use_environment`) the variables
    /// `OPENAI_API_KEY`, `OPENAI_BASE_URL` (then `OPENAI_API_BASE`), `OPENAI_MODEL`, `OPENAI_TIMEOUT_SECONDS`,
    /// `OPENAI_TEMPERATURE` and `OPENAI_MAX_TOKENS`, read through `env`.
    pub fn resolve(options: OpenOptions, env: &dyn Fn(&str) -> Option<String>) -> Result<Self, SemanticError> {
        let use_environment = options.use_environment;
        let api_key = match options.api_key {
            Some(key) => key,
            None if use_environment => env("OPENAI_API_KEY").unwrap_or_default(),
            None => String::new(),
        };
        if api_key.is_empty() {
            return Err(message(KEY_MISSING));
        }
        let base_url = match options.base_url {
            Some(base_url) => base_url,
            None if use_environment => non_empty(env("OPENAI_BASE_URL")).or_else(|| non_empty(env("OPENAI_API_BASE"))).unwrap_or_default(),
            None => String::new(),
        };
        let base_url = if base_url.is_empty() { DEFAULT_BASE_URL.to_string() } else { base_url };
        // The SDK always ends the base URL with a slash before joining the route.
        let base_url = if base_url.ends_with('/') { base_url } else { format!("{base_url}/") };

        let timeout_seconds = match options.timeout_seconds {
            Some(seconds) => seconds,
            None if use_environment => env_float(env, "OPENAI_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)?,
            None => DEFAULT_TIMEOUT_SECONDS,
        };
        if timeout_seconds.is_nan() || timeout_seconds <= 0.0 {
            return Err(message("OPENAI_TIMEOUT_SECONDS must be greater than zero."));
        }
        let timeout = Duration::try_from_secs_f64(timeout_seconds).map_err(|_| message("OPENAI_TIMEOUT_SECONDS must be a number."))?;

        let model = match (options.model.filter(|model| !model.is_empty()), use_environment) {
            (Some(model), _) => model,
            (None, true) => env("OPENAI_MODEL").unwrap_or_else(|| DEFAULT_MODEL.to_string()),
            (None, false) => return Err(message("OpenAI model is not configured.")),
        };
        let temperature = match options.temperature {
            Some(temperature) => temperature,
            None if use_environment => env_float(env, "OPENAI_TEMPERATURE", DEFAULT_TEMPERATURE)?,
            None => DEFAULT_TEMPERATURE,
        };
        if !temperature.is_finite() {
            return Err(message("OPENAI_TEMPERATURE must be a number."));
        }
        let max_tokens = match options.max_tokens {
            Some(max_tokens) => max_tokens,
            None if use_environment => env_positive_int(env, "OPENAI_MAX_TOKENS", DEFAULT_MAX_TOKENS)?,
            None => DEFAULT_MAX_TOKENS,
        };
        Ok(Self {
            api_key,
            base_url,
            model,
            temperature,
            max_tokens,
            timeout,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_base_delay: Duration::from_secs_f64(RETRY_BASE_SECONDS),
        })
    }

    /// [`OpenConfig::resolve`] over the process environment.
    pub fn from_env(options: OpenOptions) -> Result<Self, SemanticError> {
        Self::resolve(options, &|name| std::env::var(name).ok())
    }

    /// The base URL as the SDK holds it (with the trailing slash).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// The HTTP request of one classification (the key is only in the `authorization` header value).
#[derive(Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// Always `POST`.
    pub method: &'static str,
    /// `<base_url>chat/completions`.
    pub url: String,
    /// Header names (lower case) and values; `authorization` carries the key.
    pub headers: Vec<(&'static str, String)>,
    /// The JSON body, byte for byte what the SDK sends.
    pub body: Vec<u8>,
}

impl fmt::Debug for OpenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (*name, if *name == "authorization" { "<redacted>" } else { value.as_str() }))
            .collect();
        formatter
            .debug_struct("OpenRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""))
}

/// The request body: `{"messages": [...], "model": ..., "max_tokens": ..., "response_format": ..., "temperature": ...}`
/// in that key order, compact, non-ASCII text unescaped (what `httpx` writes for the SDK's parameters).
pub fn request_body(config: &OpenConfig, text: &str) -> Vec<u8> {
    // `serde_json` writes an `f64` as the shortest round-trip decimal with a fraction (`1.0`, `0.25`), as `repr(float)`
    // does, except for exponent forms below 1e-4 or above 1e16 (a temperature never reaches them).
    let temperature = serde_json::Number::from_f64(config.temperature).map_or_else(|| String::from("0.0"), |number| number.to_string());
    format!(
        "{{\"messages\":[{{\"role\":\"system\",\"content\":{system}}},{{\"role\":\"user\",\"content\":{user}}}],\"model\":{model},\"max_tokens\":{max_tokens},\"response_format\":{{\"type\":\"json_object\"}},\"temperature\":{temperature}}}",
        system = json_string(SYSTEM_PROMPT),
        user = json_string(&user_prompt(text)),
        model = json_string(&config.model),
        max_tokens = config.max_tokens,
    )
    .into_bytes()
}

/// The request for one text.
pub fn build_request(config: &OpenConfig, text: &str) -> OpenRequest {
    OpenRequest {
        method: "POST",
        url: format!("{}chat/completions", config.base_url),
        headers: vec![
            ("accept", "application/json".to_string()),
            ("authorization", format!("Bearer {}", config.api_key)),
            ("content-type", "application/json".to_string()),
        ],
        body: request_body(config, text),
    }
}

/// The blocking client of the external classifier.
#[derive(Debug)]
pub struct OpenClassifier {
    config: OpenConfig,
    client: Client,
}

/// Retryable statuses of the SDK: request timeout, conflict, rate limit and server errors.
fn retryable(status: u16) -> bool {
    matches!(status, 408 | 409 | 429) || status >= 500
}

impl OpenClassifier {
    /// A client for `config`. TLS is rustls with the bundled web roots; there is no OpenSSL.
    pub fn new(config: OpenConfig) -> Result<Self, SemanticError> {
        let client = Client::builder()
            .connect_timeout(config.timeout)
            .timeout(config.timeout)
            .user_agent(concat!("privoke-semantic/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| message("Connection error."))?;
        Ok(Self { config, client })
    }

    /// The configuration in use.
    pub fn config(&self) -> &OpenConfig {
        &self.config
    }

    fn delay(&self, attempt: u32, retry_after: Option<&str>) -> Duration {
        // The SDK honours a `retry-after` of 0 to 60 seconds, and otherwise backs off exponentially.
        if let Some(seconds) = retry_after.and_then(|value| value.trim().parse::<f64>().ok())
            && seconds > 0.0
            && seconds <= 60.0
        {
            return Duration::from_secs_f64(seconds);
        }
        let base = self.config.retry_base_delay.as_secs_f64();
        Duration::from_secs_f64((base * 2f64.powi(attempt as i32)).min(RETRY_MAX_SECONDS.max(base)))
    }

    /// One exchange with retries: the final status and body, or the SDK's connection and timeout errors.
    fn exchange(&self, request: &OpenRequest) -> Result<(u16, Vec<u8>), SemanticError> {
        let mut attempt = 0;
        loop {
            let mut builder = self.client.post(&request.url).body(request.body.clone());
            for (name, value) in &request.headers {
                let mut value = match reqwest::header::HeaderValue::from_str(value) {
                    Ok(value) => value,
                    Err(_) => return Err(message("Connection error.")),
                };
                value.set_sensitive(*name == "authorization");
                builder = builder.header(*name, value);
            }
            let outcome = builder.send().map_err(|error| error.is_timeout()).and_then(|response| {
                let status = response.status().as_u16();
                let retry_after = response.headers().get("retry-after").and_then(|value| value.to_str().ok()).map(str::to_string);
                let mut body = Vec::new();
                response
                    .take(MAX_RESPONSE_BYTES as u64 + 1)
                    .read_to_end(&mut body)
                    .map_err(|error| error.kind() == std::io::ErrorKind::TimedOut)?;
                Ok((status, body, retry_after))
            });
            match outcome {
                Ok((status, body, retry_after)) => {
                    if retryable(status) && attempt < self.config.max_retries {
                        std::thread::sleep(self.delay(attempt, retry_after.as_deref()));
                        attempt += 1;
                        continue;
                    }
                    return Ok((status, body));
                }
                Err(timed_out) => {
                    if attempt < self.config.max_retries {
                        std::thread::sleep(self.delay(attempt, None));
                        attempt += 1;
                        continue;
                    }
                    return Err(message(if timed_out { "Request timed out." } else { "Connection error." }));
                }
            }
        }
    }

    /// `classify` with every field of the result (the confidence stays optional).
    pub fn classify_detailed(&self, text: &str) -> Result<Vec<ExternalResult>, SemanticError> {
        let request = build_request(&self.config, text);
        let (status, body) = self.exchange(&request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(message("Semantic classifier returned an invalid HTTP response."));
        }
        parse_http_response(status, &body, text)
    }
}

impl SemanticClassifier for OpenClassifier {
    fn classify(&self, text: &str) -> Result<Vec<Finding>, SemanticError> {
        Ok(self.classify_detailed(text)?.into_iter().map(ExternalResult::into_finding).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())).collect();
        move |name| pairs.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone())
    }

    #[test]
    fn debug_output_never_holds_the_key() {
        let env = env_with(&[("OPENAI_API_KEY", "PLACEHOLDER")]);
        let config = OpenConfig::resolve(OpenOptions::default(), &env).unwrap_or_else(|error| panic!("{error}"));
        assert!(!format!("{config:?}").contains("PLACEHOLDER"));
        let request = build_request(&config, "hello");
        assert!(!format!("{request:?}").contains("PLACEHOLDER"));
        assert!(!format!("{:?}", OpenOptions { api_key: Some("PLACEHOLDER".into()), ..OpenOptions::default() }).contains("PLACEHOLDER"));
    }

    #[test]
    fn retryable_statuses_follow_the_sdk() {
        for status in [408, 409, 429, 500, 502, 503] {
            assert!(retryable(status), "{status}");
        }
        for status in [200, 400, 401, 403, 404, 422] {
            assert!(!retryable(status), "{status}");
        }
    }

    #[test]
    fn delays_double_and_cap() {
        let env = env_with(&[("OPENAI_API_KEY", "PLACEHOLDER")]);
        let config = OpenConfig::resolve(OpenOptions::default(), &env).unwrap_or_else(|error| panic!("{error}"));
        let client = OpenClassifier::new(config).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(client.delay(0, None), Duration::from_millis(500));
        assert_eq!(client.delay(1, None), Duration::from_secs(1));
        assert_eq!(client.delay(10, None), Duration::from_secs(8));
        assert_eq!(client.delay(0, Some("3")), Duration::from_secs(3));
        assert_eq!(client.delay(0, Some("120")), Duration::from_millis(500));
    }
}
