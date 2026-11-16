//! The connection to model-streaming: which target, and how it is secured.
//!
//! The rule is the Python client's (`grpc_channel`): a loopback target is plaintext, the workstation boundary of the
//! local development stack, and every other target needs mutual TLS with the installation certificate and a pinned
//! server CA. `PRIVOKE_MODEL_STREAMING_TLS=true` keeps mutual TLS on loopback too. There is no setting that sends a certificate-less call to a non-loopback host.
//!
//! The installation credential is `PRIVOKE_TLS_CERT_FILE` and `PRIVOKE_TLS_KEY_FILE` when both are set (the way the
//! Python runtime is configured), else `client.crt` and `client.key` in the credential directory that `enrol` and
//! `install-cert` maintain. The server CA is `PRIVOKE_TLS_CA_FILE`, else `server-ca.pem` there. A CA is always
//! required: the supervisor never falls back to system roots.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use privoke_transport::ClientTlsConfig;
use tonic::transport::{Channel, Endpoint};

use crate::config::{Environment, credential_dir};

/// Why a channel could not be set up or opened.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// No target is configured.
    #[error("Configure PRIVOKE_CLOUD_TARGET (or PRIVOKE_CLOUD_MODEL_TARGET) in the client runtime .env.")]
    NoTarget,
    /// The target is not `host:port`.
    #[error("the model-streaming target {0:?} is not host:port")]
    BadTarget(String),
    /// A credential file is missing.
    #[error("{0}")]
    Credential(String),
    /// The connection failed.
    #[error("{0}")]
    Connect(String),
}

/// Which model-streaming to talk to.
#[derive(Debug, Clone)]
pub struct ModelEndpoint {
    /// `host:port`.
    pub target: String,
    host: String,
    /// Plaintext loopback or mutual TLS.
    pub security: Security,
}

/// How the channel is secured.
#[derive(Debug, Clone)]
pub enum Security {
    /// Loopback only; the workstation boundary.
    LoopbackPlaintext,
    /// Mutual TLS with the installation identity.
    MutualTls(ClientTlsConfig),
}

/// The model-streaming target for the stack in `environment`: the local stack target (default `127.0.0.1:50051`)
/// when `PRIVOKE_USE_LOCAL_STACK` is true, else `PRIVOKE_CLOUD_MODEL_TARGET`, falling back to `PRIVOKE_CLOUD_TARGET`.
pub fn model_target(environment: &Environment) -> Result<String, ChannelError> {
    let get = |name: &str| environment.get(name).map(|v| v.trim().to_string()).unwrap_or_default();
    if environment.get("PRIVOKE_STACK_MODE").is_some_and(|mode| mode == "internal") {
        let target = get("MODEL_STREAMING_TARGET");
        return if target.is_empty() { Err(ChannelError::NoTarget) } else { Ok(target) };
    }
    let local = matches!(get("PRIVOKE_USE_LOCAL_STACK").to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on");
    let target = if local {
        let configured = get("PRIVOKE_LOCAL_MODEL_STREAMING_TARGET");
        if configured.is_empty() { "127.0.0.1:50051".to_string() } else { configured }
    } else {
        let model = get("PRIVOKE_CLOUD_MODEL_TARGET");
        if model.is_empty() { get("PRIVOKE_CLOUD_TARGET") } else { model }
    };
    if target.is_empty() { Err(ChannelError::NoTarget) } else { Ok(target) }
}

fn split_target(target: &str) -> Result<(String, u16), ChannelError> {
    let bad = || ChannelError::BadTarget(target.to_string());
    let (host, port) = target.rsplit_once(':').ok_or_else(bad)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().map_err(|_| bad())?;
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host.to_string(), port))
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl ModelEndpoint {
    /// Resolve the target and the credential files. Missing credentials for a non-loopback target are an error here,
    /// before any connection.
    pub fn from_environment(environment: &Environment) -> Result<Self, ChannelError> {
        let target = model_target(environment)?;
        let (host, _port) = split_target(&target)?;
        // `PRIVOKE_MODEL_STREAMING_TLS=true` keeps mutual TLS on a loopback target, which the Rust model-streaming
        // service needs when it runs locally: it has no plaintext listener. It can only make the channel stricter.
        let force_tls = matches!(
            environment.get("PRIVOKE_MODEL_STREAMING_TLS").map(|v| v.trim().to_ascii_lowercase()).as_deref(),
            Some("true" | "1" | "yes" | "on")
        );
        if is_loopback(&host) && !force_tls {
            return Ok(Self { target, host, security: Security::LoopbackPlaintext });
        }
        let directory = credential_dir(environment);
        let pick = |name: &str, file: &str| {
            environment.get(name).map(|v| v.trim()).filter(|v| !v.is_empty()).map_or_else(|| directory.join(file), PathBuf::from)
        };
        let cert = pick("PRIVOKE_TLS_CERT_FILE", "client.crt");
        let key = pick("PRIVOKE_TLS_KEY_FILE", "client.key");
        let ca = pick("PRIVOKE_TLS_CA_FILE", "server-ca.pem");
        for (what, path) in [("installation certificate", &cert), ("installation key", &key), ("server CA", &ca)] {
            if !path.is_file() {
                return Err(ChannelError::Credential(format!(
                    "Non-loopback connections need the {what}, but {} is missing. Run enrol and install-cert first.",
                    path.display()
                )));
            }
        }
        Ok(Self {
            target,
            host: host.clone(),
            security: Security::MutualTls(ClientTlsConfig { server_ca: ca, identity: Some((cert, key)), server_name: host }),
        })
    }

    /// A mutual-TLS endpoint built by the caller (tests, and clients that already hold the paths).
    pub fn mutual_tls(target: &str, tls: ClientTlsConfig) -> Result<Self, ChannelError> {
        let (host, _) = split_target(target)?;
        Ok(Self { target: target.to_string(), host, security: Security::MutualTls(tls) })
    }

    /// Open the channel within `timeout`.
    pub async fn connect(&self, timeout: Duration) -> Result<Channel, ChannelError> {
        let attempt = async {
            match &self.security {
                Security::LoopbackPlaintext => {
                    let (host, port) = split_target(&self.target)?;
                    let host = if host.contains(':') { format!("[{host}]") } else { host };
                    Endpoint::from_shared(format!("http://{host}:{port}"))
                        .map_err(|error| ChannelError::Connect(error.to_string()))?
                        .connect()
                        .await
                        .map_err(|error| ChannelError::Connect(error.to_string()))
                }
                Security::MutualTls(tls) => {
                    privoke_transport::client::connect(&self.target, tls).await.map_err(|error| ChannelError::Connect(error.to_string()))
                }
            }
        };
        tokio::time::timeout(timeout, attempt).await.map_err(|_| ChannelError::Connect(format!("connecting to {} timed out", self.host)))?
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn environment(pairs: &[(&str, &str)]) -> Environment {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn target_follows_the_stack_choice() {
        assert!(matches!(model_target(&environment(&[])), Err(ChannelError::NoTarget)));
        assert_eq!(model_target(&environment(&[("PRIVOKE_CLOUD_TARGET", "a.example:443")])).unwrap(), "a.example:443");
        assert_eq!(
            model_target(&environment(&[("PRIVOKE_CLOUD_TARGET", "a.example:443"), ("PRIVOKE_CLOUD_MODEL_TARGET", "m.example:50443")]))
                .unwrap(),
            "m.example:50443"
        );
        assert_eq!(model_target(&environment(&[("PRIVOKE_USE_LOCAL_STACK", "true")])).unwrap(), "127.0.0.1:50051");
    }

    #[test]
    fn a_remote_target_without_credentials_never_falls_back_to_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let env = environment(&[("PRIVOKE_CLOUD_TARGET", "model.example:443"), ("PRIVOKE_CREDENTIAL_DIR", dir.path().to_str().unwrap())]);
        let error = ModelEndpoint::from_environment(&env).unwrap_err();
        assert!(matches!(error, ChannelError::Credential(_)), "{error}");
    }

    #[test]
    fn loopback_targets_are_plaintext() {
        for target in ["127.0.0.1:50051", "localhost:50051", "[::1]:50051"] {
            let endpoint = ModelEndpoint::from_environment(&environment(&[("PRIVOKE_CLOUD_TARGET", target)])).unwrap();
            assert!(matches!(endpoint.security, Security::LoopbackPlaintext), "{target}");
        }
    }

    #[test]
    fn forced_tls_applies_to_loopback_and_still_needs_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let env = environment(&[
            ("PRIVOKE_CLOUD_TARGET", "127.0.0.1:50051"),
            ("PRIVOKE_MODEL_STREAMING_TLS", "true"),
            ("PRIVOKE_CREDENTIAL_DIR", dir.path().to_str().unwrap()),
        ]);
        assert!(matches!(ModelEndpoint::from_environment(&env), Err(ChannelError::Credential(_))));
    }

    #[test]
    fn bad_targets_are_refused() {
        for target in ["nohost", ":50051", "host:notaport", "host:99999"] {
            assert!(
                matches!(
                    ModelEndpoint::from_environment(&environment(&[("PRIVOKE_CLOUD_TARGET", target)])),
                    Err(ChannelError::BadTarget(_))
                ),
                "{target}"
            );
        }
    }
}
