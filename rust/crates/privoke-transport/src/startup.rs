//! Fail-closed startup for cloud binaries.
//!
//! A cloud server needs all five of `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`. If any is missing,
//! unreadable, empty or invalid (the registry included), [`CloudTlsArgs::into_config`] returns an error and the binary must exit non-zero
//! before it binds a socket. There is no flag and no feature in this build that turns authentication off.

use std::path::PathBuf;

use crate::error::TransportError;
use crate::registry::RegistryFileReloader;
use crate::reload::ReloadableTls;
use crate::tls::{ClientTlsConfig, ServerTlsConfig};

/// The command-line flags every cloud server flattens into its own arguments.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct CloudTlsArgs {
    /// Server certificate chain (PEM).
    #[arg(long)]
    pub cert: Option<PathBuf>,
    /// Server private key (PEM).
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// CA bundle that signs client certificates (PEM).
    #[arg(long)]
    pub client_ca: Option<PathBuf>,
    /// CRL signed by the client CA (PEM). Required even when nothing is revoked.
    #[arg(long)]
    pub crl: Option<PathBuf>,
    /// Identity registry file.
    #[arg(long)]
    pub registry: Option<PathBuf>,
}

/// A validated transport configuration, ready to bind.
#[derive(Debug, Clone)]
pub struct CloudTransport {
    /// The live TLS configuration, validated and ready to hot reload.
    pub tls: ReloadableTls,
    /// The parsed registry file with its reloader; start `registry.spawn_watcher` to follow changes.
    pub registry: RegistryFileReloader,
}

fn required(flag: &str, value: Option<PathBuf>) -> Result<PathBuf, TransportError> {
    let path = value.ok_or_else(|| TransportError::Startup(format!("missing required {flag}")))?;
    let metadata = std::fs::metadata(&path).map_err(|error| TransportError::Startup(format!("{flag} {}: {error}", path.display())))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(TransportError::Startup(format!("{flag} {} is not a non-empty file", path.display())));
    }
    Ok(path)
}

impl CloudTlsArgs {
    /// Validate every input and build the TLS configuration, or refuse.
    pub fn into_config(self) -> Result<CloudTransport, TransportError> {
        let cert = required("--cert", self.cert)?;
        let key = required("--key", self.key)?;
        let client_ca = required("--client-ca", self.client_ca)?;
        let crl = required("--crl", self.crl)?;
        let registry_path = required("--registry", self.registry)?;
        let tls = ReloadableTls::load(ServerTlsConfig::new(cert, key, client_ca, crl))?;
        let registry =
            RegistryFileReloader::load(&registry_path).map_err(|error| TransportError::Startup(format!("--registry: {error}")))?;
        Ok(CloudTransport { tls, registry })
    }
}

/// The five flags, for diagnostics.
pub const REQUIRED_FLAGS: [&str; 5] = ["--cert", "--key", "--client-ca", "--crl", "--registry"];

/// The credentials every outbound channel presents: the service's registered certificate and the server CA
/// (`PRIVOKE_TLS_CA_FILE`, `PRIVOKE_TLS_CERT_FILE`, `PRIVOKE_TLS_KEY_FILE`). A missing or empty file is an error, so a
/// deployment without credentials fails at startup instead of sending plaintext.
///
/// `server_name_variable` names the optional override of the name the server certificate must carry; without it the host of
/// `target` is used. The error is the message to show the operator.
pub fn client_tls_from_lookup(
    target: &str,
    server_name_variable: &str,
    get: impl Fn(&str) -> Option<String>,
) -> Result<ClientTlsConfig, String> {
    let file = |variable: &str| -> Result<PathBuf, String> {
        let path =
            get(variable).filter(|value| !value.trim().is_empty()).map(PathBuf::from).ok_or_else(|| format!("{variable} is required."))?;
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() && metadata.len() > 0 => Ok(path),
            _ => Err(format!("{variable} {} is not a non-empty file.", path.display())),
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
#[allow(clippy::unwrap_used)]
mod client_credentials {
    use super::*;

    #[test]
    fn client_credentials_are_required_files() {
        let directory = tempfile::tempdir().unwrap();
        assert!(client_tls_from_lookup("runtime:50054", "X", |_| None).is_err());
        let file = directory.path().join("c.pem");
        std::fs::write(&file, b"synthetic").unwrap();
        let path = file.to_string_lossy().to_string();
        let credentials = |key: &str| match key {
            "PRIVOKE_TLS_CA_FILE" | "PRIVOKE_TLS_CERT_FILE" | "PRIVOKE_TLS_KEY_FILE" => Some(path.clone()),
            _ => None,
        };
        let spec = client_tls_from_lookup("runtime:50054", "X", credentials).unwrap();
        assert_eq!(spec.server_name, "runtime");
        let named = |key: &str| if key == "N" { Some("custom".to_string()) } else { credentials(key) };
        assert_eq!(client_tls_from_lookup("[::1]:1", "N", named).unwrap().server_name, "custom");
        let empty = directory.path().join("e.pem");
        std::fs::write(&empty, b"").unwrap();
        let empty_path = empty.to_string_lossy().to_string();
        let broken = |key: &str| if key == "PRIVOKE_TLS_KEY_FILE" { Some(empty_path.clone()) } else { credentials(key) };
        assert!(client_tls_from_lookup("runtime:50054", "X", broken).unwrap_err().contains("PRIVOKE_TLS_KEY_FILE"));
    }
}
