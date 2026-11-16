//! Fail-closed startup for cloud binaries.
//!
//! A cloud server needs all five of `--cert`, `--key`, `--client-ca`, `--crl` and `--registry`. If any is missing,
//! unreadable, empty or invalid, [`CloudTlsArgs::into_config`] returns an error and the binary must exit non-zero
//! before it binds a socket. There is no flag and no feature in this build that turns authentication off.

use std::path::PathBuf;

use crate::error::TransportError;
use crate::reload::ReloadableTls;
use crate::tls::ServerTlsConfig;

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
    /// The registry file, whose format and reload belong to the registry module of stage 2.
    pub registry_path: PathBuf,
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
        Ok(CloudTransport { tls, registry_path })
    }
}

/// The five flags, for diagnostics.
pub const REQUIRED_FLAGS: [&str; 5] = ["--cert", "--key", "--client-ca", "--crl", "--registry"];
