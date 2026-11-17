//! `enrol`, `install-cert`, `renew` and `status`: thin, tested wrappers on `privoke_pki::client`.
//!
//! The private key is generated in the credential directory and never leaves it; only the CSR is public. The
//! operator-side steps (`sign`, `crl`, `revoke`) stay in `privoke-pki`.

use std::path::{Path, PathBuf};

use privoke_pki::PkiError;
use privoke_pki::client::{self, CredentialState, CredentialStatus};
use time::OffsetDateTime;

fn read(path: &Path) -> Result<String, PkiError> {
    privoke_pki::files::read_text(path)
}

/// The text `enrol` and `renew` print.
pub fn describe_enrolment(enrolment: &client::Enrolment) -> String {
    format!(
        "installation {}\nCSR: {}\nCSR fingerprint (confirm with the operator): {}",
        enrolment.installation,
        enrolment.csr_path.display(),
        enrolment.csr_fingerprint
    )
}

/// `enrol`: installation id, key and CSR in `dir`.
pub fn enrol(dir: &Path) -> Result<String, PkiError> {
    std::fs::create_dir_all(dir).map_err(|source| PkiError::Io { path: dir.to_path_buf(), source })?;
    client::enrol(dir).map(|enrolment| describe_enrolment(&enrolment))
}

/// `renew`: a new key and CSR under the same installation id.
pub fn renew(dir: &Path) -> Result<String, PkiError> {
    client::renew(dir).map(|enrolment| describe_enrolment(&enrolment))
}

/// The files `install-cert` takes besides the certificate.
#[derive(Debug, Default, Clone)]
pub struct InstallFiles {
    /// The CA that signed the server certificate.
    pub server_ca: Option<PathBuf>,
    /// The shared telemetry reporter certificate and key.
    pub reporter: Option<(PathBuf, PathBuf)>,
}

/// `install-cert`: check the certificate against the local key and installation id, then store it.
pub fn install_cert(dir: &Path, cert: &Path, files: &InstallFiles, now: OffsetDateTime) -> Result<String, PkiError> {
    let server_ca = files.server_ca.as_deref().map(read).transpose()?;
    let reporter = match &files.reporter {
        Some((cert, key)) => Some((read(cert)?, read(key)?)),
        None => None,
    };
    let installed =
        client::install_cert(dir, &read(cert)?, server_ca.as_deref(), reporter.as_ref().map(|(c, k)| (c.as_str(), k.as_str())), now)?;
    Ok(format!("installed for {}{}", installed.installation, if installed.renewed { " (renewal promoted)" } else { "" }))
}

/// `status`: the credential state and what still works. Reads local files only.
pub fn status(dir: &Path, now: OffsetDateTime) -> Result<CredentialStatus, PkiError> {
    client::status(dir, now)
}

/// Whether `status` should tell the user to renew.
pub fn needs_renewal(status: &CredentialStatus) -> bool {
    matches!(status.state, CredentialState::Expired | CredentialState::ExpiringSoon)
}
