//! The installation side of enrolment: key and CSR generation, certificate installation, renewal and status.
//!
//! This is the logic behind `privoke-supervisor enrol`, `install-cert`, `renew` and `status`; the supervisor calls
//! it, and `privoke-pki` exposes the same commands for operators and tests. The private key never leaves the
//! credential directory.
//!
//! Files in a credential directory:
//!
//! | File | Content | Secret |
//! | --- | --- | --- |
//! | `installation.id` | the installation UUID | no |
//! | `client.key` | active private key | yes |
//! | `client.crt` | active certificate | no |
//! | `client.csr` | CSR awaiting the operator | no |
//! | `client.next.key`, `client.next.csr` | renewal key and CSR | key: yes |
//! | `client.prev.key`, `client.prev.crt` | previous pair, kept until the new one is confirmed | key: yes |
//! | `server-ca.pem` | CA that signed the server certificate | no |
//! | `reporter.crt`, `reporter.key` | shared telemetry credential | key: yes |

use std::path::{Path, PathBuf};

use privoke_contracts::digest::sha256_hex;
use privoke_transport::identity::{Identity, identity_from_certificate};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::PkiError;
use crate::files::{read_text, write_atomic};

/// Certificates last 180 days.
pub const CERTIFICATE_DAYS: i64 = 180;
/// `status` warns from this many days before expiry.
pub const WARNING_DAYS: i64 = 30;

/// What `enrol` and `renew` produce for the operator.
#[derive(Debug, Clone)]
pub struct Enrolment {
    /// The installation UUID, fixed at enrolment and kept at renewal.
    pub installation: String,
    /// The CSR file to send to the operator. It is public.
    pub csr_path: PathBuf,
    /// SHA-256 of the CSR, to confirm out of band with the operator before they sign.
    pub csr_fingerprint: String,
}

/// What `install_cert` did.
#[derive(Debug, Clone)]
pub struct Installed {
    /// The installation UUID.
    pub installation: String,
    /// Expiry as a Unix time.
    pub not_after: i64,
    /// True when the certificate matched the renewal key and replaced the active pair.
    pub renewed: bool,
}

/// How far the installed certificate is from expiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialState {
    /// No certificate has been installed yet.
    NotInstalled,
    /// Valid with more than [`WARNING_DAYS`] left.
    Valid,
    /// Valid, but inside the warning window: renew now.
    ExpiringSoon,
    /// Past `notAfter`: the cloud refuses the handshake until the user renews.
    Expired,
}

/// The result of `status`.
#[derive(Debug, Clone)]
pub struct CredentialStatus {
    /// The installation UUID, when enrolled.
    pub installation: Option<String>,
    /// The state.
    pub state: CredentialState,
    /// Whole days until expiry; negative once expired.
    pub days_left: Option<i64>,
    /// A human message that states what still works.
    pub message: String,
}

fn installation_urn(id: &str) -> String {
    Identity::Installation(id.to_string()).urn()
}

fn csr_for(id: &str, key: &KeyPair) -> Result<(String, Vec<u8>), PkiError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(PkiError::certificate)?;
    params.subject_alt_names.push(SanType::URI(installation_urn(id).try_into().map_err(PkiError::certificate)?));
    let request = params.serialize_request(key).map_err(PkiError::certificate)?;
    Ok((request.pem().map_err(PkiError::certificate)?, request.der().to_vec()))
}

fn read_id(dir: &Path) -> Result<String, PkiError> {
    let id = read_text(&dir.join("installation.id"))?.trim().to_string();
    match Identity::parse_urn(&installation_urn(&id)) {
        Some(Identity::Installation(_)) => Ok(id),
        _ => Err(PkiError::Data(format!("{} holds a malformed installation id", dir.join("installation.id").display()))),
    }
}

/// First enrolment: create the installation id, a fresh key pair and a CSR. Refuses if the directory is enrolled.
pub fn enrol(dir: &Path) -> Result<Enrolment, PkiError> {
    if dir.join("installation.id").exists() {
        return Err(PkiError::refused("this directory is already enrolled; use renew"));
    }
    let id = uuid::Uuid::new_v4().hyphenated().to_string();
    let key = KeyPair::generate().map_err(PkiError::certificate)?;
    let (pem, der) = csr_for(&id, &key)?;
    write_atomic(&dir.join("client.key"), key.serialize_pem().as_bytes(), true)?;
    write_atomic(&dir.join("client.csr"), pem.as_bytes(), false)?;
    write_atomic(&dir.join("installation.id"), format!("{id}\n").as_bytes(), false)?;
    Ok(Enrolment { installation: id, csr_path: dir.join("client.csr"), csr_fingerprint: sha256_hex(&der) })
}

/// Renewal: a new key and CSR under the same UUID. The active pair stays in force until `install_cert` confirms the new one.
pub fn renew(dir: &Path) -> Result<Enrolment, PkiError> {
    let id = read_id(dir).map_err(|_| PkiError::refused("this directory is not enrolled; run enrol first"))?;
    let key = KeyPair::generate().map_err(PkiError::certificate)?;
    let (pem, der) = csr_for(&id, &key)?;
    write_atomic(&dir.join("client.next.key"), key.serialize_pem().as_bytes(), true)?;
    write_atomic(&dir.join("client.next.csr"), pem.as_bytes(), false)?;
    Ok(Enrolment { installation: id, csr_path: dir.join("client.next.csr"), csr_fingerprint: sha256_hex(&der) })
}

struct Checked {
    not_after: i64,
}

/// Check a certificate against the profile and a local private key.
fn check_certificate(cert_pem: &str, key_pem: &str, expected: &Identity, now: OffsetDateTime) -> Result<Checked, PkiError> {
    let der = rustls_pem_der(cert_pem)?;
    let (_, certificate) = X509Certificate::from_der(&der).map_err(|_| PkiError::refused("certificate is not valid X.509"))?;
    let identity = identity_from_certificate(&der).map_err(|error| PkiError::refused(error.to_string()))?;
    if &identity != expected {
        return Err(PkiError::refused(format!("certificate identity {identity} differs from the expected {expected}")));
    }
    let usages = certificate.extended_key_usage().ok().flatten();
    if !usages.is_some_and(|usages| usages.value.client_auth) {
        return Err(PkiError::refused("certificate lacks the clientAuth extended key usage"));
    }
    let validity = certificate.validity();
    let (not_before, not_after) = (validity.not_before.timestamp(), validity.not_after.timestamp());
    if now.unix_timestamp() >= not_after {
        return Err(PkiError::refused("certificate has already expired"));
    }
    if now.unix_timestamp() < not_before - 300 {
        return Err(PkiError::refused("certificate is not yet valid"));
    }
    let key = KeyPair::from_pem(key_pem).map_err(PkiError::certificate)?;
    if rcgen::PublicKeyData::subject_public_key_info(&key) != certificate.public_key().raw {
        return Err(PkiError::refused("certificate does not match the private key"));
    }
    Ok(Checked { not_after })
}

fn rustls_pem_der(pem: &str) -> Result<Vec<u8>, PkiError> {
    CertificateDer::from_pem_slice(pem.as_bytes()).map(|der| der.as_ref().to_vec()).map_err(|_| PkiError::refused("not a PEM certificate"))
}

/// Install a certificate the operator signed, with the server CA and (optionally) the reporter credential.
///
/// The certificate must carry this installation's identity, the `clientAuth` EKU, be inside its validity window and
/// match either the active key or the renewal key. A match with the renewal key promotes it: the active pair moves to
/// `client.prev.*` and the new pair becomes `client.key` and `client.crt`.
pub fn install_cert(
    dir: &Path,
    cert_pem: &str,
    server_ca_pem: Option<&str>,
    reporter: Option<(&str, &str)>,
    now: OffsetDateTime,
) -> Result<Installed, PkiError> {
    let id = read_id(dir)?;
    let expected = Identity::Installation(id.clone());
    let active_key = read_text(&dir.join("client.key"))?;
    let next_path = dir.join("client.next.key");
    let (key_pem, renewed) = match check_certificate(cert_pem, &active_key, &expected, now) {
        Ok(checked) => {
            finish_install(dir, cert_pem, &active_key, false)?;
            copy_extras(dir, server_ca_pem, reporter, now)?;
            return Ok(Installed { installation: id, not_after: checked.not_after, renewed: false });
        }
        Err(first) => {
            if !next_path.is_file() {
                return Err(first);
            }
            (read_text(&next_path)?, true)
        }
    };
    let checked = check_certificate(cert_pem, &key_pem, &expected, now).map_err(|_| {
        PkiError::refused("certificate matches neither the active key nor the renewal key, or fails the profile (identity, EKU, validity)")
    })?;
    finish_install(dir, cert_pem, &key_pem, renewed)?;
    copy_extras(dir, server_ca_pem, reporter, now)?;
    Ok(Installed { installation: id, not_after: checked.not_after, renewed })
}

fn finish_install(dir: &Path, cert_pem: &str, key_pem: &str, promote: bool) -> Result<(), PkiError> {
    if promote {
        // Keep the previous pair until the operator and user have confirmed the new one works.
        if let Ok(old_key) = read_text(&dir.join("client.key")) {
            write_atomic(&dir.join("client.prev.key"), old_key.as_bytes(), true)?;
        }
        if let Ok(old_cert) = read_text(&dir.join("client.crt")) {
            write_atomic(&dir.join("client.prev.crt"), old_cert.as_bytes(), false)?;
        }
        write_atomic(&dir.join("client.key"), key_pem.as_bytes(), true)?;
        let _ = std::fs::remove_file(dir.join("client.next.key"));
        let _ = std::fs::remove_file(dir.join("client.next.csr"));
    }
    write_atomic(&dir.join("client.crt"), cert_pem.as_bytes(), false)
}

fn copy_extras(dir: &Path, server_ca: Option<&str>, reporter: Option<(&str, &str)>, now: OffsetDateTime) -> Result<(), PkiError> {
    if let Some(pem) = server_ca {
        if !pem.contains("-----BEGIN CERTIFICATE-----") {
            return Err(PkiError::refused("server CA file holds no certificate"));
        }
        write_atomic(&dir.join("server-ca.pem"), pem.as_bytes(), false)?;
    }
    if let Some((cert, key)) = reporter {
        check_certificate(cert, key, &Identity::Reporter, now)
            .map_err(|error| PkiError::refused(format!("reporter credential: {error}")))?;
        write_atomic(&dir.join("reporter.crt"), cert.as_bytes(), false)?;
        write_atomic(&dir.join("reporter.key"), key.as_bytes(), true)?;
    }
    Ok(())
}

/// Report the state of the installed certificate. Reads only local files, so it works offline and never touches the
/// network or the cached model package.
pub fn status(dir: &Path, now: OffsetDateTime) -> Result<CredentialStatus, PkiError> {
    let Ok(id) = read_id(dir) else {
        return Ok(CredentialStatus {
            installation: None,
            state: CredentialState::NotInstalled,
            days_left: None,
            message: "Not enrolled. Run enrol, send client.csr to the operator, then install-cert.".into(),
        });
    };
    let Ok(cert) = read_text(&dir.join("client.crt")) else {
        return Ok(CredentialStatus {
            installation: Some(id),
            state: CredentialState::NotInstalled,
            days_left: None,
            message: "Enrolled, waiting for the operator's certificate. Send client.csr and run install-cert.".into(),
        });
    };
    let der = rustls_pem_der(&cert)?;
    let (_, parsed) = X509Certificate::from_der(&der).map_err(|_| PkiError::Data("client.crt is not valid X.509".into()))?;
    let seconds = parsed.validity().not_after.timestamp() - now.unix_timestamp();
    let days = seconds.div_euclid(86_400);
    let (state, message) = if seconds <= 0 {
        (
            CredentialState::Expired,
            "The certificate has expired. Cloud model refresh and telemetry delivery fail at the handshake until you renew. \
             Local inspection keeps using the cached, pin-verified model package."
                .to_string(),
        )
    } else if days < WARNING_DAYS {
        (CredentialState::ExpiringSoon, format!("The certificate expires in {days} days. Run renew and send the new CSR to the operator."))
    } else {
        (CredentialState::Valid, format!("The certificate is valid for {days} more days."))
    };
    Ok(CredentialStatus { installation: Some(id), state, days_left: Some(days), message })
}
