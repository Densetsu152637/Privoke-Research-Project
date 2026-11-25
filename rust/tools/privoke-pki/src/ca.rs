//! The operator's certificate authority: key generation, issuing, the ledger and CRL generation.
//!
//! A CA directory holds `ca.key` (owner-only, keep offline), `ca.crt`, `ledger.toml` (every certificate issued, with
//! its revocation) and optionally `reporter/` (the shared telemetry credential). The ledger is what lets `revoke`
//! name an installation instead of a serial number.

use std::path::{Path, PathBuf};

use privoke_transport::identity::Identity;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertificateSigningRequestParams, CertifiedIssuer, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType,
    SerialNumber,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::error::PkiError;
use crate::files::{read_text, write_atomic};

const CLOCK_SKEW: Duration = Duration::minutes(5);

/// How long a certificate lasts and what the clock reads. Tests move `now` into the past to make expired certificates.
#[derive(Debug, Clone, Copy)]
pub struct Validity {
    /// Start of issuance; the certificate is valid from five minutes before this.
    pub now: OffsetDateTime,
    /// Length of validity from `now`.
    pub duration: Duration,
}

impl Validity {
    /// `days` from the current time.
    pub fn days(days: i64) -> Self {
        Self { now: OffsetDateTime::now_utc(), duration: Duration::days(days) }
    }
}

/// A certificate and its private key, PEM encoded.
#[derive(Debug, Clone)]
pub struct KeyedCertificate {
    /// Certificate PEM.
    pub cert_pem: String,
    /// Private key PEM.
    pub key_pem: String,
    /// Serial number as 32 lowercase hex digits.
    pub serial: String,
    /// Expiry as a Unix time.
    pub not_after: i64,
}

/// A certificate issued from a CSR.
#[derive(Debug, Clone)]
pub struct SignedCertificate {
    /// Certificate PEM.
    pub cert_pem: String,
    /// Serial number as 32 lowercase hex digits.
    pub serial: String,
    /// Expiry as a Unix time.
    pub not_after: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Issued {
    urn: String,
    serial: String,
    not_after: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Ledger {
    #[serde(default)]
    crl_number: u64,
    #[serde(default)]
    issued: Vec<Issued>,
}

/// An opened CA directory.
#[derive(Debug)]
pub struct CaDir {
    dir: PathBuf,
}

fn random_serial() -> ([u8; 16], String) {
    let mut bytes = *uuid::Uuid::new_v4().as_bytes();
    bytes[0] = (bytes[0] & 0x7f) | 0x40; // positive, never leading zero
    let hex = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    (bytes, hex)
}

fn serial_from_hex(hex: &str) -> Result<SerialNumber, PkiError> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PkiError::Data(format!("malformed serial {hex:?} in the ledger")));
    }
    let bytes: Result<Vec<u8>, _> = (0..hex.len()).step_by(2).map(|index| u8::from_str_radix(&hex[index..index + 2], 16)).collect();
    Ok(SerialNumber::from_slice(&bytes.map_err(|_| PkiError::Data("malformed serial".into()))?))
}

impl CaDir {
    /// Create a new CA in an empty or absent directory. Refuses to overwrite an existing key.
    pub fn init(dir: &Path, common_name: &str, validity: Validity) -> Result<Self, PkiError> {
        if dir.join("ca.key").exists() {
            return Err(PkiError::refused(format!("{} already holds a CA key", dir.display())));
        }
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(PkiError::certificate)?;
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        params.not_before = validity.now - CLOCK_SKEW;
        params.not_after = validity.now + validity.duration;
        let key = KeyPair::generate().map_err(PkiError::certificate)?;
        let key_pem = key.serialize_pem();
        let issuer = CertifiedIssuer::self_signed(params, key).map_err(PkiError::certificate)?;
        write_atomic(&dir.join("ca.key"), key_pem.as_bytes(), true)?;
        write_atomic(&dir.join("ca.crt"), issuer.pem().as_bytes(), false)?;
        let ca = Self { dir: dir.to_path_buf() };
        ca.write_ledger(&Ledger::default())?;
        Ok(ca)
    }

    /// Open an existing CA directory.
    pub fn open(dir: &Path) -> Result<Self, PkiError> {
        for name in ["ca.key", "ca.crt"] {
            if !dir.join(name).is_file() {
                return Err(PkiError::refused(format!("{} is not a CA directory (missing {name})", dir.display())));
            }
        }
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// The CA certificate, to hand to peers that must trust it.
    pub fn ca_cert_pem(&self) -> Result<String, PkiError> {
        read_text(&self.dir.join("ca.crt"))
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, PkiError> {
        let key = KeyPair::from_pem(&read_text(&self.dir.join("ca.key"))?).map_err(PkiError::certificate)?;
        Issuer::from_ca_cert_pem(&self.ca_cert_pem()?, key).map_err(PkiError::certificate)
    }

    fn read_ledger(&self) -> Result<Ledger, PkiError> {
        let path = self.dir.join("ledger.toml");
        toml::from_str(&read_text(&path)?).map_err(|error| PkiError::Data(format!("{}: {error}", path.display())))
    }

    fn write_ledger(&self, ledger: &Ledger) -> Result<(), PkiError> {
        let text = toml::to_string(ledger).map_err(|error| PkiError::Data(error.to_string()))?;
        write_atomic(&self.dir.join("ledger.toml"), text.as_bytes(), false)
    }

    fn leaf_params(
        urn: Option<&str>,
        eku: ExtendedKeyUsagePurpose,
        validity: Validity,
    ) -> Result<(CertificateParams, [u8; 16], String), PkiError> {
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(PkiError::certificate)?;
        if let Some(urn) = urn {
            params.subject_alt_names.push(SanType::URI(urn.to_string().try_into().map_err(PkiError::certificate)?));
        }
        params.extended_key_usages = vec![eku];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = validity.now - CLOCK_SKEW;
        params.not_after = validity.now + validity.duration;
        let (bytes, hex) = random_serial();
        params.serial_number = Some(SerialNumber::from_slice(&bytes));
        Ok((params, bytes, hex))
    }

    fn record(&self, urn: &str, serial: &str, not_after: i64) -> Result<(), PkiError> {
        let mut ledger = self.read_ledger()?;
        ledger.issued.push(Issued { urn: urn.to_string(), serial: serial.to_string(), not_after, revoked_at: None });
        self.write_ledger(&ledger)
    }

    /// Issue a server certificate for `dns_names` with a fresh key.
    pub fn issue_server(&self, dns_names: &[String], validity: Validity) -> Result<KeyedCertificate, PkiError> {
        if dns_names.is_empty() {
            return Err(PkiError::refused("a server certificate needs at least one DNS name"));
        }
        let (mut params, _, serial) = Self::leaf_params(None, ExtendedKeyUsagePurpose::ServerAuth, validity)?;
        for name in dns_names {
            match name.parse::<std::net::IpAddr>() {
                Ok(address) => params.subject_alt_names.push(SanType::IpAddress(address)),
                Err(_) => params.subject_alt_names.push(SanType::DnsName(name.clone().try_into().map_err(PkiError::certificate)?)),
            }
        }
        let key = KeyPair::generate().map_err(PkiError::certificate)?;
        let certificate = params.signed_by(&key, &self.issuer()?).map_err(PkiError::certificate)?;
        Ok(KeyedCertificate {
            cert_pem: certificate.pem(),
            key_pem: key.serialize_pem(),
            serial,
            not_after: params.not_after.unix_timestamp(),
        })
    }

    /// Issue a certificate for an installation from its CSR.
    ///
    /// The CSR must verify, must carry exactly the one `urn:privoke:installation:<uuid>` URI SAN the operator named with
    /// `expected_installation`, and nothing else in the SAN. The profile is fixed here and ignores whatever else the
    /// CSR asked for: a leaf, `clientAuth` only, digital signature only.
    pub fn sign_installation(&self, csr_pem: &str, expected_installation: &str, validity: Validity) -> Result<SignedCertificate, PkiError> {
        let request =
            CertificateSigningRequestParams::from_pem(csr_pem).map_err(|error| PkiError::refused(format!("CSR rejected: {error}")))?;
        let mut identities = Vec::new();
        for name in &request.params.subject_alt_names {
            match name {
                SanType::URI(uri) => identities.push(uri.as_str().to_string()),
                _ => return Err(PkiError::refused("CSR carries a SAN other than the installation URI")),
            }
        }
        let expected = Identity::Installation(expected_installation.to_string());
        if Identity::parse_urn(&expected.urn()) != Some(expected.clone()) {
            return Err(PkiError::refused(format!("{expected_installation:?} is not a lowercase UUID")));
        }
        if identities != [expected.urn()] {
            return Err(PkiError::refused(format!("CSR identity {identities:?} does not match --installation {expected_installation}")));
        }
        let (params, _, serial) = Self::leaf_params(Some(&expected.urn()), ExtendedKeyUsagePurpose::ClientAuth, validity)?;
        let certificate = params.signed_by(&request.public_key, &self.issuer()?).map_err(PkiError::certificate)?;
        let not_after = params.not_after.unix_timestamp();
        self.record(&expected.urn(), &serial, not_after)?;
        Ok(SignedCertificate { cert_pem: certificate.pem(), serial, not_after })
    }

    /// Issue a service principal certificate with a fresh key. The role is assigned in the registry, not the certificate.
    pub fn issue_service(&self, name: &str, validity: Validity) -> Result<KeyedCertificate, PkiError> {
        let identity = Identity::Service(name.to_string());
        if Identity::parse_urn(&identity.urn()) != Some(identity.clone()) {
            return Err(PkiError::refused(format!("service name {name:?} is malformed")));
        }
        self.issue_keyed(&identity.urn(), validity)
    }

    /// Issue the shared telemetry reporter credential and keep it in `reporter/` for delivery with each enrolment.
    pub fn issue_reporter(&self, validity: Validity) -> Result<KeyedCertificate, PkiError> {
        let issued = self.issue_keyed(&Identity::Reporter.urn(), validity)?;
        write_atomic(&self.dir.join("reporter/reporter.crt"), issued.cert_pem.as_bytes(), false)?;
        write_atomic(&self.dir.join("reporter/reporter.key"), issued.key_pem.as_bytes(), true)?;
        Ok(issued)
    }

    /// The current reporter credential, if one was issued.
    pub fn reporter(&self) -> Result<Option<(String, String)>, PkiError> {
        let cert = self.dir.join("reporter/reporter.crt");
        let key = self.dir.join("reporter/reporter.key");
        if cert.is_file() && key.is_file() { Ok(Some((read_text(&cert)?, read_text(&key)?))) } else { Ok(None) }
    }

    fn issue_keyed(&self, urn: &str, validity: Validity) -> Result<KeyedCertificate, PkiError> {
        let (params, _, serial) = Self::leaf_params(Some(urn), ExtendedKeyUsagePurpose::ClientAuth, validity)?;
        let key = KeyPair::generate().map_err(PkiError::certificate)?;
        let certificate = params.signed_by(&key, &self.issuer()?).map_err(PkiError::certificate)?;
        let not_after = params.not_after.unix_timestamp();
        self.record(urn, &serial, not_after)?;
        Ok(KeyedCertificate { cert_pem: certificate.pem(), key_pem: key.serialize_pem(), serial, not_after })
    }

    /// Mark every certificate issued to `identity` as revoked. Returns how many entries changed. The next CRL lists them.
    pub fn revoke(&self, identity: &Identity, now: OffsetDateTime) -> Result<usize, PkiError> {
        let urn = identity.urn();
        let mut ledger = self.read_ledger()?;
        let mut changed = 0;
        let mut known = false;
        for entry in ledger.issued.iter_mut().filter(|entry| entry.urn == urn) {
            known = true;
            if entry.revoked_at.is_none() {
                entry.revoked_at = Some(now.unix_timestamp());
                changed += 1;
            }
        }
        if !known {
            return Err(PkiError::refused(format!("this CA never issued a certificate to {urn}")));
        }
        self.write_ledger(&ledger)?;
        Ok(changed)
    }

    /// Build a CRL of every revoked certificate, valid for `valid_for`. Publish a fresh one before it lapses: servers
    /// fail handshakes once the CRL's `nextUpdate` has passed.
    pub fn crl_pem(&self, now: OffsetDateTime, valid_for: Duration) -> Result<String, PkiError> {
        let mut ledger = self.read_ledger()?;
        ledger.crl_number += 1;
        let revoked_certs = ledger
            .issued
            .iter()
            .filter_map(|entry| {
                let revoked_at = entry.revoked_at?;
                Some(serial_from_hex(&entry.serial).map(|serial_number| RevokedCertParams {
                    serial_number,
                    revocation_time: OffsetDateTime::from_unix_timestamp(revoked_at).unwrap_or(now),
                    reason_code: Some(RevocationReason::CessationOfOperation),
                    invalidity_date: None,
                }))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let params = CertificateRevocationListParams {
            this_update: now - CLOCK_SKEW,
            next_update: now + valid_for,
            crl_number: SerialNumber::from(ledger.crl_number),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let pem = params.signed_by(&self.issuer()?).map_err(PkiError::certificate)?.pem().map_err(PkiError::certificate)?;
        self.write_ledger(&ledger)?;
        Ok(pem)
    }
}
