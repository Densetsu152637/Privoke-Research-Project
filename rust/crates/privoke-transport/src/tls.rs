//! Server and client TLS configuration, the client-certificate verifier and CRL validation.
//!
//! The server verifier requires, in this order: a certificate that chains to the client CA, is inside its validity
//! window and is not listed in a current CRL signed by that CA (all enforced by `rustls`' `WebPkiClientVerifier`);
//! the `clientAuth` extended key usage to be present and explicit; and exactly one well-formed `urn:privoke:` URI SAN.
//! Anonymous clients are refused at the handshake.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ServerConfig, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;

use crate::error::TransportError;
use crate::identity::identity_from_parsed;

/// Where a server finds its credentials. There is deliberately no constructor without a client CA and a CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTlsConfig {
    cert: PathBuf,
    key: PathBuf,
    client_ca: PathBuf,
    crl: PathBuf,
}

impl ServerTlsConfig {
    /// Every argument is required: the server certificate chain, its key, the client CA bundle and the CRL file.
    pub fn new(cert: impl Into<PathBuf>, key: impl Into<PathBuf>, client_ca: impl Into<PathBuf>, crl: impl Into<PathBuf>) -> Self {
        Self { cert: cert.into(), key: key.into(), client_ca: client_ca.into(), crl: crl.into() }
    }

    /// The files whose contents decide the configuration, for change detection.
    pub fn files(&self) -> [&Path; 4] {
        [&self.cert, &self.key, &self.client_ca, &self.crl]
    }
}

/// How a client authenticates itself and the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTlsConfig {
    /// CA bundle that must have signed the server certificate.
    pub server_ca: PathBuf,
    /// Client certificate chain and key, absent only in negative tests and for plain-server probes.
    pub identity: Option<(PathBuf, PathBuf)>,
    /// The name the server certificate must carry.
    pub server_name: String,
}

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| TransportError::pem(path, error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransportError::pem(path, error.to_string()))?;
    if certificates.is_empty() {
        return Err(TransportError::pem(path, "no certificate found"));
    }
    Ok(certificates)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| TransportError::pem(path, error.to_string()))
}

fn read_crls(path: &Path) -> Result<Vec<CertificateRevocationListDer<'static>>, TransportError> {
    CertificateRevocationListDer::pem_file_iter(path)
        .map_err(|error| TransportError::pem(path, error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransportError::pem(path, error.to_string()))
}

fn root_store(certificates: &[CertificateDer<'static>], path: &Path) -> Result<RootCertStore, TransportError> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate.clone()).map_err(|error| TransportError::pem(path, format!("unusable CA certificate: {error}")))?;
    }
    Ok(roots)
}

/// Parse every CRL, require a signature by one of the CA certificates and a `nextUpdate` in the future.
fn validate_crls(crls: &[CertificateRevocationListDer<'static>], authorities: &[CertificateDer<'static>]) -> Result<(), TransportError> {
    if crls.is_empty() {
        return Err(TransportError::Crl("no CRL in the CRL file; publish a signed, possibly empty, CRL".into()));
    }
    let parsed_authorities: Vec<X509Certificate<'_>> =
        authorities.iter().filter_map(|der| X509Certificate::from_der(der.as_ref()).ok().map(|(_, parsed)| parsed)).collect();
    if parsed_authorities.is_empty() {
        return Err(TransportError::Crl("client CA bundle holds no parseable certificate".into()));
    }
    let now = ASN1Time::now();
    for der in crls {
        let (_, crl) =
            CertificateRevocationList::from_der(der.as_ref()).map_err(|error| TransportError::Crl(format!("malformed CRL: {error}")))?;
        let next_update = crl.next_update().ok_or_else(|| TransportError::Crl("CRL has no nextUpdate".into()))?;
        if next_update <= now {
            return Err(TransportError::Crl("CRL is stale (nextUpdate is in the past)".into()));
        }
        if !parsed_authorities.iter().any(|authority| crl.verify_signature(authority.public_key()).is_ok()) {
            return Err(TransportError::Crl("CRL is not signed by the client CA".into()));
        }
    }
    Ok(())
}

/// Build the rustls server configuration from the files, refusing anything unsafe.
pub fn build_server_config(spec: &ServerTlsConfig) -> Result<Arc<ServerConfig>, TransportError> {
    let chain = read_certificates(&spec.cert)?;
    let key = read_key(&spec.key)?;
    let authorities = read_certificates(&spec.client_ca)?;
    let crls = read_crls(&spec.crl)?;
    validate_crls(&crls, &authorities)?;

    let roots = Arc::new(root_store(&authorities, &spec.client_ca)?);
    let webpki = WebPkiClientVerifier::builder_with_provider(roots, provider())
        .with_crls(crls)
        // Client certificates are issued directly by the client CA; no intermediates need their own CRL.
        .only_check_end_entity_revocation()
        // A CRL that has gone stale since it was loaded fails every handshake rather than being trusted.
        .enforce_revocation_expiration()
        .build()
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    let verifier = Arc::new(PrivokeClientVerifier { inner: webpki });

    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::Tls(error.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|error| TransportError::Tls(error.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    // A resumed session would skip client-certificate and CRL verification, so a revoked client could resume.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

/// Build the rustls client configuration.
pub fn build_client_config(spec: &ClientTlsConfig) -> Result<Arc<ClientConfig>, TransportError> {
    let roots = root_store(&read_certificates(&spec.server_ca)?, &spec.server_ca)?;
    let builder = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::Tls(error.to_string()))?
        .with_root_certificates(roots);
    let mut config = match &spec.identity {
        Some((cert, key)) => builder
            .with_client_auth_cert(read_certificates(cert)?, read_key(key)?)
            .map_err(|error| TransportError::Tls(error.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

/// `WebPkiClientVerifier` plus the two checks it leaves optional: an explicit `clientAuth` EKU and a PriVoke identity.
struct PrivokeClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
}

impl fmt::Debug for PrivokeClientVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrivokeClientVerifier").finish_non_exhaustive()
    }
}

fn refuse(reason: &str) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(RefusedCertificate(reason.to_string())))))
}

#[derive(Debug)]
struct RefusedCertificate(String);

impl fmt::Display for RefusedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RefusedCertificate {}

impl ClientCertVerifier for PrivokeClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        let (_, certificate) =
            X509Certificate::from_der(end_entity.as_ref()).map_err(|_| refuse("client certificate is not valid X.509"))?;
        let usages = certificate
            .extended_key_usage()
            .map_err(|_| refuse("client certificate has a malformed extended key usage"))?
            .ok_or_else(|| refuse("client certificate lacks the clientAuth extended key usage"))?;
        if !usages.value.client_auth {
            return Err(refuse("client certificate is not valid for client authentication"));
        }
        identity_from_parsed(&certificate).map_err(|error| refuse(&error.to_string()))?;
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
