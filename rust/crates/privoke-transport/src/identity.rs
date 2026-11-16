//! Peer identity carried in the certificate's URI SAN, and the roles the authorisation policy reasons about.
//!
//! * `urn:privoke:installation:<uuid>`: one desktop installation, role `consumer`.
//! * `urn:privoke:service:<name>`: a server-side principal, role `publisher`, `trainer` or `runtime` from the registry.
//! * `urn:privoke:reporter`: the shared telemetry credential, role `reporter`.

use std::fmt;

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const INSTALLATION_PREFIX: &str = "urn:privoke:installation:";
const SERVICE_PREFIX: &str = "urn:privoke:service:";
const REPORTER_URN: &str = "urn:privoke:reporter";

/// Who a certificate says its holder is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identity {
    /// A desktop installation, identified by its lowercase UUID.
    Installation(String),
    /// A server-side service principal.
    Service(String),
    /// The shared telemetry reporter credential.
    Reporter,
}

impl Identity {
    /// Parse a PriVoke URN; anything else, including malformed ids, is `None`.
    pub fn parse_urn(urn: &str) -> Option<Self> {
        if let Some(id) = urn.strip_prefix(INSTALLATION_PREFIX) {
            return is_uuid(id).then(|| Self::Installation(id.to_string()));
        }
        if let Some(name) = urn.strip_prefix(SERVICE_PREFIX) {
            return is_service_name(name).then(|| Self::Service(name.to_string()));
        }
        (urn == REPORTER_URN).then_some(Self::Reporter)
    }

    /// The canonical URN.
    pub fn urn(&self) -> String {
        match self {
            Self::Installation(id) => format!("{INSTALLATION_PREFIX}{id}"),
            Self::Service(name) => format!("{SERVICE_PREFIX}{name}"),
            Self::Reporter => REPORTER_URN.to_string(),
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.urn())
    }
}

fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, length)| group.len() == length && group.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
}

fn is_service_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// What a principal may do, assigned by the registry and checked against the per-RPC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// An installation retrieving models.
    Consumer,
    /// A service allowed to publish parameter updates.
    Publisher,
    /// A trainer reading update status.
    Trainer,
    /// A client runtime calling the server side.
    Runtime,
    /// The shared telemetry reporter.
    Reporter,
}

/// An authenticated and registered caller, inserted into every authorised request's extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The certificate identity.
    pub identity: Identity,
    /// The role the registry grants.
    pub role: Role,
}

impl Principal {
    /// Require that a request field naming the caller agrees with the certificate identity.
    ///
    /// Services call this for `consumer_id` and `source_id`. An empty claim is accepted so that clients which
    /// predate certificate identities keep working; a non-empty claim must equal the identity's id (the UUID of an
    /// installation, the name of a service) or its full URN.
    pub fn check_claim(&self, claimed: &str) -> Result<(), tonic::Status> {
        if claimed.is_empty() {
            return Ok(());
        }
        let id = match &self.identity {
            Identity::Installation(id) => id.clone(),
            Identity::Service(name) => name.clone(),
            Identity::Reporter => "reporter".to_string(),
        };
        if claimed == id || claimed == self.identity.urn() {
            Ok(())
        } else {
            Err(tonic::Status::permission_denied("claimed identity differs from the client certificate"))
        }
    }
}

/// Why a certificate carries no usable identity.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The DER does not parse as X.509.
    #[error("certificate is not valid X.509")]
    Unparseable,
    /// No `urn:privoke:` URI SAN.
    #[error("certificate has no PriVoke identity URI SAN")]
    Missing,
    /// More than one `urn:privoke:` URI SAN, so the identity would be ambiguous.
    #[error("certificate carries more than one PriVoke identity")]
    Ambiguous,
    /// A `urn:privoke:` URI whose id is malformed.
    #[error("certificate carries a malformed PriVoke identity")]
    Malformed,
}

/// Extract the single PriVoke identity from a DER certificate.
pub fn identity_from_certificate(der: &[u8]) -> Result<Identity, IdentityError> {
    let (_, certificate) = X509Certificate::from_der(der).map_err(|_| IdentityError::Unparseable)?;
    identity_from_parsed(&certificate)
}

pub(crate) fn identity_from_parsed(certificate: &X509Certificate<'_>) -> Result<Identity, IdentityError> {
    let names = certificate
        .subject_alternative_name()
        .map_err(|_| IdentityError::Unparseable)?
        .map(|extension| extension.value.general_names.clone())
        .unwrap_or_default();
    let mut found = None;
    for name in names {
        let GeneralName::URI(uri) = name else { continue };
        if !uri.starts_with("urn:privoke:") {
            continue;
        }
        let identity = Identity::parse_urn(uri).ok_or(IdentityError::Malformed)?;
        if found.replace(identity).is_some() {
            return Err(IdentityError::Ambiguous);
        }
    }
    found.ok_or(IdentityError::Missing)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn parses_the_three_identity_forms() {
        let id = "123e4567-e89b-42d3-a456-426614174000";
        assert_eq!(Identity::parse_urn(&format!("urn:privoke:installation:{id}")), Some(Identity::Installation(id.into())));
        assert_eq!(Identity::parse_urn("urn:privoke:service:param-update"), Some(Identity::Service("param-update".into())));
        assert_eq!(Identity::parse_urn("urn:privoke:reporter"), Some(Identity::Reporter));
    }

    #[test]
    fn rejects_malformed_identities() {
        for urn in [
            "urn:privoke:installation:",
            "urn:privoke:installation:123E4567-E89B-42D3-A456-426614174000",
            "urn:privoke:installation:not-a-uuid",
            "urn:privoke:service:",
            "urn:privoke:service:Upper",
            "urn:privoke:service:1starts-with-digit",
            "urn:privoke:service:has space",
            "urn:privoke:reporter:extra",
            "urn:other:reporter",
            "https://example.com",
        ] {
            assert_eq!(Identity::parse_urn(urn), None, "{urn}");
        }
    }

    #[test]
    fn claims_must_match_the_certificate() {
        let id = "123e4567-e89b-42d3-a456-426614174000";
        let principal = Principal { identity: Identity::Installation(id.into()), role: Role::Consumer };
        assert!(principal.check_claim("").is_ok());
        assert!(principal.check_claim(id).is_ok());
        assert!(principal.check_claim(&format!("urn:privoke:installation:{id}")).is_ok());
        assert_eq!(principal.check_claim("someone-else").unwrap_err().code(), tonic::Code::PermissionDenied);
    }
}
