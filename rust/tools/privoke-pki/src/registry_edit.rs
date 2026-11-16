//! Operator edits of the registry file. Every edit re-validates the whole file and writes it atomically, so a running
//! server's reloader never sees a half-written or invalid registry from these tools.

use std::path::Path;

use privoke_transport::identity::Identity;
use privoke_transport::registry::{DenyEntry, InstallationEntry, RegistryFile, ServiceEntry};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::PkiError;
use crate::files::write_atomic;

fn load(path: &Path) -> Result<RegistryFile, PkiError> {
    if path.exists() { RegistryFile::read(path).map_err(|error| PkiError::Data(error.to_string())) } else { Ok(RegistryFile::default()) }
}

fn save(path: &Path, file: &RegistryFile) -> Result<(), PkiError> {
    file.validate().map_err(|error| PkiError::Data(error.to_string()))?;
    let text = file.to_toml().map_err(|error| PkiError::Data(error.to_string()))?;
    write_atomic(path, text.as_bytes(), false)
}

fn rfc3339(unix: i64) -> Result<String, PkiError> {
    OffsetDateTime::from_unix_timestamp(unix).map_err(PkiError::certificate)?.format(&Rfc3339).map_err(PkiError::certificate)
}

/// Register (or refresh the expiry of) an installation. Removing a deny entry is deliberately not done here.
pub fn add_installation(path: &Path, id: &str, label: Option<&str>, expires_unix: i64) -> Result<(), PkiError> {
    let mut file = load(path)?;
    let expires = Some(rfc3339(expires_unix)?);
    match file.installations.iter_mut().find(|entry| entry.id == id) {
        Some(entry) => {
            entry.expires = expires;
            if label.is_some() {
                entry.label = label.map(str::to_string);
            }
        }
        None => file.installations.push(InstallationEntry { id: id.to_string(), label: label.map(str::to_string), expires }),
    }
    save(path, &file)
}

/// Register a service principal with a role.
pub fn add_service(path: &Path, name: &str, role: &str, expires_unix: i64) -> Result<(), PkiError> {
    let mut file = load(path)?;
    let expires = Some(rfc3339(expires_unix)?);
    match file.services.iter_mut().find(|entry| entry.name == name) {
        Some(entry) => {
            entry.role = role.to_string();
            entry.expires = expires;
        }
        None => file.services.push(ServiceEntry { name: name.to_string(), role: role.to_string(), expires }),
    }
    save(path, &file)
}

/// Admit or stop admitting the shared reporter credential.
pub fn set_reporter(path: &Path, admitted: bool) -> Result<(), PkiError> {
    let mut file = load(path)?;
    file.reporter = admitted;
    save(path, &file)
}

/// Put an identity on the deny list (immediate on open connections once the server reloads the file).
pub fn deny(path: &Path, identity: &Identity, reason: Option<&str>) -> Result<(), PkiError> {
    let mut file = load(path)?;
    let urn = identity.urn();
    if !file.denied.iter().any(|entry| entry.urn == urn) {
        file.denied.push(DenyEntry { urn, reason: reason.map(str::to_string) });
    }
    save(path, &file)
}
