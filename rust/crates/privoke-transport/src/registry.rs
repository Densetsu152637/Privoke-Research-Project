//! The identity registry: who may call at all, with which role, until when, and who is denied.
//!
//! The file is TOML, version 1:
//!
//! ```toml
//! version = 1
//! reporter = true                      # admit the shared telemetry reporter credential
//!
//! [[installation]]
//! id = "123e4567-e89b-42d3-a456-426614174000"
//! label = "alice laptop"               # optional, for operators
//! expires = "2027-05-01T00:00:00Z"     # optional RFC 3339 UTC; absent means no expiry
//!
//! [[service]]
//! name = "param-update"
//! role = "publisher"                   # publisher, trainer or runtime
//!
//! [[deny]]
//! urn = "urn:privoke:installation:123e4567-e89b-42d3-a456-426614174000"
//! reason = "device lost"
//! ```
//!
//! An invalid file is refused whole. The server keeps the registry it had, so a typo cannot lock everyone out or,
//! worse, admit someone by dropping a deny entry.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::identity::{Identity, Principal, Role};
use crate::reload::WatcherGuard;

/// The only supported file version.
pub const REGISTRY_VERSION: u32 = 1;

/// Why the registry refused an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    /// The identity is on the deny list.
    #[error("identity is revoked")]
    Denied,
    /// The identity is not registered.
    #[error("identity is not registered")]
    Unregistered,
    /// The registry entry has expired.
    #[error("registration has expired")]
    Expired,
}

/// Why a registry file was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The file cannot be read.
    #[error("cannot read registry {path}: {reason}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The cause.
        reason: String,
    },
    /// The text is not valid TOML for this schema.
    #[error("registry is not valid: {0}")]
    Parse(String),
    /// A rule of the registry contract failed.
    #[error("registry rejected: {0}")]
    Invalid(String),
}

/// One installation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEntry {
    /// Lowercase UUID from the certificate's `urn:privoke:installation:<uuid>`.
    pub id: String,
    /// Free text for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// RFC 3339 UTC expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// One service principal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEntry {
    /// Service name from `urn:privoke:service:<name>`.
    pub name: String,
    /// `publisher`, `trainer` or `runtime`.
    pub role: String,
    /// RFC 3339 UTC expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// One deny-list entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyEntry {
    /// Full identity URN.
    pub urn: String,
    /// Free text for operators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The registry file as written and edited by the operator tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryFile {
    /// Must be [`REGISTRY_VERSION`].
    pub version: u32,
    /// Admit the shared telemetry reporter credential.
    #[serde(default)]
    pub reporter: bool,
    /// Registered installations.
    #[serde(default, rename = "installation", skip_serializing_if = "Vec::is_empty")]
    pub installations: Vec<InstallationEntry>,
    /// Registered service principals.
    #[serde(default, rename = "service", skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceEntry>,
    /// Denied identities.
    #[serde(default, rename = "deny", skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<DenyEntry>,
}

impl Default for RegistryFile {
    fn default() -> Self {
        Self { version: REGISTRY_VERSION, reporter: false, installations: Vec::new(), services: Vec::new(), denied: Vec::new() }
    }
}

impl RegistryFile {
    /// Parse and validate TOML text.
    pub fn from_toml(text: &str) -> Result<Self, RegistryError> {
        let file: Self = toml::from_str(text).map_err(|error| RegistryError::Parse(error.to_string()))?;
        file.validate()?;
        Ok(file)
    }

    /// Read, parse and validate a file.
    pub fn read(path: &Path) -> Result<Self, RegistryError> {
        let text =
            std::fs::read_to_string(path).map_err(|error| RegistryError::Read { path: path.to_path_buf(), reason: error.to_string() })?;
        Self::from_toml(&text)
    }

    /// Render as TOML.
    pub fn to_toml(&self) -> Result<String, RegistryError> {
        toml::to_string(self).map_err(|error| RegistryError::Parse(error.to_string()))
    }

    /// Check every rule without building the lookup tables.
    pub fn validate(&self) -> Result<(), RegistryError> {
        self.to_registry().map(|_| ())
    }

    /// Build the in-memory registry.
    pub fn to_registry(&self) -> Result<Registry, RegistryError> {
        let invalid = |message: String| RegistryError::Invalid(message);
        if self.version != REGISTRY_VERSION {
            return Err(invalid(format!("unsupported version {}", self.version)));
        }
        let mut registry = Registry::new();
        registry.reporter = self.reporter;
        for entry in &self.installations {
            if !matches!(Identity::parse_urn(&format!("urn:privoke:installation:{}", entry.id)), Some(Identity::Installation(_))) {
                return Err(invalid(format!("installation id {:?} is not a lowercase UUID", entry.id)));
            }
            let expiry = parse_expiry(entry.expires.as_deref())?;
            if registry.installations.insert(entry.id.clone(), expiry).is_some() {
                return Err(invalid(format!("duplicate installation {}", entry.id)));
            }
        }
        for entry in &self.services {
            if !matches!(Identity::parse_urn(&format!("urn:privoke:service:{}", entry.name)), Some(Identity::Service(_))) {
                return Err(invalid(format!("service name {:?} is malformed", entry.name)));
            }
            let role = match entry.role.as_str() {
                "publisher" => Role::Publisher,
                "trainer" => Role::Trainer,
                "runtime" => Role::Runtime,
                other => return Err(invalid(format!("service {} has unknown role {other:?}", entry.name))),
            };
            let expiry = parse_expiry(entry.expires.as_deref())?;
            if registry.services.insert(entry.name.clone(), (role, expiry)).is_some() {
                return Err(invalid(format!("duplicate service {}", entry.name)));
            }
        }
        for entry in &self.denied {
            let identity =
                Identity::parse_urn(&entry.urn).ok_or_else(|| invalid(format!("deny entry {:?} is not a PriVoke identity", entry.urn)))?;
            registry.denied.insert(identity);
        }
        Ok(registry)
    }
}

fn parse_expiry(text: Option<&str>) -> Result<Option<i64>, RegistryError> {
    let Some(text) = text else { return Ok(None) };
    let parsed = OffsetDateTime::parse(text, &Rfc3339).map_err(|error| RegistryError::Invalid(format!("expiry {text:?}: {error}")))?;
    if parsed.offset().whole_seconds() != 0 {
        return Err(RegistryError::Invalid(format!("expiry {text:?} must be UTC")));
    }
    Ok(Some(parsed.unix_timestamp()))
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
}

/// Who may call at all, and with which role.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    installations: HashMap<String, Option<i64>>,
    services: HashMap<String, (Role, Option<i64>)>,
    denied: HashSet<Identity>,
    reporter: bool,
}

impl Registry {
    /// An empty registry that admits nobody.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read and validate a registry file.
    pub fn load(path: &Path) -> Result<Self, RegistryError> {
        RegistryFile::read(path)?.to_registry()
    }

    /// Register an installation (role `consumer`) with no expiry.
    #[must_use]
    pub fn with_installation(mut self, uuid: &str) -> Self {
        self.installations.insert(uuid.to_string(), None);
        self
    }

    /// Register an installation until a Unix time.
    #[must_use]
    pub fn with_installation_until(mut self, uuid: &str, expires_unix: i64) -> Self {
        self.installations.insert(uuid.to_string(), Some(expires_unix));
        self
    }

    /// Register a service principal with its role.
    #[must_use]
    pub fn with_service(mut self, name: &str, role: Role) -> Self {
        self.services.insert(name.to_string(), (role, None));
        self
    }

    /// Admit the shared telemetry reporter credential.
    #[must_use]
    pub fn with_reporter(mut self) -> Self {
        self.reporter = true;
        self
    }

    /// Put an identity on the deny list; it wins over registration.
    #[must_use]
    pub fn deny(mut self, identity: Identity) -> Self {
        self.denied.insert(identity);
        self
    }

    /// Resolve an authenticated identity to a principal now.
    pub fn resolve(&self, identity: &Identity) -> Result<Principal, Denial> {
        self.resolve_at(identity, now_unix())
    }

    /// Resolve an authenticated identity to a principal at a Unix time.
    pub fn resolve_at(&self, identity: &Identity, now: i64) -> Result<Principal, Denial> {
        if self.denied.contains(identity) {
            return Err(Denial::Denied);
        }
        let (role, expiry) = match identity {
            Identity::Installation(id) => self.installations.get(id).map(|expiry| (Role::Consumer, *expiry)),
            Identity::Service(name) => self.services.get(name).copied(),
            Identity::Reporter => self.reporter.then_some((Role::Reporter, None)),
        }
        .ok_or(Denial::Unregistered)?;
        if expiry.is_some_and(|limit| now >= limit) {
            return Err(Denial::Expired);
        }
        Ok(Principal { identity: identity.clone(), role })
    }
}

/// A registry that can be replaced atomically while requests are in flight.
#[derive(Debug, Clone)]
pub struct SharedRegistry(Arc<ArcSwap<Registry>>);

impl SharedRegistry {
    /// Wrap an initial registry.
    pub fn new(registry: Registry) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(registry)))
    }

    /// The current registry.
    pub fn load(&self) -> Arc<Registry> {
        self.0.load_full()
    }

    /// Replace the registry; the next request sees it, including on connections that are already open.
    pub fn replace(&self, registry: Registry) {
        self.0.store(Arc::new(registry));
    }
}

/// What the registry file reloads did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegistryStatus {
    /// Registries installed from the file, including the first.
    pub generation: u64,
    /// Why the most recent reload was refused, cleared by the next success.
    pub last_error: Option<String>,
}

/// Reloads a registry file into a [`SharedRegistry`] when its bytes change. An invalid file is refused and the
/// previous registry stays in force.
#[derive(Debug, Clone)]
pub struct RegistryFileReloader {
    path: PathBuf,
    shared: SharedRegistry,
    state: Arc<Mutex<(RegistryStatus, Option<Vec<u8>>)>>,
}

impl RegistryFileReloader {
    /// Load the file now and return the reloader. A first load that fails is an error: servers must not start with
    /// no registry.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let path = path.into();
        let bytes = std::fs::read(&path).map_err(|error| RegistryError::Read { path: path.clone(), reason: error.to_string() })?;
        let registry = RegistryFile::from_toml(&String::from_utf8_lossy(&bytes))?.to_registry()?;
        let state = (RegistryStatus { generation: 1, last_error: None }, Some(bytes));
        Ok(Self { path, shared: SharedRegistry::new(registry), state: Arc::new(Mutex::new(state)) })
    }

    /// The registry handle to give to the authorisation layer.
    pub fn registry(&self) -> SharedRegistry {
        self.shared.clone()
    }

    /// The reload status.
    pub fn status(&self) -> RegistryStatus {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0.clone()
    }

    /// Re-read the file if its bytes changed since the last attempt.
    pub fn reload_if_changed(&self) {
        let bytes = std::fs::read(&self.path).ok();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.1 == bytes {
            return;
        }
        let outcome = match &bytes {
            None => Err(RegistryError::Read { path: self.path.clone(), reason: "file is missing or unreadable".into() }),
            Some(bytes) => std::str::from_utf8(bytes)
                .map_err(|_| RegistryError::Parse("registry is not UTF-8".into()))
                .and_then(RegistryFile::from_toml)
                .and_then(|file| file.to_registry()),
        };
        state.1 = bytes;
        match outcome {
            Ok(registry) => {
                self.shared.replace(registry);
                state.0.generation += 1;
                state.0.last_error = None;
                tracing::info!(generation = state.0.generation, "registry reloaded");
            }
            Err(error) => {
                state.0.last_error = Some(error.to_string());
                tracing::error!(%error, "registry reload refused; the previous registry stays active");
            }
        }
    }

    /// Poll the file until the guard is dropped.
    pub fn spawn_watcher(&self, poll: Duration) -> WatcherGuard {
        let this = self.clone();
        WatcherGuard::new(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                this.reload_if_changed();
            }
        }))
    }
}
