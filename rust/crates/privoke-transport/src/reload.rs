//! Hot reload of the server TLS configuration, the CRL included.
//!
//! The active `rustls::ServerConfig` lives in an `ArcSwap`. A reload parses the credential files, validates the CRL
//! (signature by the client CA, `nextUpdate` in the future), builds a complete new configuration and swaps it in
//! atomically, so new handshakes use it while existing connections keep the configuration they were accepted under.
//! A reload that fails for any reason leaves the previous configuration active and records the error.

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use notify::{RecursiveMode, Watcher};
use rustls::ServerConfig;
use tokio::task::JoinHandle;

use crate::error::TransportError;
use crate::tls::{ServerTlsConfig, build_server_config};

/// What the last reloads did, for the `Health` RPC and logs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReloadStatus {
    /// Number of configurations installed, including the first.
    pub generation: u64,
    /// Unix seconds of the last successful install.
    pub last_success_unix: Option<u64>,
    /// The reason the most recent reload was refused, cleared by the next success.
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct Inner {
    spec: ServerTlsConfig,
    config: ArcSwap<ServerConfig>,
    status: Mutex<ReloadStatus>,
    last_digest: Mutex<u64>,
}

/// A cloneable handle to the live server configuration. Construction fails closed.
#[derive(Debug, Clone)]
pub struct ReloadableTls {
    inner: Arc<Inner>,
}

fn digest_of(spec: &ServerTlsConfig) -> u64 {
    let mut hasher = DefaultHasher::new();
    for path in spec.files() {
        path.hash(&mut hasher);
        std::fs::read(path).ok().hash(&mut hasher);
    }
    hasher.finish()
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

impl ReloadableTls {
    /// Build the first configuration. Any problem with the credentials, CA or CRL is an error: a server must not
    /// start without a working client verifier.
    pub fn load(spec: ServerTlsConfig) -> Result<Self, TransportError> {
        let config = build_server_config(&spec)?;
        let digest = digest_of(&spec);
        let status = ReloadStatus { generation: 1, last_success_unix: Some(now_unix()), last_error: None };
        Ok(Self {
            inner: Arc::new(Inner { spec, config: ArcSwap::new(config), status: Mutex::new(status), last_digest: Mutex::new(digest) }),
        })
    }

    /// The configuration new handshakes should use.
    pub fn current(&self) -> Arc<ServerConfig> {
        self.inner.config.load_full()
    }

    /// The reload status.
    pub fn status(&self) -> ReloadStatus {
        self.inner.status.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Re-read every credential file and swap the configuration in, or keep the old one and record why not.
    pub fn reload(&self) -> Result<(), TransportError> {
        let digest = digest_of(&self.inner.spec);
        *self.inner.last_digest.lock().unwrap_or_else(PoisonError::into_inner) = digest;
        let mut status = self.inner.status.lock().unwrap_or_else(PoisonError::into_inner);
        match build_server_config(&self.inner.spec) {
            Ok(config) => {
                self.inner.config.store(config);
                status.generation += 1;
                status.last_success_unix = Some(now_unix());
                status.last_error = None;
                tracing::info!(generation = status.generation, "TLS configuration reloaded");
                Ok(())
            }
            Err(error) => {
                status.last_error = Some(error.to_string());
                tracing::error!(%error, "TLS reload refused; the previous configuration stays active");
                Err(error)
            }
        }
    }

    /// Reload only when a credential file's bytes differ from the last attempt. `None` means nothing changed.
    pub fn reload_if_changed(&self) -> Option<Result<(), TransportError>> {
        let digest = digest_of(&self.inner.spec);
        if digest == *self.inner.last_digest.lock().unwrap_or_else(PoisonError::into_inner) {
            return None;
        }
        Some(self.reload())
    }

    /// Watch the credential directories and also poll, reloading on change. The task ends when the guard is dropped.
    pub fn spawn_watcher(&self, poll: Duration) -> WatcherGuard {
        let this = self.clone();
        let handle = tokio::spawn(async move {
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<()>();
            let directories: BTreeSet<PathBuf> =
                this.inner.spec.files().iter().filter_map(|path| path.parent().map(Path::to_path_buf)).collect();
            let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if event.is_ok() {
                    let _ = sender.send(());
                }
            });
            // Keep the watcher alive for the life of the task; if it cannot start, polling still works.
            let _watcher = match watcher {
                Ok(mut watcher) => {
                    for directory in &directories {
                        if let Err(error) = watcher.watch(directory, RecursiveMode::NonRecursive) {
                            tracing::warn!(%error, directory = %directory.display(), "cannot watch directory; relying on polling");
                        }
                    }
                    Some(watcher)
                }
                Err(error) => {
                    tracing::warn!(%error, "file watcher unavailable; relying on polling");
                    None
                }
            };
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    event = receiver.recv() => {
                        if event.is_none() {
                            return;
                        }
                        // Let a multi-file update (replace CA, then CRL) settle, then drain the burst.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        while receiver.try_recv().is_ok() {}
                    }
                }
                let _ = this.reload_if_changed();
            }
        });
        WatcherGuard(handle)
    }
}

/// Stops the reload task when dropped.
#[derive(Debug)]
pub struct WatcherGuard(JoinHandle<()>);

impl Drop for WatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
