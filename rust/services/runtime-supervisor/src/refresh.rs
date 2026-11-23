//! The refresh loop of the V3 model cache (stage V3-R4b of the V3 routine-training plan).
//!
//! Routine training publishes a new version of a tier now and then (see `docs/runtime/v3-publication.md`). The controller asks
//! model-streaming again every [`V3_PACKAGE_REFRESH_SECONDS`]; a version whose statement the lineage rule admits
//! ([`crate::fetch::LineageAdmission`]) is downloaded, verified and then made current by moving the high-water mark. The
//! worker never has to be told: it reads the cache with [`privoke_contracts::model_cache::ModelCache::select`] on every request,
//! so its snapshot of the model is rebuilt as soon as the mark names another version (and keeps serving the version at the mark
//! while the server is unreachable, so an offline restart serves the high-water version). After each successful refresh the versions
//! the mark has superseded are deleted, never the pinned ORIGINAL and never the version at the mark.
//!
//! Nothing here turns a failure into a decision to allow: a transient failure keeps what is cached, a refusal by the lineage
//! rule keeps it too and is reported, and neither changes the high-water mark.

use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tonic::transport::Channel;

use crate::channel::ModelEndpoint;
use crate::config::{Environment, positive_seconds};
use crate::fetch::{FetchConfig, Fetcher, LineageAdmission};

/// The default of how often the controller asks for a newer version of a V3 model, in seconds.
pub const V3_PACKAGE_REFRESH_SECONDS: u64 = 3600;
/// The environment variable that sets the interval in seconds (a positive number); [`V3_PACKAGE_REFRESH_SECONDS`] when unset.
pub const REFRESH_SECONDS_VARIABLE: &str = "V3_PACKAGE_REFRESH_SECONDS";
/// The environment variable that lists the V3 model ids to keep fresh, separated by commas. Unset or empty: no refresh loop.
pub const REFRESH_MODELS_VARIABLE: &str = "V3_PACKAGE_REFRESH_MODELS";

/// How often to refresh: `V3_PACKAGE_REFRESH_SECONDS`, else [`V3_PACKAGE_REFRESH_SECONDS`].
pub fn refresh_interval(environment: &Environment) -> Result<Duration, String> {
    positive_seconds(environment, REFRESH_SECONDS_VARIABLE, V3_PACKAGE_REFRESH_SECONDS as f64)
}

/// The models to keep fresh: `V3_PACKAGE_REFRESH_MODELS`, each a standard V3 model id (`privoke-v3-<tier>`).
pub fn refresh_models(environment: &Environment) -> Result<Vec<String>, String> {
    let mut models: Vec<String> = Vec::new();
    for model in environment.get(REFRESH_MODELS_VARIABLE).map(String::as_str).unwrap_or_default().split(',') {
        let model = model.trim();
        if model.is_empty() {
            continue;
        }
        if privoke_contracts::v3::standard_pin(model).is_none() {
            return Err(format!("{REFRESH_MODELS_VARIABLE} names {model}, which is not a standard V3 model id."));
        }
        if !models.iter().any(|known| known == model) {
            models.push(model.to_string());
        }
    }
    Ok(models)
}

/// What one refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refreshed {
    /// The version the server serves is the one already current.
    Unchanged {
        /// The manifest SHA-256 now current.
        manifest_sha: String,
    },
    /// A new version was admitted and is current; the worker picks it up on its next request.
    Updated {
        /// The version that was current before, if any.
        from: Option<String>,
        /// The version that is current now.
        to: String,
        /// The superseded versions that were deleted.
        removed: Vec<String>,
    },
    /// The server could not be reached or did not answer in time. Nothing changed.
    Offline(String),
    /// The server's version was refused (the lineage rule, a corrupted package, a legacy answer). Nothing changed.
    Refused(String),
}

/// The refresh of a controller's model cache.
#[derive(Debug)]
pub struct Refresher {
    fetcher: Fetcher,
    admission: LineageAdmission,
    config: FetchConfig,
}

impl Refresher {
    /// A refresher that admits with `admission` into the cache of `config`.
    pub fn new(admission: LineageAdmission, config: FetchConfig) -> Self {
        Self { fetcher: Fetcher::new(), admission, config }
    }

    /// The admission rule (and through it the cache).
    pub fn admission(&self) -> &LineageAdmission {
        &self.admission
    }

    /// Ask for `model_id` once over `channel`, admit what the server serves, make it current and delete what it superseded.
    pub async fn refresh(&self, channel: Channel, target: &str, model_id: &str) -> Refreshed {
        // The cache reads, the advisory lock and the deletions are blocking file work: they run off the async threads.
        let before = {
            let (admission, model) = (self.admission.clone(), model_id.to_string());
            tokio::task::spawn_blocking(move || admission.current_version(&model)).await.ok().flatten()
        };
        match self.fetcher.fetch(channel, target, model_id, &self.admission, &self.config).await {
            Ok(Some(package)) => {
                // The mark has moved (or the pin is current); what it superseded is no longer needed.
                let removed = {
                    let (admission, model) = (self.admission.clone(), package.model_id.clone());
                    tokio::task::spawn_blocking(move || admission.collect_garbage(&model))
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or_default()
                };
                if before.as_deref() == Some(package.pin.as_str()) {
                    Refreshed::Unchanged { manifest_sha: package.pin }
                } else {
                    Refreshed::Updated { from: before, to: package.pin, removed }
                }
            }
            Ok(None) => Refreshed::Refused("the server answered with a legacy model".to_string()),
            Err(error) if error.is_transient() => Refreshed::Offline(error.to_string()),
            Err(error) => Refreshed::Refused(error.to_string()),
        }
    }

    /// Refresh every model of `models` at start-up and then every `interval`, for as long as the task lives. A model that cannot
    /// be refreshed keeps what is cached; the loop never ends because of a failure.
    pub async fn run(&self, endpoint: &ModelEndpoint, models: &[String], interval: Duration, connect_timeout: Duration) {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            // The first tick is immediate: the start-up refresh, which fails harmlessly when offline.
            ticker.tick().await;
            for model in models {
                let outcome = match endpoint.connect(connect_timeout).await {
                    Ok(channel) => self.refresh(channel, &endpoint.target, model).await,
                    Err(error) => Refreshed::Offline(error.to_string()),
                };
                match outcome {
                    Refreshed::Unchanged { .. } => {}
                    Refreshed::Updated { from, to, removed } => {
                        tracing::info!(
                            "model {model}: version {to} is current (was {from:?}); {} superseded version(s) removed",
                            removed.len()
                        );
                    }
                    Refreshed::Offline(reason) => tracing::info!("model {model}: refresh skipped, the server is not reachable ({reason})"),
                    Refreshed::Refused(reason) => tracing::warn!("model {model}: the server's version was refused ({reason})"),
                }
            }
        }
    }
}
