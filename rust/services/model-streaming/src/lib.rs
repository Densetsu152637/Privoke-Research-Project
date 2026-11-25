//! The PriVoke model-streaming service in Rust (stage 3 of the server rewrite). It replaces
//! `services/model-streaming-service` (Go) with the same artifact contracts and wire output, in-service mutual TLS
//! instead of the nginx ingress, and two listeners:
//!
//! * public: `Health`, `StreamModelParameters`, `GetModelPackage`, `StreamModelAsset` for registered installations;
//! * internal: `GetModelParameters` and `Health` for registered services.
//!
//! Modules mirror the Go files: [`artifact`] (artifact.go), [`contextual`], [`presence`], [`scratch`], [`pretrained`]
//! (the per-architecture validators), [`catalog`] (catalog.go), [`releases`] (standard_v3.go), [`service`] and
//! [`response`] (streaming_server.go), [`config`] (config.go), [`healthcheck`] (health.go) and [`server`] (main.go).
//!
//! [`published`] has no Go counterpart: it serves the trained V3 versions that param-update publishes (stage V3-R3 of the
//! routine-training plan), next to the pinned standard releases.

pub mod artifact;
pub mod catalog;
pub mod config;
pub mod contextual;
pub mod error;
pub mod healthcheck;
pub mod jsonx;
pub mod presence;
pub mod pretrained;
pub mod published;
pub mod releases;
pub mod response;
pub mod scratch;
pub mod server;
pub mod service;
pub mod util;

pub use error::{Error, Result};
