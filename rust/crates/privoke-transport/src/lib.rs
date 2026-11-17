//! In-service authentication, authorisation and limits for the PriVoke Rust servers. This replaces nginx.
//!
//! * [`tls`]: server and client `rustls` configuration and the client-certificate verifier (CA chain, validity window,
//!   CRL, explicit `clientAuth` EKU, PriVoke identity SAN). [`tls::ServerTlsConfig`] cannot be built without a client CA
//!   and a CRL path.
//! * [`reload`]: the live configuration in an `ArcSwap`, with CRL validation and a file watcher.
//! * [`listener`]: the accept loop that completes mutual TLS and hands the verified identity to tonic.
//! * [`authz`]: the registry, the per-RPC [`authz::Policy`], per-peer rate limits and the [`authz::AuthLayer`].
//! * [`limits`]: timeouts, size, connection and rate limits with the nginx defaults.
//! * [`startup`]: the fail-closed argument set every cloud binary uses.
//! * [`client`]: a mutual-TLS gRPC channel.
//!
//! Plaintext exists only behind the `workstation-loopback` cargo feature, as `listener::loopback`, and refuses
//! non-loopback addresses. Cloud builds leave the feature off.
//!
//! # Serving
//!
//! ```ignore
//! let tls = ReloadableTls::load(ServerTlsConfig::new(cert, key, client_ca, crl))?; // fails closed
//! let _reloader = tls.spawn_watcher(Duration::from_secs(60));
//! let auth = AuthLayer::new(policy, SharedRegistry::new(registry), limits.rate);
//! let listener = SecureListener::bind(addr, tls, limits.clone()).await?;
//! secure_server(&limits, auth)
//!     .add_service(MyServer::new(service).max_decoding_message_size(limits.max_message_bytes))
//!     .serve_with_incoming(listener.incoming())
//!     .await?;
//! ```

pub mod authz;
pub mod client;
pub mod error;
pub mod identity;
pub mod limits;
pub mod listener;
pub mod registry;
pub mod reload;
pub mod startup;
pub mod tls;

pub use authz::{AuthLayer, LimiterKey, Policy};
pub use error::TransportError;
pub use identity::{Identity, Principal, Role};
pub use limits::{Limits, RateLimit};
pub use listener::{ConnectionInfo, SecureListener, Transport, secure_server};
pub use registry::{Registry, SharedRegistry};
pub use reload::{ReloadStatus, ReloadableTls};
pub use tls::{ClientTlsConfig, ServerTlsConfig};
