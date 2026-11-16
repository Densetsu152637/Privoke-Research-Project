//! The PriVoke workstation runtime controller (plan stages 7 and W4).
//!
//! The browser starts it as a native-messaging host. It owns a sandboxed pool of W1 inference workers and answers the
//! extension over the native-messaging port; it opens no listening socket. The Python native host, supervisor and
//! gRPC-Web bridge stay in the tree as the oracle.
//!
//! | Module | Does |
//! | --- | --- |
//! | [`native_host`] | Native-messaging framing: length-prefixed JSON on stdio. |
//! | [`controller`] | The session: request envelope, methods, fail-closed replies, shutdown with the port. |
//! | [`runtime`] | The worker pool's lifecycle: enable, disable, status, one analysis. |
//! | [`worker`] | The W1 worker behind the W2 pool: frame codec, pool protocol, settings and sandbox policy. |
//! | [`health`] | The model-streaming health check. |
//! | [`channel`], [`fetch`] | Model fetch over mutual TLS with the installation certificate, pin checks, user cache. |
//! | [`credentials`] | `enrol`, `install-cert`, `renew` and `status`, on `privoke_pki::client`. |
//! | [`config`] | `.env` loading, cache and credential locations. |

pub mod channel;
pub mod config;
pub mod controller;
pub mod credentials;
pub mod fetch;
pub mod health;
pub mod native_host;
pub mod runtime;
pub mod worker;
