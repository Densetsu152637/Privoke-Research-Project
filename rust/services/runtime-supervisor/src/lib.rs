//! The PriVoke workstation runtime supervisor (plan stage 7).
//!
//! It replaces three Python pieces: the native-messaging host (`native_messaging_host.py`), the process supervisor
//! (`runtime_supervisor.py`) and `PrivokeRuntimeControlService` (`main.py`). The gRPC-Web bridge is not rebuilt.
//!
//! | Module | Does |
//! | --- | --- |
//! | [`native_host`], [`pyjson`] | The stdio host: framing, the one supported action, byte-identical replies. |
//! | [`process`], [`confine`] | The runtime child: start, stop, stack switch, status. It dies with the supervisor. |
//! | [`control`] | `PrivokeRuntimeControlService` on plaintext loopback. |
//! | [`channel`], [`fetch`] | Model fetch over mutual TLS with the installation certificate, pin checks, user cache. |
//! | [`credentials`] | `enrol`, `install-cert`, `renew` and `status`, on `privoke_pki::client`. |
//! | [`config`] | `.env` loading, cache and credential locations. |

pub mod channel;
pub mod config;
pub mod confine;
pub mod control;
pub mod credentials;
pub mod fetch;
pub mod native_host;
pub mod process;
pub mod pyjson;

/// A failure of the supervisor's own plumbing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A listener could not be bound.
    #[error("could not bind: {0}")]
    Bind(String),
    /// A server stopped with an error.
    #[error("server error: {0}")]
    Serve(String),
}
