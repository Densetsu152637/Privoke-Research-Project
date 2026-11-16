//! Accepting connections: TCP accept, a per-connection TLS handshake against the live configuration, connection caps,
//! and the connect info that lets the authorisation layer see the verified identity.
//!
//! tonic's built-in TLS cannot swap its configuration, so each listener runs its own accept loop and builds a
//! `TlsAcceptor` from the current `ReloadableTls` configuration for every connection.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::transport::server::Connected;
use tower::layer::util::{Identity as LayerIdentity, Stack};

use crate::authz::AuthLayer;
use crate::error::TransportError;
use crate::identity::{Identity, identity_from_certificate};
use crate::limits::Limits;
use crate::reload::ReloadableTls;

/// How a connection was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// TLS with a verified client certificate.
    MutualTls,
    /// Plaintext on the workstation loopback interface. Never carries an identity.
    LoopbackPlaintext,
}

/// What the accept loop knows about a connection, available to the authorisation layer as a request extension.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The remote socket address.
    pub peer_addr: Option<SocketAddr>,
    /// The identity from the verified client certificate; always `None` for plaintext loopback.
    pub identity: Option<Identity>,
    /// The transport.
    pub transport: Transport,
}

#[derive(Debug)]
struct Gate {
    max_total: usize,
    max_per_ip: usize,
    state: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

impl Gate {
    fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<Permit> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let per_ip = state.1.get(&ip).copied().unwrap_or(0);
        if state.0 >= self.max_total || per_ip >= self.max_per_ip {
            return None;
        }
        state.0 += 1;
        state.1.insert(ip, per_ip + 1);
        Some(Permit { gate: self.clone(), ip })
    }
}

/// A connection slot, released when the connection is dropped.
#[derive(Debug)]
struct Permit {
    gate: Arc<Gate>,
    ip: IpAddr,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.0 = state.0.saturating_sub(1);
        if let Some(count) = state.1.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.1.remove(&self.ip);
            }
        }
    }
}

/// An accepted, mutually authenticated connection.
#[derive(Debug)]
pub struct TlsConnection {
    stream: TlsStream<TcpStream>,
    info: ConnectionInfo,
    _permit: Permit,
}

impl AsyncRead for TlsConnection {
    fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl Connected for TlsConnection {
    type ConnectInfo = ConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

/// A TCP listener that completes a mutual-TLS handshake for every connection.
#[derive(Debug)]
pub struct SecureListener {
    listener: TcpListener,
    tls: ReloadableTls,
    limits: Limits,
}

impl SecureListener {
    /// Bind `address`. The TLS configuration is already validated, so a listener cannot exist without a verifier.
    pub async fn bind(address: SocketAddr, tls: ReloadableTls, limits: Limits) -> Result<Self, TransportError> {
        Ok(Self { listener: TcpListener::bind(address).await?, tls, limits })
    }

    /// The bound address, useful with port 0.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.listener.local_addr()?)
    }

    /// Start accepting and return the stream of authenticated connections for `Server::serve_with_incoming`.
    ///
    /// Dropping the stream stops the accept loop. Handshakes run concurrently and are bounded by the handshake
    /// timeout, so a slow client cannot block others. Connections beyond the global or per-IP cap are closed before
    /// any TLS work.
    pub fn incoming(self) -> impl Stream<Item = Result<TlsConnection, io::Error>> + Send + 'static {
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let gate = Arc::new(Gate {
            max_total: self.limits.max_connections,
            max_per_ip: self.limits.max_connections_per_ip,
            state: Mutex::default(),
        });
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    () = sender.closed() => return,
                    accepted = self.listener.accept() => accepted,
                };
                let (tcp, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::warn!(%error, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Some(permit) = gate.acquire(peer.ip()) else {
                    tracing::debug!("connection cap reached; closing");
                    continue;
                };
                let acceptor = TlsAcceptor::from(self.tls.current());
                let timeout = self.limits.handshake_timeout;
                let sender = sender.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(timeout, acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => {
                            let identity = stream
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|chain| chain.first())
                                .and_then(|certificate| identity_from_certificate(certificate.as_ref()).ok());
                            // The verifier already required an identity; a missing one here is a bug, so fail closed.
                            if identity.is_none() {
                                tracing::error!("verified connection without an identity; closing");
                                return;
                            }
                            let info = ConnectionInfo { peer_addr: Some(peer), identity, transport: Transport::MutualTls };
                            let _ = sender.send(Ok(TlsConnection { stream, info, _permit: permit })).await;
                        }
                        Ok(Err(error)) => tracing::debug!(%error, "TLS handshake refused"),
                        Err(_) => tracing::debug!("TLS handshake timed out"),
                    }
                });
            }
        });
        ReceiverStream::new(receiver)
    }
}

/// A tonic server with the listener limits and the authorisation layer applied. Add services and call
/// `serve_with_incoming(listener.incoming())` (or the `_shutdown` variant) on the router.
///
/// Apply `limits.max_message_bytes` to each generated service with `max_decoding_message_size`.
pub fn secure_server(limits: &Limits, auth: AuthLayer) -> Server<Stack<AuthLayer, LayerIdentity>> {
    limits.apply(Server::builder()).layer(auth)
}

/// Plaintext on the loopback interface, for the workstation supervisor and tests only.
#[cfg(feature = "workstation-loopback")]
pub mod loopback {
    use super::*;

    /// A listener that refuses to bind, or accept from, anything but loopback.
    #[derive(Debug)]
    pub struct LoopbackListener {
        listener: TcpListener,
    }

    impl LoopbackListener {
        /// Bind a loopback address; any other address is an error.
        pub async fn bind(address: SocketAddr) -> Result<Self, TransportError> {
            if !address.ip().is_loopback() {
                return Err(TransportError::NotLoopback(address));
            }
            Ok(Self { listener: TcpListener::bind(address).await? })
        }

        /// The bound address.
        pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
            Ok(self.listener.local_addr()?)
        }

        /// Accepted connections, never carrying an identity.
        pub fn incoming(self) -> impl Stream<Item = Result<LoopbackConnection, io::Error>> + Send + 'static {
            futures_util::stream::unfold(self.listener, |listener| async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) if peer.ip().is_loopback() => {
                            let info = ConnectionInfo { peer_addr: Some(peer), identity: None, transport: Transport::LoopbackPlaintext };
                            return Some((Ok(LoopbackConnection { stream, info }), listener));
                        }
                        Ok(_) => continue,
                        Err(error) => return Some((Err(error), listener)),
                    }
                }
            })
        }
    }

    /// A plaintext loopback connection.
    #[derive(Debug)]
    pub struct LoopbackConnection {
        stream: TcpStream,
        info: ConnectionInfo,
    }

    impl AsyncRead for LoopbackConnection {
        fn poll_read(mut self: Pin<&mut Self>, context: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for LoopbackConnection {
        fn poll_write(mut self: Pin<&mut Self>, context: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(context, data)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(context)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(context)
        }
    }

    impl Connected for LoopbackConnection {
        type ConnectInfo = ConnectionInfo;

        fn connect_info(&self) -> Self::ConnectInfo {
            self.info.clone()
        }
    }
}
