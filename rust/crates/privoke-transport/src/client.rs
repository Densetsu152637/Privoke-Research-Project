//! A gRPC channel over mutual TLS built from the same rustls configuration helpers as the server.

use std::io;

use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::error::TransportError;
use crate::tls::{ClientTlsConfig, build_client_config};

/// Connect to `address` (`host:port`) over TLS, presenting the client identity if the configuration has one.
///
/// TLS 1.3 reports a refused client certificate when the connection is first used rather than at connect time, so a
/// successful return does not prove the server accepted the identity; the first RPC does.
pub async fn connect(address: &str, spec: &ClientTlsConfig) -> Result<Channel, TransportError> {
    let config = build_client_config(spec)?;
    let name = ServerName::try_from(spec.server_name.clone()).map_err(|error| TransportError::Tls(error.to_string()))?;
    let connector = TlsConnector::from(config);
    let target = address.to_string();
    let service = tower::service_fn(move |_uri: Uri| {
        let connector = connector.clone();
        let name = name.clone();
        let target = target.clone();
        async move {
            let tcp = TcpStream::connect(&target).await?;
            let stream = connector.connect(name, tcp).await?;
            Ok::<_, io::Error>(TokioIo::new(stream))
        }
    });
    let endpoint = Endpoint::from_shared(format!("http://{address}")).map_err(|error| TransportError::Tls(error.to_string()))?;
    endpoint.connect_with_connector(service).await.map_err(|error| TransportError::Tls(error.to_string()))
}
