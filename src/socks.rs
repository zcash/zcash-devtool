//! SOCKS5 connector for routing gRPC connections through external proxies.
//!
//! This allows routing lightwalletd connections through SOCKS5 proxies such as:
//! - Tor (for `.onion` addresses and privacy)
//! - Nym mixnet
//! - Any other SOCKS5-compatible proxy

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio_socks::tcp::Socks5Stream;
use tonic::transport::Uri;
use tower::Service;

/// A connector that routes connections through a SOCKS5 proxy.
///
/// Implements `tower::Service<Uri>` for use with tonic's `Endpoint::connect_with_connector()`.
#[derive(Clone)]
pub struct SocksConnector {
    proxy_addr: SocketAddr,
}

impl SocksConnector {
    /// Creates a new SOCKS connector with the given proxy address.
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self { proxy_addr }
    }
}

impl Service<Uri> for SocksConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Stateless connector - always ready
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let proxy_addr = self.proxy_addr;

        Box::pin(async move {
            let host = uri.host().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing host in URI")
            })?;

            let port = uri.port_u16().unwrap_or(443);
            let target = format!("{}:{}", host, port);

            // Connect through SOCKS5 with 30s timeout.
            // DNS resolution happens on the proxy side (critical for .onion addresses).
            let socks_stream = tokio::time::timeout(
                Duration::from_secs(30),
                Socks5Stream::connect(proxy_addr, target.as_str()),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS connection timed out")
            })??;

            // Wrap for tonic/hyper compatibility
            Ok(TokioIo::new(socks_stream.into_inner()))
        })
    }
}
