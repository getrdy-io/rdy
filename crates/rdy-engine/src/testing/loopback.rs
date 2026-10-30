//! Loopback servers for the network tests (feature `loopback`, M1-090, ADR 0035).
//!
//! These are real sockets on `127.0.0.1` ephemeral ports. They let the facade and the network checks
//! meet the failures that matter on install day without a real network:
//!
//! | Server | What a client sees |
//! | --- | --- |
//! | [`HttpServer`] with a [`TestCa`] leaf | a TLS handshake that validates only when the test CA is trusted; a 200, a 302, another status, a body (with a length or chunked), or bytes that are not HTTP |
//! | [`ConnectProxy`] | `200`, `403`, `407` with Basic or with Negotiate to a `CONNECT` |
//! | [`closed_port`] | connection refused |
//! | [`NeverAccepts`] | a connect that succeeds and a read that never returns |
//! | [`ResetAfterClientHello`] | a TCP reset right after the ClientHello (SNI filtering, legacy servers) |
//! | [`DualStack`] | a live IPv4 address and a dead IPv6 address on the same port |
//!
//! A black hole (a SYN with no answer) cannot exist on loopback, because the kernel completes the
//! handshake itself. It stays a scripted outcome of the Replay `net.json` (`blackhole`, 03 net.egress).
//!
//! # Rules
//!
//! - Every server binds port 0 on loopback and reports the address it got. Nothing here dials out: the
//!   [`ConnectProxy`] tunnels only to loopback addresses or to routes the test names.
//! - A server runs as tasks of the current tokio runtime and stops when its handle is dropped, together
//!   with every connection it accepted. A server never times out by itself, so do not pause the tokio
//!   clock while a test waits on one; let the client side carry the timeout.
//! - Setup that cannot fail in a working test (making a key, a certificate) panics with a message,
//!   like the other helpers of [`crate::testing`]. Binding returns an [`std::io::Result`]. The
//!   connection handlers never panic.
//! - Certificates and keys are made in memory for each test and never written by this module. Nothing
//!   here is for the release binary: the feature is test-only and `cargo tree` for the `rdy` package must
//!   not show it (ADR 0035).

mod ca;
mod http;
mod proxy;
mod raw;

pub use ca::{Leaf, TestCa, Validity};
pub use http::{HttpOptions, HttpServer, Reply, Request};
pub use proxy::{ConnectProxy, ConnectRequest, ProxyMode};
pub use raw::{
    DualStack, NeverAccepts, ResetAfterClientHello, closed_port, ipv6_loopback_available,
};

use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{AbortHandle, JoinSet};

/// A task that ends when this guard is dropped. Connection tasks live in a [`JoinSet`] inside it, so
/// they end with it.
#[derive(Debug)]
struct Guard(AbortHandle);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Accepts connections on `listener` and runs `per_conn` for each, until the returned guard drops.
fn serve<F, Fut>(listener: TcpListener, mut per_conn: F) -> Guard
where
    F: FnMut(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        conns.spawn(per_conn(stream));
                    }
                    // A connection that died in the queue is not the listener's fault: take the next.
                    Err(e) if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::Interrupted
                    ) => {}
                    // Out of descriptors or the like: wait a moment and try again. Stopping would
                    // refuse every later connect with no sign of why.
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                },
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    Guard(task.abort_handle())
}

#[cfg(test)]
mod tests;
