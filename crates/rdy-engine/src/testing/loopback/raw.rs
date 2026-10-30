//! The servers that are not HTTP: a closed port, a listener that never accepts, a reset after the
//! ClientHello and the dual-stack case.

use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use super::http::{HttpOptions, HttpServer};
use super::{Guard, serve};

/// An address on loopback where nothing listens, so a connect is refused. The port was free a moment
/// ago and is given back before this returns; another process could take it, which a test on a shared
/// machine accepts.
///
/// # Errors
///
/// If no socket can be bound.
pub async fn closed_port() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    listener.local_addr()
}

/// Whether this machine has IPv6 on loopback. Some containers do not. A test of the dual-stack case
/// expects a refused connect when it does and any failure when it does not.
pub async fn ipv6_loopback_available() -> bool {
    TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.is_ok()
}

/// A listener that never calls `accept`. The kernel completes the handshake for the first connections
/// itself, so a connect succeeds, a write succeeds and a read never returns. It is not a black hole:
/// that needs an unanswered SYN, which loopback cannot give (03 net.egress).
#[derive(Debug)]
pub struct NeverAccepts {
    addr: SocketAddr,
    _listener: TcpListener,
}

impl NeverAccepts {
    /// Starts the listener on `127.0.0.1:0`.
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        Ok(Self {
            addr: listener.local_addr()?,
            _listener: listener,
        })
    }

    /// The address the listener holds.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// A server that reads the ClientHello and then resets the connection (RST, not FIN). It is what SNI
/// filtering and a legacy server that speaks only old TLS look like to a client (03 net.egress,
/// `reset_after_hello`).
#[derive(Debug)]
pub struct ResetAfterClientHello {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    hello_bytes: Arc<AtomicUsize>,
    _guard: Guard,
}

impl ResetAfterClientHello {
    /// Starts the server on `127.0.0.1:0`.
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let hello_bytes = Arc::new(AtomicUsize::new(0));
        let (a, h) = (Arc::clone(&accepted), Arc::clone(&hello_bytes));
        let guard = serve(listener, move |stream| {
            reset_after_hello(stream, Arc::clone(&a), Arc::clone(&h))
        });
        Ok(Self {
            addr,
            accepted,
            hello_bytes,
            _guard: guard,
        })
    }

    /// The address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connections accepted.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Bytes of ClientHello read before the reset.
    #[must_use]
    pub fn hello_bytes(&self) -> usize {
        self.hello_bytes.load(Ordering::SeqCst)
    }
}

/// Reads one TLS record (5 byte header, then its body) and closes with a zero linger, which makes the
/// operating system send a reset. `socket2` sets the linger, because the tokio method is deprecated.
async fn reset_after_hello(
    mut stream: TcpStream,
    accepted: Arc<AtomicUsize>,
    hello_bytes: Arc<AtomicUsize>,
) {
    accepted.fetch_add(1, Ordering::SeqCst);
    let mut header = [0u8; 5];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let mut read = header.len();
    if header[0] == 0x16 {
        let body = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut left = body;
        let mut buf = [0u8; 1024];
        while left > 0 {
            let want = left.min(buf.len());
            match stream.read(buf.get_mut(..want).unwrap_or_default()).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    left -= n;
                    read += n;
                }
            }
        }
    }
    hello_bytes.fetch_add(read, Ordering::SeqCst);
    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
    drop(stream);
}

/// A live IPv4 address and a dead IPv6 address on the same port. A client that tries IPv6 first is
/// refused (or cannot route, on a machine with no IPv6), then falls through to IPv4 and gets its
/// answer (03 net.egress: a dead AAAA record is a top cause of "hangs").
#[derive(Debug)]
pub struct DualStack {
    v4: SocketAddr,
    dead_v6: SocketAddr,
    server: HttpServer,
}

impl DualStack {
    /// Starts an [`HttpServer`] with `options` on `127.0.0.1:<port>` and picks `[::1]:<port>` where
    /// nothing listens. A port that is busy on `[::1]` is dropped and another is tried.
    ///
    /// # Errors
    ///
    /// If no socket can be bound, or no port is free on both stacks after 32 tries.
    pub async fn start(options: HttpOptions) -> io::Result<Self> {
        let mut options = Some(options);
        for _ in 0..32 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let port = listener.local_addr()?.port();
            // A bind that fails because the address is busy means another process holds the port on
            // IPv6: try another. Any other error means this machine has no IPv6 loopback, and the
            // address is dead all the same.
            match TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await {
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
                Ok(_) | Err(_) => {}
            }
            let Some(taken) = options.take() else {
                break;
            };
            let server = HttpServer::on(listener, taken);
            return Ok(Self {
                v4: server.addr(),
                dead_v6: SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
                server,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "no port was free on both IPv4 and IPv6 loopback",
        ))
    }

    /// The live address, `127.0.0.1:<port>`.
    #[must_use]
    pub fn v4(&self) -> SocketAddr {
        self.v4
    }

    /// The dead address, `[::1]:<port>`, with the same port.
    #[must_use]
    pub fn dead_v6(&self) -> SocketAddr {
        self.dead_v6
    }

    /// The server behind the IPv4 address.
    #[must_use]
    pub fn server(&self) -> &HttpServer {
        &self.server
    }
}
