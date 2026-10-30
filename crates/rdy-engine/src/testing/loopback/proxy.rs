//! A CONNECT proxy on loopback with the four answers of 08 section 8: `ok`, `403`, `407-basic` and
//! `407-negotiate`.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use super::http::{parse_head, read_head};
use super::{Guard, serve};

/// How the proxy answers a `CONNECT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// `200 Connection Established`, then it tunnels to the target.
    Ok,
    /// `403 Forbidden`: the target is not on the allow list.
    Forbidden,
    /// `407` with `Proxy-Authenticate: Basic`. It never accepts credentials.
    Basic407,
    /// `407` with `Proxy-Authenticate: Negotiate`. rdy classifies this answer and never authenticates.
    Negotiate407,
}

/// One `CONNECT` the proxy read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    /// The request target, `host:port`.
    pub target: String,
    /// The `Proxy-Authorization` header as sent, if any. Tests send synthetic credentials only.
    pub proxy_authorization: Option<String>,
}

#[derive(Debug, Default)]
struct Shared {
    accepted: AtomicUsize,
    bytes_received: AtomicUsize,
    requests: Mutex<Vec<ConnectRequest>>,
}

/// A running proxy. It stops when dropped.
#[derive(Debug)]
pub struct ConnectProxy {
    addr: SocketAddr,
    shared: Arc<Shared>,
    _guard: Guard,
}

impl ConnectProxy {
    /// Starts a proxy on `127.0.0.1:0` that answers `mode`. In [`ProxyMode::Ok`] it tunnels only to a
    /// loopback IP literal or to `localhost`, so a test cannot reach a real network through it. Any
    /// other target gets `502`. Use [`ConnectProxy::start_with_routes`] to give a name a loopback
    /// address.
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn start(mode: ProxyMode) -> io::Result<Self> {
        Self::start_with_routes(mode, &[]).await
    }

    /// Like [`ConnectProxy::start`], and in [`ProxyMode::Ok`] a `CONNECT` to a `host:port` in
    /// `routes` (compared ignoring case) is tunnelled to the address next to it. A test uses this to
    /// reach its loopback server under a name such as `registry.acme.example:443`.
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn start_with_routes(
        mode: ProxyMode,
        routes: &[(&str, SocketAddr)],
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared::default());
        let routes: Arc<Vec<(String, SocketAddr)>> = Arc::new(
            routes
                .iter()
                .map(|(name, to)| (name.to_ascii_lowercase(), *to))
                .collect(),
        );
        let for_conns = Arc::clone(&shared);
        let guard = serve(listener, move |stream| {
            handle(stream, Arc::clone(&for_conns), mode, Arc::clone(&routes))
        });
        Ok(Self {
            addr,
            shared,
            _guard: guard,
        })
    }

    /// The address the proxy listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The URL a client puts in `HTTPS_PROXY`, such as `http://127.0.0.1:41234`.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Connections accepted. A connect the client refuses before it sends a byte still counts here.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// Bytes read from clients before the tunnel opened. Zero proves a client sent nothing.
    #[must_use]
    pub fn bytes_received(&self) -> usize {
        self.shared.bytes_received.load(Ordering::SeqCst)
    }

    /// The `CONNECT` requests read so far.
    #[must_use]
    pub fn requests(&self) -> Vec<ConnectRequest> {
        self.shared
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn handle(
    mut stream: TcpStream,
    shared: Arc<Shared>,
    mode: ProxyMode,
    routes: Arc<Vec<(String, SocketAddr)>>,
) {
    shared.accepted.fetch_add(1, Ordering::SeqCst);
    let Some(head) = read_head(&mut stream, &shared.bytes_received).await else {
        return;
    };
    let request = parse_head(&head);
    if !request.method.eq_ignore_ascii_case("CONNECT") {
        let _ = respond(&mut stream, "405 Method Not Allowed", &[]).await;
        return;
    }
    shared
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(ConnectRequest {
            target: request.target.clone(),
            proxy_authorization: request.header("Proxy-Authorization").map(str::to_owned),
        });
    match mode {
        ProxyMode::Forbidden => {
            let _ = respond(&mut stream, "403 Forbidden", &[]).await;
        }
        ProxyMode::Basic407 => {
            let challenge = [("Proxy-Authenticate", "Basic realm=\"rdy-test\"")];
            let _ = respond(&mut stream, "407 Proxy Authentication Required", &challenge).await;
        }
        ProxyMode::Negotiate407 => {
            let challenge = [("Proxy-Authenticate", "Negotiate")];
            let _ = respond(&mut stream, "407 Proxy Authentication Required", &challenge).await;
        }
        ProxyMode::Ok => {
            let Some(to) = destination(&request.target, &routes) else {
                let _ = respond(&mut stream, "502 Bad Gateway", &[]).await;
                return;
            };
            let Ok(mut upstream) = TcpStream::connect(to).await else {
                let _ = respond(&mut stream, "502 Bad Gateway", &[]).await;
                return;
            };
            if respond(&mut stream, "200 Connection Established", &[])
                .await
                .is_err()
            {
                return;
            }
            // Bytes that came with the head belong to the tunnel.
            let end = head
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map_or(head.len(), |at| at + 4);
            if let Some(rest) = head.get(end..).filter(|r| !r.is_empty())
                && upstream.write_all(rest).await.is_err()
            {
                return;
            }
            let _ = copy_bidirectional(&mut stream, &mut upstream).await;
        }
    }
}

/// Where a `CONNECT` target goes: a route, or a loopback address. Never anything else.
fn destination(target: &str, routes: &[(String, SocketAddr)]) -> Option<SocketAddr> {
    let lower = target.to_ascii_lowercase();
    if let Some((_, to)) = routes.iter().find(|(name, _)| *name == lower) {
        return Some(*to);
    }
    let (host, port) = lower.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host == "localhost" {
        return Some(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let ip: IpAddr = host.parse().ok()?;
    ip.is_loopback().then(|| SocketAddr::new(ip, port))
}

/// A status line, the given headers and an empty body. The connection closes after a refusal; for a
/// `200` the caller keeps using the stream as a tunnel.
async fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)]) -> io::Result<()> {
    let mut text = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    if status.starts_with("200") {
        text.push_str("\r\n");
    } else {
        text.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    }
    stream.write_all(text.as_bytes()).await?;
    if !status.starts_with("200") {
        stream.shutdown().await?;
    }
    Ok(())
}
