//! A one-shot HTTP/1.1 server on loopback, with or without TLS. It answers every request with a fixed
//! reply and closes the connection.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring::default_provider;

use super::{Guard, Leaf, serve};

/// The longest request head the server reads. A longer one gets no answer.
const MAX_HEAD: usize = 16 * 1024;

/// The `Date` header every reply carries unless [`HttpOptions::date`] says otherwise.
const FIXED_DATE: &str = "Thu, 01 Jan 2026 00:00:00 GMT";

/// What the server answers to every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `200 OK` with an empty body.
    Ok,
    /// `302 Found` with this `Location`.
    Redirect(String),
    /// This status code, with an empty body.
    Status(u16),
}

/// One request the server read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The method, such as `GET`.
    pub method: String,
    /// The request target, such as `/` or an absolute URL.
    pub target: String,
    /// The header lines as sent, in order.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// The value of the first header called `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// How to start an [`HttpServer`].
pub struct HttpOptions {
    tls: Option<ServerConfig>,
    reply: Reply,
    date: String,
}

impl std::fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOptions")
            .field("tls", &self.tls.is_some())
            .field("reply", &self.reply)
            .field("date", &self.date)
            .finish()
    }
}

impl HttpOptions {
    /// Plain HTTP, answering `200`.
    #[must_use]
    pub fn plain() -> Self {
        Self {
            tls: None,
            reply: Reply::Ok,
            date: FIXED_DATE.to_owned(),
        }
    }

    /// TLS 1.2 and 1.3 with `leaf` (rustls on ring), answering `200`.
    ///
    /// # Panics
    ///
    /// If the leaf's key and certificate do not make a server config, which is a broken build.
    #[must_use]
    pub fn tls(leaf: &Leaf) -> Self {
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("TLS protocol versions")
            .with_no_client_auth()
            .with_single_cert(leaf.chain().to_vec(), leaf.key())
            .expect("a server config from the leaf");
        Self {
            tls: Some(config),
            ..Self::plain()
        }
    }

    /// What the server answers.
    #[must_use]
    pub fn reply(mut self, reply: Reply) -> Self {
        if let Reply::Redirect(location) = &reply {
            assert!(
                !location.contains(['\r', '\n']),
                "a Location with a line break"
            );
        }
        self.reply = reply;
        self
    }

    /// The ALPN protocols a TLS server offers, in its order of preference, such as `["h2", "http/1.1"]`.
    /// It has no effect on a plain server.
    #[must_use]
    pub fn alpn(mut self, protocols: &[&str]) -> Self {
        if let Some(config) = &mut self.tls {
            config.alpn_protocols = protocols.iter().map(|p| p.as_bytes().to_vec()).collect();
        }
        self
    }

    /// The value of the `Date` header, so a test can fake a skewed clock.
    #[must_use]
    pub fn date(mut self, date: &str) -> Self {
        assert!(!date.contains(['\r', '\n']), "a Date with a line break");
        date.clone_into(&mut self.date);
        self
    }
}

#[derive(Debug, Default)]
struct Shared {
    accepted: AtomicUsize,
    handshakes: AtomicUsize,
    application_bytes: AtomicUsize,
    sni: Mutex<Vec<Option<String>>>,
    requests: Mutex<Vec<Request>>,
}

/// A running HTTP server. It stops when dropped.
#[derive(Debug)]
pub struct HttpServer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    _guard: Guard,
}

impl HttpServer {
    /// Starts a server on `127.0.0.1:0`.
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn start(options: HttpOptions) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        Ok(Self::on(listener, options))
    }

    /// A plain server that answers `302` with this `Location` (03 net.egress: a redirect to a second
    /// host).
    ///
    /// # Errors
    ///
    /// If the socket cannot be bound.
    pub async fn redirect(location: &str) -> io::Result<Self> {
        Self::start(HttpOptions::plain().reply(Reply::Redirect(location.to_owned()))).await
    }

    pub(super) fn on(listener: TcpListener, options: HttpOptions) -> Self {
        let addr = listener.local_addr().unwrap_or_else(|_| {
            // A bound listener always has an address. This arm only keeps the function total.
            SocketAddr::from(([127, 0, 0, 1], 0))
        });
        let shared = Arc::new(Shared::default());
        let acceptor = options
            .tls
            .map(|config| TlsAcceptor::from(Arc::new(config)));
        let reply = options.reply;
        let date = options.date;
        let for_conns = Arc::clone(&shared);
        let guard = serve(listener, move |stream| {
            handle(
                stream,
                Arc::clone(&for_conns),
                acceptor.clone(),
                reply.clone(),
                date.clone(),
            )
        });
        Self {
            addr,
            shared,
            _guard: guard,
        }
    }

    /// The address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Connections accepted so far, with or without a finished handshake.
    #[must_use]
    pub fn accepted(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// TLS handshakes that finished.
    #[must_use]
    pub fn handshakes(&self) -> usize {
        self.shared.handshakes.load(Ordering::SeqCst)
    }

    /// Bytes read from clients after the TLS handshake (all bytes on a plain server). A probe that
    /// only reads the chain sends none (03 net.tls_intercept).
    #[must_use]
    pub fn application_bytes(&self) -> usize {
        self.shared.application_bytes.load(Ordering::SeqCst)
    }

    /// The server name each finished handshake asked for, `None` when the ClientHello had no SNI.
    #[must_use]
    pub fn sni_seen(&self) -> Vec<Option<String>> {
        self.shared
            .sni
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The requests read so far.
    #[must_use]
    pub fn requests(&self) -> Vec<Request> {
        self.shared
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn handle(
    stream: TcpStream,
    shared: Arc<Shared>,
    acceptor: Option<TlsAcceptor>,
    reply: Reply,
    date: String,
) {
    shared.accepted.fetch_add(1, Ordering::SeqCst);
    match acceptor {
        None => exchange(stream, &shared, &reply, &date).await,
        Some(acceptor) => {
            let Ok(tls) = acceptor.accept(stream).await else {
                return;
            };
            shared.handshakes.fetch_add(1, Ordering::SeqCst);
            let name = tls.get_ref().1.server_name().map(str::to_owned);
            shared
                .sni
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(name);
            exchange(tls, &shared, &reply, &date).await;
        }
    }
}

async fn exchange<S>(mut stream: S, shared: &Shared, reply: &Reply, date: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(head) = read_head(&mut stream, &shared.application_bytes).await else {
        return;
    };
    let request = parse_head(&head);
    shared
        .requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request);
    let (code, location) = match reply {
        Reply::Ok => (200, None),
        Reply::Redirect(location) => (302, Some(location.as_str())),
        Reply::Status(code) => (*code, None),
    };
    let mut text = format!("HTTP/1.1 {code} {}\r\nDate: {date}\r\n", reason(code));
    if let Some(location) = location {
        text.push_str("Location: ");
        text.push_str(location);
        text.push_str("\r\n");
    }
    text.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(text.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Reads up to the blank line that ends a request head and adds the bytes read to `counter`. `None`
/// when the peer closes first, a read fails or the head is longer than [`MAX_HEAD`]. Bytes after the
/// blank line may come with it.
pub(super) async fn read_head<S>(stream: &mut S, counter: &AtomicUsize) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > MAX_HEAD {
            return None;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => {
                counter.fetch_add(n, Ordering::SeqCst);
                head.extend_from_slice(&buf[..n]);
            }
        }
    }
    Some(head)
}

/// The request line and header lines of `head`. A malformed head gives empty fields.
pub(super) fn parse_head(head: &[u8]) -> Request {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let target = first.next().unwrap_or_default().to_owned();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Request {
        method,
        target,
        headers,
    }
}
