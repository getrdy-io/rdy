//! The HTTP/1.1 probe (M1-093, ADR 0014 decision 4, INV-13, 02 "Network").
//!
//! [`Probe::http`] sends one `HEAD` or `GET` to one of the check's own spec hosts over a connection the
//! facade opened itself (the same policy, address rule, attempts and proxy `CONNECT` as
//! [`Probe::tcp`]) and returns what a readiness check may keep: the status, a short fixed list of
//! headers, timings, and the host a redirect points at.
//!
//! **No redirect is followed.** A `302` returns its `Location` host in [`HttpOutcome::location_host`] and
//! the facade sends no second request. The path and query of a `Location` are not kept: they can hold a
//! token.
//!
//! **No body is kept.** The facade reads at most [`MAX_BODY`] bytes of the body and discards them. It
//! returns how many it counted and whether it cut the rest. Reads come in chunks of at most 16 KiB, so
//! the socket may deliver one chunk more than the cap before the facade stops; the count never
//! exceeds the cap. The body is never logged, returned or passed to the redactor.
//!
//! **Verified, strictly.** An `https://` target is verified with the strict configuration of
//! `tls/strict.rs`: the OS roots for [`Roots::System`], the bundled Mozilla list for
//! [`Roots::Bundled`], and nothing else. A chain they do not accept fails the handshake and no request is
//! sent: [`NetFailure::TlsUntrusted`] names the class (`UnknownIssuer`, `Expired`, ...). The recording
//! verifier of `tls_chain` is private to the `tls` module and is never used here. An `http://` target is
//! plain text, as the spec wrote it. There is no revocation check.
//!
//! **What is sent.** One request: the method, the path and query of the target, `Host`, a fixed
//! `User-Agent`, `Accept: */*` and `Connection: close`. No credentials, no cookies, no body, no
//! compression offer.
//!
//! **Not built here.** A plain `http://` target through the proxy needs the absolute form of the request
//! line, which M1-097 builds; until then the call is refused. HTTP/2 is not spoken: the ALPN offer is
//! `http/1.1` alone.
//!
//! **Failures.** Each class a check reports has its own value: [`NetFailure::Dns`], the refusals of the
//! address rule (`ProbeError::Denied`), [`NetFailure::NotConnected`] (refused or silent, by its typed `outcome`),
//! [`NetFailure::ProxyForbidden`] and [`NetFailure::ProxyAuthRequired`], [`NetFailure::TlsReset`],
//! [`NetFailure::TlsAlert`], [`NetFailure::TlsUntrusted`], [`NetFailure::NoTrustRoots`],
//! [`NetFailure::HttpFailed`] and [`ProbeError::Timeout`]. An HTTP status is data in the outcome, not an
//! error.
//!
//! **The log.** One `http` entry per call: `method`, `url` (the scheme, host and path, never the query;
//! the port only when it is not the scheme's default), `via_proxy`, `addr` and the `status`. `addr` is set
//! as soon as a direct connection opens, so a call that fails after it still names the address. No header
//! and no body.

use std::future::poll_fn;
use std::pin::pin;
use std::time::Duration;

use hyper::Request;
use hyper::body::Body;
use hyper::client::conn::http1;
use hyper::header::{self, HeaderMap, HeaderValue};
use rdy_spec::Target;
use rdy_spec::result::ActionKind;
use rdy_spec::scalar::Host;
use serde_json::{Map, Value};
use tokio::time::{Instant, timeout};

use self::io::{Io, NoBody};
use super::tls::Secured;
use super::{
    BoxedStream, Dialed, NetFailure, Probe, ProbeError, ProbeHub, Roots, Route, TcpReport,
};
use super::{fail_net, proxy_for, settle};
use crate::probe::log::Pending;
use crate::probe::refuse;
use crate::probe::sock::host_port;

mod io;
#[cfg(test)]
mod tests;

/// The most body the facade reads, and the most it counts. The rest is never read.
pub const MAX_BODY: usize = 64 * 1024;

/// The longest the reply head takes, from the request written to the end of the headers.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest the body takes to discard, from the end of the head.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest reply head accepted, status line and headers. hyper reads into a buffer of exactly
/// [`READ_CHUNK`] bytes, so this is also the most one head can take.
const MAX_HEAD: usize = READ_CHUNK;

/// The most header lines accepted.
const MAX_HEADERS: usize = 64;

/// The size of one read from the socket.
const READ_CHUNK: usize = 16 * 1024;

/// The longest header value kept, and the longest `Location` that is read.
const MAX_VALUE: usize = 256;

/// The `Location` text longer than this is not read.
const MAX_LOCATION: usize = 2048;

/// The `User-Agent` of every request.
const USER_AGENT: &str = concat!("rdy/", env!("CARGO_PKG_VERSION"));

/// The response headers the outcome keeps, in this order. Nothing else is kept: no `Set-Cookie`, no
/// `Authorization` echo, no `Location` (its host is read apart), no custom header.
pub const REPORTED_HEADERS: [&str; 6] = [
    "server",
    "content-type",
    "content-length",
    "date",
    "via",
    "retry-after",
];

/// The rule of a call whose target is a `host:port` and not an `http://` or `https://` URL.
pub const RULE_HTTP_NOT_URL: &str = "the target is not an http:// or https:// URL";

/// The rule of a plain `http://` call through the proxy, which needs the absolute form (M1-097).
pub const RULE_HTTP_PLAIN_VIA_PROXY: &str =
    "plain http through the proxy is not built yet (it needs the absolute form, M1-097)";

/// The method of an HTTP probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpMethod {
    /// `HEAD`: the headers only.
    Head,
    /// `GET`: the headers, and a body the facade discards.
    Get,
}

impl HttpMethod {
    /// The method as the request line and the log write it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Head => "HEAD",
            Self::Get => "GET",
        }
    }
}

/// One HTTP call: which URL, how, by which route and against which roots. Its `Debug` shows the URL
/// without its query, as the log does: a query can hold a token.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpProbe {
    /// The URL: an `http://` or `https://` target, with its path and query. Its host and port must be
    /// one of the check's spec hosts.
    pub target: Target,
    /// `HEAD` or `GET`.
    pub method: HttpMethod,
    /// Direct or through the run's proxy.
    pub route: Route,
    /// The roots an `https://` target is verified against.
    pub roots: Roots,
}

impl std::fmt::Debug for HttpProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpProbe")
            .field("url", &shown_url(&self.target))
            .field("method", &self.method)
            .field("route", &self.route)
            .field("roots", &self.roots)
            .finish()
    }
}

impl HttpProbe {
    /// A call to `target` that goes direct and verifies against the OS roots.
    #[must_use]
    pub fn new(target: Target, method: HttpMethod) -> Self {
        Self {
            target,
            method,
            route: Route::Direct,
            roots: Roots::System,
        }
    }

    /// Sets the route.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Sets the roots (`trust: system` or `trust: bundled`).
    #[must_use]
    pub fn roots(mut self, roots: Roots) -> Self {
        self.roots = roots;
        self
    }
}

/// How long each stage of a call took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpTiming {
    /// The lookup, the connection attempts and, through a proxy, the `CONNECT`.
    pub connect: Duration,
    /// The TLS handshake, for `https`.
    pub tls: Option<Duration>,
    /// From the request written to the end of the reply head.
    pub first_byte: Duration,
    /// The whole call, to the end of the discard.
    pub total: Duration,
}

/// The TLS session of an `https` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpTls {
    /// `"TLS 1.2"` or `"TLS 1.3"`.
    pub protocol: Option<&'static str>,
    /// The protocol the server chose. The offer is `http/1.1` alone.
    pub alpn: Option<&'static str>,
}

/// What one HTTP call found. It holds no body and no URL.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpOutcome {
    /// The status code.
    pub status: u16,
    /// The headers of [`REPORTED_HEADERS`] the reply had, lowercase names, in that list's order, with
    /// values cut to 256 printable ASCII characters. The first one of each name wins.
    pub headers: Vec<(&'static str, String)>,
    /// The host of the `Location` header, when it is an absolute URL: no scheme, port, path, query or
    /// user info. The facade did not follow it.
    pub location_host: Option<String>,
    /// How many body bytes were counted and discarded, at most [`MAX_BODY`].
    pub body_bytes: usize,
    /// `true` when the facade stopped before the end of the body: the cap, the time limit or a read error.
    pub body_cut: bool,
    /// The TLS session, for an `https` call.
    pub tls: Option<HttpTls>,
    /// The connection that carried the request: its attempts and, through a proxy, the `CONNECT`.
    pub connect: TcpReport,
    /// The stage timings.
    pub timing: HttpTiming,
}

impl HttpOutcome {
    /// The value of one reported header, by lowercase name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

impl Probe {
    /// Sends one `HEAD` or `GET` and returns the status, a fixed list of headers, timings and the
    /// `Location` host. See the [module docs](crate::probe::net).
    ///
    /// The policy is that of [`Probe::tcp`]: the check must declare `PeerClass::SpecHosts` (and
    /// `PeerClass::Proxy` for `Route::ViaProxy`), the host and port must be one of its spec hosts, and a
    /// forbidden address, literal or resolved, is refused.
    ///
    /// # Errors
    ///
    /// - [`ProbeError::Denied`] as for `tcp`, for a target that is not a URL, and for a plain `http://`
    ///   target through the proxy.
    /// - [`ProbeError::Net`] for a name that did not resolve, a proxy that refused, a connection that
    ///   could not be made ([`NetFailure::NotConnected`]), a TLS failure, a certificate the roots did not
    ///   accept ([`NetFailure::TlsUntrusted`]), no roots to check against and an HTTP exchange that
    ///   failed ([`NetFailure::HttpFailed`]).
    /// - [`ProbeError::Timeout`] when a stage ran out of time.
    /// - [`ProbeError::NotRecorded`] on a replay backend with no answer recorded.
    pub async fn http(&self, request: HttpProbe) -> Result<HttpOutcome, ProbeError> {
        let HttpProbe {
            target,
            method,
            route,
            roots,
        } = request;
        let what = host_port(&target);
        let mut fields = Map::new();
        fields.insert("method".to_owned(), method.as_str().into());
        fields.insert("url".to_owned(), shown_url(&target).into());
        fields.insert("via_proxy".to_owned(), Value::Null);
        fields.insert("addr".to_owned(), Value::Null);
        let (hub, mut entry) = self.begin(ActionKind::Http, fields, &what)?;

        if target.scheme().is_none() {
            return Err(refuse(entry, RULE_HTTP_NOT_URL, &what));
        }
        if let Err(rule) = self.admit_tcp(&target, route) {
            return Err(refuse(entry, rule, &what));
        }
        if route == Route::ViaProxy && target.scheme() == Some("http") {
            return Err(refuse(entry, RULE_HTTP_PLAIN_VIA_PROXY, &what));
        }
        let proxy = match proxy_for(hub, route, &mut entry) {
            Ok(proxy) => proxy,
            Err(failure) => return Err(fail_net(entry, failure)),
        };

        let result = self
            .unless_ended(
                &what,
                self.exchange(hub, &mut entry, &target, method, roots, proxy),
            )
            .await;
        match result {
            Err(ProbeError::Net(failure)) => Err(fail_net(entry, failure)),
            other => settle(entry, other, |outcome, entry| {
                entry.set("status", outcome.status);
            }),
        }
    }

    /// Connection, handshake, request, reply. Everything that can fail before the entry is closed.
    async fn exchange(
        &self,
        hub: &ProbeHub,
        entry: &mut Pending,
        target: &Target,
        method: HttpMethod,
        roots: Roots,
        proxy: Option<&crate::probe::proxy::ProxyUrl>,
    ) -> Result<HttpOutcome, ProbeError> {
        let what = host_port(target);
        // Everything that can be wrong with the call itself is found before a connection opens: a
        // request that cannot be sent, a store that is missing, a name TLS cannot carry.
        let request = build_request(target, method).map_err(|reason| failed(&what, reason))?;
        let strict = if target.scheme() == Some("https") {
            Some(self.strict_tls(hub, target, roots).await?)
        } else {
            None
        };

        let started = Instant::now();
        let Dialed { report, stream } = self.dial(hub, target, proxy).await?;
        // Through a proxy the connected address is the proxy's, and the log shows the target.
        if let Some(addr) = report.addr.filter(|_| !report.via_proxy) {
            entry.set("addr", addr.ip().to_string());
        }
        let Some(stream) = stream else {
            return Err(ProbeError::Net(report.not_connected(&what)));
        };
        let connect = started.elapsed();

        // `https` is verified before one byte of the request is written. `http` is plain text.
        let (io, tls, tls_time): (BoxedStream, Option<HttpTls>, Option<Duration>) = match strict {
            Some(strict) => {
                let Secured {
                    stream,
                    protocol,
                    alpn,
                    handshake,
                } = self.secure(strict, target, stream).await?;
                (
                    Box::new(stream),
                    Some(HttpTls { protocol, alpn }),
                    Some(handshake),
                )
            }
            None => (stream, None, None),
        };

        let reply = converse(
            io,
            request,
            self.scope.peers.timeout(RESPONSE_TIMEOUT),
            self.scope.peers.timeout(BODY_TIMEOUT),
            &what,
        )
        .await?;
        Ok(HttpOutcome {
            status: reply.status,
            headers: reply.headers,
            location_host: reply.location_host,
            body_bytes: reply.body_bytes,
            body_cut: reply.body_cut,
            tls,
            connect: report,
            timing: HttpTiming {
                connect,
                tls: tls_time,
                first_byte: reply.first_byte,
                total: started.elapsed(),
            },
        })
    }
}

/// What the reply showed.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    location_host: Option<String>,
    body_bytes: usize,
    body_cut: bool,
    first_byte: Duration,
}

/// Writes `request` on `io`, reads the head and counts and discards the body. The connection is
/// closed when this returns.
async fn converse(
    io: BoxedStream,
    request: Request<NoBody>,
    head_limit: Duration,
    body_limit: Duration,
    what: &str,
) -> Result<Reply, ProbeError> {
    let (mut sender, connection) = http1::Builder::new()
        .read_buf_exact_size(Some(READ_CHUNK))
        .max_header_size(MAX_HEAD)
        .max_headers(MAX_HEADERS)
        .handshake::<_, NoBody>(Io::new(io))
        .await
        .map_err(|error| http_error(&error, what))?;

    let work = async {
        let sent = Instant::now();
        let response = match timeout(head_limit, sender.send_request(request)).await {
            Err(_elapsed) => return Err(ProbeError::Timeout),
            Ok(Err(error)) => return Err(http_error(&error, what)),
            Ok(Ok(response)) => response,
        };
        let first_byte = sent.elapsed();
        let status = response.status().as_u16();
        let headers = reported_headers(response.headers());
        let location_host = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(location_host);
        let (body_bytes, body_cut) = discard(response.into_body(), body_limit).await;
        Ok(Reply {
            status,
            headers,
            location_host,
            body_bytes,
            body_cut,
            first_byte,
        })
    };

    // The connection task moves bytes for the body, so it is polled alongside the exchange. When it
    // ends, with or without an error, the exchange goes on with what it has: hyper has already handed
    // the error to the request (no head yet) or to the body (a cut, a reset, a close with no
    // `close_notify`), and the status and `Location` of a head that arrived are data. The stage timeouts
    // stop an exchange that has nothing more to wait for.
    let mut work = pin!(work);
    let mut connection = pin!(connection);
    let mut open = true;
    loop {
        tokio::select! {
            result = &mut work => return result,
            _ended = &mut connection, if open => open = false,
        }
    }
}

/// Counts the body up to [`MAX_BODY`] bytes and drops it. Returns the count and whether the facade
/// stopped before the end.
async fn discard(body: hyper::body::Incoming, limit: Duration) -> (usize, bool) {
    let mut body = pin!(body);
    let mut counted = 0_usize;
    let read = async {
        loop {
            match poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                None => return false,
                Some(Err(_)) => return true,
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        counted = counted.saturating_add(data.len());
                        if counted > MAX_BODY {
                            return true;
                        }
                        if counted == MAX_BODY {
                            // A body of exactly the cap is complete if nothing follows it. One more
                            // look tells, and the bytes of a further frame are not counted.
                            return poll_fn(|cx| body.as_mut().poll_frame(cx)).await.is_some();
                        }
                    }
                }
            }
        }
    };
    let cut = timeout(limit, read).await.unwrap_or(true);
    (counted.min(MAX_BODY), cut)
}

/// The request line and headers. `Err` is a fixed phrase.
fn build_request(target: &Target, method: HttpMethod) -> Result<Request<NoBody>, &'static str> {
    let tail = target.path_and_query().unwrap_or_default();
    let path = if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    let uri: hyper::Uri = path.parse().map_err(|_| "the URL path cannot be sent")?;
    let host =
        HeaderValue::from_str(&host_header(target)).map_err(|_| "the host cannot be sent")?;
    Request::builder()
        .method(method.as_str())
        .uri(uri)
        .header(header::HOST, host)
        .header(header::USER_AGENT, USER_AGENT)
        .header(header::ACCEPT, "*/*")
        .header(header::CONNECTION, "close")
        .body(NoBody)
        .map_err(|_| "the request cannot be built")
}

/// `Host`: the host, and the port when it is not the default of the scheme.
fn host_header(target: &Target) -> String {
    let default = if target.scheme() == Some("http") {
        80
    } else {
        443
    };
    if target.port() == default {
        target.host().to_string()
    } else {
        format!("{}:{}", target.host(), target.port())
    }
}

/// The URL for the log: scheme, host and path, never the query. The port is left out when it is the
/// default of the scheme, as in the examples of 01.
fn shown_url(target: &Target) -> String {
    let scheme = target.scheme().unwrap_or("tcp");
    let tail = target.path_and_query().unwrap_or_default();
    let path = tail.split('?').next().unwrap_or_default();
    let path = if path.is_empty() && target.scheme().is_some() {
        "/"
    } else {
        path
    };
    let default = match target.scheme() {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    };
    let port = if Some(target.port()) == default {
        String::new()
    } else {
        format!(":{}", target.port())
    };
    format!("{scheme}://{}{port}{path}", target.host())
}

/// The headers of [`REPORTED_HEADERS`] the reply had.
fn reported_headers(headers: &HeaderMap) -> Vec<(&'static str, String)> {
    REPORTED_HEADERS
        .iter()
        .filter_map(|name| {
            let value = headers.get(*name)?;
            Some((*name, printable(value.as_bytes())))
        })
        .collect()
}

/// `bytes` as printable ASCII, at most [`MAX_VALUE`] characters. Anything else is dropped, so a header
/// cannot carry control characters or a line break into a report.
fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|b| (0x20..0x7f).contains(*b))
        .take(MAX_VALUE)
        .map(|b| char::from(*b))
        .collect()
}

/// The host of an absolute `Location`. A relative one, one over [`MAX_LOCATION`] and one with user info
/// give `None`.
///
/// Only `scheme://authority` is parsed. The scheme is matched without regard to case, and the text is
/// cut at the first `/`, `?` or `#` after the `//`, so the path, the query and the fragment (a signed
/// redirect can run to a thousand characters of them) are never read or judged.
fn location_host(value: &str) -> Option<String> {
    if value.len() > MAX_LOCATION {
        return None;
    }
    let value = value.trim();
    // A scheme-relative `//host/path` keeps its host and takes https.
    let (scheme, rest) = if let Some(rest) = value.strip_prefix("//") {
        ("https", rest)
    } else {
        let (scheme, rest) = value.split_once("://")?;
        let scheme = if scheme.eq_ignore_ascii_case("https") {
            "https"
        } else if scheme.eq_ignore_ascii_case("http") {
            "http"
        } else {
            return None;
        };
        (scheme, rest)
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let parsed = Target::parse(&format!("{scheme}://{authority}"))
        .ok()
        .filter(Target::is_url)?;
    match parsed.host() {
        Host::Name(name) => Some(name.clone()),
        other => Some(other.to_string()),
    }
}

/// A failed exchange, with a fixed phrase.
fn failed(what: &str, reason: &'static str) -> ProbeError {
    ProbeError::Net(NetFailure::HttpFailed {
        target: what.to_owned(),
        reason,
    })
}

/// Types a hyper error. The text of the error is never kept: it can quote the peer's bytes.
fn http_error(error: &hyper::Error, what: &str) -> ProbeError {
    let reason = if error.is_parse() || error.is_parse_status() {
        "the reply is not valid HTTP/1.1, or its head is too large"
    } else if error.is_incomplete_message() || error.is_closed() || error.is_canceled() {
        "the connection closed before the reply ended"
    } else if reset(error) {
        "the connection was reset"
    } else {
        "the exchange failed"
    };
    failed(what, reason)
}

/// Whether an I/O error in the source chain says the peer reset the connection.
fn reset(error: &hyper::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(error);
    while let Some(inner) = source {
        if let Some(io) = inner.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            )
        {
            return true;
        }
        source = inner.source();
    }
    false
}
