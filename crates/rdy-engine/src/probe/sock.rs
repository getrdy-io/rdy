//! Datagram exchanges and unix sockets (M1-144, ADR 0014 decision 8, 02 "Catalog hooks").
//!
//! Two facade methods, for the checks that cannot use a command:
//!
//! - [`Probe::udp_exchange`] sends one datagram to one server and reads one reply. It serves the SNTP
//!   offset of `host.time_sync`.
//! - [`Probe::unix_get`] sends one `GET` over a unix socket and returns the status and the body. It
//!   serves the Docker and Podman Engine API of `host.container_runtime`.
//!
//! Both go in the order the rest of the facade does: the handle is checked, the policy is applied, the
//! backend runs, and the entry is closed. A refused call never reaches the backend. There is one
//! action-log entry per call.
//!
//! **UDP policy.**
//! - The check must declare [`PeerClass::NtpServers`] in `CheckInfo::peers`.
//! - The server must be one of the check's own spec hosts (host and port), set by
//!   `Probe::permit_hosts`. A check that has no spec hosts, or a probe nobody gave any, can send
//!   nothing. A check cannot name an address of its own (INV-11).
//! - A name is resolved by the backend through the system resolver, for that spec name only. If any
//!   answer, or a literal address, is in an `is_forbidden` range (INV-12) or is an unspecified,
//!   multicast or broadcast address, the call is refused. The first answer is used. There is no retry
//!   on the next address.
//! - The payload is 1 to [`MAX_UDP_PAYLOAD`] bytes and the reply is cut at the smaller of `max_reply`
//!   and [`MAX_UDP_REPLY`]. The socket is connected, so a datagram from any other source is never read.
//! - The whole call has [`UDP_TIMEOUT`]. A silent server is [`ProbeError::Timeout`].
//! - The entry is a `connect` with `proto` `udp`, the `host` and `port` as the spec wrote them, the
//!   `addr` used, and the reply `bytes`. The payload and the reply are never logged.
//!
//! **Unix socket policy.**
//! - The check must declare the socket as [`PeerClass::UnixSocket`] in `CheckInfo::peers`. The path is
//!   absolute, has no `..`, and matches the declared text component by component. A component
//!   `{uid}` matches the real user id of the process and no other (read through the backend, so a
//!   fixture sets it with `Replay::ids`), for a rootless socket such as `/run/user/{uid}/docker.sock`.
//!   Under `sudo` that is root's id, not the user's. If the id cannot be read, `{uid}` matches nothing.
//!   The path is used as declared. A link in it (`/var/run` is one on most systems) is followed by the
//!   OS.
//! - The method is `GET`. [`Probe::unix_get`] cannot send anything else. The crate-private
//!   `unix_request` takes the method so the guard, and its test, sit on the one path every request
//!   takes. A `POST`, `PUT`, `DELETE` or any other method is refused.
//! - The API path is one of [`UNIX_GET_PATHS`], optionally after a version prefix such as `/v1.43`.
//!   There is no query string. So `/containers/json`, `/events`, `/exec/...` and `/images/...` are
//!   refused, and a `POST` to `/containers/create` is refused twice over.
//! - The request has no body and no credential. The reply is read to [`BODY_LIMIT`] bytes and the cut
//!   is flagged. The whole call has [`UNIX_TIMEOUT`].
//! - The entry is an `http` with `method`, `path` (the socket) and `url` (the API path), then the
//!   `status` and body `bytes`. The body is never logged: `/info` can carry proxy settings, so a check
//!   redacts what it keeps.
//! - On Windows the call is refused with [`RULE_UNIX_OS`] and logged. A check maps that to Skipped
//!   with a reason. The Windows named pipe is M2.

use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rdy_spec::Target;
use rdy_spec::result::ActionKind;
use rdy_spec::scalar::Host;
use serde_json::Map;

use super::addr::is_unusable_peer;
use super::{Probe, ProbeError, refuse, settle};
use crate::check::{Os, PeerClass};
use crate::family::HostSet;

#[cfg(any(test, feature = "testing"))]
pub(super) mod replay;
#[cfg(test)]
mod tests;

/// The most time one UDP exchange may take, name lookup included.
pub const UDP_TIMEOUT: Duration = Duration::from_secs(3);

/// The most time one unix socket request may take.
pub const UNIX_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest datagram a check may send. An SNTP packet is 48 bytes and a DNS query is far under this.
pub const MAX_UDP_PAYLOAD: usize = 512;

/// The largest reply kept, whatever `max_reply` asks for.
pub const MAX_UDP_REPLY: usize = 4096;

/// The most body bytes of a unix socket reply that are kept.
pub const BODY_LIMIT: usize = 256 * 1024;

/// The API paths `unix_get` may ask for. The Docker and Podman Engine API both serve them.
pub const UNIX_GET_PATHS: [&str; 3] = ["/_ping", "/version", "/info"];

/// The rule of a datagram from a check that did not declare `PeerClass::NtpServers`.
pub const RULE_UDP_UNDECLARED: &str = "udp peer class not declared by the check";

/// The rule of a datagram to a server that is not one of the check's spec hosts.
pub const RULE_UDP_HOST: &str = "server is not one of the check's spec hosts";

/// The rule of a datagram whose payload is empty or too long.
pub const RULE_UDP_SIZE: &str = "datagram must be 1 to 512 bytes and ask for a reply";

/// The rule of a datagram to a forbidden, unspecified, multicast or broadcast address.
pub const RULE_UDP_ADDRESS: &str =
    "address is link-local, metadata, unspecified, multicast or broadcast";

/// The rule of a unix socket request on an OS without unix sockets.
pub const RULE_UNIX_OS: &str = "unix sockets are not available on this OS";

/// The rule of a unix socket path that is relative or has a `..` component.
pub const RULE_UNIX_PATH_SHAPE: &str = "socket path must be absolute with no .. component";

/// The rule of a socket the check did not declare in `CheckInfo::peers`.
pub const RULE_UNIX_UNDECLARED: &str = "unix socket not declared by the check";

/// The rule of a method other than `GET`.
pub const RULE_UNIX_METHOD: &str = "only GET is allowed on a unix socket";

/// The rule of an API path that is not on the allowlist.
pub const RULE_UNIX_API_PATH: &str = "API path is not on the read-only allowlist";

/// What an exchange gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpReply {
    /// The reply datagram. Raw: parse it, do not print it.
    pub bytes: Vec<u8>,
    /// `true` when the datagram was longer than `max_reply` and the rest was cut.
    pub truncated: bool,
    /// The address that answered.
    pub addr: IpAddr,
}

impl UdpReply {
    /// A whole reply from `addr`.
    #[must_use]
    pub fn new(bytes: Vec<u8>, addr: IpAddr) -> Self {
        Self {
            bytes,
            truncated: false,
            addr,
        }
    }
}

/// What a unix socket `GET` gave back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnixResponse {
    /// The HTTP status, 200 to 599. A 404 or a 500 is a reply, not an error.
    pub status: u16,
    /// The body, at most [`BODY_LIMIT`] bytes. Raw: redact before it is shown.
    pub body: Vec<u8>,
    /// `true` when the server sent more than was kept.
    pub truncated: bool,
}

impl UnixResponse {
    /// A whole reply.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            truncated: false,
        }
    }
}

/// What a check's probe may reach over sockets, beyond its manifest: the spec hosts, set once.
#[derive(Debug, Default)]
pub(super) struct Peers {
    hosts: OnceLock<HostSet>,
    #[cfg(test)]
    pub(super) timeout: OnceLock<Duration>,
}

impl Peers {
    /// Whether `target` (host and port) is one of the check's spec hosts. A probe nobody gave hosts to
    /// has none.
    pub(super) fn is_spec_host(&self, target: &Target) -> bool {
        self.hosts.get().is_some_and(|hosts| {
            hosts
                .iter()
                .any(|t| t.host() == target.host() && t.port() == target.port())
        })
    }

    pub(super) fn timeout(&self, normal: Duration) -> Duration {
        #[cfg(test)]
        if let Some(short) = self.timeout.get() {
            return *short;
        }
        normal
    }
}

impl Probe {
    /// Gives the probe the check's spec hosts: the only servers `udp_exchange` may send to. It can be
    /// set once. A later call changes nothing and returns `false`.
    ///
    /// The scheduler calls it with the check's `Built::hosts` when it builds the probe of a check
    /// (`Planned::with_hosts`, M1-091). Until a probe has hosts, every datagram and every TCP call is
    /// refused.
    #[cfg_attr(
        not(any(test, feature = "testing", feature = "runtime")),
        expect(
            dead_code,
            reason = "only the scheduler and the test helpers set hosts"
        )
    )]
    pub(crate) fn permit_hosts(&self, hosts: HostSet) -> bool {
        self.scope.peers.hosts.set(hosts).is_ok()
    }

    /// Sends `payload` to `server` and reads one reply of at most `max_reply` bytes.
    ///
    /// The check must declare [`PeerClass::NtpServers`] and `server` must be one of its spec hosts.
    /// See the [module docs](crate::probe::sock) for the address rules, the caps and the timeout.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for an undeclared class, a server that is not a spec host, a bad size,
    /// a forbidden address, or a call after the check ended; [`ProbeError::Timeout`] when no reply
    /// came in time; the other variants when the lookup or the socket fails.
    pub async fn udp_exchange(
        &self,
        server: &Target,
        payload: &[u8],
        max_reply: usize,
    ) -> Result<UdpReply, ProbeError> {
        let host = server.host().to_string();
        let port = server.port();
        let what = host_port(server);
        let mut fields = Map::new();
        fields.insert("host".to_owned(), host.into());
        fields.insert("port".to_owned(), port.into());
        fields.insert("proto".to_owned(), "udp".into());
        let (hub, entry) = self.begin(ActionKind::Connect, fields, &what)?;

        let result = match self.admit_udp(server, payload, max_reply) {
            Err(error) => Err(error),
            Ok(cap) => {
                let timeout = self.scope.peers.timeout(UDP_TIMEOUT);
                let work = async {
                    let started = Instant::now();
                    let ip = match server.host() {
                        Host::Ipv4(addr) => IpAddr::V4(*addr),
                        Host::Ipv6(addr) => IpAddr::V6(*addr),
                        Host::Name(name) => {
                            let answers = hub
                                .backend
                                .resolve(name, port, timeout)
                                .await
                                .map_err(|e| ProbeError::from_io(&e))?;
                            // Any answer in a refused range refuses the call: a name that points at a
                            // metadata address is not a time server.
                            if answers.iter().any(|ip| is_unusable_peer(*ip)) {
                                return Err(ProbeError::denied(RULE_UDP_ADDRESS, &what));
                            }
                            *answers.first().ok_or(ProbeError::NotFound)?
                        }
                        _ => return Err(ProbeError::denied(RULE_UDP_HOST, &what)),
                    };
                    if is_unusable_peer(ip) {
                        return Err(ProbeError::denied(RULE_UDP_ADDRESS, &what));
                    }
                    let left = timeout.saturating_sub(started.elapsed());
                    hub.backend
                        .udp_exchange(SocketAddr::new(ip, port), payload, cap, left)
                        .await
                };
                self.unless_ended(&what, work).await
            }
        };
        settle(entry, result, |reply, entry| {
            entry.set("addr", reply.addr.to_string());
            entry.set("bytes", reply.bytes.len());
            entry.set("truncated", reply.truncated);
        })
    }

    /// The policy before any lookup. Returns the reply cap to use.
    fn admit_udp(
        &self,
        server: &Target,
        payload: &[u8],
        max_reply: usize,
    ) -> Result<usize, ProbeError> {
        let what = host_port(server);
        let declared = self
            .scope
            .info
            .is_some_and(|info| info.peers.contains(&PeerClass::NtpServers));
        if !declared {
            return Err(ProbeError::denied(RULE_UDP_UNDECLARED, what));
        }
        if !self.scope.peers.is_spec_host(server) {
            return Err(ProbeError::denied(RULE_UDP_HOST, what));
        }
        if payload.is_empty() || payload.len() > MAX_UDP_PAYLOAD || max_reply == 0 {
            return Err(ProbeError::denied(RULE_UDP_SIZE, what));
        }
        Ok(max_reply.min(MAX_UDP_REPLY))
    }

    /// Sends `GET path` over the unix socket at `socket` and returns the status and body.
    ///
    /// Only `GET` can be sent, and only to the paths in [`UNIX_GET_PATHS`], with or without a version
    /// prefix. The check must declare the socket as [`PeerClass::UnixSocket`]. See the
    /// [module docs](crate::probe::sock).
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for an OS without unix sockets, a socket the check did not declare, a
    /// path off the allowlist, or a call after the check ended; [`ProbeError::NotFound`] and
    /// [`ProbeError::PermissionDenied`] when the socket is missing or the user may not open it;
    /// [`ProbeError::Timeout`]; the other variants for a reply that is not HTTP.
    pub async fn unix_get(&self, socket: &Path, path: &str) -> Result<UnixResponse, ProbeError> {
        self.unix_request("GET", socket, path, None).await
    }

    /// Like [`Probe::unix_get`], with a shorter limit than [`UNIX_TIMEOUT`]. The limit can only be
    /// lowered: a longer `within` is cut to [`UNIX_TIMEOUT`]. A check that asks several daemons uses it
    /// so one that hangs cannot use the whole check budget (M1-150).
    ///
    /// # Errors
    ///
    /// The same as [`Probe::unix_get`]. A daemon that does not answer within `within` is
    /// [`ProbeError::Timeout`].
    pub async fn unix_get_within(
        &self,
        socket: &Path,
        path: &str,
        within: Duration,
    ) -> Result<UnixResponse, ProbeError> {
        self.unix_request("GET", socket, path, Some(within)).await
    }

    /// The one path every unix socket request takes. The method is a parameter so the guard has a
    /// test; the public method passes `GET`.
    pub(crate) async fn unix_request(
        &self,
        method: &str,
        socket: &Path,
        path: &str,
        within: Option<Duration>,
    ) -> Result<UnixResponse, ProbeError> {
        let shown = self.shown(socket);
        let mut fields = Map::new();
        fields.insert("method".to_owned(), clip(method).into());
        fields.insert("path".to_owned(), shown.clone().into());
        fields.insert("url".to_owned(), clip(path).into());
        let what = format!("{shown} {}", clip(path));
        let (hub, entry) = self.begin(ActionKind::Http, fields, &what)?;

        let result = match self.admit_unix_shape(method, socket, path) {
            Err(rule) => return Err(refuse(entry, rule, &what)),
            Ok(()) => {
                // The real user id, asked of the backend only when a declared socket has `{uid}`.
                // If it cannot be read, `{uid}` matches nothing.
                let uid = if self.declares_uid_socket() {
                    self.process_ids().await.ok().map(|ids| ids.uid[0])
                } else {
                    None
                };
                if !self.socket_declared(socket, uid) {
                    return Err(refuse(entry, RULE_UNIX_UNDECLARED, &what));
                }
                let timeout = self
                    .scope
                    .peers
                    .timeout(within.map_or(UNIX_TIMEOUT, |w| w.min(UNIX_TIMEOUT)));
                self.unless_ended(&what, hub.backend.unix_get(socket, path, timeout))
                    .await
            }
        };
        settle(entry, result, |reply, entry| {
            entry.set("status", reply.status);
            entry.set("bytes", reply.body.len());
            entry.set("truncated", reply.truncated);
        })
    }

    /// The policy that needs no user id: the OS, the shape of the socket path, the method and the API
    /// path. Returns the rule that refuses the request.
    fn admit_unix_shape(
        &self,
        method: &str,
        socket: &Path,
        path: &str,
    ) -> Result<(), &'static str> {
        if self.scope.os == Os::Windows {
            return Err(RULE_UNIX_OS);
        }
        // By text, not `Path::is_absolute`, so the answer is the same on every host OS.
        let rooted = socket.to_str().is_some_and(|text| text.starts_with('/'));
        if !rooted || socket.components().any(|c| c == Component::ParentDir) {
            return Err(RULE_UNIX_PATH_SHAPE);
        }
        if method != "GET" {
            return Err(RULE_UNIX_METHOD);
        }
        if !api_path_allowed(path) {
            return Err(RULE_UNIX_API_PATH);
        }
        Ok(())
    }

    /// Whether any socket the check declared has a `{uid}` segment.
    fn declares_uid_socket(&self) -> bool {
        self.scope.info.is_some_and(|info| {
            info.peers
                .iter()
                .any(|peer| matches!(peer, PeerClass::UnixSocket(p) if p.contains(UID_SEGMENT)))
        })
    }

    /// Whether the check declared `socket`. `uid` is the process's real user id, if it is known.
    fn socket_declared(&self, socket: &Path, uid: Option<u32>) -> bool {
        self.scope.info.is_some_and(|info| {
            info.peers.iter().any(
                |peer| matches!(peer, PeerClass::UnixSocket(p) if socket_matches(p, socket, uid)),
            )
        })
    }

    /// The path as the log shows it.
    fn shown(&self, path: &Path) -> String {
        self.hub.as_ref().map_or_else(
            || path.to_string_lossy().into_owned(),
            |hub| hub.log.display_path(path),
        )
    }
}

/// `host:port` for messages, with brackets around an IPv6 literal.
pub(super) fn host_port(server: &Target) -> String {
    match server.host() {
        Host::Ipv6(addr) => format!("[{addr}]:{}", server.port()),
        host => format!("{host}:{}", server.port()),
    }
}

/// Cuts text that a check chose before it goes into the log or an error.
fn clip(text: &str) -> String {
    text.chars().take(256).collect()
}

/// Whether `path` is an allowlisted API path, after an optional `/v<major>.<minor>` prefix. A query
/// string, a fragment, an empty segment, a `.` or `..` segment and any other character fail.
fn api_path_allowed(path: &str) -> bool {
    let tail = match path.strip_prefix("/v") {
        Some(after) if after.starts_with(|c: char| c.is_ascii_digit()) => {
            let Some((version, tail)) = after.split_once('/') else {
                return false;
            };
            let mut parts = version.split('.');
            let numeric = |part: Option<&str>| {
                part.is_some_and(|p| {
                    !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit())
                })
            };
            if !(numeric(parts.next()) && numeric(parts.next()) && parts.next().is_none()) {
                return false;
            }
            tail
        }
        _ => path.strip_prefix('/').unwrap_or("/"),
    };
    UNIX_GET_PATHS
        .iter()
        .any(|allowed| allowed.strip_prefix('/') == Some(tail))
}

/// The segment of a declared socket that stands for the user id.
const UID_SEGMENT: &str = "{uid}";

/// Whether `socket` is the declared `pattern`, segment by segment, where `{uid}` matches the decimal
/// text of `uid`, the real user id of this process, and nothing else (no sign, no leading zero). With
/// no `uid`, `{uid}` matches nothing. Both are absolute. An empty segment (`//`), a `.` and a trailing
/// slash do not match.
fn socket_matches(pattern: &str, socket: &Path, uid: Option<u32>) -> bool {
    let Some(text) = socket.to_str() else {
        return false;
    };
    let (Some(wanted), Some(have)) = (pattern.strip_prefix('/'), text.strip_prefix('/')) else {
        return false;
    };
    let mut wanted = wanted.split('/');
    let mut have = have.split('/');
    loop {
        match (wanted.next(), have.next()) {
            (None, None) => return true,
            (Some(want), Some(got)) if !got.is_empty() && got != "." && got != ".." => {
                let same = if want == UID_SEGMENT {
                    uid.is_some_and(|uid| got == uid.to_string())
                } else {
                    want == got
                };
                if !same {
                    return false;
                }
            }
            _ => return false,
        }
    }
}
