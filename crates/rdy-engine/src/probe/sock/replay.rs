//! The recorded half of the socket calls: names, datagram servers and unix socket replies.
//!
//! A fixture run goes through the same policy and the same action log as a live run. Only the I/O is
//! replaced, so a test sees what a run would refuse. Anything the fixture does not hold is "not
//! recorded" (a name), "not found" (a socket) or "refused" (a datagram server), so a test that forgets
//! one fails loudly.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{DnsTransport, UdpReply, UnixResponse};
use crate::probe::ProbeError;
use crate::probe::replay::{DnsAnswer, Replay, Unrecorded};

/// How a recorded datagram server answers: bytes back, or `None` for a server that stays silent.
type Responder = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// What a scripted DNS server does with one query.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsScript {
    /// Answers with these bytes: the bare DNS message, with no TCP length prefix.
    Answer(Vec<u8>),
    /// Does not answer. The call takes its whole timeout and ends as `Timeout`.
    Silent,
    /// Refuses: an ICMP port unreachable over UDP, a refused connect over TCP. A server that speaks UDP
    /// only answers `Refused` to the TCP queries.
    Refused,
}

/// How a scripted DNS server answers a query, given the transport it came in on.
type DnsResponder = Arc<dyn Fn(&[u8], DnsTransport) -> DnsScript + Send + Sync>;

/// The first answer, the later answer and the lookups so far of a rebinding name.
type Rebind = (Vec<IpAddr>, Vec<IpAddr>, Arc<AtomicUsize>);

/// The recorded names, datagram servers and unix socket replies of a [`Replay`].
#[derive(Clone, Default)]
pub(crate) struct ReplayNet {
    names: HashMap<String, DnsAnswer>,
    /// Names whose answer changes after the first lookup: `(first, later, lookups so far)`.
    rebinding: HashMap<String, Rebind>,
    /// Names whose lookup waits first, on the tokio clock.
    delays: HashMap<String, Duration>,
    udp: HashMap<SocketAddr, Responder>,
    dns: HashMap<SocketAddr, DnsResponder>,
    dns_delays: HashMap<SocketAddr, Duration>,
    unix: HashMap<(PathBuf, String), (u16, Vec<u8>, Duration)>,
}

impl fmt::Debug for ReplayNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayNet")
            .field("names", &self.names)
            .field("udp", &self.udp.keys().collect::<Vec<_>>())
            .field("unix", &self.unix.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ReplayNet {
    /// Records the answer for a name. Names compare without regard to case, so the key is lower case.
    pub(crate) fn insert_name(&mut self, host: &str, answer: DnsAnswer) {
        self.names.insert(host.to_ascii_lowercase(), answer);
    }

    /// The recorded answer for a name, or `None`.
    pub(crate) fn name(&self, host: &str) -> Option<&DnsAnswer> {
        self.names.get(&host.to_ascii_lowercase())
    }

    /// How long a lookup of `host` waits before it answers.
    pub(crate) fn delay(&self, host: &str) -> Duration {
        self.delays
            .get(&host.to_ascii_lowercase())
            .copied()
            .unwrap_or_default()
    }

    /// What a lookup of `host` gives. A name the fixture does not hold is "not recorded": nothing says
    /// the name does not exist, so the test fails loudly. A recorded `NXDOMAIN` is "not found".
    pub(crate) fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Some((first, later, seen)) = self.rebinding.get(&host.to_ascii_lowercase()) {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            return Ok(if n == 0 { first.clone() } else { later.clone() });
        }
        match self.name(host) {
            Some(DnsAnswer::Addrs(addrs)) => Ok(addrs.clone()),
            Some(DnsAnswer::NxDomain) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no such name in the replay fixture: {host}"),
            )),
            None => Err(Unrecorded::error(format!("a lookup of {host}"))),
        }
    }

    pub(crate) fn udp(
        &self,
        to: SocketAddr,
        payload: &[u8],
        max_reply: usize,
    ) -> Result<UdpReply, ProbeError> {
        let Some(responder) = self.udp.get(&to) else {
            return Err(ProbeError::from_io(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("no datagram server in the replay fixture at {to}"),
            )));
        };
        let Some(mut bytes) = responder(payload) else {
            return Err(ProbeError::Timeout);
        };
        let truncated = bytes.len() > max_reply;
        bytes.truncate(max_reply);
        let mut reply = UdpReply::new(bytes, to.ip());
        reply.truncated = truncated;
        Ok(reply)
    }

    /// How long a scripted DNS server at `to` waits before it answers.
    pub(crate) fn dns_delay(&self, to: SocketAddr) -> Duration {
        self.dns_delays.get(&to).copied().unwrap_or_default()
    }

    /// What the scripted DNS server at `to` does with `payload`. No server there is a refusal.
    pub(crate) fn dns(
        &self,
        to: SocketAddr,
        payload: &[u8],
        transport: DnsTransport,
        max_reply: usize,
    ) -> Result<UdpReply, ProbeError> {
        let refused = || {
            ProbeError::from_io(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("no DNS server in the replay fixture at {to}"),
            ))
        };
        let Some(responder) = self.dns.get(&to) else {
            return Err(refused());
        };
        match responder(payload, transport) {
            DnsScript::Answer(mut bytes) => {
                let truncated = bytes.len() > max_reply;
                bytes.truncate(max_reply);
                let mut reply = UdpReply::new(bytes, to.ip());
                reply.truncated = truncated;
                Ok(reply)
            }
            DnsScript::Silent => Err(ProbeError::Timeout),
            DnsScript::Refused => Err(refused()),
        }
    }

    /// The recorded reply to `GET path` on `socket` and how long the server waits before it answers.
    pub(crate) fn unix(
        &self,
        socket: &Path,
        path: &str,
    ) -> Result<(UnixResponse, Duration), ProbeError> {
        self.unix
            .get(&(socket.to_path_buf(), path.to_owned()))
            .map(|(status, body, delay)| (UnixResponse::new(*status, body.clone()), *delay))
            .ok_or(ProbeError::NotFound)
    }
}

impl Replay {
    /// Makes every lookup of `name` wait `delay` on the tokio clock before it answers, as a slow
    /// resolver does. Under paused time the wait costs nothing and a timing reads the exact delay.
    #[must_use]
    pub fn lookup_delay(mut self, name: &str, delay: Duration) -> Self {
        self.net.delays.insert(name.to_ascii_lowercase(), delay);
        self
    }

    /// Adds a name that answers `first` to its first lookup and `later` to every lookup after it, as a
    /// DNS rebinding attack does: a public address for the check's vetting lookup, a metadata address
    /// for the connect-time lookup. The facade must refuse the second answer on its own.
    #[must_use]
    pub fn host_rebinding(
        mut self,
        name: &str,
        first: impl IntoIterator<Item = IpAddr>,
        later: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        self.net.rebinding.insert(
            name.to_ascii_lowercase(),
            (
                first.into_iter().collect(),
                later.into_iter().collect(),
                Arc::new(AtomicUsize::new(0)),
            ),
        );
        self
    }

    /// Adds a name that `udp_exchange` can resolve. A name that is not added is "not recorded". Names
    /// compare without regard to case. A fixture's `net.json` fills the same table.
    #[must_use]
    pub fn host(mut self, name: &str, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.net
            .insert_name(name, DnsAnswer::Addrs(addrs.into_iter().collect()));
        self
    }

    /// The recorded answer for a name, or `None` when the machine holds none. Names compare without
    /// regard to case.
    #[must_use]
    pub fn dns(&self, host: &str) -> Option<&DnsAnswer> {
        self.net.name(host)
    }

    /// Adds a datagram server at `addr`. `reply` gets the datagram that was sent and returns the
    /// reply, so a test can echo the transmit timestamp of an SNTP request.
    #[must_use]
    pub fn udp_server(
        mut self,
        addr: SocketAddr,
        reply: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.net
            .udp
            .insert(addr, Arc::new(move |sent| Some(reply(sent))));
        self
    }

    /// Adds a datagram server at `addr` that never answers. The call times out.
    #[must_use]
    pub fn udp_silent(mut self, addr: SocketAddr) -> Self {
        self.net.udp.insert(addr, Arc::new(|_| None));
        self
    }

    /// Adds a scripted DNS server at `addr`, the address of a nameserver in the fixture's
    /// `/etc/resolv.conf` (port 53, as `Probe::nameserver_exchange` uses). `script` gets the query as
    /// the check sent it (no TCP length prefix) and the transport, and says what the server does. A
    /// later call for the same address replaces the earlier one.
    #[must_use]
    pub fn dns_server(
        mut self,
        addr: SocketAddr,
        script: impl Fn(&[u8], DnsTransport) -> DnsScript + Send + Sync + 'static,
    ) -> Self {
        self.net.dns.insert(addr, Arc::new(script));
        self
    }

    /// Adds a DNS server at `addr` that never answers, over UDP or TCP.
    #[must_use]
    pub fn dns_silent(self, addr: SocketAddr) -> Self {
        self.dns_server(addr, |_, _| DnsScript::Silent)
    }

    /// Makes the DNS server at `addr` wait `delay` on the tokio clock before every answer, as a slow
    /// first nameserver does. A delay at or past the call's timeout is a timeout. Under paused time the
    /// wait costs nothing.
    #[must_use]
    pub fn dns_delay(mut self, addr: SocketAddr, delay: Duration) -> Self {
        self.net.dns_delays.insert(addr, delay);
        self
    }

    /// Adds the reply to `GET path` on the unix socket at `socket`.
    #[must_use]
    pub fn unix_get(
        self,
        socket: impl Into<PathBuf>,
        path: &str,
        status: u16,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        self.unix_get_after(socket, path, status, body, Duration::ZERO)
    }

    /// Adds the reply to `GET path` on the unix socket at `socket`, sent after `delay` on the tokio
    /// clock. A delay past the check's timeout is a daemon that hangs (a fixture `api/*.json` file with
    /// a large `delay_ms`). It needs feature `runtime`.
    #[must_use]
    pub fn unix_get_after(
        mut self,
        socket: impl Into<PathBuf>,
        path: &str,
        status: u16,
        body: impl Into<Vec<u8>>,
        delay: Duration,
    ) -> Self {
        self.net.unix.insert(
            (socket.into(), path.to_owned()),
            (status, body.into(), delay),
        );
        self
    }
}
