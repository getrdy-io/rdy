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
use std::time::Duration;

use super::{UdpReply, UnixResponse};
use crate::probe::ProbeError;
use crate::probe::replay::{DnsAnswer, Replay, Unrecorded};

/// How a recorded datagram server answers: bytes back, or `None` for a server that stays silent.
type Responder = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// The recorded names, datagram servers and unix socket replies of a [`Replay`].
#[derive(Clone, Default)]
pub(crate) struct ReplayNet {
    names: HashMap<String, DnsAnswer>,
    udp: HashMap<SocketAddr, Responder>,
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

    /// What a lookup of `host` gives. A name the fixture does not hold is "not recorded": nothing says
    /// the name does not exist, so the test fails loudly. A recorded `NXDOMAIN` is "not found".
    pub(crate) fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
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
