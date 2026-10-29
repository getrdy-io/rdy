//! The recorded half of the socket calls: names, datagram servers and unix socket replies.
//!
//! A fixture run goes through the same policy and the same action log as a live run. Only the I/O is
//! replaced, so a test sees what a run would refuse. Anything the fixture does not hold is "not
//! found" (a name, a socket) or "refused" (a datagram server), so a test that forgets one fails loudly.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{UdpReply, UnixResponse};
use crate::probe::ProbeError;
use crate::probe::replay::Replay;

/// How a recorded datagram server answers: bytes back, or `None` for a server that stays silent.
type Responder = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// The recorded names, datagram servers and unix socket replies of a [`Replay`].
#[derive(Clone, Default)]
pub(crate) struct ReplayNet {
    names: HashMap<String, Vec<IpAddr>>,
    udp: HashMap<SocketAddr, Responder>,
    unix: HashMap<(PathBuf, String), (u16, Vec<u8>)>,
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
    pub(crate) fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.names.get(host).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("not in the replay fixture: {host}"),
            )
        })
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

    pub(crate) fn unix(&self, socket: &Path, path: &str) -> Result<UnixResponse, ProbeError> {
        self.unix
            .get(&(socket.to_path_buf(), path.to_owned()))
            .map(|(status, body)| UnixResponse::new(*status, body.clone()))
            .ok_or(ProbeError::NotFound)
    }
}

impl Replay {
    /// Adds a name that `udp_exchange` can resolve. A name that is not added is "not found".
    #[must_use]
    pub fn host(mut self, name: &str, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.net
            .names
            .insert(name.to_owned(), addrs.into_iter().collect());
        self
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
        mut self,
        socket: impl Into<PathBuf>,
        path: &str,
        status: u16,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        self.net
            .unix
            .insert((socket.into(), path.to_owned()), (status, body.into()));
        self
    }
}
