//! `net.json`: scripted name lookups and connections (08 Appendix A).
//!
//! The connections are data in [`NetScript`], read through [`Replay::dial`](super::Replay::dial). The
//! name answers are not here: the loader puts them in the one table that `Backend::resolve` reads (see
//! `sock::replay`), so a fixture's recorded answer is what the facade's lookup gets. A lookup may
//! answer with an address the engine refuses (a link-local one, say): the table holds it as recorded
//! so that the address rule runs in every net fixture, and the rule is the facade's.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

/// What a name lookup answers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsAnswer {
    /// These addresses, in order. They may include ones the address rule refuses.
    Addrs(Vec<IpAddr>),
    /// The name does not exist.
    NxDomain,
}

/// What connecting to an address does.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpScript {
    /// The connection works and an in-process server answers. The name is a server factory that the
    /// test registers (it comes from the loopback test support of `rdy-checks-net`).
    Serve(String),
    /// The connection is refused.
    Refused,
    /// The connection is reset.
    Reset,
    /// The connection never completes. No timer and no thread: the caller's timeout ends it, and
    /// under paused time the wait costs nothing.
    Blackhole,
}

/// The parsed `net.json` of a fixture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetScript {
    tcp: BTreeMap<SocketAddr, TcpScript>,
}

impl NetScript {
    /// What connecting to `addr` does, or `None` when the fixture has no entry.
    #[must_use]
    pub fn tcp(&self, addr: SocketAddr) -> Option<&TcpScript> {
        self.tcp.get(&addr)
    }

    pub(crate) fn insert_tcp(&mut self, addr: SocketAddr, script: TcpScript) {
        self.tcp.insert(addr, script);
    }
}
