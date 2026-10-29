//! `net.json`: scripted name lookups and connections (08 Appendix A).
//!
//! The script is data. The facade's name and socket calls arrive with the network tickets (M1-091 and
//! M1-094), and they read it through [`NetScript`] and [`Replay::dial`](super::Replay::dial). A lookup
//! may answer with an address the engine refuses (a link-local one, say): the script holds it as
//! recorded so that the address rule runs in every net fixture, and the rule is the facade's.

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
    dns: BTreeMap<String, DnsAnswer>,
    tcp: BTreeMap<SocketAddr, TcpScript>,
}

impl NetScript {
    /// The answer for a host name, or `None` when the fixture has none. Names compare without regard
    /// to case.
    #[must_use]
    pub fn dns(&self, host: &str) -> Option<&DnsAnswer> {
        self.dns.get(&host.to_ascii_lowercase())
    }

    /// What connecting to `addr` does, or `None` when the fixture has no entry.
    #[must_use]
    pub fn tcp(&self, addr: SocketAddr) -> Option<&TcpScript> {
        self.tcp.get(&addr)
    }

    pub(super) fn insert_dns(&mut self, host: &str, answer: DnsAnswer) {
        self.dns.insert(host.to_ascii_lowercase(), answer);
    }

    pub(super) fn insert_tcp(&mut self, addr: SocketAddr, script: TcpScript) {
        self.tcp.insert(addr, script);
    }
}
