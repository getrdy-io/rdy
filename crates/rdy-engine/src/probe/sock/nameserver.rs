//! Direct nameserver queries (M1-155, ADR 0051, 02 "Network", 05 SEC-17).
//!
//! [`Probe::nameserver_exchange`] sends one DNS query to one of the nameservers the OS lists and reads
//! one reply. It serves the per-nameserver lookups of `net.dns`. [`Probe::nameserver_count`] says how
//! many there are.
//!
//! **A check names no address (INV-11).** The facade reads the OS nameserver list itself, with its own
//! read policy ([`NAMESERVER_FILES`], Linux only for now), and the check passes an index into it. The
//! list is read once per check and kept, so the count and the indexes agree. At most
//! [`MAX_NAMESERVERS`] are used, as the system resolver does. A line is `nameserver <address>`. A zone
//! id (`fe80::1%eth0`) is cut off before the address is judged.
//!
//! **Admission.**
//! - The check must declare [`PeerClass::SystemResolver`].
//! - The port is [`NAMESERVER_PORT`] (53). The check cannot change it.
//! - The transport is UDP or TCP ([`DnsTransport`]). TCP is framed by the backend with the two byte
//!   length of RFC 1035.
//! - The payload is a DNS query: 12 to [`MAX_DNS_QUERY`] bytes, opcode 0, one question with no name
//!   compression, no answer or authority records, at most one additional record. Anything else is
//!   refused, so this call cannot carry arbitrary bytes to port 53.
//! - An address that `is_unusable_peer` rejects is refused: link-local, the cloud metadata addresses,
//!   unspecified, multicast and broadcast, and the IPv4-mapped, IPv4-compatible and NAT64 forms of
//!   them. Loopback and private addresses pass (a stub resolver on `127.0.0.53` is normal).
//! - **The Azure door.** `168.63.129.16` is the Azure virtual DNS address and is refused everywhere
//!   else. Here, and only here, it passes when it is the exact IPv4 address that the OS list gave. The
//!   port is 53 by construction. A spec host at that address, any other port, and the IPv4-mapped and
//!   NAT64 forms stay refused.
//!
//! **Caps.** The reply is cut at [`MAX_NAMESERVER_UDP_REPLY`] over UDP and [`MAX_NAMESERVER_TCP_REPLY`]
//! over TCP, and the cut is flagged. The whole call takes at most [`NAMESERVER_TIMEOUT`]. A silent
//! server is [`ProbeError::Timeout`].
//!
//! **Log.** One `dns` entry per call: `server` (the address), `name` and `rtype` of the question,
//! `proto` `udp` for a datagram (absent for TCP, as for `connect`), and the reply `bytes` and
//! `truncated`. The payload and the reply are never logged. The read of the list is its own `read`
//! entry, once per check.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rdy_spec::result::ActionKind;
use serde_json::Map;

use super::UdpReply;
use crate::check::{Os, PeerClass};
use crate::probe::addr::{is_azure_dns, is_unusable_peer};
use crate::probe::policy::ReadGuard;
use crate::probe::{MAX_READ, Probe, ProbeError, RULE_NO_NETWORK, ReadRange, settle};

/// The port of every nameserver query.
pub const NAMESERVER_PORT: u16 = 53;

/// The most nameservers used. The system resolver ignores any after the third.
pub const MAX_NAMESERVERS: usize = 3;

/// The most time one nameserver exchange may take.
pub const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(3);

/// The largest query a check may send.
pub const MAX_DNS_QUERY: usize = 512;

/// The largest UDP reply kept.
pub const MAX_NAMESERVER_UDP_REPLY: usize = 4096;

/// The largest TCP reply kept.
pub const MAX_NAMESERVER_TCP_REPLY: usize = 16 * 1024;

/// The files the facade reads the nameserver list from, as its own read policy. The first is the one it
/// reads. The other two are where it may lead (`systemd-resolved`).
pub const NAMESERVER_FILES: &[&str] = &[
    "/etc/resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/run/systemd/resolve/stub-resolv.conf",
];

/// The rule of a nameserver call from a check that did not declare `PeerClass::SystemResolver`.
pub const RULE_NS_UNDECLARED: &str = "system resolver peer class not declared by the check";

/// The rule of a nameserver whose address is in a refused range. A check reports it as Skipped.
pub const RULE_NS_ADDRESS: &str = "nameserver in a refused range";

/// The rule of an index past the end of the nameserver list.
pub const RULE_NS_INDEX: &str = "no such nameserver in the OS list";

/// The rule of a payload that is not a single plain DNS query.
pub const RULE_NS_PAYLOAD: &str = "payload must be one DNS query of 12 to 512 bytes";

/// How a query travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DnsTransport {
    /// One datagram, one reply.
    Udp,
    /// One stream, with the two byte length prefix of RFC 1035 on the query and the reply. The probe
    /// and the caller see the bare message.
    Tcp,
}

impl DnsTransport {
    /// The reply cap of this transport.
    #[must_use]
    pub const fn reply_cap(self) -> usize {
        match self {
            Self::Udp => MAX_NAMESERVER_UDP_REPLY,
            Self::Tcp => MAX_NAMESERVER_TCP_REPLY,
        }
    }
}

impl Probe {
    /// How many nameservers the OS lists, at most [`MAX_NAMESERVERS`]. It returns a count and no address.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] when the check did not declare [`PeerClass::SystemResolver`] or ended;
    /// [`ProbeError::Unsupported`] on an OS that has no source yet; [`ProbeError::NotFound`] when the
    /// list file is missing; the other variants when the read fails.
    pub async fn nameserver_count(&self) -> Result<usize, ProbeError> {
        Ok(self.nameserver_list().await?.len())
    }

    /// Sends the DNS query `payload` to nameserver number `index` of the OS list and reads one reply.
    /// See the [module docs](crate::probe::sock::nameserver) for the admission rules and the caps.
    ///
    /// # Errors
    ///
    /// [`ProbeError::Denied`] for an undeclared class, a payload that is not one DNS query, an index
    /// past the list, a nameserver in a refused range, `--no-network`, or a call after the check ended;
    /// [`ProbeError::Timeout`] when no reply came in time; [`ProbeError::ConnectionRefused`] for a
    /// refusal; [`ProbeError::Unsupported`] and [`ProbeError::NotFound`] as [`Probe::nameserver_count`];
    /// [`ProbeError::Io`] for the other failures.
    pub async fn nameserver_exchange(
        &self,
        index: usize,
        payload: &[u8],
        transport: DnsTransport,
    ) -> Result<UdpReply, ProbeError> {
        let what = format!("nameserver {index}");
        let (hub, mut entry) = self.begin(ActionKind::Dns, Map::new(), &what)?;
        if transport == DnsTransport::Udp {
            entry.set("proto", "udp");
        }
        let result = match self.admit_nameserver(payload, &what) {
            Err(error) => Err(error),
            Ok(question) => {
                entry.set("name", question.name);
                entry.set("rtype", question.rtype);
                let timeout = self.scope.peers.timeout(NAMESERVER_TIMEOUT);
                let work = async {
                    let started = Instant::now();
                    let list = self.nameserver_list().await?;
                    let ip = *list
                        .get(index)
                        .ok_or_else(|| ProbeError::denied(RULE_NS_INDEX, &what))?;
                    entry.set("server", ip.to_string());
                    if is_unusable_peer(ip) && !is_azure_dns(ip) {
                        return Err(ProbeError::denied(RULE_NS_ADDRESS, &what));
                    }
                    let left = timeout.saturating_sub(started.elapsed());
                    hub.backend
                        .dns_exchange(
                            SocketAddr::new(ip, NAMESERVER_PORT),
                            payload,
                            transport,
                            transport.reply_cap(),
                            left,
                        )
                        .await
                };
                self.unless_ended(&what, work).await
            }
        };
        settle(entry, result, |reply, entry| {
            entry.set("bytes", reply.bytes.len());
            entry.set("truncated", reply.truncated);
        })
    }

    /// The checks before any file is read or socket opened.
    fn admit_nameserver(&self, payload: &[u8], what: &str) -> Result<Question, ProbeError> {
        if self.offline() {
            return Err(ProbeError::denied(RULE_NO_NETWORK, what));
        }
        self.require_system_resolver(what)?;
        parse_query(payload).ok_or_else(|| ProbeError::denied(RULE_NS_PAYLOAD, what))
    }

    fn require_system_resolver(&self, what: &str) -> Result<(), ProbeError> {
        let declared = self
            .scope
            .info
            .is_some_and(|info| info.peers.contains(&PeerClass::SystemResolver));
        if declared {
            Ok(())
        } else {
            Err(ProbeError::denied(RULE_NS_UNDECLARED, what))
        }
    }

    /// The OS nameserver list, read once through the facade's own file policy and kept.
    async fn nameserver_list(&self) -> Result<Vec<IpAddr>, ProbeError> {
        let path = NAMESERVER_FILES[0];
        if let Some(list) = self.scope.peers.nameservers.get() {
            self.require_system_resolver(path)?;
            return Ok(list.clone());
        }
        let mut fields = Map::new();
        fields.insert("path".to_owned(), path.into());
        let (hub, entry) = self.begin(ActionKind::Read, fields, path)?;
        let read = match self.require_system_resolver(path) {
            Err(error) => Err(error),
            Ok(()) if self.scope.os != Os::Linux => {
                Err(ProbeError::Unsupported("the nameserver list".to_owned()))
            }
            Ok(()) => {
                let guard = ReadGuard::new(Os::Linux, Some(NAMESERVER_FILES));
                let file_path = std::path::Path::new(path);
                match guard.admit(file_path) {
                    Err(rule) => Err(ProbeError::denied(rule, path)),
                    Ok(()) => {
                        self.unless_ended(path, async {
                            hub.backend
                                .open_read(file_path, ReadRange::Head(MAX_READ), &guard)
                                .await
                                .map_err(|e| ProbeError::from_file_io(&e, path))
                        })
                        .await
                    }
                }
            }
        };
        let file = settle(entry, read, |file, entry| {
            entry.set("bytes", file.bytes.len());
            entry.set("truncated", file.truncated());
        })?;
        let list = parse_nameservers(&file.bytes);
        // A second reader may have set it first. The list that won is the one every call sees.
        let _ = self.scope.peers.nameservers.set(list);
        Ok(self
            .scope
            .peers
            .nameservers
            .get()
            .cloned()
            .unwrap_or_default())
    }
}

/// The nameservers of a `resolv.conf`, in order, at most [`MAX_NAMESERVERS`]. A line that is not
/// `nameserver <address>` and an address that does not parse are skipped.
pub(crate) fn parse_nameservers(bytes: &[u8]) -> Vec<IpAddr> {
    let text = String::from_utf8_lossy(bytes);
    let mut list = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() != Some("nameserver") {
            continue;
        }
        let Some(word) = words.next() else { continue };
        // A zone id is the interface of a link-local address. The address is judged without it.
        let bare = word.split('%').next().unwrap_or(word);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            list.push(ip);
            if list.len() == MAX_NAMESERVERS {
                break;
            }
        }
    }
    list
}

/// The question of a query, for the log.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub(crate) name: String,
    pub(crate) rtype: String,
}

/// Reads the one question of a plain query, or `None` when the payload is anything else.
pub(crate) fn parse_query(payload: &[u8]) -> Option<Question> {
    if payload.len() < 12 || payload.len() > MAX_DNS_QUERY {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let count = |at: usize| u16::from_be_bytes([payload[at], payload[at + 1]]);
    // A query (QR 0), opcode QUERY, one question, no answer or authority records, at most one
    // additional record (EDNS).
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 {
        return None;
    }
    if count(4) != 1 || count(6) != 0 || count(8) != 0 || count(10) > 1 {
        return None;
    }
    let mut at = 12;
    let mut name = String::new();
    loop {
        let len = usize::from(*payload.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        // A label is at most 63 bytes. The top two bits mean compression or an extended label.
        if len > 63 {
            return None;
        }
        let label = payload.get(at..at + len)?;
        at += len;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                char::from(b.to_ascii_lowercase())
            } else {
                '?'
            }
        }));
        if name.len() > 253 {
            return None;
        }
    }
    let tail = payload.get(at..at + 4)?;
    let rtype = rtype_text(u16::from_be_bytes([tail[0], tail[1]]));
    if name.is_empty() {
        name.push('.');
    }
    Some(Question { name, rtype })
}

fn rtype_text(code: u16) -> String {
    match code {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        12 => "PTR".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        28 => "AAAA".to_owned(),
        33 => "SRV".to_owned(),
        255 => "ANY".to_owned(),
        other => format!("TYPE{other}"),
    }
}

#[cfg(test)]
mod tests;
