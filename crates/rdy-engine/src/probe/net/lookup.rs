//! Name lookups for a check's own spec hosts (M1-094, ADR 0014 decision 2, 02 "Network").
//!
//! [`Probe::lookup`] resolves one spec host through the backend (the system resolver live, the
//! `net.json` `dns` table in a fixture) and vets every answer with the facade's address rule before it
//! returns anything. It is the lookup stage of `net.egress` (M1-095). `Probe::tcp` runs the same
//! resolve step inside its own call.
//!
//! **Policy, in order.** Every refusal is logged as `denied` and never reaches the backend.
//! - The check must declare [`PeerClass::SpecHosts`].
//! - The host must be one of the check's own spec hosts, at any port. A host that only another check
//!   lists is refused (INV-11). The text is compared in lower case, and an IPv6 literal may be written
//!   with or without brackets.
//! - A literal is judged without any lookup, and a refused literal is refused.
//! - If any answer of a name is in a refused range, the whole call is refused and the check gets no
//!   address at all (INV-12). A name that also points at a metadata address is not one to connect to.
//!   This holds for a recorded answer too: a Replay fixture with a link-local answer is refused here,
//!   not by the backend.
//!
//! **Answers.** Repeats are removed, the order the resolver gave is kept, and at most
//! [`MAX_ANSWERS`] are returned. A lookup that finds nothing is [`NetFailure::Dns`]. The lookup takes
//! at most [`RESOLVE_TIMEOUT`].
//!
//! **The log.** One `lookup` entry per call: `host` (as the check wrote it, cut to 256 characters) and
//! `answers`, the count returned. The addresses are not logged.

use std::net::IpAddr;

use rdy_spec::result::ActionKind;
use rdy_spec::scalar::Host;
use serde_json::Map;

use super::{RESOLVE_TIMEOUT, RULE_TCP_ADDRESS, RULE_TCP_UNDECLARED, fail_net, literal};
use crate::check::PeerClass;
use crate::probe::addr::is_unusable_peer;
use crate::probe::log::Pending;
use crate::probe::{NetFailure, Probe, ProbeError, ProbeHub, refuse, settle};

#[cfg(test)]
mod tests;

/// The most addresses one lookup returns.
pub const MAX_ANSWERS: usize = 64;

/// The rule of a lookup of a name that is not one of the check's spec hosts.
pub const RULE_LOOKUP_HOST: &str = "name is not one of the check's spec hosts";

impl Probe {
    /// Resolves `host`, one of the check's own spec hosts, and returns its addresses. See the
    /// [module docs](crate::probe::net).
    ///
    /// # Errors
    ///
    /// - [`ProbeError::Denied`] for an undeclared peer class, a host that is not one of the check's
    ///   spec hosts, an address in a refused range (literal or in any answer), or a call after the
    ///   check ended.
    /// - [`ProbeError::Net`] with [`NetFailure::Dns`] for a name that did not resolve.
    /// - [`ProbeError::Timeout`] when the resolver ran out of time.
    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ProbeError> {
        let shown: String = host.chars().take(256).collect();
        let mut fields = Map::new();
        fields.insert("host".to_owned(), shown.clone().into());
        let (hub, entry) = self.begin(ActionKind::Lookup, fields, &shown)?;

        let (spec_host, port) = match self.admit_lookup(host) {
            Ok(found) => found,
            Err(rule) => return Err(refuse(entry, rule, &shown)),
        };
        let name = match &spec_host {
            Host::Name(name) => name,
            other => {
                // A literal is judged as it is. No resolver is asked.
                return match literal(other) {
                    Some(addr) if is_unusable_peer(addr) => {
                        Err(refuse(entry, RULE_TCP_ADDRESS, &shown))
                    }
                    Some(addr) => settle(entry, Ok(vec![addr]), |answers, entry| {
                        noted(answers, entry)
                    }),
                    None => Err(refuse(entry, RULE_LOOKUP_HOST, &shown)),
                };
            }
        };

        let work = self.answers_of(hub, name, port);
        let result = match self.unless_ended(&shown, work).await {
            // Any answer in a refused range refuses the call, and the check sees none of them.
            Ok(answers) if answers.iter().any(|ip| is_unusable_peer(*ip)) => {
                Err(ProbeError::denied(RULE_TCP_ADDRESS, &shown))
            }
            Ok(answers) => Ok(dedupe(answers)),
            Err(error) => Err(error),
        };
        match result {
            Err(ProbeError::Net(failure)) => Err(fail_net(entry, failure)),
            other => settle(entry, other, |answers, entry| noted(answers, entry)),
        }
    }

    /// The policy before any lookup. Returns the matching spec host and its port.
    fn admit_lookup(&self, host: &str) -> Result<(Host, u16), &'static str> {
        let declared = self
            .scope
            .info
            .is_some_and(|info| info.peers.contains(&PeerClass::SpecHosts));
        if !declared {
            return Err(RULE_TCP_UNDECLARED);
        }
        self.scope
            .peers
            .spec_host(&host_of(host))
            .ok_or(RULE_LOOKUP_HOST)
    }

    /// What the resolver gave for `name`: an empty answer or a failure is [`NetFailure::Dns`], and a
    /// missing fixture or a timeout keeps its own error. The answers are not vetted here.
    pub(super) async fn answers_of(
        &self,
        hub: &ProbeHub,
        name: &str,
        port: u16,
    ) -> Result<Vec<IpAddr>, ProbeError> {
        let dns = |name: &str| {
            ProbeError::Net(NetFailure::Dns {
                host: name.to_owned(),
            })
        };
        let timeout = self.scope.peers.timeout(RESOLVE_TIMEOUT);
        let found = hub
            .backend
            .resolve(name, port, timeout)
            .await
            .map_err(|error| match ProbeError::from_io(&error) {
                failure @ (ProbeError::NotRecorded(_) | ProbeError::Timeout) => failure,
                _ => dns(name),
            })?;
        if found.is_empty() {
            return Err(dns(name));
        }
        Ok(found)
    }
}

/// The `answers` field of a successful lookup.
fn noted(answers: &[IpAddr], entry: &mut Pending) {
    entry.set("answers", answers.len());
}

/// The host a text names: an address literal (IPv6 with or without brackets), else a name in lower
/// case. The spec's names never end in a number, so a name does not parse as an address.
fn host_of(text: &str) -> Host {
    let bare = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Host::Ipv4(v4),
        Ok(IpAddr::V6(v6)) => Host::Ipv6(v6),
        Err(_) => Host::Name(text.to_ascii_lowercase()),
    }
}

/// Removes repeats and keeps the first [`MAX_ANSWERS`], in the order the resolver gave.
fn dedupe(answers: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::with_capacity(answers.len().min(MAX_ANSWERS));
    for ip in answers {
        if out.len() == MAX_ANSWERS {
            break;
        }
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}
