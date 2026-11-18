//! The per-nameserver lookups of `net.dns` (M1-155).
//!
//! For one name this asks each nameserver of the OS list, in order, with `Probe::nameserver_exchange`.
//! The check holds an **index** into that list and never an address (INV-11, ADR 0051): the facade reads the
//! list itself. So nothing here, and nothing in the evidence, can name a nameserver.
//!
//! Per nameserver: an A query over UDP. A reply with the TC bit is asked again over TCP. A reply with no A
//! address (NODATA), or a system answer that has IPv6 addresses, adds an AAAA query. A nameserver that
//! stays silent costs the facade's 3 s and is not asked a second question. The nameservers are asked one
//! after the other, so the time of the first is its own.

use std::net::IpAddr;
use std::time::Duration;

use rdy_engine::check::{CheckContext, CheckError, Need};
use rdy_engine::probe::sock::{DnsTransport, RULE_NS_ADDRESS};
use rdy_engine::probe::{ProbeError, RULE_NO_NETWORK};

use super::wire::{self, Qtype, Rcode};
use crate::text::{short, soft};

/// What one nameserver gave for one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NsAnswer {
    /// A well-formed reply to our question. `addrs` joins the A and, when asked, the AAAA answers.
    Replied {
        rcode: Rcode,
        addrs: Vec<IpAddr>,
        /// Whether the answer came over TCP after a truncated UDP reply.
        over_tcp: bool,
        /// Whether AAAA was asked too, so the family set to compare is both.
        asked_v6: bool,
    },
    /// No reply in time.
    Timeout,
    /// The nameserver refused the connection (ICMP port unreachable, or a closed TCP port).
    Refused,
    /// The facade will not query this nameserver. The text is the facade's rule.
    Skipped(&'static str),
    /// Bytes came back that are not an answer to our question. The text says how.
    Bad(&'static str),
    /// Another failure. The text says what.
    Failed(String),
    /// The check ran out of time before this nameserver.
    NotTried,
}

/// One nameserver, by its place in the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NsResult {
    /// Zero-based place in the OS list.
    pub(super) index: usize,
    pub(super) took: Duration,
    pub(super) answer: NsAnswer,
}

/// What one exchange came to, before it is joined with the others.
enum Exchange {
    Reply(wire::Reply),
    Over(NsAnswer),
}

async fn exchange(
    ctx: &CheckContext,
    index: usize,
    name: &str,
    qtype: Qtype,
    transport: DnsTransport,
) -> Result<Exchange, CheckError> {
    let query = match wire::build_query(name, qtype) {
        Ok(q) => q,
        Err(why) => return Ok(Exchange::Over(NsAnswer::Bad(why))),
    };
    match ctx
        .probe()
        .nameserver_exchange(index, &query, transport)
        .await
    {
        Ok(reply) => Ok(match reply.query_id {
            // The facade picked the message ID and reports it. A reply without one cannot be matched.
            None => Exchange::Over(NsAnswer::Bad("the facade gave no message ID")),
            Some(id) => match wire::parse_reply(&reply.bytes, reply.truncated, id, name, qtype) {
                Ok(parsed) => Exchange::Reply(parsed),
                Err(why) => Exchange::Over(NsAnswer::Bad(why)),
            },
        }),
        Err(error) if error.is_no_network() => Err(CheckError::MissingNeed(Need::Network)),
        // A nameserver in a refused range (the GCE metadata address is the usual one) is skipped with
        // the facade's own words. Every other refusal is a mistake in this check's manifest.
        Err(ProbeError::Denied { rule, .. }) if rule == RULE_NS_ADDRESS => {
            Ok(Exchange::Over(NsAnswer::Skipped(RULE_NS_ADDRESS)))
        }
        Err(ProbeError::Denied { rule, .. }) if rule == RULE_NO_NETWORK => {
            Err(CheckError::MissingNeed(Need::Network))
        }
        Err(ProbeError::Timeout) => Ok(Exchange::Over(NsAnswer::Timeout)),
        Err(ProbeError::ConnectionRefused) => Ok(Exchange::Over(NsAnswer::Refused)),
        Err(other) => Ok(Exchange::Over(NsAnswer::Failed(short(&soft(other)?)))),
    }
}

/// One nameserver: A, TCP if truncated, AAAA if wanted.
async fn ask_one(
    ctx: &CheckContext,
    index: usize,
    name: &str,
    want_v6: bool,
) -> Result<NsAnswer, CheckError> {
    let mut over_tcp = false;
    let mut first = match exchange(ctx, index, name, Qtype::A, DnsTransport::Udp).await? {
        Exchange::Over(answer) => return Ok(answer),
        Exchange::Reply(reply) => reply,
    };
    if first.truncated {
        over_tcp = true;
        first = match exchange(ctx, index, name, Qtype::A, DnsTransport::Tcp).await? {
            Exchange::Over(answer) => return Ok(answer),
            Exchange::Reply(reply) => reply,
        };
    }
    let mut addrs = first.addrs;
    let mut asked_v6 = false;
    // A name with no A record may be IPv6 only, and a system answer with IPv6 is compared like for like.
    if first.rcode == Rcode::NoError && (want_v6 || addrs.is_empty()) {
        asked_v6 = true;
        match exchange(ctx, index, name, Qtype::Aaaa, DnsTransport::Udp).await? {
            Exchange::Reply(second) if !second.truncated => {
                for ip in second.addrs {
                    if !addrs.contains(&ip) {
                        addrs.push(ip);
                    }
                }
            }
            // A failed or truncated second question leaves the first answer, and the family set shrinks
            // back to IPv4, so the comparison never blames a name for what rdy could not ask.
            _ => asked_v6 = false,
        }
    }
    Ok(NsAnswer::Replied {
        rcode: first.rcode,
        addrs,
        over_tcp,
        asked_v6,
    })
}

/// Asks nameservers `0..count` about `name`, in order, until `budget` is spent. A nameserver not reached
/// in time is `NotTried`.
pub(super) async fn ask_all(
    ctx: &CheckContext,
    name: &str,
    count: usize,
    want_v6: bool,
    budget: Duration,
) -> Result<Vec<NsResult>, CheckError> {
    let mut out = Vec::with_capacity(count);
    let start = ctx.remaining();
    for index in 0..count {
        let spent = start.saturating_sub(ctx.remaining());
        let left = budget.saturating_sub(spent);
        if left.is_zero() {
            out.push(NsResult {
                index,
                took: Duration::ZERO,
                answer: NsAnswer::NotTried,
            });
            continue;
        }
        let before = ctx.remaining();
        let answer = match ctx.within(left, ask_one(ctx, index, name, want_v6)).await {
            Some(done) => done?,
            None => NsAnswer::Timeout,
        };
        out.push(NsResult {
            index,
            took: before.saturating_sub(ctx.remaining()),
            answer,
        });
    }
    Ok(out)
}
