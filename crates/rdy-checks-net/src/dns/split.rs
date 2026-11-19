//! What the direct nameserver answers mean (M1-155): split horizon, a slow or dead first nameserver,
//! NXDOMAIN, and the `nsswitch.conf` and `resolv.conf` findings. Pure, so the tests feed it facts.
//!
//! Nameservers are named by **position** in the OS list, counted from 1 ("nameserver 2"). The check never
//! holds an address (INV-11), so none can reach a message or the evidence.
//!
//! Rules (03 section 3, net.dns):
//! - A nameserver that answers with addresses that differ from the system answer, within the families
//!   asked: warn, split horizon.
//! - A nameserver that does not answer while another does: warn, "slow first hop adds a timeout to every
//!   lookup" when it is the first.
//! - A nameserver that answers slower than `max_latency`: warn.
//! - NXDOMAIN from every nameserver that answered, with no system answer: the `not found` block of the
//!   system lookup stands, and its fix names the nameserver and the code. NXDOMAIN while the system
//!   answer exists: warn (the name is found only through `/etc/hosts` or another NSS source).
//! - `mdns` with `[NOTFOUND=return]` before `dns`: warn when a spec name ends in `.local`, a note
//!   otherwise. `sss`: warn when a name failed or was slow, a note otherwise. No `dns` or `resolve`: warn.

use std::net::IpAddr;
use std::time::Duration;

use serde_json::{Value, json};

use super::direct::{NsAnswer, NsResult};
use super::judge::{Answer, Looked, Rule};
use super::parse::{Hosts, ResolvFacts};
use super::wire::Rcode;
use crate::text::code;

/// The most addresses of one nameserver's answer shown in the evidence.
const SHOWN: usize = 16;

/// What was read of this machine's resolver files.
#[derive(Debug, Clone, Default)]
pub(super) struct Machine {
    pub(super) hosts: Option<Hosts>,
    pub(super) facts: Option<ResolvFacts>,
    /// How many nameservers the facade listed, which is how many were asked about each name.
    pub(super) asked: usize,
    /// Why no nameserver was asked, when the list could not be read.
    pub(super) list_problem: Option<String>,
}

/// What the direct answers add to the finding.
#[derive(Debug, Default)]
pub(super) struct Assessment {
    pub(super) warns: Vec<String>,
    pub(super) notes: Vec<String>,
    pub(super) fixes: Vec<String>,
    /// Positions (from 1) the facade would not query.
    pub(super) skipped: Vec<usize>,
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn push_once(list: &mut Vec<String>, text: String) {
    if !list.contains(&text) {
        list.push(text);
    }
}

/// Whether the addresses a nameserver gave share at least one address with the system answer, within the
/// families that were asked. A CDN, a round-robin name or a geo name gives different but overlapping sets
/// from different resolvers, and that is not split horizon. Two sets with nothing in common are.
fn overlaps(system: &[IpAddr], direct: &[IpAddr], asked_v6: bool) -> bool {
    let keep = |ip: &&IpAddr| asked_v6 || ip.is_ipv4();
    // With nothing of the system answer in the families asked (it is IPv6 only and the AAAA question failed)
    // there is nothing to compare, so the comparison is skipped and never warns.
    if !system.iter().any(|ip| keep(&ip)) {
        return true;
    }
    system
        .iter()
        .filter(keep)
        .any(|ip| direct.iter().filter(keep).any(|d| d == ip))
}

/// The text of the `sss` finding (03, net.dns). M1-154 builds on it, so the words are fixed here.
pub(super) const SSS_WARNING: &str = "The `hosts:` line of `/etc/nsswitch.conf` lists `sss`: every lookup asks sssd first, and a stopped or slow sssd stalls them";

/// The positions of the nameservers that said NXDOMAIN for this name.
pub(super) fn nxdomain_positions(l: &Looked) -> Vec<usize> {
    l.direct
        .iter()
        .filter(|r| {
            matches!(
                r.answer,
                NsAnswer::Replied {
                    rcode: Rcode::NxDomain,
                    ..
                }
            )
        })
        .map(|r| r.index + 1)
        .collect()
}

fn positions(list: &[usize]) -> String {
    let words: Vec<String> = list.iter().map(ToString::to_string).collect();
    match words.as_slice() {
        [one] => format!("nameserver {one}"),
        many => format!("nameservers {}", many.join(", ")),
    }
}

/// The findings of the direct answers and the resolver files, for names looked up as `looked`.
pub(super) fn assess(
    rules: &[Rule],
    looked: &[Looked],
    machine: &Machine,
    max_latency: Duration,
) -> Assessment {
    let mut out = Assessment::default();
    let asked = machine.asked;

    // Per name: the comparison with the system answer, and the codes.
    for l in looked {
        let Answer::Found(system) = &l.answer else {
            continue;
        };
        let mut differing: Vec<usize> = Vec::new();
        let mut errors: Vec<(usize, Rcode)> = Vec::new();
        let mut nx: Vec<usize> = Vec::new();
        let mut replied_ok = 0_usize;
        for r in &l.direct {
            let NsAnswer::Replied {
                rcode,
                addrs,
                asked_v6,
                ..
            } = &r.answer
            else {
                continue;
            };
            match rcode {
                Rcode::NoError => {
                    replied_ok += 1;
                    if !overlaps(system, addrs, *asked_v6) {
                        differing.push(r.index + 1);
                    }
                }
                Rcode::NxDomain => nx.push(r.index + 1),
                other => errors.push((r.index + 1, *other)),
            }
        }
        if !differing.is_empty() {
            push_once(
                &mut out.warns,
                format!(
                    "{} resolves differently by nameserver (split horizon): {} gives no address the system resolver gives",
                    code(&l.name),
                    positions(&differing)
                ),
            );
            out.fixes.push(format!(
                "{} gets different answers from different resolvers. The system resolver, which software on this machine uses, is the one that counts: check the order of the `nameserver` lines in `/etc/resolv.conf` (or the DNS servers of the network connection) and ask the DNS team which view should answer for {}.",
                code(&l.name),
                code(zone_of(&l.name))
            ));
        }
        if !nx.is_empty() {
            let who = positions(&nx);
            let found_where = if replied_ok == 0 && errors.is_empty() {
                " The system resolver still finds it, so it comes from `/etc/hosts` or another `nsswitch.conf` source, which a container or a product with its own resolver will not see."
            } else {
                ""
            };
            push_once(
                &mut out.warns,
                format!(
                    "{} answered NXDOMAIN for {}, which the system resolver finds.{found_where}",
                    who,
                    code(&l.name)
                ),
            );
        }
        for (pos, rcode) in errors {
            push_once(
                &mut out.warns,
                format!(
                    "nameserver {pos} answered {} for {}",
                    rcode.text(),
                    code(&l.name)
                ),
            );
        }
    }

    // Per nameserver, across names.
    for index in 0..asked {
        let rows: Vec<&NsResult> = looked
            .iter()
            .filter_map(|l| l.direct.iter().find(|r| r.index == index))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let pos = index + 1;
        if rows
            .iter()
            .any(|r| matches!(r.answer, NsAnswer::Skipped(_)))
        {
            out.skipped.push(pos);
        }
        let replied = |r: &&&NsResult| matches!(r.answer, NsAnswer::Replied { .. });
        let silent = |r: &&NsResult| {
            matches!(
                r.answer,
                NsAnswer::Timeout | NsAnswer::Refused | NsAnswer::Failed(_) | NsAnswer::Bad(_)
            )
        };
        let someone_else_replied = looked.iter().any(|l| {
            l.direct
                .iter()
                .any(|r| r.index != index && matches!(r.answer, NsAnswer::Replied { .. }))
        });
        if rows.iter().any(silent) && someone_else_replied {
            let how = if rows.iter().any(|r| matches!(r.answer, NsAnswer::Timeout)) {
                "did not answer in time"
            } else if rows.iter().any(|r| matches!(r.answer, NsAnswer::Refused)) {
                "refused the connection"
            } else {
                "gave no usable answer"
            };
            let tail = if index == 0 {
                ": a slow first hop adds a timeout to every lookup"
            } else {
                ""
            };
            push_once(
                &mut out.warns,
                format!("nameserver {pos} {how} while another nameserver answered{tail}"),
            );
            out.fixes.push(format!(
                "Nameserver {pos} in `/etc/resolv.conf` does not answer, and every lookup that reaches it waits for its timeout. Remove it or put a working one first: change the DNS servers of the connection (`nmcli con mod <connection> ipv4.dns <servers>`, `/etc/systemd/resolved.conf`, or the DHCP option) so the file is rewritten, and set `options timeout:1 attempts:2` to shorten the wait. Ask the network team to allow udp/53 and tcp/53 to it."
            ));
        }
        let slowest = rows
            .iter()
            .filter(replied)
            .map(|r| r.took)
            .max()
            .unwrap_or_default();
        if slowest > max_latency {
            let tail = if index == 0 && asked > 1 {
                ": a slow first hop adds that time to every lookup"
            } else {
                ""
            };
            push_once(
                &mut out.warns,
                format!(
                    "nameserver {pos} took {} ms to answer, above {} ms{tail}",
                    ms(slowest),
                    ms(max_latency)
                ),
            );
            out.fixes.push(format!(
                "Nameserver {pos} in `/etc/resolv.conf` is slow. Put the nearest nameserver first by changing the DNS servers of the connection (`nmcli con mod <connection> ipv4.dns <servers>` or `/etc/systemd/resolved.conf`), or ask the DNS team why it answers slowly."
            ));
        }
    }
    out.skipped.sort_unstable();
    for pos in &out.skipped {
        out.notes.push(format!(
            "nameserver {pos} was not queried directly: nameserver in a refused range. It is a link-local, metadata or other address rdy will not contact, so only the system answer is reported for it."
        ));
    }

    // Nothing answered directly although nameservers exist.
    let any_reply = looked.iter().any(|l| {
        l.direct
            .iter()
            .any(|r| matches!(r.answer, NsAnswer::Replied { .. }))
    });
    let any_tried = looked.iter().any(|l| {
        l.direct
            .iter()
            .any(|r| !matches!(r.answer, NsAnswer::Skipped(_) | NsAnswer::NotTried))
    });
    if asked > 0 && any_tried && !any_reply {
        out.notes.push(
            "No nameserver answered rdy's direct queries, so the system answer could not be compared with them. A local stub resolver or a firewall that allows only the system resolver can cause this."
                .to_owned(),
        );
    }
    if let Some(why) = &machine.list_problem {
        out.notes
            .push(format!("rdy sent no direct nameserver queries: {why}."));
    }
    if machine.facts.is_some_and(|f| f.stub_first) && asked > 0 {
        out.notes.push(
            "The first nameserver is the systemd-resolved stub on 127.0.0.53, so direct queries reach the local stub, not the upstream servers (`resolvectl status` lists them)."
                .to_owned(),
        );
    }
    if let Some(f) = machine.facts
        && f.listed > 3
    {
        out.notes.push(format!(
            "/etc/resolv.conf lists {} nameservers. The resolver reads the first three, and rdy asks the same three.",
            f.listed
        ));
    }

    nsswitch(&mut out, rules, looked, machine, max_latency);
    out
}

/// The `nsswitch.conf` `hosts:` findings.
fn nsswitch(
    out: &mut Assessment,
    rules: &[Rule],
    looked: &[Looked],
    machine: &Machine,
    max_latency: Duration,
) {
    let Some(hosts) = machine.hosts else { return };
    let trouble = looked.iter().any(|l| {
        matches!(
            l.answer,
            Answer::NotFound | Answer::Timeout | Answer::Failed(_)
        )
    }) || looked.iter().any(|l| l.took > max_latency);
    if !hosts.has_dns {
        let text = "The `hosts:` line of `/etc/nsswitch.conf` lists neither `dns` nor `resolve`, so no name is ever sent to a nameserver";
        if trouble {
            out.warns.push(text.to_owned());
            out.fixes.push("Add `dns` to the `hosts:` line of `/etc/nsswitch.conf`, for example `hosts: files dns`.".to_owned());
        } else {
            out.notes.push(format!("{text}."));
        }
    }
    if hosts.mdns_return_before_dns {
        let local: Vec<String> = rules
            .iter()
            .filter(|r| r.name.ends_with(".local"))
            .map(|r| code(&r.name))
            .collect();
        if local.is_empty() {
            out.notes.push("The `hosts:` line of `/etc/nsswitch.conf` has an mDNS source with `[NOTFOUND=return]` before `dns`. Names ending in `.local` go to mDNS only and never to a nameserver. No name in this spec ends in `.local`.".to_owned());
        } else {
            out.warns.push(format!(
                "{} ends in `.local` and `/etc/nsswitch.conf` has an mDNS source with `[NOTFOUND=return]` before `dns`, so it is never sent to a nameserver",
                local.join(", ")
            ));
            out.fixes.push("Edit the `hosts:` line of `/etc/nsswitch.conf` so `dns` comes before the mDNS source, or remove the mDNS source: `hosts: files dns`. On Ubuntu `apt remove libnss-mdns` removes it.".to_owned());
        }
    }
    if hosts.has_sss {
        let text = SSS_WARNING;
        if trouble {
            out.warns.push(text.to_owned());
            out.fixes.push("Check `systemctl status sssd`. If sssd does not serve hosts here, remove `sss` from the `hosts:` line of `/etc/nsswitch.conf`.".to_owned());
        } else {
            out.notes.push(format!("{text}."));
        }
    }
}

/// The evidence of one name's direct answers.
pub(super) fn ns_json(results: &[NsResult]) -> Value {
    Value::Array(
        results
            .iter()
            .map(|r| {
                let mut o = json!({ "position": r.index + 1, "ms": ms(r.took) });
                match &r.answer {
                    NsAnswer::Replied {
                        rcode,
                        addrs,
                        over_tcp,
                        asked_v6,
                    } => {
                        o["status"] = json!("replied");
                        o["rcode"] = json!(rcode.text());
                        o["addresses"] = json!(
                            addrs
                                .iter()
                                .take(SHOWN)
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                        );
                        o["addresses_total"] = json!(addrs.len());
                        o["aaaa_asked"] = json!(asked_v6);
                        if *over_tcp {
                            o["transport"] = json!("tcp");
                        }
                    }
                    NsAnswer::Timeout => o["status"] = json!("timeout"),
                    NsAnswer::Refused => o["status"] = json!("refused"),
                    NsAnswer::Skipped(why) => {
                        o["status"] = json!("skipped");
                        o["reason"] = json!(why);
                    }
                    NsAnswer::Bad(why) => {
                        o["status"] = json!("bad_reply");
                        o["reason"] = json!(why);
                    }
                    NsAnswer::Failed(_) => o["status"] = json!("failed"),
                    NsAnswer::NotTried => o["status"] = json!("not_tried"),
                }
                o
            })
            .collect(),
    )
}

/// The evidence of the resolver files.
pub(super) fn machine_json(machine: &Machine) -> Option<Value> {
    if machine.hosts.is_none() && machine.facts.is_none() && machine.asked == 0 {
        return None;
    }
    let mut out = json!({ "nameservers_asked": machine.asked });
    if let Some(f) = machine.facts {
        out["resolv_conf"] = json!({ "nameservers": f.listed, "stub_first": f.stub_first });
    }
    if let Some(h) = machine.hosts {
        out["nsswitch_hosts"] = json!({
            "dns": h.has_dns,
            "sss": h.has_sss,
            "mdns_return_before_dns": h.mdns_return_before_dns,
        });
    }
    Some(out)
}

fn zone_of(name: &str) -> &str {
    name.split_once('.')
        .map_or(name, |(_, rest)| rest)
        .trim_matches('.')
}
