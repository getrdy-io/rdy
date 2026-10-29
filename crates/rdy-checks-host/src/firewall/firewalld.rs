//! firewalld: the output of `firewall-cmd --get-active-zones` and `--list-all --zone=<zone>`, and the
//! judgement of one inbound TCP port against a zone.
//!
//! The parsers read text that the tool wrote for people, so they take only what they know and drop the
//! rest. Every list has a limit. Nothing here panics on any input.

use super::Verdict;
use super::ports::PortRange;
use super::service::{Cover, Services};

/// The most lines of a listing that are read.
const MAX_LINES: usize = 600;
/// The most words read from one list line.
const MAX_WORDS: usize = 2048;
/// The most zones read from `--get-active-zones`.
const MAX_ZONES: usize = 64;
/// The most rich rules kept.
const MAX_RULES: usize = 100;
/// The longest rich rule kept, in characters.
const MAX_RULE: usize = 1024;
/// The longest rich rule quoted in a message, in characters.
pub(super) const QUOTE_RULE: usize = 160;

/// One zone from `--get-active-zones`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ActiveZone {
    pub(super) name: String,
    pub(super) interfaces: Vec<String>,
}

/// Reads `--get-active-zones`: an unindented zone name, then indented `interfaces:` and `sources:`.
pub(super) fn parse_active_zones(text: &str) -> Vec<ActiveZone> {
    let mut zones: Vec<ActiveZone> = Vec::new();
    for line in text.lines().take(MAX_LINES) {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            if let (Some(zone), Some(("interfaces", list))) = (
                zones.last_mut(),
                line.trim().split_once(':').map(|(k, v)| (k.trim(), v)),
            ) {
                zone.interfaces
                    .extend(list.split_whitespace().take(MAX_WORDS).map(str::to_owned));
            }
        } else if zones.len() < MAX_ZONES {
            zones.push(ActiveZone {
                name: line.trim().to_owned(),
                interfaces: Vec::new(),
            });
        }
    }
    zones
}

/// What a zone does with traffic that no rule in it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Target {
    /// `default`: reject.
    #[default]
    Default,
    Accept,
    Drop,
    Reject,
}

impl Target {
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Accept => "ACCEPT",
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
        }
    }
}

/// A zone as `--list-all --zone=<zone>` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Zone {
    pub(super) name: String,
    pub(super) target: Target,
    pub(super) services: Vec<String>,
    pub(super) tcp: Vec<PortRange>,
    pub(super) rich_rules: Vec<String>,
    /// The zone has sources that are address sets (`ipset:name`). Traffic from those addresses may be
    /// handled by this zone and not by the interface's zone, and the listing cannot say which.
    pub(super) ipset_sources: bool,
}

/// Reads one zone listing. `None` when the first line is not a zone header.
pub(super) fn parse_zone(text: &str) -> Option<Zone> {
    let mut lines = text.lines().take(MAX_LINES);
    let header = lines.find(|l| !l.trim().is_empty())?;
    if header.starts_with(char::is_whitespace) {
        return None;
    }
    let name = header.split_whitespace().next()?;
    let mut zone = Zone {
        name: name.to_owned(),
        ..Zone::default()
    };
    for line in lines {
        let trimmed = line.trim();
        // A rich rule is printed on its own line after `rich rules:`. It can hold colons (IPv6), so it
        // is recognised by its first word and never split at a colon.
        if trimmed.starts_with("rule ") || trimmed == "rule" {
            if zone.rich_rules.len() < MAX_RULES {
                zone.rich_rules.push(cut_chars(trimmed, MAX_RULE));
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let words = || value.split_whitespace().take(MAX_WORDS);
        match key.trim() {
            "target" => {
                zone.target = match value.trim() {
                    "ACCEPT" => Target::Accept,
                    "DROP" => Target::Drop,
                    "REJECT" | "%%REJECT%%" => Target::Reject,
                    _ => Target::Default,
                };
            }
            "services" => zone.services = words().map(str::to_owned).collect(),
            "ports" => {
                zone.tcp = words()
                    .filter_map(|w| w.strip_suffix("/tcp"))
                    .filter_map(|w| PortRange::parse(w, '-'))
                    .collect();
            }
            "sources" => zone.ipset_sources = words().any(|w| w.starts_with("ipset:")),
            _ => {}
        }
    }
    Some(zone)
}

fn cut_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The service names a zone refers to, in its `services:` line and in its rich rules.
pub(super) fn service_names(zone: &Zone) -> Vec<String> {
    let mut names = zone.services.clone();
    for rule in &zone.rich_rules {
        for element in elements(rule) {
            if element.name == "service"
                && let Some(name) = element.attr("name")
            {
                names.push(name.to_owned());
            }
        }
    }
    names
}

/// A bare word of a rich rule and the `key="value"` words that follow it.
struct Element {
    name: String,
    attrs: Vec<(String, String)>,
}

impl Element {
    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Splits a rich rule into words (quotes keep a value together) and groups attributes under the bare
/// word before them. `rule family="ipv4" source address="10.0.0.0/8" port port="6443" protocol="tcp"
/// accept` gives `rule`, `source`, `port`, `accept`.
fn elements(rule: &str) -> Vec<Element> {
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in rule.chars().take(MAX_RULE) {
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    let mut out: Vec<Element> = Vec::new();
    for word in words {
        match word.split_once('=') {
            Some((key, value)) => {
                if let Some(last) = out.last_mut() {
                    last.attrs
                        .push((key.to_owned(), value.trim_matches('"').to_owned()));
                }
            }
            None => out.push(Element {
                name: word,
                attrs: Vec::new(),
            }),
        }
    }
    out
}

/// Whether a `port="..." protocol="..."` pair covers TCP `port`. Anything unreadable counts as
/// covering, because the safe answer to "cannot tell" is "it might apply".
fn port_element_covers(element: &Element, port: u16) -> bool {
    match element.attr("protocol") {
        Some(p) if !p.eq_ignore_ascii_case("tcp") => return false,
        _ => {}
    }
    element
        .attr("port")
        .and_then(|p| PortRange::parse(p, '-'))
        .is_none_or(|range| range.covers(port))
}

/// Whether a rich rule might change what happens to inbound TCP `port`.
///
/// A rule is left out only when it names a port or a service that does not cover the port, or a
/// kind of rule that has nothing to do with inbound TCP (ICMP, masquerade, source ports). A rule with
/// no such element applies to all traffic from or to some address, so it counts.
fn rich_rule_applies(rule: &str, services: &Services, port: u16) -> bool {
    let elems = elements(rule);
    let find = |name: &str| elems.iter().find(|e| e.name == name);
    if find("protocol").is_some() {
        return true;
    }
    if let Some(element) = find("port").or_else(|| find("forward-port")) {
        return port_element_covers(element, port);
    }
    if let Some(name) = find("service").and_then(|e| e.attr("name")) {
        return services.covers(name, port) != Cover::No;
    }
    let unrelated = ["icmp-block", "icmp-type", "masquerade", "source-port"];
    !elems.iter().any(|e| unrelated.contains(&e.name.as_str()))
}

/// Judges inbound TCP `port` against `zone`.
pub(super) fn judge(zone: &Zone, services: &Services, port: u16) -> Verdict {
    let mut unresolved: Option<String> = None;
    let mut limited: Option<String> = None;
    let mut open: Option<String> = None;
    if zone.tcp.iter().any(|range| range.covers(port)) {
        open = Some(format!("ports: {port}/tcp"));
    }
    if open.is_none() {
        for name in &zone.services {
            match services.covers(name, port) {
                Cover::Yes => {
                    open = Some(format!("service {name}"));
                    break;
                }
                Cover::Limited => limited = Some(name.clone()),
                Cover::Unknown(why) => unresolved = Some(why),
                Cover::No => {}
            }
        }
    }
    if open.is_none() && zone.target == Target::Accept {
        open = Some("zone target ACCEPT".to_owned());
    }

    let applying: Vec<&String> = zone
        .rich_rules
        .iter()
        .filter(|rule| rich_rule_applies(rule, services, port))
        .collect();
    if let Some(rule) = applying.first() {
        let shown = cut_chars(rule, QUOTE_RULE);
        return Verdict::Unknown(format!(
            "a rich rule applies and firewalld rich rules are not evaluated: {shown}"
        ));
    }
    if zone.ipset_sources {
        return Verdict::Unknown(
            "the zone has an ipset as a source, and the listing does not say which addresses it holds"
                .to_owned(),
        );
    }
    if let Some(via) = open {
        return Verdict::Open(via);
    }
    if let Some(name) = limited {
        return Verdict::Unknown(format!(
            "service {name} opens the port only toward some destination addresses"
        ));
    }
    if let Some(why) = unresolved {
        return Verdict::Unknown(why);
    }
    Verdict::Closed(format!(
        "not in ports or services, and the zone target is {}",
        zone.target.word()
    ))
}
