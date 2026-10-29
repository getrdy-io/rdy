//! firewalld: the output of `firewall-cmd --get-active-zones` and `--list-all --zone=<zone>`, and the
//! judgement of one inbound TCP port against a zone.
//!
//! The parsers read text that the tool wrote for people, so they take only what they know and drop the
//! rest. Every list has a limit, and a limit that cuts the text is recorded: a cut listing gives
//! "unknown", never "closed". Nothing here panics on any input.

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

/// One zone from `--get-active-zones`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ActiveZone {
    pub(super) name: String,
    pub(super) interfaces: Vec<String>,
    /// The addresses, networks and address sets bound to the zone. Traffic from them is handled by this
    /// zone before the zone of the interface is looked at.
    pub(super) sources: Vec<String>,
}

/// Every active zone, and whether the listing was longer than rdy reads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ActiveZones {
    pub(super) zones: Vec<ActiveZone>,
    /// A limit cut the listing, so a zone or a source may be missing from `zones`.
    pub(super) truncated: bool,
}

impl ActiveZones {
    /// The names of the active zones other than `picked` that have sources.
    pub(super) fn source_bound_besides(&self, picked: &str) -> Vec<&str> {
        self.zones
            .iter()
            .filter(|z| z.name != picked && !z.sources.is_empty())
            .map(|z| z.name.as_str())
            .collect()
    }
}

/// The first [`MAX_WORDS`] words of a list line, and whether there were more.
fn words(value: &str) -> (Vec<&str>, bool) {
    let mut list: Vec<&str> = value.split_whitespace().take(MAX_WORDS + 1).collect();
    let more = list.len() > MAX_WORDS;
    list.truncate(MAX_WORDS);
    (list, more)
}

/// Reads `--get-active-zones`: an unindented zone name, then indented `interfaces:` and `sources:`.
pub(super) fn parse_active_zones(text: &str) -> ActiveZones {
    let mut out = ActiveZones::default();
    let mut lines = text.lines();
    for line in lines.by_ref().take(MAX_LINES) {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            let Some(zone) = out.zones.last_mut() else {
                continue;
            };
            let Some((key, list)) = line.trim().split_once(':') else {
                continue;
            };
            let (list, more) = words(list);
            out.truncated |= more;
            match key.trim() {
                "interfaces" => zone.interfaces.extend(list.into_iter().map(str::to_owned)),
                "sources" => zone.sources.extend(list.into_iter().map(str::to_owned)),
                _ => {}
            }
        } else if out.zones.len() < MAX_ZONES {
            out.zones.push(ActiveZone {
                name: line.trim().to_owned(),
                ..ActiveZone::default()
            });
        } else {
            out.truncated = true;
        }
    }
    out.truncated |= lines.next().is_some();
    out
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
    /// `protocols: tcp` opens every TCP port.
    pub(super) all_tcp: bool,
    pub(super) rich_rules: Vec<String>,
    /// The zone has sources that are address sets (`ipset:name`). Traffic from those addresses may be
    /// handled by this zone and not by the interface's zone, and the listing cannot say which.
    pub(super) ipset_sources: bool,
    /// Why the listing was not read to its end: a limit cut it. What is missing might change the
    /// answer, so every port is "unknown".
    pub(super) incomplete: Option<&'static str>,
}

/// Reads one zone listing. `None` when the first line is not a zone header.
pub(super) fn parse_zone(text: &str) -> Option<Zone> {
    let mut lines = text.lines();
    let header = lines
        .by_ref()
        .take(MAX_LINES)
        .find(|l| !l.trim().is_empty())?;
    if header.starts_with(char::is_whitespace) {
        return None;
    }
    let name = header.split_whitespace().next()?;
    let mut zone = Zone {
        name: name.to_owned(),
        ..Zone::default()
    };
    let mut cut = false;
    for line in lines.by_ref().take(MAX_LINES) {
        let trimmed = line.trim();
        // A rich rule is printed on its own line after `rich rules:`. It can hold colons (IPv6), so it
        // is recognised by its first word and never split at a colon.
        if trimmed.starts_with("rule ") || trimmed == "rule" {
            if zone.rich_rules.len() < MAX_RULES {
                cut |= trimmed.chars().nth(MAX_RULE).is_some();
                zone.rich_rules.push(cut_chars(trimmed, MAX_RULE));
            } else {
                cut = true;
            }
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let (list, more) = words(value);
        cut |= more;
        match key.trim() {
            "target" => {
                zone.target = match value.trim() {
                    "ACCEPT" => Target::Accept,
                    "DROP" => Target::Drop,
                    "REJECT" | "%%REJECT%%" => Target::Reject,
                    _ => Target::Default,
                };
            }
            "services" => {
                zone.services.clear();
                for word in list {
                    if !zone.services.iter().any(|s| s == word) {
                        zone.services.push(word.to_owned());
                    }
                }
            }
            "ports" => {
                zone.tcp = list
                    .into_iter()
                    .filter_map(|w| w.strip_suffix("/tcp"))
                    .filter_map(|w| PortRange::parse(w, '-'))
                    .collect();
            }
            "protocols" => zone.all_tcp = list.iter().any(|w| matches!(*w, "tcp" | "6")),
            "sources" => zone.ipset_sources = list.iter().any(|w| w.starts_with("ipset:")),
            _ => {}
        }
    }
    if cut || lines.next().is_some() {
        zone.incomplete = Some("is longer than rdy reads");
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
/// no such element applies to all traffic from or to some address, so it counts. The verdict does not
/// depend on this (any rich rule gives "unknown"); it picks which rule the message describes.
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

/// What a rich rule says, from its parsed parts only: the family, whether it has a source or a
/// destination, what it names (a port or a service), and the action. The values of `source`,
/// `destination`, `log` and `audit` are never repeated, because they can hold addresses, set names and
/// free text.
fn describe(rule: &str) -> String {
    let elems = elements(rule);
    let find = |name: &str| elems.iter().find(|e| e.name == name);
    let mut parts: Vec<String> = Vec::new();
    if let Some(family) = find("rule").and_then(|e| e.attr("family"))
        && matches!(family, "ipv4" | "ipv6")
    {
        parts.push(family.to_owned());
    }
    for word in ["source", "destination"] {
        if let Some(element) = find(word) {
            parts.push(if element.attr("address").is_some() {
                format!("{word} address")
            } else {
                word.to_owned()
            });
        }
    }
    if let Some(element) = find("port") {
        let port = element
            .attr("port")
            .filter(|p| PortRange::parse(p, '-').is_some());
        let proto = element
            .attr("protocol")
            .filter(|p| p.eq_ignore_ascii_case("tcp") || p.eq_ignore_ascii_case("udp"));
        parts.push(match (port, proto) {
            (Some(port), Some(proto)) => format!("port {port}/{}", proto.to_ascii_lowercase()),
            (Some(port), None) => format!("port {port}"),
            _ => "port".to_owned(),
        });
    } else if let Some(element) = find("service") {
        parts.push(match element.attr("name") {
            Some(name) if super::service::valid_name(name) => format!("service {name}"),
            _ => "service".to_owned(),
        });
    } else if find("forward-port").is_some() {
        parts.push("forward-port".to_owned());
    } else if find("protocol").is_some() {
        parts.push("protocol".to_owned());
    }
    if let Some(action) = ["accept", "reject", "drop", "mark"]
        .into_iter()
        .find(|a| find(a).is_some())
    {
        parts.push(action.to_owned());
    }
    if parts.is_empty() {
        "rule".to_owned()
    } else {
        parts.join(", ")
    }
}

/// Judges inbound TCP `port` against `zone`.
///
/// The work is bounded: at most [`MAX_WORDS`] distinct service names in the zone, each looked up in a
/// map of at most 32 services and walked in at most 513 steps (see `Services::search`).
pub(super) fn judge(zone: &Zone, services: &Services, port: u16) -> Verdict {
    if let Some(why) = zone.incomplete {
        return Verdict::Unknown(format!("the zone listing {why}"));
    }
    let mut unresolved: Option<String> = None;
    let mut limited: Option<String> = None;
    let mut open: Option<String> = None;
    if zone.tcp.iter().any(|range| range.covers(port)) {
        open = Some(format!("ports: {port}/tcp"));
    }
    if open.is_none() && zone.all_tcp {
        open = Some("protocols: tcp".to_owned());
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

    // Any rich rule makes the answer unknown: rdy does not evaluate them. The one described is the
    // first that touches the port, or else the first.
    let named = zone
        .rich_rules
        .iter()
        .find(|rule| rich_rule_applies(rule, services, port))
        .or_else(|| zone.rich_rules.first());
    if let Some(rule) = named {
        return Verdict::Unknown(format!(
            "the zone has {} rich rule(s) and firewalld rich rules are not evaluated (for example: {})",
            zone.rich_rules.len(),
            describe(rule)
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
