//! firewalld service definitions: the XML under `/etc/firewalld/services` and `/usr/lib/firewalld/services`.
//!
//! A zone can open a port by service name (`services: ssh kube-apiserver`). The ports live in the
//! service file. The file in `/etc` replaces the one in `/usr/lib`, as firewalld does.
//!
//! No XML crate: a check crate may not take new dependencies for this, and the format is a short list
//! of tags with attributes. The scanner below reads only what it needs, never allocates more than the
//! input, and stops at fixed limits on any input.

use std::collections::{BTreeMap, VecDeque};

use rdy_engine::probe::{Probe, ProbeError};

use super::ports::PortRange;

/// Where an administrator's service files live. They win over the packaged ones.
const ADMIN_DIR: &str = "/etc/firewalld/services";
/// Where the packaged service files live.
const PACKAGED_DIR: &str = "/usr/lib/firewalld/services";

/// The most bytes of one service file that are scanned.
const MAX_XML: usize = 64 * 1024;
/// The most tags read from one service file.
const MAX_TAGS: usize = 2000;
/// The most service files read in one run (zone services, rich rule services and includes).
const MAX_SERVICES: usize = 32;
/// The deepest chain of `<include>` that is followed. A service at that depth that includes more is
/// "unknown".
const MAX_DEPTH: usize = 4;
/// The most distinct `<include>` elements read from one service file. More makes the file "unknown".
const MAX_INCLUDES: usize = 16;
/// The longest service name that is looked up.
const MAX_NAME: usize = 64;

/// What one service file says about TCP ports.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct ServiceDef {
    tcp: Vec<PortRange>,
    includes: Vec<String>,
    /// The service has a `<destination>`, so it opens ports only toward some addresses.
    limited: bool,
    /// Why the file was not read to its end: a limit was hit or the text was not in the form rdy reads.
    /// What it says then cannot be trusted either way, so the service is "unknown".
    doubt: Option<&'static str>,
}

/// What reading one service name gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Svc {
    Found(ServiceDef),
    /// Neither directory has a file for it.
    Missing,
    /// It could not be read; the text says why.
    Unreadable(String),
}

/// Whether a service opens a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Cover {
    Yes,
    /// It opens the port, but only toward some destination addresses.
    Limited,
    /// The answer is not known; the text says why.
    Unknown(String),
    No,
}

/// The services read for one run, by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Services(BTreeMap<String, Svc>);

impl Services {
    #[cfg(test)]
    pub(super) fn with(mut self, name: &str, svc: Svc) -> Self {
        self.0.insert(name.to_owned(), svc);
        self
    }

    /// Whether the service `name` opens TCP `port`, following includes.
    pub(super) fn covers(&self, name: &str, port: u16) -> Cover {
        self.search(name, port).0
    }

    /// The walk behind [`Services::covers`], and how many services it visited.
    ///
    /// Breadth first, with one visited set for the whole walk, so a service is looked at once however
    /// many files include it and a cycle ends by itself. The services read are at most [`MAX_SERVICES`]
    /// and each names at most [`MAX_INCLUDES`] includes, so a walk visits at most
    /// `1 + MAX_SERVICES * MAX_INCLUDES` names, whatever the files say. The answer is "yes" over
    /// "limited" over "unknown" over "no", so it does not depend on the order of the includes.
    fn search<'a>(&'a self, root: &'a str, port: u16) -> (Cover, usize) {
        let mut seen: Vec<&str> = vec![root];
        let mut queue: VecDeque<(&str, usize)> = VecDeque::from([(root, 0)]);
        let mut visited = 0;
        let mut limited = false;
        let mut unknown: Option<String> = None;
        while let Some((name, depth)) = queue.pop_front() {
            visited += 1;
            let def = match self.0.get(name) {
                None => {
                    unknown.get_or_insert(format!("service {name} was not read"));
                    continue;
                }
                Some(Svc::Missing) => {
                    unknown.get_or_insert(format!("service {name} has no definition file"));
                    continue;
                }
                Some(Svc::Unreadable(why)) => {
                    unknown.get_or_insert(format!("service {name} could not be read ({why})"));
                    continue;
                }
                Some(Svc::Found(def)) => def,
            };
            if let Some(why) = def.doubt {
                unknown.get_or_insert(format!("service {name} {why}"));
                continue;
            }
            if def.tcp.iter().any(|range| range.covers(port)) {
                if def.limited {
                    limited = true;
                    continue;
                }
                return (Cover::Yes, visited);
            }
            if def.includes.is_empty() {
                continue;
            }
            if depth >= MAX_DEPTH {
                unknown.get_or_insert(format!(
                    "service {name} includes services nested deeper than rdy follows"
                ));
                continue;
            }
            for include in &def.includes {
                if !seen.contains(&include.as_str()) {
                    seen.push(include);
                    queue.push_back((include, depth + 1));
                }
            }
        }
        let cover = if limited {
            Cover::Limited
        } else {
            unknown.map_or(Cover::No, Cover::Unknown)
        };
        (cover, visited)
    }

    /// How many services a walk from `name` visits.
    #[cfg(test)]
    pub(super) fn visits(&self, name: &str, port: u16) -> usize {
        self.search(name, port).1
    }
}

/// A service name rdy looks up: letters, digits, `-` and `_`. No dot, so no `..` and no hidden file,
/// and no `/`, so it cannot leave the directory.
pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Reads the service files for `names` and for every service they include.
///
/// # Errors
///
/// Only a refusal by rdy's own policy, which means the check's manifest is wrong. A file that is
/// missing or unreadable is recorded in the result.
pub(super) async fn load(
    probe: &Probe,
    names: impl IntoIterator<Item = String>,
) -> Result<Services, ProbeError> {
    let mut queue: VecDeque<String> = names.into_iter().collect();
    let mut out = BTreeMap::new();
    while let Some(name) = queue.pop_front() {
        if out.contains_key(&name) {
            continue;
        }
        if out.len() >= MAX_SERVICES {
            out.insert(name, Svc::Unreadable("too many services".to_owned()));
            continue;
        }
        let svc = if valid_name(&name) {
            read_one(probe, &name).await?
        } else {
            Svc::Unreadable("the name has characters rdy does not look up".to_owned())
        };
        if let Svc::Found(def) = &svc {
            queue.extend(def.includes.iter().cloned());
        }
        out.insert(name, svc);
    }
    Ok(Services(out))
}

async fn read_one(probe: &Probe, name: &str) -> Result<Svc, ProbeError> {
    for dir in [ADMIN_DIR, PACKAGED_DIR] {
        let path = std::path::Path::new(dir).join(format!("{name}.xml"));
        match probe.read(&path).await {
            Ok(file) => return Ok(Svc::Found(parse(&String::from_utf8_lossy(&file.bytes)))),
            Err(ProbeError::NotFound) => {}
            Err(
                error @ (ProbeError::Denied { .. } | ProbeError::Policy(_) | ProbeError::Table(_)),
            ) => {
                return Err(error);
            }
            Err(other) => return Ok(Svc::Unreadable(super::short(&other))),
        }
    }
    Ok(Svc::Missing)
}

/// One tag with its attributes.
struct Tag<'a> {
    name: &'a str,
    attrs: Vec<(&'a str, &'a str)>,
}

impl Tag<'_> {
    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// Reads the TCP ports, includes and destination limit from a service file.
pub(super) fn parse(xml: &str) -> ServiceDef {
    let mut def = ServiceDef::default();
    if xml.len() > MAX_XML {
        def.doubt = Some("is longer than rdy reads");
    }
    let (found, doubt) = tags(cut(xml, MAX_XML));
    if def.doubt.is_none() {
        def.doubt = doubt;
    }
    for tag in found {
        match tag.name {
            "port" => {
                let tcp = tag
                    .attr("protocol")
                    .is_some_and(|p| p.eq_ignore_ascii_case("tcp"));
                if let (true, Some(range)) =
                    (tcp, tag.attr("port").and_then(|p| PortRange::parse(p, '-')))
                {
                    def.tcp.push(range);
                }
            }
            "include" => {
                if let Some(service) = tag.attr("service")
                    && !def.includes.iter().any(|i| i == service)
                {
                    if def.includes.len() < MAX_INCLUDES {
                        def.includes.push(service.to_owned());
                    } else {
                        def.doubt
                            .get_or_insert("includes more services than rdy follows");
                    }
                }
            }
            "destination" => def.limited = true,
            _ => {}
        }
    }
    def
}

/// Whether the file has a start tag called `name`. `Err` says why the file could not be read to its
/// end without finding one, so the answer is not known.
pub(super) fn has_tag(xml: &str, name: &str) -> Result<bool, &'static str> {
    let (found, doubt) = tags(cut(xml, MAX_XML));
    if found.iter().any(|t| t.name == name) {
        return Ok(true);
    }
    match (xml.len() > MAX_XML, doubt) {
        (true, _) => Err("is longer than rdy reads"),
        (_, Some(why)) => Err(why),
        _ => Ok(false),
    }
}

/// The first `max` bytes of `text`, cut on a character boundary.
fn cut(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The start tags of `xml`, in order, and why the scan stopped early if it did. Comments, CDATA
/// sections, processing instructions and end tags are skipped. Text between tags is ignored. A
/// DOCTYPE, a tag that is cut off or cannot be read, an unfinished comment or section, and more than
/// [`MAX_TAGS`] tags all end the scan with a reason, because the tags after that point are not known.
fn tags(xml: &str) -> (Vec<Tag<'_>>, Option<&'static str>) {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(open) = rest.find('<') {
        rest = &rest[open..];
        let skip = |marker: &str, from: usize, rest: &str| {
            rest[from..]
                .find(marker)
                .map(|end| from + end + marker.len())
        };
        if rest.starts_with("<!--") {
            let Some(next) = skip("-->", 4, rest) else {
                return (out, Some("has a comment that does not end"));
            };
            rest = &rest[next..];
        } else if rest.starts_with("<![CDATA[") {
            let Some(next) = skip("]]>", 9, rest) else {
                return (out, Some("has a CDATA section that does not end"));
            };
            rest = &rest[next..];
        } else if rest
            .get(..9)
            .is_some_and(|w| w.eq_ignore_ascii_case("<!DOCTYPE"))
        {
            return (out, Some("has a DOCTYPE, which rdy does not read"));
        } else if rest.starts_with("<?") {
            let Some(next) = skip("?>", 2, rest) else {
                return (out, Some("has an instruction that does not end"));
            };
            rest = &rest[next..];
        } else if rest.starts_with("<!") {
            return (out, Some("has a declaration rdy does not read"));
        } else if rest.starts_with("</") {
            let Some(next) = skip(">", 2, rest) else {
                return (out, Some("has an end tag that does not end"));
            };
            rest = &rest[next..];
        } else {
            if out.len() >= MAX_TAGS {
                return (out, Some("has more tags than rdy reads"));
            }
            let Some((tag, after)) = start_tag(&rest[1..]) else {
                return (out, Some("has a tag rdy cannot read"));
            };
            out.push(tag);
            rest = after;
        }
    }
    (out, None)
}

/// Reads `name attr="v" attr='v' ...>` and returns the tag and the text after the `>`.
fn start_tag(text: &str) -> Option<(Tag<'_>, &str)> {
    let name_end = text.find(|c: char| c.is_whitespace() || c == '/' || c == '>')?;
    let name = &text[..name_end];
    let mut rest = &text[name_end..];
    let mut attrs = Vec::new();
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        if let Some(after) = rest.strip_prefix('>') {
            return Some((Tag { name, attrs }, after));
        }
        let key_end = rest.find(|c: char| c == '=' || c == '>' || c == '/' || c.is_whitespace())?;
        let key = &rest[..key_end];
        rest = &rest[key_end..];
        if let Some(after) = rest.strip_prefix('=') {
            let quote = after.chars().next().filter(|c| *c == '"' || *c == '\'')?;
            let body = &after[1..];
            let end = body.find(quote)?;
            attrs.push((key, &body[..end]));
            rest = &body[end + 1..];
        }
        if attrs.len() > 64 {
            return None;
        }
    }
}
