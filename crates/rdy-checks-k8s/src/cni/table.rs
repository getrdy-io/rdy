//! The network plugin table behind `k8s.cni`.
//!
//! The table is `data/cni.toml`, embedded at build time (03 Appendix B). It says which node condition
//! reason, API group, OpenShift network type or DaemonSet names which plugin, and whether the plugin
//! enforces `NetworkPolicy`. The file is parsed once, on first use, and checked hard, like the provisioner
//! table: the tests parse the shipped file, so a bad entry fails the build and never reaches a customer.
//! The file holds no free text. The check prints fixed words and the names it finds.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use k8s_openapi::jiff::civil::Date;
use serde::Deserialize;

/// The only schema number this build reads.
const SCHEMA: u32 = 1;
/// The most entries a table may hold.
const MAX_ENTRIES: usize = 64;
/// The most DaemonSets one entry may name.
pub(super) const MAX_DAEMONSETS: usize = 4;
/// The longest URL, in bytes.
const MAX_URL: usize = 300;

/// Whether a plugin enforces `NetworkPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Enforces {
    /// It does.
    Yes,
    /// It does not (Flannel alone).
    No,
    /// It does when a setting on its DaemonSet says so.
    Env,
}

/// What a plugin does next to others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    /// It gives pods their network and does not enforce policy by itself.
    Base,
    /// It enforces policy and can run on top of a base plugin.
    Policy,
    /// It does both and runs alone.
    Full,
}

/// Where the pod ranges of a plugin are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum PodCidr {
    /// The `spec.podCIDRs` of the nodes.
    Node,
    /// The plugin's own pool, so the node field says nothing.
    Own,
}

/// A network plugin the table knows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) family: String,
    pub(super) node_reasons: Vec<String>,
    pub(super) crd_groups: Vec<String>,
    pub(super) network_types: Vec<String>,
    pub(super) daemonsets: Vec<String>,
    pub(super) role: Role,
    pub(super) enforces: Enforces,
    pub(super) pod_cidr: PodCidr,
    pub(super) source: String,
    pub(super) verified: bool,
    #[serde(default)]
    pub(super) checked_on: Option<String>,
}

impl Entry {
    /// The DaemonSets of the entry as `(namespace, name)`.
    pub(super) fn daemonset_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.daemonsets
            .iter()
            .filter_map(|pair| pair.split_once('/'))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u32,
    #[serde(default)]
    cni: Vec<Entry>,
}

/// Why a table could not be read. The shipped table never fails; a test holds that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum TableError {
    /// The text is not TOML in the table's shape.
    #[error(
        "cni.toml is not in the expected form: {0}. Fix: use a build of rdy that ships a valid table"
    )]
    Form(String),
    /// An entry broke a rule.
    #[error("cni.toml entry {entry}: {why}. Fix: use a build of rdy that ships a valid table")]
    Entry {
        /// The id of the entry, or its place in the file.
        entry: String,
        /// The rule it broke.
        why: String,
    },
}

/// The parsed, checked table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Table {
    entries: Vec<Entry>,
}

impl Table {
    /// Parses and checks table text.
    ///
    /// # Errors
    ///
    /// [`TableError`] naming the first entry that breaks a rule.
    pub(super) fn parse(text: &str) -> Result<Self, TableError> {
        let file: File = toml::from_str(text).map_err(|e| {
            TableError::Form(e.to_string().lines().next().unwrap_or_default().to_owned())
        })?;
        if file.schema != SCHEMA {
            return Err(TableError::Form(format!(
                "schema {} is not the {SCHEMA} this build reads",
                file.schema
            )));
        }
        if file.cni.len() > MAX_ENTRIES {
            return Err(TableError::Form(format!("more than {MAX_ENTRIES} entries")));
        }
        let mut ids = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for (n, entry) in file.cni.iter().enumerate() {
            let label = if entry.id.is_empty() {
                format!("#{}", n + 1)
            } else {
                entry.id.clone()
            };
            let bad = |why: &str| TableError::Entry {
                entry: label.clone(),
                why: why.to_owned(),
            };
            check_entry(entry).map_err(|why| bad(&why))?;
            if !ids.insert(entry.id.clone()) {
                return Err(bad("the id is used twice"));
            }
            for pair in &entry.daemonsets {
                if !pairs.insert(pair.clone()) {
                    return Err(bad("a DaemonSet is named by two entries"));
                }
            }
        }
        Ok(Self { entries: file.cni })
    }

    /// The table this build ships.
    ///
    /// # Errors
    ///
    /// The reason the embedded file did not parse, which a test rules out.
    pub(super) fn shipped() -> Result<&'static Self, &'static TableError> {
        static SHIPPED: OnceLock<Result<Table, TableError>> = OnceLock::new();
        SHIPPED
            .get_or_init(|| Self::parse(super::EMBEDDED))
            .as_ref()
    }

    /// The entries, in file order.
    pub(super) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry with this id.
    pub(super) fn by_id(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// Every DaemonSet the table names, as `(namespace, name, entry)`, in file order.
    pub(super) fn daemonsets(&self) -> impl Iterator<Item = (&str, &str, &Entry)> {
        self.entries.iter().flat_map(|entry| {
            entry
                .daemonset_pairs()
                .map(move |(ns, name)| (ns, name, entry))
        })
    }
}

fn is_label(text: &str) -> bool {
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    !text.is_empty()
        && text.len() <= 63
        && text.starts_with(edge)
        && text.ends_with(edge)
        && text.chars().all(|c| edge(c) || c == '-')
}

fn is_dns_name(text: &str) -> bool {
    text.len() <= 253 && text.split('.').all(is_label)
}

fn is_word(text: &str) -> bool {
    !text.is_empty() && text.len() <= 64 && text.chars().all(|c| c.is_ascii_alphanumeric())
}

fn check_entry(entry: &Entry) -> Result<(), String> {
    if !is_label(&entry.id) {
        return Err("the id must be lower case letters, digits and dashes".to_owned());
    }
    if entry.name.is_empty()
        || entry.name.len() > 64
        || !entry
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '(' | ')' | '-' | '.'))
    {
        return Err("the name must be plain words".to_owned());
    }
    if !is_label(&entry.family) {
        return Err("the family must be lower case letters, digits and dashes".to_owned());
    }
    if !entry.node_reasons.iter().all(|r| is_word(r)) {
        return Err("a node reason must be letters and digits".to_owned());
    }
    if !entry.network_types.iter().all(|t| is_word(t)) {
        return Err("a network type must be letters and digits".to_owned());
    }
    if !entry.crd_groups.iter().all(|g| is_dns_name(g)) {
        return Err("a CRD group must be a DNS name".to_owned());
    }
    if entry.daemonsets.len() > MAX_DAEMONSETS {
        return Err(format!("more than {MAX_DAEMONSETS} DaemonSets"));
    }
    for pair in &entry.daemonsets {
        let ok = pair
            .split_once('/')
            .is_some_and(|(ns, name)| is_label(ns) && is_dns_name(name));
        if !ok {
            return Err("a DaemonSet must be written namespace/name".to_owned());
        }
    }
    if !entry.source.starts_with("https://")
        || entry.source.len() > MAX_URL
        || !entry.source.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("the source must be an https URL".to_owned());
    }
    match (&entry.checked_on, entry.verified) {
        (Some(day), true) if day.parse::<Date>().is_ok() => {}
        (None, false) => {}
        _ => {
            return Err(
                "a verified entry has checked_on (a date, YYYY-MM-DD) and an unverified one has none"
                    .to_owned(),
            );
        }
    }
    Ok(())
}
