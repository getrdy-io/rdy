//! The provisioner table behind `k8s.storageclass`.
//!
//! The table is `data/provisioners.toml`, embedded at build time (03 Appendix B). A StorageClass cannot
//! say which access modes it serves, so the check reads them from here. The table also maps the in-tree
//! provisioner names to the CSI drivers that serve them after CSI migration, so the check looks for the
//! driver that will really run.
//!
//! The file is parsed once, on first use, and checked hard: a name used twice, a mode that is not an
//! access mode, a source that is not `https`, a date that is not a date. The tests parse the shipped file,
//! so a bad entry fails the build and never reaches a customer. [`Catalog::parse`] takes any text, so the
//! tests can also show that each rule refuses what it should.
//!
//! The file holds no free text. The check prints fixed words and the names it finds.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use k8s_openapi::jiff::civil::Date;
use rdy_spec::check::AccessMode;
use serde::Deserialize;

#[cfg(test)]
mod tests;

/// The shipped table text.
const EMBEDDED: &str = include_str!("../data/provisioners.toml");

/// The only schema number this build reads.
const SCHEMA: u32 = 1;
/// The most entries of either kind a table may hold.
const MAX_ENTRIES: usize = 200;
/// The longest provisioner name, in bytes. It is the longest name Kubernetes allows for an object.
const MAX_NAME: usize = 253;
/// The longest URL and condition, in bytes.
const MAX_URL: usize = 300;
const MAX_CONDITION: usize = 80;

/// The provisioner that creates no volumes: an admin makes them by hand (static provisioning).
pub(crate) const NO_PROVISIONER: &str = "kubernetes.io/no-provisioner";

/// How a driver entry matches a provisioner name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Match {
    /// The whole name.
    Exact,
    /// The name, or any name that ends with a dot and then it.
    Suffix,
}

/// Where a volume of a driver lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Topology {
    /// One availability zone.
    Zone,
    /// One node.
    Node,
    /// Reachable from every node.
    None,
}

/// A provisioner or CSI driver the table knows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Driver {
    name: String,
    #[serde(rename = "match")]
    matching: Match,
    csi: bool,
    modes: Vec<AccessMode>,
    #[serde(default)]
    conditional_modes: Vec<AccessMode>,
    condition: Option<String>,
    topology: Topology,
    source: String,
    checked_on: String,
}

impl Driver {
    /// The name of the entry, as written in the table.
    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// True for a CSI driver. Only a CSI driver registers on `CSINode`.
    pub(crate) fn is_csi(&self) -> bool {
        self.csi
    }

    /// True for an entry with `csi = false` and a name that has no `/`: a CSI-style name that rdy cannot
    /// confirm on `CSINode` (EKS Auto Mode). Its listed modes are served, but a mode it does not list is
    /// "not verified", never "refused", because rdy does not know the driver.
    pub(crate) fn is_unverified_csi(&self) -> bool {
        !self.csi && !self.name.contains('/')
    }

    /// Where a volume of this driver lives.
    pub(crate) fn topology(&self) -> Topology {
        self.topology
    }

    /// The modes the driver serves.
    pub(crate) fn modes(&self) -> &[AccessMode] {
        &self.modes
    }

    /// The modes the driver serves only under [`Driver::condition`].
    pub(crate) fn conditional_modes(&self) -> &[AccessMode] {
        &self.conditional_modes
    }

    /// The fixed words for the condition of the conditional modes.
    pub(crate) fn condition(&self) -> Option<&str> {
        self.condition.as_deref()
    }
}

/// In-tree provisioner name to CSI driver name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct InTree {
    from: String,
    to: String,
}

/// The raw file: a schema number and the entries.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u32,
    #[serde(default)]
    in_tree: Vec<InTree>,
    #[serde(default)]
    driver: Vec<Driver>,
}

/// Why a table could not be read. The shipped table never fails; a test holds that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum CatalogError {
    /// The text is not TOML in the table's shape.
    #[error(
        "provisioners.toml is not in the expected form: {0}. Fix: use a build of rdy that ships a valid table"
    )]
    Form(String),
    /// An entry broke a rule.
    #[error(
        "provisioners.toml entry {entry}: {why}. Fix: use a build of rdy that ships a valid table"
    )]
    Entry {
        /// The name of the entry, or its place in the file when it has none.
        entry: String,
        /// The rule it broke.
        why: String,
    },
}

/// A provisioner name after the in-tree map was applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Normalised<'a> {
    /// The name to look for on `CSINode` and `CSIDriver`, and in the table.
    pub(crate) name: &'a str,
    /// True when `name` replaced an in-tree name.
    pub(crate) migrated: bool,
}

/// What the table says about the provisioner of a class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind<'a> {
    /// `kubernetes.io/no-provisioner`: no volumes are created.
    NoProvisioner,
    /// A CSI driver in the table.
    Csi(&'a Driver),
    /// A CSI driver by the in-tree map, with no table entry of its own.
    MigratedCsi,
    /// A provisioner in the table that is not CSI.
    NotCsi(&'a Driver),
    /// A name the table does not know.
    Unknown,
}

/// The parsed, checked table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Catalog {
    in_tree: Vec<InTree>,
    drivers: Vec<Driver>,
}

impl Catalog {
    /// Parses and checks table text.
    ///
    /// # Errors
    ///
    /// [`CatalogError`] naming the first entry that breaks a rule.
    pub(crate) fn parse(text: &str) -> Result<Self, CatalogError> {
        let file: File =
            toml::from_str(text).map_err(|e| CatalogError::Form(first_line(&e.to_string())))?;
        if file.schema != SCHEMA {
            return Err(CatalogError::Form(format!(
                "schema {} is not the {SCHEMA} this build reads",
                file.schema
            )));
        }
        if file.in_tree.len() > MAX_ENTRIES || file.driver.len() > MAX_ENTRIES {
            return Err(CatalogError::Form(format!(
                "more than {MAX_ENTRIES} entries of one kind"
            )));
        }
        let mut seen = BTreeSet::new();
        for (n, map) in file.in_tree.iter().enumerate() {
            let entry = if map.from.is_empty() {
                format!("in_tree #{}", n + 1)
            } else {
                map.from.clone()
            };
            let bad = |why: String| CatalogError::Entry {
                entry: entry.clone(),
                why,
            };
            for (field, name) in [("from", &map.from), ("to", &map.to)] {
                if !is_name(name) {
                    return Err(bad(format!("{field} must be a provisioner name")));
                }
            }
            if !seen.insert(map.from.clone()) {
                return Err(bad("the name is mapped twice".to_owned()));
            }
        }
        let mut names = BTreeSet::new();
        for (n, driver) in file.driver.iter().enumerate() {
            let entry = if driver.name.is_empty() {
                format!("driver #{}", n + 1)
            } else {
                driver.name.clone()
            };
            let bad = |why: String| CatalogError::Entry {
                entry: entry.clone(),
                why,
            };
            check_driver(driver).map_err(bad)?;
            if !names.insert(driver.name.clone()) {
                return Err(bad(
                    "the name is used twice, as an exact and as a suffix entry or twice over"
                        .to_owned(),
                ));
            }
            if seen.contains(&driver.name) {
                return Err(bad("the name is an in-tree name".to_owned()));
            }
        }
        Ok(Self {
            in_tree: file.in_tree,
            drivers: file.driver,
        })
    }

    /// The table this build ships.
    ///
    /// # Errors
    ///
    /// The reason the embedded file did not parse, which a test rules out.
    pub(crate) fn shipped() -> Result<&'static Self, &'static CatalogError> {
        static SHIPPED: OnceLock<Result<Catalog, CatalogError>> = OnceLock::new();
        SHIPPED.get_or_init(|| Self::parse(EMBEDDED)).as_ref()
    }

    /// The driver names the table knows as in-tree names, then as CSI drivers, in file order.
    #[cfg(test)]
    pub(crate) fn drivers(&self) -> &[Driver] {
        &self.drivers
    }

    /// The in-tree pairs, in file order.
    #[cfg(test)]
    pub(crate) fn in_tree_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.in_tree
            .iter()
            .map(|map| (map.from.as_str(), map.to.as_str()))
    }

    /// Applies the in-tree map to the provisioner of a class.
    pub(crate) fn normalise<'a>(&'a self, provisioner: &'a str) -> Normalised<'a> {
        match self.in_tree.iter().find(|map| map.from == provisioner) {
            Some(map) => Normalised {
                name: &map.to,
                migrated: true,
            },
            None => Normalised {
                name: provisioner,
                migrated: false,
            },
        }
    }

    /// The entry for a name: an exact entry first, then the longest suffix entry.
    pub(crate) fn driver(&self, name: &str) -> Option<&Driver> {
        let exact = self
            .drivers
            .iter()
            .find(|driver| driver.matching == Match::Exact && driver.name == name);
        exact.or_else(|| {
            self.drivers
                .iter()
                .filter(|driver| {
                    driver.matching == Match::Suffix
                        && (name == driver.name
                            || name
                                .strip_suffix(driver.name.as_str())
                                .is_some_and(|head| head.ends_with('.')))
                })
                .max_by_key(|driver| driver.name.len())
        })
    }

    /// What the table says about a provisioner as a class writes it.
    pub(crate) fn classify<'a>(&'a self, provisioner: &'a str) -> (Normalised<'a>, Kind<'a>) {
        let normalised = self.normalise(provisioner);
        if provisioner == NO_PROVISIONER {
            return (normalised, Kind::NoProvisioner);
        }
        let kind = match self.driver(normalised.name) {
            Some(driver) if driver.csi => Kind::Csi(driver),
            Some(driver) => Kind::NotCsi(driver),
            None if normalised.migrated => Kind::MigratedCsi,
            None => Kind::Unknown,
        };
        (normalised, kind)
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

/// A provisioner name: letters, digits and `. _ / -`, 1 to 253 bytes, starting with a letter or digit.
fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

fn check_driver(driver: &Driver) -> Result<(), String> {
    if !is_name(&driver.name) {
        return Err(
            "name must be 1 to 253 ASCII letters, digits and . _ / -, starting with a letter or digit"
                .to_owned(),
        );
    }
    if driver.matching == Match::Suffix && driver.name.contains('/') {
        return Err("a suffix entry cannot hold a /".to_owned());
    }
    if driver.csi && driver.name.contains('/') {
        return Err("a CSI driver name has no /".to_owned());
    }
    if driver.modes.is_empty() {
        return Err("modes must hold at least one access mode".to_owned());
    }
    let mut seen = BTreeSet::new();
    for mode in driver.modes.iter().chain(&driver.conditional_modes) {
        if !seen.insert(format!("{mode:?}")) {
            return Err(format!(
                "{mode:?} is listed twice, in modes or conditional_modes"
            ));
        }
    }
    if !driver.csi
        && driver
            .modes
            .iter()
            .chain(&driver.conditional_modes)
            .any(|mode| matches!(mode, AccessMode::ReadWriteOncePod))
    {
        return Err("ReadWriteOncePod is for CSI volumes only".to_owned());
    }
    match (&driver.condition, driver.conditional_modes.is_empty()) {
        (Some(words), false) => {
            if words.is_empty()
                || words.len() > MAX_CONDITION
                || words
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == ' ' || c == '-'))
                || words.trim() != words
            {
                return Err(format!(
                    "condition must be 1 to {MAX_CONDITION} ASCII letters, digits, spaces and dashes, with no space at an end"
                ));
            }
        }
        (None, true) => {}
        (Some(_), true) => return Err("condition needs conditional_modes".to_owned()),
        (None, false) => return Err("conditional_modes need a condition".to_owned()),
    }
    check_url(&driver.source)?;
    if driver.checked_on.len() != 10 || driver.checked_on.parse::<Date>().is_err() {
        return Err("checked_on must be a date written YYYY-MM-DD".to_owned());
    }
    Ok(())
}

/// An `https` URL with a host and nothing a link should not carry: no user, no query, no fragment.
fn check_url(url: &str) -> Result<(), String> {
    let host = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    if url.len() > MAX_URL
        || host.is_empty()
        || host.contains('@')
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
        || url.contains('?')
        || url.contains('#')
    {
        return Err(format!(
            "source must be a plain https URL with a host, no user, query or fragment, up to {MAX_URL} characters"
        ));
    }
    Ok(())
}
