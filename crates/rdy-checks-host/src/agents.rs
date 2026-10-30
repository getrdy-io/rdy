//! The security-software catalog behind `host.security_agents`.
//!
//! The catalog is `data/agents.toml`, embedded at build time (03 Appendix B). Each entry names a product,
//! its category and the process names it runs under. A match means "a process with this name is
//! running". It does not mean the product is installed.
//!
//! The file is parsed once, on first use, and checked hard: a duplicate id, a process name that two
//! entries share, a URL that is not `https`, a date that is not a date. The tests parse the shipped file,
//! so a bad entry fails the build and never reaches a customer. [`Catalog::parse`] takes any text, so
//! the tests can also show that each rule refuses what it should.
//!
//! The file holds no free text about risk. The check prints fixed neutral words, so the catalog cannot
//! be used to say something about a vendor's product.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Deserialize;

#[cfg(test)]
mod tests;

/// The shipped catalog text.
const EMBEDDED: &str = include_str!("../data/agents.toml");

/// The only schema number this build reads.
const SCHEMA: u32 = 1;
/// The most entries a catalog may hold.
const MAX_AGENTS: usize = 200;
/// The most process names one entry may hold.
const MAX_NAMES: usize = 8;
/// The longest process name, id, display name and URL, in bytes.
const MAX_NAME: usize = 64;
const MAX_DISPLAY: usize = 80;
const MAX_URL: usize = 300;
/// The kernel keeps 15 bytes of a process name in `/proc/<pid>/comm` (a 16 byte buffer with the NUL).
pub const COMM_MAX: usize = 15;

/// What kind of software an entry is. The check prints it next to the product name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Category {
    /// Endpoint detection and response.
    Edr,
    /// Antivirus.
    Av,
    /// Data loss prevention.
    Dlp,
    /// Backup.
    Backup,
}

impl Category {
    /// The word in `agents.toml`.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Edr => "edr",
            Self::Av => "av",
            Self::Dlp => "dlp",
            Self::Backup => "backup",
        }
    }

    /// The words a person reads in a report: `EDR`, `antivirus`, `DLP`, `backup`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Edr => "EDR",
            Self::Av => "antivirus",
            Self::Dlp => "DLP",
            Self::Backup => "backup",
        }
    }
}

/// One product in the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Agent {
    /// The id the spec's `forbid` and `allow` use.
    pub id: String,
    /// The product name as its vendor writes it.
    pub display_name: String,
    /// The kind of software.
    pub category: Category,
    /// The process names the product runs under, as the kernel shows them.
    pub process_names: Vec<String>,
    /// The public page the names came from.
    pub source: String,
    /// The day someone read that page, as `YYYY-MM-DD`.
    pub checked_on: String,
    /// The vendor's own public page on exclusions, if the entry has one.
    pub exclusion_docs_url: Option<String>,
}

impl Agent {
    /// Whether `comm`, a process name as the kernel shows it, is one of this product's names.
    ///
    /// The kernel keeps 15 bytes. A product name longer than that shows up cut, so a `comm` of exactly
    /// 15 bytes also matches a longer name that starts with it. A shorter `comm` must match whole.
    #[must_use]
    pub fn matches_comm(&self, comm: &str) -> bool {
        self.process_names
            .iter()
            .any(|name| comm_matches(comm, name))
    }
}

/// Whether the process name `comm` is the product process name `name`, allowing for the 15 byte cut.
#[must_use]
pub fn comm_matches(comm: &str, name: &str) -> bool {
    if comm == name {
        return true;
    }
    name.len() > COMM_MAX
        && comm.len() == COMM_MAX
        && name
            .as_bytes()
            .get(..COMM_MAX)
            .is_some_and(|head| head == comm.as_bytes())
}

/// Why a catalog could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CatalogError {
    /// The text is not TOML in the catalog's shape.
    #[error(
        "agents.toml is not in the expected form: {0}. Fix: use a build of rdy that ships a valid list"
    )]
    Form(String),
    /// An entry broke a rule.
    #[error("agents.toml entry {entry}: {why}. Fix: use a build of rdy that ships a valid list")]
    Entry {
        /// The entry's id, or its place in the file when it has none.
        entry: String,
        /// The rule it broke.
        why: String,
    },
}

/// The raw file: a schema number and the entries.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: u32,
    #[serde(default)]
    agent: Vec<Agent>,
}

/// The parsed, checked catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    agents: Vec<Agent>,
}

impl Catalog {
    /// Parses and checks catalog text.
    ///
    /// # Errors
    ///
    /// [`CatalogError`] naming the first entry that breaks a rule.
    pub fn parse(text: &str) -> Result<Self, CatalogError> {
        let file: File =
            toml::from_str(text).map_err(|e| CatalogError::Form(first_line(&e.to_string())))?;
        if file.schema != SCHEMA {
            return Err(CatalogError::Form(format!(
                "schema {} is not the {SCHEMA} this build reads",
                file.schema
            )));
        }
        if file.agent.len() > MAX_AGENTS {
            return Err(CatalogError::Form(format!(
                "{} entries is more than the {MAX_AGENTS} this build reads",
                file.agent.len()
            )));
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        for (n, agent) in file.agent.iter().enumerate() {
            let entry = if agent.id.is_empty() {
                format!("#{}", n + 1)
            } else {
                agent.id.clone()
            };
            let bad = |why: String| CatalogError::Entry {
                entry: entry.clone(),
                why,
            };
            check_agent(agent).map_err(bad)?;
            if !ids.insert(agent.id.clone()) {
                return Err(bad("the id is used twice".to_owned()));
            }
            for name in &agent.process_names {
                // Matching sees only the first 15 bytes of a name, so that is what must be unique: two
                // names with the same cut would both match one `comm`.
                let cut = &name[..name.len().min(COMM_MAX)];
                if !names.insert(cut.to_owned()) {
                    return Err(bad(format!(
                        "process name {name} is used by another name, or has the same first {COMM_MAX} bytes as one"
                    )));
                }
            }
        }
        Ok(Self { agents: file.agent })
    }

    /// The entries, in file order.
    #[must_use]
    pub fn agents(&self) -> &[Agent] {
        &self.agents
    }

    /// The entry with this id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Agent> {
        self.agents.iter().find(|agent| agent.id == id)
    }

    /// The ids, in file order. `rdy spec lint` lists these as the known agent ids.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.agents.iter().map(|agent| agent.id.as_str())
    }

    /// The entries whose `checked_on` is more than `max_days` before `today` (`YYYY-MM-DD`).
    ///
    /// 03 Appendix B: a date older than 180 days fails the release workflow, not the pull request
    /// workflow, or every pull request would turn red on day 181. A `today` that is not a date gives
    /// no entries; the caller passes the date of the run.
    #[must_use]
    pub fn stale(&self, today: &str, max_days: i64) -> Vec<&Agent> {
        let Some(now) = days(today) else {
            return Vec::new();
        };
        self.agents
            .iter()
            .filter(|agent| days(&agent.checked_on).is_none_or(|then| now - then > max_days))
            .collect()
    }
}

/// The catalog this build ships. The error is the reason the shipped file did not parse, which a test
/// rules out.
///
/// # Errors
///
/// [`CatalogError`] if the embedded `agents.toml` is not valid.
pub fn catalog() -> Result<&'static Catalog, &'static CatalogError> {
    static SHIPPED: OnceLock<Result<Catalog, CatalogError>> = OnceLock::new();
    SHIPPED.get_or_init(|| Catalog::parse(EMBEDDED)).as_ref()
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect()
}

fn check_agent(agent: &Agent) -> Result<(), String> {
    if !is_slug(&agent.id) {
        return Err("the id must be lowercase letters, digits and dashes, 1 to 64 characters, starting with a letter or digit".to_owned());
    }
    let shown = agent.display_name.chars().count();
    if shown == 0 || shown > MAX_DISPLAY || agent.display_name.chars().any(char::is_control) {
        return Err(format!(
            "display_name must be 1 to {MAX_DISPLAY} characters with no control character"
        ));
    }
    if agent.display_name.trim() != agent.display_name {
        return Err("display_name has a space at an end".to_owned());
    }
    if agent.process_names.is_empty() || agent.process_names.len() > MAX_NAMES {
        return Err(format!("process_names must hold 1 to {MAX_NAMES} names"));
    }
    let mut seen = BTreeSet::new();
    for name in &agent.process_names {
        if !is_process_name(name) {
            return Err(format!(
                "process name {name:?} must be 1 to {MAX_NAME} ASCII letters, digits and . _ + -"
            ));
        }
        if !seen.insert(name) {
            return Err(format!("process name {name} is listed twice"));
        }
    }
    check_url("source", &agent.source)?;
    if let Some(url) = &agent.exclusion_docs_url {
        check_url("exclusion_docs_url", url)?;
    }
    if days(&agent.checked_on).is_none() {
        return Err("checked_on must be a date written YYYY-MM-DD".to_owned());
    }
    Ok(())
}

fn is_slug(text: &str) -> bool {
    let mut chars = text.chars();
    text.len() <= MAX_NAME
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A name the kernel can show: ASCII letters, digits and a few marks. No space, so a name never starts
/// or ends with one and a log line stays readable.
fn is_process_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// An `https` URL with a host and nothing a link should not carry: no user, no password, no space.
fn check_url(field: &str, url: &str) -> Result<(), String> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(format!("{field} must start with https://"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if url.len() > MAX_URL
        || host.is_empty()
        || host.contains('@')
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
        || url.contains('?')
        || url.contains('#')
    {
        return Err(format!(
            "{field} must be a plain https URL with a host, no user, query or fragment, up to {MAX_URL} characters"
        ));
    }
    Ok(())
}

/// Days since 1970-01-01 for a `YYYY-MM-DD` date, or `None` when the text is not a real date.
fn days(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = text.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if year < 1970 || day < 1 || day > longest {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm), valid for the years above.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}
