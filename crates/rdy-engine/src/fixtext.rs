//! The fix-text audit: every command and sysctl name in remediation text must be on an allow-list.
//!
//! Fix text is what a customer engineer copies into a terminal (03, "Shared helpers"). A typo in it
//! is a support ticket, and a command nobody reviewed is a risk. So the commands and the kernel
//! parameters that fix text may name live in two reviewed files, and [`audit`] reports every one that
//! is not on them. Check crates call [`check`] in their tests on each fix template. A test in this
//! crate runs it over the fix bullets of the check catalog.
//!
//! The files are `commands.txt`, `sysctls.txt` and `literals.txt` in `crates/rdy-engine/src/fixtext/`.
//! One name per line, `#` starts a comment, sorted, no duplicates (a test holds that). `literals.txt`
//! lists whole backtick spans that are not commands (a quoted log message, a line of a config file),
//! compared as exact text; there a comment is a line that starts with `#`. A name in `commands.txt`
//! is something the customer runs. It is not the same list as the commands `rdy` itself runs
//! ([`crate::exec::table`]): `rdy` never runs `lvextend`, and a customer is never told to run
//! `getent` by a check that already ran it.
//!
//! # What counts as naming a command or a sysctl
//!
//! Only text inside backticks is read, because prose is prose. Each backtick span is split into
//! command segments at `&&`, `||`, `;`, `|` and newlines outside quotes, and each segment is split
//! into words with shell-like quoting. In a segment:
//!
//! - `sudo` and its options are skipped, and so are leading `NAME=value` words;
//! - the first word is a command if it is a plain name (a letter, then letters, digits and `_ . + -`)
//!   or an absolute path (its last component is the name), and the segment has at least one more word.
//!   A span of one unknown word is a term (`noexec`, `GRUB_CMDLINE_LINUX`), not a command, and is
//!   not judged. A command with no arguments is still checked when its name is on the list;
//! - a segment whose second word starts with `=` is a config line (`SystemdCgroup = true`) and is
//!   skipped, and so is a first word that starts with anything but a letter or `/` (`{unit}`, `<cpu`,
//!   `[plugins`, `:Z`) and a first word with no lower-case letter (`GRANT`, `CONFIG`: SQL and Redis
//!   statements are not shell commands);
//! - a span that is listed in `literals.txt` is not read at all;
//! - a word is a sysctl name when it starts with `kernel.`, `vm.`, `net.`, `fs.`, `abi.`, `debug.`,
//!   `dev.`, `user.` or `crypto.`, up to a `=`, and is not a file or unit name (`user.slice`,
//!   `fs.conf`). Under `net.` a name needs three labels (`net.core.somaxconn`), because check ids such
//!   as `net.dns` have two. The words of `sysctl` itself are names too, whatever they start with.
//!
//! A `{placeholder}` stays in a name as written, so `net.ipv4.conf.{iface}.rp_filter` is listed in
//! `sysctls.txt` with its braces.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::OnceLock;

#[cfg(test)]
mod tests;

const COMMANDS_FILE: &str = include_str!("fixtext/commands.txt");
const SYSCTLS_FILE: &str = include_str!("fixtext/sysctls.txt");
const LITERALS_FILE: &str = include_str!("fixtext/literals.txt");

/// The most violations [`audit`] returns for one text.
pub const MAX_VIOLATIONS: usize = 100;

/// The first label of a kernel parameter name.
const SYSCTL_ROOTS: &[&str] = &[
    "kernel", "vm", "net", "fs", "abi", "debug", "dev", "user", "crypto",
];

/// Endings that make a dotted word a file or unit name, not a parameter.
const FILE_SUFFIXES: &[&str] = &[
    "slice", "service", "mount", "socket", "target", "scope", "timer", "conf", "json", "yaml",
    "yml", "toml", "txt", "log", "d", "sh", "crt", "pem",
];

/// What kind of name a violation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A command the customer is told to run.
    Command,
    /// A kernel parameter.
    Sysctl,
}

/// One name in fix text that is not on its allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Violation {
    /// Command or sysctl.
    pub kind: Kind,
    /// The name as written.
    pub name: String,
    /// The backtick span it was found in.
    pub span: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (what, file) = match self.kind {
            Kind::Command => ("command", "commands.txt"),
            Kind::Sysctl => ("sysctl", "sysctls.txt"),
        };
        write!(
            f,
            "fix text names the {what} `{}` in `{}`, which is not in crates/rdy-engine/src/fixtext/{file}. Fix: correct the spelling, or add it to {file} in the same change",
            self.name, self.span
        )
    }
}

/// Fix text that names something outside the allow-lists.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"))]
pub struct FixTextError(pub Vec<Violation>);

/// Why an allow-list file did not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AllowListError {
    /// A line is not a valid name.
    #[error(
        "{file} line {line}: `{text}` is not a valid name. Fix: one plain name per line, or a `#` comment"
    )]
    BadLine {
        /// The file.
        file: &'static str,
        /// The 1-based line number.
        line: usize,
        /// The line.
        text: String,
    },
}

/// The two allow-lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowLists {
    commands: BTreeSet<String>,
    sysctls: BTreeSet<String>,
    literals: BTreeSet<String>,
}

impl AllowLists {
    /// Parses the text of the three files.
    ///
    /// # Errors
    ///
    /// [`AllowListError::BadLine`] for the first line that is not a valid entry.
    pub fn parse(commands: &str, sysctls: &str, literals: &str) -> Result<Self, AllowListError> {
        let literals = literals
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect();
        Ok(Self {
            commands: parse_names("commands.txt", commands, is_command_name)?,
            sysctls: parse_names("sysctls.txt", sysctls, is_sysctl_name)?,
            literals,
        })
    }

    /// The lists built into this binary. If an embedded file does not parse (a test holds that it
    /// does) the lists are empty, so every name is a violation and nothing passes by accident.
    #[must_use]
    pub fn embedded() -> &'static Self {
        static LISTS: OnceLock<AllowLists> = OnceLock::new();
        LISTS.get_or_init(|| {
            Self::parse(COMMANDS_FILE, SYSCTLS_FILE, LITERALS_FILE).unwrap_or_default()
        })
    }

    /// Whether fix text may tell the customer to run `name`.
    #[must_use]
    pub fn allows_command(&self, name: &str) -> bool {
        self.commands.contains(name)
    }

    /// Whether fix text may name the kernel parameter `name`.
    #[must_use]
    pub fn allows_sysctl(&self, name: &str) -> bool {
        self.sysctls.contains(name)
    }

    /// Whether `span` is listed as text that is not a command.
    #[must_use]
    pub fn allows_literal(&self, span: &str) -> bool {
        self.literals.contains(span)
    }

    /// The listed literal spans, sorted.
    pub fn literals(&self) -> impl Iterator<Item = &str> {
        self.literals.iter().map(String::as_str)
    }

    /// The listed commands, sorted.
    pub fn commands(&self) -> impl Iterator<Item = &str> {
        self.commands.iter().map(String::as_str)
    }

    /// The listed kernel parameters, sorted.
    pub fn sysctls(&self) -> impl Iterator<Item = &str> {
        self.sysctls.iter().map(String::as_str)
    }
}

fn parse_names(
    file: &'static str,
    text: &str,
    valid: fn(&str) -> bool,
) -> Result<BTreeSet<String>, AllowListError> {
    let mut names = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if !valid(line) {
            return Err(AllowListError::BadLine {
                file,
                line: index + 1,
                text: raw.to_owned(),
            });
        }
        names.insert(line.to_owned());
    }
    Ok(names)
}

fn is_command_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

fn is_sysctl_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_lowercase())
        && name.contains('.')
        && !name.ends_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '/' | '{' | '}'))
}

/// Checks `text` against the lists built into this binary.
///
/// # Errors
///
/// [`FixTextError`] with every name that is not listed.
pub fn check(text: &str) -> Result<(), FixTextError> {
    let found = audit(text, AllowLists::embedded());
    if found.is_empty() {
        Ok(())
    } else {
        Err(FixTextError(found))
    }
}

/// Every command and sysctl name in `text` that is not on `allow`, at most [`MAX_VIOLATIONS`], in
/// reading order and without repeats.
#[must_use]
pub fn audit(text: &str, allow: &AllowLists) -> Vec<Violation> {
    let mut out: Vec<Violation> = Vec::new();
    let mut push = |kind: Kind, name: &str, span: &str| {
        let violation = Violation {
            kind,
            name: name.to_owned(),
            span: span.to_owned(),
        };
        if out.len() < MAX_VIOLATIONS && !out.contains(&violation) {
            out.push(violation);
        }
    };
    for span in spans(text) {
        if allow.allows_literal(span) {
            continue;
        }
        let segments = segments(span);
        for words in &segments {
            if let Some(name) = command_of(words, allow) {
                push(Kind::Command, &name, span);
            }
            for name in sysctls_of(words, allow) {
                push(Kind::Sysctl, &name, span);
            }
        }
        // A sysctl inside a quoted argument (`echo 'net.x.y = 1'`) is one word above. Read the span
        // word by word as well.
        for word in span.split_whitespace() {
            let word = word.trim_matches(|c: char| matches!(c, '\'' | '"' | '(' | ')' | ',' | ';'));
            if let Some(name) = sysctl_shaped(word)
                && !allow.allows_sysctl(&name)
            {
                push(Kind::Sysctl, &name, span);
            }
        }
    }
    out
}

/// The backtick spans of `text`. An unpaired backtick ends the scan.
fn spans(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else {
            break;
        };
        out.push(&after[..end]);
        rest = &after[end + 1..];
    }
    out
}

/// Splits one span into command segments of words. Quotes group words and are removed; a backslash
/// outside single quotes escapes the next character.
fn segments(span: &str) -> Vec<Vec<String>> {
    let mut segments: Vec<Vec<String>> = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = span.chars().peekable();

    fn end_word(words: &mut Vec<String>, word: &mut String, in_word: &mut bool) {
        if *in_word {
            words.push(std::mem::take(word));
            *in_word = false;
        }
    }
    fn end_segment(
        segments: &mut Vec<Vec<String>>,
        words: &mut Vec<String>,
        word: &mut String,
        in_word: &mut bool,
    ) {
        end_word(words, word, in_word);
        if !words.is_empty() {
            segments.push(std::mem::take(words));
        }
    }

    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                } else {
                    word.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        word.push(next);
                        in_word = true;
                    }
                }
                '&' | '|' | ';' | '\n' => {
                    end_segment(&mut segments, &mut words, &mut word, &mut in_word);
                }
                c if c.is_whitespace() => end_word(&mut words, &mut word, &mut in_word),
                c => {
                    word.push(c);
                    in_word = true;
                }
            },
        }
    }
    end_segment(&mut segments, &mut words, &mut word, &mut in_word);
    segments
}

/// The command name of a segment when it is unlisted, per the rules in the module docs.
fn command_of(words: &[String], allow: &AllowLists) -> Option<String> {
    let mut at = 0;
    if words.first().is_some_and(|w| w == "sudo") {
        at = 1;
        while words.get(at).is_some_and(|w| w.starts_with('-')) {
            at += 1;
        }
    }
    while words.get(at).is_some_and(|w| is_assignment(w)) {
        at += 1;
    }
    let first = words.get(at)?;
    let name = if first.starts_with('/') {
        first.rsplit('/').next().unwrap_or_default()
    } else {
        first.as_str()
    };
    if !is_command_name(name) || !name.chars().any(|c| c.is_ascii_lowercase()) {
        return None;
    }
    if words.get(at + 1).is_some_and(|w| w.starts_with('=')) {
        return None;
    }
    let has_arguments = words.len() > at + 1;
    if !has_arguments || allow.allows_command(name) {
        return None;
    }
    Some(name.to_owned())
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Unlisted parameter names among the words of `sysctl` itself.
fn sysctls_of(words: &[String], allow: &AllowLists) -> Vec<String> {
    let mut at = 0;
    if words.first().is_some_and(|w| w == "sudo") {
        at = 1;
    }
    let is_sysctl = words
        .get(at)
        .is_some_and(|w| w.rsplit('/').next() == Some("sysctl"));
    if !is_sysctl {
        return Vec::new();
    }
    words
        .iter()
        .skip(at + 1)
        .filter(|w| !w.starts_with(['-', '/', '{']))
        .filter_map(|w| {
            let name = w.split('=').next().unwrap_or_default();
            (is_sysctl_name(name) && !allow.allows_sysctl(name)).then(|| name.to_owned())
        })
        .collect()
}

/// The parameter name in `word` when it has the shape of one (a known root label, a dot, the rest),
/// without any `=value`.
fn sysctl_shaped(word: &str) -> Option<String> {
    let name = word
        .split('=')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let (root, rest) = name.split_once('.')?;
    if !SYSCTL_ROOTS.contains(&root) || rest.is_empty() || !is_sysctl_name(name) {
        return None;
    }
    if root == "net" && !rest.contains('.') {
        return None;
    }
    let last = name.rsplit('.').next().unwrap_or_default();
    if FILE_SUFFIXES.contains(&last) {
        return None;
    }
    Some(name.to_owned())
}
