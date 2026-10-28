//! `cargo xtask docs-lint`: fails on dashes and banned tokens in tracked text files.
//!
//! Scope: every text file that git tracks. Untracked files, binary files and files that are not
//! UTF-8 are skipped. Rules (docs/plan/09-docs-site.md, sections 10 and 11):
//!
//! - no em dash (U+2014) and no en dash (U+2013);
//! - no token whose SHA-256 is listed in `data/banned-token-sha256.txt`.
//!
//! A token is a run of letters or digits. Every other character splits tokens. Each token is
//! lowercased and then hashed. The list holds hashes only, so the lint never prints a banned word.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// The banned-token hashes. Compiled in, so the lint needs no file at run time.
const BANNED_HASHES: &str = include_str!("../data/banned-token-sha256.txt");

const EM_DASH: char = '\u{2014}';
const EN_DASH: char = '\u{2013}';

/// One line that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Path relative to the repo root.
    pub path: String,
    /// One-based line number.
    pub line: usize,
    /// What is wrong and how to fix it. Never contains the banned token.
    pub message: String,
}

/// SHA-256 hashes, as lowercase hex, of the banned tokens.
#[derive(Debug, Default)]
pub struct BannedHashes(HashSet<String>);

impl BannedHashes {
    /// Parses the list format: one hash per line. Blank lines and `#` comments are ignored.
    pub fn parse(list: &str) -> Result<Self> {
        let mut hashes = HashSet::new();
        for (index, raw) in list.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let well_formed = line.len() == 64
                && line
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !well_formed {
                bail!(
                    "banned token list line {} is not a 64-character lowercase SHA-256 hash. Fix that line in crates/xtask/data/banned-token-sha256.txt.",
                    index + 1
                );
            }
            hashes.insert(line.to_owned());
        }
        Ok(Self(hashes))
    }

    /// True when the lowercased `token` hashes to an entry in the list.
    fn matches(&self, token: &str) -> bool {
        self.0
            .contains(&hex_sha256(token.to_lowercase().as_bytes()))
    }
}

/// Lowercase hex SHA-256 of `bytes`.
fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Checks one file's text against both rules. Each finding carries its line number.
pub fn lint_text(path: &str, text: &str, banned: &BannedHashes) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        for (dash, name) in [(EM_DASH, "em dash"), (EN_DASH, "en dash")] {
            if line.contains(dash) {
                findings.push(Finding {
                    path: path.to_owned(),
                    line: number,
                    message: format!("{name} found. Use a full stop, a comma or a colon instead."),
                });
            }
        }
        let banned_here = line
            .split(|c: char| !c.is_alphanumeric())
            .any(|token| !token.is_empty() && banned.matches(token));
        if banned_here {
            findings.push(Finding {
                path: path.to_owned(),
                line: number,
                message: "banned token found. Replace the word. The list holds hashes, so this message does not name it.".to_owned(),
            });
        }
    }
    findings
}

/// Runs the lint over the tracked files of the repo at `root`. Prints each finding to stderr.
/// Returns `Ok(true)` when no finding exists.
pub fn run(root: &Path) -> Result<bool> {
    let banned = BannedHashes::parse(BANNED_HASHES)?;
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for path in tracked_files(root)? {
        let bytes = match fs::read(root.join(&path)) {
            Ok(bytes) => bytes,
            // Tracked but deleted in the working tree. Nothing to lint.
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err).with_context(|| format!("cannot read {path}")),
        };
        let Some(text) = as_text(&bytes) else {
            continue;
        };
        scanned += 1;
        findings.extend(lint_text(&path, text, &banned));
    }
    for finding in &findings {
        eprintln!("{}:{}: {}", finding.path, finding.line, finding.message);
    }
    if findings.is_empty() {
        eprintln!("docs-lint: {scanned} tracked text file(s) are clean.");
        Ok(true)
    } else {
        eprintln!(
            "docs-lint: {} finding(s) in {scanned} tracked text file(s). Fix each line above.",
            findings.len()
        );
        Ok(false)
    }
}

/// The tracked file paths under `root`, from `git ls-files`.
fn tracked_files(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .context("cannot run git. docs-lint reads the tracked files with git. Install git and run docs-lint in a git checkout.")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed in {}. Run docs-lint in a git checkout of the repo.",
            root.display()
        );
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// The text of a file, or `None` for a binary file or a file that is not UTF-8.
fn as_text(bytes: &[u8]) -> Option<&str> {
    if bytes.contains(&0) {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic banned token. Written in two pieces so this file never contains it whole.
    const SYNTHETIC_TOKEN: &str = concat!("banned", "token");

    fn banned_for_tests() -> Result<BannedHashes> {
        BannedHashes::parse(&format!("{}\n", hex_sha256(SYNTHETIC_TOKEN.as_bytes())))
    }

    #[test]
    fn shipped_list_parses() -> Result<()> {
        BannedHashes::parse(BANNED_HASHES)?;
        Ok(())
    }

    #[test]
    fn shipped_list_holds_the_synthetic_token_hash() -> Result<()> {
        let banned = BannedHashes::parse(BANNED_HASHES)?;
        assert!(banned.matches(SYNTHETIC_TOKEN));
        Ok(())
    }

    #[test]
    fn hex_sha256_matches_a_known_vector() {
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn parse_skips_comments_and_blank_lines() -> Result<()> {
        let list = format!("# comment\n\n  {}  \n", hex_sha256(b"x"));
        let banned = BannedHashes::parse(&list)?;
        assert!(banned.matches("x"));
        Ok(())
    }

    #[test]
    fn parse_rejects_a_line_that_is_not_a_hash() {
        assert!(BannedHashes::parse("not-a-hash\n").is_err());
    }

    #[test]
    fn parse_rejects_an_uppercase_hash() {
        let upper = hex_sha256(b"x").to_uppercase();
        assert!(BannedHashes::parse(&upper).is_err());
    }

    #[test]
    fn clean_text_has_no_findings() -> Result<()> {
        let findings = lint_text(
            "a.md",
            "Install the binary.\nRun it.\n",
            &banned_for_tests()?,
        );
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn em_dash_is_reported_with_its_line() -> Result<()> {
        let text = "ok\nInstall \u{2014} then run.\n";
        let findings = lint_text("docs/a.md", text, &banned_for_tests()?);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "docs/a.md");
        assert_eq!(findings[0].line, 2);
        assert!(findings[0].message.starts_with("em dash"));
        Ok(())
    }

    #[test]
    fn en_dash_is_reported() -> Result<()> {
        let findings = lint_text("docs/a.md", "2020\u{2013}2021\n", &banned_for_tests()?);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.starts_with("en dash"));
        Ok(())
    }

    #[test]
    fn banned_token_matches_in_any_case_and_next_to_punctuation() -> Result<()> {
        let banned = banned_for_tests()?;
        let upper = SYNTHETIC_TOKEN.to_uppercase();
        for text in [
            format!("Use {SYNTHETIC_TOKEN} here."),
            format!("Use {upper} here."),
            format!("(({SYNTHETIC_TOKEN}))"),
            format!("{SYNTHETIC_TOKEN}-suffix"),
        ] {
            assert_eq!(lint_text("a.md", &text, &banned).len(), 1, "{text}");
        }
        Ok(())
    }

    #[test]
    fn banned_token_does_not_match_inside_a_longer_word() -> Result<()> {
        let text = format!("The {SYNTHETIC_TOKEN}s are plural.");
        assert!(lint_text("a.md", &text, &banned_for_tests()?).is_empty());
        Ok(())
    }

    #[test]
    fn banned_finding_never_names_the_token() -> Result<()> {
        let text = format!("Use {SYNTHETIC_TOKEN} here.");
        let findings = lint_text("a.md", &text, &banned_for_tests()?);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].message.to_lowercase().contains(SYNTHETIC_TOKEN));
        Ok(())
    }

    #[test]
    fn binary_and_non_utf8_files_are_not_text() {
        assert!(as_text(b"a\0b").is_none());
        assert!(as_text(&[0xff, 0xfe]).is_none());
        assert_eq!(as_text(b"plain"), Some("plain"));
    }
}
