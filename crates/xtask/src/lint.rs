//! `cargo xtask docs-lint`: fails on dashes and banned tokens in tracked text files.
//!
//! Scope: every text file that git tracks. Untracked files are skipped. A file that holds a NUL
//! byte counts as binary and is skipped. Any other file is decoded as UTF-8, and each byte that is
//! not valid UTF-8 becomes U+FFFD. So Latin-1 text still gets its dashes checked. Rules
//! (docs/plan/09-docs-site.md, sections 10 and 11):
//!
//! - no em dash (U+2014) and no en dash (U+2013);
//! - no token whose SHA-256 is listed in `data/banned-token-sha256.txt`.
//!
//! Each line is NFKC-normalized before the checks, so compatibility forms match the same way their
//! plain forms do. A token is a run of letters or digits. Every other character splits tokens. Each
//! token is lowercased and then hashed. The list holds hashes only, so the lint never prints a
//! banned word.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// The banned-token hashes. Compiled in, so the lint needs no file at run time.
const BANNED_HASHES: &str = include_str!("../data/banned-token-sha256.txt");

const EM_DASH: char = '\u{2014}';
const EN_DASH: char = '\u{2013}';

/// How long `git ls-files` may run. A hung git fails the lint instead of blocking the run.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// How often the timeout loop checks whether the command has exited.
const POLL: Duration = Duration::from_millis(20);

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
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line: String = raw.nfkc().collect();
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
        let Some(text) = decode(&bytes) else {
            continue;
        };
        scanned += 1;
        findings.extend(lint_text(&path, &text, &banned));
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
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(["ls-files", "-z"]);
    let captured = capture_with_timeout(command, GIT_TIMEOUT).context(
        "cannot run git. docs-lint reads the tracked files with git. Install git and run docs-lint in a git checkout.",
    )?;
    let Some(captured) = captured else {
        bail!(
            "git ls-files did not finish within {} seconds in {}. Check that git runs, then run docs-lint again.",
            GIT_TIMEOUT.as_secs(),
            root.display()
        );
    };
    if !captured.success {
        bail!(
            "git ls-files failed in {}: {}. Run docs-lint in a git checkout of the repo.",
            root.display(),
            String::from_utf8_lossy(&captured.stderr).trim()
        );
    }
    Ok(captured
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect())
}

/// What a finished command left behind.
struct Captured {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs `command` and collects its stdout and stderr. Returns `None` after it kills the command
/// when the command runs longer than `timeout`.
fn capture_with_timeout(mut command: Command, timeout: Duration) -> Result<Option<Captured>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start the command")?;
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        bail!("cannot capture the output of the command");
    };
    // Each pipe drains on its own thread. A full pipe would otherwise block the child.
    let out_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.read_to_end(&mut buf);
        buf
    });
    let err_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait().context("cannot check the command")? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(POLL);
    };
    Ok(Some(Captured {
        success: status.success(),
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    }))
}

/// The text of a file, or `None` for a binary file. A file with a NUL byte is binary. Any other
/// file is decoded as UTF-8, and each invalid byte becomes U+FFFD.
fn decode(bytes: &[u8]) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
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
    fn only_a_nul_byte_makes_a_file_binary() {
        assert!(decode(b"a\0b").is_none());
        assert_eq!(decode(b"plain").as_deref(), Some("plain"));
        assert!(decode(&[0xff, 0xfe]).is_some());
    }

    #[test]
    fn latin1_text_still_gets_its_dashes_checked() -> Result<()> {
        // 0xE9 is Latin-1 e-acute, which is not valid UTF-8. The em dash after it is valid.
        let bytes: &[u8] = b"Caf\xe9 \xe2\x80\x94 open\n";
        let text = decode(bytes).context("no NUL byte, so the file is text")?;
        let findings = lint_text("legacy.txt", &text, &banned_for_tests()?);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 1);
        assert!(findings[0].message.starts_with("em dash"));
        Ok(())
    }

    #[test]
    fn fullwidth_letters_match_the_banned_hash_after_nfkc() -> Result<()> {
        // Fullwidth lowercase letters that spell the synthetic token. NFKC maps them to ASCII.
        let fullwidth = "\u{ff42}\u{ff41}\u{ff4e}\u{ff4e}\u{ff45}\u{ff44}\u{ff54}\u{ff4f}\u{ff4b}\u{ff45}\u{ff4e}";
        let text = format!("Use {fullwidth} here.\n");
        assert_eq!(lint_text("a.md", &text, &banned_for_tests()?).len(), 1);
        Ok(())
    }

    #[test]
    fn a_small_em_dash_is_reported_after_nfkc() -> Result<()> {
        // U+FE58 SMALL EM DASH normalizes to U+2014.
        let findings = lint_text("a.md", "Install \u{fe58} now.\n", &banned_for_tests()?);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.starts_with("em dash"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_runs_too_long_is_stopped() -> Result<()> {
        let mut command = Command::new("sleep");
        command.arg("30");
        let started = Instant::now();
        let captured = capture_with_timeout(command, Duration::from_millis(200))?;
        assert!(captured.is_none());
        assert!(started.elapsed() < Duration::from_secs(20));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_command_that_finishes_is_captured() -> Result<()> {
        let mut command = Command::new("echo");
        command.arg("hi");
        let captured = capture_with_timeout(command, Duration::from_secs(20))?;
        assert!(captured.is_some_and(|c| c.success && c.stdout == b"hi\n"));
        Ok(())
    }
}
