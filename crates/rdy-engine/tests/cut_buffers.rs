//! Buffers the facade cut, and the run-scoped known-secret set (M1-061, ADR 0015 decisions 2, 3 and 9).
//!
//! For each facade cap (file read, tail read, stdout, stderr) a synthetic secret is placed so that the
//! cap cuts it at every offset from 1 to 64 bytes from the cap. The buffer comes back from the real
//! `Probe`, goes through `file_text`, `stdout_text` or `stderr_text`, into a report, through
//! `redact_report`, and into JSON. No fragment of the secret may survive anywhere.
//!
//! What this file proves, and what it does not:
//!
//! - A secret in the partial edge line is dropped with the line, whatever rules exist. That is what
//!   these tests place at the cap.
//! - A private key that starts in a whole line and is cut before its end is removed through the end.
//! - A secret in a whole line near the cap needs a rule for its shape (key id, URL userinfo, a complete
//!   PEM block). Those rules are M1-060, so those cases are `ignore`d until it lands.
//! - The HTML part of the exit test belongs to M1-077 (there is no renderer yet), and the stderr part to
//!   `rdy-cli/tests/log_redaction.rs`.

use std::error::Error;
use std::path::{Path, PathBuf};

use rdy_engine::check::Os;
use rdy_engine::exec::{DEFAULT_STDERR_CAP, DEFAULT_STDOUT_CAP};
use rdy_engine::probe::{MAX_READ, Output};
use rdy_engine::redact::{Redactor, TagKey};
use rdy_engine::testing::{Replay, TestRun};
use rdy_spec::result::Report;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const LOG: &str = "/var/log/synthetic.log";
const TAIL_MAX: usize = 64 * 1024;

/// A secret and the strings that must not survive in any form.
struct Canary {
    name: &'static str,
    /// The text as it stands in a file, newline included.
    text: String,
    /// Every 8-byte window of the secret part.
    needles: Vec<String>,
}

fn windows(secret: &str) -> Vec<String> {
    secret
        .as_bytes()
        .windows(8)
        .filter_map(|w| std::str::from_utf8(w).ok().map(str::to_owned))
        .collect()
}

fn pem() -> Canary {
    let body: Vec<String> = (0..5)
        .map(|i| {
            let line: String = (0..64)
                .map(|j| {
                    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                    char::from(table[(i * 17 + j * 7 + j / 3) % 64])
                })
                .collect();
            format!("{line}Zk{i}")
        })
        .collect();
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        body.join("\n")
    );
    let needles = body.iter().flat_map(|line| windows(line)).collect();
    Canary {
        name: "pem",
        text,
        needles,
    }
}

fn aws() -> Canary {
    let id = "AKIAZ3Q7XK2MCANARY4B";
    Canary {
        name: "aws key id",
        text: format!("id: {id}\n"),
        needles: windows(id),
    }
}

fn url() -> Canary {
    let userinfo = "svcuser:Pw7canaryZq9";
    Canary {
        name: "url userinfo",
        text: format!("proxy: https://{userinfo}@proxy.example.test:3128/\n"),
        needles: windows(userinfo),
    }
}

/// Exactly `n` bytes of 63 `x` and a newline, repeated.
fn filler(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| if i % 64 == 63 { b'\n' } else { b'x' })
        .collect()
}

/// A file whose first `cap` bytes hold `canary` starting `k` bytes before the cap. The canary is
/// followed by `p` up to the cap, with no newline, then 100 more bytes the cap cuts off.
fn tail_cut_file(cap: usize, k: usize, canary: &str) -> Vec<u8> {
    let mut data = filler(cap - k);
    data.extend_from_slice(canary.as_bytes());
    if canary.len() < k {
        data.extend(std::iter::repeat_n(b'p', k - canary.len()));
    }
    data.extend(std::iter::repeat_n(b'q', 100));
    data
}

/// A file whose last `max` bytes start `s` bytes into `canary`. The canary is whole in the file; what
/// follows it is filler lines.
fn head_cut_file(max: usize, s: usize, canary: &str) -> Vec<u8> {
    let mut data = filler(5000);
    data.extend_from_slice(canary.as_bytes());
    let after = max + s - canary.len();
    data.extend(filler(after));
    data
}

fn run_with(replay: Replay) -> TestRun {
    TestRun::new(replay)
}

/// Puts `text` in every string field a check can fill, redacts the report and returns its JSON.
///
/// Only the first and last 4 KiB go in: the cut is at an edge, and 1 MiB three times per offset is slow in a
/// debug build. The whole text is checked before this.
fn through_report(redactor: &Redactor, text: &str) -> TestResult<String> {
    let head = &text[..text.floor_char_boundary(4096)];
    let tail = &text[text.ceil_char_boundary(text.len().saturating_sub(4096))..];
    let text = format!("{head}\n...\n{tail}");
    let text = text.as_str();
    let mut doc = sample()?;
    doc["checks"][0]["message"] = json!(format!("read it: {text}"));
    doc["checks"][0]["observed"] = json!({ "evidence": text });
    doc["checks"][0]["notes"] = json!([text]);
    let report: Report = serde_json::from_value(doc)?;
    let redacted = redactor.redact_report(report)?;
    Ok(serde_json::to_string(&*redacted)?)
}

/// The 01 section 7.2 sample report, read from the plan as `redacted_report.rs` does.
fn sample() -> TestResult<Value> {
    let path: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/01-spec-format.md");
    let doc = std::fs::read_to_string(path)?.replace("\r\n", "\n");
    let start = doc.find("\n### 7.2 ").ok_or("heading not found")?;
    let section = &doc[start + 1..];
    let open = section.find("```json\n").ok_or("no json block")? + "```json\n".len();
    let body = &section[open..];
    let close = body.find("\n```").ok_or("unterminated json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

fn assert_clean(what: &str, offset: usize, text: &str, canary: &Canary) {
    for needle in &canary.needles {
        assert!(
            !text.contains(needle.as_str()),
            "{what}: {} survived at offset {offset} (needle {needle})",
            canary.name
        );
    }
}

/// The offsets from the cap to try. A cap of 64 KiB or less gets every offset from 1 to 64. The 1 MiB caps
/// get a spread that includes both ends and every size of canary edge, because a debug build redacts
/// 1 MiB slowly and the partial-line drop does not depend on the offset.
fn offsets(cap: usize) -> Vec<usize> {
    if cap <= 64 * 1024 {
        (1..=64).collect()
    } else {
        vec![1, 2, 27, 28, 29, 63, 64]
    }
}

/// Where a canary starts, counted back from the cap. A key also starts further back, so whole body lines
/// of it lie inside the buffer and only the unterminated key guard can remove them.
fn back(canary: &Canary, k: usize) -> Vec<usize> {
    if canary.name == "pem" {
        vec![k, k + 140]
    } else {
        vec![k]
    }
}

/// Every canary at the offsets of [`offsets`] from the cap of a file read.
#[tokio::test(flavor = "current_thread")]
async fn a_secret_cut_by_the_file_cap_never_reaches_the_report() -> TestResult {
    let redactor = Redactor::new(TagKey::fixed([4; 32]));
    for canary in [pem(), aws(), url()] {
        let text = canary.text.trim_end_matches('\n').to_owned();
        let text = if canary.name == "pem" {
            canary.text.clone()
        } else {
            text
        };
        for k in offsets(MAX_READ).into_iter().flat_map(|k| back(&canary, k)) {
            let run = run_with(Replay::new().file(LOG, tail_cut_file(MAX_READ, k, &text)));
            let ctx = run.context("host.synthetic", Os::Linux, []);
            let file = ctx.probe().read(Path::new(LOG)).await?;
            assert!(file.truncated_tail && !file.truncated_head);
            assert_eq!(file.bytes.len(), MAX_READ);
            let shown = ctx.probe().file_text(&file)?;
            assert_clean("file", k, &shown, &canary);
            assert_clean(
                "file report",
                k,
                &through_report(&redactor, &shown)?,
                &canary,
            );
        }
    }
    Ok(())
}

/// The same for stdout and stderr, which the facade cuts at the end.
#[test]
fn a_secret_cut_by_the_stdout_or_stderr_cap_never_reaches_the_report() -> TestResult {
    let redactor = Redactor::new(TagKey::fixed([4; 32]));
    let run = run_with(Replay::new());
    let ctx = run.context("net.synthetic", Os::Linux, []);
    for canary in [pem(), aws(), url()] {
        let text = if canary.name == "pem" {
            canary.text.clone()
        } else {
            canary.text.trim_end_matches('\n').to_owned()
        };
        // The default stdout cap, a lower cap a check declared, and the stderr cap.
        for cap in [DEFAULT_STDOUT_CAP, 64 * 1024] {
            for k in offsets(cap).into_iter().flat_map(|k| back(&canary, k)) {
                let data = tail_cut_file(cap, k, &text);
                let mut out = Output::new(Some(0), data[..cap].to_vec());
                out.stdout_truncated = true;
                let shown = ctx.probe().stdout_text(&out)?;
                assert_clean("stdout", k, &shown, &canary);
                assert_clean(
                    "stdout report",
                    k,
                    &through_report(&redactor, &shown)?,
                    &canary,
                );
            }
        }
        for k in offsets(DEFAULT_STDERR_CAP) {
            let data = tail_cut_file(DEFAULT_STDERR_CAP, k, &text);
            let mut out = Output::new(Some(1), Vec::new());
            out.stderr = data[..DEFAULT_STDERR_CAP].to_vec();
            out.stderr_truncated = true;
            let shown = ctx.probe().stderr_text(&out)?;
            assert_clean("stderr", k, &shown, &canary);
            assert_clean(
                "stderr report",
                k,
                &through_report(&redactor, &shown)?,
                &canary,
            );
        }
    }
    Ok(())
}

/// A tail read cuts the head. The window starts `s` bytes into the secret.
#[tokio::test(flavor = "current_thread")]
async fn a_secret_cut_by_the_tail_cap_never_reaches_the_report() -> TestResult {
    let redactor = Redactor::new(TagKey::fixed([4; 32]));
    for canary in [pem(), aws(), url()] {
        let len = canary.text.len();
        for s in 1..=64.min(len - 1) {
            let run = run_with(Replay::new().file(LOG, head_cut_file(TAIL_MAX, s, &canary.text)));
            let ctx = run.context("host.synthetic", Os::Linux, []);
            let file = ctx.probe().read_tail(Path::new(LOG), TAIL_MAX).await?;
            assert!(file.truncated_head && !file.truncated_tail);
            assert_eq!(file.bytes.len(), TAIL_MAX);
            let shown = ctx.probe().file_text(&file)?;
            assert_clean("tail", s, &shown, &canary);
            assert_clean(
                "tail report",
                s,
                &through_report(&redactor, &shown)?,
                &canary,
            );
        }
    }
    Ok(())
}

/// A secret in a whole line near the cap needs the rule for its shape.
#[tokio::test(flavor = "current_thread")]
#[ignore = "M1-060"]
async fn a_whole_line_secret_just_inside_the_cap_needs_its_rule() -> TestResult {
    let redactor = Redactor::new(TagKey::fixed([4; 32]));
    for canary in [aws(), url(), pem()] {
        for k in 1..=64 {
            // The canary ends with a newline and `p` fill follows it, so it is whole.
            let mut data = filler(MAX_READ - k - 100);
            data.extend_from_slice(canary.text.as_bytes());
            data.extend(filler(MAX_READ + 100 - data.len()));
            let run = run_with(Replay::new().file(LOG, data));
            let ctx = run.context("host.synthetic", Os::Linux, []);
            let file = ctx.probe().read(Path::new(LOG)).await?;
            let shown = ctx.probe().file_text(&file)?;
            assert_clean("whole line", k, &shown, &canary);
            assert_clean(
                "whole line report",
                k,
                &through_report(&redactor, &shown)?,
                &canary,
            );
        }
    }
    Ok(())
}

const TOKEN: &str = "kt-Zk3v9Qx7canaryTOKEN";

fn token_windows() -> Vec<String> {
    windows(TOKEN)
}

fn assert_no_token(what: &str, text: &str) {
    for needle in token_windows() {
        assert!(
            !text.contains(&needle),
            "{what}: the token leaked ({needle})"
        );
    }
}

/// A run over a file at [`LOG`] with the token already in the known-secret set.
fn run_knowing_the_token(data: impl Into<Vec<u8>>) -> TestRun {
    let run = run_with(Replay::new().file(LOG, data));
    assert!(run.add_known_secret(TOKEN));
    run
}

#[tokio::test(flavor = "current_thread")]
async fn a_known_token_is_removed_from_a_whole_line_with_no_key_name_around_it() -> TestResult {
    let run = run_knowing_the_token(format!("context: staging\nsee {TOKEN} for details\n"));
    let ctx = run.context("k8s.synthetic", Os::Linux, []);
    let file = ctx.probe().read(Path::new(LOG)).await?;
    let shown = ctx.probe().file_text(&file)?;
    assert_no_token("uncut file", &shown);
    assert!(shown.contains("see [REDACTED:known_secret:"), "{}", *shown);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_known_token_is_removed_from_a_file_the_cap_cut() -> TestResult {
    for k in [1, 8, 33, 64] {
        // A whole copy in a whole line, then a copy that starts k bytes before the cap.
        let mut data = filler(MAX_READ - k - 300);
        data.extend_from_slice(format!("\nwhole {TOKEN} copy\n").as_bytes());
        data.extend(std::iter::repeat_n(b'.', MAX_READ - k - data.len()));
        data.extend_from_slice(TOKEN.as_bytes());
        data.extend(std::iter::repeat_n(b'q', 300));
        let run = run_knowing_the_token(data);
        let ctx = run.context("k8s.synthetic", Os::Linux, []);
        let file = ctx.probe().read(Path::new(LOG)).await?;
        assert!(file.truncated_tail);
        let shown = ctx.probe().file_text(&file)?;
        assert_no_token("file cap", &shown);
        assert!(shown.contains("whole [REDACTED:known_secret:"), "k {k}");
    }
    Ok(())
}

#[test]
fn a_known_token_is_removed_from_every_string_of_a_report() -> TestResult {
    let redactor = Redactor::new(TagKey::fixed([4; 32]));
    assert!(redactor.add_known_secret(TOKEN));
    let mut doc = sample()?;
    doc["host"]["hostname"] = json!(format!("h-{TOKEN}"));
    doc["checks"][0]["message"] = json!(format!("a {TOKEN} b"));
    doc["checks"][0]["fix"] = json!(format!("run with {TOKEN}"));
    doc["checks"][0]["observed"] = json!({ "free": format!("x{TOKEN}y"), "list": [TOKEN] });
    let report: Report = serde_json::from_value(doc)?;
    let redacted = redactor.redact_report(report)?;
    let text = serde_json::to_string(&*redacted)?;
    assert_no_token("report", &text);
    assert!(redacted.redaction.by_rule.contains_key("known_secret"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_known_token_is_removed_from_the_action_log() -> TestResult {
    let run = run_knowing_the_token("x");
    let ctx = run.context("k8s.synthetic", Os::Linux, []);
    // The path is in the log entry of a read that fails.
    let result = ctx
        .probe()
        .read(Path::new(&format!("/var/log/{TOKEN}.log")))
        .await;
    assert!(result.is_err());
    let log = serde_json::to_string(&run.action_log().actions)?;
    assert_no_token("action log", &log);
    assert!(log.contains("known_secret"), "{log}");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_value_of_a_declared_secret_env_name_joins_the_set_and_a_plain_name_does_not()
-> TestResult {
    let replay = Replay::new()
        .env("DB_PASSWORD", "env-pw-Zk3v9Qx7canary")
        .env("HOME_DIR", "/home/synthetic-user-dir")
        .file(
            LOG,
            "x env-pw-Zk3v9Qx7canary y /home/synthetic-user-dir z\n",
        );
    let run = run_with(replay);
    let ctx = run.context("host.synthetic", Os::Linux, []);
    assert_eq!(
        ctx.probe().env("DB_PASSWORD")?.as_deref(),
        Some("env-pw-Zk3v9Qx7canary")
    );
    assert_eq!(
        ctx.probe().env("HOME_DIR")?.as_deref(),
        Some("/home/synthetic-user-dir")
    );
    let file = ctx.probe().read(Path::new(LOG)).await?;
    let shown = ctx.probe().file_text(&file)?;
    assert!(!shown.contains("env-pw-Zk3v9Qx7canary"), "{}", *shown);
    assert!(shown.contains("/home/synthetic-user-dir"), "{}", *shown);
    Ok(())
}
