//! The open files limit that services get: `DefaultLimitNOFILE` of systemd.
//!
//! The service manager reads `system.conf` (the first file found in `/etc/systemd`, `/run/systemd`,
//! `/usr/local/lib/systemd` and `/usr/lib/systemd`) and then the drop-ins of `system.conf.d`, which
//! follow the layering rule in `layers`. The last assignment of `DefaultLimitNOFILE=` in the
//! `[Manager]` section wins, and an empty one puts the built-in default back. The value is `N`,
//! `soft:hard` or `infinity`. The limit applies to services after `systemctl daemon-reexec`.
//!
//! rdy's own limit is read too, and labelled a shell limit: it says nothing about services.

use std::path::Path;

use rdy_engine::check::{CheckContext, CheckError, Level};
use rdy_engine::probe::{NativeCall, NativeValue, Resource};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{Compare, ValueRule};
use serde_json::{Value, json};

use super::layers::{Layer, read_first, read_layers};
use super::value::{Judged, judge_number, need_words, rule_text};
use super::{PERSIST_FILE, Problem};
use crate::text::{code, soft};

/// The main file, in the order systemd looks. Only the first one found is used.
pub(super) const MAIN: [&str; 4] = [
    "/etc/systemd/system.conf",
    "/run/systemd/system.conf",
    "/usr/local/lib/systemd/system.conf",
    "/usr/lib/systemd/system.conf",
];
/// The drop-in directories, highest priority first.
pub(super) const DROPIN_DIRS: [&str; 5] = [
    "/etc/systemd/system.conf.d",
    "/run/systemd/system.conf.d",
    "/usr/local/lib/systemd/system.conf.d",
    "/usr/lib/systemd/system.conf.d",
    "/lib/systemd/system.conf.d",
];
/// The most open files any process may have, a kernel setting.
pub(super) const NR_OPEN: &str = "/proc/sys/fs/nr_open";
/// The most open files the whole system may have.
pub(super) const FILE_MAX: &str = "/proc/sys/fs/file-max";

/// The soft limit systemd gives services when nothing sets one, at most. It is 1024 on systemd 240
/// and newer and 4096 or 1024 before. No version gives more.
const BUILT_IN_SOFT_MAX: i128 = 4096;
/// The least soft limit any systemd version gives services when nothing sets one.
const BUILT_IN_SOFT_MIN: i128 = 1024;

/// One side of a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Limit {
    /// A number of files.
    Count(u64),
    /// No limit below the kernel's `fs.nr_open`.
    Infinity,
}

impl Limit {
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.eq_ignore_ascii_case("infinity") {
            return Some(Self::Infinity);
        }
        let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        digits.then(|| text.parse().ok().map(Self::Count)).flatten()
    }

    fn to_json(self) -> Value {
        match self {
            Self::Count(n) => json!(n),
            Self::Infinity => json!("infinity"),
        }
    }
}

/// A parsed `DefaultLimitNOFILE` value: the soft limit services start with and the hard limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Nofile {
    pub soft: Limit,
    pub hard: Limit,
}

/// `1024`, `1024:524288`, `infinity` and `65536:infinity`.
pub(super) fn parse_nofile(text: &str) -> Option<Nofile> {
    let (soft, hard) = match text.split_once(':') {
        Some((soft, hard)) => (Limit::parse(soft)?, Limit::parse(hard)?),
        None => {
            let both = Limit::parse(text)?;
            (both, both)
        }
    };
    Some(Nofile { soft, hard })
}

/// The last `DefaultLimitNOFILE=` in the `[Manager]` section of `text`. `Some(None)` is an empty
/// assignment, which puts the built-in default back. `None` means the file does not mention it.
pub(super) fn assignment(text: &str) -> Option<Option<String>> {
    let mut section = "";
    let mut found = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name.trim();
        } else if section == "Manager"
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "DefaultLimitNOFILE"
        {
            let value = value.trim();
            found = Some((!value.is_empty()).then(|| value.to_owned()));
        }
    }
    found
}

/// Where `DefaultLimitNOFILE` is set, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Configured {
    /// The value as written.
    pub raw: String,
    /// The parsed value, `None` when rdy does not understand the text.
    pub value: Option<Nofile>,
    /// The file that sets it.
    pub file: String,
}

/// The effective assignment of the files, first to last.
pub(super) fn configured(files: &[Layer]) -> Option<Configured> {
    let mut current = None;
    for file in files {
        if let Some(found) = assignment(&file.text) {
            current = found.map(|raw| Configured {
                value: parse_nofile(&raw),
                raw,
                file: file.path.clone(),
            });
        }
    }
    current
}

/// What rdy read about the open files limit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Facts {
    pub configured: Option<Configured>,
    pub nr_open: Option<u64>,
    pub file_max: Option<u64>,
    /// rdy's own limits: soft and hard, `None` for unlimited.
    pub shell: Option<(Option<u64>, Option<u64>)>,
    /// Why the configuration may be incomplete.
    pub unknown: Vec<String>,
}

async fn kernel_number(ctx: &CheckContext, path: &str) -> Result<Option<u64>, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(String::from_utf8_lossy(&file.bytes).trim().parse().ok()),
        Err(error) => {
            soft(error)?;
            Ok(None)
        }
    }
}

/// Reads the configuration and the kernel ceilings.
///
/// # Errors
///
/// [`CheckError`] only for a refusal by rdy's own policy.
pub(super) async fn gather(ctx: &CheckContext) -> Result<Facts, CheckError> {
    let (main, mut unknown) = read_first(ctx, &MAIN).await?;
    let dropins = read_layers(ctx, &DROPIN_DIRS, ".conf", &[], false).await?;
    unknown.extend(dropins.unknown.iter().cloned());
    let files: Vec<Layer> = main.into_iter().chain(dropins.files).collect();
    let shell = match ctx
        .probe()
        .native(NativeCall::Rlimit(Resource::Nofile))
        .await
    {
        Ok(NativeValue::Rlimit(limit)) => Some((limit.soft, limit.hard)),
        Ok(_) => None,
        Err(error) => {
            soft(error)?;
            None
        }
    };
    Ok(Facts {
        configured: configured(&files),
        nr_open: kernel_number(ctx, NR_OPEN).await?,
        file_max: kernel_number(ctx, FILE_MAX).await?,
        shell,
        unknown,
    })
}

/// What the open files limit comes to.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Judgement {
    /// What is wrong, if anything.
    pub problem: Option<Problem>,
    /// The limit in a sentence, for a result with no problem.
    pub summary: String,
    /// The evidence.
    pub observed: Value,
    pub notes: Vec<String>,
    /// Set when the answer rests on less than was wanted.
    pub unverified: Option<String>,
}

fn limit_json(limit: Option<Limit>) -> Value {
    limit.map_or(Value::Null, Limit::to_json)
}

fn problem(level: Level, text: String, fix: Option<String>) -> Option<Problem> {
    Some(Problem {
        level,
        text,
        fix,
        apply: false,
    })
}

/// The fix for a limit that is too low: where to set `DefaultLimitNOFILE=`, and that it needs
/// `daemon-reexec`. The unit file is the other way, and often the better one.
fn set_limit_fix(want: i128) -> String {
    format!(
        "Set `LimitNOFILE={want}` in the service unit, or for every service set `DefaultLimitNOFILE={want}` under `[Manager]` in a file in `/etc/systemd/system.conf.d/` and run `systemctl daemon-reexec`."
    )
}

/// Judges the limit against the spec's rule.
pub(super) fn judge(rule: &ValueRule, facts: &Facts) -> Judgement {
    let want = rule.integer().map(i128::from);
    let shown = need_words(rule);
    let mut notes = Vec::new();
    if let Some((soft, hard)) = facts.shell {
        let word =
            |limit: Option<u64>| limit.map_or_else(|| "unlimited".to_owned(), |n| n.to_string());
        notes.push(format!(
            "rdy's own open files limit is {} (soft) and {} (hard). That is a shell limit and does not apply to services.",
            word(soft),
            word(hard)
        ));
    }
    let mut observed = json!({
        "default_limit_nofile": facts.configured.as_ref().map(|c| escape_untrusted(&c.raw)),
        "file": facts.configured.as_ref().map(|c| escape_untrusted(&c.file)),
        "nr_open": facts.nr_open,
        "file_max": facts.file_max,
        "shell_limit": facts.shell.map(|(soft, hard)| json!({ "soft": soft, "hard": hard })),
    });
    let done =
        |problem: Option<Problem>, summary: String, unverified: Option<String>, obs: Value| {
            Judgement {
                problem,
                summary,
                observed: obs,
                notes: notes.clone(),
                unverified,
            }
        };

    let (Some(want), true) = (
        want,
        matches!(
            rule.compare,
            Compare::Equal | Compare::AtLeast | Compare::AtMost
        ),
    ) else {
        let text = format!(
            "The spec asks for the open files limit to be {}, which is not a whole number, so it cannot be checked.",
            code(&rule_text(rule))
        );
        return done(
            problem(Level::Warn, text, None),
            String::new(),
            Some("the limit in the spec is not a whole number".to_owned()),
            observed,
        );
    };

    // A limit above the kernel's ceiling cannot be set by anyone.
    if matches!(rule.compare, Compare::Equal | Compare::AtLeast)
        && let Some(ceiling) = facts.nr_open.filter(|n| i128::from(*n) < want)
    {
        let text = format!("`fs.nr_open` is {ceiling}, so no service can have {want} open files.");
        let fix = format!(
            "Raise the ceiling first: `echo 'fs.nr_open = {want}' | sudo tee -a {PERSIST_FILE}`, then run `sysctl --system`. Then set the limit for the service."
        );
        return done(
            problem(Level::Fail, text, Some(fix)),
            String::new(),
            None,
            observed,
        );
    }

    let Some(configured) = &facts.configured else {
        if let Some(why) = facts.unknown.first() {
            let text =
                format!("The open files limit could not be read ({why}), so it is not verified.");
            return done(
                problem(Level::Warn, text, None),
                String::new(),
                Some(why.clone()),
                observed,
            );
        }
        // Nothing sets it, so systemd's built-in default applies. rdy cannot read that default, but
        // no version gives services more than 4096 or less than 1024.
        let verdict = match rule.compare {
            Compare::AtLeast if want <= BUILT_IN_SOFT_MIN => Judged::Met,
            Compare::AtLeast if want > BUILT_IN_SOFT_MAX => Judged::Unmet,
            Compare::Equal if !(BUILT_IN_SOFT_MIN..=BUILT_IN_SOFT_MAX).contains(&want) => {
                Judged::Unmet
            }
            Compare::AtMost if want >= BUILT_IN_SOFT_MAX => Judged::Met,
            Compare::AtMost if want < BUILT_IN_SOFT_MIN => Judged::Unmet,
            _ => Judged::NotNumber,
        };
        observed["source"] = json!("built-in default");
        return match verdict {
            Judged::Met => done(
                None,
                "Services get systemd's built-in open files limit, which meets the spec."
                    .to_owned(),
                None,
                observed,
            ),
            Judged::Unmet => {
                let text = format!(
                    "No file sets `DefaultLimitNOFILE`, so services get systemd's built-in open files limit (1024 on systemd 240 and newer, never more than 4096), need {shown}."
                );
                done(
                    problem(Level::Fail, text, Some(set_limit_fix(want))),
                    String::new(),
                    None,
                    observed,
                )
            }
            Judged::NotNumber => {
                let text = format!(
                    "No file sets `DefaultLimitNOFILE`, so services get systemd's built-in open files limit, which rdy cannot read. It is not verified against {shown}."
                );
                done(
                    problem(Level::Warn, text, Some(set_limit_fix(want))),
                    String::new(),
                    Some("systemd's built-in limit cannot be read".to_owned()),
                    observed,
                )
            }
        };
    };

    let Some(parsed) = configured.value else {
        let text = format!(
            "`DefaultLimitNOFILE` is {} in {}, a value rdy does not understand, so the limit is not verified.",
            code(&configured.raw),
            code(&configured.file)
        );
        return done(
            problem(Level::Warn, text, None),
            String::new(),
            Some("DefaultLimitNOFILE is in a form rdy does not read".to_owned()),
            observed,
        );
    };
    observed["soft"] = limit_json(Some(parsed.soft));
    observed["hard"] = limit_json(Some(parsed.hard));
    // `infinity` means the kernel ceiling.
    let soft_count = match parsed.soft {
        Limit::Count(n) => i128::from(n),
        Limit::Infinity => i128::from(facts.nr_open.unwrap_or(u64::MAX)),
    };
    match judge_number(rule.compare, want, soft_count) {
        Judged::Met => done(
            None,
            format!(
                "Services get an open files limit of {} ({} in {}).",
                match parsed.soft {
                    Limit::Count(n) => n.to_string(),
                    Limit::Infinity => "infinity".to_owned(),
                },
                code(&format!("DefaultLimitNOFILE={}", configured.raw)),
                code(&configured.file)
            ),
            None,
            observed,
        ),
        _ => {
            let text = format!(
                "{} in {} gives services an open files limit of {}, need {shown}.",
                code(&format!("DefaultLimitNOFILE={}", configured.raw)),
                code(&configured.file),
                soft_count
            );
            done(
                problem(Level::Fail, text, Some(set_limit_fix(want))),
                String::new(),
                None,
                observed,
            )
        }
    }
}
