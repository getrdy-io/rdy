//! `host.sysctl`: kernel parameters and file limits against the spec, and whether a live value survives
//! a reboot.
//!
//! Linux only. Every source is a file, read through the probe. No command runs and no privilege is
//! needed, because `/proc/sys` files and the configuration directories are world readable. A few
//! parameters are not (`0200` and `0600` files); those give a warning with `partial`, never a block.
//!
//! - **Live value.** `/proc/sys/<name with slashes>`. A value that differs blocks. A parameter that
//!   does not exist blocks, with the module that usually provides it (`br_netfilter` for
//!   `net.bridge.*`).
//! - **Persisted value.** The files of `sysctl.d` and then `/etc/sysctl.conf`, in the order the boot
//!   applies them (see `layers`). A right live value that no file sets warns "not persisted". One that a
//!   later file sets to another value warns too: a reboot changes it. A file hidden by a same-named file
//!   in a higher directory is named, because that is how a customer's `/etc/sysctl.d/99-x.conf` loses a
//!   vendor's line without a sound.
//! - **Limits.** `limits.nofile` is `DefaultLimitNOFILE` of systemd, the limit services get (see
//!   `limits`). rdy's own limit is shown and labelled a shell limit.
//!
//! A value from the spec goes into a command that a customer may copy only when it is made of plain
//! characters. Anything else is described, never pasted.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Os, Partial,
};
use rdy_engine::probe::ProbeError;
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::{HostSysctl, ValueRule};
use serde_json::{Map, Value, json};

use crate::family::OS;
use crate::text::{code, short, soft};

mod layers;
mod limits;
mod persist;
mod value;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use persist::{Persisted, Setting};
use value::{Judged, clip, is_quotable, need_words, normalise, rule_text};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux kernel parameter files and has no data source on this OS yet";

const PROC_SYS: &str = "/proc/sys";
/// The file the fix text asks a customer to add a line to. It sorts after almost every other name.
pub(super) const PERSIST_FILE: &str = "/etc/sysctl.d/99-rdy.conf";
/// The most characters of a live value in a sentence.
const SHOWN_VALUE: usize = 128;
/// The most characters of a live value in the evidence.
const KEPT_VALUE: usize = 256;
/// The most problems named in the message and the fix. The evidence holds all of them.
const SHOWN_PROBLEMS: usize = 3;

/// The static facts about `host.sysctl` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.sysctl",
    family: "host",
    summary: "Kernel parameters and limits",
    meta: CheckMeta {
        title: "Kernel parameters and limits",
        remediation: "Set the value now with `sysctl -w vm.max_map_count=262144`, using the parameter and value from the result. Then persist it in a file under `/etc/sysctl.d/` and run `sysctl --system`. `sysctl -p` does not read `sysctl.d`. For file limits, set `LimitNOFILE=` in the service unit.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(2)),
    os: OS,
    reads: &[
        PROC_SYS,
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
        "/lib/sysctl.d",
        "/etc/sysctl.conf",
        "/etc/systemd/system.conf",
        "/run/systemd/system.conf",
        "/usr/local/lib/systemd/system.conf",
        "/usr/lib/systemd/system.conf",
        "/etc/systemd/system.conf.d",
        "/run/systemd/system.conf.d",
        "/usr/local/lib/systemd/system.conf.d",
        "/usr/lib/systemd/system.conf.d",
        "/lib/systemd/system.conf.d",
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// One thing wrong, or not verified.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Problem {
    pub level: Level,
    /// One sentence.
    pub text: String,
    /// What to do about it. It does not include the closing "run `sysctl --system`".
    pub fix: Option<String>,
    /// The fix ends with applying the `sysctl.d` files, so the closing sentence is added once.
    pub apply: bool,
}

/// A parameter the spec asks about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Wanted {
    /// The name as the spec writes it.
    name: String,
    /// The path under `/proc/sys`, with slashes.
    canonical: String,
    rule: ValueRule,
}

/// `host.sysctl`.
///
/// Built from the spec entry. The spec holds at least one of `expect` and `limits`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sysctl {
    expect: Vec<Wanted>,
    nofile: Option<ValueRule>,
}

impl Sysctl {
    /// A check for these parameters.
    #[must_use]
    pub fn new(params: &HostSysctl) -> Self {
        let expect = params
            .expect
            .iter()
            .flat_map(|map| map.iter())
            .map(|(name, rule)| Wanted {
                name: name.as_str().to_owned(),
                canonical: name.canonical(),
                rule: rule.clone(),
            })
            .collect();
        let nofile = params
            .limits
            .as_ref()
            .and_then(|limits| limits.nofile.clone());
        Self { expect, nofile }
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let mut live = Vec::with_capacity(self.expect.len());
        for wanted in &self.expect {
            live.push(read_live(ctx, &wanted.canonical).await?);
        }
        // Boot-time files matter only when there is a live value to compare them with.
        let persisted = if live.iter().any(|l| matches!(l, Live::Value(_))) {
            let keys: BTreeSet<String> = self.expect.iter().map(|w| w.canonical.clone()).collect();
            Some(persist::gather(ctx, &keys).await?)
        } else {
            None
        };
        let limit = match &self.nofile {
            Some(rule) => Some(limits::judge(rule, &limits::gather(ctx).await?)),
            None => None,
        };
        Ok(self.judge(&live, persisted.as_ref(), limit))
    }
}

impl Check for Sysctl {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

// ---- facts ---------------------------------------------------------------------------------------

/// What `/proc/sys` said about one parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Live {
    /// The value, with white space runs made one space.
    Value(String),
    /// The kernel has no such parameter.
    Missing,
    /// The name is a directory of parameters, not one value.
    Group,
    /// The file could not be read. The reason is short.
    Unreadable(String),
}

async fn read_live(ctx: &CheckContext, canonical: &str) -> Result<Live, CheckError> {
    let path = format!("{PROC_SYS}/{canonical}");
    match ctx.probe().read(Path::new(&path)).await {
        Ok(file) => Ok(Live::Value(normalise(&String::from_utf8_lossy(
            &file.bytes,
        )))),
        // Nothing under `/proc/sys` is on the deny list, so the one refusal left is "not a regular
        // file": a directory of parameters.
        Err(ProbeError::Denied { .. }) => Ok(Live::Group),
        Err(error) => Ok(match soft(error)? {
            ProbeError::NotFound => Live::Missing,
            ProbeError::PermissionDenied => Live::Unreadable("permission denied".to_owned()),
            other => Live::Unreadable(short(&other)),
        }),
    }
}

/// What the boot-time files say about one parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Saved {
    Set(Setting),
    Unset,
    /// Some file or directory could not be read, so "unset" would be a guess.
    Unknown(String),
}

// ---- judgement -----------------------------------------------------------------------------------

/// The verdict on one parameter.
struct Row {
    problem: Option<Problem>,
    /// Set when the verdict rests on something rdy could not read.
    unverified: Option<String>,
    observed: Value,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

/// `Persist `name` with `echo ...`.`, or a description when the value is not plain.
fn persist_step(name: &str, rule: &ValueRule) -> String {
    let value = normalise(&rule.value);
    if is_quotable(&value) {
        format!("Persist `{name}` with `echo '{name} = {value}' | sudo tee -a {PERSIST_FILE}`.")
    } else {
        format!(
            "Persist `{name}`: set it to the value the spec asks for in a file under `/etc/sysctl.d/`."
        )
    }
}

/// `Change the line in FILE to `name = value`.`
fn change_step(name: &str, rule: &ValueRule, file: &str) -> String {
    let value = normalise(&rule.value);
    if is_quotable(&value) {
        format!(
            "Change the line for `{name}` in {} to `{name} = {value}`.",
            code(file)
        )
    } else {
        format!(
            "Change the line for `{name}` in {} to the value the spec asks for.",
            code(file)
        )
    }
}

impl Sysctl {
    fn judge_row(
        &self,
        wanted: &Wanted,
        live: &Live,
        saved: &Saved,
        persisted: Option<&Persisted>,
    ) -> Row {
        let name = &wanted.name;
        let need = need_words(&wanted.rule);
        let mut observed = json!({
            "live": Value::Null,
            "persisted": match saved {
                Saved::Set(s) => json!({
                    "value": escape_untrusted(&clip(&s.value, KEPT_VALUE)),
                    "file": escape_untrusted(&s.file),
                }),
                _ => Value::Null,
            },
        });
        let row = |state: &'static str,
                   problem: Option<Problem>,
                   unverified: Option<String>,
                   observed: Value| Row {
            problem,
            unverified,
            observed: with_state(observed, state),
        };
        match live {
            Live::Missing => {
                let fix = missing_fix(name);
                row(
                    "missing",
                    Some(Problem {
                        level: Level::Fail,
                        text: format!("`{name}` does not exist on this machine."),
                        fix: Some(fix),
                        apply: false,
                    }),
                    None,
                    observed,
                )
            }
            Live::Group => row(
                "not_a_value",
                Some(Problem {
                    level: Level::Warn,
                    text: format!(
                        "`{name}` is a group of parameters, not one value, so it is not verified."
                    ),
                    fix: None,
                    apply: false,
                }),
                Some(format!("{name} is not a single parameter")),
                observed,
            ),
            Live::Unreadable(why) => row(
                "unreadable",
                Some(Problem {
                    level: Level::Warn,
                    text: format!("`{name}` could not be read ({why}), so it is not verified."),
                    fix: Some(format!(
                        "Run rdy as root, or read it by hand with `sysctl -n {name}`."
                    )),
                    apply: false,
                }),
                Some(format!("{name} could not be read ({why})")),
                observed,
            ),
            Live::Value(have) => {
                observed["live"] = json!(escape_untrusted(&clip(have, KEPT_VALUE)));
                let shown = code(&clip(have, SHOWN_VALUE));
                match value::judge(&wanted.rule, have) {
                    Judged::NotNumber => row(
                        "not_a_number",
                        Some(Problem {
                            level: Level::Warn,
                            text: format!(
                                "`{name}` is {shown}, which is not a whole number, so the spec's {} cannot be checked.",
                                code(&rule_text(&wanted.rule))
                            ),
                            fix: None,
                            apply: false,
                        }),
                        Some(format!("{name} is not a whole number")),
                        observed,
                    ),
                    Judged::Unmet => {
                        let (extra, fix, apply) = match saved {
                            Saved::Set(s) if value::judge(&wanted.rule, &s.value) == Judged::Met => (
                                format!(" {} already sets it to {}, but the running value differs.", code(&s.file), code(&clip(&s.value, SHOWN_VALUE))),
                                format!("{} already sets `{name}`.", code(&s.file)),
                                true,
                            ),
                            Saved::Set(s) => (
                                format!(" {} sets it to {}, which is also wrong.", code(&s.file), code(&clip(&s.value, SHOWN_VALUE))),
                                change_step(name, &wanted.rule, &s.file),
                                true,
                            ),
                            _ => (String::new(), persist_step(name, &wanted.rule), true),
                        };
                        row(
                            "wrong_value",
                            Some(Problem {
                                level: Level::Fail,
                                text: format!("`{name}` is {shown}, need {need}.{extra}"),
                                fix: Some(fix),
                                apply,
                            }),
                            None,
                            observed,
                        )
                    }
                    Judged::Met => match saved {
                        Saved::Set(s) if value::judge(&wanted.rule, &s.value) != Judged::Met => row(
                            "persisted_wrong",
                            Some(Problem {
                                level: Level::Warn,
                                text: format!(
                                    "`{name}` is {shown}, as needed, but {} sets it to {} at boot, so a reboot changes it.",
                                    code(&s.file),
                                    code(&clip(&s.value, SHOWN_VALUE))
                                ),
                                fix: Some(change_step(name, &wanted.rule, &s.file)),
                                apply: true,
                            }),
                            None,
                            observed,
                        ),
                        Saved::Set(_) => row("ok", None, None, observed),
                        Saved::Unset => {
                            let lost = persisted
                                .and_then(|p| p.hidden.get(&wanted.canonical))
                                .map(|h| {
                                    format!(
                                        " {} sets it, but {} has the same name and takes its place.",
                                        code(&h.setting.file),
                                        code(&h.by)
                                    )
                                })
                                .unwrap_or_default();
                            row(
                                "not_persisted",
                                Some(Problem {
                                    level: Level::Warn,
                                    text: format!(
                                        "`{name}` is {shown}, as needed, but it is not persisted: no file in a `sysctl.d` directory sets it, so a reboot loses it.{lost}"
                                    ),
                                    fix: Some(persist_step(name, &wanted.rule)),
                                    apply: true,
                                }),
                                None,
                                observed,
                            )
                        }
                        Saved::Unknown(why) => row(
                            "persist_unknown",
                            Some(Problem {
                                level: Level::Warn,
                                text: format!(
                                    "`{name}` is {shown}, as needed, but whether it survives a reboot is not verified: {why}."
                                ),
                                fix: Some(
                                    "Run rdy as root, or read the files under `/etc/sysctl.d/` by hand."
                                        .to_owned(),
                                ),
                                apply: false,
                            }),
                            Some(why.clone()),
                            observed,
                        ),
                    },
                }
            }
        }
    }

    fn judge(
        &self,
        live: &[Live],
        persisted: Option<&Persisted>,
        limit: Option<limits::Judgement>,
    ) -> Finding {
        let mut rows: Vec<(&Wanted, Row)> = Vec::new();
        for (wanted, live) in self.expect.iter().zip(live) {
            let saved = match persisted {
                None => Saved::Unset,
                Some(p) => match p.settings.get(&wanted.canonical) {
                    Some(setting) => Saved::Set(setting.clone()),
                    None => p
                        .unknown
                        .first()
                        .map_or(Saved::Unset, |why| Saved::Unknown(why.clone())),
                },
            };
            rows.push((wanted, self.judge_row(wanted, live, &saved, persisted)));
        }

        let mut problems: Vec<&Problem> = rows
            .iter()
            .filter_map(|(_, r)| r.problem.as_ref())
            .collect();
        if let Some(p) = limit.as_ref().and_then(|l| l.problem.as_ref()) {
            problems.push(p);
        }
        // Blocks first, and the order of the spec inside a level.
        problems.sort_by_key(|p| std::cmp::Reverse(rank(p.level)));
        let level = problems
            .iter()
            .map(|p| p.level)
            .max_by_key(|l| rank(*l))
            .unwrap_or(Level::Pass);

        let message = if problems.is_empty() {
            let mut parts = Vec::new();
            if !rows.is_empty() {
                let n = rows.len();
                parts.push(format!(
                    "{n} kernel parameter{} {} the wanted value and {} set at boot.",
                    if n == 1 { "" } else { "s" },
                    if n == 1 { "has" } else { "have" },
                    if n == 1 { "is" } else { "are" },
                ));
            }
            if let Some(limit) = &limit {
                parts.push(limit.summary.clone());
            }
            parts.join(" ")
        } else {
            let mut text: Vec<String> = problems
                .iter()
                .take(SHOWN_PROBLEMS)
                .map(|p| p.text.clone())
                .collect();
            if problems.len() > SHOWN_PROBLEMS {
                text.push(format!(
                    "{} more are in the evidence.",
                    problems.len() - SHOWN_PROBLEMS
                ));
            }
            text.join(" ")
        };

        let mut parameters = Map::new();
        let mut expected = Map::new();
        for (wanted, row) in &rows {
            parameters.insert(wanted.name.clone(), row.observed.clone());
            expected.insert(wanted.name.clone(), json!(rule_text(&wanted.rule)));
        }
        let mut observed = Map::new();
        let mut expected_all = Map::new();
        if !rows.is_empty() {
            observed.insert("parameters".to_owned(), Value::Object(parameters));
            expected_all.insert("parameters".to_owned(), Value::Object(expected));
        }
        if let (Some(rule), Some(limit)) = (&self.nofile, &limit) {
            observed.insert("limits".to_owned(), json!({ "nofile": limit.observed }));
            expected_all.insert("limits".to_owned(), json!({ "nofile": rule_text(rule) }));
        }

        let mut finding = Finding::new(level, message)
            .with_observed(Value::Object(observed))
            .with_expected(Value::Object(expected_all));
        let sysctl_conf_decides = rows.iter().any(|(wanted, _)| {
            persisted
                .and_then(|p| p.settings.get(&wanted.canonical))
                .is_some_and(|setting| setting.file == persist::SYSCTL_CONF)
        });
        for note in notes(
            persisted,
            limit.as_ref(),
            !rows.is_empty(),
            sysctl_conf_decides,
        ) {
            finding = finding.with_note(note);
        }
        if level != Level::Pass
            && let Some(fix) = fix_text(&problems)
        {
            finding = finding.with_fix(fix);
        }
        let mut unverified: Vec<String> = rows
            .iter()
            .filter_map(|(_, r)| r.unverified.clone())
            .collect();
        unverified.extend(limit.and_then(|l| l.unverified));
        if !unverified.is_empty() {
            finding = finding.with_partial(Partial::new(
                Vec::new(),
                format!("Not verified: {}.", unverified.join("; ")),
            ));
        }
        finding
    }
}

/// Adds the state word to the evidence of one parameter.
fn with_state(mut observed: Value, state: &str) -> Value {
    observed["state"] = json!(state);
    observed
}

/// What to do about a parameter the kernel does not have. Some come from a module.
fn missing_fix(name: &str) -> String {
    let module = if name.starts_with("net.bridge.") || name.starts_with("net/bridge/") {
        Some("br_netfilter")
    } else if name.starts_with("net.netfilter.") || name.starts_with("net/netfilter/") {
        Some("nf_conntrack")
    } else {
        None
    };
    match module {
        Some(module) => format!(
            "The `{module}` module provides it. Load it with `modprobe {module}`, and at every boot with `echo {module} | sudo tee /etc/modules-load.d/{module}.conf`."
        ),
        None => "Check the name against the vendor's documentation. If a kernel module provides it, load the module with `modprobe` and add it to `/etc/modules-load.d/`.".to_owned(),
    }
}

/// The fix of the first few problems, then the closing step once.
fn fix_text(problems: &[&Problem]) -> Option<String> {
    let mut parts: Vec<String> = problems
        .iter()
        .filter(|p| p.level != Level::Pass)
        .filter_map(|p| p.fix.clone())
        .take(SHOWN_PROBLEMS)
        .collect();
    if parts.is_empty() {
        return None;
    }
    let more = problems.len().saturating_sub(SHOWN_PROBLEMS);
    if more > 0 {
        parts.push(format!("Do the same for the other {more}."));
    }
    if problems.iter().any(|p| p.apply) {
        parts.push(
            "Then run `sysctl --system` to apply the files. `sysctl -p` does not read `sysctl.d`."
                .to_owned(),
        );
    }
    Some(parts.join(" "))
}

/// The lines for the report that are not about one parameter.
fn notes(
    persisted: Option<&Persisted>,
    limit: Option<&limits::Judgement>,
    any_rows: bool,
    sysctl_conf_decides: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(p) = persisted {
        if any_rows {
            out.push(format!(
                "Read {} sysctl configuration file(s), in boot order.",
                p.applied
            ));
        }
        if sysctl_conf_decides {
            out.push(
                "`/etc/sysctl.conf` is read by `sysctl --system`. The boot service, systemd-sysctl, reads it only when a file in a sysctl.d directory links to it, so put the setting in `/etc/sysctl.d/` to be sure."
                    .to_owned(),
            );
        }
        for path in p.null_masks.iter().take(SHOWN_PROBLEMS) {
            out.push(format!(
                "{} is a link to /dev/null: it hides the file of the same name below it and sets nothing.",
                code(path)
            ));
        }
        for why in p.unknown.iter().take(SHOWN_PROBLEMS) {
            out.push(format!("Not read: {}.", clip(why, 200)));
        }
        if p.settings.skipped_globs > 0 {
            out.push(format!(
                "{} wildcard line(s) in the sysctl.d files were not read (character classes, or too many).",
                p.settings.skipped_globs
            ));
        }
    }
    if let Some(limit) = limit {
        out.extend(limit.notes.iter().cloned());
    }
    out
}
