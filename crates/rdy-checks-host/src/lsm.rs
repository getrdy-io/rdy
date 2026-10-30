//! `host.lsm`: SELinux and AppArmor state, and recent SELinux denials.
//!
//! Linux only. Every source is a file, read through the probe: the mode files under `/sys`, the SELinux
//! config, the tail of the audit log and the AppArmor profile list. No command runs.
//!
//! Without a spec key the check only reports what it finds. With `selinux` it judges the mode and the
//! recent denials, with `apparmor` the state and the required profiles. The judgement is made from
//! facts gathered first, so the rules are plain functions of those facts.
//!
//! Three things the check does not claim:
//!
//! - Inside a container `/sys/fs/selinux` is often masked. A missing `enforce` file there says "not
//!   visible", never "disabled".
//! - Without root the audit log and the AppArmor profile list cannot be read. The result then carries
//!   `partial`, because the denials were not inspected, which is different from no denials.
//! - Denials kept only in the journal (a host without auditd) are not read in M1.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Need, Os, Partial,
};
use rdy_engine::probe::ProbeError;
use rdy_spec::check::{ApparmorMode, HostLsm, SelinuxMode};
use serde_json::{Value, json};

use crate::family::{OS, ROOT};
use crate::reads::{Read, read_text, short, soft};

mod apparmor;
mod audit;
mod selinux;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux security module files and has no data source on this OS yet";

const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
const SELINUX_DIR: &str = "/sys/fs/selinux";
const SELINUX_CONFIG: &str = "/etc/selinux/config";
const AUDIT_LOG: &str = "/var/log/audit/audit.log";
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Files a container runtime leaves in the container.
const CONTAINER_MARKERS: [&str; 2] = ["/.dockerenv", "/run/.containerenv"];
const APPARMOR_ENABLED: &str = "/sys/module/apparmor/parameters/enabled";
const APPARMOR_PROFILES: &str = "/sys/kernel/security/apparmor/profiles";

/// How much of the end of the audit log is read.
const AUDIT_TAIL: usize = 1 << 20;
/// The window when the spec gives none: 24 hours.
const DEFAULT_WINDOW_SECS: u64 = 24 * 60 * 60;
const DEFAULT_WINDOW_TEXT: &str = "24h";
/// The most denial groups, and the most names, listed in the evidence.
const SHOWN: usize = 5;

/// The static facts about `host.lsm` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.lsm",
    family: "host",
    summary: "SELinux and AppArmor state, recent denials",
    meta: CheckMeta {
        title: "SELinux and AppArmor",
        remediation: "On SELinux, read recent denials with `ausearch -m avc -ts recent`. Install the vendor's policy module, or label the volume with `chcon -Rt container_file_t` or the `:Z` mount option. As a last resort, run `setenforce 0` and set `SELINUX=permissive` in `/etc/selinux/config`. This turns SELinux protection off, so ask the security team first. On AppArmor, read denials with `journalctl -k` and ask the vendor for a profile.",
    },
    needs: &[],
    wants: ROOT,
    default_timeout: Some(std::time::Duration::from_secs(3)),
    os: OS,
    reads: &[
        SELINUX_DIR,
        SELINUX_CONFIG,
        AUDIT_LOG,
        MOUNTINFO,
        CONTAINER_MARKERS[0],
        CONTAINER_MARKERS[1],
        APPARMOR_ENABLED,
        APPARMOR_PROFILES,
    ],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// What the spec expects of SELinux, with the defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SelinuxRule {
    /// `None`: every mode is fine. `Some` of an empty list: no mode is fine.
    allow: Option<Vec<SelinuxMode>>,
    denials_max: usize,
    window_secs: u64,
    window_text: String,
    watch: Vec<String>,
    /// The spec set `denials_max`, `denials_window` or `watch`, so missing denial data is a warning.
    denials_asked: bool,
}

/// What the spec expects of AppArmor.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApparmorRule {
    /// `None`: either state is fine. `Some` of an empty list: no state is fine.
    allow: Option<Vec<ApparmorMode>>,
    require_profiles: Vec<String>,
}

/// `host.lsm`.
///
/// Built from the spec entry. With neither `selinux` nor `apparmor` it reports and passes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lsm {
    selinux: Option<SelinuxRule>,
    apparmor: Option<ApparmorRule>,
    /// Unix seconds. `None` reads the clock when the check runs.
    now: Option<u64>,
}

impl Lsm {
    /// A check for these parameters.
    #[must_use]
    pub fn new(params: &HostLsm) -> Self {
        let selinux = params.selinux.as_ref().map(|policy| SelinuxRule {
            allow: policy.allow.as_ref().map(|list| list.to_vec()),
            denials_max: policy
                .denials_max
                .map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX)),
            window_secs: policy
                .denials_window
                .as_ref()
                .map_or(DEFAULT_WINDOW_SECS, |d| d.as_millis() / 1000),
            window_text: policy
                .denials_window
                .as_ref()
                .map_or_else(|| DEFAULT_WINDOW_TEXT.to_owned(), |d| d.as_str().to_owned()),
            watch: policy
                .watch
                .iter()
                .flat_map(|list| list.iter())
                .map(|item| item.as_str().to_owned())
                .collect(),
            denials_asked: policy.denials_max.is_some()
                || policy.denials_window.is_some()
                || policy.watch.is_some(),
        });
        let apparmor = params.apparmor.as_ref().map(|policy| ApparmorRule {
            allow: policy.allow.as_ref().map(|list| list.to_vec()),
            require_profiles: policy
                .require_profiles
                .iter()
                .flat_map(|list| list.iter())
                .map(|item| item.as_str().to_owned())
                .collect(),
        });
        Self {
            selinux,
            apparmor,
            now: None,
        }
    }

    /// Fixes the time the denial window counts back from, in Unix seconds. Tests use it. A run reads
    /// the clock.
    #[must_use]
    pub fn at(mut self, unix_seconds: u64) -> Self {
        self.now = Some(unix_seconds);
        self
    }

    fn now(&self) -> u64 {
        self.now.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        })
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let root = ctx.has(&Need::Root);
        let selinux = selinux_facts(ctx, self.selinux.as_ref(), self.now()).await?;
        let apparmor = apparmor_facts(ctx, self.apparmor.as_ref()).await?;
        Ok(self.judge(&selinux, &apparmor, root))
    }
}

impl Check for Lsm {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

// ---- facts ---------------------------------------------------------------------------------------

/// What rdy could tell about the runtime SELinux mode.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SeState {
    /// `enforce` says so, or the kernel has no SELinux file system and nothing hides it.
    Mode(SelinuxMode),
    /// The path is masked or this is a container. The sentence says why.
    NotVisible(String),
    /// The state could not be read. The sentence says why.
    Unreadable(String),
}

/// What reading the audit log gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Denials {
    /// Not read: no SELinux rule in the spec, or SELinux is not active.
    NotWanted,
    Scanned {
        scan: audit::Scan,
        /// The tail does not reach back to the start of the window.
        truncated: bool,
        /// How far back the tail reaches, in seconds.
        reach: Option<u64>,
    },
    /// There is no audit log.
    NoLog,
    /// The audit log exists and cannot be read by this user.
    Forbidden,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelinuxFacts {
    state: SeState,
    configured: selinux::Configured,
    denials: Denials,
}

/// What rdy could tell about AppArmor.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AaState {
    On,
    Off,
    Unreadable(String),
}

/// What reading the profile list gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Loaded {
    /// Not read: no profile is required, or AppArmor is not on.
    NotWanted,
    Listed(apparmor::Profiles),
    /// The securityfs file is missing, as in a container.
    NotVisible,
    Forbidden,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApparmorFacts {
    state: AaState,
    loaded: Loaded,
}

async fn selinux_facts(
    ctx: &CheckContext,
    rule: Option<&SelinuxRule>,
    now: u64,
) -> Result<SelinuxFacts, CheckError> {
    let state = selinux_state(ctx).await?;
    let configured = match read_text(ctx, SELINUX_CONFIG).await? {
        Read::Text(text) => selinux::parse_config(&text),
        Read::Absent | Read::Unreadable(_) => selinux::Configured::Unset,
    };
    let active = matches!(
        state,
        SeState::Mode(SelinuxMode::Enforcing | SelinuxMode::Permissive)
    );
    let denials = match rule {
        Some(rule) if active => read_denials(ctx, rule, now).await?,
        _ => Denials::NotWanted,
    };
    Ok(SelinuxFacts {
        state,
        configured,
        denials,
    })
}

async fn selinux_state(ctx: &CheckContext) -> Result<SeState, CheckError> {
    match read_text(ctx, SELINUX_ENFORCE).await? {
        Read::Text(text) => Ok(match selinux::parse_enforce(&text) {
            Some(mode) => SeState::Mode(mode),
            None => SeState::Unreadable("the enforce file holds neither 0 nor 1".to_owned()),
        }),
        Read::Unreadable(why) => Ok(SeState::Unreadable(format!(
            "{SELINUX_ENFORCE} could not be read ({why})"
        ))),
        Read::Absent => absent_state(ctx).await,
    }
}

/// `enforce` is missing: SELinux is off in the kernel, or the path is hidden from this process.
async fn absent_state(ctx: &CheckContext) -> Result<SeState, CheckError> {
    if let Read::Text(text) = read_text(ctx, MOUNTINFO).await? {
        match selinux::selinux_mount(&text) {
            Some(selinux::Mount::Masked(fstype)) => {
                return Ok(SeState::NotVisible(format!(
                    "{SELINUX_DIR} is covered by a {fstype} mount, which is how a container runtime hides it"
                )));
            }
            Some(selinux::Mount::Selinuxfs) => {
                return Ok(SeState::Unreadable(format!(
                    "{SELINUX_DIR} is mounted but has no enforce file"
                )));
            }
            None => {}
        }
    }
    for marker in CONTAINER_MARKERS {
        match ctx.probe().stat(Path::new(marker)).await {
            Ok(Some(_)) => {
                return Ok(SeState::NotVisible(format!(
                    "this looks like a container ({marker} exists) and {SELINUX_DIR} has no enforce file"
                )));
            }
            Ok(None) => {}
            Err(error) => {
                soft(error)?;
            }
        }
    }
    Ok(SeState::Mode(SelinuxMode::Disabled))
}

async fn read_denials(
    ctx: &CheckContext,
    rule: &SelinuxRule,
    now: u64,
) -> Result<Denials, CheckError> {
    let probe = ctx.probe();
    let file = match probe.read_tail(Path::new(AUDIT_LOG), AUDIT_TAIL).await {
        Ok(file) => file,
        Err(error) => {
            return Ok(match soft(error)? {
                ProbeError::NotFound => Denials::NoLog,
                ProbeError::PermissionDenied => Denials::Forbidden,
                other => Denials::Failed(short(&other)),
            });
        }
    };
    // The text comes back redacted and without the partial first line of a cut tail.
    let text = probe.file_text(&file).map_err(CheckError::Probe)?;
    let cutoff = now.saturating_sub(rule.window_secs);
    let scan = audit::scan(&text, cutoff, &rule.watch);
    let truncated = file.truncated_head && scan.oldest.is_none_or(|oldest| oldest > cutoff);
    let reach = scan.oldest.map(|oldest| now.saturating_sub(oldest));
    Ok(Denials::Scanned {
        scan,
        truncated,
        reach,
    })
}

async fn apparmor_facts(
    ctx: &CheckContext,
    rule: Option<&ApparmorRule>,
) -> Result<ApparmorFacts, CheckError> {
    let state = match read_text(ctx, APPARMOR_ENABLED).await? {
        Read::Text(text) => match apparmor::parse_enabled(&text) {
            Some(true) => AaState::On,
            Some(false) => AaState::Off,
            None => AaState::Unreadable("the enabled file holds neither Y nor N".to_owned()),
        },
        // The module is not in the kernel.
        Read::Absent => AaState::Off,
        Read::Unreadable(why) => {
            AaState::Unreadable(format!("{APPARMOR_ENABLED} could not be read ({why})"))
        }
    };
    let wanted = rule.is_some_and(|r| !r.require_profiles.is_empty()) && state == AaState::On;
    let loaded = if wanted {
        match ctx.probe().read(Path::new(APPARMOR_PROFILES)).await {
            Ok(file) => {
                let text = ctx.probe().file_text(&file).map_err(CheckError::Probe)?;
                Loaded::Listed(apparmor::parse_profiles(&text))
            }
            Err(error) => match soft(error)? {
                ProbeError::NotFound => Loaded::NotVisible,
                ProbeError::PermissionDenied => Loaded::Forbidden,
                other => Loaded::Failed(short(&other)),
            },
        }
    } else {
        Loaded::NotWanted
    };
    Ok(ApparmorFacts { state, loaded })
}

// ---- judgement -----------------------------------------------------------------------------------

/// One thing the spec asked for and the machine does not give.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Problem {
    level: Level,
    text: String,
    fix: String,
}

/// What one module contributes to the finding.
#[derive(Debug, Default)]
struct Part {
    problems: Vec<Problem>,
    notes: Vec<String>,
    /// Why a part of the answer rests on less than wanted, when root would have helped.
    needs_root: Vec<String>,
    /// The module in one sentence, for a finding with no problem.
    summary: String,
    observed: Value,
    /// The module is judged and absent, which is enough for what the spec allows.
    absent_ok: bool,
    judged: bool,
}

impl Part {
    fn problem(&mut self, level: Level, text: impl Into<String>, fix: impl Into<String>) {
        self.problems.push(Problem {
            level,
            text: text.into(),
            fix: fix.into(),
        });
    }
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

fn se_word(mode: SelinuxMode) -> &'static str {
    match mode {
        SelinuxMode::Enforcing => "enforcing",
        SelinuxMode::Permissive => "permissive",
        SelinuxMode::Disabled => "disabled",
        _ => "unknown",
    }
}

fn aa_word(mode: ApparmorMode) -> &'static str {
    match mode {
        ApparmorMode::Enabled => "enabled",
        ApparmorMode::Disabled => "disabled",
        _ => "unknown",
    }
}

fn join_or(words: impl IntoIterator<Item = &'static str>) -> String {
    let words: Vec<&str> = words.into_iter().collect();
    match words.as_slice() {
        [] => "no mode".to_owned(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} or {last}", init.join(", ")),
    }
}

/// `5m`, `3h 20m` or `2d 4h`.
fn age(secs: u64) -> String {
    let (days, hours, minutes) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

impl Lsm {
    fn judge(&self, selinux: &SelinuxFacts, apparmor: &ApparmorFacts, root: bool) -> Finding {
        let se = self.judge_selinux(selinux, root);
        let aa = self.judge_apparmor(apparmor, root);

        let level = se
            .problems
            .iter()
            .chain(&aa.problems)
            .map(|p| p.level)
            .max_by_key(|l| rank(*l))
            .unwrap_or(Level::Pass);
        let judged_any = se.judged || aa.judged;
        let absent_only = judged_any
            && (!se.judged || se.absent_ok)
            && (!aa.judged || aa.absent_ok)
            && level == Level::Pass;

        let message = if level == Level::Pass {
            // A requirement met by absence names only what the spec asked about.
            let shown: Vec<&str> = [(&se, se.judged), (&aa, aa.judged)]
                .into_iter()
                .filter(|(_, judged)| *judged || !absent_only)
                .map(|(part, _)| part.summary.as_str())
                .collect();
            if absent_only {
                format!("{} The spec allows that.", shown.join(" "))
            } else {
                shown.join(" ")
            }
        } else {
            se.problems
                .iter()
                .chain(&aa.problems)
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };

        let mut finding = if absent_only {
            Finding::pass_by_absence(message)
        } else {
            Finding::new(level, message)
        };
        finding = finding
            .with_observed(json!({ "selinux": se.observed, "apparmor": aa.observed }))
            .with_expected(self.expected());
        for note in se.notes.iter().chain(&aa.notes) {
            finding = finding.with_note(note.clone());
        }
        if level != Level::Pass {
            let fixes: Vec<&str> = se
                .problems
                .iter()
                .chain(&aa.problems)
                .filter(|p| p.level != Level::Pass && !p.fix.is_empty())
                .map(|p| p.fix.as_str())
                .collect();
            if !fixes.is_empty() {
                finding = finding.with_fix(fixes.join(" "));
            }
        }
        let why: Vec<String> = se.needs_root.into_iter().chain(aa.needs_root).collect();
        if !why.is_empty() {
            finding = finding.with_partial(Partial::new(vec![Need::Root], why.join(" ")));
        }
        finding
    }

    fn expected(&self) -> Value {
        let mut out = serde_json::Map::new();
        if let Some(rule) = &self.selinux {
            out.insert(
                "selinux".to_owned(),
                json!({
                    "allow": rule.allow.as_ref().map(|a| a.iter().map(|m| se_word(*m)).collect::<Vec<_>>()),
                    "denials_max": rule.denials_max,
                    "denials_window": rule.window_text,
                    "watch": rule.watch,
                }),
            );
        }
        if let Some(rule) = &self.apparmor {
            out.insert(
                "apparmor".to_owned(),
                json!({
                    "allow": rule.allow.as_ref().map(|a| a.iter().map(|m| aa_word(*m)).collect::<Vec<_>>()),
                    "require_profiles": rule.require_profiles,
                }),
            );
        }
        Value::Object(out)
    }

    fn judge_selinux(&self, facts: &SelinuxFacts, root: bool) -> Part {
        let rule = self.selinux.as_ref();
        let mut part = Part {
            judged: rule.is_some(),
            ..Part::default()
        };
        let configured = match &facts.configured {
            selinux::Configured::Mode(mode) => json!(se_word(*mode)),
            selinux::Configured::Unset => Value::Null,
            selinux::Configured::Other(text) => json!(format!("unrecognized: {text}")),
        };
        part.observed = json!({ "configured": configured });

        match &facts.state {
            SeState::Mode(mode) => {
                part.summary = format!("SELinux is {}.", se_word(*mode));
                part.observed["state"] = json!(se_word(*mode));
                part.absent_ok = *mode == SelinuxMode::Disabled;
                if let Some(rule) = rule {
                    judge_mode(rule, *mode, &facts.configured, &mut part);
                }
                note_config_drift(*mode, &facts.configured, &mut part);
                if let Some(rule) = rule {
                    judge_denials(rule, *mode, &facts.denials, root, &mut part);
                }
            }
            SeState::NotVisible(why) => {
                part.summary = "SELinux is not visible from here.".to_owned();
                part.observed["state"] = json!("not visible");
                part.observed["why"] = json!(why);
                part.notes.push(format!("SELinux is not visible: {why}."));
                if rule.is_some_and(|r| r.allow.is_some()) {
                    part.problem(
                        Level::Warn,
                        "SELinux is not visible from here, so its mode cannot be checked.",
                        "Run rdy on the host, not inside a container, or run `getenforce` on the host.",
                    );
                }
            }
            SeState::Unreadable(why) => {
                part.summary = "The SELinux state could not be read.".to_owned();
                part.observed["state"] = json!("unreadable");
                part.observed["why"] = json!(why);
                part.notes
                    .push(format!("The SELinux state could not be read: {why}."));
                if rule.is_some_and(|r| r.allow.is_some()) {
                    part.problem(
                        Level::Warn,
                        "The SELinux mode could not be read, so it cannot be checked.",
                        "Run `getenforce` on the host to see the mode.",
                    );
                }
            }
        }
        part
    }

    fn judge_apparmor(&self, facts: &ApparmorFacts, root: bool) -> Part {
        let rule = self.apparmor.as_ref();
        let mut part = Part {
            judged: rule.is_some(),
            ..Part::default()
        };
        match &facts.state {
            AaState::On | AaState::Off => {
                let on = facts.state == AaState::On;
                let mode = if on {
                    ApparmorMode::Enabled
                } else {
                    ApparmorMode::Disabled
                };
                part.summary = format!("AppArmor is {}.", if on { "on" } else { "off" });
                part.observed = json!({ "state": aa_word(mode) });
                part.absent_ok = !on;
                if let Some(rule) = rule {
                    judge_apparmor_state(rule, mode, &mut part);
                    judge_profiles(rule, on, &facts.loaded, root, &mut part);
                }
            }
            AaState::Unreadable(why) => {
                part.summary = "The AppArmor state could not be read.".to_owned();
                part.observed = json!({ "state": "unreadable", "why": why });
                part.notes
                    .push(format!("The AppArmor state could not be read: {why}."));
                if rule.is_some() {
                    part.problem(
                        Level::Warn,
                        "The AppArmor state could not be read, so it cannot be checked.",
                        "Run `aa-status` on the host to see the state.",
                    );
                }
            }
        }
        part
    }
}

const SELINUX_LAST_RESORT: &str = "Last resort: run `setenforce 0` now and set `SELINUX=permissive` in `/etc/selinux/config`. This turns SELinux protection off, so ask the security team first.";

/// A runtime mode the spec does not allow, and a configured mode that will not be allowed after a reboot.
fn judge_mode(
    rule: &SelinuxRule,
    mode: SelinuxMode,
    configured: &selinux::Configured,
    part: &mut Part,
) {
    let Some(allow) = &rule.allow else {
        return;
    };
    let allowed = join_or(allow.iter().map(|m| se_word(*m)));
    if !allow.contains(&mode) {
        // An empty list is read as written: no mode is fine. Nothing on the machine can fix that, so
        // the sentence points at the spec.
        if allow.is_empty() {
            part.problem(
                Level::Fail,
                format!(
                    "SELinux is {}, but the spec's allow list is empty, so no mode is accepted. Ask the vendor to fix the spec.",
                    se_word(mode)
                ),
                "",
            );
            return;
        }
        let fix = match mode {
            SelinuxMode::Disabled => "Turn SELinux on: set `SELINUX=enforcing` in `/etc/selinux/config` and reboot. The first boot relabels the disk and can take minutes.".to_owned(),
            SelinuxMode::Permissive => "Run `setenforce 1`, and set `SELINUX=enforcing` in `/etc/selinux/config` so it stays.".to_owned(),
            _ => format!("The spec does not accept enforcing mode. Ask the vendor for a policy module before you change anything. {SELINUX_LAST_RESORT}"),
        };
        part.problem(
            Level::Fail,
            format!(
                "SELinux is {}, and the spec allows {allowed}.",
                se_word(mode)
            ),
            fix,
        );
        return;
    }
    if let selinux::Configured::Mode(next) = configured
        && !allow.contains(next)
    {
        part.problem(
            Level::Warn,
            format!(
                "SELinux is {} now, but /etc/selinux/config sets {}, which the spec does not allow after a reboot.",
                se_word(mode),
                se_word(*next)
            ),
            format!(
                "Set `SELINUX={}` in `/etc/selinux/config`.",
                se_word(mode)
            ),
        );
    }
}

/// The runtime mode differs from the configured one: say so, the next boot changes it.
fn note_config_drift(mode: SelinuxMode, configured: &selinux::Configured, part: &mut Part) {
    match configured {
        selinux::Configured::Mode(next) if *next != mode => part.notes.push(format!(
            "SELinux is {} now, and /etc/selinux/config sets {}. The next boot applies the configured mode.",
            se_word(mode),
            se_word(*next)
        )),
        selinux::Configured::Other(_) => part
            .notes
            .push("/etc/selinux/config has a SELINUX= value rdy does not know.".to_owned()),
        _ => {}
    }
}

fn ausearch_since(window_secs: u64) -> &'static str {
    if window_secs <= 24 * 3600 {
        "today"
    } else if window_secs <= 7 * 24 * 3600 {
        "this-week"
    } else {
        "this-month"
    }
}

fn judge_denials(
    rule: &SelinuxRule,
    mode: SelinuxMode,
    denials: &Denials,
    root: bool,
    part: &mut Part,
) {
    match denials {
        Denials::NotWanted => {}
        Denials::Scanned {
            scan,
            truncated,
            reach,
        } => {
            let groups: Vec<Value> = scan
                .groups
                .iter()
                .take(SHOWN)
                .map(|g| json!({ "source": g.source, "target": g.target, "class": g.class, "count": g.count }))
                .collect();
            part.observed["denials"] = json!({
                "inspected": true,
                "window": rule.window_text,
                "count": scan.total,
                "permissive": scan.permissive,
                "window_truncated": truncated,
                "groups": groups,
                "watched": scan.watched,
            });
            if *truncated {
                let reaches = reach.map_or_else(
                    || "no dated record".to_owned(),
                    |secs| format!("back {}", age(secs)),
                );
                part.notes.push(format!(
                    "Window truncated: the last 1 MiB of the audit log reaches {reaches}, not {}. Older denials were not read, and rotated logs such as audit.log.1 are not read.",
                    rule.window_text
                ));
            }
            if scan.permissive > 0 {
                part.notes.push(format!(
                    "{} of the denials were logged in permissive mode, so they were not blocked.",
                    scan.permissive
                ));
            }
            if scan.total > rule.denials_max {
                let level = if scan.watched_total > 0 {
                    Level::Fail
                } else {
                    Level::Warn
                };
                let who = denial_subjects(rule, scan);
                part.problem(
                    level,
                    format!(
                        "SELinux is {} and denied {} in the last {}{who}.",
                        se_word(mode),
                        plural(scan.total, "action", "actions"),
                        rule.window_text
                    ),
                    format!(
                        "Read them with `ausearch -m avc -ts {}`. Install the vendor policy module, or label the volume with `chcon -Rt container_file_t <volume path>` or the `:Z` mount option. {SELINUX_LAST_RESORT}",
                        ausearch_since(rule.window_secs)
                    ),
                );
            }
        }
        Denials::NoLog => {
            part.observed["denials"] = json!({ "inspected": false, "why": "no audit log" });
            part.notes.push(format!(
                "There is no {AUDIT_LOG}, so denials were not inspected. Denials kept only in the journal are not read."
            ));
            if rule.denials_asked {
                part.problem(
                    Level::Warn,
                    "SELinux denials were not inspected: there is no audit log.",
                    "Start auditd with `systemctl enable --now auditd`, or read the denials from the journal with `journalctl -k`.",
                );
            }
        }
        Denials::Forbidden if !root => {
            part.observed["denials"] = json!({ "inspected": false, "why": "needs root" });
            part.needs_root
                .push("SELinux denials were not inspected: the audit log needs root.".to_owned());
        }
        Denials::Forbidden => {
            part.observed["denials"] =
                json!({ "inspected": false, "why": "permission denied as root" });
            part.problem(
                Level::Warn,
                "SELinux denials were not inspected: the audit log could not be read as root (permission denied).",
                format!(
                    "Read the denials by hand with `ausearch -m avc -ts {}`.",
                    ausearch_since(rule.window_secs)
                ),
            );
        }
        Denials::Failed(why) => {
            part.observed["denials"] = json!({ "inspected": false, "why": why });
            part.problem(
                Level::Warn,
                format!(
                    "SELinux denials were not inspected: the audit log could not be read ({why})."
                ),
                format!(
                    "Read the denials by hand with `ausearch -m avc -ts {}`.",
                    ausearch_since(rule.window_secs)
                ),
            );
        }
    }
}

/// ` for acme_t` or ` for container_t, tmp_t`: the watched entries that matched, else the busiest sources.
fn denial_subjects(rule: &SelinuxRule, scan: &audit::Scan) -> String {
    let names: Vec<&str> = if scan.watched.is_empty() {
        let mut seen: Vec<&str> = Vec::new();
        for group in &scan.groups {
            if !seen.contains(&group.source.as_str()) {
                seen.push(group.source.as_str());
            }
        }
        seen.into_iter().take(3).collect()
    } else {
        rule.watch
            .iter()
            .filter(|w| scan.watched.contains_key(*w))
            .map(String::as_str)
            .take(3)
            .collect()
    };
    if names.is_empty() {
        String::new()
    } else {
        format!(" for {}", names.join(", "))
    }
}

fn judge_apparmor_state(rule: &ApparmorRule, mode: ApparmorMode, part: &mut Part) {
    let Some(allow) = &rule.allow else {
        return;
    };
    if allow.contains(&mode) {
        return;
    }
    let allowed = join_or(allow.iter().map(|m| aa_word(*m)));
    let text = if allow.is_empty() {
        format!(
            "AppArmor is {}, but the spec's allow list is empty, so no state is accepted. Ask the vendor to fix the spec.",
            aa_word(mode)
        )
    } else {
        format!(
            "AppArmor is {}, and the spec allows {allowed}.",
            aa_word(mode)
        )
    };
    let fix = if allow.is_empty() {
        String::new()
    } else if mode == ApparmorMode::Disabled {
        "Turn AppArmor on with `systemctl enable --now apparmor`. If the kernel has it off, add `apparmor=1 security=apparmor` to the kernel command line and reboot.".to_owned()
    } else {
        "The spec expects AppArmor to be off. Ask the vendor whether a profile exists before you change anything. To turn it off for a boot, add `apparmor=0` to the kernel command line.".to_owned()
    };
    part.problem(Level::Fail, text, fix);
}

fn judge_profiles(rule: &ApparmorRule, on: bool, loaded: &Loaded, root: bool, part: &mut Part) {
    if rule.require_profiles.is_empty() {
        return;
    }
    let required = json!(rule.require_profiles);
    if !on {
        part.observed["required_profiles"] = json!({ "required": required, "loaded": Value::Null });
        // The state problem, if the spec forbids off, is already reported. A profile cannot be loaded
        // while AppArmor is off, so say so once more only when the state itself was allowed.
        if rule
            .allow
            .as_ref()
            .is_none_or(|a| a.contains(&ApparmorMode::Disabled))
        {
            part.problem(
                Level::Fail,
                if rule.require_profiles.len() == 1 {
                    "AppArmor is off, so the required profile cannot be loaded.".to_owned()
                } else {
                    "AppArmor is off, so the required profiles cannot be loaded.".to_owned()
                },
                "Turn AppArmor on with `systemctl enable --now apparmor`, then load the vendor's profile with `apparmor_parser -r <profile file>`.",
            );
        }
        return;
    }
    match loaded {
        Loaded::NotWanted => {}
        Loaded::Listed(profiles) => {
            let missing: Vec<&String> = rule
                .require_profiles
                .iter()
                .filter(|p| !profiles.names.contains(*p))
                .collect();
            part.observed["profiles"] = json!({
                "loaded": profiles.names.len(),
                "enforce": profiles.enforce,
                "complain": profiles.complain,
            });
            part.observed["required_profiles"] = json!({
                "required": required,
                "missing": missing,
            });
            if !missing.is_empty() && profiles.cut {
                part.problem(
                    Level::Warn,
                    "The AppArmor profile list is longer than rdy reads, so a required profile may be loaded and not seen.",
                    "Run `aa-status` and check the required profiles by hand.",
                );
            } else if !missing.is_empty() {
                let names: Vec<&str> = missing.iter().take(SHOWN).map(|s| s.as_str()).collect();
                let more = missing.len().saturating_sub(SHOWN);
                let tail = if more > 0 {
                    format!(" and {more} more")
                } else {
                    String::new()
                };
                part.problem(
                    Level::Fail,
                    if missing.len() == 1 {
                        format!("The AppArmor profile {}{tail} is not loaded.", names.join(", "))
                    } else {
                        format!("The AppArmor profiles {}{tail} are not loaded.", names.join(", "))
                    },
                    "Ask the vendor for the profile, load it with `apparmor_parser -r <profile file>`, and check it with `aa-status`.",
                );
            }
        }
        Loaded::NotVisible => {
            part.observed["required_profiles"] =
                json!({ "required": required, "loaded": Value::Null });
            part.problem(
                Level::Warn,
                "The AppArmor profile list is not visible from here, so the required profiles cannot be checked.",
                "Run rdy on the host, not inside a container, or run `aa-status` on the host.",
            );
        }
        Loaded::Forbidden if !root => {
            part.observed["required_profiles"] =
                json!({ "required": required, "loaded": Value::Null });
            part.needs_root
                .push("The AppArmor profile list was not read: it needs root.".to_owned());
        }
        Loaded::Forbidden => {
            part.observed["required_profiles"] =
                json!({ "required": required, "loaded": Value::Null });
            part.problem(
                Level::Warn,
                "The AppArmor profile list could not be read as root (permission denied).",
                "Run `aa-status` on the host to see the loaded profiles.",
            );
        }
        Loaded::Failed(why) => {
            part.observed["required_profiles"] =
                json!({ "required": required, "loaded": Value::Null });
            part.problem(
                Level::Warn,
                format!("The AppArmor profile list could not be read ({why})."),
                "Run `aa-status` on the host to see the loaded profiles.",
            );
        }
    }
}
