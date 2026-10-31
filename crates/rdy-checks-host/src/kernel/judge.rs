//! The judgement of `host.kernel`: a pure function of what was read and what the spec wants.
//!
//! Levels (03 section 2). A kernel below the minimum, a module that is not loaded, not built in and not
//! installed, and a missing BTF block. A module that is installed but not loaded warns. Whatever could
//! not be read warns and says what: "cannot tell" never blocks.

use std::collections::BTreeSet;

use rdy_engine::check::{Finding, Level};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::KernelVersion;
use serde_json::{Map, Value, json};

use super::modules::{Dep, normalize};
use super::version::{self, Release, Standing};
use crate::os::release::Release as OsRelease;
use crate::text::code;

/// The most names listed in one sentence.
const SHOWN: usize = 8;

/// What the spec asks of the kernel.
#[derive(Debug, Clone, Default)]
pub(super) struct Rules {
    /// `min`.
    pub(super) min: Option<KernelVersion>,
    /// `distro_min`: the `/etc/os-release` id and the minimum that replaces `min` on it.
    pub(super) distro_min: Vec<(String, KernelVersion)>,
    /// `modules`, as written.
    pub(super) modules: Vec<String>,
    /// `btf: true`.
    pub(super) btf: bool,
}

impl Rules {
    pub(super) fn wants_version(&self) -> bool {
        self.min.is_some() || !self.distro_min.is_empty()
    }
}

/// What reading one source gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Got<T> {
    Value(T),
    /// The file does not exist.
    Absent,
    /// The source could not be read. The text says why.
    Failed(String),
}

impl<T> Got<T> {
    pub(super) fn value(&self) -> Option<&T> {
        match self {
            Self::Value(v) => Some(v),
            Self::Absent | Self::Failed(_) => None,
        }
    }
}

/// What was read about the modules, only for the names the spec lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Modules {
    /// The directory the module files were looked for in, such as `/lib/modules/5.14.0-362.el9.x86_64`.
    pub(super) dir: String,
    /// `false` when the kernel release has characters rdy does not put in a path, so nothing was read there.
    pub(super) path_safe: bool,
    /// `/proc/modules`.
    pub(super) loaded: Got<BTreeSet<String>>,
    /// `modules.builtin`.
    pub(super) builtin: Got<BTreeSet<String>>,
    /// `modules.dep`.
    pub(super) dep: Got<Dep>,
}

/// Everything read from the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Facts {
    /// The running kernel's release string.
    pub(super) release: Got<String>,
    /// `os-release`: the id picks the `distro_min` entry, and the family picks the fix text.
    pub(super) distro: Got<OsRelease>,
    /// Read only when the spec lists modules.
    pub(super) modules: Option<Modules>,
    /// Whether `/sys/kernel/btf/vmlinux` exists. Read only when the spec asks for BTF.
    pub(super) btf: Option<Got<bool>>,
}

/// One module's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum State {
    Loaded,
    BuiltIn,
    /// Installed for this kernel but not loaded.
    Available,
    /// Not loaded, not built in and not installed.
    Absent,
    /// The sources could not settle it. The text says why.
    Unknown(Cause, String),
}

impl State {
    fn word(&self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::BuiltIn => "built_in",
            Self::Available => "available",
            Self::Absent => "absent",
            Self::Unknown(..) => "unknown",
        }
    }
}

/// The family of the OS, for the fix text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Rhel,
    Ubuntu,
    Debian,
    Other,
}

impl Family {
    fn of(distro: &Got<OsRelease>) -> Self {
        let Got::Value(release) = distro else {
            return Self::Other;
        };
        let is = |word: &str| release.id == word || release.id_like.iter().any(|l| l == word);
        if is("rhel") || is("fedora") || is("centos") {
            Self::Rhel
        } else if is("ubuntu") {
            Self::Ubuntu
        } else if is("debian") {
            Self::Debian
        } else {
            Self::Other
        }
    }

    fn is_apt(self) -> bool {
        matches!(self, Self::Ubuntu | Self::Debian)
    }
}

/// One thing wrong with the machine.
struct Problem {
    level: Level,
    message: String,
    fix: String,
}

/// What the judgement collects.
#[derive(Default)]
struct Judged {
    problems: Vec<Problem>,
    passes: Vec<String>,
    notes: Vec<String>,
    observed: Map<String, Value>,
    expected: Map<String, Value>,
}

/// The state of `name` (already normalized).
pub(super) fn state_of(modules: &Modules, name: &str) -> State {
    if modules.loaded.value().is_some_and(|set| set.contains(name)) {
        return State::Loaded;
    }
    if modules
        .builtin
        .value()
        .is_some_and(|set| set.contains(name))
    {
        return State::BuiltIn;
    }
    if let Got::Value(dep) = &modules.dep
        && dep.found.contains(name)
    {
        return State::Available;
    }
    let sure = modules.path_safe
        && matches!(modules.loaded, Got::Value(_))
        && !matches!(modules.builtin, Got::Failed(_))
        && matches!(&modules.dep, Got::Value(dep) if dep.complete);
    if sure {
        State::Absent
    } else {
        let (cause, why) = unknown_reason(modules);
        State::Unknown(cause, why)
    }
}

/// Which source stopped the check from settling a module. It picks the fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cause {
    /// The module files of the running kernel are missing, unreadable or not usable.
    Files,
    /// A module file is larger than rdy reads.
    Large,
    /// `/proc/modules` is missing or unreadable.
    Proc,
}

/// Why the sources could not settle a module, as a clause that follows a colon.
fn unknown_reason(modules: &Modules) -> (Cause, String) {
    let dir = &modules.dir;
    if !modules.path_safe {
        return (
            Cause::Files,
            "the kernel release is unknown or has characters rdy does not put in a path".to_owned(),
        );
    }
    match &modules.dep {
        Got::Absent => {
            return (
                Cause::Files,
                format!(
                    "{dir}/modules.dep does not exist, so the modules installed for this kernel cannot be listed"
                ),
            );
        }
        Got::Failed(why) => {
            return (
                Cause::Files,
                format!("{dir}/modules.dep could not be read ({why})"),
            );
        }
        Got::Value(dep) if !dep.complete => {
            return (
                Cause::Large,
                format!("{dir}/modules.dep is larger than rdy reads"),
            );
        }
        Got::Value(_) => {}
    }
    if let Got::Failed(why) = &modules.builtin {
        return (
            Cause::Files,
            format!("{dir}/modules.builtin could not be read ({why})"),
        );
    }
    match &modules.loaded {
        Got::Absent => (Cause::Proc, "/proc/modules does not exist".to_owned()),
        Got::Failed(why) => (
            Cause::Proc,
            format!("/proc/modules could not be read ({why})"),
        ),
        Got::Value(_) => (
            Cause::Files,
            "the module files could not settle it".to_owned(),
        ),
    }
}

/// Where the version threshold came from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Min,
    DistroMin(String),
}

/// The threshold that applies, and what was learned while choosing it.
struct Threshold<'a> {
    want: Option<(&'a KernelVersion, Source)>,
    /// `true` when the distribution is unknown and `distro_min` was set, so a failure is only a warning.
    unsure: bool,
    notes: Vec<String>,
    /// A problem found while choosing, such as an unidentified distribution with nothing else to use.
    problem: Option<Problem>,
}

fn choose<'a>(rules: &'a Rules, distro: &Got<OsRelease>) -> Threshold<'a> {
    let mut chosen = Threshold {
        want: None,
        unsure: false,
        notes: Vec::new(),
        problem: None,
    };
    let by_min = rules.min.as_ref().map(|min| (min, Source::Min));
    if rules.distro_min.is_empty() {
        chosen.want = by_min;
        return chosen;
    }
    match distro {
        Got::Value(release) => {
            if let Some((id, want)) = rules.distro_min.iter().find(|(id, _)| *id == release.id) {
                chosen.want = Some((want, Source::DistroMin(id.clone())));
                return chosen;
            }
            chosen.want = by_min;
            let like = rules
                .distro_min
                .iter()
                .find(|(id, _)| release.id_like.contains(id));
            if let Some((id, _)) = like {
                let hint = format!(
                    "distro_min has an entry for {}, which {} lists in ID_LIKE. It is not applied to {}. Ask the vendor to add a {} entry.",
                    code(id),
                    code(&release.id),
                    code(&release.id),
                    code(&release.id),
                );
                if chosen.want.is_some() {
                    chosen.notes.push(hint);
                } else {
                    chosen.problem = Some(Problem {
                        level: Level::Warn,
                        message: format!(
                            "The kernel minimum was not checked: the spec has no distro_min entry for {}. {hint}",
                            code(&release.id)
                        ),
                        fix: "Check the kernel against the vendor's requirement by hand with `uname -r`, or ask the vendor for a minimum for this OS.".to_owned(),
                    });
                }
            }
        }
        Got::Absent | Got::Failed(_) => {
            chosen.want = by_min;
            if chosen.want.is_some() {
                chosen.unsure = true;
                chosen.notes.push(
                    "The distribution could not be identified, so distro_min was not applied. A kernel below min is reported as a warning for that reason."
                        .to_owned(),
                );
            } else {
                chosen.problem = Some(Problem {
                    level: Level::Warn,
                    message: "The kernel minimum was not checked: the distribution could not be identified, and the spec sets the minimum per distribution.".to_owned(),
                    fix: "Check the kernel against the vendor's requirement by hand with `uname -r`. If `/etc/os-release` is missing, use an OS image that has it.".to_owned(),
                });
            }
        }
    }
    chosen
}

/// Judges the machine against the rules.
pub(super) fn judge(rules: &Rules, facts: &Facts) -> Finding {
    let mut out = Judged::default();
    let family = Family::of(&facts.distro);

    let release_text = facts.release.value().cloned();
    let shown = release_text
        .as_deref()
        .map_or_else(|| "(unknown)".to_owned(), code);
    let parsed = release_text.as_deref().and_then(version::parse);

    if let Some(text) = &release_text {
        out.observed
            .insert("release".to_owned(), json!(escape_untrusted(text)));
    }
    if let Some(parsed) = &parsed {
        out.observed
            .insert("base".to_owned(), json!(parsed.base.as_str()));
        if let Some(build) = &parsed.build {
            out.observed
                .insert("build".to_owned(), json!(build.as_str()));
        }
    }

    if rules.wants_version() {
        let cx = VersionContext {
            shown: &shown,
            parsed: parsed.as_ref(),
            family,
        };
        judge_version(rules, facts, &cx, &mut out);
    }
    if let Some(modules) = &facts.modules {
        judge_modules(rules, modules, &shown, family, &mut out);
    }
    if rules.btf {
        out.expected.insert("btf".to_owned(), json!(true));
        judge_btf(facts.btf.as_ref(), family, &mut out);
    }

    let Judged {
        problems,
        passes,
        notes,
        observed,
        expected,
    } = out;
    let level = problems.iter().map(|p| p.level).fold(Level::Pass, worst);
    let message = if problems.is_empty() {
        passes.join(" ")
    } else {
        problems
            .iter()
            .map(|p| p.message.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut finding = Finding::new(level, message)
        .with_observed(Value::Object(observed))
        .with_expected(Value::Object(expected));
    for note in notes {
        finding = finding.with_note(note);
    }
    if !problems.is_empty() {
        let fixes: Vec<&str> = problems.iter().map(|p| p.fix.as_str()).collect();
        finding = finding.with_fix(fixes.join(" "));
    }
    finding
}

fn worst(a: Level, b: Level) -> Level {
    match (a, b) {
        (Level::Fail, _) | (_, Level::Fail) => Level::Fail,
        (Level::Warn, _) | (_, Level::Warn) => Level::Warn,
        _ => Level::Pass,
    }
}

/// What the version judgement reads besides the rules and facts.
struct VersionContext<'a> {
    shown: &'a str,
    parsed: Option<&'a Release>,
    family: Family,
}

fn judge_version(rules: &Rules, facts: &Facts, cx: &VersionContext<'_>, out: &mut Judged) {
    if let Some(min) = &rules.min {
        out.expected.insert("min".to_owned(), json!(min.as_str()));
    }
    if !rules.distro_min.is_empty() {
        let map: Map<String, Value> = rules
            .distro_min
            .iter()
            .map(|(id, want)| (id.clone(), json!(want.as_str())))
            .collect();
        out.expected
            .insert("distro_min".to_owned(), Value::Object(map));
    }
    if let Got::Value(release) = &facts.distro {
        out.observed
            .insert("distro".to_owned(), json!(escape_untrusted(&release.id)));
    }

    let chosen = choose(rules, &facts.distro);
    out.notes.extend(chosen.notes);
    if let Some(problem) = chosen.problem {
        out.problems.push(problem);
        return;
    }
    let Some((want, source)) = chosen.want else {
        // distro_min only, and this distribution is not in it: the spec sets no minimum here.
        out.passes.push(format!(
            "Kernel {} has no minimum in the spec for this OS.",
            cx.shown
        ));
        return;
    };
    let applied = match &source {
        Source::Min => json!({"source": "min", "version": want.as_str()}),
        Source::DistroMin(id) => {
            json!({"source": "distro_min", "distro": id, "version": want.as_str()})
        }
    };
    out.expected.insert("applied".to_owned(), applied);
    let needs = match &source {
        Source::Min => want.as_str().to_owned(),
        Source::DistroMin(id) => format!("{} on {}", want.as_str(), code(id)),
    };

    let Some(parsed) = cx.parsed else {
        let why = match &facts.release {
            Got::Value(_) => format!("kernel release {} is not in a form rdy compares", cx.shown),
            Got::Absent => "the kernel release does not exist".to_owned(),
            Got::Failed(why) => format!("the kernel release could not be read ({why})"),
        };
        out.problems.push(Problem {
            level: Level::Warn,
            message: format!("The kernel version was not checked: {why}. The minimum is {needs}."),
            fix: "Run `uname -r` and compare it with the vendor's minimum by hand.".to_owned(),
        });
        return;
    };
    match version::compare(parsed, want) {
        Standing::AtLeast => out.passes.push(format!(
            "Kernel {} meets the minimum of {needs}.",
            cx.shown
        )),
        Standing::Below => out.problems.push(Problem {
            level: if chosen.unsure {
                Level::Warn
            } else {
                Level::Fail
            },
            message: format!(
                "Kernel {} is older than the minimum of {needs}.",
                cx.shown
            ),
            fix: upgrade_fix(cx.family),
        }),
        Standing::NoBuild => out.problems.push(Problem {
            level: Level::Warn,
            message: format!(
                "The kernel version was not fully checked: {} has no build number to compare with {}.",
                cx.shown,
                want.as_str()
            ),
            fix: "Run `uname -r` and compare it with the vendor's minimum by hand.".to_owned(),
        }),
    }
}

fn upgrade_fix(family: Family) -> String {
    let steps = match family {
        Family::Rhel => "Install a newer kernel with `sudo dnf upgrade kernel`",
        Family::Ubuntu | Family::Debian => {
            "Install a newer kernel with `sudo apt update && sudo apt full-upgrade`"
        }
        Family::Other => "Install a newer kernel from the OS vendor",
    };
    let tail = if family.is_apt() {
        ". If the newest kernel for this release is still too old, use a newer OS release"
    } else {
        ""
    };
    format!("{steps}, reboot into it and confirm with `uname -r`{tail}.")
}

fn judge_modules(rules: &Rules, modules: &Modules, shown: &str, family: Family, out: &mut Judged) {
    let states: Vec<(&str, State)> = rules
        .modules
        .iter()
        .map(|name| (name.as_str(), state_of(modules, &normalize(name))))
        .collect();
    out.expected
        .insert("modules".to_owned(), json!(rules.modules));
    let table: Map<String, Value> = states
        .iter()
        .map(|(name, state)| ((*name).to_owned(), json!(state.word())))
        .collect();
    out.observed
        .insert("modules".to_owned(), Value::Object(table));

    let names = |wanted: fn(&State) -> bool| -> Vec<&str> {
        states
            .iter()
            .filter(|(_, state)| wanted(state))
            .map(|(name, _)| *name)
            .collect()
    };
    let absent = names(|s| matches!(s, State::Absent));
    let available = names(|s| matches!(s, State::Available));
    let unknown = names(|s| matches!(s, State::Unknown(..)));

    if !absent.is_empty() {
        out.problems.push(Problem {
            level: Level::Fail,
            message: format!(
                "{} not available for kernel {shown}: not loaded, not built in and not installed.",
                module_list(&absent, "Module", "Modules", "is", "are")
            ),
            fix: absent_fix(family),
        });
    }
    if !available.is_empty() {
        out.problems.push(Problem {
            level: Level::Warn,
            message: format!(
                "{} installed but not loaded.",
                module_list(&available, "Module", "Modules", "is", "are")
            ),
            fix: load_fix(&available),
        });
    }
    let why = states.iter().find_map(|(_, state)| match state {
        State::Unknown(cause, why) => Some((*cause, why.as_str())),
        _ => None,
    });
    if let Some((cause, why)) = why {
        out.problems.push(Problem {
            level: Level::Warn,
            message: format!(
                "Could not tell whether {} available: {why}.",
                module_list(&unknown, "module", "modules", "is", "are")
            ),
            fix: unknown_fix(cause, unknown.first().copied().unwrap_or_default()),
        });
    }
    if absent.is_empty() && available.is_empty() && unknown.is_empty() {
        let count = rules.modules.len();
        out.passes.push(if count == 1 {
            "The required module is loaded or built in.".to_owned()
        } else {
            format!("All {count} required modules are loaded or built in.")
        });
    }
}

/// "Module `a` is" or "Modules `a`, `b` and 3 more are". The word forms are given so one function
/// serves both sentence starts.
fn module_list(names: &[&str], one: &str, many: &str, is: &str, are: &str) -> String {
    let shown: Vec<String> = names.iter().take(SHOWN).map(|n| code(n)).collect();
    let mut list = shown.join(", ");
    if names.len() > SHOWN {
        list.push_str(&format!(" and {} more", names.len() - SHOWN));
    }
    if names.len() == 1 {
        format!("{one} {list} {is}")
    } else {
        format!("{many} {list} {are}")
    }
}

fn absent_fix(family: Family) -> String {
    match family {
        Family::Rhel => "Install the package that ships the module: try `sudo dnf install kernel-modules-extra`, then reboot if `uname -r` shows an older kernel than the one installed.".to_owned(),
        Family::Ubuntu => "Install the package that ships the module: try `sudo apt install linux-modules-extra-$(uname -r)`.".to_owned(),
        Family::Debian | Family::Other => "Install the package that ships the module for the running kernel, or boot a kernel that has it. A custom kernel needs the module built in or as a module.".to_owned(),
    }
}

fn load_fix(names: &[&str]) -> String {
    let list = names.join(" ");
    format!(
        "Load now with `sudo modprobe -a {list}`. Load at every boot with `printf '%s\\n' {list} | sudo tee -a /etc/modules-load.d/vendor.conf`."
    )
}

fn unknown_fix(cause: Cause, first: &str) -> String {
    let by_hand = format!("To check by hand, run `sudo modprobe -n -v {first}`.");
    match cause {
        Cause::Files => format!(
            "Reboot into the newest installed kernel, or install the kernel modules package for the running kernel, then run rdy again. {by_hand}"
        ),
        Cause::Large => format!("rdy could not search the whole module list. {by_hand}"),
        Cause::Proc => format!(
            "Run rdy on the host itself, as a user that can read `/proc/modules`, and not inside a container. {by_hand}"
        ),
    }
}

fn judge_btf(btf: Option<&Got<bool>>, family: Family, out: &mut Judged) {
    let fix = match family {
        Family::Rhel => {
            "Boot a kernel built with BTF: `sudo dnf upgrade kernel`, reboot, and check that `/sys/kernel/btf/vmlinux` exists."
        }
        Family::Ubuntu | Family::Debian => {
            "Boot a kernel built with BTF: `sudo apt update && sudo apt full-upgrade`, reboot, and check that `/sys/kernel/btf/vmlinux` exists."
        }
        Family::Other => {
            "Boot a kernel built with `CONFIG_DEBUG_INFO_BTF=y`, then check that `/sys/kernel/btf/vmlinux` exists."
        }
    };
    match btf {
        Some(Got::Value(true)) => {
            out.observed.insert("btf".to_owned(), json!(true));
            out.passes
                .push("BTF type information is present.".to_owned());
        }
        Some(Got::Value(false) | Got::Absent) => {
            out.observed.insert("btf".to_owned(), json!(false));
            out.problems.push(Problem {
                level: Level::Fail,
                message: "This kernel has no BTF type information: /sys/kernel/btf/vmlinux is missing."
                    .to_owned(),
                fix: fix.to_owned(),
            });
        }
        Some(Got::Failed(why)) => out.problems.push(Problem {
            level: Level::Warn,
            message: format!(
                "Could not tell whether the kernel has BTF: /sys/kernel/btf/vmlinux could not be read ({why})."
            ),
            fix: "Check that `/sys/kernel/btf/vmlinux` exists, as the user that will run the product."
                .to_owned(),
        }),
        None => {}
    }
}
