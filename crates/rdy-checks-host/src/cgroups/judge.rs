//! The judgement of `host.cgroups`: a pure function from facts and rules to one finding.
//!
//! Nothing here reads the machine. The thresholds are the ones in 03, "host.cgroups":
//!
//! - the wrong cgroup state for `version` is a fail. `v2` needs the unified hierarchy alone. `v1` is
//!   met by a v1 host and by a hybrid host, because a hybrid host keeps its controllers in v1;
//! - a required controller the kernel does not offer is a fail;
//! - a required controller that cannot be confirmed (a file that could not be read, a v1 hierarchy
//!   that is not mounted where rdy can see it) is a warn;
//! - with no `version` and no `controllers` the check reports what it finds and passes.

use std::collections::BTreeMap;

use rdy_engine::check::{Finding, Level};
use serde_json::{Value, json};

use super::fix::{self, Disabled};
use super::parse::{ProcController, disabling_word, word_value};
use crate::cgroup::{Controllers, Layout};
use crate::os::release::Release;

/// The cgroup version the spec asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wanted {
    Any,
    V1,
    V2,
}

impl Wanted {
    fn word(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// What the spec asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rules {
    pub version: Wanted,
    /// Controller names as written in the spec, in order, without repeats.
    pub controllers: Vec<String>,
}

/// What the machine said.
#[derive(Debug, Clone, Default)]
pub(super) struct Facts {
    /// `None` when the cgroup files could not be used at all.
    pub controllers: Option<Controllers>,
    /// `None` when `/proc/cgroups` could not be read.
    pub proc_cgroups: Option<Vec<ProcController>>,
    /// The cgroup-related words of the kernel command line.
    pub cmdline: Vec<String>,
    pub release: Option<Release>,
    /// The device tree says this is a Raspberry Pi.
    pub raspberry_pi: bool,
    /// Things the reads could not settle, for the report.
    pub notes: Vec<String>,
}

/// Why a required controller is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Why {
    /// `/proc/cgroups` says `enabled 0`. The word is the `cgroup_disable=` word that did it, if any.
    Disabled(Option<String>),
    /// Attached to a v1 hierarchy, so v2 does not offer it.
    BoundToV1,
    /// The hierarchy does not list it.
    NotOffered,
    /// `/proc/cgroups` does not list it at all.
    NotInKernel,
}

impl Why {
    fn text(&self) -> String {
        match self {
            Self::Disabled(Some(word)) => {
                format!("it is turned off in the kernel (`{word}` is on the command line)")
            }
            Self::Disabled(None) => {
                "it is turned off in the kernel (`/proc/cgroups` says enabled 0)".to_owned()
            }
            Self::BoundToV1 => "it is attached to a cgroup v1 hierarchy".to_owned(),
            Self::NotOffered => "the cgroup hierarchy does not offer it".to_owned(),
            Self::NotInKernel => "`/proc/cgroups` does not list it".to_owned(),
        }
    }
}

/// What the check found for one required controller.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Ok,
    Missing(Why),
    /// Could not be confirmed. The text says why.
    Unseen(&'static str),
}

/// The v2 name of a controller: v1 calls `io` `blkio`.
fn v2_name(name: &str) -> &str {
    if name == "blkio" { "io" } else { name }
}

/// The v1 name of a controller.
fn v1_name(name: &str) -> &str {
    if name == "io" { "blkio" } else { name }
}

fn layout_word(layout: Layout) -> Option<&'static str> {
    match layout {
        Layout::V1 => Some("v1"),
        Layout::Hybrid => Some("hybrid"),
        Layout::V2 => Some("v2"),
        _ => None,
    }
}

fn expected(rules: &Rules) -> Value {
    json!({
        "version": rules.version.word(),
        "controllers": rules.controllers,
    })
}

/// The finding when no cgroup file system could be seen.
fn unknown(rules: &Rules, facts: &Facts) -> Finding {
    let asked = rules.version != Wanted::Any || !rules.controllers.is_empty();
    let level = if asked { Level::Warn } else { Level::Pass };
    let mut finding = Finding::new(
        level,
        "rdy could not see a cgroup file system, so the cgroup version is not known",
    );
    finding.observed = json!({ "layout": null, "cmdline": facts.cmdline });
    finding.expected = expected(rules);
    finding.notes.clone_from(&facts.notes);
    if asked {
        finding.fix = Some(
            "Run rdy on the host itself, not in a container, and make sure `/sys/fs/cgroup` is mounted and readable by this user."
                .to_owned(),
        );
    }
    finding
}

/// The verdict for one controller.
fn verdict(name: &str, ctl: &Controllers, facts: &Facts) -> Verdict {
    let v1 = v1_name(name);
    let row = facts
        .proc_cgroups
        .as_ref()
        .map(|rows| rows.iter().find(|row| row.name == v1));
    let disabled = |row: Option<&ProcController>| {
        row.filter(|row| !row.enabled).map(|_| {
            Why::Disabled(disabling_word(&facts.cmdline, [v1, v2_name(name)]).map(str::to_owned))
        })
    };
    match ctl.layout {
        Layout::V2 => {
            let Some(v2) = &ctl.v2 else {
                return Verdict::Unseen("the v2 controller lists could not be read");
            };
            let Some(offered) = v2.top_available.as_ref().or(v2.own_available.as_ref()) else {
                return Verdict::Unseen("the v2 controller lists could not be read");
            };
            if offered.contains(v2_name(name)) {
                return Verdict::Ok;
            }
            let listed = row.flatten();
            let attached = listed.is_some_and(|r| r.hierarchy != 0);
            Verdict::Missing(disabled(listed).unwrap_or(if attached {
                Why::BoundToV1
            } else {
                Why::NotOffered
            }))
        }
        _ => {
            if ctl.v1.contains(v1) {
                return Verdict::Ok;
            }
            let in_v2 = ctl
                .v2
                .as_ref()
                .and_then(|v2| v2.top_available.as_ref())
                .is_some_and(|set| set.contains(v2_name(name)));
            if in_v2 {
                return Verdict::Ok;
            }
            match row {
                None => Verdict::Unseen("`/proc/cgroups` could not be read"),
                Some(None) => Verdict::Missing(Why::NotInKernel),
                Some(Some(row)) if !row.enabled => {
                    Verdict::Missing(disabled(Some(row)).unwrap_or(Why::Disabled(None)))
                }
                // Enabled and attached to nothing: no mount namespace can hide it, so it is not offered.
                Some(Some(row)) if row.hierarchy == 0 => Verdict::Missing(Why::NotOffered),
                Some(Some(_)) => Verdict::Unseen(
                    "it is enabled in the kernel but its hierarchy is not mounted where rdy can see it",
                ),
            }
        }
    }
}

/// Judges the machine against the rules.
pub(super) fn judge(rules: &Rules, facts: &Facts) -> Finding {
    let Some(raw) = facts.controllers.as_ref() else {
        return unknown(rules, facts);
    };
    // A v1 mount with no controller in it (`name=systemd` beside a unified tree) is not a hybrid host.
    let unified;
    let ctl = if raw.layout == Layout::Hybrid && raw.v1.is_empty() {
        unified = Controllers {
            layout: Layout::V2,
            ..raw.clone()
        };
        &unified
    } else {
        raw
    };
    let Some(layout) = layout_word(ctl.layout) else {
        return unknown(rules, facts);
    };
    let mut notes = facts.notes.clone();

    let version_ok = matches!(
        (rules.version, ctl.layout),
        (Wanted::Any, _) | (Wanted::V2, Layout::V2) | (Wanted::V1, Layout::V1 | Layout::Hybrid)
    );
    let verdicts: Vec<(&String, Verdict)> = rules
        .controllers
        .iter()
        .map(|name| (name, verdict(name, ctl, facts)))
        .collect();

    // What the report says about the layout.
    let base = match ctl.layout {
        Layout::V2 => "cgroup v2 in use",
        Layout::V1 => "cgroup v1 in use",
        _ => "cgroup hybrid layout in use",
    };
    if ctl.layout == Layout::Hybrid {
        notes.push(
            "Hybrid layout: the controllers are in cgroup v1 hierarchies, and a v2 hierarchy is mounted beside them."
                .to_owned(),
        );
    }
    if !version_ok
        && let Some(value) = word_value(&facts.cmdline, "systemd.unified_cgroup_hierarchy=")
        && matches!(
            (rules.version, value),
            (Wanted::V2, "0" | "false" | "no") | (Wanted::V1, "1" | "true" | "yes")
        )
    {
        notes.push(format!(
            "The kernel command line has `systemd.unified_cgroup_hierarchy={value}`. Change that word instead of adding a second one."
        ));
    }

    let missing: Vec<(&String, &Why)> = verdicts
        .iter()
        .filter_map(|(name, v)| match v {
            Verdict::Missing(why) => Some((*name, why)),
            _ => None,
        })
        .collect();
    let unseen: Vec<(&String, &str)> = verdicts
        .iter()
        .filter_map(|(name, v)| match v {
            Verdict::Unseen(why) => Some((*name, *why)),
            _ => None,
        })
        .collect();
    for (name, why) in &missing {
        notes.push(format!("`{name}` is missing: {}.", why.text()));
    }
    for (name, why) in &unseen {
        notes.push(format!("`{name}` was not confirmed: {why}."));
    }
    // v2 only: a controller the kernel offers but the top of the tree does not pass on yet.
    if let Some(v2) = ctl.v2.as_ref().filter(|_| ctl.layout == Layout::V2)
        && let (Some(offered), Some(enabled)) = (&v2.top_available, &v2.top_enabled)
    {
        let idle: Vec<String> = verdicts
            .iter()
            .filter(|(name, v)| {
                *v == Verdict::Ok && {
                    let n = v2_name(name);
                    offered.contains(n) && !enabled.contains(n)
                }
            })
            .map(|(name, _)| format!("`{name}`"))
            .collect();
        if !idle.is_empty() {
            notes.push(format!(
                "Offered by the kernel but not yet enabled for child cgroups at the top of the tree: {}. systemd turns a controller on when a unit needs it.",
                fix::list(&idle)
            ));
        }
    }

    let level = if !version_ok || !missing.is_empty() {
        Level::Fail
    } else if !unseen.is_empty() {
        Level::Warn
    } else {
        Level::Pass
    };

    // The sentence.
    let mut parts = vec![base.to_owned()];
    if !version_ok {
        parts.push(format!("{} needed", rules.version.word()));
    }
    let names = |items: &[&String]| {
        items
            .iter()
            .map(|name| format!("`{name}`"))
            .collect::<Vec<_>>()
    };
    if !missing.is_empty() {
        let list = fix::list(&names(&missing.iter().map(|(n, _)| *n).collect::<Vec<_>>()));
        parts.push(if missing.len() == 1 {
            format!("controller {list} is missing")
        } else {
            format!("controllers {list} are missing")
        });
    }
    if !unseen.is_empty() {
        let list = fix::list(&names(&unseen.iter().map(|(n, _)| *n).collect::<Vec<_>>()));
        parts.push(format!("could not confirm {list}"));
    }
    if level == Level::Pass && !rules.controllers.is_empty() {
        let list = fix::list(&names(&rules.controllers.iter().collect::<Vec<_>>()));
        parts.push(if rules.controllers.len() == 1 {
            format!("controller {list} available")
        } else {
            format!("controllers {list} available")
        });
    }
    let message = parts.join(", ");

    let fix = (level != Level::Pass).then(|| fix_text(rules, facts, version_ok, &missing, &unseen));

    let mut finding = Finding::new(level, message);
    finding.observed = observed(ctl, facts, layout, &verdicts);
    finding.expected = expected(rules);
    finding.fix = fix;
    finding.notes = notes;
    finding
}

fn fix_text(
    rules: &Rules,
    facts: &Facts,
    version_ok: bool,
    missing: &[(&String, &Why)],
    unseen: &[(&String, &str)],
) -> String {
    let boot = fix::boot_for(facts.release.as_ref(), facts.raspberry_pi);
    let mut parts = Vec::new();
    if !version_ok {
        parts.push(fix::version_fix(
            boot,
            rules.version == Wanted::V2,
            facts.release.as_ref(),
        ));
    }
    let disabled: Vec<Disabled> = missing
        .iter()
        .filter_map(|(name, why)| match why {
            Why::Disabled(word) => Some(Disabled {
                controller: v2_name(name).to_owned(),
                word: word.clone(),
            }),
            _ => None,
        })
        .collect();
    if !disabled.is_empty() {
        parts.push(fix::disabled_fix(boot, &disabled));
    }
    let other: Vec<String> = missing
        .iter()
        .filter(|(_, why)| !matches!(why, Why::Disabled(_)))
        .map(|(name, _)| format!("`{name}`"))
        .collect();
    if !other.is_empty() {
        parts.push(fix::not_offered_fix(&other));
    }
    if !unseen.is_empty() {
        parts.push(
            "If rdy runs in a container, run it on the host so every controller is visible. On the host, check that each one is mounted under `/sys/fs/cgroup`."
                .to_owned(),
        );
    }
    parts.join(" ")
}

fn observed(
    ctl: &Controllers,
    facts: &Facts,
    layout: &str,
    verdicts: &[(&String, Verdict)],
) -> Value {
    let v2 = ctl.v2.as_ref();
    let strings = |set: Option<&std::collections::BTreeSet<String>>| -> Value {
        set.map_or(Value::Null, |set| json!(set.iter().collect::<Vec<_>>()))
    };
    let available = if ctl.layout == Layout::V2 {
        strings(v2.and_then(|v| v.top_available.as_ref()))
    } else {
        json!(ctl.v1.iter().collect::<Vec<_>>())
    };
    let mut states = BTreeMap::new();
    let mut proc_rows = BTreeMap::new();
    for (name, verdict) in verdicts {
        let state = match verdict {
            Verdict::Ok => "ok",
            Verdict::Missing(_) => "missing",
            Verdict::Unseen(_) => "not_confirmed",
        };
        states.insert((*name).clone(), state);
        let found = facts
            .proc_cgroups
            .iter()
            .flatten()
            .find(|row| row.name == v1_name(name));
        if let Some(row) = found {
            proc_rows.insert(
                (*name).clone(),
                json!({ "enabled": row.enabled, "hierarchy": row.hierarchy }),
            );
        }
    }
    json!({
        "layout": layout,
        "controllers_available": available,
        "controllers_enabled": strings(v2.and_then(|v| v.top_enabled.as_ref())),
        "controllers": states,
        "proc_cgroups": proc_rows,
        "cmdline": facts.cmdline,
    })
}
