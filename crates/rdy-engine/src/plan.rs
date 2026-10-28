//! The run plan: what each spec entry will do on this OS, worked out before anything runs.
//!
//! [`Registry::plan`] maps every entry of a spec to a [`PlanAction::Run`] with a built check, or to a
//! [`PlanAction::Skip`] with a skip kind and the words for it. It is pure: it reads the spec, the
//! registry and the OS, and does no I/O, so a plan is the same on every machine with that OS. The
//! needs that must be probed (root, a cluster) are not decided here. They come after planning, and a
//! hard need that is missing becomes `missing_need` in the scheduler.
//!
//! Each entry is decided by the first rule that fits (01 section 5.2, ADR 0013):
//!
//! | Order | Situation | Skip kind |
//! | --- | --- | --- |
//! | 1 | The entry's `os` list leaves this OS out | `not_applicable` (never counts) |
//! | 2 | The `os` list is empty | `unsupported_spec` |
//! | 3 | The id is on the reserved list and this build lacks it | `not_in_build` |
//! | 4 | The id is not reserved | `unknown_check` |
//! | 5 | A known id that no registered family builds | `not_in_build` |
//! | 6 | A known id with a field or value this rdy cannot read | `unsupported_spec` |
//! | 7 | The family refuses to build it | `unsupported_spec` |
//! | 8 | [`CheckInfo::os`](crate::check::CheckInfo::os) is `NotYet` here | `not_yet_on_os` |
//!
//! Only rule 1 produces `not_applicable`, and only from the vendor's own `os` list. A check with no
//! data source on this OS is rule 8 and counts as not run.
//!
//! Every value from the spec (an id, a field name) is cut and has control characters replaced before it
//! goes into a message, a key or a result id, so a spec cannot put escape codes on a terminal.
//!
//! The reserved-id list is `rdy_spec::reserved`.
//!
//! The words here follow 01 section 5.2. M1-057 reconciles them with `SkipWhy` in `rdy-cli`, which also
//! adds the did-you-mean hint.

use rdy_spec::check::{CheckParams, UnsupportedReason};
use rdy_spec::reserved::{RESERVED_IDS, UnknownKind};
use rdy_spec::result::{CheckResult, FixSource, Severity, SkipKind};
use rdy_spec::spec::{CheckSpec, Lenient, OsFamily, Spec};

use crate::check::Os;
use crate::family::{Built, HostSet, Registry};
use crate::outcome::os_name;

#[cfg(test)]
mod tests;

/// The longest part of a spec value that goes into a message, in characters.
const MAX_ECHO_CHARS: usize = 64;

const NEWER_RDY: &str = "Install a newer rdy. If there is none yet, ask the vendor how to go on.";
const FIX_ENTRY: &str = "Tell the vendor to correct the entry. rdy spec lint shows which one.";

/// Why one entry will not run, with the words for the report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlanSkip {
    /// The skip kind of the result.
    pub kind: SkipKind,
    /// One line, starting with `Not run.` (or `Does not apply here.`).
    pub message: String,
    /// What to do. `None` only for `not_applicable`.
    pub fix: Option<String>,
}

impl PlanSkip {
    fn new(kind: SkipKind, message: String, fix: &str) -> Self {
        Self {
            kind,
            message,
            fix: Some(fix.to_owned()),
        }
    }
}

/// What the run does with one spec entry.
#[derive(Debug)]
#[non_exhaustive]
pub enum PlanAction {
    /// The check is built and waits for the scheduler.
    Run(Built),
    /// The check does not run. The result is a skip.
    Skip(PlanSkip),
}

/// One spec entry and what the run does with it.
#[derive(Debug)]
#[non_exhaustive]
pub struct PlanEntry {
    /// The position of the entry in the spec's `checks`. The scheduler reads the entry from there.
    pub index: usize,
    /// The result key: the id, or `id/name`. Safe to print.
    pub key: String,
    /// The check id as written, cut and made safe to print.
    pub id: String,
    /// The family part of [`PlanEntry::id`], or the whole id when it has no dot.
    pub family: String,
    /// The severity of the entry. An unreadable one counts as `block`.
    pub severity: Severity,
    /// What happens to the entry.
    pub action: PlanAction,
}

impl PlanEntry {
    /// The skip result for an entry that does not run, or `None` for one that does.
    ///
    /// The timing fields stay zero: a skipped entry never started.
    #[must_use]
    pub fn skip_result(&self) -> Option<CheckResult> {
        let PlanAction::Skip(skip) = &self.action else {
            return None;
        };
        let mut result = CheckResult::skipped(
            self.id.clone(),
            self.family.clone(),
            self.severity.clone(),
            skip.kind.clone(),
        );
        result.key.clone_from(&self.key);
        result.message.clone_from(&skip.message);
        if let Some(fix) = &skip.fix {
            result.fix = Some(fix.clone());
            result.fix_source = Some(FixSource::Rdy);
        }
        Some(result)
    }

    /// The hosts the check may reach, or `None` when the entry does not run.
    #[must_use]
    pub fn hosts(&self) -> Option<&HostSet> {
        match &self.action {
            PlanAction::Run(built) => Some(&built.hosts),
            PlanAction::Skip(_) => None,
        }
    }
}

/// The plan of a run: one [`PlanEntry`] per spec entry, in spec order.
#[derive(Debug)]
pub struct RunPlan {
    os: Os,
    entries: Vec<PlanEntry>,
}

impl RunPlan {
    /// The OS the plan is for.
    #[must_use]
    pub fn os(&self) -> Os {
        self.os
    }

    /// Every entry, in spec order.
    #[must_use]
    pub fn entries(&self) -> &[PlanEntry] {
        &self.entries
    }

    /// The entries that run.
    pub fn runnable(&self) -> impl Iterator<Item = &PlanEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.action, PlanAction::Run(_)))
    }

    /// The entries that are skipped.
    pub fn skipped(&self) -> impl Iterator<Item = &PlanEntry> {
        self.entries
            .iter()
            .filter(|e| matches!(e.action, PlanAction::Skip(_)))
    }
}

impl Registry {
    /// Plans a run of `spec` on `os`. Pure: no I/O.
    ///
    /// `rdy_version` is the version of the rdy binary, for the words of an unknown id. The engine does
    /// not know it, because the binary's version is not the engine crate's.
    #[must_use]
    pub fn plan(&self, spec: &Spec, os: Os, rdy_version: &str) -> RunPlan {
        let entries = spec
            .checks
            .iter()
            .enumerate()
            .map(|(index, entry)| self.plan_entry(spec, index, entry, os, rdy_version))
            .collect();
        RunPlan { os, entries }
    }

    fn plan_entry(
        &self,
        spec: &Spec,
        index: usize,
        entry: &CheckSpec,
        os: Os,
        rdy_version: &str,
    ) -> PlanEntry {
        let id = echo(&entry.id);
        let family = id
            .split_once('.')
            .map_or_else(|| id.clone(), |(family, _)| family.to_owned());
        let key = match &entry.name {
            None => id.clone(),
            Some(Lenient::Valid(name)) => format!("{id}/{}", echo(name.as_str())),
            // An unreadable name has no key of its own. The index keeps two such entries apart.
            Some(_) => format!("{id}#{index}"),
        };
        let action = match self.decide(spec, entry, os, rdy_version) {
            Ok(built) => PlanAction::Run(built),
            Err(skip) => PlanAction::Skip(skip),
        };
        PlanEntry {
            index,
            key,
            id,
            family,
            severity: Severity::from(entry.effective_severity()),
            action,
        }
    }

    fn decide(
        &self,
        spec: &Spec,
        entry: &CheckSpec,
        os: Os,
        rdy_version: &str,
    ) -> Result<Built, PlanSkip> {
        // Rules 1 and 2: the vendor's own `os` list.
        if let Some(Lenient::Valid(list)) = &entry.os {
            if list.is_empty() {
                // An empty list would hide the check on every OS. Refuse it instead.
                return Err(PlanSkip::new(
                    SkipKind::UnsupportedSpec,
                    format!("Not run. The 'os' list in {} is empty.", echo(&entry.id)),
                    "Tell the vendor to list at least one OS, or to remove 'os'.",
                ));
            }
            if !list.contains(&os) {
                return Err(not_applicable(list));
            }
        }

        let version = echo(rdy_version);
        let params = entry.decode_params();
        // Rules 3 and 4.
        if let CheckParams::Unknown { id, .. } = &params {
            return Err(unknown(self, &params, id, &version));
        }
        // Rule 5: rdy-spec reads the id, but no registered family builds it yet. This comes before the
        // fields are judged, because a field of a check this build lacks is not a typo.
        let id = params.id().to_owned();
        let Some((family, info)) = self.check(&id) else {
            return Err(not_in_build(self, &id));
        };
        // Rule 6.
        if let CheckParams::Unsupported { reason, .. } = &params {
            return Err(unsupported(&id, reason, &version));
        }
        // Rule 7.
        let built = family.build(entry, params, spec).map_err(|error| {
            PlanSkip::new(
                SkipKind::UnsupportedSpec,
                format!("Not run. {}: {}.", echo(&id), echo(&error.to_string())),
                FIX_ENTRY,
            )
        })?;
        if built.check.info().id != id {
            // A family built another check than the one it was asked for. That is a bug in the
            // family. Fail closed: the entry does not run, and it still counts as not run.
            debug_assert!(
                false,
                "family '{}' built the wrong check for {id}",
                info.family
            );
            return Err(not_in_build(self, &id));
        }
        // Rule 8.
        if let Some(kind) = info.os.on(os).skip_kind() {
            return Err(PlanSkip::new(
                kind,
                format!("Not run. This check does not work on {} yet.", os_name(os)),
                "Run rdy on the machine you will install on.",
            ));
        }
        Ok(built)
    }
}

fn not_applicable(list: &[OsFamily]) -> PlanSkip {
    let names: Vec<&str> = list
        .iter()
        .map(|os| match os {
            OsFamily::Linux => "linux",
            OsFamily::Macos => "macos",
            OsFamily::Windows => "windows",
            _ => "another OS",
        })
        .collect();
    PlanSkip {
        kind: SkipKind::NotApplicable,
        message: format!(
            "Does not apply here. This check is for {} only.",
            names.join(" and ")
        ),
        fix: None,
    }
}

fn unknown(registry: &Registry, params: &CheckParams, id: &str, version: &str) -> PlanSkip {
    match params.unknown_kind() {
        Some(UnknownKind::UnknownCheck) => {}
        // `NotInBuild`, and any kind a later rdy-spec adds: say the id is not in this build, which
        // points the customer at a newer rdy and is the safe wording.
        _ => return not_in_build(registry, id),
    }
    let id = echo(id);
    match id.split_once('.') {
        Some((family, _)) if family_is_reserved(family) => PlanSkip::new(
            SkipKind::UnknownCheck,
            format!("Not run. rdy {version} does not know the check '{id}'."),
            &format!(
                "Tell the vendor. The spec may have a typo, or it may need a newer rdy than {version}."
            ),
        ),
        other => PlanSkip::new(
            SkipKind::UnknownCheck,
            format!(
                "Not run. No version of rdy has checks named {}.",
                other.map_or(id.as_str(), |(family, _)| family)
            ),
            "Tell the vendor. The spec may have a typo.",
        ),
    }
}

/// Whether some reserved id has this family prefix, so a newer rdy may know the check.
fn family_is_reserved(family: &str) -> bool {
    RESERVED_IDS
        .iter()
        .any(|reserved| reserved.split_once('.').is_some_and(|(f, _)| f == family))
}

fn not_in_build(registry: &Registry, id: &str) -> PlanSkip {
    let id = echo(id);
    let message = match id.split_once('.') {
        Some((family, _)) if registry.family(family).is_none() => {
            format!("Not run. This version of rdy has no {family} checks yet.")
        }
        _ => format!("Not run. This version of rdy does not have the check {id} yet."),
    };
    PlanSkip::new(SkipKind::NotInBuild, message, NEWER_RDY)
}

fn unsupported(id: &str, reason: &UnsupportedReason, version: &str) -> PlanSkip {
    let id = echo(id);
    match reason {
        UnsupportedReason::UnknownField { field } => PlanSkip::new(
            SkipKind::UnsupportedSpec,
            format!("Not run. rdy {version} cannot read '{field}' in {id}."),
            &format!(
                "Tell the vendor. The spec may have a typo, or it may need a newer rdy than {version}."
            ),
        ),
        // The reason's own text is already cut and escaped by rdy-spec.
        other => PlanSkip::new(
            SkipKind::UnsupportedSpec,
            format!("Not run. {id}: {other}."),
            FIX_ENTRY,
        ),
    }
}

/// Cuts `text` to [`MAX_ECHO_CHARS`] characters and replaces control characters, so it is safe to print.
fn echo(text: &str) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == MAX_ECHO_CHARS {
            out.push_str("...");
            break;
        }
        out.push(if c.is_control() { '\u{fffd}' } else { c });
    }
    out
}
