//! What the answers of the cluster mean for `k8s.crds`: the findings, with fix text, and what could not be
//! read.
//!
//! The rules (03, "k8s.crds"):
//!
//! - A definition that is not installed, or does not serve a version the spec names, blocks.
//! - An operator Deployment that is missing, scaled to zero or has fewer replicas ready than it wants warns.
//! - An operator whose version is below `min_version` blocks.
//! - What could not be read is never a block: the result is partial and `missing_grants` names what to ask
//!   for. A version that cannot be read from the image tag or the label is such a case.

use std::collections::BTreeMap;

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::units::compare_versions;
use rdy_spec::Version;
use rdy_spec::check::K8sCrds;
use serde_json::{Value, json};

use super::fix;
use super::objects::{Fetched, OperatorDeployment, Unread, Versions, versions_of};

/// The most names listed in one sentence before "and N more".
const LISTED: usize = 4;

/// What the cluster said about the API group of a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupState {
    /// `GET /apis` lists no such group.
    Absent,
    /// The group and the versions it serves, in the order the server gave them (preferred first).
    Served(Vec<String>),
    Unread(Unread),
}

/// What was read for one entry of `crds`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CrdRead {
    /// The name from the spec.
    pub(super) name: String,
    /// `(plural, group)`, or `None` when the name has no dot.
    pub(super) split: Option<(String, String)>,
    /// The versions the spec needs. Empty means any.
    pub(super) wanted: Vec<String>,
    pub(super) group: GroupState,
    /// For each version whose document was read: whether it lists the plural.
    pub(super) listed: Vec<(String, Result<bool, Unread>)>,
}

/// What was read for one entry of `operators`.
#[derive(Debug, Clone)]
pub(super) struct OperatorRead {
    pub(super) namespace: String,
    pub(super) deployment: String,
    pub(super) min: Option<Version>,
    pub(super) state: Fetched<OperatorDeployment>,
}

/// What was read, before any judgement.
#[derive(Debug, Default)]
pub(super) struct Gathered {
    pub(super) crds: Vec<CrdRead>,
    pub(super) operators: Vec<OperatorRead>,
}

/// True when `text` has the shape of an API version: `v1`, `v2beta1`, `v1alpha3`.
pub(super) fn is_version(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('v') else {
        return false;
    };
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 || digits > 4 {
        return false;
    }
    let stage = &rest[digits..];
    if stage.is_empty() {
        return true;
    }
    let tail = stage
        .strip_prefix("alpha")
        .or_else(|| stage.strip_prefix("beta"));
    tail.is_some_and(|n| (1..=4).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A permission the identity lacked: the wire text, and the command that checks it.
struct Grant {
    text: String,
    can_i: String,
}

/// One thing that stops the install or may stop it.
struct Issue {
    level: Level,
    message: String,
    fix: String,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Fail => 2,
        Level::Warn => 1,
        _ => 0,
    }
}

/// What the cluster says about one definition.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Installed, and serving these versions.
    Served(Vec<String>),
    /// The cluster serves no such group.
    GroupMissing,
    /// The group is served, but not this definition.
    NotInGroup,
    /// Installed, without these versions. It serves `served`, which may be none the server named.
    VersionsMissing {
        missing: Vec<String>,
        served: Vec<String>,
    },
    /// Could not be judged.
    Unverified(Unread),
    /// The name has no group.
    Unsplit,
}

pub(super) fn verdict(read: &CrdRead) -> Verdict {
    if read.split.is_none() {
        return Verdict::Unsplit;
    }
    let group_versions = match &read.group {
        GroupState::Absent => return Verdict::GroupMissing,
        GroupState::Unread(why) => return Verdict::Unverified(*why),
        GroupState::Served(versions) => versions,
    };
    let listing = |version: &str| read.listed.iter().find(|(v, _)| v == version);
    let served: Vec<String> = group_versions
        .iter()
        .filter(|version| matches!(listing(version), Some((_, Ok(true)))))
        .cloned()
        .collect();
    let first_unread = read.listed.iter().find_map(|(_, got)| got.as_ref().err());
    if read.wanted.is_empty() {
        return if !served.is_empty() {
            Verdict::Served(served)
        } else if let Some(why) = first_unread {
            Verdict::Unverified(*why)
        } else {
            Verdict::NotInGroup
        };
    }
    let mut missing = Vec::new();
    let mut unread = None;
    for version in &read.wanted {
        if !group_versions.contains(version) {
            missing.push(version.clone());
            continue;
        }
        match listing(version) {
            Some((_, Ok(true))) => {}
            Some((_, Ok(false))) => missing.push(version.clone()),
            Some((_, Err(why))) => unread = unread.or(Some(*why)),
            None => unread = unread.or(Some(Unread::Budget)),
        }
    }
    if !missing.is_empty() {
        // Not installed at all, when no version of the group lists it and every one was read.
        let all_read = group_versions
            .iter()
            .all(|version| matches!(listing(version), Some((_, Ok(_)))));
        if served.is_empty() && all_read {
            return Verdict::NotInGroup;
        }
        return Verdict::VersionsMissing { missing, served };
    }
    match unread {
        Some(why) => Verdict::Unverified(why),
        None => Verdict::Served(served),
    }
}

/// What the judgement collects on the way to a finding.
#[derive(Default)]
struct Sink {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unverified: Vec<String>,
    fixes_unverified: Vec<String>,
    grants: Vec<Grant>,
    crd_rows: Vec<Value>,
    operator_rows: Vec<Value>,
    /// Definitions of a missing group, or a group without them, by group.
    missing: BTreeMap<String, Vec<String>>,
}

impl Sink {
    fn fix_once(&mut self, line: String) {
        if !self.fixes_unverified.contains(&line) {
            self.fixes_unverified.push(line);
        }
    }

    fn grant(&mut self, text: String, can_i: String) {
        if !self.grants.iter().any(|have| have.text == text) {
            self.grants.push(Grant { text, can_i });
        }
    }

    fn unread(&mut self, why: Unread, what: &str, grant: Option<(String, String)>) {
        self.unverified
            .push(format!("{what} was not read: {}", why.why()));
        if why == Unread::Forbidden
            && let Some((text, can_i)) = grant
        {
            self.grant(text, can_i);
        }
    }
}

/// The names of a list, the first few and a count of the rest.
fn names(list: &[String]) -> String {
    let head: Vec<String> = list.iter().take(LISTED).map(|n| format!("`{n}`")).collect();
    let mut out = head.join(", ");
    if list.len() > LISTED {
        out.push_str(&format!(" and {} more", list.len() - LISTED));
    }
    out
}

pub(super) fn judge(params: &K8sCrds, found: &Gathered) -> Finding {
    let mut sink = Sink::default();
    let mut served_crds = 0_usize;
    for read in &found.crds {
        if judge_crd(read, &mut sink) {
            served_crds += 1;
        }
    }
    flush_missing(&mut sink);
    let mut quiet = Vec::new();
    for read in &found.operators {
        judge_operator(read, &mut sink, &mut quiet);
    }
    if !found.crds.is_empty() && served_crds == found.crds.len() {
        let noun = if served_crds == 1 {
            "definition is"
        } else {
            "definitions are"
        };
        quiet.insert(
            0,
            format!("{served_crds} {noun} installed at the versions the product needs"),
        );
    }
    sink.notes.push(
        "Definitions are read from API discovery, so installed means served: aggregated APIs and built-in groups count (pods.metrics.k8s.io and deployments.apps pass), a CRD that is being deleted stays listed, and storage versions and deprecation are not visible. A CRD that is still being installed, or whose names conflict, shows as missing. The CustomResourceDefinition objects are not read."
            .to_owned(),
    );

    let Sink {
        mut issues,
        notes,
        unverified,
        fixes_unverified,
        grants,
        crd_rows,
        operator_rows,
        ..
    } = sink;
    // Stable sort: a block before a warning, and each in the order the spec lists them.
    issues.sort_by_key(|issue| std::cmp::Reverse(rank(issue.level)));
    let level = issues.first().map_or(Level::Pass, |issue| issue.level);
    let message = match issues.first() {
        Some(first) if issues.len() > 1 => format!(
            "{} (and {} more, see the notes)",
            first.message,
            issues.len() - 1
        ),
        Some(first) => first.message.clone(),
        None => pass_message(&quiet),
    };
    let mut finding = Finding::new(level, message);
    let mut fixes: Vec<String> = Vec::new();
    for issue in &issues {
        if !fixes.contains(&issue.fix) {
            fixes.push(issue.fix.clone());
        }
    }
    fixes.extend(fixes_unverified);
    if !grants.is_empty() {
        let can_i: Vec<String> = grants.iter().map(|g| g.can_i.clone()).collect();
        let wanted: Vec<String> = grants.iter().map(|g| g.text.clone()).collect();
        fixes.push(fix::grants(&can_i, &wanted));
    }
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for issue in issues.iter().skip(1) {
        finding = finding.with_note(issue.message.clone());
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(
            Partial::new(Vec::new(), unverified.join("; "))
                .with_missing_grants(grants.iter().map(|g| g.text.clone()).collect()),
        );
    }
    finding
        .with_observed(json!({"crds": crd_rows, "operators": operator_rows}))
        .with_expected(expected(params))
}

fn pass_message(quiet: &[String]) -> String {
    let text = quiet.join("; ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Nothing found that stops the install".to_owned(),
    }
}

fn expected(params: &K8sCrds) -> Value {
    let crds: Vec<Value> = params
        .crds
        .iter()
        .flat_map(|list| list.iter())
        .map(|rule| {
            json!({
                "name": rule.name.as_str(),
                "versions": rule.versions.as_ref().map(|list| list.iter().map(|v| v.as_str()).collect::<Vec<_>>()),
            })
        })
        .collect();
    let operators: Vec<Value> = params
        .operators
        .iter()
        .flat_map(|list| list.iter())
        .map(|rule| {
            json!({
                "namespace": rule.namespace.as_str(),
                "deployment": rule.deployment.as_str(),
                "min_version": rule.min_version.as_ref().map(Version::as_str),
            })
        })
        .collect();
    json!({"crds": crds, "operators": operators})
}

// ---- definitions ----------------------------------------------------------------------------------------------

/// Judges one definition. True when it is installed at every version the spec needs.
fn judge_crd(read: &CrdRead, sink: &mut Sink) -> bool {
    let name = &read.name;
    let state = |state: &str, served: &[String]| {
        json!({
            "name": name,
            "state": state,
            "served": served.iter().filter(|v| is_version(v)).collect::<Vec<_>>(),
        })
    };
    let group = read
        .split
        .as_ref()
        .map(|(_, group)| group.clone())
        .unwrap_or_default();
    match verdict(read) {
        Verdict::Served(served) => {
            sink.crd_rows.push(state("served", &served));
            true
        }
        Verdict::GroupMissing => {
            sink.crd_rows.push(state("missing", &[]));
            sink.missing.entry(group).or_default().push(name.clone());
            false
        }
        Verdict::NotInGroup => {
            sink.crd_rows.push(state("missing", &[]));
            sink.missing.entry(group).or_default().push(name.clone());
            false
        }
        Verdict::VersionsMissing { missing, served } => {
            sink.crd_rows.push(state("version_missing", &served));
            let wanted = missing.join(", ");
            let serves: Vec<&String> = served.iter().filter(|v| is_version(v)).collect();
            let tail = if serves.is_empty() {
                String::new()
            } else {
                let list: Vec<&str> = serves.iter().map(|v| v.as_str()).collect();
                format!("; it serves {}", list.join(", "))
            };
            sink.issues.push(Issue {
                level: Level::Fail,
                message: format!("CRD {name} is installed but does not serve {wanted}{tail}"),
                fix: fix::upgrade(&group),
            });
            false
        }
        Verdict::Unverified(why) => {
            sink.crd_rows.push(state("unverified", &[]));
            sink.unread(
                why,
                &format!("whether CRD {name} is installed"),
                Some((
                    "get /apis".to_owned(),
                    "`kubectl auth can-i get /apis`".to_owned(),
                )),
            );
            false
        }
        Verdict::Unsplit => {
            sink.crd_rows.push(state("unverified", &[]));
            sink.unverified.push(format!(
                "CRD {name} has no API group in its name, so it was not looked up"
            ));
            sink.fix_once(fix::crd_name().to_owned());
            false
        }
    }
}

/// Turns the definitions of a missing group into one block per group.
fn flush_missing(sink: &mut Sink) {
    let missing = std::mem::take(&mut sink.missing);
    for (group, list) in missing {
        let message = if list.len() == 1 {
            format!(
                "CRD {} is not installed: the cluster has no definition of it in API group {group}",
                list[0]
            )
        } else {
            format!(
                "{} CRDs of API group {group} are not installed: {}",
                list.len(),
                names(&list)
            )
        };
        sink.issues.push(Issue {
            level: Level::Fail,
            message,
            fix: fix::install(&group),
        });
    }
}

// ---- operators ------------------------------------------------------------------------------------------------

fn judge_operator(read: &OperatorRead, sink: &mut Sink, quiet: &mut Vec<String>) {
    let (ns, name) = (&read.namespace, &read.deployment);
    let row = |state: &str| json!({"namespace": ns, "deployment": name, "state": state});
    match &read.state {
        Fetched::Missing => {
            sink.operator_rows.push(row("missing"));
            sink.issues.push(Issue {
                level: Level::Warn,
                message: format!(
                    "No Deployment named {name} in {ns}; the operator may be a StatefulSet or OLM-managed"
                ),
                fix: fix::operator_missing(ns, name),
            });
        }
        Fetched::Unread(why) => {
            sink.operator_rows.push(row("unverified"));
            sink.unread(
                *why,
                &format!("operator Deployment {name} in namespace {ns}"),
                Some((
                    format!("get deployments.apps/{name} in {ns}"),
                    format!("`kubectl auth can-i get deployments.apps/{name} -n {ns}`"),
                )),
            );
        }
        Fetched::Got(deployment) => judge_found(read, deployment, sink, quiet),
    }
}

fn judge_found(
    read: &OperatorRead,
    deployment: &OperatorDeployment,
    sink: &mut Sink,
    quiet: &mut Vec<String>,
) {
    let (ns, name) = (&read.namespace, &read.deployment);
    let versions = versions_of(deployment, name);
    let have = versions.best();
    let ready = deployment.ready;
    let desired = deployment.desired;
    sink.operator_rows.push(json!({
        "namespace": ns,
        "deployment": name,
        "state": if ready >= desired && desired > 0 { "ready" } else { "not_ready" },
        "desired": desired,
        "ready": ready,
        "version": have.map(super::objects::Tag::text),
        "version_source": have.map(|_| if versions.image.is_some() { "image tag" } else { "label" }),
    }));

    // Readiness: a warning.
    if desired == 0 {
        sink.issues.push(Issue {
            level: Level::Warn,
            message: format!("Operator Deployment {name} in namespace {ns} is scaled to 0"),
            fix: fix::operator_not_ready(ns, name, 0),
        });
    } else if ready < desired {
        sink.issues.push(Issue {
            level: Level::Warn,
            message: format!(
                "Operator Deployment {name} in namespace {ns} has {ready} of {desired} replicas ready"
            ),
            fix: fix::operator_not_ready(ns, name, desired),
        });
    }

    // Version: a block when below the minimum.
    let mut version_note = String::new();
    if let Some(min) = &read.min {
        match have {
            Some(tag) => {
                let order = compare_versions(&tag.version, min);
                // 1.15.0-rc1 sorts below 1.15.0, so an equal number that is a pre-release is below.
                let below = order.is_lt() || (order.is_eq() && tag.pre);
                if below {
                    sink.issues.push(Issue {
                        level: Level::Fail,
                        message: format!(
                            "Operator {name} in namespace {ns} runs {} and the product needs {} or later",
                            tag.text(),
                            min.as_str()
                        ),
                        fix: fix::operator_old(ns, name),
                    });
                } else {
                    version_note = format!(" at {}", tag.text());
                }
            }
            None => {
                let why = if versions.ambiguous {
                    "its containers have different versions and none is named like the Deployment"
                } else {
                    "neither its image tag nor its app.kubernetes.io/version label reads as a version"
                };
                sink.unverified.push(format!(
                    "the version of operator {name} in namespace {ns} was not read: {why}"
                ));
                sink.fix_once(fix::check_version(ns, name));
            }
        }
    }
    note_label_mismatch(&versions, name, ns, sink);
    if ready >= desired && desired > 0 {
        quiet.push(format!(
            "operator {name} in namespace {ns} has {ready} of {desired} replicas ready{version_note}"
        ));
    }
}

/// A note when the image tag and the label name different versions: the image is what runs.
fn note_label_mismatch(versions: &Versions, name: &str, ns: &str, sink: &mut Sink) {
    if let (Some(image), Some(label)) = (&versions.image, &versions.label)
        && image.version != label.version
    {
        sink.notes.push(format!(
            "Operator {name} in namespace {ns} has an image tag of {} and a version label of {}. rdy judges the image tag.",
            image.text(),
            label.text()
        ));
    }
}
