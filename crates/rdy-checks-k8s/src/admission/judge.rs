//! What the answers of the cluster mean for `k8s.admission`: the findings, with fix text, and what could
//! not be read.
//!
//! The rules (03, "k8s.admission"):
//!
//! - A namespace that **enforces** a stricter level than the product needs blocks. A **warn** or **audit**
//!   label stricter than the product needs warns. A label value that is not a level is read the way the API
//!   server reads it: `restricted` for `enforce`, `privileged` for `warn` and `audit`.
//! - No enforce label means the cluster default, which is not readable. That is a note, and for RKE2, whose
//!   hardened profile defaults to `restricted`, it is also "not verified".
//! - OpenShift without a named SCC warns with the SCC text. With a named SCC it passes and says how to bind it.
//! - A policy engine that discovery shows warns, with its name and the API groups that show it.
//! - What could not be read is never a block: the result is partial and `missing_grants` says what to ask
//!   for.

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::K8sAdmission;
use serde_json::{Value, json};

use super::Read;
use super::engines::Found;
use super::fix;
use super::level::{Label, Labels, Need, Standard};

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// What `k8s.admission` takes from the target namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NsFacts {
    pub(super) labels: Labels,
    /// `openshift.io/sa.scc.uid-range`, when it has the shape of one.
    pub(super) uid_range: Option<String>,
}

/// Whether the cluster is OpenShift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Openshift {
    Yes,
    No,
    /// The group list could not be read.
    Unknown,
}

/// What was read, before any judgement.
#[derive(Debug)]
pub(super) struct Gathered {
    /// The namespace judged: the spec's, or the family's.
    pub(super) namespace: Option<String>,
    /// The namespace, read when one is named.
    pub(super) ns: Option<Read<NsFacts>>,
    /// The group list. Only the answer matters here; the groups became `openshift` and `engines`.
    pub(super) groups: Read<()>,
    pub(super) openshift: Openshift,
    pub(super) engines: Vec<Found>,
    /// Whether the SCC the spec names is on the cluster, when the SCC list was read for it.
    pub(super) scc: Option<Read<bool>>,
    /// True when the server says it is RKE2.
    pub(super) rke2: bool,
}

/// One thing that can reject the product's pods.
struct Issue {
    level: Level,
    message: String,
    fix: String,
}

/// A permission the identity lacked: the wire text, and the command that checks it.
struct Grant {
    text: &'static str,
    can_i: &'static str,
}

const GET_NAMESPACES: Grant = Grant {
    text: "get namespaces",
    can_i: "`kubectl auth can-i get namespaces`",
};

const GET_APIS: Grant = Grant {
    text: "get /apis",
    can_i: "`kubectl auth can-i get /apis`",
};

/// Text from the server, safe for a terminal and for a sentence, and cut short.
pub(super) fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    // A backtick would let the text open a command span in the sentence around it.
    let mut out = escape_untrusted(&head).replace('`', "'");
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Fail => 2,
        Level::Warn => 1,
        _ => 0,
    }
}

pub(super) fn judge(params: &K8sAdmission, need: Option<&Need>, found: &Gathered) -> Finding {
    let mut issues: Vec<Issue> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut fixes_unverified: Vec<String> = Vec::new();
    // The sentences of a pass.
    let mut quiet: Vec<String> = Vec::new();
    let ns = found.namespace.as_deref();
    let ns_text = ns.map_or_else(|| "<namespace>".to_owned(), str::to_owned);

    // ---- Pod Security labels ---------------------------------------------------------------------------
    match (need, &found.ns) {
        (None, None) => quiet.push("the spec states no Pod Security level to judge".to_owned()),
        (None, Some(Read::Ok(facts))) => quiet.push(format!(
            "Namespace {ns_text} has Pod Security enforce {}, warn {}, audit {}",
            facts.labels.enforce.word(),
            facts.labels.warn.word(),
            facts.labels.audit.word()
        )),
        (None, Some(other)) => notes.push(format!(
            "The Pod Security labels of namespace {ns_text} were not read ({}).",
            other.why()
        )),
        (Some(_), None) => {
            unverified.push(
                "the Pod Security labels were not read: the spec names no namespace".to_owned(),
            );
            fixes_unverified.push(fix::name_the_namespace().to_owned());
        }
        (Some(_), Some(Read::Forbidden)) => {
            unverified.push(format!(
                "the Pod Security labels of namespace {ns_text} were not read: the identity may not read it"
            ));
            grants.push(GET_NAMESPACES);
        }
        (Some(_), Some(Read::Missing)) => {
            quiet.push(format!("namespace {ns_text} does not exist yet"));
            notes.push(format!(
                "Namespace {ns_text} does not exist, so its Pod Security labels were not read. A new namespace takes the cluster default, which rdy cannot read. If the installer creates it with labels, those apply."
            ));
        }
        (Some(need), Some(Read::Ok(facts))) => {
            let mut sink = Sink::default();
            judge_labels(need, facts, &ns_text, found, &mut sink);
            issues.append(&mut sink.issues);
            notes.append(&mut sink.notes);
            unverified.append(&mut sink.unverified);
            quiet.append(&mut sink.quiet);
        }
        (Some(_), Some(other)) => unverified.push(format!(
            "the Pod Security labels of namespace {ns_text} were not read: {}",
            other.why()
        )),
    }

    // ---- OpenShift and policy engines -------------------------------------------------------------------
    match &found.groups {
        Read::Ok(()) => {}
        other => {
            unverified.push(format!(
                "policy engines and OpenShift were not checked: the API group list could not be read ({})",
                other.why()
            ));
            if matches!(other, Read::Forbidden) {
                grants.push(GET_APIS);
            }
        }
    }
    let scc = params.scc.as_ref().map(|scc| scc.as_str());
    match (found.openshift, scc) {
        (Openshift::Yes, Some(scc)) => {
            quiet.push(format!("OpenShift, and the product documents the SCC {scc}"));
            notes.push(fix::bind_scc(scc, ns));
            match &found.scc {
                Some(Read::Ok(true)) => notes.push(format!("The SCC `{scc}` exists on this cluster.")),
                Some(Read::Ok(false)) => notes.push(format!(
                    "The SCC `{scc}` is not on this cluster. That is expected if the product's installer creates it. If not, ask the vendor which SCC the install needs."
                )),
                Some(other) => notes.push(format!(
                    "rdy could not list the SCCs ({}), so it did not check that `{scc}` exists.",
                    other.why()
                )),
                None => {}
            }
        }
        (Openshift::Yes, None) => issues.push(Issue {
            level: Level::Warn,
            message: "This is OpenShift: security context constraints decide whether the product's pods are admitted, and the spec names none".to_owned(),
            fix: fix::openshift(ns),
        }),
        (Openshift::No, Some(scc)) => notes.push(format!(
            "The spec names the SCC `{scc}`. It is ignored: this cluster is not OpenShift."
        )),
        _ => {}
    }
    if found.openshift == Openshift::Yes
        && let Some(Read::Ok(facts)) = &found.ns
        && let Some(range) = &facts.uid_range
    {
        notes.push(format!(
            "Namespace {ns_text} allocates the UID range {range}. Under `restricted-v2` a pod that sets `runAsUser` outside it is rejected."
        ));
    }
    if !found.engines.is_empty() {
        let names: Vec<&str> = found.engines.iter().map(|engine| engine.engine).collect();
        let groups: Vec<&str> = found
            .engines
            .iter()
            .flat_map(|engine| engine.groups.iter().map(|group| group.group))
            .collect();
        let named: Vec<String> = found
            .engines
            .iter()
            .map(|engine| {
                let groups: Vec<&str> = engine.groups.iter().map(|group| group.group).collect();
                format!("{} ({})", engine.engine, groups.join(", "))
            })
            .collect();
        issues.push(Issue {
            level: Level::Warn,
            message: format!(
                "Policy engine found: {}. Its policies can reject the product's pods",
                named.join("; ")
            ),
            fix: fix::engines(&names, &groups, ns),
        });
        for engine in &found.engines {
            for group in &engine.groups {
                if group.kinds.is_empty() {
                    continue;
                }
                let kinds: Vec<String> = group.kinds.iter().map(|kind| shown(kind)).collect();
                let more = if group.more > 0 {
                    format!(" and {} more", group.more)
                } else {
                    String::new()
                };
                notes.push(format!(
                    "{} serves these kinds in {}: {}{more}.",
                    engine.engine,
                    group.group,
                    kinds.join(", ")
                ));
            }
        }
        notes.push(
            "A group shows that the engine is installed. It does not show which policies enforce, and CRDs can outlive an uninstall."
                .to_owned(),
        );
    } else if matches!(found.groups, Read::Ok(())) && found.openshift == Openshift::No {
        quiet.push("no policy engine or OpenShift found".to_owned());
    }
    notes.push(
        "Admission webhooks and ValidatingAdmissionPolicy are not evaluated by this version."
            .to_owned(),
    );

    // ---- The finding -----------------------------------------------------------------------------------
    issues.sort_by_key(|issue| std::cmp::Reverse(rank(issue.level)));
    let level = issues.first().map_or(Level::Pass, |issue| issue.level);
    let message = match issues.first() {
        Some(first) if issues.len() > 1 => {
            format!(
                "{} (and {} more, see the notes)",
                first.message,
                issues.len() - 1
            )
        }
        Some(first) => first.message.clone(),
        None => pass_message(&quiet),
    };
    let mut finding = Finding::new(level, message);
    let mut fixes: Vec<String> = issues.iter().map(|issue| issue.fix.clone()).collect();
    fixes.extend(fixes_unverified);
    if !grants.is_empty() {
        let can_i: Vec<String> = grants.iter().map(|g| g.can_i.to_owned()).collect();
        let wanted: Vec<String> = grants.iter().map(|g| g.text.to_owned()).collect();
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
                .with_missing_grants(grants.iter().map(|g| g.text.to_owned()).collect()),
        );
    }
    finding
        .with_observed(observed(need, found))
        .with_expected(expected(params, need, ns))
}

/// The sentences of a pass, as one.
fn pass_message(quiet: &[String]) -> String {
    let text = quiet.join("; ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Nothing found that rejects the product's pods".to_owned(),
    }
}

/// What one part of the judgement adds to the finding.
#[derive(Default)]
struct Sink {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unverified: Vec<String>,
    quiet: Vec<String>,
}

/// The labels of the namespace against the level the product needs.
fn judge_labels(need: &Need, facts: &NsFacts, ns: &str, found: &Gathered, out: &mut Sink) {
    let Sink {
        issues,
        notes,
        unverified,
        quiet,
    } = out;
    let labels = &facts.labels;
    let level = need.level.name();
    match labels.enforce {
        Label::Absent => {
            quiet.push(format!(
                "namespace {ns} sets no Pod Security enforce label, and the product needs {level}"
            ));
            // The default only matters when it could be stricter than what the product needs.
            if need.level < Standard::Restricted {
                if found.openshift == Openshift::Yes {
                    notes.push("On OpenShift the global default enforces `privileged` and warns and audits at `restricted`. The SCCs are the real gate.".to_owned());
                } else {
                    notes.push(format!(
                        "Namespace {ns} has no enforce label, so it takes the cluster default from the API server's configuration. rdy cannot read that default (cluster default not readable)."
                    ));
                }
                if found.rke2 {
                    unverified.push("the cluster default was not read: RKE2 with the CIS profile enforces `restricted` everywhere but a few system namespaces".to_owned());
                }
            }
        }
        Label::Valid(have) if have > need.level => issues.push(Issue {
            level: Level::Fail,
            message: format!(
                "Namespace {ns} enforces {}, and the product needs {level}",
                have.name()
            ),
            fix: fix::enforce(ns, have, false, need),
        }),
        Label::Valid(have) => quiet.push(format!(
            "namespace {ns} enforces {}, and the product needs {level}",
            have.name()
        )),
        Label::Invalid => {
            notes.push(format!(
                "The enforce label of namespace {ns} is not a Pod Security level. The API server reads it as `restricted`. Set it to `privileged`, `baseline` or `restricted`."
            ));
            if Standard::Restricted > need.level {
                issues.push(Issue {
                    level: Level::Fail,
                    message: format!(
                        "Namespace {ns} has an invalid Pod Security enforce label, which the API server reads as restricted, and the product needs {level}"
                    ),
                    fix: fix::enforce(ns, Standard::Restricted, true, need),
                });
            } else {
                quiet.push(format!(
                    "namespace {ns} has an invalid enforce label, read as restricted, which the product fits"
                ));
            }
        }
    }
    for (mode, label) in [("warn", labels.warn), ("audit", labels.audit)] {
        if let Label::Valid(have) = label
            && have > need.level
        {
            // On OpenShift a controller syncs these two labels from the SCCs the service accounts of the
            // namespace may use, so they say what would warn, not what is rejected. The SCC is the gate.
            if found.openshift == Openshift::Yes {
                notes.push(format!(
                    "Namespace {ns} sets {mode} to {}. On OpenShift that label is synced from the SCCs, so pods are not rejected for it.",
                    have.name()
                ));
                continue;
            }
            // The enforce fix comes first and the person has the whole picture in one place: the warn and
            // audit labels are said in a note, with their own command.
            if issues.iter().any(|issue| issue.level == Level::Fail) {
                notes.push(fix::soften(ns, mode, have, need));
                continue;
            }
            let effect = if mode == "warn" {
                "pods still start, and the person who installs sees a warning"
            } else {
                "pods still start, and each one adds an audit log entry"
            };
            issues.push(Issue {
                level: Level::Warn,
                message: format!(
                    "Namespace {ns} sets {mode} to {}, and the product needs {level}: {effect}",
                    have.name()
                ),
                fix: fix::soften(ns, mode, have, need),
            });
        }
    }
}

fn observed(need: Option<&Need>, found: &Gathered) -> Value {
    let (state, labels) = match &found.ns {
        None => ("not_named", None),
        Some(Read::Ok(facts)) => ("read", Some(facts)),
        Some(Read::Missing) => ("missing", None),
        Some(Read::Forbidden) => ("forbidden", None),
        Some(_) => ("unreadable", None),
    };
    let pod_security = labels.map(|facts| {
        json!({
            "enforce": facts.labels.enforce.word(),
            "audit": facts.labels.audit.word(),
            "warn": facts.labels.warn.word(),
            "enforce_version": facts.labels.enforce_version.word(),
        })
    });
    let openshift = match found.openshift {
        Openshift::Yes => json!(true),
        Openshift::No => json!(false),
        Openshift::Unknown => Value::Null,
    };
    let engines = if matches!(found.groups, Read::Ok(())) {
        Value::Array(
            found
                .engines
                .iter()
                .map(|engine| {
                    json!({
                        "name": engine.engine,
                        "groups": engine.groups.iter().map(|group| group.group).collect::<Vec<_>>(),
                        "kinds": engine
                            .groups
                            .iter()
                            .flat_map(|group| group.kinds.iter().map(|kind| shown(kind)))
                            .collect::<Vec<_>>(),
                    })
                })
                .collect(),
        )
    } else {
        Value::Null
    };
    let scc = found.scc.as_ref().map(|read| match read {
        Read::Ok(present) => json!(present),
        _ => Value::Null,
    });
    json!({
        "namespace": found.namespace,
        "namespace_read": state,
        "pod_security": pod_security,
        "need": need.map(|need| json!({"level": need.level.name(), "uses": need.uses})),
        "openshift": openshift,
        "uid_range": labels.and_then(|facts| facts.uid_range.clone()),
        "scc_on_cluster": scc,
        "policy_engines": engines,
    })
}

fn expected(params: &K8sAdmission, need: Option<&Need>, ns: Option<&str>) -> Value {
    json!({
        "needs_level": need.map(|need| need.level.name()),
        "namespace": ns,
        "scc": params.scc.as_ref().map(|scc| scc.as_str()),
    })
}
