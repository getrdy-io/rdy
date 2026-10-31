//! What the answers of the cluster mean for `k8s.namespace`: the findings, with fix text, and what could
//! not be read.
//!
//! The rules (03, "k8s.namespace"):
//!
//! - A namespace that is `Terminating` blocks. A missing namespace that the identity may not create blocks.
//! - A quota with less left than a `quota_needs` amount blocks, and only unscoped quotas are judged: a
//!   scoped one is listed as "not evaluated" and makes the result partial.
//! - A `Container` or `Pod` memory `max` in a limit range below `container_max_memory` blocks. A
//!   `Container` default limit below it is a note: it fails the install only if the product sets a memory
//!   request and no limit, which the spec does not say.
//! - What could not be read is never a block: the result is partial and `missing_grants` says what to ask
//!   for.

use std::collections::BTreeMap;

use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::K8sNamespace;
use serde_json::{Value, json};

use super::Read;
use super::amount::{Amount, show};
use super::fix;
use super::objects::{Limits, Page, Quota};

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// What `k8s.namespace` takes from the target namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NsFacts {
    /// True when the phase is `Terminating` or a deletion time is set.
    pub(super) terminating: bool,
    /// The types of the conditions that are `True`, such as `NamespaceContentRemaining`.
    pub(super) conditions: Vec<String>,
}

/// Which review asks whether the identity may create the namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Via {
    /// `create namespaces`. `sure` is false when the group list could not be read, so the cluster may be
    /// OpenShift, where this review is the wrong question.
    Namespaces { sure: bool },
    /// `create projectrequests` in `project.openshift.io`.
    ProjectRequests,
}

/// The answer of a `SelfSubjectAccessReview`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    Allowed,
    /// Not allowed. The reason is the server's text.
    NotAllowed(String),
    /// The review could not say, and why.
    Unknown(String),
}

/// The review of the create rights, for a namespace that is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Create {
    pub(super) via: Via,
    pub(super) answer: Answer,
}

/// What was read, before any judgement.
#[derive(Debug)]
pub(super) struct Gathered {
    /// The namespace judged: the spec's, or the family's.
    pub(super) namespace: Option<String>,
    /// The namespace, read when one is named.
    pub(super) ns: Option<Read<NsFacts>>,
    /// The quotas of the namespace. `None` when they were not asked for.
    pub(super) quotas: Option<Read<Page<Quota>>>,
    /// The limit ranges of the namespace. `None` when they were not asked for.
    pub(super) limits: Option<Read<Page<Limits>>>,
    /// The create review, for a missing namespace.
    pub(super) create: Option<Create>,
}

impl Gathered {
    /// Nothing was read, because no namespace is named.
    pub(super) fn unnamed() -> Self {
        Self {
            namespace: None,
            ns: None,
            quotas: None,
            limits: None,
            create: None,
        }
    }
}

/// Reads the status of an access review. An explicit deny wins over an evaluation error.
pub(super) fn answer_of(status: &SubjectAccessReviewStatus) -> Answer {
    let reason = status.reason.clone().unwrap_or_default();
    if status.allowed {
        Answer::Allowed
    } else if status.denied == Some(true) {
        Answer::NotAllowed(reason)
    } else if status
        .evaluation_error
        .as_deref()
        .is_some_and(|error| !error.is_empty())
    {
        Answer::Unknown("the authorizer reported an error".to_owned())
    } else {
        Answer::NotAllowed(reason)
    }
}

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

/// A permission the identity lacked: the wire text, and the command that checks it.
struct Grant {
    text: &'static str,
    can_i: &'static str,
}

const GET_NAMESPACES: Grant = Grant {
    text: "get namespaces",
    can_i: "`kubectl auth can-i get namespaces`",
};

const LIST_QUOTAS: Grant = Grant {
    text: "list resourcequotas",
    can_i: "`kubectl auth can-i list resourcequotas -n <namespace>`",
};

const LIST_LIMITS: Grant = Grant {
    text: "list limitranges",
    can_i: "`kubectl auth can-i list limitranges -n <namespace>`",
};

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

/// A quota resource name in its one form: `cpu` is `requests.cpu`, and so on.
pub(super) fn normalize(resource: &str) -> String {
    if matches!(resource, "cpu" | "memory" | "ephemeral-storage")
        || resource.starts_with("hugepages-")
    {
        format!("requests.{resource}")
    } else {
        resource.to_owned()
    }
}

/// True when the last part of a quota resource name counts bytes.
pub(super) fn counts_bytes(resource: &str) -> bool {
    let last = resource.rsplit(['.', '/']).next().unwrap_or(resource);
    matches!(last, "memory" | "storage" | "ephemeral-storage") || last.starts_with("hugepages-")
}

/// One amount the product needs from a quota.
struct QuotaNeed {
    resource: String,
    norm: String,
    text: String,
    amount: Option<Amount>,
    bytes: bool,
}

fn quota_needs(params: &K8sNamespace) -> Vec<QuotaNeed> {
    params
        .quota_needs
        .iter()
        .flat_map(|map| map.iter())
        .map(|(resource, amount)| QuotaNeed {
            resource: resource.as_str().to_owned(),
            norm: normalize(resource.as_str()),
            text: amount.as_str().to_owned(),
            amount: Amount::parse(amount.as_str()),
            bytes: counts_bytes(resource.as_str()),
        })
        .collect()
}

/// The memory a container needs, from the spec: its text and its amount.
fn container_memory(params: &K8sNamespace) -> Option<(String, Amount)> {
    let size = params.limit_needs.as_ref()?.container_max_memory?;
    Some((size.to_string(), Amount::from_bytes(size.bytes())))
}

/// What the judgement collects on the way to a finding.
#[derive(Default)]
struct Sink {
    issues: Vec<Issue>,
    notes: Vec<String>,
    unverified: Vec<String>,
    fixes_unverified: Vec<String>,
    quiet: Vec<String>,
    grants: Vec<&'static Grant>,
    /// The rows of `observed.quotas.checks`.
    quota_rows: Vec<Value>,
}

impl Sink {
    fn grant(&mut self, grant: &'static Grant) {
        if !self.grants.iter().any(|have| have.text == grant.text) {
            self.grants.push(grant);
        }
    }
}

pub(super) fn judge(params: &K8sNamespace, found: &Gathered) -> Finding {
    let mut sink = Sink::default();
    let needs = quota_needs(params);
    let memory = container_memory(params);

    match found.namespace.as_deref() {
        None => {
            sink.unverified
                .push("the spec names no namespace, so nothing was read".to_owned());
            sink.fixes_unverified
                .push(fix::name_the_namespace().to_owned());
        }
        Some(ns) => {
            judge_namespace(ns, found, &mut sink);
            if let Some(quotas) = &found.quotas {
                judge_quotas(ns, quotas, &needs, &mut sink);
            }
            if let Some(limits) = &found.limits {
                judge_limits(ns, limits, memory.as_ref(), &mut sink);
            }
        }
    }

    let Sink {
        mut issues,
        mut notes,
        unverified,
        fixes_unverified,
        quiet,
        grants,
        quota_rows,
    } = sink;
    notes.push(
        "Only the ResourceQuota and LimitRange objects of the namespace are read. An OpenShift ClusterResourceQuota is not evaluated."
            .to_owned(),
    );
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
        .with_observed(observed(found, quota_rows))
        .with_expected(expected(params, found.namespace.as_deref()))
}

/// The sentences of a pass, as one.
fn pass_message(quiet: &[String]) -> String {
    let text = quiet.join("; ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => "Nothing found that stops the install".to_owned(),
    }
}

// ---- the namespace --------------------------------------------------------------------------------------------

fn judge_namespace(ns: &str, found: &Gathered, sink: &mut Sink) {
    match &found.ns {
        Some(Read::Ok(facts)) if facts.terminating => {
            sink.issues.push(Issue {
                level: Level::Fail,
                message: format!(
                    "Namespace {ns} is Terminating: it is being deleted and takes no new objects"
                ),
                fix: fix::terminating(ns),
            });
            if !facts.conditions.is_empty() {
                let shown: Vec<String> =
                    facts.conditions.iter().take(8).map(|c| shown(c)).collect();
                sink.notes.push(format!(
                    "Namespace {ns} reports these conditions: {}.",
                    shown.join(", ")
                ));
            }
        }
        Some(Read::Ok(_)) => sink
            .quiet
            .push(format!("namespace {ns} exists and is active")),
        Some(Read::Missing) => judge_create(ns, found.create.as_ref(), sink),
        Some(Read::Forbidden) => {
            sink.unverified.push(format!(
                "whether namespace {ns} exists and is active was not read: the identity may not read it"
            ));
            sink.grant(&GET_NAMESPACES);
        }
        Some(other) => sink.unverified.push(format!(
            "whether namespace {ns} exists and is active was not read: {}",
            other.why()
        )),
        None => {}
    }
}

fn judge_create(ns: &str, create: Option<&Create>, sink: &mut Sink) {
    let Some(create) = create else {
        sink.unverified.push(format!(
            "namespace {ns} does not exist and the right to create it was not checked"
        ));
        return;
    };
    match (&create.answer, create.via) {
        (Answer::Allowed, via) => {
            sink.quiet.push(format!(
                "namespace {ns} does not exist yet, and this identity may create it"
            ));
            sink.notes.push(fix::create_it(ns, via));
            sink.notes.push(
                "A new namespace has no quota or limit range of its own yet. Ones the platform team adds when a namespace is created cannot be seen before it exists."
                    .to_owned(),
            );
        }
        (Answer::NotAllowed(reason), Via::Namespaces { sure: false }) => {
            sink.unverified.push(format!(
                "namespace {ns} does not exist and this identity may not create namespaces, but the API group list could not be read, so rdy cannot tell whether this is OpenShift, where the question is project requests{}",
                reason_suffix(reason)
            ));
            sink.fixes_unverified.push(fix::ask_platform(ns, create.via));
        }
        (Answer::NotAllowed(reason), via) => {
            let what = match via {
                Via::ProjectRequests => "request it as a project",
                Via::Namespaces { .. } => "create it",
            };
            sink.issues.push(Issue {
                level: Level::Fail,
                message: format!(
                    "Namespace {ns} does not exist, and this identity may not {what}"
                ),
                fix: fix::ask_platform(ns, via),
            });
            if !reason.is_empty() {
                sink.notes.push(format!(
                    "The cluster said: {}.",
                    shown(reason)
                ));
            }
        }
        (Answer::Unknown(why), _) => sink.unverified.push(format!(
            "namespace {ns} does not exist and rdy could not check whether this identity may create it ({})",
            shown(why)
        )),
    }
}

fn reason_suffix(reason: &str) -> String {
    if reason.is_empty() {
        String::new()
    } else {
        format!(" (the cluster said: {})", shown(reason))
    }
}

// ---- quotas ---------------------------------------------------------------------------------------------------

fn judge_quotas(ns: &str, quotas: &Read<Page<Quota>>, needs: &[QuotaNeed], sink: &mut Sink) {
    let page = match quotas {
        Read::Ok(page) => page,
        other => {
            if needs.is_empty() {
                sink.notes.push(format!(
                    "The quotas of namespace {ns} were not listed ({}).",
                    other.why()
                ));
            } else {
                sink.unverified.push(format!(
                    "quota headroom in namespace {ns} was not checked: the quotas could not be listed ({})",
                    other.why()
                ));
                if matches!(other, Read::Forbidden) {
                    sink.grant(&LIST_QUOTAS);
                }
            }
            return;
        }
    };
    if page.cut {
        let text = "the namespace has more than 500 quotas and only the first 500 were read";
        if needs.is_empty() {
            sink.notes.push(format!(
                "Namespace {ns} has more than 500 quotas; only the first 500 were read."
            ));
        } else {
            sink.unverified.push(text.to_owned());
        }
    }
    // Every quota is listed, scoped ones as "not evaluated".
    for quota in page.items.iter().filter(|quota| quota.scoped) {
        let scopes: Vec<String> = quota.scopes.iter().map(|scope| shown(scope)).collect();
        let scope_text = if scopes.is_empty() {
            "a scope".to_owned()
        } else {
            scopes.join(", ")
        };
        sink.notes.push(format!(
            "Quota {} has {scope_text}, so it applies only to the pods it selects. Not evaluated.",
            shown(&quota.name)
        ));
    }
    if needs.is_empty() {
        let plain = page.items.iter().filter(|quota| !quota.scoped).count();
        if plain > 0 {
            let names: Vec<String> = page
                .items
                .iter()
                .filter(|quota| !quota.scoped)
                .take(5)
                .map(|quota| shown(&quota.name))
                .collect();
            sink.notes.push(format!(
                "Namespace {ns} has {plain} unscoped quota(s): {}. The spec states no quota need, so none was judged.",
                names.join(", ")
            ));
        }
        return;
    }

    let mut evaluated = 0usize;
    let mut unscoped_limit = false;
    for need in needs {
        let Some(wanted) = need.amount else {
            sink.unverified.push(format!(
                "the amount {} for {} in the spec was not understood",
                shown(&need.text),
                shown(&need.resource)
            ));
            continue;
        };
        for quota in &page.items {
            for (key, hard_text) in quota
                .hard
                .iter()
                .filter(|(key, _)| normalize(key) == need.norm)
            {
                if quota.scoped {
                    sink.unverified.push(format!(
                        "quota {} is scoped and limits {}, so it was not evaluated",
                        shown(&quota.name),
                        shown(&need.resource)
                    ));
                    continue;
                }
                unscoped_limit = true;
                let used_text = quota.used.as_ref().and_then(|used| used.get(key));
                let (Some(hard), Some(used)) = (
                    Amount::parse(hard_text),
                    used_text.and_then(|text| Amount::parse(text)),
                ) else {
                    sink.unverified.push(format!(
                        "quota {} limits {}, but its amounts were not readable (limit {}, used {})",
                        shown(&quota.name),
                        shown(&need.resource),
                        shown(hard_text),
                        used_text.map_or_else(|| "not reported".to_owned(), |text| shown(text))
                    ));
                    continue;
                };
                evaluated += 1;
                let left = hard.minus(used);
                let enough = wanted <= left;
                let left_text = show(left.at_least_zero(), need.bytes);
                // `hard` and `used` parsed, so their text holds only digits, a dot, a sign and a suffix.
                sink.quota_rows.push(json!({
                    "resource": need.resource,
                    "quota": shown(&quota.name),
                    "limit": hard_text,
                    "used": used_text,
                    "left": left_text,
                    "needed": need.text,
                    "enough": enough,
                }));
                if !enough {
                    sink.issues.push(Issue {
                        level: Level::Fail,
                        message: format!(
                            "Quota {} in {ns} leaves {left_text} of {} ({hard_text} allowed, {} used), and the product needs {}",
                            shown(&quota.name),
                            need.resource,
                            used_text.map_or("?", |text| text.as_str()),
                            need.text
                        ),
                        fix: fix::quota(&quota.name, ns, &need.resource, &left_text, hard_text, used_text.map_or("?", |text| text.as_str()), &need.text),
                    });
                }
            }
        }
    }
    if evaluated > 0 && !sink.issues.iter().any(|issue| issue.level == Level::Fail) {
        sink.quiet
            .push("the quotas leave room for what the product needs".to_owned());
    } else if !unscoped_limit && sink.unverified.is_empty() {
        sink.quiet
            .push("no quota in the namespace limits what the product needs".to_owned());
    }
}

// ---- limit ranges ---------------------------------------------------------------------------------------------

fn judge_limits(
    ns: &str,
    limits: &Read<Page<Limits>>,
    memory: Option<&(String, Amount)>,
    sink: &mut Sink,
) {
    let page = match limits {
        Read::Ok(page) => page,
        other => {
            if memory.is_none() {
                sink.notes.push(format!(
                    "The limit ranges of namespace {ns} were not listed ({}).",
                    other.why()
                ));
            } else {
                sink.unverified.push(format!(
                    "limit ranges in namespace {ns} were not checked: they could not be listed ({})",
                    other.why()
                ));
                if matches!(other, Read::Forbidden) {
                    sink.grant(&LIST_LIMITS);
                }
            }
            return;
        }
    };
    if page.cut {
        if memory.is_none() {
            sink.notes.push(format!(
                "Namespace {ns} has more than 500 limit ranges; only the first 500 were read."
            ));
        } else {
            sink.unverified.push(
                "the namespace has more than 500 limit ranges and only the first 500 were read"
                    .to_owned(),
            );
        }
    }
    let Some((need_text, need)) = memory else {
        if !page.items.is_empty() {
            let names: Vec<String> = page.items.iter().take(5).map(|r| shown(&r.name)).collect();
            sink.notes.push(format!(
                "Namespace {ns} has {} limit range(s): {}. The spec states no limit need, so none was judged.",
                page.items.len(),
                names.join(", ")
            ));
        }
        return;
    };
    let before = sink.issues.len();
    let mut unreadable = false;
    for range in &page.items {
        let mut warned = false;
        for item in &range.items {
            let kind = match item.kind.as_str() {
                "Container" => "container",
                "Pod" => "pod",
                _ => continue,
            };
            if let Some(max_text) = &item.memory.max {
                match Amount::parse(max_text) {
                    Some(max) if *need > max => sink.issues.push(Issue {
                        level: Level::Fail,
                        message: format!(
                            "LimitRange {} in {ns} caps a {kind} at {} of memory, and the product's largest container needs {need_text}",
                            shown(&range.name),
                            show(max, true)
                        ),
                        fix: fix::limit_max(&range.name, ns, kind, &show(max, true), need_text),
                    }),
                    Some(_) => {}
                    None => unreadable = true,
                }
            }
            if kind == "container"
                && !warned
                && let Some(default_text) = &item.memory.default
            {
                match Amount::parse(default_text) {
                    Some(default) if *need > default => {
                        // The spec does not say whether the product sets limits, so this is a note.
                        warned = true;
                        sink.notes.push(fix::limit_default(
                            &range.name,
                            ns,
                            &show(default, true),
                            need_text,
                        ));
                    }
                    Some(_) => {}
                    None => unreadable = true,
                }
            }
        }
    }
    if unreadable {
        sink.unverified
            .push("a limit range holds a memory amount that rdy could not read".to_owned());
    }
    if sink.issues.len() == before && !unreadable {
        sink.quiet.push(if page.items.is_empty() {
            "no limit range in the namespace".to_owned()
        } else {
            format!("the limit ranges allow a container of {need_text}")
        });
    }
}

// ---- observed and expected --------------------------------------------------------------------------------------

fn read_word<T>(read: &Read<T>) -> &'static str {
    match read {
        Read::Ok(_) => "read",
        Read::Missing => "missing",
        Read::Forbidden => "forbidden",
        Read::Unreadable(_) => "unreadable",
        Read::Refused => "refused",
        Read::OutOfTime => "out_of_time",
    }
}

fn observed(found: &Gathered, quota_rows: Vec<Value>) -> Value {
    let state = match &found.ns {
        None => "not_named",
        Some(Read::Ok(facts)) if facts.terminating => "terminating",
        Some(Read::Ok(_)) => "active",
        Some(Read::Missing) => "missing",
        Some(Read::Forbidden) => "forbidden",
        Some(_) => "unreadable",
    };
    let conditions: Vec<String> = match &found.ns {
        Some(Read::Ok(facts)) => facts.conditions.iter().take(8).map(|c| shown(c)).collect(),
        _ => Vec::new(),
    };
    let create = found.create.as_ref().map(|create| {
        json!({
            "via": match create.via {
                Via::ProjectRequests => "projectrequests",
                Via::Namespaces { .. } => "namespaces",
            },
            "answer": match create.answer {
                Answer::Allowed => "allowed",
                Answer::NotAllowed(_) => "not_allowed",
                Answer::Unknown(_) => "unknown",
            },
        })
    });
    let quotas = found.quotas.as_ref().map(|read| match read {
        Read::Ok(page) => json!({
            "read": "read",
            "count": page.items.len(),
            "cut": page.cut,
            "scoped": page.items.iter().filter(|q| q.scoped).map(|q| shown(&q.name)).collect::<Vec<_>>(),
            "checks": quota_rows,
        }),
        other => json!({"read": read_word(other)}),
    });
    let limits = found.limits.as_ref().map(|read| match read {
        Read::Ok(page) => json!({
            "read": "read",
            "count": page.items.len(),
            "cut": page.cut,
        }),
        other => json!({"read": read_word(other)}),
    });
    json!({
        "namespace": found.namespace,
        "namespace_state": state,
        "conditions": conditions,
        "create": create,
        "quotas": quotas,
        "limit_ranges": limits,
    })
}

fn expected(params: &K8sNamespace, ns: Option<&str>) -> Value {
    let quota_needs: Option<BTreeMap<&str, &str>> = params.quota_needs.as_ref().map(|map| {
        map.iter()
            .map(|(resource, amount)| (resource.as_str(), amount.as_str()))
            .collect()
    });
    json!({
        "namespace": ns,
        "quota_needs": quota_needs,
        "container_max_memory": params
            .limit_needs
            .as_ref()
            .and_then(|needs| needs.container_max_memory)
            .map(|size| size.to_string()),
    })
}
