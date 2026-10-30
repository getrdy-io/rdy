//! Turns what `k8s.rbac` read into a finding. A pure function, so the unit tests and the fixture tests call
//! the same code.

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_spec::check::K8sRbac;
use serde_json::{Map, Value, json};

use super::ask::{Ask, MAX_REVIEWS};
use super::fix;
use super::rules::RulesView;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 160;

/// How many items a sentence lists before it counts the rest.
const LISTED: usize = 3;

/// How many entries a list of the observed value keeps.
const OBSERVED_ITEMS: usize = 25;

/// Text from the server or the cluster, safe for a terminal and cut to `max` characters.
pub(super) fn shown(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max).collect();
    // A backtick would let the text open a command span in the sentence around it.
    let mut out = escape_untrusted(&head).replace('`', "'");
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// What the server said about one permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    /// `allowed: true`.
    Allowed,
    /// `allowed: false`, no explicit deny and no evaluation error: no rule grants it.
    NotAllowed { reason: String },
    /// `denied: true`: an authorizer said no, and a role cannot change that.
    Denied { reason: String },
    /// `allowed: false` with an `evaluationError`: an authorizer failed, so the answer is not reliable.
    Unclear { reason: String },
    /// The review was not asked, or the server could not answer it.
    NotEvaluated(Why),
}

impl Answer {
    /// True for an answer that means the permission is missing.
    fn is_missing(&self) -> bool {
        matches!(self, Self::NotAllowed { .. } | Self::Denied { .. })
    }

    /// True for any answer that is not a yes and not a gap in evidence.
    fn is_negative(&self) -> bool {
        self.is_missing() || matches!(self, Self::Unclear { .. })
    }

    /// The word of the observed value.
    fn wire(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::NotAllowed { .. } => "not_allowed",
            Self::Denied { .. } => "denied",
            Self::Unclear { .. } => "unclear",
            Self::NotEvaluated(_) => "not_evaluated",
        }
    }

    /// A few words for a sentence.
    fn short(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::NotAllowed { .. } => "not allowed",
            Self::Denied { .. } => "denied by an authorizer",
            Self::Unclear { .. } => "could not be fully evaluated",
            Self::NotEvaluated(_) => "not evaluated",
        }
    }

    /// The sentence for the notes, with the server's reason.
    fn long(&self) -> String {
        let (lead, reason) = match self {
            Self::NotAllowed { reason } => ("not allowed, no rule grants it", reason),
            Self::Denied { reason } => (
                "explicitly denied (denied: true) by an authorizer, so adding a role cannot fix it",
                reason,
            ),
            Self::Unclear { reason } => (
                "not allowed by RBAC, and an authorizer reported an error (evaluationError), so the answer may be wrong",
                reason,
            ),
            Self::Allowed => ("allowed", &String::new()),
            Self::NotEvaluated(why) => return why.text(),
        };
        if reason.is_empty() {
            lead.to_owned()
        } else {
            format!("{lead}. The server said: {}", shown(reason, SHOWN))
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::NotAllowed { reason } | Self::Denied { reason } | Self::Unclear { reason } => {
                Some(reason.as_str()).filter(|reason| !reason.is_empty())
            }
            _ => None,
        }
    }
}

/// Why a review gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Why {
    /// 403: the identity may not create access reviews.
    Forbidden,
    /// 404: the server has no such API.
    Missing,
    /// Any other status of the server.
    Status(u16),
    /// The server answered, and the answer had no status to read.
    NoStatus,
    /// The check ran out of time before it asked.
    OutOfTime,
    /// The identity may not impersonate the `as:` user. The text is the ask it lacks.
    Impersonate(String),
}

impl Why {
    pub(super) fn text(&self) -> String {
        match self {
            Self::Forbidden => "the identity may not create access reviews".to_owned(),
            Self::Missing => "the server has no access review API".to_owned(),
            Self::Status(code) => format!("the server answered {code}"),
            Self::NoStatus => "the server's answer had no status".to_owned(),
            Self::OutOfTime => "rdy ran out of time".to_owned(),
            Self::Impersonate(ask) => format!("the identity may not `{ask}`"),
        }
    }

    /// The grant that would remove the gap, if a grant would.
    fn grant(&self) -> Option<String> {
        match self {
            Self::Forbidden => {
                Some("create selfsubjectaccessreviews.authorization.k8s.io".to_owned())
            }
            Self::Impersonate(ask) => Some(ask.clone()),
            _ => None,
        }
    }
}

/// Who the server says rdy is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Identity {
    Verified { user: String, groups: Vec<String> },
    Unverified(Why),
}

/// Whether the reviews could be sent as the `as:` user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Impersonation {
    /// The spec has no `as:`.
    NotUsed,
    /// The identity may impersonate the user.
    Allowed,
    /// The identity may not. The text is the ask it lacks.
    Refused(String),
    /// The question could not be asked.
    Unknown(Why),
}

impl Impersonation {
    /// True when no review can be sent as the user.
    pub(super) fn blocks_reviews(&self) -> bool {
        matches!(self, Self::Refused(_) | Self::Unknown(_))
    }

    /// The gap that every review then has.
    pub(super) fn why(&self) -> Why {
        match self {
            Self::Refused(ask) => Why::Impersonate(ask.clone()),
            Self::Unknown(why) => why.clone(),
            Self::NotUsed | Self::Allowed => Why::OutOfTime,
        }
    }
}

/// Whether a namespace that a denied item names exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NamespaceState {
    Exists,
    Missing,
    /// The identity may not read it, or the server answered something else.
    Unknown,
}

/// Everything the check read.
#[derive(Debug)]
pub(super) struct Gathered {
    pub(super) identity: Identity,
    /// The `as:` user, when the reviews ran as another user.
    pub(super) as_user: Option<String>,
    pub(super) impersonation: Impersonation,
    /// The spec's items, in order, with the answers.
    pub(super) spec: Vec<(Ask, Answer)>,
    /// The `escalate` and `bind` asks the check added, with the answers.
    pub(super) implied: Vec<(Ask, Answer)>,
    /// Implied asks left out because the run is at the cap.
    pub(super) dropped: usize,
    /// What the tested user may do in the namespace, when something was denied.
    pub(super) rules: Option<RulesView>,
    /// Whether the namespaces of denied items exist.
    pub(super) namespaces: Vec<(String, NamespaceState)>,
    /// How many access reviews were sent, the impersonation question included.
    pub(super) sent: usize,
}

impl Gathered {
    /// True when any answer is a no or unclear.
    pub(super) fn has_denial(&self) -> bool {
        self.spec
            .iter()
            .chain(&self.implied)
            .any(|(_, answer)| answer.is_negative())
    }

    /// The namespace for the rules review: the entry's, else the first denied item's.
    pub(super) fn rules_namespace(
        &self,
        entry: Option<&rdy_spec::check::K8sName>,
    ) -> Option<String> {
        entry
            .map(|namespace| namespace.as_str().to_owned())
            .or_else(|| self.denied_namespaces().into_iter().next())
    }

    /// The namespaces named by items that were answered no, in order, without repeats.
    pub(super) fn denied_namespaces(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (ask, answer) in self.spec.iter().chain(&self.implied) {
            if let Some(namespace) = ask.namespace().filter(|_| answer.is_negative())
                && !out.iter().any(|seen| seen == namespace)
            {
                out.push(namespace.to_owned());
            }
        }
        out
    }
}

/// The subject of a sentence: the `as:` user, else the identity the server reported, else a plain phrase.
fn subject(gathered: &Gathered) -> String {
    let name = match (&gathered.as_user, &gathered.identity) {
        (Some(user), _) => Some(user.as_str()),
        (None, Identity::Verified { user, .. }) => Some(user.as_str()),
        (None, Identity::Unverified(_)) => None,
    };
    name.map_or_else(
        || "The kubeconfig identity".to_owned(),
        |name| format!("`{}`", shown(name, SHOWN)),
    )
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// `a, b, c, and N more`.
fn listed(items: &[String]) -> String {
    let head = items
        .iter()
        .take(LISTED)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    match items.len().checked_sub(LISTED) {
        Some(rest) if rest > 0 => format!("{head}; and {rest} more"),
        _ => head,
    }
}

/// Turns what was read into a finding.
pub(super) fn judge(params: &K8sRbac, gathered: &Gathered) -> Finding {
    let who = subject(gathered);
    let total = gathered.spec.len();
    let missing: Vec<&(Ask, Answer)> = gathered
        .spec
        .iter()
        .filter(|(_, answer)| answer.is_missing())
        .collect();
    let unclear: Vec<&(Ask, Answer)> = gathered
        .spec
        .iter()
        .filter(|(_, answer)| matches!(answer, Answer::Unclear { .. }))
        .collect();
    let implied: Vec<&(Ask, Answer)> = gathered
        .implied
        .iter()
        .filter(|(_, answer)| answer.is_negative())
        .collect();
    let gaps: Vec<&(Ask, Answer)> = gathered
        .spec
        .iter()
        .chain(&gathered.implied)
        .filter(|(_, answer)| matches!(answer, Answer::NotEvaluated(_)))
        .collect();
    let evaluated = gathered
        .spec
        .iter()
        .filter(|(_, answer)| !matches!(answer, Answer::NotEvaluated(_)))
        .count();

    let item =
        |(ask, answer): &&(Ask, Answer)| format!("`{}` ({})", ask.describe(), answer.short());

    // The level and the headline.
    let (level, message) = if !missing.is_empty() {
        let texts: Vec<String> = missing.iter().map(item).collect();
        let message = if let [only] = missing.as_slice() {
            format!("{who} cannot `{}`: {}", only.0.describe(), only.1.short())
        } else {
            format!(
                "{} of {total} permissions are missing for {who}: {}",
                missing.len(),
                listed(&texts)
            )
        };
        (Level::Fail, message)
    } else if !unclear.is_empty() {
        let texts: Vec<String> = unclear.iter().map(item).collect();
        (
            Level::Warn,
            format!(
                "{} for {who} could not be fully evaluated: {}",
                plural(unclear.len(), "permission", "permissions"),
                listed(&texts)
            ),
        )
    } else if !implied.is_empty() {
        let texts: Vec<String> = implied.iter().map(item).collect();
        (
            Level::Warn,
            format!(
                "Cannot prove {who} may grant roles ({}). It passes if the identity already holds every rule it grants",
                listed(&texts)
            ),
        )
    } else if evaluated == 0 {
        (
            Level::Pass,
            format!("No permission could be evaluated for {who}"),
        )
    } else if gaps.is_empty() {
        let extra = if gathered.implied.is_empty() {
            String::new()
        } else {
            format!(
                ", and may escalate and bind ({} more reviews)",
                gathered.implied.len()
            )
        };
        (
            Level::Pass,
            format!(
                "{who} can do all {}{extra}",
                plural(total, "permission", "permissions")
            ),
        )
    } else {
        (
            Level::Pass,
            format!("{who} can do the {evaluated} permissions that were evaluated"),
        )
    };

    let mut finding = Finding::new(level, message);

    // Notes: each missing item with its reason, then the rest.
    for (ask, answer) in &missing {
        finding = finding.with_note(format!("`{}`: {}", ask.describe(), answer.long()));
    }
    for (ask, answer) in &unclear {
        finding = finding.with_note(format!("`{}`: {}", ask.describe(), answer.long()));
    }
    for (ask, answer) in &implied {
        finding = finding.with_note(format!(
            "`{}` (added because the spec creates or changes roles or bindings): {}",
            ask.describe(),
            answer.long()
        ));
    }
    if let Some(note) = impersonation_note(gathered) {
        finding = finding.with_note(note);
    }
    if let Identity::Unverified(why) = &gathered.identity {
        finding = finding.with_note(format!(
            "The identity is not verified by the API server: {}",
            match why {
                Why::Missing => "SelfSubjectReview needs Kubernetes 1.28".to_owned(),
                other => other.text(),
            }
        ));
    }
    if let Some(rules) = &gathered.rules {
        finding = finding.with_note(rules.sentence(&who));
    }
    for (namespace, state) in &gathered.namespaces {
        if *state == NamespaceState::Missing {
            finding = finding.with_note(format!(
                "Namespace `{}` does not exist, so a namespaced permission there fails until it is created",
                shown(namespace, SHOWN)
            ));
        }
    }
    if gathered.dropped > 0 {
        finding = finding.with_note(format!(
            "{} implied escalate or bind {} left out: a run sends {MAX_REVIEWS} reviews at most",
            gathered.dropped,
            if gathered.dropped == 1 {
                "review was"
            } else {
                "reviews were"
            }
        ));
    }
    finding = finding.with_note(format!(
        "rdy sent {} (one entry each in the cluster's audit log, up to {MAX_REVIEWS}). A review creates nothing.",
        plural(gathered.sent, "access review", "access reviews")
    ));

    // The fix, only when something is wrong.
    if level != Level::Pass {
        let of_kind = |denied: bool| -> Vec<&Ask> {
            missing
                .iter()
                .filter(|(_, answer)| matches!(answer, Answer::Denied { .. }) == denied)
                .map(|(ask, _)| ask)
                .collect()
        };
        let mut text = fix::text(&fix::Context {
            who: fix::Who::of(gathered),
            grantable: of_kind(false),
            denied: of_kind(true),
            implied: implied.iter().map(|(ask, _)| ask).collect(),
            unclear: unclear.iter().map(|(ask, _)| ask).collect(),
            missing_namespaces: gathered
                .namespaces
                .iter()
                .filter(|(_, state)| *state == NamespaceState::Missing)
                .map(|(namespace, _)| namespace.as_str())
                .collect(),
        });
        if text.is_empty() {
            text.push_str("Run `kubectl auth can-i --list` as the identity to see what it may do.");
        }
        finding = finding.with_fix(text);
    }

    // What was not evaluated.
    if !gaps.is_empty() {
        let mut parts: Vec<String> = Vec::new();
        let mut grants: Vec<String> = Vec::new();
        let mut reasons: Vec<Why> = Vec::new();
        for (_, answer) in &gaps {
            if let Answer::NotEvaluated(why) = answer
                && !reasons.contains(why)
            {
                reasons.push(why.clone());
            }
        }
        for why in &reasons {
            let count = gaps
                .iter()
                .filter(|(_, answer)| matches!(answer, Answer::NotEvaluated(w) if w == why))
                .count();
            parts.push(format!(
                "{} not evaluated: {}",
                plural(count, "permission was", "permissions were"),
                why.text()
            ));
            grants.extend(why.grant());
        }
        grants.dedup();
        finding = finding
            .with_partial(Partial::new(Vec::new(), parts.join("; ")).with_missing_grants(grants));
    }

    finding
        .with_observed(observed(gathered, &who))
        .with_expected(expected(params, gathered))
}

/// What the notes say about the reviews running as another user.
fn impersonation_note(gathered: &Gathered) -> Option<String> {
    let user = shown(gathered.as_user.as_deref()?, SHOWN);
    Some(match &gathered.identity {
        Identity::Verified { user: real, .. } => format!(
            "The reviews ran as `{user}` (spec as). rdy itself is `{}`.",
            shown(real, SHOWN)
        ),
        Identity::Unverified(_) => format!("The reviews ran as `{user}` (spec as)."),
    })
}

fn observed(gathered: &Gathered, who: &str) -> Value {
    let mut map = Map::new();
    let identity = match &gathered.identity {
        Identity::Verified { user, groups } => json!({
            "user": shown(user, SHOWN),
            "groups": groups.iter().take(OBSERVED_ITEMS).map(|group| shown(group, SHOWN)).collect::<Vec<_>>(),
            "verified": true,
        }),
        Identity::Unverified(_) => json!({"verified": false}),
    };
    map.insert("identity".into(), identity);
    if let Some(user) = &gathered.as_user {
        map.insert("tested_as".into(), json!(shown(user, SHOWN)));
    }
    map.insert("tested".into(), json!(who.trim_matches('`')));
    map.insert("reviews".into(), json!(gathered.sent));
    let count = |wire: &str| {
        gathered
            .spec
            .iter()
            .filter(|(_, answer)| answer.wire() == wire)
            .count()
    };
    map.insert("allowed".into(), json!(count("allowed")));
    let entries = |items: &[(Ask, Answer)], keep: &dyn Fn(&Answer) -> bool| -> Vec<Value> {
        items
            .iter()
            .filter(|(_, answer)| keep(answer))
            .take(OBSERVED_ITEMS)
            .map(|(ask, answer)| {
                let mut entry = Map::new();
                entry.insert("permission".into(), json!(ask.describe()));
                entry.insert("answer".into(), json!(answer.wire()));
                if let Some(reason) = answer.reason() {
                    entry.insert("reason".into(), json!(shown(reason, SHOWN)));
                }
                if let Answer::NotEvaluated(why) = answer {
                    entry.insert("why".into(), json!(why.text()));
                }
                Value::Object(entry)
            })
            .collect()
    };
    let not_allowed = entries(&gathered.spec, &|answer| answer.is_negative());
    if !not_allowed.is_empty() {
        map.insert("missing".into(), Value::Array(not_allowed));
    }
    let implied = entries(&gathered.implied, &|answer| {
        !matches!(answer, Answer::Allowed)
    });
    if !implied.is_empty() {
        map.insert("implied".into(), Value::Array(implied));
    }
    let gaps = entries(&gathered.spec, &|answer| {
        matches!(answer, Answer::NotEvaluated(_))
    });
    if !gaps.is_empty() {
        map.insert("not_evaluated".into(), Value::Array(gaps));
    }
    if let Some(rules) = &gathered.rules {
        map.insert(
            "rules".into(),
            json!({
                "namespace": rules.namespace,
                "rules": rules.rules,
                "total": rules.total,
                "incomplete": rules.incomplete,
            }),
        );
    }
    if !gathered.namespaces.is_empty() {
        let namespaces: Vec<Value> = gathered
            .namespaces
            .iter()
            .map(|(namespace, state)| {
                let exists = match state {
                    NamespaceState::Exists => Value::Bool(true),
                    NamespaceState::Missing => Value::Bool(false),
                    NamespaceState::Unknown => Value::Null,
                };
                json!({"namespace": shown(namespace, SHOWN), "exists": exists})
            })
            .collect();
        map.insert("namespaces".into(), Value::Array(namespaces));
    }
    Value::Object(map)
}

/// The effective thresholds: the permissions asked for and the user they were asked as.
fn expected(params: &K8sRbac, gathered: &Gathered) -> Value {
    let mut map = Map::new();
    let can: Vec<String> = gathered
        .spec
        .iter()
        .take(OBSERVED_ITEMS)
        .map(|(ask, _)| ask.describe())
        .collect();
    map.insert("can".into(), json!(can));
    map.insert("permissions".into(), json!(gathered.spec.len()));
    if let Some(user) = &params.as_user {
        map.insert("as".into(), json!(shown(user.as_str(), SHOWN)));
    }
    Value::Object(map)
}
