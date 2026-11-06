//! The policies of Kyverno and Gatekeeper themselves (03, "k8s.admission", M1-160).
//!
//! M1-114 finds the engines by their API groups. This reads their policy objects, so the result can name the
//! policies that can reject the product's pods. What is listed, first page of 500 each, cluster-scoped kinds
//! only (a namespaced Kyverno `Policy` is not listed):
//!
//! - Kyverno `kyverno.io/v1` `ClusterPolicy`, only when discovery showed the kind in `v1`. A group that
//!   serves only `PolicyException` and the cleanup kinds has no policy kind, so nothing is listed.
//! - Kyverno `policies.kyverno.io` `ValidatingPolicy` and `ImageValidatingPolicy` (`v1`, `v1beta1` or, on
//!   Kyverno 1.14 and 1.15, `v1alpha1`).
//! - Gatekeeper `constraints.gatekeeper.sh/v1beta1`, one list per constraint kind the group serves, at most
//!   [`MAX_CONSTRAINT_KINDS`] (ADR 0042).
//!
//! Each object is cut down to its name, whether it rejects, and whether it applies to a pod create in the
//! namespace; the rules' bodies, parameters and CEL expressions are dropped while reading. A policy that
//! only audits or warns is counted and never named as a blocker. A policy that applies by its kind and
//! namespace filters, but also filters on users, roles or a pod label selector, is `Maybe`.
//!
//! Kyverno's match filters are read the way its documentation says: `match.any` is an OR, `match.all` an
//! AND, a bare `match.resources` is one filter. `exclude` is not read, so a policy may be reported as applying
//! to a namespace that it excludes. That is the conservative side: the result says "may apply".

use k8s_openapi::api::admissionregistration::v1::MatchResources;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use serde_json::{Value, json};

use super::judge::{Grant, Part, shown};
use super::matching::{self, Applies, NsLabels};
use super::{Listed, Read};

/// The most Gatekeeper constraint kinds listed.
pub(super) const MAX_CONSTRAINT_KINDS: usize = 6;

/// The most policy lists one run makes, all engines together.
pub(super) const MAX_LISTS: usize = 8;

/// One resource of a group version, from discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ApiKind {
    /// The plural name, the path segment.
    pub(super) plural: String,
    pub(super) kind: String,
    pub(super) namespaced: bool,
}

/// One list of policy objects to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyList {
    pub(super) engine: &'static str,
    pub(super) group: &'static str,
    pub(super) version: String,
    pub(super) plural: String,
    pub(super) kind: String,
}

/// True when `plural` has the shape of a resource name: lower case letters and digits, 63 at most. Only such
/// a name is put in a path.
fn plural_shaped(plural: &str) -> bool {
    !plural.is_empty()
        && plural.len() <= 63
        && plural
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The policy lists that one discovered group version calls for.
pub(super) fn plan(group: &str, version: &str, resources: &[ApiKind]) -> Vec<PolicyList> {
    let find = |kind: &str, plural: &str| {
        resources
            .iter()
            .find(|r| r.kind == kind && r.plural == plural && !r.namespaced)
    };
    let list = |engine, group, kind: &ApiKind| PolicyList {
        engine,
        group,
        version: version.to_owned(),
        plural: kind.plural.clone(),
        kind: kind.kind.clone(),
    };
    match (group, version) {
        ("kyverno.io", "v1") => find("ClusterPolicy", "clusterpolicies")
            .map(|kind| list("Kyverno", "kyverno.io", kind))
            .into_iter()
            .collect(),
        ("policies.kyverno.io", "v1" | "v1beta1" | "v1alpha1") => [
            ("ValidatingPolicy", "validatingpolicies"),
            ("ImageValidatingPolicy", "imagevalidatingpolicies"),
        ]
        .into_iter()
        .filter_map(|(kind, plural)| find(kind, plural))
        .map(|kind| list("Kyverno", "policies.kyverno.io", kind))
        .collect(),
        ("constraints.gatekeeper.sh", "v1beta1") => {
            let mut kinds: Vec<&ApiKind> = resources
                .iter()
                .filter(|r| !r.namespaced && plural_shaped(&r.plural))
                .collect();
            // Names shaped like a kind first, so a hostile kind cannot push the real ones out of the cap.
            kinds.sort_by(|a, b| {
                (!super::engines::is_kind_shaped(&a.kind), &a.plural)
                    .cmp(&(!super::engines::is_kind_shaped(&b.kind), &b.plural))
            });
            kinds.dedup_by(|a, b| a.plural == b.plural);
            // The cap of [`MAX_CONSTRAINT_KINDS`] is applied by the reader, which counts what it leaves out.
            kinds
                .into_iter()
                .map(|kind| list("Gatekeeper", "constraints.gatekeeper.sh", kind))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// One policy object, cut down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PolicyFact {
    pub(super) name: String,
    /// The kind of the list it came from.
    pub(super) kind: String,
    /// It rejects (Kyverno `Enforce`, `validationActions` with `Deny`, Gatekeeper `deny`), as opposed to
    /// auditing or warning.
    pub(super) enforcing: bool,
    pub(super) applies: Applies,
}

/// The answer of one list.
#[derive(Debug)]
pub(super) struct PolicyRead {
    pub(super) list: PolicyList,
    pub(super) result: Read<Listed<PolicyFact>>,
}

/// Everything read about the engines' policies.
#[derive(Debug, Default)]
pub(super) struct EnginePolicies {
    pub(super) reads: Vec<PolicyRead>,
    /// Lists that were planned and not made, because of the cap on lists or the clock.
    pub(super) skipped: usize,
}

// ---- reading one object -----------------------------------------------------------------------------------

/// The object cut down to a [`PolicyFact`].
pub(super) fn fact(
    list: &PolicyList,
    name: &str,
    data: &Value,
    labels: &NsLabels,
    ns: Option<&str>,
) -> PolicyFact {
    let (enforcing, applies) = match list.group {
        "kyverno.io" => kyverno_legacy(data, labels, ns),
        "policies.kyverno.io" => kyverno_cel(data, labels),
        _ => gatekeeper(data, labels, ns),
    };
    PolicyFact {
        name: name.to_owned(),
        kind: list.kind.clone(),
        enforcing,
        applies: if enforcing { applies } else { Applies::No },
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

fn selector(value: &Value, key: &str) -> Option<LabelSelector> {
    value
        .get(key)
        .filter(|v| v.is_object())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// `*` matches any run of characters and `?` one, as Kyverno and Gatekeeper write namespace patterns.
pub(super) fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(c) if *c == '?' || *c == t[ti] => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Do the namespace names (patterns) include the namespace? `None` when the namespace is not named.
fn names_include(patterns: &[String], ns: Option<&str>) -> Applies {
    match ns {
        None => Applies::Maybe,
        Some(ns) if patterns.iter().any(|p| glob(p, ns)) => Applies::Yes,
        Some(_) => Applies::No,
    }
}

fn is_pod_kind(kind: &str) -> bool {
    // Kyverno writes `Pod`, `v1/Pod` and `*`.
    let last = kind.rsplit('/').next().unwrap_or(kind);
    last == "Pod" || last == "*"
}

// Kyverno, the legacy `ClusterPolicy`.

fn kyverno_legacy(data: &Value, labels: &NsLabels, ns: Option<&str>) -> (bool, Applies) {
    let Some(spec) = data.get("spec") else {
        return (false, Applies::No);
    };
    let default_enforce = text(spec, "validationFailureAction")
        .is_some_and(|action| action.eq_ignore_ascii_case("enforce"));
    // `validationFailureActionOverrides` set the action per namespace and can flip Audit to Enforce.
    let overrides = spec
        .get("validationFailureActionOverrides")
        .and_then(Value::as_array)
        .filter(|list| !list.is_empty());
    let override_enforces = overrides.is_some_and(|list| {
        list.iter().any(|entry| {
            text(entry, "action").is_some_and(|action| action.eq_ignore_ascii_case("enforce"))
        })
    });
    let mut enforcing = false;
    let mut applies = Applies::No;
    for rule in spec
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let validate = rule.get("validate");
        let verify = rule.get("verifyImages").and_then(Value::as_array);
        if validate.is_none() && verify.is_none() {
            continue;
        }
        let own = |v: &Value| text(v, "failureAction").map(|a| a.eq_ignore_ascii_case("enforce"));
        let rule_enforces = validate
            .and_then(own)
            .or_else(|| verify.and_then(|items| items.iter().find_map(own)))
            .unwrap_or(default_enforce)
            || override_enforces;
        if !rule_enforces {
            continue;
        }
        enforcing = true;
        // Things the check does not evaluate: overrides, `exclude`, object names and a policy that is
        // switched off for admission. PolicyException objects are not read either.
        let uncertain = overrides.is_some()
            || admission_off(spec)
            || rule.get("exclude").is_some()
            || rule.get("match").is_some_and(match_has_names);
        applies = applies.or(rule
            .get("match")
            .map_or(Applies::Maybe, |m| kyverno_match(m, labels, ns))
            .capped(uncertain));
    }
    (enforcing, applies)
}

/// True when `spec.evaluation.admission.enabled` is `false`: the policy does not run at admission.
fn admission_off(spec: &Value) -> bool {
    spec.pointer("/evaluation/admission/enabled") == Some(&Value::Bool(false))
}

/// True when a `match` block filters on object names, which a generated pod name cannot be judged against.
fn match_has_names(block: &Value) -> bool {
    let has = |filter: &Value| {
        filter
            .get("resources")
            .and_then(|r| r.get("names"))
            .and_then(Value::as_array)
            .is_some_and(|names| !names.is_empty())
    };
    let any_of = |key: &str| {
        block
            .get(key)
            .and_then(Value::as_array)
            .is_some_and(|list| list.iter().any(has))
    };
    has(block) || any_of("any") || any_of("all")
}

/// One `match` block against a pod create.
fn kyverno_match(block: &Value, labels: &NsLabels, ns: Option<&str>) -> Applies {
    let filters = |key: &str| -> Vec<Applies> {
        block
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|filter| kyverno_filter(filter, labels, ns))
            .collect()
    };
    let mut parts: Vec<Applies> = Vec::new();
    let any = filters("any");
    if !any.is_empty() {
        parts.push(any.into_iter().fold(Applies::No, Applies::or));
    }
    let all = filters("all");
    if !all.is_empty() {
        parts.push(all.into_iter().fold(Applies::Yes, Applies::and));
    }
    if block.get("resources").is_some() {
        parts.push(kyverno_filter(block, labels, ns));
    }
    if parts.is_empty() {
        return Applies::Maybe;
    }
    parts.into_iter().fold(Applies::Yes, Applies::and)
}

/// One filter: `resources` (kinds, namespaces, selectors, operations) and the user filters.
fn kyverno_filter(filter: &Value, labels: &NsLabels, ns: Option<&str>) -> Applies {
    let Some(resources) = filter.get("resources") else {
        // A filter on users or roles alone: whether it applies depends on who creates the pod.
        return Applies::Maybe;
    };
    let kinds = strings(resources, "kinds");
    if !kinds.is_empty() && !kinds.iter().any(|kind| is_pod_kind(kind)) {
        return Applies::No;
    }
    let operations = strings(resources, "operations");
    if !operations.is_empty() && !operations.iter().any(|op| op == "CREATE") {
        return Applies::No;
    }
    let mut applies = Applies::Yes;
    let namespaces = strings(resources, "namespaces");
    if !namespaces.is_empty() {
        applies = applies.and(names_include(&namespaces, ns));
    }
    applies = applies.and(matching::selects(
        selector(resources, "namespaceSelector").as_ref(),
        labels,
    ));
    // A pod label selector, or a filter on who creates the pod, cannot be judged.
    let uncertain = resources.get("selector").is_some_and(Value::is_object)
        || ["subjects", "roles", "clusterRoles"]
            .iter()
            .any(|key| filter.get(key).is_some());
    applies.capped(uncertain)
}

// Kyverno, the CEL policies.

fn kyverno_cel(data: &Value, labels: &NsLabels) -> (bool, Applies) {
    let Some(spec) = data.get("spec") else {
        return (false, Applies::No);
    };
    let enforcing = strings(spec, "validationActions")
        .iter()
        .any(|action| action == "Deny");
    let constraints = spec
        .get("matchConstraints")
        .and_then(|v| serde_json::from_value::<MatchResources>(v.clone()).ok());
    let applies = match constraints {
        Some(_) => matching::match_resources(constraints.as_ref(), labels, false),
        None => Applies::Maybe,
    };
    let conditions = spec
        .get("matchConditions")
        .and_then(Value::as_array)
        .is_some_and(|c| !c.is_empty());
    (enforcing, applies.capped(conditions || admission_off(spec)))
}

// Gatekeeper, one constraint.

fn gatekeeper(data: &Value, labels: &NsLabels, ns: Option<&str>) -> (bool, Applies) {
    let spec = data.get("spec").unwrap_or(&Value::Null);
    let enforcing = match text(spec, "enforcementAction") {
        // `deny` is the default.
        None | Some("deny") => true,
        Some("scoped") => spec
            .get("scopedEnforcementActions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|entry| {
                // A scoped `deny` rejects at admission only for the enforcement point
                // `validation.gatekeeper.sh` (or `*`). No points listed means the default.
                let points = entry.get("enforcementPoints").and_then(Value::as_array);
                text(entry, "action") == Some("deny")
                    && points.is_none_or(|points| {
                        points.is_empty()
                            || points.iter().any(|point| {
                                matches!(
                                    text(point, "name"),
                                    Some("validation.gatekeeper.sh" | "*")
                                )
                            })
                    })
            }),
        Some(_) => false,
    };
    let ignored = labels
        .as_ref()
        .is_some_and(|l| l.contains_key("admission.gatekeeper.sh/ignore"));
    let Some(m) = spec.get("match").filter(|m| m.is_object()) else {
        return (enforcing, Applies::Yes.capped(ignored));
    };
    // `kinds`: entries of apiGroups and kinds. None listed means every kind.
    let kinds = m.get("kinds").and_then(Value::as_array);
    if let Some(kinds) = kinds.filter(|k| !k.is_empty()) {
        let pod = kinds.iter().any(|entry| {
            let groups = strings(entry, "apiGroups");
            let names = strings(entry, "kinds");
            groups.iter().any(|g| g.is_empty() || g == "*")
                && names.iter().any(|k| k == "Pod" || k == "*")
        });
        if !pod {
            return (enforcing, Applies::No);
        }
    }
    if text(m, "scope").is_some_and(|scope| scope == "Cluster") {
        return (enforcing, Applies::No);
    }
    let mut applies = Applies::Yes;
    let namespaces = strings(m, "namespaces");
    if !namespaces.is_empty() {
        applies = applies.and(names_include(&namespaces, ns));
    }
    let excluded = strings(m, "excludedNamespaces");
    if !excluded.is_empty() && names_include(&excluded, ns) == Applies::Yes {
        applies = Applies::No;
    }
    applies = applies.and(matching::selects(
        selector(m, "namespaceSelector").as_ref(),
        labels,
    ));
    let pod_labels = m.get("labelSelector").is_some_and(Value::is_object);
    // `match.name` names the object, and a pod made by a controller has a generated name. The label
    // `admission.gatekeeper.sh/ignore` exempts a namespace when Gatekeeper is set to honour it.
    let by_name = text(m, "name").is_some_and(|name| !name.is_empty());
    (enforcing, applies.capped(pod_labels || by_name || ignored))
}

// ---- judging ----------------------------------------------------------------------------------------------

fn grant_of(list: &PolicyList) -> Grant {
    // One grant per kind, so each constraint kind keeps its own `can-i` command.
    Grant::list(&list.plural, list.group)
}

/// The finding part for the engines' policies.
pub(super) fn judge(found: &EnginePolicies, ns: Option<&str>) -> Part {
    let mut part = Part::default();
    let mut blockers: Vec<String> = Vec::new();
    let mut read = 0_usize;
    let mut enforcing = 0_usize;
    for entry in &found.reads {
        match &entry.result {
            Read::Ok(listed) => {
                read += listed.items.len();
                if listed.cut {
                    part.unverified.push(format!(
                        "only the first {} {} objects were read, so later policies are not evaluated",
                        super::PAGE,
                        shown(&entry.list.kind)
                    ));
                }
                for policy in &listed.items {
                    if policy.enforcing {
                        enforcing += 1;
                    }
                    if policy.enforcing && policy.applies != Applies::No {
                        let maybe = if policy.applies == Applies::Maybe {
                            " (may apply)"
                        } else {
                            ""
                        };
                        blockers.push(format!(
                            "{} {} {}{maybe}",
                            entry.list.engine,
                            shown(&policy.kind),
                            shown(&policy.name)
                        ));
                    }
                }
            }
            Read::Missing => {}
            other => {
                part.unverified.push(format!(
                    "{} {} policies were not evaluated: the list could not be read ({})",
                    entry.list.engine,
                    shown(&entry.list.kind),
                    other.why()
                ));
                if matches!(other, Read::Forbidden) {
                    part.grants.push(grant_of(&entry.list));
                }
            }
        }
    }
    if found.skipped > 0 {
        part.unverified.push(format!(
            "rdy lists at most {MAX_CONSTRAINT_KINDS} Gatekeeper constraint kinds and {MAX_LISTS} policy lists, so {} more were not listed and their policies are not evaluated",
            found.skipped
        ));
    }
    if found.reads.is_empty() {
        return part;
    }
    let in_ns = ns.map_or_else(String::new, |ns| format!(" for namespace {ns}"));
    if blockers.is_empty() {
        if found.reads.iter().all(|r| matches!(r.result, Read::Ok(_))) {
            part.notes.push(format!(
                "rdy read {read} policy objects of the engines and none that rejects can apply to pods{in_ns}. Namespaced Kyverno `Policy` objects are not listed."
            ));
        }
    } else {
        let (names, more) = super::cut_list(blockers);
        part.notes.push(format!(
            "Policies that reject and can apply to the product's pods{in_ns} ({enforcing} of {read} read reject): {}{more}. Their rules were not evaluated, and Gatekeeper Config exemptions and Kyverno PolicyException objects are not read, so a policy may apply to fewer pods than listed.",
            names.join(", ")
        ));
    }
    part
}

/// What the result records about the engines' policies.
pub(super) fn observed(found: &EnginePolicies) -> Value {
    let lists: Vec<Value> = found
        .reads
        .iter()
        .map(|entry| {
            let (state, policies) = match &entry.result {
                Read::Ok(listed) => (
                    "read",
                    listed
                        .items
                        .iter()
                        .filter(|p| p.enforcing)
                        .take(super::LISTED)
                        .map(|p| {
                            json!({
                                "name": shown(&p.name),
                                "applies": match p.applies {
                                    Applies::Yes => "yes",
                                    Applies::Maybe => "maybe",
                                    Applies::No => "no",
                                },
                            })
                        })
                        .collect::<Vec<_>>(),
                ),
                Read::Forbidden => ("forbidden", Vec::new()),
                _ => ("unreadable", Vec::new()),
            };
            json!({
                "engine": entry.list.engine,
                "group": entry.list.group,
                "kind": shown(&entry.list.kind),
                "list": state,
                "enforcing": policies,
            })
        })
        .collect();
    Value::Array(lists)
}
