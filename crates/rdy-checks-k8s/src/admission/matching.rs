//! Does an admission rule apply to the creation of a pod in the target namespace?
//!
//! The same question is asked of a webhook, a `ValidatingAdmissionPolicy` binding and the CEL policies of the
//! policy engines, and they all describe "what I match" the same way: rules of operations, API groups,
//! versions and resources, a `namespaceSelector` and an `objectSelector`. The answer is three-valued,
//! because the check does not know everything the API server would use:
//!
//! - [`Applies::Yes`]: the rules and the namespace selector match.
//! - [`Applies::Maybe`]: something the check cannot read decides. The namespace labels were not read, or the
//!   `objectSelector` matches on the labels of the pod, which the product's chart sets and rdy does not see.
//! - [`Applies::No`]: a rule or the namespace selector excludes it for certain.
//!
//! The thing judged is a `CREATE` of a core `v1` `Pod`. The product creates other objects (Deployments,
//! Services), and a controller creates the pods from them, so the pod is what the cluster finally admits. A
//! webhook that only matches Deployments is not judged.
//!
//! `matchPolicy` (`Exact` or `Equivalent`) decides whether a request is converted to another version of the
//! resource a rule names. A pod has one group and one version, `v1`, so nothing is converted and both values
//! give the same answer here: a rule must name `v1` (or `*`). It is therefore not a field this module reads.

use std::collections::BTreeMap;

use k8s_openapi::api::admissionregistration::v1::{
    MatchResources, NamedRuleWithOperations, RuleWithOperations,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

/// The labels of the target namespace, or `None` when they were not read.
pub(super) type NsLabels = Option<BTreeMap<String, String>>;

/// Whether something applies to a pod create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Applies {
    No,
    Maybe,
    Yes,
}

impl Applies {
    /// Both must hold: `No` wins, then `Maybe`.
    pub(super) fn and(self, other: Self) -> Self {
        self.min(other)
    }

    /// Either may hold: `Yes` wins, then `Maybe`.
    pub(super) fn or(self, other: Self) -> Self {
        self.max(other)
    }

    /// `Maybe` when the thing is not certain to apply because of a part the check cannot read.
    pub(super) fn capped(self, uncertain: bool) -> Self {
        if uncertain {
            self.min(Self::Maybe)
        } else {
            self
        }
    }
}

/// One rule: operations, groups, versions, resources, scope.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Rule {
    pub(super) operations: Vec<String>,
    pub(super) groups: Vec<String>,
    pub(super) versions: Vec<String>,
    pub(super) resources: Vec<String>,
    pub(super) scope: Option<String>,
    /// True when the rule names objects (`resourceNames`). A new pod has a generated name, so it is not one.
    pub(super) names: bool,
}

impl Rule {
    /// True when the rule matches the creation of a core `v1` `Pod` in a namespace.
    pub(super) fn matches_pod_create(&self) -> bool {
        let has =
            |list: &[String], wanted: &[&str]| list.iter().any(|v| wanted.contains(&v.as_str()));
        has(&self.operations, &["CREATE", "*"])
            && has(&self.groups, &["", "*"])
            && has(&self.versions, &["v1", "*"])
            // `pods/*` is every subresource of a pod, never the pod. `*` is every resource without its
            // subresources, `*/*` both.
            && has(&self.resources, &["pods", "*", "*/*"])
            && self.scope.as_deref().is_none_or(|scope| matches!(scope, "*" | "Namespaced"))
            && !self.names
    }
}

impl From<&RuleWithOperations> for Rule {
    fn from(rule: &RuleWithOperations) -> Self {
        Self {
            operations: rule.operations.clone().unwrap_or_default(),
            groups: rule.api_groups.clone().unwrap_or_default(),
            versions: rule.api_versions.clone().unwrap_or_default(),
            resources: rule.resources.clone().unwrap_or_default(),
            scope: rule.scope.clone(),
            names: false,
        }
    }
}

impl From<&NamedRuleWithOperations> for Rule {
    fn from(rule: &NamedRuleWithOperations) -> Self {
        Self {
            operations: rule.operations.clone().unwrap_or_default(),
            groups: rule.api_groups.clone().unwrap_or_default(),
            versions: rule.api_versions.clone().unwrap_or_default(),
            resources: rule.resources.clone().unwrap_or_default(),
            scope: rule.scope.clone(),
            names: rule.resource_names.as_ref().is_some_and(|n| !n.is_empty()),
        }
    }
}

/// True when any rule matches the creation of a pod.
pub(super) fn any_matches(rules: &[Rule]) -> bool {
    rules.iter().any(Rule::matches_pod_create)
}

/// True when a selector selects everything: none, or one with no label and no expression.
pub(super) fn is_empty(selector: Option<&LabelSelector>) -> bool {
    selector.is_none_or(|s| {
        s.match_labels.as_ref().is_none_or(BTreeMap::is_empty)
            && s.match_expressions.as_ref().is_none_or(Vec::is_empty)
    })
}

/// Does `selector` select a namespace with `labels`? An empty selector selects everything. Unknown labels
/// give [`Applies::Maybe`] for any selector that is not empty. An operator this build does not know is
/// `Maybe` too.
pub(super) fn selects(selector: Option<&LabelSelector>, labels: &NsLabels) -> Applies {
    if is_empty(selector) {
        return Applies::Yes;
    }
    let (Some(selector), Some(labels)) = (selector, labels) else {
        return Applies::Maybe;
    };
    for (key, value) in selector.match_labels.iter().flatten() {
        if labels.get(key) != Some(value) {
            return Applies::No;
        }
    }
    for expression in selector.match_expressions.iter().flatten() {
        let have = labels.get(&expression.key);
        let values = expression.values.as_deref().unwrap_or_default();
        let holds = match expression.operator.as_str() {
            "In" => have.is_some_and(|v| values.contains(v)),
            "NotIn" => have.is_none_or(|v| !values.contains(v)),
            "Exists" => have.is_some(),
            "DoesNotExist" => have.is_none(),
            _ => return Applies::Maybe,
        };
        if !holds {
            return Applies::No;
        }
    }
    Applies::Yes
}

/// The `matchConstraints` of a policy or the `matchResources` of a binding against a pod create.
///
/// A policy must name `resourceRules`, so none means it matches nothing. A binding that names none does not
/// narrow the policy, so none means everything it allows. `excludeResourceRules` win over the rules.
pub(super) fn match_resources(
    resources: Option<&MatchResources>,
    labels: &NsLabels,
    is_binding: bool,
) -> Applies {
    let Some(resources) = resources else {
        return if is_binding {
            Applies::Yes
        } else {
            Applies::No
        };
    };
    let rules: Vec<Rule> = resources
        .resource_rules
        .iter()
        .flatten()
        .map(Rule::from)
        .collect();
    if rules.is_empty() {
        if !is_binding {
            return Applies::No;
        }
    } else if !any_matches(&rules) {
        return Applies::No;
    }
    let excluded: Vec<Rule> = resources
        .exclude_resource_rules
        .iter()
        .flatten()
        .map(Rule::from)
        .collect();
    if any_matches(&excluded) {
        return Applies::No;
    }
    selects(resources.namespace_selector.as_ref(), labels)
        .capped(!is_empty(resources.object_selector.as_ref()))
}
