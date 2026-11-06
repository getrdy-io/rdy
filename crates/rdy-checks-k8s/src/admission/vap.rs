//! `ValidatingAdmissionPolicy` and its bindings (`admissionregistration.k8s.io/v1`, GA in 1.30).
//!
//! A policy is the CEL rule and a binding turns it on. Only a binding with the `Deny` action rejects
//! requests (`Warn` and `Audit` do not), so the check reads the policy list, and the binding list only when
//! the first one holds a policy. A policy and its binding apply to a pod create when the policy's
//! `matchConstraints` and the binding's `matchResources` both match it. The CEL expressions are not read and
//! not evaluated: a policy that applies is listed by name and the result says the expressions were not
//! evaluated. `matchConditions` and an `objectSelector` make an applying policy a `Maybe`.
//!
//! The warning is the same shape as for a policy engine: something here can reject the product's pods, and
//! only the platform team can say whether it will.

use k8s_openapi::api::admissionregistration::v1::{
    MatchResources, ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
};
use rdy_engine::check::Level;
use serde_json::{Value, json};

use super::judge::{Grant, Issue, Part, shown};
use super::matching::{self, Applies, NsLabels};
use super::{Listed, Read, fix};

/// A policy, as far as the check reads it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Policy {
    pub(super) name: String,
    pub(super) constraints: Option<MatchResources>,
    /// `matchConditions` is not empty: a CEL expression may exempt the request.
    pub(super) conditions: bool,
}

/// A binding, as far as the check reads it.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Binding {
    pub(super) name: String,
    pub(super) policy: String,
    /// `validationActions` holds `Deny`.
    pub(super) deny: bool,
    pub(super) resources: Option<MatchResources>,
}

/// What was read.
#[derive(Debug)]
pub(super) struct Policies {
    pub(super) policies: Read<Listed<Policy>>,
    /// `None` when the policy list held nothing, so the bindings were not asked for.
    pub(super) bindings: Option<Read<Listed<Binding>>>,
}

pub(super) fn policy_of(policy: ValidatingAdmissionPolicy) -> Policy {
    let spec = policy.spec;
    Policy {
        name: policy.metadata.name.unwrap_or_default(),
        constraints: spec.as_ref().and_then(|s| s.match_constraints.clone()),
        conditions: spec
            .as_ref()
            .and_then(|s| s.match_conditions.as_ref())
            .is_some_and(|c| !c.is_empty()),
    }
}

pub(super) fn binding_of(binding: ValidatingAdmissionPolicyBinding) -> Binding {
    let spec = binding.spec;
    Binding {
        name: binding.metadata.name.unwrap_or_default(),
        policy: spec.policy_name,
        deny: spec.validation_actions.iter().any(|a| a == "Deny"),
        resources: spec.match_resources,
    }
}

/// A binding that rejects, with whether it applies to a pod create.
struct Rejecting<'a> {
    binding: &'a Binding,
    applies: Applies,
}

fn rejecting<'a>(found: &'a Policies, labels: &NsLabels) -> Vec<Rejecting<'a>> {
    let (Read::Ok(policies), Some(Read::Ok(bindings))) = (&found.policies, &found.bindings) else {
        return Vec::new();
    };
    bindings
        .items
        .iter()
        .filter(|binding| binding.deny)
        .filter_map(|binding| {
            let policy = policies.items.iter().find(|p| p.name == binding.policy)?;
            let applies = matching::match_resources(policy.constraints.as_ref(), labels, false)
                .and(matching::match_resources(
                    binding.resources.as_ref(),
                    labels,
                    true,
                ))
                .capped(policy.conditions);
            (applies != Applies::No).then_some(Rejecting { binding, applies })
        })
        .collect()
}

/// The finding part for the policies.
pub(super) fn judge(found: &Policies, labels: &NsLabels, ns: Option<&str>) -> Part {
    let mut part = Part::default();
    match &found.policies {
        Read::Ok(listed) => {
            if listed.cut {
                part.notes.push(format!(
                    "Only the first {} ValidatingAdmissionPolicy objects were read.",
                    super::PAGE
                ));
            }
        }
        Read::Missing => part.notes.push(
            "The server does not serve ValidatingAdmissionPolicy in admissionregistration.k8s.io/v1 (it is GA in Kubernetes 1.30), so there are none."
                .to_owned(),
        ),
        other => {
            part.unverified.push(format!(
                "ValidatingAdmissionPolicy objects were not evaluated: the list could not be read ({})",
                other.why()
            ));
            if matches!(other, Read::Forbidden) {
                part.grants
                    .push(Grant::list("validatingadmissionpolicies", "admissionregistration.k8s.io"));
            }
        }
    }
    match &found.bindings {
        Some(Read::Ok(listed)) if listed.cut => part.notes.push(format!(
            "Only the first {} ValidatingAdmissionPolicyBinding objects were read.",
            super::PAGE
        )),
        Some(Read::Ok(_)) | None => {}
        Some(other) => {
            part.unverified.push(format!(
                "ValidatingAdmissionPolicyBinding objects were not evaluated: the list could not be read ({})",
                other.why()
            ));
            if matches!(other, Read::Forbidden) {
                part.grants.push(Grant::list(
                    "validatingadmissionpolicybindings",
                    "admissionregistration.k8s.io",
                ));
            }
        }
    }
    let rejecting = rejecting(found, labels);
    if rejecting.is_empty() {
        return part;
    }
    let names: Vec<String> = rejecting
        .iter()
        .map(|r| {
            let maybe = if r.applies == Applies::Maybe {
                " (may apply)"
            } else {
                ""
            };
            format!(
                "{} of policy {}{maybe}",
                shown(&r.binding.name),
                shown(&r.binding.policy)
            )
        })
        .collect();
    let (shown_names, more) = super::cut_list(names);
    let in_ns = ns.map_or_else(String::new, |ns| format!(" in namespace {ns}"));
    part.issues.push(Issue {
        level: Level::Warn,
        message: format!(
            "ValidatingAdmissionPolicy bindings that deny can reject the product's pods{in_ns}: {}{more}. The CEL expressions were not evaluated",
            shown_names.join(", ")
        ),
        fix: fix::admission_policies(ns),
    });
    part
}

/// What the result records about the policies.
pub(super) fn observed(found: &Policies, labels: &NsLabels) -> Value {
    let count = |read: &Read<Listed<Policy>>| match read {
        Read::Ok(listed) => json!(listed.items.len()),
        _ => Value::Null,
    };
    let denying: Vec<Value> = rejecting(found, labels)
        .iter()
        .map(|r| {
            json!({
                "binding": shown(&r.binding.name),
                "policy": shown(&r.binding.policy),
                "applies": if r.applies == Applies::Yes { "yes" } else { "maybe" },
            })
        })
        .collect();
    json!({"policies": count(&found.policies), "denying": denying})
}
