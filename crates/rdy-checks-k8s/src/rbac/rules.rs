//! What the tested user may already do in a namespace, from `SelfSubjectRulesReview`.
//!
//! The rules come from the server, so every text is escaped and cut before it is kept. The list is a hint
//! for the admin who reads the result, not a judgement: an authorizer outside RBAC may not report its
//! rules, and the server says so with `incomplete`.

use k8s_openapi::api::authorization::v1::SubjectRulesReviewStatus;

use super::judge::shown;

/// The most rules kept.
const MAX_RULES: usize = 12;

/// The longest text of one rule, in characters.
const RULE_CHARS: usize = 120;

/// The rules of a user in one namespace, as short texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RulesView {
    pub(super) namespace: String,
    /// `get,list pods` and `get /healthz`, at most [`MAX_RULES`].
    pub(super) rules: Vec<String>,
    /// How many rules the server returned in all.
    pub(super) total: usize,
    /// The server could not list every rule (an authorizer that cannot enumerate).
    pub(super) incomplete: bool,
}

impl RulesView {
    pub(super) fn from_status(namespace: &str, status: &SubjectRulesReviewStatus) -> Self {
        let resource = status.resource_rules.iter().map(|rule| {
            let list = |items: &Option<Vec<String>>| items.as_ref().map(|items| items.join(","));
            let mut text = format!(
                "{} {}",
                rule.verbs.join(","),
                list(&rule.resources).unwrap_or_default()
            );
            if let Some(groups) = list(&rule.api_groups).filter(|groups| !groups.is_empty()) {
                text.push_str(" in group ");
                text.push_str(&groups);
            }
            if let Some(names) = list(&rule.resource_names).filter(|names| !names.is_empty()) {
                text.push_str(" named ");
                text.push_str(&names);
            }
            text
        });
        let non_resource = status.non_resource_rules.iter().map(|rule| {
            format!(
                "{} {}",
                rule.verbs.join(","),
                rule.non_resource_urls
                    .as_ref()
                    .map(|urls| urls.join(","))
                    .unwrap_or_default()
            )
        });
        let all: Vec<String> = resource.chain(non_resource).collect();
        Self {
            namespace: shown(namespace, RULE_CHARS),
            total: all.len(),
            rules: all
                .iter()
                .take(MAX_RULES)
                .map(|rule| shown(rule, RULE_CHARS))
                .collect(),
            incomplete: status.incomplete,
        }
    }

    /// One sentence for the notes.
    pub(super) fn sentence(&self, subject: &str) -> String {
        let mut text = if self.total == 0 {
            format!(
                "{subject} may do nothing in `{}` according to the server",
                self.namespace
            )
        } else {
            let more = self.total.saturating_sub(self.rules.len());
            let tail = if more > 0 {
                format!(", and {more} more")
            } else {
                String::new()
            };
            format!(
                "{subject} may already do this in `{}`: {}{tail}",
                self.namespace,
                self.rules.join("; ")
            )
        };
        if self.incomplete {
            text.push_str(". The list may be short: an authorizer could not list its rules");
        }
        text
    }
}
