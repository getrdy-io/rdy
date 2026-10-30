//! The judgement of `k8s.access`: facts in, one [`Finding`] out. Nothing here touches the cluster.
//!
//! Thresholds (03 `k8s.access`):
//!
//! | Condition | Level |
//! | --- | --- |
//! | the server did not accept the credentials (401), or refused the identity review (403) | fail |
//! | a credential in the kubeconfig has ended | fail |
//! | the context or the server does not match its spec pattern | fail |
//! | connected as `system:anonymous` | warn |
//! | `insecure-skip-tls-verify: true` | warn |
//! | a token or client certificate ends in under 7 days | warn |
//! | `GET /version` slower than `max_latency` (default 2 s) | warn |
//! | the identity review answered something else (a 5xx) | warn |
//!
//! When several apply, the level is the worst, the message is the first, and each of the others is a note
//! that starts with "Also:". The fix text is the fixes of all of them, once each.

use std::time::Duration;

use rdy_engine::check::{Finding, Level, Partial};
use rdy_engine::text::escape_untrusted;
use serde_json::{Value, json};

use super::fix;
use crate::client::{ConnectionFacts, Credential, KubeError, ProxyRule, ServerVersion};

/// A token or certificate that ends within this many seconds earns a warning: 7 days.
pub(super) const EXPIRY_WARN_SECS: i64 = 7 * 86_400;

/// `max_latency` when the spec does not set one.
pub(super) const DEFAULT_MAX_LATENCY: Duration = Duration::from_secs(2);

/// The most groups listed in a report. A user in a large directory can have hundreds.
const GROUPS_LISTED: usize = 10;

/// The most groups kept at all.
const GROUPS_KEPT: usize = 50;

/// The longest text from the server that goes into a sentence, in characters.
const SHOWN: usize = 96;

/// The spec's thresholds, with the defaults filled in.
#[derive(Debug, Clone)]
pub(super) struct Rules {
    pub(super) context_pattern: Option<String>,
    pub(super) server_pattern: Option<String>,
    pub(super) max_latency: Duration,
}

/// Who the server says rdy is.
#[derive(Debug)]
pub(super) enum Who {
    /// `SelfSubjectReview` answered. The texts are escaped and cut.
    Verified {
        username: String,
        groups: Vec<String>,
        group_count: usize,
    },
    /// The server predates `SelfSubjectReview` (before 1.28). One access review was accepted, so the
    /// credentials work, but the identity is not known.
    NotVerified,
    /// 401.
    Unauthorized,
    /// 403.
    Forbidden,
    /// Another status of the server.
    Other { code: u16 },
    /// The answer held no user.
    Silent,
    /// The connection broke while asking.
    Broken(KubeError),
}

/// What discovery said. A failure of either request is a note, never a failure of the check.
#[derive(Debug, Default)]
pub(super) struct Discovery {
    pub(super) core_versions: Option<Vec<String>>,
    pub(super) group_count: Option<usize>,
    pub(super) notes: Vec<String>,
}

/// Everything the check learned from a connection that worked.
pub(super) struct Seen<'a> {
    pub(super) facts: &'a ConnectionFacts,
    pub(super) version: &'a ServerVersion,
    pub(super) latency: Duration,
    pub(super) who: Who,
    pub(super) discovery: Discovery,
}

/// One thing wrong, with its own fix.
struct Issue {
    level: Level,
    text: String,
    fix: String,
}

/// A server or user text, escaped and cut.
pub(super) fn shown(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(SHOWN).collect();
    let mut out = escape_untrusted(&head);
    if chars.next().is_some() {
        out.push_str("...");
    }
    out
}

/// `3 days`, `5 hours`, `20 minutes`, for a span in seconds (its sign is the caller's business).
pub(super) fn span(seconds: i64) -> String {
    let seconds = seconds.unsigned_abs();
    let (n, unit) = if seconds >= 86_400 {
        (seconds / 86_400, "day")
    } else if seconds >= 3_600 {
        (seconds / 3_600, "hour")
    } else {
        ((seconds / 60).max(1), "minute")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

fn kind_name(credential: &Credential) -> &'static str {
    match credential {
        Credential::Token { .. } => "token",
        Credential::ClientCertificate { .. } => "client certificate",
        Credential::Password => "password",
        Credential::Plugin { .. } => "credential plugin",
        Credential::ServiceAccount => "service account token",
    }
}

fn matches(pattern: &str, text: &str) -> Option<bool> {
    rdy_spec::pattern::compile(pattern)
        .ok()
        .map(|regex| regex.is_match(text))
}

/// The finding for a connection that worked.
pub(super) fn judge(rules: &Rules, seen: &Seen<'_>) -> Finding {
    let facts = seen.facts;
    let guess = fix::guess(Some(facts));
    let has_credentials = !facts.credentials().is_empty();
    let mut issues: Vec<Issue> = Vec::new();

    // Credentials that have ended explain a 401, so they come first and the 401 text is left out.
    let mut credential_ended = false;
    for credential in facts.credentials() {
        let Some(left) = credential.expires_in() else {
            continue;
        };
        let kind = kind_name(credential);
        if left < 0 {
            credential_ended = true;
            issues.push(Issue {
                level: Level::Fail,
                text: ended_text(credential, left),
                fix: fix::renew(&guess, credential),
            });
        } else if left < EXPIRY_WARN_SECS {
            issues.push(Issue {
                level: Level::Warn,
                text: format!("The {kind} in the kubeconfig ends in {}.", span(left)),
                fix: fix::renew(&guess, credential),
            });
        }
    }

    match &seen.who {
        Who::Unauthorized if !credential_ended => issues.push(Issue {
            level: Level::Fail,
            text: format!(
                "The API server at {} did not accept the credentials (401).",
                facts.line().server()
            ),
            fix: fix::unauthorized(&guess),
        }),
        Who::Unauthorized => {}
        Who::Forbidden => issues.push(Issue {
            level: Level::Fail,
            text: if has_credentials {
                "The API server refused to say who rdy is (403 on the identity review).".to_owned()
            } else {
                "The kubeconfig has no credentials, so the server treats rdy as anonymous and refuses it (403)."
                    .to_owned()
            },
            fix: fix::review_forbidden(has_credentials, &guess),
        }),
        Who::Verified { username, .. } if username == "system:anonymous" => issues.push(Issue {
            level: Level::Warn,
            text: "rdy is connected as system:anonymous.".to_owned(),
            fix: fix::anonymous(&guess, has_credentials),
        }),
        Who::Broken(error) => issues.push(Issue {
            level: Level::Fail,
            text: error.to_string(),
            fix: fix::for_error(
                error,
                Some(facts),
                facts.proxy().describe().as_deref(),
            ),
        }),
        Who::Other { code } => issues.push(Issue {
            level: Level::Warn,
            text: format!("The identity review answered with status {code}, so who rdy is could not be confirmed."),
            fix: "Run rdy again. If it repeats, the API server may be overloaded or an admission webhook may be failing: check the API server logs.".to_owned(),
        }),
        Who::Silent => issues.push(Issue {
            level: Level::Warn,
            text: "The identity review answered without a user, so who rdy is could not be confirmed.".to_owned(),
            fix: "Tell the vendor which Kubernetes distribution this is, with the JSON report.".to_owned(),
        }),
        Who::Verified { .. } | Who::NotVerified => {}
    }

    if let Some(pattern) = &rules.context_pattern
        && matches(pattern, facts.line().context()) == Some(false)
    {
        issues.push(Issue {
            level: Level::Fail,
            text: format!(
                "The kube context is {}, which does not match the pattern {} in the spec.",
                facts.line().context(),
                shown(pattern)
            ),
            fix: "Switch to the cluster the vendor expects: `kubectl config get-contexts` lists them, then pass one with `--kube-context <name>` or run `kubectl config use-context <name>`.".to_owned(),
        });
    }
    if let Some(pattern) = &rules.server_pattern
        && matches(pattern, facts.line().server()) == Some(false)
    {
        issues.push(Issue {
            level: Level::Fail,
            text: format!(
                "The API server is {}, which does not match the pattern {} in the spec.",
                facts.line().server(),
                shown(pattern)
            ),
            fix: "This kubeconfig points at another cluster than the spec expects. Pass the right kubeconfig with `--kubeconfig <file>`, or its context with `--kube-context <name>`.".to_owned(),
        });
    }

    if facts.line().tls_verification_off() {
        issues.push(Issue {
            level: Level::Warn,
            text: "TLS verification is off in the kubeconfig (insecure-skip-tls-verify), so rdy cannot tell this server from an impostor.".to_owned(),
            fix: "Give the cluster its CA: `kubectl config set-cluster <cluster> --certificate-authority=<ca-file> --embed-certs=true --insecure-skip-tls-verify=false`.".to_owned(),
        });
    }

    if seen.latency > rules.max_latency {
        issues.push(Issue {
            level: Level::Warn,
            text: format!(
                "GET /version took {} ms, above the {} ms limit.",
                seen.latency.as_millis(),
                rules.max_latency.as_millis()
            ),
            fix: "A slow answer usually means a distant region, a VPN or an overloaded proxy. Run rdy from a host nearer the cluster, or raise `max_latency` in the spec if this is expected.".to_owned(),
        });
    }

    // Worst first, then the order they were found in.
    issues.sort_by_key(|issue| std::cmp::Reverse(rank(issue.level)));
    let level = issues.first().map_or(Level::Pass, |issue| issue.level);

    let version = shown(&seen.version.git_version);
    let message = match issues.first() {
        Some(first) => first.text.clone(),
        None => pass_message(seen, &version),
    };
    let mut finding = Finding::new(level, message)
        .with_observed(observed(seen, &version))
        .with_expected(expected(rules));
    let mut fixes: Vec<&str> = Vec::new();
    for (index, issue) in issues.iter().enumerate() {
        if index > 0 {
            finding = finding.with_note(format!("Also: {}", issue.text));
        }
        if !fixes.contains(&issue.fix.as_str()) {
            fixes.push(&issue.fix);
        }
    }
    if !fixes.is_empty() {
        finding = finding.with_fix(fixes.join(" "));
    }
    for note in evidence(seen, &version) {
        finding = finding.with_note(note);
    }
    if matches!(seen.who, Who::NotVerified) {
        finding = finding.with_partial(Partial::new(
            Vec::new(),
            "who rdy is was not verified: the server is older than 1.28 and has no SelfSubjectReview",
        ));
    }
    finding
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

fn pass_message(seen: &Seen<'_>, version: &str) -> String {
    let server = seen.facts.line().server();
    let ms = seen.latency.as_millis();
    match &seen.who {
        Who::Verified { username, .. } => {
            format!("Connected to {server} as {username}, Kubernetes {version}, {ms} ms.")
        }
        _ => format!(
            "Connected to {server}, Kubernetes {version}, {ms} ms. Who rdy is could not be shown."
        ),
    }
}

/// The evidence lines of the report, whatever the level.
fn evidence(seen: &Seen<'_>, version: &str) -> Vec<String> {
    let facts = seen.facts;
    let mut notes = Vec::new();
    notes.push(format!(
        "Kubeconfig from {}; context {}; Kubernetes {version} on {}.",
        facts.source().label(),
        facts.line().context(),
        shown(&seen.version.platform)
    ));
    match &seen.who {
        Who::Verified {
            username,
            groups,
            group_count,
        } => {
            let listed: Vec<&str> = groups.iter().take(GROUPS_LISTED).map(String::as_str).collect();
            let mut line = format!("Identity: {username}");
            if !listed.is_empty() {
                line.push_str(&format!("; groups: {}", listed.join(", ")));
                if *group_count > listed.len() {
                    line.push_str(&format!(" and {} more", group_count - listed.len()));
                }
            }
            notes.push(line);
        }
        Who::NotVerified => notes.push(
            "Identity: not verified. The server has no SelfSubjectReview (added in 1.28); one access review was accepted, so the credentials work.".to_owned(),
        ),
        _ => {}
    }
    notes.extend(facts_notes(facts));
    match (&seen.discovery.core_versions, seen.discovery.group_count) {
        (Some(core), Some(groups)) => notes.push(format!(
            "Discovery: /api serves {}; /apis lists {groups} groups.",
            core.join(", ")
        )),
        (Some(core), None) => notes.push(format!("Discovery: /api serves {}.", core.join(", "))),
        (None, Some(groups)) => notes.push(format!("Discovery: /apis lists {groups} groups.")),
        (None, None) => {}
    }
    notes.extend(seen.discovery.notes.iter().cloned());
    notes
}

/// What the config says, as evidence lines: the credential plugin, the credentials, the route and the
/// trust. These are known before any request, so a failed connection reports them too.
pub(super) fn facts_notes(facts: &ConnectionFacts) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(binary) = facts
        .credentials()
        .iter()
        .find_map(|credential| match credential {
            Credential::Plugin { binary } => Some(binary),
            _ => None,
        })
    {
        notes.push(format!(
            "This kubeconfig runs `{binary}` to get credentials. They are short-lived and refreshed by `{binary}`, so no expiry is checked."
        ));
    }
    for credential in facts.credentials() {
        if matches!(credential, Credential::Token { expires_in: None }) {
            notes.push("The token in the kubeconfig has no known expiry (it is not a JWT with an exp claim).".to_owned());
        }
        if matches!(
            credential,
            Credential::ClientCertificate { expires_in: None }
        ) {
            notes.push("The expiry of the client certificate could not be read.".to_owned());
        }
    }
    if facts.credentials().is_empty() {
        notes.push("The kubeconfig user has no credentials.".to_owned());
    }
    match facts.proxy().describe() {
        Some(route) => notes.push(format!("Route to the API server: {route}.")),
        None => notes.push("Route to the API server: direct, no proxy configured.".to_owned()),
    }
    if facts.line().tls_verification_off() {
        notes.push("TLS verification is OFF.".to_owned());
    } else if !facts.ca_set() {
        notes.push("The kubeconfig names no certificate authority, so rdy trusts only its bundled public roots, not this machine's store.".to_owned());
    }
    notes
}

/// The credential in `facts` that has already ended, with the sentence that says so.
pub(super) fn first_ended(facts: &ConnectionFacts) -> Option<(String, &Credential)> {
    facts.credentials().iter().find_map(|credential| {
        let left = credential.expires_in().filter(|left| *left < 0)?;
        Some((ended_text(credential, left), credential))
    })
}

fn ended_text(credential: &Credential, left: i64) -> String {
    format!(
        "The {} in the kubeconfig ended {} ago.",
        kind_name(credential),
        span(left)
    )
}

fn credential_json(credential: &Credential) -> Value {
    match credential {
        Credential::Token { expires_in } => {
            json!({"kind": "token", "expires_in_seconds": expires_in})
        }
        Credential::ClientCertificate { expires_in } => {
            json!({"kind": "client_certificate", "expires_in_seconds": expires_in})
        }
        Credential::Password => json!({"kind": "password"}),
        Credential::Plugin { binary } => json!({"kind": "exec_plugin", "binary": binary}),
        Credential::ServiceAccount => json!({"kind": "service_account"}),
    }
}

/// The proxy part of `observed`, also used for a failed connection.
pub(super) fn proxy_json(facts: &ConnectionFacts) -> Value {
    let rule = match facts.proxy().rule() {
        ProxyRule::None => "none",
        ProxyRule::KubeconfigProxyUrl => "kubeconfig_proxy_url",
        ProxyRule::Environment(_) => "environment",
        ProxyRule::Bypassed { .. } => "bypassed",
    };
    json!({"rule": rule, "proxy": facts.proxy().proxy(), "description": facts.proxy().describe()})
}

fn observed(seen: &Seen<'_>, version: &str) -> Value {
    let facts = seen.facts;
    let identity = match &seen.who {
        Who::Verified {
            username,
            groups,
            group_count,
        } => json!({
            "verified": true,
            "username": username,
            "groups": groups.iter().take(GROUPS_LISTED * 2).collect::<Vec<_>>(),
            "group_count": group_count,
        }),
        _ => json!({"verified": false}),
    };
    let tls = if facts.line().tls_verification_off() {
        "off"
    } else if facts.ca_set() {
        "kubeconfig_ca"
    } else {
        "bundled_roots"
    };
    json!({
        "state": "connected",
        "context": facts.line().context(),
        "server": facts.line().server(),
        "source": facts.source().label(),
        "version": version,
        "latency_ms": u64::try_from(seen.latency.as_millis()).unwrap_or(u64::MAX),
        "identity": identity,
        "credentials": facts.credentials().iter().map(credential_json).collect::<Vec<_>>(),
        "proxy": proxy_json(facts),
        "tls_verification": tls,
        "discovery": {
            "core_versions": seen.discovery.core_versions,
            "group_count": seen.discovery.group_count,
        },
    })
}

fn expected(rules: &Rules) -> Value {
    json!({
        "context_pattern": rules.context_pattern,
        "server_pattern": rules.server_pattern,
        "max_latency_ms": u64::try_from(rules.max_latency.as_millis()).unwrap_or(u64::MAX),
        "credential_expiry_warn_days": EXPIRY_WARN_SECS / 86_400,
    })
}

/// The `expected` value of a connection that did not work: the same keys.
pub(super) fn expected_for(rules: &Rules) -> Value {
    expected(rules)
}

/// The groups of a `SelfSubjectReview` answer, escaped and cut.
pub(super) fn who_from_user(username: &str, groups: &[String]) -> Who {
    Who::Verified {
        username: shown(username),
        groups: groups
            .iter()
            .take(GROUPS_KEPT)
            .map(|group| shown(group))
            .collect(),
        group_count: groups.len(),
    }
}

#[cfg(test)]
mod unit_tests;
