//! Tests of the small pure parts of the judgement: spans of time, the cut of server text, and the order of
//! several problems. The whole check is in `access/tests.rs`.

use super::*;
use crate::client::Env;
use crate::client::testkit::{facts, kubeconfig};

#[test]
fn a_span_counts_in_the_largest_whole_unit() {
    for (seconds, want) in [
        (0, "1 minute"),
        (59, "1 minute"),
        (60, "1 minute"),
        (119, "1 minute"),
        (120, "2 minutes"),
        (3_599, "59 minutes"),
        (3_600, "1 hour"),
        (7_199, "1 hour"),
        (7_200, "2 hours"),
        (86_399, "23 hours"),
        (86_400, "1 day"),
        (3 * 86_400 + 5, "3 days"),
        (-86_400, "1 day"),
        (-100, "1 minute"),
        (i64::MIN, "106751991167300 days"),
    ] {
        assert_eq!(span(seconds), want, "{seconds}");
    }
}

#[test]
fn server_text_is_escaped_and_cut() {
    assert_eq!(shown("plain"), "plain");
    assert_eq!(shown("a\u{1b}[2Jb"), "a\\x1b[2Jb");
    let long = "x".repeat(SHOWN + 10);
    let cut = shown(&long);
    assert_eq!(cut.len(), SHOWN + 3);
    assert!(cut.ends_with("..."));
    // The cut counts characters, so a multi-byte character is never split.
    assert!(shown(&"\u{e9}".repeat(SHOWN + 1)).ends_with("..."));
}

#[test]
fn a_user_is_kept_whole_and_its_groups_are_capped_but_counted() {
    let groups: Vec<String> = (0..80).map(|n| format!("g{n}")).collect();
    match who_from_user("jane", &groups) {
        Who::Verified {
            username,
            groups,
            group_count,
        } => {
            assert_eq!(username, "jane");
            assert_eq!(groups.len(), GROUPS_KEPT);
            assert_eq!(group_count, 80);
        }
        other => panic!("{other:?}"),
    }
}

fn token_facts() -> ConnectionFacts {
    facts(
        &kubeconfig(
            "ctx",
            "https://k8s.acme.example:6443",
            "",
            "\n    token: t\n",
        ),
        &[],
        &Env::empty(),
    )
}

fn rules() -> Rules {
    Rules {
        context_pattern: None,
        server_pattern: None,
        max_latency: DEFAULT_MAX_LATENCY,
    }
}

fn seen<'a>(facts: &'a ConnectionFacts, version: &'a ServerVersion, who: Who) -> Seen<'a> {
    Seen {
        facts,
        version,
        latency: Duration::from_millis(5),
        who,
        discovery: Discovery::default(),
    }
}

fn version() -> ServerVersion {
    ServerVersion {
        git_version: "v1.30.2".to_owned(),
        major: "1".to_owned(),
        minor: "30".to_owned(),
        platform: "linux/amd64".to_owned(),
    }
}

#[test]
fn the_worst_problem_leads_and_the_others_follow_as_notes() {
    let facts = token_facts();
    let version = version();
    let rules = Rules {
        // Both patterns fail (a block each), and the identity is anonymous (a warning).
        context_pattern: Some("^nope".to_owned()),
        server_pattern: Some("^nope".to_owned()),
        ..rules()
    };
    let who = Who::Verified {
        username: "system:anonymous".to_owned(),
        groups: Vec::new(),
        group_count: 0,
    };
    let finding = judge(&rules, &seen(&facts, &version, who));
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.starts_with("The kube context is ctx"),
        "{}",
        finding.message
    );
    let also: Vec<&String> = finding
        .notes
        .iter()
        .filter(|note| note.starts_with("Also: "))
        .collect();
    assert_eq!(also.len(), 2, "{:?}", finding.notes);
    assert!(also[0].contains("The API server is"), "{also:?}");
    assert!(also[1].contains("system:anonymous"), "{also:?}");
}

#[test]
fn identical_fixes_are_given_once() {
    let facts = token_facts();
    let version = version();
    let rules = Rules {
        context_pattern: Some("^nope".to_owned()),
        server_pattern: Some("^nope".to_owned()),
        ..rules()
    };
    let finding = judge(
        &rules,
        &seen(
            &facts,
            &version,
            who_from_user("jane", &["system:authenticated".to_owned()]),
        ),
    );
    let fix = finding.fix.expect("a fix");
    assert_eq!(fix.matches("`--kube-context <name>`").count(), 2, "{fix}");
    assert_eq!(
        fix.matches("`kubectl config get-contexts`").count(),
        1,
        "{fix}"
    );
}

#[test]
fn a_pattern_that_cannot_be_compiled_here_is_not_a_mismatch() {
    // `AccessCheck::new` refuses such a pattern, so this cannot happen. If it did, the check would not
    // block a run on a pattern it cannot read.
    assert_eq!(matches("(", "anything"), None);
    assert_eq!(matches("^a", "abc"), Some(true));
    assert_eq!(matches("^a", "xbc"), Some(false));
}

#[test]
fn a_connection_that_breaks_while_asking_is_a_block_with_that_errors_fix() {
    let facts = token_facts();
    let version = version();
    let error = KubeError::Timeout {
        server: "https://k8s.acme.example:6443".to_owned(),
        proxied: false,
    };
    let finding = judge(&rules(), &seen(&facts, &version, Who::Broken(error)));
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "no answer from https://k8s.acme.example:6443 in time"
    );
    assert!(finding.fix.expect("a fix").contains("No reply from"));
}
