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

/// A JWT whose `exp` is 100 s before `NOW`.
const JWT_EXPIRED: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTMzMTgzMDB9.c2ln";
/// 2026-10-30 00:00:00 UTC.
const NOW: i64 = 1_793_318_400;

fn expired_token_facts() -> ConnectionFacts {
    facts(
        &kubeconfig(
            "ctx",
            "https://k8s.acme.example:6443",
            "",
            &format!("\n    token: {JWT_EXPIRED}\n"),
        ),
        &[],
        &Env::empty().with_now(NOW),
    )
}

#[test]
fn an_ended_credential_blocks_only_when_the_server_says_401() {
    let facts = expired_token_facts();
    let version = version();
    let finding = judge(&rules(), &seen(&facts, &version, Who::Unauthorized));
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "The token in the kubeconfig ended 1 minute ago."
    );
    // The 401 text is left out: the ended token explains it.
    assert!(
        !finding
            .notes
            .iter()
            .any(|note| note.contains("did not accept")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn an_ended_credential_the_server_accepted_is_a_clock_warning_for_every_answer_of_the_review() {
    let facts = expired_token_facts();
    let version = version();
    for who in [
        who_from_user("jane", &["system:authenticated".to_owned()]),
        who_from_user("system:anonymous", &[]),
        Who::NotVerified(NotVerified::Before128 { v1beta1: false }),
    ] {
        let finding = judge(&rules(), &seen(&facts, &version, who));
        assert_eq!(finding.level, Level::Warn, "{}", finding.message);
        assert!(
            finding.message.contains("clock is probably wrong"),
            "{}",
            finding.message
        );
        assert!(finding.message.contains("yet the server did not reject it"));
        assert!(finding.fix.expect("a fix").contains("`timedatectl`"));
    }
    // A 403 on the review is a block of its own, and the server still did not say 401.
    let finding = judge(&rules(), &seen(&facts, &version, Who::Forbidden));
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("clock is probably wrong")),
        "{:?}",
        finding.notes
    );
}

#[test]
fn an_ended_credential_without_an_answer_is_a_plain_warning_that_blames_no_clock() {
    let facts = expired_token_facts();
    let version = version();
    for who in [
        Who::Broken(KubeError::Timeout {
            server: "https://k8s.acme.example".to_owned(),
            proxied: false,
        }),
        Who::Other { code: 500 },
        Who::Silent,
    ] {
        let finding = judge(&rules(), &seen(&facts, &version, who));
        let text = format!(
            "{} {:?} {}",
            finding.message,
            finding.notes,
            finding.fix.unwrap_or_default()
        );
        // A broken connection blocks on its own and lists the ended credential under "Also".
        assert!(
            text.contains(
                "The token in the kubeconfig ended 1 minute ago by this machine's clock."
            ),
            "{text}"
        );
        assert!(!text.contains("did not reject"), "{text}");
        assert!(!text.contains("clock is probably wrong"), "{text}");
        assert!(!text.contains("timedatectl"), "{text}");
    }
}

fn version_of(git_version: &str, major: &str, minor: &str) -> ServerVersion {
    ServerVersion {
        git_version: git_version.to_owned(),
        major: major.to_owned(),
        minor: minor.to_owned(),
        platform: "linux/amd64".to_owned(),
    }
}

#[test]
fn the_version_says_why_the_identity_review_has_no_route() {
    for (version, want) in [
        (
            version_of("v1.27.9", "1", "27"),
            NotVerified::Before128 { v1beta1: true },
        ),
        (
            version_of("v1.26.1", "1", "26"),
            NotVerified::Before128 { v1beta1: false },
        ),
        (version_of("v1.28.0", "1", "28"), NotVerified::NotServed),
        (
            version_of("v1.29.4-eks-abc123", "1", "29+"),
            NotVerified::NotServed,
        ),
        (version_of("v1.36.0", "1", "36"), NotVerified::NotServed),
        // A git version that does not parse falls back to the minor, then to unknown.
        (
            version_of("garbage", "1", "27"),
            NotVerified::Before128 { v1beta1: true },
        ),
        (version_of("garbage", "1", "29+"), NotVerified::NotServed),
        (version_of("garbage", "", ""), NotVerified::Unknown),
        (version_of("v2.1.0", "2", "1"), NotVerified::Unknown),
    ] {
        assert_eq!(NotVerified::of(&version), want, "{}", version.git_version);
    }
}

#[test]
fn each_reason_has_its_own_words_and_none_is_empty() {
    let texts: Vec<(&str, &str)> = [
        NotVerified::Before128 { v1beta1: true },
        NotVerified::Before128 { v1beta1: false },
        NotVerified::NotServed,
        NotVerified::Unknown,
    ]
    .into_iter()
    .map(|why| (why.why(), why.short()))
    .collect();
    for (long, short) in &texts {
        assert!(!long.is_empty() && !short.is_empty());
        assert!(!long.contains('\u{2014}') && !short.contains('\u{2014}'));
    }
    assert!(texts[0].0.contains("v1beta1") && texts[0].0.contains("1.27"));
    assert!(texts[2].0.contains("although it is 1.28 or later"));
    assert!(texts[2].0.contains("disabled") && texts[2].0.contains("gateway"));
    let distinct: std::collections::BTreeSet<&str> = texts.iter().map(|(long, _)| *long).collect();
    assert_eq!(distinct.len(), 4);
}

#[test]
fn a_proxy_in_the_path_with_tls_verification_off_says_it_can_read_the_token() {
    let env = Env::empty().with_https_proxy("http://proxy.acme.example:3128");
    let yaml = kubeconfig(
        "ctx",
        "https://k8s.acme.example:6443",
        "    insecure-skip-tls-verify: true\n",
        "\n    token: t\n",
    );
    let facts = facts(&yaml, &[], &env);
    let version = version();
    let finding = judge(
        &rules(),
        &seen(
            &facts,
            &version,
            who_from_user("jane", &["system:authenticated".to_owned()]),
        ),
    );
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("A proxy is in the path, and it can read the credentials rdy sends."),
        "{}",
        finding.message
    );
    // Without a proxy the warning does not claim it.
    let direct = facts_direct_insecure();
    let finding = judge(
        &rules(),
        &seen(
            &direct,
            &version,
            who_from_user("jane", &["system:authenticated".to_owned()]),
        ),
    );
    assert!(!finding.message.contains("proxy"), "{}", finding.message);
}

fn facts_direct_insecure() -> ConnectionFacts {
    facts(
        &kubeconfig(
            "ctx",
            "https://k8s.acme.example:6443",
            "    insecure-skip-tls-verify: true\n",
            "\n    token: t\n",
        ),
        &[],
        &Env::empty(),
    )
}
