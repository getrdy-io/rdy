//! Tests of `Probe::lookup` and the address rule it applies (M1-094).
//!
//! The exit test: link-local, metadata and IPv4-mapped answers are refused, including the GCP IPv6
//! metadata address and a recorded link-local answer from a Replay fixture; an unlisted name is
//! refused; the lookup is one `lookup` entry that holds the count and no address.

use std::net::IpAddr;

use rdy_spec::result::{ActionKind, ActionOutcome};
use serde_json::json;

use super::*;
use crate::probe::net::tests::{
    assert_matches_result_schema, denied_rule, direct_only, entries, field, hub_over, ip, load_net,
    no_peers, probe, probe_with,
};
use crate::probe::replay::Replay;
use crate::probe::{ProbeError, RULE_CHECK_FINISHED};

/// Every address the facade must refuse, as a resolver might answer it.
const REFUSED: [&str; 14] = [
    "169.254.169.254",
    "169.254.0.1",
    "100.100.100.200",
    "168.63.129.16",
    "fe80::1",
    "fd00:ec2::254",
    "fd20:ce::254",
    "::ffff:169.254.169.254",
    "::ffff:168.63.129.16",
    "::169.254.169.254",
    "64:ff9b::a9fe:a9fe",
    "64:ff9b::a83f:8110",
    "0.0.0.0",
    "224.0.0.1",
];

#[tokio::test(start_paused = true)]
async fn a_lookup_returns_the_answers_and_logs_a_count_but_no_address() {
    let hub = hub_over(Replay::new().host(
        "web.acme.test",
        [ip("192.0.2.7"), ip("2001:db8::7"), ip("192.0.2.7")],
    ));
    let probe = probe(&hub, &["web.acme.test:443"]);
    let answers = probe.lookup("web.acme.test").await.expect("answers");
    assert_eq!(answers, vec![ip("192.0.2.7"), ip("2001:db8::7")]);
    // The name is compared in lower case.
    assert_eq!(
        probe.lookup("WEB.acme.test").await.expect("answers").len(),
        2
    );

    let log = entries(&hub);
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].kind, ActionKind::Lookup);
    assert_eq!(log[0].outcome, ActionOutcome::Ok);
    assert_eq!(field(&log[0], "host"), Some(&json!("web.acme.test")));
    assert_eq!(field(&log[0], "answers"), Some(&json!(2)));
    let text = serde_json::to_string(&log).expect("log");
    assert!(!text.contains("192.0.2.7"), "{text}");
}

#[tokio::test(start_paused = true)]
async fn a_refused_answer_refuses_the_whole_lookup_and_returns_no_address() {
    let mut replay =
        Replay::new().host("mixed.acme.test", [ip("192.0.2.7"), ip("169.254.169.254")]);
    let mut names = vec!["mixed.acme.test:443".to_owned()];
    for (i, text) in REFUSED.iter().enumerate() {
        replay = replay.host(&format!("bad{i}.acme.test"), [ip(text)]);
        names.push(format!("bad{i}.acme.test:443"));
    }
    let hub = hub_over(replay);
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let probe = probe(&hub, &names);
    for name in &names {
        let host = name.trim_end_matches(":443");
        let error = probe.lookup(host).await.expect_err("a refused answer");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{host}");
    }
    let log = entries(&hub);
    assert_eq!(log.len(), names.len());
    for entry in &log {
        assert_eq!(entry.outcome, ActionOutcome::Denied);
        assert_eq!(field(entry, "rule"), Some(&json!(RULE_TCP_ADDRESS)));
        assert_eq!(field(entry, "answers"), None, "no count of refused answers");
    }
}

#[tokio::test(start_paused = true)]
async fn a_recorded_link_local_answer_from_a_fixture_is_refused_by_the_address_rule() {
    // The fixture records the forbidden answers as they are. The loader accepts them and the
    // facade's rule, not the backend, refuses them (correction 18).
    let fixture = load_net(
        r#"{"dns": {"meta.acme.test": ["169.254.169.254"],
                    "gcp6.acme.test": ["fd20:ce::254"],
                    "wire.acme.test": ["168.63.129.16"],
                    "ok.acme.test": ["192.0.2.9"]}}"#,
    );
    let hub = hub_over(fixture.into_replay());
    let probe = probe(
        &hub,
        &[
            "meta.acme.test:443",
            "gcp6.acme.test:443",
            "wire.acme.test:443",
            "ok.acme.test:443",
        ],
    );
    for host in ["meta.acme.test", "gcp6.acme.test", "wire.acme.test"] {
        let error = probe.lookup(host).await.expect_err("recorded and refused");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{host}");
    }
    assert_eq!(
        probe.lookup("ok.acme.test").await.expect("allowed"),
        vec![ip("192.0.2.9")]
    );
}

#[tokio::test(start_paused = true)]
async fn a_name_that_is_not_one_of_the_checks_hosts_is_refused_before_any_lookup() {
    let hub = hub_over(Replay::new().host("other.acme.test", [ip("192.0.2.7")]));
    // `other.acme.test` is in the replay, and listed for another check only.
    let probe = probe(&hub, &["web.acme.test:443"]);
    let error = probe.lookup("other.acme.test").await.expect_err("unlisted");
    assert_eq!(denied_rule(&error), RULE_LOOKUP_HOST);
    // A name the replay does not hold would be `NotRecorded` if the backend were asked.
    let error = probe
        .lookup("web.acme.test")
        .await
        .expect_err("not recorded");
    assert!(matches!(error, ProbeError::NotRecorded(_)), "{error:?}");

    let log = entries(&hub);
    assert_eq!(log[0].outcome, ActionOutcome::Denied);
    assert_eq!(log[0].kind, ActionKind::Lookup);
}

#[tokio::test(start_paused = true)]
async fn a_check_without_the_peer_class_or_hosts_can_look_up_nothing() {
    let hub = hub_over(Replay::new().host("web.acme.test", [ip("192.0.2.7")]));
    // Hosts given, class not declared.
    let undeclared = probe_with(&hub, no_peers(), "net.none", &["web.acme.test:443"]);
    let error = undeclared.lookup("web.acme.test").await.expect_err("class");
    assert_eq!(denied_rule(&error), RULE_TCP_UNDECLARED);
    // Class declared, no hosts given.
    let bare = hub.check_probe("net.direct", crate::check::Os::Linux, Some(direct_only()));
    let error = bare.lookup("web.acme.test").await.expect_err("no hosts");
    assert_eq!(denied_rule(&error), RULE_LOOKUP_HOST);
    // The run-level probe has no check and no hosts.
    let error = hub
        .run_probe()
        .lookup("web.acme.test")
        .await
        .expect_err("run");
    assert_eq!(denied_rule(&error), RULE_TCP_UNDECLARED);
}

#[tokio::test(start_paused = true)]
async fn a_literal_is_judged_without_asking_the_resolver() {
    // The replay holds no names, so any resolver call would be `NotRecorded`.
    let hub = hub_over(Replay::new());
    let probe = probe(
        &hub,
        &[
            "10.0.0.5:443",
            "[2001:db8::5]:443",
            "169.254.169.254:80",
            "[fd20:ce::254]:80",
            "168.63.129.16:80",
            "[fe80::1]:80",
        ],
    );
    assert_eq!(
        probe.lookup("10.0.0.5").await.expect("literal"),
        vec![ip("10.0.0.5")]
    );
    // An IPv6 literal may be written with or without brackets.
    for text in ["2001:db8::5", "[2001:db8::5]"] {
        assert_eq!(
            probe.lookup(text).await.expect("literal"),
            vec![ip("2001:db8::5")]
        );
    }
    for text in [
        "169.254.169.254",
        "fd20:ce::254",
        "[fd20:ce::254]",
        "168.63.129.16",
        "fe80::1",
    ] {
        let error = probe.lookup(text).await.expect_err("refused literal");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "{text}");
    }
    // A literal the spec did not list is refused as an unlisted host.
    let error = probe.lookup("10.0.0.6").await.expect_err("unlisted");
    assert_eq!(denied_rule(&error), RULE_LOOKUP_HOST);
}

#[tokio::test(start_paused = true)]
async fn a_name_that_does_not_resolve_is_a_typed_failure_with_a_fixed_log_phrase() {
    let fixture = load_net(r#"{"dns": {"gone.acme.test": "NXDOMAIN", "empty.acme.test": []}}"#);
    let hub = hub_over(fixture.into_replay());
    let probe = probe(&hub, &["gone.acme.test:443", "empty.acme.test:443"]);
    for host in ["gone.acme.test", "empty.acme.test"] {
        let error = probe.lookup(host).await.expect_err("no answer");
        assert!(
            matches!(&error, ProbeError::Net(NetFailure::Dns { host: h }) if h == host),
            "{error:?}"
        );
    }
    let log = entries(&hub);
    assert!(log.iter().all(|e| e.outcome == ActionOutcome::Failed));
    assert_eq!(
        field(&log[0], "error"),
        Some(&json!("the name did not resolve"))
    );
}

#[tokio::test(start_paused = true)]
async fn repeats_are_removed_and_the_answers_are_capped() {
    let many: Vec<IpAddr> = (1..=100_u8)
        .flat_map(|n| [ip(&format!("192.0.2.{n}")), ip(&format!("192.0.2.{n}"))])
        .collect();
    let hub = hub_over(Replay::new().host("big.acme.test", many));
    let probe = probe(&hub, &["big.acme.test:443"]);
    let answers = probe.lookup("big.acme.test").await.expect("answers");
    assert_eq!(answers.len(), MAX_ANSWERS);
    assert_eq!(answers[0], ip("192.0.2.1"));
    assert_eq!(answers[1], ip("192.0.2.2"));
    let log = entries(&hub);
    assert_eq!(field(&log[0], "answers"), Some(&json!(MAX_ANSWERS)));
}

#[tokio::test(start_paused = true)]
async fn a_lookup_after_the_check_ended_is_denied_and_logged() {
    let hub = hub_over(Replay::new().host("web.acme.test", [ip("192.0.2.7")]));
    let probe = probe(&hub, &["web.acme.test:443"]);
    probe.end();
    let error = probe.lookup("web.acme.test").await.expect_err("ended");
    assert_eq!(denied_rule(&error), RULE_CHECK_FINISHED);
    assert_eq!(entries(&hub).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn lookup_entries_match_the_result_schema() {
    let hub = hub_over(
        Replay::new()
            .host("web.acme.test", [ip("192.0.2.7")])
            .host("meta.acme.test", [ip("169.254.169.254")]),
    );
    let probe = probe(
        &hub,
        &[
            "web.acme.test:443",
            "meta.acme.test:443",
            "gone.acme.test:443",
        ],
    );
    probe.lookup("web.acme.test").await.expect("ok");
    probe.lookup("meta.acme.test").await.expect_err("denied");
    probe.lookup("other.acme.test").await.expect_err("unlisted");

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sample =
        std::fs::read_to_string(root.join("../../tests/fixtures/reports/not-ready-7.2.json"))
            .expect("the fixture is in the repo");
    let mut report: rdy_spec::result::Report = serde_json::from_str(&sample).expect("a report");
    hub.action_log().apply(&mut report);
    let json = serde_json::to_value(&report).expect("report");
    assert_matches_result_schema(&json);
    let lookups = json["actions"]
        .as_array()
        .expect("actions")
        .iter()
        .filter(|a| a["kind"] == "lookup" && a["check"] == "net.egress")
        .count();
    assert_eq!(lookups, 3);
}

#[tokio::test(start_paused = true)]
async fn tls_and_http_apply_the_same_host_set_and_address_rule_as_tcp() {
    use crate::probe::net::{HttpMethod, HttpProbe, Route};
    use crate::probe::{NativeCall, NativeValue};
    use crate::testing::loopback::TestCa;
    let root = TestCa::root("Acme Test Root").root_der().as_ref().to_vec();
    let hub = hub_over(
        Replay::new()
            .native(
                NativeCall::SystemRoots,
                NativeValue::SystemRoots(vec![root].into()),
            )
            .host("meta.acme.test", [ip("fd20:ce::254")])
            .host("other.acme.test", [ip("192.0.2.7")]),
    );
    let probe = probe(
        &hub,
        &[
            "meta.acme.test:443",
            "169.254.169.254:443",
            "168.63.129.16:443",
        ],
    );
    for text in [
        "meta.acme.test:443",
        "169.254.169.254:443",
        "168.63.129.16:443",
    ] {
        let target = crate::probe::net::tests::target(text);
        let error = probe
            .tls_chain(&target, Route::Direct)
            .await
            .expect_err("refused address");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "tls {text}");
        let url = crate::probe::net::tests::target(&format!("https://{text}/"));
        let error = probe
            .http(HttpProbe::new(url, HttpMethod::Get))
            .await
            .expect_err("refused address");
        assert_eq!(denied_rule(&error), RULE_TCP_ADDRESS, "http {text}");
    }
    // An endpoint the check does not list is refused, whatever it resolves to.
    let unlisted = crate::probe::net::tests::target("other.acme.test:443");
    let error = probe
        .tls_chain(&unlisted, Route::Direct)
        .await
        .expect_err("unlisted");
    assert_eq!(denied_rule(&error), crate::probe::net::RULE_TCP_HOST);
    let url = crate::probe::net::tests::target("https://other.acme.test/");
    let error = probe
        .http(HttpProbe::new(url, HttpMethod::Get))
        .await
        .expect_err("unlisted");
    assert_eq!(denied_rule(&error), crate::probe::net::RULE_TCP_HOST);
    // Only the run-level roots read is allowed; every network call was refused.
    assert!(
        entries(&hub)
            .iter()
            .filter(|e| e.kind != ActionKind::Native)
            .all(|e| e.outcome == ActionOutcome::Denied)
    );
}
