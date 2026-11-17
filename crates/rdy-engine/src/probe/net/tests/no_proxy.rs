//! `NO_PROXY`, two spellings of one variable, and the proxy reach call (M1-098).

use super::*;
use crate::probe::{EnvConflict, Exemption, env_conflicts};

fn proxy_only() -> &'static CheckInfo {
    static INFO: CheckInfo = CheckInfo {
        id: "net.proxy",
        family: "net",
        summary: "A fixture check.",
        meta: META,
        needs: &[],
        wants: &[],
        default_timeout: None,
        os: ALL_OS,
        reads: &[],
        statfs: &[],
        env: &[],
        commands: &[],
        peers: &[PeerClass::Proxy],
    };
    &INFO
}

#[tokio::test]
async fn route_for_sends_a_no_proxy_host_direct_and_every_other_host_through_the_proxy() {
    let hub = hub_over(
        Replay::new()
            .env("HTTPS_PROXY", &proxy_url(false))
            .env("NO_PROXY", "direct.acme.test, 10.0.0.0/8"),
    );
    assert_eq!(hub.set_proxy_from_env(), Ok(Some("HTTPS_PROXY")));
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    let direct = probe.route_for(&target("direct.acme.test:443"));
    assert_eq!(direct.route, Route::Direct);
    assert_eq!(
        direct.exempt,
        Some(Exemption::Entry("direct.acme.test".to_owned()))
    );
    let subdomain = probe.route_for(&target("a.direct.acme.test:443"));
    assert_eq!(subdomain.route, Route::Direct);
    assert_eq!(
        probe.route_for(&target("10.2.3.4:5000")).route,
        Route::Direct
    );
    // Everything else uses the proxy, and so does a host that only looks like an entry.
    for text in [
        "api.acme.test:443",
        "notdirect.acme.test:443",
        "11.0.0.1:80",
    ] {
        let other = probe.route_for(&target(text));
        assert_eq!(other.route, Route::ViaProxy, "{text}");
        assert_eq!(other.exempt, None, "{text}");
    }
    // Loopback never uses a proxy, with or without a list.
    let loopback = probe.route_for(&target("127.0.0.1:80"));
    assert_eq!(
        (loopback.route, loopback.exempt),
        (Route::Direct, Some(Exemption::Loopback))
    );
    // The routing call is a read of the run's state: it writes no log entry.
    let before = hub.action_log().actions.len();
    let _ = probe.route_for(&target("api.acme.test:443"));
    assert_eq!(hub.action_log().actions.len(), before);
    let (list, var) = probe.no_proxy().expect("the list");
    assert_eq!((var, list.len()), ("NO_PROXY", 2));
}

#[tokio::test]
async fn no_proxy_reads_the_lower_case_name_and_skips_a_blank_upper_case_one() {
    let hub = hub_over(
        Replay::new()
            .env("HTTPS_PROXY", &proxy_url(false))
            .env("no_proxy", ".acme.test"),
    );
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert_eq!(
        probe.route_for(&target("api.acme.test:443")).route,
        Route::Direct
    );
    assert_eq!(probe.no_proxy().map(|(_, var)| var), Some("no_proxy"));

    let hub = hub_over(
        Replay::new()
            .env("HTTPS_PROXY", &proxy_url(false))
            .env("NO_PROXY", "  ")
            .env("no_proxy", ".acme.test"),
    );
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert_eq!(probe.no_proxy().map(|(_, var)| var), Some("no_proxy"));
}

#[tokio::test]
async fn a_run_with_no_proxy_has_no_route_to_take_and_no_list_means_loopback_only() {
    let hub = hub_over(Replay::new());
    assert_eq!(hub.set_proxy_from_env(), Ok(None));
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    let direct = probe.route_for(&target("api.acme.test:443"));
    assert_eq!((direct.route, direct.exempt), (Route::Direct, None));
    assert!(probe.no_proxy().is_none());
    assert!(hub.action_log().actions.is_empty(), "no variable, no entry");

    let hub = hub_over(Replay::new().env("HTTPS_PROXY", &proxy_url(false)));
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert_eq!(
        probe.route_for(&target("api.acme.test:443")).route,
        Route::ViaProxy
    );
    assert_eq!(probe.route_for(&target("[::1]:443")).route, Route::Direct);
}

#[tokio::test]
async fn a_no_proxy_list_alone_is_kept_and_logged_by_name_only() {
    let hub = hub_over(Replay::new().env("NO_PROXY", "internal-canary.acme.test"));
    assert_eq!(hub.set_proxy_from_env(), Ok(None));
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert!(probe.no_proxy().is_some());
    assert!(probe.proxy_origin().is_none());
    let log = log_text(&hub);
    assert!(log.contains("NO_PROXY"), "{log}");
    assert!(!log.contains("internal-canary"), "{log}");
}

#[tokio::test]
async fn two_spellings_that_differ_are_recorded_by_name_and_equal_ones_are_not() {
    let hub = hub_over(
        Replay::new()
            .env("HTTPS_PROXY", &proxy_url(true))
            .env("https_proxy", "http://other.acme.test:8080")
            .env("HTTP_PROXY", "http://same.acme.test:80")
            .env("http_proxy", "http://same.acme.test:80")
            .env("NO_PROXY", ".svc")
            .env("no_proxy", ".svc "),
    );
    assert_eq!(hub.set_proxy_from_env(), Ok(Some("HTTPS_PROXY")));
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert_eq!(
        probe.proxy_env_conflicts(),
        [EnvConflict {
            upper: "HTTPS_PROXY",
            lower: "https_proxy"
        }]
    );
    let shown = format!("{:?} {}", probe.proxy_env_conflicts(), log_text(&hub));
    assert!(
        !shown.contains("other.acme.test") && !shown.contains(PASSWORD_RAW),
        "{shown}"
    );
    // A run that never read the environment has none.
    let bare = hub_over(Replay::new());
    let probe = bare.check_probe("net.egress", Os::Linux, Some(egress()));
    assert!(probe.proxy_env_conflicts().is_empty());
}

#[test]
fn env_conflicts_compares_trimmed_values_and_skips_blank_ones() {
    let get = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_owned())
        }
    };
    assert!(env_conflicts(get(&[("HTTPS_PROXY", "a"), ("https_proxy", " a ")])).is_empty());
    assert!(env_conflicts(get(&[("HTTPS_PROXY", "a"), ("https_proxy", "  ")])).is_empty());
    assert!(env_conflicts(get(&[("HTTPS_PROXY", "a")])).is_empty());
    assert_eq!(
        env_conflicts(get(&[("HTTP_PROXY", "a"), ("http_proxy", "b")])),
        [EnvConflict {
            upper: "HTTP_PROXY",
            lower: "http_proxy"
        }]
    );
}

/// A machine whose proxy name resolves to `192.0.2.50:3128`, with `script` for that address.
fn reach_machine(script: TcpScript) -> Replay {
    Replay::new()
        .env("HTTPS_PROXY", &proxy_url(true))
        .host("proxy.acme.test", [ip("192.0.2.50")])
        .tcp(addr("192.0.2.50:3128"), script)
}

#[tokio::test]
async fn proxy_reach_opens_one_connection_to_the_proxy_and_sends_nothing() {
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let machine = reach_machine(TcpScript::Serve("proxy".to_owned())).serve_duplex(
        "proxy",
        move |mut stream| {
            let counter = Arc::clone(&counter);
            async move {
                let mut buf = [0_u8; 64];
                // The client closes at once: whatever it sent is counted.
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    counter.fetch_add(n, Ordering::SeqCst);
                }
            }
        },
    );
    let hub = hub_over(machine);
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.proxy", Os::Linux, Some(proxy_only()));
    let report = probe.proxy_reach().await.expect("a report");
    assert!(report.connected);
    drop(probe);
    tokio::task::yield_now().await;
    assert_eq!(seen.load(Ordering::SeqCst), 0, "no byte was sent");
    let log = hub.action_log().actions;
    let connects: Vec<&Action> = log
        .iter()
        .filter(|a| a.kind == ActionKind::Connect)
        .collect();
    assert_eq!(connects.len(), 1, "{log:?}");
    assert_eq!(connects[0].fields["host"], "proxy.acme.test");
    assert_eq!(connects[0].fields["port"], 3128);
    assert!(connects[0].fields["via_proxy"].is_null());
    assert_eq!(connects[0].fields["addr"], "192.0.2.50");
    assert_eq!(connects[0].outcome, ActionOutcome::Ok);
    assert_no_credentials(&log_text(&hub));
}

#[tokio::test]
async fn proxy_reach_reports_a_closed_port_as_data_and_the_other_failures_as_errors() {
    let hub = hub_over(reach_machine(TcpScript::Refused));
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.proxy", Os::Linux, Some(proxy_only()));
    let report = probe.proxy_reach().await.expect("a report");
    assert!(!report.connected);
    assert_eq!(report.attempts[0].outcome, AttemptOutcome::Refused);
    let log = hub.action_log().actions;
    let connect = log
        .iter()
        .find(|a| a.kind == ActionKind::Connect)
        .expect("an entry");
    assert_eq!(connect.outcome, ActionOutcome::Failed);

    // A check that did not declare the proxy peer class is refused before any lookup.
    let hub = hub_over(reach_machine(TcpScript::Refused));
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.direct", Os::Linux, Some(direct_only()));
    let error = probe.proxy_reach().await.expect_err("undeclared");
    assert!(
        matches!(error, ProbeError::Denied { rule, .. } if rule == RULE_PROXY_UNDECLARED),
        "{error:?}"
    );
    assert!(
        !hub.action_log()
            .actions
            .iter()
            .any(|a| a.kind == ActionKind::Lookup),
        "no lookup"
    );

    // A run with no proxy has none to reach.
    let hub = hub_over(Replay::new());
    hub.set_proxy_from_env().expect("none");
    let probe = hub.check_probe("net.proxy", Os::Linux, Some(proxy_only()));
    let error = probe.proxy_reach().await.expect_err("no proxy");
    assert!(
        matches!(error, ProbeError::Net(NetFailure::NoProxy)),
        "{error:?}"
    );

    // `--no-network` is a refusal the check can read.
    let hub = hub_over(reach_machine(TcpScript::Refused));
    hub.set_proxy_from_env().expect("set");
    hub.set_network(false);
    let probe = hub.check_probe("net.proxy", Os::Linux, Some(proxy_only()));
    let error = probe.proxy_reach().await.expect_err("offline");
    assert!(error.is_no_network(), "{error:?}");
}

#[tokio::test]
async fn proxy_reach_refuses_a_proxy_that_resolves_to_a_forbidden_address() {
    let machine = Replay::new()
        .env("HTTPS_PROXY", &proxy_url(false))
        .host("proxy.acme.test", [ip("169.254.169.254")])
        .tcp(addr("169.254.169.254:3128"), TcpScript::Refused);
    let hub = hub_over(machine);
    hub.set_proxy_from_env().expect("set");
    let probe = hub.check_probe("net.proxy", Os::Linux, Some(proxy_only()));
    let error = probe.proxy_reach().await.expect_err("refused");
    assert!(
        matches!(error, ProbeError::Denied { rule, .. } if rule == RULE_PROXY_ADDRESS),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_all_proxy_password_is_hidden_and_one_the_set_refuses_is_an_error() {
    // ALL_PROXY is not the run's proxy, but `net.proxy` reports it, so its password joins the known secrets.
    let hub =
        hub_over(Replay::new().env("ALL_PROXY", "http://admin:All-canary-pw@all.acme.test:8080"));
    assert_eq!(hub.set_proxy_from_env(), Ok(None));
    let probe = hub.check_probe("net.egress", Os::Linux, Some(egress()));
    assert!(
        probe.proxy_origin().is_none(),
        "ALL_PROXY is not used by a run"
    );
    let shown = hub
        .run_probe()
        .file_text(&FileBytes::new(b"x All-canary-pw y".to_vec()))
        .expect("text")
        .to_string();
    assert!(!shown.contains("All-canary-pw"), "{shown}");
    assert!(log_text(&hub).contains("ALL_PROXY"));
    assert!(!log_text(&hub).contains("All-canary-pw"));

    let hub = hub_over(Replay::new().env("all_proxy", "http://svc:pw@z.acme.test:1"));
    let error = hub.set_proxy_from_env().expect_err("refused");
    assert_eq!(
        (error.var, error.error),
        ("all_proxy", ProxyError::SecretRefused)
    );

    // Next to a proxy that is used, a refused ALL_PROXY password is still an error for its variable.
    let hub = hub_over(
        Replay::new()
            .env("HTTPS_PROXY", &proxy_url(false))
            .env("ALL_PROXY", "http://svc:pw@z.acme.test:1"),
    );
    let error = hub.set_proxy_from_env().expect_err("refused");
    assert_eq!(
        (error.var, error.error),
        ("ALL_PROXY", ProxyError::SecretRefused)
    );
}
