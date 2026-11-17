//! `net.egress` through the proxy (M1-097).
//!
//! The proxy and the servers are in-process loopback servers (`rdy_engine::testing::loopback`); the
//! machine's names point at them, so nothing leaves the host. The proxy URL carries a planted password,
//! and every test that proxies checks that it is in no finding, result or log entry.

use rdy_engine::testing::loopback::{ConnectProxy, ProxyMode};

use super::*;

/// The planted proxy password, and the base64 of `svc:` and the password, as `Proxy-Authorization`
/// would carry it.
const PASSWORD: &str = "longer-canary-pw";
const PAIR: &str = "c3ZjOmxvbmdlci1jYW5hcnktcHc=";

const PROXY_URL: &str = "http://svc:longer-canary-pw@proxy.acme.test:3128";
const PROXY_ORIGIN: &str = "http://proxy.acme.test:3128";

/// A machine whose `proxy.acme.test:3128` is the loopback `proxy`. Names are not looked up through a
/// proxy, so no other host is scripted; the OS store trusts `ca` when one is given.
fn through(proxy: &ConnectProxy, ca: Option<&TestCa>) -> Replay {
    let replay = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp(
            "192.0.2.50:3128".parse().expect("addr"),
            TcpScript::Serve("proxy".to_owned()),
        )
        .serve_tcp("proxy", proxy.addr());
    match ca {
        Some(ca) => replay.native(
            NativeCall::SystemRoots,
            NativeValue::SystemRoots(vec![der(ca)].into()),
        ),
        None => replay,
    }
}

fn kinds(ran: &Ran) -> Vec<rdy_spec::result::ActionKind> {
    ran.run
        .action_log()
        .actions
        .iter()
        .filter(|a| a.check.as_deref() == Some("net.egress"))
        .map(|a| a.kind.clone())
        .collect()
}

fn assert_secrets_absent(ran: &Ran) {
    ran.assert_no_secret(PASSWORD);
    ran.assert_no_secret(PAIR);
    ran.assert_no_secret("svc:");
}

// ---- CONNECT ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_https_url_is_tunnelled_with_connect_and_verified_end_to_end() {
    let ca = TestCa::root("Acme Test Root");
    let server = tls_server(&ca, "api.acme.test", Validity::Always).await;
    let at = format!("api.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, Some(&ca)),
        json!([url("api.acme.test", &server, "/health")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    let e = ran.endpoint(0);
    assert_eq!(e["route"], "proxy");
    assert_eq!(e["proxy"], PROXY_ORIGIN);
    assert!(
        e["proxy_attempts"].is_array() && e.get("attempts").is_none(),
        "{e}"
    );
    assert_eq!(e["tls_stage"]["roots"], "system");
    assert_eq!(e["http_stage"]["status"], 200);
    // The name resolved at the proxy: this machine looked up nothing for the endpoint.
    let log = kinds(&ran);
    assert!(
        !log.contains(&rdy_spec::result::ActionKind::Lookup),
        "{log:?}"
    );
    // Two tunnels, one for the handshake stage and one for the request, each with the credential, and the
    // origin saw one request with none.
    let connects = proxy.requests();
    assert_eq!(connects.len(), 2, "{connects:?}");
    for connect in &connects {
        assert_eq!(connect.target, at);
        assert_eq!(
            connect.proxy_authorization.as_deref(),
            Some(format!("Basic {PAIR}").as_str())
        );
    }
    let seen = server.requests();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].header("proxy-authorization"), None);
    assert!(
        ran.finding().notes.iter().any(|n| n.contains(PROXY_ORIGIN)),
        "{:?}",
        ran.finding().notes
    );
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_host_port_endpoint_is_tunnelled_and_passes() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([at]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert_eq!(proxy.requests().len(), 1);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_403_to_connect_is_proxy_403_with_the_allow_list_text() {
    let proxy = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!(["registry.acme.test:8443"]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(
        fix.starts_with("The proxy refused CONNECT to registry.acme.test:8443."),
        "{fix}"
    );
    assert!(fix.contains("add it to the allow list"), "{fix}");
    // A port other than 443 gets the Squid hint, because a default proxy allows tunnels only to 443.
    assert!(fix.contains("only to port 443"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_407_to_connect_names_what_the_proxy_wants() {
    for (mode, url, word, want) in [
        (
            ProxyMode::Basic407,
            PROXY_URL,
            "rejected",
            "rejected the user name or password",
        ),
        (
            ProxyMode::Basic407,
            "http://proxy.acme.test:3128",
            "needed",
            "wants a user name and password",
        ),
        (
            ProxyMode::Negotiate407,
            PROXY_URL,
            "negotiate",
            "wants integrated sign-in",
        ),
    ] {
        let proxy = ConnectProxy::start(mode).await.expect("proxy");
        let ran = run_via(
            through(&proxy, None),
            json!(["registry.acme.test:443"]),
            json!({}),
            NET,
            Some(url),
        )
        .await;
        assert_eq!(ran.endpoint(0)["class"], "proxy_407", "{word}");
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains(want), "{word}: {fix}");
        assert_eq!(ran.result().status, Status::Block);
        assert_secrets_absent(&ran);
    }
}

#[tokio::test]
async fn another_status_to_connect_is_proxy_refused_with_its_status() {
    // The proxy has no route for the name, so it answers 502.
    let proxy = ConnectProxy::start(ProxyMode::Ok).await.expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!(["gone.acme.test:443"]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_refused");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("answered 502"), "{fix}");
    assert_secrets_absent(&ran);
}

#[tokio::test(start_paused = true)]
async fn a_proxy_that_cannot_be_reached_is_proxy_unreachable_and_not_a_fault_of_the_endpoint() {
    let refused = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp("192.0.2.50:3128".parse().expect("addr"), TcpScript::Refused);
    let silent = Replay::new()
        .host("proxy.acme.test", ["192.0.2.50".parse().expect("ip")])
        .tcp(
            "192.0.2.50:3128".parse().expect("addr"),
            TcpScript::Blackhole,
        );
    // The proxy's own name does not resolve: the answer is empty.
    let no_name = Replay::new().host("proxy.acme.test", Vec::<std::net::IpAddr>::new());
    for (what, replay) in [
        ("refused", refused),
        ("silent", silent),
        ("no name", no_name),
    ] {
        for endpoint in [
            "registry.acme.test:8443",
            "https://api.acme.test/",
            "http://mirror.acme.test/",
        ] {
            let ran = run_via(
                replay.clone(),
                json!([endpoint]),
                json!({}),
                NET,
                Some(PROXY_URL),
            )
            .await;
            assert_eq!(
                ran.endpoint(0)["class"],
                "proxy_unreachable",
                "{what}: {endpoint}"
            );
            let fix = ran.finding().fix.as_deref().expect("a fix");
            assert!(fix.contains("`HTTPS_PROXY` or `HTTP_PROXY`"), "{fix}");
            assert_secrets_absent(&ran);
        }
    }
}

// ---- the absolute form -----------------------------------------------------------------------------

#[tokio::test]
async fn an_http_url_uses_the_absolute_form_and_never_connect() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let target = format!("http://{at}/repo/index?token=q-canary");
    let ran = run_via(
        through(&proxy, None),
        json!([target]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(
        ran.finding().level,
        Level::Pass,
        "{}",
        ran.finding().message
    );
    assert!(
        proxy.requests().is_empty(),
        "no CONNECT: {:?}",
        proxy.requests()
    );
    let plain = proxy.plain_requests();
    assert_eq!(plain.len(), 1);
    assert_eq!(
        plain[0].target,
        format!("http://{at}/repo/index?token=q-canary")
    );
    assert_eq!(
        plain[0].proxy_authorization.as_deref(),
        Some(format!("Basic {PAIR}").as_str())
    );
    assert_eq!(server.requests()[0].target, "/repo/index?token=q-canary");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 200);
    assert_secrets_absent(&ran);
    ran.assert_no_secret("q-canary");
}

#[tokio::test]
async fn a_403_to_the_absolute_form_is_proxy_403_unless_the_spec_lists_it() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Forbidden, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([format!("http://{at}/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_403");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("answered 403 to the request"), "{fix}");
    assert!(fix.contains("expect_status"), "{fix}");
    assert_eq!(ran.result().status, Status::Block);

    // The vendor says 403 is a normal answer of the server: it passes.
    let ran = run_via(
        through(&proxy, None),
        json!([{"target": format!("http://{at}/"), "expect_status": [403]}]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_407_to_the_absolute_form_is_proxy_407() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Basic407, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, None),
        json!([format!("http://{at}/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["class"], "proxy_407");
    let fix = ran.finding().fix.as_deref().expect("a fix");
    assert!(fix.contains("rejected the user name or password"), "{fix}");
    assert_eq!(server.accepted(), 0, "the origin was never reached");
    assert_secrets_absent(&ran);
}

// ---- redirects -------------------------------------------------------------------------------------

#[tokio::test]
async fn a_302_records_the_location_host_is_not_followed_and_says_to_add_it() {
    let location = "https://cdn.acme.example/next?token=hunter2-canary#frag";
    let server =
        HttpServer::start(HttpOptions::plain().reply(Reply::Redirect(location.to_owned())))
            .await
            .expect("server");
    let replay = Replay::new()
        .host("www.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let target = format!("http://www.acme.test:{}/", server.addr().port());
    let ran = run_on(replay.clone(), json!([target]), json!({}), NET).await;
    let http = &ran.endpoint(0)["http_stage"];
    assert_eq!(http["status"], 302);
    assert_eq!(http["location_host"], "cdn.acme.example");
    assert_eq!(server.requests().len(), 1, "the redirect was not followed");
    assert!(
        ran.finding().notes.iter().any(|n| n.contains(
            "redirects to cdn.acme.example, which rdy did not follow. Add cdn.acme.example:443 to the endpoints to test it."
        )),
        "{:?}",
        ran.finding().notes
    );
    // Only the host is kept: the path, the query and the fragment are not in the result.
    ran.assert_no_secret("hunter2-canary");
    ran.assert_no_secret("/next");

    // A host the check lists already needs no advice.
    let both = json!([
        format!("http://www.acme.test:{}/", server.addr().port()),
        "cdn.acme.example:8443"
    ]);
    let replay = replay
        .host("cdn.acme.example", ["127.0.0.1".parse().expect("ip")])
        .tcp(
            "127.0.0.1:8443".parse().expect("addr"),
            TcpScript::Serve("web".to_owned()),
        );
    let ran = run_on(replay, both, json!({}), NET).await;
    assert!(
        !ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("Add cdn.acme.example")),
        "{:?}",
        ran.finding().notes
    );
}

// ---- the route of each endpoint --------------------------------------------------------------------

#[tokio::test]
async fn the_route_follows_via_proxy_and_whether_the_run_has_a_proxy() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let direct_machine = || {
        through(&proxy, None)
            .host("db.acme.test", ["127.0.0.1".parse().expect("ip")])
            .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
            .serve_tcp("web", server.addr())
    };

    // `auto` with a proxy goes through it.
    let ran = run_via(
        direct_machine(),
        json!([at]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.endpoint(0)["route"], "proxy");
    assert_eq!(proxy.requests().len(), 1);

    // `direct` never touches it.
    let ran = run_via(
        direct_machine(),
        json!([at]),
        json!({"via_proxy": "direct"}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert!(ran.endpoint(0).get("route").is_none());
    assert_eq!(ran.finding().level, Level::Pass);
    assert_eq!(proxy.requests().len(), 1, "no second CONNECT");

    // `auto` with no proxy is direct; `proxy_only` with none is not tried.
    let ran = run_on(direct_machine(), json!([at]), json!({}), NET).await;
    assert!(ran.endpoint(0).get("route").is_none());
    let ran = run_on(
        direct_machine(),
        json!([at]),
        json!({"via_proxy": "proxy_only"}),
        NET,
    )
    .await;
    assert_eq!(ran.endpoint(0)["result"], "not_tried");
    assert!(
        ran.endpoint(0)["why"]
            .as_str()
            .is_some_and(|why| why.contains("HTTPS_PROXY or HTTP_PROXY")),
        "{}",
        ran.endpoint(0)
    );

    // An endpoint of its own beats the entry.
    let ran = run_via(
        direct_machine(),
        json!([{"target": at, "via_proxy": "direct"}]),
        json!({"via_proxy": "proxy_only"}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert!(ran.endpoint(0).get("route").is_none());
}

// ---- review round ------------------------------------------------------------------------------------

#[tokio::test]
async fn a_403_inside_an_https_tunnel_is_the_servers_and_only_warns() {
    let ca = TestCa::root("Acme Test Root");
    let options =
        HttpOptions::tls(&ca.issue(&["api.acme.test"], Validity::Always)).reply(Reply::Status(403));
    let server = HttpServer::start(options).await.expect("server");
    let at = format!("api.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let ran = run_via(
        through(&proxy, Some(&ca)),
        json!([url("api.acme.test", &server, "/")]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    // The tunnel was open and verified, so the 403 came from the server: the direct rule applies.
    assert_eq!(
        ran.finding().level,
        Level::Warn,
        "{}",
        ran.finding().message
    );
    assert_eq!(ran.endpoint(0)["result"], "reached");
    assert_ne!(ran.endpoint(0)["class"], "proxy_403");
    assert_eq!(ran.endpoint(0)["http_stage"]["status"], 403);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn a_direct_http_endpoint_sends_no_proxy_credential_when_a_proxy_is_set() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("mirror.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_forwarding(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    let replay = through(&proxy, None)
        .host("mirror.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let ran = run_via(
        replay,
        json!([{"target": format!("http://{at}/"), "via_proxy": "direct"}]),
        json!({}),
        NET,
        Some(PROXY_URL),
    )
    .await;
    assert_eq!(ran.finding().level, Level::Pass);
    let seen = server.requests();
    assert!(!seen.is_empty());
    assert!(
        seen.iter()
            .all(|r| r.header("proxy-authorization").is_none())
    );
    assert_eq!(proxy.accepted(), 0);
    assert_secrets_absent(&ran);
}

#[tokio::test]
async fn no_proxy_is_reported_as_not_applied_without_its_value() {
    let server = HttpServer::start(HttpOptions::plain())
        .await
        .expect("server");
    let at = format!("db.acme.test:{}", server.addr().port());
    let proxy = ConnectProxy::start_with_routes(ProxyMode::Ok, &[(&at, server.addr())])
        .await
        .expect("proxy");
    for name in ["NO_PROXY", "no_proxy"] {
        let replay = through(&proxy, None).env(name, "internal-canary.example,10.0.0.0/8");
        let ran = run_via(replay, json!([at]), json!({}), NET, Some(PROXY_URL)).await;
        assert!(
            ran.finding()
                .notes
                .iter()
                .any(|n| n.starts_with("NO_PROXY is set, and this build of rdy does not apply it")),
            "{name}: {:?}",
            ran.finding().notes
        );
        ran.assert_no_secret("internal-canary");
    }
    // Blank, or no proxy in use: no note.
    for (env, proxied) in [("   ", true), ("internal.example", false)] {
        let replay = through(&proxy, None).env("NO_PROXY", env);
        let proxy_text = proxied.then_some(PROXY_URL);
        let ran = run_via(
            replay
                .host("db.acme.test", ["127.0.0.1".parse().expect("ip")])
                .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
                .serve_tcp("web", server.addr()),
            json!([at]),
            json!({}),
            NET,
            proxy_text,
        )
        .await;
        assert!(
            !ran.finding().notes.iter().any(|n| n.contains("NO_PROXY")),
            "{env:?}: {:?}",
            ran.finding().notes
        );
    }
}

#[tokio::test]
async fn a_proxy_read_from_http_proxy_is_named_for_an_https_endpoint_and_in_the_fixes() {
    // A tunnelled TLS endpoint (port 443): the note names the variable. The proxy refuses, which is
    // enough: the endpoint went through the proxy.
    let forbidden = ConnectProxy::start(ProxyMode::Forbidden)
        .await
        .expect("proxy");
    let ran = run_from_env(
        through(&forbidden, None).env("http_proxy", PROXY_URL),
        json!(["registry.acme.test:443"]),
        json!({}),
        NET,
    )
    .await;
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.starts_with("An https endpoint went through a proxy read from http_proxy")),
        "{:?}",
        ran.finding().notes
    );
    // HTTPS_PROXY as the source: no such note.
    let ran = run_from_env(
        through(&forbidden, None).env("HTTPS_PROXY", PROXY_URL),
        json!(["registry.acme.test:443"]),
        json!({}),
        NET,
    )
    .await;
    assert!(!ran.finding().notes.iter().any(|n| n.contains("read from")));

    // The 407 fix names the variable the proxy came from.
    for (var, want) in [
        ("HTTP_PROXY", "`HTTP_PROXY`"),
        ("https_proxy", "`https_proxy`"),
    ] {
        let denied = ConnectProxy::start(ProxyMode::Basic407)
            .await
            .expect("proxy");
        let ran = run_from_env(
            through(&denied, None).env(var, PROXY_URL),
            json!(["registry.acme.test:443"]),
            json!({}),
            NET,
        )
        .await;
        let fix = ran.finding().fix.as_deref().expect("a fix");
        assert!(fix.contains(want), "{var}: {fix}");
        assert_secrets_absent(&ran);
    }
}

#[tokio::test]
async fn a_redirect_to_a_plain_http_host_suggests_port_80() {
    let server = HttpServer::start(
        HttpOptions::plain().reply(Reply::Redirect("http://old.acme.example/x".to_owned())),
    )
    .await
    .expect("server");
    let replay = Replay::new()
        .host("www.acme.test", ["127.0.0.1".parse().expect("ip")])
        .tcp(server.addr(), TcpScript::Serve("web".to_owned()))
        .serve_tcp("web", server.addr());
    let target = format!("http://www.acme.test:{}/", server.addr().port());
    let ran = run_on(replay, json!([target]), json!({}), NET).await;
    assert!(
        ran.finding()
            .notes
            .iter()
            .any(|n| n.contains("Add old.acme.example:80 to the endpoints")),
        "{:?}",
        ran.finding().notes
    );
}
